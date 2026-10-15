#!/usr/bin/env python3
"""Print QUIC packet timelines from testbed pcaps (stdlib only).

  tools/quic_timeline.py RUN_DIR [--last N] [--server-port PORT ...]

Reads odq-cp.pcap and odq-pr.pcap in RUN_DIR, groups UDP datagrams into
connections (client addr:port <-> server addr:port), decodes the QUIC packet
types inside each datagram (Initial, 0-RTT, Handshake, Retry, 1-RTT; walks
coalesced long-header packets), and prints the last N client->proxy
connections plus every proxy->resolver connection that overlaps them.

Times are milliseconds relative to the first packet of the client
connection being shown; both files share the host clock.

Why not tcpdump: tcpdump 4.99 only decodes QUIC on port 443 and has no
`-T quic` option.
"""

import argparse
import struct
from collections import OrderedDict
from pathlib import Path

LONG_TYPES = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}


def read_pcap(path):
    data = Path(path).read_bytes()
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
    else:
        raise SystemExit(f"{path}: not a classic pcap file (pcapng unsupported)")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    out, off = [], 24
    while off + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        pkt = data[off + 16:off + 16 + incl]
        off += 16 + incl
        t = sec + frac / (1e9 if nano else 1e6)
        udp = parse_udp(pkt, linktype)
        if udp:
            out.append((t,) + udp)
    return out


def parse_udp(pkt, linktype):
    if linktype == 1:            # Ethernet
        if len(pkt) < 14:
            return None
        etype = struct.unpack("!H", pkt[12:14])[0]
        ip = pkt[14:]
        if etype == 0x8100:      # VLAN
            etype = struct.unpack("!H", pkt[16:18])[0]
            ip = pkt[18:]
        if etype != 0x0800:
            return None
    elif linktype in (0, 108):   # null / loopback
        ip = pkt[4:]
    elif linktype == 113:        # Linux cooked
        ip = pkt[16:]
    elif linktype == 101:        # raw IP
        ip = pkt
    else:
        return None
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 17:
        return None
    ihl = (ip[0] & 0x0F) * 4
    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    sport, dport, ulen = struct.unpack("!HHH", ip[ihl:ihl + 6])
    payload = ip[ihl + 8:ihl + ulen]
    return src, sport, dst, dport, payload


def varint(b, i):
    if i >= len(b):
        raise IndexError
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


def quic_types(p):
    """List the QUIC packet types coalesced in one UDP payload."""
    types, i = [], 0
    try:
        while i < len(p):
            first = p[i]
            if not first & 0x40:          # fixed bit clear: datagram padding
                break
            if not first & 0x80:          # short header: rest of datagram
                types.append("1-RTT")
                break
            version = struct.unpack("!I", p[i + 1:i + 5])[0]
            if version == 0:
                types.append("VersionNeg")
                break
            ptype = LONG_TYPES[(first >> 4) & 0x03]
            j = i + 5
            dcl = p[j]
            j += 1 + dcl
            scl = p[j]
            j += 1 + scl
            if ptype == "Retry":
                types.append("Retry")
                break
            if ptype == "Initial":
                tl, j = varint(p, j)
                j += tl
            ln, j = varint(p, j)
            types.append(ptype)
            i = j + ln
    except (IndexError, KeyError, struct.error):
        types.append("?")
    return types


def connections(pkts, server_ports):
    conns = OrderedDict()
    for t, src, sp, dst, dp, payload in pkts:
        if dp in server_ports:
            key, direction = (src, sp, dst, dp), "->"
        elif sp in server_ports:
            key, direction = (dst, dp, src, sp), "<-"
        else:
            continue
        conns.setdefault(key, []).append((t, direction, len(payload),
                                          quic_types(payload)))
    return conns


def show(name, key, pkts, t0):
    c = f"{key[0]}:{key[1]}"
    s = f"{key[2]}:{key[3]}"
    print(f"  [{name}] client {c}  server {s}")
    for t, d, n, types in pkts:
        arrow = "client -> server" if d == "->" else "client <- server"
        print(f"    {1000 * (t - t0):9.2f} ms  {arrow}  {n:5d} B  {'+'.join(types)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--last", type=int, default=2,
                    help="how many of the last client connections to show")
    ap.add_argument("--server-port", type=int, action="append",
                    default=None, help="QUIC server ports (default 853 8853-8855)")
    a = ap.parse_args()
    ports = set(a.server_port or [853, 8853, 8854, 8855])
    cp = connections(read_pcap(a.run_dir / "odq-cp.pcap"), ports)
    pr = connections(read_pcap(a.run_dir / "odq-pr.pcap"), ports)
    print(f"{a.run_dir}: {len(cp)} client->proxy and {len(pr)} proxy->resolver "
          f"connections")
    if not cp:
        print("  no client->proxy connections found (DoQ run? then use odq-cr)")
        return
    for key in list(cp)[-a.last:]:
        pk = cp[key]
        t0, t_end = pk[0][0], pk[-1][0]
        print(f"\n=== client connection starting {t0:.6f}")
        show("client<->proxy", key, pk, t0)
        for k2, p2 in pr.items():
            if p2[-1][0] >= t0 and p2[0][0] <= t_end:
                show("proxy<->resolver", k2, p2, t0)


if __name__ == "__main__":
    main()
