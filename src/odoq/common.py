"""Shared helpers for every testbed component.

Timing: all timestamps are CLOCK_MONOTONIC in nanoseconds. On Linux this
clock is system-wide, and Docker does not use time namespaces by default, so
timestamps taken in different containers on the same host are directly
comparable. That is what makes per-hop breakdowns valid in this testbed.
"""

import asyncio
import contextlib
import json
import os
import socket
import struct
import sys
import threading
import time
from typing import Dict, Optional

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    QuicEvent,
    StreamDataReceived,
)
from dnslib import DNSRecord, EDNS0, EDNSOption

PADDING_OPTION = 12  # RFC 7830


def now_ns() -> int:
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

class JsonLog:
    """Append-only JSON Lines log. One object per line, flushed per write.

    Never log key material or plaintext payloads here: logs are meant to be
    published with the paper's artifact.
    """

    def __init__(self, path: Optional[str], component: str):
        self.component = component
        self._lock = threading.Lock()
        self._fh = None
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self._fh = open(path, "a", buffering=1)
        self.write("component_start", pid=os.getpid(), host=socket.gethostname(),
                   argv=sys.argv)

    def write(self, event: str, **fields) -> None:
        rec = {"t_ns": now_ns(), "component": self.component, "event": event}
        rec.update(fields)
        line = json.dumps(rec, separators=(",", ":"), default=str)
        if self._fh is None:
            print(line, flush=True)
            return
        with self._lock:
            self._fh.write(line + "\n")

    def close(self) -> None:
        if self._fh:
            self._fh.close()


def open_secrets(path: Optional[str]):
    """Open a TLS key log (NSS format, for Wireshark). Testbed keys only."""
    if not path:
        return None
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    return open(path, "a", buffering=1)


# --------------------------------------------------------------------------
# Stream framing (RFC 9250 section 4.2: 2-byte length prefix on every message)
# --------------------------------------------------------------------------

def frame(msg: bytes) -> bytes:
    if len(msg) > 0xFFFF:
        raise ValueError("message too large for 2-byte length prefix")
    return struct.pack("!H", len(msg)) + msg


def unframe(data: bytes) -> bytes:
    if len(data) < 2:
        raise ValueError("stream shorter than length prefix")
    (n,) = struct.unpack("!H", data[:2])
    if len(data) - 2 != n:
        raise ValueError(f"length prefix {n} != payload {len(data) - 2}")
    return data[2:]


# --------------------------------------------------------------------------
# DNS helpers
# --------------------------------------------------------------------------

def build_query(qname: str, qtype: str, edns_bufsize: int = 1232,
                pad_block: int = 0) -> bytes:
    """Build a DNS query with message ID 0 (required by RFC 9250) and EDNS(0).

    The same builder is used for every protocol so the inner DNS message is
    byte-identical across protocols for the same (qname, qtype, padding).
    """
    q = DNSRecord.question(qname, qtype)
    q.header.id = 0
    q.header.rd = 1
    q.add_ar(EDNS0(udp_len=edns_bufsize))
    wire = q.pack()
    return pad_dns(wire, pad_block) if pad_block else wire


def pad_dns(wire: bytes, block: int) -> bytes:
    """Apply RFC 7830 EDNS(0) padding so len(message) is a multiple of block.

    Applied at the DNS layer, so it is protocol-neutral: DoQ, ODoQ and later
    DoH/ODoH carry the same padded message. Returns the input unchanged if
    block <= 0 or the message has no OPT record.
    """
    if block <= 0:
        return wire
    rec = DNSRecord.parse(wire)
    opt = None
    for rr in rec.ar:
        if rr.rtype == 41:  # OPT
            opt = rr
            break
    if opt is None:
        return wire
    opt.rdata = [o for o in opt.rdata if o.code != PADDING_OPTION]
    base = len(rec.pack()) + 4  # +4 for padding option code/length
    pad_len = (-base) % block
    opt.rdata.append(EDNSOption(PADDING_OPTION, b"\x00" * pad_len))
    out = rec.pack()
    if len(out) % block != 0:  # dnslib re-packing changed compression
        raise RuntimeError("padding failed to reach block boundary")
    return out


def has_padding(wire: bytes) -> bool:
    """True if the message carries an RFC 7830 padding option."""
    try:
        for rr in DNSRecord.parse(wire).ar:
            if rr.rtype == 41 and any(o.code == PADDING_OPTION for o in rr.rdata):
                return True
    except Exception:
        pass
    return False


def set_dns_id(wire: bytes, msg_id: int) -> bytes:
    return struct.pack("!H", msg_id) + wire[2:]


def check_response(query_wire: bytes, resp_wire: bytes) -> dict:
    """Validate a response against its query. Returns fields for the log.

    A mismatch is reported as ok=False (never silently ignored).
    """
    q = DNSRecord.parse(query_wire)
    r = DNSRecord.parse(resp_wire)
    problems = []
    if r.header.id != q.header.id:
        problems.append("id")
    if not r.q or str(r.q.qname).lower() != str(q.q.qname).lower():
        problems.append("qname")
    elif r.q.qtype != q.q.qtype:
        problems.append("qtype")
    return {
        "ok": not problems,
        "problems": problems,
        "rcode": r.header.rcode,
        "tc": bool(r.header.tc),
        "answers": len(r.rr),
        "dns_resp_bytes": len(resp_wire),
    }


# --------------------------------------------------------------------------
# QUIC protocol base with per-stream buffering
# --------------------------------------------------------------------------

class StreamBufferProtocol(QuicConnectionProtocol):
    """Buffers each stream until FIN, then hands the full message on.

    Fixes the old code, which used only the first (or last) StreamDataReceived
    chunk and silently corrupted any message split across frames.

    Client side: request() opens a stream, sends, and awaits the full reply.
    Server side: subclasses override on_stream_complete().
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._bufs: Dict[int, bytearray] = {}
        self._waiters: Dict[int, asyncio.Future] = {}
        self.handshake: Optional[HandshakeCompleted] = None
        self.terminated: Optional[ConnectionTerminated] = None

    # -- client role -------------------------------------------------------
    async def request(self, payload: bytes, info: Optional[dict] = None) -> bytes:
        """Send payload on a new stream; return the full reply.

        If info is given, info["stream_id"] is set so logs can be joined
        with the peer's log (peer address + stream id identify a query).
        """
        if self.terminated is not None:
            raise ConnectionError("connection already terminated")
        sid = self._quic.get_next_available_stream_id()
        if info is not None:
            info["stream_id"] = sid
        fut = self._loop.create_future()
        self._waiters[sid] = fut
        self._quic.send_stream_data(sid, payload, end_stream=True)
        self.transmit()
        return await fut

    # -- server role -------------------------------------------------------
    def on_stream_complete(self, stream_id: int, data: bytes, t_ns: int) -> None:
        """Peer-initiated stream finished. Default: ignore (client roles)."""

    # -- shared ------------------------------------------------------------
    def peer_addr(self):
        try:
            return self._quic._network_paths[0].addr  # aioquic private attr
        except (AttributeError, IndexError):
            return None

    def local_addr(self):
        try:
            return self._transport.get_extra_info("sockname")
        except AttributeError:
            return None

    def path_bytes(self):
        """(sent, received) UDP payload bytes on the primary network path."""
        try:
            p = self._quic._network_paths[0]
            return p.bytes_sent, p.bytes_received
        except (AttributeError, IndexError):
            return None, None

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            buf = self._bufs.setdefault(event.stream_id, bytearray())
            buf += event.data
            if event.end_stream:
                data = bytes(self._bufs.pop(event.stream_id))
                t = now_ns()
                fut = self._waiters.pop(event.stream_id, None)
                if fut is not None:
                    if not fut.done():
                        fut.set_result(data)
                else:
                    self.on_stream_complete(event.stream_id, data, t)
        elif isinstance(event, HandshakeCompleted):
            self.handshake = event
        elif isinstance(event, ConnectionTerminated):
            self.terminated = event
            err = ConnectionError(
                f"connection terminated: {event.error_code} {event.reason_phrase}")
            for fut in self._waiters.values():
                if not fut.done():
                    fut.set_exception(err)
            self._waiters.clear()


# --------------------------------------------------------------------------
# Address-family-aware replacement for aioquic.asyncio.connect
# --------------------------------------------------------------------------

@contextlib.asynccontextmanager
async def quic_connect(host, port, *, configuration, create_protocol,
                       session_ticket_handler=None, wait_connected=True):
    """Same behaviour as aioquic.asyncio.connect (including waiting for the
    closing period on exit), but opens an AF_INET socket for IPv4 targets.

    aioquic's connect() always opens a dual-stack AF_INET6 socket, which
    fails on hosts/containers without IPv6 and makes log addresses
    inconsistent ("::ffff:10.77.1.20" vs "10.77.1.20").
    """
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    family, _, _, _, addr = infos[0]
    connection = QuicConnection(configuration=configuration,
                                session_ticket_handler=session_ticket_handler)
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 0) if family == socket.AF_INET else ("::", 0, 0, 0))
    except Exception:
        sock.close()
        raise
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: create_protocol(connection), sock=sock)
    try:
        protocol.connect(addr, transmit=wait_connected)
        if wait_connected:
            await protocol.wait_connected()
        yield protocol
    finally:
        protocol.close()
        await protocol.wait_closed()
        transport.close()
