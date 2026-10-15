#!/usr/bin/env python3
"""Generate NSD zone files, NSD zone list, Unbound stub zones and the qname
list from config/domains.json.  Usage: tools/gen_zones.py [config_dir]

Every qname also gets a wildcard sibling (*.qname) with the same record set,
so cache-busting queries (cb<random>.qname) miss Unbound's cache but receive a
response of the same shape.  Addresses are deterministic, from documentation
ranges (RFC 5737 / RFC 3849).
"""
import hashlib
import json
import sys
from pathlib import Path

cfg_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "config")
cfg = json.loads((cfg_dir / "domains.json").read_text())
ttl, auth = cfg["ttl"], cfg["auth_addr"]
zones = {}
for d in cfg["domains"]:
    zones.setdefault(d["zone"], []).append(d)

def v4(seed, i):
    h = hashlib.sha256(f"{seed}/{i}".encode()).digest()
    net = ["192.0.2", "198.51.100", "203.0.113"][h[0] % 3]
    return f"{net}.{1 + h[1] % 254}"

def v6(seed, i):
    h = hashlib.sha256(f"{seed}/v6/{i}".encode()).hexdigest()
    return f"2001:db8:{h[0:4]}:{h[4:8]}::{h[8:12]}"

zdir = cfg_dir / "zones"
zdir.mkdir(exist_ok=True)
nsd_list, stubs = [], []
for zone, items in sorted(zones.items()):
    lines = [f"$ORIGIN {zone}.", f"$TTL {ttl}",
             f"@ IN SOA ns1.{zone}. hostmaster.{zone}. 1 3600 600 86400 {ttl}",
             f"@ IN NS ns1.{zone}.", f"ns1 IN A {auth}"]
    for d in items:
        q = d["qname"]
        rel = "@" if q == zone else q[: -len(zone) - 1]
        wild = "*" if rel == "@" else f"*.{rel}"
        for owner in (rel, wild):
            for i in range(d["a"]):
                lines.append(f"{owner} IN A {v4(q, i)}")
            for i in range(d["aaaa"]):
                lines.append(f"{owner} IN AAAA {v6(q, i)}")
    (zdir / f"{zone}.zone").write_text("\n".join(lines) + "\n")
    nsd_list.append(f'zone:\n    name: "{zone}"\n    zonefile: "{zone}.zone"\n')
    stubs.append(f'stub-zone:\n    name: "{zone}"\n    stub-addr: {auth}\n')

(cfg_dir / "nsd_zones.conf").write_text("".join(nsd_list))
(cfg_dir / "unbound_stubs.conf").write_text("".join(stubs))
(cfg_dir / "qnames.txt").write_text("\n".join(d["qname"] for d in cfg["domains"]) + "\n")
print(f"{len(zones)} zones, {len(cfg['domains'])} qnames -> {cfg_dir}")
