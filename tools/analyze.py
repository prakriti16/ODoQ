#!/usr/bin/env python3
"""Summarise a campaign (stdlib only).

  tools/analyze.py results/stage1_smoke_<stamp>

Writes into the campaign directory:
  queries.csv    every timed query (client view) with run factors
  summary.csv    per cell: n, failures, mean/median/p5/p95/p99/min/max latency,
                 sizes at each layer, 0-RTT acceptance
  breakdown.csv  per cell: median time per hop/stage, from joining the client,
                 proxy and resolver logs (same CLOCK_MONOTONIC, so valid)

Joins: client.local port + stream_id == proxy.peer port + stream_id (ODoQ) or
resolver.peer port + stream_id (DoQ); proxy.up_local port + up_stream_id ==
resolver.peer port + stream_id. Joins are restricted to each run's window.
"""

import argparse
import csv
import json
import math
import statistics as st
from collections import defaultdict
from pathlib import Path

FACTORS = ["variant", "conn_mode", "cache", "netem", "padding"]


def pct(xs, p):
    """Linear-interpolated percentile, p in [0, 100]."""
    if not xs:
        return math.nan
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100
    lo, hi = math.floor(k), math.ceil(k)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def read_jsonl(path):
    out = []
    if Path(path).exists():
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass  # torn last line of a live log
    return out


def port(addr):
    return addr[1] if isinstance(addr, (list, tuple)) and len(addr) > 1 else None


def index_component(rows, addr_key, sid_key):
    idx = defaultdict(list)
    for r in rows:
        if r.get("event") == "query" and r.get(addr_key) is not None:
            idx[(port(r[addr_key]), r.get(sid_key))].append(r)
    return idx


def find(idx, key, t_lo, t_hi):
    for r in idx.get(key, []):
        if t_lo <= r["t_recv"] <= t_hi:
            return r
    return None


def ms(a, b):
    return (b - a) / 1e6 if a is not None and b is not None else None


def stages(c, p, r):
    s = {"c_build": ms(c.get("t_start"), c.get("t_built")),
         "c_connect": ms(c.get("t_built"), c.get("t_connected")),
         "c_open": ms(c.get("t_resp"), c.get("t_done"))}
    if r is not None:
        s["r_open"] = ms(r["t_recv"], r.get("t_opened"))
        s["r_backend"] = ms(r.get("t_opened", r["t_recv"]), r.get("t_backend"))
        s["r_seal"] = ms(r.get("t_backend"), r.get("t_sealed"))
        s["r_send"] = ms(r.get("t_sealed"), r.get("t_tx"))
    if p is None:  # DoQ
        if r is not None:
            s["net_c_to_r"] = ms(c.get("t_sent"), r["t_recv"])
            s["net_r_to_c"] = ms(r.get("t_tx"), c.get("t_resp"))
        return s
    s["net_c_to_p"] = ms(c.get("t_sent"), p["t_recv"])
    s["p_split"] = ms(p["t_recv"], p.get("t_split"))
    s["p_up_connect"] = ms(p.get("t_up_conn_start"), p.get("t_up_conn_done"))
    s["p_relay"] = ms(p.get("t_up_recv"), p.get("t_tx"))
    s["net_p_to_c"] = ms(p.get("t_tx"), c.get("t_resp"))
    if p.get("t_up_recv_before_close"):
        s["p_legacy_close_wait"] = ms(p["t_up_recv_before_close"], p["t_up_recv"])
    if r is not None:
        s["net_p_to_r"] = ms(p.get("t_up_sent"), r["t_recv"])
        end = p.get("t_up_recv_before_close", p.get("t_up_recv"))
        s["net_r_to_p"] = ms(r.get("t_tx"), end)
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("campaign_dir", type=Path)
    ap.add_argument("--components", type=Path, default=None,
                    help="dir with proxy.jsonl/resolver.jsonl "
                         "(default: <results>/components)")
    a = ap.parse_args()
    d = a.campaign_dir
    comp = a.components or d.parent / "components"
    proxy_idx = index_component(read_jsonl(comp / "proxy.jsonl"), "peer", "stream_id")
    res_rows = read_jsonl(comp / "resolver.jsonl")
    res_idx = index_component(res_rows, "peer", "stream_id")

    runs = read_jsonl(d / "runs.jsonl")
    queries, groups, bgroups = [], defaultdict(list), defaultdict(lambda: defaultdict(list))
    joined = unjoined = 0
    for run in runs:
        lo, hi = run["t_start_ns"], run["t_end_ns"]
        key = tuple(run[f] for f in FACTORS)
        for c in read_jsonl(d / "runs" / run["run_id"] / "client.jsonl"):
            if c.get("event") != "query":
                continue
            row = {f: run[f] for f in FACTORS}
            row.update(run_id=run["run_id"], rep=run["rep"], seq=c["seq"],
                       qname=c.get("base_qname"), ok=c.get("ok", False),
                       error=c.get("error"), rcode=c.get("rcode"),
                       latency_ms=(c["latency_ns"] / 1e6 if c.get("ok") else None),
                       dns_query_bytes=c.get("dns_query_bytes"),
                       dns_resp_bytes=c.get("dns_resp_bytes"),
                       req_stream_bytes=c.get("req_stream_bytes"),
                       resp_stream_bytes=c.get("resp_stream_bytes"),
                       udp_sent_bytes=c.get("udp_sent_bytes"),
                       udp_recv_bytes=c.get("udp_recv_bytes"),
                       early_data_accepted=c.get("early_data_accepted"),
                       session_resumed=c.get("session_resumed"))
            queries.append(row)
            groups[key].append(row)
            if not c.get("ok"):
                continue
            if run["variant"].startswith("odoh"):
                continue  # ODoH hop logs are separate; breakdown not joined here
            jk = (port(c.get("local")), c.get("stream_id"))
            if run["variant"] == "doq":
                p, r = None, find(res_idx, jk, lo, hi)
            else:
                p = find(proxy_idx, jk, lo, hi)
                r = None
                if p is not None:
                    r = find(res_idx, (port(p.get("up_local")), p.get("up_stream_id")),
                             lo, hi)
            if (run["variant"] != "doq" and p is None) or r is None:
                unjoined += 1
            else:
                joined += 1
            for k, v in stages(c, p, r).items():
                if v is not None:
                    bgroups[key][k].append(v)

    if not queries:
        raise SystemExit("no queries found")
    with open(d / "queries.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(queries[0]))
        w.writeheader()
        w.writerows(queries)

    summ = []
    for key, rows in sorted(groups.items()):
        lat = [r["latency_ms"] for r in rows if r["ok"]]
        okr = [r for r in rows if r["ok"]]

        def med(f):
            v = [r[f] for r in okr if r[f] is not None]
            return st.median(v) if v else None
        e0 = [r["early_data_accepted"] for r in okr if r["early_data_accepted"] is not None]
        summ.append(dict(zip(FACTORS, key), n=len(rows), failures=len(rows) - len(okr),
                         mean_ms=st.fmean(lat) if lat else None,
                         std_ms=st.stdev(lat) if len(lat) > 1 else None,
                         median_ms=pct(lat, 50), p5_ms=pct(lat, 5), p95_ms=pct(lat, 95),
                         p99_ms=pct(lat, 99), min_ms=min(lat, default=None),
                         max_ms=max(lat, default=None),
                         dns_query_bytes=med("dns_query_bytes"),
                         dns_resp_bytes=med("dns_resp_bytes"),
                         req_stream_bytes=med("req_stream_bytes"),
                         resp_stream_bytes=med("resp_stream_bytes"),
                         udp_sent_bytes=med("udp_sent_bytes"),
                         udp_recv_bytes=med("udp_recv_bytes"),
                         early_data_rate=(sum(e0) / len(e0)) if e0 else None))
    with open(d / "summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summ[0]))
        w.writeheader()
        w.writerows(summ)

    stage_names = sorted({s for g in bgroups.values() for s in g})
    with open(d / "breakdown.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(FACTORS + [f"{s}_median_ms" for s in stage_names])
        for key, g in sorted(bgroups.items()):
            w.writerow(list(key) + [f"{st.median(g[s]):.4f}" if g.get(s) else ""
                                    for s in stage_names])

    print(f"{len(queries)} queries, {sum(not q['ok'] for q in queries)} failed; "
          f"hop join: {joined} joined, {unjoined} unjoined")
    hdr = f"{'variant':16}{'mode':7}{'cache':6}{'netem':13}{'pad':9}{'n':>5}{'fail':>5}" \
          f"{'median':>9}{'p95':>9}{'p99':>9}{'req_B':>7}{'resp_B':>7}"
    print(hdr)
    for s in summ:
        print(f"{s['variant']:16}{s['conn_mode']:7}{s['cache']:6}{s['netem']:13}"
              f"{s['padding']:9}{s['n']:5}{s['failures']:5}{s['median_ms']:9.2f}"
              f"{s['p95_ms']:9.2f}{s['p99_ms']:9.2f}"
              f"{(s['req_stream_bytes'] or 0):7.0f}{(s['resp_stream_bytes'] or 0):7.0f}")
    sanity_check(d, summ)
    print(f"wrote queries.csv, summary.csv, breakdown.csv to {d}")


def sanity_check(d, summ):
    """Warm-mode median must be at least the emulated path RTT. A median
    below that floor means the shaping was not what the profile says."""
    try:
        man = json.loads((d / "manifest.json").read_text())
        profiles = json.loads(man["configs"]["config/netem_profiles.json"])
    except (OSError, KeyError, ValueError):
        return
    bad = []
    for s in summ:
        prof = profiles.get(s["netem"])
        if prof is None or s["conn_mode"] != "warm" or s["median_ms"] != s["median_ms"]:
            continue
        rtt = lambda k: prof.get(k, {}).get("rtt_ms", 0)  # noqa: E731
        if s["variant"] == "doq":
            floor = rtt("cr")
        elif s["variant"].startswith("odoh"):
            floor = rtt("co") + rtt("ot")
        else:
            floor = rtt("cp") + rtt("pr")
        if s["cache"] == "miss":
            floor += rtt("ra")
        if s["median_ms"] < 0.97 * floor:
            bad.append(f"{s['variant']} {s['cache']} {s['netem']} {s['padding']}: "
                       f"median {s['median_ms']:.1f} ms < path RTT {floor} ms")
    if bad:
        print("SANITY CHECK FAILED (shaping not as configured):")
        for b in bad:
            print("  " + b)
    else:
        print("sanity check: warm medians >= emulated path RTT")


if __name__ == "__main__":
    main()
