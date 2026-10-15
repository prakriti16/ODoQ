#!/usr/bin/env python3
"""Make the paper's figures from a campaign (matplotlib + stdlib).

  tools/plot.py results/stage1_main_<stamp>

Reads queries.csv (per-query, for CDFs and distributions) and summary.csv
(per-cell medians/percentiles) and writes PDF + PNG into <dir>/figures/:

  fig_latency_vs_rtt        median latency vs link RTT, warm hit, with p95 band
  fig_variants              ODoQ persistent/per-query vs DoQ, warm hit, by RTT
  fig_cdf_rtt50             latency CDF at rtt50, warm hit
  fig_cdf_loss              latency CDF at rtt50_loss5, warm hit (the tail story)
  fig_zerortt               cold vs resume (0-RTT) saving, rtt50 hit
  fig_sizes                 request/response bytes per protocol
  fig_breakdown             per-hop median stack, rtt50 warm hit (needs breakdown.csv)

Only the protocols/cells present in the data are drawn, so it also works on
the smoke campaign. Colours and markers are fixed per protocol across figures.
"""

import argparse
import csv
import math
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

STYLE = {  # protocol/variant -> (label, colour, marker)
    "doq": ("DoQ", "#1b9e77", "o"),
    "odoq-persistent": ("ODoQ (persistent)", "#d95f02", "s"),
    "odoq-per-query": ("ODoQ (per-query)", "#7570b3", "^"),
    "odoq-legacy": ("ODoQ (legacy)", "#e7298a", "D"),
    "odoh-h3": ("ODoH (HTTP/3)", "#66a61e", "v"),
    "odoh-h2": ("ODoH (HTTP/2)", "#e6ab02", "P"),
}
RTT_OF = {"lan": 0, "rtt10": 10, "rtt50": 50, "rtt100": 100,
          "rtt50_loss1": 50, "rtt50_loss5": 50}


def load(path):
    with open(path) as fh:
        return list(csv.DictReader(fh))


def f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return math.nan


def variants_in(rows):
    seen = [v for v in STYLE if any(r["variant"] == v for r in rows)]
    return seen


def save(fig, out, name):
    out.mkdir(exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(out / f"{name}.{ext}", bbox_inches="tight", dpi=150)
    plt.close(fig)
    print(f"  {name}")


# --------------------------------------------------------------------------

def fig_latency_vs_rtt(summ, out):
    profiles = [p for p in ("lan", "rtt10", "rtt50", "rtt100")
                if any(s["netem"] == p for s in summ)]
    fig, ax = plt.subplots(figsize=(5, 3.4))
    for v in variants_in(summ):
        label, col, mk = STYLE[v]
        xs, med, p95 = [], [], []
        for p in profiles:
            cell = [s for s in summ if s["variant"] == v and s["netem"] == p
                    and s["conn_mode"] == "warm" and s["cache"] == "hit"
                    and s["padding"] == "none"]
            if not cell:
                continue
            xs.append(RTT_OF[p])
            med.append(f(cell[0]["median_ms"]))
            p95.append(f(cell[0]["p95_ms"]))
        if xs:
            ax.plot(xs, med, marker=mk, color=col, label=label)
            ax.fill_between(xs, med, p95, color=col, alpha=0.12)
    ax.set_xlabel("Link RTT (ms)")
    ax.set_ylabel("Resolution latency (ms)")
    ax.set_title("Warm connection, cache hit (median; band to p95)")
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8)
    save(fig, out, "fig_latency_vs_rtt")


def fig_variants(summ, out):
    profiles = [p for p in ("lan", "rtt50", "rtt100") if any(
        s["netem"] == p for s in summ)]
    vs = variants_in(summ)
    fig, ax = plt.subplots(figsize=(5.5, 3.4))
    w = 0.8 / max(len(vs), 1)
    for i, v in enumerate(vs):
        label, col, _ = STYLE[v]
        ys = []
        for p in profiles:
            cell = [s for s in summ if s["variant"] == v and s["netem"] == p
                    and s["conn_mode"] == "warm" and s["cache"] == "hit"
                    and s["padding"] == "none"]
            ys.append(f(cell[0]["median_ms"]) if cell else math.nan)
        xs = [j + (i - (len(vs) - 1) / 2) * w for j in range(len(profiles))]
        ax.bar(xs, ys, w, color=col, label=label)
    ax.set_xticks(range(len(profiles)))
    ax.set_xticklabels([p if p == "lan" else f"{RTT_OF[p]} ms" for p in profiles])
    ax.set_xlabel("Link RTT")
    ax.set_ylabel("Median latency (ms)")
    ax.set_title("Protocol comparison, warm, cache hit")
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend(fontsize=8)
    save(fig, out, "fig_variants")


def cdf(ax, xs, label, col):
    xs = sorted(v for v in xs if not math.isnan(v))
    if not xs:
        return
    ys = [(i + 1) / len(xs) for i in range(len(xs))]
    ax.step(xs, ys, where="post", label=label, color=col)


def fig_cdf(queries, out, netem, name, title):
    rows = [r for r in queries if r["netem"] == netem and r["conn_mode"] == "warm"
            and r["cache"] == "hit" and r["padding"] == "none" and r["ok"] == "True"]
    if not rows:
        return
    by = defaultdict(list)
    for r in rows:
        by[r["variant"]].append(f(r["latency_ms"]))
    fig, ax = plt.subplots(figsize=(5, 3.4))
    for v in variants_in(rows):
        label, col, _ = STYLE[v]
        cdf(ax, by[v], label, col)
    ax.set_xlabel("Resolution latency (ms)")
    ax.set_ylabel("CDF")
    ax.set_title(title)
    ax.set_ylim(0, 1)
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8, loc="lower right")
    save(fig, out, name)


def fig_cdf_loss_log(queries, out):
    rows = [r for r in queries if r["netem"] == "rtt50_loss5"
            and r["conn_mode"] == "warm" and r["cache"] == "hit"
            and r["padding"] == "none" and r["ok"] == "True"]
    if not rows:
        return
    by = defaultdict(list)
    for r in rows:
        by[r["variant"]].append(f(r["latency_ms"]))
    fig, ax = plt.subplots(figsize=(5, 3.4))
    for v in variants_in(rows):
        label, col, _ = STYLE[v]
        cdf(ax, by[v], label, col)
    ax.set_xscale("log")
    ax.set_xlabel("Resolution latency (ms, log scale)")
    ax.set_ylabel("CDF")
    ax.set_title("Latency CDF at 50 ms RTT, 5% loss (warm, hit)")
    ax.set_ylim(0, 1)
    ax.grid(True, which="both", alpha=0.3)
    ax.legend(fontsize=8, loc="lower right")
    save(fig, out, "fig_cdf_loss")


def fig_zerortt(summ, out):
    profiles = [p for p in ("rtt50", "rtt100") if any(
        s["netem"] == p for s in summ)]
    vs = [v for v in variants_in(summ) if v != "odoq-legacy"]
    fig, ax = plt.subplots(figsize=(5.5, 3.4))
    groups = [(v, p) for v in vs for p in profiles]
    x = range(len(groups))
    for mode, hatch, a in (("cold", "", 1.0), ("resume", "//", 0.55)):
        ys = []
        for v, p in groups:
            cell = [s for s in summ if s["variant"] == v and s["netem"] == p
                    and s["conn_mode"] == mode and s["cache"] == "hit"
                    and s["padding"] == "none"]
            ys.append(f(cell[0]["median_ms"]) if cell else math.nan)
        cols = [STYLE[v][1] for v, _ in groups]
        off = -0.2 if mode == "cold" else 0.2
        ax.bar([i + off for i in x], ys, 0.4, color=cols, alpha=a, hatch=hatch,
               label="cold (full handshake)" if mode == "cold" else "resume (0-RTT)")
    ax.set_xticks(list(x))
    ax.set_xticklabels([f"{STYLE[v][0].split()[0]}\n{RTT_OF[p]}ms" for v, p in groups],
                       fontsize=7)
    ax.set_ylabel("Median latency (ms)")
    ax.set_title("0-RTT resumption saving, cache hit")
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend(fontsize=8)
    save(fig, out, "fig_zerortt")


def fig_sizes(summ, out):
    vs = variants_in(summ)
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(7, 3.2))
    for ax, field, title in ((a1, "req_stream_bytes", "Request"),
                             (a2, "resp_stream_bytes", "Response")):
        ys = []
        for v in vs:
            cell = [s for s in summ if s["variant"] == v and s["netem"] == "lan"
                    and s["conn_mode"] == "warm" and s["cache"] == "hit"
                    and s["padding"] == "none"]
            ys.append(f(cell[0][field]) if cell else math.nan)
        ax.bar([STYLE[v][0].replace(" ", "\n") for v in vs], ys,
               color=[STYLE[v][1] for v in vs])
        ax.set_ylabel("Bytes (QUIC stream payload)")
        ax.set_title(title)
        ax.tick_params(axis="x", labelsize=7)
        ax.grid(True, axis="y", alpha=0.3)
    fig.suptitle("On-wire message sizes (unpadded)")
    save(fig, out, "fig_sizes")


def fig_breakdown(path, out):
    if not path.exists():
        return
    rows = [r for r in load(path) if r["netem"] == "rtt50"
            and r["conn_mode"] == "warm" and r["cache"] == "hit"
            and r["padding"] == "none"]
    if not rows:
        return
    stages = [c[:-10] for c in rows[0] if c.endswith("_median_ms")]
    keep = [s for s in stages if any(f(r[s + "_median_ms"]) for r in rows)]
    fig, ax = plt.subplots(figsize=(6.5, 3.6))
    cmap = plt.get_cmap("tab20")
    for ri, r in enumerate(rows):
        bottom = 0
        for si, s in enumerate(keep):
            val = f(r[s + "_median_ms"])
            if math.isnan(val) or val <= 0:
                continue
            ax.barh(ri, val, left=bottom, color=cmap(si % 20),
                    label=s if ri == 0 else None)
            bottom += val
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([STYLE.get(r["variant"], (r["variant"],))[0] for r in rows],
                       fontsize=8)
    ax.set_xlabel("Median time (ms)")
    ax.set_title("Per-hop breakdown, 50 ms RTT, warm, hit")
    ax.legend(fontsize=6, ncol=2, bbox_to_anchor=(1.02, 1), loc="upper left")
    save(fig, out, "fig_breakdown")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("campaign_dir", type=Path)
    a = ap.parse_args()
    d = a.campaign_dir
    summ = load(d / "summary.csv")
    queries = load(d / "queries.csv")
    out = d / "figures"
    print(f"figures -> {out}")
    fig_latency_vs_rtt(summ, out)
    fig_variants(summ, out)
    fig_cdf(queries, out, "rtt50", "fig_cdf_rtt50",
            "Latency CDF at 50 ms RTT (warm, hit)")
    fig_cdf_loss_log(queries, out)
    fig_zerortt(summ, out)
    fig_sizes(summ, out)
    fig_breakdown(d / "breakdown.csv", out)


if __name__ == "__main__":
    main()
