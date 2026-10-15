#!/usr/bin/env python3
"""Per-domain bar charts in the style of the earlier paper (hatched, B/W).

  tools/plot_bars.py results/stage2_main_<stamp> [--netem rtt50]

Reads <dir>/queries.csv (written by analyze.py) and writes into <dir>/figures/:

  fig_resolution_bars   (a) warm and (b) cold connections, cache hit, no
                        padding: mean resolution time per domain and protocol,
                        error bars = 95% confidence interval of the mean
  fig_size_bars         (a) request and (b) response size per domain and
                        protocol (median, no padding). ODoH/H3 and ODoH/H2
                        carry identical bodies, so ODoH is shown once.

Sizes are the bytes on the QUIC stream (DoQ, ODoQ) or in the HTTP body (ODoH).
"""

import argparse
import csv
import math
import statistics as st
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

LAT_VARIANTS = [("doq", "DoQ", "///"), ("odoq-persistent", "ODoQ", "xxx"),
                ("odoh-h3", "ODoH/H3", "..."), ("odoh-h2", "ODoH/H2", "---")]
SIZE_VARIANTS = [("doq", "DoQ", "///"), ("odoq-persistent", "ODoQ", "xxx"),
                 ("odoh-h3", "ODoH", "...")]


def load(path):
    with open(path) as fh:
        return list(csv.DictReader(fh))


def ci95(xs):
    if len(xs) < 2:
        return 0.0
    return 1.96 * st.stdev(xs) / math.sqrt(len(xs))


def grouped_bars(ax, domains, series, ylabel, err=None):
    """series: list of (label, hatch, [value per domain]); err same shape."""
    n = len(series)
    w = 0.8 / n
    for i, (label, hatch, vals) in enumerate(series):
        xs = [d + (i - (n - 1) / 2) * w for d in range(len(domains))]
        ax.bar(xs, vals, w, label=label, hatch=hatch, facecolor="white",
               edgecolor="black", linewidth=0.8,
               yerr=err[i] if err else None,
               error_kw={"capsize": 2, "elinewidth": 0.8} if err else None)
    ax.set_xticks(range(len(domains)))
    ax.set_xticklabels(domains, rotation=25, ha="right", fontsize=8)
    ax.set_ylabel(ylabel)
    ax.grid(True, axis="y", alpha=0.3)
    ax.set_axisbelow(True)


def save(fig, out, name):
    out.mkdir(exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(out / f"{name}.{ext}", bbox_inches="tight", dpi=200)
    plt.close(fig)
    print(f"  {name}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("campaign_dir", type=Path)
    ap.add_argument("--netem", default="rtt50")
    a = ap.parse_args()
    rows = [r for r in load(a.campaign_dir / "queries.csv")
            if r["ok"] == "True" and r["cache"] == "hit" and r["padding"] == "none"]
    out = a.campaign_dir / "figures"
    print(f"figures -> {out}")

    # ---------------- resolution time, warm + cold ----------------
    lat = defaultdict(list)
    for r in rows:
        if r["netem"] == a.netem:
            lat[(r["conn_mode"], r["variant"], r["qname"])].append(float(r["latency_ms"]))
    domains = sorted({k[2] for k in lat})
    variants = [v for v in LAT_VARIANTS if any(k[1] == v[0] for k in lat)]
    if domains and variants:
        fig, axes = plt.subplots(2, 1, figsize=(7.2, 5.6), sharex=True)
        for ax, mode, tag in zip(axes, ("warm", "cold"), ("(a)", "(b)")):
            series, errs = [], []
            for v, label, hatch in variants:
                xs = [lat.get((mode, v, d), []) for d in domains]
                series.append((label, hatch, [st.fmean(x) if x else math.nan for x in xs]))
                errs.append([ci95(x) for x in xs])
            grouped_bars(ax, domains, series, "Resolution time (ms)", errs)
            ax.set_title(f"{tag} {mode.capitalize()} connections", fontsize=9, loc="left")
        axes[0].legend(fontsize=8, ncol=len(variants), loc="upper center",
                       bbox_to_anchor=(0.5, 1.28), frameon=False)
        save(fig, out, "fig_resolution_bars")
        print("    per-domain n:", sorted({len(x) for x in lat.values()}))

    # ---------------- request / response sizes ----------------
    req, resp = defaultdict(list), defaultdict(list)
    for r in rows:
        if r["conn_mode"] == "warm":
            req[(r["variant"], r["qname"])].append(float(r["req_stream_bytes"]))
            resp[(r["variant"], r["qname"])].append(float(r["resp_stream_bytes"]))
    domains = sorted({k[1] for k in req})
    variants = [v for v in SIZE_VARIANTS if any(k[0] == v[0] for k in req)]
    if domains and variants:
        fig, axes = plt.subplots(2, 1, figsize=(7.2, 5.6), sharex=True)
        for ax, data, tag in zip(axes, (req, resp), ("(a) Request", "(b) Response")):
            series = [(label, hatch, [st.median(data[(v, d)]) if data.get((v, d)) else math.nan
                                      for d in domains]) for v, label, hatch in variants]
            grouped_bars(ax, domains, series, "Message size (bytes)")
            ax.set_title(f"{tag} sizes", fontsize=9, loc="left")
        axes[0].legend(fontsize=8, ncol=len(variants), loc="upper center",
                       bbox_to_anchor=(0.5, 1.28), frameon=False)
        save(fig, out, "fig_size_bars")


if __name__ == "__main__":
    main()
