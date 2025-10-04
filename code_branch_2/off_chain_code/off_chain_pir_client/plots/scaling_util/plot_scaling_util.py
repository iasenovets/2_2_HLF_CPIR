#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utilization stacked bars (IEEE, grayscale)

Reads : ./data/scaling_util.csv  (columns: logN,target_record_s,actual_record_s,n,N,utilization)
Writes: ./figures/scaling_util_utilization_stacked.pdf / .png
Bar per ring size (2^13, 2^14, 2^15) stacked: [utilized, unused].
"""

import os
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

def ieee_figsize_single_column(aspect=0.70):
    w = 3.5  # inches
    return (w, w*aspect)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--indir", default="data", help="input folder")
    p.add_argument("--outdir", default="figures", help="output folder")
    p.add_argument("--png_dpi", type=int, default=300)
    p.add_argument("--aggregate", choices=["mean","median"], default="mean",
                   help="aggregation across record_s per logN")
    args = p.parse_args()

    os.makedirs(args.indir, exist_ok=True)
    os.makedirs(args.outdir, exist_ok=True)

    csv_path = os.path.join(args.indir, "scaling_util.csv")
    if not os.path.exists(csv_path):
        raise SystemExit(f"missing input: {csv_path}")

    df = pd.read_csv(csv_path)

    # Aggregate utilization per ring size
    agg = df.groupby("logN")["utilization"]
    if args.aggregate == "mean":
        by_ring = agg.mean()
    else:
        by_ring = agg.median()

    # Prepare bar data
    rings = [13,14,15]
    utilized = np.array([by_ring.get(r, np.nan) for r in rings], dtype=float)
    unused   = 1.0 - utilized

    # Style (IEEE grayscale)
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 9,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
    })

    fig, ax = plt.subplots(figsize=ieee_figsize_single_column(aspect=0.75))

    x = np.arange(len(rings))
    width = 0.55

    # Colors (gray shades), hatches for clarity if printed
    col_util = "0.30"
    col_free = "0.75"
    bars1 = ax.bar(x, utilized, width, color=col_util, edgecolor="black", linewidth=0.6,
                   label="Utilized", hatch="")
    bars2 = ax.bar(x, unused, width, bottom=utilized, color=col_free, edgecolor="black",
                   linewidth=0.6, label="Unused", hatch="//")

    # X labels as ring size
    xticklabels = [r"$2^{%d}$" % L for L in rings]
    ax.set_xticks(x)
    ax.set_xticklabels(xticklabels)
    ax.set_xlabel(r"Ring size $N$")
    ax.set_ylabel(r"Fraction of slots")
    ax.set_title("Allocated-slot utilization by ring (stacked)")

    ax.set_ylim(0.0, 1.05)
    ax.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.6)
    ax.legend(frameon=True, loc="upper right", ncol=1)

    # Annotate percentages on each segment
    for xi, u in enumerate(utilized):
        if np.isnan(u):
            continue
        # utilized label
        ax.text(xi, u/2, f"{100*u:.1f}%", ha="center", va="center", color="white", fontsize=7)
        # unused label
        rem = 1.0 - u
        if rem > 0.03:
            ax.text(xi, u + rem/2, f"{100*rem:.1f}%", ha="center", va="center", color="black", fontsize=7)

    fig.tight_layout()
    pdf_path = os.path.join(args.outdir, "scaling_util_utilization_stacked.pdf")
    png_path = os.path.join(args.outdir, "scaling_util_utilization_stacked.png")
    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(png_path, dpi=args.png_dpi, bbox_inches="tight")
    print(f"[OK] wrote {pdf_path}\n[OK] wrote {png_path}")

if __name__ == "__main__":
    main()
