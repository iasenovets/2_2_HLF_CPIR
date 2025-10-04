#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Artifacts size comparison (per ring).
- Input : ./plots/artifacts_size/data/artifacts_<logN>_<record_s>.csv
- Output: ./plots/artifacts_size/figures/artifacts_sizes.pdf/.png
- Also  : ./plots/artifacts_size/figures/artifacts_sizes_summary.csv

Bars (gray/hatch, IEEE single-column):
  pk, sk, ct_q, ct_r, m_DB, metadata_json
X-axis: ring size N = 2^{logN}
"""

import os, re, glob, argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

FRE = re.compile(r"artifacts_(\d+)_(\d+)\.csv$")  # logN, record_s
ARTS = ["pk", "sk", "ct_q", "ct_r", "m_DB", "metadata_json"]

GRAY = ["0.20", "0.35", "0.50", "0.65", "0.80", "0.90"]
HATCH = ["", "//", "xx", "++", "..", "\\\\"]

def figsize_ieee_single(aspect=0.75):
    w = 3.5  # inches
    return (w, w*aspect)

def load_one(path):
    df = pd.read_csv(path)
    if set(df.columns) != {"artifact", "bytes"}:
        raise ValueError(f"bad columns in {path}: {df.columns.tolist()}")
    out = {}
    for a in ARTS:
        v = df.loc[df["artifact"] == a, "bytes"]
        out[a] = int(v.iloc[0]) if not v.empty else np.nan
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="plots/artifacts_size/data", help="input CSV folder")
    ap.add_argument("--figdir", default="plots/artifacts_size/figures", help="figures output folder")
    ap.add_argument("--dpi", type=int, default=300)
    ap.add_argument("--unit", choices=["bytes","KB","MB"], default="KB")
    args = ap.parse_args()

    os.makedirs(args.figdir, exist_ok=True)

    paths = sorted(glob.glob(os.path.join(args.data, "artifacts_*.csv")))
    if not paths:
        raise SystemExit(f"No CSVs found in {args.data}")

    rows = []
    for p in paths:
        m = FRE.search(os.path.basename(p))
        if not m:
            continue
        logN = int(m.group(1))
        record_s = int(m.group(2))
        vals = load_one(p)
        vals.update({"logN": logN, "record_s": record_s})
        rows.append(vals)

    df = pd.DataFrame(rows).sort_values(["logN", "record_s"])

    # unit scale
    scale = {"bytes":1.0, "KB":1/1024.0, "MB":1/(1024.0*1024.0)}[args.unit]
    df_plot = df.copy()
    for a in ARTS:
        df_plot[a] = df_plot[a] * scale

    # aggregate by logN (mean over record_s if multiple)
    grp = df_plot.groupby("logN")[ARTS].mean().reset_index()
    labels = [rf"$2^{{{int(x)}}}$" for x in grp["logN"].tolist()]
    x = np.arange(len(grp))
    width = 0.12

    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 9,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
    })

    fig, ax = plt.subplots(figsize=figsize_ieee_single(0.80))

    # grouped bars
    for i, art in enumerate(ARTS):
        vals = grp[art].to_numpy(dtype=float)
        ax.bar(x + (i-2.5)*width, vals, width,
               color=GRAY[i % len(GRAY)],
               hatch=HATCH[i % len(HATCH)],
               edgecolor="black", linewidth=0.5,
               label=art)

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_xlabel(r"Ring size $N$")
    ax.set_ylabel(f"Size ({args.unit})")
    ax.set_title("Artifacts size by ring configuration")
    ax.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.6)

    # tight legend
    ax.legend(ncol=2, frameon=True, loc="upper left", bbox_to_anchor=(0.0, 1.03))

    fig.tight_layout()

    out_pdf = os.path.join(args.figdir, "artifacts_sizes.pdf")
    out_png = os.path.join(args.figdir, "artifacts_sizes.png")
    fig.savefig(out_pdf, bbox_inches="tight")
    fig.savefig(out_png, dpi=args.dpi, bbox_inches="tight")

    # summary CSV
    sum_csv = os.path.join(args.figdir, "artifacts_sizes_summary.csv")
    grp.to_csv(sum_csv, index=False)

    print(f"[OK] Wrote {out_pdf}")
    print(f"[OK] Wrote {out_png}")
    print(f"[OK] Wrote {sum_csv}")

if __name__ == "__main__":
    main()
