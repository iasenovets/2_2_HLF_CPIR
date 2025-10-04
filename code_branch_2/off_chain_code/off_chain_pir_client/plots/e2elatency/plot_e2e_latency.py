#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Plot: End-to-end single-query latency by stage; ct×pt path (IEEE grayscale).
- Reads CSVs from: ./data/e2elatency_<logN>_<record_s>.csv
- Saves figures into: ./figures/
- Generates: stacked latency plot + summary CSV
"""

import argparse
import os
import re
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--indir", default="data", help="input folder with CSVs")
    p.add_argument("--outdir", default="figures", help="output folder for figures and summary")
    p.add_argument("--png_dpi", type=int, default=300, help="PNG resolution")
    return p.parse_args()

# ---------- Constants ----------
FNAME_RE = re.compile(r"e2elatency_(\d+)_(\d+)\.csv$")
STAGE_ORDER = ["keygen_ms", "enc_ms", "eval_ms", "dec_ms"]
STAGE_NAMES = ["KeyGen", "Enc", "Eval", "Dec"]
GRAY_COLORS = ["0.85", "0.65", "0.45", "0.25"]
HATCH_PATTERNS = ["//", "xx", "\\\\", ".."]

# ---------- Helpers ----------
def load_one(path):
    df = pd.read_csv(path)
    if set(df.columns) != {"epoch", "stage", "latency_ms"}:
        raise ValueError(f"Unexpected columns in {path}: {df.columns.tolist()}")
    piv = df.pivot(index="epoch", columns="stage", values="latency_ms")
    if "eval_ms" not in piv.columns and "eval_rtt_ms" in piv.columns:
        piv["eval_ms"] = piv["eval_rtt_ms"]
    for s in STAGE_ORDER:
        if s not in piv.columns:
            piv[s] = np.nan
    return piv[STAGE_ORDER].sort_index()

def ieee_figsize_single_column(aspect=0.7):
    w = 3.5
    return (w, w * aspect)

# ---------- Main ----------
def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    csv_paths = sorted(glob.glob(os.path.join(args.indir, "e2elatency_*.csv")))
    if not csv_paths:
        raise SystemExit(f"No CSVs found in {args.indir}")

    series_list, summary_rows = [], []

    for pth in csv_paths:
        m = FNAME_RE.search(os.path.basename(pth))
        if not m:
            continue
        logN, record_s = int(m.group(1)), int(m.group(2))
        piv = load_one(pth)
        means, stds = piv.mean(skipna=True), piv.std(ddof=1, skipna=True)
        total_mean = float(np.nansum([means.get(s, np.nan) for s in STAGE_ORDER]))
        total_std = float(np.sqrt(np.nansum([stds.get(s, 0.0)**2 for s in STAGE_ORDER])))

        series_list.append({
            "logN": logN, "record_s": record_s,
            "means": means, "stds": stds,
            "total_mean": total_mean, "total_std": total_std
        })
        summary_rows.append({
            "logN": logN, "record_s": record_s,
            **{f"mean_{k}": means.get(k, np.nan) for k in STAGE_ORDER},
            **{f"std_{k}": stds.get(k, np.nan) for k in STAGE_ORDER},
            "total_mean_ms": total_mean, "total_std_ms": total_std,
            "epochs": piv.shape[0],
        })

    series_list.sort(key=lambda d: d["logN"])
    summary_df = pd.DataFrame(summary_rows).sort_values(["logN", "record_s"])
    summary_csv = os.path.join(args.outdir, "e2e_latency_summary.csv")
    summary_df.to_csv(summary_csv, index=False)

        # ---------- Plot ----------
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 9,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
    })

    fig, ax = plt.subplots(figsize=ieee_figsize_single_column())

    x = np.arange(len(series_list))
    width = 0.58
    bottoms = np.zeros_like(x, dtype=float)

    for i, (stage_key, stage_disp) in enumerate(zip(STAGE_ORDER, STAGE_NAMES)):
        vals = np.array([d["means"].get(stage_key, np.nan) for d in series_list], dtype=float)
        ax.bar(
            x, np.nan_to_num(vals, nan=0.0),
            width, bottom=bottoms,
            label=stage_disp,
            color=GRAY_COLORS[i],
            hatch=HATCH_PATTERNS[i],
            edgecolor="black", linewidth=0.5
        )
        bottoms += np.nan_to_num(vals, nan=0.0)

    # X-axis as ring sizes
    xtick_labels = [f"$2^{{{d['logN']}}}$" for d in series_list]
    ax.set_xticks(x)
    ax.set_xticklabels(xtick_labels)
    ax.set_xlabel("Ring size $N$")
    ax.set_ylabel("Latency per query (ms)")
    ax.set_title("End-to-end single-query latency by stage (ct×pt)")
    ax.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.6)

    # --- Fixed Y range for consistency ---
    ax.set_ylim(0, 200)

    # Annotate total means
    for xi, d in zip(x, series_list):
        total = d["total_mean"]
        if not np.isnan(total):
            ax.text(xi, bottoms[xi] + 2, f"{total:.1f}",
                    ha="center", va="bottom", fontsize=7)

    ax.legend(frameon=True, ncol=2, loc="upper left", bbox_to_anchor=(0.0, 1.03))
    fig.tight_layout()


    pdf_path = os.path.join(args.outdir, "e2e_latency_stacked.pdf")
    png_path = os.path.join(args.outdir, "e2e_latency_stacked.png")
    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(png_path, dpi=args.png_dpi, bbox_inches="tight")

    print(f"[OK] Wrote {pdf_path}")
    print(f"[OK] Wrote {png_path}")
    print(f"[OK] Wrote {summary_csv}")

if __name__ == "__main__":
    main()
