#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Plot: Block size vs World-state (LevelDB) size per ring configuration/channel.

Input is embedded below (from your notes):
- Channels: 13_64_128, 14_73_224, 14_128_256
- For each: block size (KB), state LevelDB size (KB),
            plus some per-key GetState sizes (kept for the summary CSV).

Output:
  figures/block_vs_worldstate_bw.pdf/.png
  figures/block_vs_worldstate_summary.csv
"""

import os
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# --- raw data (from the message) --------------------------------------

DATA = [
    {
        "channel": "13_64_128",
        "friendly": "mini",
        "logN": 13,
        # per-key GetState sizes (bytes) — included for summary/reference
        "m_DB_B": 65838,
        "bgv_params_B": 56,
        "n_B": 2,
        "record_s_B": 3,
        "record_013_B": 126,
        # aggregate sizes
        "block_KB": 77,     # block size containing init writes (approx)
        "stateLevelDB_KB": 112,  # du -h --max-depth=1 (approx)
        "init_txid": "00220f4d5125a6f38bcfbcefae6b95ce7747869ec57fbc0cf6092e22149eba78",
    },
    {
        "channel": "14_73_224",
        "friendly": "mid",
        "logN": 14,
        "m_DB_B": 131374,
        "bgv_params_B": 57,
        "n_B": 2,
        "record_s_B": 3,
        "record_013_B": 222,
        "block_KB": 149,
        "stateLevelDB_KB": 184,
        "init_txid": "197c444dd6658f65ae0f14073a42e509ade0916f25007392334711ed9d713ae6",
    },
    {
        "channel": "15_128_256", 
        "friendly": "rich",
        "logN": 15,
        "m_DB_B": 262446,
        "bgv_params_B": 57,
        "n_B": 3,
        "record_s_B": 3,
        "record_013_B": 254,
        "block_KB": 294,
        "stateLevelDB_KB": 332,
        "init_txid": "9ce13ee1a7fb1fa7fc029ee8e0fe7790a8354e05d6df2cfb4e01df6fbf10dcf6",
    },
]

# --- styling -----------------------------------------------------------

def figsize_ieee_single(aspect=0.75):
    w = 3.5
    return (w, w * aspect)

GRAY = ["0.25", "0.65"]     # two greys for two bars
HATCH = ["", "//"]          # distinct hatches for B/W print

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 8,
    "axes.labelsize": 8,
    "axes.titlesize": 9,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "legend.fontsize": 7,
})

# --- core --------------------------------------------------------------

def build_dataframe():
    df = pd.DataFrame(DATA)
    # Keep a tidy set of columns for summary
    cols = [
        "channel", "friendly", "logN",
        "block_KB", "stateLevelDB_KB",
        "m_DB_B", "bgv_params_B", "n_B", "record_s_B", "record_013_B",
        "init_txid",
    ]
    return df[cols].copy()

def plot_block_vs_state(df, figdir, dpi):
    # x-axis: friendly label (mini, mid, rich)
    order = ["mini", "mid", "rich"]
    df = df.set_index("friendly").loc[[x for x in order if x in df["friendly"].values]]
    xlabels = df.index.tolist()
    x = np.arange(len(xlabels))
    width = 0.35

    fig, ax = plt.subplots(figsize=figsize_ieee_single(0.80))

    ax.bar(x - width/2, df["block_KB"].to_numpy(dtype=float), width,
           color=GRAY[0], hatch=HATCH[0], edgecolor="black", linewidth=0.5,
           label="Block size (KB)")
    ax.bar(x + width/2, df["stateLevelDB_KB"].to_numpy(dtype=float), width,
           color=GRAY[1], hatch=HATCH[1], edgecolor="black", linewidth=0.5,
           label="World state LevelDB (KB)")

    ax.set_xticks(x)
    ax.set_xticklabels(xlabels)
    ax.set_xlabel("Channel (mini, mid, rich)")
    ax.set_ylabel("Size (KB)")
    ax.set_title("Block vs. World-state size by channel")
    ax.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.6)
    ax.legend(frameon=True, loc="upper left", bbox_to_anchor=(0.0, 1.02), ncol=1)

    fig.tight_layout()
    os.makedirs(figdir, exist_ok=True)
    fig.savefig(os.path.join(figdir, "block_vs_worldstate_bw.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(figdir, "block_vs_worldstate_bw.png"), dpi=dpi, bbox_inches="tight")
    print(f"[OK] Wrote: {os.path.join(figdir, 'block_vs_worldstate_bw.pdf')}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--figdir", default="plots/block_vs_worldstate/figures", help="output folder for figures/summary")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    df = build_dataframe()

    # write summary CSV (also includes the per-key GetState sizes you listed)
    os.makedirs(args.figdir, exist_ok=True)
    sum_csv = os.path.join(args.figdir, "block_vs_worldstate_summary.csv")
    df.to_csv(sum_csv, index=False)
    print(f"[OK] Wrote: {sum_csv}")

    plot_block_vs_state(df, args.figdir, args.dpi)

if __name__ == "__main__":
    main()
