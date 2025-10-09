#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import glob
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Order & display names (now using PIRQuery)
# tuple: (Legend Label, (subfolder, [possible csv filenames in order of preference]))
FUNCS = [
    ("InitLedger",  ("initLedger",  ["InitLedger_server_timing.csv"])),
    ("GetMetadata", ("getMetadata", ["GetMetadata_server_timing.csv"])),
    ("PIRQuery",    ("pirQuery",    ["PIRQuery_server_timing.csv", "PIRQueryAuto_server_timing.csv"])),
]

# Greys + hatching for clarity when printed in B/W
GRAY = ["0.25", "0.55", "0.75"]
HATCH = ["", "//", "xx"]

def figsize_ieee_single(aspect=0.75):
    w = 3.5
    return (w, w*aspect)

def avg_exec_time(csv_path: str) -> float:
    if not os.path.exists(csv_path):
        return np.nan
    try:
        df = pd.read_csv(csv_path)
    except Exception:
        return np.nan
    # find the execution_time_ms column (case/whitespace tolerant)
    col = None
    for c in df.columns:
        if c.strip().lower() == "execution_time_ms":
            col = c
            break
    if col is None:
        return np.nan
    s = pd.to_numeric(df[col], errors="coerce").dropna()
    return float(s.mean()) if not s.empty else np.nan

def avg_exec_time_first_existing(basedir: str, candidates: list[str]) -> float:
    for fname in candidates:
        path = os.path.join(basedir, fname)
        if os.path.exists(path):
            val = avg_exec_time(path)
            if not np.isnan(val):
                return val
    return np.nan

def find_channel_dirs(root: str):
    chans = []
    for path in glob.glob(os.path.join(root, "*_*_*")):
        if not os.path.isdir(path):
            continue
        base = os.path.basename(path.rstrip("/\\"))
        parts = base.split("_")
        if len(parts) != 3:
            continue
        try:
            logN, n, rec = map(int, parts)
        except ValueError:
            continue
        chans.append((base, path, logN, n, rec))
    return sorted(chans, key=lambda t: t[2])  # sort by logN

def collect_rows(root: str):
    rows = []
    for chan, path, logN, n, rec in find_channel_dirs(root):
        vals = {"channel": chan, "logN": logN, "n": n, "record_s": rec}
        for label, (sub, fnames) in FUNCS:
            subdir = None
            for entry in os.listdir(path):
                if entry.lower() == sub.lower():
                    subdir = os.path.join(path, entry)
                    break
            if not subdir:
                vals[label] = np.nan
                continue
            vals[label] = avg_exec_time_first_existing(subdir, fnames)
        rows.append(vals)
    return pd.DataFrame(rows)

def make_plot(df: pd.DataFrame, figdir: str, dpi: int):
    if df.empty:
        raise SystemExit("No timing data found.")
    # Label map from numeric folder to friendly names
    label_map = {
        "13_64_128": "mini",
        "14_73_224": "mid",
        "15_128_256": "rich"
    }
    df["friendly"] = df["channel"].map(label_map).fillna(df["channel"])
    funcs = [f[0] for f in FUNCS]  # ["InitLedger","GetMetadata","PIRQuery"]
    xlabels = df["friendly"].tolist()
    x = np.arange(len(xlabels))
    width = 0.25

    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 9,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
    })

    fig, ax = plt.subplots(figsize=figsize_ieee_single(0.8))

    for i, func in enumerate(funcs):
        y = df[func].to_numpy(dtype=float)
        ax.bar(x + (i - (len(funcs)-1)/2)*width,
               y, width,
               color=GRAY[i % len(GRAY)],
               hatch=HATCH[i % len(HATCH)],
               edgecolor="black", linewidth=0.5,
               label=func)

    ax.set_xticks(x)
    ax.set_xticklabels(xlabels)
    ax.set_xlabel("Channel (mini, mid, rich)")
    ax.set_ylabel("Execution time (ms)")
    ax.set_title("Execution time of chaincode functions per channel (server-side avg)")
    ax.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.6)
    ax.legend(ncol=1, frameon=True, loc="upper left", bbox_to_anchor=(0.0, 1.02))
    fig.tight_layout()

    os.makedirs(figdir, exist_ok=True)
    fig.savefig(os.path.join(figdir, "chaincode_timings_bw.pdf"), bbox_inches="tight")
    fig.savefig(os.path.join(figdir, "chaincode_timings_bw.png"), dpi=dpi, bbox_inches="tight")
    print(f"[OK] Wrote greyscale plot to", figdir)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="folder containing channel folders")
    ap.add_argument("--figdir", default="figures", help="output folder for figures")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    df = collect_rows(args.root)
    os.makedirs(args.figdir, exist_ok=True)
    df.to_csv(os.path.join(args.figdir, "chaincode_timings_summary.csv"), index=False)
    make_plot(df, args.figdir, args.dpi)

if __name__ == "__main__":
    main()
