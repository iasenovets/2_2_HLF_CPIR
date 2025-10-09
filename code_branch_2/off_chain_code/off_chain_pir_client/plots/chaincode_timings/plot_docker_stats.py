#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import glob
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# ======= Config =======
# channels → friendly labels
CHANNEL_LABELS = {
    "13_64_128": "mini",
    "14_73_224": "mid",
    "15_128_256": "rich",
}

# Where to look under each channel dir
# (folder name on disk, legend label)
SUBSETS = [
    ("initLedger",  "InitLedger"),
    ("getMetadata", "GetMetadata"),
    ("pirQuery",    "PIRQuery"),
]

# Greys + hatching (B/W friendly), one per function in the order above
GRAY  = ["0.25", "0.55", "0.75"]
HATCH = ["",      "//",   "xx"]

def figsize_ieee_single(aspect=0.75):
    w = 3.5
    return (w, w*aspect)

# ======= parsing helpers =======
_UNITS = {
    "b": 1, "kb": 1_000, "mb": 1_000_000, "gb": 1_000_000_000, "tb": 1_000_000_000_000,
    "kib": 1024, "mib": 1024**2, "gib": 1024**3, "tib": 1024**4,
}

def _to_bytes(token: str) -> float:
    s = token.strip()
    m = re.match(r"^\s*([0-9]*\.?[0-9]+)\s*([A-Za-z]+)\s*$", s)
    if not m:
        try: return float(s)
        except Exception: return np.nan
    val = float(m.group(1))
    unit = m.group(2).lower()
    unit = {"kb":"kb", "mb":"mb", "gb":"gb", "b":"b"}.get(unit, unit)
    factor = _UNITS.get(unit)
    if factor is None:
        unit2 = unit.rstrip("b")
        factor = _UNITS.get(unit2 + "b", 1)
    return val * factor

def _parse_pair_bytes(field: str):
    if not isinstance(field, str) or "/" not in field:
        return (np.nan, np.nan)
    a, b = field.split("/", 1)
    return _to_bytes(a), _to_bytes(b)

def _pct(s: str) -> float:
    try: return float(str(s).strip().rstrip("%"))
    except Exception: return np.nan

def _normalize_df(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out.rename(columns={c: c.strip() for c in out.columns}, inplace=True)
    needed = ["epoch", "CONTAINER", "CPU %", "MEM USAGE / LIMIT", "MEM %", "NET I/O", "BLOCK I/O"]
    missing = [c for c in needed if c not in out.columns]
    if missing:
        raise ValueError(f"Missing columns in docker_stats.csv: {missing}")

    out["epoch"]   = pd.to_numeric(out["epoch"], errors="coerce")
    out["CPU_pct"] = out["CPU %"].map(_pct)
    out["MEM_pct"] = out["MEM %"].map(_pct)

    u_l = out["MEM USAGE / LIMIT"].astype(str).map(_parse_pair_bytes)
    out["MEM_usage_B"] = u_l.map(lambda x: x[0])
    out["MEM_limit_B"] = u_l.map(lambda x: x[1])

    net = out["NET I/O"].astype(str).map(_parse_pair_bytes)
    out["NET_in_B_snap"]  = net.map(lambda x: x[0])
    out["NET_out_B_snap"] = net.map(lambda x: x[1])

    blk = out["BLOCK I/O"].astype(str).map(_parse_pair_bytes)
    out["BLK_in_B_snap"]  = blk.map(lambda x: x[0])
    out["BLK_out_B_snap"] = blk.map(lambda x: x[1])

    return out[[
        "epoch","CONTAINER","CPU_pct","MEM_pct",
        "MEM_usage_B","MEM_limit_B",
        "NET_in_B_snap","NET_out_B_snap",
        "BLK_in_B_snap","BLK_out_B_snap"
    ]].dropna(subset=["epoch","CONTAINER"])

def _deltas_by_container_subset(df_norm: pd.DataFrame) -> pd.DataFrame:
    """
    Convert cumulative NET/BLOCK snapshots to per-epoch deltas
    keeping groups by (CONTAINER, subset).
    """
    frames = []
    for (cont, subset), g in df_norm.groupby(["CONTAINER", "subset"], sort=False):
        g = g.sort_values("epoch").copy()
        for col in ["NET_in_B_snap","NET_out_B_snap","BLK_in_B_snap","BLK_out_B_snap"]:
            g[col.replace("_snap","_delta")] = g[col].diff()
        frames.append(g)
    out = pd.concat(frames, ignore_index=True)
    for col in ["NET_in_B_delta","NET_out_B_delta","BLK_in_B_delta","BLK_out_B_delta"]:
        out[col] = out[col].where(out[col] >= 0, np.nan)
    # drop first rows per (container, subset) where deltas NaN
    out = out.dropna(subset=["NET_in_B_delta","NET_out_B_delta","BLK_in_B_delta","BLK_out_B_delta"], how="all")
    return out

# ======= data collection =======
def find_channel_dirs(root: str):
    chans = []
    for path in glob.glob(os.path.join(root, "*_*_*")):
        if not os.path.isdir(path): continue
        base = os.path.basename(path.rstrip("/\\"))
        parts = base.split("_")
        if len(parts) != 3: continue
        try:
            logN, n, rec = map(int, parts)
        except ValueError:
            continue
        chans.append((base, path, logN))
    return sorted(chans, key=lambda t: t[2])

def load_all_stats_for_channel(chan_path: str) -> pd.DataFrame:
    frames = []
    for subdir, label in SUBSETS:
        csv_path = os.path.join(chan_path, subdir, "docker_stats.csv")
        if not os.path.exists(csv_path):
            continue
        try:
            raw = pd.read_csv(csv_path)
            norm = _normalize_df(raw)
            norm["subset"] = label  # store the function name
            frames.append(norm)
        except Exception:
            continue
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)

def summarize_peer0_by_function(chan_name: str, chan_path: str) -> pd.DataFrame:
    """
    Return per-function summary for peer0 only:
      CPU_pct_mean, MEM_pct_mean, NET_KB_delta_mean (in+out), BLK_KB_delta_mean (in+out).
    """
    df = load_all_stats_for_channel(chan_path)
    if df.empty:
        return pd.DataFrame()

    # filter to peer0 only (case-insensitive contains 'peer0')
    df = df[df["CONTAINER"].str.contains("peer0", case=False, na=False)].copy()
    if df.empty:
        return pd.DataFrame()

    df_d = _deltas_by_container_subset(df)

    # CPU/MEM means per function
    cpu_mem = (
        df.groupby("subset", as_index=False)
          .agg(CPU_pct=("CPU_pct","mean"),
               MEM_pct=("MEM_pct","mean"))
    )

    # I/O deltas per function: average of (in+out) deltas / 1024
    if not df_d.empty:
        # join in/out by index to avoid group alignment headaches
        df_d = df_d.copy()
        df_d["NET_sum"] = df_d["NET_in_B_delta"].fillna(0) + df_d["NET_out_B_delta"].fillna(0)
        df_d["BLK_sum"] = df_d["BLK_in_B_delta"].fillna(0) + df_d["BLK_out_B_delta"].fillna(0)
        io = (
            df_d.groupby("subset", as_index=False)
                .agg(NET_KB=("NET_sum", lambda s: float(s.mean())/1024.0 if len(s) else np.nan),
                     BLK_KB=("BLK_sum", lambda s: float(s.mean())/1024.0 if len(s) else np.nan))
        )
    else:
        io = pd.DataFrame({"subset": cpu_mem["subset"].values, "NET_KB": np.nan, "BLK_KB": np.nan})

    out = pd.merge(cpu_mem, io, on="subset", how="outer")
    out["channel"]  = chan_name
    out["friendly"] = CHANNEL_LABELS.get(chan_name, chan_name)
    out["CONTAINER"] = "peer0"
    return out[["channel","friendly","subset","CONTAINER","CPU_pct","MEM_pct","NET_KB","BLK_KB"]]

# ======= plotting =======
def _bar_funcs_peer(ax, df, metric, title, ylabel):
    """
    x = channel (mini/mid/rich), bars = functions (InitLedger, GetMetadata, PIRQuery),
    data = peer0 only.
    """
    channels = df["friendly"].unique().tolist()
    funcs = [lbl for (_, lbl) in SUBSETS]  # ordered: InitLedger, GetMetadata, PIRQuery

    # build matrix [len(funcs) x len(channels)]
    mat = np.full((len(funcs), len(channels)), np.nan, dtype=float)
    for j, ch in enumerate(channels):
        sub = df[df["friendly"] == ch]
        for i, f in enumerate(funcs):
            v = sub.loc[sub["subset"] == f, metric]
            mat[i, j] = float(v.iloc[0]) if not v.empty else np.nan

    x = np.arange(len(channels))
    width = 0.22

    for i, f in enumerate(funcs):
        ax.bar(x + (i - (len(funcs)-1)/2) * width,
               mat[i, :], width,
               color=GRAY[i % len(GRAY)],
               hatch=HATCH[i % len(HATCH)],
               edgecolor="black", linewidth=0.5,
               label=f)

    ax.set_xticks(x)
    ax.set_xticklabels(channels)
    ax.set_xlabel("Channel (mini, mid, rich)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.6)
    ax.legend(ncol=1, frameon=True, loc="upper left", bbox_to_anchor=(0.0, 1.02))

def make_plots_peer_funcs(summary: pd.DataFrame, figdir: str, dpi: int):
    if summary.empty:
        raise SystemExit("No docker_stats parsed for peer0. Check folder structure and CSVs.")

    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 9,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
    })

    os.makedirs(figdir, exist_ok=True)

    # CPU%
    fig1, ax1 = plt.subplots(figsize=figsize_ieee_single(0.80))
    _bar_funcs_peer(ax1, summary, "CPU_pct", "peer0 CPU usage by function/channel (avg)", "CPU (%)")
    fig1.tight_layout()
    fig1.savefig(os.path.join(figdir, "peer0_cpu_by_func_bw.pdf"), bbox_inches="tight")
    fig1.savefig(os.path.join(figdir, "peer0_cpu_by_func_bw.png"), dpi=dpi, bbox_inches="tight")

    # MEM%
    fig2, ax2 = plt.subplots(figsize=figsize_ieee_single(0.80))
    _bar_funcs_peer(ax2, summary, "MEM_pct", "peer0 Memory usage by function/channel (avg)", "Memory (%)")
    fig2.tight_layout()
    fig2.savefig(os.path.join(figdir, "peer0_mem_by_func_bw.pdf"), bbox_inches="tight")
    fig2.savefig(os.path.join(figdir, "peer0_mem_by_func_bw.png"), dpi=dpi, bbox_inches="tight")

    # NET delta (KB/epoch)
    fig3, ax3 = plt.subplots(figsize=figsize_ieee_single(0.80))
    _bar_funcs_peer(ax3, summary, "NET_KB", "peer0 Network I/O per epoch (avg delta)", "KB / epoch")
    fig3.tight_layout()
    fig3.savefig(os.path.join(figdir, "peer0_net_by_func_bw.pdf"), bbox_inches="tight")
    fig3.savefig(os.path.join(figdir, "peer0_net_by_func_bw.png"), dpi=dpi, bbox_inches="tight")

    # BLK delta (KB/epoch)
    fig4, ax4 = plt.subplots(figsize=figsize_ieee_single(0.80))
    _bar_funcs_peer(ax4, summary, "BLK_KB", "peer0 Block I/O per epoch (avg delta)", "KB / epoch")
    fig4.tight_layout()
    fig4.savefig(os.path.join(figdir, "peer0_blk_by_func_bw.pdf"), bbox_inches="tight")
    fig4.savefig(os.path.join(figdir, "peer0_blk_by_func_bw.png"), dpi=dpi, bbox_inches="tight")

    print(f"[OK] Wrote plots to {figdir}")

# ======= main =======
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="folder with channel dirs (e.g., 13_64_128/)")
    ap.add_argument("--figdir", default="plots/docker_stats/figures", help="output dir for figures & summary")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    rows = []
    for chan_name, chan_path, _logN in find_channel_dirs(args.root):
        s = summarize_peer0_by_function(chan_name, chan_path)
        if not s.empty:
            rows.append(s)

    if not rows:
        raise SystemExit(f"No docker_stats.csv (peer0) found under {args.root}")

    summary = pd.concat(rows, ignore_index=True)
    summary["friendly"] = summary["channel"].map(CHANNEL_LABELS).fillna(summary["channel"])

    os.makedirs(args.figdir, exist_ok=True)
    out_csv = os.path.join(args.figdir, "docker_stats_peer0_by_function_summary.csv")
    summary.to_csv(out_csv, index=False)
    print(f"[OK] Wrote {out_csv}")

    make_plots_peer_funcs(summary, args.figdir, args.dpi)

if __name__ == "__main__":
    main()
