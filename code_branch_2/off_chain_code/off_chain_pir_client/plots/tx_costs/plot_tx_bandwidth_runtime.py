#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

GRAY = ["0.25", "0.55", "0.75"]
HATCH = ["", "//", "xx"]
COUNTS = [100, 1000, 10000]

LABELS = {
    "13_64_128": "mini",
    "14_73_224": "mid",
    "15_128_256": "rich",
}

def figsize_ieee_double(aspect=0.35):
    w = 7.2  # IEEE double-column width in inches
    return (w, w * aspect)

def load_net(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df = df.copy()
    df["friendly"] = df.get("friendly", pd.Series(dtype=str))
    if "friendly" not in df.columns or df["friendly"].isna().all():
        df["friendly"] = df["channel"].map(LABELS).fillna(df["channel"])
    df = df[(df["CONTAINER"].str.contains("peer", case=False, na=False)) &
            (df["subset"].str.lower() == "pirquery")]
    out = df[["channel", "friendly", "NET_KB"]].groupby(["channel", "friendly"], as_index=False).mean()
    return out

def load_time(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    if "channel" not in df.columns:
        raise SystemExit(f"timings CSV missing 'channel': {csv_path}")
    cols = {c: c.strip() for c in df.columns}
    df.rename(columns=cols, inplace=True)
    pir_col = None
    for c in df.columns:
        if c.strip().lower() == "pirquery":
            pir_col = c
            break
    if pir_col is None:
        raise SystemExit("timings CSV must contain a 'PIRQuery' column (ms).")
    df["friendly"] = df["channel"].map(LABELS).fillna(df["channel"])
    return df[["channel", "friendly", pir_col]].rename(columns={pir_col: "PIR_ms"})

def compute_projection(net_df: pd.DataFrame, time_df: pd.DataFrame) -> pd.DataFrame:
    m = pd.merge(net_df, time_df, on=["channel", "friendly"], how="inner")
    # Convert KB → MB (decimal)
    m["MB_per_tx"] = m["NET_KB"] / 1000.0
    # PIR ms → minutes per tx
    m["min_per_tx"] = (m["PIR_ms"] / 1000.0) / 60.0

    rows = []
    for _, row in m.iterrows():
        for count in COUNTS:
            rows.append({
                "channel": row["channel"],
                "friendly": row["friendly"],
                "tx_count": count,
                "bandwidth_MB": row["MB_per_tx"] * count,
                "runtime_min": row["min_per_tx"] * count,
                "MB_per_tx": row["MB_per_tx"],
                "ms_per_tx": row["PIR_ms"],
            })
    return pd.DataFrame(rows)

def plot_plate(df_proj: pd.DataFrame, figdir: str, dpi: int):
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

    ch_order = ["mini", "mid", "rich"]
    df_proj["friendly"] = pd.Categorical(df_proj["friendly"], categories=ch_order, ordered=True)
    df_proj.sort_values(["friendly", "tx_count"], inplace=True)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=figsize_ieee_double(0.40))
    x = np.arange(len(COUNTS))
    width = 0.24

    # Panel A: bandwidth (MB)
    for i, ch in enumerate(ch_order):
        sub = df_proj[df_proj["friendly"] == ch]
        y = [sub[sub["tx_count"] == c]["bandwidth_MB"].mean() for c in COUNTS]
        ax1.bar(x + (i - 1) * width, y, width,
                color=GRAY[i % len(GRAY)],
                hatch=HATCH[i % len(HATCH)],
                edgecolor="black", linewidth=0.5,
                label=ch)
    ax1.set_xticks(x)
    ax1.set_xticklabels([str(c) for c in COUNTS])
    ax1.set_xlabel("Transactions")
    ax1.set_ylabel("Total bandwidth (MB)")
    ax1.set_title("Peer NET I/O for batched PIRQuery")
    ax1.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.6)
    ax1.legend(ncol=1, frameon=True, loc="upper left", bbox_to_anchor=(0.0, 1.02))

    # Panel B: runtime (minutes)
    for i, ch in enumerate(ch_order):
        sub = df_proj[df_proj["friendly"] == ch]
        y = [sub[sub["tx_count"] == c]["runtime_min"].mean() for c in COUNTS]
        ax2.bar(x + (i - 1) * width, y, width,
                color=GRAY[i % len(GRAY)],
                hatch=HATCH[i % len(HATCH)],
                edgecolor="black", linewidth=0.5)
    ax2.set_xticks(x)
    ax2.set_xticklabels([str(c) for c in COUNTS])
    ax2.set_xlabel("Transactions")
    ax2.set_ylabel("Total chaincode time (min)")
    ax2.set_title("Server-side PIRQuery time for batches")
    ax2.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.6)

    fig.tight_layout()
    out_pdf = os.path.join(figdir, "pirquery_batch_cost_bw.pdf")
    out_png = os.path.join(figdir, "pirquery_batch_cost_bw.png")
    fig.savefig(out_pdf, bbox_inches="tight")
    fig.savefig(out_png, dpi=dpi, bbox_inches="tight")
    print(f"[OK] Wrote {out_pdf}")
    print(f"[OK] Wrote {out_png}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--netcsv", required=True, help="docker stats summary CSV with NET_KB (peer0, PIRQuery)")
    ap.add_argument("--timings", required=True, help="chaincode timings summary CSV with PIRQuery (ms)")
    ap.add_argument("--outdir", default="plots/tx_costs/figures", help="output directory for figures")
    ap.add_argument("--outcsv", default="plots/tx_costs/batch_projection.csv", help="output CSV for projections")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args()

    net_df = load_net(args.netcsv)
    time_df = load_time(args.timings)
    proj = compute_projection(net_df, time_df)

    os.makedirs(os.path.dirname(args.outcsv), exist_ok=True)
    proj.to_csv(args.outcsv, index=False)
    print(f"[OK] Wrote {args.outcsv}")

    plot_plate(proj, args.outdir, args.dpi)

if __name__ == "__main__":
    main()
