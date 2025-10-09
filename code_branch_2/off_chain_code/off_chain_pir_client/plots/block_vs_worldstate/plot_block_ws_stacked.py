#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Block (channel) vs World-state stacked size breakdown per ring/channel.
Version 3 — merges bgv_params, n, and record_s into 'metadata'
and adds configurable Y-axis upper limits.
"""

import os, argparse, numpy as np, pandas as pd, matplotlib.pyplot as plt

# ---------------- Raw data ----------------
DATA = [
    {
        "channel": "13_64_128",
        "friendly": "mini",
        "logN": 13,
        "m_DB_B": 65838,
        "bgv_params_B": 56,
        "n_B": 2,
        "record_s_B": 3,
        "record_013_B": 126,
        "block_KB": 77,
        "stateLevelDB_KB": 112,
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
    },
    {
        "channel": "14_128_256",
        "friendly": "rich",
        "logN": 14,
        "m_DB_B": 262446,
        "bgv_params_B": 57,
        "n_B": 3,
        "record_s_B": 3,
        "record_013_B": 254,
        "block_KB": 294,
        "stateLevelDB_KB": 332,
    },
]

# ---------------- Helpers ----------------
def figsize_ieee_single(aspect=0.75):
    w = 3.5
    return (w, w * aspect)

PALETTE = [
    ("m_DB_B", "0.20", ""),      # darkest
    ("metadata_B", "0.55", "//"),# merged meta
    ("json_est_B", "0.75", "++"),
    ("overhead_B", "0.90", "\\\\"),
]

plt.rcParams.update({
    "font.family": "sans-serif", "font.size": 8,
    "axes.labelsize": 8, "axes.titlesize": 9,
    "xtick.labelsize": 7, "ytick.labelsize": 7,
    "legend.fontsize": 7,
})

def bytes_from_kb(kb): return float(kb) * 1000
def clamp(x): return x if x > 0 else 0

def parse_records(chan):
    try: return int(chan.split("_")[1])
    except: return np.nan

def build_dataframe():
    rows = []
    for d in DATA:
        nrec = parse_records(d["channel"])
        json_est_B = d["record_013_B"] * (nrec if not np.isnan(nrec) else 0)
        metadata_B = d["bgv_params_B"] + d["n_B"] + d["record_s_B"]
        block_total_B = bytes_from_kb(d["block_KB"])
        ws_total_B = bytes_from_kb(d["stateLevelDB_KB"])
        known_B = d["m_DB_B"] + metadata_B + json_est_B
        rows.append({
            "channel": d["channel"], "friendly": d["friendly"],
            "logN": d["logN"], "num_records": nrec,
            "m_DB_B": d["m_DB_B"], "metadata_B": metadata_B,
            "json_est_B": json_est_B,
            "overhead_block_B": clamp(block_total_B - known_B),
            "overhead_ws_B": clamp(ws_total_B - known_B),
            "block_total_B": block_total_B, "ws_total_B": ws_total_B,
        })
    return pd.DataFrame(rows)

def to_kb(df, cols):
    out = df.copy()
    for c in cols: out[c] = out[c]/1000
    return out

# ---------------- Plot ----------------
def plot_stacked(ax, df, title, ylabel, overhead_col, ylim_top=None):
    order = ["mini", "mid", "rich"]
    df = df.set_index("friendly").loc[[x for x in order if x in df["friendly"].values]].reset_index()
    x = np.arange(len(df)); width = 0.55
    stack_cols, colors, hatches, labels = [], [], [], []
    for k,g,h in PALETTE:
        col = overhead_col if k=="overhead_B" else k
        if col not in df.columns: continue
        stack_cols.append(col); colors.append(g); hatches.append(h)
        labels.append({"m_DB_B":"m_DB","metadata_B":"metadata",
                       "json_est_B":"json (est.)",
                       "overhead_block_B":"overhead","overhead_ws_B":"overhead"}[col])
    dfp = to_kb(df, stack_cols); bottom=np.zeros(len(x))
    for col,color,hatch,lab in zip(stack_cols,colors,hatches,labels):
        vals=dfp[col].to_numpy()
        ax.bar(x,vals,width,bottom=bottom,color=color,hatch=hatch,
               edgecolor="black",linewidth=0.5,label=lab)
        bottom+=vals
    ax.set_xticks(x); ax.set_xticklabels(df["friendly"])
    ax.set_xlabel("Channel (mini, mid, rich)")
    ax.set_ylabel(ylabel); ax.set_title(title)
    ax.grid(axis="y",linestyle=":",linewidth=0.6,alpha=0.6)
    if ylim_top: ax.set_ylim(0, ylim_top)
    ax.legend(ncol=2,frameon=True,loc="upper left",bbox_to_anchor=(0.0,1.03))

def save_fig(fig,figdir,name,dpi):
    os.makedirs(figdir,exist_ok=True)
    fig.tight_layout()
    fig.savefig(os.path.join(figdir,f"{name}.pdf"),bbox_inches="tight")
    fig.savefig(os.path.join(figdir,f"{name}.png"),dpi=dpi,bbox_inches="tight")
    print(f"[OK] Wrote {name}.*")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--figdir",default="plots/block_vs_worldstate/figures")
    ap.add_argument("--dpi",type=int,default=300)
    ap.add_argument("--ylim_block",type=float,default=None,help="set Y-axis top limit for block plot (KB)")
    ap.add_argument("--ylim_ws",type=float,default=None,help="set Y-axis top limit for world-state plot (KB)")
    args=ap.parse_args()

    df=build_dataframe()
    csv=os.path.join(args.figdir,"block_worldstate_components_summary_v3.csv")
    os.makedirs(args.figdir,exist_ok=True)
    df_out=df.copy()
    for c in ["m_DB_B","metadata_B","json_est_B","overhead_block_B",
              "overhead_ws_B","block_total_B","ws_total_B"]:
        df_out[c.replace("_B","_KB")]=df_out[c]/1000; del df_out[c]
    df_out.to_csv(csv,index=False); print(f"[OK] Wrote {csv}")

    fig1,ax1=plt.subplots(figsize=figsize_ieee_single(0.80))
    plot_stacked(ax1,df,"Block size breakdown by channel","Size (KB)",
                 "overhead_block_B",ylim_top=args.ylim_block)
    save_fig(fig1,args.figdir,"blockchan_components_bw_v3",args.dpi)

    fig2,ax2=plt.subplots(figsize=figsize_ieee_single(0.80))
    plot_stacked(ax2,df,"World-state (LevelDB) breakdown by channel","Size (KB)",
                 "overhead_ws_B",ylim_top=args.ylim_ws)
    save_fig(fig2,args.figdir,"worldstate_components_bw_v3",args.dpi)

if __name__=="__main__":
    main()
