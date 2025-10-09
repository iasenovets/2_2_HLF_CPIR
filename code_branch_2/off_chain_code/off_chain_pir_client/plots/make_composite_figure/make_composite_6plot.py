#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Combine 6 plot images into a single 2x3 panel figure (A–F).
Intended for compact composite figures in academic papers.

Example usage:
  python make_composite_6_plot.py \
    --out figures/composite_plate.pdf \
    --width-in 22 --height-in 9 \
    --cols 3 --rows 2 \
    --wspace 0.06 --hspace 0.08 \
    --label-size 14 \
    block_size_bw.png \
    worldstate_bw.png \
    block_vs_ws_bw.png \
    peer_cpu_bw.png \
    peer_mem_bw.png \
    peer_net_bw.png
"""

import os
import argparse
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from matplotlib.offsetbox import AnchoredText

def load_image(path):
    try:
        return mpimg.imread(path)
    except Exception as e:
        raise SystemExit(f"Failed to read image: {path}\n{e}")

def letter(n):
    return chr(ord('A') + n)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("images", nargs="+", help="paths to 6 plot images (png/pdf)")
    ap.add_argument("--out", default="composite_plate.pdf", help="output PDF path")
    ap.add_argument("--width-in", type=float, default=22.0, help="figure width in inches")
    ap.add_argument("--height-in", type=float, default=9.0, help="figure height in inches")
    ap.add_argument("--cols", type=int, default=3, help="columns")
    ap.add_argument("--rows", type=int, default=2, help="rows")
    ap.add_argument("--wspace", type=float, default=0.06, help="horizontal space between panels")
    ap.add_argument("--hspace", type=float, default=0.08, help="vertical space between panels")
    ap.add_argument("--pad", type=float, default=0.02, help="outer padding")
    ap.add_argument("--label-size", type=int, default=14, help="panel label font size")
    ap.add_argument("--label-offset", type=float, default=0.015, help="offset from top-left")
    ap.add_argument("--dpi", type=int, default=300, help="output DPI")
    args = ap.parse_args()

    n = len(args.images)
    if n != 6:
        raise SystemExit(f"Expected 6 images for a 2x3 grid, got {n}.")

    # Set style
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 9,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
    })

    fig = plt.figure(figsize=(args.width_in, args.height_in), constrained_layout=False)

    pad = args.pad
    grid_w = 1.0 - 2 * pad
    grid_h = 1.0 - 2 * pad
    cell_w = (grid_w - (args.cols - 1) * args.wspace) / args.cols
    cell_h = (grid_h - (args.rows - 1) * args.hspace) / args.rows

    if cell_w <= 0 or cell_h <= 0:
        raise SystemExit("Negative cell size. Adjust wspace/hspace/pad or grid size.")

    for idx, img_path in enumerate(args.images):
        r = idx // args.cols
        c = idx % args.cols
        top_row_y = pad + (args.rows - 1 - r) * (cell_h + args.hspace)
        left_x = pad + c * (cell_w + args.wspace)

        ax = fig.add_axes([left_x, top_row_y, cell_w, cell_h])
        ax.axis("off")
        img = load_image(img_path)
        ax.imshow(img)
        ax.set_aspect('auto')

        # Panel label A–F
        label = letter(idx)
        at = AnchoredText(label, prop=dict(size=args.label_size, weight='bold'),
                          frameon=False, loc='upper left',
                          bbox_to_anchor=(0, 1), bbox_transform=ax.transAxes,
                          borderpad=0.0, pad=0.0)
        at.txt._x0 = args.label_offset
        at.txt._y0 = -args.label_offset
        ax.add_artist(at)

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    fig.savefig(args.out, dpi=args.dpi, bbox_inches="tight")
    print(f"[OK] Composite 6-panel figure written to {args.out}")

if __name__ == "__main__":
    main()
