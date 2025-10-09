#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Compose multiple existing plot images into a single, wide PDF plate.
- Input: paths to 2–6 images (PNG recommended; PDF supported if your env can render them)
- Output: single-page PDF with configurable size and grid, with panel labels (A, B, C, ...)

Examples:
  python make_composite_figure.py \
    --out composite_2page.pdf \
    --width-in 22 --height-in 7 \
    --cols 3 --rows 1 \
    --wspace 0.06 --hspace 0.02 \
    plots/chaincode_timings/figures/chaincode_timings_bw.png \
    plots/docker_stats/figures/docker_cpu_bw.png \
    plots/block_vs_worldstate/figures/blockchan_components_bw_v3.png

"""

import os
import argparse
import math
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from matplotlib.offsetbox import AnchoredText

def load_image(path):
    # mpimg can read PNGs reliably; for PDFs, matplotlib may rasterize via backend if available
    try:
        return mpimg.imread(path)
    except Exception as e:
        raise SystemExit(f"Failed to read image: {path}\n{e}")

def letter(n):
    return chr(ord('A') + n)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("images", nargs="+", help="plot image paths (PNG preferred; PDF if supported)")
    ap.add_argument("--out", default="composite_figure.pdf", help="output PDF path")
    ap.add_argument("--width-in", type=float, default=22.0, help="figure width in inches (two-page feel ~22-24\")")
    ap.add_argument("--height-in", type=float, default=7.0, help="figure height in inches")
    ap.add_argument("--cols", type=int, default=3, help="number of columns")
    ap.add_argument("--rows", type=int, default=1, help="number of rows")
    ap.add_argument("--wspace", type=float, default=0.05, help="horizontal whitespace (0..1) between panels")
    ap.add_argument("--hspace", type=float, default=0.05, help="vertical whitespace (0..1) between panels")
    ap.add_argument("--pad", type=float, default=0.02, help="outer padding (0..0.1) around figure")
    ap.add_argument("--label-size", type=int, default=12, help="panel label font size")
    ap.add_argument("--label-offset", type=float, default=0.015, help="panel label offset from top-left (axes fraction)")
    ap.add_argument("--dpi", type=int, default=300, help="render DPI for the output PDF")
    args = ap.parse_args()

    n = len(args.images)
    if n == 0:
        raise SystemExit("No images provided.")
    if args.cols * args.rows < n:
        raise SystemExit(f"Grid {args.rows}x{args.cols} cannot fit {n} images. Increase rows/cols.")

    # Matplotlib styling for publication
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 9,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
    })

    fig_w, fig_h = args.width_in, args.height_in
    fig = plt.figure(figsize=(fig_w, fig_h), constrained_layout=False)

    # Compute normalized panel size
    pad = args.pad
    grid_w = 1.0 - 2*pad
    grid_h = 1.0 - 2*pad
    cell_w = (grid_w - (args.cols - 1) * args.wspace) / args.cols
    cell_h = (grid_h - (args.rows - 1) * args.hspace) / args.rows
    if cell_w <= 0 or cell_h <= 0:
        raise SystemExit("Negative cell size. Reduce wspace/hspace/pad or cols/rows.")

    # Place each image
    for idx, img_path in enumerate(args.images):
        r = idx // args.cols
        c = idx % args.cols
        # Top-left origin for row index (row 0 = top)
        top_row_y = pad + (args.rows - 1 - r) * (cell_h + args.hspace)
        left_x = pad + c * (cell_w + args.wspace)

        # Add axes for this slot
        ax = fig.add_axes([left_x, top_row_y, cell_w, cell_h])
        ax.axis("off")

        # Read and draw the image (fill, keeping aspect)
        img = load_image(img_path)
        ax.imshow(img)
        ax.set_aspect('auto')

        # Panel label (A, B, C, ...)
        label = letter(idx)
        at = AnchoredText(label, prop=dict(size=args.label_size, weight='bold'),
                          frameon=False, loc='upper left',
                          bbox_to_anchor=(0, 1), bbox_transform=ax.transAxes,
                          borderpad=0.0, pad=0.0)
        # nudging label a little inward
        at.txt._x0 = args.label_offset
        at.txt._y0 = -args.label_offset
        ax.add_artist(at)

    # Save as a single-page PDF
    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    fig.savefig(args.out, dpi=args.dpi, bbox_inches="tight")
    print(f"[OK] Wrote {args.out}")

if __name__ == "__main__":
    main()
