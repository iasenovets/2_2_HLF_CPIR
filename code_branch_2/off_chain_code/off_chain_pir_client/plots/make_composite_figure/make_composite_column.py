#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Compose 3 plot images into a single 1x3 (column-width) PDF plate.
Great for papers: one column, three stacked panels (A–C).

Example:
  python make_composite_1x3.py \
    --out figures/plate_1x3.pdf \
    --width-in 3.5 --height-in 7.8 \
    --hspace 0.04 --pad 0.02 --label-size 12 \
    figA.png figB.png figC.png
"""

import os
import argparse
import matplotlib.pyplot as plt
import matplotlib.image as mpimg

def load_image(path):
    try:
        return mpimg.imread(path)
    except Exception as e:
        raise SystemExit(f"Failed to read image: {path}\n{e}")

def letter(n):
    return chr(ord('A') + n)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("images", nargs="+", help="paths to exactly 3 images (PNG preferred; PDF ok if backend supports)")
    ap.add_argument("--out", default="composite_1x3.pdf", help="output PDF path")
    ap.add_argument("--width-in", type=float, default=3.5, help="figure width in inches (≈ column width)")
    ap.add_argument("--height-in", type=float, default=7.8, help="figure height in inches")
    ap.add_argument("--wspace", type=float, default=0.0, help="horizontal space between panels (fraction)")
    ap.add_argument("--hspace", type=float, default=0.05, help="vertical space between panels (fraction)")
    ap.add_argument("--pad", type=float, default=0.02, help="outer padding (fraction of canvas)")
    ap.add_argument("--label-size", type=int, default=12, help="panel label font size")
    ap.add_argument("--label-offset", type=float, default=0.015, help="label inset from top-left (axes fraction)")
    ap.add_argument("--dpi", type=int, default=300, help="render DPI for output PDF")
    args = ap.parse_args()

    if len(args.images) != 3:
        raise SystemExit(f"Expected exactly 3 images for a 1x3 grid, got {len(args.images)}.")

    # Pub-friendly defaults
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 9,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
    })

    cols, rows = 1, 3
    fig = plt.figure(figsize=(args.width_in, args.height_in), constrained_layout=False)

    # Normalized layout math
    pad = args.pad
    grid_w = 1.0 - 2*pad
    grid_h = 1.0 - 2*pad
    cell_w = grid_w  # single column
    cell_h = (grid_h - (rows - 1) * args.hspace) / rows
    if cell_w <= 0 or cell_h <= 0:
        raise SystemExit("Negative cell size. Adjust hspace/pad/height.")

    for idx, img_path in enumerate(args.images):
        r = idx  # row index 0..2
        c = 0
        # Top-left origin (row 0 at top)
        top_row_y = pad + (rows - 1 - r) * (cell_h + args.hspace)
        left_x = pad + c * (cell_w + args.wspace)

        ax = fig.add_axes([left_x, top_row_y, cell_w, cell_h])
        ax.axis("off")

        img = load_image(img_path)
        ax.imshow(img)
        ax.set_aspect('auto')

        # Panel label A/B/C — safer than AnchoredText poking internals
        ax.text(args.label_offset, 1 - args.label_offset,
                letter(idx),
                transform=ax.transAxes,
                fontsize=args.label_size,
                fontweight='bold',
                va='top', ha='left')

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    fig.savefig(args.out, dpi=args.dpi, bbox_inches="tight")
    print(f"[OK] Wrote {args.out}")

if __name__ == "__main__":
    main()

