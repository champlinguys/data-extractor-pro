#!/usr/bin/env python3
"""Watermarked contact-sheet PDF of a customer's recovered images.

Usage:
  contact_sheet.py OUT.pdf ROOT [--title TEXT] [--exclude SUBPATH ...] DIR [DIR ...]

DIRs are relative to ROOT and are searched recursively; captions show each
image's path relative to ROOT. Every thumbnail carries a diagonal
"CHAMPLIN GUYS" watermark so the sheet works as a preview, not a copy.
"""
import argparse
import os
import sys
from datetime import date

from PIL import Image, ImageDraw, ImageFont, ImageOps

Image.MAX_IMAGE_PIXELS = None

EXTS = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tif', '.tiff')
DPI = 150
PAGE_W, PAGE_H = int(8.5 * DPI), int(11 * DPI)
MARGIN = int(0.4 * DPI)
HEADER_H = int(0.55 * DPI)
FOOTER_H = int(0.3 * DPI)
COLS, ROWS = 4, 5
CAPTION_H = 34
GAP = 12
WATERMARK = "CHAMPLIN GUYS"

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"


def font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except OSError:
        return ImageFont.load_default()


def find_images(root, dirs, excludes):
    out = []
    for d in dirs:
        for base, subdirs, files in os.walk(os.path.join(root, d)):
            rel_base = os.path.relpath(base, root)
            if any(rel_base == e or rel_base.startswith(e + os.sep) for e in excludes):
                subdirs[:] = []
                continue
            subdirs.sort(key=str.lower)
            for f in sorted(files, key=str.lower):
                if f.lower().endswith(EXTS):
                    out.append(os.path.join(rel_base, f))
    return out


def watermark_layer(w, h):
    """A diagonal semi-transparent CHAMPLIN GUYS stamp sized to a thumbnail."""
    diag = int((w * w + h * h) ** 0.5)
    size = max(10, int(diag / (len(WATERMARK) * 0.68)))
    f = font(FONT_BOLD, size)
    tw, th = f.getbbox(WATERMARK)[2:]
    layer = Image.new('RGBA', (tw + 20, th + 20), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    d.text((10, 10), WATERMARK, font=f, fill=(255, 255, 255, 120),
           stroke_width=max(1, size // 18), stroke_fill=(0, 0, 0, 90))
    layer = layer.rotate(35, expand=True, resample=Image.BICUBIC)
    layer.thumbnail((w, h))
    canvas = Image.new('RGBA', (w, h), (0, 0, 0, 0))
    canvas.alpha_composite(layer, ((w - layer.width) // 2, (h - layer.height) // 2))
    return canvas


def fit_caption(text, f, max_w):
    if f.getlength(text) <= max_w:
        return text
    while text and f.getlength('…' + text) > max_w:
        text = text[1:]
    return '…' + text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('root')
    ap.add_argument('dirs', nargs='+')
    ap.add_argument('--title', default='Recovered Images')
    ap.add_argument('--exclude', action='append', default=[])
    a = ap.parse_args()

    images = find_images(a.root, a.dirs, a.exclude)
    if not images:
        sys.exit('no images found')

    cell_w = (PAGE_W - 2 * MARGIN - (COLS - 1) * GAP) // COLS
    cell_h = (PAGE_H - 2 * MARGIN - HEADER_H - FOOTER_H - (ROWS - 1) * GAP) // ROWS
    thumb_h = cell_h - CAPTION_H
    per_page = COLS * ROWS
    n_pages = (len(images) + per_page - 1) // per_page

    f_title = font(FONT_BOLD, 26)
    f_sub = font(FONT, 16)
    f_cap = font(FONT, 12)
    wm_cache = {}
    unreadable = []
    pages = []

    for p in range(n_pages):
        page = Image.new('RGB', (PAGE_W, PAGE_H), 'white')
        d = ImageDraw.Draw(page)
        d.text((MARGIN, MARGIN), f"Champlin Guys Data Recovery — {a.title}",
               font=f_title, fill=(20, 20, 20))
        d.text((MARGIN, MARGIN + 34),
               f"Preview of recovered images · {len(images)} images · {date.today():%B %d, %Y}",
               font=f_sub, fill=(90, 90, 90))
        d.line((MARGIN, MARGIN + HEADER_H - 6, PAGE_W - MARGIN, MARGIN + HEADER_H - 6),
               fill=(180, 180, 180), width=2)

        for i, rel in enumerate(images[p * per_page:(p + 1) * per_page]):
            col, row = i % COLS, i // COLS
            x = MARGIN + col * (cell_w + GAP)
            y = MARGIN + HEADER_H + row * (cell_h + GAP)
            d.rectangle((x, y, x + cell_w - 1, y + thumb_h - 1), fill=(240, 240, 240))
            try:
                with Image.open(os.path.join(a.root, rel)) as im:
                    im.seek(0)
                    im = ImageOps.exif_transpose(im)
                    im.draft('RGB', (cell_w * 2, thumb_h * 2))
                    im = im.convert('RGBA')
                    im.thumbnail((cell_w, thumb_h), Image.LANCZOS)
                key = im.size
                if key not in wm_cache:
                    wm_cache[key] = watermark_layer(*key)
                im.alpha_composite(wm_cache[key])
                bg = Image.new('RGB', im.size, 'white')
                bg.paste(im, mask=im.getchannel('A'))
                page.paste(bg, (x + (cell_w - im.width) // 2, y + (thumb_h - im.height) // 2))
            except Exception as e:
                unreadable.append((rel, str(e)))
                d.text((x + 8, y + thumb_h // 2 - 8), "cannot preview", font=f_cap,
                       fill=(150, 0, 0))
            cap = fit_caption(rel.replace(os.sep, ' / '), f_cap, cell_w - 4)
            d.text((x + 2, y + thumb_h + 6), cap, font=f_cap, fill=(60, 60, 60))

        d.text((MARGIN, PAGE_H - MARGIN - 14),
               "All images are watermarked previews. Originals delivered without watermark.",
               font=f_cap, fill=(120, 120, 120))
        pg = f"Page {p + 1} of {n_pages}"
        d.text((PAGE_W - MARGIN - f_cap.getlength(pg), PAGE_H - MARGIN - 14), pg,
               font=f_cap, fill=(120, 120, 120))
        pages.append(page)
        print(f"\rpage {p + 1}/{n_pages}", end='', flush=True)

    print()
    pages[0].save(a.out, save_all=True, append_images=pages[1:], resolution=DPI,
                  quality=82, title=f"Champlin Guys — {a.title}", author="Champlin Guys")
    print(f"wrote {a.out}: {n_pages} pages, {len(images)} images, "
          f"{len(unreadable)} could not be previewed")
    for rel, err in unreadable:
        print(f"  cannot preview: {rel} ({err})")


if __name__ == '__main__':
    main()
