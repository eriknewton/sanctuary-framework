#!/usr/bin/env python3
"""Generate placeholder PNG icons for the Sanctuary menubar app using only the
Python standard library. Visual polish lands in Sprint Piece 3 via AI design tools.

This script writes:
  icons/icon.png         512x512 RGBA, opaque dark "S" on light background (app icon)
  icons/icon-256.png     256x256 RGBA, same design
  icons/icon-128.png     128x128 RGBA, same design
  icons/tray-clear.png   44x44 RGBA, transparent background, dark "S" (template image)
  icons/tray-alert.png   44x44 RGBA, transparent background, dark "S" with dot accent

macOS treats the tray icon as a template image when iconAsTemplate=true in
tauri.conf.json; the system colors it for light/dark menubar automatically.
For that to work, the image must be black (or near-black) on a fully transparent
background. The "alert" variant adds a small filled dot in a corner to signal
that approval is pending without depending on red color (template images are
recolored by the system).
"""

import os
import struct
import zlib
from pathlib import Path

ICONS_DIR = Path(__file__).resolve().parent


def png_chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def build_png(width: int, height: int, pixels: bytes) -> bytes:
    """pixels is a flat bytes object of length width*height*4, RGBA."""
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    raw_rows = bytearray()
    stride = width * 4
    for y in range(height):
        raw_rows.append(0)  # filter type 0 = None
        raw_rows.extend(pixels[y * stride:(y + 1) * stride])
    idat = zlib.compress(bytes(raw_rows), 9)
    return sig + png_chunk(b"IHDR", ihdr) + png_chunk(b"IDAT", idat) + png_chunk(b"IEND", b"")


def make_app_icon(size: int) -> bytes:
    """Light background with a dark rounded-square frame and an "S" glyph in the middle.
    Glyph is drawn from a low-res mask so it scales cleanly across sizes."""
    # 16x16 glyph mask for "S" (1 = ink). Hand-drawn.
    glyph = [
        "  ##########  ",
        " ############ ",
        "##         ###",
        "##          ##",
        "##            ",
        " ##           ",
        "  ##########  ",
        "   ########## ",
        "            ##",
        "             #",
        "##          ##",
        "##         ###",
        " ############ ",
        "  ##########  ",
    ]
    gh = len(glyph)
    gw = max(len(r) for r in glyph)

    pixels = bytearray()
    bg_r, bg_g, bg_b = 245, 245, 247  # very light gray
    fg_r, fg_g, fg_b = 28, 28, 30  # near black
    border_thickness = max(2, size // 32)

    for y in range(size):
        for x in range(size):
            # Rounded square frame: simple inset rect for now. Visual polish in Piece 3.
            in_border = (
                x < border_thickness
                or y < border_thickness
                or x >= size - border_thickness
                or y >= size - border_thickness
            )
            if in_border:
                pixels.extend([fg_r, fg_g, fg_b, 255])
                continue
            # Map pixel back into glyph cell.
            inset = size // 6
            cx = x - inset
            cy = y - inset
            cw = size - 2 * inset
            ch = size - 2 * inset
            if 0 <= cx < cw and 0 <= cy < ch:
                gx = cx * gw // cw
                gy = cy * gh // ch
                if gy < gh and gx < len(glyph[gy]) and glyph[gy][gx] == "#":
                    pixels.extend([fg_r, fg_g, fg_b, 255])
                    continue
            pixels.extend([bg_r, bg_g, bg_b, 255])

    return build_png(size, size, bytes(pixels))


def make_tray_icon(size: int, alert: bool) -> bytes:
    """Transparent background with a black "S" glyph. Template image style for macOS.
    If alert=True, add a small filled dot in the upper-right corner."""
    glyph = [
        " ####### ",
        "##     ##",
        "##       ",
        " ####### ",
        "       ##",
        "##     ##",
        " ####### ",
    ]
    gh = len(glyph)
    gw = max(len(r) for r in glyph)

    pixels = bytearray()
    fg_r, fg_g, fg_b = 0, 0, 0  # black for template image

    inset = max(1, size // 8)
    cw = size - 2 * inset
    ch = size - 2 * inset

    # Pre-compute alert dot region (small filled circle in upper-right).
    dot_r = max(2, size // 6)
    dot_cx = size - dot_r - 2
    dot_cy = dot_r + 2

    for y in range(size):
        for x in range(size):
            # Alert dot
            if alert:
                dx = x - dot_cx
                dy = y - dot_cy
                if dx * dx + dy * dy <= dot_r * dot_r:
                    pixels.extend([fg_r, fg_g, fg_b, 255])
                    continue
            cx = x - inset
            cy = y - inset
            if 0 <= cx < cw and 0 <= cy < ch:
                gx = cx * gw // cw
                gy = cy * gh // ch
                if gy < gh and gx < len(glyph[gy]) and glyph[gy][gx] == "#":
                    pixels.extend([fg_r, fg_g, fg_b, 255])
                    continue
            pixels.extend([0, 0, 0, 0])  # transparent

    return build_png(size, size, bytes(pixels))


def main() -> None:
    os.makedirs(ICONS_DIR, exist_ok=True)

    (ICONS_DIR / "icon.png").write_bytes(make_app_icon(512))
    (ICONS_DIR / "icon-256.png").write_bytes(make_app_icon(256))
    (ICONS_DIR / "icon-128.png").write_bytes(make_app_icon(128))

    (ICONS_DIR / "tray-clear.png").write_bytes(make_tray_icon(44, alert=False))
    (ICONS_DIR / "tray-alert.png").write_bytes(make_tray_icon(44, alert=True))

    # macOS template-image variants at 1x and 2x for retina menubars.
    (ICONS_DIR / "tray-clear@2x.png").write_bytes(make_tray_icon(88, alert=False))
    (ICONS_DIR / "tray-alert@2x.png").write_bytes(make_tray_icon(88, alert=True))

    print("Wrote placeholder icons to", ICONS_DIR)


if __name__ == "__main__":
    main()
