#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Значок сайта файлами (поисковики показывают его в выдаче только по адресу, встроенный data: им не подходит): site/favicon.svg, site/favicon.ico (16, 32, 48 px)
и site/apple-touch-icon.png (180 px). Рисунок тот же, что был встроен в страницу: синий скруглённый квадрат и белая «линия графика». Только стандартная библиотека."""
import os
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")
BLUE = (0x0b, 0x5f, 0xff)
POLY = [(6, 21), (12, 11), (17, 18), (20, 14), (26, 21)]          # в координатах 32x32, как в SVG: M6 21 l6-10 5 7 3-4 6 7 z
SVG = ("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\"><rect width=\"32\" height=\"32\" rx=\"7\" fill=\"#0b5fff\"/>"
       "<path d=\"M6 21l6-10 5 7 3-4 6 7z\" fill=\"#fff\"/></svg>\n")


def inside_poly(x, y):
    c = False
    n = len(POLY)
    for i in range(n):
        x1, y1 = POLY[i]
        x2, y2 = POLY[(i + 1) % n]
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / (y2 - y1) + x1:
            c = not c
    return c


def inside_rrect(x, y, r=7.0, s=32.0):
    cx = min(max(x, r), s - r)
    cy = min(max(y, r), s - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def render(size, ss=4, r=7.0):
    """RGBA построчно, сглаживание выборкой ss x ss на пиксель."""
    rows = []
    k = 32.0 / size
    for py in range(size):
        row = bytearray()
        for px in range(size):
            bg = wt = 0
            for sy in range(ss):
                for sx in range(ss):
                    x = (px + (sx + 0.5) / ss) * k
                    y = (py + (sy + 0.5) / ss) * k
                    if inside_rrect(x, y, r) if r else True:
                        if inside_poly(x, y):
                            wt += 1
                        else:
                            bg += 1
            tot = ss * ss
            a = (bg + wt) / tot
            if a == 0:
                row += bytes((0, 0, 0, 0))
                continue
            f = wt / (bg + wt)                                      # доля белого среди закрашенного
            rgb = [round(BLUE[i] * (1 - f) + 255 * f) for i in range(3)]
            row += bytes(rgb + [round(255 * a)])
        rows.append(bytes(row))
    return rows


def png(size, r=7.0):
    rows = render(size, r=r)
    raw = b"".join(b"\x00" + r for r in rows)

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def ico(sizes):
    imgs = [png(s) for s in sizes]
    head = struct.pack("<HHH", 0, 1, len(imgs))
    off = 6 + 16 * len(imgs)
    dirs = b""
    for s, data in zip(sizes, imgs):
        dirs += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), off)
        off += len(data)
    return head + dirs + b"".join(imgs)


if __name__ == "__main__":
    open(os.path.join(SITE, "favicon.svg"), "w", encoding="utf-8", newline="\n").write(SVG)
    open(os.path.join(SITE, "favicon.ico"), "wb").write(ico([16, 32, 48]))
    open(os.path.join(SITE, "apple-touch-icon.png"), "wb").write(png(180, r=0))          # iOS скругляет углы сам: квадрат без прозрачности
    print("favicon.svg, favicon.ico, apple-touch-icon.png записаны в", SITE)
