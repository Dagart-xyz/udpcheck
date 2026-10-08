# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Логотип провайдера для карточки: скачивает значок сайта провайдера и кладёт на хаб как /logos/<ASN>.<ext>.

Пример:  python add_logo.py --asn 29124 --domain www.seven-sky.net
Берёт apple-touch-icon или значок из <link rel="icon">, иначе /favicon.ico. Принимает только PNG, WEBP, JPEG и ICO до 200 КБ
(SVG не берём). Свой файл можно положить и вручную: dagart.xyz:/var/www/udpcheck-site/logos/<ASN>.png (или .svg, .webp, .jpg, .ico).
Право на торговые знаки принадлежит провайдерам; значок используется только как опознавательный знак их сети.
"""
import argparse
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

import os
KEY = os.environ.get("UDPCHECK_KEY_HUB", "")          # файл ключа SSH для хаба (пусто: ключ по умолчанию)
HUB = os.environ.get("UDPCHECK_HUB_HOST", "dagart.xyz")

ap = argparse.ArgumentParser()
ap.add_argument("--asn", type=int, required=True)
ap.add_argument("--domain", required=True)
args = ap.parse_args()


def get(url, limit=400000):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (udpcheck logo fetch)"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read(limit), r.geturl()


def kind(b):
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if b[:4] == b"\x00\x00\x01\x00":
        return "ico"
    if b[:3] == b"\xff\xd8\xff":
        return "jpg"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "webp"
    return None


base = "https://" + args.domain.strip("/") + "/"
cands = []
try:
    html, final = get(base)
    html = html.decode("utf-8", "replace")
    for m in re.finditer(r"<link[^>]+>", html, re.I):
        tag = m.group(0)
        rel = re.search(r'rel=["\']([^"\']+)', tag, re.I)
        href = re.search(r'href=["\']([^"\']+)', tag, re.I)
        if rel and href and "icon" in rel.group(1).lower():
            score = 2 if "apple" in rel.group(1).lower() else 1
            cands.append((score, urllib.parse.urljoin(final, href.group(1))))
    cands.sort(key=lambda x: -x[0])
except Exception as e:
    print("страницу не прочитал (%s), пробую /favicon.ico" % e.__class__.__name__)
urls = [u for _, u in cands] + [base + "favicon.ico"]
for u in urls:
    try:
        b, _ = get(u)
    except Exception:
        continue
    k = kind(b)
    if k and len(b) <= 200000:
        print("нашёл:", u, k, len(b), "байт")
        with tempfile.NamedTemporaryFile(delete=False, suffix="." + k) as tf:
            tf.write(b)
        ssh = ["-i", KEY, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
        subprocess.run(["ssh"] + ssh + ["root@" + HUB, "mkdir -p /var/www/udpcheck-site/logos && rm -f /var/www/udpcheck-site/logos/%d.*" % args.asn], check=True)
        subprocess.run(["scp"] + ssh + [tf.name, "root@%s:/var/www/udpcheck-site/logos/%d.%s" % (HUB, args.asn, k)], check=True, capture_output=True)
        subprocess.run(["ssh"] + ssh + ["root@" + HUB, "chmod 644 /var/www/udpcheck-site/logos/*"], check=True)
        print("загружено: /logos/%d.%s" % (args.asn, k))
        sys.exit(0)
sys.exit("подходящий значок не найден: положите файл вручную в /var/www/udpcheck-site/logos/%d.png" % args.asn)
