# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Логотипы провайдеров (add_logo.py, ops/deploy_site.sh, ops/udpcheck-restore): форматы и размеры картинок, выбор значка со страницы,
запрет адресов не из интернета, отбраковка одинаковых значков у разных сетей, отклонённые, выкладка папки logos/ и то, что
восстановление хаба не трогает уже выложенный сайт. Сеть не нужна."""
import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:300]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


spec = importlib.util.spec_from_file_location("add_logo", os.path.join(ROOT, "add_logo.py"))
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)


def png(w, h):
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + struct.pack(">II", w, h) + b"\x08\x06\x00\x00\x00" + b"\x00" * 20


def ico(*sizes):
    b = b"\x00\x00\x01\x00" + struct.pack("<H", len(sizes))
    for s in sizes:
        b += bytes([s % 256, s % 256]) + b"\x00" * 14
    return b + b"\x00" * 10


print("A. Форматы и размеры")
check("PNG 180x180", L.image_info(png(180, 180)) == ("png", 180, 180))
check("ICO: берётся самый крупный, 0 = 256", L.image_info(ico(16, 32, 256)) == ("ico", 256, 256), L.image_info(ico(16, 32, 256)))
jpg = b"\xff\xd8\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00" + b"\x00" * 9 + b"\xff\xc0" + struct.pack(">HBHH", 17, 8, 96, 128) + b"\x00" * 20
check("JPEG: размер из SOF0", L.image_info(jpg) == ("jpg", 128, 96), L.image_info(jpg))
vp8x = b"RIFF" + b"\x00" * 4 + b"WEBP" + b"VP8X" + b"\x00" * 8 + (63).to_bytes(3, "little") + (63).to_bytes(3, "little")
check("WEBP VP8X 64x64", L.image_info(vp8x) == ("webp", 64, 64), L.image_info(vp8x))
v = (48 - 1) | ((48 - 1) << 14)
vp8l = b"RIFF" + b"\x00" * 4 + b"WEBP" + b"VP8L" + b"\x00" * 4 + b"\x2f" + v.to_bytes(4, "little") + b"\x00" * 10
check("WEBP VP8L 48x48", L.image_info(vp8l) == ("webp", 48, 48), L.image_info(vp8l))
check("SVG не берём", L.image_info(b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')[0] is None)
check("HTML вместо картинки не берём", L.image_info(b"<!doctype html><html>")[0] is None)

print("B. Значки со страницы")
page = ('<link rel="icon" href="/fav-16.png" sizes="16x16"><link rel="mask-icon" href="/m.svg">'
        '<link href="https://cdn.example.com/a.png" rel="apple-touch-icon" sizes="180x180"><link rel="icon" href="i.png?x=1&amp;y=2" sizes="96x96">')
u = L.icon_links(page, "https://isp.example.net/ru/")
check("apple-touch-icon первым, потом по размеру, mask-icon пропущен", u == ["https://cdn.example.com/a.png", "https://isp.example.net/ru/i.png?x=1&y=2",
                                                                           "https://isp.example.net/fav-16.png"], u)
u = L.icon_links('<link rel="icon" href="https://x.example:99999/a.png"><link rel="icon" href="/b.png">', "https://isp.example/")
check("битый адрес значка не мешает остальным", u[-1] == "https://isp.example/b.png" and len(u) == 2, u)
check("страница ВКонтакте и Telegram — не сайт провайдера", not L.own_site("https://vk.com/myisp") and not L.own_site("m.vk.com/isp")
      and not L.own_site("https://t.me/isp"))
check("похожие имена не путаются с соцсетями", L.own_site("https://globconnex.com") and L.own_site("ok-telecom.ru") and L.own_site("www.isp.example"))
check("адрес сайта без схемы получает https://", L.site_url("www.isp.example") == "https://www.isp.example/")
u = L.icon_links('<link rel="icon" href="/значок 1.png">', "https://провайдер.рф/")
check("кириллический домен в IDNA, кириллица и пробел в пути кодируются", u == ["https://xn--80adhes1agig.xn--p1ai/%D0%B7%D0%BD%D0%B0%D1%87%D0%BE%D0%BA%201.png"], u)

print("C. Только адреса в интернете")
for url in ("http://127.0.0.1/favicon.ico", "http://192.168.1.1/x.png", "http://10.0.0.5/", "http://[::1]/", "http://169.254.169.254/latest/",
            "file:///etc/passwd", "javascript:alert(1)", "ftp://1.1.1.1/x"):
    check("отказ: " + url, not L.host_allowed(url))
check("адрес в интернете разрешён", L.host_allowed("https://1.1.1.1/favicon.ico"))
try:
    L.fetch("http://127.0.0.1:9/x", 100)
    refused = False
except ValueError:
    refused = True
check("fetch не идёт на localhost", refused)
import http.server
import threading


class _Local(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        _Local.hits.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(png(64, 64))

    def log_message(self, *a):
        pass


srv = http.server.HTTPServer(("127.0.0.1", 0), _Local)
threading.Thread(target=srv.serve_forever, daemon=True).start()
_ha = L.host_allowed
L.host_allowed = lambda url: True          # имя «разрешилось» в интернет, а соединение ушло в локальную сеть (DNS rebinding)
try:
    L.fetch("http://127.0.0.1:%d/router-reboot" % srv.server_address[1], 100)
    blocked = False
except Exception:
    blocked = True
L.host_allowed = _ha
srv.shutdown()
check("подмена адреса после проверки: соединение с 127.0.0.1 обрывается до запроса", blocked and _Local.hits == [], (blocked, _Local.hits))

print("D. Пакетный запуск: отбраковка, отклонённые, ручной сайт")
T = tempfile.mkdtemp()
L.LOGOS = os.path.join(T, "logos")
os.makedirs(L.LOGOS)
plist = [{"asn": 100, "name": "Alpha", "kind": "isp"}, {"asn": 200, "name": "Beta", "kind": "isp"}, {"asn": 300, "name": "Gamma", "kind": "isp"},
         {"asn": 400, "name": "Delta", "kind": "hosting", "asns": [400, 401]}, {"asn": 500, "name": "Eps", "kind": "isp"},
         {"asn": 600, "name": "Zeta", "kind": "isp"}]
L.save_json("rejected.json", {"500": "отклонён владельцем"})
L.save_json("domains.json", {"600": "zeta.example"})
seen_sites = []
same = png(64, 64)


def fake_best(site):
    seen_sites.append(site)
    if site in ("beta.example", "gamma.example"):
        return (same, "png", 64, "https://%s/favicon.png" % site), ""
    if site == "alpha.example":
        return (png(180, 180), "png", 180, "https://alpha.example/apple.png"), ""
    if site == "delta-group.example":
        return (ico(48), "ico", 48, "https://delta-group.example/favicon.ico"), ""
    if site == "zeta.example":
        return (png(96, 96), "png", 96, "https://zeta.example/z.png"), ""
    return None, "подходящего значка нет"


L.providers = lambda: plist
L.pdb_websites = lambda asns: {100: "alpha.example", 200: "beta.example", 300: "gamma.example", 401: "delta-group.example", 500: "eps.example"}
L.best_icon = fake_best
L.run_all(False, 0)
files = sorted(os.listdir(L.LOGOS))
check("сохранены разные значки (сайт группы взят по второй сети, ручной сайт из domains.json)",
      {"100.png", "400.ico", "600.png"} <= set(files), files)
check("одинаковая картинка у двух сетей не сохранена ни у одной", "200.png" not in files and "300.png" not in files, files)
check("отклонённая сеть не скачивается", "eps.example" not in seen_sites, seen_sites)
src = L.load_json("sources.json", {})
check("источник записан: адрес, размер, хэш", src.get("100", {}).get("url") == "https://alpha.example/apple.png" and src["100"]["px"] == 180
      and src["100"]["sha256"] == hashlib.sha256(png(180, 180)).hexdigest(), src.get("100"))
rv = open(os.path.join(L.LOGOS, "review.html"), encoding="utf-8").read()
check("страница проверки: значки и причины отказа", "100.png" in rv and "значок движка" in rv, rv[:200])
seen_sites.clear()
L.run_all(False, 0)
check("повторный запуск не качает уже сохранённые", "alpha.example" not in seen_sites and "zeta.example" not in seen_sites, seen_sites)
L.pdb_websites = lambda asns: {100: "alpha.example", 200: "beta.example", 300: "gamma.example", 401: "delta-group.example", 700: "new.example"}
plist.append({"asn": 700, "name": "Eta", "kind": "isp"})
_old = fake_best
L.best_icon = lambda site: ((png(180, 180), "png", 180, "https://new.example/x.png"), "") if site == "new.example" else _old(site)
L.run_all(False, 0)
check("новая сеть с той же картинкой, что у сохранённой, не сохраняется", "700.png" not in os.listdir(L.LOGOS), os.listdir(L.LOGOS))
L.pdb_websites = lambda asns: {800: "https://www.group.example/contact", 900: "https://group.example"}
plist[:] = [{"asn": 800, "name": "Group DE", "kind": "hosting"}, {"asn": 900, "name": "Group", "kind": "hosting"}]
grp = png(128, 128)
L.best_icon = lambda site: ((grp, "png", 128, "https://group.example/i.png"), "")
L.run_all(False, 0)
check("одна картинка у сетей с одним сайтом (одна компания) сохраняется у обеих",
      os.path.exists(os.path.join(L.LOGOS, "800.png")) and os.path.exists(os.path.join(L.LOGOS, "900.png")), os.listdir(L.LOGOS))
L.run_reject([600])
check("--reject: файл убран, сеть в отклонённых", not os.path.exists(os.path.join(L.LOGOS, "600.png"))
      and "600" in L.load_json("rejected.json", {}) and "600" not in L.load_json("sources.json", {}))

print("E. Выкладка logos/ и восстановление хаба (sh)")
SH = shutil.which("sh")
if not SH:
    check("нужен sh (Git Bash или Linux) для проверки скриптов", False)
else:
    W = os.path.join(T, "w")
    dst = os.path.join(W, "srv")
    os.makedirs(os.path.join(dst, "logos"))
    open(os.path.join(dst, "logos", "999.png"), "wb").write(b"old")          # значок, которого больше нет в локальной папке
    work = os.path.join(W, "src")
    os.makedirs(os.path.join(work, "logos"))
    open(os.path.join(work, "logos", "100.png"), "wb").write(png(64, 64))
    open(os.path.join(work, "logos", "sources.json"), "w").write("{}")
    open(os.path.join(work, "logos", "review.html"), "w").write("x")
    open(os.path.join(work, "logos", "evil.svg"), "w").write("<svg/>")
    blk = open(os.path.join(ROOT, "ops", "deploy_site.sh"), encoding="utf-8").read()
    blk = blk[blk.index("if [ -d logos ]; then"):]
    blk = blk[:blk.index("\nfi\n") + 4]
    fake = os.path.join(W, "ssh")
    with open(fake, "w", newline="\n") as fh:
        fh.write('#!/bin/sh\nfor last; do :; done\nexec sh -c "$last"\n')
    os.chmod(fake, 0o755)
    script = 'set -e\nSSHO=""; HUB=h; DST="%s"\nssh() { "%s" "$@"; }\ncd "%s"\n%s' % (dst.replace("\\", "/"), fake.replace("\\", "/"), work.replace("\\", "/"), blk)
    r = subprocess.run([SH, "-c", script], capture_output=True, text=True)
    got = sorted(os.listdir(os.path.join(dst, "logos")))
    check("logos/ на сервере заменена целиком: новый значок есть, убранный исчез, служебные файлы и SVG не уехали",
          r.returncode == 0 and got == ["100.png"] and not os.path.exists(os.path.join(dst, "logos.new")) and not os.path.exists(os.path.join(dst, "logos.old")),
          (r.returncode, got, r.stderr[-300:]))
    rs = open(os.path.join(ROOT, "ops", "udpcheck-restore"), encoding="utf-8").read()
    rb = rs[rs.index("if [ -f /var/www/udpcheck-site/index.html ]; then"):]
    rb = rb[:rb.index("\nfi\n") + 4]
    for case, has_site in (("сайт уже выложен", True), ("чистый сервер", False)):
        www = os.path.join(W, "www-" + str(has_site))
        bk = os.path.join(W, "bk-" + str(has_site), "files", "site", "logos")
        os.makedirs(bk)
        open(os.path.join(bk, "29124.ico"), "wb").write(ico(48))
        open(os.path.join(os.path.dirname(bk), "index.html"), "w").write("old")
        if has_site:
            os.makedirs(os.path.join(www, "udpcheck-site"))
            open(os.path.join(www, "udpcheck-site", "index.html"), "w").write("new")
        body = rb.replace("/var/www", www.replace("\\", "/")).replace('install -d -m 755 ' + www.replace("\\", "/"), 'mkdir -p ' + www.replace("\\", "/"))
        r = subprocess.run([SH, "-c", 'set -eu\nW="%s"\n%s' % (os.path.join(W, "bk-" + str(has_site)).replace("\\", "/"), body)], capture_output=True, text=True)
        idx = open(os.path.join(www, "udpcheck-site", "index.html")).read() if os.path.exists(os.path.join(www, "udpcheck-site", "index.html")) else None
        if has_site:
            check("восстановление: " + case + " — сайт не тронут", r.returncode == 0 and idx == "new", (r.returncode, idx, r.stderr[-300:]))
        else:
            check("восстановление: " + case + " — сайт из копии", r.returncode == 0 and idx == "old"
                  and os.path.exists(os.path.join(www, "udpcheck-site", "logos", "29124.ico")), (r.returncode, idx, r.stderr[-300:]))

shutil.rmtree(T, ignore_errors=True)
print("\nИТОГ: " + ("всё прошло" if not fails else "ошибок: %d" % fails))
sys.exit(1 if fails else 0)
