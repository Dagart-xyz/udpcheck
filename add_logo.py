# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Логотипы провайдеров для карточек: скачивает значок с официального сайта сети и кладёт в папку logos/ рядом со скриптом
как <ASN>.<ext>. На сайт их выкладывает ops/deploy_site.sh (вместе со страницами, на всех кандидатов в хабы).

  python add_logo.py --all                      все сети из списка провайдеров сайта (адрес сайта сети берётся из PeeringDB
                                                или из logos/domains.json); уже скачанные и отклонённые пропускаются
  python add_logo.py --all --refresh            скачать заново и те, что уже есть (отклонённые всё равно пропускаются)
  python add_logo.py --asn 29124 --domain www.seven-sky.net    одна сеть с указанным сайтом
  python add_logo.py --reject 12345,23456       значок не подошёл: удалить и больше не скачивать (logos/rejected.json)
  python add_logo.py --review                   заново собрать logos/review.html — страницу для проверки глазами

Скачивание идёт с компьютера, где запущен скрипт, заранее и пакетом: ни страница посетителя, ни хаб к сайтам провайдеров
не обращаются, поэтому сайт провайдера не узнаёт, что кто-то из его сети пользуется проверкой.
Берём только PNG, WEBP, JPEG и ICO не меньше MIN_PX пикселей и до MAX_BYTES (SVG не берём: в нём может быть скрипт).
Одинаковая картинка у разных сетей — обычно значок движка сайта, а не провайдера: такие не сохраняются.
Адреса из локальной сети и самого компьютера не запрашиваются, даже если на них указывает страница провайдера.
Право на торговые знаки принадлежит провайдерам; значок используется только как опознавательный знак их сети.
Папка logos/ в публичный репозиторий не входит (ops/export_public.py берёт только перечисленные в нём файлы и папки).
"""
import argparse
import datetime
import hashlib
import html
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
LOGOS = os.path.join(ROOT, "logos")
SITE = os.environ.get("UDPCHECK_SITE", "https://dagart.xyz")
MIN_PX = 32
MAX_BYTES = 200000
EXTS = ("png", "ico", "jpg", "webp")
UA = "Mozilla/5.0 (compatible; udpcheck-logo/1.0; +https://dagart.xyz)"
SITE_BUDGET = 40          # секунд на один сайт: медленный сайт не задерживает весь запуск


def image_info(b):
    """(тип, ширина, высота) по первым байтам файла; (None, 0, 0) — не картинка или формат, который не берём."""
    if b[:8] == b"\x89PNG\r\n\x1a\n" and len(b) >= 24:
        w, h = struct.unpack(">II", b[16:24])
        return "png", w, h
    if b[:4] == b"\x00\x00\x01\x00" and len(b) >= 6:
        n = struct.unpack("<H", b[4:6])[0]
        best = 0
        for i in range(n):
            o = 6 + 16 * i
            if len(b) < o + 16:
                break
            w = b[o] or 256
            h = b[o + 1] or 256
            best = max(best, min(w, h))
        return ("ico", best, best) if best else (None, 0, 0)
    if b[:3] == b"\xff\xd8\xff":
        i = 2
        while i + 9 < len(b):
            if b[i] != 0xFF:
                i += 1
                continue
            marker = b[i + 1]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                h, w = struct.unpack(">HH", b[i + 5:i + 9])
                return "jpg", w, h
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            i += 2 + struct.unpack(">H", b[i + 2:i + 4])[0]
        return None, 0, 0
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP" and len(b) >= 30:
        chunk = b[12:16]
        if chunk == b"VP8X":
            w = 1 + int.from_bytes(b[24:27], "little")
            h = 1 + int.from_bytes(b[27:30], "little")
            return "webp", w, h
        if chunk == b"VP8 ":
            w, h = struct.unpack("<HH", b[26:30])
            return "webp", w & 0x3FFF, h & 0x3FFF
        if chunk == b"VP8L":
            v = int.from_bytes(b[21:25], "little")
            return "webp", (v & 0x3FFF) + 1, ((v >> 14) & 0x3FFF) + 1
    return None, 0, 0


def ascii_url(u):
    """Кириллический домен -> IDNA (xn--...), кириллица и пробелы в пути -> %XX: http.client принимает только ASCII."""
    try:
        p = urllib.parse.urlsplit(u)
        host = (p.hostname or "").encode("idna").decode("ascii")
        net = host + (":%d" % p.port if p.port else "")
    except (UnicodeError, ValueError):
        return u          # битый адрес (неверный порт и т. п.): fetch его просто не откроет, остальные значки страницы проверяются
    q = lambda x: urllib.parse.quote(x, safe="/?&=+:@!$'()*,;%~")
    return urllib.parse.urlunsplit((p.scheme, net, q(p.path), q(p.query), ""))


def icon_links(page, base):
    """Адреса значков из <link rel="...icon..."> страницы; apple-touch-icon и указанные крупные размеры — первыми."""
    out = []
    for m in re.finditer(r"<link\b[^>]*>", page, re.I):
        tag = m.group(0)
        rel = re.search(r'\brel\s*=\s*["\']([^"\']+)', tag, re.I)
        href = re.search(r'\bhref\s*=\s*["\']([^"\']+)', tag, re.I)
        if not rel or not href or "icon" not in rel.group(1).lower() or "mask" in rel.group(1).lower():
            continue
        u = urllib.parse.urljoin(base, html.unescape(href.group(1).strip()))
        u = ascii_url(u)
        sizes = re.findall(r"(\d+)x\d+", (re.search(r'\bsizes\s*=\s*["\']([^"\']+)', tag, re.I) or [None, ""])[1])
        score = max([int(s) for s in sizes] or [0]) + (500 if "apple" in rel.group(1).lower() else 0)
        out.append((score, u))
    out.sort(key=lambda x: -x[0])
    seen, urls = set(), []
    for _s, u in out:
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def host_allowed(url):
    """Только http(s) и только адреса в интернете: страница провайдера не должна заставить нас обратиться к роутеру или localhost."""
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80), proto=socket.IPPROTO_TCP)}
    except OSError:
        return False
    for a in addrs:
        try:
            if not ipaddress.ip_address(a.split("%")[0]).is_global:
                return False
        except ValueError:
            return False
    return bool(addrs)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not host_allowed(newurl):
            raise urllib.error.URLError("перенаправление на адрес не из интернета")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _peer_ok(sock):
    """Проверка уже установленного соединения: имя могли переразрешить на адрес в локальной сети после host_allowed (DNS rebinding)."""
    ip = sock.getpeername()[0].split("%")[0]
    if not ipaddress.ip_address(ip).is_global:
        sock.close()
        raise OSError("соединение с адресом не из интернета")


class _GuardHTTP(http.client.HTTPConnection):
    def connect(self):
        super().connect()
        _peer_ok(self.sock)


class _GuardHTTPS(http.client.HTTPSConnection):
    def connect(self):
        super().connect()
        _peer_ok(self.sock)          # запрос ещё не отправлен: TLS-рукопожатие прошло, но ни путь, ни заголовки не ушли


class _HTTP(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_GuardHTTP, req)


class _HTTPS(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_GuardHTTPS, req, context=ssl.create_default_context())


# без системного прокси: иначе проверка адреса смотрела бы на прокси, а не на сайт провайдера
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _HTTP, _HTTPS, _SafeRedirect)


def fetch(url, limit):
    if not host_allowed(url):
        raise ValueError("адрес не из интернета")
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Language": "ru,en"})
    with _opener.open(req, timeout=12) as r:
        return r.read(limit + 1), r.geturl()


def site_url(site):
    site = (site or "").strip()
    if not site:
        return ""
    if not re.match(r"^https?://", site, re.I):
        site = "https://" + site
    return ascii_url(site.rstrip("/") + "/")


def site_host(site):
    """Имя сайта без www.: по нему видно, что несколько сетей принадлежат одной компании."""
    h = (urllib.parse.urlsplit(site_url(site)).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


# страница в соцсети или справочнике — не сайт провайдера: значок был бы чужой (ВКонтакте, Telegram, PeeringDB)
NOT_OWN_SITE = ("vk.com", "vk.ru", "t.me", "telegram.me", "facebook.com", "instagram.com", "ok.ru", "linkedin.com", "twitter.com", "x.com",
                "youtube.com", "wa.me", "github.com", "github.io", "sites.google.com", "google.com", "yandex.ru", "dzen.ru", "bgp.he.net",
                "peeringdb.com", "ripe.net", "wikipedia.org", "2gis.ru")


def own_site(site):
    h = site_host(site)
    return bool(h) and not any(h == d or h.endswith("." + d) for d in NOT_OWN_SITE)


def best_icon(site):
    """Лучший значок сайта: (байты, тип, сторона, адрес) или (None, причина)."""
    base = site_url(site)
    if not base:
        return None, "нет адреса сайта"
    cands = []
    try:
        page, final = fetch(base, 600000)
        cands = icon_links(page.decode("utf-8", "replace"), final)
    except Exception as e:
        final = base
        cands = []
        why = "сайт не открылся (%s)" % e.__class__.__name__
    else:
        why = "подходящего значка нет"
    cands = cands[:6]          # со страницы не больше шести, запасные адреса проверяются всегда
    for extra in ("/apple-touch-icon.png", "/favicon.ico"):
        u = urllib.parse.urljoin(final, extra)
        if u not in cands:
            cands.append(u)
    best = None
    deadline = time.monotonic() + SITE_BUDGET
    for u in cands:
        if time.monotonic() > deadline:
            break
        try:
            b, _ = fetch(u, MAX_BYTES)
        except Exception:
            continue
        if len(b) > MAX_BYTES:
            continue
        k, w, h = image_info(b)
        side = min(w, h)
        if k and side >= MIN_PX and (best is None or side > best[2]):
            best = (b, k, side, u)
    return (best, "") if best else (None, why)


def load_json(name, default):
    try:
        with open(os.path.join(LOGOS, name), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def save_json(name, data):
    os.makedirs(LOGOS, exist_ok=True)
    tmp = os.path.join(LOGOS, name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, os.path.join(LOGOS, name))


def logo_file(asn):
    for k in EXTS:
        p = os.path.join(LOGOS, "%d.%s" % (asn, k))
        if os.path.exists(p):
            return p
    return None


def store(asn, b, kind):
    os.makedirs(LOGOS, exist_ok=True)
    for k in EXTS:
        p = os.path.join(LOGOS, "%d.%s" % (asn, k))
        if os.path.exists(p):
            os.remove(p)
    with open(os.path.join(LOGOS, "%d.%s" % (asn, kind)), "wb") as fh:
        fh.write(b)


def providers():
    req = urllib.request.Request(SITE.rstrip("/") + "/api/v2/providers", headers={"User-Agent": UA, "Accept-Language": "ru"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))["providers"]


def pdb_websites(asns):
    """Сайты сетей из PeeringDB пачками по 80 номеров (открытый API без ключа, пауза между запросами)."""
    out = {}
    asns = sorted(asns)
    for i in range(0, len(asns), 80):
        url = "https://www.peeringdb.com/api/net?asn__in=%s&fields=asn,website" % ",".join(str(a) for a in asns[i:i + 80])
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as r:
            for d in json.loads(r.read().decode("utf-8")).get("data", []):
                if d.get("website"):
                    out[int(d["asn"])] = str(d["website"])[:200]
        if i + 80 < len(asns):
            time.sleep(3)
    return out


def review(plist=None, skipped=None):
    """logos/review.html: все сохранённые значки в квадрате 40 пикселей, как на сайте, и что не нашлось. Только для проверки, на сайт не выкладывается."""
    src = load_json("sources.json", {})
    names = {str(p["asn"]): p.get("name") or "" for p in (plist or [])}
    cards = []
    for asn in sorted(src, key=lambda a: (src[a].get("name") or names.get(a) or "").lower()):
        f = logo_file(int(asn))
        if not f:
            continue
        s = src[asn]
        cards.append('<div class="c"><img class="pav" src="%s" alt=""><div><b>%s</b><br>AS%s · %s · %s×%s · %s<br><a href="%s">%s</a></div></div>' % (
            html.escape(os.path.basename(f)), html.escape(s.get("name") or names.get(asn) or ""), asn, html.escape(s.get("kind") or ""),
            s.get("px", ""), s.get("px", ""), html.escape(s.get("date") or ""), html.escape(s.get("url") or ""), html.escape(s.get("url") or "")))
    miss = "".join("<li>AS%s %s — %s</li>" % (html.escape(str(a)), html.escape(n), html.escape(w)) for a, n, w in (skipped or []))
    doc = ("<!doctype html><meta charset=utf-8><title>Логотипы: проверка</title><style>body{font:14px system-ui;margin:20px;max-width:1100px}"
           ".g{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:10px}.c{display:flex;gap:10px;align-items:center;"
           "border:1px solid #ddd;border-radius:10px;padding:8px}.pav{width:40px;height:40px;border-radius:10px;background:#fff;object-fit:contain;"
           "padding:4px;border:1px solid #ddd;flex:none}a{color:#666;font-size:12px;word-break:break-all}</style>"
           "<h1>Логотипы: %d</h1><p>Не подошёл значок — <code>python add_logo.py --reject ASN,ASN</code>.</p><div class=g>%s</div>%s") % (
        len(cards), "".join(cards), ("<h2>Не нашлось в этот запуск: %d</h2><ul>%s</ul>" % (len(skipped), miss)) if skipped else "")
    os.makedirs(LOGOS, exist_ok=True)
    with open(os.path.join(LOGOS, "review.html"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(doc)
    return os.path.join(LOGOS, "review.html")


def run_all(refresh, limit):
    try:
        plist = providers()
    except Exception as e:
        sys.exit("не получила список провайдеров с %s (%s: %s)" % (SITE, e.__class__.__name__, e))
    domains = {str(k): v for k, v in load_json("domains.json", {}).items()}
    rejected = load_json("rejected.json", {})
    src = load_json("sources.json", {})
    try:
        web = pdb_websites({a for p in plist for a in (p.get("asns") or [p["asn"]])})
    except Exception as e:
        sys.exit("PeeringDB не ответил (%s: %s); повторите позже" % (e.__class__.__name__, e))
    got, skipped, found = 0, [], {}
    todo = []
    for p in plist:
        asn = int(p["asn"])
        if str(asn) in rejected or (logo_file(asn) and not refresh):
            continue
        if str(asn) in domains:
            site = domains[str(asn)]
        else:
            site = web.get(asn) or next((web[a] for a in (p.get("asns") or []) if a in web), "")
        if not site:
            skipped.append((asn, p.get("name") or "", "сайт неизвестен: впишите его в logos/domains.json"))
            continue
        if not own_site(site):
            skipped.append((asn, p.get("name") or "", "вместо сайта страница в соцсети или справочнике (%s): впишите сайт в logos/domains.json" % site_host(site)))
            continue
        todo.append((p, site))
    if limit:
        todo = todo[:limit]
    for n, (p, site) in enumerate(todo, 1):
        asn = int(p["asn"])
        best, why = best_icon(site)
        print("[%d/%d] AS%d %s: %s" % (n, len(todo), asn, p.get("name") or "", ("%s %dpx" % (best[1], best[2])) if best else why), flush=True)
        if not best:
            skipped.append((asn, p.get("name") or "", why))
            continue
        found[asn] = (p, site, best)
    # одна и та же картинка у разных сетей (в том числе у уже сохранённых) — значок движка сайта, не провайдера
    by_hash = {}
    for asn, (_p, _s, best) in found.items():
        by_hash.setdefault(hashlib.sha256(best[0]).hexdigest(), []).append(asn)
    for a, s in src.items():
        if int(a) not in found and logo_file(int(a)):
            by_hash.setdefault(s.get("sha256"), []).append(int(a))
    for h, asns in by_hash.items():
        if len(asns) < 2:
            continue
        hosts = {site_host(found[a][1] if a in found else src.get(str(a), {}).get("site", "")) for a in asns}
        if len(hosts) == 1 and "" not in hosts:
            continue          # один сайт у всех этих сетей: это одна компания (несколько сетей Leaseweb), а не значок движка
        for asn in asns:
            if asn in found:
                p = found.pop(asn)[0]
                skipped.append((asn, p.get("name") or "", "такая же картинка у других сетей (AS%s): похоже на значок движка сайта" % ", AS".join(
                    str(x) for x in asns if x != asn)))
    today = datetime.date.today().isoformat()
    for asn, (p, site, best) in found.items():
        b, kind, side, url = best
        store(asn, b, kind)
        src[str(asn)] = {"name": p.get("name") or "", "kind": p.get("kind") or "", "site": site, "url": url, "px": side,
                         "bytes": len(b), "sha256": hashlib.sha256(b).hexdigest(), "date": today}
        got += 1
    save_json("sources.json", src)
    page = review(plist, skipped)
    have = sum(1 for p in plist if logo_file(int(p["asn"])))
    print("\nскачано сейчас: %d; со значком: %d из %d; не нашлось: %d" % (got, have, len(plist), len(skipped)))
    print("проверьте глазами: %s; затем выложите сайт (ops/deploy_site.sh)" % page)


def run_one(asn, domain):
    best, why = best_icon(domain)
    if not best:
        sys.exit("AS%d: %s" % (asn, why))
    b, kind, side, url = best
    store(asn, b, kind)
    src = load_json("sources.json", {})
    try:
        name = next((p.get("name") or "" for p in providers() if int(p["asn"]) == asn), "")
    except Exception:
        name = ""
    src[str(asn)] = {"name": name, "kind": "", "site": domain, "url": url, "px": side, "bytes": len(b),
                     "sha256": hashlib.sha256(b).hexdigest(), "date": datetime.date.today().isoformat()}
    save_json("sources.json", src)
    rej = load_json("rejected.json", {})
    if rej.pop(str(asn), None) is not None:
        save_json("rejected.json", rej)
    review()
    print("AS%d: %s %dpx из %s -> logos/%d.%s; выложите сайт (ops/deploy_site.sh)" % (asn, kind, side, url, asn, kind))


def run_reject(asns):
    rej = load_json("rejected.json", {})
    src = load_json("sources.json", {})
    for asn in asns:
        f = logo_file(asn)
        if f:
            os.remove(f)
        src.pop(str(asn), None)
        rej[str(asn)] = "отклонён владельцем " + datetime.date.today().isoformat()
        print("AS%d: значок убран и больше не скачивается" % asn)
    save_json("rejected.json", rej)
    save_json("sources.json", src)
    review()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Логотипы провайдеров для карточек сайта")
    ap.add_argument("--all", action="store_true", help="все сети из списка провайдеров сайта")
    ap.add_argument("--refresh", action="store_true", help="с --all: скачать заново и уже имеющиеся")
    ap.add_argument("--limit", type=int, default=0, help="с --all: не больше стольких сетей за запуск")
    ap.add_argument("--asn", type=int)
    ap.add_argument("--domain")
    ap.add_argument("--reject", help="номера сетей через запятую")
    ap.add_argument("--review", action="store_true")
    a = ap.parse_args(argv)
    if a.all:
        run_all(a.refresh, a.limit)
    elif a.asn and a.domain:
        run_one(a.asn, a.domain)
    elif a.reject:
        run_reject([int(x) for x in re.split(r"[,\s]+", a.reject.strip()) if x])
    elif a.review:
        print(review())
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
