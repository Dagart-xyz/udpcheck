# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Интерфейсные тесты сайта без сети и без хаба: страница открывается в Chromium (Playwright), ответы хаба и WebRTC подменяются данными из fixtures.py.
Снимаются тексты страницы во всех состояниях: главная, поиск, страница провайдера, все вердикты проверки, ошибки, обращение в поддержку.

  python harness.py --site /site --lang ru --out /out/ru.json               записать снимки
  python harness.py --site /site --lang ru --compare /t/golden_ru.json      сравнить с эталоном (русская версия не должна меняться)
  python harness.py --site /site --lang en --check-en                       английская версия: нет кириллицы, нет русских подсказок, ссылки с /en

Запуск в Docker:  docker run --rm -v <сайт>:/site -v <tests/i18n>:/t -w /t mcr.microsoft.com/playwright/python:v1.49.1-noble
                  sh -c "pip install -q playwright==1.49.1 && python harness.py ..." """
import argparse
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures as F
from playwright.sync_api import sync_playwright

ORIGIN = "https://site.test"
WIDTH = 1000
FROZEN_MS = F.NOW * 1000

INIT_JS = r"""
(function(){
  var FIXED = %(frozen)d, _D = Date;
  function FD(){ var a = arguments; if (!(this instanceof FD)) return new _D(FIXED).toString();
    return a.length === 0 ? new _D(FIXED) : (a.length === 1 ? new _D(a[0]) : new _D(a[0], a[1], a[2] || 1, a[3] || 0, a[4] || 0, a[5] || 0, a[6] || 0)); }
  FD.prototype = _D.prototype; FD.now = function(){ return FIXED; }; FD.UTC = _D.UTC; FD.parse = _D.parse; window.Date = FD;
  window.__stun = %(stun)s; window.__ext = %(ext)s;
  if (%(webrtc)s) {
    window.RTCPeerConnection = function(cfg){ this.url = cfg.iceServers[0].urls.replace("stun:", ""); this.onicecandidate = null; };
    window.RTCPeerConnection.prototype.createDataChannel = function(){ return {}; };
    window.RTCPeerConnection.prototype.createOffer = function(){ return Promise.resolve({type: "offer", sdp: ""}); };
    window.RTCPeerConnection.prototype.close = function(){};
    window.RTCPeerConnection.prototype.setLocalDescription = function(){
      var pc = this, ip = pc.url.split(":")[0], ok = window.__stun[pc.url] !== false, ext = window.__ext[ip] || "203.0.113.7";
      setTimeout(function(){ if (!pc.onicecandidate) return;
        if (ok) pc.onicecandidate({candidate: {candidate: "candidate:1 1 udp 1 " + ext + " 5000 typ srflx raddr 0.0.0.0 rport 0"}}); else pc.onicecandidate({candidate: null}); }, 3);
      return Promise.resolve(); };
  } else { try { delete window.RTCPeerConnection; window.RTCPeerConnection = undefined; } catch (e) {} }
  %(extra)s
})();
"""

SNAP_JS = """() => {
  [...document.querySelectorAll('details')].forEach(function(x){ x.open = true; });
  var nv = document.getElementById('newver'); if (nv) nv.hidden = false;
  return {lang: document.documentElement.lang, title: document.title, text: document.body.innerText,
          placeholders: [...document.querySelectorAll('[placeholder]')].map(function(e){ return e.placeholder; }),
          titles: [...document.querySelectorAll('[title]')].map(function(e){ return e.title; }),
          aria: [...document.querySelectorAll('[aria-label]')].map(function(e){ return e.getAttribute('aria-label'); }),
          hrefs: [...document.querySelectorAll('a[href]')].map(function(a){ return a.getAttribute('href'); }),
          desc: (document.querySelector('meta[name=description]') || {}).content || '',
          langsw: document.querySelector('#langlist a[data-lang]') ? document.querySelector('#langlist a[data-lang]').getAttribute('href') : '',
          hint: !document.getElementById('langhint').hidden,
          canon: (document.querySelector('link[rel=canonical]') || {}).href || '',
          alts: [...document.querySelectorAll('link[rel=alternate]')].map(function(l){ return l.hreflang + '=' + l.getAttribute('href'); }),
          overflow: [document.documentElement.scrollWidth, window.innerWidth]};
}"""


def S(name, **kw):
    kw["name"] = name
    return kw


GO = ("go",)
SNAP = ("snap",)
SCENARIOS = [
    S("home"),
    S("home_notice_closed", actions=[("click", "#noticeBtn"), SNAP]),
    S("home_search_none", actions=[("fill", "#psearch", "zzzz"), ("wait", 300), SNAP]),
    S("home_search_found", actions=[("fill", "#psearch", {"ru": "мегафон", "en": "megafon"}), ("wait", 300), SNAP]),
    S("home_search_asn", actions=[("fill", "#psearch", "as 12389"), ("wait", 300), SNAP]),
    S("home_more", actions=[("click", "#pmore button"), ("wait", 300), SNAP]),
    S("home_api_errors", fail={"providers", "journal", "nodes"}),
    S("home_empty", empty=True),
    S("provider_12389", path="/as12389"),
    S("provider_12389_7d", path="/as12389", actions=[("click", ".seg button:nth-child(2)"), SNAP]),
    S("provider_ok_hosting", path="/as8075", detail="ok"),
    S("provider_404", path="/as99999"),
    S("provider_500", path="/as12389", fail={"detail"}),
    S("chk_ok", me="none", stun="ok", trace="ok", actions=[GO, SNAP]),
    S("chk_ok_copy", me="none", stun="ok", trace="ok", actions=[GO, ("click", "button.copy[data-for=c1]"), ("wait", 200), SNAP]),
    S("chk_in_cut_full", me="in_cut_tcp", stun="in_cut", trace="ok", stats="long_cut", actions=[GO, SNAP]),
    S("chk_in_cut_full_copy", me="in_cut_tcp", stun="in_cut", trace="ok", stats="long_cut", actions=[GO, ("click", "#support button.copy"), ("wait", 200), SNAP]),
    S("chk_in_cut_nonode", me="none", stun="in_cut", trace="ok", actions=[GO, SNAP]),
    S("chk_in_cut_sparse_trace", me="in_cut", stun="in_cut", trace="none_reach", stats="empty", actions=[GO, SNAP]),
    S("chk_out_cut", me="out_cut", stun="out_cut", trace="ok", actions=[GO, SNAP]),
    S("chk_partial", me="partial", stun="partial", trace="allreach", actions=[GO, SNAP]),
    S("chk_ctrl_bad", me="none", stun="ctrl_bad", trace="ok", actions=[GO, SNAP]),
    S("chk_mixed", me="none", stun="mixed", trace="ok", actions=[GO, SNAP]),
    S("chk_sizecut", me="ok", stun="sizecut", trace="allreach", actions=[GO, SNAP]),
    S("chk_sizecut_nonode", me="none", stun="sizecut", trace="allreach", actions=[GO, SNAP]),
    S("chk_sizepart", me="none", stun="size_part", trace="allreach", actions=[GO, SNAP]),
    S("chk_noanchor", me="noanchor", stun="noanchor", trace="ok", actions=[GO, SNAP]),
    S("chk_community_ok", me="none", stun="community_ok", trace="ok", actions=[GO, SNAP]),
    S("chk_seen_failed", me="none", stun="seen_failed", trace="ok", fail={"stunseen"}, actions=[GO, SNAP]),
    S("chk_unsupported", me="none", stun="ok", trace="ok", webrtc=False, actions=[GO, SNAP]),
    S("chk_stun_error", me="none", stun="ok", trace="ok", fail={"stun"}, actions=[GO, SNAP]),
    S("chk_me_error", me="none", stun="ok", trace="ok", fail={"me"}, actions=[GO, SNAP]),
    S("chk_trace_429_old", me="none", stun="ok", trace="429", old_trace=True, actions=[GO, SNAP]),
    S("chk_trace_429_none", me="none", stun="ok", trace="429", actions=[GO, SNAP]),
    S("chk_trace_500", me="none", stun="ok", trace="500", actions=[GO, SNAP]),
    S("chk_trace_mixed_status", me="in_cut", stun="in_cut", trace="mixed_status", actions=[GO, SNAP]),
    S("chk_me_weak", me="weak", stun="in_cut", trace="ok", actions=[GO, SNAP]),
    S("chk_me_ok", me="ok", stun="ok", trace="ok", actions=[GO, SNAP]),
    S("chk_me_ctrl", me="ctrl", stun="ok", trace="ok", actions=[GO, SNAP]),
    S("chk_me_unstable", me="unstable", stun="ok", trace="ok", actions=[GO, SNAP]),
    S("chk_me_noforeign", me="noforeign", stun="ok", trace="ok", actions=[GO, SNAP]),
    S("chk_me_controldown", me="controldown", stun="ok", trace="ok", actions=[GO, SNAP]),
    S("chk_me_noanchor_rounds", me="noanchor_rounds", stun="ok", trace="ok", actions=[GO, SNAP]),
    S("chk_unknown_me", me="unknown", stun="ok", trace="ok", actions=[GO, SNAP]),
    S("chk_report429", me="none", stun="ok", trace="ok", report=429, actions=[GO, SNAP]),
    S("chk_twice", me="none", stun="ok", trace="ok", actions=[GO, GO, SNAP]),
    S("lang_hint_other_browser", locale="other", actions=[SNAP, ("click", "#langhintClose"), SNAP, ("reload",), SNAP], skip_cyr=True),
    S("lang_switch_click", locale="other", path="/as12389", actions=[("click", "#langbtn"), ("click", "#langlist a[data-lang]"), ("wait", 600), SNAP], skip_cyr=True),
]


SC_BY_NAME = {sc["name"]: sc for sc in SCENARIOS}


def en_pick(v, lang):
    return v[lang] if isinstance(v, dict) else v


class Mock:
    def __init__(self, site, lang, sc):
        self.site, self.lang, self.sc = site, lang, sc
        self.fail = sc.get("fail", set())
        self.stun_profile = sc.get("stun", "ok")
        self.me_profile = sc.get("me", "none")

    def static(self, path):
        """Как у Caddy: /en/... отдаёт английскую версию, остальное русскую; /asN и /en/asN отдают главную страницу своего языка."""
        en = path == "/en" or path.startswith("/en/")
        p = (path[3:] or "/") if en else path
        base = os.path.join(self.site, "en") if en else self.site
        if re.fullmatch(r"/as\d+/?", p) or p in ("/", ""):
            return os.path.join(base, "index.html")
        if p in ("/privacy", "/terms"):
            return os.path.join(base, p[1:] + ".html")
        f = os.path.normpath(os.path.join(self.site, path.lstrip("/")))
        return f if f.startswith(os.path.normpath(self.site)) and os.path.isfile(f) else None

    def handle(self, route):
        req = route.request
        u = urlsplit(req.url)
        path, method = u.path, req.method
        if path.startswith("/api/"):
            return self.api(route, path, method, parse_qs(u.query))
        if path.startswith("/logos/"):
            return route.fulfill(status=404, body="")
        f = self.static(path)
        if f is None:
            return route.fulfill(status=404, body="")
        ctype = "text/html; charset=utf-8" if f.endswith(".html") else "text/plain; charset=utf-8"
        with open(f, "rb") as fh:
            return route.fulfill(status=200, headers={"content-type": ctype}, body=fh.read())

    def js(self, route, obj, status=200):
        route.fulfill(status=status, headers={"content-type": "application/json; charset=utf-8"}, body=json.dumps(obj, ensure_ascii=False))

    def api(self, route, path, method, q):
        sc = self.sc
        if path == "/api/v2/version":
            return self.js(route, {"site": "x"})
        if path == "/api/v2/providers":
            if "providers" in self.fail:
                return self.js(route, {"error": "x"}, 500)
            return self.js(route, {"generated": F.NOW, "providers": []} if sc.get("empty") else F.providers())
        if path == "/api/v2/journal":
            if "journal" in self.fail:
                return self.js(route, {"error": "x"}, 500)
            return self.js(route, {"generated": F.NOW, "events": []} if sc.get("empty") else F.journal())
        if path == "/api/v2/nodes":
            if "nodes" in self.fail:
                return self.js(route, {"error": "x"}, 500)
            return self.js(route, F.nodes_empty() if sc.get("empty") else F.nodes())
        m = re.fullmatch(r"/api/v2/providers/(\d+)", path)
        if m:
            if "detail" in self.fail:
                return self.js(route, {"error": "x"}, 500)
            d = (F.detail_ok if sc.get("detail") == "ok" else F.detail)(int(m.group(1)))
            return self.js(route, d, 200) if d else self.js(route, {"error": "not found"}, 404)
        if path.startswith("/api/v2/stats/asn/"):
            if sc.get("stats") == "long_cut":
                base = F.NOW // 3600 - 100
                return self.js(route, {"asn": 12389, "window_hours": 168, "buckets": [{"hour": (base + i) * 3600, "rounds": 3, "verdicts": {"FOREIGN_IN_CUT": 3}} for i in range(100)]})
            if sc.get("stats") == "empty":
                return self.js(route, {"asn": 12389, "window_hours": 168, "buckets": []})
            return self.js(route, F.stats_asn())
        if path == "/api/v2/web/me":
            if "me" in self.fail:
                return self.js(route, {"error": "x"}, 500)
            return self.js(route, F.me(self.me_profile))
        if path == "/api/v2/web/stun":
            if "stun" in self.fail:
                return self.js(route, {"error": "x"}, 500)
            return self.js(route, {"country": "RU", "targets": F.stun_targets(self.stun_profile), "attempts": 3})
        if path == "/api/v2/web/stunseen" and method == "POST":
            if "stunseen" in self.fail:
                return self.js(route, {"error": "x"}, 500)
            return self.js(route, {"id": "aaaaaaaaaaaaaaaa"}, 202)
        if path.startswith("/api/v2/web/stunseen/"):
            return self.js(route, F.stunseen(self.stun_profile))
        if path == "/api/v2/web/trace" and method == "POST":
            t = sc.get("trace", "ok")
            if t == "429":
                route.fulfill(status=429, headers={"content-type": "application/json", "retry-after": "180"}, body=json.dumps({"error": "x"}))
                return
            if t == "500":
                return self.js(route, {"error": "Ошибка сервера: подробности"}, 500)
            return self.js(route, {"id": "bbbbbbbbbbbbbbbb", "targets": [{"code": a["code"], "kind": "home" if a["country"] == "RU" else "foreign", "name": a["name"], "name_en": a["name_en"]}
                                                                          for a in F.ANCHORS]}, 202)
        if path.startswith("/api/v2/web/trace/"):
            return self.js(route, F.trace_result(sc.get("trace", "ok"), F.ANCHORS))
        if path == "/api/v2/web/report":
            if sc.get("report") == 429:
                return self.js(route, {"error": "x"}, 429)
            return self.js(route, {"ok": True, "counted": True})
        return self.js(route, {"error": "not found"}, 404)


def run_scenario(browser, site, lang, sc):
    mock = Mock(site, lang, sc)
    stun = {}
    for k in F.stun_dead(mock.stun_profile):
        stun[k] = False
    old = ""
    if sc.get("old_trace"):
        t = [{"code": "HEL1-FI", "kind": "foreign", "name": "Финляндия, Хельсинки", "name_en": "Finland, Helsinki", "status": "done",
              "results": {"icmp": {"as_path": [{"asn": 3356, "org": "Lumen"}, {"asn": 12389, "org": "PJSC Rostelecom"}], "reached": False, "last_responding_ttl": 7}}},
             {"code": "DAGART-RU", "kind": "home", "name": "Россия, Москва-1", "name_en": "Russia, Moscow-1", "status": "done",
              "results": {"icmp": {"as_path": [{"asn": 12389, "org": "PJSC Rostelecom"}], "reached": True, "last_responding_ttl": 9}}}]
        old = "try { localStorage.setItem('udpc_trace', JSON.stringify({ts: %d, targets: %s})); } catch (e) {}" % (FROZEN_MS - 3600 * 1000, json.dumps(t, ensure_ascii=False))
    loc = "en-US" if lang == "en" else "ru-RU"
    if sc.get("locale") == "other":
        loc = "ru-RU" if lang == "en" else "en-US"
    ctx = browser.new_context(locale=loc, timezone_id="Europe/Moscow", viewport={"width": WIDTH, "height": 900})
    ctx.add_init_script(INIT_JS % {"frozen": FROZEN_MS, "stun": json.dumps(stun), "ext": json.dumps(F.stun_ext_ips(mock.stun_profile)),
                                   "webrtc": "true" if sc.get("webrtc", True) else "false", "extra": old})
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    ctx.route("**/*", mock.handle)
    pre = "/en" if lang == "en" else ""
    path = sc.get("path", "/")
    url = ORIGIN + (pre + (path if path != "/" else "/")) if lang == "en" else ORIGIN + path
    page.goto(url, wait_until="load")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(500)
    snaps = {}
    n = 0
    actions = sc.get("actions", [SNAP])
    for a in actions:
        if a[0] == "snap":
            snaps["s%d" % n] = page.evaluate(SNAP_JS)
            n += 1
        elif a[0] == "click":
            page.click(a[1])
        elif a[0] == "fill":
            page.fill(a[1], en_pick(a[2], lang))
        elif a[0] == "reload":
            page.reload(wait_until="load")
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(400)
        elif a[0] == "wait":
            page.wait_for_timeout(a[1])
        elif a[0] == "go":
            page.click("#go")
            page.wait_for_function("() => !document.getElementById('go').disabled", timeout=40000)
            page.wait_for_timeout(500)
    if not actions or actions == [SNAP] or not snaps:
        pass
    ctx.close()
    return {"snaps": snaps, "errors": errors}


def lang_asserts(res, lang, only):
    """Проверки переключения языка: адрес другой версии, canonical и hreflang, подсказка о языке и запоминание выбора."""
    fails = 0

    def check(name, cond, extra=""):
        nonlocal fails
        print("  %s %s%s" % ("OK  " if cond else "FAIL", name, "" if cond else "   " + str(extra)[:200]))
        if not cond:
            fails += 1
    me, other, pre, opre = lang, ("en" if lang == "ru" else "ru"), ("/en" if lang == "en" else ""), ("" if lang == "en" else "/en")
    if "home" in res and res["home"]["snaps"]:
        h = res["home"]["snaps"]["s0"]
        check("[%s] главная: адрес другой версии" % lang, h["langsw"] == opre + "/", h["langsw"])
        check("[%s] главная: canonical на себя" % lang, h["canon"] == ORIGIN + pre + "/", h["canon"])
        check("[%s] главная: обе версии и x-default в hreflang" % lang, set(h["alts"]) == {"ru=" + ORIGIN + ("" if lang == "ru" else "") + "/", "en=" + ORIGIN + "/en/", "x-default=" + ORIGIN + "/"}, h["alts"])
        check("[%s] главная: подсказка о языке не показана при совпадении языка браузера" % lang, h["hint"] is False)
    if "provider_12389" in res and res["provider_12389"]["snaps"]:
        h = res["provider_12389"]["snaps"]["s0"]
        check("[%s] страница провайдера: переключатель ведёт на ту же страницу другой версии" % lang, h["langsw"] == opre + "/as12389", h["langsw"])
        check("[%s] страница провайдера: canonical на саму страницу" % lang, h["canon"] == ORIGIN + pre + "/as12389", h["canon"])
    if "lang_hint_other_browser" in res and len(res["lang_hint_other_browser"]["snaps"]) == 3:
        s0, s1, s2 = [res["lang_hint_other_browser"]["snaps"]["s%d" % i] for i in range(3)]
        check("[%s] язык браузера другой: подсказка показана" % lang, s0["hint"] is True)
        check("[%s] после закрытия подсказка скрыта" % lang, s1["hint"] is False)
        check("[%s] после перезагрузки выбор помнится, подсказки нет" % lang, s2["hint"] is False)
    if "lang_switch_click" in res and res["lang_switch_click"]["snaps"]:
        s0 = res["lang_switch_click"]["snaps"]["s0"]
        check("[%s] щелчок по переключателю открывает страницу провайдера другой версии" % lang, s0["lang"] == other and s0["canon"] == ORIGIN + opre + "/as12389", (s0["lang"], s0["canon"]))
    return fails


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--site", required=True)
    ap.add_argument("--lang", default="ru")
    ap.add_argument("--out")
    ap.add_argument("--compare")
    ap.add_argument("--check-en", action="store_true")
    ap.add_argument("--check-overflow", action="store_true", help="только проверить, что нет горизонтальной прокрутки")
    ap.add_argument("--only", help="часть имени сценария")
    ap.add_argument("--width", type=int, default=1000, help="ширина окна (для проверки узких экранов)")
    a = ap.parse_args()
    global WIDTH
    WIDTH = a.width
    res = {}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for sc in SCENARIOS:
            if a.only and a.only not in sc["name"]:
                continue
            t0 = time.time()
            try:
                res[sc["name"]] = run_scenario(browser, a.site, a.lang, sc)
            except Exception as e:
                res[sc["name"]] = {"snaps": {}, "errors": ["ИСКЛЮЧЕНИЕ СЦЕНАРИЯ: " + str(e)[:200].replace(chr(10), " ")]}
            print("  снято: %-26s %.1f с%s" % (sc["name"], time.time() - t0, ("  ОШИБКИ JS: " + str(res[sc["name"]]["errors"])) if res[sc["name"]]["errors"] else ""))
        browser.close()
    if a.out:
        json.dump(res, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1, sort_keys=True)
        print("записано:", a.out)
    fails = 0
    js_errs = [(k, v["errors"]) for k, v in res.items() if v["errors"]]
    if js_errs:
        print("ОШИБКИ JS на странице:", js_errs)
        fails += 1
    if a.compare:
        gold = json.load(open(a.compare, encoding="utf-8"))

        def norm(snap):
            """Переключатель языка и подсказка о языке появились после записи эталона: их исключаем, остальное должно совпасть до буквы."""
            if snap is None:
                return None
            d = dict(snap)
            for k in ("langsw", "hint", "canon", "alts"):         # поля, которых нет в эталоне
                d.pop(k, None)
            d["text"] =chr(10).join(l for l in d["text"].split(chr(10)) if l not in ("EN", "RU"))
            d["titles"] = [x for x in d["titles"] if x not in ("English version", "Русская версия", "Язык (Language)", "Language")]
            d["aria"] = [x for x in d["aria"] if x not in ("Close", "Закрыть")]
            d["hrefs"] = [h for h in d["hrefs"] if not (h == "/en/" or h.startswith("/en/") or h == "/en")]
            return d
        for name, v in res.items():
            if name not in gold:
                continue
            for sk, snap in v["snaps"].items():
                g = norm(gold[name]["snaps"].get(sk))
                snap = norm(snap)
                if g != snap:
                    fails += 1
                    print("РАЗЛИЧИЕ:", name, sk)
                    for key in snap:
                        if g is None or g.get(key) != snap[key]:
                            gv, nv = (g or {}).get(key), snap[key]
                            if key == "text":
                                gl, nl = (gv or "").split("\n"), nv.split("\n")
                                for i, (x, y) in enumerate(zip(gl, nl)):
                                    if x != y:
                                        print("   строка %d:\n     было:  %r\n     стало: %r" % (i, x, y))
                                        break
                                else:
                                    print("   длина текста: было %d строк, стало %d" % (len(gl), len(nl)))
                            else:
                                print("   поле %s:\n     было:  %r\n     стало: %r" % (key, str(gv)[:300], str(nv)[:300]))
        print("сравнение с эталоном:", "ОК, русская версия не изменилась" if not fails else "РАЗЛИЧИЙ: %d" % fails)
    if a.check_en:
        cyr = re.compile(r"[А-Яа-яЁё]")
        allowed_fixture = ("Лумен",)           # данных фикстур на русском, которые страница обязана показывать как есть: пока таких нет
        for name, v in res.items():
            if SC_BY_NAME[name].get("skip_cyr"):          # сценарии переключения языка: страница намеренно оказывается русской
                continue
            for sk, snap in v["snaps"].items():
                bad = []
                for key in ("text", "title", "desc"):
                    for line in str(snap[key]).split("\n"):
                        if cyr.search(line) and not SC_BY_NAME[name].get("skip_cyr"):
                            bad.append((key, line[:140]))
                for key in ("placeholders", "titles", "aria"):
                    for line in snap[key]:
                        if cyr.search(line) and line not in ("Русская версия", "Закрыть", "Язык (Language)"):      # переключатель на русский язык и подсказка о языке: по-русски намеренно
                            bad.append((key, line[:140]))
                bad_h = [h for h in snap["hrefs"] if h.startswith("/") and not h.startswith(("/en", "/api", "/#", "/logos", "/protocol", "/install", "/i")) and h != "/"]
                plain_as = [h for h in bad_h if re.fullmatch(r"/as\d+", h)]
                if len(plain_as) <= 2:           # две ссылки на русскую версию страницы провайдера: переключатель в шапке и подсказка о языке
                    bad_h = [h for h in bad_h if h not in plain_as]
                if snap["lang"] != "en":
                    bad.append(("lang", snap["lang"]))
                if bad or bad_h:
                    fails += 1
                    print("EN-ПРОБЛЕМЫ:", name, sk, bad[:6], bad_h[:4])
                if snap["overflow"][0] > snap["overflow"][1] + 1:
                    fails += 1
                    print("EN: горизонтальная прокрутка:", name, sk, snap["overflow"])
        print("проверка английской версии:", "ОК" if not fails else "ПРОБЛЕМ: %d" % fails)
    if a.check_overflow:
        for name, v in res.items():
            for sk, snap in v["snaps"].items():
                if snap["overflow"][0] > snap["overflow"][1] + 1:
                    fails += 1
                    print("горизонтальная прокрутка:", name, sk, snap["overflow"])
        print("проверка ширины %d: %s" % (WIDTH, "ОК" if not fails else "ПРОБЛЕМ: %d" % fails))
    fails += lang_asserts(res, a.lang, a.only)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
