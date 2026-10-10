# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Сборка страниц сайта на двух языках из шаблона siteparts/index.tpl.html и текстов siteparts/strings.py.
Русский: site/index.html (адрес /), английский: site/en/index.html (адрес /en/). Здесь же robots.txt и sitemap.xml."""
import datetime
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SITE = os.path.join(ROOT, "site")
sys.path.insert(0, HERE)
import strings as ST

ORIGIN = os.environ.get("UDPCHECK_ORIGIN", "https://dagart.xyz")

# Языки сайта: (код, название на самом языке, префикс адреса). Для нового языка добавьте строку, словарь в strings.py и страницу в build();
# выпадающий список в шапке и ссылки в нём строятся отсюда. Название пишется на своём языке всегда, его не переводят.
LANGS = [("ru", "Русский", ""), ("en", "English", "/en")]
GLOBE = ('<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.3"/><path d="M1.7 8h12.6M8 1.7c1.8 1.8 2.7 3.9 2.7 6.3S9.8 12.5 8 14.3C6.2 12.5 5.3 10.4 5.3 8S6.2 3.5 8 1.7z"/></svg>')
CHEVRON = '<svg class="chev" viewBox="0 0 10 10" aria-hidden="true"><path d="M2 3.5l3 3 3-3"/></svg>'


def lang_menu(lang, title):
    items = []
    for code, name, pfx in LANGS:
        if code == lang:
            items.append('<li><span class="cur" aria-current="true" lang="%s">%s</span></li>' % (code, name))
        else:
            items.append('<li><a href="%s/" data-lang="%s" data-pfx="%s" hreflang="%s" lang="%s">%s</a></li>' % (pfx, code, pfx, code, code, name))
    return ('<div class="langmenu" id="langmenu"><button type="button" id="langbtn" aria-haspopup="true" aria-expanded="false" aria-controls="langlist" title="%s">%s<span>%s</span>%s</button>'
            '<ul id="langlist" hidden>%s</ul></div>' % (title, GLOBE, lang.upper(), CHEVRON, "".join(items)))


def render_index(lang):
    tpl = open(os.path.join(HERE, "index.tpl.html"), encoding="utf-8").read()
    html = ST.HTML[lang]
    out = re.sub(r"@\{(\w+)\}", lambda m: html[m.group(1)], tpl)          # строго: нет ключа в словаре, нет сборки
    jsd = json.dumps(ST.js_dict(lang), ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    ru = lang == "ru"
    for k, v in (("@@I18N@@", jsd), ("@@LANG@@", lang), ("@@LP@@", "" if ru else "/en"), ("@@ALTHOME@@", "/en/" if ru else "/"),
                 ("@@ALTLANG@@", "en" if ru else "ru"), ("@@ORIGIN@@", ORIGIN), ("@@OGLOCALE@@", "ru_RU" if ru else "en_US")):
        out = out.replace(k, v)
    out = out.replace("@@LANGMENU@@", lang_menu(lang, html["langsw_title"]))
    assert "@@" not in out and not re.search(r"@\{\w+\}", out), "в странице остались неподставленные метки"
    return out


def build():
    for lang, path in (("ru", os.path.join(SITE, "index.html")), ("en", os.path.join(SITE, "en", "index.html"))):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w", encoding="utf-8", newline="\n").write(render_index(lang))
    # карта сайта: главная и документы на двух языках с взаимными ссылками; страницы провайдеров открыты для обхода, но закрыты от индексации заголовком X-Robots-Tag (Caddyfile)
    today = datetime.date.today().isoformat()
    pages = [("/", "/en/"), ("/privacy", "/en/privacy"), ("/terms", "/en/terms")]
    sm = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">']
    for ru_p, en_p in pages:
        for p in (ru_p, en_p):
            sm.append("<url><loc>%s%s</loc><lastmod>%s</lastmod>" % (ORIGIN, p, today))
            sm.append('<xhtml:link rel="alternate" hreflang="ru" href="%s%s"/><xhtml:link rel="alternate" hreflang="en" href="%s%s"/>'
                      '<xhtml:link rel="alternate" hreflang="x-default" href="%s%s"/></url>' % (ORIGIN, ru_p, ORIGIN, en_p, ORIGIN, ru_p))
    sm.append("</urlset>")
    open(os.path.join(SITE, "sitemap.xml"), "w", encoding="utf-8", newline="\n").write("\n".join(sm) + "\n")
    open(os.path.join(SITE, "robots.txt"), "w", encoding="utf-8", newline="\n").write(
        "User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /udpcheck/\n\nSitemap: %s/sitemap.xml\n" % ORIGIN)


if __name__ == "__main__":
    build()
    print("страницы собраны: site/index.html, site/en/index.html, sitemap.xml, robots.txt")
