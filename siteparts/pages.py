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


def render_index(lang):
    tpl = open(os.path.join(HERE, "index.tpl.html"), encoding="utf-8").read()
    html = ST.HTML[lang]
    out = re.sub(r"@\{(\w+)\}", lambda m: html[m.group(1)], tpl)          # строго: нет ключа в словаре, нет сборки
    jsd = json.dumps(ST.js_dict(lang), ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    ru = lang == "ru"
    for k, v in (("@@I18N@@", jsd), ("@@LANG@@", lang), ("@@LP@@", "" if ru else "/en"), ("@@ALTHOME@@", "/en/" if ru else "/"),
                 ("@@ALTLANG@@", "en" if ru else "ru"), ("@@ORIGIN@@", ORIGIN), ("@@OGLOCALE@@", "ru_RU" if ru else "en_US")):
        out = out.replace(k, v)
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
