# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Живая проверка английской версии на настоящем сайте (без моков): проверка из браузера, скриншоты, поиск русского текста.
В общую статистику результат не отправляется (запрос report перехватывается).
  docker run --rm -v <tests/i18n>:/t -v <каталог снимков>:/out -w /t mcr.microsoft.com/playwright/python:v1.49.1-noble
         sh -c "pip install -q playwright==1.49.1 && python live_en.py https://dagart.xyz" """
import re
import sys
import time

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://dagart.xyz"
cyr = re.compile(r"[А-Яа-яЁё]")
fails = 0

with sync_playwright() as p:
    b = p.chromium.launch()
    for name, w, h in (("desktop", 1100, 900), ("mobile", 375, 800)):
        ctx = b.new_context(locale="en-US", timezone_id="Europe/Moscow", viewport={"width": w, "height": h})
        page = ctx.new_page()
        page.route("**/api/v2/web/report", lambda r: r.abort())
        errs = []
        page.on("pageerror", lambda e: errs.append(str(e)))
        page.goto(BASE + "/en/", wait_until="load", timeout=60000)
        time.sleep(3)
        page.screenshot(path="/out/en-%s-1-top.png" % name)
        txt = page.evaluate("document.body.innerText")
        ru = [l for l in txt.split(chr(10)) if cyr.search(l)]
        print(name, "главная: русский текст в строках:", ru[:8])
        page.click("#go")
        t0 = time.time()
        while time.time() - t0 < 60 and page.evaluate("document.getElementById('go').disabled"):
            time.sleep(0.5)
        time.sleep(1)
        page.evaluate("document.getElementById('result').scrollIntoView()")
        page.screenshot(path="/out/en-%s-2-result.png" % name)
        txt = page.evaluate("document.getElementById('result').innerText")
        ru = [l for l in txt.split(chr(10)) if cyr.search(l)]
        print(name, "результат: русский текст:", ru[:8], "| кнопка:", page.evaluate("document.getElementById('go').innerText"))
        print(name, "ответ:", page.evaluate("document.getElementById('answer').innerText")[:300].replace(chr(10), " / "))
        page.goto(BASE + "/en/as12389", wait_until="load", timeout=60000)
        time.sleep(2.5)
        page.screenshot(path="/out/en-%s-3-provider.png" % name, full_page=True)
        txt = page.evaluate("document.body.innerText")
        ru = [l for l in txt.split(chr(10)) if cyr.search(l)]
        print(name, "провайдер: русский текст:", ru[:6], "| заголовок:", page.title())
        w_over = page.evaluate("[document.documentElement.scrollWidth, window.innerWidth]")
        print(name, "ширина:", w_over, "прокрутка:", "ЕСТЬ" if w_over[0] > w_over[1] + 1 else "нет", "| ошибки JS:", errs)
        fails += bool(errs) or w_over[0] > w_over[1] + 1
        ctx.close()
    b.close()
sys.exit(1 if fails else 0)
