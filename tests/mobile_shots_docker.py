# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Снимки страницы в мобильных размерах (Playwright в Docker): главная, список провайдеров с поиском, страница провайдера, результат проверки.
Запуск: docker run --rm -v <каталог проекта>/tests:/t -v <каталог снимков>:/out -w /t mcr.microsoft.com/playwright/python:v1.49.1-noble
        sh -c "pip install -q playwright==1.49.1 && python mobile_shots_docker.py https://dagart.xyz"
"""
import sys
import time
from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://dagart.xyz"
OUT = "/out"

with sync_playwright() as p:
    for name, dev in (("iphone", "iPhone 13"), ("pixel", "Pixel 7")):
        kw = dict(p.devices[dev])
        kw["device_scale_factor"] = 1
        browser = (p.webkit if "iPhone" in dev else p.chromium).launch()
        ctx = browser.new_context(**kw)
        page = ctx.new_page()
        page.route("**/api/v2/web/report", lambda r: r.abort())
        page.goto(BASE + "/", wait_until="load", timeout=60000)
        time.sleep(2)
        page.screenshot(path="%s/%s-1-top.png" % (OUT, name))
        page.evaluate("document.getElementById('providers').scrollIntoView()")
        time.sleep(0.5)
        page.screenshot(path="%s/%s-2-providers.png" % (OUT, name))
        page.fill("#psearch", "мегафон")
        time.sleep(0.5)
        page.evaluate("document.getElementById('providers').scrollIntoView()")
        page.screenshot(path="%s/%s-3-search.png" % (OUT, name))
        page.fill("#psearch", "")
        page.evaluate("document.getElementById('pmore').scrollIntoView({block: 'center'})")
        time.sleep(0.3)
        page.screenshot(path="%s/%s-4-more-button.png" % (OUT, name))
        page.goto(BASE + "/as12389", wait_until="load", timeout=60000)
        time.sleep(2)
        page.screenshot(path="%s/%s-5-provider-page.png" % (OUT, name), full_page=True)
        page.goto(BASE + "/", wait_until="load", timeout=60000)
        page.click("#go")
        t0 = time.time()
        while time.time() - t0 < 40 and "Длинные" not in page.evaluate("document.getElementById('udpweb').innerText"):
            time.sleep(0.5)
        time.sleep(1)
        page.evaluate("document.getElementById('result').scrollIntoView()")
        page.screenshot(path="%s/%s-6-result.png" % (OUT, name), full_page=False)
        w = page.evaluate("[document.documentElement.scrollWidth, window.innerWidth]")
        print(name, "ширина страницы / окна:", w, "горизонтальная прокрутка:", "ЕСТЬ" if w[0] > w[1] + 1 else "нет")
        browser.close()
