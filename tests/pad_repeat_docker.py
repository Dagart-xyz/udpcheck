# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Повтор браузерной проверки длинных ответов с паузами: видно, теряет ли что-то сам сервис или это соседние запуски. Запуск в Docker (см. browsers_docker.py)."""
import sys
import time
from playwright.sync_api import sync_playwright

ENGINE = sys.argv[1] if len(sys.argv) > 1 else "chromium"
PAUSE = int(sys.argv[2]) if len(sys.argv) > 2 else 70
RUNS = int(sys.argv[3]) if len(sys.argv) > 3 else 3

with sync_playwright() as p:
    b = getattr(p, ENGINE).launch()
    for i in range(RUNS):
        ctx = b.new_context()
        page = ctx.new_page()
        page.route("**/api/v2/web/report", lambda r: r.abort())
        page.goto("https://dagart.xyz/", wait_until="load", timeout=60000)
        page.click("#go")
        t0 = time.time()
        while time.time() - t0 < 60:
            if page.evaluate("document.querySelectorAll('#udpweb .cutline').length") >= 5 and "Длинные" in page.evaluate("document.getElementById('udpweb').innerText"):
                break
            time.sleep(0.5)
        txt = page.evaluate("document.getElementById('udpweb').innerText").split("\n")
        print(ENGINE, "запуск", i + 1, "сек", round(time.time() - t0), [x.replace("длинные ответы: ", "") for x in txt if x.startswith("длинные")])
        sys.stdout.flush()
        ctx.close()
        if i + 1 < RUNS:
            time.sleep(PAUSE)
    b.close()
