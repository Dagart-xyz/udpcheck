# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
import json, sys, time
from playwright.sync_api import sync_playwright

def run(p, name, device=None):
    b = getattr(p, name).launch()
    kw = dict(p.devices[device]) if device else {}
    ctx = b.new_context(**kw)
    page = ctx.new_page()
    page.route("**/api/v2/web/report", lambda r: r.abort())      # в общую статистику эти пробные проверки не отправляем
    out = {"engine": name, "device": device}
    try:
        page.goto("https://dagart.xyz/", wait_until="load", timeout=60000)
        out["webrtc"] = page.evaluate("typeof RTCPeerConnection")
        page.click("#go")
        t0 = time.time()
        while time.time() - t0 < 60:
            n = page.evaluate("document.querySelectorAll('#udpweb .cutline').length")
            if n >= 5:
                break
            time.sleep(1)
        out["seconds"] = round(time.time() - t0)
        out["web"] = page.evaluate("document.getElementById('udpweb').innerText")
        out["answer"] = page.evaluate("document.getElementById('answer').innerText.slice(0,160)")
    except Exception as e:
        out["error"] = repr(e)[:300]
    b.close()
    return out

with sync_playwright() as p:
    for args in (("chromium", None), ("chromium", "Pixel 7"), ("firefox", None), ("webkit", None), ("webkit", "iPhone 13")):
        r = run(p, *args)
        print(json.dumps(r, ensure_ascii=False))
        sys.stdout.flush()
