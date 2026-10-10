# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Проверка замедлителя роботов (ops/udpcheck-tarpit.py): отдаёт ту же страницу с задержкой, соблюдает лимиты, не падает на мусоре."""
import http.client
import http.server
import os
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:300]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


BODY = (b"<html>" + b"x" * 60000 + b"</html>")


class Up(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen = []

    def do_GET(self):
        Up.seen.append((self.path, self.headers.get("Host"), self.headers.get("Connection"), self.headers.get("X-Forwarded-For")))
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 28082), Up)
threading.Thread(target=srv.serve_forever, daemon=True).start()


def start(**env):
    e = dict(os.environ, TARPIT_LISTEN="127.0.0.1:28081", TARPIT_UPSTREAM="127.0.0.1:28082", TARPIT_MIN_S="0.5", TARPIT_MAX_S="0.8", TARPIT_PAUSE_S="0.02",
             TARPIT_CHUNK="16384")
    e.update(env)
    p = subprocess.Popen([sys.executable, os.path.join(ROOT, "ops", "udpcheck-tarpit.py")], env=e, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", 28081), timeout=0.3).close()
            return p
        except OSError:
            time.sleep(0.1)
    return p


def get(ip="198.51.100.9", path="/", extra=None):
    t0 = time.time()
    c = http.client.HTTPConnection("127.0.0.1", 28081, timeout=30)
    h = {"X-Forwarded-For": ip, "Host": "dagart.xyz", "Connection": "keep-alive"}
    h.update(extra or {})
    c.request("GET", path, headers=h)
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b, time.time() - t0


p = start()
try:
    st, b, dt = get(path="/some/page")
    check("страница отдаётся целиком, как у внутреннего адреса", st == 200 and b == BODY, (st, len(b)))
    check("ответ задержан (не меньше 0,5 с)", dt >= 0.5, dt)
    check("внутреннему адресу уходит тот же путь и Host, соединение одноразовое", Up.seen[-1][0] == "/some/page" and Up.seen[-1][1] == "dagart.xyz" and Up.seen[-1][2] == "close", Up.seen[-1])

    res = []

    def worker(i):
        res.append(get(ip="203.0.113.7")[0])
    th = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    [t.start() for t in th]
    [t.join() for t in th]
    check("с одного адреса не больше 6 ожиданий одновременно: остальные 429 сразу", res.count(200) == 6 and res.count(429) == 4, res)
    st, b, dt = get(ip="203.0.113.7")
    check("после разгрузки тот же адрес снова обслуживается (с задержкой)", st == 200 and dt >= 0.5, (st, dt))

    # мусор и обрывы не роняют службу
    for junk in (b"", b"GARBAGE", b"GET / HTTP/1.1\r\n", b"\x00" * 20000 + b"\r\n\r\n", b"GET / HTTP/1.1\r\nHost: x\r\n" + b"A: " + b"b" * 30000 + b"\r\n\r\n"):
        try:
            s = socket.create_connection(("127.0.0.1", 28081), timeout=3)
            s.sendall(junk)
            s.close()
        except OSError:
            pass
    time.sleep(0.3)
    check("служба жива после мусора", get(ip="198.51.100.11")[0] == 200 and p.poll() is None)
finally:
    p.terminate()
    p.wait(timeout=5)

# общий предел: сверх него запросы идут без задержки
p = start(TARPIT_MAX_TOTAL="2", TARPIT_MIN_S="1.2", TARPIT_MAX_S="1.3")
try:
    out = {}

    def w(i):
        out[i] = get(ip="192.0.2.%d" % (10 + i))[2]
    th = [threading.Thread(target=w, args=(i,)) for i in range(5)]
    [t.start() for t in th]
    [t.join() for t in th]
    slow = sorted(out.values())[-2:]
    fast = sorted(out.values())[:3]
    check("при пределе 2 ожиданий медленных ровно два, остальные три быстрые", min(slow) >= 1.2 and max(fast) < 1.0, out)
finally:
    p.terminate()
    p.wait(timeout=5)
srv.shutdown()
print("\nИТОГ: " + ("всё прошло" if not fails else "ошибок: %d" % fails))
sys.exit(1 if fails else 0)
