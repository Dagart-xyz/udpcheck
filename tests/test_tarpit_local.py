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
# запросы-атаки (X-Probe): 404 с задержкой, страницу не отдаём, строка PROBE в журнале
import json
fake = {"198.51.100.20": ["crawl-198-51-100-20.googlebot.com", ["198.51.100.20"]],      # настоящий: имя Google, прямой DNS ведёт на тот же адрес
        "198.51.100.21": ["evil.example.net", ["198.51.100.21"]],                         # чужое имя
        "198.51.100.22": ["crawl-x.googlebot.com", ["203.0.113.99"]],                      # имя Google, но прямой DNS ведёт на другой адрес (подделка записи)
        "2001:db8::20": ["spider-2001.yandex.com", ["2001:db8::20"]]}
p = start(TARPIT_PROBE_MIN_S="0.6", TARPIT_PROBE_MAX_S="0.8", TARPIT_FAKE_DNS=json.dumps(fake))
try:
    n0 = len(Up.seen)
    st, b, dt = get(ip="198.51.100.30", path="/wp-login.php?x=1", extra={"X-Probe": "1"})
    check("запрос-атака: 404 и тело not found, не страница", st == 404 and b == b"not found\n", (st, b[:40]))
    check("запрос-атака задержан (не меньше 0,6 с)", dt >= 0.6, dt)
    check("запрос-атака не уходит во внутренний адрес сайта", len(Up.seen) == n0, Up.seen[n0:])
    # цепочка в X-Forwarded-For: берётся последний адрес (его ставит Caddy)
    get(ip="203.0.113.1, 198.51.100.31", path="/.env", extra={"X-Probe": "1"})
    # нечитаемый адрес в журнал не попадает
    get(ip="not-an-ip", path="/.git/config", extra={"X-Probe": "1"})
    # попытка вписать вторую строку журнала через путь: пробелы и управляющие символы превращаются в _
    get(ip="198.51.100.32", path="/x%20PROBE%20203.0.113.9%20y", extra={"X-Probe": "1"})
    s2 = socket.create_connection(("127.0.0.1", 28081), timeout=10)
    s2.sendall(b"GET /a\x01b\xffPROBE 8.8.8.8 HTTP/1.1\r\nHost: d\r\nX-Forwarded-For: 198.51.100.33\r\nX-Probe: 1\r\n\r\n")
    s2.settimeout(10)
    s2.recv(4096)
    s2.close()
    # без заголовка X-Probe строки в журнале не появляется, даже если путь похож на атаку
    get(ip="198.51.100.34", path="/wp-login.php")

    # поисковики: настоящий проходит без задержки, подделки идут медленным путём
    H = {"X-Claimed-Bot": "1"}
    st, b, dt = get(ip="198.51.100.20", path="/p", extra=H)
    check("настоящий Googlebot (обратное имя Google + прямой DNS совпал): страница сразу", st == 200 and b == BODY and dt < 0.4, (st, dt))
    st, b, dt = get(ip="2001:db8::20", path="/p", extra=H)
    check("настоящий Яндекс по IPv6: сразу", st == 200 and dt < 0.4, (st, dt))
    for ip, why in (("198.51.100.21", "чужое обратное имя"), ("198.51.100.22", "прямой DNS ведёт на другой адрес"), ("198.51.100.23", "нет обратной записи")):
        st, b, dt = get(ip=ip, path="/p", extra=H)
        check("подделка (%s): та же страница, но с задержкой" % why, st == 200 and b == BODY and dt >= 0.5, (st, dt))
    st, b, dt = get(ip="198.51.100.20", path="/p")
    check("без заголовка X-Claimed-Bot проверки нет: обычный путь с задержкой", st == 200 and dt >= 0.5, (st, dt))
finally:
    p.terminate()
    out = p.stdout.read().decode("utf-8", "replace")
    p.wait(timeout=5)
lines = [l for l in out.splitlines() if l.strip()]
check("в журнале только строки PROBE", all(l.startswith("PROBE ") for l in lines), lines)
check("строка PROBE: адрес и запрос без пробелов", "PROBE 198.51.100.30 GET_/wp-login.php?x=1_HTTP/1.1" in lines, lines)
check("цепочка X-Forwarded-For: записан последний адрес", any(l.startswith("PROBE 198.51.100.31 ") for l in lines) and not any(l.startswith("PROBE 203.0.113.1 ") for l in lines), lines)
check("нечитаемый адрес в журнал не попал", not any("not-an-ip" in l or l.startswith("PROBE ? ") for l in lines), lines)
check("через путь нельзя вписать чужой адрес: на запрос одна строка, адрес первый", sum(1 for l in lines if "198.51.100.32" in l) == 1 and sum(1 for l in lines if "198.51.100.33" in l) == 1
      and not any(l.startswith("PROBE 203.0.113.9") or l.startswith("PROBE 8.8.8.8") for l in lines), lines)
check("без X-Probe записи нет", not any("198.51.100.34" in l for l in lines), lines)
check("всего ровно 4 строки (по числу запросов-атак с читаемым адресом)", len(lines) == 4, lines)

# проверка DNS по частям (без сети): сбой DNS не наказывает
import importlib.util
spec = importlib.util.spec_from_file_location("tarpit", os.path.join(ROOT, "ops", "udpcheck-tarpit.py"))
tp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tp)
tp.FAKE_DNS = None
orig = socket.gethostbyaddr
try:
    def boom(ip):
        raise socket.gaierror(socket.EAI_AGAIN, "temporary failure")
    socket.gethostbyaddr = boom
    check("временный сбой DNS: ответ «не знаю» (None), а не «подделка»", tp._dns_check("198.51.100.50") is None)

    def nx(ip):
        raise socket.herror(1, "Unknown host")
    socket.gethostbyaddr = nx
    check("нет обратной записи: подделка (False)", tp._dns_check("198.51.100.50") is False)
finally:
    socket.gethostbyaddr = orig


srv.shutdown()
print("\nИТОГ: " + ("всё прошло" if not fails else "ошибок: %d" % fails))
sys.exit(1 if fails else 0)
