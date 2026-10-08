# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Нагрузочная проверка хаба: тестовый хаб и опорный сервер на этой же машине, виртуальные посетители проходят браузерную проверку
(страница, API, UDP-запросы к серверам, отправка результата). Процессы сервера привязаны к одному ядру, нагрузка идёт с другого.
Нужны Linux и root (порты 777 и 47321 привилегированные), поэтому запускается в Docker:

  docker run --rm --cpus=2 --memory=1g -v <каталог проекта>:/p:ro python:3.12-slim python /p/tests/load_local.py [уровни: посетителей в минуту через запятую]

Результат: на каждом уровне задержки по шагам (p50 / p95 / p99), доля ошибок, загрузка ядра и память хаба.
"""
import http.client
import json
import os
import random
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.abspath(os.path.join(HERE, ".."))
LEVELS = [int(x) for x in (sys.argv[1] if len(sys.argv) > 1 else "30,120,360,900").split(",")]
SECONDS = int(os.environ.get("LOAD_SECONDS", "40"))
COOKIE = bytes((0x21, 0x12, 0xA4, 0x42))
HUB_PORT = 18080

work = tempfile.mkdtemp(prefix="udpc_load_")
for f in ("udpcheck_server.py", "udpcheck_v2.py"):
    shutil.copy(os.path.join(SRC, f), os.path.join(work, f))
secA, secB = secrets.token_hex(32), secrets.token_hex(32)
targets = [
    {"code": "RU-T", "name": "ru test", "country": "XX", "ip": "127.0.0.2", "ports": [993, 777, 47321], "secret": secA, "tcp_port": 18443},
    {"code": "F-T", "name": "foreign test", "country": "YY", "ip": "127.0.0.3", "ports": [993, 777, 47321], "secret": secB, "tcp_port": 28443},
]
tfile = os.path.join(work, "targets.json")
json.dump(targets, open(tfile, "w"))
base = dict(os.environ, UDPCHECK_TRUSTED_PROXIES="127.0.0.1", UDPCHECK_GEO_DIR=os.path.join(work, "nogeo"), UDPCHECK_ALLOW_NON_GLOBAL="1",
            UDPCHECK_DEFAULT_COUNTRY="XX", UDPCHECK_PAD_PORTS="3478:600,19302:1200", UDPCHECK_HUB_URL="http://127.0.0.1:%d/udpcheck" % HUB_PORT,
            UDPCHECK_SITE_DIR=work)


def pin(cpu):
    return lambda: os.sched_setaffinity(0, {cpu})


def start(http_port, bind, tid, sec, tcp, extra=None):
    env = dict(base, UDPCHECK_HTTP_PORT=str(http_port), UDPCHECK_UDP_BIND=bind, UDPCHECK_TARGET_ID=tid, UDPCHECK_TARGET_SECRET=sec,
               UDPCHECK_TARGET_TCP_PORT=str(tcp))
    env.update(extra or {})
    return subprocess.Popen([sys.executable, os.path.join(work, "udpcheck_server.py")], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            preexec_fn=pin(0))


hub = start(HUB_PORT, "127.0.0.2", "RU-T", secA, 18443, {"UDPCHECK_HUB_DB": os.path.join(work, "hub.db"), "UDPCHECK_HUB_TARGETS": tfile})
tgt = start(18081, "127.0.0.3", "F-T", secB, 28443)
os.sched_setaffinity(0, {1})          # сам генератор нагрузки на другом ядре


def call(method, path, ip, body=None, cid=None, timeout=30):
    c = http.client.HTTPConnection("127.0.0.1", HUB_PORT, timeout=timeout)
    h = {"X-Forwarded-For": ip}
    if cid:
        h["X-Client"] = cid
    data = json.dumps(body).encode() if body is not None else None
    t0 = time.time()
    try:
        c.request(method, "/udpcheck" + path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        st = r.status
    except OSError:
        return 0, None, time.time() - t0
    finally:
        c.close()
    try:
        return st, json.loads(raw or b"{}"), time.time() - t0
    except ValueError:
        return st, None, time.time() - t0


for _ in range(100):
    if call("GET", "/api/v1/health", "127.1.0.1")[0] == 200:
        break
    time.sleep(0.2)
else:
    sys.exit("хаб не поднялся: " + hub.stderr.read().decode(errors="replace")[-500:])
# заполняем базу так, как она выглядит на боевом хабе: ~110 провайдеров, ~5000 проверок посетителей за сутки, ~8000 трассировок
import sqlite3
_db = sqlite3.connect(os.path.join(work, "hub.db"), timeout=30)
_now = int(time.time())
_orgs = ["Org %d LLC" % i for i in range(1, 114)]
for i in range(5000):
    a = random.randint(1, 113)
    _db.execute("INSERT INTO webchecks(ts, asn, verdict, data, org, cid) VALUES(?,?,?,?,?,?)",
                (_now - random.randint(0, 86400), 64000 + a, random.choice(["NO_BLOCK"] * 8 + ["FOREIGN_IN_CUT", "FOREIGN_PARTIAL"]),
                 json.dumps([{"code": "RU-T", "ok": 6, "n": 6, "seen": 6, "pad": [[600, 3, 3], [1200, 3, 3]]}]), _orgs[a - 1], secrets.token_hex(8)))
for i in range(8000):
    a = random.randint(1, 113)
    _db.execute("INSERT INTO traces(ts, asn, src_org, src, target, kind, method, last_asn, last_org, last_ttl, reached, path) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (_now - random.randint(0, 6 * 86400), 64000 + a, _orgs[a - 1], "web", "F-T", "foreign", "icmp", 65000 + random.randint(1, 30), "Transit", 9, 0, "[]"))
_db.commit()
_db.close()
time.sleep(5)           # цели успевают опросить хаб и сообщить порты длинных ответов


def stun_once(src_ip, dst_ip, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.bind((src_ip, 0))
        s.sendto(struct.pack("!HH", 1, 0) + COOKIE + os.urandom(12), (dst_ip, port))
        s.recvfrom(2048)
        return True
    except OSError:
        return False
    finally:
        s.close()


STATS = {}
LOCK = threading.Lock()


def note(step, dt, status):
    with LOCK:
        e = STATS.setdefault(step, {"t": [], "err": 0, "limit": 0, "n": 0})
        e["n"] += 1
        e["t"].append(dt)
        if status == 429:
            e["limit"] += 1
        elif status == 0 or status >= 500:
            e["err"] += 1


def visitor(n):
    ip = "127.1.%d.%d" % (n // 250 % 250, n % 250 + 1)
    cid = secrets.token_hex(16)
    for step, path in (("страница: список провайдеров", "/api/v2/providers"), ("страница: журнал", "/api/v2/journal"), ("страница: узлы", "/api/v2/nodes"),
                       ("кто вы (web/me)", "/api/v2/web/me")):
        st, _b, dt = call("GET", path, ip, cid=cid)
        note(step, dt, st)
    st, body, dt = call("GET", "/api/v2/web/stun", ip, cid=cid)
    note("web/stun (с разрешением длинных ответов)", dt, st)
    if st != 200 or not body:
        return
    lost = 0
    t0 = time.time()
    for t in body["targets"]:
        if t.get("community"):
            continue
        for port in list(t["ports"]) + [p["port"] for p in t.get("pad", [])]:
            if not any(stun_once(ip, t["ip"], port) for _ in range(2)):
                lost += 1
    note("UDP: все запросы посетителя к серверам", time.time() - t0, 0 if lost else 200)
    st, sk, dt = call("POST", "/api/v2/web/stunseen", ip, cid=cid)
    note("stunseen: старт", dt, st)
    if st == 202:
        for _ in range(9):
            st, g, dt = call("GET", "/api/v2/web/stunseen/" + sk["id"], ip, cid=cid)
            note("stunseen: опрос", dt, st)
            if st == 200 and g.get("done"):
                break
            time.sleep(0.4)
    st, _b, dt = call("POST", "/api/v2/web/report", ip, body={"verdict": "NO_BLOCK", "results": [{"code": "RU-T", "ok": 6, "n": 6, "seen": 6}]}, cid=cid)
    note("web/report", dt, st)


def cpu_rss(pid):
    with open("/proc/%d/stat" % pid) as fh:
        parts = fh.read().rsplit(")", 1)[1].split()
    ticks = int(parts[11]) + int(parts[12])
    rss = 0
    with open("/proc/%d/status" % pid) as fh:
        for ln in fh:
            if ln.startswith("VmRSS"):
                rss = int(ln.split()[1]) // 1024
    return ticks / os.sysconf("SC_CLK_TCK"), rss


def pct(a, p):
    a = sorted(a)
    return a[min(len(a) - 1, int(len(a) * p))] if a else 0


counter = [0]
print("Нагрузочная проверка: %d с на уровень, хаб привязан к одному ядру" % SECONDS)
for rate in LEVELS:
    STATS.clear()
    c0, _r = cpu_rss(hub.pid)
    w0 = time.time()
    threads, peak_rss = [], 0
    n = 0
    next_at = w0
    while time.time() - w0 < SECONDS:
        now = time.time()
        if now >= next_at:
            counter[0] += 1
            th = threading.Thread(target=visitor, args=(counter[0],), daemon=True)
            th.start()
            threads.append(th)
            n += 1
            next_at += random.expovariate(rate / 60.0)
        else:
            time.sleep(min(0.01, next_at - now))
        if n % 20 == 0:
            peak_rss = max(peak_rss, cpu_rss(hub.pid)[1])
    t_end = time.time()
    for th in threads:
        th.join(timeout=60)
    c1, rss = cpu_rss(hub.pid)
    peak_rss = max(peak_rss, rss)
    wall = t_end - w0
    errs = sum(e["err"] for e in STATS.values())
    total = sum(e["n"] for e in STATS.values())
    print("\n=== %d посетителей в минуту (запущено %d, запросов %d) ===" % (rate, n, total))
    print("ядро хаба занято на %.0f%%, память хаба до %d МБ, ошибок: %d, отказов по лимиту (429): %d" % ((c1 - c0) / wall * 100, peak_rss, errs, sum(e["limit"] for e in STATS.values())))
    for step, e in STATS.items():
        print("  %-46s p50 %5.0f мс | p95 %5.0f мс | p99 %5.0f мс | запросов %d, ошибок %d, лимит %d" % (step, pct(e["t"], .5) * 1000, pct(e["t"], .95) * 1000, pct(e["t"], .99) * 1000, e["n"], e["err"], e["limit"]))
    sys.stdout.flush()
    time.sleep(3)
hub.terminate()
tgt.terminate()
err = hub.stderr.read().decode(errors="replace").strip()
print("\nпечатал ли хаб что-то в stderr:", err[-300:] if err else "нет")
shutil.rmtree(work, ignore_errors=True)
