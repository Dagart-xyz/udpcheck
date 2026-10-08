# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Фаззинг: случайные и намеренно кривые UDP-пакеты в порты STUN/эха и мусорные HTTP-запросы в хаб.
Сервер не должен падать, зависать, писать трассировки в stderr и отвечать 500 на мусор; после атаки обязан отвечать на нормальные запросы.
Запуск: python tests/fuzz_local.py"""
import json
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:300]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


tmp = tempfile.mkdtemp(prefix="udpc_fuzz_")
tfile = os.path.join(tmp, "targets.json")
json.dump([{"code": "RU-T", "name": "ru test", "country": "XX", "ip": "127.0.0.1", "ports": [19993, 19777, 19321], "secret": "aa" * 16, "tcp_port": 18443}], open(tfile, "w"))
env = dict(os.environ, UDPCHECK_TRUSTED_PROXIES="", UDPCHECK_GEO_DIR=os.path.join(tmp, "nogeo"), UDPCHECK_ALLOW_NON_GLOBAL="1", UDPCHECK_DEFAULT_COUNTRY="XX",
           UDPCHECK_HTTP_PORT="18090", UDPCHECK_UDP_BIND="127.0.0.1", UDPCHECK_UDP_PORTS="19993,19777,19321", UDPCHECK_PAD_PORTS="19600:600",
           UDPCHECK_TARGET_ID="RU-T", UDPCHECK_TARGET_SECRET="aa" * 16, UDPCHECK_HUB_URL="http://127.0.0.1:18090/udpcheck", UDPCHECK_TARGET_TCP_PORT="18443",
           UDPCHECK_HUB_DB=os.path.join(tmp, "hub.db"), UDPCHECK_HUB_TARGETS=tfile, UDPCHECK_BEAT_SECRET="b" * 32)
proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "udpcheck_server.py")], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
HUB = "http://127.0.0.1:18090/udpcheck"


def up():
    for _ in range(75):
        try:
            urllib.request.urlopen(HUB + "/api/v2/version", timeout=2)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def stun_ok(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.sendto(struct.pack("!HHI", 1, 0, 0x2112A442) + os.urandom(12), ("127.0.0.1", port))
    try:
        d, _ = s.recvfrom(2048)
        return len(d) >= 20 and d[0:2] == b"\x01\x01"
    except OSError:
        return False
    finally:
        s.close()


random.seed(7)
try:
    check("сервер поднялся", up())
    check("до атаки: STUN отвечает на всех портах", all(stun_ok(p) for p in (19993, 19777, 19321)))

    print("[UDP: случайный мусор и кривые STUN-пакеты]")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cookie = struct.pack("!I", 0x2112A442)
    pk = []
    for _ in range(1500):                                   # чистый мусор разной длины
        pk.append(os.urandom(random.choice((0, 1, 3, 19, 20, 21, 28, 100, 576, 1200, 1472, 4000, 9000))))
    for t in (0x0001, 0x0101, 0x0011, 0xFFFF, 0x0003):      # похоже на STUN, но поля врут
        for ln in (0, 1, 3, 4, 8, 65535, 0x8000):
            for body in (b"", os.urandom(8), os.urandom(40), b"\xc0\x57\x00\x04abcd", b"\xc0\x57\xff\xff", b"\x00\x20\x00\x08\x00\x01\x00\x00\x00\x00\x00\x00"):
                pk.append(struct.pack("!HH", t, ln) + cookie + os.urandom(12) + body)
    for _ in range(300):                                    # верный заголовок, случайные атрибуты
        attrs = b"".join(struct.pack("!HH", random.randint(0, 0xFFFF), random.randint(0, 70)) + os.urandom(random.randint(0, 40)) for _ in range(random.randint(1, 6)))
        pk.append(struct.pack("!HH", 1, len(attrs)) + cookie + os.urandom(12) + attrs)
    pk.append(b"UDPC" + os.urandom(40))                     # похоже на эхо-пакет без верной подписи
    pk.append(b"UDPC\x02\x00" + os.urandom(100))
    for p in pk:
        for port in (19993, 19777, 19321, 19600):
            try:
                s.sendto(p, ("127.0.0.1", port))
            except OSError:
                pass
    time.sleep(1.5)
    s.close()
    check("процесс жив после %d пакетов в 4 порта" % len(pk), proc.poll() is None)
    time.sleep(61 if False else 0)
    # лимит частоты на адрес сбрасывается не сразу: пробуем подождать, пока снимут ограничение
    ok = False
    for _ in range(40):
        if all(stun_ok(p) for p in (19993, 19777, 19321)):
            ok = True
            break
        time.sleep(2)
    check("после атаки STUN снова отвечает на нормальный запрос", ok)

    print("[HTTP: мусорные запросы прямо в хаб]")

    def raw(data, wait=0.4):
        sk = socket.create_connection(("127.0.0.1", 18090), timeout=5)
        try:
            sk.sendall(data)
        except OSError:
            pass
        time.sleep(wait)
        sk.settimeout(0.8)
        out = b""
        try:
            while True:
                d = sk.recv(65536)
                if not d:
                    break
                out += d
        except OSError:
            pass
        sk.close()
        return out
    junk = [b"", b"\r\n\r\n", b"GARBAGE\r\n\r\n", b"GET\r\n\r\n", b"GET / HTTP/9.9\r\n\r\n", b"GET /" + b"A" * 70000 + b" HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET /udpcheck/api/v2/version HTTP/1.1\r\nHost: x\r\n" + b"X: " + b"B" * 70000 + b"\r\n\r\n", b"GET /udpcheck/api/v2/version HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: " + b"1.1.1.1, " * 5000 + b"\r\n\r\n",
            b"GET /udpcheck/api/v2/providers/%00 HTTP/1.1\r\nHost: x\r\n\r\n", b"GET /udpcheck/api/v2/providers/99999999999999999999999 HTTP/1.1\r\nHost: x\r\n\r\n",
            b"POST /udpcheck/api/v2/node/result HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\n", b"POST /udpcheck/api/v2/node/result HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999\r\n\r\n",
            b"POST /udpcheck/api/v2/node/result HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!", b"GET /udpcheck/api/v2/version\x00 HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET /udpcheck/api/v2/stats?hours=-1 HTTP/1.1\r\nHost: x\r\n\r\n", b"GET /udpcheck/api/v2/stats?hours=%ff%fe HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET /udpcheck/api/v2/web/me HTTP/1.1\r\nHost: x\r\nX-Client: " + b"\xff" * 40 + b"\r\n\r\n", b"GET /udpcheck/api/v2/health HTTP/1.1\r\nHost: x\r\nX-Beat: \xff\xfe\xfd\r\n\r\n",
            b"POST /udpcheck/api/v2/names/review HTTP/1.1\r\nHost: x\r\nX-Beat: \xc3\x28\r\nContent-Length: 2\r\n\r\n{}",
            b"GET /udpcheck/api/v2/nodes HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + b"z" * 5000 + b"\r\n\r\n",
            b"POST /udpcheck/api/v2/node/poll HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer \xff\xfe\r\nContent-Length: 0\r\n\r\n"]
    bad500 = []
    for j in junk:
        r = raw(j)
        if r.startswith(b"HTTP/1.1 500"):
            bad500.append((j[:70], r[:60]))
    check("мусорные запросы не дают 500", not bad500, bad500)
    check("процесс жив после HTTP-мусора", proc.poll() is None)
    # медленные соединения: сотня открытых и молчащих не мешает нормальным
    slow = [socket.create_connection(("127.0.0.1", 18090), timeout=5) for _ in range(150)]
    for sk in slow:
        sk.sendall(b"GET /udpcheck/api/v2/version HTTP/1.1\r\nHost: x\r\nX-Slow: ")
    t0 = time.time()
    try:
        urllib.request.urlopen(HUB + "/api/v2/version", timeout=5).read()
        check("при 150 зависших соединениях нормальный запрос обслуживается (%.2f с)" % (time.time() - t0), time.time() - t0 < 3)
    except Exception as e:
        check("при 150 зависших соединениях нормальный запрос обслуживается", False, e)
    for sk in slow:
        sk.close()
    check("хаб отвечает после всего", up())
finally:
    proc.terminate()
    try:
        _o, err = proc.communicate(timeout=8)
    except Exception:
        proc.kill()
        _o, err = proc.communicate()
    err = (err or b"").decode("utf-8", "replace")
    check("в stderr сервера нет трассировок ошибок", "Traceback" not in err, err[-600:])
print("\nИТОГ: " + ("всё прошло" if not fails else "ошибок: %d" % fails))
sys.exit(1 if fails else 0)
