# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Длинные STUN-ответы (проверка по длине пакета): длина ответа, разрешение от хаба, лимиты. Запуск: python tests/test_pad_local.py"""
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import udpcheck_server as S

FAILS = []


def check(name, cond, extra=""):
    print(("  OK   " if cond else "  FAIL ") + name + ("" if cond else "  " + str(extra)))
    if not cond:
        FAILS.append(name)


def request():
    return struct.pack("!HH", 1, 0) + S.STUN_COOKIE + os.urandom(12)


print("[длинные STUN-ответы]")
req = request()
short = S.stun_reply(req, ("203.0.113.5", 40000))
check("обычный ответ короткий (32 байта) и не изменился", len(short) == 32, len(short))
for size in (600, 1200, 1400):
    r = S.stun_reply(req, ("203.0.113.5", 40000), size)
    check("ответ нужной длины %d (с точностью до 4 байт)" % size, size - 4 <= len(r) <= size, len(r))
    ok = (struct.unpack("!HH", r[:4]) == (0x0101, len(r) - 20) and r[4:8] == S.STUN_COOKIE and r[8:20] == req[8:20]
          and r[20:24] == struct.pack("!HH", 0x0020, 8))
    check("размер %d: тип, длина, cookie и transaction id верные, XOR-MAPPED-ADDRESS первым" % size, ok)
    off, types = 20, []
    while off < len(r):
        t, ln = struct.unpack("!HH", r[off:off + 4])
        types.append(t)
        off += 4 + ln
    check("размер %d: атрибуты разбираются точно до конца, лишний атрибут необязательный (>=0x8000)" % size,
          off == len(r) and types == [0x0020, 0xC057], (off, len(r), types))
check("запрос чужого вида (не Binding) не получает ответа", S.stun_reply(struct.pack("!HH", 0x0101, 0) + S.STUN_COOKIE + os.urandom(12), ("1.2.3.4", 1), 600) is None)

# ---- настоящий сокет на порту длинных ответов
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(("127.0.0.1", 0))
port = srv.getsockname()[1]
S.PAD_BOUND[port] = 1200
cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
cli.settimeout(0.4)


def ask():
    cli.sendto(request(), ("127.0.0.1", port))
    srv.settimeout(1)
    try:
        data, addr = srv.recvfrom(2048)
    except socket.timeout:
        return "нет запроса"
    S.handle_udp(srv, data, addr)
    try:
        return cli.recvfrom(2048)[0]
    except socket.timeout:
        return None


check("адрес не разрешён хабом: длинного ответа нет (защита от усиления трафика)", ask() is None)
S.pad_allow("127.0.0.1", 60)
r = ask()
check("после разрешения хаба приходит ответ длиной ~1200", isinstance(r, bytes) and 1196 <= len(r) <= 1200, r if not isinstance(r, bytes) else len(r))
check("разрешение с истёкшим сроком не действует", (S.PAD_ALLOW.__setitem__("127.0.0.1", time.time() - 1), ask() is None)[1])
S.pad_allow("127.0.0.1", 60)
got = sum(1 for _ in range(170) if isinstance(ask(), bytes))
check("лимит: не больше 150 длинных ответов в минуту одному адресу", 148 <= got <= 150, got)
# не-STUN на порту длинных ответов игнорируется
S.PAD_ALLOW["127.0.0.1"] = time.time() + 60
S.rl_pad.hits.clear()
cli.sendto(b"x" * 100, ("127.0.0.1", port))
data, addr = srv.recvfrom(2048)
S.handle_udp(srv, data, addr)
try:
    cli.recvfrom(2048)
    junk = True
except socket.timeout:
    junk = False
check("посторонний (не STUN) пакет на порту длинных ответов не получает ответа", not junk)
S.PAD_BOUND.pop(port, None)

print()
print("ИТОГ: всё прошло" if not FAILS else "ИТОГ: ПРОВАЛЕНО %d: %s" % (len(FAILS), "; ".join(FAILS)))
sys.exit(1 if FAILS else 0)
