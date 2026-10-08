#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Проверка читателя mmdb на реальных базах (запускать на сервере, где лежат базы).
Запуск:  python3 geo_selftest.py [путь_к_каталогу_с_udpcheck_server.py] [IP_для_проверки ...]
"""
import os
import sys
import time

here = sys.argv[1] if len(sys.argv) > 1 else "."
sys.path.insert(0, here)
import udpcheck_server as U

extra = sys.argv[2:]
fails = 0


def check(name, cond, info=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + ("   " + str(info) if not cond else ""))
    fails += 0 if cond else 1


g = U.GEO
check("обе базы загружены", set(g.db) == {"asn", "city"}, list(g.db))
for k, d in g.db.items():
    print("  %s: record_size=%s ip_version=%s node_count=%s build=%s" % (
        k, d.rec, d.ipv, d.node_count, d.meta.get("build_epoch")))

known = {
    "8.8.8.8": 15169,          # Google
    "1.1.1.1": 13335,          # Cloudflare
    "77.88.8.8": 13238,        # Яндекс
    "2001:4860:4860::8888": 15169,
}
for ip, asn in known.items():
    r = g.lookup(ip)
    print("   %-24s %s" % (ip, r))
    check("ASN %s -> %d" % (ip, asn), r.get("asn") == asn, r)

check("частный адрес -> пусто", g.lookup("192.168.1.1") == {} and g.lookup("10.0.0.1") == {})
check("кривой адрес не падает", g.lookup("999.1.1.1") == {})
check("IPv4-mapped IPv6 == IPv4", g.lookup("::ffff:8.8.8.8").get("asn") == 15169)

print("\nадреса из трассировки и этого сервера:")
for ip in extra:                  # свои адреса (трассировки, серверы) передаются аргументами командной строки
    r = g.lookup(ip)
    print("   %-16s AS%-7s %-34s %s %s %s" % (ip if ip not in extra else "[ваш адрес]", r.get("asn"), (r.get("org") or "")[:34],
                                           r.get("country"), r.get("city"), r.get("region")))

t = time.time()
n = 20000
import random
random.seed(1)
for _ in range(n):
    g.lookup("%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)))
dt = time.time() - t
print("\n%d случайных адресов за %.2f с (%.0f мкс на адрес)" % (n, dt, dt / n * 1e6))
rss = [l for l in open("/proc/self/status") if l.startswith(("VmRSS", "RssFile"))]
print("".join(rss).strip())
print("\nИТОГ:", "всё прошло" if fails == 0 else "ПРОВАЛОВ: %d" % fails)
sys.exit(1 if fails else 0)
