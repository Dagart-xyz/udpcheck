#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Здоровье серверов: (A) хаб сам проверяет UDP-ответ серверов проекта и добровольцев и временно убирает молчащие из выдачи,
(B) разбор проверок посетителей: сервер не отвечает людям, у которых другие серверы отвечают. И тревоги наблюдателя по обоим.
Серверы изображают локальные UDP-ответчики (настоящие пакеты через 127.0.0.1). Запуск: python tests/test_health_local.py"""
import importlib.util
import json
import os
import socket
import sqlite3
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)
import udpcheck_v2 as V

fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:400]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


class Responder:
    """Отвечает на пакет UDPC2 тем же пакетом с флагом «ответ», как опорный сервер. stop() закрывает порт: сервер «молчит»."""
    def __init__(self):
        self.sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sk.bind(("127.0.0.1", 0))
        self.port = self.sk.getsockname()[1]
        self.on = True
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        self.sk.settimeout(0.2)
        while True:
            try:
                d, a = self.sk.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            if self.on and len(d) >= V.UDP2.size:
                r = bytearray(d)
                r[5] = 1
                try:
                    self.sk.sendto(bytes(r), a)
                except OSError:
                    pass


def dead_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Geo:
    def lookup(self, ip, force=False):
        return {}


class Srv:
    GEO = Geo()
    ALLOW_NON_GLOBAL = True


V.S = Srv
V.DB = sqlite3.connect(":memory:", check_same_thread=False)
V.DB.executescript(V.SCHEMA)
V.migrate(V.DB)
V.HEALTH_FAILS = 3

rA, rC, rV = Responder(), Responder(), Responder()
pB, pW = dead_port(), dead_port()
V.TARGETS = [
    {"code": "AAA", "name": "Сервер A", "name_en": "A", "country": "XX", "ip": "127.0.0.1", "ports": [rA.port], "secret": b"a" * 16, "tcp_port": 0},
    {"code": "BBB", "name": "Сервер B", "name_en": "B", "country": "YY", "ip": "127.0.0.1", "ports": [pB], "secret": b"b" * 16, "tcp_port": 0},
    {"code": "CCC", "name": "Сервер C", "name_en": "C", "country": "YY", "ip": "127.0.0.1", "ports": [rC.port], "secret": b"c" * 16, "tcp_port": 0},
]
now = int(time.time())
for nid, cs, ip, port in ((1, "calm-otter-11", "127.0.0.2", rV.port), (2, "quiet-raven-22", "127.0.0.3", pW)):
    V.db_exec("INSERT INTO nodes(id, token_hash, callsign, created, last_seen) VALUES(?,?,?,?,?)", (nid, "t%d" % nid, cs, now - 9999, now))
    V.db_exec("INSERT INTO refs(id, node_id, secret, ip, udp_ports, tcp_port, kind, asn, country, verified, created) VALUES(?,?,?,?,?,0,'ZZ',?,'ZZ',1,?)",
              (nid, nid, "ab" * 16, ip, json.dumps([port]), 64500 + nid, now))
# ответы приходят с 127.0.0.1, а сервер добровольца «живёт» на 127.0.0.2: _probe_ref сверяет адрес отправителя, поэтому шлём на 127.0.0.1
V.db_exec("UPDATE refs SET ip='127.0.0.1' WHERE id=1")
V.db_exec("UPDATE refs SET ip='127.0.0.1' WHERE id=2")

print("A. проверка серверов хабом")
res = V.health_round()
check("первый круг: отвечающие серверы живы, молчащие нет", res == {"AAA": True, "BBB": False, "CCC": True, "REF-1": True, "REF-2": False}, res)
check("после одной неудачи сервер ещё выдаётся", V._health_ok("BBB") and V._health_ok("REF-2"))
V.health_round()
V.health_round()
check("после трёх неудач подряд сервер проекта и сервер добровольца из выдачи убраны", not V._health_ok("BBB") and not V._health_ok("REF-2"), V.HEALTH)
check("отвечающие остаются", V._health_ok("AAA") and V._health_ok("CCC") and V._health_ok("REF-1"))
check("список целей для узлов и браузеров без молчащего сервера проекта", [t["code"] for t in V._health_filter(V.TARGETS)] == ["AAA", "CCC"])
comm = V.community_refs(99, "10.9.9.9", None)
check("узлу выдаётся только отвечающий сервер добровольца", [c["code"] for c in comm] == ["REF-1"], comm)
br = V._community_for_browser("10.9.9.9", None, "XX")
check("браузеру тоже только отвечающий сервер добровольца", [c["code"] for c in br] == ["REF-1"], br)
rep = V.health_report()
check("отчёт для наблюдателя: B и REF-2 помечены, у добровольца позывной, адресов и секретов нет",
      rep["servers"]["BBB"]["down"] and rep["servers"]["REF-2"]["down"] and rep["servers"]["REF-2"]["name"] == "quiet-raven-22"
      and rep["servers"]["REF-2"]["community"] and not rep["servers"]["AAA"]["down"] and "127.0.0." not in json.dumps(rep), rep)
check("кругов «хаб сам виноват» не было", rep["suspect"] is False, rep)

# сервер ожил: первый же ответ возвращает его
rB = Responder()
V.TARGETS[1]["ports"] = [rB.port]
V.health_round()
check("ожившего сервера проекта первый ответ возвращает в выдачу", V._health_ok("BBB") and not V.health_report()["servers"]["BBB"]["down"], V.HEALTH.get("BBB"))

# хаб не получает ответов почти ни от кого: виноват скорее он сам, никого не убираем
for r in (rA, rB, rC, rV):
    r.on = False
before = {k: v["fails"] for k, v in V.HEALTH.items()}
V.health_round()
rep = V.health_report()
check("молчит больше половины серверов: круг помечен как «проблема у хаба»", rep["suspect"] is True and rep["failed"] == 5 and rep["total"] == 5, rep)
check("в таком круге счётчики неудач не растут и серверы не убираются", {k: v["fails"] for k, v in V.HEALTH.items()} == before and V._health_ok("AAA"), V.HEALTH)
for r in (rA, rB, rC, rV):
    r.on = True
V.health_round()
check("ответы вернулись: пометка снята", V.health_report()["suspect"] is False)

# если молчат все серверы проекта, список не опустошаем: без них проверять не на чем
for c in ("AAA", "BBB", "CCC"):
    V.HEALTH[c]["fails"] = 5
check("все серверы проекта «молчат»: выдаются все, а не пустой список", len(V._health_filter(V.TARGETS)) == 3)
for c in ("AAA", "BBB", "CCC"):
    V.HEALTH[c]["fails"] = 0

# доброволец ушёл со связи: его не проверяем
V.db_exec("UPDATE nodes SET last_seen=? WHERE id=2", (now - 3600,))
codes = [c[0] for c in V._health_candidates()]
check("доброволец не на связи в круг не попадает", "REF-2" not in codes and "REF-1" in codes, codes)

# запуск из janitor: в отдельном потоке и не чаще HEALTH_EVERY
V.HEALTH_STATE.update(next=0, running=False)
t0 = time.time()
V.health_tick(t0)
check("health_tick не ждёт круга (идёт в фоне)", time.time() - t0 < 0.5)
nxt = V.HEALTH_STATE["next"]
V.health_tick(t0 + 1)
check("второй вызов раньше срока круг не запускает", V.HEALTH_STATE["next"] == nxt)
for _ in range(50):
    if not V.HEALTH_STATE["running"]:
        break
    time.sleep(0.1)
check("фоновый круг завершился", not V.HEALTH_STATE["running"])

print("B. проверки посетителей")
V.db_exec("DELETE FROM webchecks")


def web(asn, res, ago=60):
    V.db_exec("INSERT INTO webchecks(ts, asn, verdict, data) VALUES(?,?,?,?)", (now - ago, asn, "NO_BLOCK", json.dumps(res)))


def r(code, ok, seen=-1, replied=-1):
    return {"code": code, "ok": ok, "n": 3, "seen": seen, "replied": replied}


# сервер BBB молчит у посетителей из 4 разных сетей, AAA у них же отвечает
for i in range(8):
    web(65000 + i % 4, [r("AAA", 3, 3, 3), r("BBB", 0, 0 if i < 5 else 3, 0 if i < 5 else 3)], ago=60 + i)
# CCC молчит только у одной сети (её провайдер режет): это не про сервер
for i in range(8):
    web(65100, [r("AAA", 3), r("CCC", 0, 3, 3)], ago=200 + i)
# у посетителя не ответил никто: это его сеть, такие проверки не считаются
for i in range(10):
    web(65200 + i, [r("AAA", 0), r("BBB", 0), r("CCC", 0)], ago=300 + i)
# A и C отвечают вместе, проверок больше, чем VIS_LAST
for i in range(14):
    web(65400 + i, [r("AAA", 3), r("CCC", 3)], ago=500 + i)
# сервер добровольца: мало проверок, судить рано
for i in range(3):
    web(65300 + i, [r("AAA", 3), r("REF-1", 0)], ago=400 + i)
V._vis_cache["t"] = 0
vh = V.visitor_health()
b = vh.get("BBB", {})
check("сервер, молчащий у разных сетей при живых других, помечен", b.get("bad") is True and b.get("checks") == 8 and b.get("failed") == 8 and b.get("asns") == 4, b)
check("причины разделены: запросы не дошли до сервера и ответ не дошёл до посетителя", b.get("unseen") == 5 and b.get("lost") == 3, b)
check("сервер, молчащий только у одной сети (провайдер режет), не помечен", vh.get("CCC", {}).get("bad") is False and vh["CCC"]["failed"] == 8 and vh["CCC"]["asns"] == 1, vh.get("CCC"))
check("проверки, где не ответил никто, не считаются", vh.get("BBB", {}).get("checks") == 8 and vh.get("AAA", {}).get("failed") == 0, (vh.get("BBB"), vh.get("AAA")))
check("мало проверок: судить рано", vh.get("REF-1", {}).get("bad") is False and vh["REF-1"]["checks"] == 3, vh.get("REF-1"))
check("берём только последние VIS_LAST проверок сервера", vh.get("AAA", {}).get("checks") == V.VIS_LAST, vh.get("AAA"))
# старше суток не смотрим
V.db_exec("UPDATE webchecks SET ts = ts - 90000")
V._vis_cache["t"] = 0
check("проверки старше суток не учитываются", V.visitor_health() == {}, V.visitor_health())
V.db_exec("UPDATE webchecks SET ts = ts + 90000")
V._vis_cache["t"] = 0
vr = V._visitors_report(time.time())
check("отчёт для наблюдателя с именами, у добровольца позывной", vr["BBB"]["name"] == "Сервер B" and vr["REF-1"]["name"] == "calm-otter-11" and vr["REF-1"]["community"], vr)

print("наблюдатель")
spec = importlib.util.spec_from_file_location("watch", os.path.join(ROOT, "ops", "udpcheck-watch.py"))
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)
sent = []
W.deliver = lambda text: sent.append(text) or True
W.quiet = lambda t: False
st = {"checks": {}, "queue": []}
health = {"probe": {"suspect": False, "failed": 1, "total": 5, "servers": {
    "BBB": {"name": "Сервер B", "community": False, "down": True, "fails": 3},
    "REF-2": {"name": "quiet-raven-22", "community": True, "down": True, "fails": 4},
    "AAA": {"name": "Сервер A", "community": False, "down": False, "fails": 0}}},
    "visitors": {"BBB": dict(vh["BBB"], name="Сервер B", community=False), "CCC": dict(vh["CCC"], name="Сервер C", community=False)}}
W.probe_check(st, health)
txt = "\n".join(sent)
check("тревога по серверу проекта, который не отвечает хабу", any("ПРОБЛЕМА" in s and "сервер проекта «Сервер B» не отвечает хабу" in s for s in sent), txt)
check("тревога по серверу добровольца с позывным", any("сервер добровольца quiet-raven-22 не отвечает хабу" in s for s in sent), txt)
check("тревога по посетителям с причинами", any("не отвечает посетителям" in s and "в 8 из 8" in s and "не дошли" in s for s in sent), txt)
check("про отвечающие серверы ничего не пишем", not any("Сервер A" in s or "Сервер C" in s for s in sent), txt)
n1 = len(sent)
W.probe_check(st, health)
check("повторно та же тревога не шлётся", len(sent) == n1, sent[n1:])
health["probe"]["servers"]["BBB"]["down"] = False
W.probe_check(st, health)
check("сервер ожил: «ВОССТАНОВЛЕНО»", any(s.startswith("ВОССТАНОВЛЕНО") and "Сервер B" in s for s in sent[n1:]), sent[n1:])
sent.clear()
health["probe"]["suspect"] = True
W.probe_check(st, health)
check("одна «проблема у хаба» ещё не тревога (нужно два круга)", not any("большинства серверов" in s for s in sent), sent)
W.probe_check(st, health)
check("вторая подряд: тревога «дело в самом хабе»", any("большинства серверов" in s for s in sent), sent)
W.probe_check(st, {})
check("пустой ответ хаба (старая версия) не ломает наблюдателя", True)

print("E. серверы добровольцев для браузера: устойчивый выбор")
check("подсеть посетителя: /24 для IPv4, /48 для IPv6", V._vol_net("10.9.9.9") == "10.9.9.0/24" and V._vol_net("2001:db8:1:2::5") == "2001:db8:1::/48",
      (V._vol_net("10.9.9.9"), V._vol_net("2001:db8:1:2::5")))
check("одно число для адресов из одной /24 в те же сутки, другое в другие сутки и в другой подсети",
      V._vol_pick("10.9.9.9", "REF-1", "order", "2026-10-31") == V._vol_pick("10.9.9.200", "REF-1", "order", "2026-10-31")
      and V._vol_pick("10.9.9.9", "REF-1", "order", "2026-11-01") != V._vol_pick("10.9.9.9", "REF-1", "order", "2026-10-31")
      and V._vol_pick("10.9.8.9", "REF-1", "order", "2026-10-31") != V._vol_pick("10.9.9.9", "REF-1", "order", "2026-10-31"))
orig_ok = V._health_ok
V._health_ok = lambda code: True
for nid in (3, 4, 5):
    V.db_exec("INSERT INTO nodes(id, token_hash, callsign, created, last_seen) VALUES(?,?,?,?,?)", (nid, "t%d" % nid, "vol-%d" % nid, now - 9999, int(time.time())))
    V.db_exec("INSERT INTO refs(id, node_id, secret, ip, udp_ports, tcp_port, kind, asn, country, verified, created) VALUES(?,?,?,?,?,0,'ZZ',?,'ZZ',1,?)",
              (nid, nid, "ab" * 16, "127.0.0.%d" % (nid + 1), json.dumps([pW]), 64500 + nid, now))
V.db_exec("UPDATE nodes SET last_seen=? WHERE id IN (1, 2)", (int(time.time()),))
runs = {tuple(c["code"] for c in V._community_for_browser("10.9.9.%d" % (i % 250 + 1), None, "XX")) for i in range(40)}
check("из одной /24 сорок запросов подряд дают одни и те же два сервера (перебором весь список не собрать)", len(runs) == 1 and len(next(iter(runs))) == 2, runs)
seen = set()
for i in range(60):
    seen |= {c["code"] for c in V._community_for_browser("10.%d.%d.1" % (i // 200, i % 200), None, "XX")}
check("разные подсети получают разные серверы: нагрузка расходится по всем", len(seen) >= 4, seen)
V._health_ok = orig_ok

print("F. срок хранения записей серверов добровольцев")
t = int(time.time())
V.db_exec("UPDATE nodes SET last_seen=? WHERE id=3", (t - (V.REF_KEEP_DAYS + 1) * 86400,))
V.db_exec("UPDATE nodes SET last_seen=? WHERE id=4", (t - (V.REF_KEEP_DAYS - 1) * 86400,))
V.purge_old(t)
left = {r[0] for r in V.db_exec("SELECT node_id FROM refs", many=True)}
nodes_left = {r[0] for r in V.db_exec("SELECT id FROM nodes", many=True)}
check("молчит дольше REF_KEEP_DAYS: запись с IP удалена, а за ней и сам узел без замеров", 3 not in left and 3 not in nodes_left, (left, nodes_left))
check("молчит меньше срока и на связи: записи остаются", {1, 2, 4, 5} <= left and {1, 2, 4, 5} <= nodes_left, (left, nodes_left))

print("ИТОГ:", "всё прошло" if not fails else "ошибок: %d" % fails)
sys.exit(1 if fails else 0)
