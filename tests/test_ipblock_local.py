#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Сервер недоступен целиком (блокировка по IP или подсети) не должен давать ложное «режется UDP»:
итог узла (UDP и TCP не проходят -> IPBLOCK, в вывод про UDP не входит), подсказка браузеру по замерам узлов той же сети,
сверка адресов с реестром блокировок (добровольцы в «грязной» подсети не берутся свидетелями) и тревоги наблюдателя.
Запуск: python tests/test_ipblock_local.py"""
import importlib.util
import json
import os
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)
import udpcheck_v2 as V

fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:500]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


GEO = {"10.0.0.5": {"asn": 64600, "country": "XX"}, "10.0.0.6": {"asn": 64601, "country": "XX"}}


class Geo:
    def lookup(self, ip, force=False):
        return dict(GEO.get(ip, {}))


class Srv:
    GEO = Geo()
    ALLOW_NON_GLOBAL = True
    GEO_ATTRIBUTION = ""

    @staticmethod
    def is_public(ip):
        return False


class H:
    """Заглушка запроса: ответ хаба просто возвращается."""
    def __init__(self):
        self.headers = {}
        self.path = ""

    def send_json(self, code, obj):
        return code, obj

    def err(self, code, msg, retry=None):
        return code, {"error": msg}


class Allow:
    def allow(self, key):
        return True, 0


V.S = Srv
V.DB = sqlite3.connect(":memory:", check_same_thread=False)
V.DB.executescript(V.SCHEMA)
V.migrate(V.DB)
V.rl_web = Allow()
now = int(time.time())

print("итог узла")
home = lambda st: {"code": "R", "kind": "home", "status": st}
fr = lambda c, st: {"code": c, "kind": "foreign", "status": st}
code, text = V.make_verdict([home("OK"), fr("F1", "IPBLOCK"), fr("F2", "INCUT")])
check("недоступный целиком сервер не входит в вывод про UDP, остальные решают", code == "FOREIGN_IN_CUT" and "(F2)" in text and "Адрес F1 недоступен целиком" in text, (code, text))
code, text = V.make_verdict([home("OK"), fr("F1", "IPBLOCK"), fr("F2", "OK")])
check("остальные чистые: «блокировки UDP нет» и отдельная фраза про адрес", code == "NO_BLOCK" and "Адрес F1 недоступен целиком" in text, (code, text))
code, text = V.make_verdict([home("OK"), fr("F1", "IPBLOCK"), fr("F2", "IPBLOCK")])
check("все зарубежные недоступны целиком: отдельный вердикт IP_BLOCKED, не «режется»", code == "IP_BLOCKED" and "F1, F2" in text and "ни UDP, ни TCP" in text, (code, text))
code, text = V.make_verdict([home("OK"), fr("F1", "IPBLOCK")], "en")
check("английский текст есть", code == "IP_BLOCKED" and "Neither UDP nor TCP" in text, text)
code, _ = V.make_verdict([home("IPBLOCK"), fr("F1", "OK")])
check("контроль в стране недоступен целиком: сравнивать не с чем", code == "CONTROL_DOWN", code)
check("IP_BLOCKED не считается порезкой в статистике провайдера", "IP_BLOCKED" not in V.CUT_W)

# полный проход node_result: узел прислал результаты, цели отчитались
V.TARGETS = []                     # без трассировки до узла
V.RESULT_WAIT = 1
V.db_exec("INSERT INTO nodes(id, token_hash, callsign, asn, created, last_seen) VALUES(1, 't1', 'calm-otter-11', 64600, ?, ?)", (now, now))
V._auth_node = lambda h, ip: (1,)


def run_task(tcp_f1, rep_f1, back_f1, tcp_f2=None, rep_f2=100, back_f2=0):
    cfg = lambda code, kind: {"code": code, "name": code, "kind": kind, "ports": [5001, 5002], "tcp_port": 5003}
    tid = "t%d" % len(V.TASKS)
    V.TASKS[tid] = {"node_id": 1, "ip": "10.0.0.5", "created": time.time(), "reports": {
        "R": {"ports": {5001: 100, 5002: 100}, "srcs": []}, "F1": {"ports": {5001: rep_f1, 5002: rep_f1}, "srcs": []},
        "F2": {"ports": {5001: rep_f2, 5002: rep_f2}, "srcs": []}},
        "targets": {c: {"taskid": "%s%s" % (tid, c), "cfg": cfg(c, k)} for c, k in (("R", "home"), ("F1", "foreign"), ("F2", "foreign"))}}
    res = [{"code": "R", "ports": {"5001": {"back": 100}, "5002": {"back": 100}}, "tcp": {"down_ok": 1, "up_ok": 1}},
           {"code": "F1", "ports": {"5001": {"back": back_f1}, "5002": {"back": back_f1}}, "tcp": tcp_f1},
           {"code": "F2", "ports": {"5001": {"back": back_f2}, "5002": {"back": back_f2}}, "tcp": tcp_f2 or {"down_ok": 1, "up_ok": 1}}]
    code, out = V.node_result(H(), "10.0.0.5", json.dumps({"task": tid, "results": res}).encode())
    return out


out = run_task({"error": "timeout"}, 0, 0)
st = {t["code"]: t["status"] for t in out["targets"]}
check("UDP не доходит и TCP не соединяется: статус IPBLOCK", st["F1"] == "IPBLOCK", st)
check("сервер, до которого TCP проходит, остаётся с порезкой UDP", st["F2"] == "INCUT", st)
check("итог про UDP по второму серверу, с пометкой про первый", out["verdict"]["code"] == "FOREIGN_IN_CUT" and "Адрес F1" in out["verdict"]["text"], out["verdict"])
rows = dict(V.db_exec("SELECT target, status FROM tres WHERE round_id = ?", (out["round"],), many=True))
check("в базе замер записан как IPBLOCK", rows.get("F1") == "IPBLOCK", rows)
out = run_task({"down_ok": 0, "up_ok": 0}, 100, 0)
check("UDP: ответы не приходят, TCP соединился, но данные не прошли: тоже IPBLOCK", {t["code"]: t["status"] for t in out["targets"]}["F1"] == "IPBLOCK", out["targets"])
out = run_task({"down_ok": 1, "up_ok": 1}, 0, 0)
check("UDP не доходит, а TCP проходит: это порезка UDP, а не адреса", {t["code"]: t["status"] for t in out["targets"]}["F1"] == "OUTCUT", out["targets"])
out = run_task({}, 0, 0)
check("TCP не мерялся: судим только по UDP", {t["code"]: t["status"] for t in out["targets"]}["F1"] == "OUTCUT", out["targets"])

print("подсказка браузеру")
V.db_exec("DELETE FROM tres")
for i in range(3):
    V.db_exec("INSERT INTO tres(round_id, ts, asn, target, kind, status, tcp) VALUES(0, ?, 64600, 'F1', 'foreign', 'IPBLOCK', 'ERR')", (now - 100 * i,))
V.db_exec("INSERT INTO tres(round_id, ts, asn, target, kind, status, tcp) VALUES(0, ?, 64600, 'F1', 'foreign', 'OK', 'OK')", (now,))
V.db_exec("INSERT INTO tres(round_id, ts, asn, target, kind, status, tcp) VALUES(0, ?, 64600, 'F2', 'foreign', 'IPBLOCK', 'ERR')", (now,))
V.db_exec("INSERT INTO tres(round_id, ts, asn, target, kind, status, tcp) VALUES(0, ?, 64601, 'F1', 'foreign', 'IPBLOCK', 'ERR')", (now - 90000,))
V.db_exec("INSERT INTO tres(round_id, ts, asn, target, kind, status, tcp) VALUES(0, ?, 64600, 'REF-3', 'foreign', 'IPBLOCK', 'ERR')", (now,))
check("сервер, недоступный целиком в большинстве замеров узлов сети, попадает в подсказку", V.ipblock_hint(64600, now) == {"F1"}, V.ipblock_hint(64600, now))
check("одного замера мало, серверы добровольцев не подсказываем", "F2" not in V._ipb_cache[64600][1] and "REF-3" not in V._ipb_cache[64600][1])
check("замеры старше суток не учитываются", V.ipblock_hint(64601, now) == set())
check("без номера сети подсказки нет", V.ipblock_hint(None) == set())
V.TARGETS = [{"code": "R", "name": "R", "name_en": "R", "country": "XX", "ip": "192.0.2.10", "ports": [777, 47321], "secret": b"r" * 16, "tcp_port": 0},
             {"code": "F1", "name": "F1", "name_en": "F1", "country": "YY", "ip": "198.51.100.2", "ports": [777, 47321], "secret": b"f" * 16, "tcp_port": 0}]
code, ws = V.web_stun(H(), "10.0.0.5")
flags = {t["code"]: t.get("ipblock", False) for t in ws["targets"]}
check("в задании браузеру сервер помечен ipblock для этой сети", flags == {"R": False, "F1": True}, flags)
code, ws = V.web_stun(H(), "10.0.0.6")
check("для посетителя из другой сети пометки нет", not any(t.get("ipblock") for t in ws["targets"]), ws["targets"])
check("браузер может прислать вердикт IP_BLOCKED", "IP_BLOCKED" in V.WEB_VERDICTS)

print("реестр блокировок")
lines = ["# комментарий", "203.0.113.9", "203.0.113.9", "192.0.2.300", "10.20.0.0/16"] + ["10.%d.%d.%d" % (a, b, c) for a in range(101, 103) for b in range(0, 10) for c in range(1, 60)]
lines += ["198.51.100.%d" % i for i in (7, 8)]
check("до загрузки списка все адреса считаются чистыми", V.rkn_state("203.0.113.9") is None and V._rkn_clean("203.0.113.9"))
try:
    V.rkn_load_text("192.0.2.10\n198.51.100.10\n")
    short = False
except ValueError:
    short = True
check("подозрительно короткий список не применяется", short and V.RKN["t"] == 0)
n = V.rkn_load_text("\n".join(lines), now)
check("список разобран: только адреса IPv4, без повторов, подсетей и мусора", n == 2 * 10 * 59 + 1 + 2, n)
check("адрес в реестре", V.rkn_state("203.0.113.9") == (True, 0))
check("соседи по /24 считаются без самого адреса", V.rkn_state("198.51.100.2") == (False, 2) and V.rkn_state("198.51.100.7") == (True, 1))
check("чистый адрес", V.rkn_state("192.0.2.1") == (False, 0) and V._rkn_clean("192.0.2.1"))
check("адрес с соседями в реестре свидетелем не годится", not V._rkn_clean("198.51.100.200"))
# добровольцы: один в «грязной» подсети, другой в чистой
for nid, cs, ip in ((11, "dusty-raven-11", "198.51.100.50"), (12, "tidy-maple-12", "192.0.2.77")):
    V.db_exec("INSERT INTO nodes(id, token_hash, callsign, created, last_seen) VALUES(?,?,?,?,?)", (nid, "x%d" % nid, cs, now - 99999, now))
    V.db_exec("INSERT INTO refs(id, node_id, secret, ip, udp_ports, tcp_port, kind, asn, country, verified, created) VALUES(?,?,?,?,?,0,'ZZ',?,'ZZ',1,?)",
              (nid, nid, "ab" * 16, ip, json.dumps([47321]), 64700 + nid, now))
comm = V.community_refs(99, "10.9.9.9", None)
check("узлу не выдаётся доброволец из подсети с адресами из реестра", [c["code"] for c in comm] == ["REF-12"], comm)
br = V._community_for_browser("10.9.9.9", None, "XX")
check("браузеру тоже", [c["code"] for c in br] == ["REF-12"], br)
rk = V.rkn_report(now)
sv = rk["servers"]
check("отчёт для наблюдателя: сервер проекта F1 с двумя соседями помечен", sv["F1"] == {"name": "F1", "community": False, "listed": False, "neighbors": 2, "dirty": True}, sv.get("F1"))
check("чистый сервер проекта не помечен", sv["R"]["dirty"] is False and sv["R"]["neighbors"] == 0, sv.get("R"))
check("доброволец в отчёте под позывным, без адреса", sv["REF-11"]["name"] == "dusty-raven-11" and sv["REF-11"]["dirty"] and "198.51.100" not in json.dumps(rk), rk)
check("в отчёте возраст и размер списка", rk["enabled"] and rk["age_s"] is not None and rk["size"] == n, rk)

print("наблюдатель")
spec = importlib.util.spec_from_file_location("watch", os.path.join(ROOT, "ops", "udpcheck-watch.py"))
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)
sent = []
W.deliver = lambda text: sent.append(text) or True
W.quiet = lambda t: False
st = {"checks": {}, "queue": []}
W.rkn_check(st, {"rkn": rk})
txt = "\n".join(sent)
check("тревога по серверу проекта с соседями из реестра", any("в подсети сервера проекта «F1»" in s and ": 2." in s for s in sent), txt)
check("про серверы добровольцев и чистые серверы молчим", not any("dusty-raven" in s or "«R»" in s for s in sent), txt)
rk2 = json.loads(json.dumps(rk))
rk2["servers"]["F1"].update(listed=True, dirty=True)
st2 = {"checks": {}, "queue": []}
sent.clear()
W.rkn_check(st2, {"rkn": rk2})
check("сам адрес в реестре: своя формулировка", any("адрес сервера проекта «F1» в реестре" in s for s in sent), sent)
sent.clear()
rk2["servers"]["F1"].update(listed=False, neighbors=0, dirty=False)
W.rkn_check(st2, {"rkn": rk2})
check("адрес стал чистым: «ВОССТАНОВЛЕНО»", any(s.startswith("ВОССТАНОВЛЕНО") and "F1" in s for s in sent), sent)
sent.clear()
st3 = {"checks": {}, "queue": []}
for _ in range(30):
    W.rkn_check(st3, {"rkn": {"enabled": True, "age_s": None, "servers": {}}})
check("список так и не скачался полчаса: тревога", any("не обновлял список реестра" in s for s in sent), sent)
print("наблюдатель: тревоги по реестру, принятые как известные")
import tempfile as _tf
mark = os.path.join(_tf.mkdtemp(), "accept")
W.RKN_ACCEPT_FILE = mark
srv = lambda listed, nb: {"F1": {"name": "F1", "community": False, "listed": listed, "neighbors": nb, "dirty": listed or nb >= 1},
                          "R": {"name": "R", "community": False, "listed": False, "neighbors": 0, "dirty": False}}
st4 = {"checks": {}, "queue": []}
sent.clear()
W.rkn_check(st4, {"rkn": {"enabled": True, "age_s": 60, "servers": srv(False, 8)}})
check("без отметки: обычная тревога", any("в подсети сервера проекта «F1»" in s for s in sent) and st4["checks"]["rkn:F1"]["alerted"], sent)
open(mark, "w").close()
sent.clear()
W.rkn_check(st4, {"rkn": {"enabled": True, "age_s": 60, "servers": srv(False, 8)}})
check("отметка: одно сообщение «принято как известное», без «ВОССТАНОВЛЕНО»", len(sent) == 1 and "принято как известное" in sent[0] and "F1 (соседей 8)" in sent[0], sent)
sent.clear()
for _ in range(3):
    W.rkn_check(st4, {"rkn": {"enabled": True, "age_s": 60, "servers": srv(False, 8)}})
check("дальше по тому же состоянию молчим", not sent and st4["rkn_accept"]["F1"] == {"listed": False, "neighbors": 8}, (sent, st4.get("rkn_accept")))
W.rkn_check(st4, {"rkn": {"enabled": True, "age_s": 60, "servers": srv(False, 6)}})
check("стало лучше (соседей меньше): молчим", not sent, sent)
W.rkn_check(st4, {"rkn": {"enabled": True, "age_s": 60, "servers": srv(False, 9)}})
check("стало хуже (соседей больше): тревога с пометкой «теперь хуже»", any("соседей было 8" in s and "теперь хуже" in s for s in sent), sent)
sent.clear()
W.rkn_check(st4, {"rkn": {"enabled": True, "age_s": 60, "servers": srv(False, 8)}})
check("вернулось к принятому: «снова не хуже принятого»", any(s.startswith("ВОССТАНОВЛЕНО") and "не хуже принятого" in s for s in sent), sent)
sent.clear()
W.rkn_check(st4, {"rkn": {"enabled": True, "age_s": 60, "servers": srv(True, 8)}})
check("сам адрес попал в реестр: тревога", any("адрес сервера проекта «F1» в реестре" in s for s in sent), sent)
sent.clear()
W.rkn_check({"checks": {}, "queue": []}, {"rkn": {"enabled": False}})
W.rkn_check({"checks": {}, "queue": []}, {})
check("сверка выключена или хаб старый: молчим", not sent, sent)

print("ИТОГ:", "всё прошло" if not fails else "ошибок: %d" % fails)
sys.exit(1 if fails else 0)
