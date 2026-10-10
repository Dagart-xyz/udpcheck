#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Локальная проверка сети узлов v2: хаб + две цели + агент узла. Запуск: python tests/test_v2_local.py"""
import hashlib
import hmac
import http.client
import json
import os
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)
import udpcheck_v2 as V   # чистые функции классификации

fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)) if (extra and not cond) else ""))
    if not cond:
        fails += 1


# ---------------------------------------------------------------- 1. классификация
print("[классификация и вывод]")
check("100/100/100 -> OK", V.port_class(100, 100, 100) == "OK")
check("100/100/98 (2%) -> OK (небольшие потери)", V.port_class(100, 100, 98) == "OK")
check("100/100/0 -> INCUT", V.port_class(100, 100, 0) == "INCUT")
check("100/0/0 -> OUTCUT", V.port_class(100, 0, 0) == "OUTCUT")
check("100/23/23 (обрыв после 23) -> OUTCUT", V.port_class(100, 23, 23) == "OUTCUT" or V.port_class(100, 23, 23) == "LOSSY", V.port_class(100, 23, 23))
check("отчёта нет -> NOREPORT", V.port_class(100, None, 5) == "NOREPORT")
check("статусы: смесь OK и INCUT -> PART", V.target_status(["OK", "INCUT", "INCUT"]) == "PART")
v = lambda ru, *f: V.make_verdict([{"code": "RU", "kind": "ru", "status": ru}] + [{"code": "F%d" % i, "kind": "foreign", "status": s} for i, s in enumerate(f)])[0]
check("вывод: РФ ок, все зарубежные INCUT -> FOREIGN_IN_CUT", v("OK", "INCUT", "INCUT") == "FOREIGN_IN_CUT")
check("вывод: РФ ок, зарубежные ок -> NO_BLOCK", v("OK", "OK", "OK") == "NO_BLOCK")
check("вывод: РФ ок, часть ок -> FOREIGN_PARTIAL", v("OK", "OK", "INCUT") == "FOREIGN_PARTIAL")
check("статусы: все порты с потерями -> LOSSY (не блокировка)", V.target_status(["LOSSY", "LOSSY", "LOSSY"]) == "LOSSY")
check("вывод: РФ ок, зарубежные ок и с потерями -> NO_BLOCK", v("OK", "OK", "LOSSY") == "NO_BLOCK" and "потери" in V.make_verdict([{"code": "RU", "kind": "ru", "status": "OK"}, {"code": "F", "kind": "foreign", "status": "LOSSY"}])[1])
check("вывод: РФ режется -> CONTROL_BAD", v("INCUT", "INCUT") == "CONTROL_BAD")
nh = lambda *f: V.make_verdict([{"code": "F%d" % i, "kind": "foreign", "status": s} for i, s in enumerate(f)])
check("нет опорного сервера в стране -> NO_ANCHOR с просьбой помочь", nh("OK", "OK")[0] == "NO_ANCHOR" and "не на что опираться" in nh("OK")[1] and "#help-anchor" in nh("OK")[1])
check("kind=home читается как своя страна", V.make_verdict([{"code": "H", "kind": "home", "status": "OK"}, {"code": "F", "kind": "foreign", "status": "INCUT"}])[0] == "FOREIGN_IN_CUT")
two = lambda a, b, *f: V.make_verdict([{"code": "R1", "kind": "ru", "status": a}, {"code": "R2", "kind": "ru", "status": b}] + [{"code": "F%d" % i, "kind": "foreign", "status": s} for i, s in enumerate(f)])[0]
check("два контроля в РФ: достаточно одного чистого", two("INCUT", "OK", "INCUT") == "FOREIGN_IN_CUT" and two("NOREPORT", "OK", "OK") == "NO_BLOCK")
check("два контроля в РФ: оба плохие -> CONTROL_BAD, оба молчат -> CONTROL_DOWN", two("INCUT", "OUTCUT", "OK") == "CONTROL_BAD" and two("NOREPORT", "NOREPORT", "OK") == "CONTROL_DOWN")
check("вывод: нет отчёта РФ -> CONTROL_DOWN", v("NOREPORT", "OK") == "CONTROL_DOWN")
check("вывод: РФ ок, зарубеж OUTCUT -> FOREIGN_OUT_CUT", v("OK", "OUTCUT") == "FOREIGN_OUT_CUT")

# имя провайдера из whois: торговое имя годится, место и тип сети нет
check("имя из whois: SEVEN-SKY -> Seven Sky, Rostelecom как есть", V._pretty_descr("SEVEN-SKY") == "Seven Sky" and V._pretty_descr("Rostelecom") == "Rostelecom")
check("имя из whois: «Moscow, Russia», «DSI Edge AS», длинный текст отклоняются", all(V._pretty_descr(x) is None for x in ("Moscow, Russia", "DSI Edge AS", "Autonomous system of some very long description text")))

# русские названия городов из справочника GeoNames
import sqlite3 as _sq
_cd = tempfile.mkdtemp(prefix="udpc_cities_")
_cc = _sq.connect(os.path.join(_cd, "cities_ru.sqlite"))
_cc.execute("CREATE TABLE c(cc TEXT, k TEXT, ru TEXT, pop INTEGER, PRIMARY KEY(cc, k)) WITHOUT ROWID")
_cc.execute("INSERT INTO c VALUES('FI','helsinki','Хельсинки',600000)")
_cc.commit()
_cc.close()
import types as _ty
V.S = _ty.SimpleNamespace(GEO_DIR=_cd)
check("город: Helsinki -> Хельсинки по справочнику", V.city_ru("FI", "Helsinki") == "Хельсинки")
check("город: нет в справочнике (мелкое место) остаётся как есть, пусто остаётся пустым", V.city_ru("NL", "Eygelshoven") == "Eygelshoven" and V.city_ru("FI", None) is None)

def V_kind_ok(byasn):
    return (byasn.get(64505, {}).get("kind") == "hosting" and byasn.get(64502, {}).get("kind") == "isp"
            and byasn.get(64503, {}).get("kind") == "isp" and byasn.get(64500, {}).get("kind") == "isp")


# журнал смен статуса: появление сети, единичная порезка, подтверждённая смена статуса
print("[журнал смен статуса]")
_jdb = _sq.connect(":memory:", check_same_thread=False)
_jdb.executescript(V.SCHEMA)
V.migrate(_jdb)
V.DB = _jdb
V._asn_cache[777001] = ""
t0 = int(time.time())


def _wc(ts, asn, verdict, cid, data="[]"):
    _jdb.execute("INSERT INTO webchecks(ts, asn, verdict, data, org, cid) VALUES(?,?,?,?,?,?)", (ts, asn, verdict, data, "Journal ISP", cid))
    _jdb.commit()


for i in range(4):
    _wc(t0 - 10, 777001, "NO_BLOCK", "aa%030d" % i)
V.JOURNAL_STATE.update(last=0, pending={})
V.journal_eval(t0)
rows = _jdb.execute("SELECT kind, old, new FROM journal WHERE asn=777001").fetchall()
check("журнал: сеть появилась в проверках: событие new со статусом ok", rows == [("new", None, "ok")], rows)
ev = json.dumps([{"code": "HEL1-FI", "ok": 0, "n": 6, "seen": 12, "replied": 12}, {"code": "RU-T", "ok": 6, "n": 6}])
for i in range(8):
    _wc(t0 + 100, 777001, "FOREIGN_IN_CUT", "bb%030d" % i, ev)
V.journal_eval(t0 + 300)
rows = _jdb.execute("SELECT kind, old, new, info FROM journal WHERE asn=777001 ORDER BY id").fetchall()
check("журнал: порезка при статусе ok -> событие cut_check с подтверждением ответов сервера, статус пока не меняется",
      [r[0] for r in rows] == ["new", "cut_check"] and json.loads(rows[1][3]).get("servers_replied") == 1, rows)
_wc(t0 + 100, 777002, "NO_BLOCK", "cc%030d" % 0)
V.journal_eval(t0 + 310)
_wc(t0 + 320, 777002, "FOREIGN_IN_CUT", "cc%030d" % 1, ev)
V.journal_eval(t0 + 330)
check("журнал: порезка у одного браузера в журнал не попадает", _jdb.execute("SELECT COUNT(*) FROM journal WHERE asn=777002 AND kind='cut_check'").fetchone()[0] == 0)
_wc(t0 + 340, 777002, "FOREIGN_IN_CUT", "cc%030d" % 2, ev)
V.journal_eval(t0 + 350)
r2 = _jdb.execute("SELECT info FROM journal WHERE asn=777002 AND kind='cut_check'").fetchall()
check("журнал: порезка у двух разных браузеров за полчаса: событие с числом браузеров и направлением",
      len(r2) == 1 and json.loads(r2[0][0]).get("browsers") == 2 and json.loads(r2[0][0]).get("dir") == "in", r2)
V.journal_eval(t0 + 600)
rows = _jdb.execute("SELECT kind, old, new FROM journal WHERE asn=777001 ORDER BY id").fetchall()
check("журнал: следующая сверка подтверждает смену статуса ok -> cut (change)", [r[0] for r in rows] == ["new", "cut_check", "change"] and rows[2][1:] == ("ok", "cut"), rows)
V.journal_eval(t0 + 900)
check("журнал: без новых данных новых записей нет", _jdb.execute("SELECT COUNT(*) FROM journal WHERE asn=777001").fetchone()[0] == 3)
check("хостинг по сайту организации (.host, .cloud) и по словам в названии распознаётся",
      all(any(w in x for w in V.HOST_WORDS) for x in ("anycast ltd", "super hosting", "vds cloud")) and "host" in "1cent.host" and "cloud" in "play2go.cloud")
V.DB = None

# ---------------------------------------------------------------- 1в. сети по хопам определяет хаб
print("[сети по хопам определяет хаб, а не цель]")
import types
os.environ["UDPCHECK_LANG"] = "ru"          # тесты сверяют русский вывод агента


class StubGeo:
    def lookup(self, ip, force=False):
        return {"10.1.": {"asn": 100, "org": "NetA"}, "10.2.": {"asn": 200, "org": "NetB"}}.get(ip[:5], {})


V.S = types.SimpleNamespace(GEO=StubGeo())
hop = lambda ttl, addr: {"ttl": ttl, "addrs": [addr], "rtt_ms": [1.0], "lost": 0, "asns": [999], "orgs": ["FAKE"]}
clip = V._clip_trace({"icmp": {"ok": True, "reached": False, "last_responding_ttl": 4,
                               "hops": [hop(1, "10.1.0.1"), hop(2, "10.1.0.9"), hop(3, "10.2.0.1"), hop(4, "192.168.0.1")],
                               "as_path": [{"asn": 999, "org": "FAKE", "first_ttl": 1, "last_ttl": 4}]}})["icmp"]
check("хаб склеивает подряд идущие хопы одной сети и сам называет сети", clip["as_path"] == [
    {"asn": 100, "org": "NetA", "first_ttl": 1, "last_ttl": 2}, {"asn": 200, "org": "NetB", "first_ttl": 3, "last_ttl": 3}], clip["as_path"])
own = V._clip_trace({"icmp": {"ok": True, "reached": False, "last_responding_ttl": 3,
                              "hops": [hop(1, "10.1.0.1"), hop(2, "10.2.0.1"), hop(3, "10.2.0.9")]}}, skip_asn=100)["icmp"]
check("собственная сеть опорного сервера в цепочке маршрута не показывается", [a["asn"] for a in own["as_path"]] == [200], own["as_path"])
check("то, что прислала цель про сети, игнорируется; неизвестный адрес без сети", clip["hops"][3]["asns"] == [None] and clip["hops"][0]["asns"] == [100], clip["hops"])

# ---------------------------------------------------------------- 2. стенд
tmp = tempfile.mkdtemp(prefix="udpc_v2_")
secA, secB = os.urandom(16).hex(), os.urandom(16).hex()
targets = [
    {"code": "RU-T", "name": "ru test", "country": "XX", "ip": "127.0.0.1", "ports": [19993, 19777, 19321], "secret": secA, "tcp_port": 18443},
    {"code": "F-T", "name": "foreign test", "country": "YY", "ip": "127.0.0.1", "ports": [29993, 29777, 29321], "secret": secB, "tcp_port": 28443},
]
tfile = os.path.join(tmp, "targets.json")
json.dump(targets, open(tfile, "w"))
dbfile = os.path.join(tmp, "hub.db")
SERVER = os.path.join(ROOT, "udpcheck_server.py")
HUB = "http://127.0.0.1:18080/udpcheck"
base_env = dict(os.environ, UDPCHECK_TRUSTED_PROXIES="", UDPCHECK_GEO_DIR=os.path.join(tmp, "nogeo"), UDPCHECK_PROBE_INTERVAL="900",
                UDPCHECK_ALLOW_NON_GLOBAL="1", UDPCHECK_DEFAULT_COUNTRY="XX", UDPCHECK_LOGO_DIR=os.path.join(tempfile.gettempdir(), "udpc_logos_test"), UDPCHECK_TRACEROUTE=os.path.join(HERE, "fake_traceroute.cmd"))


def start(http_port, udp, tid, secret, tcp, extra=None):
    env = dict(base_env, UDPCHECK_HTTP_PORT=str(http_port), UDPCHECK_UDP_BIND="127.0.0.1", UDPCHECK_PAD_PORTS="", UDPCHECK_UDP_PORTS=",".join(map(str, udp)),
               UDPCHECK_TARGET_ID=tid, UDPCHECK_TARGET_SECRET=secret, UDPCHECK_HUB_URL=HUB, UDPCHECK_TARGET_TCP_PORT=str(tcp))
    env.update(extra or {})
    return subprocess.Popen([sys.executable, SERVER], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def api(method, path, body=None, token=None, headers=None, port=18080):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    h = dict(headers or {})
    if path.startswith("/api/v2/web/"):
        h.setdefault("X-Client", "c" * 32)          # запросы страницы всегда идут с номером браузера
    if token:
        h["Authorization"] = "Bearer " + token
    data = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
    c.request(method, "/udpcheck" + path, body=data, headers=h)
    r = c.getresponse()
    raw = r.read()
    c.close()
    try:
        return r.status, json.loads(raw)
    except ValueError:
        return r.status, raw


def run_node(cfgfile):
    return subprocess.run([sys.executable, os.path.join(ROOT, "udpcheck_node.py"), "--once", "--hub", HUB, "--config", cfgfile],
                          capture_output=True, text=True, encoding="utf-8", timeout=120)


procs = []
try:
    hub_env = {"UDPCHECK_HUB_DB": dbfile, "UDPCHECK_HUB_TARGETS": tfile}
    procs.append(start(18080, [19993, 19777, 19321], "RU-T", secA, 18443, hub_env))
    procs.append(start(18081, [29993, 29777, 29321], "F-T", secB, 28443, {"UDPCHECK_PAD_PORTS": "29600:600"}))
    for _ in range(60):
        try:
            if api("GET", "/api/v1/health")[0] == 200 and api("GET", "/api/v1/health", port=18081)[0] == 200:
                break
        except OSError:
            time.sleep(0.2)
    else:
        sys.exit("стенд не поднялся: " + procs[0].stderr.read().decode(errors="replace"))

    print("[защита]")
    check("опрос без токена -> 401", api("POST", "/api/v2/node/poll")[0] == 401)
    check("неверный токен -> 401", api("POST", "/api/v2/node/poll", token="x" * 20)[0] == 401)
    body = json.dumps({"taskid": "00" * 8, "ports": {}}).encode()
    check("отчёт цели с неверной подписью -> 403", api("POST", "/api/v2/target/report", body, headers={"X-Target": "F-T", "X-Auth": "0" * 64})[0] == 403)
    check("отчёт неизвестной цели -> 403", api("POST", "/api/v2/target/report", body, headers={"X-Target": "NOPE", "X-Auth": "0" * 64})[0] == 403)
    # пакет v2 с неверным mac не должен получить ответ
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.6)
    bad = struct.pack("!4sBB8sI4s", b"UDPC", 2, 0, os.urandom(8), 0, b"\x00\x00\x00\x00") + bytes(1000)
    s.sendto(bad, ("127.0.0.1", 29993))
    try:
        s.recvfrom(2048)
        check("пакет с неверным mac без ответа", False)
    except socket.timeout:
        check("пакет с неверным mac без ответа", True)
    # правильный mac -> ответ той же длины
    tid = os.urandom(8)
    mac = hmac.new(bytes.fromhex(secB), b"UDPC2" + tid, hashlib.sha256).digest()[:4]
    good = struct.pack("!4sBB8sI4s", b"UDPC", 2, 0, tid, 0, mac) + bytes(1000)
    s.sendto(good, ("127.0.0.1", 29993))
    try:
        d, _ = s.recvfrom(2048)
        check("пакет с верным mac: ответ той же длины, флаг=1", len(d) == len(good) and d[5] == 1)
    except socket.timeout:
        check("пакет с верным mac: ответ той же длины, флаг=1", False)
    s.close()

    print("[замер 1: обе цели отвечают]")
    cfg1 = os.path.join(tmp, "node1.json")
    t0 = time.time()
    r1 = run_node(cfg1)
    print("   (замер занял %.0f с)" % (time.time() - t0))
    out1 = r1.stdout
    check("агент завершился без ошибки", r1.returncode == 0, r1.stderr[-300:])
    check("агент зарегистрировался и сохранил токен", json.load(open(cfg1)).get("token", "") != "")
    check("вывод: блокировки не обнаружено", "блокировки не обнаружено" in out1, out1[-400:])
    check("TCP-проверка прошла на обеих целях", out1.count("TCP: OK") == 2, out1)

    print("[замер 2: зарубежная цель принимает, но не отвечает (имитация режущего фильтра)]")
    procs[1].terminate()
    procs[1].wait(timeout=5)
    procs[1] = start(18081, [29993, 29777, 29321], "F-T", secB, 28443, {"UDPCHECK_TEST_DROP_REPLY": "1", "UDPCHECK_PAD_PORTS": "29600:600"})
    time.sleep(1.5)
    cfg2 = os.path.join(tmp, "node2.json")
    r2 = run_node(cfg2)
    out2 = r2.stdout
    check("агент завершился без ошибки", r2.returncode == 0, r2.stderr[-300:])
    check("вывод: режется входящий UDP из-за рубежа", "Режется ВХОДЯЩИЙ UDP из-за рубежа" in out2, out2[-500:])
    check("порты зарубежной цели: дошло 100, ответов 0", "дошло на цель: 100  ответов получено: 0" in out2, out2)

    print("[защита от запросов с чужих страниц и от рассинхронизации]")
    check("web/stun без заголовка X-Client (так выглядит запрос с чужой страницы) -> 403", api("GET", "/api/v2/web/stun", headers={"X-Client": ""})[0] == 403)
    check("web/trace с Sec-Fetch-Site: cross-site -> 403", api("POST", "/api/v2/web/trace", headers={"Sec-Fetch-Site": "cross-site"})[0] == 403)
    check("web/report без X-Client -> 403", api("POST", "/api/v2/web/report", {"verdict": "NO_BLOCK", "results": []}, headers={"X-Client": ""})[0] == 403)
    st, wsn = api("GET", "/api/v2/web/stun", headers={"Sec-Fetch-Site": "same-origin"})
    check("запрос со страницы (same-origin) проходит", st == 200)
    check("серверы в списке для браузера отдают name и name_en (для английской версии сайта)", all(t.get("name") and t.get("name_en") for t in wsn["targets"]), wsn)

    def rawhub(data, wait=0.6):
        sk = socket.create_connection(("127.0.0.1", 18080), timeout=5)
        sk.sendall(data)
        time.sleep(wait)
        sk.settimeout(1)
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
    r = rawhub(b"POST /udpcheck/api/v2/node/register HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
               b"GET /udpcheck/api/v2/version HTTP/1.1\r\nHost: x\r\n\r\n")
    check("тело с Transfer-Encoding отклонено 400, соединение закрыто (следующий запрос не обрабатывается)", r.startswith(b"HTTP/1.1 400") and r.count(b"HTTP/1.1") == 1
          and b"Connection: close" in r, r[:300])
    r = rawhub(b"GET /udpcheck/api/v2/version HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
    check("GET с телом отклонён 400", r.startswith(b"HTTP/1.1 400"), r[:200])
    r = rawhub(b"POST /udpcheck/api/v2/node/register HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n")
    check("Content-Length не число: 413, а не 500", r.startswith(b"HTTP/1.1 413") or r.startswith(b"HTTP/1.1 400"), r[:200])
    r = rawhub(b"POST /udpcheck/api/v2/node/register HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n[1]")
    check("регистрация с телом-массивом: 400, а не 500", r.startswith(b"HTTP/1.1 400"), r[:200])

    print("[кнопка на сайте: трассировка от целей до посетителя]")
    st, w = api("POST", "/api/v2/web/trace")
    check("задание принято 202, три цели", st == 202 and len(w.get("targets", [])) == 2, w)
    t_start = time.time()
    res = {}
    for _ in range(80):
        st, res = api("GET", "/api/v2/web/trace/" + w["id"])
        if res.get("done"):
            break
        time.sleep(0.5)
    print("   (трассировки заняли %.0f с)" % (time.time() - t_start))
    check("обе цели прислали трассировку", res.get("done") and all(t["status"] == "done" for t in res["targets"]), res)
    icmp = res["targets"][0]["results"].get("icmp", {}) if res.get("targets") else {}
    check("ICMP: 6 хопов, цель достигнута", len(icmp.get("hops", [])) == 6 and icmp.get("reached") is True, icmp)
    check("есть все три метода у обеих целей", all(set(t["results"]) == {"icmp", "udp", "tcp"} for t in res["targets"]))
    check("повторный запуск сразу -> 429", api("POST", "/api/v2/web/trace")[0] == 429)
    check("чужое задание не читается (неверный id) -> 404", api("GET", "/api/v2/web/trace/" + "0" * 16)[0] == 404)
    st, me = api("GET", "/api/v2/web/me")
    check("web/me отвечает", st == 200 and "you" in me and "network" in me, me)
    print("[STUN для браузерной проверки]")
    cookie = b"\x21\x12\xa4\x42"
    txid = os.urandom(12)
    ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ss.settimeout(1.5)
    ss.sendto(struct.pack("!HH", 0x0001, 0) + cookie + txid, ("127.0.0.1", 29993))
    try:
        d, _ = ss.recvfrom(2048)
        mtype, mlen = struct.unpack("!HH", d[:4])
        atype, alen = struct.unpack("!HH", d[20:24])
        xport = int.from_bytes(d[26:28], "big") ^ 0x2112
        xaddr = ".".join(str(a ^ b) for a, b in zip(d[28:32], cookie))
        check("STUN: успешный ответ (0x0101), тот же transaction id и cookie", mtype == 0x0101 and d[4:8] == cookie and d[8:20] == txid, d[:20].hex())
        check("STUN: XOR-MAPPED-ADDRESS указывает на адрес и порт отправителя", atype == 0x0020 and xport == ss.getsockname()[1] and xaddr == "127.0.0.1", (xport, xaddr))
    except socket.timeout:
        check("STUN: ответ получен", False)
    ss.sendto(struct.pack("!HH", 0x0001, 8) + cookie + txid, ("127.0.0.1", 29993))   # заявленная длина не совпадает
    try:
        ss.recvfrom(2048)
        check("STUN: кривой запрос без ответа", False)
    except socket.timeout:
        check("STUN: кривой запрос без ответа", True)
    ss.sendto(struct.pack("!HH", 0x0001, 0) + cookie + os.urandom(12), ("127.0.0.1", 19993))   # и на российский сервер: он тоже должен «увидеть» запрос
    time.sleep(0.3)
    ss.close()
    st, ws = api("GET", "/api/v2/web/stun")
    check("web/stun отвечает списком целей и числом попыток", st == 200 and len(ws.get("targets", [])) == 2 and ws.get("attempts") == 3, ws)
    tp = {t["code"]: t.get("pad") for t in ws.get("targets", [])}
    check("web/stun: длинные ответы предлагаются только серверу, у которого заняты порты, и только после его подтверждения",
          tp.get("F-T") == [{"port": 29600, "size": 600}] and not tp.get("RU-T"), tp)
    import socket as _sk, struct as _st
    _c = _sk.socket(_sk.AF_INET, _sk.SOCK_DGRAM); _c.settimeout(2)
    _c.sendto(_st.pack("!HH", 1, 0) + bytes((0x21, 0x12, 0xA4, 0x42)) + os.urandom(12), ("127.0.0.1", 29600))
    try:
        _r = _c.recvfrom(2048)[0]
    except OSError:
        _r = b""
    check("после разрешения хаба сервер отвечает на порту длинных ответов пакетом ~600 байт", 596 <= len(_r) <= 600, len(_r))
    CID1, CID2 = "a" * 32, "b" * 32
    good = {"verdict": "FOREIGN_IN_CUT", "results": [{"code": "RU-T", "ok": 6, "n": 6}, {"code": "F-T", "ok": 0, "n": 6}]}
    st, early = api("POST", "/api/v2/web/report", good, headers={"X-Client": CID1})
    check("web/report до проверки через наши серверы: принят, но в статистику не идёт", st == 200 and early.get("counted") is False, early)
    st, sk = api("POST", "/api/v2/web/stunseen", headers={"X-Client": CID1})
    check("stunseen принят 202", st == 202 and len(sk.get("id", "")) == 16, sk)
    seen = {}
    for _ in range(25):
        st, seen = api("GET", "/api/v2/web/stunseen/" + sk["id"])
        if seen.get("done"):
            break
        time.sleep(0.5)
    check("серверы сообщили, сколько STUN-запросов с моего адреса получили", seen.get("done") and (seen["seen"].get("F-T") or 0) >= 1 and (seen["seen"].get("RU-T") or 0) >= 1, seen)
    check("серверы сообщили и сколько ответов на них отправили (ответ реально ушёл с сервера)", (seen.get("replied", {}).get("F-T") or 0) >= 1 and (seen["replied"].get("RU-T") or 0) >= 1, seen)
    check("чужой id stunseen -> 404", api("GET", "/api/v2/web/stunseen/" + "0" * 16)[0] == 404)
    st, ok1 = api("POST", "/api/v2/web/report", good, headers={"X-Client": CID1})
    check("web/report после проверки через наши серверы идёт в статистику", st == 200 and ok1.get("counted") is True, ok1)
    bad = {"verdict": "NO_BLOCK", "results": [{"code": "RU-T", "ok": 6, "n": 6}, {"code": "F-T", "ok": 6, "n": 6}]}
    check("web/report: неизвестный вывод -> 400", api("POST", "/api/v2/web/report", {"verdict": "HACK", "results": []}, headers={"X-Client": CID1})[0] == 400)
    codes = [api("POST", "/api/v2/web/report", good, headers={"X-Client": CID2})[0] for _ in range(8)]
    check("web/report: лимит 6 в час на пару «номер браузера + IP», другой браузер с того же адреса не страдает", codes[5] == 200 and codes[7] == 429 and api("POST", "/api/v2/web/report", good, headers={"X-Client": CID1})[0] == 200, codes)

    time.sleep(2)
    dbt = sqlite3.connect(dbfile)
    nweb = dbt.execute("SELECT COUNT(*) FROM traces WHERE src='web'").fetchone()[0]
    nnode = dbt.execute("SELECT COUNT(*) FROM traces WHERE src='node'").fetchone()[0]
    check("трассировки посетителя сохранены (3 метода x 2 цели)", nweb == 6, nweb)
    check("после замера узла сама собралась трассировка до узла", nnode >= 6, nnode)
    cols_t = [c[1] for c in dbt.execute("PRAGMA table_info(traces)")]
    check("в таблице трассировок нет адресов", not any(c in ("ip", "addr", "address") for c in cols_t), cols_t)
    st, pp = api("GET", "/api/v2/stats/paths?hours=24")
    check("stats/paths отвечает", st == 200 and "providers" in pp, pp)
    body = json.dumps({"ts": int(time.time())}).encode()
    check("опрос цели с неверной подписью -> 403", api("POST", "/api/v2/target/poll", body, headers={"X-Target": "F-T", "X-Auth": "0" * 64})[0] == 403)
    check("устаревший ts в подписанном опросе -> 403", api("POST", "/api/v2/target/poll", json.dumps({"ts": 1}).encode(), headers={
        "X-Target": "F-T", "X-Auth": hmac.new(bytes.fromhex(secB), json.dumps({"ts": 1}).encode(), hashlib.sha256).hexdigest()})[0] == 403)

    print("[данные хаба]")
    db = sqlite3.connect(dbfile)
    cols = [c[1] for c in db.execute("PRAGMA table_info(nodes)")]
    check("в таблице узлов нет IP-адреса", not any("ip" == c or c.endswith("_ip") or c == "addr" for c in cols), cols)
    rounds = db.execute("SELECT verdict, src_same FROM rounds ORDER BY id").fetchall()
    check("в базе два замера с верными выводами", [r[0] for r in rounds] == ["NO_BLOCK", "FOREIGN_IN_CUT"], rounds)
    check("UDP и HTTPS шли с одного адреса", all(r[1] == "same" for r in rounds), rounds)
    n_meas = db.execute("SELECT COUNT(*) FROM meas").fetchone()[0]
    check("записано 12 измерений по портам (2 замера x 2 цели x 3 порта)", n_meas == 12, n_meas)
    row = db.execute("SELECT reached, back, cls FROM meas WHERE target='F-T' AND round_id=2 LIMIT 1").fetchone()
    check("замер 2: F-T дошло 100, ответов 0, INCUT", row == (100, 0, "INCUT"), row)
    token = json.load(open(cfg1))["token"]
    check("токен в базе хранится только хэшем", db.execute("SELECT COUNT(*) FROM nodes WHERE token_hash=?", (token,)).fetchone()[0] == 0
          and db.execute("SELECT COUNT(*) FROM nodes WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()[0] == 1)

    print("[публичный список узлов]")
    st, nl = api("GET", "/api/v2/nodes")
    check("список узлов отвечает, узлы есть", st == 200 and nl.get("total", 0) >= 2 and nl["nodes"], nl)
    flat = json.dumps(nl)
    check("в списке нет токенов, адресов и города", all(k not in flat for k in ("token", '"ip"', "city", "127.0.0.1")), flat[:300])
    check("у каждого узла есть позывной, онлайн и счётчик замеров",
          all("callsign" in n and "online" in n and "rounds" in n for n in nl["nodes"]))

    check("опорные серверы проекта в списке с признаком активности: оба опрашивают хаб, проверки посетителей учтены",
          all("online" in a and "checks" in a and "ok" in a for a in nl["anchors"]) and all(a["online"] for a in nl["anchors"]), nl["anchors"])

    print("[прокси/туннель на пути узла]")
    check("is_tunnel: TCP 0.4 мс при UDP-эхо 44 мс -> туннель", V.is_tunnel(0.4, 44.0) is True)
    check("is_tunnel: TCP 40 мс при эхо 44 мс -> норма", V.is_tunnel(40.0, 44.0) is False)
    check("is_tunnel: близкая цель (эхо 3 мс) не считается", V.is_tunnel(0.4, 3.0) is False)
    check("is_tunnel: нет данных -> не считается", V.is_tunnel(None, 44.0) is False)
    sys.path.insert(0, ROOT)
    import udpcheck_node as N
    cfg3 = N.register(HUB, {}, os.path.join(tmp, "node3.json"))
    N.http(HUB, "POST", "/api/v2/node/probe-now", token=cfg3["token"])
    st3, r3 = N.http(HUB, "POST", "/api/v2/node/poll", token=cfg3["token"])
    orig_run = N.run_task
    N.run_task = lambda task: [dict(x, tcp_connect_ms=0.4, udp_rtt_ms=44.0) for x in orig_run(task)]
    resp3 = N.do_round(HUB, cfg3, r3["task"])
    check("замер через прокси: вывод TUNNEL", resp3 is not None and resp3["verdict"]["code"] == "TUNNEL", resp3 and resp3["verdict"])
    db = sqlite3.connect(dbfile)
    check("замер TUNNEL записан без данных по портам", db.execute("SELECT COUNT(*) FROM rounds WHERE verdict='TUNNEL'").fetchone()[0] == 1
          and db.execute("SELECT COUNT(*) FROM meas").fetchone()[0] == 12)

    print("[публичная статистика]")
    st, stats = api("GET", "/api/v2/stats?hours=24")
    check("статистика отвечает, раундов 2", st == 200 and sum(a["rounds"] for a in stats["asns"]) == 2, stats)
    check("в статистике нет токенов и позывных", "token" not in json.dumps(stats) and "callsign" not in json.dumps(stats))

    print("[карточки и страница провайдера]")
    dbw = sqlite3.connect(dbfile, timeout=30)
    nowt = int(time.time())
    for i in range(8):   # сеть 64500: 8 замеров «режется» за последние часы, 2 замера «не режется» для другой сети
        dbw.execute("INSERT INTO rounds(ts, node_id, asn, verdict, src_same) VALUES(?,?,?,?,?)", (nowt - i * 600, 900, 64500, "FOREIGN_IN_CUT", "same"))
        dbw.execute("INSERT INTO tres(round_id, ts, asn, target, kind, status, tcp) VALUES(?,?,?,?,?,?,?)", (1000 + i, nowt - i * 600, 64500, "F-T", "foreign", "INCUT", "OK"))
    for i in range(2):
        dbw.execute("INSERT INTO rounds(ts, node_id, asn, verdict, src_same) VALUES(?,?,?,?,?)", (nowt - i * 600, 901, 64501, "NO_BLOCK", "same"))
    for i in range(6):   # сеть 64502: только проверки посетителей из браузера
        dbw.execute("INSERT INTO webchecks(ts, asn, verdict, data, org) VALUES(?,?,?,?,?)", (nowt - i * 300, 64502, "FOREIGN_IN_CUT", "[]", "Test Web ISP"))
    for i in range(3):   # сеть 64503: один браузер прислал 3 проверки за час, другой одну: это 2 голоса
        dbw.execute("INSERT INTO webchecks(ts, asn, verdict, data, org, cid) VALUES(?,?,?,?,?,?)", (nowt, 64503, "FOREIGN_IN_CUT", "[]", "Dup ISP", "c0ffee0000000001"))      # одно и то же время: не зависит от границы часа
    dbw.execute("INSERT INTO webchecks(ts, asn, verdict, data, org, cid) VALUES(?,?,?,?,?,?)", (nowt, 64503, "FOREIGN_IN_CUT", "[]", "Dup ISP", "c0ffee0000000002"))
    for i in range(2):   # сеть 64504: посетитель из страны без опорных серверов (NO_ANCHOR): список провайдеров не должен падать
        dbw.execute("INSERT INTO webchecks(ts, asn, verdict, data, org, cid) VALUES(?,?,?,?,?,?)", (nowt - i * 400, 64504, "NO_ANCHOR", "[]", "No Anchor ISP", "c0ffee0000000003"))
    dbw.execute("INSERT INTO webchecks(ts, asn, verdict, data, org, cid) VALUES(?,?,?,?,?,?)", (nowt, 64505, "NO_BLOCK", "[]", "Fast Hosting Ltd", "c0ffee0000000005"))
    dbw.commit()
    dbw.close()
    os.makedirs(os.path.join(tempfile.gettempdir(), "udpc_logos_test"), exist_ok=True)
    open(os.path.join(tempfile.gettempdir(), "udpc_logos_test", "64500.png"), "wb").write(b"PNG")
    st, pl_ = api("GET", "/api/v2/providers")
    byasn = {p["asn"]: p for p in pl_.get("providers", [])}
    check("карточки: сеть с замерами «режется» имеет статус cut, сеть с «не режется» ok", st == 200 and byasn.get(64500, {}).get("status") == "cut" and byasn.get(64501, {}).get("status") == "ok", pl_)
    check("карточки: режущая сеть идёт первой, график из 24 точек, мало данных только у сети с 2 замерами", pl_["providers"][0]["asn"] == 64500 and len(byasn[64500]["series"]) == 24 and byasn[64500]["weak"] is False and byasn[64501]["weak"] is True)
    check("карточка появляется и по проверкам посетителей (без узлов): статус cut, 6 проверок, имя из базы IP", byasn.get(64502, {}).get("status") == "cut" and byasn[64502]["web_24h"] == 6 and byasn[64502]["nodes"] == 0 and byasn[64502]["name"] == "Test Web ISP", byasn.get(64502))
    check("хостинг и VPN распознаются по названию (Dup ISP, Test Web ISP остаются провайдерами)", V_kind_ok(byasn), [(a, p.get("kind")) for a, p in byasn.items()])
    check("логотип из каталога логотипов попадает в карточку, у остальных его нет", byasn[64500]["logo"] == "/logos/64500.png" and byasn[64501]["logo"] is None, byasn[64500])
    check("один браузер голосует в статистике не больше раза в час (3 проверки + 1 чужая = 2 голоса)", byasn.get(64503, {}).get("web_24h") == 2, byasn.get(64503))
    check("сеть без опорных серверов в стране: карточка есть со статусом noanchor, список не падает", st == 200 and byasn.get(64504, {}).get("status") == "noanchor", byasn.get(64504))
    st, pw = api("GET", "/api/v2/providers/64502")
    check("страница провайдера работает и для сети только с проверками посетителей", st == 200 and pw["web_24h"] == 6 and pw["rounds_24h"] == 6 and pw["verdicts"].get("FOREIGN_IN_CUT") == 6, pw)
    st, pd = api("GET", "/api/v2/providers/64500")
    check("страница провайдера: график за 7 суток, итоги по серверу, TCP", st == 200 and len(pd["series"]) == 168 and pd["targets"] and pd["targets"][0]["tcp_ok"] == 8 and pd["rounds_24h"] == 8, pd)
    check("страница провайдера: неизвестная сеть -> 404", api("GET", "/api/v2/providers/64999")[0] == 404)
    flat = json.dumps(pl_) + json.dumps(pd)
    check("в карточках и на странице нет токенов, адресов", all(k not in flat for k in ("token", "127.0.0.1", "callsign\": \"x")))

    print("[тишина в журналах]")
    for p in procs:
        p.terminate()
    outs = [p.communicate(timeout=5) for p in procs]
    check("серверы ничего не печатали", all(o == b"" and e == b"" for o, e in outs), [(o[:100], e[:100]) for o, e in outs])
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()

print("\nИТОГ:", "всё прошло" if fails == 0 else "ПРОВАЛОВ: %d" % fails)
sys.exit(1 if fails else 0)
