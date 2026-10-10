#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Опорные серверы участников: узел с --ref принимает задания хаба, хаб проверяет доступность, другие узлы замеряют до него.
Запуск: python tests/test_refs_local.py   (хаб и две цели поднимаются локально, адреса узлов подставляются через X-Forwarded-For)"""
import contextlib
import hashlib
import hmac
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)
os.environ["UDPCHECK_LANG"] = "ru"          # тесты сверяют русский вывод агента
import udpcheck_node as N


fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)) if (extra and not cond) else ""))
    if not cond:
        fails += 1


tmp = tempfile.mkdtemp(prefix="udpc_ref_")
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
base_env = dict(os.environ, UDPCHECK_TRUSTED_PROXIES="127.0.0.1", UDPCHECK_GEO_DIR=os.path.join(tmp, "nogeo"),
                UDPCHECK_PROBE_INTERVAL="900", UDPCHECK_ALLOW_NON_GLOBAL="1", UDPCHECK_DEFAULT_COUNTRY="XX", UDPCHECK_DEV_COUNTRIES="10.1.=ZZ", UDPCHECK_AGENT_FILE=os.path.join(ROOT, "udpcheck_node.py"), UDPCHECK_VOL_EXPLORE="0", UDPCHECK_VOL_CACHE="0", UDPCHECK_REF_MIN_AGE="0", UDPCHECK_REF_MIN_ROUNDS="1", UDPCHECK_TRACEROUTE=os.path.join(HERE, "fake_traceroute.cmd"))

# порты опорного сервера на время теста (боевые 47321/51820 могут быть заняты)
N.REF_UDP_PORTS = [38321, 38322]
N.REF_TCP_PORT = 38321

XFF = {"v": "127.0.0.1"}


def http_x(hub, method, path, body=None, token=None, timeout=40):
    """N.http с подставленным адресом клиента: хаб читает его из X-Forwarded-For (доверенный прокси 127.0.0.1)."""
    data = json.dumps(body).encode("utf-8") if body is not None else (b"" if method == "POST" else None)
    req = urllib.request.Request(hub + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Forwarded-For", XFF["v"])
    if path.startswith("/api/v2/web/"):
        req.add_header("X-Client", "d" * 32)          # запросы страницы идут с номером браузера
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


N.http = http_x


def start(http_port, udp, tid, secret, tcp, extra=None):
    env = dict(base_env, UDPCHECK_HTTP_PORT=str(http_port), UDPCHECK_UDP_BIND="127.0.0.1", UDPCHECK_PAD_PORTS="", UDPCHECK_UDP_PORTS=",".join(map(str, udp)),
               UDPCHECK_TARGET_ID=tid, UDPCHECK_TARGET_SECRET=secret, UDPCHECK_HUB_URL=HUB, UDPCHECK_TARGET_TCP_PORT=str(tcp))
    env.update(extra or {})
    return subprocess.Popen([sys.executable, SERVER], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def db_q(sql, args=()):
    c = sqlite3.connect(dbfile)
    try:
        return c.execute(sql, args).fetchall()
    finally:
        c.close()


procs = []
try:
    procs.append(start(18080, [19993, 19777, 19321], "RU-T", secA, 18443, {"UDPCHECK_HUB_DB": dbfile, "UDPCHECK_HUB_TARGETS": tfile, "UDPCHECK_POLL_WAIT": "3"}))
    procs.append(start(18081, [29993, 29777, 29321], "F-T", secB, 28443))
    for _ in range(60):
        try:
            if N.http(HUB, "GET", "/api/v1/health")[0] == 200 and urllib.request.urlopen("http://127.0.0.1:18081/udpcheck/api/v1/health").status == 200:
                break
        except OSError:
            time.sleep(0.2)
    else:
        sys.exit("стенд не поднялся: " + procs[0].stderr.read().decode(errors="replace"))

    print("[узел B: включение опорной роли]")
    XFF["v"] = "127.0.0.1"
    cfgB = N.register(HUB, {}, os.path.join(tmp, "nodeB.json"))
    tokB = cfgB["token"]
    check("без токена объявить опорный сервер нельзя -> 401", N.http(HUB, "POST", "/api/v2/node/ref", {"udp_ports": [38321]})[0] == 401)
    check("порт ниже 1024 -> 400", N.http(HUB, "POST", "/api/v2/node/ref", {"udp_ports": [777]}, token=tokB)[0] == 400)
    check("четыре порта -> 400", N.http(HUB, "POST", "/api/v2/node/ref", {"udp_ports": [2000, 2001, 2002, 2003]}, token=tokB)[0] == 400)
    ref = N.RefServer(HUB, tokB)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        started = ref.start()
    check("опорная роль запустилась и хаб принял её (доступность подтверждена)", started and ref.verified is True, buf.getvalue())
    check("агент сообщил о включённой роли", "Опорная роль включена" in buf.getvalue(), buf.getvalue())
    rows = db_q("SELECT id, ip, udp_ports, tcp_port, kind, verified FROM refs")
    check("в базе одна запись, проверена, порты и TCP сохранены", len(rows) == 1 and rows[0][5] == 1 and rows[0][3] == 38321
          and json.loads(rows[0][2]) == [38321, 38322], rows)
    st, nl = N.http(HUB, "GET", "/api/v2/nodes")
    refinfo = [n.get("ref") for n in nl.get("nodes", []) if n.get("callsign") == cfgB["callsign"]]
    check("в публичном списке у узла B виден опорный сервер", refinfo and refinfo[0] and refinfo[0]["active"] is True, nl)
    flat = json.dumps(nl)
    check("в публичном списке нет секрета и адреса опорного сервера", ref.secret.hex() not in flat and "127.0.0.1" not in flat)

    print("[защита]")
    XFF["v"] = "127.0.0.1"
    cfgC = N.register(HUB, {}, os.path.join(tmp, "nodeC.json"))
    st, r = N.http(HUB, "POST", "/api/v2/node/ref", {"udp_ports": [38321], "verify": True}, token=cfgC["token"])
    check("второй опорный сервер с тем же адресом отклонён", st == 200 and r.get("ok") is False and "уже работает" in (r.get("reason") or ""), r)
    XFF["v"] = "::1"
    st6, r6 = N.http(HUB, "POST", "/api/v2/node/ref", {"udp_ports": [38399]}, token=cfgC["token"])
    check("узел на IPv6 опорным не становится", st6 == 200 and r6.get("ok") is False and "IPv6" in (r6.get("reason") or ""), r6)
    XFF["v"] = "10.255.255.1"
    cfgD = N.register(HUB, {}, os.path.join(tmp, "nodeD.json"))
    t0 = time.time()
    st, r = N.http(HUB, "POST", "/api/v2/node/ref", {"udp_ports": [38399]}, token=cfgD["token"])
    check("недоступный снаружи порт: запись есть, но не проверена", st == 200 and r.get("ok") is True and r.get("verified") is False, r)
    st, r = N.http(HUB, "POST", "/api/v2/node/ref", {"udp_ports": [38399], "verify": True}, token=cfgD["token"])
    check("проверка недоступного порта отклоняется с причиной", st == 200 and r.get("verified") is False and r.get("reason"), r)
    print("   (проверки недоступного порта заняли %.0f с)" % (time.time() - t0))
    rid_b = rows[0][0]
    body = json.dumps({"taskid": "00" * 8, "ports": {}}).encode()
    for who, sec in (("с чужим секретом", bytes.fromhex(secA)), ("с секретом хаба", os.urandom(32))):
        req = urllib.request.Request(HUB + "/api/v2/target/report", data=body, method="POST",
                                     headers={"X-Target": "REF-%d" % rid_b, "X-Auth": hmac.new(sec, body, hashlib.sha256).hexdigest()})
        try:
            code = urllib.request.urlopen(req).status
        except urllib.error.HTTPError as e:
            code = e.code
        check("отчёт опорного сервера %s -> 403" % who, code == 403, code)
    unver = db_q("SELECT id FROM refs WHERE verified=0")
    req = urllib.request.Request(HUB + "/api/v2/target/report", data=body, method="POST",
                                 headers={"X-Target": "REF-%d" % unver[0][0], "X-Auth": "0" * 64})
    try:
        code = urllib.request.urlopen(req).status
    except urllib.error.HTTPError as e:
        code = e.code
    check("отчёт непроверенного опорного сервера -> 403", code == 403, code)

    print("[узел A: замер получает чужой опорный сервер]")
    XFF["v"] = "10.0.0.5"
    cfgA = N.register(HUB, {}, os.path.join(tmp, "nodeA.json"))
    N.http(HUB, "POST", "/api/v2/node/probe-now", token=cfgA["token"])
    st, pr0 = N.http(HUB, "POST", "/api/v2/node/poll", token=cfgA["token"])
    check("новому узлу (без замеров) чужие опорные серверы не выдаются", pr0.get("task") and len(pr0["task"]["targets"]) == 2 and not any(t.get("community") for t in pr0["task"]["targets"]), pr0)
    N.do_round(HUB, cfgA, pr0["task"])
    cdb0 = sqlite3.connect(dbfile)
    cdb0.execute("UPDATE nodes SET probe_now=1 WHERE callsign=?", (cfgA["callsign"],))
    cdb0.commit()
    cdb0.close()
    st, pr = N.http(HUB, "POST", "/api/v2/node/poll", token=cfgA["token"])
    task = pr.get("task") or {}
    comm = [t for t in task.get("targets", []) if t.get("community")]
    check("в задании две обычные цели и один чужой опорный сервер", len(task.get("targets", [])) == 3 and len(comm) == 1, task)
    check("опорный сервер участника выдан с кодом REF-<n> и позывным узла", comm and comm[0]["code"] == "REF-%d" % rid_b and comm[0]["name"] == cfgB["callsign"], comm)
    t0 = time.time()
    resp = N.do_round(HUB, cfgA, task)
    print("   (замер занял %.0f с)" % (time.time() - t0))
    import socket as _sk, struct as _st
    ssk = _sk.socket(_sk.AF_INET, _sk.SOCK_DGRAM)
    ssk.settimeout(1.5)
    cookie, txid = bytes((0x21, 0x12, 0xA4, 0x42)), os.urandom(12)
    ssk.sendto(_st.pack("!HH", 0x0001, 0) + cookie + txid, ("127.0.0.1", 38321))
    try:
        d, _ = ssk.recvfrom(2048)
        mt, _ml = _st.unpack("!HH", d[:4])
        port = int.from_bytes(d[26:28], "big") ^ 0x2112
        check("агент-опорный сервер отвечает на STUN: успешный ответ, тот же transaction id, адрес и порт отправителя",
              mt == 0x0101 and d[8:20] == txid and port == ssk.getsockname()[1], d[:20].hex())
    except _sk.timeout:
        check("агент-опорный сервер отвечает на STUN", False)
    ssk.sendto(_st.pack("!HH", 0x0001, 8) + cookie + txid, ("127.0.0.1", 38321))      # заявленная длина не совпадает
    try:
        ssk.recvfrom(2048)
        check("агент: кривой STUN-запрос без ответа", False)
    except _sk.timeout:
        check("агент: кривой STUN-запрос без ответа", True)
    ssk.close()
    st, wsx = N.http(HUB, "GET", "/api/v2/web/stun")
    vol = [t for t in wsx.get("targets", []) if t.get("community")]
    check("в списке для браузера посетителя есть сервер добровольца (свидетель), у проекта их нет среди community", len(vol) == 1 and vol[0]["code"] == "REF-%d" % rid_b
          and sorted(vol[0]["ports"]) == [38321, 38322] and not vol[0]["control"], wsx)
    check("в списке для браузера по-прежнему обе цели проекта", len([t for t in wsx["targets"] if not t.get("community")]) == 2, wsx)
    # здоровье серверов добровольцев: если до него почти никто из посетителей не достаёт, ему перестают показывать проверки
    hdb = sqlite3.connect(dbfile)
    for i in range(8):
        hdb.execute("INSERT INTO webchecks(ts, asn, verdict, data, org, cid) VALUES(?,?,?,?,?,?)", (int(time.time()) - i, 64999, "NO_BLOCK",
                    json.dumps([{"code": "REF-%d" % rid_b, "ok": 0, "n": 6, "seen": -1}]), "Probe ISP", "feed%028d" % i))
    hdb.commit()
    st, wsy = N.http(HUB, "GET", "/api/v2/web/stun")
    check("сервер добровольца, до которого не достают посетители (0 из 8 проверок), из списка для браузера убран", not [t for t in wsy["targets"] if t.get("community")], wsy)
    hdb.execute("DELETE FROM webchecks WHERE asn=64999")
    hdb.commit()
    hdb.close()
    st, wsz = N.http(HUB, "GET", "/api/v2/web/stun")
    check("после удаления плохой статистики сервер снова показывается", len([t for t in wsz["targets"] if t.get("community")]) == 1, wsz)
    check("итог не изменился: блокировки не обнаружено", resp and resp["verdict"]["code"] == "NO_BLOCK", resp and resp["verdict"])
    rt = [t for t in resp["targets"] if t.get("community")]
    check("опорный сервер участника: отчёт пришёл, все порты чисто", rt and rt[0]["status"] == "OK" and all(p["class"] == "OK" for p in rt[0]["ports"]), rt)
    check("TCP-проверка до опорного сервера участника прошла", rt and rt[0]["tcp"] == "OK", rt)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        N.show(resp)
    check("агент пишет про опорный сервер участника и что в итог он не входит", "опорный сервер участника" in buf.getvalue() and "в итог не входит" in buf.getvalue(), buf.getvalue())
    check("в таблицах замеров есть строки опорного сервера", db_q("SELECT COUNT(*) FROM tres WHERE target=?", ("REF-%d" % rid_b,))[0][0] == 1)
    st, stats = N.http(HUB, "GET", "/api/v2/stats?hours=24")
    check("статистика по провайдерам не содержит серверов участников", st == 200 and "REF-" not in json.dumps(stats), stats)
    st, nl = N.http(HUB, "GET", "/api/v2/nodes")
    refinfo = [n.get("ref") for n in nl["nodes"] if n.get("callsign") == cfgB["callsign"]][0]
    check("в списке у опорного сервера растёт число проверок", refinfo["checks"] == 1 and refinfo["ok"] == 1, refinfo)
    XFF["v"] = "127.0.0.1"
    N.http(HUB, "POST", "/api/v2/node/probe-now", token=tokB)
    st, prb = N.http(HUB, "POST", "/api/v2/node/poll", token=tokB)
    check("узлу B задание приходит без его же опорного сервера", prb.get("task") and not any(t.get("community") for t in prb["task"]["targets"]), prb)
    check("опрос сообщает состояние опорного сервера", prb.get("ref_verified") is True, prb)
    # дорешать задание B, чтобы оно не висело
    N.do_round(HUB, {"token": tokB}, prb["task"])

    print("[другая страна: нет опорного сервера проекта]")
    XFF["v"] = "10.1.0.5"
    cfgE = N.register(HUB, {}, os.path.join(tmp, "nodeE.json"))
    st, wm = N.http(HUB, "GET", "/api/v2/web/me")
    check("посетитель из страны без опорных серверов: web/me знает страну и что опоры нет", wm["you"]["country"] == "ZZ" and wm["home"] == {"anchors": 0, "community": 0}, wm)
    st, ws = N.http(HUB, "GET", "/api/v2/web/stun")
    check("для него все серверы проекта «зарубежные»", ws["country"] == "ZZ" and all(t["kind"] == "foreign" for t in ws["targets"]), ws)
    cdb = sqlite3.connect(dbfile)
    cdb.execute("UPDATE nodes SET probe_now=1 WHERE callsign=?", (cfgE["callsign"],))
    cdb.commit()
    st, pe = N.http(HUB, "POST", "/api/v2/node/poll", token=cfgE["token"])
    check("в задании узла из этой страны нет контроля «своя страна»", pe.get("task") and not any(t["kind"] == "home" and not t["community"] for t in pe["task"]["targets"]), pe)
    resp = N.do_round(HUB, cfgE, pe["task"])
    check("итог: NO_ANCHOR с предложением помочь", resp and resp["verdict"]["code"] == "NO_ANCHOR" and "не на что опираться" in resp["verdict"]["text"], resp and resp["verdict"])
    print("[другая страна: серверы участников как контроль]")
    cdb.execute("UPDATE refs SET country='ZZ' WHERE id=?", (rid_b,))      # «сервер B стоит в стране ZZ»
    cdb.execute("UPDATE nodes SET probe_now=1 WHERE callsign=?", (cfgE["callsign"],))
    cdb.commit()
    st, wm = N.http(HUB, "GET", "/api/v2/web/me")
    check("web/me: в стране есть один сервер участника", wm["home"] == {"anchors": 0, "community": 1}, wm)
    st, pe = N.http(HUB, "POST", "/api/v2/node/poll", token=cfgE["token"])
    ctl = [t for t in pe["task"]["targets"] if t.get("control")]
    check("серверу участника в этой стране выдана роль контроля, он «своя страна»", len(ctl) == 1 and ctl[0]["kind"] == "home" and ctl[0]["code"] == "REF-%d" % rid_b, pe)
    resp = N.do_round(HUB, cfgE, pe["task"])
    check("с контролем участника итог строится (NO_BLOCK), сервер помечен контролем", resp and resp["verdict"]["code"] == "NO_BLOCK" and any(t.get("control") for t in resp["targets"]), resp and resp["verdict"])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        N.show(resp)
    check("агент пишет «в итог входит» для контроля участника", "входит в итог" in buf.getvalue(), buf.getvalue())
    cdb.execute("UPDATE refs SET country='XX' WHERE id=?", (rid_b,))
    cdb.commit()
    cdb.close()
    XFF["v"] = "10.0.0.5"

    print("[роль «опорный сервер»: заданий на проверку нет]")
    XFF["v"] = "127.0.0.1"
    cdb = sqlite3.connect(dbfile)
    cdb.execute("UPDATE nodes SET probe_now=1 WHERE callsign=?", (cfgC["callsign"],))
    cdb.commit()
    cdb.close()
    st, pc = N.http(HUB, "POST", "/api/v2/node/poll", {"role": "ref"}, token=cfgC["token"])
    check("узел с ролью ref не получает заданий, даже если время пришло", st == 200 and pc.get("task") is None, pc)
    st, nl2 = N.http(HUB, "GET", "/api/v2/nodes")
    roles = {n["callsign"]: n["role"] for n in nl2["nodes"]}
    check("в списке у него роль ref, у обычного узла node", roles.get(cfgC["callsign"]) == "ref" and roles.get(cfgA["callsign"]) == "node", roles)
    ent = [n for n in nl2["nodes"] if n["callsign"] == cfgC["callsign"]][0]
    check("в публичном списке про сервер нет хостинга (сети и организации), домашний узел остаётся с сетью",
          ent["asn"] is None and ent["org"] is None and all(n["role"] != "node" or "asn" in n for n in nl2["nodes"]), ent)
    check("у опорных серверов проекта в списке код, имя, страна и активность (без сети и хостинга)",
          all(set(a) == {"code", "name", "name_en", "country", "online", "checks", "ok"} for a in nl2["anchors"]), nl2["anchors"])
    st, ipr = N.http(HUB, "GET", "/api/v2/ip")
    check("/api/v2/ip отдаёт адрес запрашивающего (для выбора роли установщиком)", st == 200 and ipr.get("ip") == "127.0.0.1", ipr)
    XFF["v"] = "10.0.0.5"

    print("[версия агента: только уведомляем]")
    cdb = sqlite3.connect(dbfile)
    cdb.execute("UPDATE nodes SET probe_now=0 WHERE callsign=?", (cfgC["callsign"],))
    cdb.commit()
    cdb.close()
    XFF["v"] = "127.0.0.1"
    st, pv = N.http(HUB, "POST", "/api/v2/node/poll", {"role": "ref", "v": "0.1"}, token=cfgC["token"])
    check("старая версия агента: хаб сообщает, что есть новая (outdated), но работать не мешает", st == 200 and pv.get("agent", {}).get("outdated") is True and pv["agent"]["latest"] == N.VERSION, pv)
    st, nlv = N.http(HUB, "GET", "/api/v2/nodes")
    check("в списке узлов у такого узла стоит пометка outdated и версия", any(n["callsign"] == cfgC["callsign"] and n.get("outdated") and n.get("ver") == "0.1" for n in nlv["nodes"]), nlv)
    st, pv2 = N.http(HUB, "POST", "/api/v2/node/poll", {"role": "ref", "v": N.VERSION}, token=cfgC["token"])
    check("актуальная версия: уведомления нет", pv2.get("agent", {}).get("outdated") is False, pv2)
    XFF["v"] = "10.0.0.5"

    print("[агент без опорной роли]")
    st, rr = N.http(HUB, "POST", "/api/v2/node/poll", {"ref": True}, token=tokB)
    check("опрос с ref:true запись сохраняет", db_q("SELECT COUNT(*) FROM refs WHERE id=?", (rid_b,))[0][0] == 1)
    print("[смена адреса узла]")
    XFF["v"] = "127.0.0.2"
    st, pr2 = N.http(HUB, "POST", "/api/v2/node/poll", token=tokB)
    check("после смены адреса хаб сбрасывает проверку и говорит об этом узлу", pr2.get("ref_verified") is False, pr2)
    check("в базе опорный сервер снят с выдачи", db_q("SELECT verified FROM refs WHERE id=?", (rid_b,))[0][0] == 0)
    XFF["v"] = "10.0.0.5"
    cdb = sqlite3.connect(dbfile)
    cdb.execute("UPDATE nodes SET probe_now=1 WHERE callsign=?", (cfgA["callsign"],))   # probe-now ограничен раз в минуту
    cdb.commit()
    cdb.close()
    st, pa = N.http(HUB, "POST", "/api/v2/node/poll", token=cfgA["token"])
    check("пока адрес не подтверждён, другим узлам опорный сервер не выдаётся", pa.get("task") and not any(t.get("community") for t in pa["task"]["targets"]), pa)
    N.do_round(HUB, cfgA, pa["task"])
    XFF["v"] = "127.0.0.1"    # (ответ на 127.0.0.2 в Windows приходит с 127.0.0.1, поэтому «возвращаем» прежний адрес)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ref.maybe_handshake(False)
    check("агент сам заново подтверждает опорный сервер", ref.verified is True and db_q("SELECT verified, ip FROM refs WHERE id=?", (rid_b,))[0] == (1, "127.0.0.1"), (buf.getvalue(), ref.verified, db_q("SELECT verified, ip, udp_ports FROM refs WHERE id=?", (rid_b,))))

    N.http(HUB, "POST", "/api/v2/node/poll", {"ref": False}, token=tokB)
    check("опрос с ref:false (агент без опорной роли) убирает запись о ней", db_q("SELECT COUNT(*) FROM refs WHERE id=?", (rid_b,))[0][0] == 0)

    print("[тишина в журналах]")
    for p in procs:
        p.terminate()
    outs = [p.communicate(timeout=5) for p in procs]
    check("серверы ничего не печатали", all(o == b"" and e == b"" for o, e in outs), [(o[:100], e[:200]) for o, e in outs])
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()

print("\nИТОГ:", "всё прошло" if fails == 0 else "ПРОВАЛОВ: %d" % fails)
sys.exit(1 if fails else 0)
