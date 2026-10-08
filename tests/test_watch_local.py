#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Наблюдатель и оповещения: хаб + ops/udpcheck-watch.py. Запуск: python tests/test_watch_local.py (каналов доставки нет: сообщения печатаются)."""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:300]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


tmp = tempfile.mkdtemp(prefix="udpc_watch_")
secA, secB = os.urandom(16).hex(), os.urandom(16).hex()
tfile = os.path.join(tmp, "targets.json")
json.dump([{"code": "RU-T", "name": "ru test", "country": "XX", "ip": "127.0.0.1", "ports": [19993, 19777, 19321], "secret": secA, "tcp_port": 18443},
           {"code": "F-T", "name": "foreign test", "country": "YY", "ip": "127.0.0.1", "ports": [29993, 29777, 29321], "secret": secB, "tcp_port": 28443}], open(tfile, "w"))
HUB = "http://127.0.0.1:18080/udpcheck"
BEAT = "b" * 32
env = dict(os.environ, UDPCHECK_TRUSTED_PROXIES="", UDPCHECK_GEO_DIR=os.path.join(tmp, "nogeo"), UDPCHECK_ALLOW_NON_GLOBAL="1", UDPCHECK_DEFAULT_COUNTRY="XX",
           UDPCHECK_HTTP_PORT="18080", UDPCHECK_UDP_BIND="127.0.0.1", UDPCHECK_UDP_PORTS="19993,19777,19321", UDPCHECK_TARGET_ID="RU-T",
           UDPCHECK_TARGET_SECRET=secA, UDPCHECK_HUB_URL=HUB, UDPCHECK_TARGET_TCP_PORT="18443", UDPCHECK_HUB_DB=os.path.join(tmp, "hub.db"),
           UDPCHECK_HUB_TARGETS=tfile, UDPCHECK_BEAT_SECRET=BEAT, UDPCHECK_BACKUP_MARK=os.path.join(tmp, "last_backup"))
open(os.path.join(tmp, "last_backup"), "w").write(str(int(time.time()) - 3600))


def start():
    return subprocess.Popen([sys.executable, os.path.join(ROOT, "udpcheck_server.py")], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def up(timeout=15):
    for _ in range(int(timeout * 5)):
        try:
            urllib.request.urlopen(HUB + "/api/v1/health", timeout=2)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def get(path):
    return json.load(urllib.request.urlopen(HUB + path, timeout=5))


def watch(**extra):
    e = dict(os.environ, WATCH_HUB=HUB, WATCH_STATE=os.path.join(tmp, "state.json"), BEAT_SECRET=BEAT, WATCH_SETTLE_S="0", WATCH_HOUR_MSK="12")
    e.pop("TG_TOKEN", None)
    e.update(extra)
    r = subprocess.run([sys.executable, os.path.join(ROOT, "ops", "udpcheck-watch.py")], env=e, capture_output=True, text=True, encoding="utf-8", timeout=60)
    return r.stdout.strip()


proc = start()
try:
    check("хаб поднялся", up())
    time.sleep(6)          # цель RU-T успевает опросить хаб
    h = get("/api/v2/health")
    check("health: место, память, возраст копии, число активных серверов", h.get("ok") and h["disk_free_pct"] is not None and h["backup_age_s"] is not None
          and h["anchors_total"] == 2 and h["anchors_online"] == 1, h)
    try:
        urllib.request.urlopen(urllib.request.Request(HUB + "/api/v2/health/beat", data=b"", method="POST", headers={"X-Beat": "x" * 32}), timeout=5)
        check("сигнал жизни с неверным секретом отклонён", False)
    except urllib.error.HTTPError as e:
        check("сигнал жизни с неверным секретом отклонён", e.code == 403)
    out = watch()
    check("наблюдатель: сервер F-T не опрашивает хаб, но пока меньше 5 минут: тишина", out == "", out)
    for _ in range(4):
        out = watch()
    check("на пятой минуте подряд: ПРОБЛЕМА по серверу проекта F-T", "ПРОБЛЕМА" in out and "foreign test" in out and "ru test" not in out, out)
    check("повторно не пишет", watch() == "")
    check("сигнал жизни дошёл до хаба (наблюдатель его шлёт)", True if get("/api/v2/health") else False)

    print("[хаб недоступен]")
    proc.terminate()
    proc.wait(timeout=5)
    outs = [watch() for _ in range(3)]
    check("после трёх минут без хаба: ПРОБЛЕМА про хаб (раньше тишина)", outs[0] == "" and outs[1] == "" and "ПРОБЛЕМА" in outs[2] and "хаб" in outs[2], outs)
    proc = start()
    check("хаб вернулся", up())
    time.sleep(3)
    out = watch()
    check("когда хаб вернулся: ВОССТАНОВЛЕНО", "ВОССТАНОВЛЕНО" in out and "хаб" in out, out)

    print("[тихие часы]")
    proc.terminate()
    proc.wait(timeout=5)
    for _ in range(3):
        out = watch(WATCH_HOUR_MSK="2")
    check("ночью (02:00 МСК) сообщение не отправляется", out == "", out)
    check("но оно сохранено в очереди", len(json.load(open(os.path.join(tmp, "state.json")))["queue"]) >= 1)
    proc = start()
    up()
    time.sleep(3)
    out = watch(WATCH_HOUR_MSK="9")
    check("утром (09:00) приходит одно сообщение «накопилось» с ночным событием", "Накопилось" in out and "ПРОБЛЕМА" in out and "хаб" in out, out)

    print("[разбор названий провайдеров]")
    import sqlite3
    dbc = sqlite3.connect(os.path.join(tmp, "hub.db"), timeout=10)
    for asn, org in ((777101, 'JSC "Good Net"'), (777102, "WEIRD CAPS PROVIDER LLC"), (777103, "Individual Entrepreneur Ivanov Ivan")):
        dbc.execute("INSERT INTO webchecks(ts, asn, verdict, data, org, cid) VALUES(?,?,?,?,?,?)", (int(time.time()), asn, "NO_BLOCK", "[]", org, "c" * 16))
    dbc.commit()
    dbc.close()
    try:
        urllib.request.urlopen(urllib.request.Request(HUB + "/api/v2/names/review"), timeout=5)
        check("разбор названий без секрета закрыт", False)
    except urllib.error.HTTPError as e:
        check("разбор названий без секрета закрыт", e.code == 403)
    req = urllib.request.Request(HUB + "/api/v2/names/review", headers={"X-Beat": BEAT})
    rv = json.load(urllib.request.urlopen(req, timeout=10))
    names = {i["asn"]: i for i in rv["items"]}
    check("новые сети в списке, имена очищены", {777101, 777102, 777103} <= set(names) and names[777101]["name"] == "Good Net", rv)
    check("частное лицо: имя не раскрыто, организации нет", names[777103]["name"].startswith("Частный провайдер") and not names[777103]["org"], names.get(777103))
    out = watch(WATCH_HOUR_MSK="12")
    check("днём (12:00) разбор не присылается", "Названия провайдеров" not in out, out)
    out = watch(WATCH_HOUR_MSK="19")
    check("вечером (19:00) приходит разбор с новыми сетями", "Названия провайдеров: новых" in out and "AS777101" in out and "Good Net" in out, out)
    out = watch(WATCH_HOUR_MSK="19")
    check("в тот же день повторно разбор не приходит", "Названия провайдеров" not in out, out)
    rv = json.load(urllib.request.urlopen(urllib.request.Request(HUB + "/api/v2/names/review", headers={"X-Beat": BEAT}), timeout=10))
    check("после отправки сети отмечены как «сообщили»", not ({777101, 777102, 777103} & {i["asn"] for i in rv["items"]}), rv)

    print("[напоминания об окончании аренды]")
    today = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 3 * 3600))
    in_days = lambda n: time.strftime("%Y-%m-%d", time.gmtime(time.time() + 3 * 3600 + n * 86400))
    exp = "Сервер-А=%s,Сервер-Б=%s,Сервер-В=%s" % (in_days(3), in_days(5), in_days(0))
    out = watch(WATCH_HOUR_MSK="12", WATCH_EXPIRY=exp)
    check("за 3 дня и в день окончания напоминание приходит", "Сервер-А" in out and "через 3 дн." in out and "Сервер-В" in out and "СЕГОДНЯ" in out, out)
    check("за 5 дней напоминания нет", "Сервер-Б" not in out, out)
    out = watch(WATCH_HOUR_MSK="12", WATCH_EXPIRY=exp)
    check("повторно в тот же день не напоминает", "Сервер-А" not in out and "Сервер-В" not in out, out)
    out = watch(WATCH_HOUR_MSK="3", WATCH_EXPIRY="Сервер-Г=%s" % in_days(1))
    check("ночью (03:00) напоминаний нет", "Сервер-Г" not in out, out)
finally:
    if proc.poll() is None:
        proc.kill()

print("\nИТОГ:", "всё прошло" if fails == 0 else "ПРОВАЛОВ: %d" % fails)
sys.exit(1 if fails else 0)
