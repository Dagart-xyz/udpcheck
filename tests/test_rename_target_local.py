#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Переименование кода опорного сервера в истории хаба (ops/rename_target.py) на временной базе со схемой хаба.
Запуск: python tests/test_rename_target_local.py"""
import json
import os
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "ops"))
import udpcheck_v2 as V
import rename_target as RT

fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:400]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


p = os.path.join(tempfile.mkdtemp(), "hub.db")
db = sqlite3.connect(p)
db.executescript(V.SCHEMA)
V.migrate(db)
for code in ("AAA1-XA", "AAA1-XA", "CCC1-XC", "AAA1-XAX"):
    db.execute("INSERT INTO tres(ts, asn, target, kind, status, tcp) VALUES(1, 1, ?, 'foreign', 'OK', 'OK')", (code,))
db.execute("INSERT INTO meas(ts, target, port, sent) VALUES(1, 'AAA1-XA', 777, 100)")
db.execute("INSERT INTO traces(ts, target) VALUES(1, 'AAA1-XA')")
db.execute("INSERT INTO webchecks(ts, asn, verdict, data) VALUES(1, 1, 'NO_BLOCK', ?)", (json.dumps([{"code": "AAA1-XA", "ok": 3}, {"code": "CCC1-XC", "ok": 3}]),))
db.execute("INSERT INTO webchecks(ts, asn, verdict, data) VALUES(1, 1, 'NO_BLOCK', ?)", (json.dumps([{"code": "CCC1-XC", "ok": 3}]),))
db.execute("INSERT INTO webchecks(ts, asn, verdict, data) VALUES(1, 1, 'NO_BLOCK', 'битый json \"AAA1-XA\"')")
db.commit()
db.close()

out = RT.rename(p, "AAA1-XA", "EEE1-XE")
check("посчитано, что изменено", out == {"tres": 2, "meas": 1, "traces": 1, "webchecks": 1}, out)
db = sqlite3.connect(p)
tg = sorted(r[0] for r in db.execute("SELECT target FROM tres"))
check("в замерах код заменён, похожий код (AAA1-XAX) и чужие не тронуты", tg == ["AAA1-XAX", "CCC1-XC", "EEE1-XE", "EEE1-XE"], tg)
wc = [json.loads(r[0]) for r in db.execute("SELECT data FROM webchecks WHERE data NOT LIKE 'битый%' ORDER BY id")]
check("в браузерных проверках код заменён внутри JSON", wc[0][0]["code"] == "EEE1-XE" and wc[0][1]["code"] == "CCC1-XC" and wc[1] == [{"code": "CCC1-XC", "ok": 3}], wc)
check("битая строка пропущена, не сломала остальное", db.execute("SELECT COUNT(*) FROM webchecks WHERE data LIKE 'битый%'").fetchone()[0] == 1)
db.close()
for args, why in ((("EEE1-XE", "CCC1-XC"), "склейка с существующим кодом"), (("AAA1-XA", "bad code"), "кривой код"), (("CCC1-XC", "CCC1-XC"), "тот же код")):
    try:
        RT.rename(p, *args)
        ok = False
    except ValueError:
        ok = True
    check("отказ: %s" % why, ok)
db = sqlite3.connect(p)
check("после отказов база не изменилась", sorted(r[0] for r in db.execute("SELECT target FROM tres")) == ["AAA1-XAX", "CCC1-XC", "EEE1-XE", "EEE1-XE"])
db.close()
print("настройки (--config)")
d = tempfile.mkdtemp()
tj, te, re_, fe = (os.path.join(d, n) for n in ("targets.json", "target.env", "role.env", "failover.env"))
json.dump([{"code": "AAA1-XA", "name": "Город", "secret": "s1"}, {"code": "CCC1-XC", "secret": "s2"}, {"code": "AAA1-XAX", "secret": "s3"}], open(tj, "w", encoding="utf-8"), ensure_ascii=False)
open(te, "w", newline="").write("UDPCHECK_TARGET_ID=AAA1-XA\nUDPCHECK_TARGET_SECRET=abc\nUDPCHECK_HUB_URL=https://x/udpcheck\n")
open(re_, "w", newline="").write("ROLE_SELF=AAA1-XA\n")
open(fe, "w", newline="").write("CANDIDATES=DDD1-XD=192.0.2.1,BBB1-XB=192.0.2.2,AAA1-XA=192.0.2.3\nDOMAIN=example.test\nNTFY_TOPIC=t\n")
if hasattr(os, "chmod"):
    os.chmod(te, 0o600)
out = RT.rename_config("AAA1-XA", "EEE1-XE", (tj, te, re_, fe, os.path.join(d, "нет.env")))
check("посчитаны замены по файлам, отсутствующий пропущен", out == {"targets.json": 1, "target.env": 1, "role.env": 1, "failover.env": 1}, out)
t = json.load(open(tj, encoding="utf-8"))
check("в targets.json заменён только нужный code, секреты и похожий код целы", [x["code"] for x in t] == ["EEE1-XE", "CCC1-XC", "AAA1-XAX"] and t[0]["secret"] == "s1" and t[0]["name"] == "Город", t)
check("target.env: только код, секрет и адрес хаба как были, перевод строки в конце цел",
      open(te, newline="").read() == "UDPCHECK_TARGET_ID=EEE1-XE\nUDPCHECK_TARGET_SECRET=abc\nUDPCHECK_HUB_URL=https://x/udpcheck\n", repr(open(te, newline="").read()))
check("role.env с переводом строки в конце", open(re_, newline="").read() == "ROLE_SELF=EEE1-XE\n", repr(open(re_, newline="").read()))
check("failover.env: код в CANDIDATES заменён, остальное как было",
      open(fe, newline="").read() == "CANDIDATES=DDD1-XD=192.0.2.1,BBB1-XB=192.0.2.2,EEE1-XE=192.0.2.3\nDOMAIN=example.test\nNTFY_TOPIC=t\n", repr(open(fe, newline="").read()))
if os.name != "nt":
    check("права файла с секретом сохранены (0600)", oct(os.stat(te).st_mode & 0o777) == "0o600")
check("повторный запуск ничего не меняет", RT.rename_config("AAA1-XA", "EEE1-XE", (tj, te, re_, fe)) == {"targets.json": 0, "target.env": 0, "role.env": 0, "failover.env": 0})
try:
    RT.rename_config("CCC1-XC", "EEE1-XE", (tj,))
    ok = False
except ValueError:
    ok = True
check("в targets.json есть и старый, и новый код (два сервера): отказ, файл не тронут", ok and [x["code"] for x in json.load(open(tj, encoding="utf-8"))] == ["EEE1-XE", "CCC1-XC", "AAA1-XAX"])

print("ИТОГ:", "всё прошло" if not fails else "ошибок: %d" % fails)
sys.exit(1 if fails else 0)
