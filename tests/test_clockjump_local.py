#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Сбой 12.11.2026: часы хаба на 4 минуты ушли вперёд на полчаса, лимиты частоты «застряли», наблюдатель и переключатель получили 429
от живого хаба, переключатель увёл хаб на резерв, при возврате база прежнего хаба пропала. Здесь проверяется каждое звено:
  1. RateLimiter (udpcheck_server.py) не зависит от прыжков часов;
  2. переключатель (ops/udpcheck-failover): 429 от самого хаба = хаб на месте, а пустой 429, 502 и тишина — нет; готовность нового хаба строгая;
  3. наблюдатель (ops/udpcheck-watch.py): 429 от хаба не «не отвечает», а отдельная тревога через 10 минут;
  4. роль (ops/udpcheck-role): новый хаб сразу делает свою копию;
  5. восстановление (ops/udpcheck-restore, save_db): прежняя база сохраняется при каждом восстановлении, с журналом WAL, две последние.
Запуск: python tests/test_clockjump_local.py"""
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)
fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:400]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


# ---------------------------------------------------------------- 1. RateLimiter
print("1. лимит частоты при прыжке часов")
import udpcheck_server as S

JUMP = 2016                          # на столько часы хаба ушли вперёд (22:45:44 вместо ~22:12:08)
real = [0.0]                          # настоящее время от 22:00:00
ORIG = (time.time, time.monotonic)


def wall():
    return 1_794_520_800 + real[0] + (JUMP if 12 * 60 + 8 <= real[0] < 16 * 60 + 21 else 0)


time.time = wall
time.monotonic = lambda: 50_000.0 + real[0]
try:
    rl = S.RateLimiter(60, 60)        # как rl_stats на хабе
    refused = []
    while real[0] < 3600:
        for k in range(3):            # наблюдатель (nodes + health) и переключатель (health): 3 запроса в минуту с одного адреса
            real[0] = (real[0] // 60) * 60 + k
            if not rl.allow("watcher")[0]:
                refused.append(real[0])
        real[0] = (real[0] // 60 + 1) * 60
    check("3 запроса в минуту при лимите 60/мин: ни одного отказа, хотя часы прыгали вперёд и назад", not refused,
          "первый отказ на %d с" % refused[0] if refused else "")

    real[0] = 10_000.0
    rl = S.RateLimiter(5, 60)
    oks = [rl.allow("a")[0] for _ in range(6)]
    check("лимит по-прежнему держится: 5 из 6 подряд, шестой отказ", oks == [True] * 5 + [False], oks)
    ok, retry = rl.allow("a")
    check("время до следующей попытки положительное и в пределах окна", not ok and 1 <= retry <= 61, retry)
    check("over(): лимит исчерпан", rl.over("a") is True)
    check("другой ключ не задет", rl.allow("b")[0] is True)
    real[0] += 61
    check("через окно снова можно", rl.allow("a")[0] is True and rl.over("a") is False)
    real[0] += JUMP                   # прыжок часов не мешает и очистке
    time.time = lambda: 0.0
    rl.purge()
    check("purge() по монотонным часам: старые ключи убраны, хотя time.time() показывает ноль", not rl.hits, rl.hits)
finally:
    time.time, time.monotonic = ORIG

src = open(os.path.join(ROOT, "udpcheck_server.py"), encoding="utf-8").read()
check("janitor не передаёт в purge() время по часам (смешало бы два источника времени)",
      re.search(r"rl_(stun|pad)\.purge\(\s*\)", src) and not re.search(r"rl_(stun|pad)\.purge\(\s*\w", src))

# ---------------------------------------------------------------- 2. переключатель
print("2. переключатель: 429 от живого хаба")
F = load("udpcheck_failover", os.path.join(ROOT, "ops", "udpcheck-failover"))
IPS = {"DDD1-XD": "198.51.100.1", "BBB1-XB": "198.51.100.2"}
CONF = {"CANDIDATES": ",".join("%s=%s" % kv for kv in IPS.items()), "DOMAIN": "example.test", "DOWN_AFTER": "300", "UP_AFTER": "1800",
        "READY_WAIT": "900", "DNS_EVERY": "600"}
LIMITED = (429, '{"error": "слишком часто"}'.encode("utf-8"))


class Net:
    def __init__(self):
        self.t = 1_000_000.0
        self.store = {"control/active.json": {"active": "DDD1-XD", "epoch": 3, "mode": "takeover", "from": None, "since": 0}}
        self.health = {c: (200, b'{"ok": true, "db_ok": true}') for c in IPS}
        self.dns = {"": [IPS["DDD1-XD"]], "www": [IPS["DDD1-XD"]]}
        self.notes, self.gets = [], 0

    def get(self, ip, path):
        code = next(c for c, i in IPS.items() if i == ip)
        if path == "/api/v2/health":
            self.gets += 1
            h = self.health[code]
            if h is None:
                raise OSError("нет соединения")
            return h
        return 200, b""

    def reach(self, url):
        return True

    def s3_keys(self, prefix):
        return {k for k in self.store if k.startswith(prefix)}

    def s3_get_json(self, key):
        return dict(self.store[key])

    def s3_put_json(self, key, obj):
        self.store[key] = obj

    def dns_get(self, sub):
        return list(self.dns[sub])

    def dns_set(self, sub, ip):
        self.dns[sub] = [ip]

    def notify(self, text):
        self.notes.append(text)
        return True

    def now(self):
        return self.t


def run(net, st, n=1):
    out = None
    for _ in range(n):
        out = F.step(net, CONF, st)
        net.t += 60
    return out


net, st = Net(), {}
net.health["DDD1-XD"] = LIMITED
outs = [run(net, st) for _ in range(12)]
check("хаб 12 минут отказывает по лимиту (429 с {\"error\"}): остаётся хабом, без оповещений",
      net.store["control/active.json"]["active"] == "DDD1-XD" and all(o == "хаб DDD1-XD в порядке" for o in outs) and not net.notes, (outs[-1], net.notes))
for name, resp in (("пустой 429 (замедлитель роботов)", (429, b"")), ("429 не JSON", (429, b"<html>busy</html>")), ("502 (программа хаба не отвечает)", (502, b"")),
                   ("200 с JSON-списком вместо объекта", (200, b"[1]")), ("нет соединения", None)):
    net, st = Net(), {}
    net.health["DDD1-XD"] = resp
    run(net, st, n=6)
    check("%s 6 минут: хаб считается молчащим, назначен резерв" % name, net.store["control/active.json"]["active"] == "BBB1-XB", net.store["control/active.json"])
net, st = Net(), {}
net.health["DDD1-XD"] = LIMITED
run(net, st)
check("одна проверка активного = один запрос /api/v2/health (как раньше)", net.gets == 1, net.gets)

net, st = Net(), {}
net.health["DDD1-XD"] = None
run(net, st, n=6)
net.store["control/ready-4-BBB1-XB.json"] = {}
net.health["BBB1-XB"] = LIMITED
out = run(net, st, n=3)
check("новый хаб готов, но отвечает 429: DNS не переводим (для готовности нужен настоящий ответ хаба)",
      net.dns[""] == [IPS["DDD1-XD"]] and out.startswith("жду"), (out, net.dns))
net.health["BBB1-XB"] = (200, b'{"ok": true, "db_ok": true}')
run(net, st)
check("ответил как хаб: DNS переведён", net.dns[""] == [IPS["BBB1-XB"]], net.dns)
check("hub_ok по-прежнему строгий: 429 не «хаб в порядке»", F.hub_ok(type("N", (), {"get": lambda self, ip, p: LIMITED})(), "x") is False)

# ---------------------------------------------------------------- 3. наблюдатель
print("3. наблюдатель: 429 от живого хаба")
tmp = tempfile.mkdtemp(prefix="udpc_jump_")
os.environ.update(WATCH_STATE=os.path.join(tmp, "watch.json"), WATCH_HOUR_MSK="12", BEAT_SECRET="", WATCH_EXPIRY="")
W = load("udpcheck_watch", os.path.join(ROOT, "ops", "udpcheck-watch.py"))
sent = []
W.deliver = lambda text: sent.append(text) or True
mode = ["limited"]


def fake_http(path, method="GET", headers=None, timeout=8):
    if mode[0] == "limited":
        raise urllib.error.HTTPError("https://x" + path, 429, "Too Many Requests", {}, io.BytesIO('{"error": "слишком часто"}'.encode("utf-8")))
    if mode[0] == "tarpit":
        raise urllib.error.HTTPError("https://x" + path, 429, "Too Many Requests", {}, io.BytesIO(b""))
    if mode[0] == "down":
        raise OSError("нет соединения")
    if path == "/api/v2/nodes":
        return {"anchors": []}
    if path == "/api/v2/health":
        return {"ok": True, "db_ok": True, "uptime_s": 10_000}
    return {}


W.http = fake_http
for i in range(9):
    W.run()
check("9 минут 429 от хаба: ни «не отвечает», ни других тревог", not sent, sent)
W.run()
check("10-я минута: одна тревога «отказывает по лимиту», без «не отвечает»",
      len(sent) == 1 and "по лимиту частоты" in sent[0] and "не отвечает" not in sent[0], sent)
for i in range(5):
    W.run()
check("тревога не повторяется каждую минуту", len(sent) == 1, sent)
mode[0] = "ok"
W.run()
check("хаб снова отдаёт данные: «ВОССТАНОВЛЕНО»", len(sent) == 2 and "ВОССТАНОВЛЕНО" in sent[1] and "снова отдаёт" in sent[1], sent)
sent.clear()
os.remove(os.environ["WATCH_STATE"])


def fake_http_health(path, method="GET", headers=None, timeout=8):          # список узлов отдал, а состояние хаба уже по лимиту
    if path == "/api/v2/health":
        raise urllib.error.HTTPError("https://x" + path, 429, "Too Many Requests", {}, io.BytesIO('{"error": "слишком часто"}'.encode("utf-8")))
    return fake_http(path, method, headers, timeout)


mode[0] = "ok"
W.http = fake_http_health
for i in range(10):
    W.run()
check("nodes ответил, health по лимиту, 10 минут: тоже «по лимиту», не «не отвечает»", len(sent) == 1 and "по лимиту частоты" in sent[0], sent)
W.http = fake_http
for m in ("tarpit", "down"):
    sent.clear()
    os.remove(os.environ["WATCH_STATE"])
    mode[0] = m
    for i in range(3):
        W.run()
    check("%s 3 минуты: как раньше, «хаб не отвечает»" % ("пустой 429 замедлителя" if m == "tarpit" else "нет соединения"),
          len(sent) == 1 and "не отвечает" in sent[0], sent)

# ---------------------------------------------------------------- 4. роль
print("4. новый хаб сразу делает копию")
R = load("udpcheck_role", os.path.join(ROOT, "ops", "udpcheck-role"))


class Sys:
    def __init__(self):
        self.store = {"control/active.json": {"active": "DDD1-XD", "epoch": 5, "mode": "takeover", "from": "BBB1-XB", "since": 1}}
        self.files = {"/etc/caddy/Caddyfile.hub", "/etc/caddy/Caddyfile.standby"}
        self.cmds, self.fail = [], set()

    def s3_keys(self, prefix):
        return {k for k in self.store if k.startswith(prefix)}

    def s3_get_json(self, key):
        return self.store[key]

    def s3_put_json(self, key, obj):
        self.cmds.append("put " + key)
        self.store[key] = obj

    def run(self, cmd, timeout=900, env=None):
        line = " ".join(cmd) + (" FORCE" if (env or {}).get("UDPCHECK_BACKUP_FORCE") == "1" else "")
        self.cmds.append(line)
        if any(f in line for f in self.fail):
            raise RuntimeError("сбой")
        if cmd[0].endswith("udpcheck-restore") and len(cmd) == 1:
            self.files.add(R.HUB_DROPIN)
        return ""

    def exists(self, path):
        return path in self.files

    def rename(self, a, b):
        self.files.discard(a)
        self.files.add(b)

    def now(self):
        return 1_000_000.0


f, st = Sys(), {}
out = R.tick(f, "DDD1-XD", st)
bk = "/usr/local/sbin/udpcheck-backup FORCE"
check("включил роль и сделал копию (без проверки is-active: состояние ещё не сохранено)", out == "включил роль хаба" and bk in f.cmds, (out, f.cmds))
check("копия после отметки готовности (переключатель её не ждёт)", bk in f.cmds and f.cmds.index("put control/ready-5-DDD1-XD.json") < f.cmds.index(bk), f.cmds)
f.cmds.clear()
check("следующий шаг: уже хаб, повторной копии нет", R.tick(f, "DDD1-XD", st) == "хаб" and not f.cmds, f.cmds)
f, st = Sys(), {}
f.fail.add("udpcheck-backup")
out = R.tick(f, "DDD1-XD", st)
check("копия не ушла: роль всё равно включена, готовность записана", out == "включил роль хаба" and "control/ready-5-DDD1-XD.json" in f.store
      and st.get("ready_epoch") == 5, (out, st))

# ---------------------------------------------------------------- 5. восстановление: прежняя база
print("5. udpcheck-restore: прежняя база при каждом восстановлении")
sh = shutil.which("sh")
script = open(os.path.join(ROOT, "ops", "udpcheck-restore"), encoding="utf-8").read()
m = re.search(r"^save_db\(\) \{\n.*?^\}\n", script, re.S | re.M)
check("в udpcheck-restore есть save_db() и она вызывается для базы хаба", bool(m) and 'save_db "$D/hub.db"' in script and 'keep "$D/hub.db"' not in script)
if not sh:
    print("  ПРОПУСК: нет sh")
elif m:
    d = os.path.join(tmp, "state")
    os.makedirs(d)
    shim = os.path.join(tmp, "bin")
    os.makedirs(shim)
    with open(os.path.join(shim, "python3"), "w", newline="\n") as fh:
        fh.write('#!/bin/sh\nexec "%s" "$@"\n' % sys.executable.replace("\\", "/"))
    os.chmod(os.path.join(shim, "python3"), 0o755)
    db = os.path.join(d, "hub.db")
    open(db + ".pre-restore", "wb").write(b"\0" * 4096)          # как на одном из хабов 12.11: пустой файл с прошлого раза
    c = sqlite3.connect(db)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA wal_autocheckpoint=0")
    c.execute("CREATE TABLE webchecks (id INTEGER)")
    c.executemany("INSERT INTO webchecks VALUES (?)", [(i,) for i in range(50)])
    c.commit()                                                   # данные только в журнале WAL: соединение открыто, сброса не было
    wal = os.path.getsize(db + "-wal") if os.path.exists(db + "-wal") else 0
    env = dict(os.environ, PATH=shim.replace("\\", "/") + os.pathsep + os.environ.get("PATH", ""))
    outs = []
    for i in range(3):
        r = subprocess.run([sh, "-c", "set -eu\n" + m.group(0) + 'save_db "$1"', "x", db.replace("\\", "/")], capture_output=True, text=True, env=env)
        outs.append((r.returncode, r.stdout.strip(), r.stderr.strip()))
        if i < 2:
            time.sleep(1.1)                                      # имена копий до секунды
    c.close()
    copies = sorted(x for x in os.listdir(d) if x.startswith("hub.db.pre-restore-"))
    check("три восстановления подряд: каждое сохранило базу, код 0", all(o[0] == 0 and "сохранена" in o[1] for o in outs), outs)
    check("осталось две последние копии", len(copies) == 2, copies)
    cnt, modes = [], []
    for x in copies:
        cc = sqlite3.connect(os.path.join(d, x))
        cnt.append(cc.execute("SELECT COUNT(*) FROM webchecks").fetchone()[0])
        modes.append(cc.execute("PRAGMA journal_mode").fetchone()[0])
        cc.close()
    check("в копиях и то, что было только в журнале WAL (%d байт)" % wal, wal > 0 and cnt == [50, 50], (wal, cnt))
    check("копии одним файлом (journal_mode=delete): открытие не плодит -wal и -shm", modes == ["delete", "delete"], modes)
    side = os.path.join(d, copies[0])                            # кто-то открывал самую старую копию в режиме WAL: рядом служебные файлы
    for suf in ("-wal", "-shm"):
        open(side + suf, "wb").write(b"x")
    time.sleep(1.1)
    r = subprocess.run([sh, "-c", "set -eu\n" + m.group(0) + 'save_db "$1"', "x", db.replace("\\", "/")], capture_output=True, text=True, env=env)
    left = sorted(x for x in os.listdir(d) if x.startswith("hub.db.pre-restore-"))
    check("служебные -wal/-shm не считаются копиями и удаляются вместе со своей копией",
          r.returncode == 0 and len(left) == 2 and copies[0] not in left and not any(x.endswith(("-wal", "-shm")) for x in left), (r.returncode, r.stderr, left))
    copies = left
    check("старый пустой hub.db.pre-restore не мешает и не тронут", os.path.getsize(db + ".pre-restore") == 4096)
    r = subprocess.run([sh, "-c", "set -eu\n" + m.group(0) + 'save_db "$1"; echo конец', "x", os.path.join(d, "нет.db").replace("\\", "/")],
                       capture_output=True, text=True, env=env)
    check("базы нет (чистый сервер): ничего не делает, без ошибки", r.returncode == 0 and r.stdout.strip() == "конец", (r.returncode, r.stdout, r.stderr))
    with open(os.path.join(shim, "python3"), "w", newline="\n") as fh:
        fh.write("#!/bin/sh\nexit 1\n")                         # снимок не удался (например, нет python3): копия файла как есть
    time.sleep(1.1)
    r = subprocess.run([sh, "-c", "set -eu\n" + m.group(0) + 'save_db "$1"; echo конец', "x", db.replace("\\", "/")], capture_output=True, text=True, env=env)
    newest = sorted(x for x in os.listdir(d) if x.startswith("hub.db.pre-restore-"))
    check("снимок не вышел: файл скопирован как есть, скрипт идёт дальше, копий по-прежнему две",
          r.returncode == 0 and "как есть" in r.stdout and r.stdout.strip().endswith("конец") and len(newest) == 2 and newest[-1] not in copies
          and os.path.getsize(os.path.join(d, newest[-1])) == os.path.getsize(db), (r.returncode, r.stdout, r.stderr, newest))

print("ИТОГ:", "всё прошло" if not fails else "ошибок: %d" % fails)
sys.exit(1 if fails else 0)
