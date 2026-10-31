#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Несколько кандидатов в хабы (ops/udpcheck-role): кто хаб, решает файл control/active.json в S3. Проверяются переходы роли, плановая передача
с последней копией, защита от поздней копии, поведение без связи с S3, сертификаты на резерве; и ступенчатое хранение копий (ops/udpcheck-s3).
S3, systemd и файлы подменены. Запуск: python tests/test_role_local.py"""
import importlib.machinery
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
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


R = load("udpcheck_role", os.path.join(ROOT, "ops", "udpcheck-role"))
S = load("udpcheck_s3", os.path.join(ROOT, "ops", "udpcheck-s3"))


class Fake:
    """Подставная система: S3 как словарь, файлы как множество, команды записываются."""
    def __init__(self, hub=False, caddy=True):
        self.store, self.files, self.cmds, self.t = {}, set(), [], 1_000_000.0
        self.s3_down = False
        self.fail = set()
        if hub:
            self.files.add(R.HUB_DROPIN)
        if caddy:
            self.files |= {"/etc/caddy/Caddyfile.hub", "/etc/caddy/Caddyfile.standby"}

    def s3_keys(self, prefix):
        if self.s3_down:
            raise RuntimeError("нет связи")
        return {k for k in self.store if k.startswith(prefix)}

    def s3_get_json(self, key):
        if self.s3_down:
            raise RuntimeError("нет связи")
        if key not in self.store:
            raise RuntimeError("404")
        return self.store[key]

    def s3_put_json(self, key, obj):
        if self.s3_down:
            raise RuntimeError("нет связи")
        self.store[key] = obj

    def run(self, cmd, timeout=900, env=None):
        line = " ".join(cmd) + (" FORCE" if (env or {}).get("UDPCHECK_BACKUP_FORCE") == "1" else "")
        self.cmds.append(line)
        for f in self.fail:
            if f in line:
                raise RuntimeError("сбой " + f)
        if cmd[0].endswith("udpcheck-restore") and len(cmd) == 1:
            self.files.add(R.HUB_DROPIN)          # восстановление кладёт hub.conf из копии
        if cmd[0].endswith("udpcheck-backup"):
            self.store["hub/hub-NEW"] = "копия"
        return ""

    def exists(self, path):
        return path in self.files

    def rename(self, a, b):
        self.files.discard(a)
        self.files.add(b)

    def now(self):
        return self.t


def ctl(active, epoch=1, mode="takeover", frm=None, since=1_000_000):
    return {"active": active, "epoch": epoch, "mode": mode, "from": frm, "since": since}


print("переходы роли")
f = Fake()
st = {}
f.s3_down = True
out = R.tick(f, "DDD1-XD", st)
check("нет связи с S3: ничего не делаем", "ничего не меняю" in out and not f.cmds and "s3_error" in st, (out, f.cmds))
f.s3_down = False
out = R.tick(f, "DDD1-XD", st)
check("файла нет: тоже ничего", "ничего не меняю" in out and not f.cmds, (out, f.cmds))

f.store["control/active.json"] = ctl("DDD1-XD")
out = R.tick(f, "DDD1-XD", st)
check("назначен хабом, роли нет: восстановление из копии и включение", out == "включил роль хаба" and f.cmds[0] == "/usr/local/sbin/udpcheck-restore", (out, f.cmds))
check("Caddy переведён в режим хаба полным перезапуском (перезагрузка не подхватывает сертификаты)", "cp /etc/caddy/Caddyfile.hub /etc/caddy/Caddyfile" in f.cmds
      and "systemctl restart caddy" in f.cmds and not any("reload" in c for c in f.cmds), f.cmds)
check("отметка готовности для переключателя", "control/ready-1-DDD1-XD.json" in f.store, list(f.store))
check("ошибки S3 забыты", "s3_error" not in st and st["active"] == "DDD1-XD")
f.cmds.clear()
check("повторный шаг: уже хаб, ничего не делаем", R.tick(f, "DDD1-XD", st) == "хаб" and not f.cmds, f.cmds)

f.store["control/active.json"] = ctl("BBB1-XB", epoch=2)
out = R.tick(f, "DDD1-XD", st)
check("аварийно назначен другой: роль снята без копии", "выключил роль хаба" in out and not any("udpcheck-backup" in c for c in f.cmds), (out, f.cmds))
check("hub.conf отложен, udpcheck перезапущен, Caddy в ожидании", R.HUB_DROPIN not in f.files and R.HUB_DROPIN_OFF in f.files
      and "systemctl restart udpcheck" in f.cmds and "cp /etc/caddy/Caddyfile.standby /etc/caddy/Caddyfile" in f.cmds, f.cmds)
check("перед режимом ожидания раскладываются свои сертификаты (бывший хаб мог не восстанавливаться)",
      f.cmds.index("/usr/local/sbin/udpcheck-restore --local-certs") < f.cmds.index("cp /etc/caddy/Caddyfile.standby /etc/caddy/Caddyfile"), f.cmds)

f = Fake(hub=True)
st = {}
f.store["control/active.json"] = ctl("DDD1-XD", epoch=9)
out = R.tick(f, "DDD1-XD", st)
check("хаб уже здесь, а готовности нет (включение прервалось): Caddy в режим хаба и отметка", out == "хаб: дописал готовность"
      and "control/ready-9-DDD1-XD.json" in f.store and "cp /etc/caddy/Caddyfile.hub /etc/caddy/Caddyfile" in f.cmds, (out, f.cmds))
f.cmds.clear()
check("дальше без лишних действий", R.tick(f, "DDD1-XD", st) == "хаб" and not f.cmds, f.cmds)
f = Fake(hub=True)
st = {}
f.store["control/active.json"] = ctl("DDD1-XD", epoch=9)
f.store["control/ready-9-DDD1-XD.json"] = {}
check("отметка уже есть: ничего не трогаем", R.tick(f, "DDD1-XD", st) == "хаб" and not f.cmds and st["ready_epoch"] == 9, f.cmds)

print("плановая передача")
f = Fake(hub=True)
st = {"active": "AAA1-XA"}
f.store["control/active.json"] = ctl("DDD1-XD", epoch=5, mode="handover", frm="AAA1-XA")
out = R.tick(f, "AAA1-XA", st)
check("отдающий хаб: сначала последняя копия (в обход проверки активного)", f.cmds[0] == "/usr/local/sbin/udpcheck-backup FORCE", f.cmds)
check("потом отметка released и выключение роли", "control/released-5.json" in f.store and R.HUB_DROPIN not in f.files, (list(f.store), f.files))

f = Fake(hub=True)
f.store["control/active.json"] = ctl("DDD1-XD", epoch=5, mode="handover", frm="AAA1-XA")
f.store["control/ready-5-DDD1-XD.json"] = {}
R.tick(f, "AAA1-XA", {})
check("новый уже поднялся: поздней копии нет (не откатит его данные)", not any("udpcheck-backup" in c for c in f.cmds) and R.HUB_DROPIN not in f.files, f.cmds)

f = Fake(hub=True)
f.fail.add("udpcheck-backup")
f.store["control/active.json"] = ctl("DDD1-XD", epoch=5, mode="handover", frm="AAA1-XA")
try:
    R.tick(f, "AAA1-XA", {})
    raised = False
except RuntimeError:
    raised = True
check("копия не удалась: роль не снимается и отметки нет (повторим)", raised and R.HUB_DROPIN in f.files and "control/released-5.json" not in f.store)

f = Fake()
st = {}
f.store["control/active.json"] = ctl("DDD1-XD", epoch=6, mode="handover", frm="AAA1-XA", since=1_000_000)
f.t = 1_000_100
out = R.tick(f, "DDD1-XD", st)
check("принимающий ждёт отметку прежнего хаба", "жду" in out and not f.cmds, (out, f.cmds))
f.store["control/released-6.json"] = {}
out = R.tick(f, "DDD1-XD", st)
check("отметка есть: восстанавливается и включается", out == "включил роль хаба", out)
f = Fake()
f.store["control/active.json"] = ctl("DDD1-XD", epoch=6, mode="handover", frm="AAA1-XA", since=1_000_000)
f.t = 1_000_000 + R.HANDOVER_WAIT + 1
check("прежний не ответил за HANDOVER_WAIT: включается без отметки", R.tick(f, "DDD1-XD", {}) == "включил роль хаба")

f = Fake()
f.fail.add("udpcheck-restore")
f.store["control/active.json"] = ctl("DDD1-XD")
try:
    R.tick(f, "DDD1-XD", {})
    raised = False
except RuntimeError:
    raised = True
check("восстановление не удалось: отметки готовности нет", raised and not any(k.startswith("control/ready") for k in f.store))

print("резерв")
f = Fake()
st = {}
f.store["control/active.json"] = ctl("DDD1-XD")
out = R.tick(f, "BBB1-XB", st)
check("резерв берёт сертификаты из копии", out == "резерв: обновил сертификаты" and f.cmds == ["/usr/local/sbin/udpcheck-restore --certs-only"], (out, f.cmds))
f.cmds.clear()
f.t += 3600
check("второй раз не раньше чем через сутки", R.tick(f, "BBB1-XB", st) == "резерв (хаб DDD1-XD)" and not f.cmds)
f.t += R.CERTS_EVERY
f.fail.add("certs-only")
out = R.tick(f, "BBB1-XB", st)
check("не вышло: сообщает и повторит через час", "не обновились" in out and f.t - st["certs_t"] == R.CERTS_EVERY - 3600, (out, st))
f.fail.clear()
f.t += 3600
check("через час повторяет", R.tick(f, "BBB1-XB", st) == "резерв: обновил сертификаты")

print("is-active (по нему udpcheck-backup решает, делать ли копию)")
orig_sys, orig_load, orig_env = R.System, R.load_state, R.read_env
for hub, active, want in ((True, "DDD1-XD", 0), (True, "BBB1-XB", 1), (False, "DDD1-XD", 1), (True, None, 0)):
    R.System = lambda h=hub: Fake(hub=h)
    R.load_state = lambda a=active: ({"active": a} if a else {})
    R.read_env = lambda p: {"ROLE_SELF": "DDD1-XD"}
    check("роль %s, в файле %s -> код %d" % ("есть" if hub else "нет", active or "не видели", want), R.main(["x", "is-active"]) == want)
R.System, R.load_state, R.read_env = orig_sys, orig_load, orig_env

print("режим ожидания Caddy")
sys.path.insert(0, os.path.join(ROOT, "ops"))
import caddy_modes as CM
hubtxt = open(os.path.join(ROOT, "Caddyfile.dagart"), encoding="utf-8").read()
sb = CM.standby(hubtxt)
check("в ожидании API не идёт в хаб, отвечает 503", "reverse_proxy 127.0.0.1:18080" not in sb and "503" in sb and "reverse_proxy 127.0.0.1:18080" in hubtxt)
tls = [l.strip() for l in sb.splitlines() if l.strip().startswith("tls ")]
check("у каждого сайта по имени готовый сертификат из файлов, у внутреннего адреса нет", tls == [
    "tls /etc/caddy/standby-certs/dagart.xyz.crt /etc/caddy/standby-certs/dagart.xyz.key",
    "tls /etc/caddy/standby-certs/www.dagart.xyz.crt /etc/caddy/standby-certs/www.dagart.xyz.key"], tls)
a, b = CM.hub_block(hubtxt)
rest = [l for l in sb.splitlines() if not l.strip().startswith("tls ")]
check("остальное без изменений", "\n".join(rest) == (hubtxt[:a] + CM.STANDBY_HUB + hubtxt[b:]).rstrip("\n"))
try:
    CM.standby("nothing")
    bad = False
except ValueError:
    bad = True
check("нет блока (hub): отказ, а не тихая порча", bad)


def default_log(text):
    """Глобальный блок «log default {...}» (в начале файла, до первого сниппета) одной строкой без отступов."""
    head = text[:text.index("(hub) {")]
    i = head.find("\tlog default {")
    if i < 0:
        return ""
    depth, out = 0, []
    for line in head[i:].splitlines():
        depth += line.count("{") - line.count("}")
        out.append(line.strip())
        if depth == 0:
            break
    return " ".join(out)


want = ["exclude http.log.access", "request>remote_ip delete", "request>remote_port delete", "request>client_ip delete", "request>headers delete"]
for name, txt in (("хаба", hubtxt), ("ожидания", sb)):
    dl = default_log(txt)
    check("журнал Caddy %s: без журнала доступа, у ошибок вырезаны адрес и заголовки" % name, all(w in dl for w in want), dl)

print("ступенчатое хранение копий")
keys = ["hub/hub-202610%02d-%02d17.tar.gz.enc" % (d, h) for d in range(1, 26) for h in range(24)] + ["hub/hub-20261003-0330.tar.gz.enc", "hub/readme.txt"]
gone = S.tiered_gone(keys, 48, 14)
kept = sorted(set(keys) - set(gone))
check("остаются 48 последних, по одной на 14 суток до них и файл без даты", len(kept) == 48 + 14 + 1, len(kept))
check("из суток остаётся последняя копия", "hub/hub-20261023-2317.tar.gz.enc" in kept and "hub/hub-20261023-2217.tar.gz.enc" not in kept)
check("старше 14 суток удаляется, файл без даты нет", "hub/hub-20261009-2317.tar.gz.enc" not in kept and "hub/readme.txt" in kept)
check("старая ежедневная копия 03:30 удаляется вместе со своими сутками", "hub/hub-20261003-0330.tar.gz.enc" in gone)
check("копий мало: ничего не удаляется", S.tiered_gone(keys[:10], 48, 14) == [])

print("ИТОГ:", "всё прошло" if not fails else "ошибок: %d" % fails)
sys.exit(1 if fails else 0)
