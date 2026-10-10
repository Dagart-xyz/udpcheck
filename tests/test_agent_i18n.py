# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Тексты агента на двух языках: одинаковые наборы ключей и подстановок, вывод результата по-английски без русских букв, выбор языка."""
import importlib
import io
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:300]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


def load(lang):
    os.environ["UDPCHECK_LANG"] = lang
    import udpcheck_node
    return importlib.reload(udpcheck_node)


ru = load("ru")
MSG = ru.MSG
check("наборы ключей совпадают", set(MSG["ru"]) == set(MSG["en"]), set(MSG["ru"]) ^ set(MSG["en"]))
spec = lambda s: sorted(re.findall(r"%[-0-9]*[sd]", s))
bad = [k for k in MSG["ru"] if spec(MSG["ru"][k]) != spec(MSG["en"][k]) and k not in ("got_task",)]
check("число и вид подстановок (%s, %d) одинаковы", not bad, bad)
cyr = re.compile(r"[А-Яа-яЁё]")
check("в английских текстах нет русских букв", not [k for k, v in MSG["en"].items() if cyr.search(v)])
check("установщик ищет в журнале «Позывной» и «Опорная роль» (рус.) и «Callsign», «Anchor role», «not active» (англ.)",
      "Позывной" in MSG["ru"]["reg_ok"] and "Опорная роль" in MSG["ru"]["ref_on"] and "не активна" in MSG["ru"]["ref_off"]
      and "Callsign" in MSG["en"]["reg_ok"] and "Anchor role" in MSG["en"]["ref_on"] and "Anchor role" in MSG["en"]["ref_off"] and "not active" in MSG["en"]["ref_off"])

resp = {"targets": [{"code": "HEL1-FI", "kind": "foreign", "name": "x", "status": "INCUT", "tcp": "OK", "community": False,
                     "ports": [{"port": 777, "reached": 100, "back": 0, "class": "INCUT"}, {"port": 47321, "reached": None, "back": 0, "class": "NOREPORT"}]},
                {"code": "REF-4", "kind": "foreign", "name": "brave-juniper-81", "status": "OK", "tcp": "OK", "community": True, "control": True,
                 "ports": [{"port": 38321, "reached": 100, "back": 100, "class": "OK"}]}],
        "verdict": {"code": "FOREIGN_IN_CUT", "text": "по-русски", "text_en": "in English"}, "src_same": "different", "attribution": "IP geolocation by DB-IP.com"}


def capture(mod):
    buf, old = io.StringIO(), sys.stdout
    sys.stdout = buf
    try:
        mod.show(resp)
    finally:
        sys.stdout = old
    return buf.getvalue()


out = capture(ru)
check("итог по-русски: как раньше", "ВЫВОД: по-русски" in out and "ВНИМАНИЕ" in out and "дошло на цель: 100" in out, out)
en = load("en")
out = capture(en)
check("итог по-английски: вывод и предупреждение о другом адресе", "VERDICT: in English" in out and "WARNING" in out and not cyr.search(out), out)
resp["verdict"] = {"code": "TUNNEL", "text": "прокси"}            # старый хаб без text_en: показываем то, что есть
check("если хаб не прислал text_en, показывается русский текст", "VERDICT: прокси" in capture(en))

# выбор языка: UDPCHECK_LANG сильнее языка системы
for env, want in (({"UDPCHECK_LANG": "en", "LANG": "ru_RU.UTF-8"}, "en"), ({"UDPCHECK_LANG": "ru", "LANG": "en_US.UTF-8"}, "ru"), ({"LANG": "ru_RU.UTF-8"}, "ru"), ({"LANG": "en_US.UTF-8"}, "en")):
    e = {k: v for k, v in os.environ.items() if k not in ("UDPCHECK_LANG", "LANG", "LC_ALL", "LC_MESSAGES")}
    e.update(env)
    r = subprocess.run([sys.executable, "-c", "import udpcheck_node; print(udpcheck_node.LANG_UI)"], cwd=ROOT, env=e, capture_output=True, text=True)
    check("язык по окружению %s -> %s" % (env, want), r.stdout.strip() == want, r.stdout + r.stderr)
print("\nИТОГ: " + ("всё прошло" if not fails else "ошибок: %d" % fails))
sys.exit(1 if fails else 0)
