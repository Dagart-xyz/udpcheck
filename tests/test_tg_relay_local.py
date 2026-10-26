#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Пересылка ntfy -> Telegram (ops/udpcheck-tg-relay): порядок, отметка «прочитано до», повтор при отказе Telegram, без повторов, без настроек.
ntfy и Telegram подменены. Запуск: python tests/test_tg_relay_local.py"""
import importlib.machinery
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:400]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


loader = importlib.machinery.SourceFileLoader("relay", os.path.join(HERE, "..", "ops", "udpcheck-tg-relay"))
spec = importlib.util.spec_from_loader("relay", loader)
R = importlib.util.module_from_spec(spec)
loader.exec_module(R)

CONF = {"NTFY_TOPIC": "t", "TG_TOKEN": "x", "TG_CHAT": "1"}
TOPIC = []          # [(id, текст)] в порядке публикации
asked, sent = [], []
tg_ok = {"v": True}


def fetch(topic, since):
    asked.append(since)
    ids = [i for i, _t in TOPIC]
    start = ids.index(since) + 1 if since in ids else 0
    return [{"id": i, "event": "message", "message": t} for i, t in TOPIC[start:]]


def send(token, chat, text):
    if not tg_ok["v"]:
        return False
    sent.append(text)
    return True


st = {}
check("без настроек ничего не делает", "не настроено" in R.step({}, st, fetch, send))
out = R.step(CONF, st, fetch, send, now=1_700_000_000)
check("первый запуск: читает последние 10 минут; пусто, дальше с метки времени", asked[-1] == "10m" and st["last"] == "1700000000", (asked, st))
TOPIC += [("a", "хаб лежит"), ("b", "переключаю")]
R.step(CONF, st, fetch, send)
check("пересланы по порядку", sent == ["хаб лежит", "переключаю"] and st["last"] == "b", (sent, st))
R.step(CONF, st, fetch, send)
check("повторно не пересылает", sent == ["хаб лежит", "переключаю"] and asked[-1] == "b")
TOPIC += [("c", "DNS переключён"), ("d", "всё ок")]
tg_ok["v"] = False
out = R.step(CONF, st, fetch, send)
check("Telegram не принял: отметка не сдвинулась", "не принял" in out and st["last"] == "b", (out, st))
tg_ok["v"] = True
R.step(CONF, st, fetch, send)
check("следующий запуск дослал оба", sent[-2:] == ["DNS переключён", "всё ок"] and st["last"] == "d", sent)


def broken(topic, since):
    raise OSError("нет связи")


check("ntfy недоступен: сообщает, отметку не трогает", "ntfy недоступен" in R.step(CONF, st, broken, send) and st["last"] == "d")
print("ИТОГ:", "всё прошло" if not fails else "ошибок: %d" % fails)
sys.exit(1 if fails else 0)
