#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Пересылка ntfy -> Telegram (ops/udpcheck-tg-relay): порядок, повтор при отказе Telegram, без повторов, без потерь, без настроек.
ntfy и Telegram подменены. Подделка ntfy ведёт себя как настоящий ntfy.sh (проверено 02.11.2026 на тестовом топике):
since=<время> отдаёт сообщения с time >= времени; since=<id> отдаёт всё с time >= time(id), кроме самого id, то есть и соседей
по той же секунде, уже пересланных раньше; свежее сообщение видно не в первом же опросе.
Запуск: python tests/test_tg_relay_local.py"""
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
T0 = 1_700_000_000
TOPIC = []          # [{"id", "time", "message", "hidden"}] в порядке публикации; hidden: сколько опросов ntfy его ещё не показывает
asked, sent = [], []
tg_ok = {"v": True}


def publish(mid, t, text, hidden=0):
    TOPIC.append({"id": mid, "time": t, "message": text, "hidden": hidden})


def fetch(topic, since):
    asked.append(since)
    if since.isdigit():
        tmin, skip = int(since), None
    else:
        known = [m for m in TOPIC if m["id"] == since]
        tmin, skip = (known[0]["time"], since) if known else (0, None)
    out = []
    for m in TOPIC:
        if m["hidden"] > 0:
            m["hidden"] -= 1
            continue
        if m["time"] >= tmin and m["id"] != skip:
            out.append({"id": m["id"], "time": m["time"], "event": "message", "message": m["message"]})
    return out


def send(token, chat, text):
    if not tg_ok["v"]:
        return False
    sent.append(text)
    return True


st = {}
check("без настроек ничего не делает", "не настроено" in R.step({}, st, fetch, send))
R.step(CONF, st, fetch, send, now=T0)
check("первый запуск: читает последние 10 минут (по времени, с запасом)", asked[-1] == str(T0 - R.FIRST_SINCE - R.OVERLAP) and not sent, (asked, st))

publish("a", T0 + 10, "хаб лежит")
publish("b", T0 + 10, "переключаю")
R.step(CONF, st, fetch, send, now=T0 + 60)
check("пересланы по порядку", sent == ["хаб лежит", "переключаю"], (sent, st))
for k in range(5):
    R.step(CONF, st, fetch, send, now=T0 + 120 + 60 * k)
check("два сообщения в одну секунду не пересылаются по кругу", sent == ["хаб лежит", "переключаю"], sent)
check("запросы только по времени, не по id", all(s.isdigit() for s in asked), asked)

# четыре напоминания, по два в одну секунду: раньше пересылка ходила по кругу между ними часами
sent.clear()
for i, (name, t) in enumerate([("SRV-A", 500), ("SRV-B", 500), ("SRV-C", 501), ("SRV-D", 501)]):
    publish("r%d" % i, T0 + t, "Аренда сервера «%s» заканчивается через 3 дн." % name)
for k in range(10):
    R.step(CONF, st, fetch, send, now=T0 + 540 + 60 * k)
check("четыре напоминания: каждое ровно один раз", len(sent) == 4 and len(set(sent)) == 4, sent)

sent.clear()
publish("late", T0 + 1200, "опоздавшее", hidden=1)
R.step(CONF, st, fetch, send, now=T0 + 1201)
check("ntfy ещё не показал сообщение: пока ничего", sent == [], sent)
R.step(CONF, st, fetch, send, now=T0 + 1260)
check("опоздавшее досылается следующим запуском, не теряется", sent == ["опоздавшее"], sent)

sent.clear()
publish("c", T0 + 1300, "DNS переключён")
publish("d", T0 + 1300, "всё ок")
tg_ok["v"] = False
out = R.step(CONF, st, fetch, send, now=T0 + 1320)
check("Telegram не принял: сообщает", "не принял" in out and sent == [], (out, sent))
tg_ok["v"] = True
R.step(CONF, st, fetch, send, now=T0 + 1380)
R.step(CONF, st, fetch, send, now=T0 + 1440)
check("следующий запуск дослал оба, без повторов", sent == ["DNS переключён", "всё ок"], sent)

sent.clear()
for i in range(R.MAX_PER_RUN + 5):
    publish("m%d" % i, T0 + 2000, "сообщение %d" % i)
R.step(CONF, st, fetch, send, now=T0 + 2010)
check("за запуск не больше MAX_PER_RUN", len(sent) == R.MAX_PER_RUN, len(sent))
R.step(CONF, st, fetch, send, now=T0 + 2070)
R.step(CONF, st, fetch, send, now=T0 + 2130)
check("остаток дослан следующим запуском, каждое ровно раз", sent == ["сообщение %d" % i for i in range(R.MAX_PER_RUN + 5)], sent)

R.step(CONF, st, fetch, send, now=T0 + 9000)
publish("e", T0 + 9100, "через два часа")
R.step(CONF, st, fetch, send, now=T0 + 9160)
check("после тишины новое приходит, старое не повторяется", sent[-1] == "через два часа" and len(sent) == R.MAX_PER_RUN + 6, sent[-3:])
check("память пересланных не растёт бесконечно", len(st.get("seen", {})) <= 3, st.get("seen"))


def broken(topic, since):
    raise OSError("нет связи")


before = dict(st, seen=dict(st["seen"]))
check("ntfy недоступен: сообщает, состояние не трогает", "ntfy недоступен" in R.step(CONF, st, broken, send, now=T0 + 9220) and st == before)

# состояние старой версии: {"last": "<id>"} (так оно лежит на сервере, где пересылка ходила по кругу) или {"last": "<метка времени>"}
asked.clear()
sent.clear()
st_old = {"last": "r3"}
R.step(CONF, st_old, fetch, send, now=T0 + 9300)
check("переход со старого состояния (id): читает последние 10 минут по времени, без круга",
      asked == [str(T0 + 9300 - R.FIRST_SINCE - R.OVERLAP)] and sent == ["через два часа"] and "last" not in st_old, (asked, sent, st_old))
asked.clear()
st_old = {"last": str(T0 + 9150)}
R.step(CONF, st_old, fetch, send, now=T0 + 9300)
check("переход со старого состояния (метка времени): читает с неё", asked == [str(T0 + 9150 - R.OVERLAP)] and "last" not in st_old, (asked, st_old))

print("ИТОГ:", "всё прошло" if not fails else "ошибок: %d" % fails)
sys.exit(1 if fails else 0)
