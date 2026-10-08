#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""udpcheck-watch: наблюдатель за сетью udpcheck. Работает на ЗАРУБЕЖНОМ сервере (оттуда доступен Telegram), запускается раз в минуту.

Проверяет снаружи: отвечает ли хаб, активны ли опорные серверы проекта, свежа ли резервная копия, хватает ли места и памяти на хабе.
Пишет только при смене состояния («упало» и «снова работает»), напоминает о долгой неполадке раз в 6 часов. Тихие часы 23:00-08:00
по Москве: ночью ничего не шлёт, утром отправляет одно сообщение «накопилось, пока было тихо».
Каналы: Telegram (основной), ntfy.sh (запасной, если Telegram не ответил). Настройки в /etc/udpcheck-watch.env:
  TG_TOKEN=...  TG_CHAT=...  NTFY_TOPIC=...  BEAT_SECRET=...  WATCH_HUB=https://dagart.xyz
Ключи для запуска:  (без ключей)  одна проверка;  --test  тестовое сообщение;  --find-chat  показать id чата после /start боту;  --status  состояние.
Только стандартная библиотека. Если не настроен ни один канал, сообщения печатаются на экран (так же работают тесты).
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HUB = os.environ.get("WATCH_HUB", "https://dagart.xyz").rstrip("/")
TG_TOKEN = os.environ.get("TG_TOKEN", "")
TG_CHAT = os.environ.get("TG_CHAT", "")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "")
BEAT_SECRET = os.environ.get("BEAT_SECRET", "")
STATE = os.environ.get("WATCH_STATE") or os.path.join(os.environ.get("STATE_DIRECTORY", "/var/lib/udpcheck-watch"), "state.json")
QUIET_FROM, QUIET_TO = int(os.environ.get("QUIET_FROM", "23")), int(os.environ.get("QUIET_TO", "8"))     # по Москве
QUIET_CRITICAL = os.environ.get("QUIET_CRITICAL", "0") == "1"      # 1: падение хаба будит и ночью
FAILS_HUB, FAILS_ANCHOR = 3, 5                                      # сколько минут подряд, прежде чем сообщить
REMIND = 6 * 3600
NAMES_HOUR = int(os.environ.get("NAMES_HOUR", "19"))                  # во сколько по Москве присылать разбор названий провайдеров
NAMES_EVERY_DAYS = int(os.environ.get("NAMES_EVERY_DAYS", "1"))       # как часто (потом можно поставить 7)


def now():
    return float(os.environ.get("WATCH_NOW") or time.time())


def msk_hour(t):
    h = os.environ.get("WATCH_HOUR_MSK")
    return int(h) if h is not None else (time.gmtime(t).tm_hour + 3) % 24


def quiet(t):
    h = msk_hour(t)
    return h >= QUIET_FROM or h < QUIET_TO


def http(path, method="GET", headers=None, timeout=8):
    req = urllib.request.Request(HUB + path, method=method, data=b"" if method == "POST" else None, headers=dict(headers or {}, **{"User-Agent": "udpcheck-watch"}))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(1 << 20) or b"{}")


def load():
    try:
        with open(STATE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"checks": {}, "queue": []}


def save(st):
    try:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        with open(STATE, "w", encoding="utf-8") as fh:
            json.dump(st, fh, ensure_ascii=False)
    except OSError:
        pass


# ---------------------------------------------------------------- доставка
def send_tg(text):
    if not (TG_TOKEN and TG_CHAT):
        return None
    try:
        body = urllib.parse.urlencode({"chat_id": TG_CHAT, "text": text}).encode()
        with urllib.request.urlopen(urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % TG_TOKEN, data=body), timeout=15) as r:
            return r.status == 200
    except Exception:
        return False


def send_ntfy(text):
    if not NTFY_TOPIC:
        return None
    try:
        req = urllib.request.Request("https://ntfy.sh/" + NTFY_TOPIC, data=text.encode("utf-8"), method="POST",
                                     headers={"X-Title": "udpcheck", "X-Priority": "4", "User-Agent": "udpcheck-watch"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 200
    except Exception:
        return False


def deliver(text):
    """True, если сообщение ушло хотя бы одним каналом (или каналов нет вовсе: тогда просто печатаем)."""
    if not (TG_TOKEN and TG_CHAT) and not NTFY_TOPIC:
        print("ОПОВЕЩЕНИЕ:", text)
        return True
    ok = send_tg(text)
    if ok:
        return True
    return bool(send_ntfy(text))          # Telegram не ответил или не настроен: запасной канал


def notify(st, text, critical=False):
    t = now()
    if quiet(t) and not (critical and QUIET_CRITICAL):
        st["queue"].append("%s %s" % (time.strftime("%H:%M", time.gmtime(t + 3 * 3600)), text))
        st["queue"] = st["queue"][-40:]
        return
    flush(st)
    if not deliver(text):
        st["queue"].append("%s %s" % (time.strftime("%H:%M", time.gmtime(t + 3 * 3600)), text))     # не ушло: попробуем в следующую минуту


def flush(st):
    t = now()
    if st["queue"] and not quiet(t):
        msg = "Накопилось, пока было тихо или не было связи:" + chr(10) + chr(10).join(st["queue"])
        if deliver(msg):
            st["queue"] = []


# ---------------------------------------------------------------- состояние проверок
def check(st, name, bad, need, down_text, up_text, critical=False):
    """bad: сейчас плохо? need: сколько проверок подряд плохо, чтобы сообщить. Сообщаем при переходе, напоминаем раз в REMIND."""
    c = st["checks"].setdefault(name, {"fail": 0, "alerted": False, "last": 0})
    t = now()
    if bad:
        c["fail"] += 1
        if c["fail"] >= need and not c["alerted"]:
            c["alerted"], c["last"] = True, t
            notify(st, "ПРОБЛЕМА: " + down_text, critical)
        elif c["alerted"] and t - c["last"] >= REMIND:
            c["last"] = t
            notify(st, "ВСЁ ЕЩЁ: " + down_text, critical)
    else:
        if c["alerted"]:
            notify(st, "ВОССТАНОВЛЕНО: " + up_text, critical)
        c.update(fail=0, alerted=False)


def names_digest(st):
    """Раз в NAMES_EVERY_DAYS дней в NAMES_HOUR по Москве: новые провайдеры и подозрительные названия, чтобы поправить базу имён."""
    t = now()
    day = int((t + 3 * 3600) // 86400)
    if not (NAMES_HOUR <= msk_hour(t) < NAMES_HOUR + 3) or day - st.get("names_day", 0) < NAMES_EVERY_DAYS or not BEAT_SECRET:
        return
    try:
        data = http("/api/v2/names/review", headers={"X-Beat": BEAT_SECRET})
    except Exception:
        return
    items = data.get("items") or []
    if not items:
        st["names_day"] = day
        return
    bad = [i for i in items if i.get("flags")]
    head = "Названия провайдеров: новых %d, с пометкой %d" % (data.get("total", len(items)), len(bad))
    lines = []
    for i in items:
        mark = "⚠ " if i.get("flags") else "• "
        org = (" — " + i["org"]) if i.get("org") and i["org"] != i["name"] else ""
        why = (" — " + "; ".join(i["flags"])) if i.get("flags") else ""
        lines.append("%sAS%d «%s»%s [%s]%s" % (mark, i["asn"], i["name"], org, "хостинг" if i.get("kind") == "hosting" else "провайдер", why))
    tail = "Поправить: names.json (имя по номеру AS) или brands.json (оператор из нескольких сетей). Скажите Claude, что исправить."
    chunks, cur = [], head
    for ln in lines:
        if len(cur) + len(ln) + 1 > 3500:
            chunks.append(cur)
            cur = ""
        cur += (chr(10) if cur else "") + ln
    chunks.append(cur + chr(10) + tail)
    if all([deliver(c) for c in chunks]):
        try:
            body = json.dumps({"asns": [i["asn"] for i in items]}).encode()
            req = urllib.request.Request(HUB + "/api/v2/names/review", data=body, method="POST",
                                         headers={"X-Beat": BEAT_SECRET, "Content-Type": "application/json", "User-Agent": "udpcheck-watch"})
            urllib.request.urlopen(req, timeout=8).read()
            st["names_day"] = day
        except Exception:
            pass


def run():
    st = load()
    st.setdefault("checks", {})
    st.setdefault("queue", [])
    nodes = health = None
    try:
        nodes = http("/api/v2/nodes")
        health = http("/api/v2/health")
    except Exception:
        pass
    hub_bad = nodes is None or health is None or not health.get("ok")
    check(st, "hub", hub_bad, FAILS_HUB, "хаб dagart.xyz не отвечает уже %d мин." % FAILS_HUB, "хаб dagart.xyz отвечает", critical=True)
    if not hub_bad:
        if BEAT_SECRET:
            try:
                http("/api/v2/health/beat", "POST", {"X-Beat": BEAT_SECRET})
            except Exception:
                pass
        settled = (health.get("uptime_s") or 0) > int(os.environ.get("WATCH_SETTLE_S", "180"))        # только что перезапущенный хаб ещё не видит активность серверов
        for a in nodes.get("anchors", []):
            check(st, "anchor:" + a["code"], settled and not a.get("online"), FAILS_ANCHOR,
                  "сервер проекта «%s» не опрашивает хаб больше %d мин." % (a["name"], FAILS_ANCHOR), "сервер проекта «%s» снова на связи" % a["name"])
        ba = health.get("backup_age_s")
        if ba is not None:
            check(st, "backup", ba > 36 * 3600, 1, "последняя резервная копия хаба старше 36 часов (%d ч)." % (ba // 3600), "резервная копия снова свежая")
        df, ma = health.get("disk_free_pct"), health.get("mem_avail_mb")
        if df is not None:
            check(st, "disk", df < 10, 1, "на хабе мало места на диске (свободно %d%%)." % df, "места на диске хаба снова достаточно")
        if ma is not None:
            check(st, "mem", ma < 50, 3, "на хабе заканчивается память (доступно %d МБ)." % ma, "память хаба снова в порядке")
    names_digest(st)
    flush(st)
    save(st)


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--test":
        print("Telegram:", {None: "не настроен", True: "доставлено", False: "ошибка"}[send_tg("Тест: оповещения udpcheck работают (Telegram).")])
        print("ntfy:   ", {None: "не настроен", True: "доставлено", False: "ошибка"}[send_ntfy("Тест: оповещения udpcheck работают (ntfy).")])
        return 0
    if arg == "--find-chat":
        if not TG_TOKEN:
            print("Сначала впишите TG_TOKEN в /etc/udpcheck-watch.env")
            return 1
        try:
            with urllib.request.urlopen("https://api.telegram.org/bot%s/getUpdates" % TG_TOKEN, timeout=15) as r:
                data = json.loads(r.read())
        except Exception as e:
            print("Не удалось спросить Telegram:", e.__class__.__name__)
            return 1
        seen = {}
        for u in data.get("result", []):
            ch = (u.get("message") or u.get("channel_post") or {}).get("chat")
            if ch:
                seen[ch["id"]] = ch.get("title") or ch.get("username") or ch.get("first_name") or ""
        if not seen:
            print("Чатов не видно: откройте своего бота в Telegram, нажмите Start и отправьте любое сообщение, потом повторите.")
            return 1
        for cid, name in seen.items():
            print("TG_CHAT=%s    (%s)" % (cid, name))
        return 0
    if arg == "--status":
        print(json.dumps(load(), ensure_ascii=False, indent=1))
        return 0
    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
