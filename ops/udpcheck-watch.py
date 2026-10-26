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
import calendar
import hashlib
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
EXPIRY = [x.strip() for x in os.environ.get("WATCH_EXPIRY", "").split(",") if "=" in x]     # "Имя сервера=2026-11-05,Другой=2026-10-13": когда кончается аренда
EXPIRY_HOUR = int(os.environ.get("EXPIRY_HOUR", "10"))                # во сколько по Москве напоминать
NAMES_HOUR = int(os.environ.get("NAMES_HOUR", "19"))                  # во сколько по Москве присылать разбор названий провайдеров
NAMES_EVERY_DAYS = int(os.environ.get("NAMES_EVERY_DAYS", "1"))       # как часто (потом можно поставить 7)
SITE_HOUR = int(os.environ.get("SITE_HOUR", "9"))                          # во сколько по Москве присылать вчерашние итоги сайта (SITE_DIGEST=0 отключает)
SITE_DIGEST = os.environ.get("SITE_DIGEST", "1") != "0"
REBOOT_AFTER_H = int(os.environ.get("WATCH_REBOOT_AFTER_H", "48"))    # сколько часов можно жить с неприменённым обновлением ядра, прежде чем сообщить
SECUPD_AFTER_H = int(os.environ.get("WATCH_SECUPD_AFTER_H", "72"))    # сколько часов обновления безопасности могут ждать установки
BANS_SURGE = int(os.environ.get("WATCH_BANS_SURGE", "60"))            # банов fail2ban за час на одном сервере: волна подбора
SSH_LEARN_H = int(os.environ.get("WATCH_SSH_LEARN_H", "24"))
RKN_ACCEPT_FILE = os.environ.get("WATCH_RKN_ACCEPT_FILE", "/etc/udpcheck-watch.rkn-accept")    # touch: принять текущие тревоги по реестру как известные
BACKUP_MAX_H = int(os.environ.get("WATCH_BACKUP_MAX_H", "3"))         # копии делаются раз в час: старше 3 часов значит, что они не идут          # первые часы входы по SSH только запоминаем (какие адреса «свои»)


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
def check(st, name, bad, need, down_text, up_text, critical=False, remind=None):
    """bad: сейчас плохо? need: сколько проверок подряд плохо, чтобы сообщить. Сообщаем при переходе, напоминаем раз в REMIND."""
    c = st["checks"].setdefault(name, {"fail": 0, "alerted": False, "last": 0})
    t = now()
    if bad:
        c["fail"] += 1
        if c["fail"] >= need and not c["alerted"]:
            c["alerted"], c["last"] = True, t
            notify(st, "ПРОБЛЕМА: " + down_text, critical)
        elif c["alerted"] and t - c["last"] >= (remind or REMIND):
            c["last"] = t
            notify(st, "ВСЁ ЕЩЁ: " + down_text, critical)
    else:
        if c["alerted"]:
            notify(st, "ВОССТАНОВЛЕНО: " + up_text, critical)
        c.update(fail=0, alerted=False)


def host_check(st, health, anchors):
    """Состояние самих серверов (его присылают серверы проекта через хаб): висящая перезагрузка, неустановленные обновления безопасности,
    волна банов, вход по SSH с нового адреса. Адреса «своих» входов в состоянии хранятся хэшами."""
    hosts = health.get("hosts") or {}
    if not hosts:
        return
    t = now()
    names = {a["code"]: a["name"] for a in anchors}
    known = st.setdefault("known_ssh", {})
    learning = t < st.setdefault("known_since", t) + SSH_LEARN_H * 3600
    since = st.setdefault("secupd", {})
    for code, h in sorted(hosts.items()):
        name = names.get(code, code)
        stale = h.get("age_s", 0) > 1800
        check(st, "host-stale:" + code, stale, 3, "нет свежих данных о состоянии сервера «%s» (служба udpcheck-hostcheck.timer остановилась?)" % name,
              "данные о состоянии сервера «%s» снова приходят" % name, remind=86400)
        if stale:
            continue
        days = (t - h.get("reboot_since", t)) / 86400
        check(st, "reboot:" + code, bool(h.get("reboot")) and (t - h.get("reboot_since", t)) > REBOOT_AFTER_H * 3600, 1,
              "серверу «%s» уже %d дн. нужна перезагрузка (обновлено ядро или системная библиотека). Перезагружайте серверы по одному и после каждого проверяйте сайт." % (name, int(days)),
              "сервер «%s» перезагружен" % name, remind=86400)
        sec = h.get("sec_updates", -1)
        if sec > 0:
            since.setdefault(code, t)
        else:
            since.pop(code, None)
        check(st, "secupd:" + code, sec > 0 and t - since.get(code, t) > SECUPD_AFTER_H * 3600, 1,
              "на сервере «%s» уже больше %d ч не ставятся обновления безопасности (ждут %d шт.): проверьте apt-daily-upgrade.timer и unattended-upgrades" % (name, SECUPD_AFTER_H, sec),
              "обновления безопасности на сервере «%s» установлены" % name, remind=86400)
        check(st, "bans:" + code, h.get("bans_1h", 0) >= BANS_SURGE, 1,
              "на сервере «%s» за последний час забанено %d адресов: идёт волна подбора входа по SSH (fail2ban справляется, но смотрите на сервер)" % (name, h.get("bans_1h", 0)),
              "волна банов на сервере «%s» закончилась" % name, remind=6 * 3600)
        for ip in h.get("ssh_ips", []):
            key = hashlib.sha256(ip.encode()).hexdigest()[:12]
            if key in known:
                continue
            known[key] = int(t)
            if not learning:
                notify(st, "Вход по SSH на сервер «%s» с нового адреса %s. Если это вы, ничего делать не нужно. Если нет, срочно сообщите: это может быть чужой доступ." % (name, ip))


def _who(v):
    return ("сервер добровольца %s" if v.get("community") else "сервер проекта «%s»") % v.get("name", "?")


def probe_check(st, health):
    """Здоровье серверов глазами хаба: (A) отвечают ли они хабу по UDP, (B) отвечают ли посетителям, у которых другие серверы отвечают."""
    pr = health.get("probe") or {}
    check(st, "probe-hub", bool(pr.get("suspect")), 2,
          "хаб не получает UDP-ответов от большинства серверов (%s из %s молчат): похоже, дело в самом хабе или его сети. Серверы из проверок не убраны."
          % (pr.get("failed"), pr.get("total")), "хаб снова получает UDP-ответы от серверов")
    for code, v in sorted((pr.get("servers") or {}).items()):
        check(st, "probe:" + code, bool(v.get("down")), 1,
              "%s не отвечает хабу по UDP (проверок подряд без ответа: %d, проверка раз в 10 мин). Он убран из проверок посетителей и узлов и вернётся сам, когда ответит."
              % (_who(v), v.get("fails", 0)), "%s снова отвечает по UDP и вернулся в проверки" % _who(v), remind=6 * 3600)
    for code, v in sorted((health.get("visitors") or {}).items()):
        why = []
        if v.get("unseen"):
            why.append("в %d запросы посетителя до сервера не дошли" % v["unseen"])
        if v.get("lost"):
            why.append("в %d сервер ответил, но ответ не дошёл до посетителя" % v["lost"])
        check(st, "vis:" + code, bool(v.get("bad")), 1,
              "%s не отвечает посетителям: в %d из %d последних проверок ответа не было, хотя другие серверы у тех же людей отвечали (сетей: %d)%s."
              % (_who(v), v.get("failed", 0), v.get("checks", 0), v.get("asns", 0), (": " + "; ".join(why)) if why else ""),
              "%s снова отвечает посетителям" % _who(v), remind=86400)


def rkn_check(st, health):
    """Адреса серверов проекта и реестр блокировок: сам адрес в реестре или соседи по /24 (провайдеры, блокирующие подсетями, режут его целиком)."""
    rk = health.get("rkn") or {}
    if not rk.get("enabled"):
        return
    age = rk.get("age_s")
    check(st, "rkn-list", age is None or age > 3 * 86400, 30,
          "хаб давно не обновлял список реестра блокировок (%s): сверка адресов серверов не работает." % ("ни разу" if age is None else "%d ч назад" % (age // 3600)),
          "список реестра блокировок снова обновляется", remind=86400)
    # Известное и принятое владельцем: отметка RKN_ACCEPT_FILE новее прошлой -> текущее состояние «грязных» серверов запоминается, их тревоги
    # снимаются молча; дальше по ним тревога только если станет хуже (сам адрес попал в реестр или соседей в /24 прибавилось).
    accepted = st.setdefault("rkn_accept", {})
    try:
        mark = os.path.getmtime(RKN_ACCEPT_FILE)
    except OSError:
        mark = 0
    if mark and mark > st.get("rkn_accept_t", 0):
        took = []
        for code, v in sorted((rk.get("servers") or {}).items()):
            if not v.get("community") and v.get("dirty"):
                accepted[code] = {"listed": bool(v.get("listed")), "neighbors": int(v.get("neighbors", 0))}
                st["checks"].pop("rkn:" + code, None)
                took.append("%s (%s)" % (v.get("name"), "сам в реестре" if v.get("listed") else "соседей %d" % v.get("neighbors", 0)))
        st["rkn_accept_t"] = mark
        if took:
            notify(st, "Реестр блокировок: принято как известное, напоминать не буду, сообщу только если станет хуже: " + ", ".join(took) + ".")
    for code, v in sorted((rk.get("servers") or {}).items()):
        if v.get("community"):
            continue          # серверы добровольцев в «грязной» подсети хаб просто не берёт свидетелями
        bad = bool(v.get("dirty"))
        a = accepted.get(code)
        if a is not None:
            bad = (bool(v.get("listed")) and not a["listed"]) or int(v.get("neighbors", 0)) > a["neighbors"]
        if v.get("listed"):
            text = "адрес сервера проекта «%s» в реестре блокировок РКН: в России он недоступен по любому протоколу, его проверки ничего не говорят про UDP." % v.get("name")
        else:
            text = ("в подсети сервера проекта «%s» (/24) адресов из реестра блокировок РКН: %d. Провайдеры, которые блокируют подсетями, режут его целиком: "
                    "у их абонентов он молчит по любому протоколу. Стоит подумать о другом адресе." % (v.get("name"), v.get("neighbors", 0)))
        if a is not None and bad:
            text += " Раньше это было принято как известное (%s), теперь хуже." % ("адрес в реестре" if a["listed"] else "соседей было %d" % a["neighbors"])
        check(st, "rkn:" + code, bad, 1, text, "адрес сервера проекта «%s» больше не задевает реестр блокировок" % v.get("name")
              if a is None else "по серверу проекта «%s» снова не хуже принятого" % v.get("name"), remind=7 * 86400)


def expiry_check(st):
    """Напоминания об окончании аренды серверов: за 7, 3 и 1 день, в день окончания и на следующий день. Список в WATCH_EXPIRY."""
    t = now()
    if not EXPIRY or not (EXPIRY_HOUR <= msk_hour(t) < EXPIRY_HOUR + 3):
        return
    today = int((t + 3 * 3600) // 86400)
    sent = st.setdefault("expiry_sent", {})
    for item in EXPIRY:
        name, _eq, date = item.partition("=")
        try:
            end = calendar.timegm(time.strptime(date.strip(), "%Y-%m-%d")) // 86400
        except ValueError:
            continue
        left = end - today
        if left not in (7, 3, 1, 0, -1):
            continue
        key = "%s|%s|%d" % (name.strip(), date.strip(), left)
        if key in sent:
            continue
        if left > 1:
            text = "Аренда сервера «%s» заканчивается через %d дн. (%s). Продлите, иначе он пропадёт из проверок." % (name.strip(), left, date.strip())
        elif left == 1:
            text = "Аренда сервера «%s» заканчивается ЗАВТРА (%s)." % (name.strip(), date.strip())
        elif left == 0:
            text = "Аренда сервера «%s» заканчивается СЕГОДНЯ (%s)." % (name.strip(), date.strip())
        else:
            text = "Аренда сервера «%s» закончилась вчера (%s). Если не продлена, он скоро пропадёт." % (name.strip(), date.strip())
        if deliver(text):
            sent[key] = today
    for k in [k for k, v in sent.items() if today - v > 30]:
        del sent[k]


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


# что означают имена запросов в счётчике ответов 429 (хаб отдаёт их как rate_limited в /api/v2/stats/site)
RL_WHY = {"web/trace": "повторная трассировка раньше 5 минут", "web/report": "результат в статистику чаще 6 раз в час", "web/stun": "проверка UDP из браузера",
          "web/me": "данные о посетителе", "web/stunseen": "подтверждение пакетов", "providers": "список провайдеров", "providers/*": "страница провайдера",
          "journal": "журнал", "nodes": "узлы и опорные серверы", "stats/asn": "график провайдера", "health": "состояние хаба", "node/register": "регистрация узла"}


def site_digest(st):
    """Раз в сутки в SITE_HOUR по Москве: итоги вчерашнего дня с хаба (заходы, браузеры, нажатия «Проверить», ответы не успехом) и среднее за неделю до этого."""
    t = now()
    day = int((t + 3 * 3600) // 86400)
    if not SITE_DIGEST or not BEAT_SECRET or not (SITE_HOUR <= msk_hour(t) < SITE_HOUR + 3) or st.get("site_day", 0) >= day:
        return
    try:
        data = http("/api/v2/stats/site?days=9", headers={"X-Beat": BEAT_SECRET})
    except Exception:
        return
    y = time.strftime("%Y-%m-%d", time.gmtime(t + 3 * 3600 - 86400))
    rows = {r["day"]: r for r in data.get("days", [])}
    r = rows.get(y) or {"views": 0, "browsers": 0, "starts": 0, "checks": 0, "check_browsers": 0, "http_errors": {}}
    prev = [v for d, v in sorted(rows.items(), reverse=True) if d < y and v.get("browsers")][:7]          # только дни, когда счёт уже шёл
    avg = (sum(v["browsers"] for v in prev) // len(prev)) if prev else None
    why = {"400": "плохой запрос", "403": "запрещено", "404": "не найдено, в основном сканеры", "405": "метод", "429": "лимит частоты", "499": "клиент оборвал соединение", "500": "ошибка", "502": "хаб недоступен", "503": "сервис занят", "504": "хаб не ответил"}
    nl = chr(10)
    errs = sorted(r["http_errors"].items(), key=lambda x: -x[1])[:5]
    rl = sorted((r.get("rate_limited") or {}).items(), key=lambda x: (-x[1], x[0]))[:5]
    lines = ["Сайт за %s.%s" % (y[8:10], y[5:7]),
             "• Загрузок страницы: %d" % r["views"],
             "• Разных браузеров: %d%s" % (r["browsers"], (" (в среднем за прошлые дни %d)" % avg) if avg is not None else ""),
             "• Нажали «Проверить»: браузеров %d, проверок в статистике %d" % (r["check_browsers"], r["checks"]),
             "Ответы не успехом:"]
    lines += ["• %s%s: %d" % (c, (" (" + why[c] + ")") if c in why else "", n) for c, n in errs] or ["• нет"]
    if rl:
        lines.append("429 по запросам:")
        lines += ["• %s%s: %d" % (k, (" (" + RL_WHY[k] + ")") if k in RL_WHY else "", n) for k, n in rl]
        # остаток общего числа 429 (его считает Caddy) отдаёт замедлитель роботов ops/udpcheck-tarpit.py: люди с браузером к нему не попадают
        tarpit = r["http_errors"].get("429", 0) - sum((r.get("rate_limited") or {}).values())
        if tarpit > 0:
            lines.append("• замедлитель роботов (много медленных запросов сразу с одного адреса): %d" % tarpit)
    text = nl.join(lines)
    if deliver(text):
        st["site_day"] = day


def run():
    st = load()
    st.setdefault("checks", {})
    st.setdefault("queue", [])
    nodes = health = None
    try:
        nodes = http("/api/v2/nodes")
        health = http("/api/v2/health", headers={"X-Beat": BEAT_SECRET} if BEAT_SECRET else None)
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
        check(st, "db", health.get("db_ok") is False, 2, "хаб не может писать в базу (проверки посетителей и узлы не сохраняются). Частая причина: после "
              "переноса файл базы остался у root, нужен chown -R на каталог состояния.", "хаб снова пишет в базу", critical=True)
        ba = health.get("backup_age_s")
        if ba is not None:
            check(st, "backup", ba > BACKUP_MAX_H * 3600, 1, "последняя резервная копия хаба старше %d ч (%d ч): при аварии потеряется больше часа данных."
                  % (BACKUP_MAX_H, ba // 3600), "резервная копия снова свежая")
        host_check(st, health, nodes.get("anchors", []))
        if settled:
            probe_check(st, health)
            rkn_check(st, health)
        df, ma = health.get("disk_free_pct"), health.get("mem_avail_mb")
        if df is not None:
            check(st, "disk", df < 10, 1, "на хабе мало места на диске (свободно %d%%)." % df, "места на диске хаба снова достаточно")
        if ma is not None:
            check(st, "mem", ma < 50, 3, "на хабе заканчивается память (доступно %d МБ)." % ma, "память хаба снова в порядке")
    expiry_check(st)
    names_digest(st)
    site_digest(st)
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
