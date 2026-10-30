#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Обезличенные счётчики сайта: загрузки страницы, уникальные браузеры за сутки, нажатия «Проверить», ответы Caddy не успехом, итоги и вечерняя сводка наблюдателя.
Запуск: python tests/test_sitestats_local.py"""
import http.server
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)
import udpcheck_v2 as V
fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:400]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


# подставной Caddy: отдаёт счётчики в формате Prometheus; значения меняем по ходу теста
METRICS = {"text": ""}


def mk(code, n, handler="subroute", method="GET", server="srv1"):
    return 'caddy_http_request_duration_seconds_count{code="%s",handler="%s",method="%s",server="%s"} %d\n' % (code, handler, method, server, n)


class M(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = METRICS["text"].encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


msrv = http.server.ThreadingHTTPServer(("127.0.0.1", 18199), M)
threading.Thread(target=msrv.serve_forever, daemon=True).start()

tmp = tempfile.mkdtemp(prefix="udpc_site_")
run_dir = os.path.join(tmp, "run")          # как RuntimeDirectory= у службы: /run/udpcheck в памяти, переживает перезапуск службы
os.makedirs(run_dir)
tfile = os.path.join(tmp, "targets.json")
json.dump([{"code": "RU-T", "name": "ru test", "country": "XX", "ip": "127.0.0.1", "ports": [19993, 19777, 19321], "secret": "a" * 32, "tcp_port": 18443}], open(tfile, "w"))
HUB = "http://127.0.0.1:18180/udpcheck"
BEAT = "b" * 32
env = dict(os.environ, UDPCHECK_RKN_LIST="", UDPCHECK_TRUSTED_PROXIES="", UDPCHECK_GEO_DIR=os.path.join(tmp, "nogeo"), UDPCHECK_ALLOW_NON_GLOBAL="1", UDPCHECK_DEFAULT_COUNTRY="XX",
           UDPCHECK_HTTP_PORT="18180", UDPCHECK_UDP_BIND="127.0.0.1", UDPCHECK_UDP_PORTS="19993,19777,19321", UDPCHECK_HUB_DB=os.path.join(tmp, "hub.db"),
           UDPCHECK_HUB_TARGETS=tfile, UDPCHECK_BEAT_SECRET=BEAT, UDPCHECK_CADDY_METRICS="http://127.0.0.1:18199/metrics", UDPCHECK_CADDY_SAMPLE_S="1", RUNTIME_DIRECTORY=run_dir)


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


def req(path, method="GET", headers=None):
    r = urllib.request.Request(HUB + path, method=method, data=b"" if method == "POST" else None, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def stats(days=3):
    st, j = req("/api/v2/stats/site?days=%d" % days, headers={"X-Beat": BEAT})
    return st, j


def today_row(j):
    for r in j.get("days", []):
        if r["day"] == j["today"]:
            return r
    return {}


# имя запроса для счётчика 429: без номеров, токенов и адресов, только известные части пути
for path, want in (("/udpcheck/api/v2/providers/12345?x=1", "providers/*"), ("/api/v2/providers", "providers"), ("/api/v2/web/trace", "web/trace"),
                   ("/api/v2/web/trace/" + "ab" * 16, "web/trace"), ("/api/v2/web/stunseen/tok-123", "web/stunseen"), ("/api/v2/stats/asn/8359", "stats/asn"),
                   ("/etc/passwd", "other"), ("/api/v2/%3Cscript%3E", "other"), ("/api/v2/", "other")):
    check("имя запроса для 429: %s -> %s" % (path, want), V._rl_group(path) == want, V._rl_group(path))

C1, C2, C3 = "1" * 32, "2" * 32, "3" * 32
proc = start()
try:
    check("хаб поднялся", up())
    time.sleep(1)
    # три загрузки страницы от двух браузеров и одна без номера браузера
    for c in (C1, C1, C2):
        req("/api/v2/providers", headers={"X-Client": c})
    req("/api/v2/providers")
    # нажатие «Проверить» (запуск трассировки): считается, даже если трассировка не удалась
    req("/api/v2/web/trace", "POST", {"X-Client": C1, "Sec-Fetch-Site": "same-origin"})
    # запрос не со страницы (чужой сайт) не считается как нажатие
    req("/api/v2/web/trace", "POST", {"X-Client": C1, "Sec-Fetch-Site": "cross-site"})
    METRICS["text"] = mk("200", 99999) + mk("404", 10) + mk("429", 2) + mk("404", 7, handler="file_server", server="srv0") + mk("301", 5, method="POST")
    st, _ = req("/api/v2/stats/site")
    check("итоги без секрета закрыты", st == 403, st)
    st, j = stats()
    row = today_row(j)
    check("итоги с секретом отдаются", st == 200 and row, j)
    check("загрузки страницы: 4 (3 с номером браузера и 1 без)", row.get("views") == 4, row)
    check("уникальные браузеры за сутки: 2", row.get("browsers") == 2, row)
    check("нажатия «Проверить»: 1 (чужой сайт не считается)", row.get("starts") == 1, row)
    check("ответы Caddy не успехом: 404 и 429 основного сайта, успешные, 3xx и внутренний адрес не учтены", row.get("http_errors") == {"404": 10, "429": 2}, row.get("http_errors"))

    time.sleep(1.2)
    METRICS["text"] = mk("200", 100050) + mk("404", 14) + mk("429", 2) + mk("301", 5)
    st, j = stats()
    check("прирост Caddy добавляется (404: 10 -> 14)", today_row(j)["http_errors"].get("404") == 14, today_row(j))
    time.sleep(1.2)
    METRICS["text"] = mk("404", 3)          # Caddy перезапустили: счётчик начался с нуля
    st, j = stats()
    check("после перезапуска Caddy счётчик берётся целиком (14 + 3 = 17), без отрицательного прироста", today_row(j)["http_errors"].get("404") == 17, today_row(j))
    time.sleep(1.2)
    METRICS["text"] = ""                    # Caddy недоступен или пусто: ничего не ломается
    st, j = stats()
    check("пустые счётчики не ломают итоги", st == 200 and today_row(j)["http_errors"].get("404") == 17, j)

    # ответы 429 самого хаба считаются по имени запроса: часто дёргаем журнал (лимит 60 в минуту на адрес)
    got429 = sum(1 for _ in range(70) if req("/api/v2/journal")[0] == 429)
    st, j = stats()
    check("429 хаба по запросам: только journal и ровно столько, сколько получил клиент (%d)" % got429,
          got429 > 0 and today_row(j).get("rate_limited") == {"journal": got429}, today_row(j).get("rate_limited"))

    # перезапуск хаба: накопленное в базе, число браузеров за сутки не уменьшается
    proc.terminate()
    proc.wait(timeout=5)
    proc = start()
    check("хаб перезапущен", up())
    time.sleep(1)
    req("/api/v2/providers", headers={"X-Client": C1})
    req("/api/v2/providers", headers={"X-Client": C3})
    st, j = stats()
    row = today_row(j)
    check("после перезапуска хаба загрузки сохранены и растут (6)", row.get("views") == 6, row)
    check("после перезапуска набор браузеров продолжается: прежние 2 + новый 1, повторный не считается (3)", row.get("browsers") == 3, row)
    saved = open(os.path.join(run_dir, "site-browsers.bin"), "rb").read()
    check("в /run только дата и хэши: самих номеров браузеров там нет", saved[:10].decode() == j["today"] and (len(saved) - 10) == 3 * 8
          and all(c.encode() not in saved for c in (C1, C2, C3)), saved[:40])

    # набор за другие сутки или испорченный файл не подхватывается
    V.SITE_UNIQ.update(day="", set=set())
    os.environ["RUNTIME_DIRECTORY"] = run_dir
    for bad in (b"2000-01-01" + b"A" * 8, saved[:10] + b"xyz", b""):
        open(os.path.join(run_dir, "site-browsers.bin"), "wb").write(bad)
        V.SITE_STATE["uniq_loaded"] = False
        V._uniq_boot()
        check("не подхватывается: %r" % bad[:14], len(V.SITE_UNIQ["set"]) == 0, V.SITE_UNIQ)
    os.environ.pop("RUNTIME_DIRECTORY")
    V.SITE_STATE["uniq_loaded"] = False
    V._uniq_boot()
    check("без RUNTIME_DIRECTORY (ручной запуск, тесты) ничего не читается и не падает", len(V.SITE_UNIQ["set"]) == 0)

    # в базе только числа: нет ни номеров браузеров, ни их хэшей, ни адресов
    db = sqlite3.connect(os.path.join(tmp, "hub.db"), timeout=10)
    rows = db.execute("SELECT day, k, n FROM sitestats").fetchall()
    keys = {k for _, k, _ in rows}
    check("в таблице sitestats только известные ключи и числа", keys <= {"views", "browsers", "starts", "http:404", "http:429", "rl:journal"}, keys)
    dump = json.dumps(rows)
    check("номеров браузеров и их хэшей в базе нет", C1 not in dump and C2 not in dump and "127.0.0.1" not in dump, dump)

    # вчерашний день для сводки наблюдателя
    y = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 3 * 3600 - 86400))
    y2 = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 3 * 3600 - 2 * 86400))
    for d, v, b, s_, e in ((y, 150, 98, 74, 530), (y2, 100, 60, 40, 10)):
        for k, n in (("views", v), ("browsers", b), ("starts", s_), ("http:404", e), ("http:429", 75), ("rl:providers", 40), ("rl:web/trace", 12), ("rl:web/stun", 9)):
            db.execute("INSERT OR REPLACE INTO sitestats(day, k, n) VALUES(?,?,?)", (d, k, n))
    db.execute("INSERT INTO webchecks(ts, asn, verdict, data, org, cid) VALUES(?,?,?,?,?,?)", (int(time.time()) - 86400, 777, "NO_BLOCK", "[]", "X", "d" * 16))
    db.commit()
    db.close()

    def watch(hour):
        e = dict(os.environ, WATCH_HUB=HUB, WATCH_STATE=os.path.join(tmp, "state.json"), BEAT_SECRET=BEAT, WATCH_SETTLE_S="0", WATCH_HOUR_MSK=str(hour))
        for k in ("TG_TOKEN", "TG_CHAT", "NTFY_TOPIC"):
            e.pop(k, None)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "ops", "udpcheck-watch.py")], env=e, capture_output=True, text=True, encoding="utf-8", timeout=60)
        return r.stdout
    out = watch(14)
    check("днём (14:00) сводка сайта не приходит", "Сайт за" not in out, out)
    out = watch(9)
    check("утром (09:00) приходит сводка за вчера с числами", "Сайт за" in out and "• Загрузок страницы: 150" in out and "• Разных браузеров: 98 (в среднем за прошлые дни 60)" in out
          and "• 404 (не найдено, в основном сканеры): 530" in out, out)
    check("сводка читается по строкам: каждое число на своей строке", out.count(chr(10) + "• ") >= 8 and (chr(10) + "Ответы не успехом:" + chr(10)) in out, out)
    check("в сводке разбивка лимита частоты по запросам с пояснениями, по убыванию",
          (chr(10) + "429 по запросам:" + chr(10) + "• web/trace (повторная трассировка раньше 5 минут): 12" + chr(10)) not in out
          and out.find("• providers (список провайдеров): 40") < out.find("• web/trace (повторная трассировка раньше 5 минут): 12") < out.find("• web/stun (проверка UDP из браузера): 9")
          and out.find("• providers (список провайдеров): 40") > out.find("429 по запросам:") > 0, out)
    check("в сводке остаток 429 приписан замедлителю роботов (75 - 61 = 14), после списка запросов хаба",
          out.find("• замедлитель роботов (много медленных запросов сразу с одного адреса): 14") > out.find("• web/stun (проверка UDP из браузера): 9") > 0, out)
    out = watch(10)
    check("в тот же день повторно сводка не приходит", "Сайт за" not in out, out)
    out = watch(9) if False else out
finally:
    if proc.poll() is None:
        proc.kill()
    if fails:
        print("stderr хаба:", proc.stderr.read().decode("utf-8", "replace")[-2500:])
    msrv.shutdown()
print("\nИТОГ:", "всё прошло" if fails == 0 else "ПРОВАЛОВ: %d" % fails)
sys.exit(1 if fails else 0)
