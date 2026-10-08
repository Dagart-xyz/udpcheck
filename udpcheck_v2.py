# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""udpcheck v2: хаб (узлы, задания, результаты, статистика) и роль цели (подписанное UDP/TCP-эхо + отчёты хабу).

Подключается к udpcheck_server.py (см. PROTOCOL.md). Только стандартная библиотека, Python 3.10+.
Включается переменными окружения:
  хаб:   UDPCHECK_HUB_DB=/var/lib/udpcheck/hub.db  UDPCHECK_HUB_TARGETS=/путь/targets.json
  цель:  UDPCHECK_TARGET_ID=HEL1-FI  UDPCHECK_TARGET_SECRET=<hex>  UDPCHECK_HUB_URL=https://dagart.xyz/udpcheck
         UDPCHECK_TARGET_TCP_PORT=8443 (необязательно)
Без этих переменных модуль ничего не делает.
"""

import hashlib
import hmac
import json
import os
import random
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import threading
import time
import urllib.request

S = None   # модуль сервера (GEO, RateLimiter, to_ranges, is_public, MAX_*, udp_bucket)

# ---------------------------------------------------------------- настройки
HUB_DB = os.environ.get("UDPCHECK_HUB_DB")
TARGETS_FILE = os.environ.get("UDPCHECK_HUB_TARGETS") or (
    os.path.join(os.environ["CREDENTIALS_DIRECTORY"], "targets.json") if os.environ.get("CREDENTIALS_DIRECTORY") else "")
PROBE_INTERVAL = int(os.environ.get("UDPCHECK_PROBE_INTERVAL", "900"))   # с между замерами одного узла
RETENTION_DAYS = int(os.environ.get("UDPCHECK_RETENTION_DAYS", "60"))
POLL_WAIT = int(os.environ.get("UDPCHECK_POLL_WAIT", "25"))             # с long-poll
RESULT_WAIT = int(os.environ.get("UDPCHECK_RESULT_WAIT", "12"))         # с ждать отчёты целей
MAX_NODES = 20000
MAX_POLLERS = 150
DEFAULT_COUNTRY = os.environ.get("UDPCHECK_DEFAULT_COUNTRY", "")          # только для разработки: страна, если база IP её не знает
DEV_COUNTRIES = [tuple(x.split("=", 1)) for x in os.environ.get("UDPCHECK_DEV_COUNTRIES", "").split(",") if "=" in x]   # "10.7.=FR,10.8.=DE"
REF_MIN_AGE = int(os.environ.get("UDPCHECK_REF_MIN_AGE", "86400"))          # чужие опорные серверы выдаём только узлам, работающим не меньше суток
REF_MIN_ROUNDS = int(os.environ.get("UDPCHECK_REF_MIN_ROUNDS", "3"))       # ...и сделавшим хотя бы столько замеров
REF_MAX_PER_DAY = int(os.environ.get("UDPCHECK_REF_MAX_PER_DAY", "5"))     # разных чужих опорных серверов на один узел в сутки
BEAT_SECRET = os.environ.get("UDPCHECK_BEAT_SECRET", "")           # секрет «сигнала жизни» от наблюдателя (оповещения)
NTFY_TOPIC = os.environ.get("UDPCHECK_NTFY_TOPIC", "")             # тема ntfy.sh: с хаба Telegram недоступен, а ntfy доступен
BACKUP_MARK = os.environ.get("UDPCHECK_BACKUP_MARK", "/var/lib/private/udpcheck/last_backup")    # сюда скрипт копий пишет время успеха
T0 = time.time()
BEAT = {"last": 0, "alerted": False}
CUT_CHECK_WINDOW = 1800      # окно, за которое порезку должны увидеть минимум два разных браузера, с
JOURNAL_EVERY = int(os.environ.get("UDPCHECK_JOURNAL_EVERY", "300"))      # как часто сверять статусы провайдеров для журнала, с
NODE_VISIBLE_DAYS = int(os.environ.get("UDPCHECK_NODE_VISIBLE_DAYS", "3"))   # узел, молчащий дольше, из публичного списка пропадает
MAX_REFS = 500                                                           # опорных серверов участников
COMMUNITY_PER_TASK = int(os.environ.get("UDPCHECK_COMMUNITY_PER_TASK", "2"))   # сколько чужих опорных серверов в одном задании

TARGET_ID = os.environ.get("UDPCHECK_TARGET_ID", "")
_sec = os.environ.get("UDPCHECK_TARGET_SECRET", "")
TARGET_SECRET = bytes.fromhex(_sec) if _sec else None
HUB_URL = os.environ.get("UDPCHECK_HUB_URL", "").rstrip("/")
TARGET_TCP_PORT = int(os.environ.get("UDPCHECK_TARGET_TCP_PORT", "0") or 0)
TEST_DROP_REPLY = os.environ.get("UDPCHECK_TEST_DROP_REPLY") == "1"      # только для тестов: принимать, но не отвечать

UDP2 = struct.Struct("!4sBB8sI4s")      # magic ver flags taskid seq mac = 22 байта
TCP2 = struct.Struct("!4sBB8s4sI")      # magic ver mode taskid mac kb   = 22 байта

HUB_ENABLED = bool(HUB_DB)
TARGET_ENABLED = bool(TARGET_SECRET and TARGET_ID and HUB_URL)


def _is_home(kind):
    """«Своя страна» относительно того, кого проверяем (узла или посетителя). Старое значение 'ru' читаем как home."""
    return kind in ("home", "ru")


def _kind_rel(target_country, subject_country):
    return "home" if target_country and subject_country and target_country == subject_country else "foreign"


def _mac(tag, taskid, secret=None):
    return hmac.new(secret or TARGET_SECRET, tag + taskid, hashlib.sha256).digest()[:4]


# ================================================================ классификация (чистые функции)
def dir_class(d):
    """Класс направления по доле доставленных пакетов (пороги как в udp_test.bat)."""
    if d < 0.05:
        return "CUT"
    if d < 0.5:
        return "PART"
    loss = 1 - d
    if loss < 0.01:
        return "OK"
    if loss <= 0.05:
        return "LOSS"
    return "BAD"


def port_class(sent, reached, back):
    if reached is None:
        return "NOREPORT"
    d_out = reached / sent if sent else 0.0
    d_in = back / reached if reached else 0.0
    good = ("OK", "LOSS")
    if dir_class(d_out) in good and dir_class(d_in) in good:
        return "OK"
    if d_out < 0.05:
        return "OUTCUT"
    if d_in < 0.5:
        return "INCUT"
    return "LOSSY"


def target_status(classes):
    if not classes:
        return "NOREPORT"
    if "NOREPORT" in classes:
        return "NOREPORT"
    uq = set(classes)
    if len(uq) == 1:
        return classes[0]                 # OK, INCUT, OUTCUT или LOSSY (потери выше нормы, но это не блокировка)
    if uq <= {"OK", "LOSSY"}:
        return "LOSSY"
    return "PART" if "OK" in uq else "MIXED"


def is_tunnel(tcp_ms, rtt_ms):
    """TCP-соединение намного быстрее UDP-эха до той же цели: рукопожатие завершает прокси/туннель рядом с узлом."""
    try:
        return rtt_ms >= 8 and tcp_ms < 0.5 * rtt_ms
    except TypeError:
        return False


NO_ANCHOR_TEXT = ("В вашей стране нашему сервису пока не на что опираться: нет опорного сервера, с которым можно сравнить. "
                  "Вы можете помочь, добавив сервер из вашей страны: https://dagart.xyz/#help-anchor")


def make_verdict(results):
    """results: [{code, kind('home'|'foreign'), status}] -> (код, текст по-русски). home: сервер в той же стране, что и проверяемый."""
    skip = ("NOREPORT", "NOHTTPS")
    if not any(_is_home(r["kind"]) for r in results):
        return "NO_ANCHOR", NO_ANCHOR_TEXT
    rus = [r for r in results if _is_home(r["kind"]) and r["status"] not in skip]
    foreign = [r for r in results if not _is_home(r["kind"]) and r["status"] not in skip]
    if not rus:
        return "CONTROL_DOWN", "Контрольная точка в вашей стране не дала результата: сравнивать не с чем. Повторите проверку."
    if not any(r["status"] in ("OK", "LOSSY") for r in rus):      # контролей в стране может быть несколько: достаточно одного чистого
        return "CONTROL_BAD", ("UDP до контрольной точки в вашей стране не проходит чисто (статус %s): проблема на линии или на ПК, "
                               "выводы по зарубежным серверам ненадёжны." % rus[0]["status"])
    if not foreign:
        return "NO_FOREIGN", "Зарубежные серверы не дали результата, сравнить UDP нельзя."
    names = lambda lst: ", ".join(r["code"] for r in lst)
    ok = [r for r in foreign if r["status"] in ("OK", "LOSSY")]      # LOSSY: проходит, но с потерями выше нормы
    lossy = [r for r in foreign if r["status"] == "LOSSY"]
    inn = [r for r in foreign if r["status"] in ("INCUT", "PART")]
    out = [r for r in foreign if r["status"] == "OUTCUT"]
    if len(ok) == len(foreign):
        extra = (" До %s заметные потери пакетов (случайные потери, не блокировка)." % names(lossy)) if lossy else ""
        return "NO_BLOCK", "UDP проходит и внутри страны, и до всех зарубежных серверов: блокировки не обнаружено." + extra
    if not ok and inn and not out:
        part = [r for r in foreign if r["status"] == "PART"]
        extra = (" На части портов у %s ответы изредка проходят: фильтр выборочный." % names(part)) if part else ""
        return "FOREIGN_IN_CUT", ("UDP до точки в вашей стране проходит чисто, а из-за рубежа (%s) ответы не приходят: пакеты узел -> сервер "
                                  "доходят, обратно нет. Режется ВХОДЯЩИЙ UDP из-за рубежа.%s Контроль в вашей стране в этот же момент чистый, "
                                  "поэтому на общую аварию канала это не похоже." % (names(inn), extra))
    if not ok and out:
        return "FOREIGN_OUT_CUT", ("UDP внутри страны проходит, а до зарубежных серверов (%s) пакеты не доходят: режется ИСХОДЯЩИЙ UDP за рубеж."
                                   % names(out))
    return "FOREIGN_PARTIAL", ("Избирательно: внутри страны UDP проходит; чисто до %s; режется или теряется до %s."
                               % (names(ok) or "никого", names([r for r in foreign if r["status"] != "OK"])))


# ================================================================ роль цели
T2 = {}                      # taskid(bytes) -> состояние замера на цели
TLOCK = threading.Lock()


def target_udp(sock, data, addr):
    """Пакет версии 2 на UDP-порт цели. Вызывается из udp-цикла сервера."""
    if not TARGET_ENABLED:
        return
    if len(data) < UDP2.size or len(data) > S.MAX_PAYLOAD:
        return
    magic, ver, flags, taskid, seq, mac = UDP2.unpack_from(data)
    if magic != b"UDPC" or ver != 2 or flags != 0 or seq >= S.MAX_SEQ:
        return
    if not hmac.compare_digest(mac, _mac(b"UDPC2", taskid)):
        return
    port = sock.getsockname()[1]
    now = time.time()
    with TLOCK:
        t = T2.get(taskid)
        if t is None:
            if len(T2) >= 500:
                return
            t = T2[taskid] = {"created": now, "last": now, "rx": {}, "replies": 0, "srcs": [],
                              "reported": False, "tries": 0}
        got = t["rx"].setdefault(port, set())
        if len(got) >= S.MAX_PKTS_PER_PORT:
            return
        got.add(seq)
        t["last"] = now
        t["reported"] = False
        if addr[0] not in t["srcs"] and len(t["srcs"]) < 8:
            t["srcs"].append(addr[0])
        if t["replies"] >= S.MAX_REPLIES or not S.udp_bucket.take():
            return
        t["replies"] += 1
    if TEST_DROP_REPLY:
        return
    reply = bytearray(data)
    reply[5] = 1
    try:
        sock.sendto(bytes(reply), addr)
    except OSError:
        pass


def _post_report(taskid, snap):
    body = json.dumps({"taskid": taskid.hex(), "ports": snap["ports"], "srcs": snap["srcs"]}).encode()
    sig = hmac.new(TARGET_SECRET, body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(HUB_URL + "/api/v2/target/report", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "X-Target": TARGET_ID, "X-Auth": sig})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 200
    except Exception:
        return False


def reporter_loop():
    """Раз в секунду: замеры, по которым 4 с тишины, отправляем хабу."""
    while True:
        time.sleep(1)
        now = time.time()
        due = []
        with TLOCK:
            for tid, t in list(T2.items()):
                if now - t["created"] > 600:
                    del T2[tid]
                    continue
                if not t["reported"] and now - t["last"] >= 4 and t["tries"] < 4:
                    snap = {"ports": {str(p): {"rx": len(v), "ranges": ",".join("%d-%d" % (a, b) for a, b in S.to_ranges(v))}
                                      for p, v in t["rx"].items()}, "srcs": list(t["srcs"])}
                    due.append((tid, snap))
        for tid, snap in due:
            ok = _post_report(tid, snap)
            with TLOCK:
                t = T2.get(tid)
                if t is not None:
                    if ok:
                        t["reported"] = True
                    else:
                        t["tries"] += 1


def _signed_post(path, obj, timeout):
    body = json.dumps(obj).encode()
    sig = hmac.new(TARGET_SECRET, body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(HUB_URL + path, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "X-Target": TARGET_ID, "X-Auth": sig})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def _do_trace_job(job):
    """Трассировка до адреса посетителя сайта (адрес даёт хаб; не публичные адреса не трассируем никогда)."""
    ip = str(job.get("ip", ""))
    if not (S.is_public(ip) or S.ALLOW_NON_GLOBAL):
        return
    results = {}
    lock = threading.Lock()

    def one(m):
        r = S.run_trace(m, ip, 443)
        with lock:
            results[m] = r
    ths = [threading.Thread(target=one, args=(m,), daemon=True) for m in ("icmp", "udp", "tcp")]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    try:
        _signed_post("/api/v2/target/trace-result", {"id": str(job.get("id", "")), "results": results}, 15)
    except Exception:
        pass


def trace_poller_loop():
    """Цель сама спрашивает хаб, нет ли трассировок для посетителей сайта (исходящее соединение, как у узлов)."""
    slots = threading.BoundedSemaphore(2)
    backoff = 3
    got = []                                              # id заданий из прошлого ответа: подтверждаем их в следующем опросе
    while True:
        try:
            r = _signed_post("/api/v2/target/poll", {"ts": int(time.time()), "ack": got, "pad": {str(p): n for p, n in S.PAD_BOUND.items()}}, 40)
            backoff = 3
            jobs = sorted((r.get("jobs") or [])[:300], key=lambda j: 0 if j.get("kind") == "pad" else 1)      # быстрые разрешения длинных ответов первыми
            got = [str(j.get("id", "")) for j in jobs]
            for job in jobs:
                if job.get("kind") == "pad":                   # хаб подтвердил посетителя: можно отвечать ему длинными пакетами
                    S.pad_allow(str(job.get("ip", "")))
                    continue
                if job.get("kind") == "stun":              # быстрое задание: сколько STUN-запросов с этого адреса мы получили
                    try:
                        seen, sent = S.stun_seen(str(job.get("ip", "")))
                        _signed_post("/api/v2/target/stun-result", {"id": str(job.get("id", "")), "seen": {str(p): n for p, n in seen.items()},
                                                                    "replied": {str(p): n for p, n in sent.items()}}, 10)
                    except Exception:
                        pass
                    continue
                if slots.acquire(blocking=False):
                    def run(j=job):
                        try:
                            _do_trace_job(j)
                        finally:
                            slots.release()
                    threading.Thread(target=run, daemon=True).start()
        except Exception:
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)


def _tcp_conn(conn):
    try:
        conn.settimeout(15)
        raw = b""
        while len(raw) < TCP2.size:
            chunk = conn.recv(TCP2.size - len(raw))
            if not chunk:
                return
            raw += chunk
        magic, ver, mode, taskid, mac, kb = TCP2.unpack(raw)
        if magic != b"TCPC" or ver != 2 or mode not in (0, 1) or not 1 <= kb <= 512:
            return
        if not hmac.compare_digest(mac, _mac(b"TCPC2", taskid)):
            return
        total = kb * 1024
        if mode == 0:
            left = total
            while left > 0:
                n = min(16384, left)
                conn.sendall(os.urandom(n))
                left -= n
        else:
            got = 0
            while got < total:
                chunk = conn.recv(min(16384, total - got))
                if not chunk:
                    break
                got += len(chunk)
            conn.sendall(struct.pack("!I", got))
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def tcp_loop(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(32)
    slots = threading.BoundedSemaphore(20)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            time.sleep(0.1)
            continue
        if not slots.acquire(blocking=False):
            conn.close()
            continue

        def run(c=conn):
            try:
                _tcp_conn(c)
            finally:
                slots.release()
        threading.Thread(target=run, daemon=True).start()


# ================================================================ хаб: БД, узлы, задания
DBL = threading.Lock()
DB = None
HLOCK = threading.Lock()
TARGETS = []                 # [{code,name,kind,ip,ports,secret(bytes),tcp_port}]
_targets_mtime = 0
TASKS = {}                   # task_id -> {node_id, ip, created, targets:{code:{...}}, reports:{code:{...}}}
TASKIDX = {}                 # taskid_hex -> (task_id, code)
POLLERS = [0]
PADS = {}                    # id -> {ip, created, targets:{code: None|True}, sent}: «разрешить серверам слать посетителю длинные STUN-ответы»
TARGET_PAD = {}              # код опорного сервера -> {порт: длина ответа}: какие порты для длинных ответов у него заняты
SEEN = {}                    # id -> {ip, created, targets:{code: None|{порт: n}}, sent:set()}: «видели ли серверы STUN-запросы посетителя»
JOURNAL_STATE = {"last": 0, "pending": {}}     # время последней сверки; кандидаты на смену статуса (нужно подтверждение следующей сверкой)
SEEN_DONE = {}               # ip -> (время, {код сервера: сколько STUN-запросов он получил}): посетитель прошёл проверку через наши серверы
TARGET_SEEN = {}             # код опорного сервера проекта -> время последнего опроса хаба (они опрашивают хаб каждые ~20 с)
REF_SEEN = {}                # node_id -> [день, множество id выданных опорных серверов участников]
WTRACES = {}                 # id -> {ip, asn, org, src, created, targets:{code: None|результат}, sent:set()}
LAST_NODE_TRACE = {}         # node_id -> время последней трассировки до узла (раз в 6 часов)
rl_register = rl_auth = rl_stats = rl_now = rl_web = rl_wtrace = rl_webrep = rl_ref = rl_seen = None
rl_wtrace_ip = rl_trace_all = rl_webrep_ip = rl_seen_ip = None   # создаются в init() для хаба

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes(id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT UNIQUE NOT NULL, callsign TEXT,
  asn INTEGER, org TEXT, country TEXT, city TEXT, client TEXT, created INTEGER, last_seen INTEGER,
  next_due INTEGER DEFAULT 0, probe_now INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS rounds(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, node_id INTEGER, asn INTEGER,
  verdict TEXT, src_same TEXT);
CREATE TABLE IF NOT EXISTS tres(id INTEGER PRIMARY KEY AUTOINCREMENT, round_id INTEGER, ts INTEGER, asn INTEGER,
  target TEXT, kind TEXT, status TEXT, tcp TEXT);
CREATE TABLE IF NOT EXISTS meas(id INTEGER PRIMARY KEY AUTOINCREMENT, round_id INTEGER, ts INTEGER, node_id INTEGER,
  asn INTEGER, target TEXT, port INTEGER, sent INTEGER, reached INTEGER, back INTEGER, cls TEXT);
CREATE TABLE IF NOT EXISTS traces(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, asn INTEGER, src_org TEXT, src TEXT,
  target TEXT, kind TEXT, method TEXT, last_asn INTEGER, last_org TEXT, last_ttl INTEGER, reached INTEGER, path TEXT);
CREATE INDEX IF NOT EXISTS traces_ts ON traces(ts);
CREATE TABLE IF NOT EXISTS webchecks(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, asn INTEGER, verdict TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS web_ts ON webchecks(ts);
CREATE TABLE IF NOT EXISTS refs(id INTEGER PRIMARY KEY AUTOINCREMENT, node_id INTEGER UNIQUE, secret TEXT, ip TEXT, udp_ports TEXT,
  tcp_port INTEGER DEFAULT 0, kind TEXT, asn INTEGER, country TEXT, verified INTEGER DEFAULT 0, created INTEGER, verified_at INTEGER);
CREATE TABLE IF NOT EXISTS asnames(asn INTEGER PRIMARY KEY, name TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS journal(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, asn INTEGER, name TEXT, kind TEXT, old TEXT, new TEXT, info TEXT);
CREATE INDEX IF NOT EXISTS journal_ts ON journal(ts);
CREATE TABLE IF NOT EXISTS asnstate(asn INTEGER PRIMARY KEY, status TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS asnmeta(asn INTEGER PRIMARY KEY, pdb_type TEXT, pdb_name TEXT, website TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS namesrep(asn INTEGER PRIMARY KEY, name TEXT, ts INTEGER);
CREATE INDEX IF NOT EXISTS web_asn ON webchecks(asn, ts);
CREATE INDEX IF NOT EXISTS rounds_asn ON rounds(asn, ts);
CREATE INDEX IF NOT EXISTS tres_asn ON tres(asn, ts);
CREATE INDEX IF NOT EXISTS traces_asn ON traces(asn, ts);
CREATE INDEX IF NOT EXISTS rounds_ts ON rounds(ts);
CREATE INDEX IF NOT EXISTS tres_ts ON tres(ts);
CREATE INDEX IF NOT EXISTS meas_ts ON meas(ts);
"""

ADJ = ["sensible", "boring", "quiet", "brave", "calm", "eager", "gentle", "honest", "jolly", "keen", "lucky", "modest",
       "noble", "polite", "rapid", "steady", "tidy", "witty", "zesty", "amber", "bright", "clever", "dusty", "fuzzy"]
NOUN = ["indigo", "purple", "falcon", "otter", "maple", "harbor", "meadow", "pebble", "comet", "ember", "willow", "lantern",
        "sparrow", "thistle", "violet", "walnut", "yarrow", "cobalt", "juniper", "marble", "orchid", "quartz", "raven", "tundra"]


def db_exec(sql, args=(), one=False, many=False, commit=True):
    with DBL:
        cur = DB.execute(sql, args)
        if commit and sql.lstrip()[:6].upper() != "SELECT":
            DB.commit()
        if one:
            return cur.fetchone()
        if many:
            return cur.fetchall()
        return cur.lastrowid


def _target_country(t):
    """Страна опорного сервера: поле country в targets.json, иначе по базе IP, иначе (старые записи) kind=ru -> RU."""
    c = str(t.get("country") or "").upper()
    if c:
        return c
    try:
        c = (S.GEO.lookup(t["ip"], force=True) or {}).get("country")
    except Exception:
        c = None
    return c or ("RU" if t.get("kind") == "ru" else None)


def load_targets(force=False):
    global TARGETS, _targets_mtime
    if not TARGETS_FILE:
        return
    try:
        mt = os.stat(TARGETS_FILE).st_mtime
    except OSError:
        return
    if not force and mt == _targets_mtime:
        return
    with open(TARGETS_FILE, encoding="utf-8") as fh:
        raw = json.load(fh)
    out = []
    for t in raw:
        out.append({"code": t["code"], "name": t.get("name", t["code"]), "country": _target_country(t),
                    "ip": t["ip"], "ports": [int(p) for p in t["ports"]], "secret": bytes.fromhex(t["secret"]),
                    "tcp_port": int(t.get("tcp_port", 0) or 0)})
    TARGETS = out
    _targets_mtime = mt


REF_SELECT = ("SELECT r.id, r.node_id, r.secret, r.ip, r.udp_ports, r.tcp_port, r.kind, n.callsign, r.asn, r.country FROM refs r "
              "JOIN nodes n ON n.id = r.node_id ")


def _ref_cfg(row):
    rid, node_id, secret, rip, ports, tcp_port, _kind, callsign, _asn, country = row[:10]
    return {"code": "REF-%d" % rid, "name": callsign or "REF-%d" % rid, "country": country, "ip": rip,
            "ports": json.loads(ports), "secret": bytes.fromhex(secret), "tcp_port": int(tcp_port or 0),
            "community": True, "node_id": node_id}


def community_refs(node_id, node_ip, node_asn, node_country=None, need_home=False):
    """Опорные серверы участников, которые сейчас на связи и прошли проверку доступности. Свой сервер узла, серверы
    с тем же адресом и из той же сети (ASN) не берём: сравнивать с ними нечего.
    need_home: в стране узла нет опорных серверов проекта. Тогда серверы участников из этой страны (из разных сетей)
    становятся контролем «своя страна» (control): они могут только забраковать замер, обвинить провайдера не могут."""
    rows = db_exec(REF_SELECT + "WHERE r.verified = 1 AND n.last_seen >= ?", (int(time.time()) - 180,), many=True)
    ok = [r for r in rows if r[1] != node_id and r[3] != node_ip and not (node_asn and r[8] == node_asn)]
    day = int(time.time()) // 86400
    entry = REF_SEEN.get(node_id)
    if entry is None or entry[0] != day:
        entry = REF_SEEN[node_id] = [day, set()]
    seen = entry[1]
    ok = [r for r in ok if r[0] in seen or len(seen) < REF_MAX_PER_DAY]      # узел видит не больше N разных чужих серверов в сутки
    if len(REF_SEEN) > 5000:
        REF_SEEN.clear()
    random.shuffle(ok)
    picked, control = [], set()
    if need_home and node_country:
        seen_asn = set()
        for r in ok:
            if r[9] == node_country and r[8] not in seen_asn and len(picked) < COMMUNITY_PER_TASK:
                picked.append(r)
                seen_asn.add(r[8])
                control.add(r[0])
    for r in ok:
        if len(picked) >= COMMUNITY_PER_TASK:
            break
        if r not in picked:
            picked.append(r)
    out = []
    for r in picked:
        seen.add(r[0])
        c = _ref_cfg(r)
        if r[0] in control:
            c["control"] = True
        out.append(c)
    return out


def _find_target(code):
    t = next((x for x in TARGETS if x["code"] == code), None)
    if t is not None or not code.startswith("REF-") or not code[4:].isdigit():
        return t
    row = db_exec(REF_SELECT + "WHERE r.id = ? AND r.verified = 1", (int(code[4:]),), one=True)
    return _ref_cfg(row) if row else None


def _probe_ref(ip, ports, tcp_port, secret):
    """Хаб сам проверяет, что опорный сервер участника доступен из интернета: подписанный UDP-пакет на каждый порт
    (ждём эхо) и короткий TCP-запрос. Возвращает (порты, ответившие по UDP; tcp_port или 0)."""
    alive = []
    for port in ports:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.settimeout(0.4)
        try:
            taskid = secrets.token_bytes(8)
            pkt = UDP2.pack(b"UDPC", 2, 0, taskid, 0, _mac(b"UDPC2", taskid, secret))
            end, got = time.time() + 2.5, False
            while not got and time.time() < end:
                sk.sendto(pkt, (ip, port))
                try:
                    d, a = sk.recvfrom(2048)
                except socket.timeout:
                    continue
                if a[0] == ip and len(d) >= UDP2.size:
                    mg, ver, fl, tid, _seq, _m = UDP2.unpack_from(d)
                    got = (mg == b"UDPC" and ver == 2 and fl == 1 and tid == taskid)
            if got:
                alive.append(port)
        except OSError:
            pass
        finally:
            sk.close()
    tcp_ok = 0
    if tcp_port and alive:
        try:
            taskid = secrets.token_bytes(8)
            c = socket.create_connection((ip, tcp_port), timeout=3)
            c.settimeout(3)
            c.sendall(TCP2.pack(b"TCPC", 2, 0, taskid, _mac(b"TCPC2", taskid, secret), 1))
            got = 0
            while got < 1024:
                chunk = c.recv(1024 - got)
                if not chunk:
                    break
                got += len(chunk)
            c.close()
            tcp_ok = tcp_port if got == 1024 else 0
        except OSError:
            tcp_ok = 0
    return alive, tcp_ok


def migrate(db):
    """Добавляем колонки, которых нет в базах, созданных прежними версиями."""
    for alter in ("ALTER TABLE nodes ADD COLUMN role TEXT",          # node | ref | both; пусто у старых агентов (= node)
                  "ALTER TABLE webchecks ADD COLUMN org TEXT",
                  "ALTER TABLE webchecks ADD COLUMN cid TEXT",
                  "ALTER TABLE nodes ADD COLUMN ver TEXT"):
        try:
            db.execute(alter)
        except sqlite3.OperationalError:
            pass
    db.commit()


def init(server_module):
    """Вызывается сервером при старте."""
    global S, DB
    S = server_module
    if HUB_ENABLED:
        os.makedirs(os.path.dirname(HUB_DB) or ".", exist_ok=True)
        DB = sqlite3.connect(HUB_DB, check_same_thread=False, timeout=30)
        DB.execute("PRAGMA journal_mode=WAL")
        DB.executescript(SCHEMA)
        migrate(DB)
        DB.commit()
        load_targets(force=True)
        global rl_register, rl_auth, rl_stats, rl_now, rl_web, rl_wtrace, rl_webrep, rl_ref, rl_seen
        global rl_wtrace_ip, rl_trace_all, rl_webrep_ip, rl_seen_ip
        rl_register = S.RateLimiter(10, 86400)
        rl_auth = S.RateLimiter(30, 60)
        rl_stats = S.RateLimiter(60, 60)
        rl_now = S.RateLimiter(1, 60)
        rl_web = S.RateLimiter(90, 60)      # страница опрашивает трассировку и подтверждения раз в секунду-две
        rl_wtrace = S.RateLimiter(1, 300)             # на анонимный номер браузера (или на IP, если номера нет)
        rl_wtrace_ip = S.RateLimiter(12, 300)         # потолок на IP: за одним адресом оператора много людей
        rl_trace_all = S.RateLimiter(300, 3600)       # общий бюджет дорогой операции: трассировки с пяти серверов
        rl_webrep = S.RateLimiter(6, 3600)            # на пару «номер браузера + IP»
        rl_webrep_ip = S.RateLimiter(60, 3600)
        rl_ref = S.RateLimiter(20, 3600)
        rl_seen = S.RateLimiter(20, 3600)
        rl_seen_ip = S.RateLimiter(200, 3600)
    if TARGET_ENABLED:
        threading.Thread(target=reporter_loop, daemon=True).start()
        threading.Thread(target=trace_poller_loop, daemon=True).start()
        if TARGET_TCP_PORT:
            threading.Thread(target=tcp_loop, args=(TARGET_TCP_PORT,), daemon=True).start()


def janitor():
    """Вызывается сервером раз в 30 с."""
    now = time.time()
    if HUB_ENABLED:
        try:
            load_targets()
        except Exception:
            pass
        try:
            beat_watch(now)
        except Exception:
            pass
        if now - JOURNAL_STATE["last"] >= JOURNAL_EVERY:
            try:
                journal_eval()
            except Exception:
                pass
        with HLOCK:
            for wid in [k for k, v in WTRACES.items() if now - v["created"] > 300]:
                del WTRACES[wid]
            for sid in [k for k, v in SEEN.items() if now - v["created"] > 60]:
                del SEEN[sid]
            for sid in [k for k, v in PADS.items() if now - v["created"] > 60]:
                del PADS[sid]
            for tid in [k for k, v in TASKS.items() if now - v["created"] > 300]:
                for tg in TASKS[tid]["targets"].values():
                    TASKIDX.pop(tg["taskid"], None)
                del TASKS[tid]
        # раз в час чистим старые сырые данные
        if int(now) // 30 % 120 == 0:
            cutoff = int(now - RETENTION_DAYS * 86400)
            for tbl in ("meas", "tres", "rounds", "traces", "webchecks"):
                try:
                    db_exec("DELETE FROM %s WHERE ts < ?" % tbl, (cutoff,))
                except Exception:
                    pass


# ---------------------------------------------------------------- узлы
def _hash(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def _callsign():
    return "%s-%s-%02d" % (random.choice(ADJ), random.choice(NOUN), random.randint(0, 99))


def _auth_node(h, ip):
    """-> строка узла (sqlite Row-кортеж) или None; ошибки считаем по IP."""
    auth = h.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or len(auth) > 200:
        return None
    row = db_exec("SELECT id, callsign, asn, next_due, probe_now FROM nodes WHERE token_hash = ?", (_hash(auth[7:].strip()),), one=True)
    if row is None and ip:
        rl_auth.allow("bad:" + ip)
    return row


_cities_db = {"conn": None, "tried": 0}
_city_cache = {}


def city_ru(cc, name):
    """Русское название города по справочнику GeoNames (cities_ru.sqlite рядом с базами GeoIP, собирается ops/build_cities_ru.py).
    Нет в справочнике (мелкие места): оставляем название как есть."""
    if not name:
        return None
    key = (cc or "", str(name).lower())
    if key in _city_cache:
        return _city_cache[key]
    conn = _cities_db["conn"]
    if conn is None and time.time() - _cities_db["tried"] > 300:
        _cities_db["tried"] = time.time()
        try:
            conn = _cities_db["conn"] = sqlite3.connect("file:%s?mode=ro" % os.path.join(S.GEO_DIR, "cities_ru.sqlite"), uri=True, check_same_thread=False)
        except Exception:
            conn = None
    res = name
    if conn is not None:
        try:
            row = conn.execute("SELECT ru FROM c WHERE cc=? AND k=?", key).fetchone()
            if row:
                res = row[0]
        except Exception:
            pass
    if len(_city_cache) > 5000:
        _city_cache.clear()
    _city_cache[key] = res
    return res


def _geo_of(ip):
    g = S.GEO.lookup(ip) if ip else {}
    country = g.get("country")
    if not country and S.ALLOW_NON_GLOBAL and ip:          # режим разработки: адреса из частных сетей
        country = next((c for pfx, c in DEV_COUNTRIES if ip.startswith(pfx)), None) or DEFAULT_COUNTRY or None
    return g.get("asn"), g.get("org"), country, g.get("city")


def node_register(h, ip, body):
    ok, retry = rl_register.allow(ip)
    if not ok:
        return h.err(429, "слишком много регистраций с этого адреса", retry)
    n = db_exec("SELECT COUNT(*) FROM nodes", one=True)[0]
    if n >= MAX_NODES:
        return h.err(503, "достигнут предел числа узлов")
    try:
        req = json.loads(body.decode("utf-8")) if body else {}
    except ValueError:
        return h.err(400, "некорректный JSON")
    client = str(req.get("client", ""))[:60]
    token = secrets.token_urlsafe(24)
    asn, org, country, city = _geo_of(ip)
    now = int(time.time())
    nid = db_exec("INSERT INTO nodes(token_hash, callsign, asn, org, country, city, client, created, last_seen, next_due) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?)", (_hash(token), _callsign(), asn, org, country, city, client, now, now, now))
    callsign = db_exec("SELECT callsign FROM nodes WHERE id=?", (nid,), one=True)[0]
    return h.send_json(201, {"token": token, "callsign": callsign, "asn": asn, "org": org, "country": country, "city": city,
                             "interval": PROBE_INTERVAL})


def _ref_eligible(node_id):
    """IP серверов участников получают только «обжитые» узлы: так их трудно собрать, регистрируя узлы пачками."""
    row = db_exec("SELECT created FROM nodes WHERE id=?", (node_id,), one=True)
    if row is None or time.time() - (row[0] or 0) < REF_MIN_AGE:
        return False
    return db_exec("SELECT COUNT(*) FROM rounds WHERE node_id=? AND verdict != 'TUNNEL'", (node_id,), one=True)[0] >= REF_MIN_ROUNDS


def _make_task(node_id, ip):
    if not TARGETS:
        return None
    tid = secrets.token_hex(8)
    targets = {}
    nasn, _org, ncountry, _city = _geo_of(ip)
    trusted_home = any(t.get("country") and t["country"] == ncountry for t in TARGETS)
    try:
        extra = community_refs(node_id, ip, nasn, ncountry, need_home=not trusted_home) if _ref_eligible(node_id) else []
    except Exception:
        extra = []
    with HLOCK:
        for t in TARGETS + extra:
            t = dict(t, kind=_kind_rel(t.get("country"), ncountry))      # home/foreign считается относительно страны узла
            taskid = secrets.token_bytes(8)
            targets[t["code"]] = {"taskid": taskid.hex(), "cfg": t, "mac": _mac(b"UDPC2", taskid, t["secret"]).hex(),
                                  "tmac": _mac(b"TCPC2", taskid, t["secret"]).hex()}
            TASKIDX[taskid.hex()] = (tid, t["code"])
        TASKS[tid] = {"node_id": node_id, "ip": ip, "created": time.time(), "targets": targets, "reports": {}}
    return {
        "task": tid, "type": "udp_probe", "count": 100, "size": 1200, "gap_ms": 1.0, "wait_s": 3,
        "targets": [{"code": c, "name": v["cfg"]["name"], "kind": v["cfg"]["kind"], "ip": v["cfg"]["ip"], "ports": v["cfg"]["ports"],
                     "taskid": v["taskid"], "mac": v["mac"], "tcp_port": v["cfg"]["tcp_port"], "tmac": v["tmac"],
                     "community": bool(v["cfg"].get("community")), "control": bool(v["cfg"].get("control"))}
                    for c, v in targets.items()],
    }


AGENT_FILE = os.environ.get("UDPCHECK_AGENT_FILE", "/var/www/udpcheck-site/node/udpcheck_node.py")
_agent_latest = {"mtime": 0, "v": None}


def _vt(v):
    try:
        return tuple(int(x) for x in str(v).split("."))
    except ValueError:
        return (0,)


def _agent_info(ver):
    """Актуальная версия агента (читаем из выложенного на сайте файла) и отстаёт ли узел. Только уведомляем, обновлять не заставляем."""
    try:
        mt = os.stat(AGENT_FILE).st_mtime
        if mt != _agent_latest["mtime"]:
            with open(AGENT_FILE, encoding="utf-8") as fh:
                m = re.search(r'^VERSION = "([0-9.]+)"', fh.read(20000), re.M)
            _agent_latest.update(mtime=mt, v=m.group(1) if m else None)
    except OSError:
        pass
    latest = _agent_latest["v"]
    return {"latest": latest, "outdated": bool(latest and ver and _vt(ver) < _vt(latest))}


def _ref_state(node_id):
    r = db_exec("SELECT verified FROM refs WHERE node_id=?", (node_id,), one=True)
    return None if r is None else bool(r[0])


def node_ref(h, ip, body):
    """Узел объявляет свой опорный сервер (порты, на которых он слушает). Хаб выдаёт секрет, затем по просьбе проверяет
    доступность снаружи. Адрес берём из соединения, а не из запроса: чужой адрес указать нельзя."""
    row = _auth_node(h, ip)
    if row is None:
        return h.err(401, "неверный токен узла")
    nid = row[0]
    ok, retry = rl_ref.allow("n%d" % nid)
    if not ok:
        return h.err(429, "слишком часто", retry)
    try:
        req = json.loads(body.decode("utf-8")) if body else {}
        ports = sorted({int(p) for p in req.get("udp_ports", [])})
        tcp_port = int(req.get("tcp_port") or 0)
        verify = bool(req.get("verify"))
        if (not ports or len(ports) > 3 or any(not 1024 <= p <= 65535 for p in ports)
                or not (tcp_port == 0 or 1024 <= tcp_port <= 65535)):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        return h.err(400, "некорректный запрос")
    if ":" in ip:
        return h.send_json(200, {"ok": False, "reason": "узел вышел к хабу по IPv6, а опорный сервер работает только по IPv4"})
    if not (S.is_public(ip) or S.ALLOW_NON_GLOBAL):
        return h.send_json(200, {"ok": False, "reason": "у узла не публичный адрес"})
    now = int(time.time())
    # устаревшие записи с тем же адресом (узел переустановили) убираем; один адрес держит один опорный сервер
    db_exec("DELETE FROM refs WHERE ip = ? AND node_id != ? AND node_id IN (SELECT id FROM nodes WHERE last_seen < ?)",
            (ip, nid, now - 3600))
    if db_exec("SELECT 1 FROM refs WHERE ip = ? AND node_id != ?", (ip, nid), one=True):
        return h.send_json(200, {"ok": False, "reason": "с этого адреса опорный сервер уже работает"})
    cur = db_exec("SELECT id, secret, ip, udp_ports, tcp_port, verified FROM refs WHERE node_id = ?", (nid,), one=True)
    if cur is None and db_exec("SELECT COUNT(*) FROM refs", one=True)[0] >= MAX_REFS:
        return h.send_json(200, {"ok": False, "reason": "достигнут предел числа опорных серверов"})
    asn, _org, country, _city = _geo_of(ip)
    kind = country or "?"      # колонка kind в refs осталась от прежней версии: храним страну
    ports_json = json.dumps(ports)
    if cur is None:
        secret = secrets.token_hex(32)
        rid = db_exec("INSERT INTO refs(node_id, secret, ip, udp_ports, tcp_port, kind, asn, country, verified, created) "
                      "VALUES(?,?,?,?,?,?,?,?,0,?)", (nid, secret, ip, ports_json, tcp_port, kind, asn, country, now))
        verified = False
    else:
        rid, secret = cur[0], cur[1]
        changed = (cur[2], cur[3], cur[4]) != (ip, ports_json, tcp_port)
        verified = bool(cur[5]) and not (changed and not verify)
        db_exec("UPDATE refs SET ip=?, udp_ports=?, tcp_port=?, kind=?, asn=?, country=?, verified=? WHERE id=?",
                (ip, ports_json, tcp_port, kind, asn, country, 1 if verified else 0, rid))
    reason = None
    if verify:
        alive, tcp_ok = _probe_ref(ip, ports, tcp_port, bytes.fromhex(secret))
        if alive:
            db_exec("UPDATE refs SET udp_ports=?, tcp_port=?, verified=1, verified_at=? WHERE id=?",
                    (json.dumps(alive), tcp_ok, now, rid))
            ports, tcp_port, verified = alive, tcp_ok, True
        else:
            db_exec("UPDATE refs SET verified=0 WHERE id=?", (rid,))
            verified = False
            reason = "хаб не получил ответ ни на одном из портов: они закрыты фаерволом или NAT"
    return h.send_json(200, {"ok": True, "code": "REF-%d" % rid, "secret": secret, "verified": verified, "kind": kind,
                             "udp_ports": ports, "tcp_port": tcp_port, "reason": reason})


def node_poll(h, ip, body=b""):
    row = _auth_node(h, ip)
    if row is None:
        return h.err(401, "неверный токен узла")
    node_id = row[0]
    try:
        req = json.loads(body.decode("utf-8")) if body else {}
    except ValueError:
        req = {}
    if isinstance(req, dict) and req.get("ref") is False:      # агент работает без опорной роли: запись о ней убираем
        db_exec("DELETE FROM refs WHERE node_id=?", (node_id,))
    ver = req.get("v") if isinstance(req, dict) else None
    if isinstance(ver, str) and re.fullmatch(r"\d{1,3}(\.\d{1,3}){0,2}", ver):
        db_exec("UPDATE nodes SET ver=? WHERE id=? AND (ver IS NULL OR ver != ?)", (ver, node_id, ver))
    else:
        r1 = db_exec("SELECT ver FROM nodes WHERE id=?", (node_id,), one=True)
        ver = r1[0] if r1 else None
    agent = _agent_info(ver)
    role = req.get("role") if isinstance(req, dict) and req.get("role") in ("node", "ref", "both") else None
    if role:
        db_exec("UPDATE nodes SET role=? WHERE id=? AND (role IS NULL OR role != ?)", (role, node_id, role))
    else:
        r0 = db_exec("SELECT role FROM nodes WHERE id=?", (node_id,), one=True)
        role = (r0[0] if r0 else None) or "node"
    with HLOCK:
        if POLLERS[0] >= MAX_POLLERS:
            return h.err(503, "сервер занят, повторите позже", 30)
        POLLERS[0] += 1
    try:
        deadline = time.time() + POLL_WAIT
        asn, org, country, city = _geo_of(ip)
        db_exec("UPDATE nodes SET last_seen=?, asn=COALESCE(?, asn), org=COALESCE(?, org), country=COALESCE(?, country), "
                "city=COALESCE(?, city) WHERE id=?", (int(time.time()), asn, org, country, city, node_id))
        if ip and ":" not in ip:
            db_exec("UPDATE refs SET verified=0 WHERE node_id=? AND ip != ? AND verified=1", (node_id, ip))   # адрес сменился
        while True:
            now = int(time.time())
            nd = db_exec("SELECT next_due, probe_now FROM nodes WHERE id=?", (node_id,), one=True)
            if role != "ref" and (nd[1] or now >= nd[0]):      # роль «опорный сервер»: заданий на проверку не выдаём
                task = _make_task(node_id, ip)
                nxt = now + int(PROBE_INTERVAL * random.uniform(0.85, 1.15))
                db_exec("UPDATE nodes SET next_due=?, probe_now=0 WHERE id=?", (nxt, node_id))
                return h.send_json(200, {"task": task, "next_in": nxt - now, "ref_verified": _ref_state(node_id), "agent": agent})
            if time.time() >= deadline:
                return h.send_json(200, {"task": None, "next_in": max(1, nd[0] - now), "ref_verified": _ref_state(node_id), "agent": agent})
            time.sleep(1)
    finally:
        with HLOCK:
            POLLERS[0] -= 1


def node_probe_now(h, ip):
    row = _auth_node(h, ip)
    if row is None:
        return h.err(401, "неверный токен узла")
    ok, retry = rl_now.allow("n%d" % row[0])
    if not ok:
        return h.err(429, "не чаще раза в минуту", retry)
    db_exec("UPDATE nodes SET probe_now=1 WHERE id=?", (row[0],))
    return h.send_json(200, {"ok": True})


# ---------------------------------------------------------------- отчёты целей и результаты узлов
def target_report(h, body):
    tgt = h.headers.get("X-Target", "")
    sig = h.headers.get("X-Auth", "")
    cfg = _find_target(tgt)
    if cfg is None or not body:
        return h.err(403, "неизвестная цель")
    want = hmac.new(cfg["secret"], body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, sig):
        return h.err(403, "неверная подпись")
    try:
        rep = json.loads(body.decode("utf-8"))
        taskid = str(rep["taskid"])
    except (ValueError, KeyError):
        return h.err(400, "некорректный отчёт")
    with HLOCK:
        ref = TASKIDX.get(taskid)
        if ref is None or ref[1] != tgt:
            return h.send_json(200, {"ok": True, "ignored": True})
        task = TASKS.get(ref[0])
        if task is not None:
            ports = {}
            for p, v in (rep.get("ports") or {}).items():
                try:
                    ports[int(p)] = int(v.get("rx", 0))
                except (ValueError, TypeError, AttributeError):
                    continue
            task["reports"][tgt] = {"ports": ports, "srcs": [str(x) for x in (rep.get("srcs") or [])][:8]}
    return h.send_json(200, {"ok": True})


def _src_same(task):
    flags = []
    for rep in task["reports"].values():
        for s in rep["srcs"]:
            flags.append(s == task["ip"])
    if not flags:
        return "?"
    if all(flags):
        return "same"
    if not any(flags):
        return "different"
    return "mixed"


def node_result(h, ip, body):
    row = _auth_node(h, ip)
    if row is None:
        return h.err(401, "неверный токен узла")
    try:
        req = json.loads(body.decode("utf-8"))
        tid = str(req["task"])
        results = req["results"]
        if not isinstance(results, list):
            raise ValueError
    except (ValueError, KeyError):
        return h.err(400, "некорректный результат")
    with HLOCK:
        task = TASKS.get(tid)
    if task is None or task["node_id"] != row[0]:
        return h.err(404, "задание не найдено или устарело")
    codes = list(task["targets"].keys())
    own = [c for c in codes if not task["targets"][c]["cfg"].get("community")]
    deadline = time.time() + RESULT_WAIT
    own_done = None
    while time.time() < deadline:
        with HLOCK:
            have = task["reports"]
            if all(c in have for c in codes):
                break
            if all(c in have for c in own):
                own_done = own_done or time.time()
                if time.time() - own_done > 5:      # серверы участников могут не ответить, ждём их недолго
                    break
        time.sleep(0.25)
    time.sleep(0.3)   # запоздавшие дополнения отчётов
    now = int(time.time())
    asn = db_exec("SELECT asn FROM nodes WHERE id=?", (row[0],), one=True)[0]
    by_code = {str(r.get("code")): r for r in results if isinstance(r, dict)}
    out_targets, verdict_in, rows, tstats, tainted = [], [], [], [], []
    sent = 100
    with HLOCK:
        reports = dict(task["reports"])
        same = _src_same(task)
    for c in codes:
        cfg = task["targets"][c]["cfg"]
        nr = by_code.get(c, {})
        nports = nr.get("ports") if isinstance(nr.get("ports"), dict) else {}
        rep = reports.get(c)
        port_rows, classes = [], []
        for p in cfg["ports"]:
            reached = None if rep is None else int(rep["ports"].get(p, 0))
            try:
                back = int((nports.get(str(p)) or {}).get("back", 0))
            except (ValueError, TypeError, AttributeError):
                back = 0
            if cfg.get("control") and reached is not None:
                reached = max(reached, max(0, min(back, sent)))    # сервер участника как контроль: верим тому, что реально вернулось узлу
            back = max(0, min(back, reached if reached is not None else back, sent))
            if reached is not None:
                reached = max(0, min(reached, sent))
            cls = port_class(sent, reached, back)
            classes.append(cls)
            port_rows.append({"port": p, "reached": reached, "back": back, "class": cls})
            rows.append((c, p, sent, reached, back, cls))
        status = target_status(classes)
        comm = bool(cfg.get("community"))
        if not comm and is_tunnel(nr.get("tcp_connect_ms"), nr.get("udp_rtt_ms")):
            tainted.append(c)
        tcp = nr.get("tcp") if isinstance(nr.get("tcp"), dict) else {}
        tcp_state = "NA"
        if tcp:
            tcp_state = "OK" if (tcp.get("down_ok") and tcp.get("up_ok")) else ("ERR" if tcp.get("error") else "CUT")
        if not comm or cfg.get("control"):
            verdict_in.append({"code": c, "kind": cfg["kind"], "status": status})   # серверы участников в итог не входят (кроме контроля)
        tstats.append((c, cfg["kind"], status, tcp_state))
        out_targets.append({"code": c, "kind": cfg["kind"], "name": cfg["name"], "status": status, "ports": port_rows, "tcp": tcp_state,
                            "community": comm, "control": bool(cfg.get("control"))})
    if tainted:
        vcode = "TUNNEL"
        vtext = ("На пути узла стоит прозрачный прокси или туннель: TCP-соединение с %s завершается быстрее, чем идёт UDP-эхо, то есть "
                 "рукопожатие делает не цель, а что-то рядом с вами. Замер отражает этот прокси, а не провайдера, "
                 "и в статистику не попадает." % ", ".join(tainted))
    else:
        vcode, vtext = make_verdict(verdict_in)
    rid = db_exec("INSERT INTO rounds(ts, node_id, asn, verdict, src_same) VALUES(?,?,?,?,?)", (now, row[0], asn, vcode, same))
    with DBL:
        for c, p, snt, rch, bk, cls in ([] if tainted else rows):
            DB.execute("INSERT INTO meas(round_id, ts, node_id, asn, target, port, sent, reached, back, cls) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (rid, now, row[0], asn, c, p, snt, rch, bk, cls))
        for c, kind, status, tcp_state in ([] if tainted else tstats):
            DB.execute("INSERT INTO tres(round_id, ts, asn, target, kind, status, tcp) VALUES(?,?,?,?,?,?,?)",
                       (rid, now, asn, c, kind, status, tcp_state))
        DB.commit()
    with HLOCK:
        for tg in task["targets"].values():
            TASKIDX.pop(tg["taskid"], None)
        TASKS.pop(tid, None)
        if (not tainted and time.time() - LAST_NODE_TRACE.get(row[0], 0) > 6 * 3600 and len(WTRACES) < 150
                and (S.is_public(task["ip"]) or S.ALLOW_NON_GLOBAL) and TARGETS):
            LAST_NODE_TRACE[row[0]] = time.time()
            g = S.GEO.lookup(task["ip"]) or {}
            WTRACES[secrets.token_hex(8)] = {"ip": task["ip"], "asn": g.get("asn"), "org": g.get("org"), "src": "node",
                                             "country": _geo_of(task["ip"])[2], "created": time.time(), "targets": {t["code"]: None for t in TARGETS}, "sent": {}}
    return h.send_json(200, {"round": rid, "verdict": {"code": vcode, "text": vtext}, "targets": out_targets,
                             "src_same": same, "attribution": S.GEO_ATTRIBUTION})


# ---------------------------------------------------------------- публичная статистика
def stats_overview(h, ip, hours):
    ok, retry = rl_stats.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    since = int(time.time()) - hours * 3600
    asns = {}
    for asn, nodes, rounds in db_exec("SELECT asn, COUNT(DISTINCT node_id), COUNT(*) FROM rounds WHERE ts>=? AND verdict != 'TUNNEL' GROUP BY asn", (since,), many=True):
        org = db_exec("SELECT org FROM nodes WHERE asn IS ? AND org IS NOT NULL LIMIT 1", (asn,), one=True)
        asns[asn] = {"asn": asn, "org": org[0] if org else None, "nodes": nodes, "rounds": rounds, "verdicts": {}, "targets": {}}
    for asn, v, n in db_exec("SELECT asn, verdict, COUNT(*) FROM rounds WHERE ts>=? AND verdict != 'TUNNEL' GROUP BY asn, verdict", (since,), many=True):
        asns[asn]["verdicts"][v] = n
    for asn, tgt, st, n in db_exec("SELECT asn, target, status, COUNT(*) FROM tres WHERE ts>=? AND target NOT LIKE 'REF-%' GROUP BY asn, target, status", (since,), many=True):
        asns[asn]["targets"].setdefault(tgt, {})[st] = n
    return h.send_json(200, {"window_hours": hours, "generated": int(time.time()), "asns": sorted(asns.values(), key=lambda a: -a["rounds"]),
                             "note": "Агрегаты по провайдерам (ASN). Отдельные узлы не показываются.", "attribution": S.GEO_ATTRIBUTION})


def stats_paths(h, ip, hours):
    """По провайдерам (ASN): после какой AS замолкают трассировки от наших целей (ICMP). Только номера сетей, без адресов."""
    ok, retry = rl_stats.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    since = int(time.time()) - hours * 3600
    out = {}
    q = ("SELECT asn, kind, last_asn, MAX(last_org), COUNT(*), MAX(last_ttl) FROM traces "
         "WHERE ts>=? AND method='icmp' AND asn IS NOT NULL AND last_asn IS NOT NULL GROUP BY asn, kind, last_asn")
    for asn, kind, last_asn, last_org, n, ttl in db_exec(q, (since,), many=True):
        e = out.setdefault(asn, {"asn": asn, "org": None, "cuts": {"home": [], "foreign": []}, "traces": 0})
        e["cuts"].setdefault("foreign" if kind == "foreign" else "home", []).append({"asn": last_asn, "org": last_org, "n": n, "ttl": ttl})
        e["traces"] += n
    for asn, e in out.items():
        r = db_exec("SELECT src_org FROM traces WHERE asn=? AND src_org IS NOT NULL LIMIT 1", (asn,), one=True)
        e["org"] = r[0] if r else None
        for k in e["cuts"]:
            e["cuts"][k] = sorted(e["cuts"][k], key=lambda x: -x["n"])[:6]
    return h.send_json(200, {"window_hours": hours, "providers": sorted(out.values(), key=lambda e: -e["traces"]),
                             "note": "Обрыв в трассировке не доказывает, что режет именно эта сеть: дальше оборудование просто не отвечает."})


def nodes_public(h, ip):
    """Публичный список узлов: позывной, сеть провайдера, система, онлайн, число замеров, последний итог, опорный сервер.
    Без города, без адресов, без токенов. Показываем узлы, которые выходили на связь за последние NODE_VISIBLE_DAYS суток."""
    ok, retry = rl_stats.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    now = int(time.time())
    rows = db_exec(
        "SELECT n.id, n.callsign, n.asn, n.org, n.country, n.client, n.last_seen, n.created, n.role, n.ver, n.city, "
        "(SELECT COUNT(*) FROM rounds r WHERE r.node_id = n.id AND r.verdict != 'TUNNEL'), "
        "(SELECT COUNT(*) FROM rounds r WHERE r.node_id = n.id AND r.verdict = 'TUNNEL'), "
        "(SELECT r.verdict FROM rounds r WHERE r.node_id = n.id AND r.verdict != 'TUNNEL' ORDER BY r.id DESC LIMIT 1) "
        "FROM nodes n WHERE n.last_seen >= ? ORDER BY n.last_seen DESC LIMIT 200", (now - NODE_VISIBLE_DAYS * 86400,), many=True)
    refs = {r[0]: r for r in db_exec("SELECT node_id, id, verified, country FROM refs", many=True)}
    refstat = {}
    for tgt, st, n in db_exec("SELECT target, status, COUNT(*) FROM tres WHERE ts>=? AND target LIKE 'REF-%' GROUP BY target, status",
                              (now - 86400,), many=True):
        refstat.setdefault(tgt, {})[st] = n
    out, online, refs_on = [], 0, 0
    latest_agent = _agent_info(None)["latest"]
    for nid, callsign, asn, org, country, client, last_seen, created, role, ver, city, rounds, tunnel, last_verdict in rows:
        is_on = now - (last_seen or 0) < 120
        online += 1 if is_on else 0
        osname = "Windows" if "Windows" in (client or "") else ("macOS" if "Darwin" in (client or "") else "Linux")
        r = refs.get(nid)
        role = role or ("both" if r is not None else "node")
        refinfo = None
        if r is not None:
            ss = refstat.get("REF-%d" % r[1], {})
            refinfo = {"active": bool(r[2]) and is_on, "country": r[3], "checks": sum(ss.values()), "ok": ss.get("OK", 0)}
            refs_on += 1 if refinfo["active"] else 0
        is_server = role in ("ref", "both")      # про серверы показываем только позывной, город и страну: хостинг не светим
        entry = {"callsign": callsign, "asn": None if is_server else asn, "org": None if is_server else org,
                 "country": country, "os": osname, "online": is_on,
                    "last_seen_age": now - (last_seen or now), "since_days": max(0, (now - (created or now)) // 86400),
                    "rounds": rounds, "tunnel_rounds": tunnel, "last_verdict": last_verdict, "ref": refinfo, "role": role,
                    "ver": ver, "outdated": bool(ver and latest_agent and _vt(ver) < _vt(latest_agent))}
        if is_server:
            entry["city"] = city_ru(country, city)      # русское название; у домашних узлов города в списке нет
            entry["city_en"] = city
        out.append(entry)
    anchors = []
    astat = {}                             # по проверкам посетителей за сутки: сколько раз сервер участвовал и сколько раз ответил
    for (d,) in db_exec("SELECT data FROM webchecks WHERE ts>=?", (now - 86400,), many=True):
        try:
            for r in json.loads(d):
                e = astat.setdefault(str(r.get("code")), [0, 0])
                e[0] += 1
                e[1] += 1 if int(r.get("ok", 0)) >= 0.8 * int(r.get("n", 1) or 1) else 0
        except (ValueError, TypeError, AttributeError):
            continue
    for t in TARGETS:                      # опорные серверы проекта: по ним строится вывод (адресов не отдаём)
        g = S.GEO.lookup(t["ip"], force=True) or {}
        st = astat.get(t["code"], [0, 0])
        anchors.append({"code": t["code"], "name": t["name"], "country": t.get("country") or g.get("country"),
                        "online": now - TARGET_SEEN.get(t["code"], 0) < 90, "checks": st[0], "ok": st[1]})
    return h.send_json(200, {"online": online, "total": len(out), "refs_active": refs_on, "nodes": out, "anchors": anchors})


# ---------------------------------------------------------------- карточки провайдеров и страница провайдера
CUT_W = {"FOREIGN_IN_CUT": 1.0, "FOREIGN_OUT_CUT": 1.0, "FOREIGN_PARTIAL": 0.5}   # вес «режется» в итоге замера
_names = {"mtime": 0, "data": {}}


_brands = {"mtime": 0, "data": []}
_org_cache = {"t": 0, "data": {}}
_gmap = {"t": 0, "key": {}, "members": {}}
LEGAL_PHRASES = re.compile(r"(?i)public\s+joint[\s-]*stock\s+company|open\s+joint[\s-]*stock\s+company|closed\s+joint[\s-]*stock\s+company|"
                           r"joint[\s-]*stock\s+company|limited\s+liability\s+company|limited\s+liability\s+partnership|"
                           r"sabiedriba\s+ar\s+ierobezotu\s+atbildibu|\bbranch\b")
LEGAL_TOKENS = {"pjsc", "ojsc", "cjsc", "jsc", "llc", "ooo", "oao", "zao", "pao", "ltd", "limited", "inc", "corp", "srl", "sarl", "gmbh", "bv", "ou", "oü",
                "sia", "llp", "fzco", "sas", "plc", "co", "sa", "spa", "ab", "the", "sl", "sro", "kft", "oy"}
GENERIC_NAMES = {"retail", "hosting services", "uplinks", "telecommunication business", "customer", "customers", "internet", "network", "networks",
                 "telecom", "hosting", "cloud", "isp", "datacenter", "data center", "transit", "backbone", "default", "services", "service"}
PERSON_RE = re.compile(r"(?i)individual\s+entrepreneur|sole\s+proprietor|private\s+person|^ie\s|^ип\s|индивидуальный\s+предприниматель|"
                       r"\b\w+(?:evich|ovich|yevich|evna|ovna|yevna)\b")           # отчество в названии: сеть записана на человека
STOPWORDS = {"for", "of", "the", "and", "in", "on", "at", "to"}


def _is_person(text):
    return bool(text and PERSON_RE.search(str(text)))


def clean_name(text):
    """Читаемое имя из строки whois: без правовых форм (PJSC, LLC, ООО), кавычек и КРИКА ЗАГЛАВНЫМИ; сайт вида https://x.com -> X."""
    t = str(text or "").strip()
    if not t:
        return ""
    m = re.match(r"(?i)^https?://(?:www\.)?([^/\s:]+)", t)
    if m:
        t = m.group(1).split(".")[0].capitalize()
    t = LEGAL_PHRASES.sub(" ", t)
    t = re.sub(r"[\"“”«»`'/\\]+", " ", t)
    toks = t.split()

    def norm(x):
        return re.sub(r"[.,:;()]", "", x).lower()
    while toks and norm(toks[0]) in LEGAL_TOKENS:
        toks.pop(0)
    while toks and (norm(toks[-1]) in LEGAL_TOKENS or not norm(toks[-1]) or (len(toks) > 1 and norm(toks[-1]) == "as")):
        toks.pop()
    out = []
    for w in toks:
        w = w.strip(" ,:;")
        letters = re.sub(r"[^A-Za-z]", "", w)
        if len(letters) > 4 and w == w.upper():
            w = re.sub(r"[^-.]+", lambda m: m.group(0).capitalize(), w)         # KVANT-TELEKOM -> Kvant-Telekom
        elif len(toks) >= 5 and w.lower() in STOPWORDS:
            w = w.lower()
        out.append(w)
    if out and out[0][:1].islower():
        out[0] = out[0][:1].upper() + out[0][1:]
    t = " ".join(out).strip(" .,:;-")
    if len(t) > 42:
        t = t[:42].rsplit(" ", 1)[0] + "…"
    return t


def _bad_name(t, strict=True):
    if not t or len(t) < 3:
        return True
    low = t.lower()
    if re.search(r"announce|^as\d+|\bas\d{3,}\b|https?:|\.\.", low):
        return True
    return strict and low in GENERIC_NAMES


def _load_names():
    try:
        f = os.path.join(S.GEO_DIR, "names.json")
        mt = os.stat(f).st_mtime
        if mt != _names["mtime"]:
            with open(f, encoding="utf-8") as fh:
                _names["data"] = {str(k): str(v) for k, v in json.load(fh).items()}
            _names["mtime"] = mt
    except (OSError, ValueError, AttributeError):
        pass
    try:
        f = os.path.join(S.GEO_DIR, "brands.json")
        mt = os.stat(f).st_mtime
        if mt != _brands["mtime"]:
            with open(f, encoding="utf-8") as fh:
                _brands["data"] = [(str(b["name"]), [re.compile(p, re.I) for p in b["match"]]) for b in json.load(fh)]
            _brands["mtime"] = mt
    except (OSError, ValueError, AttributeError, KeyError, TypeError, re.error):
        pass


def _org_of(asn):
    now = time.time()
    if now - _org_cache["t"] > 300:
        d = {}
        try:
            for a, o in db_exec("SELECT asn, MAX(org) FROM webchecks WHERE asn IS NOT NULL AND org IS NOT NULL GROUP BY asn", many=True):
                d[a] = o
            for a, o in db_exec("SELECT asn, MAX(org) FROM nodes WHERE asn IS NOT NULL AND org IS NOT NULL GROUP BY asn", many=True):
                d[a] = o
        except Exception:
            d = _org_cache["data"]
        _org_cache.update(t=now, data=d)
    return _org_cache["data"].get(asn)


def public_org(asn, org):
    """Название организации для показа: частных лиц (ИП и подобное) публично не называем."""
    o = org or _org_of(asn)
    _load_names()
    return None if (not o or _is_person(o) or _is_person(_asn_name(asn)) or str(_names["data"].get(str(asn), "")).startswith("Частный")) else o


def provider_group(asn, org=None):
    """(ключ группы, имя для показа). Сети одного оператора (несколько AS у Ростелекома, ЭР-Телекома и др.) сводятся в одну карточку:
    сначала список брендов brands.json, иначе одинаковое очищенное имя."""
    _load_names()
    org = org or _org_of(asn)
    desc = _asn_name(asn)
    if _names["data"].get(str(asn)):
        name = _names["data"][str(asn)]
    elif _is_person(org) or _is_person(desc):
        return ("asn:%d" % asn, "Частный провайдер AS%d" % asn)
    else:
        c1, c2 = clean_name(desc), clean_name(org)
        name = c1 if not _bad_name(c1) else (c2 if not _bad_name(c2, strict=False) else ("AS%d" % asn))
    text = " ".join([str(org or ""), str(desc or ""), name])
    for bname, pats in _brands["data"]:
        if any(p.search(text) for p in pats):
            return ("b:" + bname, bname)
    return (("n:" + name.lower()) if not name.startswith("AS") else ("asn:%d" % asn), name)


def provider_name(asn, org=None):
    return provider_group(asn, org)[1]


def _groups():
    now = time.time()
    if now - _gmap["t"] < 30:
        return _gmap
    asns = set()
    since = int(now) - 30 * 86400
    for q in ("SELECT DISTINCT asn FROM webchecks WHERE asn IS NOT NULL AND ts>=?", "SELECT DISTINCT asn FROM rounds WHERE asn IS NOT NULL AND ts>=?"):
        asns |= {a for (a,) in db_exec(q, (since,), many=True)}
    key, members = {}, {}
    for a in asns:
        k, _n = provider_group(a)
        key[a] = k
        members.setdefault(k, []).append(a)
    _gmap.update(t=now, key=key, members=members)
    return _gmap


def group_members(asn):
    """Все сети того же оператора, что и asn (включая её саму)."""
    k, _n = provider_group(asn)
    m = list(_groups()["members"].get(k, []))
    if asn not in m:
        m.append(asn)
    return sorted(set(m))


_asn_cache = {}             # asn -> имя из RIPE или "" (ничего подходящего)
_asn_try = {}               # asn -> время последней попытки спросить RIPE
LOGO_DIR = os.environ.get("UDPCHECK_LOGO_DIR", "/var/www/udpcheck-site/logos")


def _pretty_descr(d):
    """Описание сети из whois («SEVEN-SKY») -> короткое имя («Seven Sky»); длинные тексты и адреса почты не годятся."""
    d = re.sub(r"\s+", " ", str(d).strip())
    if not d or len(d) > 28 or "@" in d or "," in d or d.lower().startswith(("as ", "autonomous", "private", "customer")):
        return None
    if {w.lower() for w in re.split(r"[-_ .]+", d)} & {"edge", "network", "networks", "net", "as", "backbone", "transit", "internet",
                                                        "russia", "moscow", "spb", "ru", "carrier", "isp", "customers"}:
        return None            # это не имя бренда (место или тип сети): лучше взять имя организации из базы IP
    if d.upper() == d:
        d = " ".join(w.capitalize() for w in re.split(r"[-_ ]+", d) if w)
    return d


def _asn_fetch(asn):
    """Спрашиваем у RIPEstat whois сети: поле descr обычно содержит торговое имя провайдера. Результат кладём в базу на 30 суток."""
    try:
        req = urllib.request.Request("https://stat.ripe.net/data/whois/data.json?resource=AS%d" % asn, headers={"User-Agent": "udpcheck-hub"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read(300000))["data"]
        name = ""
        for rec in data.get("records", []):
            for f in rec:
                if f.get("key") == "descr" and not name:
                    name = _pretty_descr(f.get("value", "")) or ""
        db_exec("INSERT OR REPLACE INTO asnames(asn, name, ts) VALUES(?,?,?)", (asn, name, int(time.time())))
        _asn_cache[asn] = name
    except Exception:
        pass


def _asn_name(asn):
    if asn in _asn_cache:
        return _asn_cache[asn]
    row = db_exec("SELECT name, ts FROM asnames WHERE asn=?", (asn,), one=True)
    if row is not None:
        _asn_cache[asn] = row[0] or ""
        if time.time() - (row[1] or 0) < 30 * 86400:
            return _asn_cache[asn]
    now = time.time()
    if now - _asn_try.get(asn, 0) > 3600 and len(_asn_try) < 5000:
        _asn_try[asn] = now
        threading.Thread(target=_asn_fetch, args=(asn,), daemon=True).start()
    return _asn_cache.get(asn, "")


HOST_WORDS = ("host", "cloud", "server", "vps", "vds", "vpn", "datacenter", "data center", "datacent", "dedic", "colocation", "hetzner", "ovh",
              "digitalocean", "amazon", "google", "microsoft", "oracle", "leaseweb", "contabo", "vultr", "linode", "akamai", "m247", "aeza", "selectel",
              "netcrafters", "fzco", "colo", "cdn", "proxy", "anycast", "ddos", "хостинг", "облак", "сервер", "впн")
HOST_SITE_WORDS = ("host", "cloud", "vps", "vds", "vpn", "server", "datacenter", "cdn", "proxy")     # слова в адресе сайта организации (PeeringDB)
_meta_cache = {}
_meta_try = {}
_kinds = {"mtime": 0, "data": {}}


def _pdb_fetch(asn):
    """Тип сети по PeeringDB (Content = контент/хостинг, Cable/DSL/ISP = провайдер доступа), имя и сайт. Пустой ответ тоже кэшируем."""
    try:
        req = urllib.request.Request("https://www.peeringdb.com/api/net?asn=%d&fields=info_type,name,website" % asn, headers={"User-Agent": "udpcheck-hub"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = (json.loads(r.read(200000)).get("data") or [{}])
        d = data[0] if data else {}
        row = (d.get("info_type") or "", str(d.get("name") or "")[:60], str(d.get("website") or "")[:120])
        db_exec("INSERT OR REPLACE INTO asnmeta(asn, pdb_type, pdb_name, website, ts) VALUES(?,?,?,?,?)", (asn,) + row + (int(time.time()),))
        _meta_cache[asn] = row
    except Exception:
        pass


def _pdb_type(asn):
    """(тип, название, сайт) сети по PeeringDB; пока данных нет, пустые строки."""
    if asn in _meta_cache:
        return _meta_cache[asn]
    row = db_exec("SELECT pdb_type, pdb_name, website, ts FROM asnmeta WHERE asn=?", (asn,), one=True)
    if row is not None:
        _meta_cache[asn] = (row[0] or "", row[1] or "", row[2] or "")
        if time.time() - (row[3] or 0) < 30 * 86400:
            return _meta_cache[asn]
    now = time.time()
    if now - _meta_try.get(asn, 0) > 3600 and len(_meta_try) < 5000:
        _meta_try[asn] = now
        threading.Thread(target=_pdb_fetch, args=(asn,), daemon=True).start()
    return _meta_cache.get(asn, ("", "", ""))


def provider_kind(asn, org, name):
    """«hosting» (хостинг, VPN, облако: адрес не обычного провайдера) или «isp». Порядок: ручной список provider_kinds.json, слова в названии,
    тип Content в PeeringDB. Неизвестное считаем провайдером."""
    try:
        f = os.path.join(S.GEO_DIR, "provider_kinds.json")
        mt = os.stat(f).st_mtime
        if mt != _kinds["mtime"]:
            with open(f, encoding="utf-8") as fh:
                _kinds["data"] = {str(k): str(v) for k, v in json.load(fh).items()}
            _kinds["mtime"] = mt
    except (OSError, ValueError, AttributeError):
        pass
    if str(asn) in _kinds["data"]:
        return _kinds["data"][str(asn)]
    text = ("%s %s" % (org or "", name or "")).lower()
    if any(w in text for w in HOST_WORDS):
        return "hosting"
    ptype, pname, site = _pdb_type(asn)
    if ptype == "Content":
        return "hosting"
    host = re.sub(r"^https?://", "", (site or "").lower()).split("/")[0]
    if host and (any(w in host for w in HOST_SITE_WORDS) or host.rsplit(".", 1)[-1] in ("host", "cloud", "hosting", "vps", "server", "servers")):
        return "hosting"          # сайт вида 1cent.host или play2go.cloud
    if pname and any(w in pname.lower() for w in HOST_WORDS):
        return "hosting"
    return "isp"


def provider_logo(asn):
    """Логотип лежит файлом LOGO_DIR/<asn>.svg|webp|png|jpg|ico (раздаётся сайтом как /logos/...); нет файла, на странице буквы."""
    for ext in ("svg", "webp", "png", "jpg", "ico"):
        if os.path.exists(os.path.join(LOGO_DIR, "%d.%s" % (asn, ext))):
            return "/logos/%d.%s" % (asn, ext)
    return None


def prov_status(cut, total):
    """cut: взвешенное число замеров «режется», total: число надёжных замеров за окно."""
    if total <= 0:
        return "stale"
    share = cut / total
    return "cut" if share >= 0.6 else ("partial" if share >= 0.2 else "ok")


def status_from(bk):
    """Статус по последним 6 часам; если замеров нет, по последним суткам, но с пометкой «данные устарели»."""
    cut, tot = sum(b["cut"] for b in bk[-6:]), sum(b["cut"] + b["ok"] for b in bk[-6:])
    if tot > 0:
        return prov_status(cut, tot), False
    cut, tot = sum(b["cut"] for b in bk[-24:]), sum(b["cut"] + b["ok"] for b in bk[-24:])
    if tot == 0 and sum(b["na"] for b in bk[-24:]) > 0:
        return "noanchor", False
    return prov_status(cut, tot), tot > 0


def _hour_buckets(rows, hour_now, n):
    """rows: [(hour, verdict, count)] -> [{cut, ok, bad}] за n часов, самый старый первым."""
    out = [{"cut": 0.0, "ok": 0, "bad": 0, "na": 0} for _ in range(n)]
    for hr, v, c in rows:
        i = n - 1 - (hour_now - hr)
        if 0 <= i < n:
            if v in CUT_W:
                out[i]["cut"] += CUT_W[v] * c
                out[i]["ok"] += (1 - CUT_W[v]) * c
            elif v == "NO_BLOCK":
                out[i]["ok"] += c
            elif v == "NO_ANCHOR":
                out[i]["na"] += c
            else:
                out[i]["bad"] += c
    return out


def _size_scan(since, until=None, asn=None):
    """Проверки посетителей с длинными ответами: {asn: {"tested", "cut", "max", "cids"}}. Проверка считается порезанной по размеру, если у серверов,
    чьи короткие ответы дошли, не дошла половина и больше длинных ответов; один браузер считается раз в час."""
    out = {}
    done = set()
    q = "SELECT id, ts, asn, data, cid FROM webchecks WHERE ts>? AND asn IS NOT NULL AND data LIKE '%\"pad\"%'"
    args = [since]
    if until:
        q += " AND ts<=?"
        args.append(until)
    for rid, ts, a, data, cid in db_exec(q, tuple(args), many=True):
        if asn is not None and a not in asn:
            continue
        try:
            d = json.loads(data)
        except ValueError:
            continue
        pairs = fails = 0
        big = 0
        for r in d:
            if int(r.get("ok", 0)) > 0:
                for size, ok, n in (r.get("pad") or []):
                    pairs += 1
                    if ok == 0:
                        fails += 1
                        big = max(big, size)
        if not pairs:
            continue
        who = (cid or "i%d" % rid, ts // 3600)
        if who in done:
            continue
        done.add(who)
        e = out.setdefault(a, {"tested": 0, "cut": 0, "max": 0, "cids": set()})
        e["tested"] += 1
        if fails * 2 >= pairs:
            e["cut"] += 1
            e["max"] = max(e["max"], big)
            e["cids"].add(who[0])
    return out


def _size_sum(stats, asns):
    t = c = m = 0
    cids = set()
    for a in asns:
        e = stats.get(a)
        if e:
            t += e["tested"]
            c += e["cut"]
            m = max(m, e["max"])
            cids |= e["cids"]
    return {"tested": t, "cut": c, "max": m, "browsers": len(cids)}


def _log(ts, asn, kind, old, new, info):
    db_exec("INSERT INTO journal(ts, asn, name, kind, old, new, info) VALUES(?,?,?,?,?,?,?)",
            (int(ts), asn, provider_name(asn, None), kind, old, new, json.dumps(info, ensure_ascii=False)))


def journal_eval(now=None):
    """Сверяем статусы провайдеров и пишем журнал: (1) сеть появилась, (2) статус сменился (с подтверждением следующей сверкой, чтобы не мигать),
    (3) порезка у двух и более посетителей за полчаса в сети, где сейчас порезки нет (с серверным подтверждением, что ответы отправлены)."""
    now = int(now or time.time())
    hour_now = now // 3600
    last = JOURNAL_STATE["last"] or now - JOURNAL_EVERY
    JOURNAL_STATE["last"] = now
    states = {a: st for a, st in db_exec("SELECT asn, status FROM asnstate", many=True)}
    rows = {}
    for a, hr, v, c in db_exec("SELECT asn, ts/3600, verdict, COUNT(*) FROM rounds WHERE ts>=? AND asn IS NOT NULL AND verdict != 'TUNNEL' GROUP BY asn, ts/3600, verdict",
                               (now - 24 * 3600,), many=True):
        rows.setdefault(a, []).append((hr, v, c))
    brw = {}
    for a, hr, v, c, nb in db_exec("SELECT asn, ts/3600, verdict, " + "COUNT(DISTINCT COALESCE(cid, 'i' || id))" + ", COUNT(DISTINCT cid) FROM webchecks "
                                   "WHERE ts>=? AND asn IS NOT NULL GROUP BY asn, ts/3600, verdict", (now - 24 * 3600,), many=True):
        rows.setdefault(a, []).append((hr, v, c))
        if hour_now - hr < 6:
            brw[a] = brw.get(a, 0) + (nb or 0)
    for asn, rws in rows.items():
        bk = _hour_buckets(rws, hour_now, 24)
        st, old = status_from(bk)
        if old or st == "stale":                      # свежих данных нет: смену статуса не фиксируем
            continue
        cur = states.get(asn)
        recent = bk[-6:]
        info = {"checks": int(sum(b["cut"] + b["ok"] for b in recent)), "browsers": brw.get(asn, 0),
                "cut_share": round(sum(b["cut"] for b in recent) / max(1, sum(b["cut"] + b["ok"] for b in recent)), 2)}
        if cur is None:
            # время появления сети берём по первой проверке, а не по моменту сверки (при первом запуске журнала их много сразу)
            first = db_exec("SELECT MIN(t) FROM (SELECT MIN(ts) AS t FROM rounds WHERE asn=? UNION ALL SELECT MIN(ts) FROM webchecks WHERE asn=?)", (asn, asn), one=True)[0]
            _log(first or now, asn, "new", None, st, info)
            db_exec("INSERT OR REPLACE INTO asnstate(asn, status, ts) VALUES(?,?,?)", (asn, st, now))
        elif st != cur:
            if JOURNAL_STATE["pending"].get(asn) == st:           # то же самое и в прошлую сверку: подтверждаем
                _log(now, asn, "change", cur, st, info)
                db_exec("INSERT OR REPLACE INTO asnstate(asn, status, ts) VALUES(?,?,?)", (asn, st, now))
                JOURNAL_STATE["pending"].pop(asn, None)
            else:
                JOURNAL_STATE["pending"][asn] = st
        else:
            JOURNAL_STATE["pending"].pop(asn, None)
    # порезка у нескольких посетителей сети, где статус сейчас не «режется»: нужны минимум два разных браузера за полчаса
    blips = {}
    for asn, v, data, cid in db_exec("SELECT asn, verdict, data, cid FROM webchecks WHERE ts>? AND ts<=? AND asn IS NOT NULL AND verdict IN "
                                     "('FOREIGN_IN_CUT', 'FOREIGN_PARTIAL', 'FOREIGN_OUT_CUT') ORDER BY ts", (now - CUT_CHECK_WINDOW, now), many=True):
        if states.get(asn) == "cut":
            continue
        e = blips.setdefault(asn, {"n": 0, "replied": 0, "cids": set(), "dirs": set()})
        e["n"] += 1
        e["cids"].add(cid or "x%d" % e["n"])
        e["dirs"].add("out" if v == "FOREIGN_OUT_CUT" else "in")
        try:
            e["replied"] = max(e["replied"], sum(1 for r in json.loads(data) if not str(r.get("code", "")).startswith("REF-")
                                                  and int(r.get("ok", 0)) == 0 and int(r.get("replied", -1)) > 0))
        except (ValueError, TypeError, AttributeError):
            pass
    for asn, e in _size_scan(now - CUT_CHECK_WINDOW, now).items():
        if len(e["cids"]) >= 2 and states.get(asn) != "cut" and not db_exec("SELECT 1 FROM journal WHERE asn=? AND kind='size_cut' AND ts>?", (asn, now - 3 * CUT_CHECK_WINDOW), one=True):
            _log(now, asn, "size_cut", states.get(asn), None, {"browsers": len(e["cids"]), "size": e["max"]})
    for asn, e in blips.items():
        if len(e["cids"]) < 2 or db_exec("SELECT 1 FROM journal WHERE asn=? AND kind='cut_check' AND ts>?", (asn, now - CUT_CHECK_WINDOW), one=True):
            continue
        _log(now, asn, "cut_check", states.get(asn), None,
             {"checks": e["n"], "browsers": len(e["cids"]), "dir": "+".join(sorted(e["dirs"])), "servers_replied": e["replied"]})


def _quiet_now(now=None):
    """Тихие часы 23:00-08:00 по Москве (UTC+3 без перевода часов): ночью оповещений не шлём."""
    hr = (time.gmtime(now or time.time()).tm_hour + 3) % 24
    return hr >= 23 or hr < 8


def ntfy_send(text):
    if not NTFY_TOPIC:
        return False
    try:
        req = urllib.request.Request("https://ntfy.sh/" + NTFY_TOPIC, data=text.encode("utf-8"), method="POST",
                                     headers={"X-Title": "udpcheck", "X-Priority": "4", "User-Agent": "udpcheck-hub"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 200
    except Exception:
        return False


def beat_watch(now):
    """Наблюдатель присылает сигнал жизни раз в минуту. Если он молчит больше 10 минут (и это не тихие часы), пишем сами через ntfy:
    так про упавшего наблюдателя мы узнаем, даже если Telegram недоступен."""
    if not (BEAT_SECRET and BEAT["last"]):
        return
    silent = now - BEAT["last"] > 600
    if silent and not BEAT["alerted"] and not _quiet_now(now):
        if ntfy_send("Наблюдатель за udpcheck молчит больше 10 минут: оповещения о серверах могут не приходить."):
            BEAT["alerted"] = True
    elif not silent and BEAT["alerted"]:
        if ntfy_send("Наблюдатель за udpcheck снова на связи."):
            BEAT["alerted"] = False


def _db_writable():
    """Хаб умеет писать в базу? (после переноса базы файл мог остаться у root, и все записи молча падали с ошибкой 500)"""
    try:
        db_exec("CREATE TABLE IF NOT EXISTS hubmeta(k TEXT PRIMARY KEY, v TEXT)")
        db_exec("INSERT OR REPLACE INTO hubmeta(k, v) VALUES('health', ?)", (str(int(time.time())),))
        return True
    except Exception:
        return False


def web_health(h, ip):
    """Состояние хаба для наблюдателя: свободное место и память, возраст последней копии, сколько серверов проекта активны."""
    ok, retry = rl_stats.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    now = time.time()
    try:
        du = shutil.disk_usage(os.path.dirname(HUB_DB) or "/")
        disk = int(du.free * 100 / max(1, du.total))
    except OSError:
        disk = None
    mem = None
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    mem = int(line.split()[1]) // 1024
    except (OSError, ValueError):
        pass
    bage = None
    try:
        with open(BACKUP_MARK) as fh:
            bage = int(now - int(fh.read().strip()))
    except (OSError, ValueError):
        pass
    alive = sum(1 for t in TARGETS if now - TARGET_SEEN.get(t["code"], 0) < 90)
    return h.send_json(200, {"ok": True, "db_ok": _db_writable(), "uptime_s": int(now - T0), "disk_free_pct": disk, "mem_avail_mb": mem, "backup_age_s": bage,
                             "anchors_online": alive, "anchors_total": len(TARGETS),
                             "watcher_beat_age_s": int(now - BEAT["last"]) if BEAT["last"] else None})


def web_beat(h, body):
    if not BEAT_SECRET or not hmac.compare_digest(h.headers.get("X-Beat", ""), BEAT_SECRET):
        return h.err(403, "неверный секрет")
    BEAT["last"] = time.time()
    return h.send_json(200, {"ok": True})


def _name_flags(name):
    """Что в названии провайдера выглядит подозрительно (для ежедневного разбора названий)."""
    f = []
    if re.fullmatch(r"AS\d+", name):
        f.append("название не нашлось, показан номер")
    if name.endswith("…"):
        f.append("название обрезано")
    elif len(name) > 30:
        f.append("длинное название")
    if any(len(w) >= 4 and w.isalpha() and w.isupper() for w in name.split()):
        f.append("осталось капсом")
    if re.search(r"[^\w\s.\-&()'+]", name):
        f.append("странные символы")
    return f


def names_review(h, method, body):
    """Для наблюдателя: новые (или переименованные) провайдеры, о которых ещё не сообщали, с пометками подозрительных названий.
    GET отдаёт список, POST {"asns": [...]} отмечает их как «сообщили» (после успешной отправки). Доступ по секрету наблюдателя."""
    if not BEAT_SECRET or not hmac.compare_digest(h.headers.get("X-Beat", ""), BEAT_SECRET):
        return h.err(403, "неверный секрет")
    now = int(time.time())
    if method == "POST":
        try:
            asns = [int(a) for a in (json.loads((body or b"{}").decode("utf-8")).get("asns") or [])[:500]]
        except (ValueError, TypeError, AttributeError):
            return h.err(400, "некорректный запрос")
        for a in asns:
            db_exec("INSERT OR REPLACE INTO namesrep(asn, name, ts) VALUES(?,?,?)", (a, provider_name(a), now))
        return h.send_json(200, {"ok": True, "marked": len(asns)})
    since = now - 14 * 86400
    asns = {a for (a,) in db_exec("SELECT DISTINCT asn FROM webchecks WHERE asn IS NOT NULL AND ts>=?", (since,), many=True)}
    asns |= {a for (a,) in db_exec("SELECT DISTINCT asn FROM rounds WHERE asn IS NOT NULL AND ts>=?", (since,), many=True)}
    done = {a: n for a, n in db_exec("SELECT asn, name FROM namesrep", many=True)}
    items = []
    for a in sorted(asns):
        name = provider_name(a)
        if done.get(a) == name:
            continue
        org = public_org(a, None)
        items.append({"asn": a, "name": name, "org": org, "kind": provider_kind(a, org, name), "flags": _name_flags(name), "group": len(group_members(a))})
    items.sort(key=lambda x: (not x["flags"], x["asn"]))
    return h.send_json(200, {"total": len(items), "items": items[:200]})


_site = {"mtime": 0, "build": ""}


def site_build():
    """Метка версии страницы (BUILD в index.html): открытая вкладка сверяет её и предлагает обновиться."""
    f = os.path.join(os.environ.get("UDPCHECK_SITE_DIR", "/var/www/udpcheck-site"), "index.html")
    try:
        mt = os.stat(f).st_mtime
        if mt != _site["mtime"]:
            m = re.search(r'var BUILD = "([^"]{1,40})"', open(f, encoding="utf-8").read())
            _site.update(mtime=mt, build=m.group(1) if m else "")
    except OSError:
        pass
    return _site["build"]


def journal_list(h, ip):
    """Публичный журнал: последние события по провайдерам (хостинги и VPN не показываем)."""
    ok, retry = rl_stats.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    ev = []
    for ts, asn, name, kind, old, new, info in db_exec("SELECT ts, asn, name, kind, old, new, info FROM journal ORDER BY ts DESC, id DESC LIMIT 300", many=True):
        org = db_exec("SELECT MAX(org) FROM webchecks WHERE asn=?", (asn,), one=True)[0]
        if provider_kind(asn, org, provider_name(asn, org)) == "hosting":
            continue
        try:
            inf = json.loads(info or "{}")
        except ValueError:
            inf = {}
        ev.append({"ts": ts, "asn": asn, "name": provider_name(asn, org), "kind": kind, "old": old, "new": new, "info": inf})
        if len(ev) >= 100:
            break
    return h.send_json(200, {"generated": int(time.time()), "events": ev})


_plist = {"t": 0, "data": None}


def providers_list(h, ip):
    """Карточки провайдеров: статус по последним 6 часам, мини-график доли «режется» по часам за сутки."""
    ok, retry = rl_stats.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    now = int(time.time())
    if _plist["data"] is not None and now - _plist["t"] < 20:          # список один для всех посетителей: пересчитываем не чаще раза в 20 с
        return h.send_json(200, _plist["data"])
    hour_now = now // 3600
    seen = {a: (n, last) for a, n, last in db_exec(
        "SELECT asn, COUNT(DISTINCT node_id), MAX(ts) FROM rounds WHERE ts>=? AND asn IS NOT NULL AND verdict != 'TUNNEL' GROUP BY asn",
        (now - 7 * 86400,), many=True)}
    for a, last in db_exec("SELECT asn, MAX(ts) FROM webchecks WHERE ts>=? AND asn IS NOT NULL GROUP BY asn", (now - 7 * 86400,), many=True):
        n0, l0 = seen.get(a, (0, 0))
        seen[a] = (n0, max(l0, last))
    by = {}
    for a, hr, v, c in db_exec("SELECT asn, ts/3600, verdict, COUNT(*) FROM rounds WHERE ts>=? AND asn IS NOT NULL AND verdict != 'TUNNEL' "
                               "GROUP BY asn, ts/3600, verdict", (now - 24 * 3600,), many=True):
        by.setdefault(a, []).append((hr, v, c))
    web24 = {}
    for a, hr, v, c in db_exec("SELECT asn, ts/3600, verdict, COUNT(DISTINCT COALESCE(cid, 'i' || id)) FROM webchecks WHERE ts>=? AND asn IS NOT NULL GROUP BY asn, ts/3600, verdict",
                               (now - 24 * 3600,), many=True):
        by.setdefault(a, []).append((hr, v, c))        # проверка посетителя считается как один замер
        web24[a] = web24.get(a, 0) + c
    r1h = {a: n for a, n in db_exec("SELECT asn, COUNT(*) FROM rounds WHERE ts>=? AND asn IS NOT NULL AND verdict != 'TUNNEL' GROUP BY asn",
                                    (now - 3600,), many=True)}
    for a, n in db_exec("SELECT asn, COUNT(DISTINCT COALESCE(cid, 'i' || id)) FROM webchecks WHERE ts>=? AND asn IS NOT NULL GROUP BY asn", (now - 3600,), many=True):
        r1h[a] = r1h.get(a, 0) + n
    nodes24 = {a: n for a, n in db_exec("SELECT asn, COUNT(DISTINCT node_id) FROM rounds WHERE ts>=? AND asn IS NOT NULL AND verdict != 'TUNNEL' GROUP BY asn",
                                        (now - 24 * 3600,), many=True)}
    orgs = {a: o for a, o in db_exec("SELECT asn, MAX(org) FROM webchecks WHERE asn IS NOT NULL AND org IS NOT NULL GROUP BY asn", many=True)}
    orgs.update({a: o for a, o in db_exec("SELECT asn, MAX(org) FROM nodes WHERE asn IS NOT NULL GROUP BY asn", many=True) if o})
    size = _size_scan(now - 24 * 3600)
    groups = {}
    for asn in seen:
        k, gname = provider_group(asn, orgs.get(asn))
        groups.setdefault(k, {"name": gname, "asns": []})["asns"].append(asn)
    out = []
    for k, g in groups.items():
        asns = g["asns"]
        rep_asn = max(asns, key=lambda a: (sum(c for _h, _v, c in by.get(a, [])), a))
        bk = _hour_buckets([x for a in asns for x in by.get(a, [])], hour_now, 24)
        r24 = sum(b["cut"] + b["ok"] + b["bad"] + b["na"] for b in bk)
        st, old = status_from(bk)
        series = [round(b["cut"] / (b["cut"] + b["ok"]), 2) if (b["cut"] + b["ok"]) > 0 else None for b in bk]
        last = max(seen[a][1] for a in asns)
        org = public_org(rep_asn, orgs.get(rep_asn))
        sz = _size_sum(size, asns)
        out.append({"asn": rep_asn, "name": g["name"], "org": org, "status": st, "asns": sorted(asns) if len(asns) > 1 else None,
                    "weak": int(r24) < 5, "nodes": sum(nodes24.get(a, 0) for a in asns), "rounds_1h": sum(r1h.get(a, 0) for a in asns),
                    "rounds_24h": int(r24), "web_24h": sum(web24.get(a, 0) for a in asns),
                    "logo": provider_logo(rep_asn), "series": series, "last_age": now - last, "old": old,
                    "size_cut": bool(sz["browsers"] >= 2 and sz["cut"] * 2 >= sz["tested"]),
                    "kind": provider_kind(rep_asn, orgs.get(rep_asn), g["name"]),
                    "search": " ".join([g["name"], org or ""] + ["as%d" % a for a in asns] + [provider_name(a) for a in asns]).lower()})
    order = {"cut": 0, "partial": 1, "ok": 2, "noanchor": 3, "stale": 4}
    out.sort(key=lambda p: (order.get(p["status"], 9), -p["rounds_24h"]))
    _plist.update(t=now, data={"generated": now, "providers": out})
    return h.send_json(200, _plist["data"])


def provider_detail(h, ip, asn):
    """Страница провайдера: график по часам за 7 суток, итоги по серверам, TCP, где замолкают маршруты, узлы сети. Сети одного оператора сведены вместе."""
    ok, retry = rl_stats.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    now = int(time.time())
    hour_now = now // 3600
    asns = group_members(asn)
    ph = ",".join("?" * len(asns))
    A = tuple(asns)
    f1 = db_exec("SELECT MIN(ts), MAX(ts), COUNT(*) FROM rounds WHERE asn IN (%s) AND verdict != 'TUNNEL'" % ph, A, one=True)
    f2 = db_exec("SELECT MIN(ts), MAX(ts), COUNT(*) FROM webchecks WHERE asn IN (%s)" % ph, A, one=True)
    if not (f1[2] or f2[2]):
        return h.err(404, "по этой сети данных нет")
    first = (min(x for x in (f1[0], f2[0]) if x), max(x for x in (f1[1], f2[1]) if x), f1[2] + f2[2])
    rows = db_exec("SELECT ts/3600, verdict, COUNT(*) FROM rounds WHERE asn IN (%s) AND ts>=? AND verdict != 'TUNNEL' GROUP BY ts/3600, verdict" % ph,
                   A + (now - 168 * 3600,), many=True)
    rows += db_exec("SELECT ts/3600, verdict, COUNT(DISTINCT COALESCE(cid, 'i' || id)) FROM webchecks WHERE asn IN (%s) AND ts>=? GROUP BY ts/3600, verdict" % ph,
                    A + (now - 168 * 3600,), many=True)
    bk = _hour_buckets(rows, hour_now, 168)
    st, old = status_from(bk)
    day = bk[-24:]
    verdicts = {v: n for v, n in db_exec("SELECT verdict, COUNT(*) FROM rounds WHERE asn IN (%s) AND ts>=? AND verdict != 'TUNNEL' GROUP BY verdict" % ph,
                                         A + (now - 86400,), many=True)}
    targets = {}
    for tgt, kind, status, tcp, n in db_exec("SELECT target, kind, status, tcp, COUNT(*) FROM tres WHERE asn IN (%s) AND ts>=? AND target NOT LIKE 'REF-%%' "
                                             "GROUP BY target, kind, status, tcp" % ph, A + (now - 86400,), many=True):
        kind = "foreign" if kind == "foreign" else "home"
        e = targets.setdefault(tgt, {"code": tgt, "kind": kind, "name": next((t["name"] for t in TARGETS if t["code"] == tgt), tgt),
                                     "status": {}, "tcp_ok": 0, "tcp_total": 0})
        e["status"][status] = e["status"].get(status, 0) + n
        if tcp != "NA":
            e["tcp_total"] += n
            e["tcp_ok"] += n if tcp == "OK" else 0
    cuts = {"home": [], "foreign": []}
    for kind, last_asn, org, n in db_exec("SELECT kind, last_asn, MAX(last_org), COUNT(*) FROM traces WHERE ts>=? AND method='icmp' AND asn IN (%s) "
                                          "AND last_asn IS NOT NULL GROUP BY kind, last_asn" % ph, (now - 7 * 86400,) + A, many=True):
        cuts.setdefault("foreign" if kind == "foreign" else "home", []).append({"asn": last_asn, "org": org, "n": n})
    for k in cuts:
        cuts[k] = sorted(cuts[k], key=lambda x: -x["n"])[:5]
    web = {v: n for v, n in db_exec("SELECT verdict, COUNT(DISTINCT COALESCE(cid, 'i' || id)) FROM webchecks WHERE asn IN (%s) AND ts>=? GROUP BY verdict" % ph,
                                    A + (now - 86400,), many=True)}
    for v, n in web.items():
        verdicts[v] = verdicts.get(v, 0) + n
    nodes = [{"callsign": c, "online": now - (ls or 0) < 120, "os": "Windows" if "Windows" in (cl or "") else ("macOS" if "Darwin" in (cl or "") else "Linux")}
             for c, ls, cl in db_exec("SELECT callsign, last_seen, client FROM nodes WHERE asn IN (%s) AND last_seen>=? AND COALESCE(role, 'node') != 'ref' "
                                      "ORDER BY last_seen DESC LIMIT 30" % ph, A + (now - NODE_VISIBLE_DAYS * 86400,), many=True)]
    org, pcountry = db_exec("SELECT MAX(org), MAX(country) FROM nodes WHERE asn=?", (asn,), one=True)
    org = org or db_exec("SELECT MAX(org) FROM webchecks WHERE asn=?", (asn,), one=True)[0]
    nn = db_exec("SELECT COUNT(DISTINCT node_id) FROM rounds WHERE asn IN (%s) AND ts>=? AND verdict != 'TUNNEL'" % ph, A + (now - 86400,), one=True)[0]
    r24 = sum(b["cut"] + b["ok"] + b["bad"] + b["na"] for b in day)
    name = provider_name(asn, org)
    sz = _size_sum(_size_scan(now - 86400, asn=set(asns)), asns)
    return h.send_json(200, {
        "asn": asn, "asns": asns if len(asns) > 1 else None, "name": name, "org": public_org(asn, org), "country": pcountry, "status": st, "old": old,
        "kind": provider_kind(asn, org, name), "weak": int(r24) < 5, "nodes": nn, "web_24h": sum(web.values()), "logo": provider_logo(asn),
        "rounds_1h": int(sum(b["cut"] + b["ok"] + b["bad"] + b["na"] for b in bk[-1:])), "rounds_24h": int(r24), "rounds_7d": int(sum(b["cut"] + b["ok"] + b["bad"] + b["na"] for b in bk)),
        "first_seen": first[0], "last_age": now - first[1], "hour_now": hour_now * 3600,
        "series": [[round(b["cut"], 1), round(b["ok"], 1), b["bad"] + b["na"]] for b in bk],     # по часам, самый старый первым
        "verdicts": verdicts, "targets": sorted(targets.values(), key=lambda t: (t["kind"] != "home", t["code"])), "cuts": cuts,
        "web": web, "node_list": nodes, "size": {"tested": sz["tested"], "cut": sz["cut"], "max": sz["max"]},
        "journal": [{"ts": t, "kind": k, "old": o, "new": n, "info": json.loads(i or "{}")} for t, k, o, n, i in db_exec(
            "SELECT ts, kind, old, new, info FROM journal WHERE asn IN (%s) ORDER BY ts DESC, id DESC LIMIT 15" % ph, A, many=True)]})


def stats_asn(h, ip, asn, hours):
    ok, retry = rl_stats.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    since = int(time.time()) - hours * 3600
    buckets = {}
    for hr, v, n in db_exec("SELECT (ts/3600)*3600, verdict, COUNT(*) FROM rounds WHERE asn=? AND ts>=? AND verdict != 'TUNNEL' GROUP BY 1, 2", (asn, since), many=True):
        buckets.setdefault(hr, {"hour": hr, "rounds": 0, "verdicts": {}})
        buckets[hr]["verdicts"][v] = n
        buckets[hr]["rounds"] += n
    return h.send_json(200, {"asn": asn, "window_hours": hours, "buckets": [buckets[k] for k in sorted(buckets)]})


# ---------------------------------------------------------------- страница на сайте: трассировка до посетителя
def _target_auth(h, body):
    tgt = h.headers.get("X-Target", "")
    cfg = next((t for t in TARGETS if t["code"] == tgt), None)
    if cfg is None or not body:
        return None
    if not hmac.compare_digest(hmac.new(cfg["secret"], body, hashlib.sha256).hexdigest(), h.headers.get("X-Auth", "")):
        return None
    return cfg


def target_poll(h, body):
    cfg = _target_auth(h, body)
    if cfg is None:
        return h.err(403, "неверная подпись")
    TARGET_SEEN[cfg["code"]] = time.time()
    try:
        req = json.loads(body.decode("utf-8"))
        if abs(int(req.get("ts", 0)) - time.time()) > 180:
            return h.err(403, "устаревший запрос")
        acks = {str(x) for x in (req.get("ack") or [])[:400]}
        pad = {int(p): max(100, min(int(n), 1400)) for p, n in list((req.get("pad") or {}).items())[:4]}
    except (ValueError, TypeError, AttributeError):
        return h.err(400, "некорректный запрос")
    code = cfg["code"]
    TARGET_PAD[code] = pad
    deadline = time.time() + 20
    with HLOCK:
        for jid in acks:                                   # цель подтверждает, что получила задание в прошлом ответе
            for store in (WTRACES, SEEN, PADS):
                w = store.get(jid)
                if w is not None and code in w["sent"]:
                    w["sent"][code][1] = True
                    if store is PADS:
                        w["targets"][code] = True              # подтверждение и есть выполнение: цель уже разрешила посетителя
    while True:
        jobs = []
        now = time.time()
        with HLOCK:
            for store, kind in ((WTRACES, None), (SEEN, "stun"), (PADS, "pad")):
                for jid, w in store.items():
                    sent = w["sent"].get(code)
                    # не подтверждённое задание выдаём снова (ответ мог уйти в оборванное соединение, например при перезапуске цели)
                    if code in w["targets"] and w["targets"][code] is None and (sent is None or (not sent[1] and now - sent[0] > 2)):
                        w["sent"][code] = [now, False]
                        job = {"id": jid, "ip": w["ip"]}
                        if kind:
                            job["kind"] = kind
                        jobs.append(job)
        if jobs or time.time() >= deadline:
            return h.send_json(200, {"jobs": jobs})
        time.sleep(0.5)


def _enrich_hops(hops):
    """Сети (ASN) по адресам хопов определяет хаб своей базой: серверам-целям GeoIP не нужен (они присылают сырую трассировку).
    В AS-путь берём первый адрес хопа и склеиваем подряд идущие хопы одной сети."""
    as_path = []
    for hp in hops:
        infos = [(S.GEO.lookup(a) or {}) for a in hp["addrs"]]
        hp["asns"] = [i.get("asn") for i in infos]
        hp["orgs"] = [str(i["org"])[:60] if i.get("org") else None for i in infos]
        first = infos[0] if infos else {}
        if first.get("asn"):
            if as_path and as_path[-1]["asn"] == first["asn"]:
                as_path[-1]["last_ttl"] = hp["ttl"]
            else:
                as_path.append({"asn": int(first["asn"]), "org": str(first.get("org") or "")[:60], "first_ttl": hp["ttl"], "last_ttl": hp["ttl"]})
    return as_path


def _clip_trace(r, skip_asn=None):
    """Оставляем только нужные поля и ограничиваем размер (цели свои, но хаб ничему не верит вслепую)."""
    out = {}
    for m in ("icmp", "udp", "tcp"):
        v = r.get(m) if isinstance(r, dict) else None
        if not isinstance(v, dict):
            continue
        hops = []
        for hp in (v.get("hops") or [])[:30]:
            if isinstance(hp, dict):
                hops.append({"ttl": int(hp.get("ttl", 0)), "addrs": [str(a)[:45] for a in (hp.get("addrs") or [])[:3]],
                             "rtt_ms": [float(x) for x in (hp.get("rtt_ms") or [])[:3]], "lost": int(hp.get("lost", 0)),
                             "asns": [], "orgs": []})
        as_path = _enrich_hops(hops)
        if skip_asn:                                 # собственную сеть опорного сервера не показываем: хостинг не светим
            as_path = [a for a in as_path if a["asn"] != skip_asn]
        as_path = as_path[:20]          # сети определяем сами, то, что прислала цель, игнорируем
        out[m] = {"ok": bool(v.get("ok")), "reached": bool(v.get("reached")), "last_responding_ttl": int(v.get("last_responding_ttl", 0)),
                  "silent_tail_hops": int(v.get("silent_tail_hops", 0)), "as_path": as_path, "hops": hops}
    return out


def target_trace_result(h, body):
    cfg = _target_auth(h, body)
    if cfg is None:
        return h.err(403, "неверная подпись")
    try:
        req = json.loads(body.decode("utf-8"))
        wid = str(req["id"])
    except (ValueError, KeyError):
        return h.err(400, "некорректный результат")
    rows = []
    with HLOCK:
        w = WTRACES.get(wid)
        if w is not None and cfg["code"] in w["targets"] and w["targets"][cfg["code"]] is None:
            clipped = _clip_trace(req.get("results"), (S.GEO.lookup(cfg["ip"], force=True) or {}).get("asn"))
            w["targets"][cfg["code"]] = clipped
            for m, v in clipped.items():
                ap = v.get("as_path") or []
                last = ap[-1] if ap else None
                rows.append((int(time.time()), w.get("asn"), w.get("org"), w.get("src", "web"), cfg["code"], _kind_rel(cfg.get("country"), w.get("country")), m,
                             last["asn"] if last else None, last["org"] if last else None, v.get("last_responding_ttl"),
                             1 if v.get("reached") else 0, json.dumps([a["asn"] for a in ap])))
    if rows:
        with DBL:
            for r in rows:
                DB.execute("INSERT INTO traces(ts, asn, src_org, src, target, kind, method, last_asn, last_org, last_ttl, reached, path) "
                           "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", r)
            DB.commit()
    return h.send_json(200, {"ok": True})


def target_stun_result(h, body):
    cfg = _target_auth(h, body)
    if cfg is None:
        return h.err(403, "неверная подпись")
    try:
        req = json.loads(body.decode("utf-8"))
        sid = str(req["id"])
        clean = {int(p): max(0, min(int(n), 1000)) for p, n in list((req.get("seen") or {}).items())[:8]}
        replied = ({int(p): max(0, min(int(n), 1000)) for p, n in list((req.get("replied") or {}).items())[:8]}
                   if "replied" in req else None)        # старые версии не присылали число отправленных ответов
    except (ValueError, KeyError, TypeError, AttributeError):
        return h.err(400, "некорректный результат")
    with HLOCK:
        w = SEEN.get(sid)
        if w is not None and cfg["code"] in w["targets"] and w["targets"][cfg["code"]] is None:
            w["targets"][cfg["code"]] = {"seen": clean, "replied": replied}
    return h.send_json(200, {"ok": True})


def web_stunseen_start(h, ip):
    """Браузер просит серверы сказать, сколько его STUN-запросов они получили (адрес посетителя получают только наши серверы)."""
    ok, retry = rl_seen_ip.allow(ip)
    if ok:
        ok, retry = rl_seen.allow("%s|%s" % (_cid(h) or "-", ip))
    if not ok:
        return h.err(429, "слишком часто", retry)
    if not TARGETS:
        return h.err(503, "серверы не настроены")
    sid = secrets.token_hex(8)
    with HLOCK:
        if len(SEEN) >= 3000:
            return h.err(503, "сервер занят, повторите позже", 30)
        SEEN[sid] = {"ip": ip, "created": time.time(), "targets": {t["code"]: None for t in TARGETS}, "sent": {}}
    return h.send_json(202, {"id": sid})


def web_stunseen_get(h, ip, sid):
    ok, retry = rl_web.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    with HLOCK:
        w = SEEN.get(sid)
        if w is None or w["ip"] != ip:
            return h.err(404, "задание не найдено")
        res = {c: (None if v is None else sum(v["seen"].values())) for c, v in w["targets"].items()}
        rep = {c: (None if v is None or v["replied"] is None else sum(v["replied"].values())) for c, v in w["targets"].items()}
        done = all(v is not None for v in w["targets"].values()) or time.time() - w["created"] > 12
        if done:
            if len(SEEN_DONE) > 5000:
                SEEN_DONE.clear()
            SEEN_DONE[ip] = (time.time(), dict(res), dict(rep))
    return h.send_json(200, {"done": done, "seen": res, "replied": rep})


def web_ip(h, ip):
    ok, retry = rl_stats.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    return h.send_json(200, {"ip": ip})      # посетителю про его же адрес; установщик по нему определяет, публичный ли у машины IP


WEB_VERDICTS = ("NO_BLOCK", "FOREIGN_IN_CUT", "FOREIGN_OUT_CUT", "FOREIGN_PARTIAL", "CONTROL_BAD", "NO_ANCHOR")
STUN_PORTS = [777, 47321]   # 993 не берём: Chrome считает его «небезопасным» портом


VOL_EXPLORE = float(os.environ.get("UDPCHECK_VOL_EXPLORE", "0.05"))      # доля показов серверам добровольцев, которых посетители почти не достают
VOL_CACHE_S = float(os.environ.get("UDPCHECK_VOL_CACHE", "60"))
_vol_health = {"t": 0, "d": {}}


def _vol_stats():
    """Как серверы добровольцев отвечали посетителям за сутки: код -> [проверок, ответил]. Раз в минуту, из принятых проверок."""
    now = time.time()
    if now - _vol_health["t"] < VOL_CACHE_S:
        return _vol_health["d"]
    d = {}
    for (data,) in db_exec("SELECT data FROM webchecks WHERE ts>=?", (int(now) - 86400,), many=True):
        try:
            for r in json.loads(data):
                code = str(r.get("code", ""))
                if code.startswith("REF-"):
                    e = d.setdefault(code, [0, 0])
                    e[0] += 1
                    e[1] += 1 if int(r.get("ok", 0)) >= 0.8 * int(r.get("n", 1) or 1) else 0
        except (ValueError, TypeError, AttributeError):
            continue
    _vol_health.update(t=now, d=d)
    return d


def _community_for_browser(ip, vasn, vc):
    """До двух проверенных серверов добровольцев (на связи, не из сети посетителя, лучше у других хостеров, чем наши) попадают в проверку
    посетителя как НЕЗАВИСИМЫЕ СВИДЕТЕЛИ: они могут смягчить вывод («режется» -> «выборочно»), но обвинить провайдера сами не могут.
    Если в стране посетителя нет серверов проекта, сервер добровольца из этой страны становится контролем «своя страна»."""
    rows = db_exec(REF_SELECT + "WHERE r.verified = 1 AND n.last_seen >= ?", (int(time.time()) - 180,), many=True)
    ours_asn = set()
    for t in TARGETS:
        a = (S.GEO.lookup(t["ip"], force=True) or {}).get("asn")
        if a:
            ours_asn.add(a)
    home_project = any(t.get("country") and t["country"] == vc for t in TARGETS)
    cand = [r for r in rows if r[3] != ip and not (vasn and r[8] == vasn)]
    hs = _vol_stats()
    # сервер, до которого почти никто из посетителей не достаёт (например, адрес VPN в списках блокировок), не показываем, лишь изредка проверяем заново
    cand = [r for r in cand if not (hs.get("REF-%d" % r[0], [0, 0])[0] >= 6 and hs["REF-%d" % r[0]][1] < 0.1 * hs["REF-%d" % r[0]][0])
            or random.random() < VOL_EXPLORE]
    random.shuffle(cand)
    cand.sort(key=lambda r: (r[8] in ours_asn))        # сначала те, кто не у наших хостеров
    out = []
    for r in cand[:2]:
        kind = _kind_rel(r[9], vc)
        out.append({"code": "REF-%d" % r[0], "kind": kind, "name": "сервер добровольца", "country": r[9], "community": True,
                    "control": bool(kind == "home" and not home_project), "ip": r[3], "ports": json.loads(r[4])[:2]})
    return out


def web_stun(h, ip):
    """Список целей для UDP-проверки из браузера (WebRTC/STUN): адрес и порты, больше ничего."""
    ok, retry = rl_web.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    vasn, _org, vc, _city = _geo_of(ip)
    targets = [{"code": t["code"], "kind": _kind_rel(t.get("country"), vc), "name": t["name"], "ip": t["ip"],
                "ports": [p for p in t["ports"] if p in STUN_PORTS]} for t in TARGETS]
    if ip and any(TARGET_PAD.get(t["code"]) for t in TARGETS):
        # просим серверы разрешить этому посетителю длинные ответы и ждём подтверждения (адрес подтверждён: он пришёл к нам по TCP)
        jid = secrets.token_hex(8)
        want = [t["code"] for t in TARGETS if TARGET_PAD.get(t["code"])]
        with HLOCK:
            if len(PADS) < 3000:
                PADS[jid] = {"ip": ip, "created": time.time(), "targets": {c: None for c in want}, "sent": {}}
        end = time.time() + 3.5
        while jid in PADS and time.time() < end:
            with HLOCK:
                if all(PADS[jid]["targets"].values()):
                    break
            time.sleep(0.15)
        with HLOCK:
            acked = {c for c, v in (PADS.get(jid) or {"targets": {}})["targets"].items() if v}
        for t in targets:
            if t["code"] in acked:
                t["pad"] = [{"port": p, "size": n} for p, n in sorted(TARGET_PAD.get(t["code"], {}).items())]
    try:
        targets += _community_for_browser(ip, vasn, vc)
    except Exception:
        pass
    return h.send_json(200, {"country": vc, "targets": targets, "attempts": 3})


def _cid(h):
    """Случайный номер браузера (страница создаёт его сама и хранит у себя): не отпечаток и не связан с личностью.
    В базе храним только его хэш."""
    c = h.headers.get("X-Client", "")
    return hashlib.sha256(c.encode()).hexdigest()[:16] if re.fullmatch(r"[0-9a-f]{32}", c) else None


def web_report(h, ip, body):
    """Итог браузерной проверки (только счётчики ответов, без адресов). Лимит: 6 в час на пару «номер браузера + IP», 60 в час на IP.
    В статистику идёт только проверка, которую посетитель прошёл через наши серверы (они подтвердили приём его запросов), и если
    число ответов не противоречит тому, что серверы видели."""
    cid = _cid(h)
    ok, retry = rl_webrep_ip.allow(ip or "local")
    if ok:
        ok, retry = rl_webrep.allow("%s|%s" % (cid or "-", ip or "local"))
    if not ok:
        return h.err(429, "результат этого часа уже передан в статистику", retry)
    try:
        req = json.loads(body.decode("utf-8"))
        verdict = str(req["verdict"])
        results = req["results"]
        if verdict not in WEB_VERDICTS or not isinstance(results, list) or len(results) > 24:
            raise ValueError
        clean = [{"code": str(r["code"])[:24], "ok": max(0, min(int(r["ok"]), 30)), "n": max(1, min(int(r["n"]), 30)),
                  "seen": max(-1, min(int(r.get("seen", -1)), 1000))} for r in results]
        for r, c in zip(results, clean):          # итоги по длинным ответам: [[длина, дошло, попыток], ...]
            if isinstance(r.get("pad"), list):
                c["pad"] = [[max(0, min(int(x[0]), 1500)), max(0, min(int(x[1]), 30)), max(1, min(int(x[2]), 30))] for x in r["pad"][:4]]
    except (ValueError, KeyError, TypeError):
        return h.err(400, "некорректный результат")
    done = SEEN_DONE.get(ip)
    counted = bool(done and time.time() - done[0] < 600)
    if counted:
        for r in clean:
            hub_seen = done[1].get(r["code"])
            if hub_seen == 0 and r["ok"] > 0:        # ответы не могли прийти на запросы, которых сервер не получал
                counted = False
            r["seen"] = -1 if hub_seen is None else hub_seen
            hub_rep = done[2].get(r["code"]) if len(done) > 2 else None
            r["replied"] = -1 if hub_rep is None else hub_rep
    if not counted:
        return h.send_json(200, {"ok": True, "counted": False})
    g = (S.GEO.lookup(ip) or {}) if ip else {}
    db_exec("INSERT INTO webchecks(ts, asn, verdict, data, org, cid) VALUES(?,?,?,?,?,?)",
            (int(time.time()), g.get("asn"), verdict, json.dumps(clean), g.get("org"), cid))
    return h.send_json(200, {"ok": True, "counted": True})


def web_me(h, ip):
    ok, retry = rl_web.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    g = S.GEO.lookup(ip) if ip else {}
    vcountry = _geo_of(ip)[2] if ip else None
    home_n = sum(1 for t in TARGETS if vcountry and t.get("country") == vcountry)
    home_c = db_exec("SELECT COUNT(*) FROM refs r JOIN nodes n ON n.id = r.node_id WHERE r.verified = 1 AND r.country = ? AND n.last_seen >= ?",
                     (vcountry, int(time.time()) - 180), one=True)[0] if vcountry else 0
    out = {"you": {"asn": g.get("asn"), "org": g.get("org"), "country": vcountry, "city": city_ru(vcountry, g.get("city")), "city_en": g.get("city")},
           "home": {"anchors": home_n, "community": home_c},      # опорные серверы в стране посетителя: проекта и участников
           "attribution": S.GEO_ATTRIBUTION, "network": None}
    asn = g.get("asn")
    if asn:
        since = int(time.time()) - 24 * 3600
        nodes, rounds = db_exec("SELECT COUNT(DISTINCT node_id), COUNT(*) FROM rounds WHERE asn=? AND ts>=? AND verdict != 'TUNNEL'", (asn, since), one=True)
        verdicts = {v: n for v, n in db_exec("SELECT verdict, COUNT(*) FROM rounds WHERE asn=? AND ts>=? AND verdict != 'TUNNEL' GROUP BY verdict", (asn, since), many=True)}
        last = db_exec("SELECT ts, verdict FROM rounds WHERE asn=? AND verdict != 'TUNNEL' ORDER BY ts DESC LIMIT 1", (asn,), one=True)
        web = {v: n for v, n in db_exec("SELECT verdict, COUNT(DISTINCT COALESCE(cid, 'i' || id)) FROM webchecks WHERE asn=? AND ts>=? GROUP BY verdict", (asn, since), many=True)}
        tcp = {st: n for st, n in db_exec("SELECT tcp, COUNT(*) FROM tres WHERE asn=? AND ts>=? AND kind='foreign' AND target NOT LIKE 'REF-%' "
                                          "AND tcp != 'NA' GROUP BY tcp", (asn, since), many=True)}
        out["network"] = {"window_hours": 24, "nodes": nodes, "rounds": rounds, "verdicts": verdicts, "web": web,
                          "tcp_foreign": {"ok": tcp.get("OK", 0), "total": sum(tcp.values())},   # TCP до зарубежных серверов с узлов этой сети
                          "last": {"age_s": int(time.time()) - last[0], "verdict": last[1]} if last else None}
    return h.send_json(200, out)


def web_trace_start(h, ip):
    if not (S.is_public(ip) or S.ALLOW_NON_GLOBAL):
        return h.err(400, "трассировка возможна только до публичного адреса")
    cid = _cid(h)
    ok, retry = rl_wtrace_ip.allow(ip)
    if ok:
        ok, retry = rl_wtrace.allow(("c:" + cid) if cid else ("i:" + ip))
    if not ok:
        return h.err(429, "трассировку можно запускать раз в 5 минут", retry)
    if not rl_trace_all.allow("all")[0]:
        return h.err(503, "сервис сейчас занят, повторите через несколько минут", 120)
    if not TARGETS:
        return h.err(503, "цели не настроены")
    wid = secrets.token_hex(8)
    with HLOCK:
        if len(WTRACES) >= 200:
            return h.err(503, "сервер занят, повторите позже", 30)
        g = S.GEO.lookup(ip) or {}
        WTRACES[wid] = {"ip": ip, "asn": g.get("asn"), "org": g.get("org"), "src": "web", "country": _geo_of(ip)[2], "created": time.time(),
                        "targets": {t["code"]: None for t in TARGETS}, "sent": {}}
    vc = _geo_of(ip)[2]
    return h.send_json(202, {"id": wid, "targets": [{"code": t["code"], "kind": _kind_rel(t.get("country"), vc), "name": t["name"]} for t in TARGETS]})


def web_trace_get(h, ip, wid):
    ok, retry = rl_web.allow(ip or "local")
    if not ok:
        return h.err(429, "слишком часто", retry)
    with HLOCK:
        w = WTRACES.get(wid)
        if w is None or w["ip"] != ip:
            return h.err(404, "задание не найдено")
        age = time.time() - w["created"]
        tl = []
        for t in TARGETS:
            res = w["targets"].get(t["code"])
            tl.append({"code": t["code"], "kind": _kind_rel(t.get("country"), w.get("country")), "name": t["name"],
                       "status": "done" if res is not None else ("timeout" if age > 60 else "pending"),
                       "results": res if res is not None else {}})
    return h.send_json(200, {"done": all(x["status"] != "pending" for x in tl), "targets": tl})


# ---------------------------------------------------------------- маршрутизация
def dispatch(h, method, path):
    """Все /api/v2/... (хаб). Возвращает True, если обработал."""
    if not HUB_ENABLED:
        return h.err(404, "хаб не включён")
    ip = h.client_ip()
    if path == "/api/v2/target/report" and method == "POST":
        body = h.read_body(65536)
        if body is None:
            return h.err(413, "слишком большое тело")
        return target_report(h, body)
    if path == "/api/v2/target/poll" and method == "POST":
        body = h.read_body(4096)
        return target_poll(h, body) if body is not None else h.err(413, "слишком большое тело")
    if path == "/api/v2/target/stun-result" and method == "POST":
        body = h.read_body(8192)
        return target_stun_result(h, body) if body is not None else h.err(413, "слишком большое тело")
    if path == "/api/v2/target/trace-result" and method == "POST":
        body = h.read_body(262144)
        return target_trace_result(h, body) if body is not None else h.err(413, "слишком большое тело")
    if ip is None:
        return h.err(400, "не удалось определить адрес клиента")
    if path == "/api/v2/web/stun" and method == "GET":
        return web_stun(h, ip)
    if path == "/api/v2/web/report" and method == "POST":
        body = h.read_body(8192)
        return web_report(h, ip, body) if body is not None else h.err(413, "слишком большое тело")
    if path == "/api/v2/ip" and method == "GET":
        return web_ip(h, ip)
    if path == "/api/v2/web/stunseen" and method == "POST":
        h.read_body(1024)
        return web_stunseen_start(h, ip)
    m = re.fullmatch(r"/api/v2/web/stunseen/([0-9a-f]{16})", path)
    if m and method == "GET":
        return web_stunseen_get(h, ip, m.group(1))
    if path == "/api/v2/web/me" and method == "GET":
        return web_me(h, ip)
    if path == "/api/v2/web/trace" and method == "POST":
        h.read_body(4096)
        return web_trace_start(h, ip)
    m = re.fullmatch(r"/api/v2/web/trace/([0-9a-f]{16})", path)
    if m and method == "GET":
        return web_trace_get(h, ip, m.group(1))
    if path == "/api/v2/node/register" and method == "POST":
        body = h.read_body(4096)
        if body is None:
            return h.err(413, "слишком большое тело")
        return node_register(h, ip, body)
    if path == "/api/v2/node/poll" and method == "POST":
        body = h.read_body(4096)
        return node_poll(h, ip, body or b"")
    if path == "/api/v2/node/ref" and method == "POST":
        body = h.read_body(4096)
        return node_ref(h, ip, body) if body is not None else h.err(413, "слишком большое тело")
    if path == "/api/v2/node/probe-now" and method == "POST":
        h.read_body(4096)
        return node_probe_now(h, ip)
    if path == "/api/v2/node/result" and method == "POST":
        body = h.read_body(262144)
        if body is None:
            return h.err(413, "слишком большое тело")
        return node_result(h, ip, body)
    if path == "/api/v2/stats" and method == "GET":
        q = re.search(r"hours=(\d+)", h.path)
        return stats_overview(h, ip, max(1, min(int(q.group(1)) if q else 24, 24 * 60)))
    if path == "/api/v2/nodes" and method == "GET":
        return nodes_public(h, ip)
    if path == "/api/v2/health" and method == "GET":
        return web_health(h, ip)
    if path == "/api/v2/health/beat" and method == "POST":
        body = h.read_body(1024)
        return web_beat(h, body)
    if path == "/api/v2/names/review" and method in ("GET", "POST"):
        return names_review(h, method, h.read_body(8192) if method == "POST" else None)
    if path == "/api/v2/version" and method == "GET":
        return h.send_json(200, {"site": site_build()})
    if path == "/api/v2/journal" and method == "GET":
        return journal_list(h, ip)
    if path == "/api/v2/providers" and method == "GET":
        return providers_list(h, ip)
    m = re.fullmatch(r"/api/v2/providers/(\d{1,10})", path)
    if m and method == "GET":
        return provider_detail(h, ip, int(m.group(1)))
    if path == "/api/v2/stats/paths" and method == "GET":
        q = re.search(r"hours=(\d+)", h.path)
        return stats_paths(h, ip, max(1, min(int(q.group(1)) if q else 168, 24 * 60)))
    m = re.fullmatch(r"/api/v2/stats/asn/(\d+)", path)
    if m and method == "GET":
        q = re.search(r"hours=(\d+)", h.path)
        return stats_asn(h, ip, int(m.group(1)), max(1, min(int(q.group(1)) if q else 24, 24 * 60)))
    return h.err(404, "не найдено")
