#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""udpcheck-server: STUN-ответы, подписанное UDP-эхо цели и трассировка до посетителя (роли «хаб» и «опорный сервер» проекта).

Один файл, только стандартная библиотека, Python 3.10+. Рядом лежит udpcheck_v2.py (хаб и роль цели).

Что делает:
  * Отвечает на STUN-запросы (браузерная проверка): обычные и длинные (отдельные порты, только тем, кого разрешил хаб).
  * Подписанное UDP-эхо для узлов (v2): см. udpcheck_v2.target_udp.
  * Трассировка (ICMP, UDP, TCP) ТОЛЬКО до адреса посетителя, по заданию хаба.
  * Поддерживает базу GeoIP (DB-IP) и справочник городов (на хабе).

Чего не делает: ничего не пишет в журналы. Всё состояние (счётчики, лимиты, разрешения) живёт в памяти процесса и стирается по таймеру
или при перезапуске. Первая версия API (/api/v1: сессии, эхо с номерами пакетов, blob/sink, трассировка по запросу) удалена; остался только
/api/v1/health для проверки «жив ли процесс».

Настройки берутся из переменных окружения (см. блок НАСТРОЙКИ).
"""

import ipaddress
import json
import mmap
import os
import re
import selectors
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

VERSION = "0.1"


# ---------------------------------------------------------------- НАСТРОЙКИ
def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_list(name, default):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


HTTP_BIND = os.environ.get("UDPCHECK_HTTP_BIND", "127.0.0.1")
HTTP_PORT = _env_int("UDPCHECK_HTTP_PORT", 18080)
UDP_BIND = os.environ.get("UDPCHECK_UDP_BIND", "0.0.0.0")
UDP_PORTS = [int(p) for p in _env_list("UDPCHECK_UDP_PORTS", "993,777,47321")]
PAD_PORTS = {}      # дополнительные STUN-порты для проверки длины пакета: порт -> длина UDP-ответа в байтах («3478:600,19302:1200»)
for _it in _env_list("UDPCHECK_PAD_PORTS", "3478:600,19302:1200"):
    try:
        _pp, _pn = _it.split(":")
        PAD_PORTS[int(_pp)] = max(100, min(int(_pn), 1400))
    except ValueError:
        pass
PAD_BOUND = {}      # порты, которые удалось занять: порт -> длина ответа
PREFIX = os.environ.get("UDPCHECK_PREFIX", "/udpcheck")
# Заголовку X-Forwarded-For верим только от этих адресов (Caddy на этой же машине).
TRUSTED_PROXIES = set(_env_list("UDPCHECK_TRUSTED_PROXIES", "127.0.0.1,::1"))
# Только для локальных тестов: разрешить трассировку до непубличных адресов.
ALLOW_NON_GLOBAL = os.environ.get("UDPCHECK_ALLOW_NON_GLOBAL") == "1"
# Только для локальных тестов: вместо настоящего traceroute вызвать эту программу.
TRACE_BIN = os.environ.get("UDPCHECK_TRACEROUTE", "traceroute")

TRACE_TIMEOUT = _env_int("UDPCHECK_TRACE_TIMEOUT", 50)       # с на один метод

GEO_DIR = os.environ.get("UDPCHECK_GEO_DIR", "/opt/udpcheck/geo")
GEO_ATTRIBUTION = "IP geolocation by DB-IP.com (CC BY 4.0)"

MAX_SEQ = 2000            # номера пакетов 0..MAX_SEQ-1
MAX_PKTS_PER_PORT = 700   # принимаем не больше пакетов на порт в сессии
MAX_REPLIES = 1500        # ответов на сессию
MAX_PAYLOAD = 1472        # без фрагментации на обычном MTU
UDP_PPS = 6000            # общий потолок ответов в секунду на весь сервер

# ---------------------------------------------------------------- формат UDP
# magic(4) 'UDPC' | ver(1) | flags(1: 0 запрос, 1 ответ) | token(8) | seq(4, BE)
MAGIC = b"UDPC"



# ---------------------------------------------------------------- GeoIP (mmdb)
class MMDB:
    """Минимальный читатель формата MaxMind DB (mmdb): только поиск по IP.
    Файл не грузится в память, а отображается через mmap."""

    MARKER = b"\xab\xcd\xefMaxMind.com"

    def __init__(self, path):
        self.path = path
        self.mtime = os.stat(path).st_mtime
        with open(path, "rb") as fh:
            self.m = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        i = self.m.rfind(self.MARKER)
        if i < 0:
            raise ValueError("не mmdb")
        meta_start = i + len(self.MARKER)
        self.meta, _ = self._decode(meta_start, meta_start)
        self.node_count = self.meta["node_count"]
        self.rec = self.meta["record_size"]
        self.ipv = self.meta["ip_version"]
        self.node_bytes = self.rec // 4
        self.tree_size = self.node_count * self.node_bytes
        self.data_base = self.tree_size + 16
        self._v4 = None

    def _decode(self, off, base):
        m = self.m
        ctrl = m[off]
        off += 1
        typ = ctrl >> 5
        if typ == 1:   # указатель
            ss = (ctrl >> 3) & 3
            vvv = ctrl & 7
            if ss == 0:
                ptr = (vvv << 8) | m[off]
                off += 1
            elif ss == 1:
                ptr = ((vvv << 16) | int.from_bytes(m[off:off + 2], "big")) + 2048
                off += 2
            elif ss == 2:
                ptr = ((vvv << 24) | int.from_bytes(m[off:off + 3], "big")) + 526336
                off += 3
            else:
                ptr = int.from_bytes(m[off:off + 4], "big")
                off += 4
            val, _ = self._decode(base + ptr, base)
            return val, off
        if typ == 0:   # расширенный тип
            typ = 7 + m[off]
            off += 1
        size = ctrl & 31
        if size == 29:
            size = 29 + m[off]
            off += 1
        elif size == 30:
            size = 285 + int.from_bytes(m[off:off + 2], "big")
            off += 2
        elif size == 31:
            size = 65821 + int.from_bytes(m[off:off + 3], "big")
            off += 3
        if typ == 2:
            return m[off:off + size].decode("utf-8"), off + size
        if typ == 3:
            return struct.unpack(">d", m[off:off + 8])[0], off + 8
        if typ == 15:
            return struct.unpack(">f", m[off:off + 4])[0], off + 4
        if typ in (5, 6, 9, 10):
            return int.from_bytes(m[off:off + size], "big"), off + size
        if typ == 8:
            return int.from_bytes(m[off:off + size], "big", signed=(size == 4)), off + size
        if typ == 4:
            return bytes(m[off:off + size]), off + size
        if typ == 7:
            out = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                v, off = self._decode(off, base)
                out[k] = v
            return out, off
        if typ == 11:
            arr = []
            for _ in range(size):
                v, off = self._decode(off, base)
                arr.append(v)
            return arr, off
        if typ == 14:
            return bool(size), off
        raise ValueError("неизвестный тип %d" % typ)

    def _child(self, node, bit):
        m = self.m
        o = node * self.node_bytes
        if self.rec == 24:
            b = m[o:o + 6]
            return int.from_bytes(b[0:3] if bit == 0 else b[3:6], "big")
        if self.rec == 28:
            b = m[o:o + 7]
            if bit == 0:
                return ((b[3] & 0xF0) << 20) | int.from_bytes(b[0:3], "big")
            return ((b[3] & 0x0F) << 24) | int.from_bytes(b[4:7], "big")
        b = m[o:o + 8]
        return int.from_bytes(b[0:4] if bit == 0 else b[4:8], "big")

    def lookup(self, ip):
        addr = ipaddress.ip_address(ip)
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        n = int(addr)
        if addr.version == 4:
            bits = 32
            if self.ipv == 6:
                if self._v4 is None:   # IPv4 живёт в дереве IPv6 под ::/96
                    node = 0
                    for _ in range(96):
                        if node >= self.node_count:
                            break
                        node = self._child(node, 0)
                    self._v4 = node
                node = self._v4
            else:
                node = 0
        else:
            if self.ipv == 4:
                return None
            bits = 128
            node = 0
        for i in range(bits - 1, -1, -1):
            if node >= self.node_count:
                break
            node = self._child(node, (n >> i) & 1)
        if node <= self.node_count:
            return None
        rec, _ = self._decode(node - self.node_count + self.tree_size, self.data_base)
        return rec


def _name(d):
    names = (d or {}).get("names") or {}
    return names.get("en") or (next(iter(names.values())) if names else None)


class Geo:
    """ASN и город по IP. Базы DB-IP Lite лежат в GEO_DIR; нет файлов - просто нет данных."""

    FILES = {"asn": "dbip-asn-lite.mmdb", "city": "dbip-city-lite.mmdb"}

    def __init__(self):
        self.db = {}
        self.cache = {}
        self.over = []          # исправления: [(сеть, {"asn":..., "org":...})] из GEO_DIR/overrides.json
        self._over_mtime = 0
        self.reload()

    def _reload_overrides(self):
        """Исправления ошибок базы: [{"cidr": "203.0.113.0/24", "asn": 64500, "org": "Example Hosting LLC"}]."""
        path = os.path.join(GEO_DIR, "overrides.json")
        try:
            mt = os.stat(path).st_mtime
        except OSError:
            if self.over:
                self.over, self._over_mtime, self.cache = [], 0, {}
            return
        if mt == self._over_mtime:
            return
        try:
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh)
            self.over = [(ipaddress.ip_network(x["cidr"]), x) for x in raw]
            self._over_mtime = mt
            self.cache = {}
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def reload(self):
        self._reload_overrides()
        for key, fname in self.FILES.items():
            path = os.path.join(GEO_DIR, fname)
            try:
                mt = os.stat(path).st_mtime
            except OSError:
                self.db.pop(key, None)
                continue
            cur = self.db.get(key)
            if cur is not None and cur.mtime == mt:
                continue
            try:
                self.db[key] = MMDB(path)
                self.cache = {}
            except Exception:
                self.db.pop(key, None)

    @property
    def available(self):
        return bool(self.db)

    def lookup(self, ip, force=False):
        """-> {'asn': 8359, 'org': 'MTS PJSC', 'country': 'RU', 'city': ..., 'region': ...}; {} если данных нет."""
        if ip in self.cache:
            return self.cache[ip]
        out = {}
        try:
            if not force and not is_public(ip):
                return out
            a = self.db.get("asn")
            if a:
                r = a.lookup(ip) or {}
                if r.get("autonomous_system_number"):
                    out["asn"] = r["autonomous_system_number"]
                    out["org"] = r.get("autonomous_system_organization")
            c = self.db.get("city")
            if c:
                r = c.lookup(ip) or {}
                if (r.get("country") or {}).get("iso_code"):
                    out["country"] = r["country"]["iso_code"]
                if _name(r.get("city")):
                    out["city"] = _name(r["city"])
                subs = r.get("subdivisions") or []
                if subs and _name(subs[0]):
                    out["region"] = _name(subs[0])
            if self.over:
                addr = ipaddress.ip_address(ip)
                for net, o in self.over:
                    if addr.version == net.version and addr in net:
                        out["asn"] = int(o["asn"])
                        out["org"] = o.get("org") or out.get("org")
                        for k in ("country", "city", "region"):
                            if o.get(k):
                                out[k] = o[k]
                        break
        except Exception:
            return {}
        if len(self.cache) > 5000:
            self.cache = {}
        self.cache[ip] = out
        return out


# ---------------------------------------------------------------- утилиты
class RateLimiter:
    """Скользящее окно: не больше `limit` событий за `window` секунд на ключ."""

    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self.hits = {}

    def allow(self, key, now=None):
        now = time.time() if now is None else now
        q = self.hits.setdefault(key, deque())
        while q and q[0] <= now - self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False, int(q[0] + self.window - now) + 1
        q.append(now)
        return True, 0

    def over(self, key, now=None):
        """Исчерпан ли лимит по ключу (без учёта нового события)."""
        now = time.time() if now is None else now
        q = self.hits.get(key)
        if not q:
            return False
        while q and q[0] <= now - self.window:
            q.popleft()
        return len(q) >= self.limit

    def purge(self, now=None):
        now = time.time() if now is None else now
        for key in [k for k, q in self.hits.items() if not q or q[-1] <= now - self.window]:
            del self.hits[key]


class TokenBucket:
    def __init__(self, rate, burst):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.stamp = time.monotonic()

    def take(self):
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.stamp) * self.rate)
        self.stamp = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


def to_ranges(seqs):
    """{0,1,2,5,6} -> [[0, 2], [5, 6]]: показывает, где именно оборвался поток."""
    out = []
    for s in sorted(seqs):
        if out and s == out[-1][1] + 1:
            out[-1][1] = s
        else:
            out.append([s, s])
    return out


udp_bucket = TokenBucket(UDP_PPS, UDP_PPS // 4)
rl_stun = RateLimiter(60, 10)   # STUN-запросов с одного адреса за 10 с
rl_pad = RateLimiter(150, 60)   # длинных ответов одному адресу за минуту (проверка шлёт ~6 запросов, при потерях браузер повторяет их)
PAD_ALLOW = {}                  # адрес посетителя -> до какого времени ему можно слать длинные ответы (разрешает хаб, адрес подтверждён по TCP)
PAD_LOCK = threading.Lock()


def pad_allow(ip, ttl=120):
    """Хаб подтвердил адрес посетителя (он сам пришёл на сайт по TCP): длинные STUN-ответы ему можно слать. Без этого сервер не стал бы
    отвечать длинными пакетами на чужой адрес из подделанного запроса (усиление трафика)."""
    now = time.time()
    with PAD_LOCK:
        if len(PAD_ALLOW) >= 2000:
            for k in [k for k, v in PAD_ALLOW.items() if v < now]:
                PAD_ALLOW.pop(k, None)
            if len(PAD_ALLOW) >= 2000:
                return
        PAD_ALLOW[str(ip)] = now + ttl


def pad_allowed(ip):
    with PAD_LOCK:
        return PAD_ALLOW.get(ip, 0) > time.time()
GEO = Geo()
V2 = None   # модуль udpcheck_v2 (хаб и роль цели), подключается в main()


STUN_COOKIE = b"\x21\x12\xa4\x42"


def stun_reply(data, addr, size=0):
    """Ответ на STUN Binding Request (RFC 5389): XOR-MAPPED-ADDRESS. Нужен браузерной проверке (WebRTC):
    если ответ дошёл до браузера, UDP с нашего сервера до этой сети проходит."""
    if len(data) < 20 or len(data) > 548 or data[4:8] != STUN_COOKIE:
        return None
    if data[0] & 0xC0 or int.from_bytes(data[0:2], "big") != 0x0001:      # только Binding Request
        return None
    if int.from_bytes(data[2:4], "big") != len(data) - 20:
        return None
    try:
        ip = ipaddress.ip_address(addr[0])
    except ValueError:
        return None
    if ip.version != 4:
        return None
    value = struct.pack("!BBH4s", 0, 1, addr[1] ^ 0x2112, (int(ip) ^ 0x2112A442).to_bytes(4, "big"))
    attr = struct.pack("!HH", 0x0020, len(value)) + value
    if size:       # добиваем ответ до нужной длины необязательным атрибутом со случайными байтами (браузеры такие атрибуты пропускают)
        room = size - 20 - len(attr) - 4
        room -= room % 4
        if room > 0:
            attr += struct.pack("!HH", 0xC057, room) + os.urandom(room)
    return struct.pack("!HH", 0x0101, len(attr)) + STUN_COOKIE + data[8:20] + attr


STUN_SEEN = {}                    # IP -> {"t": время последнего запроса, "ports": {порт: сколько запросов получено}}; только в памяти
STUN_SEEN_LOCK = threading.Lock()


def stun_note(ip, port, sent=False):
    """Запоминаем, что STUN-запрос с этого адреса дошёл до нас (на 2 минуты, в памяти). Нужно, чтобы браузерная проверка
    могла доказать направление: «запрос дошёл до сервера, а ответ до вас нет»."""
    now = time.time()
    with STUN_SEEN_LOCK:
        e = STUN_SEEN.get(ip)
        if e is None:
            if len(STUN_SEEN) >= 4000:
                for k in [k for k, v in STUN_SEEN.items() if now - v["t"] > 120][:2000]:
                    STUN_SEEN.pop(k, None)
                if len(STUN_SEEN) >= 4000:
                    return
            e = STUN_SEEN[ip] = {"t": now, "ports": {}, "sent": {}}
        if now - e["t"] > 60:          # новая проверка: прежние счётчики не нужны
            e["ports"], e["sent"] = {}, {}
        e["t"] = now
        key = "sent" if sent else "ports"
        e[key][port] = min(e[key].get(port, 0) + 1, 1000)


def stun_seen(ip):
    """({порт: сколько STUN-запросов с этого адреса получено}, {порт: сколько ответов на них отправлено}) за последнюю проверку."""
    with STUN_SEEN_LOCK:
        e = STUN_SEEN.get(ip)
        if e is None or time.time() - e["t"] > 120:
            return {}, {}
        return dict(e["ports"]), dict(e["sent"])


def handle_udp(sock, data, addr):
    port = sock.getsockname()[1]
    if port in PAD_BOUND:                      # порт для длинных ответов: только STUN и только тем, кого разрешил хаб
        if len(data) >= 20 and data[4:8] == STUN_COOKIE and pad_allowed(addr[0]) and rl_pad.allow(addr[0])[0]:
            reply = stun_reply(data, addr, PAD_BOUND[port])
            if reply is not None and udp_bucket.take():
                try:
                    sock.sendto(reply, addr)
                except OSError:
                    pass
        return
    if len(data) >= 20 and data[4:8] == STUN_COOKIE:
        reply = stun_reply(data, addr)
        if reply is not None:
            stun_note(addr[0], sock.getsockname()[1])
        if reply is not None and rl_stun.allow(addr[0])[0] and udp_bucket.take():
            try:
                sock.sendto(reply, addr)
                stun_note(addr[0], sock.getsockname()[1], sent=True)      # ответ реально ушёл с сервера
            except OSError:
                pass
        return
    if len(data) >= 6 and data[:4] == MAGIC and data[4] == 2:   # пакет версии 2: роль цели
        if V2 is not None:
            V2.target_udp(sock, data, addr)
        return


def udp_loop(socks):
    sel = selectors.DefaultSelector()
    for s in socks:
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ)
    while True:
        try:
            for key, _ in sel.select(timeout=1.0):
                sock = key.fileobj
                for _ in range(128):
                    try:
                        data, addr = sock.recvfrom(2048)
                    except (BlockingIOError, InterruptedError):
                        break
                    except OSError:
                        break
                    handle_udp(sock, data, addr)
        except Exception:
            time.sleep(0.05)


# ---------------------------------------------------------------- трассировка
HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")


def parse_traceroute(text, dest):
    """Разбор вывода traceroute -n в список хопов. Формат строки:
       ' 3  203.0.113.1  1.2 ms  1.3 ms'  /  ' 4  * *'  /  ' 5  10.0.0.1  1 ms !H'
    """
    hops = []
    for line in text.splitlines()[:200]:
        m = HOP_RE.match(line)
        if not m:
            continue
        ttl = int(m.group(1))
        addrs, rtts, flags, lost = [], [], [], 0
        for tok in m.group(2).split():
            if tok == "*":
                lost += 1
            elif tok == "ms":
                continue
            elif tok.startswith("!"):
                flags.append(tok)
            else:
                try:
                    ipaddress.ip_address(tok)
                    if tok not in addrs:
                        addrs.append(tok)
                    continue
                except ValueError:
                    pass
                try:
                    rtts.append(float(tok))
                except ValueError:
                    pass
        hops.append({"ttl": ttl, "addrs": addrs, "rtt_ms": rtts, "lost": lost, "flags": flags})
    reached = bool(hops) and dest in hops[-1]["addrs"]
    return hops, reached


def trace_cmd(method, ip, tcp_port):
    cmd = [TRACE_BIN]
    if ":" in ip:
        cmd.append("-6")
    cmd += ["-n", "-q", "2", "-w", "1.5", "-m", "25"]
    if method == "icmp":
        cmd.append("-I")
    elif method == "tcp":
        cmd += ["-T", "-p", str(tcp_port)]
    # udp: поведение по умолчанию (порты 33434+)
    return cmd + [ip]


def run_trace(method, ip, tcp_port):
    cmd = trace_cmd(method, ip, tcp_port)
    started = time.time()
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, text=True, errors="replace")
    except OSError:
        return {"method": method, "ok": False, "error": "traceroute не запустился", "hops": []}
    timed_out = False
    try:
        out, _ = p.communicate(timeout=TRACE_TIMEOUT)
    except subprocess.TimeoutExpired:
        timed_out = True
        p.kill()
        out, _ = p.communicate()
    hops, reached = parse_traceroute(out or "", ip)
    # Хвост из молчащих хопов обрезаем: он ничего не говорит, кроме «дальше тишина».
    last = max((h["ttl"] for h in hops if h["addrs"]), default=0)
    silent_tail = sum(1 for h in hops if h["ttl"] > last)
    hops = [h for h in hops if h["ttl"] <= last]
    as_path = []     # сети (ASN) по хопам определяет хаб: цели присылают сырую трассировку и базе GeoIP им не нужна
    res = {"method": method, "ok": bool(hops), "reached": reached,
           "last_responding_ttl": last, "silent_tail_hops": silent_tail, "as_path": as_path,
           "timed_out": timed_out, "seconds": round(time.time() - started, 1), "hops": hops}
    if method == "tcp":
        res["tcp_port"] = tcp_port
    if not hops:
        res["error"] = "нет данных от traceroute"
    return res


# ---------------------------------------------------------------- HTTP
def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class Server(ThreadingHTTPServer):
    request_queue_size = 64


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 20

    def version_string(self):
        return "udpcheck"

    def log_message(self, *a):      # никаких логов
        pass

    def log_error(self, *a):
        pass

    # --- вспомогательное
    def client_ip(self):
        peer = self.client_address[0]
        if peer in TRUSTED_PROXIES:
            xff = self.headers.get("X-Forwarded-For", "")
            last = xff.split(",")[-1].strip() if xff else ""
            try:
                return str(ipaddress.ip_address(last))
            except ValueError:
                return None
        return peer

    def send_json(self, code, obj, extra=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if self.close_connection:
            self.send_header("Connection", "close")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def err(self, code, msg, retry=None):
        self.close_connection = True   # в запросе мог остаться непрочитанный body
        self.send_json(code, {"error": msg}, {"Retry-After": str(retry)} if retry else None)

    def body_len(self):
        """Заявленная длина тела; -1, если заголовок некорректный."""
        v = (self.headers.get("Content-Length", "0") or "0").strip()
        return int(v) if v.isascii() and v.isdigit() and len(v) < 10 else -1

    def read_body(self, limit):
        n = self.body_len()
        if n < 0 or n > limit:
            self.close_connection = True      # тело не прочитано: соединение дальше использовать нельзя
            return None
        return self.rfile.read(n) if n else b""

    def route(self):
        path = urlsplit(self.path).path
        if PREFIX and path.startswith(PREFIX + "/"):
            path = path[len(PREFIX):]
        return path.rstrip("/") or "/"

    # --- методы
    def do_GET(self):
        try:
            self.dispatch(self.command)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception:
            try:
                self.err(500, "внутренняя ошибка")
            except Exception:
                self.close_connection = True

    do_POST = do_GET
    do_HEAD = do_GET

    def dispatch(self, method):
        # Хаб тела с Transfer-Encoding не читает: оставшиеся в соединении байты разобрались бы как следующий запрос (рассинхронизация с прокси).
        # Так же с телом у GET/HEAD. Такие запросы отклоняем, а соединение закрываем.
        if self.headers.get("Transfer-Encoding") or (method != "POST" and self.body_len() != 0):
            return self.err(400, "запрос с таким телом не принимается")
        path = self.route()
        if path.startswith("/api/v2/") and V2 is not None:
            return V2.dispatch(self, method, path)
        if path == "/api/v1/health":
            return self.send_json(200, {"ok": True})
        return self.err(404, "не найдено")


# ---------------------------------------------------------------- обслуживание
def janitor():
    while True:
        time.sleep(30)
        now = time.time()
        rl_stun.purge(now)
        rl_pad.purge(now)
        GEO.reload()
        if V2 is not None:
            try:
                V2.janitor()
            except Exception:
                pass


def main():
    socks = []
    for port in UDP_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((UDP_BIND, port))
        except OSError as e:
            print("не удалось занять UDP %d: %s" % (port, e), file=sys.stderr)
            sys.exit(1)
        socks.append(s)
    for port, size in PAD_PORTS.items():
        if port in UDP_PORTS:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((UDP_BIND, port))
        except OSError as e:
            print("не удалось занять UDP %d для длинных ответов (пропускаем): %s" % (port, e), file=sys.stderr)
            continue
        socks.append(s)
        PAD_BOUND[port] = size
    global V2
    try:
        import udpcheck_v2
        udpcheck_v2.init(sys.modules[__name__])
        V2 = udpcheck_v2
    except ImportError:
        V2 = None
    httpd = Server((HTTP_BIND, HTTP_PORT), Handler)
    httpd.daemon_threads = True
    threading.Thread(target=udp_loop, args=(socks,), daemon=True).start()
    threading.Thread(target=janitor, daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
