#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""udpcheck-node: узел сети проверок UDP (протокол v2, см. PROTOCOL.md).

Один файл, только стандартная библиотека, Python 3.7+ (Windows, Linux, роутеры с Python).
Узел ходит ТОЛЬКО наружу: на хаб по HTTPS и на IP целей из задания (UDP/TCP). Имён, сертификатов и открытых портов не нужно.

Запуск:
  python udpcheck_node.py --once      один замер сейчас, результат на экран (сначала сам зарегистрируется)
  python udpcheck_node.py             работать постоянно: раз в ~15 минут получать задание и слать результат
  python udpcheck_node.py --role ref    работать опорным сервером: отвечать на подписанные UDP/TCP-проверки других узлов по
                                        заданиям хаба, сам ничего не проверяет (для VPS и серверов с публичным IPv4; нужны
                                        открытые снаружи порты UDP 47321, 47322 и TCP 47321, хаб сам проверит доступность)
  python udpcheck_node.py --role both   и проверять свою сеть, и служить опорным сервером (--ref то же самое)

Что отправляется хабу: токен узла, сколько ответов получено по каждому порту каждой цели, итог TCP-проверки.
Хаб видит ваш IP на время запроса и определяет по нему провайдера (ASN) и приблизительный город. IP в базе не хранится.
В режиме --ref IP узла становится известен хабу и другим узлам сети (они шлют на него проверочные UDP), а узел видит IP узлов,
которые его проверяют. Посетители сайта и их адреса к опорным серверам участников не попадают.
Файл настроек (токен узла) лежит в %APPDATA%\\udpcheck-node\\config.json или ~/.config/udpcheck-node/config.json.
"""

import argparse
import json
import os
import platform
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

VERSION = "0.5"
DEFAULT_HUB = "https://dagart.xyz"
UDP2 = struct.Struct("!4sBB8sI4s")      # magic ver flags taskid seq mac = 22 байта
TCP2 = struct.Struct("!4sBB8s4sI")      # magic ver mode taskid mac kb   = 22 байта


def _ui_lang():
    """Язык вывода: UDPCHECK_LANG (ru или en), иначе язык системы (русский: ru), иначе русский."""
    v = (os.environ.get("UDPCHECK_LANG") or "").strip().lower()[:2]
    if v in ("ru", "en"):
        return v
    for k in ("LC_ALL", "LC_MESSAGES", "LANG"):
        if os.environ.get(k):
            return "ru" if os.environ[k].lower().startswith("ru") else "en"
    try:                                           # Windows: язык интерфейса пользователя (0x19 = русский)
        import ctypes
        return "ru" if (ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3ff) == 0x19 else "en"
    except Exception:
        return "ru"


LANG_UI = _ui_lang()

MSG = {
    "ru": {
        "reg_denied": "регистрация отклонена: %s %s",
        "reg_ok": "Узел зарегистрирован. Позывной: %s. Провайдер по базе IP: %s",
        "unknown": "не определён",
        "ref_ports_busy": "Опорная роль не включена: порты UDP %s заняты другой программой.",
        "hub_said": "хаб ответил %s", "hub_no_token": "хаб не узнал токен узла", "hub_no_ports": "хаб не достучался до портов",
        "hub_noconn": "нет связи с хабом (%s)", "none": "нет",
        "ref_on": "Опорная роль включена: сервер отвечает на проверки по заданиям хаба (%s). Он виден на сайте в списке опорных серверов добровольцев.",
        "ref_off": ("Опорная роль не активна: %s. Узел работает как обычно; проверка повторится сама. Чтобы стать опорным, откройте "
                    "снаружи UDP %s и TCP %d (фаервол и NAT настраиваете вы)."),
        "checking": "  проверяю %s ...",
        "cls_OK": "чисто", "cls_INCUT": "ответы не приходят", "cls_OUTCUT": "до цели не доходит", "cls_LOSSY": "потери выше нормы", "cls_NOREPORT": "цель не отчиталась",
        "st_LOSSY": "проходит, но с потерями выше нормы", "st_OK": "чисто", "st_INCUT": "ответы не приходят", "st_OUTCUT": "до цели не доходит",
        "st_PART": "проходит только на части портов", "st_MIXED": "смешанно", "st_NOREPORT": "цель не отчиталась",
        "place_home": "в вашей стране", "place_foreign": "зарубеж",
        "comm_line": "--- опорный сервер участника %s [%s]: %s, TCP: %s (%s) ---", "comm_control": "входит в итог как контроль", "comm_noverdict": "в итог не входит",
        "target_line": "--- %s [%s]: %s, TCP: %s ---",
        "port_line": "  порт %-6s дошло на цель: %-4s ответов получено: %-4s %s",
        "verdict": "ВЫВОД: ",
        "warn_src": "ВНИМАНИЕ: UDP вышел с другого адреса, чем HTTPS (VPN или обход на роутере). Результат искажён.",
        "tunnel_hint": "Выключите прокси, VPN или туннель либо исключите из него адреса целей и повторите.",
        "hub_rejected": "Хаб не принял результат: %s %s",
        "help_hub": "адрес хаба (по умолчанию %s)", "help_config": "путь к файлу настроек", "help_once": "один замер сейчас и выход",
        "help_ref": "то же, что --role both",
        "help_role": "node: проверять свою сеть (по умолчанию); ref: только опорный сервер; both: и то и другое",
        "banner": "udpcheck-node v%s. %s", "banner_ref": "Работаю опорным сервером.", "banner_node": "Выключите VPN и обход блокировок, иначе вы проверите их, а не провайдера.",
        "no_task": "Хаб не выдал задание, повторите позже.",
        "running": "Работаю постоянно. Позывной: %s. Роль: %s. Остановить: Ctrl+C.",
        "role_node": "узел", "role_ref": "опорный сервер", "role_both": "узел и опорный сервер",
        "ref_not_on": "Опорная роль не включена (%s).", "poll_err": "опрос хаба: %s %s",
        "outdated": ("Доступна новая версия агента %s (у вас %s). Обновить: (curl -fsSL %s/i 2>/dev/null || wget -qO- %s/i) | sh. "
                     "Срочности нет, старая версия продолжит работать."),
        "got_task": "[%H:%M:%S] получено задание", "stopped": "Остановлено.", "hub_err": "Ошибка связи с хабом (%s). Повтор через %d с.",
    },
    "en": {
        "reg_denied": "registration rejected: %s %s",
        "reg_ok": "Node registered. Callsign: %s. Provider by IP database: %s",
        "unknown": "not identified",
        "ref_ports_busy": "Anchor role not enabled: UDP ports %s are taken by another program.",
        "hub_said": "the hub answered %s", "hub_no_token": "the hub did not recognise the node token", "hub_no_ports": "the hub could not reach the ports",
        "hub_noconn": "no connection to the hub (%s)", "none": "none",
        "ref_on": "Anchor role enabled: the server answers checks on the hub's assignments (%s). It is visible on the site in the list of volunteer anchor servers.",
        "ref_off": ("Anchor role is not active: %s. The node works as usual; the check will repeat on its own. To become an anchor, open "
                    "UDP %s and TCP %d from outside (you configure the firewall and NAT)."),
        "checking": "  checking %s ...",
        "cls_OK": "clean", "cls_INCUT": "replies do not arrive", "cls_OUTCUT": "does not reach the target", "cls_LOSSY": "loss above normal", "cls_NOREPORT": "target did not report",
        "st_LOSSY": "passes, but with loss above normal", "st_OK": "clean", "st_INCUT": "replies do not arrive", "st_OUTCUT": "does not reach the target",
        "st_PART": "passes on some ports only", "st_MIXED": "mixed", "st_NOREPORT": "target did not report",
        "place_home": "in your country", "place_foreign": "abroad",
        "comm_line": "--- volunteer anchor server %s [%s]: %s, TCP: %s (%s) ---", "comm_control": "counted in the verdict as a control", "comm_noverdict": "not counted in the verdict",
        "target_line": "--- %s [%s]: %s, TCP: %s ---",
        "port_line": "  port %-6s reached the target: %-4s replies received: %-4s %s",
        "verdict": "VERDICT: ",
        "warn_src": "WARNING: UDP left from a different address than HTTPS (VPN or a bypass on the router). The result is distorted.",
        "tunnel_hint": "Turn off the proxy, VPN or tunnel, or exclude the targets' addresses from it, and repeat.",
        "hub_rejected": "The hub did not accept the result: %s %s",
        "help_hub": "hub address (default %s)", "help_config": "path to the settings file", "help_once": "one measurement now, then exit",
        "help_ref": "same as --role both",
        "help_role": "node: check your own network (default); ref: anchor server only; both: both",
        "banner": "udpcheck-node v%s. %s", "banner_ref": "Running as an anchor server.", "banner_node": "Turn off your VPN and bypass tools, otherwise you will check them instead of your provider.",
        "no_task": "The hub gave no task, try again later.",
        "running": "Running continuously. Callsign: %s. Role: %s. Stop: Ctrl+C.",
        "role_node": "node", "role_ref": "anchor server", "role_both": "node and anchor server",
        "ref_not_on": "Anchor role not enabled (%s).", "poll_err": "hub poll: %s %s",
        "outdated": ("A new agent version %s is available (you have %s). Update: (curl -fsSL %s/en/i 2>/dev/null || wget -qO- %s/en/i) | sh. "
                     "No hurry, the old version keeps working."),
        "got_task": "[%H:%M:%S] task received", "stopped": "Stopped.", "hub_err": "Hub connection error (%s). Retrying in %d s.",
    },
}


def tr(key):
    return MSG[LANG_UI][key]


def say(msg=""):
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode("ascii"), flush=True)


# ---------------------------------------------------------------- настройки узла
def cfg_path():
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "udpcheck-node", "config.json")


def load_cfg(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_cfg(path, cfg):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------- HTTP к хабу
def http(hub, method, path, body=None, token=None, timeout=40):
    data = json.dumps(body).encode("utf-8") if body is not None else (b"" if method == "POST" else None)
    req = urllib.request.Request(hub + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "udpcheck-node/" + VERSION)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def _why(r):
    """Причина отказа от хаба на языке вывода (хаб присылает reason и reason_en)."""
    return (r.get("reason_en") if LANG_UI == "en" else None) or r.get("reason")


def register(hub, cfg, path):
    st, r = http(hub, "POST", "/api/v2/node/register", {"client": "udpcheck-node/%s %s" % (VERSION, platform.system())})
    if st != 201:
        raise RuntimeError(tr("reg_denied") % (st, r.get("error", "")))
    cfg.update({"hub": hub, "token": r["token"], "callsign": r["callsign"]})
    save_cfg(path, cfg)
    say(tr("reg_ok") % (r["callsign"], ("AS%s %s" % (r.get("asn"), r.get("org"))) if r.get("asn") else tr("unknown")))
    return cfg


# ---------------------------------------------------------------- опорная роль
STUN_COOKIE = bytes((0x21, 0x12, 0xA4, 0x42))
REF_UDP_PORTS = [47321, 47322]
REF_TCP_PORT = 47321
REF_PPS, REF_BURST = 500, 1500          # лимит ответов в секунду (защита от использования в атаке)


class RefServer:
    """Узел отвечает на проверки других узлов. Секрет выдаёт хаб; отвечаем только на пакеты с верной подписью HMAC,
    эхо не больше полученного пакета, на сессию не больше 1500 ответов."""

    def __init__(self, hub, token):
        import hashlib, hmac, select, threading
        self.hashlib, self.hmac, self.select, self.threading = hashlib, hmac, select, threading
        self.hub, self.token = hub, token
        self.secret = self.code = None
        self.socks, self.tcp = {}, None
        self.t2, self.lock = {}, threading.Lock()
        self.tokens, self.tok_t = float(REF_BURST), time.time()
        self.stun_rl = {}
        self.verified, self.delay, self.next_try = None, 900, 0

    def _mac(self, tag, taskid):
        return self.hmac.new(self.secret, tag + taskid, self.hashlib.sha256).digest()[:4]

    def bind(self):
        for p in REF_UDP_PORTS:
            sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sk.bind(("0.0.0.0", p))
            except OSError:
                sk.close()
                continue
            self.socks[p] = sk
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if os.name != "nt":
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", REF_TCP_PORT))
            srv.listen(8)
            self.tcp = srv
        except OSError:
            self.tcp = None
        return bool(self.socks)

    def start(self):
        if not self.bind():
            say(tr("ref_ports_busy") % ", ".join(map(str, REF_UDP_PORTS)))
            return False
        for fn in (self._udp_loop, self._report_loop) + ((self._tcp_loop,) if self.tcp else ()):
            self.threading.Thread(target=fn, daemon=True).start()
        self.handshake()
        return True

    def _declare(self, verify):
        body = {"udp_ports": sorted(self.socks), "tcp_port": self.tcp.getsockname()[1] if self.tcp else 0, "verify": verify}
        return http(self.hub, "POST", "/api/v2/node/ref", body, token=self.token, timeout=40)

    def handshake(self):
        """Получить у хаба секрет, попросить проверить доступность снаружи. True, если опорный сервер принят."""
        try:
            if self.secret is None:
                st, r = self._declare(False)
                if st != 200 or not r.get("ok"):
                    return self._state(False, _why(r) or r.get("error") or tr("hub_said") % st)
                self.secret, self.code = bytes.fromhex(r["secret"]), r["code"]
            st, r = self._declare(True)
            if st == 401:
                return self._state(False, tr("hub_no_token"))
            if st != 200 or not r.get("ok"):
                return self._state(False, _why(r) or r.get("error") or tr("hub_said") % st)
            self.secret, self.code = bytes.fromhex(r["secret"]), r["code"]
            if r.get("verified"):
                return self._state(True, "UDP %s, TCP %s" % (", ".join(map(str, r.get("udp_ports") or [])), r.get("tcp_port") or tr("none")))
            return self._state(False, _why(r) or tr("hub_no_ports"))
        except Exception as e:
            self._state(self.verified, tr("hub_noconn") % e.__class__.__name__, quiet=True)
            return False

    def _state(self, ok, text, quiet=False):
        if ok != self.verified and not quiet:
            if ok:
                say(tr("ref_on") % text)
            else:
                say(tr("ref_off") % (text, ", ".join(map(str, sorted(self.socks))), REF_TCP_PORT))
        if not quiet or self.verified is None:
            self.verified = ok
        return bool(ok)

    def maybe_handshake(self, hub_says):
        """Вызывается после каждого опроса хаба. hub_says: True/False/None, как хаб видит наш опорный сервер."""
        now = time.time()
        if hub_says is False and self.verified:      # хаб сбросил проверку: сменился адрес
            self.verified, self.delay, self.next_try = False, 900, now
        if now < self.next_try:
            return
        if self.handshake():
            self.next_try, self.delay = now + 3 * 3600, 900     # раз в 3 часа убеждаемся, что порты всё ещё открыты
        else:
            self.next_try, self.delay = now + self.delay, min(self.delay * 2, 6 * 3600)

    def new_token(self, token):
        self.token, self.secret, self.next_try = token, None, 0

    def _take(self, now):
        self.tokens = min(float(REF_BURST), self.tokens + (now - self.tok_t) * REF_PPS)
        self.tok_t = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

    def _udp_loop(self):
        socks = list(self.socks.values())
        while True:
            try:
                ready, _, _ = self.select.select(socks, [], [], 1.0)
            except (OSError, ValueError):
                time.sleep(1)
                continue
            for sk in ready:
                try:
                    data, addr = sk.recvfrom(2048)
                except OSError:
                    continue
                self._on_udp(sk, data, addr)

    def _stun(self, sk, data, addr):
        """Ответ на STUN Binding Request (RFC 5389): так браузер посетителя проверяет, доходит ли до него UDP с этого сервера.
        Отвечаем только на корректные запросы, не больше 60 в 10 секунд на адрес и в пределах общего лимита."""
        if len(data) < 20 or len(data) > 548 or data[0] & 0xC0 or int.from_bytes(data[0:2], "big") != 0x0001:
            return
        if int.from_bytes(data[2:4], "big") != len(data) - 20:
            return
        parts = addr[0].split(".")
        if len(parts) != 4:
            return
        now = time.time()
        with self.lock:
            w = self.stun_rl.get(addr[0])
            if w is None or now - w[0] > 10:
                if len(self.stun_rl) > 2000:
                    self.stun_rl.clear()
                w = self.stun_rl[addr[0]] = [now, 0]
            w[1] += 1
            if w[1] > 60 or not self._take(now):
                return
        try:
            ip = int.from_bytes(bytes(int(x) for x in parts), "big")
        except ValueError:
            return
        value = struct.pack("!BBH4s", 0, 1, addr[1] ^ 0x2112, (ip ^ 0x2112A442).to_bytes(4, "big"))
        attr = struct.pack("!HH", 0x0020, len(value)) + value
        try:
            sk.sendto(struct.pack("!HH", 0x0101, len(attr)) + STUN_COOKIE + data[8:20] + attr, addr)
        except OSError:
            pass

    def _on_udp(self, sk, data, addr):
        if len(data) >= 20 and data[4:8] == STUN_COOKIE:
            self._stun(sk, data, addr)
            return
        if self.secret is None or len(data) < UDP2.size or len(data) > 1472:
            return
        magic, ver, flags, taskid, seq, mac = UDP2.unpack_from(data)
        if magic != b"UDPC" or ver != 2 or flags != 0 or seq >= 2000:
            return
        if not self.hmac.compare_digest(mac, self._mac(b"UDPC2", taskid)):
            return
        port, now = sk.getsockname()[1], time.time()
        with self.lock:
            t = self.t2.get(taskid)
            if t is None:
                if len(self.t2) >= 200:
                    return
                t = self.t2[taskid] = {"created": now, "last": now, "rx": {}, "replies": 0, "srcs": [], "reported": False, "tries": 0}
            got = t["rx"].setdefault(port, set())
            if len(got) >= 700:
                return
            got.add(seq)
            t["last"], t["reported"] = now, False
            if addr[0] not in t["srcs"] and len(t["srcs"]) < 8:
                t["srcs"].append(addr[0])
            if t["replies"] >= 1500 or not self._take(now):
                return
            t["replies"] += 1
        reply = bytearray(data)
        reply[5] = 1
        try:
            sk.sendto(bytes(reply), addr)
        except OSError:
            pass

    def _post(self, taskid, snap):
        body = json.dumps({"taskid": taskid.hex(), "ports": snap["ports"], "srcs": snap["srcs"]}).encode("utf-8")
        sig = self.hmac.new(self.secret, body, self.hashlib.sha256).hexdigest()
        req = urllib.request.Request(self.hub + "/api/v2/target/report", data=body, method="POST",
                                     headers={"Content-Type": "application/json", "X-Target": self.code, "X-Auth": sig,
                                              "User-Agent": "udpcheck-node/" + VERSION})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status == 200
        except Exception:
            return False

    def _report_loop(self):
        """Раз в секунду: замеры, по которым уже 4 с тишины, отправляем хабу."""
        while True:
            time.sleep(1)
            now, due = time.time(), []
            with self.lock:
                for tid, t in list(self.t2.items()):
                    if now - t["created"] > 600:
                        del self.t2[tid]
                    elif not t["reported"] and now - t["last"] >= 4 and t["tries"] < 4:
                        due.append((tid, {"ports": {str(p): {"rx": len(v)} for p, v in t["rx"].items()}, "srcs": list(t["srcs"])}))
            for tid, snap in due:
                ok = self.secret is not None and self._post(tid, snap)
                with self.lock:
                    t = self.t2.get(tid)
                    if t is not None:
                        if ok:
                            t["reported"] = True
                        else:
                            t["tries"] += 1

    def _tcp_loop(self):
        slots = self.threading.BoundedSemaphore(4)
        while True:
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                time.sleep(0.2)
                continue
            if not slots.acquire(False):
                conn.close()
                continue
            self.threading.Thread(target=self._tcp_conn, args=(conn, slots), daemon=True).start()

    def _tcp_conn(self, conn, slots):
        try:
            conn.settimeout(15)
            raw = b""
            while len(raw) < TCP2.size:
                chunk = conn.recv(TCP2.size - len(raw))
                if not chunk:
                    return
                raw += chunk
            magic, ver, mode, taskid, mac, kb = TCP2.unpack(raw)
            if self.secret is None or magic != b"TCPC" or ver != 2 or mode not in (0, 1) or not 1 <= kb <= 512:
                return
            if not self.hmac.compare_digest(mac, self._mac(b"TCPC2", taskid)):
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
            slots.release()


# ---------------------------------------------------------------- замер
def _drain(socks, got, taskid, sent_at=None, rtts=None):
    for p, s in socks.items():
        while True:
            try:
                d, _ = s.recvfrom(2048)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break          # на Windows ICMP «порт недоступен» приходит как ошибка чтения
            if len(d) >= UDP2.size:
                magic, ver, flags, tid, seq, _mac = UDP2.unpack_from(d)
                if magic == b"UDPC" and ver == 2 and flags == 1 and tid == taskid:
                    got[p].add(seq)
                    if sent_at is not None and rtts is not None and seq in sent_at and len(rtts) < 400:
                        rtts.append(time.perf_counter() - sent_at[seq])


def _ranges(seqs):
    out = []
    for x in sorted(seqs):
        if out and x == out[-1][1] + 1:
            out[-1][1] = x
        else:
            out.append([x, x])
    return ",".join("%d-%d" % (a, b) for a, b in out)


def udp_stream(tg, count, size, gap, wait):
    """Поток на все порты цели одновременно. Возвращает {порт: набор seq, на которые пришёл ответ}."""
    taskid, mac = bytes.fromhex(tg["taskid"]), bytes.fromhex(tg["mac"])
    ports, ip = tg["ports"], tg["ip"]
    socks, got = {}, {}
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        except OSError:
            pass
        if hasattr(socket, "SIO_UDP_CONNRESET"):
            try:
                s.ioctl(socket.SIO_UDP_CONNRESET, False)
            except (OSError, ValueError):
                pass
        s.setblocking(False)
        socks[p], got[p] = s, set()
    pad = bytes(max(0, size - UDP2.size))
    sent_at, rtts = {}, []
    t0 = time.perf_counter()
    for seq in range(count):
        pkt = UDP2.pack(b"UDPC", 2, 0, taskid, seq, mac) + pad
        sent_at[seq] = time.perf_counter()
        for p in ports:
            try:
                socks[p].sendto(pkt, (ip, p))
            except OSError:
                pass
        _drain(socks, got, taskid, sent_at, rtts)
        until = t0 + (seq + 1) * gap
        while time.perf_counter() < until:
            pass
    deadline = time.time() + wait
    while time.time() < deadline:
        _drain(socks, got, taskid, sent_at, rtts)
        if all(len(got[p]) >= count for p in ports):
            break
        time.sleep(0.05)
    for s in socks.values():
        s.close()
    rtts.sort()
    return got, (round(rtts[len(rtts) // 2] * 1000, 1) if rtts else None)


def tcp_connect_ms(tg, n=3):
    """Наименьшее время TCP-соединения с целью, мс. Намного меньше времени UDP-эха значит, что рукопожатие
    завершается где-то рядом с вами (прозрачный прокси, туннель), а не на самой цели."""
    port = tg.get("tcp_port") or 0
    if not port:
        return None
    best = None
    for _ in range(n):
        t = time.perf_counter()
        try:
            s = socket.create_connection((tg["ip"], port), timeout=4)
            ms = (time.perf_counter() - t) * 1000
            s.close()
            best = ms if best is None else min(best, ms)
        except OSError:
            pass
    return round(best, 1) if best is not None else None


def tcp_probe(tg, down_kb=100, up_kb=200):
    port = tg.get("tcp_port") or 0
    if not port:
        return {}
    taskid, tmac = bytes.fromhex(tg["taskid"]), bytes.fromhex(tg["tmac"])
    res = {"down_ok": False, "up_ok": False}
    try:
        s = socket.create_connection((tg["ip"], port), timeout=8)
        s.settimeout(12)
        s.sendall(TCP2.pack(b"TCPC", 2, 0, taskid, tmac, down_kb))
        got, total = 0, down_kb * 1024
        while got < total:
            chunk = s.recv(min(16384, total - got))
            if not chunk:
                break
            got += len(chunk)
        s.close()
        res["down_ok"] = (got == total)
        s = socket.create_connection((tg["ip"], port), timeout=8)
        s.settimeout(12)
        s.sendall(TCP2.pack(b"TCPC", 2, 1, taskid, tmac, up_kb))
        s.sendall(bytes(up_kb * 1024))
        raw = b""
        while len(raw) < 4:
            chunk = s.recv(4 - len(raw))
            if not chunk:
                break
            raw += chunk
        s.close()
        res["up_ok"] = (len(raw) == 4 and struct.unpack("!I", raw)[0] == up_kb * 1024)
    except Exception as e:
        res["error"] = e.__class__.__name__
    return res


def run_task(task):
    results = []
    for tg in task["targets"]:
        say(tr("checking") % tg["code"])
        got, rtt_ms = udp_stream(tg, task["count"], task["size"], task["gap_ms"] / 1000.0, task["wait_s"])
        results.append({"code": tg["code"],
                        "ports": {str(p): {"back": len(got[p]), "ranges": _ranges(got[p])} for p in tg["ports"]},
                        "tcp": tcp_probe(tg), "udp_rtt_ms": rtt_ms, "tcp_connect_ms": tcp_connect_ms(tg)})
    return results


CLS = {k: tr("cls_" + k) for k in ("OK", "INCUT", "OUTCUT", "LOSSY", "NOREPORT")}
ST = {k: tr("st_" + k) for k in ("LOSSY", "OK", "INCUT", "OUTCUT", "PART", "MIXED", "NOREPORT")}


def show(resp):
    say("")
    for t in resp["targets"]:
        place = tr("place_home") if t["kind"] in ("home", "ru") else tr("place_foreign")
        if t.get("community"):
            say(tr("comm_line") % (t["name"], place, ST.get(t["status"], t["status"]), t["tcp"], tr("comm_control") if t.get("control") else tr("comm_noverdict")))
        else:
            say(tr("target_line") % (t["code"], place, ST.get(t["status"], t["status"]), t["tcp"]))
        for p in t["ports"]:
            say(tr("port_line") % (p["port"], "?" if p["reached"] is None else p["reached"], p["back"], CLS.get(p["class"], p["class"])))
    say("")
    say(tr("verdict") + ((resp["verdict"].get("text_en") if LANG_UI == "en" else None) or resp["verdict"]["text"]))
    if resp.get("src_same") in ("different", "mixed"):
        say(tr("warn_src"))
    if resp["verdict"]["code"] == "TUNNEL":
        say(tr("tunnel_hint"))
    say(resp.get("attribution", ""))


def do_round(hub, cfg, task):
    results = run_task(task)
    st, resp = http(hub, "POST", "/api/v2/node/result", {"task": task["task"], "results": results}, token=cfg["token"])
    if st != 200:
        say(tr("hub_rejected") % (st, resp.get("error", "")))
        return None
    show(resp)
    return resp


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="udpcheck-node")
    ap.add_argument("--hub", default=None, help=tr("help_hub") % DEFAULT_HUB)
    ap.add_argument("--config", default=None, help=tr("help_config"))
    ap.add_argument("--once", action="store_true", help=tr("help_once"))
    ap.add_argument("--ref", action="store_true", help=tr("help_ref"))
    ap.add_argument("--role", choices=["node", "ref", "both"], default="node", help=tr("help_role"))
    args = ap.parse_args()
    role = "both" if (args.ref and args.role == "node") else args.role
    path = args.config or cfg_path()
    cfg = load_cfg(path)
    hub = (args.hub or cfg.get("hub") or DEFAULT_HUB).rstrip("/")
    say(tr("banner") % (VERSION, tr("banner_ref") if role == "ref" else tr("banner_node")))
    if not cfg.get("token") or cfg.get("hub") != hub:
        cfg = register(hub, {}, path)
    if args.once:
        st, r = http(hub, "POST", "/api/v2/node/probe-now", token=cfg["token"])
        if st == 401:
            cfg = register(hub, {}, path)
            st, r = http(hub, "POST", "/api/v2/node/probe-now", token=cfg["token"])
        for _ in range(4):
            st, r = http(hub, "POST", "/api/v2/node/poll", token=cfg["token"], timeout=40)
            if st == 200 and r.get("task"):
                do_round(hub, cfg, r["task"])
                return 0
        say(tr("no_task"))
        return 1
    backoff = 5
    say(tr("running") % (cfg.get("callsign", "?"), tr("role_" + role)))
    ref = None
    last_notice = 0
    if role in ("ref", "both"):
        try:
            ref = RefServer(hub, cfg["token"])
            if not ref.start():
                ref = None
        except Exception as e:
            say(tr("ref_not_on") % e.__class__.__name__)
            ref = None
    while True:
        try:
            st, r = http(hub, "POST", "/api/v2/node/poll", {"ref": ref is not None, "role": role, "v": VERSION}, token=cfg["token"], timeout=40)
            if st == 401:
                cfg = register(hub, {}, path)
                if ref:
                    ref.new_token(cfg["token"])
                continue
            if st != 200:
                raise RuntimeError(tr("poll_err") % (st, r.get("error", "")))
            ag = r.get("agent") or {}
            if ag.get("outdated") and time.time() - last_notice > 12 * 3600:
                last_notice = time.time()
                say(tr("outdated") % (ag.get("latest"), VERSION, hub, hub))
            if ref:
                ref.maybe_handshake(r.get("ref_verified"))
            if r.get("task") and role != "ref":
                say(time.strftime(tr("got_task")))
                do_round(hub, cfg, r["task"])
            backoff = 5
        except KeyboardInterrupt:
            say(tr("stopped"))
            return 0
        except Exception as e:
            say(tr("hub_err") % (e.__class__.__name__, backoff))
            time.sleep(backoff)
            backoff = min(backoff * 2, 600)


if __name__ == "__main__":
    sys.exit(main())
