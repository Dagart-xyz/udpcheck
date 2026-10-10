#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Замедлитель для роботов: запросы без признаков браузера отвечаются с задержкой и неспешной отдачей, но отвечаются (не блокируются).

Как работает: Caddy направляет сюда запросы, у которых нет ни Accept-Language, ни Sec-Fetch-Mode (браузеры присылают их всегда), и которые не от поисковиков,
превью ссылок и не к служебным адресам (установщик, протокол, robots.txt). Служба ждёт случайное время, затем получает ту же страницу у внутреннего адреса
Caddy и отдаёт её порциями. Живой человек с браузером сюда не попадает. Один поток на всё (asyncio), задержки не занимают потоки хаба.

Две дополнительные роли (их включает Caddy заголовками, см. Caddyfile.dagart):
  X-Probe: 1        запрос похож на атаку (поиск служебных файлов, SQL-инъекции, WordPress и т. п.). Служба пишет в журнал одну строку «PROBE адрес путь»
                    (по ней fail2ban банит повторивших, ops/hardening/fail2ban-probe-*), ждёт и отвечает 404. Страницы не отдаёт.
  X-Claimed-Bot: 1  запрос называет себя поисковым ботом (Google, Bing, Яндекс, Apple). Подлинность проверяется по обратному DNS с подтверждением прямым: настоящий
                    бот проходит без задержки, подделка получает ту же замедленную страницу, что и прочие роботы. Нет ответа от DNS: считаем настоящим (не вредим индексации).

Лимиты, чтобы самому не стать целью: не больше TARPIT_MAX_TOTAL одновременных ожиданий и TARPIT_MAX_PER_IP с одного адреса; сверх лимита запрос
проходит без задержки (не отказ), а лишние параллельные запросы с одного адреса получают 429. Состояния нет, адреса только в памяти; журнал один: строки PROBE (только для запросов, похожих на атаку).
Настройки (переменные окружения): TARPIT_LISTEN=127.0.0.1:18081, TARPIT_UPSTREAM=127.0.0.1:18082, TARPIT_MIN_S=6, TARPIT_MAX_S=15, TARPIT_CHUNK=8192, TARPIT_PAUSE_S=0.4."""
import asyncio
import ipaddress
import json
import os
import random
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

LISTEN = os.environ.get("TARPIT_LISTEN", "127.0.0.1:18081")
UPSTREAM = os.environ.get("TARPIT_UPSTREAM", "127.0.0.1:18082")
MIN_S = float(os.environ.get("TARPIT_MIN_S", "6"))
MAX_S = float(os.environ.get("TARPIT_MAX_S", "15"))
CHUNK = int(os.environ.get("TARPIT_CHUNK", "8192"))
PAUSE_S = float(os.environ.get("TARPIT_PAUSE_S", "0.4"))
MAX_TOTAL = int(os.environ.get("TARPIT_MAX_TOTAL", "300"))
MAX_PER_IP = int(os.environ.get("TARPIT_MAX_PER_IP", "6"))
PROBE_MIN_S = float(os.environ.get("TARPIT_PROBE_MIN_S", "8"))
PROBE_MAX_S = float(os.environ.get("TARPIT_PROBE_MAX_S", "20"))
DNS_TIMEOUT_S = float(os.environ.get("TARPIT_DNS_TIMEOUT_S", "3"))
MAX_REQ_BYTES = 16384
# обратное имя настоящих поисковых ботов (проверка: имя из этого списка и прямой DNS этого имени ведёт на тот же адрес)
BOT_DOMAINS = (".googlebot.com", ".google.com", ".yandex.ru", ".yandex.net", ".yandex.com", ".search.msn.com", ".applebot.apple.com")
# только для тестов: {"адрес": ["обратное имя", ["адреса прямого DNS"]]} вместо настоящего DNS
FAKE_DNS = json.loads(os.environ.get("TARPIT_FAKE_DNS", "null") or "null")

state = {"total": 0, "per_ip": {}}
bot_cache = {}                                               # адрес -> (настоящий ли, до какого времени)
dns_pool = ThreadPoolExecutor(max_workers=4)


def split_hostport(s):
    h, _, p = s.rpartition(":")
    return h, int(p)


def client_ip(headers):
    for line in headers:
        if line.lower().startswith(b"x-forwarded-for:"):
            raw = line.split(b":", 1)[1].split(b",")[-1].strip().decode("ascii", "replace")[:64]
            try:
                return str(ipaddress.ip_address(raw))
            except ValueError:
                return "?"
    return "?"


def has_header(headers, name):
    n = name.lower().encode() + b":"
    return any(line.lower().startswith(n) for line in headers)


def _dns_check(ip):
    """True: адрес настоящего бота; False: нет (имя чужое, нет обратной записи или прямой DNS ведёт не туда); None: DNS не ответил."""
    try:
        if FAKE_DNS is not None:
            if ip not in FAKE_DNS:
                return False
            name, fwd = FAKE_DNS[ip]
        else:
            name = socket.gethostbyaddr(ip)[0]
            fwd = None
        name = name.lower().rstrip(".")
        if not any(name.endswith(d) for d in BOT_DOMAINS):
            return False
        if fwd is None:
            fwd = [a[4][0] for a in socket.getaddrinfo(name, None)]
        want = ipaddress.ip_address(ip)
        return any(ipaddress.ip_address(a) == want for a in fwd)
    except socket.herror:
        return False                                         # обратной записи нет
    except socket.gaierror as e:
        return False if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)) else None
    except (OSError, ValueError):
        return None


async def real_bot(ip):
    now = time.time()
    hit = bot_cache.get(ip)
    if hit and hit[1] > now:
        return hit[0]
    try:
        res = await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(dns_pool, _dns_check, ip), timeout=DNS_TIMEOUT_S)
    except (asyncio.TimeoutError, RuntimeError):
        res = None
    if res is None:                                          # DNS молчит: не наказываем, но и не запоминаем надолго
        bot_cache[ip] = (True, now + 30)
        return True
    if len(bot_cache) > 5000:
        bot_cache.clear()
    bot_cache[ip] = (res, now + 3600)
    return res


def log_probe(ip, request_line):
    path = re.sub(r"[^!-~]", "_", request_line.decode("latin-1", "replace"))[:90]
    print("PROBE %s %s" % (ip, path), flush=True)


async def handle(reader, writer):
    ip = "?"
    held = False
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15)
        if len(head) > MAX_REQ_BYTES:
            return
        lines = head.split(b"\r\n")
        ip = client_ip(lines[1:])
        probe = has_header(lines[1:], "x-probe")
        if probe and ip != "?":
            log_probe(ip, lines[0])                          # до ожидания: учёт нарушителя не зависит от того, дождётся ли он ответа
        n = state["per_ip"].get(ip, 0)
        if n >= MAX_PER_IP:                                  # один адрес держит слишком много ожиданий сразу
            writer.write(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        slow = state["total"] < MAX_TOTAL
        if not probe and slow and ip != "?" and has_header(lines[1:], "x-claimed-bot") and await real_bot(ip):
            slow = False                                     # настоящий поисковик: без задержки
        if slow:
            state["total"] += 1
            state["per_ip"][ip] = n + 1
            held = True
            await asyncio.sleep(random.uniform(PROBE_MIN_S, PROBE_MAX_S) if probe else random.uniform(MIN_S, MAX_S))
        if probe:                                            # страницу не отдаём
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 10\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nnot found\n")
            await writer.drain()
            return
        uh, up = split_hostport(UPSTREAM)
        ur, uw = await asyncio.open_connection(uh, up)
        # тот же запрос к внутреннему адресу Caddy; тело запросов к статике не нужно, соединение одноразовое
        req = re.sub(rb"(?im)^connection:.*\r\n", b"", head)
        req = req.replace(b"\r\n\r\n", b"\r\nConnection: close\r\n\r\n", 1)
        uw.write(req)
        await uw.drain()
        while True:
            data = await asyncio.wait_for(ur.read(CHUNK), timeout=30)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            if slow:
                await asyncio.sleep(PAUSE_S)
        uw.close()
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        if held:
            state["total"] -= 1
            c = state["per_ip"].get(ip, 1) - 1
            if c <= 0:
                state["per_ip"].pop(ip, None)
            else:
                state["per_ip"][ip] = c
        try:
            writer.close()
        except Exception:
            pass


async def main():
    h, p = split_hostport(LISTEN)
    server = await asyncio.start_server(handle, h, p, limit=MAX_REQ_BYTES * 2, backlog=256)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
