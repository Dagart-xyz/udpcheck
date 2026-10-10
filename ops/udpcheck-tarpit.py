#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Замедлитель для роботов: запросы без признаков браузера отвечаются с задержкой и неспешной отдачей, но отвечаются (не блокируются).

Как работает: Caddy направляет сюда запросы, у которых нет ни Accept-Language, ни Sec-Fetch-Mode (браузеры присылают их всегда), и которые не от поисковиков,
превью ссылок и не к служебным адресам (установщик, протокол, robots.txt). Служба ждёт случайное время, затем получает ту же страницу у внутреннего адреса
Caddy и отдаёт её порциями. Живой человек с браузером сюда не попадает. Один поток на всё (asyncio), задержки не занимают потоки хаба.

Лимиты, чтобы самому не стать целью: не больше TARPIT_MAX_TOTAL одновременных ожиданий и TARPIT_MAX_PER_IP с одного адреса; сверх лимита запрос
проходит без задержки (не отказ), а лишние параллельные запросы с одного адреса получают 429. Состояния и журналов нет: адреса только в памяти.
Настройки (переменные окружения): TARPIT_LISTEN=127.0.0.1:18081, TARPIT_UPSTREAM=127.0.0.1:18082, TARPIT_MIN_S=6, TARPIT_MAX_S=15, TARPIT_CHUNK=8192, TARPIT_PAUSE_S=0.4."""
import asyncio
import os
import random
import re
import sys

LISTEN = os.environ.get("TARPIT_LISTEN", "127.0.0.1:18081")
UPSTREAM = os.environ.get("TARPIT_UPSTREAM", "127.0.0.1:18082")
MIN_S = float(os.environ.get("TARPIT_MIN_S", "6"))
MAX_S = float(os.environ.get("TARPIT_MAX_S", "15"))
CHUNK = int(os.environ.get("TARPIT_CHUNK", "8192"))
PAUSE_S = float(os.environ.get("TARPIT_PAUSE_S", "0.4"))
MAX_TOTAL = int(os.environ.get("TARPIT_MAX_TOTAL", "300"))
MAX_PER_IP = int(os.environ.get("TARPIT_MAX_PER_IP", "6"))
MAX_REQ_BYTES = 16384

state = {"total": 0, "per_ip": {}}


def split_hostport(s):
    h, _, p = s.rpartition(":")
    return h, int(p)


def client_ip(headers):
    for line in headers:
        if line.lower().startswith(b"x-forwarded-for:"):
            return line.split(b":", 1)[1].split(b",")[-1].strip().decode("ascii", "replace")[:64]
    return "?"


async def handle(reader, writer):
    ip = "?"
    held = False
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15)
        if len(head) > MAX_REQ_BYTES:
            return
        lines = head.split(b"\r\n")
        ip = client_ip(lines[1:])
        n = state["per_ip"].get(ip, 0)
        if n >= MAX_PER_IP:                                  # один адрес держит слишком много ожиданий сразу
            writer.write(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        slow = state["total"] < MAX_TOTAL
        if slow:
            state["total"] += 1
            state["per_ip"][ip] = n + 1
            held = True
            await asyncio.sleep(random.uniform(MIN_S, MAX_S))
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
