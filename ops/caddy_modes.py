#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Две конфигурации Caddy для кандидата в хабы (ops/udpcheck-role переключает их при смене роли):
  Caddyfile.hub      как есть: API идёт в хаб (127.0.0.1:18080);
  Caddyfile.standby  то же самое, но блок (hub) вместо прокси в хаб отвечает 503 «хаб переезжает» с Retry-After. Сайт, защита и замедлитель
                     роботов работают одинаково: так посетитель, у которого в кэше DNS ещё адрес резервного сервера, видит страницу, а не ошибку.
                     Сертификаты в этом режиме берутся готовыми из /etc/caddy/standby-certs (их кладёт udpcheck-restore из копии хаба):
                     резервный сервер не пытается выпускать свои. Его проверки не прошли бы (DNS указывает на хаб), а неудачи по одному имени
                     у Let's Encrypt ограничены, и учётная запись у кандидатов общая: резерв мог бы помешать хабу продлить сертификат.
Запуск:  python3 caddy_modes.py /etc/caddy/Caddyfile.dagart /etc/caddy   (пишет Caddyfile.hub и Caddyfile.standby в указанный каталог)
"""
import os
import re
import sys

STANDBY_HUB = """(hub) {
	# резервный сервер: хаб сейчас работает на другом, у посетителя в кэше DNS ещё этот адрес
	header Retry-After 300
	header Content-Type "application/json; charset=utf-8"
	respond `{"error": "хаб переезжает на другой сервер, повторите через несколько минут", "standby": true}` 503
}
"""


def hub_block(text):
    """(начало, конец) блока «(hub) {...}» в тексте: от строки с «(hub) {» до парной закрывающей скобки включительно."""
    lines = text.splitlines(keepends=True)
    starts = [i for i, l in enumerate(lines) if l.strip() == "(hub) {"]
    if len(starts) != 1:
        raise ValueError("ожидался ровно один блок «(hub) {», найдено %d" % len(starts))
    depth, i = 0, starts[0]
    for j in range(i, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        if depth == 0:
            return sum(len(l) for l in lines[:i]), sum(len(l) for l in lines[:j + 1])
    raise ValueError("блок (hub) не закрыт")


CERT_DIR = "/etc/caddy/standby-certs"
SITE = re.compile(r"^([a-z0-9-]+(?:\.[a-z0-9-]+)+) \{\s*$")


def standby(text):
    a, b = hub_block(text)
    out = []
    for line in (text[:a] + STANDBY_HUB + text[b:]).splitlines(keepends=True):
        out.append(line)
        m = SITE.match(line)
        if m:                     # блок сайта по имени (dagart.xyz, www...): готовый сертификат вместо автоматического выпуска
            out.append("\ttls %s/%s.crt %s/%s.key\n" % (CERT_DIR, m.group(1), CERT_DIR, m.group(1)))
    return "".join(out)


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        text = fh.read()
    out = {"Caddyfile.hub": text, "Caddyfile.standby": standby(text)}
    for name, body in out.items():
        with open(os.path.join(argv[2], name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
    print("записаны Caddyfile.hub и Caddyfile.standby в %s" % argv[2])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
