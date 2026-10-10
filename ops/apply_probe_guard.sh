#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
# Включает на хабе защиту от сканеров: запросы-атаки -> замедлитель (404 + строка PROBE) -> fail2ban (джейл udpcheck-probe) и проверку поддельных поисковиков.
# Файлы заранее лежат в /tmp: Caddyfile.new, udpcheck-tarpit.py.new, udpcheck-tarpit.service.new, fail2ban-probe-filter.conf, fail2ban-probe.local, udpcheck-goodbot.sh.
# IGNORE: адреса, которые никогда не банятся (серверы сети, администратор). Запуск:  IGNORE="192.0.2.1 192.0.2.2" sh apply_probe_guard.sh
# Откат: cp /etc/caddy/Caddyfile.bak-probe /etc/caddy/Caddyfile; systemctl reload caddy; rm /etc/fail2ban/jail.d/udpcheck-probe.local; fail2ban-client reload
set -eu
[ -n "${IGNORE:-}" ] || { echo "Задайте IGNORE=\"адреса через пробел\""; exit 1; }
cd /tmp
caddy validate --config /tmp/Caddyfile.new --adapter caddyfile >/dev/null 2>&1 || { echo "Caddyfile не прошёл проверку"; exit 1; }
cp -p /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak-probe
cp -p /opt/udpcheck/udpcheck-tarpit.py /opt/udpcheck/udpcheck-tarpit.py.prev
cp -p /etc/systemd/system/udpcheck-tarpit.service /root/udpcheck-tarpit.service.prev

# 1. замедлитель
install -m 644 /tmp/udpcheck-tarpit.py.new /opt/udpcheck/udpcheck-tarpit.py
install -m 644 /tmp/udpcheck-tarpit.service.new /etc/systemd/system/udpcheck-tarpit.service
systemctl daemon-reload
systemctl restart udpcheck-tarpit
sleep 1
systemctl is-active --quiet udpcheck-tarpit || { echo "замедлитель не запустился, откат"; cp -p /opt/udpcheck/udpcheck-tarpit.py.prev /opt/udpcheck/udpcheck-tarpit.py; cp -p /root/udpcheck-tarpit.service.prev /etc/systemd/system/udpcheck-tarpit.service; systemctl daemon-reload; systemctl restart udpcheck-tarpit; exit 1; }
echo "замедлитель: active"

# 2. fail2ban (до Caddy: к моменту первых PROBE правило уже работает)
install -m 644 /tmp/fail2ban-probe-filter.conf /etc/fail2ban/filter.d/udpcheck-probe.conf
install -m 755 /tmp/udpcheck-goodbot.sh /etc/fail2ban/udpcheck-goodbot.sh
install -m 644 /tmp/fail2ban-probe.local /etc/fail2ban/jail.d/udpcheck-probe.local
sed -i "s|^ignoreip = .*|ignoreip = 127.0.0.1/8 ::1 $IGNORE|" /etc/fail2ban/jail.d/udpcheck-probe.local
if fail2ban-client -t >/dev/null 2>&1; then
  fail2ban-client reload >/dev/null 2>&1
  sleep 2
  fail2ban-client status udpcheck-probe >/dev/null 2>&1 && fail2ban-client status sshd >/dev/null 2>&1 && echo "fail2ban: udpcheck-probe и sshd работают" || { echo "fail2ban: джейл не поднялся, убираю"; rm -f /etc/fail2ban/jail.d/udpcheck-probe.local; fail2ban-client reload >/dev/null 2>&1; exit 1; }
else
  echo "fail2ban: конфигурация не прошла проверку, убираю"; rm -f /etc/fail2ban/jail.d/udpcheck-probe.local; exit 1
fi

# 3. Caddy
install -m 644 /tmp/Caddyfile.new /etc/caddy/Caddyfile
if systemctl reload caddy; then echo "Caddy: перезагружен"; else echo "Caddy не принял, откат"; cp -p /etc/caddy/Caddyfile.bak-probe /etc/caddy/Caddyfile; systemctl reload caddy; exit 1; fi
sleep 2
echo "сайт: $(curl -s -o /dev/null -w '%{http_code}' https://dagart.xyz/) API: $(curl -s -o /dev/null -w '%{http_code}' https://dagart.xyz/api/v2/health)"
