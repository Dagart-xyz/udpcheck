#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
# Выкладка сайта на хаб: ставит метку версии (BUILD) в страницу, чтобы открытые вкладки сами обновлялись.
# Запуск из udpcheck-server:  sh ops/deploy_site.sh   (ключ и адрес можно задать через KEY= HUB=)
set -e
KEY="${KEY:-}"; HUB="${HUB:-root@dagart.xyz}"          # KEY: файл ключа SSH (пусто: ключ по умолчанию)
B="$(date +%Y%m%d-%H%M%S)"
TMP="$(mktemp)"
sed "s/__BUILD__/$B/" site/index.html > "$TMP"
put() {   # put ЛОКАЛЬНЫЙ_ФАЙЛ ИМЯ_НА_СЕРВЕРЕ
  if [ -n "$KEY" ]; then scp -q -i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new "$1" "$HUB:/var/www/udpcheck-site/$2"; else scp -q -o StrictHostKeyChecking=accept-new "$1" "$HUB:/var/www/udpcheck-site/$2"; fi
}
put "$TMP" index.html
rm -f "$TMP"
for f in privacy.html terms.html robots.txt; do [ -f "site/$f" ] && put "site/$f" "$f"; done
# установщик и агент с подписями (их создаёт build_site.py)
for f in install-node.sh install-node.sh.sig node/udpcheck_node.py node/udpcheck_node.py.sig node/udpcheck_node.py.sha256; do [ -f "site/$f" ] && put "site/$f" "$f"; done
echo "страница выложена, версия $B"
