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
if [ -n "$KEY" ]; then scp -q -i "$KEY" -o IdentitiesOnly=yes "$TMP" "$HUB:/var/www/udpcheck-site/index.html"; else scp -q "$TMP" "$HUB:/var/www/udpcheck-site/index.html"; fi
rm -f "$TMP"
echo "страница выложена, версия $B"
