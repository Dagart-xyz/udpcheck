#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
# Выкладка сайта на хаб: ставит метку версии (BUILD) в страницы обоих языков, чтобы открытые вкладки сами обновлялись.
# Сначала соберите сайт (python build_site.py). Запуск из udpcheck-server:  sh ops/deploy_site.sh   (ключ и адрес можно задать через KEY= HUB=)
# Несколько кандидатов в хабы (ops/udpcheck-role): HUBS="root@адрес1 root@адрес2 ..." выкладывает одну и ту же версию на каждый
# (резервные отдают сайт тем, у кого в кэше DNS ещё их адрес).
set -e
KEY="${KEY:-}"; HUB="${HUB:-root@dagart.xyz}"          # KEY: файл ключа SSH (пусто: ключ по умолчанию)
HUBS="${HUBS:-$HUB}"
B="$(date +%Y%m%d-%H%M%S)"
DST=/var/www/udpcheck-site
if [ -n "$KEY" ]; then SSHO="-i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"; else SSHO="-o StrictHostKeyChecking=accept-new"; fi
put() {   # put ЛОКАЛЬНЫЙ_ФАЙЛ ИМЯ_НА_СЕРВЕРЕ
  scp -q $SSHO "$1" "$HUB:$DST/$2"
}
for HUB in $HUBS; do
ssh $SSHO "$HUB" "mkdir -p $DST/en $DST/node"
for f in index.html en/index.html; do
  TMP="$(mktemp)"
  sed "s/__BUILD__/$B/" "site/$f" > "$TMP"
  put "$TMP" "$f"
  rm -f "$TMP"
done
for f in privacy.html terms.html en/privacy.html en/terms.html robots.txt sitemap.xml; do [ -f "site/$f" ] && put "site/$f" "$f"; done
# значки сайта (ops/make_favicon.py) и файл ключа IndexNow (site/<ключ>.txt, ops/indexnow.py)
for f in favicon.ico favicon.svg apple-touch-icon.png $(cd site && ls | grep -E '^[0-9a-f]{32}\.txt$'); do [ -f "site/$f" ] && put "site/$f" "$f"; done
# установщик и агент с подписями (их создаёт build_site.py)
for f in install-node.sh install-node.sh.sig install-node.en.sh install-node.en.sh.sig node/udpcheck_node.py node/udpcheck_node.py.sig node/udpcheck_node.py.sha256; do [ -f "site/$f" ] && put "site/$f" "$f"; done
echo "$HUB: страницы выложены, версия $B"
done
echo "страницы выложены, версия $B"
