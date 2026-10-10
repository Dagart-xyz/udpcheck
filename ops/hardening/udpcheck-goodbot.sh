#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
# fail2ban ignorecommand: код 0 = «не банить». Настоящих поисковых ботов не баним: обратное имя адреса должно быть у Google, Яндекса, Bing или Apple,
# а прямой DNS этого имени должен вести обратно на тот же адрес (подделать обратную запись чужого адреса нельзя).
ip="$1"
name=$(getent hosts "$ip" | awk '{print $2; exit}')
name=${name,,}; name=${name%.}
case "$name" in
  *.googlebot.com|*.google.com|*.yandex.ru|*.yandex.net|*.yandex.com|*.search.msn.com|*.applebot.apple.com) ;;
  *) exit 1 ;;
esac
getent ahosts "$name" | awk '{print $1}' | grep -qxF "$ip" && exit 0
exit 1
