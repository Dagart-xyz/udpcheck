#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
# udpcheck-diag: сбор данных, почему опорный сервер не отвечает посетителям. Только читает, ничего не меняет и никуда не отправляет.
# Запуск от root:   sh diag.sh [секунд записи, по умолчанию 120]
#   или:            (curl -fsSL https://dagart.xyz/diag.sh 2>/dev/null || wget -qO- https://dagart.xyz/diag.sh) | sh
# Результат печатается на экран и пишется в /tmp/udpcheck-diag-<дата>.txt. Адреса IPv4 в отчёте обрезаны до первых двух чисел
# (95.24.x.x), паролей, ключей и настроек VPN там нет. Перед отправкой отчёт можно прочитать.
SECS="${1:-120}"
OUT="/tmp/udpcheck-diag-$(date +%Y%m%d-%H%M).txt"
PORTS="47321 47322"

mask() { sed -E 's/([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}/\1.\2.x.x/g'; }
sec() { printf '\n===== %s =====\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "Запустите от root (sudo sh diag.sh)"; exit 1; }

{
echo "udpcheck-diag, $(date '+%Y-%m-%d %H:%M:%S %Z'), запись трафика $SECS с"
sec "Система"
uname -sr
. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"

sec "Агент udpcheck-node"
if command -v systemctl >/dev/null 2>&1; then
  echo "служба: $(systemctl is-active udpcheck-node 2>&1)"
  systemctl cat udpcheck-node 2>/dev/null | grep -E '^ExecStart=|^TasksMax=|^MemoryMax=' | sed 's/--config .*//'
fi
grep -m1 '^VERSION' /opt/udpcheck-node/udpcheck_node.py 2>/dev/null | sed 's/^/версия агента: /'
echo "(версия агента должна быть 0.4 или новее: раньше агент не отвечал на STUN)"
echo "--- последние строки журнала агента:"
journalctl -u udpcheck-node --no-pager -n 40 -o cat 2>/dev/null | cut -c1-220 | tail -40

sec "Кто слушает порты (все UDP и TCP)"
if command -v ss >/dev/null 2>&1; then
  echo "--- наши порты ($PORTS):"
  ss -ulnp 2>/dev/null | grep -E ":(47321|47322) " || echo "UDP 47321/47322: никто не слушает!"
  ss -tlnp 2>/dev/null | grep -E ":47321 " || echo "TCP 47321: никто не слушает"
  echo "--- всё остальное, что слушает (только имена программ и порты):"
  ss -tulnpH 2>/dev/null | awk '{print $1, $5, $7}' | sed -E 's/users:\(\("([^"]*)".*/\1/' | sort | uniq | head -40
fi

sec "Самопроверка STUN на самом сервере (127.0.0.1)"
python3 - <<'PY' 2>&1
import os, socket, struct
cookie = bytes((0x21, 0x12, 0xA4, 0x42))
for p in (47321, 47322):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.5)
    try:
        s.sendto(struct.pack("!HH", 1, 0) + cookie + os.urandom(12), ("127.0.0.1", p))
        s.recvfrom(2048); print("порт %d: агент отвечает" % p)
    except Exception as e:
        print("порт %d: ответа нет (%s)" % (p, e.__class__.__name__))
PY

sec "Фаервол на машине"
command -v ufw >/dev/null 2>&1 && { echo "--- ufw:"; ufw status verbose 2>&1 | head -30; }
command -v firewall-cmd >/dev/null 2>&1 && { echo "--- firewalld:"; firewall-cmd --state 2>&1; firewall-cmd --list-all 2>&1 | head -20; }
if command -v iptables >/dev/null 2>&1; then
  echo "--- iptables INPUT (счётчики пакетов):"
  iptables -S INPUT 2>&1 | head -15
  iptables -L INPUT -n -v --line-numbers 2>&1 | head -30
fi
if command -v nft >/dev/null 2>&1; then
  echo "--- nftables (первые 80 строк):"
  nft list ruleset 2>&1 | head -80
fi
for s in fail2ban crowdsec crowdsec-firewall-bouncer; do
  systemctl is-active "$s" >/dev/null 2>&1 && echo "активна служба: $s (может банить адреса по UDP/TCP)"
done

sec "Сеть"
ip -4 -br addr 2>/dev/null | head -8
ip route show default 2>/dev/null
echo "rp_filter all=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null) default=$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null)"
echo "conntrack: $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)/$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
} 2>&1 | mask | tee "$OUT"

# ---- запись трафика: доходят ли пакеты до сервера и уходят ли ответы
{
sec "Запись трафика на портах UDP 47321 и 47322 ($SECS с)"
if ! command -v tcpdump >/dev/null 2>&1; then
  echo "tcpdump не установлен: поставьте (apt-get install -y tcpdump или yum/dnf install tcpdump) и запустите скрипт ещё раз."
else
  echo ">>> СЕЙЧАС идёт запись. Откройте https://dagart.xyz с телефона на мобильном интернете и/или с Wi-Fi российского провайдера"
  echo ">>> и нажмите «Проверить мою сеть» 2-3 раза, пока идёт запись." >&2
  CAP="/tmp/udpcheck-diag-cap.$$"
  timeout "$SECS" tcpdump -nn -l -i any "udp and (port 47321 or port 47322)" 2>/dev/null > "$CAP"
  TOTAL_IN=$(grep -c ' In ' "$CAP"); TOTAL_OUT=$(grep -c ' Out ' "$CAP")
  echo "пакетов пришло на сервер: $TOTAL_IN, ответов отправил сервер: $TOTAL_OUT"
  echo "--- кто присылал (первые два числа адреса, число пакетов):"
  awk '{d="";for(i=1;i<=NF;i++){if($i=="In"||$i=="Out")d=$i;if($i=="IP"){s=$(i+1);break}} sub(/\.[0-9]+$/,"",s); if(d=="In")print s}' "$CAP" | sed -E 's/^([0-9]+\.[0-9]+)\..*/\1.x.x/' | sort | uniq -c | sort -rn | head -25
  echo "--- кому отвечал сервер:"
  awk '{d="";for(i=1;i<=NF;i++){if($i=="In"||$i=="Out")d=$i;if($i=="IP"){t=$(i+3);break}} sub(/:$/,"",t); sub(/\.[0-9]+$/,"",t); if(d=="Out")print t}' "$CAP" | sed -E 's/^([0-9]+\.[0-9]+)\..*/\1.x.x/' | sort | uniq -c | sort -rn | head -25
  rm -f "$CAP"
  echo
  echo "Как читать: пакеты пришли, а ответов нет -> проблема на самом сервере (агент или фаервол)."
  echo "            пакетов от российских адресов нет совсем -> их режут по дороге (адрес сервера в блоклисте у провайдеров)."
fi
} 2>&1 | mask | tee -a "$OUT"
echo
echo "Готово. Отчёт: $OUT"
