# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Добавление зарубежной (или российской) цели в сеть узлов: ставит сервис на сервер, регистрирует цель на хабе.
Домен и Caddy не нужны. Секрет цели генерируется здесь и в вывод не попадает.

Пример:
  python add_target.py --code PAR1-FR --name "Франция, Париж" --country FR --host 203.0.113.10 --key target
Что делает: ставит traceroute (если нет), кладёт файлы сервиса, секрет цели, юнит (базы GeoIP цели не нужны: сети по хопам определяет хаб); запрещает вход по паролю
(только ключи); дописывает цель в /etc/udpcheck/targets.json на хабе и перезапускает хаб.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

PROJ = os.path.dirname(os.path.abspath(__file__))
# ключи SSH задаются переменными окружения (пусто: ключ по умолчанию из ssh-agent или ~/.ssh)
KEYS = {"target": os.environ.get("UDPCHECK_KEY_TARGET", ""), "hub": os.environ.get("UDPCHECK_KEY_HUB", "")}
HUB_HOST = os.environ.get("UDPCHECK_HUB_HOST", "dagart.xyz")
PORTS = [993, 777, 47321]
TCP_PORT = 8443

ap = argparse.ArgumentParser()
ap.add_argument("--code", required=True)
ap.add_argument("--name", required=True)
ap.add_argument("--country", required=True, help="код страны сервера (RU, FR, FI...): для посетителей и узлов этой страны он «своя страна»")
ap.add_argument("--host", required=True, help="адрес для SSH (он же адрес цели)")
ap.add_argument("--key", choices=list(KEYS), default="target", help="какой ключ использовать для нового сервера")
args = ap.parse_args()


def ssh_args(key):
    base = ["-i", KEYS[key], "-o", "IdentitiesOnly=yes"] if KEYS[key] else []
    return base + ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]


def ssh(host, key, cmd, data=None, check=True):
    r = subprocess.run(["ssh"] + ssh_args(key) + ["root@" + host, cmd], input=data, capture_output=True)
    out = (r.stdout + r.stderr).decode("utf-8", "replace")
    if check and r.returncode != 0:
        sys.exit("ошибка на %s: %s" % (host, out[-600:]))
    return out


def scp(host, key, local, remote):
    r = subprocess.run(["scp"] + ssh_args(key) + [local, "root@%s:%s" % (host, remote)], capture_output=True)
    if r.returncode != 0:
        sys.exit("scp %s: %s" % (local, r.stderr.decode(errors="replace")))


secret = os.urandom(32).hex()
print("1. подготовка сервера (пакеты, каталоги)")
print(ssh(args.host, args.key, "set -e; export DEBIAN_FRONTEND=noninteractive; "
          "if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq traceroute python3 ca-certificates >/dev/null; "
          "elif command -v dnf >/dev/null 2>&1; then dnf install -y -q traceroute python3 ca-certificates; fi; "
          "mkdir -p /opt/udpcheck/geo /etc/udpcheck /root/stage-v2; command -v traceroute python3").strip())

print("2. файлы сервиса")
for f in ("udpcheck_server.py", "udpcheck_v2.py", "udpcheck.service"):
    scp(args.host, args.key, os.path.join(PROJ, f), "/root/stage-v2/" + f)
print(ssh(args.host, args.key, "cd /root/stage-v2 && sed -i 's/\\r$//' udpcheck_server.py udpcheck_v2.py udpcheck.service && "
          "python3 -m py_compile udpcheck_server.py udpcheck_v2.py && rm -rf __pycache__ && "
          "install -m 644 udpcheck_server.py udpcheck_v2.py /opt/udpcheck/ && install -m 644 udpcheck.service /etc/systemd/system/udpcheck.service && echo ok").strip())

print("3. секрет цели и запуск")
env = ("UDPCHECK_TARGET_ID=%s\nUDPCHECK_TARGET_SECRET=%s\nUDPCHECK_HUB_URL=https://%s/udpcheck\nUDPCHECK_TARGET_TCP_PORT=%d\n"
       % (args.code, secret, HUB_HOST, TCP_PORT))
print(ssh(args.host, args.key, "umask 077; cat > /etc/udpcheck/target.env && chmod 600 /etc/udpcheck/target.env && "
          "systemctl daemon-reload && systemctl enable udpcheck >/dev/null 2>&1; systemctl restart udpcheck; sleep 3; systemctl is-active udpcheck", env.encode()).strip())

print("4. вход только по ключам")
print(ssh(args.host, args.key, "set -e; test -s /root/.ssh/authorized_keys; mkdir -p /run/sshd /etc/ssh/sshd_config.d; "
          "printf 'PasswordAuthentication no\\nPermitRootLogin prohibit-password\\n' > /etc/ssh/sshd_config.d/00-keys-only.conf; "
          "sshd -t && systemctl reload ssh; sshd -T | grep -Ei '^(passwordauthentication|permitrootlogin)'").strip())

print("5. регистрация цели на хабе")
cur = json.loads(ssh(HUB_HOST, "hub", "cat /etc/udpcheck/targets.json"))
cur = [t for t in cur if t["code"] != args.code]
cur.append({"code": args.code, "name": args.name, "country": args.country.upper(), "ip": args.host, "ports": PORTS, "secret": secret, "tcp_port": TCP_PORT})
ssh(HUB_HOST, "hub", "umask 077; cat > /etc/udpcheck/targets.json && chmod 600 /etc/udpcheck/targets.json && systemctl restart udpcheck && sleep 3 && systemctl is-active udpcheck",
    json.dumps(cur, ensure_ascii=False).encode("utf-8"))
print("   цель %s добавлена, всего целей: %d, хаб перезапущен" % (args.code, len(cur)))
