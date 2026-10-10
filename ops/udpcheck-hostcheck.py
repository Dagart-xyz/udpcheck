#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Состояние самого сервера для наблюдателя: нужна ли перезагрузка, есть ли неустановленные обновления безопасности, сколько банов
выдал fail2ban за час, с каких адресов входили по SSH. Пишет /run/udpcheck-host.json (рядом с рабочим процессом, он читает файл
и передаёт хабу в своём подписанном опросе). Запуск от root раз в 5 минут (udpcheck-hostcheck.timer), ничего не меняет в системе."""
import ipaddress
import json
import os
import re
import subprocess
import time

OUT = os.environ.get("UDPCHECK_HOST_FILE", "/run/udpcheck-host.json")
REBOOT_FLAG = "/var/run/reboot-required"


def run(cmd, timeout=40):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def security_updates():
    """Сколько пакетов из обновлений безопасности ждут установки (-1: не удалось узнать)."""
    out = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"])
    if not out:
        return -1
    return sum(1 for ln in out.splitlines() if ln.startswith("Inst ") and re.search(r"-security|Debian-Security|Ubuntu:[^ ]*/[^ ]*-security", ln))


def ssh_logins(window_min=12):
    """Различные адреса успешных входов по ключу за последние минуты."""
    out = run(["journalctl", "-u", "ssh", "-u", "sshd", "--since", "-%dmin" % window_min, "--no-pager", "-o", "cat"])
    ips = []
    for ln in out.splitlines():
        m = re.search(r"Accepted \w+ for \S+ from (\S+) port", ln)
        if m:
            try:
                ip = str(ipaddress.ip_address(m.group(1)))
            except ValueError:
                continue
            if ip not in ips:
                ips.append(ip)
    return ips[:10]


def bans_last_hour():
    out = run(["journalctl", "-u", "fail2ban", "--since", "-1h", "--no-pager", "-o", "cat"])
    return sum(1 for ln in out.splitlines() if re.search(r"\] Ban \S+", ln))


def main():
    now = int(time.time())
    reboot = os.path.exists(REBOOT_FLAG)
    try:
        since = int(os.stat(REBOOT_FLAG).st_mtime) if reboot else 0
        up = int(float(open("/proc/uptime").read().split()[0]))
    except (OSError, ValueError):
        since, up = 0, 0
    info = {"ts": now, "reboot": reboot, "reboot_since": since, "sec_updates": security_updates(), "uptime_s": up,
            "bans_1h": bans_last_hour(), "ssh_ips": ssh_logins()}
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(info, fh)
    os.chmod(tmp, 0o644)
    os.replace(tmp, OUT)


if __name__ == "__main__":
    main()
