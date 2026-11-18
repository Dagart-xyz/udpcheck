#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Адреса входов по SSH в ops/udpcheck-hostcheck.py: какие попадают к наблюдателю (тревога «вход с нового адреса»).
UDPCHECK_SSH_QUIET_USERS — служебные учётки без оболочки, которые входят с меняющихся адресов; их входы не считаются.
journalctl подменён. Запуск: python tests/test_hostcheck_local.py"""
import importlib.machinery
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:400]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


loader = importlib.machinery.SourceFileLoader("hostcheck", os.path.join(HERE, "..", "ops", "udpcheck-hostcheck.py"))
spec = importlib.util.spec_from_loader("hostcheck", loader)
H = importlib.util.module_from_spec(spec)
loader.exec_module(H)

JOURNAL = {"text": ""}
CALLS = []


def fake_run(cmd, timeout=40):
    CALLS.append(cmd)
    return JOURNAL["text"]


H.run = fake_run


def logins(lines, quiet=None):
    JOURNAL["text"] = "\n".join(lines) + "\n"
    if quiet is None:
        os.environ.pop("UDPCHECK_SSH_QUIET_USERS", None)
    else:
        os.environ["UDPCHECK_SSH_QUIET_USERS"] = quiet
    return H.ssh_logins()


ROOT = "Accepted publickey for root from 198.51.100.7 port 1127 ssh2: ED25519 SHA256:aaaa"
SVC = "Accepted publickey for svc from 203.0.113.5 port 21013 ssh2: ED25519 SHA256:bbbb"
SVC2 = "Accepted publickey for svc from 203.0.113.6 port 3061 ssh2: ED25519 SHA256:bbbb"
OTHER = "Accepted publickey for deploy from 192.0.2.10 port 4000 ssh2: ED25519 SHA256:cccc"
NOISE = ["pam_unix(sshd:session): session opened for user svc(uid=999) by svc(uid=0)",
         "Connection closed by authenticating user root 192.0.2.99 port 5555 [preauth]",
         "Failed publickey for root from 192.0.2.98 port 6666 ssh2"]

print("Без настройки — как раньше: все успешные входы")
check("переменная не задана: root, svc и deploy", logins([ROOT, SVC, OTHER] + NOISE) == ["198.51.100.7", "203.0.113.5", "192.0.2.10"],
      logins([ROOT, SVC, OTHER] + NOISE))
check("переменная пустая: то же", logins([ROOT, SVC], "") == ["198.51.100.7", "203.0.113.5"], logins([ROOT, SVC], ""))
check("неудачные и закрытые до входа не считаются", logins(NOISE) == [], logins(NOISE))
check("журнал читается за 12 минут по ssh и sshd",
      CALLS and CALLS[-1] == ["journalctl", "-u", "ssh", "-u", "sshd", "--since", "-12min", "--no-pager", "-o", "cat"], CALLS[-1:])

print("Тихие учётки")
check("svc тихий: его адреса пропущены, root и deploy остались", logins([ROOT, SVC, SVC2, OTHER], "svc") == ["198.51.100.7", "192.0.2.10"],
      logins([ROOT, SVC, SVC2, OTHER], "svc"))
check("несколько через запятую и пробелы", logins([ROOT, SVC, OTHER], " deploy,  svc ") == ["198.51.100.7"], logins([ROOT, SVC, OTHER], " deploy,  svc "))
check("только точное имя: «sv» не глушит svc", logins([SVC], "sv") == ["203.0.113.5"], logins([SVC], "sv"))
check("регистр важен: «Svc» не глушит svc", logins([SVC], "Svc") == ["203.0.113.5"], logins([SVC], "Svc"))
check("любой способ входа тихой учётки пропущен (password тоже)",
      logins([SVC.replace("publickey", "password")], "svc") == [], logins([SVC.replace("publickey", "password")], "svc"))
check("root заглушить нельзя: «root» в списке игнорируется", logins([ROOT, SVC], "root,svc") == ["198.51.100.7"], logins([ROOT, SVC], "root,svc"))
check("адрес, с которого входил и root, и тихая учётка, остаётся",
      logins([SVC, ROOT.replace("198.51.100.7", "203.0.113.5")], "svc") == ["203.0.113.5"],
      logins([SVC, ROOT.replace("198.51.100.7", "203.0.113.5")], "svc"))
check("IPv6 и повторы: адрес один раз", logins([ROOT.replace("198.51.100.7", "2001:db8::1")] * 3, "svc") == ["2001:db8::1"],
      logins([ROOT.replace("198.51.100.7", "2001:db8::1")] * 3, "svc"))
check("не больше 10 адресов", len(logins([ROOT.replace("198.51.100.7", "192.0.2.%d" % i) for i in range(1, 20)], "svc")) == 10)

print()
print("ИТОГ: %s (%d ошибок)" % ("ВСЁ OK" if not fails else "ЕСТЬ ОШИБКИ", fails))
sys.exit(1 if fails else 0)
