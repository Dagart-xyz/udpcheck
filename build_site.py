# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Собирает файлы сайта: копия агента, установщик с вшитым SHA-256 агента, протокол.
Запуск: python build_site.py   (результат в site/, затем выкладывается на сервер)"""
import hashlib
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
SITE = os.path.join(ROOT, "site")


def lf(data):
    return data.replace(b"\r\n", b"\n")


os.makedirs(os.path.join(SITE, "node"), exist_ok=True)
agent = lf(open(os.path.join(ROOT, "udpcheck_node.py"), "rb").read())
open(os.path.join(SITE, "node", "udpcheck_node.py"), "wb").write(agent)
sha = hashlib.sha256(agent).hexdigest()
open(os.path.join(SITE, "node", "udpcheck_node.py.sha256"), "w", newline="\n").write(sha + "\n")

tpl = lf(open(os.path.join(ROOT, "installer", "install-node.sh.in"), "rb").read()).decode("utf-8")
assert "@@SHA256@@" in tpl
open(os.path.join(SITE, "install-node.sh"), "w", encoding="utf-8", newline="\n").write(tpl.replace("@@SHA256@@", sha))

open(os.path.join(SITE, "protocol.txt"), "wb").write(lf(open(os.path.join(ROOT, "PROTOCOL.md"), "rb").read()))
print("агент sha256:", sha)
