# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Собирает файлы сайта: копия агента, установщик с вшитым SHA-256 агента, протокол.
Запуск: python build_site.py   (результат в site/, затем выкладывается на сервер)"""
import hashlib
import os
import sys
import subprocess

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
assert "@@SHA256@@" in tpl and "@@PUBKEY@@" in tpl
pub = open(os.path.join(ROOT, "installer", "release.pub.pem"), encoding="utf-8").read().strip()
open(os.path.join(SITE, "install-node.sh"), "w", encoding="utf-8", newline="\n").write(tpl.replace("@@SHA256@@", sha).replace("@@PUBKEY@@", pub))
# английский установщик (installer/translate_en.py): тот же сценарий, сообщения на английском, адреса /en/i
sys.path.insert(0, os.path.join(ROOT, "installer"))
import translate_en
open(os.path.join(SITE, "install-node.en.sh"), "w", encoding="utf-8", newline="\n").write(translate_en.to_english(tpl).replace("@@SHA256@@", sha).replace("@@PUBKEY@@", pub))

# Подпись выпуска (Ed25519). Закрытый ключ хранится у владельца проекта вне хаба и вне репозитория: UDPCHECK_RELEASE_KEY или ~/.udpcheck-github/release_ed25519.pem.
# Без ключа (например, сборка из чужого форка) подписи не создаются: тогда подставьте свой открытый ключ в installer/release.pub.pem.
KEY = os.environ.get("UDPCHECK_RELEASE_KEY") or os.path.join(os.path.expanduser("~"), ".udpcheck-github", "release_ed25519.pem")
if os.path.exists(KEY):
    for f in (os.path.join(SITE, "node", "udpcheck_node.py"), os.path.join(SITE, "install-node.sh"), os.path.join(SITE, "install-node.en.sh")):
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", KEY, "-rawin", "-in", f, "-out", f + ".sig"], check=True)
    print("подписаны: агент и установщик")
else:
    print("ПРЕДУПРЕЖДЕНИЕ: закрытый ключ выпуска не найден, подписи не созданы (установщик на хабе с подписью откажется ставить агент)")

# страницы на двух языках (шаблон и тексты в siteparts/), карта сайта и robots.txt
sys.path.insert(0, os.path.join(ROOT, "siteparts"))
import pages
pages.build()

open(os.path.join(SITE, "protocol.txt"), "wb").write(lf(open(os.path.join(ROOT, "PROTOCOL.md"), "rb").read()))
print("агент sha256:", sha)
