# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Английская версия установщика: install-node.en.sh собирается из install-node.sh.in таблицей замен (русская строка -> английская).
Сборка строгая: каждая русская строка из таблицы обязана встретиться, а в готовом скрипте не должно остаться кириллицы вне комментариев
(комментарии на русском в английской версии удаляются, заголовок заменяется английским). Выбор языка вывода агента задаётся переменной UDPCHECK_LANG в службе."""
import re

EN_HEADER = """# udpcheck-node: installer of a node for the UDP check network (Linux with systemd, OpenWrt). Source: https://dagart.xyz/en/
#
#   Install (one line for any Linux and OpenWrt router; it picks curl or wget and sudo itself):
#     (curl -fsSL https://dagart.xyz/en/i 2>/dev/null || wget -qO- https://dagart.xyz/en/i) | sh
#   Remove:
#     (curl -fsSL https://dagart.xyz/en/i 2>/dev/null || wget -qO- https://dagart.xyz/en/i) | sh -s -- uninstall
#
# What it does: installs Python 3 (if missing), downloads the agent, verifies its SHA-256 and signature, creates the udpcheck-node service
# that runs as a temporary unprivileged user (systemd DynamicUser). The agent only makes outgoing connections: to the hub over HTTPS
# and to the project's servers over UDP/TCP. No domain or certificate is needed.
# The role is picked automatically: a machine with a public IPv4 (VPS, server) -> ANCHOR SERVER: answers other nodes' checks on the hub's assignments
# (open UDP 47321, 47322 and TCP 47321; the hub checks reachability itself). Home PC, router, machine behind NAT -> NODE: checks your own network.
# Another role: UDPCHECK_ROLE=node|ref|both before sh:  ... | UDPCHECK_ROLE=node sh
# The installer does not touch the firewall, SSH or other services: you open the ports for the anchor role yourself.
"""

PAIRS = [
    ("printf 'Ошибка: %s\\n'", "printf 'Error: %s\\n'"),
    ("# auto | node (проверяет свою сеть) | ref (опорный сервер) | both", "# auto | node (checks its own network) | ref (anchor server) | both"),
    ("# старая переменная: REF=0 означало «только узел»", "# old variable: REF=0 meant \"node only\""),
    ("Подпись агента не проверена (нет openssl с Ed25519): проверена только контрольная сумма.", "The agent signature was not verified (no openssl with Ed25519): only the checksum was verified."),
    ("на хабе нет подписи агента. Установка прервана.", "the hub has no agent signature. Installation aborted."),
    ("Подпись агента проверена.", "Agent signature verified."),
    ("подпись агента не совпала с ключом выпуска. Установка прервана.", "the agent signature does not match the release key. Installation aborted."),
    ("установщик работает только на Linux (на macOS и Windows запустите агент вручную: скачайте ", "the installer works on Linux only (on macOS and Windows run the agent manually: download "),
    (" и выполните python3 udpcheck_node.py)", " and run python3 udpcheck_node.py)"),
    ("Нужны права root: перезапускаю установщик через sudo...", "Root rights are needed: restarting the installer through sudo..."),
    ('fetch "$HUB/install-node.sh" "$SELF" 30 || die "не удалось повторно скачать установщик"', 'fetch "$HUB/install-node.en.sh" "$SELF" 30 || die "could not download the installer again"'),
    ("нужны права root, а sudo не найден. Войдите как root (su -) и повторите ту же команду.", "root rights are needed and sudo was not found. Log in as root (su -) and repeat the same command."),
    ('ROLE_WHY="роль задана вручную"', 'ROLE_WHY="role set manually"'),
    ("неизвестная роль '$ROLE' (допустимо: auto, node, ref, both)", "unknown role '$ROLE' (allowed: auto, node, ref, both)"),
    ("домашняя сеть, роутер или машина за NAT", "home network, router or a machine behind NAT"),
    ("у машины публичный IPv4, это сервер", "the machine has a public IPv4, it is a server"),
    ("# имя таблицы и цепочки у вас может быть другим", "# your table and chain names may differ"),
    ("Хаб не смог достучаться до портов опорного сервера снаружи (нужны UDP 47321, 47322 и TCP 47321).", "The hub could not reach the anchor server's ports from outside (UDP 47321, 47322 and TCP 47321 are needed)."),
    ("на этой машине его никто не слушает (занят другой программой?). Посмотреть: ss -ulnp | grep $p", "nothing listens on it on this machine (taken by another program?). Check: ss -ulnp | grep $p"),
    ("На самой машине включённого фаервола не видно (ufw, firewalld, iptables, nftables).", "No enabled firewall is visible on the machine itself (ufw, firewalld, iptables, nftables)."),
    ("Значит, порты закрыты снаружи: в панели хостера (фаервол или группы безопасности) либо за NAT. Откройте UDP 47321, 47322 и TCP 47321 там,",
     "So the ports are closed from outside: in the hosting panel (firewall or security groups) or behind NAT. Open UDP 47321, 47322 and TCP 47321 there,"),
    ("  затем: systemctl restart $SVC", "  then: systemctl restart $SVC"),
    ("Найден фаервол: $FW. Не открыты, судя по проверке хаба: UDP 47321, UDP 47322, TCP 47321.", "Firewall found: $FW. Not open, judging by the hub's check: UDP 47321, UDP 47322, TCP 47321."),
    ("Чтобы открыть, нужно выполнить:", "To open them, run:"),
    ("Выполнить эти команды сейчас? [y/N] ", "Run these commands now? [y/N] "),
    ("y|Y|д|Д) ;;", "y|Y) ;;"),
    ("Ничего не меняю. Выполните команды сами, затем: systemctl restart $SVC", "Changing nothing. Run the commands yourself, then: systemctl restart $SVC"),
    ("Для nftables сам не открываю: имена таблиц у каждого свои, подставьте их в команды выше и выполните вручную.", "I do not open ports for nftables myself: table names differ everywhere, substitute yours into the commands above and run them manually."),
    ("выполняю: $c", "running: $c"),
    ("не удалось: $c", "failed: $c"),
    ("Правила iptables не переживут перезагрузку, сохраните их (netfilter-persistent save или iptables-save).", "iptables rules do not survive a reboot, save them (netfilter-persistent save or iptables-save)."),
    ("'Опорная роль'", "'Anchor role'"),
    ("Результат проверки пока не вижу: journalctl -u $SVC -n 20", "I do not see the result of the check yet: journalctl -u $SVC -n 20"),
    ("Роль: УЗЕЛ ($ROLE_WHY).", "Role: NODE ($ROLE_WHY)."),
    ("Агент раз в ~15 минут получает от хаба задание, шлёт UDP на опорные серверы и присылает счётчики.", "Every ~15 minutes the agent gets a task from the hub, sends UDP to the anchor servers and reports the counters."),
    ("Хаб видит IP на время запроса и определяет провайдера по ASN. IP в базу не записывается и другим не выдаётся. Открывать порты не нужно.",
     "The hub sees your IP for the duration of the request and identifies the provider by ASN. The IP is not written to the database and is not given to anyone. No ports need to be opened."),
    ("Роль: ОПОРНЫЙ СЕРВЕР ($ROLE_WHY).", "Role: ANCHOR SERVER ($ROLE_WHY)."),
    ("Машина будет отвечать на проверки других узлов по заданиям хаба, сама ничего не проверяет.", "The machine will answer other nodes' checks on the hub's assignments and checks nothing itself."),
    ("Её IP узнают хаб, узлы сети и браузеры посетителей сайта, которых она участвует проверять (как любой STUN-сервер);",
     "Its IP will be known to the hub, the network's nodes and the browsers of site visitors it helps check (like any STUN server);"),
    ("сервер увидит их IP. Трассировки до посетителей ей не передаются.", "the server will see their IPs. Traces to visitors are not passed to it."),
    ("Откройте в фаерволе UDP 47321, 47322 и TCP 47321 (сам фаервол установщик не меняет; если порты окажутся закрыты, он предложит открыть их и спросит согласия), иначе сервер останется неактивным.",
     "Open UDP 47321, 47322 and TCP 47321 in the firewall (the installer does not change the firewall itself; if the ports turn out to be closed, it will offer to open them and ask for your consent), otherwise the server stays inactive."),
    ("Роль: УЗЕЛ И ОПОРНЫЙ СЕРВЕР ($ROLE_WHY).", "Role: NODE AND ANCHOR SERVER ($ROLE_WHY)."),
    ("Агент проверяет вашу сеть и ещё отвечает на проверки других узлов. IP узнают хаб и узлы, которым хаб назначит этот сервер.",
     "The agent checks your network and also answers other nodes' checks. The IP will be known to the hub and to the nodes the hub assigns this server to."),
    ("Откройте в фаерволе UDP 47321, 47322 и TCP 47321 (сам фаервол установщик не меняет; если порты окажутся закрыты, он предложит открыть их и спросит согласия).",
     "Open UDP 47321, 47322 and TCP 47321 in the firewall (the installer does not change the firewall itself; if the ports turn out to be closed, it will offer to open them and ask for your consent)."),
    ("Другая роль: UDPCHECK_ROLE=node, ref или both перед sh.", "Another role: UDPCHECK_ROLE=node, ref or both before sh."),
    ("udpcheck-node: подключение этого роутера к сети проверок UDP (OpenWrt)", "udpcheck-node: connecting this router to the UDP check network (OpenWrt)"),
    ("Будет сделано:", "What will be done:"),
    ("1. через менеджер пакетов OpenWrt (apk или opkg) установлен Python 3 и нужные модули (около 30 МБ на флеш-памяти);",
     "1. Python 3 and the needed modules will be installed through the OpenWrt package manager (apk or opkg), about 30 MB of flash;"),
    ("2. агент скачан с $HUB/node/udpcheck_node.py, проверена контрольная сумма SHA-256;", "2. the agent is downloaded from $HUB/node/udpcheck_node.py and its SHA-256 checksum is verified;"),
    ("3. создана служба udpcheck-node (procd): запускается от пользователя nobody, только исходящие соединения.",
     "3. the udpcheck-node service (procd) is created: it runs as user nobody, outgoing connections only."),
    ("мало места: свободно около $((FREE / 1024)) МБ, нужно хотя бы 40 МБ. Освободите место или подключите USB-накопитель (extroot).",
     "not enough space: about $((FREE / 1024)) MB free, at least 40 MB needed. Free up space or attach a USB drive (extroot)."),
    ("Начало через 5 секунд. Отмена: Ctrl+C.", "Starting in 5 seconds. Cancel: Ctrl+C."),
    ("Обновляю список пакетов и ставлю Python (это может занять несколько минут)...", "Updating the package list and installing Python (this may take a few minutes)..."),
    ("apk update не сработал: проверьте интернет и время на роутере", "apk update failed: check the internet and the time on the router"),
    ("не удалось установить пакеты Python через apk", "could not install the Python packages through apk"),
    ("opkg update не сработал: проверьте интернет и время на роутере", "opkg update failed: check the internet and the time on the router"),
    ("не удалось установить пакеты Python через opkg", "could not install the Python packages through opkg"),
    ("не найден менеджер пакетов (apk или opkg)", "no package manager found (apk or opkg)"),
    ("после установки python3 не найден", "python3 was not found after installation"),
    ("Проверяю доступность хаба...", "Checking that the hub is reachable..."),
    ("хаб $HUB недоступен с роутера (нужен исходящий HTTPS и правильное время на роутере)", "the hub $HUB is unreachable from the router (outgoing HTTPS and the correct time on the router are needed)"),
    ("Скачиваю агент...", "Downloading the agent..."),
    ("не удалось скачать агент", "could not download the agent"),
    ("контрольная сумма агента не совпала (получено $GOT, ожидалось $AGENT_SHA256). Установка прервана.", "the agent checksum does not match (got $GOT, expected $AGENT_SHA256). Installation aborted."),
    ("скачанный файл не является корректным Python", "the downloaded file is not valid Python"),
    ("Служба запущена, жду регистрацию узла...", "Service started, waiting for the node to register..."),
    ("'Позывной'", "'Callsign'"),
    ('say "Готово. $CALL"', 'say "Done. $CALL"'),
    ("Служба запущена, но регистрацию в журнале пока не вижу. Проверьте:", "The service started, but I do not see the registration in the log yet. Check:"),
    ("Статус:     ", "Status:     "),
    ("Журнал:     ", "Log:        "),
    ("Результаты: $HUB (кнопка проверки и таблица провайдеров)", "Results:    $HUB/en/ (the check button and the provider table)"),
    ("Удалить:    (curl -fsSL $HUB/i 2>/dev/null || wget -qO- $HUB/i) | sh -s -- uninstall", "Remove:     (curl -fsSL $HUB/en/i 2>/dev/null || wget -qO- $HUB/en/i) | sh -s -- uninstall"),
    ("Удаляю узел udpcheck (OpenWrt)...", "Removing the udpcheck node (OpenWrt)..."),
    ("Готово: служба, файлы и настройки (включая токен узла) удалены. Пакеты Python остались: удалить можно через apk del python3-light (OpenWrt 25.12+) или opkg remove python3-light.",
     "Done: the service, files and settings (including the node token) are removed. The Python packages stay: remove them with apk del python3-light (OpenWrt 25.12+) or opkg remove python3-light."),
    ("Удаляю узел udpcheck...", "Removing the udpcheck node..."),
    ("Готово: служба, файлы и настройки (включая токен узла) удалены.", "Done: the service, files and settings (including the node token) are removed."),
    ("неизвестное действие '$ACTION' (допустимо: install, uninstall)", "unknown action '$ACTION' (allowed: install, uninstall)"),
    ("сначала поставьте Python: apk add python3; ", "first install Python: apk add python3; "),
    ("systemd не найден. Установщик пока поддерживает только системы с systemd. Запуск вручную: ", "systemd not found. The installer supports only systems with systemd for now. Manual run: "),
    ("нужен curl или wget", "curl or wget is needed"),
    ("udpcheck-node: подключение этого сервера к сети проверок UDP", "udpcheck-node: connecting this server to the UDP check network"),
    ("1. при необходимости установлен python3 (3.7 или новее);", "1. python3 (3.7 or newer) is installed if needed;"),
    ("2. агент скачан с $HUB/node/udpcheck_node.py, проверена контрольная сумма SHA-256, файл положен в $DIR;",
     "2. the agent is downloaded from $HUB/node/udpcheck_node.py, its SHA-256 checksum is verified, the file is put into $DIR;"),
    ("3. создана служба $SVC: временный пользователь без прав, только исходящие соединения.", "3. the $SVC service is created: a temporary unprivileged user, outgoing connections only."),
    ("Python 3.7+ не найден, пробую установить...", "Python 3.7+ not found, trying to install it..."),
    ("не удалось определить менеджер пакетов: установите Python 3.7+ вручную и повторите", "could not detect the package manager: install Python 3.7+ manually and repeat"),
    ("после установки Python 3.7+ всё ещё не найден", "Python 3.7+ is still not found after installation"),
    ("хаб $HUB недоступен с этого сервера (нужен исходящий HTTPS)", "the hub $HUB is unreachable from this server (outgoing HTTPS is needed)"),
    ("нет sha256sum, проверить контрольную сумму нечем", "no sha256sum, nothing to verify the checksum with"),
    ("Description=udpcheck: узел сети проверок UDP", "Description=udpcheck: UDP check network node"),
    ('*"не активна"*', '*"not active"*'),
    ("UDPCHECK_LANG=ru", "UDPCHECK_LANG=en"),
]

CYR = re.compile(r"[А-Яа-яЁё]")


def to_english(src):
    """Исходный (русский) текст установщика -> английский. Бросает AssertionError, если таблица замен разошлась с установщиком."""
    lines = src.split("\n")
    # заголовок: от первой строки «# udpcheck-node: установщик...» до строки перед set -eu
    a = next(i for i, l in enumerate(lines) if l.startswith("# udpcheck-node: установщик"))
    b = next(i for i, l in enumerate(lines) if l.strip() == "set -eu")
    lines[a:b] = EN_HEADER.rstrip("\n").split("\n")
    text = "\n".join(lines)
    for ru, en in sorted(PAIRS, key=lambda p: -len(p[0])):          # длинные строки первыми: одни содержат другие
        assert ru in text, "в установщике нет строки из таблицы замен: %r" % ru[:70]
        text = text.replace(ru, en)
    out = []
    for l in text.split("\n"):
        if CYR.search(l) and l.lstrip().startswith("#"):
            continue                                                      # русский комментарий: в английской версии не нужен
        out.append(l)
    text = "\n".join(out)
    left = [l for l in text.split("\n") if CYR.search(l)]
    assert not left, "в английском установщике осталась кириллица: %r" % left[:3]
    return text
