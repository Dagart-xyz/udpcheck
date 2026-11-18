#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Адреса хаба по умолчанию нет: агент и установщик без UDPCHECK_HUB (или --hub) не запускаются, удаление узла работает без адреса.
Сеть не нужна: агенту подставлен несуществующий прокси, установщик останавливается до первого запроса.
Установщик запускается через sh (на Windows — sh из Git for Windows); без sh эти проверки считаются ошибкой.
Запуск: python tests/test_nohub_local.py"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "installer"))
import translate_en  # noqa: E402

fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:400]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


def clean_env(**extra):
    e = {k: v for k, v in os.environ.items() if not k.startswith("UDPCHECK_")}
    # если агент всё-таки полезет в сеть, запрос упрётся в закрытый локальный порт, а не уйдёт к чужому хабу
    e.update({"HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
              "http_proxy": "http://127.0.0.1:9", "NO_PROXY": "", "no_proxy": "", "PYTHONUTF8": "1", "UDPCHECK_LANG": "ru"})
    e.update(extra)
    return e


def run_agent(args, env, timeout=8):
    try:
        r = subprocess.run([sys.executable, os.path.join(ROOT, "udpcheck_node.py")] + args, env=env, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired as ex:
        out = (ex.stdout or b"") + (ex.stderr or b"")
        return None, out.decode("utf-8", "replace") if isinstance(out, bytes) else out


print("Агент:")
tmp = tempfile.mkdtemp()
cfg = os.path.join(tmp, "config.json")
rc, out = run_agent(["--once", "--config", cfg], clean_env())
check("без --hub, UDPCHECK_HUB и сохранённого адреса — код 2 и понятная ошибка", rc == 2 and "Не задан адрес хаба" in out, (rc, out))
check("без адреса файл настроек не создаётся (регистрации не было)", not os.path.exists(cfg), os.listdir(tmp))
rc, out = run_agent(["--once", "--config", cfg], clean_env(UDPCHECK_LANG="en"))
check("то же по-английски", rc == 2 and "No hub address" in out, (rc, out))
rc, out = run_agent(["--once", "--config", cfg, "--hub", "   "], clean_env())
check("адрес из одних пробелов не считается адресом", rc == 2 and "Не задан адрес хаба" in out, (rc, out))
rc, out = run_agent(["--once", "--config", cfg], clean_env(UDPCHECK_HUB="http://127.0.0.1:9"), timeout=5)
check("UDPCHECK_HUB из окружения принимается (дальше агент идёт к хабу)", "Не задан адрес хаба" not in out, (rc, out))
rc, out = run_agent(["--once", "--config", cfg, "--hub", "http://127.0.0.1:9"], clean_env(), timeout=5)
check("--hub принимается", "Не задан адрес хаба" not in out, (rc, out))
with open(cfg, "w", encoding="utf-8") as f:
    f.write('{"hub": "http://127.0.0.1:9", "token": "t", "callsign": "x"}')
rc, out = run_agent(["--once", "--config", cfg], clean_env(), timeout=5)
check("адрес, сохранённый при регистрации, принимается (старые установки продолжают работать)", "Не задан адрес хаба" not in out, (rc, out))
shutil.rmtree(tmp, ignore_errors=True)

print("Установщик:")
SH = shutil.which("sh")
check("есть sh для запуска установщика", SH is not None)
src = open(os.path.join(ROOT, "installer", "install-node.sh.in"), encoding="utf-8").read()
check("служба systemd получает адрес через --hub", "udpcheck_node.py --hub HUB_ADDR --config /var/lib/udpcheck-node/config.json" in src)
check("служба OpenWrt получает адрес через --hub", "udpcheck_node.py --hub HUB_ADDR --config /etc/udpcheck-node/config.json" in src)
check("заглушка адреса заменяется в обоих файлах служб", src.count('sed -i "s|--hub HUB_ADDR|--hub $HUB|"') == 2)
check("в установщике нет зашитого адреса хаба", "dagart.xyz" not in src)

if SH:
    # те же команды sed, что в установщике: адрес хаба, затем роль; строки запуска служб — из самого установщика
    import re
    hub_sed = re.findall(r'sed -i "(s\|--hub HUB_ADDR\|--hub \$HUB\|)"', src)
    role_sed = re.findall(r'sed -i (?:-e )?"(s\|udpcheck_node\.py [^"]*\$ROLE[^"]*)"', src)
    check("в установщике по 2 замены адреса и роли", len(hub_sed) == 2 and len(role_sed) == 2, (hub_sed, role_sed))
    lines = [l.strip().split("command ", 1)[-1] if "procd_set_param" in l else l.strip()
             for l in src.split("\n") if "udpcheck_node.py --hub HUB_ADDR" in l]
    for hs, rs, line in zip(hub_sed, role_sed, lines):
        r = subprocess.run([SH, "-c", 'printf "%s\\n" "$L" | sed -e "' + hs + '" | sed -e "' + rs + '"'],
                           env=clean_env(L=line, HUB="https://hub.example.org:8443/udp", ROLE="ref"),
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        got = r.stdout.strip()
        check("в службе оказываются и роль, и адрес: " + line.split()[0],
              "udpcheck_node.py --role ref --hub https://hub.example.org:8443/udp --config " in got, (r.returncode, got, r.stderr))
    d = tempfile.mkdtemp()
    ru = os.path.join(d, "install-node.sh")
    en = os.path.join(d, "install-node.en.sh")
    with open(ru, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    with open(en, "w", encoding="utf-8", newline="\n") as f:
        f.write(translate_en.to_english(src))

    def sh(script, args=(), **env):
        r = subprocess.run([SH, script] + list(args), env=clean_env(**env), capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=30, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout + r.stderr

    rc, out = sh(ru)
    check("установка без UDPCHECK_HUB — отказ с подсказкой", rc == 1 and "не задан адрес хаба" in out and "UDPCHECK_HUB=" in out, (rc, out))
    rc, out = sh(en)
    check("английский установщик: тот же отказ", rc == 1 and "no hub address" in out, (rc, out))
    rc, out = sh(ru, ["install"])
    check("явное install без адреса — отказ", rc == 1 and "не задан адрес хаба" in out, (rc, out))
    rc, out = sh(ru, UDPCHECK_HUB="")
    check("пустой UDPCHECK_HUB — отказ", rc == 1 and "не задан адрес хаба" in out, (rc, out))
    for bad in ("dagart", "ftp://example.org", "https://exa mple.org", "https://example.org|x", "https://example.org/$(id)", "https://ex\"ample.org"):
        rc, out = sh(ru, UDPCHECK_HUB=bad)
        check("неверный адрес отклонён: %r" % bad, rc == 1 and "неверный адрес хаба" in out, (rc, out))
    for good in ("https://example.org", "https://example.org/", "http://127.0.0.1:18080", "https://hub.example.org/udp"):
        rc, out = sh(ru, UDPCHECK_HUB=good)
        check("правильный адрес принят: %r" % good, "адрес хаба" not in out, (rc, out))
    rc, out = sh(en, UDPCHECK_HUB="https://example.org")
    check("английский установщик принимает правильный адрес", "hub address" not in out, (rc, out))
    rc, out = sh(ru, ["uninstall"])
    check("удаление без адреса хаба не требует адреса", "адрес хаба" not in out and "не задан" not in out, (rc, out))
    rc, out = sh(en, ["uninstall"])
    check("английское удаление без адреса не требует адреса", "hub address" not in out, (rc, out))
    rc, out = sh(ru, ["uninstall"], UDPCHECK_HUB="https://example.org|x")
    check("удаление с заданным, но неверным адресом — отказ (адрес идёт в sudo-перезапуск)", rc == 1 and "неверный адрес хаба" in out, (rc, out))
    shutil.rmtree(d, ignore_errors=True)

print()
print("ИТОГ: %s (%d ошибок)" % ("ВСЁ OK" if not fails else "ЕСТЬ ОШИБКИ", fails))
sys.exit(1 if fails else 0)
