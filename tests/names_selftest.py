# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Проверка очистки названий провайдеров и группировки сетей одного оператора на живых именах из базы хаба. Запуск: python tests/names_selftest.py"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import udpcheck_server as S
import udpcheck_v2 as V

FAILS = []


def check(name, cond, extra=""):
    print(("  OK   " if cond else "  FAIL ") + name + ("" if cond else "  " + str(extra)))
    if not cond:
        FAILS.append(name)


import sqlite3
V.S = S
V.DB = sqlite3.connect(":memory:", check_same_thread=False)
V.DB.executescript(V.SCHEMA)
V.migrate(V.DB)
tmp = tempfile.mkdtemp()
S.GEO_DIR = tmp
import shutil
shutil.copy(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ops", "brands.json"), os.path.join(tmp, "brands.json"))
json.dump({"196949": "Частный провайдер AS196949"}, open(os.path.join(tmp, "names.json"), "w", encoding="utf-8"), ensure_ascii=False)

cn = V.clean_name
print("[очистка названий]")
cases = {
    'JSC "ER-Telecom Holding"': "ER-Telecom Holding",
    'OOO "IT-Region"': "IT-Region",
    'Limited liability company "New Line"': "New Line",
    'LLC "TRC FIORD"': "TRC Fiord",
    "MTS PJSC": "MTS",
    "PJSC Rostelecom": "Rostelecom",
    "AKVILON Ltd.": "Akvilon",
    "SERV.HOST GROUP LTD": "Serv.Host Group",
    "JSC KVANT-TELEKOM": "Kvant-Telekom",
    "Gigahost AS": "Gigahost",
    "Fornex Hosting S.L.": "Fornex Hosting",
    "P.A.K.T LLC": "P.A.K.T",
    "CHSL ONE LTD": "CHSL ONE",
    "////first Server Us": "First Server Us",
    "CLODO CLOUD SERVICE CO. L.L.C": "Clodo Cloud Service",
    "Sabiedriba ar ierobezotu atbildibu DELSKA Latvia": "Delska Latvia",
    "Arvid Logicum OU": "Arvid Logicum",
    "https://glesys.com": "Glesys",
    "Joint-Stock Company Investpribor": "Investpribor",
    "SkyNet Ltd.": "SkyNet",
    "Seven Sky": "Seven Sky",
}
for raw, want in cases.items():
    got = cn(raw)
    check("%r -> %r" % (raw, want), got == want, got)
check("длинное название обрезается по слову", len(cn("SCIENTIFIC RESEARCH INSTITUTE FOR SYSTEM ANALYSIS OF THE NATIONAL RESEARCH CENTER KURCHATOV INSTITUTE")) <= 43)
check("мусорные названия отвергаются", all(V._bad_name(x) for x in ("to AS51765 announce AS207569", "Retail", "Uplinks", "AS56971 Cloud", "ab")))
check("обычное имя не отвергается", not V._bad_name("Seven Sky"))
check("частное лицо распознаётся (в том числе по отчеству)", V._is_person("Individual Entrepreneur Lukyanov Maksim") and V._is_person("Baykov Ilya Sergeevich")
      and not V._is_person("PJSC Rostelecom") and not V._is_person("Seven Sky"))
check("название из заглавных с предлогом", V.clean_name("SCIENTIFIC RESEARCH INSTITUTE FOR SYSTEM ANALYSIS OF THE NATIONAL").startswith("Scientific Research Institute for System"))

print("[бренды и группы]")
V._asn_cache.update({12389: "", 42610: "", 25490: "", 41733: "", 51570: "", 16345: "", 8402: "", 8359: "", 197023: "", 31213: "", 35807: "SkyNet", 29124: "Seven Sky"})
for a, org in ((12389, "PJSC Rostelecom"), (42610, "PJSC Rostelecom"), (25490, "PJSC Rostelecom")):
    V._org_cache["data"][a] = org
V._org_cache.update(t=10 ** 12)
g = V.provider_group
check("три сети Ростелекома — один бренд", len({g(12389, "PJSC Rostelecom")[0], g(42610, "PJSC Rostelecom")[0], g(25490, "PJSC Rostelecom")[0]}) == 1)
check("имя бренда по-русски", g(12389, "PJSC Rostelecom")[1] == "Ростелеком", g(12389, "PJSC Rostelecom"))
check("ЭР-Телеком: разные сети под одним брендом", g(41733, 'JSC "ER-Telecom Holding"')[0] == g(51570, 'JSC "ER-Telecom Holding"')[0] and "Дом.ру" in g(41733, 'JSC "ER-Telecom Holding"')[1])
check("Вымпелком PJSC и OJSC вместе", g(16345, 'PJSC "Vimpelcom"')[0] == g(8402, 'OJSC "Vimpelcom"')[0])
check("МТС и «MTS Belgorod branch» вместе", g(8359, "MTS PJSC")[0] == g(197023, "MTS Belgorod branch")[0] and g(8359, "MTS PJSC")[1] == "МТС")
check("МегаФон отдельно от МТС", g(31213, "PJSC MegaFon")[0] != g(8359, "MTS PJSC")[0])
check("SkyNet и Seven Sky не склеиваются", g(35807, "SkyNet Ltd.")[0] != g(29124, "Seven Sky")[0])
check("частное лицо: публично имени нет, имя «Частный провайдер»", g(196949, "Natalia Sergeevna Filicheva")[1].startswith("Частный провайдер") and V.public_org(35420, "Individual Entrepreneur Lukyanov Maksim") is None)
check("обычная организация показывается", V.public_org(35807, "SkyNet Ltd.") == "SkyNet Ltd.")

print()
print("ИТОГ: всё прошло" if not FAILS else "ИТОГ: ПРОВАЛЕНО %d" % len(FAILS))
sys.exit(1 if FAILS else 0)
