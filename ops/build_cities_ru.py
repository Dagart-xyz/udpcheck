#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Собирает справочник «английское название города -> русское» из GeoNames (CC BY 4.0, https://www.geonames.org).

Нужны cities1000.zip и alternateNamesV2.zip из https://download.geonames.org/export/dump/ в текущем каталоге.
Результат: cities_ru.sqlite (таблица c: cc, k, ru, pop). Кладётся на хаб в /opt/udpcheck/geo/ (читает udpcheck_v2.city_ru).
Запускать на сервере с быстрым каналом: alternateNamesV2.zip около 200 МБ.
"""
import io
import os
import re
import sqlite3
import zipfile

CYR = re.compile("[А-Яа-яЁё]")
cities = {}          # geonameid -> (cc, name, ascii, population)
with zipfile.ZipFile("cities1000.zip") as z:
    for line in io.TextIOWrapper(z.open("cities1000.txt"), encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        cities[int(f[0])] = (f[8], f[1], f[2], int(f[14] or 0))
print("городов:", len(cities))

ru = {}              # geonameid -> (оценка, имя)
en = {}              # geonameid -> английские варианты
with zipfile.ZipFile("alternateNamesV2.zip") as z:
    with z.open("alternateNamesV2.txt") as fh:
        for raw in io.TextIOWrapper(fh, encoding="utf-8"):
            f = raw.rstrip("\n").split("\t")
            if len(f) < 8 or not f[1].isdigit():
                continue
            gid = int(f[1])
            if gid not in cities:
                continue
            lang, nm = f[2], f[3]
            if lang == "ru":
                if f[6] == "1" or f[7] == "1" or not CYR.search(nm):      # разговорные, исторические и не кириллица не берём
                    continue
                score = (2 if f[4] == "1" else 0) + (1 if f[5] != "1" else 0)
                if gid not in ru or score > ru[gid][0]:
                    ru[gid] = (score, nm)
            elif lang == "en":
                en.setdefault(gid, set()).add(nm)
print("с русским названием:", len(ru))

best = {}            # (cc, ключ) -> (население, русское имя)
for gid, (score, rname) in ru.items():
    cc, name, ascii_, pop = cities[gid]
    for k in {name.lower(), ascii_.lower(), *(x.lower() for x in list(en.get(gid, ()))[:8])}:
        cur = best.get((cc, k))
        if cur is None or pop > cur[0]:
            best[(cc, k)] = (pop, rname)

if os.path.exists("cities_ru.sqlite"):
    os.remove("cities_ru.sqlite")
db = sqlite3.connect("cities_ru.sqlite")
db.execute("CREATE TABLE c(cc TEXT, k TEXT, ru TEXT, pop INTEGER, PRIMARY KEY(cc, k)) WITHOUT ROWID")
db.executemany("INSERT INTO c VALUES(?,?,?,?)", [(cc, k, v[1], v[0]) for (cc, k), v in best.items()])
db.commit()
db.execute("VACUUM")
db.close()
print("записей:", len(best), "размер:", os.path.getsize("cities_ru.sqlite") // 1024, "КБ")
