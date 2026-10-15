#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Сообщить поисковикам об адресах сайта по протоколу IndexNow (https://www.indexnow.org): без личных кабинетов и регистрации.
Протокол поддерживают Яндекс, Bing (а через него DuckDuckGo и др.), Seznam, Naver, Yep; Google его не поддерживает и находит сайт по ссылкам и sitemap.xml.
Подтверждение владения: файл site/<ключ>.txt с самим ключом, выложенный в корень сайта (deploy_site.sh). Ключ не секрет: им можно только сообщить об адресах этого же сайта.
Адреса берутся из site/sitemap.xml (страницы провайдеров туда не входят: они закрыты от индексации).
Запуск после выкладки:  python ops/indexnow.py           (или --dry, чтобы только показать, что уйдёт)"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")
ORIGIN = os.environ.get("UDPCHECK_ORIGIN", "https://dagart.xyz")
ENDPOINTS = ("https://api.indexnow.org/indexnow", "https://yandex.com/indexnow")     # общий адрес делится с остальными участниками; Яндекс отдельно для надёжности
MEANING = {200: "принято", 202: "принято, ключ ещё проверяется", 400: "неверный запрос", 403: "ключ не подтвердился (файл ключа не найден на сайте)",
           422: "адреса не с этого сайта или ключ не совпал", 429: "слишком часто, повторить позже"}


def main():
    keys = [f[:-4] for f in os.listdir(SITE) if re.fullmatch(r"[0-9a-f]{32}\.txt", f)]
    if len(keys) != 1:
        sys.exit("нужен ровно один файл ключа site/<32 hex>.txt, найдено: %d" % len(keys))
    key = keys[0]
    if open(os.path.join(SITE, key + ".txt"), encoding="utf-8").read().strip() != key:
        sys.exit("в файле ключа должен быть сам ключ")
    urls = re.findall(r"<loc>([^<]+)</loc>", open(os.path.join(SITE, "sitemap.xml"), encoding="utf-8").read())
    host = re.sub(r"^https?://", "", ORIGIN).rstrip("/")
    urls = [u for u in urls if u.startswith(ORIGIN + "/")]
    body = {"host": host, "key": key, "keyLocation": "%s/%s.txt" % (ORIGIN, key), "urlList": urls}
    print("адресов: %d (%s)" % (len(urls), ", ".join(urls)))
    if "--dry" in sys.argv:
        print(json.dumps(body, ensure_ascii=False, indent=1))
        return
    try:                                            # сначала убедиться, что файл ключа уже доступен на сайте, иначе поисковик отвергнет запрос
        got = urllib.request.urlopen(urllib.request.Request(body["keyLocation"], headers={"User-Agent": "udpcheck-indexnow"}), timeout=20).read().decode().strip()
    except Exception as e:
        sys.exit("файл ключа на сайте недоступен (%s): сначала выложите сайт" % e)
    if got != key:
        sys.exit("файл ключа на сайте не совпадает с локальным")
    bad = 0
    for ep in ENDPOINTS:
        req = urllib.request.Request(ep, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "udpcheck-indexnow"})
        try:
            code = urllib.request.urlopen(req, timeout=30).status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception as e:
            code = None
            print("%s: нет ответа (%s)" % (ep, type(e).__name__))
        if code is not None:
            print("%s: %s %s" % (ep, code, MEANING.get(code, "")))
        if code not in (200, 202):
            bad += 1
    sys.exit(1 if bad == len(ENDPOINTS) else 0)


if __name__ == "__main__":
    main()
