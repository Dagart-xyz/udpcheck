# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Фикстуры ответов хаба для интерфейсных тестов (tests/i18n/harness.py): детерминированные данные всех видов, которые показывает сайт."""
import copy

NOW = 1791622800          # 2026-10-10 09:00:00 UTC, время «сейчас» в тестах (страница тоже видит его через подмену Date)

ANCHORS = [
    {"code": "DAGART-RU", "name": "Россия, Москва-1", "name_en": "Russia, Moscow-1", "country": "RU", "online": True, "checks": 626, "ok": 601, "ip": "198.51.100.1"},
    {"code": "HEL1-FI", "name": "Финляндия, Хельсинки", "name_en": "Finland, Helsinki", "country": "FI", "online": True, "checks": 626, "ok": 398, "ip": "198.51.100.2"},
    {"code": "AMS1-NL", "name": "Нидерланды, Амстердам", "name_en": "Netherlands, Amsterdam", "country": "NL", "online": True, "checks": 0, "ok": 0, "ip": "198.51.100.3"},
    {"code": "PAR1-FR", "name": "Франция, Париж", "name_en": "France, Paris", "country": "FR", "online": False, "checks": 12, "ok": 3, "ip": "198.51.100.4"},
    {"code": "MSK1-RU", "name": "Россия, Москва-2", "name_en": "Russia, Moscow-2", "country": "RU", "online": True, "checks": 626, "ok": 600, "ip": "198.51.100.5"},
    {"code": "FRA1-DE", "name": "Германия, Франкфурт", "name_en": "Germany, Frankfurt", "country": "DE", "online": True, "checks": 626, "ok": 590, "ip": "198.51.100.6"},
]
PAD = [{"port": 3478, "size": 600}, {"port": 19302, "size": 1200}]


def stun_targets(profile):
    """Список целей для браузерной проверки (web/stun)."""
    out = []
    for a in ANCHORS:
        if profile == "noanchor" and a["country"] == "RU":
            continue
        out.append({"code": a["code"], "kind": "home" if a["country"] == "RU" else "foreign", "name": a["name"], "name_en": a["name_en"], "ip": a["ip"],
                    "ports": [777, 47321], "pad": copy.deepcopy(PAD)})
    out.append({"code": "REF-4", "kind": "foreign", "name": "сервер добровольца", "name_en": "volunteer server", "country": "BG", "community": True,
                "control": False, "ip": "203.0.113.50", "ports": [38321, 38322]})
    if profile == "noanchor":
        out.append({"code": "REF-5", "kind": "home", "name": "сервер добровольца", "name_en": "volunteer server", "country": "RU", "community": True,
                    "control": True, "ip": "203.0.113.51", "ports": [38321, 38322]})
    return out


def stun_dead(profile):
    """Какие «ip:порт» не отвечают в профиле проверки."""
    dead = []
    foreign_ips = [a["ip"] for a in ANCHORS if a["country"] != "RU"]
    home_ips = [a["ip"] for a in ANCHORS if a["country"] == "RU"]
    ports = (777, 47321)
    if profile in ("in_cut", "out_cut", "ctrl_bad_foreign_dead", "seen_failed", "community_ok"):
        for ip in foreign_ips:
            dead += ["%s:%d" % (ip, p) for p in ports]
        if profile != "community_ok":
            dead += ["203.0.113.50:38321", "203.0.113.50:38322"]
    if profile == "partial":
        for ip in foreign_ips[:2]:
            dead += ["%s:%d" % (ip, p) for p in ports]
    if profile == "ctrl_bad":
        for ip in home_ips:
            dead += ["%s:%d" % (ip, p) for p in ports]
    if profile == "sizecut":
        for ip in foreign_ips:
            dead += ["%s:19302" % ip]
    if profile == "size_part":
        dead += ["%s:19302" % foreign_ips[0]]
    return dead


def stun_ext_ips(profile):
    """Внешний адрес, который видит каждый сервер (разные адреса = раздельная маршрутизация)."""
    if profile == "mixed":
        return {a["ip"]: ("203.0.113.%d" % (10 + i)) for i, a in enumerate(ANCHORS)}
    return {}


def stunseen(profile):
    seen, replied = {}, {}
    for t in stun_targets(profile):
        c = t["code"]
        if profile in ("in_cut", "seen_partial") and t["kind"] == "foreign" and not t.get("community"):
            seen[c], replied[c] = 6, 6
        elif profile == "out_cut" and t["kind"] == "foreign" and not t.get("community"):
            seen[c], replied[c] = 0, 0
        else:
            seen[c], replied[c] = 6, 6
    return {"done": True, "seen": seen, "replied": replied}


def me(profile):
    base = {"you": {"asn": 12389, "org": "PJSC Rostelecom", "country": "RU", "city": "Москва", "city_en": "Moscow"},
            "home": {"anchors": 2, "community": 1}, "attribution": "IP geolocation by DB-IP.com (CC BY 4.0)",
            "network": {"window_hours": 24, "nodes": 0, "rounds": 0, "verdicts": {}, "web": {"NO_BLOCK": 1}, "tcp_foreign": {"ok": 0, "total": 0}, "last": None}}
    if profile == "none":
        return base
    if profile == "unknown":
        base["you"] = {"asn": None, "org": None, "country": None, "city": None, "city_en": None}
        base["home"] = {"anchors": 2, "community": 0}
        base["network"] = None
        return base
    if profile == "noanchor":
        base["home"] = {"anchors": 0, "community": 0}
        return base
    n = base["network"]
    if profile in ("in_cut", "in_cut_tcp"):
        n.update(nodes=3, rounds=20, verdicts={"FOREIGN_IN_CUT": 18, "NO_BLOCK": 2}, last={"age_s": 400, "verdict": "FOREIGN_IN_CUT"})
        if profile == "in_cut_tcp":
            n["tcp_foreign"] = {"ok": 28, "total": 30}
    elif profile == "weak":
        n.update(nodes=1, rounds=3, verdicts={"FOREIGN_IN_CUT": 3}, last={"age_s": 100, "verdict": "FOREIGN_IN_CUT"})
    elif profile == "out_cut":
        n.update(nodes=2, rounds=10, verdicts={"FOREIGN_OUT_CUT": 9, "NO_BLOCK": 1}, last={"age_s": 4000, "verdict": "FOREIGN_OUT_CUT"})
    elif profile == "partial":
        n.update(nodes=4, rounds=12, verdicts={"FOREIGN_PARTIAL": 11, "NO_BLOCK": 1}, last={"age_s": 9000, "verdict": "FOREIGN_PARTIAL"})
    elif profile == "ok":
        n.update(nodes=5, rounds=40, verdicts={"NO_BLOCK": 40}, last={"age_s": 60, "verdict": "NO_BLOCK"})
    elif profile == "ctrl":
        n.update(nodes=2, rounds=8, verdicts={"CONTROL_BAD": 8}, last={"age_s": 60, "verdict": "CONTROL_BAD"})
    elif profile == "unstable":
        n.update(nodes=2, rounds=8, verdicts={"UNSTABLE_PATH": 8}, last={"age_s": 60, "verdict": "UNSTABLE_PATH"})
    elif profile == "noforeign":
        n.update(nodes=2, rounds=8, verdicts={"NO_FOREIGN": 8}, last={"age_s": 60, "verdict": "NO_FOREIGN"})
    elif profile == "controldown":
        n.update(nodes=2, rounds=8, verdicts={"CONTROL_DOWN": 8}, last={"age_s": 60, "verdict": "CONTROL_DOWN"})
    elif profile == "noanchor_rounds":
        n.update(nodes=2, rounds=8, verdicts={"NO_ANCHOR": 8}, last={"age_s": 60, "verdict": "NO_ANCHOR"})
        base["home"] = {"anchors": 0, "community": 0}
    return base


def _chain(*asns):
    return [{"asn": a, "org": o} for a, o in asns]


def trace_result(profile, targets_def):
    """Готовый результат трассировки по целям (web/trace/{id})."""
    out = []
    for t in targets_def:
        kind = "home" if t["country"] == "RU" else "foreign"
        res = {}
        status = "done"
        if profile == "ok":
            reached = kind == "home"
            res = {"icmp": {"as_path": _chain((3356, "Lumen"), (12389, "PJSC Rostelecom")) if not reached else _chain((8359, "MTS PJSC"), (12389, "PJSC Rostelecom")),
                            "reached": reached, "last_responding_ttl": 9}}
        elif profile == "allreach":
            res = {"udp": {"as_path": _chain((12389, "PJSC Rostelecom")), "reached": True, "last_responding_ttl": 11}}
        elif profile == "none_reach":
            res = {"tcp": {"as_path": _chain((1299, "Arelion"), (12389, "PJSC Rostelecom")), "reached": False, "last_responding_ttl": 6}}
        elif profile == "mixed_status":
            if t["code"] == "HEL1-FI":
                status = "timeout"
            elif t["code"] == "AMS1-NL":
                status = "done"
                res = {}
            else:
                res = {"icmp": {"as_path": _chain((12389, "PJSC Rostelecom"), (42610, "PJSC Rostelecom"), (8359, "MTS PJSC"), (1299, "Arelion"), (3356, "Lumen")),
                                "reached": kind == "home", "last_responding_ttl": 12}}
        out.append({"code": t["code"], "kind": kind, "name": t["name"], "name_en": t["name_en"], "status": status, "results": res})
    return {"done": True, "targets": out}


def providers():
    P = []

    def add(asn, name, status, **kw):
        series = kw.pop("series", [None] * 8 + [0.0] * 8 + [0.5] * 4 + [1.0] * 4)
        P.append({"asn": asn, "name": name, "org": kw.pop("org", name + " Ltd"), "status": status, "asns": kw.pop("asns", None), "weak": kw.pop("weak", False),
                  "nodes": kw.pop("nodes", 2), "rounds_1h": kw.pop("r1", 3), "rounds_24h": kw.pop("r24", 40), "web_24h": kw.pop("w24", 5), "logo": kw.pop("logo", None),
                  "series": series, "last_age": kw.pop("last_age", 600), "old": kw.pop("old", False), "size_cut": kw.pop("size_cut", False), "kind": kw.pop("kind", "isp"),
                  "search": (name + " as%d" % asn).lower(), "name_en": kw.pop("name_en", name)})
    add(29124, "Seven Sky", "cut", org="Iskratelecom JSC", logo="/logos/29124.ico", r1=1, r24=44, w24=45)
    add(12389, "Ростелеком", "partial", org="PJSC Rostelecom", asns=[12389, 42610, 25490], name_en="Rostelecom", w24=3, size_cut=True)
    add(12714, "МегаФон", "ok", org="PJSC MegaFon", name_en="MegaFon", nodes=0, w24=12)
    add(8359, "МТС", "ok", org="MTS PJSC", name_en="MTS", weak=True, r24=2, r1=0)
    add(35807, "SkyNet", "stale", org="SkyNet Ltd.", old=True, last_age=40000, r1=0, r24=0, w24=0, series=[None] * 24)
    add(196949, "Частный провайдер AS196949", "noanchor", org=None, name_en="Private provider AS196949", r24=1)
    add(8075, "Microsoft", "ok", kind="hosting", org="Microsoft Corporation")
    add(16276, "OVH", "cut", kind="hosting", org="OVH SAS")
    for i in range(1, 25):
        add(60000 + i, "Тест-провайдер %d" % i, "ok", name_en="Test ISP %d" % i)
    return {"generated": NOW, "providers": P}


def detail(asn):
    if asn == 99999:
        return None
    # столбик часа: [порезано, нормально, ненадёжно] (числа замеров)
    series = [[0, 0, 0]] * 120 + [[3, 2, 0], [0, 4, 1], [5, 0, 0], [1, 2, 5], [0, 0, 3], [0, 0, 0], [1, 1, 0], [2, 2, 0]] * 5 + [[0, 0, 0]] * 8
    series = [list(x) for x in series]
    return {"asn": asn, "asns": [12389, 42610, 25490], "name": "Ростелеком", "name_en": "Rostelecom", "org": "PJSC Rostelecom", "country": "RU", "status": "partial", "old": False,
            "kind": "isp", "weak": False, "nodes": 3, "web_24h": 7, "logo": None, "rounds_1h": 4, "rounds_24h": 46, "rounds_7d": 190, "first_seen": NOW - 9 * 86400,
            "last_age": 300, "hour_now": NOW // 3600, "series": series, "verdicts": {"FOREIGN_IN_CUT": 30, "FOREIGN_PARTIAL": 8, "NO_BLOCK": 8},
            "targets": [
                {"code": "DAGART-RU", "kind": "home", "name": "Россия, Москва-1", "name_en": "Russia, Moscow-1", "status": {"OK": 44, "NOREPORT": 2}, "tcp_total": 0, "tcp_ok": 0},
                {"code": "HEL1-FI", "kind": "foreign", "name": "Финляндия, Хельсинки", "name_en": "Finland, Helsinki",
                 "status": {"INCUT": 30, "OK": 8, "PART": 3, "MIXED": 1, "LOSSY": 2, "OUTCUT": 1, "ZZZ": 1}, "tcp_total": 40, "tcp_ok": 39},
                {"code": "AMS1-NL", "kind": "foreign", "name": "Нидерланды, Амстердам", "name_en": "Netherlands, Amsterdam", "status": {"INCUT": 25, "OK": 21}, "tcp_total": 36, "tcp_ok": 34},
            ],
            "cuts": {"foreign": [{"asn": 12389, "org": "PJSC Rostelecom", "n": 22}, {"asn": 3356, "org": "Lumen", "n": 5}],
                     "home": [{"asn": 12389, "org": "PJSC Rostelecom", "n": 46}]},
            "web": {"NO_BLOCK": 3, "FOREIGN_IN_CUT": 4}, "node_list": [{"callsign": "brave-juniper-81", "os": "Linux", "online": True}, {"callsign": "fuzzy-yarrow-96", "os": "OpenWrt", "online": False}],
            "size": {"tested": 9, "cut": 6, "max": 1200},
            "journal": [{"ts": NOW - 3600, "kind": "change", "old": "ok", "new": "cut", "info": {"checks": 7, "browsers": 4}},
                        {"ts": NOW - 7200, "kind": "cut_check", "old": "partial", "new": "partial", "info": {"checks": 2, "browsers": 2, "dir": "in+out", "servers_replied": 3}},
                        {"ts": NOW - 9000, "kind": "size_cut", "old": None, "new": None, "info": {"browsers": 3, "size": 1200}},
                        {"ts": NOW - 90000, "kind": "new", "old": None, "new": "ok", "info": {"checks": 1, "browsers": 1}}]}


def detail_ok(asn):
    d = detail(asn)
    d.update(status="ok", weak=True, old=True, kind="hosting", size={"tested": 4, "cut": 0, "max": 1200}, verdicts={}, targets=[], cuts={"foreign": [], "home": []},
             web={}, node_list=[], journal=[], asns=None, logo="/logos/29124.ico")
    return d


def journal():
    ev = [
        {"ts": NOW - 600, "asn": 12389, "name": "Ростелеком", "name_en": "Rostelecom", "kind": "change", "old": "ok", "new": "cut", "info": {"checks": 7, "browsers": 4}},
        {"ts": NOW - 1200, "asn": 29124, "name": "Seven Sky", "name_en": "Seven Sky", "kind": "new", "old": None, "new": "partial", "info": {"checks": 3}},
        {"ts": NOW - 1800, "asn": 12714, "name": "МегаФон", "name_en": "MegaFon", "kind": "cut_check", "old": None, "new": "ok", "info": {"checks": 2, "browsers": 2, "dir": "in", "servers_replied": 4}},
        {"ts": NOW - 2400, "asn": 8359, "name": "МТС", "name_en": "MTS", "kind": "cut_check", "old": "stale", "new": "stale", "info": {"checks": 1, "dir": "out"}},
        {"ts": NOW - 3000, "asn": 35807, "name": "SkyNet", "name_en": "SkyNet", "kind": "cut_check", "old": "ok", "new": "ok", "info": {"browsers": 2, "dir": "in+out", "servers_replied": 2}},
        {"ts": NOW - 3600, "asn": 196949, "name": "Частный провайдер AS196949", "name_en": "Private provider AS196949", "kind": "size_cut", "old": None, "new": None, "info": {"browsers": 3, "size": 1200}},
        {"ts": NOW - 4200, "asn": 60001, "name": "Тест-провайдер 1", "name_en": "Test ISP 1", "kind": "size_cut", "old": None, "new": None, "info": {}},
        {"ts": NOW - 4800, "asn": 60002, "name": "Тест-провайдер 2", "name_en": "Test ISP 2", "kind": "change", "old": "noanchor", "new": "cut", "info": {}},
        {"ts": NOW - 5400, "asn": 60003, "name": "Тест-провайдер 3", "name_en": "Test ISP 3", "kind": "weird", "old": None, "new": None, "info": {}},
    ]
    return {"generated": NOW, "events": ev}


def nodes():
    nl = [
        {"callsign": "clever-walnut-72", "asn": 12389, "org": "PJSC Rostelecom", "country": "RU", "os": "OpenWrt", "online": True, "last_seen_age": 3, "since_days": 1, "rounds": 15,
         "tunnel_rounds": 2, "last_verdict": "FOREIGN_IN_CUT", "ref": None, "role": "node", "ver": "0.3", "outdated": True, "city": "Москва", "city_en": "Moscow"},
        {"callsign": "quiet-pebble-11", "asn": None, "org": None, "country": None, "os": "Linux", "online": False, "last_seen_age": 99999, "since_days": 4, "rounds": 0,
         "tunnel_rounds": 0, "last_verdict": None, "ref": None, "role": "node", "ver": "0.4", "outdated": False, "city": None, "city_en": None},
        {"callsign": "fuzzy-yarrow-96", "asn": None, "org": None, "country": "NL", "os": "Linux", "online": True, "last_seen_age": 3, "since_days": 1, "rounds": 0,
         "tunnel_rounds": 0, "last_verdict": None, "ref": {"active": True, "country": "NL", "checks": 5, "ok": 4}, "role": "ref", "ver": "0.4", "outdated": False,
         "city": "Эйгельсховен", "city_en": "Eygelshoven"},
        {"callsign": "eager-orchid-71", "asn": None, "org": None, "country": "BG", "os": "Linux", "online": False, "last_seen_age": 9999, "since_days": 3, "rounds": 0,
         "tunnel_rounds": 0, "last_verdict": None, "ref": {"active": False, "country": "BG", "checks": 0, "ok": 0}, "role": "ref", "ver": "0.4", "outdated": False,
         "city": None, "city_en": None},
        {"callsign": "both-comet-05", "asn": 8359, "org": "MTS PJSC", "country": "RU", "os": "Linux", "online": True, "last_seen_age": 3, "since_days": 2, "rounds": 3,
         "tunnel_rounds": 0, "last_verdict": "NO_BLOCK", "ref": {"active": True, "country": "RU", "checks": 0, "ok": 0}, "role": "both", "ver": "0.4", "outdated": False,
         "city": "Санкт-Петербург", "city_en": "Saint Petersburg"},
    ]
    return {"online": 3, "total": 5, "refs_active": 2, "nodes": nl, "anchors": [{k: v for k, v in a.items() if k != "ip"} for a in ANCHORS]}


def nodes_empty():
    return {"online": 0, "total": 0, "refs_active": 0, "nodes": [], "anchors": []}


def stats_asn():
    base = NOW // 3600 - 100
    return {"asn": 12389, "window_hours": 168, "buckets": [{"hour": (base + i) * 3600, "rounds": 3, "verdicts": {"FOREIGN_IN_CUT": 3 if i % 2 else 0, "NO_BLOCK": 0 if i % 2 else 3}} for i in range(100)]}
