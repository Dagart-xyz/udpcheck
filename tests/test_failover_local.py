#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Переключатель хаба (ops/udpcheck-failover): вниз при недоступности активного, наверх при плановой передаче, DNS после готовности,
защита от собственной слепоты и от ложного «жив 30 минут», поведение без S3 и при ошибке DNS. Сеть, S3, Porkbun и время подменены.
Кроме того, проверка HTTPS «на адрес, но под именем домена» против локального сервера с самоподписанным сертификатом.
Запуск: python tests/test_failover_local.py"""
import importlib.machinery
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
fails = 0


def check(name, cond, extra=""):
    global fails
    print(("  OK   " if cond else "  FAIL ") + name + (("   " + str(extra)[:400]) if (extra and not cond) else ""))
    if not cond:
        fails += 1


loader = importlib.machinery.SourceFileLoader("udpcheck_failover", os.path.join(ROOT, "ops", "udpcheck-failover"))
spec = importlib.util.spec_from_loader("udpcheck_failover", loader)
F = importlib.util.module_from_spec(spec)
loader.exec_module(F)

IPS = {"DDD1-XD": "198.51.100.1", "BBB1-XB": "198.51.100.2", "AAA1-XA": "198.51.100.3"}
CONF = {"CANDIDATES": ",".join("%s=%s" % kv for kv in IPS.items()), "DOMAIN": "example.test", "DOWN_AFTER": "300", "UP_AFTER": "1800",
        "READY_WAIT": "900", "DNS_EVERY": "600"}


class Net:
    def __init__(self, active="DDD1-XD"):
        self.t = 1_000_000.0
        self.store = {"control/active.json": {"active": active, "epoch": 3, "mode": "takeover", "from": None, "since": 0}}
        self.hub = {c: True for c in IPS}           # отвечает ли /api/v2/health как хаб
        self.up = {c: True for c in IPS}            # отвечает ли по HTTPS вообще
        self.outside = True                         # видит ли переключатель внешние точки
        self.dns = {"": [IPS[active]], "www": [IPS[active]]}
        self.notes, self.s3_down, self.dns_fail = [], False, False

    def get(self, ip, path):
        code = next(c for c, i in IPS.items() if i == ip)
        if not self.up[code]:
            raise OSError("нет соединения")
        if path == "/api/v2/health":
            return (200, b'{"ok": true, "db_ok": true}') if self.hub[code] else (503, b"{}")
        return 200, b""

    def reach(self, url):
        return self.outside

    def s3_keys(self, prefix):
        if self.s3_down:
            raise RuntimeError("S3: нет связи")
        return {k for k in self.store if k.startswith(prefix)}

    def s3_get_json(self, key):
        if self.s3_down:
            raise RuntimeError("S3: нет связи")
        return dict(self.store[key])

    def s3_put_json(self, key, obj):
        if self.s3_down:
            raise RuntimeError("S3: нет связи")
        self.store[key] = obj

    def dns_get(self, sub):
        return list(self.dns[sub])

    def dns_set(self, sub, ip):
        if self.dns_fail:
            raise RuntimeError("Porkbun: ошибка")
        self.dns[sub] = [ip]

    def notify(self, text):
        self.notes.append(text)
        return True

    def now(self):
        return self.t


def run(net, st, minutes=1, n=1):
    out = None
    for _ in range(n):
        out = F.step(net, CONF, st)
        net.t += 60 * minutes
    return out


print("всё в порядке")
net, st = Net(), {}
out = run(net, st)
check("активный отвечает: ничего не трогаем", out == "хаб DDD1-XD в порядке" and not net.notes, (out, net.notes))
net.dns[""] = [IPS["AAA1-XA"]]
net.t += 600
out = run(net, st)
check("DNS разошёлся с активным: поправлен и сообщено", net.dns[""] == [IPS["DDD1-XD"]] and "поправил" in net.notes[-1], (out, net.dns))

print("вниз")
net, st = Net(), {}
net.hub["DDD1-XD"] = net.up["DDD1-XD"] = False
outs = [run(net, st) for _ in range(5)]
check("молчит меньше 5 минут: ждём", all("молчит" in o for o in outs) and net.store["control/active.json"]["active"] == "DDD1-XD", outs)
out = run(net, st)
ctl = net.store["control/active.json"]
check("5 минут: назначен следующий по приоритету (BBB1-XB), аварийно", ctl["active"] == "BBB1-XB" and ctl["mode"] == "takeover" and ctl["from"] == "DDD1-XD"
      and ctl["epoch"] == 4, (out, ctl))
check("DNS пока не трогали, о назначении сообщено", net.dns[""] == [IPS["DDD1-XD"]] and "назначаю BBB1-XB" in net.notes[-1], (net.dns, net.notes))
out = run(net, st)
check("пока назначенный не отметился готовым: ждём", out == "жду, пока BBB1-XB поднимется", out)
net.store["control/ready-4-BBB1-XB.json"] = {}
out = run(net, st)
check("готов и отвечает как хаб: обе A-записи на него", net.dns == {"": [IPS["BBB1-XB"]], "www": [IPS["BBB1-XB"]]} and "переключён на BBB1-XB" in net.notes[-1], (out, net.dns))
check("после переключения спокойно", run(net, st) == "хаб BBB1-XB в порядке")

print("назначенный не поднялся")
net, st = Net(), {}
net.hub["DDD1-XD"] = net.up["DDD1-XD"] = False
run(net, st, n=6)
check("назначен BBB1-XB", net.store["control/active.json"]["active"] == "BBB1-XB")
net.hub["BBB1-XB"] = False
run(net, st, n=15)
ctl = net.store["control/active.json"]
check("15 минут без готовности: следующий (AAA1-XA)", ctl["active"] == "AAA1-XA" and ctl["epoch"] == 5 and ctl["from"] == "BBB1-XB", ctl)

print("слепота переключателя и пустой резерв")
net, st = Net(), {}
net.hub["DDD1-XD"] = net.up["DDD1-XD"] = False
net.up["BBB1-XB"] = net.up["AAA1-XA"] = False
net.outside = False
out = run(net, st, n=8)
check("сам почти никого не видит: не переключает", "не переключаю" in out and net.store["control/active.json"]["active"] == "DDD1-XD", out)
net.outside = True
out = run(net, st)
check("видит внешние точки, но кандидаты молчат: одно оповещение, без переключения", "кандидатов нет" in out and len(net.notes) == 1
      and net.store["control/active.json"]["active"] == "DDD1-XD", (out, net.notes))
run(net, st, n=3)
check("оповещение не повторяется каждую минуту", len(net.notes) == 1, net.notes)
net.hub["DDD1-XD"] = net.up["DDD1-XD"] = True
run(net, st)
check("хаб ожил: «снова отвечает»", "снова отвечает" in net.notes[-1], net.notes)

print("наверх")
net, st = Net(active="BBB1-XB"), {"switched": 0}
outs = [run(net, st) for _ in range(29)]
check("основной жив меньше 30 минут: остаёмся", net.store["control/active.json"]["active"] == "BBB1-XB", outs[-1])
out = run(net, st, n=2)
ctl = net.store["control/active.json"]
check("30 минут жив: плановая передача наверх", ctl["active"] == "DDD1-XD" and ctl["mode"] == "handover" and ctl["from"] == "BBB1-XB", (out, ctl))
net2, st2 = Net(active="BBB1-XB"), {"switched": 1_000_000 + 600}       # переключались через 10 минут после начала отсчёта живости
run(net2, st2, n=35)
check("основной жив 35 минут, но с переключения меньше 30: остаёмся", net2.store["control/active.json"]["active"] == "BBB1-XB", net2.store["control/active.json"])
run(net2, st2, n=6)
check("30 минут и от переключения: передача наверх", net2.store["control/active.json"]["active"] == "DDD1-XD", net2.store["control/active.json"])
net3, st3 = Net(active="BBB1-XB"), {"switched": 0}
for i in range(40):
    net3.up["DDD1-XD"] = (i % 10 != 5)             # раз в 10 минут пропадает
    run(net3, st3)
check("основной то есть, то нет: наверх не переключаем", net3.store["control/active.json"]["active"] == "BBB1-XB")

print("ложное «жив 30 минут» у бывшего активного")
net, st = Net(active="BBB1-XB"), {"switched": 0, "up_since": {"BBB1-XB": 1}}
run(net, st)
check("у активного отсчёт живости сбрасывается", "BBB1-XB" not in st["up_since"], st["up_since"])

print("ошибки")
net, st = Net(), {}
net.s3_down = True
out = run(net, st, n=14)
check("S3 недоступен: ничего не делаем и пока молчим", "нет связи с S3" in out and not net.notes, (out, net.notes))
run(net, st, n=2)
check("15 минут без S3: одно оповещение", len(net.notes) == 1 and "S3" in net.notes[0], net.notes)
net.s3_down = False
run(net, st)
check("S3 вернулся: сообщено", "снова видит S3" in net.notes[-1], net.notes)
net, st = Net(), {}
net.hub["DDD1-XD"] = net.up["DDD1-XD"] = False
run(net, st, n=6)
net.store["control/ready-4-BBB1-XB.json"] = {}
net.dns_fail = True
out = run(net, st, n=3)
check("DNS не переключается: одно оповещение, пробует дальше", "DNS не переключён" in out and sum("DNS переключить не удалось" in n for n in net.notes) == 1, (out, net.notes))
net.dns_fail = False
run(net, st)
check("Porkbun ожил: DNS переключён", net.dns[""] == [IPS["BBB1-XB"]] and st.get("pending") is None, (net.dns, st))
net, st = Net(), {}
net.store["control/active.json"]["active"] = "XXX"
check("в файле неизвестный кандидат: ничего не делаем", "не в списке" in run(net, st))

print("постоянная ошибка переключателя")
class Boom(Net):
    def s3_get_json(self, key):
        raise ValueError("сломано")          # не ошибка связи с S3, а неожиданная
ORIG = (F.load_conf, F.load_state, F.save_state, F.Net, F.step)
F.load_conf = lambda: CONF
F.load_state = lambda: STATE
saved = []
F.save_state = lambda st: saved.append(dict(st))
STATE = {}
boom = Boom()
F.Net = lambda conf: boom
F.step = (lambda orig: (lambda net, conf, st: (_ for _ in ()).throw(RuntimeError("Porkbun: ключ отклонён"))))(F.step)
for _ in range(16):
    F.main(["x", "run"])
check("15 ошибок подряд: одно оповещение", sum("15 раз подряд" in n for n in boom.notes) == 1, boom.notes)
F.step = lambda net, conf, st: "ок"
F.main(["x", "run"])
check("заработал: «снова работает без ошибок»", "снова работает" in boom.notes[-1] and "errors" not in STATE, (boom.notes, STATE))
F.load_conf, F.load_state, F.save_state, F.Net, F.step = ORIG

print("HTTPS на адрес под именем домена")
import ssl, socket, threading, subprocess, tempfile, http.server
tmp = tempfile.mkdtemp()
key, crt = os.path.join(tmp, "k.pem"), os.path.join(tmp, "c.pem")
r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=example.test",
                    "-addext", "subjectAltName=DNS:example.test"], capture_output=True)
if r.returncode != 0:
    print("  ПРОПУСК: нет openssl для самоподписанного сертификата")
else:
    seen = {}

    class Hh(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen["host"] = self.headers.get("Host")
            b = b'{"ok": true, "db_ok": true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), Hh)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(crt, key)
    sni = {}
    sctx.sni_callback = lambda s, name, c: sni.update(name=name)
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    orig = F._Conn.__init__

    def init(self, ip, domain, timeout):
        orig(self, ip, domain, timeout)
        self.port = port
        self._context = ssl.create_default_context(cafile=crt)
    F._Conn.__init__ = init
    real = F.Net({"DOMAIN": "example.test", "CHECK_TIMEOUT": "5"})
    check("сертификат домена принят при соединении по адресу; SNI и Host с именем домена", F.hub_ok(real, "127.0.0.1") and sni.get("name") == "example.test"
          and seen.get("host") == "example.test", (sni, seen))
    real2 = F.Net({"DOMAIN": "other.test", "CHECK_TIMEOUT": "5"})
    check("сертификат другого имени не принимается", F.hub_ok(real2, "127.0.0.1") is False and F.alive(real2, "127.0.0.1") is False)
    F._Conn.__init__ = orig
    srv.shutdown()

print("ИТОГ:", "всё прошло" if not fails else "ошибок: %d" % fails)
sys.exit(1 if fails else 0)
