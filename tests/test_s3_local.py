# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Клиент S3 для копий (ops/udpcheck-s3): подпись по эталону AWS и работа с поддельным S3-сервером. Запуск: python tests/test_s3_local.py"""
import datetime
import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "ops", "udpcheck-s3")
FAILS = []


def check(name, cond, extra=""):
    print(("  OK   " if cond else "  FAIL ") + name + ("" if cond else "  " + str(extra)))
    if not cond:
        FAILS.append(name)


loader = importlib.machinery.SourceFileLoader("udpcheck_s3", SCRIPT)
spec = importlib.util.spec_from_loader("udpcheck_s3", loader)
M = importlib.util.module_from_spec(spec)
loader.exec_module(M)

print("[подпись SigV4]")
# эталонный пример из документации AWS S3 (GET Object с заголовком Range)
now = datetime.datetime(2013, 5, 24, 0, 0, 0, tzinfo=datetime.timezone.utc)
_h, sig = M.sigv4_headers("GET", "examplebucket.s3.amazonaws.com", "/test.txt", {}, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                          "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", now, extra={"Range": "bytes=0-9"})
check("подпись совпадает с эталоном документации AWS", sig == "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", sig)

print("[работа с S3-сервером]")
STORE = {}
SEEN = []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _key(self):
        p = urllib.parse.urlsplit(self.path)
        parts = urllib.parse.unquote(p.path).lstrip("/").split("/", 1)
        return (parts[1] if len(parts) > 1 else ""), urllib.parse.parse_qs(p.query)

    def do_PUT(self):
        key, _q = self._key()
        n = int(self.headers.get("Content-Length", "0"))
        STORE[key] = self.rfile.read(n)
        SEEN.append(self.headers.get("Authorization", ""))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        key, q = self._key()
        if key == "":
            pref = (q.get("prefix") or [""])[0]
            items = "".join("<Contents><Key>%s</Key><Size>%d</Size></Contents>" % (k, len(v)) for k, v in sorted(STORE.items()) if k.startswith(pref))
            body = ('<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>false</IsTruncated>%s</ListBucketResult>' % items).encode()
            self.send_response(200)
        elif key in STORE:
            body = STORE[key]
            self.send_response(200)
        else:
            body = b"<Error/>"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_DELETE(self):
        key, _q = self._key()
        STORE.pop(key, None)
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


srv = HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
env = dict(os.environ, S3_ENDPOINT="127.0.0.1:%d" % srv.server_port, S3_REGION="ru-3", S3_BUCKET="bk", S3_ACCESS_KEY="AK", S3_SECRET_KEY="SK",
           S3_SCHEME="http", S3_PATHSTYLE="1", PYTHONUTF8="1")


def run(*args):
    return subprocess.run([sys.executable, SCRIPT] + list(args), env=env, capture_output=True, text=True, encoding="utf-8", timeout=60)


tmp = tempfile.mkdtemp()
src = os.path.join(tmp, "a.bin")
open(src, "wb").write(os.urandom(5000))
for i in range(5):
    r = run("put", src, "hub/hub-2026100%d-0300.tar.gz.enc" % i)
check("загрузка работает", r.returncode == 0 and len(STORE) == 5, r.stderr)
check("запрос подписан (заголовок Authorization с AWS4-HMAC-SHA256)", SEEN and SEEN[0].startswith("AWS4-HMAC-SHA256 Credential=AK/") and "/ru-3/s3/aws4_request" in SEEN[0], SEEN[:1])
r = run("list", "hub/")
check("список показывает 5 объектов", len(r.stdout.strip().splitlines()) == 5, r.stdout)
out = os.path.join(tmp, "b.bin")
r = run("get", "hub/hub-20261003-0300.tar.gz.enc", out)
check("скачанный файл совпадает с загруженным", r.returncode == 0 and open(out, "rb").read() == open(src, "rb").read(), r.stderr)
r = run("prune", "hub/", "3")
check("prune оставляет 3 последних, удаляя самые старые", sorted(STORE) == ["hub/hub-20261002-0300.tar.gz.enc", "hub/hub-20261003-0300.tar.gz.enc", "hub/hub-20261004-0300.tar.gz.enc"], (r.stdout, sorted(STORE)))
r = run("delete", "hub/hub-20261002-0300.tar.gz.enc")
check("удаление работает", r.returncode == 0 and len(STORE) == 2, r.stderr)
r = run("get", "hub/нет-такого", out)
check("ошибка скачивания даёт ненулевой код", r.returncode != 0)
srv.shutdown()

print()
print("ИТОГ: всё прошло" if not FAILS else "ИТОГ: ПРОВАЛЕНО %d: %s" % (len(FAILS), "; ".join(FAILS)))
sys.exit(1 if FAILS else 0)
