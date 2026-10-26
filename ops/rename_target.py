#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 UDPcheck authors
"""Переименование кода опорного сервера в истории хаба (например, AAA1-XA -> EEE1-XE).
Меняет код в таблицах замеров (tres, meas, traces) и в результатах браузерных проверок (webchecks.data, JSON со списком серверов).
Запускать при остановленном хабе, на копии базы проверить заранее:
  systemctl stop udpcheck && python3 rename_target.py /var/lib/private/udpcheck/hub.db AAA1-XA EEE1-XE && systemctl start udpcheck
Настройки: rename_target.py --config AAA1-XA EEE1-XE  меняет код там, где он есть на ЭТОМ сервере: поле code в /etc/udpcheck/targets.json (хаб),
UDPCHECK_TARGET_ID в /etc/udpcheck/target.env и ROLE_SELF в /etc/udpcheck/role.env (сам опорный), код в CANDIDATES в
/etc/udpcheck-failover/failover.env (переключатель). Содержимое файлов не выводится, только сколько замен; права файлов сохраняются.
"""
import json
import os
import re
import sqlite3
import sys
import tempfile

CODE = re.compile(r"^[A-Z0-9]{2,8}-[A-Z]{2}$")


def rename(db_path, old, new):
    """Возвращает {таблица: сколько строк изменено}. Всё в одной транзакции: при ошибке база остаётся как была."""
    if not (CODE.match(old) and CODE.match(new)) or old == new:
        raise ValueError("коды должны быть вида ABC1-XX и различаться")
    db = sqlite3.connect(db_path)
    try:
        if db.execute("SELECT 1 FROM tres WHERE target = ? LIMIT 1", (new,)).fetchone():
            raise ValueError("код %s уже есть в истории: склеивать два сервера скрипт не будет" % new)
        out = {}
        with db:
            for tbl in ("tres", "meas", "traces"):
                out[tbl] = db.execute("UPDATE %s SET target = ? WHERE target = ?" % tbl, (new, old)).rowcount
            n = 0
            for rid, data in db.execute("SELECT id, data FROM webchecks WHERE data LIKE ?", ('%"' + old + '"%',)).fetchall():
                try:
                    res = json.loads(data)
                except ValueError:
                    continue
                changed = False
                for r in res if isinstance(res, list) else []:
                    if isinstance(r, dict) and r.get("code") == old:
                        r["code"] = new
                        changed = True
                if changed:
                    db.execute("UPDATE webchecks SET data = ? WHERE id = ?", (json.dumps(res), rid))
                    n += 1
            out["webchecks"] = n
        return out
    finally:
        db.close()


CONFIG_FILES = ("/etc/udpcheck/targets.json", "/etc/udpcheck/target.env", "/etc/udpcheck/role.env", "/etc/udpcheck-failover/failover.env")


def _write_same_mode(path, text):
    """Атомарная запись с прежними правами и владельцем (в файлах секреты: 0600 должно остаться 0600)."""
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.chmod(tmp, st.st_mode & 0o7777)
        if hasattr(os, "chown"):
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except PermissionError:
                pass
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def rename_config(old, new, files=CONFIG_FILES):
    """{файл: сколько замен} для существующих файлов из списка. Меняется только сам код, остальное содержимое как было."""
    if not (CODE.match(old) and CODE.match(new)) or old == new:
        raise ValueError("коды должны быть вида ABC1-XX и различаться")
    out = {}
    for path in files:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", newline="") as fh:
            text = fh.read()
        n = 0
        if path.endswith(".json"):
            data = json.loads(text)
            codes = [t.get("code") for t in data if isinstance(t, dict)]
            if old in codes and new in codes:          # уже переименован: ничего не делаем; оба сразу: это два разных сервера, не склеиваем
                raise ValueError("в %s есть и %s, и %s" % (os.path.basename(path), old, new))
            for t in data:
                if isinstance(t, dict) and t.get("code") == old:
                    t["code"] = new
                    n += 1
            new_text = json.dumps(data, ensure_ascii=False)
        else:
            def sub(pattern, repl, s):
                r, k = re.subn(pattern, repl, s, flags=re.M)
                return r, k
            new_text, k1 = sub(r"^(UDPCHECK_TARGET_ID|ROLE_SELF)=" + re.escape(old) + r"[ \t\r]*$", lambda m: m.group(1) + "=" + new, text)
            new_text, k2 = sub(r"(?<=[=,])" + re.escape(old) + r"(?==)", new, new_text)        # CANDIDATES="КОД=адрес,..."
            n = k1 + k2
        if n:
            _write_same_mode(path, new_text)
        out[os.path.basename(path)] = n
    return out


def main(argv):
    if len(argv) == 4 and argv[1] == "--config":
        try:
            out = rename_config(argv[2], argv[3])
        except (ValueError, OSError) as e:
            print("не переименовано: %s" % e)
            return 1
        print("настройки %s -> %s: %s" % (argv[2], argv[3], ", ".join("%s %d" % kv for kv in out.items()) or "файлов с кодом нет"))
        return 0
    if len(argv) != 4:
        print(__doc__)
        return 2
    try:
        out = rename(argv[1], argv[2], argv[3])
    except (ValueError, sqlite3.Error) as e:
        print("не переименовано: %s" % e)
        return 1
    print("переименовано %s -> %s: %s" % (argv[2], argv[3], ", ".join("%s %d" % kv for kv in out.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
