#!/bin/sh
# Интерфейсные тесты сайта (русская версия = эталон, английская без кириллицы и с верными ссылками). Нужны Docker и собранный сайт (python build_site.py).
# Запуск из каталога udpcheck-server:  sh tests/i18n/run.sh
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# в Git Bash пути для Docker переводим в вид C:/...
if command -v cygpath >/dev/null 2>&1; then S="$(cygpath -m "$ROOT/site")"; T="$(cygpath -m "$ROOT/tests/i18n")"; else S="$ROOT/site"; T="$ROOT/tests/i18n"; fi
RUN="docker run --rm -v $S:/site:ro -v $T:/t -w /t mcr.microsoft.com/playwright/python:v1.49.1-noble"
export MSYS_NO_PATHCONV=1
$RUN sh -c "pip install -q playwright==1.49.1 2>&1 | tail -0; python harness.py --site /site --lang ru --compare /t/golden_ru.json && python harness.py --site /site --lang en --check-en && python harness.py --site /site --lang en --check-en --width 360 && python harness.py --site /site --lang ru --width 360 --check-overflow"
