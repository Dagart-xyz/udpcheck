# Как запустить свой хаб и опорные серверы

Это путь для тех, кто хочет поднять свою копию UDPcheck (для другой страны, для своей сети или для опытов). Копии просим давать своё имя
и домен: см. [NOTICE](../NOTICE). Если вы запускаете изменённую версию для других людей, лицензия AGPL-3.0 требует дать им её исходный код
(например, ссылкой на ваш форк в подвале сайта).

Нужны: Linux с systemd, Python 3.10+, `traceroute`, домен с HTTPS (подойдёт Caddy). Никаких пакетов Python ставить не нужно.

## Из чего состоит сеть

| Роль | Сколько | Что делает |
|---|---|---|
| Хаб | 1 | принимает проверки, хранит их, отдаёт страницу, API, журнал |
| Опорный сервер («цель») | минимум 2: один в стране посетителей (контроль), один за рубежом | отвечает на UDP-запросы браузера и узлов, строит маршрут до посетителя |
| Узел | сколько угодно | агент у пользователя, шлёт UDP-поток на опорные серверы |

Хаб может одновременно быть и опорным сервером своей страны (так сделано у dagart.xyz): для этого добавьте его в `targets.json` и положите ему
`/etc/udpcheck/target.env` (см. раздел 2). Опорные серверы нужно держать на разных провайдерах:
вывод «режется» строится на сравнении «у вас в стране» и «из-за рубежа».

## 1. Хаб

1. Файлы на сервер:
   ```
   mkdir -p /opt/udpcheck/geo /etc/udpcheck
   cp udpcheck_server.py udpcheck_v2.py /opt/udpcheck/
   cp udpcheck.service /etc/systemd/system/
   ```
2. Базы геолокации DB-IP Lite (бесплатные, CC BY 4.0, https://db-ip.com/db/lite.php) положите в `/opt/udpcheck/geo/` под именами
   `dbip-asn-lite.mmdb` и `dbip-city-lite.mmdb`. Обновляются раз в месяц: `ops/udpcheck-geo-update` с таймером делает это сам.
3. Список опорных серверов `/etc/udpcheck/targets.json` (права 0600). Секрет у каждого свой:
   ```
   [
     {"code": "HUB-XX", "name": "Страна, Город", "country": "XX", "ip": "203.0.113.10",
      "ports": [993, 777, 47321], "secret": "<openssl rand -hex 32>", "tcp_port": 8443},
     {"code": "AAA1-YY", "name": "Другая страна, Город", "country": "YY", "ip": "198.51.100.20",
      "ports": [993, 777, 47321], "secret": "<другой секрет>", "tcp_port": 8443}
   ]
   ```
   `country`: двухбуквенный код страны сервера. От него зависит, что для посетителя «своя страна», а что «из-за рубежа».
4. Настройки хаба, файл `/etc/systemd/system/udpcheck.service.d/hub.conf`:
   ```
   [Service]
   StateDirectory=udpcheck
   StateDirectoryMode=0750
   LoadCredential=targets.json:/etc/udpcheck/targets.json
   Environment=UDPCHECK_HUB_DB=/var/lib/udpcheck/hub.db
   MemoryMax=160M
   ```
5. Сайт: `python build_site.py`, затем `site/` на сервер в `/var/www/udpcheck-site`. Подставьте свой домен вместо `dagart.xyz`:
   в `udpcheck_node.py` (`DEFAULT_HUB`), `installer/install-node.sh.in` (`HUB=`), тексте `site/index.html`, `site/.well-known/security.txt`,
   и перед выкладкой замените `__BUILD__` в `index.html` меткой версии (`ops/deploy_site.sh` делает это сам).
6. Веб-сервер: образец `Caddyfile.dagart` (замените домен). Хаб слушает только `127.0.0.1:18080`, наружу его выставляет Caddy.
   Важно оставить в Caddy `log { output discard }`: адреса посетителей в журналах быть не должно.
7. Запуск: `systemctl daemon-reload && systemctl enable --now udpcheck`. Проверка: `curl https://ваш-домен/api/v2/health`.

Основные настройки хаба (переменные окружения `UDPCHECK_*`, значения по умолчанию в `udpcheck_v2.py`):

| Переменная | Что делает |
|---|---|
| `UDPCHECK_HUB_DB` | файл базы SQLite (хаб включается, когда она задана) |
| `UDPCHECK_HUB_TARGETS` | путь к `targets.json`, если не используете `LoadCredential` |
| `UDPCHECK_RETENTION_DAYS` | сколько дней хранить замеры (60) |
| `UDPCHECK_PROBE_INTERVAL` | как часто узел делает замер, с (900) |
| `UDPCHECK_PAD_PORTS` | порты длинных ответов `порт:байт,...`; пусто = выключено (`3478:600,19302:1200`) |
| `UDPCHECK_BEAT_SECRET`, `UDPCHECK_NTFY_TOPIC` | оповещения (необязательно, см. `ops/README.md`) |
| `UDPCHECK_TRUSTED_PROXIES` | какие адреса считать доверенным прокси (`127.0.0.1,::1`) |

## 2. Опорный сервер

Быстрый способ (с вашего компьютера, нужен SSH-доступ к новому серверу и к хабу):
```
UDPCHECK_KEY_TARGET=путь/к/ключу UDPCHECK_KEY_HUB=путь/к/ключу UDPCHECK_HUB_HOST=ваш-домен \
python add_target.py --code AAA1-YY --name "Страна, Город" --country YY --host 198.51.100.20
```
Скрипт ставит `traceroute`, кладёт файлы и службу, создаёт секрет, запрещает вход по паролю, дописывает цель в `targets.json` хаба и перезапускает хаб.

Вручную то же самое: файлы в `/opt/udpcheck/`, служба `udpcheck.service`, файл `/etc/udpcheck/target.env` (права 0600):
```
UDPCHECK_TARGET_ID=AAA1-YY
UDPCHECK_TARGET_SECRET=<секрет из targets.json>
UDPCHECK_HUB_URL=https://ваш-домен/udpcheck
UDPCHECK_TARGET_TCP_PORT=8443
```
Порты, которые нужно открыть: **UDP 993, 777, 47321, 3478, 19302** и **TCP 8443**. Порты 3478 и 19302 нужны для проверки по длине
пакета; если открыть их нельзя, задайте `UDPCHECK_PAD_PORTS=` (пусто): страница тогда просто не покажет эту часть.
Опорный сервер сам опрашивает хаб (исходящее соединение), входящие соединения к его HTTP не нужны.

## 3. Узлы

Установка узла указывает на ваш хаб переменной: `UDPCHECK_HUB=https://ваш-домен sh install-node.sh`.
Агент: `python3 udpcheck_node.py --hub https://ваш-домен`. Подробности и роли (`--role node|ref|both`): [PROTOCOL.md](../PROTOCOL.md).

## 4. Необязательное

- **Названия провайдеров.** `/opt/udpcheck/geo/names.json`: `{"12345": "Имя"}` (приоритет над автоматическим), `brands.json`: операторы из
  нескольких сетей (`[{"name": "Оператор", "match": ["регулярное выражение"]}]`, образец в `ops/brands.json`), `provider_kinds.json`:
  `{"12345": "hosting"}` для ручной пометки хостингов, `overrides.json`: исправления базы GeoIP (`[{"cidr": "...", "asn": ..., "org": "..."}]`).
- **Логотипы:** `python add_logo.py --asn 12345 --domain provider.example` (файл ляжет в `/var/www/udpcheck-site/logos/`).
- **Города по-русски:** `ops/build_cities_ru.py` (GeoNames).
- **Резервные копии:** `ops/udpcheck-backup` + таймер; адрес и ключ в `/etc/udpcheck/backup.env` (`BACKUP_DEST`, `BACKUP_KEY`).
- **Оповещения:** `ops/udpcheck-watch.py` на отдельном сервере (Telegram или ntfy), описание в начале файла и в `ops/README.md`.

## 5. Проверка и сопровождение

```
python tests/test_v2_local.py      # хаб, цели, узлы, провайдеры, журнал
python tests/test_refs_local.py    # серверы добровольцев
python tests/test_pad_local.py     # длинные ответы
python tests/test_watch_local.py   # оповещения и разбор названий
python tests/names_selftest.py     # названия и группы операторов
python tests/test_s3_local.py      # клиент S3 для резервных копий
```
Обновление: заменить два файла в `/opt/udpcheck/` и `systemctl restart udpcheck` (сначала хаб, потом опорные серверы). Старые данные
удаляются сами по сроку хранения.

## Что нельзя менять, если вы называете сервис своим для людей

Принципы из [PRIVACY-PRINCIPLES.md](../PRIVACY-PRINCIPLES.md): не писать адреса посетителей в журналы и базу, не подключать стороннюю
аналитику и скрипты, не отправлять адреса посетителей сторонним сервисам. Если ваша копия от них отходит, скажите об этом посетителям прямо.
