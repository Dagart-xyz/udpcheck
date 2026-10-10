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

## Защита от ботов и сканеров

На публичном сервере сразу видны сканеры (на нашем хабе около 800 неудачных попыток входа по SSH в сутки). Минимум, который мы ставим, без журналов адресов посетителей:
- вход по SSH только по ключам (`PasswordAuthentication no`) и `fail2ban` с нарастающим баном (`ops/hardening/fail2ban-udpcheck.local` в `/etc/fail2ban/jail.d/` и `fail2ban-db.local` в `/etc/fail2ban/fail2ban.d/`): час, потом 2, 4, 8, 16, 32, 64 часа, потолок 4 недели; на Ubuntu юнит называется `ssh.service`. Снять бан: `fail2ban-client unban <адрес>`;
- `ops/hardening/udpcheck-guard.nft` (хаб) и `udpcheck-guard-anchor.nft` (опорный сервер без веб-сервера): ограничение частоты новых соединений и пакетов с одного адреса в ядре (nftables), состояние только в памяти. Новые версии nft показывают счётчики как динамические множества (`set ssh4 {...}`): смотрите `nft list table inet udpcheck_guard`;
- `ops/hardening/99-udpcheck-hardening.conf` (sysctl) и в `Caddyfile.dagart` таймауты, ограничение размера заголовков и тела запроса, сжатие ответов, HSTS, `Permissions-Policy` и строгий CSP;
- `ops/hardening/journald-udpcheck.conf` в `/etc/systemd/journald.conf.d/`: системный журнал не дольше 30 суток (в нём попытки входа по SSH; это единственное место, где остаются адреса, и политика данных об этом говорит);
- `ops/hardening/sshd-udpcheck.conf` в `/etc/ssh/sshd_config.d/10-udpcheck.conf`: только ключи, без проброса портов, X11 и агента, `LoginGraceTime 30`, `MaxAuthTries 4` (проверьте `sshd -t` и откройте второе подключение, прежде чем закрыть первое);
- автообновления безопасности: `unattended-upgrades` и `ops/hardening/20auto-upgrades`. На некоторых образах хостеров `apt-daily*.service` замаскированы (`systemctl unmask apt-daily.service apt-daily-upgrade.service`). Ядро и libc применяются только после перезагрузки: смотрите `/var/run/reboot-required` и перезагружайте серверы по одному, проверяя после каждого `nft list tables`, службы и ответ портов снаружи;
- `ops/hardening/caddy-sandbox.conf` в `/etc/systemd/system/caddy.service.d/sandbox.conf`: Caddy может писать только в `/var/lib/caddy` и `/var/log/caddy` (оценка `systemd-analyze security` 8.8 → 1.6);
- `ops/udpcheck-hostcheck.py` с `udpcheck-hostcheck.service` и `.timer` (`/usr/local/sbin`, `/etc/systemd/system`) раз в 5 минут пишет `/run/udpcheck-host.json`: нужна ли перезагрузка, есть ли обновления безопасности, баны за час, адреса входов по SSH. Рабочий процесс передаёт это хабу в своём подписанном опросе, наблюдатель сообщает о перезагрузке старше 2 суток, обновлениях безопасности старше 3 суток, волне банов (60 в час) и входе по SSH с нового адреса (первые 24 часа адреса только запоминаются; в своём состоянии наблюдатель хранит их хэши);
- перед публикацией правок прогоняйте `tests/fuzz_local.py` (мусорные UDP- и HTTP-запросы) и остальные `tests/test_*_local.py`.
Применяйте правила nftables с откатом по таймеру (`systemd-run --on-active=180 nft delete table inet udpcheck_guard`), пока не убедились, что доступ по SSH остался.

## Сайт на двух языках

Страницы собираются командой `python build_site.py` из шаблона `siteparts/index.tpl.html` и текстов `siteparts/strings.py` (русский: `site/index.html`, `/`; английский: `site/en/index.html`, `/en/`). Документы (`privacy`, `terms`) на каждом языке лежат отдельными файлами. Там же собираются `sitemap.xml` и `robots.txt`; выкладка: `ops/deploy_site.sh` (метка версии ставится в обе страницы).

- Хаб отдаёт английские названия вместе с русскими (`name_en`). Для серверов проекта задайте `name_en` в `targets.json` (иначе будет транслитерация), для провайдеров словарь `names_en.json` рядом с `names.json` (иначе транслитерация, а в еженедельном разборе названий такие сети помечаются).
- Страницы провайдеров (`/asNNN`, `/en/asNNN`) закрыты от индексации заголовком `X-Robots-Tag: noindex` (см. `Caddyfile.dagart`); главная и документы открыты. Чтобы открыть и страницы провайдеров, уберите строку `header @prov X-Robots-Tag`.
- Тесты интерфейса: `sh tests/i18n/run.sh` (нужен Docker). Русская версия сверяется с эталоном `tests/i18n/golden_ru.json` до буквы; английская проверяется на отсутствие русского текста, верные ссылки и отсутствие горизонтальной прокрутки на узком экране. Менять русские тексты можно, но эталон тогда нужно записать заново (`harness.py --out`), осознанно.

## Замедлитель роботов

`ops/udpcheck-tarpit.py` с `udpcheck-tarpit.service` (порт 127.0.0.1:18081). Caddy направляет к нему запросы страниц без признаков браузера (нет ни `Accept-Language`, ни `Sec-Fetch-Mode`; исключены поисковики, превью ссылок и служебные адреса, см. `@robotish` в `Caddyfile.dagart`). Служба ждёт 6-15 секунд, получает ту же страницу у внутреннего адреса `127.0.0.1:18082` и отдаёт её порциями. Это не блокировка: страница приходит целиком. Пределы: 300 ожиданий одновременно и 6 с одного адреса (сверх лимита с одного адреса ответ 429, сверх общего лимита без задержки). Живой посетитель с браузером под правило не попадает; если нужно отключить, уберите блок `handle @robotish` из Caddyfile.

### Защита от сканеров: запросы-атаки и поддельные поисковики

Тот же замедлитель выполняет ещё две роли, их включает Caddy заголовками (см. `@probe` и `@claimedbot` в `Caddyfile.dagart`).

- **Запросы-атаки (`X-Probe: 1`).** Адрес или User-Agent похож на сканер: поиск `.env`, `.git`, WordPress, phpMyAdmin, GraphQL, обход каталогов, SQL-инъекции, известные сканеры (sqlmap, nikto, nuclei и т. п.). Служба ждёт 8-20 секунд, отвечает `404` (страницу не отдаёт) и пишет в системный журнал строку `PROBE <адрес> <запрос>`. Адрес берётся из `X-Forwarded-For`, который ставит Caddy, и проверяется как IP; в тексте запроса пробелы и управляющие символы заменяются на `_`, поэтому вписать в журнал чужой адрес нельзя. fail2ban (`ops/hardening/fail2ban-probe.local`, фильтр `fail2ban-probe-filter.conf`) блокирует повторившего (3 раза за 10 минут) на портах 80/443 на сутки; при повторах срок растёт, как у SSH. Журнал замедлителя единственный на сайте, где остаются адреса, и только для запросов-атак; ограничение 30 суток держит journald (см. раздел про журналы). Это нужно отражать в политике конфиденциальности (`site/privacy.html`).
- **Подделки поисковиков (`X-Claimed-Bot: 1`).** User-Agent называет Googlebot, Bingbot, YandexBot или Applebot. Служба проверяет адрес по обратному DNS (имя должно быть у google.com/googlebot.com, yandex.ru/net/com, search.msn.com, applebot.apple.com) и подтверждает прямым DNS (имя ведёт обратно на тот же адрес). Настоящий бот получает страницу сразу, подделка идёт медленным путём, как любой робот без признаков браузера. Если DNS не ответил, бот считается настоящим (не вредим индексации); результат запоминается на час.
- **Исключения из бана.** В `ignoreip` джейла `udpcheck-probe` внесите адреса, которые никогда не должны блокироваться: сам хаб, опорные серверы сети (они постоянно опрашивают хаб), адрес администратора. Настоящие поисковые боты не банятся ещё и скриптом `ops/hardening/udpcheck-goodbot.sh` (та же проверка по DNS).
- **Установка.** Файлы кладёт `ops/apply_probe_guard.sh` (с проверкой конфигурации Caddy и fail2ban и автоматическим откатом): заранее скопируйте в `/tmp` на хабе `Caddyfile.new`, `udpcheck-tarpit.py.new`, `udpcheck-tarpit.service.new`, `fail2ban-probe-filter.conf`, `fail2ban-probe.local`, `udpcheck-goodbot.sh` и запустите `IGNORE="адрес1 адрес2" sh /tmp/apply_probe_guard.sh`. Проверить блокировку можно с постороннего сервера (не из `ignoreip`): три запроса `/wp-login.php`, после них порты 80/443 с этого адреса закрыты. Снять: `fail2ban-client set udpcheck-probe unbanip АДРЕС`; выключить совсем: убрать `jail.d/udpcheck-probe.local` и блок `handle @probe` из Caddyfile.

## Подпись установщика и агента

`build_site.py` подписывает агент и установщик ключом Ed25519 (закрытый ключ `release_ed25519.pem` хранится у владельца проекта вне хаба и вне репозитория, открытый лежит в `installer/release.pub.pem` и вшит в установщик). Установщик проверяет подпись агента, если у системы есть `openssl` с поддержкой Ed25519 (3.0+): нет подписи или она не сходится, установка прерывается. На роутерах и старых системах остаётся только проверка SHA-256, установщик об этом говорит.

Если хаб взломают, злоумышленник сможет подменить и установщик. Поэтому подозрительный установщик проверяйте по ключу из репозитория, а не с хаба:

```
curl -fsSL https://dagart.xyz/i -o install-node.sh
curl -fsSL https://dagart.xyz/install-node.sh.sig -o install-node.sh.sig
curl -fsSL https://raw.githubusercontent.com/Dagart-xyz/udpcheck/main/installer/release.pub.pem -o release.pub.pem
openssl pkeyutl -verify -pubin -inkey release.pub.pem -rawin -in install-node.sh -sigfile install-node.sh.sig
```

Свой форк: создайте ключ `openssl genpkey -algorithm ed25519 -out release_ed25519.pem`, положите открытую часть (`openssl pkey -in release_ed25519.pem -pubout`) в `installer/release.pub.pem` и пересоберите сайт.

## 5. Проверка и сопровождение

**Перенос базы на другой сервер.** Службе принадлежит только каталог состояния. Если вы кладёте `hub.db` от имени root, после переноса выполните
`chown -R $(stat -c %u /var/lib/private/udpcheck) /var/lib/private/udpcheck` и перезапустите службу: иначе хаб сможет читать базу, но все записи
(проверки посетителей, регистрация узлов) будут падать с ошибкой 500. Теперь `/api/v2/health` показывает `db_ok`, а наблюдатель сообщает, если запись в базу не работает.


```
python tests/test_v2_local.py      # хаб, цели, узлы, провайдеры, журнал
python tests/test_refs_local.py    # серверы добровольцев
python tests/test_pad_local.py     # длинные ответы
python tests/test_watch_local.py   # оповещения и разбор названий
python tests/names_selftest.py     # названия и группы операторов
python tests/test_s3_local.py      # клиент S3 для резервных копий
```
Нагрузочная проверка хаба (виртуальные посетители, ядро хаба ограничено одним процессором; нужен Docker):
```
docker run --rm --cpus=2 --memory=1g -v <каталог проекта>:/p:ro python:3.12-slim python /p/tests/load_local.py 120,360,900
```
На хабе с одним ядром без ошибок проходят около 1800 посетителей в минуту (ядро занято на 60%); основная нагрузка в реальной работе приходится на веб-сервер и TLS.
Обновление: заменить два файла в `/opt/udpcheck/` и `systemctl restart udpcheck` (сначала хаб, потом опорные серверы). Старые данные
удаляются сами по сроку хранения.

## Что нельзя менять, если вы называете сервис своим для людей

Принципы из [PRIVACY-PRINCIPLES.md](../PRIVACY-PRINCIPLES.md): не писать адреса посетителей в журналы и базу, не подключать стороннюю
аналитику и скрипты, не отправлять адреса посетителей сторонним сервисам. Если ваша копия от них отходит, скажите об этом посетителям прямо.
