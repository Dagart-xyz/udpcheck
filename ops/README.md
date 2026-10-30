# Что стоит на серверах (не из этого каталога кода)

Хаб:
- `udpcheck-backup` (/usr/local/sbin) + `udpcheck-backup.service/.timer`: раз в час (в 17 минут) копия хаба, вместе с сертификатами Caddy, в S3 и/или по ssh
  на сервер копий (ключ /root/.ssh/backup_ed25519, только приём архива; адрес сервера копий в /etc/udpcheck/backup.env: BACKUP_DEST=пользователь@сервер).
- `udpcheck-geo-update` + `geo.service/.timer` (в системе как udpcheck-geo.*): ежедневно в 03:00 по Москве проверка баз GeoIP DB-IP Lite.
  Только на хабе: опорным серверам базы не нужны.
- /opt/udpcheck/geo/cities_ru.sqlite: справочник русских названий городов (GeoNames, CC BY 4.0), собирается `build_cities_ru.py` на сервере с быстрым каналом
  (нужны cities1000.zip и alternateNamesV2.zip с download.geonames.org). Нет в справочнике: показываем английское название.
- файл подкачки /swapfile (1 ГБ), /etc/sysctl.d/99-udpcheck-swap.conf (vm.swappiness=10).
- /etc/udpcheck/targets.json (секреты опорных серверов, 0600), /opt/udpcheck/geo/{names,overrides}.json, /var/www/udpcheck-site/.

Сервер копий (любой отдельный сервер; адрес и ключ в /etc/udpcheck/backup.env): `udpc-backup-recv` (/usr/local/bin), пользователь udpbackup, 14 последних копий в
/home/udpbackup/backups.

Опорные серверы (HEL, AMS, PAR, MSK): только /opt/udpcheck/{udpcheck_server.py,udpcheck_v2.py}, /etc/udpcheck/target.env, служба udpcheck.
Баз GeoIP и Caddy на них нет.

Копии в S3-хранилище (рекомендуется): `ops/udpcheck-s3` (в /usr/local/sbin) загружает архив по подписи SigV4 без внешних пакетов; настройки в
/etc/udpcheck/backup.env (S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_ACCESS_KEY, S3_SECRET_KEY; хранение S3_KEEP_HOURS=48 последних копий и по одной на сутки
за S3_KEEP_DAYS=14 суток), архив шифруется паролем из
/etc/udpcheck/backup.pass (храните копию пароля вне сервера: без него копию не расшифровать). Расшифровка:
`openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:backup.pass -in копия.tar.gz.enc -out копия.tar.gz`. Просмотр и скачивание:
`udpcheck-s3 list hub/`, `udpcheck-s3 get hub/имя файл`.
Загрузку копии `udpcheck-backup` пробует до 3 раз: если 30 с нет движения (зависла) или хранилище ответило 5xx, ещё попытка через минуту
(в backup.env можно поменять: BACKUP_PUT_TRIES, BACKUP_PUT_TIMEOUT, BACKUP_PUT_PAUSE). Ответы 4xx (доступ, подпись) не повторяются.
Остальные вызовы `udpcheck-s3` (роль хаба, переключатель) делают одну попытку, как раньше. Сами переменные S3_PUT_* в backup.env
не ставьте: этот файл читает и udpcheck-role, а его вызовы S3 ограничены 120 с.

## Несколько кандидатов в хабы (переключение при аварии)

Хаб может работать на одном из нескольких серверов-кандидатов; каждый из них одновременно опорный сервер. Кто сейчас хаб, записано в S3 в
`control/active.json`, и этот файл пишет только переключатель.
- Кандидаты: `udpcheck-role` (/usr/local/sbin) + `udpcheck-role.service/.timer` (раз в 30 с). Настройка `/etc/udpcheck/role.env`: `ROLE_SELF=` код
  опорного сервера этого кандидата. Нужны те же `backup.env` и `backup.pass`, что для копий, `udpcheck-restore`, Caddy с двумя конфигурациями
  `/etc/caddy/Caddyfile.hub` и `Caddyfile.standby` (их делает `caddy_modes.py` из обычного Caddyfile) и замедлитель роботов. Роль хаба включает
  дополнение `udpcheck.service.d/hub.conf` из копии; при выключении оно откладывается в `hub.conf.standby`. Копии делает только тот, кто сейчас хаб.
  Резервный раз в сутки берёт из последней копии сертификаты Caddy (`udpcheck-restore --certs-only` кладёт их и в /etc/caddy/standby-certs):
  в режиме ожидания Caddy работает с ними как с готовыми файлами и сам ничего не выпускает (проверки Let's Encrypt у резерва не прошли бы,
  а неудачи по одному имени ограничены и учётная запись общая).
  Кроме этого кандидату нужно то же, что хабу и чего нет в копии: базы DB-IP и `udpcheck-geo-update` с таймером (без них хаб не определяет сети),
  замедлитель роботов (`udpcheck-tarpit`, работает и в режиме ожидания), `udpcheck-hostcheck`, защита как у хаба (nftables, fail2ban с джейлом
  udpcheck-probe, sysctl, journald), файл подкачки.
  Адрес хаба в `target.env` кандидата должен быть публичным (`UDPCHECK_HUB_URL=https://домен/udpcheck`), а не локальным `http://127.0.0.1:18080/...`,
  и в `/etc/hosts` не должно быть строки с доменом сайта (cloud-init при имени машины, совпадающем с доменом, пишет `127.0.1.1 домен`): иначе в режиме
  ожидания опорный сервер отчитывается сам себе, и хаб его не видит. Таймер `udpcheck-role.timer` включать с `--now`.
- Переключатель: `udpcheck-failover` + `udpcheck-failover.service/.timer` (раз в минуту) на отдельном сервере. Настройки в `/etc/udpcheck-failover/`:
  `failover.env` (`CANDIDATES="КОД=адрес,..."` по приоритету, `DOMAIN`, `NTFY_TOPIC`, сроки `DOWN_AFTER=300`, `UP_AFTER=1800`, `READY_WAIT=900`),
  `porkbun.env` (ключ API регистратора для смены A-записей домена и www), `backup.env` (доступ к S3; пароль копий переключателю не нужен).
  Первый запуск: `udpcheck-failover init КОД` записывает, кто хаб сейчас. Служба работает от временного пользователя с потолками памяти и процессора.
- Оповещения переключатель и наблюдатель шлют в ntfy; если оттуда, где они работают, Telegram недоступен, пересылку в Telegram ставят на другой сервер: `udpcheck-tg-relay` (+ `.service/.timer`),
  настройки из `/etc/udpcheck-watch.env` (NTFY_TOPIC, TG_TOKEN, TG_CHAT). Сообщение больше 4096 байт ntfy.sh превращает в файл, и пересылка
  передаёт от него только «You received a file»; поэтому наблюдатель режет длинные сообщения на части до 3900 байт (`MSG_BYTES`).
- Сайт выкладывается на всех кандидатов: `HUBS="root@адрес1 root@адрес2 ..." sh ops/deploy_site.sh`.
- Переименование кода опорного сервера в истории: `ops/rename_target.py` (при остановленном хабе).
