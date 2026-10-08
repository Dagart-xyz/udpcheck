# Что стоит на серверах (не из этого каталога кода)

Хаб:
- `udpcheck-backup` (/usr/local/sbin) + `udpcheck-backup.service/.timer`: ежедневно в 03:30 по Москве копия хаба по ssh на сервер копий
  (ключ /root/.ssh/backup_ed25519, только приём архива; адрес сервера копий в /etc/udpcheck/backup.env: BACKUP_DEST=пользователь@сервер).
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
/etc/udpcheck/backup.env (S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_ACCESS_KEY, S3_SECRET_KEY, S3_KEEP), архив шифруется паролем из
/etc/udpcheck/backup.pass (храните копию пароля вне сервера: без него копию не расшифровать). Расшифровка:
`openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:backup.pass -in копия.tar.gz.enc -out копия.tar.gz`. Просмотр и скачивание:
`udpcheck-s3 list hub/`, `udpcheck-s3 get hub/имя файл`.
