# Что стоит на серверах (не из этого каталога кода)

Хаб (сервер в России):
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

