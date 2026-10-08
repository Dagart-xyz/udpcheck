@echo off
rem Имитация traceroute для локальных тестов: печатает заготовленный вывод.
rem Последний аргумент (адрес назначения) подставляется в последние хопы.
for %%a in (%*) do set DEST=%%a
echo traceroute to %DEST% (%DEST%), 25 hops max, 60 byte packets
echo  1  192.0.2.1  0.412 ms  0.388 ms
echo  2  198.51.100.7  1.201 ms 198.51.100.8  1.350 ms
echo  3  * *
echo  4  203.0.113.9  8.100 ms  8.250 ms
echo  5  * *
echo  6  %DEST%  21.5 ms !X  21.7 ms
