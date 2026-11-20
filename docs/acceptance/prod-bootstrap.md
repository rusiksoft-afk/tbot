# Приёмка: базовая подготовка рабочей ВМ `153.51.172.30` (T-011, остаток T-709)

Дата: 2026-11-20. Принималось: условия `T-011` (swap 4 ГиБ + `vm.swappiness=10`, `chrony`,
корень НУЦ в системном хранилище) и непройденная половинка `T-709` — доверие TLS к API брокера
на реальной площадке («`curl` без `-k` отвечает 401, а не ошибкой TLS»).

Основание для работ на площадке: решение заказчика от 2026-11-20 (см. `docs/adr/ADR-001`):
отдельной тестовой ВМ в проекте нет, приёмка и работа — на живой `153.51.172.30`; разрешены
Docker/деплой, 80/443 и Caddy; допущены контуры `sandbox`, `paper`, `production`. Пауза `T-011`
с этого решения не действует на перечисленные пункты.

Инструмент приёмки — новый `scripts/prod_bootstrap_check.py`: проверка готовности машины **до**
появления Docker и образов. Он сознательно не использует `subprocess` (читает `/proc`, `/etc`,
`shutil.disk_usage`), поэтому запускается на чистой Ubuntu 24.04 штатным `python3` и не требует
новых подавлений bandit — базовый уровень 14 не изменился.

## 1. Замеры до работ (2026-11-20 05:12 UTC, `ssh rusiksoft@153.51.172.30`)

```text
host: compute-vm-2-4-74-ssd-1795094860175 · os: Ubuntu 24.04.5 LTS · kernel: x86_64 6.8.0-149-generic
cpu: 2 vCPU · Intel Xeon Processor (Icelake)
Mem: 3.8Gi total, 434Mi used, 3.4Gi available
Swap: 0B            swappiness=60          в fstab swap-записей нет
/dev/vda1  72G  2.3G  69G  4% /
docker: command not found      chrony: не установлен      ufw: inactive      iptables: ACCEPT-all
слушают только 0.0.0.0:22 и 127.0.0.1:10800 (SOCKS туннеля), tbot-контейнеров нет
снаружи (с рабочей машины): 22 OPEN, 80/443/5432/8080/9101 — closed/filtered
```

Отдельная находка про сеть: локальных фильтров нет, значит входящие 80/443 отсекает **группа
безопасности Yandex Cloud** (задача `T-708`). `yc` CLI установлен (`~\yandex-cloud\bin\yc.exe`,
1.47.0), но не авторизован: `yc init` делает владелец аккаунта. Пока шага нет, Caddy не получит
сертификат Let's Encrypt — это ограничение остаётся.

## 2. Корень НУЦ в системном хранилище (T-011 + остаток T-709)

Файл берётся из репозитория, сверяется с закреплённой политикой (`scripts/ca_policy.py`) **до**
установки и **после** — уже по месту назначения:

```text
sha256 на ВМ: e4370c9b6b540f063ba1829222d2d6041cbb0bfc5d001ee6bbb97620914594dc  (совпал с репозиторием)
OK: корень НУЦ соответствует закреплённой политике         (отпечаток d26d2d0231b7c39f…cf31)
sudo install -o root -g root -m 644 /tmp/ru-trusted-root-ca.pem \
     /usr/local/share/ca-certificates/ru-trusted-root-ca.crt
update-ca-certificates → 1 added, 0 removed; done.
OK: корень с этим отпечатком входит в /etc/ssl/certs/ca-certificates.crt
```

Половинка «с установленным доверием соединение обязано состояться» на площадке:

```text
invest-public-api.tbank.ru            New, TLSv1.3, TLS_AES_128_GCM_SHA256, Verify return code: 0 (ok)
sandbox-invest-public-api.tbank.ru    New, TLSv1.3, TLS_AES_128_GCM_SHA256, Verify return code: 0 (ok)
curl -w 'verify=%{ssl_verify_result} http=%{http_code}' https://…/            → verify=0 http=404
POST https://…/rest/tinkoff.public.invest.api.contract.v1.MarketDataService/GetCandles
  invest-public-api            → http=401 {"code":16,"message":"Authentication token is missing or invalid"}
  sandbox-invest-public-api    → http=401 {"code":16,"message":"Authentication token is missing or invalid"}
```

То есть условие «`curl` без `-k` даёт 401, а не ошибку TLS» выполнено на **обоих** контурах
(песочница и боевая точка), до установки корня те же точки давали `Verify return code: 19`.
Расширение `.crt` в верхнем уровне `/usr/local/share/ca-certificates` — не придирка стиля:
`update-ca-certificates` иначе файл не видит (в CI это была 8-я причина падения `compose-smoke`,
`docs/acceptance/broker-tls.md §5`).

Откат: `sudo rm /usr/local/share/ca-certificates/ru-trusted-root-ca.crt && sudo update-ca-certificates --fresh`.

## 3. Swap 4 ГиБ и `vm.swappiness=10`

```text
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile
Setting up swapspace version 1, size = 4 GiB (4294963200 bytes)
sudo swapon /swapfile
echo "/swapfile none swap sw,pri=1 0 0" → /etc/fstab
sudo swapoff /swapfile && sudo swapon -a     ← проверка, что запись в fstab корректна,
                                               без перезагрузки машины
/etc/sysctl.d/99-tbot.conf: vm.swappiness=10 ; sudo sysctl --system → Applying … vm.swappiness = 10
ПОСЛЕ:
  Swap: 4.0Gi total, 0B used            swapon --show: /swapfile file 4G 0B 1
  swappiness=10                         /dev/vda1 72G 6.3G 65G 9% /
```

Своп проверяется не «по факту включения», а по трём условиям: включён, достаточного объёма,
переживёт перезагрузку (запись в fstab). Именно из-за третьего условия в `prod_bootstrap_check`
есть отдельная проверка `swap_fstab`: `swapon` без fstab-записи выглядит зелёным до первой
перезагрузки, а дальше тяжёлый процесс снова упирается в OOM-killer.

Откат: `sudo swapoff /swapfile && sudo rm /swapfile` + убрать строку из `/etc/fstab` +
`sudo rm /etc/sysctl.d/99-tbot.conf`.

## 4. Синхронизация времени (`chrony`)

`chrony` 4.5-1ubuntu4.2 из репозитария Ubuntu (не из стороннего источника). `systemd-timesyncd`
не активен — часы тягает один источник.

```text
systemctl is-active chrony → active ; is-enabled → enabled
chronyc tracking: Reference ID 596DFB17 (ntp3.vniiftri.ru)
                  System time 0.001092468 seconds fast of NTP time
                  Last offset +0.000213442 seconds
chronyc sources: 6 источников stratum 2 (в т.ч. canonical и один российский — ntp3.vniiftri.ru)
timedatectl: System clock synchronized: yes
```

Граница ТЗ — расхождение больше 2 с → алерт `R32/CLOCK_SKEW` и запрет TOTP (`docs/tz/08 §8.2`,
`docs/tz/12 §12.4`): фактическое смещение 0.0011 с, то есть в ~1800 раз ниже границы. Прикладной
контроль offset выполняется не здесь, а в `deploy-check` и в метриках приложения — на уровне, где
есть свои механизмы; в `prod_bootstrap_check` смещение читается из снимка
`chronyc tracking` (флаг `--chrony-tracking`), а без снимка проверка остаётся **замечанием**, а не
«зелёной»: требовать «часы в порядке» по косвенным признакам нельзя.

## 5. Итоговый прогон проверки готовности

`python3 /tmp/tbot-bootstrap/prod_bootstrap_check.py --chrony-tracking /tmp/chrony-tracking.txt`
на ВМ, 2026-11-20T05:27:42Z:

```text
OK   python: 3.12.3 (нужно ≥3.12)
OK   swap: 4.00 GiB (4194300 КиБ) включено (нужно ≥4 GiB)
OK   swap_fstab: запись о свопе есть — переживает перезагрузку
OK   swappiness: vm.swappiness=10
OK   chronyd: процесс chronyd запущен (pid 15659)
OK   chrony_enabled: юнит chrony.service включён в автозагрузку
OK   clock_offset: смещение 0.001092 с (граница 2 с)
OK   ca_bundle: корень НУЦ входит в /etc/ssl/certs/ca-certificates.crt (отпечаток d26d2d0231b7c39f…)
OK   broker_tls: invest-public-api.tbank.ru: verified; sandbox-invest-public-api.tbank.ru: verified
OK   resources: CPU=2, RAM=3.82 GiB, диск=71.03 GiB (свободно 64.76 GiB, занято 8.8%)
ГОТОВО: блокирующих замечаний нет   (exit=0)
```

### Найденный при прогоне дефект самой проверки (важно)

Первый прогон был красным на строке `FAIL swap: 4.00 GiB, нужно ≥4 GiB`. Причина: `mkswap`
резервирует начало файла под заголовок, и файл в 4 ГиБ в `/proc/swaps` выглядит как **4194300
КиБ**, а не 4194304. Проверка «не меньше 4 ГиБ» на ровном числе отсекала правильно настроенную
машину.

Чем это опасно: автор проверки на dev-машине (Linux-файлов нет, всё «зелёное на глаз») этого бы не
увидел, а на площадке проверка либо осталась бы вечно красной, либо была бы «починена»
ослаблением границы. Исправлено допуском в 64 КиБ (`SWAP_HEADER_TOLERANCE_KIB`) с закреплением
замера тестом `test_своп_файла_на_четыре_гиб_после_заголовка_mkswap_проходит` и тестом
`test_нехватка_свопа_не_прячется_допуском_заголовка` (3.9 ГиБ по-прежнему не проходит). Это
девятый случай той же болезни, что и восемь причин падения `compose-smoke`: проверка выполняется,
но проверяет не то.

## 6. Чего на этой приёмке сделано НЕ было

| Не выполнено | Почему |
|---|---|
| Группа безопасности Yandex Cloud (80/443) | нужен `yc init` владельца аккаунта (CLI установлен, не авторизован) или правка в Cloud Console; процедура и откат — `docs/runbook/yandex-sg.md` (`T-708`) |
| `ufw default deny incoming`, `fail2ban` | идут **после** открытия 80/443, чтобы не закрыть вход на не настроенный сервис (`docs/tz/14 §14.9`, `T-708`) |
| Docker Engine + compose, деплой контейнеров | `T-712`; следующий шаг, отдельно от базовой подготовки |
| Caddy + сертификат Let's Encrypt | `T-713`, упирается в 80/443 (см. первую строку) |
| План бэкап-хранилища, RPO/RTO | `OQ-10` — ответ заказчика не получен; без него боевой контур запускать нельзя |
| Секрет токена Bot API на площадке | заказчик размещает сам (`docs/runbook/telegram-token.md`); в чат и в git значения не попадают |
| Перезагрузка ВМ ради проверки свопа | перезагрузка не согласована; стойкость проверена через `swapoff` + `swapon -a` (перечитывание fstab) |

Из-за последней строки в `T-011` остаётся открытым один пункт: **план бэкап-хранилища**. Остальные
три пункта задачи выполнены и приняты.

## 7. Как повторить

С машины, где есть доступ к репозиторию (после деплоя — из рабочего каталога, до деплоя — копией
четырёх скриптов):

```bash
# до деплоя: скрипты без зависимостей приложения
scp scripts/{prod_bootstrap_check,ca_policy,tls_trust_probe,_bootstrap}.py host:/tmp/tbot-bootstrap/
ssh host 'chronyc tracking > /tmp/chrony-tracking.txt
          python3 /tmp/tbot-bootstrap/prod_bootstrap_check.py --chrony-tracking /tmp/chrony-tracking.txt'

# после деплоя — из checkout, с машинным выводом для протокола
python3 scripts/prod_bootstrap_check.py --json
```

Локальные проверки этого модуля (без сети и без Linux):
`pytest -q tests/unit/test_prod_bootstrap_check.py` — 27 проверок.

## 8. Что разблокировано

`T-011` — принято кроме плана бэкапов; `T-709` — закрыто (образ ✓ в CI, хост ✓ здесь). Дальше по
порядку из `docs/tz/14 §14.9`: группы безопасности (80/443) → `ufw`/`fail2ban` → Docker Engine +
compose + pull образов GHCR по digest → Caddy + сертификат → мониторинг и бэкапы → `engine` в
`paper` → боевой контур на одном инструменте с лимитами «минимум».
