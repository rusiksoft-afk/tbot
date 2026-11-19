# Корневой сертификат НУЦ Минцифры в образе и на площадке (T-709)

Брокерский API отдаёт цепочку, построенную на корне «Российский доверенный корневой» (НУЦ
Минцифры). В Ubuntu 24.04 такого корня нет, поэтому без дополнительного действия проверка TLS
даёт `Verify return code: 19` / `self signed certificate in certificate chain`, а `curl` —
ошибку «self-signed certificate in certificate chain». Замер зафиксирован в
`docs/research/03 §3.3`.

Запрещённое «решение» — отключать проверку (`ssl_tbank_verify=false`, `curl -k`,
`verify=False`): конфиг этого не позволит, а тест `test_проверка_tls_нельзя_отключить...` не
даст завести такую настройку. Правильное действие — добавить корень в доверенные.

## 1. Где брать корень и как проверить

1. Официальная страница распространения доверенных корней НУЦ (портал госуслуг /
   konars.ru — корневой сертификат «Российский доверенный корневой»). Файл должен быть
   публичным, а не пришедшим из переписки или с чужого зеркала.
2. Проверить отпечаток скачанного сертификата по официальной карточке корня:

   ```bash
   openssl x509 -in deploy/ca/ru-trusted-root-ca.pem -noout -fingerprint -sha256
   ```

3. Соотнести отпечаток с тем, что реально показывает соединение (промежуточный сертификат
   выдаётся сервером брокера, корень — нет, поэтому сравнивать нужно именно корень):

   ```bash
   openssl s_client -connect invest-public-api.tbank.ru:443 -showcerts </dev/null 2>/dev/null |
     openssl x509 -noout -subject -issuer -dates
   ```

4. Положить файл в этот каталог с именем `ru-trusted-root-ca.pem` (он попадёт в образ и в
   системное хранилище), и добавить отпечаток в `scripts/deploy_check.py: EXPECTED_CA_FINGERPRINT`.

## 2. Площадка (Ubuntu 24.04)

```bash
sudo cp deploy/ca/ru-trusted-root-ca.pem /usr/local/share/ca-certificates/ru-trusted-root-ca.crt
sudo update-ca-certificates
# проверка без -k: ожидаем 401 (доступ есть, сертификаты доверены)
curl -sS -o /dev/null -w '%{http_code}\n' \
  https://invest-public-api.tbank.ru/rest/tinkoff.public.invest.api.contract.v1.InstrumentsService/Shares
```

Значение `401` вместо ошибки сертификата — признак, что корень добавлен правильно.

## 3. Образ

`deploy/Dockerfile` копирует содержимое этого каталога в
`/usr/local/share/ca-certificates/tbot/` и выполняет `update-ca-certificates`. Пока файла нет,
сборка остаётся рабочей (в каталоге только эта инструкция), но `scripts/deploy_check.py`
помечает проверку как проваленную — «боевой контур» с непроверенным TLS не запускается
(REQ-broker-gateway-02, `AC-broker-gateway-02`).

## 4. Что проверять при обновлении

- срок действия корня и самого сертификата брокера (`-dates` выше);
- неизменность отпечатка корня: подмена корня — признак перехвата или смены удостоверяющего
  центра, оба случая требуют остановки боевого контура и разбора (runbook по ЧП);
- наличие корня в образе после пересборки base-слоя (CI job `platform` проверяет
  `deploy-check`).
