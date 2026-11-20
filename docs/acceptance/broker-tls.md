# Приёмка: доверие TLS к API брокера (T-006, часть T-709)

Дата: 2026-11-20. Принималось `REQ-broker-gateway-02` / `AC-broker-gateway-02`: приложение
обязано строить TLS к API брокера со штатной проверкой цепочки, с корневым сертификатом НУЦ
в образе и на площадке; отключение проверки запрещено.

Проверялось и принималось: `main` = `31b9e71` и `5afe39f`, затем фикс образа `fix(image)…`
— CI run `44675985821` (8 job'ов из 8 ✓) и `Image` run `44675985835` ✓.
До фикса образа тот же набор шагов падал: run `44671687836` (7 ✓ / `compose-smoke` ✗).

## 1. Что именно принимается

| Критерий | Где проверяется | Итог |
|---|---|---|
| Цепочка брокера доверяется **с** закреплённым корнем | job `broker-tls` (живые точки), шаг `compose-smoke` (handshake из контейнера) | ✓ |
| Без корня цепочка **не** доверяется, и это видно как отказ по доверию, а не по сети | job `broker-tls` (mock-ЦС + живые точки), ассерт в job `deploy-check` | ✓ |
| Корень в образе и в его системном наборе доверия | шаг `compose-smoke` «корень НУЦ установлен в системный набор доверия образа» | ✓ |
| Подмена корня (тот же CN, другой ключ) не проходит | `scripts/ca_policy.py` + `deploy_check.check_ca_bundle`, тесты `tests/unit/test_broker_ca_trust.py` | ✓ |
| Срок действия контролируется | `ca_bundle` (корень, ≥90 суток) и `broker_tls` (листовой, ≥14 суток) в `make deploy-check` | ✓ |
| Проверку TLS нельзя отключить конфигурацией | `packages/common/config.py` (`ssl_tbank_verify=false` → ошибка валидатора), тест `test_проверка_tls_нельзя_отключить…` в `tests/unit/test_config_ranges.py` | ✓ |
| Контур определяет адрес брокера | `broker_endpoints(settings)`: primary — адрес контура, secondary — другой контура; тест `test_адрес_брокера_выбирается_по_контуру` | ✓ |

## 2. Артефакт и закреплённый якорь

- Файл: `deploy/ca/ru-trusted-root-ca.pem` (2090 байт, PEM).
- Отпечаток (SHA-256 DER): `d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31`
  — закреплён в `scripts/ca_policy.py` (`EXPECTED_CA_FINGERPRINT`). Это единственное место,
  где он закреплён: `deploy-check`, приёмочная проба, CI и Dockerfile берут его оттуда;
  дублирование отпечатка вне `ca_policy.py` запрещено тестом
  `test_отпечаток_корня_не_дублируется_вне_политики`.
- Субъект/издатель: `CN=Russian Trusted Root CA, O=The Ministry of Digital Development and
  Communications, C=RU` (самоподписан), срок 2022-03-01…2032-02-27 (на дату приёмки —
  1925 суток до конца).
- Получение и сверка: две независимые AIA-выдачи того же корня
  (`http://nuc-cdp.digital.gov.ru/cdp/rootca_ssl_rsa2022.crt` и
  `http://nuc-cdp.voskhod.ru/cdp/rootca_ssl_rsa2022.crt`) — файлы совпали байт в байт;
  корнем проверен промежуточный `Russian Trusted Sub CA` (`openssl verify -CAfile` OK);
  цепочка от живого соединения (`leaf *.tbank.ru` → `Sub CA` → корень) замыкается только этим
  корнем. Цепочка с сервера на 2026-11-20: `*.tbank.ru` до 2027-08-24,
  `Russian Trusted Sub CA` до 2029-07-19.

## 3. Где живёт доверие (пять мест, и их надо проходить вместе)

1. **Образ**: `COPY deploy/ca/ru-trusted-root-ca.pem
   → /usr/local/share/ca-certificates/ru-trusted-root-ca.crt`, затем `update-ca-certificates`.
2. **Площадка** (Ubuntu 24.04): тот же файл в `/usr/local/share/ca-certificates/…crt` +
   `update-ca-certificates`.
3. **dev-машина** (Windows): корень уже в хранилище «Доверенные корневые центры» —
   проверено: `certutil`/PowerShell показывают отпечаток `D26D2D02…`, штатный `ssl` проходит
   handshake к брокеру, проба `scripts/tls_trust_probe.py --expect verified` → `[verified]`.
4. **Браузеры**: Chromium/Edge берут системное хранилище, Firefox — своё
   (`docs/runbook/nucc-ca.md §3.7`).
5. **Клиенты на `certifi`** (`httpx`, `requests`, SDK брокера): системное хранилище не читают.
   Замер с dev-машины: при исправном `curl` и `ssl` клиент `httpx` даёт
   `SSLCertVerificationError` — корня в связке `certifi` нет. Реализация для приложения —
   вместе с клиентом брокера (T-012), разбор — `docs/runbook/nucc-ca.md §4.3`.

## 4. Доказательства

### 4.1 CI, job `broker-tls` (run `44675985821`, job `136087816691`)

```text
OK: корень НУЦ соответствует закреплённой политике
[unverified ] 127.0.0.1:18443 — цепочка не доверена штатному набору: self-signed certificate
[verified   ] 127.0.0.1:18443 — цепочка доверена штатному набору
[unverified ] invest-public-api.tbank.ru:443 — цепочка не доверена штатному набору: self-signed certificate in certificate chain
[unverified ] sandbox-invest-public-api.tbank.ru:443 — цепочка не доверена штатному набору: self-signed certificate in certificate chain
[verified   ] invest-public-api.tbank.ru:443 — цепочка доверена штатному набору
[verified   ] sandbox-invest-public-api.tbank.ru:443 — цепочка доверена штатному набору
```

Первая пара — детерминированная (своя ЦС, к сети раннёра отношения не имеет): она и доказывает,
что «не доверено» и «нет связи» — разные исходы, и что шаблон пробы работает в обе стороны.
Дальше — живые точки брокера: без якоря отказ по доверию (`verify=19`), с закреплённым корнем
из репозитория — успех.

### 4.2 CI, job `compose-smoke` (тот же run, job `136087816657`)

```text
OK invest-public-api.tbank.ru: цепочка доверена набору образа (TLSv1.3)
OK sandbox-invest-public-api.tbank.ru: цепочка доверена набору образа (TLSv1.3)
OK: корень d26d2d0231b7c39f… из /usr/local/share/ca-certificates/ru-trusted-root-ca.crt входит в /etc/ssl/certs/ca-certificates.crt (149 якорей)
```

То есть в собранном образе корень лежит в каталоге якорей, входит в системную связку и
реальное соединение из контейнера `engine` строится — «с установленным корнем соединение
обязано состояться» выполнено на живой точке брокера.

### 4.3 CI, job `deploy-check` (тот же run, job `136087816854`)

```text
ca_bundle: True CN=Russian Trusted Root CA,O=The Ministry of Digital Development and Communications,C=RU: срок 2022-03-01…2032-02-27 (осталось 1925 дн.), отпечаток совпадает с закреплённым
broker_tls: False sandbox-invest-public-api.tbank.ru: цепочка не доверена (19): self-signed certificate in certificate chain; invest-public-api.tbank.ru: цепочка не доверена (19): …
OK: проверка включена, без корня НУЦ цепочка отклоняется
```

`broker_tls = False` на CI-раннере — ожидаемый и закреплённый ассертом результат: на раннёре
корня НУЦ нет. Зелёным он обязан стать только на площадке (и в контейнере, см. 4.2).
Порядок адресов в выводе — `sandbox` первым: настройки контура по умолчанию = `sandbox`,
то есть выбор адреса по контуру работает и в CI.

### 4.4 Локальные гейты (dev-машина, Windows, без Docker)

`ruff format --check` / `ruff check` — чисто; `mypy --strict` — 51 файл, замечаний нет;
`pytest -m "not live_api and not e2e"` — **242 passed** (в том числе 30 тестов новой проверки
доверия: `tests/unit/test_broker_ca_trust.py`, `tests/integration/test_compose_contract.py::test_образ_кладёт_корень_так_как_ожидает_его_debian`,
`tests/contract/test_ci_workflows.py::test_приёмка_доверия_к_брокеру_покрывает_обе_половины_условия`);
покрытие **95.07%** при пороге 80%; подавлений проверок **14** (базовый уровень не изменён —
новых `noqa`/`pragma: no cover`/`nosec` не добавлялось, новые ветки разбора закрыты тестами).

## 5. Восьмая причина падения `compose-smoke`: Debian не видит корень в образе

Признак в run `44671687836`, шаг «корень НУЦ установлен в системный набор доверия образа»:
`корень НУЦ не попал в /etc/ssl/certs/ca-certificates.crt: update-ca-certificates в образе не
отработал`. Файл в образе был и совпадал с закреплённым отпечатком — не хватало только
попадания в связку.

Причина: `update-ca-certificates` в Debian читает **только** файлы `*.crt` в **верхнем уровне**
`/usr/local/share/ca-certificates`. Dockerfile клал корень как
`/usr/local/share/ca-certificates/tbot/ru-trusted-root-ca.pem` — не то расширение и не тот
уровень каталога.

Чем это опасно: дефект не ломает ни сборку, ни `up --wait`, ни healthchecks, ни `/readyz` —
образ выглядит рабочим, а доверия к брокеру в нём нет. Обнаруживается при первом же соединении
с брокером, то есть уже на площадке. Закреплено тестом
`test_образ_кладёт_корень_так_как_ожидает_его_debian` (расширение `.crt`, отсутствие
подкаталога, порядок инструкций `COPY` → `RUN update-ca-certificates`) и поведенчески — шагом
compose-smoke из 4.2. Общая причина с предшествующими семью: все восемь — «инфраструктурный
шаг выглядит выполненным, но выполняет другое»; порядок разбора — `docs/acceptance/m0-stand.md §10`.

## 6. Находка: корень не попадал в репозиторий

Правило `*.pem` в `.gitignore` (защита от приватных ключей) прятало и публичный корень: файл
лежал в рабочем каталоге, но не был в `HEAD`. Следствие: в свежем чекауте `COPY deploy/ca/`
кладёт в образ только `README.md`, все проверки сборки и стенда зелёные, а доверия нет.
Исправлено точечной отменой `!deploy/ca/*.pem` (приватные ключи по-прежнему исключены) и
тестом `test_публичный_корень_нц_не_прячется_в_gitignore`. Дополнительно: отсутствие файла в
чекауте ловят `test_политика_и_проверка_площадки_сверяют_одно_значение` (job `tests`) и
`ca_bundle` (job `deploy-check`) — то есть регрессия видна до сборки образа.

## 7. Границы приёмки: что осталось непроверенным

1. **Площадка**. Установка корня на прод-ВМ (`update-ca-certificates`) и `curl` без `-k` → `401`
   не выполнялись: прод на паузе (T-011, «пока нет, ждём»), поэтому T-709 остаётся
   `in progress` — принята образная и CI-половинка, не половинка реальной ВМ.
2. **Test-стенд** `192.168.1.40` не развёрнут (T-010), проверка доверия на нём не делалась.
3. **Клиент брокера** не реализован: реальное приложение к брокеру пока не обращается, поэтому
   «приложение ходит на брокера с доверием» принято на уровне образовых проб и живой цепи,
   а не на уровне кода приложения. Частный случай — клиенты на `certifi` (§3.5), их разбор
   перенесён в T-012.
4. **Смена удостоверяющего центра** не проверялась на реальном событии: закреплены только
   механизмы (отпечаток как якорь, падение `broker-tls`/`ca_bundle`) и процедура
   (`docs/runbook/nucc-ca.md §5`).
5. Перехват трафика (MITM) не моделировался; проверка «подмена корня» статическая — другой
   сертификат с тем же CN не проходит сверку отпечатка.
6. Исходящий трафик контейнеров (`tbot-egress`) в этом прогоне не ограничивался дополнительно:
   handshake к брокеру из `engine` — ожидаемый, а вот изоляция базы проверяется отдельным шагом
   (`у контейнера базы нет исходящего трафика`).

## 8. Как повторить

```bash
# артефакт и якорь (без зависимостей приложения)
python3 scripts/ca_policy.py
python3 scripts/ca_policy.py --verify-bundle /etc/ssl/certs/ca-certificates.crt   # Linux/контейнер
# пробы: «не доверено» и «нет связи» — разные исходы
python3 scripts/tls_trust_probe.py --host invest-public-api.tbank.ru --expect reachable
python3 scripts/tls_trust_probe.py --host invest-public-api.tbank.ru --expect verified
python3 scripts/tls_trust_probe.py --host 127.0.0.1 --port 18443 --sni localhost --expect unverified
# полный набор на площадке
make deploy-check   # Windows: .\make.ps1 deploy-check
```

Логи CI: `gh run view 44675985821 --repo rusiksoft-afk/tbot --log --job <id>`, где id см. выше;
падение до фикса — run `44671687836`, job `136073879625`.
