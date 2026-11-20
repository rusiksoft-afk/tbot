# Список задач (`tasks/todo.md`)

Формат: задача → приёмка (какие `REQ/AC` закрывает) → проверка (команда/тест) → файлы.
Одна задача ≈ одна сессия, ≤~5 файлов. Не менять нумерацию выполненных задач; новые — в конец
секции вехи. Пометка `[blocked: OQ-N]` означает нужный ответ заказчика (см. `docs/TZ.md §9`).

## M0 — каркас и окружение

- [x] **T-001** Каркас репозитория: структура TZ §5, `pyproject.toml`, ruff/mypy/pytest/coverage, `Makefile` со всеми командами TZ §4
  - Приёмка: команды TZ §4 существуют и исполняются; `mypy --strict` на пустом проекте зелёный
  - Проверка: `make lint`, `make test` (0 тестов → exit 0 с предупреждением)
  - Файлы: `pyproject.toml`, `Makefile`, `ruff.toml`, `mypy.ini`, `.gitignore`, `.editorconfig`
  - Статус 2026-11-19: выполнено. На dev-машине нет `make`, поэтому команды продублированы
    обёртками `make.ps1` и `scripts/dev.py` (единый реестр команд + контрактный тест
    `test_dev_cli_contract`); `Makefile` остаётся для Linux и CI.
- [x] **T-002** Конфигурация и секреты: pydantic-settings, `configs/tbot.example.yaml`, загрузка ENV/файлов, запрет секретов в YAML
  - Приёмка: `REQ-config-01` (диапазоны риска), отсутствие секретов в git (`gitleaks`)
  - Проверка: `make lint`, тест `test_config_ranges`
  - Файлы: `packages/common/config.py`, `configs/tbot.example.yaml`, `.github/workflows/ci.yml`
  - Статус 2026-11-19: выполнено. Порядок приоритетов закреплён явно: аргументы > ENV > YAML
    (`settings_customise_sources`); секреты — только ENV или файлы `secrets_dir`. Дополнительно:
    отключение проверки TLS (брокер, Telegram) запрещено валидаторами, а контур `production`
    требует явного `confirm_production`.
- [x] **T-003** Логирование: structlog JSON + фильтр маскирования секретов + `trace_id`
  - Приёмка: «канареечный» токен не попадает в вывод; формат полей TZ §12.1
  - Проверка: `test_logging_masking` (несколько шаблонов токена/ключей)
  - Файлы: `packages/common/logging.py`, `tests/unit/test_logging_masking.py`
  - Статус 2026-11-19: выполнено. Один конвейер для записей приложения и сторонних библиотек
    (`ProcessorFormatter` + `foreign_pre_chain`); маскируются поля по именам, `ключ=значение`,
    URI с учётными данными, Bearer, куки, PEM. 16 тестов на канареечных значениях.
- [x] **T-004** Время и идентификаторы: `common/clock.py` (UTC/МСК), UUIDv7, ключ идемпотентности
  - Приёмка: нет `datetime.now()` вне `clock`; ключ ≤36 симв., уникален
  - Проверка: `test_clock`, `test_client_key_format`
  - Файлы: `packages/common/clock.py`, `packages/common/ids.py`, тесты
  - Статус 2026-11-19: выполнено. Разметка бит UUIDv7 (версия в битах 76..63, вариант в 63..62)
    закреплена тестами: первый вариант с случайностью поверх поля версии давал `version == 3`.
- [x] **T-005** Docker/Compose dev: postgres + web + engine + tgbot + jobs, сети, healthchecks, non-root, ротация логов
  - Приёмка: `make dev` → `/readyz` 200 у web и engine; egress для БД закрыт
  - Проверка: `docker compose config`, ручной/CI-прогон `compose up && curl`
  - Файлы: `deploy/compose.yaml`, `deploy/compose.override.yaml`, Dockerfile'ы
  - Статус 2026-11-19: код и проверки написаны — контрактные тесты на compose и job
    `compose-smoke` в CI (сборка, `up --wait`, `/readyz`, запрет исходящего трафика БД).
    Приёмка не закрыта: на dev-машине нет Docker, нужен первый зелёный прогон job'а в CI.
    При написании найдена реальная ошибка: сервисам не были выданы секреты (`/run/secrets`
    пуст), из-за чего `/readyz` web не проходил проверку базы; исправлено точечной выдачей
    секретов по процессам (контрактный тест это теперь фиксирует).
  - Статус 2026-11-20: в `compose-smoke` разобрано семь причин (все — только с реальным Docker,
    локально их было не увидеть): capability базы против entrypoint/gosu, DAC_OVERRIDE для
    каталога данных (том приходит из образа владельцем uid 999, а entrypoint сам ставит на нём
    `0700`), каталог unix-сокета на read-only rootFS, `listen_addresses = 'localhost'` (база не
    слушала сеть контейнера), healthcheck `jobs` на `/readyz` (готовность на M0 честно отвечает
    «исполнителей ещё нет», поэтому `up --wait` не стал бы зелёным никогда) и `python3` внутри
    контейнера базы, где Python вообще не установлен. Исправлено: якорь `x-db-runtime` (ровно
    `CHOWN/DAC_OVERRIDE/FOWNER/SETGID/SETUID` только у базы, всё остальное hardening сохранено),
    tmpfs на `/var/run/postgresql`, `listen_addresses = '*'`, healthcheck `jobs` на
    `/healthz --liveness`, проба egress на `bash`, и путь монтирования конфига базы: compose
    разрешает относительные пути `volumes` относительно каталога compose-файла, поэтому
    `./deploy/postgres/tbot.conf` вёл к `deploy/deploy/...`, а Docker из несуществующего
    хостового пути короткой формы делает пустой каталог — postgres падал с «input in flex
    scanner failed at file /etc/postgresql/tbot.conf line 1».
    Каждое закрыто контрактным тестом (`tests/integration/test_compose_contract.py`,
    `tests/contract/test_ci_workflows.py`.
  - Статус 2026-11-20 (приёмка закрыта): первый зелёный `compose-smoke` — run `44641201161` на
    `29c9ace` (полный `CI` из 7 job'ов зелёный, `Image` — run `44641201349`). Фактически:
    `up -d --wait` дал `Healthy` у postgres/web/engine/jobs, `run --rm migrate` прогнал ревизию
    `0001`, `/readyz` web = 200 с проверкой базы («postgres доступен»), `/readyz` engine = 200
    (контур + потолки риска), `/healthz` engine и jobs = 200, проба исходящего трафика у базы
    не прошла: `OK: исходящий трафик базы заблокирован (внутренняя сеть)`. Протокол с логами,
    таблицей гарантий и границами — `docs/acceptance/m0-stand.md`. Границы приёмки: `tgbot` в
    CI-стенде не запускается (его `/readyz` требует пробы Bot API; приёмка канала управления — M3),
    `make dev` как команда на dev-машине не выполнялась (нет Docker) — стенд поднимался той же
    парой `-f`-файлов, что и в стенде разработчика.
- [x] **T-006** Сертификат НУЦ Минцифры в образе + `SSL_TBANK_VERIFY` + коннект-тест контуров
  - Приёмка: `REQ-broker-gateway-02`, `AC-broker-gateway-02`
  - Проверка: `make deploy-check` (TLS-часть), тест с mock
  - Файлы: `deploy/ca/`, `deploy/Dockerfile.engine`, `scripts/deploy_check.py`
  - Статус 2026-11-20: принято — протокол `docs/acceptance/broker-tls.md` (CI run `44675985821`,
    8 job'ов из 8 ✓). Корень `deploy/ca/ru-trusted-root-ca.pem` закреплён отпечатком в
    `scripts/ca_policy.py` (единственный источник), образ кладёт его как
    `/usr/local/share/ca-certificates/ru-trusted-root-ca.crt`. Новая пара проверок в CI:
    job `broker-tls` («без корня — `unverified`, с корнем — `verified`», mock-ЦС + живые точки
    обоих контуров) и шаг `compose-smoke` (корень в системной связке образа + живой handshake
    из контейнера). `ssl_tbank_verify=false` по-прежнему не проходит валидатор. Из
    запланированного имени `deploy/Dockerfile.engine` в проекте есть один
    `deploy/Dockerfile` (multi-target, `--build-arg APP=…`).
- [x] **T-007** Базовые health/metrics: `/healthz`, `/readyz`, `/metrics`, `tbot_build_info`
  - Приёмка: метрики TZ §12.2 (базовый набор); compose-зависимости по health
  - Проверка: интеграционный тест `test_health_readyz`, ручной `curl /metrics`
  - Файлы: `apps/*/health.py`, `packages/common/metrics.py`
  - Статус 2026-11-19: выполнено в объёме M0. Общий `HealthServer` и пробник `health_probe`
    (его вызывают healthcheck'и контейнеров), метрики сборки и транспорта Telegram; возраст
    доставки (`tg_last_delivery_age_s`) намеренно остаётся нулевым до M3.
- [x] **T-008** CI: lint, typecheck, test, coverage-порог, gitleaks, pip-audit, bandit, build+push в GHCR по digest
  - Приёмка: все шаги на зелёном коммите проходят; пороги покрытия 80%
  - Проверка: прогон workflow на тестовой ветке
  - Файлы: `.github/workflows/ci.yml`, `.github/workflows/image.yml`
  - Статус 2026-11-19: workflow'ы написаны (quality + `suppress-growth`, tests + coverage 80%,
    миграции up/down/up, gitleaks, bandit, pip-audit, compose-smoke, deploy-check, build/push
    по digest). Приёмка — по первому фактическому прогону на зелёном коммите; локально
    210 тестов и 95.07% покрытия (инвентаризация подавлений: `docs/acceptance/m0-quality.md`).
  - Статус 2026-11-20: шаг `pip-audit` починен поднятием пинов (`fastapi>=0.165,<0.166` →
    starlette 1.10.0, `cryptography>=50.0,<51.0`): нижняя граница взята из версии, в которой
    закрыт самый старший из известных advisory, понижать порог и исключать advisory не пришлось.
    Локально шаг воспроизведён без CI (venv только с продакшн-зависимостями + `pip-audit --strict`
    по `pip freeze --exclude-editable`) — «No known vulnerabilities found».
  - Статус 2026-11-20 (приёмка закрыта): весь workflow зелёный на `29c9ace` — run `44641201161`
    (7 job'ов из 7: quality+suppress-growth, тесты+покрытие, миграции up/down/up, gitleaks,
    audit+bandit, compose-smoke, проверка площадки) и `Image` run `44641201349` — 4 образа в GHCR
    по digest (web `9f8ef8e6…`, engine `6b8cb501…`, tgbot `eb72d243…`, jobs `7ba8d0d8…`).
    Фактическое покрытие 95.07% при пороге 80%, 212 тестов, подавлений 14 (базовый уровень).
    Все восемь падений (7 в `compose-smoke` + `pip-audit`) закрыты фиксами в исходниках:
    новых подавлений нет, пороги не снижались, advisory не исключались. Протокол:
    `docs/acceptance/m0-stand.md` (§6 — зависимости, §7 — digest'ы, §8 — локальные гейты).
- [ ] **T-009** `storage`: Alembic + первые миграции (users, sessions, invitations, totp, backup_codes, audit_log с append-only правами)
  - Приёмка: `REQ-identity-04`, `REQ-storage-01/02`; `upgrade head` → `downgrade base` → `upgrade head`
  - Проверка: `make migrate`, `test_audit_append_only_role`
  - Файлы: `migrations/versions/0001_*.py`, `deploy/postgres/roles.sql`
  - Статус 2026-11-19: часть выполнена — каркас Alembic (`env.py`, `script.py.mako`) и ревизия
    `0001_app_meta` есть, цикл up/down/up проверяется в CI job'ом `migrations`. Таблицы
    идентичности и `roles.sql` переносятся в M1 (T-101…T-106): выдумывать схему доступа раньше
    модели доступа смысла нет.
- [ ] **T-010** Параметры рабочей ВМ (`153.51.172.30`): лимиты Postgres под 3.8 ГиБ, swap, ретенция-конфиг, алерты диска — раньше задача формулировалась как «инфраструктура test-стенда (`192.168.1.40`)»
  - Приёмка: TZ §14.2 (все ограничения применены), замеры задокументированы
  - Проверка: `nproc/free -h/df -h` → протокол, или целиком `python3 scripts/prod_bootstrap_check.py`;
    запуск состава на рабочей ВМ — после T-712
  - Файлы: `deploy/postgres/tbot.conf`, `configs/retention.yaml`, `docs/acceptance/prod-bootstrap.md`
  - Статус 2026-11-20: **переименована** по решению заказчика (тестовой машины `192.168.1.40` в
    проекте нет, приёмка и работа — на живой ВМ, `docs/adr/ADR-001`). Отдельные
    `deploy/postgres/tbot-stand.conf` и `deploy/stand/README.md` не нужны: машина одна, лимиты живут
    в `deploy/postgres/tbot.conf` (256 МБ `shared_buffers`, 60 соединений), §14.2 пересчитан под
    3.8 ГиБ / 72 ГиБ.
    Выполнено и принято (протокол `docs/acceptance/prod-bootstrap.md`): замеры 05:12 UTC,
    swap 4 ГиБ + `vm.swappiness=10` + запись в `/etc/fstab`, `chrony` (смещение 0.001 с), корень НУЦ,
    проверка готовности `scripts/prod_bootstrap_check.py` (exit=0 на площадке).
    Остаётся: ретенция-конфиг и алерты диска (связаны с T-031 партициями и T-711), повышение
    `shared_buffers` до 512 МБ — только по замерам RSS и попаданий в кэш.
- [x] **T-011** Базовая подготовка прод-ВМ (Yandex Cloud `153.51.172.30`, конфигурация без расширения по решению OQ-11): swap 4 ГБ + `vm.swappiness=10`, `chrony` (или мониторинг offset `systemd-timesyncd`), корневой сертификат НУЦ в системное хранилище, план бэкап-хранилища `[закрыто 2026-11-20: пауза «прод не трогаем» снята (`docs/adr/ADR-001`), OQ-10 закрыт решением заказчика — локальные дампы + быстрый откат (`docs/adr/ADR-002`, TZ §14.10)]`
  - Приёмка: `docs/research/03 §3.6–3.7, §3.10`, TZ §14.9; `swapon --show` непустой; `timedatectl` синхронизирован; `curl https://invest-public-api.tbank.ru/...` **без `-k`** отвечает 401
  - Проверка: `python3 scripts/prod_bootstrap_check.py` (swap, запись в fstab, `chronyd` и юнит,
    смещение часов по снимку `chronyc tracking`, корень НУЦ в системной связке, доступность обоих
    контуров, ресурсы и пороги диска)
  - Файлы: `deploy/vps/{swap.yaml,chrony.conf,ca-nucc/}` — фактически не нужны: изменения
    применяются на площадке, а закреплены они протоколом `docs/acceptance/prod-bootstrap.md`
    (откаты — там же) и проверкой `scripts/prod_bootstrap_check.py`
  - Статус 2026-11-20: **задача закрыта, все четыре пункта приняты** — корень НУЦ
    (`update-ca-certificates`, «1 added»), `curl` **без `-k`** на обеих точках → `401` при
    `Verify return code: 0`, swap 4 ГиБ + `swappiness=10` + fstab, `chrony` 4.5 (смещение 0.001 с,
    юнит active+enabled), и план бэкап-хранилища: OQ-10 закрыт решением заказчика (локальные
    дампы `pg_dump -Fc` + WAL-архив в `/var/backups/tbot`, шифрование до записи, RPO ≤15 мин,
    RTO ≤15 мин / откат ≤5 мин, потолок 20 ГиБ) — `docs/adr/ADR-002`, TZ §14.10. Перезагрузка ВМ
    не согласована, поэтому стойкость свопа проверена через `swapoff` + `swapon -a`.
    Сама реализация дампов/ротации — **T-702**; до неё боевой контур не запускается (§14.7 шаг 3).
  - Что блокировалось, пока задача не выполнена: доверие TLS к API брокера на проде (T-709 —
    **закрыта 2026-11-20**), установку Docker (T-712 — **разрешена решением от 2026-11-20**),
    открытие 80/443 (T-708 — разрешено, но упирается в `yc init` владельца аккаунта), а значит и
    связку Caddy→панель (T-713).

## M1 — доступ, 2FA, хранилище токенов

- [ ] **T-101** Пароли и учётные записи: Argon2id, политика паролей, блокировка после 5 неудач
  - Приёмка: TZ §8.1; `REQ-identity-01`
  - Проверка: `test_password_policy`, `test_login_lockout`
  - Файлы: `packages/identity/{passwords,users}.py`, тесты
- [ ] **T-102** Сессии: куки (HttpOnly/Secure/SameSite), `auth_step`, idle 30 мин / abs 12 ч, пересоздание после критичных действий, список сессий + отзыв
  - Приёмка: TZ §8.3 (куки, CSRF, CSP, HSTS)
  - Проверка: `test_session_matrix`, `test_csrf_required`, `test_session_revoke`
  - Файлы: `apps/web/security/{sessions,csrf,csp}.py`, шаблоны
- [ ] **T-103** TOTP 2FA: привязка (QR+секрет, подтверждение 2 кода), вход с обязательным кодом, окно ±1, одноразовость кода
  - Приёмка: `REQ-identity-*` TZ §8.2; все маршруты требуют `auth_step='full'`
  - Проверка: `test_totp_flow`, `test_route_requires_full_auth` (параметризовано по всем маршрутам)
  - Файлы: `packages/identity/totp.py`, `apps/web/routes/{login,totp}.py`
- [ ] **T-104** Резервные коды: генерация 10, хэши, одноразовость, предупреждение и тайм-лимит на восстановление
  - Приёмка: TZ §8.2 (расход кода = алерт + требование перевыпустить 2FA)
  - Проверка: `test_backup_code_single_use`, `test_backup_code_flow`
  - Файлы: `packages/identity/backup_codes.py`, маршруты, тесты
- [ ] **T-105** Приглашения и одобрение (закрытый допуск): создание, ссылка TTL 14 дней, страница ожидающих, отзыв
  - Приёмка: `REQ-identity-02/03`
  - Проверка: `test_no_public_registration` (сканирование маршрутов), `test_invitation_flow`
  - Файлы: `packages/identity/invitations.py`, `apps/web/routes/admin_users.py`
- [ ] **T-106** Роли и авторизация на уровне сервиса: admin/operator/viewer, 403 без утечки, проверка владения объектом
  - Приёмка: `AC-identity-01`, TZ §1.1
  - Проверка: `test_role_matrix` (все маршруты × все роли)
  - Файлы: `packages/identity/authorization.py`, тесты
- [ ] **T-107** KEK/DEK и шифрование токенов: AES-256-GCM + AAD, `key_version`, `make rotate-keys`, тесты дешифрования
  - Приёмка: `REQ-credentials-05`, `AC-credentials-05`
  - Проверка: `test_vault_roundtrip`, `test_no_plaintext_in_db_dump`, `make secret-scan`
  - Файлы: `packages/credentials/vault.py`, `scripts/rotate_keys.py`, тесты
- [ ] **T-108** Подключение токена: форма, read-only проверка (счета/тип/статус/права), отказ для transfer-токенов и неподдерживаемых типов счетов, срок 3 месяца, напоминания 14/7/3
  - Приёмка: `REQ-credentials-01…04`, TZ §1.4
  - Проверка: `test_token_precheck_matrix` (типы счетов, transfer-токен, ошибка 401), `test_expiry_reminders`
  - Файлы: `packages/credentials/{precheck,accounts}.py`, `apps/web/routes/accounts.py`
- [ ] **T-109** Audit log: цепочка хэшей, `make audit-verify`, обязательные события TZ §8.7, уведомления админу
  - Приёмка: `AC-identity-04`
  - Проверка: `test_audit_chain_tamper_detect`, `test_audit_required_events`
  - Файлы: `packages/identity/audit.py`, `scripts/audit_verify.py`
- [ ] **T-110** IP-allowlist + Caddy (TLS, HSTS, rate limit, fail2ban-совместимость) + emergency-переключатель
  - Приёмка: TZ §8.5, §14.5 (кроме VPS-части)
  - Проверка: e2e с подменой IP-заголовка на стенде, `test_allowlist_bypass_denied`
  - Файлы: `deploy/caddy/Caddyfile`, `packages/identity/allowlist.py`
- [ ] **T-111** Страницы профиля и админа (TZ §9.3: 1–7, 11) + дизайн-токены (начало)
  - Приёмка: формы с серверной валидацией; дизайн-токены в одном CSS; grep-тест на inline-цвета
  - Проверка: e2e (вход/2FA/приглашение/одобрение/подключение токена)
  - Файлы: `apps/web/templates/*`, `web/static/tbot.css`

## M2 — брокер и рыночные данные

- [ ] **T-201** `broker_gateway`: async-клиенты боевой/песочница, request-модели, классификация ошибок `BrokerError`
  - Приёмка: `REQ-broker-gateway-01`, `REQ-broker-gateway-06`
  - Проверка: contract-тесты на gRPC-mock (все коды ошибок)
  - Файлы: `packages/broker_gateway/{client,errors,target}.py`, `tests/contract/`
- [ ] **T-202** Бюджет запросов (token bucket per service, запас 20%) + метрики + `BudgetExhausted`
  - Приёмка: `REQ-broker-gateway-03`, `AC-broker-gateway-04`
  - Проверка: `test_budget_limits` (по каждой строке таблицы лимитов TZ §3.2)
  - Файлы: `packages/broker_gateway/budget.py`, тесты
- [ ] **T-203** Каталог инструментов + расписания + торговые статусы (кэш, TTL, снимки)
  - Приёмка: `REQ-instrument-catalog-01…03`, `REQ-risk-gate-01` (готовность данных для проверки статуса)
  - Проверка: `test_catalog_metadata_required`, `test_schedule_from_api_only`
  - Файлы: `packages/instrument_catalog/`, тесты
- [ ] **T-204** Партиции свечей + `ensure_partitions` + репозиторий свечей (upsert, без дублей)
  - Приёмка: `REQ-market-data-03`, `REQ-storage-02` (NUMERIC, не float)
  - Проверка: `test_candles_upsert_idempotent`, `test_no_float_columns`
  - Файлы: `packages/storage/{partitions,candles}.py`, миграция `0002_candles.py`
- [ ] **T-205** Стримы котировок: подписки (реестр, лимиты брокера), reconnect+backoff+jitter, догрузка пропусков, `market_data_lag`
  - Приёмка: `REQ-market-data-01`, `AC-market-data-01`, TZ §2.6
  - Проверка: fault-тесты (обрыв 90 с, повторная подписка, 301 подписка)
  - Файлы: `packages/market_data/{streams,registry}.py`, `tests/fault/`
- [ ] **T-206** Загрузчик истории: окна по `limit`, чекпойнты, ретенция, `history_jobs`/`history_gaps`
  - Приёмка: `REQ-market-data-02`, `AC-market-data-02`
  - Проверка: `test_history_resume_no_duplicates` (mock), прогон на песочнице для 3 инструментов
  - Файлы: `apps/jobs/history_loader.py`, `packages/market_data/history.py`
- [ ] **T-207** Метрики брокера/данных в Prometheus + алерты TZ §12.4 (api/stream/lag) + страница `/admin/system` (набор данных)
  - Приёмка: TZ §12.2 (строки `tbot_api_*`, `tbot_stream_*`, `tbot_market_data_lag_ms`)
  - Проверка: `test_metrics_exposed`, ручной прогон алертов в dev
  - Файлы: `packages/ops/metrics.py`, `apps/web/routes/system.py`
- [ ] **T-208** Страница `/market` + watchlist (свечи, статус, расписание)
  - Приёмка: TZ §9.3 п.18
  - Проверка: e2e (выбор инструмента, смена интервала)
  - Файлы: `apps/web/routes/market.py`, шаблоны, график

## M3 — портфель, риск, исполнение

- [ ] **T-301** `portfolio-sync`: счета, портфель, позиции, деньги/блокировки, маржа, снимки, `GetMaxLots`
  - Приёмка: `REQ-portfolio-sync-01/02`
  - Проверка: contract-тесты + `test_no_position_only_from_internal_calc`
  - Файлы: `packages/portfolio_sync/`
- [ ] **T-302** `reconciliation_runs` + `position_mismatches` + изоляция инструмента
  - Приёмка: TZ §7.5, `R06/R07`
  - Проверка: `test_reconcile_after_kill9`, `test_import_foreign_order`, `test_mismatch_quarantine`
  - Файлы: `packages/portfolio_sync/reconcile.py`, `tests/fault/test_reconcile.py`
- [ ] **T-303** `risk_gate`: каркас проверок + `Intent/Approved/Denied` + `risk_snapshot` + коды R01…R35
  - Приёмка: TZ §6.1–6.4, `REQ-risk-gate-02`
  - Проверка: табличный тест на каждый код (34 случая), `test_core_limits_not_overridable`
  - Файлы: `packages/risk_gate/{model,checks}.py`, тесты
- [ ] **T-304** Дневные лимиты/ просадка/kill-switch (три уровня) + `flatten`/`cancelall` + реакция ≤2 с
  - Приёмка: `REQ-risk-gate-03`, `AC-risk-gate-03`, `AC-risk-gate-04` (маржа)
  - Проверка: e2e+fault: `test_killswitch_2s`, `test_daily_loss_blocks_new_intents`
  - Файлы: `packages/risk_gate/{limits,killswitch}.py`
- [ ] **T-305** `order_executor`: состояния, идемпотентность, `PostOrder`/`CancelOrder`/`ReplaceOrder`, частички, `order_attempts/events`
  - Приёмка: `REQ-order-executor-01…03`, `REQ-order-executor-02`
  - Проверка: `test_one_post_order_per_intent`, `test_price_normalization_rounding`, `test_partial_fill_update`
  - Файлы: `packages/order_executor/{executor,state_machine}.py`
- [ ] **T-306** Протокол `unknown` (сверка по клиентскому ключу, запрет автоповтора)
  - Приёмка: `REQ-order-executor-04`, `AC-order-executor-04`
  - Проверка: fault-тест с таймаутом (счётчик вызовов mock = 1), `test_no_retry_without_proof`
  - Файлы: `packages/order_executor/recovery.py`, `tests/fault/test_timeout.py`
- [ ] **T-307** Paper-исполнитель (`ExecutionBackend`) + модель комиссий + participation cap + гэп-правило
  - Приёмка: `REQ-order-executor-06`
  - Проверка: параметризованные тесты `paper|production` на одинаковых сценариях
  - Файлы: `packages/order_executor/paper.py`, `configs/commissions.yaml`
- [ ] **T-308** Boot sequence + `DEGRADED/HALTED` + допуск стратегий только после сверки
  - Приёмка: `REQ-arch-08`, `AC-arch-08`, `R02`
  - Проверка: fault-тест «токен отозван на старте»
  - Файлы: `apps/engine/boot.py`, тесты
- [ ] **T-309** Учение M3 в песочнице: цикл выставление/отмена/частичка/`kill -9`/посторонняя заявка + протокол
  - Приёмка: `AC-order-executor-05`, TZ §13.5 (учения 2,3,4 частично)
  - Проверка: `make test-live` + протокол `docs/acceptance/M3-*.md`
  - Файлы: `docs/acceptance/`
- [ ] **T-310** Страницы `/orders`, `/portfolio` (+ расхождения, кнопка «сверка»)
  - Приёмка: TZ §9.3 п.15, п.16
  - Проверка: e2e
  - Файлы: `apps/web/routes/{orders,portfolio}.py`

## M4 — стратегии, уведомления, Telegram (чтение)

- [ ] **T-401** `indicators` (SMA/EMA/RSI/MACD/ATR/BB) + эталонные и property-тесты + сверка с `GetTechAnalysis`
  - Приёмка: TZ §5.2 (набор индикаторов), риск-лист §4 (ошибка индикаторов)
  - Проверка: `test_indicators_reference_values`, `test_indicator_vs_server_api` (mock)
  - Файлы: `packages/indicators/`, тесты
- [ ] **T-402** `strategy_engine`: жизненный цикл, контуры, реестр стратегий, `strategy_events`, загрузка состояния
  - Приёмка: `REQ-strategy-engine-01…03`, `REQ-arch-05…07`, `AC-arch-07`
  - Проверка: `test_contour_isolation`, `test_param_change_requires_pause`, `test_plugin_import_guard`
  - Файлы: `packages/strategy_engine/`
- [ ] **T-403** Шина намерений → `risk_gate` → `order_executor` (очередь, backpressure, лимит темпа)
  - Приёмка: `REQ-arch-03/04`, `R25`
  - Проверка: тест архитектуры импортов + `test_rate_governor`
  - Файлы: `apps/engine/pipeline.py`, `tests/unit/test_arch_imports.py`
- [ ] **T-404** Стратегия `grid`: параметры (TZ §5.1), инварианты, уровни, `recenter`, цель по позиции, `max_drawdown_pct`
  - Приёмка: все инварианты 1–10 TZ §5.1 + строки таблицы «специфические ситуации»
  - Проверка: property-тесты инвариантов; `test_grid_{gap,halt,restart,rejected,target_cycle}`
  - Файлы: `packages/strategy_grid/`, тесты
- [ ] **T-405** Стратегия `ta`: правила входа/выхода, размер от риска, стоп/тейк (брокер vs локально), закрытые свечи
  - Приёмка: `REQ-strategy-ta-01…05`
  - Проверка: `test_only_closed_candles`, `test_position_size_by_risk`, `test_stop_pair_removed`
  - Файлы: `packages/strategy_ta/`, тесты
- [ ] **T-406** Wizard создания стратегии (TZ §9.3 п.13) + превью риска + подтверждение TOTP для production
  - Приёмка: `AC-strategy-engine-01`, TZ §6.6 (маржа)
  - Проверка: e2e: полный сценарий создания в paper и production
  - Файлы: `apps/web/routes/strategy_wizard.py`
- [ ] **T-407** Страница стратегии (TZ §9.3 п.14): уровни, лента событий, отказы риск-гейта со снимком, эквити
  - Приёмка: TZ §9.3 п.14
  - Проверка: e2e
  - Файлы: `apps/web/routes/strategy_detail.py`
- [ ] **T-408** `notifications`: правила, дедупликация, агрегация, outbox с backoff, суточный дайджест
  - Приёмка: `REQ-notifications-01/02`, TZ §10.3 (все коды), §12.4 (алерты)
  - Проверка: `test_dedup_window`, `test_aggregation`, `test_digest_schedule_calendar_aware`
  - Файлы: `packages/notifications/`
- [ ] **T-409** Telegram: привязка с TOTP, `/help`, `/status`, `/pnl`, `/positions`, `/orders`, `/strategies`, `/strategy`, `/alerts`, `/limits`
  - Приёмка: `REQ-telegram-01`, `AC-telegram-01`, TZ §10.4
  - Проверка: `test_binding_requires_totp`, `test_unbound_chat_silent`, тесты всех команд
  - Файлы: `apps/tgbot/{binding,commands_read}.py`, тесты
- [ ] **T-410** Paper-обкатка ≥10 торговых дней + отчёт (метрики, сравнение ожиданий)
  - Приёмка: TZ §11.5, план §5 checkpoint M4
  - Проверка: отчёт `docs/acceptance/M4-paper.md`
  - Файлы: `docs/acceptance/`

## M5 — история и бэктест

- [ ] **T-501** Датасеты: манифест, хэш, контроль полноты (`history_gaps`), хранение Parquet для архива
  - Приёмка: `REQ-backtest-01`
  - Проверка: `test_dataset_manifest_reproducible`
  - Файлы: `packages/backtest/datasets.py`, миграция `0003_backtest.py`
- [ ] **T-502** Событийный движок бэктеста: порядок событий, запрет look-ahead, один код стратегии с боевым
  - Приёмка: TZ §11.2, «отравленный бар»
  - Проверка: `test_no_lookahead_poison_bar`, `test_event_order`
  - Файлы: `packages/backtest/engine.py`
- [ ] **T-503** Модель исполнения: `fill_model`, `participation_cap`, slippage, gap rule, делистинг `forced_exit`
  - Приёмка: таблица TZ §11.2
  - Проверка: `test_limit_fill_pessimistic`, `test_gap_worse_price`, `test_forced_exit`
  - Файлы: `packages/backtest/fill_model.py`
- [ ] **T-504** Метрики (полный набор TZ §11.2) + формулы с версиями + вырожденные случаи
  - Приёмка: `REQ-backtest-02`
  - Проверка: `test_metrics_reference`, `test_metrics_degenerate`
  - Файлы: `packages/backtest/metrics.py`
- [ ] **T-505** Оптимизатор: сетка/рандом, walk-forward (≥5 окон), правило устойчивости ≤30%, стресс-периоды, бюджеты
  - Приёмка: TZ §11.3
  - Проверка: `test_walkforward_split_integrity`, `test_fragile_detection`
  - Файлы: `packages/backtest/optimizer.py`
- [ ] **T-506** UI бэктестов (TZ §9.3 п.19, §11.4) + предупреждения + запрет запуска при незакрытых предупреждениях
  - Приёмка: `REQ-backtest-03`
  - Проверка: e2e + `test_start_blocked_on_warnings`
  - Файлы: `apps/web/routes/backtests.py`
- [ ] **T-507** Отчёт «paper vs backtest» + `SUSPECT_MISMATCH`
  - Приёмка: TZ §11.5
  - Проверка: `test_mismatch_flag`
  - Файлы: `packages/backtest/compare.py`

## M6 — консоль, Telegram-управление, отчёты

- [ ] **T-601** Telegram-управление: `/pause`, `/resume`, `/stop`, `/flatten`, `/cancelall`, `/kill` с TOTP и привязкой кода к `command_id`
  - Приёмка: `REQ-telegram-03`, `AC-telegram-03`, TZ §10.5
  - Проверка: `test_command_code_binding`, `test_totp_single_use`, тесты лимитов TG
  - Файлы: `apps/tgbot/commands_control.py`, очередь команд
- [ ] **T-602** Отчёты и экспорт (CSV/XLSX) + одноразовые ссылки + печатные стили
  - Приёмка: TZ §9.3 п.20, §8.3 (ссылки TTL 5 мин)
  - Проверка: `test_export_owner_only`, `test_link_ttl`, e2e печати
  - Файлы: `apps/web/routes/reports.py`, `packages/storage/export.py`
- [ ] **T-603** Страницы админа: `/admin/limits` (диапазоны, двойное подтверждение), `/admin/instruments` (whitelist), `/alerts`
  - Приёмка: TZ §6.5, §9.3 п.9,10,21
  - Проверка: e2e + `test_limits_change_requires_totp`
  - Файлы: `apps/web/routes/admin_*.py`
- [ ] **T-604** Дизайн-система целиком + доступность (axe, клавиатура, печатные формы, print)
  - Приёмка: TZ §9.2, §9.5 (весь чек-лист)
  - Проверка: `make e2e` + axe без critical/serious, grep-тест inline-цветов
  - Файлы: `web/static/tbot.css`, шаблоны, `tests/e2e/a11y.py`
- [ ] **T-605** Производительность страниц (p95 ≤500 мс) + индексы + пагинация курсором
  - Приёмка: TZ §9.1, §7.7 (UI-часть)
  - Проверка: нагрузочный smoke (100 подписок, 10 пользователей)
  - Файлы: миграции с индексами, репозитории запросов

## M7 — наблюдаемость, надёжность, запуск

- [ ] **T-701** Полный набор метрик TZ §12.2 + алерты TZ §12.4 + проверка доставки (canary)
  - Приёмка: все строки таблиц §12.2/§12.4
  - Проверка: `test_alert_rules_fire` (на стенде)
  - Файлы: `deploy/prometheus/`, `packages/ops/`
- [ ] **T-702** Бэкапы: `pg_dump` + WAL-архив + шифрование + ротация + `restore-verify` с контрольными запросами
  - Приёмка: TZ §4.13, RPO ≤15 мин / RTO ≤2 ч; параметры схемы получены — TZ §14.10, `docs/adr/ADR-002`
    (локально в `/var/backups/tbot`, `pg_dump -Fc` + `archive_command` → тот же каталог, шифрование
    до записи, 3 ежедневных + 2 еженедельных + 3 pre-deploy с потолком 20 ГиБ)
  - Проверка: `make backup`, `make restore-verify` (протокол); отдельно — алерт на сбой
    `archive_command`: при падении архивации Postgres копит WAL в `PGDATA`, и на диске 72 ГиБ это
    заканчивается местом, а не только просроченным RPO
  - Файлы: `deploy/backup/`, `scripts/restore_verify.py`
- [ ] **T-703** Runbook (8 процедур TZ §12.6) + `docs/incidents/` шаблон + эскалация §15.5
  - Приёмка: каждая процедура проверена на стенде
  - Проверка: прогон `rotate-token`, `emergency-flatten`, `restore-db` вручную с протоколом
  - Файлы: `docs/runbook/`
- [ ] **T-704** Обновления/откат: blue/green, совместимость миграций, `deploy-check`, план окна
  - Приёмка: TZ §12.7
  - Проверка: учебный откат версии на стенде
  - Файлы: `scripts/deploy.sh`, миграции
- [ ] **T-705** Учения §13.5 полностью (7 сценариев) + протоколы в `docs/acceptance/`
  - Приёмка: TZ §13.5, §13.6 M7
  - Проверка: протоколы учений (подписи, логи, скриншоты)
  - Файлы: `docs/acceptance/`
- [ ] **T-706** Прод-развёртывание (VPS РФ) + egress-политика + UFW/fail2ban/chrony + TLS домена
  - Приёмка: TZ §14.5–14.6, §8.5
  - Проверка: `make deploy-check` на проде, тест egress, прогон alerтов
  - Файлы: `deploy/vps/`, `deploy/nftables/`
- [ ] **T-707** Боевой запуск: 1 стратегия, 1 уровень, капитал 2%, лимиты «минимум»; мониторинг 10 торговых дней
  - Приёмка: план §5 (перед боевым запуском), разрешение владельца приложено
  - Проверка: еженедельные отчёты + сверка с выгрузкой брокера за месяц
  - Файлы: `docs/acceptance/go-live.md`
- [x] **T-708** Группа безопасности Yandex Cloud: входящие 80/443; затем `ufw default deny incoming` + `fail2ban` (22, 443). Решение по SSH (22): оставить `0.0.0.0/0`, компенсация — ключевая аутентификация, ufw, fail2ban; сужение источников — позже, после проверки запасного канала `yc compute ssh` `[принято 2026-11-20: SG изменена владельцем (проверено снаружи: пакеты доходят до хоста), `ufw` active c `deny incoming`, `fail2ban` 1.0.2 с баном 30 мин; `yc init` по-прежнему не выполнен, поэтому правила применялись вручную в Cloud Console]`
  - Приёмка: снаружи коннект к 80/443 устанавливается; к прочим портам — нет; `ufw status` active; fail2ban баннит пробы; SSH-доступ не потерян (правило 22 в новой SG есть, старая SG не откреплена)
  - Проверка: пробы с рабочей машины (`curl -m6 http://153.51.172.30/` — коннект вместо таймаута), журнал fail2ban, запасной вход через `yc compute ssh`; дамп правил до/после в `docs/acceptance/`
  - Файлы: `deploy/vps/{ufw.rules,firewall.sh,ufw_apply_safe.sh,fail2ban-jail.local}`, `docs/runbook/yandex-sg.md` — формат `ufw.yaml` из первоначальной формулировки не используется: ufw не читает YAML, правила описаны в `ufw.rules`, а применяет их `firewall.sh` (с `--revert` и watchdog на время включения)
  - Статус 2026-11-20: **принято** (`docs/acceptance/prod-firewall.md`) — SG: `22` OPEN, `80/443`
    отвечают `Connection refused` (SG пропускает, слушателя нет — он появится в **T-713**),
    `5432/8080/9101/10800` теряются как отфильтрованные; `ufw status` active, правила 22/80/443;
    учение fail2ban: 5 неудачных входов → бан источника (SSH `Connection timed out`) →
    автоматический размбан по `systemd-run` → вход восстановлен, `Total banned: 3` (плюс пробы
    сканеров). Запасной вход через `yc compute ssh` **не проверен** (нет `yc init`) — риск принят
    сознательно: единственный путь управления при бане — консоль Yandex Cloud.
  - Что осталось: после Caddy (T-713) повторить пробы 80/443 уже со слушателем; сузить SG с
    «разрешено всё» до `22/80/443` (сейчас единственным фильтром портов является `ufw` хоста).
- [x] **T-709** Доверие TLS брокера: корневой сертификат НУЦ в хост (`update-ca-certificates`) и в образ, `SSL_TBANK_VERIFY`, тест CI «без доверия — падение», контроль даты сертификата в `deploy-check`
  - Приёмка: `AC-broker-gateway-02` на реальной ВМ; в `deploy-check` вывод срока сертификата (текущий до 2027-08-24)
  - Проверка: `curl` без `-k` → 401 (не ошибка TLS); контейнер без корня → ошибка; CI валится
  - Файлы: `deploy/ca/`, `deploy/Dockerfile.*`, `scripts/deploy_check.py`
  - Статус 2026-11-20: **принято целиком** — образ и CI (run `44675985821`, job `broker-tls`,
    шаг `compose-smoke`) + хост на живой площадке (`curl` без `-k` → `401` при
    `Verify return code: 0` на обеих точках; протокол `docs/acceptance/prod-bootstrap.md §2`).
    Контроль срока корня и сертификата брокера в `deploy-check` ✓, `SSL_TBANK_VERIFY` ✓ (отключить
    нельзя), подмена корня по отпечатку ловится ✓. Инструкцию по установке на хост и на рабочий
    компьютер даёт `docs/runbook/nucc-ca.md` (§2 сервер, §3 десктоп, §4 срок и `certifi`, §5 смена ЦС).
    Дальнейшая работа по доверию — в T-012: клиентам на `certifi` (`httpx`, SDK брокера)
    системное хранилище не помогает, нужна явная CA-связка (`verify=` на файл).
- [ ] **T-710** Транспорт Telegram, схема A (прод): пул `TG_API_ENDPOINTS` с health-check `getMe`, проверкой SNI/цепочки, backoff и метриками; дублирующий канал критичных алертов (e-mail)
  - Приёмка: `docs/tz/10 §10.7`, `AC-telegram-04`, `docs/research/03 §3.4`; живой адрес сейчас только `149.154.167.220:443`; дайджест и тестовый алерт реально доставлены с прод-площадки; при недоступности всех адресов — статус «канал Telegram: деградация» в панели ≤60 с
  - Проверка: `tests/integration/test_tg_transport.py` (переключение, подмена имени в сертификате → отказ от адреса + алерт), ручной прогон `/status` с прод-ВМ
  - Файлы: `apps/tgbot/transport.py`, `apps/tgbot/endpoints.yaml`, `configs/alerting/second-channel.yaml`
- [ ] **T-711** Фиксация ограничений прод-ВМ (решение OQ-11: **без расширения**): конфиг Postgres под 3.8 ГБ (`shared_buffers ≤512 МБ`, `max_connections ≤60`), 1 бэктест-воркер на проде, ретенция минутных свечей 12 мес. + Parquet-архив, тяжёлые прогоны на dev-машине, дампы вне раздела БД
  - Приёмка: TZ §14.9; `nproc/free -h/df -h` зафиксированы в `docs/acceptance/vm-sizing.md`; пределы не «подкручены» в сторону ослабления риск-лимита
  - Проверка: прогон 1 бэктест-воркера + 100 подписок без роста RSS/очередей; алерты RSS/диска сработали на тестовой нагрузке
  - Файлы: `deploy/postgres/prod.conf`, `configs/retention.yaml`, `docs/acceptance/vm-sizing.md`
  - Статус 2026-11-20: фактические границы зафиксированы и проверены на машине (замеры, swap,
    `chrony`, доверие НУЦ) — `docs/acceptance/prod-bootstrap.md`; отдельный `prod.conf` не нужен:
    рабочая ВМ одна, её конфиг — `deploy/postgres/tbot.conf` (256 МБ / 60 соединений, потолок
    OQ-11 — 512 МБ). `docs/acceptance/vm-sizing.md`, `configs/retention.yaml` и прогоны
    1 воркера + 100 подписок — в силе, они выполняются вместе с загрузкой данных (M4).
- [ ] **T-714** C′: туннельный egress через `rusiksoft.ru` (`176.32.39.234`): отдельный пользователь VLESS на существующем входе 443 + клиент Xray с локальным SOCKS5 на проде + правила маршрутизации на узле B (запрет внутренних адресов, фиксированный exit) + ADR. Пошаговая инструкция, проверки и откат — `docs/runbook/telegram-egress-proxy.md` `[in progress: транспорт выбран (вариант 443 + свой пользователь, `runbook §4.2`), клиент на проде установлен постоянно; остаются правила на узле B и секрет токена]`
  - Обязательное предусловие: **ротация всех затронутых учётных данных** — значения попадали в переписку (фрагмент JSON входа, `ss://`-URI с двумя ключами, `vless://`-URI личного клиента), а при моём локальном дампе структуры конфига в вывод попали и `id` клиентов входа 443 (маска была настроена на `password`/`uuid`, но не на поле `id`) — считать экспонированными, заменить затронутые
  - Прогресс (2026-11-19, вечер): **транспорт работает** — проверено с прод-ВМ временным `xray` 26.11.9 (удалён после теста): `getMe` → HTTP 401, цепочка `api.telegram.org` настоящая (`verify ok`), медиана 0.27 с. Обнаружено: exit выбран балансировщиком и оказывается в диапазонах **Cloudflare (AS13335, Амстердам)** → без явного outbound правила наш канал управления работает «через чужой выбор», что рискованно для Bot API. Протокол: `docs/research/03 §3.9`, `runbook §4.3`
  - Выполнено (2026-11-19, 16:00 UTC): клиент туннеля установлен **постоянно** по решению заказчика (на тот момент остальная T-011 была отложена; пауза T-011 снята решением от 2026-11-20): `/usr/local/bin/xray` 26.11.9 с закреплённым дайджестом пакета, служба `tbot-tunnel.service` с песочником и лимитами (`MemoryMax=96M`, `CPUQuota=60%`, `TasksMax=64`), SOCKS5 только на loopback с парольной аутентификацией, клиентский `blackhole` на приватные/link-local/CGNAT-диапазоны, пользователь `tbot-tunnel` (`nologin`), юнит `enabled`; локальные пароли SOCKS сгенерированы на площадке (`/etc/tbot/secrets/telegram_socks_*`, `600`). Полный протокол: `docs/acceptance/tg-egress.md` (проверки 1–8 пройдены, 9 провалена намеренно зафиксирована, 10–11 отложены)
  - Остаётся: (1) два правила маршрутизации по пользователю `tbot` на узле B — запрет приватных/link-local и **конкретный** exit: сейчас балансировщик ротирует выход (замеры: Амстердам → Стокгольм, оба Cloudflare), из-за чего Telegram видит разные IP одного бота; (2) `getMe` с настоящим токеном (проверка 10) — после самостоятельного размещения секрета заказчиком в `/etc/tbot/secrets/telegram_token`; (3) стойкость службы после перезагрузки (проверка 11) — нужна согласованная перезагрузка; (4) ADR `ADR-0xx-tg-egress-via-node-b.md` с зафиксированными замерами
  - Приёмка: `docs/runbook/telegram-egress-proxy.md` шаги 1–6, `docs/research/03 §3.7.1, §3.9`, `AC-telegram-07`. С прод-ВМ: `curl -x socks5h://127.0.0.1:10800 …/getMe` даёт 401/404 при корректной проверке цепочки; прямой заход падает; через туннель нет доступа к `127.0.0.1`, приватным и link-local сетям и к портам прода; медиана задержки и IP, который видит Telegram, записаны
  - Проверка: `scripts/tg_egress_probe.sh` (A напрямую / C′ через SOCKS / поддельный CA отклоняется + `tg_tls_mismatch` / приложение не резолвит `api.telegram.org` заранее); тесты `tests/integration/test_tg_transport.py`
  - Файлы: `docs/adr/ADR-0xx-tg-egress-via-node-b.md`, `deploy/vps/tbot-tunnel/{config.yaml.example,systemd.service}`, `configs/telegram/transport.yaml`, `scripts/tg_egress_probe.sh`
  - Статус 2026-11-19 (вечер, часть по коду): приложение выбирает путь **явно** —
    `telegram.transport = tunnel | direct` (`TBOT_TELEGRAM__TRANSPORT`), при `tunnel` клиент
    идёт через `socks5h://…@127.0.0.1:10800` (имя разрешается на узле B), пароль читается из
    файла секрета `tg_socks_password`. Логика пробы транспорта и проверок готовности покрыта
    тестами без сети: `tests/unit/test_tgbot_transport.py` (9 проверок: нет токена / успех /
    401 при живой связности / сетевой сбой / замер выхода / состояние до пробы / путь direct /
    маска пароля SOCKS). `scripts/tg_egress_probe.sh` и ADR пока не написаны.
  - Примечание: вариант B (контейнер `tgbot` на узле) в backlog не ставится — только резерв ради изоляции процесса управления (`docs/tz/10 §10.7`); `AC-telegram-05/06` тогда и применяются.
- [ ] **T-712** Docker Engine + compose на прод (из репозитариев дистрибутива), pull образов GHCR по digest, non-root, сети, tmpfs для секретов, ротация логов
  - Приёмка: TZ §14.6; `docker compose config` валиден; конвейер `pull → migrate → restart` воспроизведён
  - Проверка: учебный деплой предыдущей версии и откат (TZ §12.7)
  - Файлы: `deploy/compose.yaml`, `deploy/compose.prod.yaml`, `deploy/tbot.prod.env`, `deploy/vps/docker-daemon.json`
  - Статус 2026-11-20: **половина принята** — Docker Engine 29.1.3 (`docker.io`) и compose v2 2.40.3
    (`docker-compose-v2`: в Ubuntu нет пакета `docker-compose-plugin`, это имя из вендорного
    Docker CE), юнит active+enabled, `/etc/docker/daemon.json` из `deploy/vps/docker-daemon.json`
    (json-file 50 МБ × 10), smoke-подтверждения hardening на площадке (read-only, `NoNewPrivs: 1`,
    `CapEff: 0`, `--network none` → только `lo`, egress контейнера → `ghcr.io/v2/` 401) —
    `docs/acceptance/prod-firewall.md §5`.
  - Что блокирует остаток (обновлено 2026-11-20 вечером): **блокировок нет** — шесть ответов
    заказчика получены и закреплены в `docs/adr/ADR-003-prod-deploy-edge-decisions.md`
    (деплой разрешён, доступ через `sudo`, секреты кладёт заказчик). Нужны действия владельца
    площадки: выпустить и завести `ghcr_token` и секреты приложения скриптом
    `deploy/vps/secrets-setup.sh`; добавить публичную часть deploy-ключа ВМ в репозиторий
    (read-only); сообщить логин — владельца токена; согласовать `systemctl restart docker` и ребут.
    Проверка pull по digest для публичного образа
    выполнена: `postgres:16.4` = `sha256:e62fbf9d3e2b49816a32c400ed2dba83e3b361e6833e624024309c35d334b412`.
  - Что сделано дополнительно 2026-11-20: `deploy/compose.prod.yaml` написан (единственные
    публикуемые наружу порты — 80/443 Caddy, секреты файлами из `/etc/tbot/secrets`, лимиты под
    3.8 ГиБ, все образы по digest, включая образ базы); блоки `build:` вынесены из
    `compose.yaml` в `compose.override.yaml`, потому что `build: !reset null` в overlay
    **не убирает сборку** из разобранной модели compose — в `config --format json` остаются
    `context`/`dockerfile` из базового файла (нашёл первый прогон job'а `prod-config`,
    `docs/acceptance/tls-edge.md §5, п.6`);
    compose на площадке — **2.40.3** из пакета Ubuntu, на CI-раннёре — **v5.1.3**, поэтому
    разбор в CI проверяет более новую реализацию и требует повторного `config` на ВМ;
    состав разбирается и проверяется в CI (job `prod-config`:
    `docker compose config` + `scripts/prod_compose_check.py` + `caddy validate` внутри образа с
    закреплённым digest) и статически (`test_compose_prod_contract`, `test_prod_compose_check`).
    Остаток задачи — реальный `pull → migrate → restart` и учебный откат на площадке.
  - Добавлено 2026-11-20 (вечер): порядок деплоя описан в `docs/runbook/stand-deploy.md`
    (клон по read-only deploy-ключу, `config` на ВМ, `pull` по digest, `migrate`, первый срез
    `postgres + web + caddy`); ввод секретов — новый артефакт `deploy/vps/secrets-setup.sh` и
    `docs/runbook/secrets-on-host.md`; `AGENTS.md` приведён к `ADR-001`; дайджесты в
    `deploy/tbot.prod.env` пересняты с commit `b235d29` (run `Image` 44716926556).
    Предыдущий набор `21579ba` / run 44708907667 остаётся в истории как точка отката.
    Deploy-ключ ВМ создан 2026-11-20: `/root/.ssh/tbot_deploy_key` (600 root:root), отпечаток
    `SHA256:bYb6ZnLlpjbjQoAG3GomNid/zWuRgL0yXvr8N6KVYxI`, публичная часть — в
    `docs/runbook/stand-deploy.md §2`. Сборка образов не воспроизводима по digest: наборы
    меняются после каждого мержа, поэтому пересъёмка делается непосредственно перед деплоем
    (`docs/runbook/ghcr-pull.md §2`).
  - Новая подзадача остатка: `scripts/deploy_check.py` ищет в каталоге секретов имена
    *конфигурации* (`tg_bot_token`, `tg_socks_password`), а на площадке файлы названы по TZ §14.3
    (`telegram_token`, `telegram_socks_pass`) → `secret_files` краснеет на готовой площадке.
    Чинить по замеру на хосте, файлы с именами конфигурации создавать нельзя (имена задаёт
    `deploy/compose.prod.yaml`) — `docs/runbook/stand-deploy.md §8`.
  - Ещё одна подзадача остатка (замечено 2026-11-20, по замеру на хосте): `--check` в
    `deploy/vps/secrets-setup.sh` покрывает четыре имени, а compose читает пять файлов —
    `telegram_socks_pass` создаётся туннелем (T-714) и выведен из ответственности скрипта
    контрактом. Готовность площадки надо проверять и по нему тоже (`sudo ls -l
    /etc/tbot/secrets`): на замере 2026-11-20 он есть, 24 байта, `600 root:root`. Способ
    закрытия — расширить `--check` списком имён только для проверки и одновременно добавить фиктивное
    значение в CI-прогон; делать это надо вместе с правкой `deploy_check.py`, чтобы проверки
    готовности не разъехались.
- [ ] **T-713** Caddy + сертификат Let's Encrypt на `tbot.rusiksoft.ru`, редирект HTTP→HTTPS, HSTS, базовые заголовки CSP/CSRF-защита уровня прокси
  - Приёмка: TZ §8.3, §14.9; в браузере — валидный сертификат, HSTS, редирект
  - Проверка: `curl -I https://tbot.rusiksoft.ru/healthz`, тест на отсутствие смешанного содержимого и внешних CDN
  - Файлы: `deploy/caddy/Caddyfile`, `deploy/compose.prod.yaml`, `deploy/tbot.prod.env`,
    `scripts/prod_compose_check.py`, `docs/acceptance/tls-edge.md`
  - Статус 2026-11-20: **в процессе, не принята**. Проверено без запуска контура:
    Caddyfile валиден и отформатирован `caddy` v2.11.9 (та же версия, что у закреплённого digest),
    21 поведенческая проба на копии Caddyfile (`tls internal`, upstream-заглушка) — заголовки
    TZ §8.3, `-Server` снимает и чужой `Server`, TRACE→405, `/metrics`→404, тело 11 МиБ→413 без
    доступа к приложению, заголовки 100 КиБ→431, TLS 1.2/1.3 работают, `X-Forwarded-*`/
    `X-Real-IP` доходят до upstream, журнал — JSON. Снаружи: DNS → `153.51.172.30`, 80/443
    отвечают `Connection refused` (SG и ufw пропускают, слушателя нет) —
    `docs/acceptance/tls-edge.md §2`.
  - Находки пробы, уже внесённые в артефакты: (1) журнал прокси писал `?token=…` и `X-Api-Key`
    открытым текстом → добавлен `format filter` (query `token|key|sig`, `X-Api-Key`) и запрещена
    опция `log_credentials`; (2) Caddy сам навешивал `Alt-Svc: h3`, а UDP/443 не открыт →
    `protocols h1 h2`; (3) фактический порог `max_header_size 16KB` измерен: 431 начинается с
    ≈21 КиБ, а не ровно с 16 КиБ.
  - Изменения после ответов заказчика (тот же день, вечер): `443/udp` открыт (правило в
    `deploy/vps/ufw.rules` + применено на площадке), **HTTP/3 включён** — Caddyfile переведён на
    `protocols h1 h2 h3`. Проход udp доказан счётчиком правила: 20 датаграмм снаружи →
    `20 900 ACCEPT udp dpt:443` в `ufw-user-input` (`docs/acceptance/tls-edge.md §2.1`); локально
    переснято: `adapt` даёт `protocols ["h1","h2","h3"]`, в ответе появился `Alt-Svc: h3`,
    udp-сокет поднят. Связка «udp-правило ↔ h3» держится тестом
    `test_HTTP_3_объявлен_только_вместе_с_открытым_UDP_443`.
  - Что осталось (требует деплоя): выпуск сертификата ACME, `curl -I https://…/healthz`,
    редирект :80→:443 живым трафиком, заголовки против живого `web`, `openssl s_client -tls1_1`
    (отказ), `curl --http3` (на dev-машине curl 8.22.0 без nghttp3 — проверять на площадке или
    счётчиком udp), ротация логов `json-file` в контейнере, поведение после рестарта docker и ребута.
  - Блокировки сняты 2026-11-20 (вечер): деплой разрешён и описан в
    `docs/runbook/stand-deploy.md`, доступ к Docker — через `sudo`, ограничитель запросов
    перенесён в приложение (TZ §8.3 поправлен с разрешения заказчика, `ADR-003 §4`), `443/udp`
    открыт, `80/tcp` остаётся, секреты кладёт заказчик скриптом `deploy/vps/secrets-setup.sh`.
    Ждут только действия владельца площадки (секреты, **добавление deploy-ключа ВМ в GitHub**,
    логин владельца `ghcr_token`, сужение SG, согласие на рестарт docker и ребут) —
    `docs/HANDOFF.md §4`, `docs/acceptance/tls-edge.md §7`.
  - 2026-11-20 13:25: PR #2 влито в `main` (мерж `b235d29`), CI зелёный целиком, включая
    `prod-config`; набор дайджестов переснят с прогона `Image` 44716926556 (commit `b235d29`).

## Позже (вне M0–M7, зафиксировано объёмом ТЗ)

- [ ] **T-901** Фьючерсы: `price_type=POINT`, ГО/СО, экспирация/ролловер (`REQ` из TZ §5.3) `[blocked: OQ-4]`
- [ ] **T-902** Валютные пары и денежный рынок (LQD) `[blocked: OQ-4]`
- [ ] **T-903** Следование сигналам `SignalService` как отдельная стратегия
- [ ] **T-904** WebAuthn/аппаратные ключи как второй фактор вместо/кроме TOTP
- [ ] **T-905** Реплика Postgres / отказоустойчивый контур при росте числа пользователей
