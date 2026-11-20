# Приёмка M0: dev-стенд в Docker Compose (T-005) и CI (T-008)

Дата: 2026-11-20. Коммит: `29c9ace` (`main`). Область: `deploy/compose.yaml`,
`deploy/compose.override.yaml`, `deploy/postgres/tbot.conf`, Dockerfile'ы,
`.github/workflows/ci.yml`, `.github/workflows/image.yml`, `pyproject.toml` (зависимости).

Где проверялось: GitHub Actions, образ раннера `ubuntu-26.04` (релиз образов `20261116.202`),
Docker Engine + Docker Compose v2 из образа раннера, Python 3.12.16. На dev-машине (Windows)
Docker отсутствует, поэтому реальная проверка контейнеров выполняется **только** в CI job
`compose-smoke`, а локально — контрактные тесты на compose и workflow'ы
(`tests/integration/test_compose_contract.py`, `tests/contract/test_ci_workflows.py`).

Зелёные прогоны на этом коммите:

| Workflow | Run | Итог |
|---|---|---|
| `CI` (7 job'ов: quality, tests+coverage, миграции, gitleaks, audit, compose-smoke, площадка) | `44641201161` | все ✓ |
| `Image` (сборка и публикация 4 образов в GHCR) | `44641201349` | ✓ |
| `CI` предыдущий, перед добавлением явной readiness-пробы engine | `44640263199` (`2b465a5`) | все ✓ |
| `CI` и `Image` на документационном push'е (протокол и статусы) | `44642149252` / `44642149493` (`2592eae`) | все ✓ |

## 1. Что проверил job `compose-smoke`

| # | Шаг | Что делается | Результат |
|---|---|---|---|
| 1 | dev-секреты стенда | в `deploy/secrets/` кладутся 4 фейльных значения (`ci-stand-*`) — compose разрешает пути секретов относительно `deploy/compose.yaml` | ✓ |
| 2 | `docker compose config --quiet` | синтаксис и разрешения якорей/переменных | ✓ |
| 3 | `docker compose build` | 4 образа (`web`, `engine`, `tgbot`, `jobs`) из одного `deploy/Dockerfile` с `ARG APP` | ✓ |
| 4 | `up -d --wait --wait-timeout 180 postgres web engine jobs` | старт с ожиданием **healthy** (не «запущен») | `tbot-postgres-1 Healthy`, `tbot-web-1 Healthy`, `tbot-engine-1 Healthy`, `tbot-jobs-1 Healthy` |
| 5 | `run --rm migrate` | миграции из контейнера стенда (`alembic upgrade head`) | `Running upgrade -> 0001` |
| 6 | `exec -T web … /readyz` | readiness web, включая проверку базы | `status=200 … "checks":{"database":{"ok":true,"detail":"postgres доступен"}}` |
| 7 | `exec -T engine … /readyz` и `/healthz`; `exec -T jobs … /healthz` | readiness engine (контур + потолки риска) и liveness engine/jobs | см. §2 |
| 8 | `exec -T postgres bash -s` (probe `8.8.8.8:443`) | исходящий трафик контейнера базы | `OK: исходящий трафик базы заблокирован (внутренняя сеть)` |
| 9 | журнал контейнеров при неудаче | `logs --tail=200` | шаг пропущен (job зелёный) |

## 2. Доказательные строки логов (run `44641201161`, job `135972400303`)

```text
postgres-1  LOG:  listening on IPv4 address "0.0.0.0", port 5432
postgres-1  LOG:  listening on IPv6 address "::", port 5432
postgres-1  LOG:  listening on Unix socket "/var/run/postgresql/.s.PGSQL.5432"
postgres-1  LOG:  database system is ready to accept connections

web готов          OK http://127.0.0.1:8080/readyz  status=200 {"status":"ready","app":"web",
                   "contour":"sandbox","checks":{"database":{"ok":true,"detail":"postgres доступен"}}}
engine и jobs живы OK http://127.0.0.1:9101/readyz  status=200 {"status":"ready","app":"engine",
                   "checks":{"contour":{"ok":true,"detail":"контур sandbox разрешён на текущей вехе"},
                             "config":{"ok":true,"detail":"потолки риска: 5.00% на стратегию,
                             уровней сетки ≤6, множитель ≤1.3"}}}
engine и jobs живы OK http://127.0.0.1:9101/healthz status=200 {"status":"alive","app":"engine"}
engine и jobs живы OK http://127.0.0.1:9103/healthz status=200 {"status":"alive","app":"jobs"}
нет исходящего     OK: исходящий трафик базы заблокирован (внутренняя сеть)
```

`/readyz` engine проверяется **явно** (не только через healthcheck контейнера): иначе приёмка
висела бы на косвенном признаке. Держится тестом
`test_приёмка_стенда_требует_readyz_у_web_и_engine`.

## 3. Гарантии, которые этот прогон подтверждает фактически

| Гарантия | Где задано | Чем подтверждено |
|---|---|---|
| У базы нет исходящего трафика | сеть `tbot-backend` = `internal: true`, наружу портов нет; `tbot-egress` (единственная bridge-сеть) база не подключена | шаг 8 + `docker compose config` (публикация порта только в dev-дополнении и только на `127.0.0.1:5433`) |
| База слушает сеть контейнера | `deploy/postgres/tbot.conf`: `listen_addresses = '*'` | `listening on IPv4 address "0.0.0.0"` + успешные подключения web/engine/jobs |
| Read-only rootFS у всех процессов | `read_only: true` в `x-runtime` и `x-db-runtime` | стенд поднялся и стал healthy; у базы сокет на `tmpfs /var/run/postgresql` |
| Минимум capability | `cap_drop: ALL` у всех; `cap_add: CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID` **только** у `postgres` | прогон + `test_база_получает_только_те_capability_которые_нужны_entrypoint`, `test_прикладные_процессы_не_получают_capability` |
| Без эскалации привилегий | `no-new-privileges:true` у всех (включая базу: `gosu` — не setuid-бинарник) | прогон |
| Секреты — только получателям | `secrets:` у `postgres` = `db_password`; у `web`/`engine`/`jobs` = `db_url`; `tg_bot_token`/`tg_socks_password` — только `tgbot` | `test_стенд_в_ci_использует_каталог_секретов_compose` + прогон (web видит базу, токена бота не имеет) |
| Готовность через healthcheck, а не `sleep` | `depends_on: postgres: condition: service_healthy`; healthcheck'и на `health_probe` | `up --wait` стал зелёным только после healthy всех четырёх |
| Ограничения ресурсов и процессов | `pids_limit: 256`, лимиты CPU/памяти в `x-runtime`/`x-db-runtime` (площадка 2 vCPU / 3.8 ГиБ, OQ-11) | контрактные тесты на compose |
| Ротация логов | `logging: json-file, max-size 10m, max-file 5` | контрактный тест на compose |

## 4. Что этот прогон **не** покрывает (границы приёмки)

1. **`tgbot` в CI-стенде не запускается.** Его `/readyz` требует успешной пробы Bot API
   (`telegram_transport`, `telegram_token`, см. `readiness_checks` в `apps/tgbot/main.py`), а из
   CI-раннера Bot API недоступен — readiness была бы 503 и `up --wait` не стал бы зелёным никогда.
   Образ `tgbot` собирается в CI и публикуется в GHCR (digest в §7), конфиг сервиса в compose есть
   и проходит `compose config`. Приёмка канала управления — в M3, вместе с `tbot-tunnel` на площадке
   (`docs/acceptance/tg-egress.md`).
2. **`make dev` как команда не выполнялась** (на dev-машине нет Docker). В CI используются те же
   файлы с той же парой `-f deploy/compose.yaml -f deploy/compose.override.yaml`; корректность
   самой обвязки `make.ps1`/`scripts/dev.py` проверяется контрактом `test_dev_cli_contract`,
   а не реальным запуском.
3. **Проба egress базы — одно конкретное соединение** (`/dev/tcp/8.8.8.8/443` изнутри контейнера)
   плюс отсутствие опубликованных портов и `internal`-сеть. Сниффер (tcpdump) не поднимался.
4. **Не проверялись**: персистентность тома `pgdata` при пересоздании контейнера, бэкапы и
   восстановление, контуры `paper`/`production` (`TBOT_CONFIRM_PRODUCTION`), поведение после
   перезагрузки хоста, поведение под реальной нагрузкой площадки.
5. **Длительность steady-state не наблюдалась**: `--wait-timeout 180` покрывает старт, но не
   многочасовую работу.

## 5. Семь причин падения `compose-smoke`, найденные по прогонам

Все семь видно только с реальным Docker; локально (без Docker) их не воспроизвести. Каждая
закрыта контрактом, чтобы не вернулась.

| # | Симптом в логе CI | Причина | Коммит |
|---|---|---|---|
| 1 | `chmod: … Operation not permitted`, `failed switching to "postgres"` | entrypoint `postgres` под root требует `CHOWN`/`FOWNER`/`SETGID`/`SETUID` из дефолтного набора Docker'а, а у сервиса был `cap_drop: ALL` без исключений | `9574537` |
| 2 | `chmod: /var/run/postgresql: Read-only file system` | каталог unix-сокета на read-only rootFS → нужен `tmpfs` (в `/tmp` нельзя: временный сервер внутри `initdb` использует каталог сокета по умолчанию) | `9574537` |
| 3 | (ещё не упало, но упало бы) `connection refused` от web/engine/jobs | `listen_addresses = 'localhost'` — только loopback самого контейнера | `9574537` |
| 4 | (никогда не стал бы зелёным) `jobs` не переходил в healthy | healthcheck `jobs` висел на `/readyz`, который на M0 честно отвечает «исполнителей задач ещё нет» → переведён на `/healthz --liveness` | `9574537` |
| 5 | шаг приёмки egress падал бы на `executable file not found` | проба запускала `python3` внутри контейнера базы, а в образе `postgres` Python не установлен вовсе → переписано на `bash` + `/dev/tcp` + `timeout` | `9574537` |
| 6 | `find: '/var/lib/postgresql/data': Permission denied` | entrypoint сначала делает `chmod 00700 $PGDATA`, том приходит из образа владельцем uid 999 → root без `DAC_OVERRIDE` не входит в каталог | `58c3889` |
| 7 | `LOG: input in flex scanner failed at file "/etc/postgresql/tbot.conf" line 1` + `FATAL: configuration file contains errors` после успешного `initdb` | в `volumes` стояло `./deploy/postgres/tbot.conf`: compose разрешает относительные пути относительно каталога compose-файла (`deploy/`) → `deploy/deploy/...`; несуществующий хостовый путь в короткой форме Docker молча становится **пустым каталогом** | `2b465a5` |

Формулировка 7 важна как урок по инструменту: сообщение об ошибке не содержало ни слова о
пропущенном монтировании, поэтому «битый конфиг» оказался несуществующим файлом. Проверка
`test_хостовые_пут_и_монтирований_существуют` сверяет каждый относительный источник томов с
реальным расположением относительно каталога compose-файла.

## 6. Зависимости: job `audit` (`pip-audit`) — как чинилось и что зелёное

Причина падения — advisory по `starlette` (транзитивно от `fastapi>=0.115,<0.116`, ставился
`starlette 0.46.2`) и по `cryptography 43.0.3` (прямая зависимость). Поднятие нижней границы:
`fastapi>=0.165,<0.166` (иначе исправленную `starlette` resolver поставить не может — ветки
0.115–0.130 ограничивают starlette сверху версиями 0.46–0.99) и `cryptography>=50.0,<51.0`
(50.0.0 — самый «старший» fix, `PYSEC-2026-3552`; 49.0.0 закрывала только -3553/-3554, и это
поймал локальный прогон аудита, а не CI).

Фактические версии в зелёном прогоне CI: `fastapi 0.165.0`, `starlette 1.10.0`,
`cryptography 50.0.2`. Локальное воспроизведение шага (без Docker, ровно те же команды): venv
**вне** дерева репозитория → `pip install -e .` → `pip freeze --exclude-editable` →
`pip-audit --strict -r <файл>` → «No known vulnerabilities found» по 41 продакшн-пакету.

## 7. Образы в GHCR (run `44641201349`, `main`, `sha-29c9ace`)

Публикация идёт по digest — это вход для `make deploy` (TZ §14.6).

| Образ | Digest |
|---|---|
| `ghcr.io/rusiksoft-afk/tbot-web` | `sha256:9f8ef8e686fc943f9a361f231de6ce48c235622a15a47ac02480fc79465947dd` |
| `ghcr.io/rusiksoft-afk/tbot-engine` | `sha256:6b8cb501ceead1ca87479d002bcbc5b6a656c07283a32d1aa1162b99b710d439` |
| `ghcr.io/rusiksoft-afk/tbot-tgbot` | `sha256:eb72d2436878812cb2b9a69d43ff6a82ddd74ac848c568e98e38971727bb38db` |
| `ghcr.io/rusiksoft-afk/tbot-jobs` | `sha256:7ba8d0d8634049a93aecafa55a5d2a9f64955862e79e79e3010dd6c9885dea47` |

## 8. Локальные гейты на том же коммите

| Гейт | Команда | Результат |
|---|---|---|
| Формат | `ruff format --check .` | чисто |
| Линтеры | `ruff check .` | All checks passed |
| Типы | `mypy .` (`--strict`) | no issues, 48 файла |
| Тесты | `pytest -m "not live_api and not e2e"` | **212 passed** |
| Покрытие | `pytest --cov` | **95.07%** при пороге 80% |
| Подавления | `scripts/count_suppressions.py` | **14** (базовый уровень, рост ловит `suppress-growth`) |
| Статический аудит | `bandit` | замечаний нет |

## 9. Итог

- **T-005 (dev-стенд) — принято.** Приёмка «`/readyz` 200 у web и engine; egress для БД закрыт»
  подтверждена зелёным `compose-smoke` (шаги 4, 6, 7, 8). Оговорки — §4, они относятся к `tgbot`
  (M3) и к отсутствию Docker на dev-машине, а не к составу стенда.
- **T-008 (CI) — принято.** Все job'ы `CI` зелёные на `29c9ace` (run `44641201161`), пороги
  покрытия 80% выдержаны фактическими 95.07%, `Image` публикует 4 образа по digest
  (run `44641201349`).
- Восемь падений CI (7 в `compose-smoke` + `pip-audit`) закрыты фиксами в исходниках, а не
  ослаблением проверок: подавлений не добавлено, пороги не снижались.

## 10. Как повторить или диагностировать

```bash
# CI-эквивалент стенда (там, где есть Docker):
mkdir -p deploy/secrets
printf 'ci-stand-db-password' > deploy/secrets/db_password
printf 'postgresql://tbot:ci-stand-db-password@postgres:5432/tbot' > deploy/secrets/db_url
printf 'ci-stand-not-a-real-token' > deploy/secrets/tg_bot_token
printf 'ci-stand-not-a-real-password' > deploy/secrets/tg_socks_password
docker compose -f deploy/compose.yaml -f deploy/compose.override.yaml config --quiet
docker compose -f deploy/compose.yaml -f deploy/compose.override.yaml build
docker compose -f deploy/compose.yaml -f deploy/compose.override.yaml \
  up -d --wait --wait-timeout 180 postgres web engine jobs
```

Если `up --wait` снова покраснеет — смотреть вывод шага `журнал контейнеров при неудаче`
(`docker compose logs --tail=200`), а не текст ошибки `up --wait`: он показывает только
«unhealthy», а истинная причина — в журнале контейнера.
