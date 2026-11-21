# Приёмка: схема идентичности и права роли приложения (T-009)

Площадка: `153.51.172.30` (`compute-vm-2-4-74-ssd-1795094860175`, Yandex Cloud, Ubuntu 24.04.5 LTS,
`fv48ibn5ff3ff5gd0e3v`). Дата работ: 2026-11-20. Основание: TZ §4.1 (`REQ-identity-04`,
`REQ-storage-01`, `REQ-storage-02`), §8.1–§8.4; ADR-003 (деплой разрешён), ADR-005 (права
файлов секретов), ADR-002 (откат по digest). Задача — **T-009**, веха M1.

Код: ревизия `migrations/versions/0002_identity_access.py`, модели `packages/storage/`,
права `deploy/postgres/roles.sql`. Коммиты среза: `028902b` (модели + ревизия),
`03c7eca` (права роли + тесты), `df03e89` (пересъёмка digest'ов). CI: прогон
`44799084782` (схема и права на живой Postgres 16.4) и `44800434747` (все 9 job'ов зелёные).

## 1. Что принималось и чем проверяется

| Требование | Проверка | Где закреплена |
| --- | --- | --- |
| `REQ-storage-01` — миграции применяются и сворачиваются (`upgrade head → downgrade base → upgrade head`) | job `migrations`, Postgres 16.4 как service | `.github/workflows/ci.yml`, job `migrations` |
| `REQ-storage-02` — нет floating-point и «денег» в модели данных | офлайн-разбор DDL: нет `DOUBLE PRECISION`, `REAL`, `FLOAT`, `MONEY`; нет наивного `TIMESTAMP` | `tests/contract/test_identity_schema.py` |
| Схема моделей = схема ревизии (имена таблиц, колонок, ограничений, индексов) | сравнение офлайн SQL и `Base.metadata`; на живой базе — `information_schema`/`pg_constraint`/`pg_indexes` | `tests/contract/test_identity_schema.py`, `tests/integration/test_identity_schema_db.py` |
| `REQ-identity-04` — журнал только дописывается, в том числе «не редактируется правами приложения» | `test_audit_append_only_role` + 8 проверок прав | `tests/integration/test_postgres_roles.py`, `tests/contract/test_db_roles.py` |
| `AC-identity-04` — изменённая вручную копия дампа находится | целостность цепочки `hash_prev`/`hash` | **не в этой задаче**: `make audit-verify` (T-109), см. §4 |

## 2. CI: что именно доказано

Job `migrations` (Postgres 16.4): `upgrade head → downgrade base → upgrade head`, затем два
шага на живой базе — `tests/integration/test_identity_schema_db.py` (**9 passed**) и
`tests/integration/test_postgres_roles.py` (**8 passed**). В журнале Postgres за этот прогон —
настоящие отказы прав, а не «зелёно потому что не проверилось»:

```
ERROR:  permission denied for table audit_log     (×3: UPDATE, DELETE, TRUNCATE)
ERROR:  permission denied for schema public       (CREATE TABLE под ролью приложения)
```

Отдельно зафиксировано, что `alembic check` приёмкой схемы **не** является: сравнение
`server_default` у Alembic эвристическое и даёт фантомные различия на приводимых значениях
(`'invited'::text` против `'invited'::character varying`). Точность даёт сравнение каталога живой
базы с моделями.

Локальные гейты среза: `ruff format --check` (64 файла), `ruff check`, `mypy --strict`
(66 файлов, без ошибок), `pytest -m "not live_api and not e2e"` → **410 passed / 24 skipped**
(24 — живые проверки, которым нужна база), покрытие **95.74 %**, подавлений **14** (порог).

## 3. Площадка: фактическое применение

### 3.1 Клон и соответствие набору

```
sudo git -C /opt/tbot -c core.sshCommand="ssh -o IdentitiesOnly=yes -i /root/.ssh/tbot_deploy_key" pull --ff-only
HEAD: df03e89 chore(deploy,T-009): дайджесты образов пересняты — 3ac5849, run Image 44800434749
git diff --name-only 3ac5849..HEAD → deploy/tbot.prod.env
```

Хеш клона (`df03e89`) не совпадает с коммитом, из которого собраны образы (`3ac5849`), — это
разрешённое runbook §2 исключение: различие затрагивает только `deploy/tbot.prod.env`, ни одного
пути из `apps/`, `packages/`, `deploy/Dockerfile`, `pyproject.toml`, `deploy/compose*.yaml`.
Дерево чистое. `secrets-setup.sh --check`: пять `OK` и код 0 (`db_password` 48, `db_url` 93,
`ghcr_token` 40, `telegram_token` 46, `telegram_socks_pass` 24 байт; смонтированные — `640 root:tbot`).

Место на диске перед pull: 63 ГиБ свободных (требование §14.6/ADR-002 — не меньше 15 ГиБ, два
набора образов нужны одновременно).

### 3.2 Pull по digest

`sudo sh -c "docker login ghcr.io --username rusiksoft-afk --password-stdin < /etc/tbot/secrets/ghcr_token"`
→ `Login Succeeded`. Грабля: перенаправление `< /etc/tbot/secrets/ghcr_token` обязано выполняться
внутри `sudo sh -c` — под `rusiksoft` файл `600 root:root` не читается, и первая попытка дала
`Permission denied` ещё до обращения к реестру.

```
$COMPOSE config | grep image:            → все четыре образа приложения с digest из env-файла
$COMPOSE pull                            → web, engine, jobs, tgbot: Pulled
```

Совпадение закреплённого и привезённого (то, что и требовалось доказать):

| Образ | Digest из `deploy/tbot.prod.env` | Привезённый digest |
| --- | --- | --- |
| `tbot-web` | `844e21f511af59…` | `844e21f511af59…` |
| `tbot-engine` | `6fd462bc7dd4aa…` | `6fd462bc7dd4aa…` |
| `tbot-jobs` | `dc1af6ee1ea925…` | `dc1af6ee1ea925…` |
| `tbot-tgbot` | `710ca9020df87d…` | `710ca9020df87d…` |

Прежний набор (`95d6a2a1`, `6f65253d`, `cf4f08b9`, `b2bc564d` из commit `d35f957`) на площадке
сохранён — это цель отката по ADR-002; `docker system prune` не выполнялся.

### 3.3 Миграция

```
$COMPOSE run --rm migrate
INFO  [alembic.runtime.migration] Running upgrade 0001 -> 0002, Идентичность и доступ: таблицы §4.1 техзадания (T-009, веха M1).
alembic_version.version_num = 0002
```

Состояние базы после (`psql -U tbot -d tbot`):

| Замер | Значение |
| --- | --- |
| таблиц в `public` | 10 (8 таблиц идентичности + `app_meta` + `alembic_version`) |
| расширений | `citext`, `plpgsql` |
| CHECK-ограничений в `public` | 16 |
| индексы `audit_log` | `pk_audit_log`, `ix_audit_log_at`, `ix_audit_log_actor_at`, `ix_audit_log_entity` |
| `audit_log.id` (`pg_attribute.attidentity`) | `d` — `GENERATED BY DEFAULT AS IDENTITY` (не `always`) |

### 3.4 Права роли приложения

`deploy/postgres/roles.sql` применён **дважды**, оба раза `rc=0` (идемпотентность; второй прогон
даёт единственный `NOTICE: role "tbot" has already been granted membership in role "tbot_app"`).
Файл читается внутри `sudo sh -c '… < /opt/tbot/deploy/postgres/roles.sql'` — по той же причине,
что и токен: `/opt/tbot` — `750 root:root`.

| Замер | Значение |
| --- | --- |
| `tbot_app` | `rolcanlogin=f`, `rolsuper=f`, `rolcreaterole=f`, `rolcreatedb=f`, `rolreplication=f`, `rolbypassrls=f` |
| `tbot_app` → `audit_log` | `INSERT`, `SELECT` (ничего больше) |
| `tbot_app` → `users` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` (отзыв точечный) |
| владелец `audit_log` | `tbot` (не приложение) — иначе отзыв прав не действует |
| членство | `GRANT tbot_app TO tbot` (проверка прав через `SET ROLE`, без пароля) |

### 3.5 Поведенческие пробы под ролью приложения

Одна сессия: `BEGIN; SET ROLE tbot_app; DO $pl$ … $pl$; ROLLBACK;`. Каждая попытка правки —
вложенный блок `plpgsql` с обработчиком `insufficient_privilege` (он же savepoint): без этого
откат по отказу снял бы и `SET ROLE`, и следующие попытки уходили бы под ролью владельца.

```
NOTICE:  роль внутри сессии: tbot_app
NOTICE:  INSERT audit_log: OK, id=1 (id выдан базой, прав на последовательность нет)
NOTICE:  UPDATE audit_log: отказ SQLSTATE=42501 (permission denied for table audit_log)
NOTICE:  DELETE audit_log: отказ SQLSTATE=42501
NOTICE:  TRUNCATE audit_log: отказ SQLSTATE=42501
NOTICE:  SELECT audit_log: OK, строк=1
NOTICE:  UPDATE users: разрешён (отзыв точечный, только журнал)
NOTICE:  CREATE TABLE под ролью приложения: отказ SQLSTATE=42501 (permission denied for schema public)
NOTICE:  ALTER TABLE audit_log: отказ SQLSTATE=42501
```

Транзакция свёрнута: `select count(*) from audit_log` → `0`, `tbot_probe_ddl` не существует.
Побочный эффект замера — счётчик identity израсходован (первая боевая запись журнала получит
`id = 2`); на append-only это не влияет.

Про `INSERT` без прав на последовательность: у `GENERATED … AS IDENTITY` PostgreSQL проверяет
право `INSERT` на таблицу, а не на sequence. Если бы `audit_log.id` был `serial` (default
`nextval()`), приложению пришлось бы выдавать `USAGE`/`UPDATE` на последовательность — то есть
разрешать двигать счётчик журнала. Поэтому в схеме нет `serial`, и это различие закреплено
поведенчески, а не комментарием.

### 3.6 Перекат состава и проба снаружи

```
$COMPOSE up -d web     → tbot-web-1 на ghcr.io/…/tbot-web@sha256:844e21f5…, Up (healthy)
curl https://tbot.rusiksoft.ru/readyz
{"status":"ready","app":"web","contour":"sandbox","checks":{"database":{"ok":true,"detail":"postgres доступен"}}}
http=200  healthz http=200
```

`postgres` и `caddy` не пересоздавались (digestы не менялись), том `pgdata` и том `caddy_data`
не трогались — сертификат Let's Encrypt остаётся в томе (лимит выпуска 5 на домен в неделю).

## 4. Что приёмка НЕ доказывает (остаток T-009)

1. **Приложение ходит ролью-владельцем.** В `db_url` — роль `tbot`: она владелец схемы и
   суперпользователь кластера (`POSTGRES_USER`). У владельца таблицы `REVOKE` прав не отнимает,
   поэтому append-only, выданный `roles.sql`, к работе `web` пока не относится. Замер §3.5 получен
   через `SET ROLE`, то есть доказывает модель прав, а не факт применения к процессу.
2. **Измеренное препятствие для шага переключения.** Секрет `db_url` смонтирован четырём
   сервисам — `web`, `engine`, `jobs` **и `migrate`** (`deploy/compose.yaml`, `migrate.command =
   alembic upgrade head`). Заменить `db_url` на роль приложения — значит перевести на неё и
   миграции, а под `tbot_app` `CREATE TABLE` уже отказывает (`42501 permission denied for schema
   public`, замер §3.5). Значит следующая ревизия (M1: `T-101…T-106` создают таблицы) на площадке
   упадёт. Варианты и их цена — `docs/runbook/postgres-roles.md §5.1`; выбор за заказчиком,
   потому что один из вариантов меняет перечень секретов состава и TZ §14.9.
3. **Общий пароль ролей не даёт жёсткой границы.** При выбранном общем пароле `tbot_app` и `tbot`
   приложение знает свой DSN — а значит знает и пароль роли-владельца, и может войти под ним.
   Отзыв прав остаётся политикой, а не границей. Жёсткая граница требует разных паролей и двух
   DSN-секретов (прикладного и владельца) — см. тот же §5.1.
4. **Вторая половина `AC-identity-04`** (найти изменённую вручную копию дампа по цепочке хэшей) —
   `make audit-verify`, задача T-109; в T-009 не входила.

Итог по `AC-identity-04` в границах T-009: **принято** — журнал не редактируется правами роли,
которой приложение будет работать (CI + площадка, коды `42501`); **не принято** — применение этих
прав к работающему приложению (шаг переключения, п. 1–3).

## 5. Откат

```bash
# схема (на площадке не требовался: данных нет; цикл проверен в CI)
$COMPOSE run --rm migrate alembic downgrade 0001_app_meta

# состав: прежний набор digest скачан, откат = прежние значения в deploy/tbot.prod.env (ADR-002)

# права роли (полное снятие созданного roles.sql)
sudo docker exec tbot-postgres-1 psql -U tbot -d tbot -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
REVOKE tbot_app FROM tbot;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM tbot_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM tbot_app;
DROP ROLE IF EXISTS tbot_app;
COMMIT;
SQL
```

Права файлов секретов после всех шагов не менялись: `secrets-setup.sh --check` остаётся зелёным,
`--remed` не требовался.
