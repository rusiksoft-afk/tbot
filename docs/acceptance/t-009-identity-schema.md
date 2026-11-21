# Приёмка: схема идентичности и права роли приложения (T-009)

Площадка: `153.51.172.30` (`compute-vm-2-4-74-ssd-1795094860175`, Yandex Cloud, Ubuntu 24.04.5 LTS,
`fv48ibn5ff3ff5gd0e3v`). Даты работ: 2026-11-20 и 2026-11-21 (шаг переключения роли).
Основание: TZ §4.1 (`REQ-identity-04`,
`REQ-storage-01`, `REQ-storage-02`), §8.1–§8.4; ADR-003 (деплой разрешён), ADR-005 (права
файлов секретов), ADR-002 (откат по digest). Задача — **T-009**, веха M1.

Код: ревизия `migrations/versions/0002_identity_access.py`, модели `packages/storage/`,
права `deploy/postgres/roles.sql`. Коммиты среза: `028902b` (модели + ревизия),
`03c7eca` (права роли + тесты), `df03e89` (пересъёмка digest'ов), `ae4662f` (вариант Б:
миграции ролью приложения + возврат владения журналом), `5fab972` (guard роли запуска в п. 0).
CI: прогоны `44799084782` и `44851684679` (схема — 9 проверок, права — 10, живая база
PostgreSQL 16.4), `44800434747` и `44848903053` (все 9 job'ов зелёные).

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

### 3.7 Шаг переключения: приложение ходит ролью приложения (2026-11-21 01:44–01:52 UTC)

Шаг сделан по решению заказчика (ask `8d2be9bb`: вариант Б — миграции идут ролью приложения,
пароль роли общий с `db_password`). Перед шагом снято «до»:

```
роль: tbot | superuser: True
UPDATE audit_log: РАЗРЕШЁН   DELETE audit_log: РАЗРЕШЁН   TRUNCATE audit_log: РАЗРЕШЁН
```

Замер из контейнера `web` тем же путём к базе, которым ходит процесс (`psycopg_dsn` из
секрета `db_url`). То есть до шага приложение могло править, удалять и очищать журнал —
`REQ-identity-04` на площадке не действовало физически.

Порядок шага и замеры:

| Шаг | Команда (сокращённо) | Результат |
| --- | --- | --- |
| права обновлены | `psql -f - < /opt/tbot/deploy/postgres/roles.sql` | `rc=0`; `has_schema_privilege(tbot_app,'public','create') = t`, `has_table_privilege(tbot_app,'audit_log','update') = f`, владелец журнала `tbot` |
| guard роли запуска | тот же сеанс: `SET ROLE tbot_app;` + содержимое файла | `ERROR: roles.sql обязан запускаться ролью-владельцем схемы, не приложением (п. 0 файла прав)`, `psql_rc=3`; права не изменились |
| возврат владения (моделирование следующей ревизии) | `ALTER TABLE audit_log OWNER TO tbot_app` → снова `roles.sql` | после передачи: владелец `tbot_app`, `update = t` (у владельца отзыв не работает); после файла прав: владелец `tbot`, `select = t`, `insert = t`, `update/truncate/references/trigger = f` |
| пароль и вход роли приложения | `psql` c `\set pw \`cat /run/secrets/db_password\`` → `ALTER ROLE tbot_app PASSWORD :'pw'; ALTER ROLE tbot_app LOGIN;` | `rc=0`; в `pg_authid`: `tbot_app` — `rolcanlogin = t`, `rolsuper = f`, хэш `SCRAM-SHA-…`. Значение не печатается и не попадает в argv: его читает `psql` внутри контейнера |
| DSN приложения | `TBOT_DB_USER=tbot_app secrets-setup.sh --only db_url --force` | `db_url: записано (97 байт)` (было 93); `--check` — пять `OK`, код 0; разбор DSN внутри контейнера: `user=tbot_app`, `scheme=postgresql+psycopg` |
| перезапуск | `$COMPOSE restart web` | `tbot-web-1 Up (healthy)`. Отдельный замер: `up -d web` контейнер **не пересоздаёт** (состав и путь секрета не менялись), поэтому процесс продолжал держать прежний DSN — перезапуск обязателен |
| серверное доказательство роли процесса | `ALTER SYSTEM SET log_connections = on` + `pg_reload_conf()`, затем 3 запроса через Caddy, затем `ALTER SYSTEM RESET` | `tbot_app@tbot LOG: connection authorized: user=tbot_app database=tbot` ×3 (административные `psql`-сессии в том же окне дают `user=tbot`). Настройка возвращена: `show log_connections` → `off`, `postgresql.auto.conf` чист. Поллинг `pg_stat_activity` не работает: соединение пробы живёт меньше миллисекунды (40 параллельных запросов + `\watch 0.1` — ни одного попадания) |
| права «в бою» | та же проба из контейнера `web` | `роль: tbot_app`, `superuser: False`; `UPDATE`/`DELETE`/`TRUNCATE audit_log` → `sqlstate = 42501`; `INSERT` проходит (`id = 2`), транзакт свёрнут, `count(*) = 0`. В журнале Postgres те же отказы сервером: `tbot_app@tbot ERROR: permission denied for table audit_log` ×3 |
| миграции под ролью приложения | `$COMPOSE run --rm migrate` | `rc=0`; отдельная проба образа migrate: `migrate session role: tbot_app`, `has CREATE on schema public: True`. Под способностью делать DDL — проба под `SET ROLE tbot_app`: `CREATE TABLE`/`ALTER TABLE`/`DROP TABLE` своей таблицы проходят, чужие объекты — отказ |
| состояние площадки | `sudo python3 /opt/tbot/scripts/prod_bootstrap_check.py` | `ГОТОВО: блокирующих замечаний нет` (диск 61.50 ГиБ свободно) |
| панель снаружи | `curl https://tbot.rusiksoft.ru/readyz` | `{"status":"ready", …, "checks":{"database":{"ok":true}}}`, `healthz=200`, HTTP/3 работает |

Соответствие клона и закрепленного набора после этих коммитов: клон — `5fab972`, образы — из
`3ac5849`; `git diff --name-only 3ac5849..HEAD` даёт `deploy/postgres/roles.sql`,
`deploy/tbot.prod.env`, `tests/…` и документы — ни одного пути из перечня сборки образа
(`apps/`, `packages/`, `deploy/Dockerfile`, `pyproject.toml`, `deploy/compose*.yaml`,
`migrations/`, `deploy/caddy/`, `deploy/postgres/tbot.conf`), поэтому пересъёмка digest'ов не
требовалась (правило — `docs/runbook/stand-deploy.md §2`).

## 4. Вердикт и остаток

`AC-identity-04` в границах `T-009`: **принято**.
- журнал не редактируется правами роли, которой работает приложение — отказ `42501` на
  `UPDATE`/`DELETE`/`TRUNCATE` при работающем `INSERT` (CI job `migrations`, 10 проверок;
  площадка — проба из контейнера `web` и серверные строки Postgres);
- приложение ходит НЕ владельцем журнала, владение возвращается файлом прав (замер с
  моделированием следующей ревизии);
- `REQ-storage-01` (цикл `upgrade head → downgrade base → upgrade head`) и `REQ-storage-02`
  (нет вещественных типов, время с поясом) — CI + офлайн-контракт.

Что приёмка **не** доказывает и что остаётся осознанным риском:

1. **Общий пароль ролей — по решению заказчика (ask `8d2be9bb`).** Процесс, знающий свой DSN,
   знает и пароль роли-владельца `tbot`, а `tbot` — суперпользователь кластера: отзыв прав
   остаётся политикой, а не границей. Обнаружение подделки — цепочка хэшей и `make
   audit-verify` (T-109), постфактум. Жёсткая граница потребовала бы отдельных паролей и двух
   DSN-секретов (вариант А); таблица рисков и компенсирующих контролей варианта Б —
   `docs/runbook/postgres-roles.md §5.1`.
2. **Владение новыми таблицами — у роли приложения.** Таблицы, которые создадут ревизии M1,
   будут принадлежать `tbot_app`; append-only держится только для таблиц реестра
   `APPEND_ONLY_TABLES`, владение которыми возвращает `roles.sql`. Правило для каждой новой
   таблицы журнала — имя в реестр + `ALTER TABLE … OWNER TO CURRENT_USER` + `REVOKE`
   (сверяет контрактный тест `tests/contract/test_db_roles.py`, 11 проверок).
3. **`AC-identity-04` вторая половина** — найти изменённую вручную копию дампа по цепочке
   хэшей: `make audit-verify`, задача `T-109`. В `T-009` не входила (см. и `tasks/todo.md`).
4. **`engine`, `jobs` и `tgbot` на площадке не запущены** (контур `sandbox`, торговля
   отключена): их соединения под `tbot_app` будут проверены тем же способом при включении
   контуров `paper`/`production`.

Откат шага переключения — `docs/runbook/postgres-roles.md §6` (`ALTER ROLE tbot_app NOLOGIN` +
пересборка `db_url` с пользователем по умолчанию + `restart`); данные не затрагиваются.

## 5. Откат

```bash
# схема (на площадке не требовался: данных нет; цикл проверен в CI)
$COMPOSE run --rm migrate alembic downgrade 0001_app_meta

# состав: прежний набор digest скачан, откат = прежние значения в deploy/tbot.prod.env (ADR-002)

# права роли (полное снятие созданного roles.sql) — без stdin: `docker exec -i` внутри
# `bash -s <<HEREDOC` забирает остаток скрипта (грабля, runbook `postgres-roles §5`)
sudo docker exec tbot-postgres-1 psql -U tbot -d tbot -v ON_ERROR_STOP=1   -c 'BEGIN' -c 'REVOKE tbot_app FROM tbot'   -c 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM tbot_app'   -c 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM tbot_app'   -c 'DROP ROLE IF EXISTS tbot_app' -c 'COMMIT'

# шаг переключения, если он сделан — docs/runbook/postgres-roles.md §6:
# ALTER ROLE tbot_app NOLOGIN + пересборка db_url под tbot + restart сервиса (не up -d)
```

Права файлов секретов после всех шагов не менялись: `secrets-setup.sh --check` остаётся зелёным,
`--remed` не требовался.
