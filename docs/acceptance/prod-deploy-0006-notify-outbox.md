# Приёмка: деплой головы `T-116 R1` на `153.51.172.30` (ревизия `0006`, журнал решений порога `web_audit_outbox`)

Дата: 2026-11-24 (работы 20:05–20:13 UTC). Принималось: деплой головы репозитория среза `R1`
задачи `T-116` на живую ВМ `153.51.172.30` (`tbot.rusiksoft.ru`) — пересъёмка дайджестов парой
«прогон → коммит», **применение ревизии Alembic `0006` способом, отличным от штатного прогона
миграций** (кандидат `А`), повторный идемпотентный прогон `deploy/postgres/roles.sql`
ролью-владельцем, перекат `web` и `jobs` на новый набор образов, приёмка наружного контура
и свёртка разбора цепочки журнала.

Основания для работ на площадке — `ADR-001` (живая ВМ вместо тестовой), `ADR-003` (деплой
разрешён, Docker через `sudo docker`, SG = 22/80/443 tcp + 443 udp), `ADR-005` (права файлов
секретов), `ADR-018` (роль миграций — владелец схемы; порядок «миграции → `roles.sql` →
приложение»), `ADR-022` (слот `0006` и гейт состава ревизий), `ADR-025` (цепочка хэшей журнала и
её страж), `ADR-028` (носитель решения порога, append-only права `web_audit_outbox`).

Отдельные решения заказчика этого среза — ask `cec16572-0e09-4a11-bd3a-d1fc23344ca8`
(2026-11-24): следующий срез — **`deploy0006`**; форма применения `0006` — **кандидат `А`**
из `docs/acceptance/t-116-notify-outbox.md §7.3`; форма третьего признака §8.7 (для будущего
среза) — **gitleaks по дампу логов за сутки** (`gitleaks`). Дамп перед `0006` не снимается —
прежнее решение того же заказчика ask
`128ac2e2-877d-45ec-8e6d-d8b63cab8f53` (`keep_no_dump`).

Замеры — командами из `docs/runbook/stand-deploy.md` (§1–§8, §13), `docs/runbook/ghcr-pull.md §2`,
`docs/runbook/postgres-roles.md`, `docs/runbook/kek-keys.md`, `docs/runbook/audit-chain-check.md`.
Значения секретов не выводились: только имена, размеры и права через `--check`
(`ADR-004`, `ADR-005`).

## 1. Что входило в срез и что в него не входило

Runtime-дифф от прежнего набора образов (`aa24f6a`) — только срез `R1` задачи `T-116`:

```text
$ sudo git -C /opt/tbot diff --name-only aa24f6a..a0732ef     # сокращённо, всего 35 файлов
apps/web/main.py  apps/web/routes/login.py  apps/web/routes/notifications.py
apps/web/routes/totp.py  apps/web/store.py  apps/web/templates/notifications.html
packages/identity/notify.py  packages/identity/audit.py  packages/storage/audit_store.py
packages/storage/base.py  packages/storage/models.py
migrations/versions/0006_audit_notify_outbox.py  migrations/versions/0007_audit_log_chain_no_fork.py
deploy/postgres/roles.sql
```

В коде `apps/jobs/**` отличий нет; образ `jobs` переснят вместе с набором (сборка не
воспроизводима по digest) и контейнер `jobs` перезапущен на новом образе — он поднят на площадке
с 2026-11-24 (§1.69) и крутит ежедневную `integrity-check` (`ADR-026`).

В срез **не** входило: канал доставки (`T-714` открыта, `tgbot` не поднят, §4.8
`notification_outbox` и §4.9 `telegram_messages_log` не заводились), право `UPDATE` на
`web_audit_outbox` (не выдавалось), третий признак §8.7 — поиск секретов в логах (`ADR-029`,
будущий срез), ретенция таблицы (`T-603@M6`), бэкапы и WAL-архив (`T-702`), `engine`/`tgbot`,
учения TZ §13.5, планировщик на ВМ (`ADR-003`: агент cron не заводит).

## 2. Пара «прогон → коммит» и дайджесты

| Что | Значение |
|---|---|
| голова, из которой собраны образы | `a0732ef` (HANDOFF §2 с итогами `R1`) |
| прогон `CI` по этой голове | `45376261134` — 9 job'ов, успех |
| прогон `Image` по этой голове | `45376261238` — успех, 4 образа, 2026-11-24 10:35:40 UTC |
| коммит дайджестов | `4f26df4` (`build(deploy): дайджесты образов пересняты с a0732ef …`) |
| прогон `CI` по коммиту дайджестов | `45477102887` — успех, 9 job'ов (гейт §1 п. 6) |
| прогон `Image` по коммиту дайджестов | `45477102554` — успех, **не деплоится** |

Дайджесты из `45376261238`, записанные в `deploy/tbot.prod.env`:

```text
web    sha256:01d18d6f4af0f6b4e09055c8d4cf4727b05689f0ac4d8f7d1c4d174d1a42b863
jobs   sha256:3aa7c78d739809eb01cc7906636a89a7b9070b5303ac409827573164b1393528
tgbot  sha256:725da6499ee64f2745668808c693e2402fc64abfc0b516fe39b4fc7b3356d1e9
engine sha256:91623635472bdd8e92efaf02e43bf182d168e3cab1a232b01f2bce833c1aea22
```

`postgres:16.4` (`sha256:e62fbf9d…334b412`) и `caddy:2` (`sha256:4851e54a…84a75b`) не
переснимались и не пересоздавались.

Клон площадки: `69dae6d → 4f26df4` (fast-forward, деплой-ключ
`/root/.ssh/tbot_deploy_key_20261122`, `-c core.sshCommand="ssh -o IdentitiesOnly=yes -i …"`).
Прослеживаемость соблюдена — образы собраны из ровно того же кода, что лежит на площадке:

```text
$ sudo git -C /opt/tbot diff --name-only a0732ef..HEAD
deploy/tbot.prod.env
```

Разбор состава на этой машине зелёный: `sudo docker compose -f deploy/compose.yaml
-f deploy/compose.prod.yaml --env-file deploy/tbot.prod.env config --quiet` → `rc=0`
(compose `2.40.3+ds1-0ubuntu1~24.04.1`).

## 3. Готовность по гейтам `stand-deploy §1` (замер до работ)

| Гейт | Замер | Вердикт |
|---|---|---|
| п. 2 `ufw` | `sudo ufw status numbered` — 8 правил: `22/tcp`, `80/tcp`, `443/tcp`, `443/udp` (+ v6), deny incoming | зелёный, изменений не было |
| п. 3 секреты | `sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --check` | `OK` по 5 файлам (`db_password` 48 Б, `db_url` 97 Б, `ghcr_token` 40 Б `600 root:root`, `telegram_token` 46 Б, `telegram_socks_pass` 24 Б; права `640 root:tbot`) — `--remed` не запускался |
| п. 3.1 файл ключей | `sudo python3 /opt/tbot/deploy/vps/keys_setup.py --check` | `OK`: `kek.json` 158 Б, `640`, `0:10001`, версия ключа 1, активная 1, длина 32 Б |
| п. 4 дайджесты | §2 этой приёмки | зелёный |
| п. 5 разбор состава | `config --quiet` | `rc=0` |
| п. 6 CI | `45477102887` | успех, 9 job'ов |
| свободное место | `df -h /var/lib/docker` | `58G` свободных из `72G` (порог §4 — не меньше 15 ГиБ на два набора) |
| память | `free -m` | `total 3914`, `available 3099` |

Состояние схемы и данных до работ (роль-владелец `tbot`):

```text
alembic_version                     = 0007 (одна строка)
таблиц схемы public                 = 11 (web_audit_outbox отсутствует: to_regclass = NULL)
индекс-страж развилки журнала       = ix_audit_log_hash_prev_linked  (создан 0007)
audit_log, count(*)                 = 4   (id 3…6)
sessions без отзыва / users / backup_codes = 17 / 3 / 30
владелец всех таблиц                = tbot (11 из 11)
права tbot_app на audit_log         = SELECT+INSERT, без UPDATE/DELETE/TRUNCATE
```

**Поправка к прежним записям.** В §1.69 и §1.70 п. 10 было записано «`audit_log` — 6 строк».
Фактически строк **4** (`id 3…6`): `6` — это `max(id)`, а не число строк; разрыв `id 1–2` остаётся
от откаченных транзакций (§1.68). На разбор цепочки это не влияет (цепочка читается по хэшам, а не
по `id`), но размер журнала в планировании операции `Б` (§7.3 приёмки `T-116`) тоже был
переоценён в два раза — для полноты: `Б` этот срез не исполнялся.

## 4. Замер ловушки: штатный прогон миграций `0006` не применяет

Шаг исполнен ДО каких-либо правок схемы, на уже приехавшем новом образе `web@sha256:01d18d6f…`
(то есть в `migrate` ревизия `0006` видна):

```text
$COMPOSE run -T --rm migrate
 Container tbot-postgres-1  Running
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
migrate rc=0

после: alembic_version = 0007, to_regclass('public.web_audit_outbox') = NULL
```

Ни одной строки `Running upgrade` — проход пустой, ровно как предсказывал замер
`alembic upgrade 0007:head --sql` → `BEGIN; COMMIT;` (§7.1 приёмки `T-116`). Следующий по порядку
шаг прав на этом состоянии обязан был упасть: в `deploy/postgres/roles.sql` стоит
`ALTER TABLE web_audit_outbox OWNER TO CURRENT_USER` без `IF EXISTS`. Именно поэтому выбрана
форма `А`.

Ловушка запуска (не площадки, а канала агента): `docker compose run` и `docker exec` без `-T`
съедают остаток heredoc-скрипта своим stdin — прогон обрывается на середине. Нужен `-T`
(или `< /dev/null`), см. `runbook stand-deploy §12`.

## 5. Применение `0006` — кандидат `А`: DDL из `--sql`, ролью-владельцем, голову не трогать

Генерация — тем же образом, что поднят на площадке (клон `4f26df4`, `migrate` с
`TBOT_MIGRATION_DB_USER: tbot`), в offline-режиме: к базе подключение не выполняется вовсе
(`migrations/env.py::run_migrations_offline` работает через `url=`, без `engine.connect()`):

```text
$ sudo docker compose … run -T --rm migrate alembic upgrade 0004:0006 --sql
INFO  [alembic.runtime.migration] Generating static SQL
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade 0004 -> 0006, Журнал решений порога
      уведомлений `web_audit_outbox` (TZ §8.7, `T-116`, `ADR-028`).
gen rc=0
-rw------- 1 root root 1900  /root/tbot-0006-forward.sql
ee69ca7f244db30623c0f015c0b3d5350f9180ce7f693daec822d91240ba6599  /root/tbot-0006-forward.sql
```

Набор операций в этом файле (полностью — `CREATE TABLE` + `COMMENT` + три индекса + одна строка
`UPDATE alembic_version`), ключевые строки:

```sql
CREATE TABLE web_audit_outbox ( id BIGINT GENERATED BY DEFAULT AS IDENTITY, at …, ground …,
  outcome …, reason …, audit_id BIGINT NOT NULL, user_id UUID, dedup_key TEXT, details JSONB,
  CONSTRAINT pk_web_audit_outbox PRIMARY KEY (id),
  CONSTRAINT fk_web_audit_outbox_audit_id_audit_log FOREIGN KEY(audit_id)
      REFERENCES audit_log (id) ON DELETE RESTRICT,
  CONSTRAINT fk_web_audit_outbox_user_id_users FOREIGN KEY(user_id) REFERENCES users (id)
      ON DELETE RESTRICT,
  CONSTRAINT ck_web_audit_outbox_ground CHECK (ground IN (…пять оснований…)),
  CONSTRAINT ck_web_audit_outbox_outcome CHECK (outcome IN ('notify','muted')),
  CONSTRAINT ck_web_audit_outbox_reason_code CHECK (reason ~ '^[a-z][a-z0-9_]{0,39}$'),
  CONSTRAINT ck_web_audit_outbox_notify_has_dedup_key CHECK (outcome <> 'notify' OR dedup_key IS NOT NULL),
  CONSTRAINT ck_web_audit_outbox_dedup_key_format CHECK (dedup_key IS NULL OR dedup_key ~ '^[a-z0-9._:-]{1,128}$')
);
CREATE UNIQUE INDEX ix_web_audit_outbox_dedup_key ON web_audit_outbox (dedup_key) WHERE dedup_key IS NOT NULL;
CREATE INDEX ix_web_audit_outbox_at ON web_audit_outbox (at);
CREATE INDEX ix_web_audit_outbox_user_ground ON web_audit_outbox (user_id, ground);
UPDATE alembic_version SET version_num='0006' WHERE alembic_version.version_num = '0004';
```

Файл целиком — один транзакт (`BEGIN; … COMMIT;`). Исполнен ролью-владельцем схемы:

```text
$ sudo sh -c 'docker exec -i tbot-postgres-1 psql -U tbot -d tbot -v ON_ERROR_STOP=1 -f - \
      < /root/tbot-0006-forward.sql'
BEGIN
CREATE TABLE
COMMENT
CREATE INDEX
CREATE INDEX
CREATE INDEX
UPDATE 0
COMMIT
apply rc=0
```

Главная строка этого замера — **`UPDATE 0`**: запечатанный в сгенерированном SQL `UPDATE`
рассчитан на переход `0004 → 0006` и на площадке с записанным `0007` не задевает ни одной строки.
Значит `alembic_version` остаётся `0007` **сама**, без ручных правок таблицы версий и без
обещаний, которых нет: alembic исходит из того, что все предки записанной ревизии применены, —
`0006` теперь из применённых. Проверка после:

```text
alembic_version                     = 0007 (одна строка)
таблиц схемы public                 = 12 (web_audit_outbox есть)
владелец web_audit_outbox           = tbot
колонок                             = 9 (id, at, ground, outcome, reason, audit_id, user_id,
                                        dedup_key, details)
индексы                             = pk_web_audit_outbox, ix_web_audit_outbox_at,
                                      ix_web_audit_outbox_dedup_key,
                                      ix_web_audit_outbox_user_ground
ограничения                         = pk + 2 FK (RESTRICT) + 5 CHECK
ix_audit_log_hash_prev_linked       = на месте всё время работы (писателей не останавливали)
```

Плюс кандидата `А` подтверждён на факте: окно без стража развилки цепочки хэшей не возникало,
`web` и `jobs` не останавливались. Минус тоже зафиксирован честно: операция вне онлайн-команд
alembic, поэтому протокол обязателен, а артефакт применённого DDL сохранён на ВМ
(`/root/tbot-0006-forward.sql`, `600 root:root`, sha256 выше).

## 6. Права: повторный идемпотентный `roles.sql` ролью-владельцем

Порядок `ADR-018` п. 4 выдержан: миграция → `roles.sql` → приложение. Ролью приложения файл
запускать нельзя (в файле guard, п. 0):

```text
$ sudo sh -c 'docker exec -i tbot-postgres-1 psql -U tbot -d tbot -v ON_ERROR_STOP=1 -q -f - \
      < /opt/tbot/deploy/postgres/roles.sql'
psql:<stdin>:125: NOTICE:  role "tbot" has already been granted membership in role "tbot_app" by role "tbot"
roles.sql rc=0
```

Единственный вывод — `NOTICE` про уже выданное членство. Замер прав после:

```text
tbot_app на web_audit_outbox (SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER)
                                  = t | t | f | f | f | f | f
tbot_app на audit_log   (SELECT,INSERT,UPDATE,DELETE,TRUNCATE)  = t | t | f | f | f
has_schema_privilege(tbot_app, public, create | usage)          = f | t
владелец web_audit_outbox                                     = tbot
таблиц схемы public, принадлежащих tbot                       = 12 из 12
```

Отдельно зафиксировано состояние **между** шагами: сразу после создания таблицы (до `roles.sql`)
права приложения на неё были `t | t | t | t | f` — их выдала выдача по умолчанию
(`ALTER DEFAULT PRIVILEGES … GRANT SELECT, INSERT, UPDATE, DELETE`, п. 5 файла прав). Отзыв
п. 4.1 возвращает нужную картину, и именно поэтому повторный запуск `roles.sql` после каждой
ревизии с новой журнальной таблицей — обязательный шаг, а не формальность.

## 7. Перекат приложения

```text
$COMPOSE up -d web jobs
 Container tbot-postgres-1  Waiting / Healthy
 Container tbot-jobs-1  Started      Container tbot-web-1  Started       (up rc=0)

tbot-web-1    ghcr.io/rusiksoft-afk/tbot-web@sha256:01d18d6f…   Up (healthy)
              created 2026-11-24T20:11:26.327Z, running, health=healthy, restarts=0
tbot-jobs-1   ghcr.io/rusiksoft-afk/tbot-jobs@sha256:3aa7c78d…  Up (healthy)
              created 2026-11-24T20:11:26.287Z, running, health=healthy, restarts=0
tbot-caddy-1    Up 4 days (healthy)      tbot-postgres-1  Up 4 days (healthy)
```

Журнал `web`: `Started server process`, `Application startup complete.`,
`Uvicorn running on http://0.0.0.0:8080` — ошибок и трейсбеков за 10 минут после переката
ноль (`grep -icE 'error|traceback|exception'` → `0`). Журнал `jobs` — ноль записей уровня
`error`/`critical`.

Первая задача `jobs` на новом образе стартовала сразу после запуска процесса
(`run_id 116970c349ed`, `2026-11-24T20:11:31.269Z`):

```text
вердикт: intact; строк 4 (id 3..6); место: 79% свободно (60670074880 из 76267479040 байт, ok);
строка журнала: 7
```

Readiness процесса показывает исполнителей: `job_executors` =
`['rate_bucket_purge', 'integrity-check']`, ожидают — `history_load@M2`, `instrument_catalog_sync@M2`,
`digest_report@M3`, `data_retention@M6`, `backup@M6`.

Старый набор образов на диске сохранён целиком (`web@sha256:51e76247…`, `jobs@sha256:d7dba51a…`),
`docker system prune` и удаление старых образов не выполнялись (`AGENTS.md`, `ADR-002`).
Диск после деплоя: `15G` занято, `57G` свободно; память: `total 3914`, `available 3088`.

## 8. Свёртка: разбор цепочки журнала и живой след `integrity-check`

Ручной прогон из клона площадки (`runbook stand-deploy §13`: `scripts/` в образ не входят,
каталог монтируется read-only, роль — приложения):

```text
выборка: весь журнал (хронология по id)
строк: 5, с 3 по 7
вердикт: цепочка цела; код 0
audit-verify rc=0
```

Строк `integrity.audit_chain` за последние сутки — 2 (прогон 07:53 UTC на прежнем образе и прогон
20:11 UTC на новом): ежедневная задача исполняется, а не имитируется (`ADR-026`).
`web_audit_outbox` на момент свёртки — **0 строк**: производителей решения порога вызывает полный
шаг входа и расход резервного кода, а нового входа после переката ещё не было (см. §10).

## 9. Приёмка наружного контура (с dev-машины, без сеанса)

| Проба | Результат |
|---|---|
| `GET /` | `200` (JSON-заглушка каркаса, `contour: sandbox`) |
| `GET /login` | `200`, страница с формой |
| `GET /healthz` | `200` |
| `GET /admin/notifications` (новый раздел) без сеанса | `302 → https://tbot.rusiksoft.ru/login` |
| `GET /admin/users` | `302 → …/login` (матрица допусков не изменилась) |
| `POST /admin/notifications` | `405` `{"detail":"Method Not Allowed"}` — форма отсутствует, раздел только читает (`ADR-008`: CSRF не нужен) |
| заголовки `https` | `Strict-Transport-Security: max-age=63072000; includeSubDomains`, CSP из TZ §8.3, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `Permissions-Policy`, `Cache-Control: no-store`; заголовка `Server` нет |
| `ufw` | 8 правил, те же, что до работ |
| сертификат, `caddy`, `postgres` | не трогались (контейнеры `Up 4 days`) |

## 10. Что этим деплоем НЕ подтверждено (отдельный перечень)

1. **Строка решения порога в натуре.** `web_audit_outbox` пуста: producers срабатывают на полном
   шаге входа (`auth_step = 'full'`) и на расходе резервного кода, а новый вход после переката
   обязан сделать оператор — значения учётной записи, 2FA и резервных кодов агент не получает и не
   вводит (`ADR-004`). Проверка после первого входа: в таблице обязана появиться ровно одна строка
   на вход (`ground = 'session.login'`, вердикт `notify` при новом сочетании или `muted` при
   известном сочетании/в окне), `audit_id` обязан ссылаться на строку журнала этого входа
   (`RESTRICT` держит), `dedup_key` обязан читаться как ключ сочетания, `details` — содержать
   `address_fp`/`device_fp`. Подтверждение отложено и отмечено в `docs/HANDOFF.md §2`; оно не
   меняет состава и не требует правок схемы.
2. **Доставка решений.** Канала нет: `T-714` открыта (правила маршрутизации на узле B
   `176.32.39.234` — в стоп-листе), `tgbot` не поднят, §4.8 `notification_outbox` и
   §4.9 `telegram_messages_log` не заводились. Право `UPDATE` на `web_audit_outbox` не выдавалось:
   «уведомление ушло» обязан доказывать транспорт своей строкой со ссылкой на
   `web_audit_outbox.id`.
3. **Третий признак §8.7** (поиск секретов в дампе логов) — не исполнен; форма выбрана
   заказчиком (`gitleaks` по дампу `docker logs --since 24h`), оформление — `ADR-029` в будущем
   срезе, слот ревизии `0008` при этом не занят (новая таблица для этого признака не нужна).
4. **Ретенция `web_audit_outbox`** — `data_retention@M6` (`T-603`) в реестре `jobs` её ещё нет;
   вырез делает служебная процедура от роли-владельца схемы (сначала решения, потом журнал:
   `RESTRICT` держит).

## 11. Откат

* Приложения — прежний набор digest (`web@sha256:51e76247…2941`, `jobs@sha256:d7dba51a…8969e`):
  значения лежат в истории git (`git log -p deploy/tbot.prod.env`, коммит `69dae6d`), откат =
  вернуть файл + `pull` + `up -d` (RTO ≤5 мин по `ADR-002`). Оба набора сейчас на диске.
* Схемы — `DROP TABLE web_audit_outbox` (таблица пуста, `0006` не правила существующие объекты).
  Эквивалент, сгенерированный тем же alembic `1.14.1` в offline-режиме
  (`alembic downgrade 0006:0004 --sql`, замер с dev-машины):

```sql
BEGIN;
DROP INDEX ix_web_audit_outbox_user_ground;
DROP INDEX ix_web_audit_outbox_at;
DROP INDEX ix_web_audit_outbox_dedup_key;
DROP TABLE web_audit_outbox;
UPDATE alembic_version SET version_num='0004' WHERE alembic_version.version_num = '0006';
COMMIT;
```

  `UPDATE` здесь тоже задевает ноль строк (записано `0007`), то есть откат не трогает голову.
  **`alembic downgrade 0004` онлайн-командой на площадке не запускать:** он снял бы и индекс
  `0007`, то есть страж развилки цепочки хэшей.
* Дамп базы не снимался и при откате не требуется (`keep_no_dump`, ask `128ac2e2…`): ревизия
  создаёт только новую таблицу и снимает её же.
* Права: `roles.sql` идемпотентен; после отката схемы его повторный прогон ролью `tbot` не
  требуется (строки п. 2.1 и 4.1 обратятся к отсутствующей таблице только если файл запустить
  до применения `0006` — этого делать не надо).

## 12. Итог: состояние площадки после деплоя

```text
клон /opt/tbot            = 4f26df4 (коммит дайджестов; a0732ef..4f26df4 — только tbot.prod.env)
alembic_version           = 0007 (не менялась; 0006 применена DDL из --sql, UPDATE 0)
таблиц схемы public       = 12 (web_audit_outbox есть, владелец tbot, прав 8: pk+2 FK+5 CHECK)
индексов web_audit_outbox = 4 (включая частичный уникальный по dedup_key)
audit_log                 = 5 строк (id 3…7), цепочка цела (код 0), страж развилки на месте
web_audit_outbox          = 0 строк; tbot_app — SELECT+INSERT (остальное отозвано)
web   = ghcr.io/rusiksoft-afk/tbot-web@sha256:01d18d6f…   Up (healthy), restarts=0
jobs  = ghcr.io/rusiksoft-afk/tbot-jobs@sha256:3aa7c78d…  Up (healthy), restarts=0
postgres@sha256:e62fbf9d…334b412 и caddy@sha256:4851e54a…84a75b — не пересоздавались, Up 4 days
цель отката на диске      = web@sha256:51e76247…, jobs@sha256:d7dba51a…
ufw                       = 8 правил (без изменений); секреты и kek.json — не трогались
диск                      = 15G занято / 57G свободно; память available 3088 МиБ
артефакт применённого DDL = /root/tbot-0006-forward.sql (600 root:root,
                            sha256 ee69ca7f244db30623c0f015c0b3d5350f9180ce7f693daec822d91240ba6599)
```
