# Приёмка: деплой головы после `T-109 R4b` на `153.51.172.30` (ревизия `0007`, живой журнал `audit_log`)

Дата: 2026-11-24. Принималось: деплой головы репозитория срезов `T-109` `R2`…`R4b` на живую ВМ
`153.51.172.30` (`tbot.rusiksoft.ru`) — пересъёмка дайджестов парой «прогон → коммит», применение
ревизии Alembic `0007`, повторный идемпотентный прогон `deploy/postgres/roles.sql` ролью-владельцем,
перекат `web` на новый набор образов, приёмка наружного контура и **первая на площадке проверка
того, что журнал `audit_log` пишется и цепочка хэшей читается**.

Основание для работ на площадке — `ADR-001` (живая ВМ вместо тестовой), `ADR-003` (деплой
разрешён, Docker через `sudo docker`, SG = 22/80/443 tcp + 443 udp), `ADR-005` (права файлов
секретов), `ADR-018` (роль миграций — владелец схемы; порядок «миграции → `roles.sql` → приложение»),
`ADR-022` (слот `0007`), `ADR-025` (цепочка хэшей и коды возврата разбора), `ADR-026`
(`integrity-check` в `jobs`; на площадке `jobs` не поднят). Отдельные решения заказчика:
выбор следующего среза — `deploy_0007` (ask `67d34811-008d-46e7-9729-899e365ad462`),
**дамп базы перед миграцией не снимается** — `no_dump` (ask
`0797afbe-c666-418c-87e2-40c76d528577`).

Замеры — командами из `docs/runbook/stand-deploy.md` (§1–§7, §13), `docs/runbook/ghcr-pull.md §2`,
`docs/runbook/postgres-roles.md`, `docs/runbook/kek-keys.md`, `docs/runbook/audit-chain-check.md`.
Значения секретов не выводились: только имена, размеры и права через `--check`.

## 1. Что входило в срез и что в него не входило

В runtime-слой этого деплоя попали срезы `T-109`: `R2`/`R2b` (протокол добавления записи журнала
с блокировкой хвоста цепи, имена событий §8.7 в слое входа и у мутаций маршрутов), `R3.1`
(`scripts/audit_verify.py` + `make audit-verify`), `R3.2` (задача `integrity-check` в реестре `jobs`,
`ADR-026`), `R4a` (производитель `account.role_changed`), `R4b` (производитель `totp.revoked` —
сброс второго фактора администратором, `ADR-027`).

Схема: одна ревизия `0007` — частичный уникальный индекс `ix_audit_log_hash_prev_linked`
(страж развилки цепи хэшей). **Новых таблиц `0007` не создаёт**: `audit_log` стоит с `0002`,
поэтому шаг «имя в `APPEND_ONLY_TABLES` + `ALTER TABLE … OWNER TO` + `REVOKE`» этой ревизии
не требовался (`AGENTS.md`, признак — отсутствие `op.create_table` в `upgrade()`), но идемпотентный
прогон `roles.sql` ролью `tbot` выполнен как часть порядка «миграции → `roles.sql` → приложение».

В срез **не** входило: поднятие `jobs`, `tgbot`, `engine` (`T-714`), транспорт уведомлений
`web_audit_outbox` и ревизия `0006` (`T-116`), бэкапы и WAL-архив (`T-702`), плановой
планировщик на ВМ для ручного разбора (`ADR-003`: агент cron не заводит).

## 2. Пара «прогон → коммит» и дайджесты

| Что | Значение |
|---|---|
| голова, из которой собраны образы | `aa24f6a` (docs-срез с итогом `R4a`/`R4b`) |
| прогон `CI` по этой голове | `45339984694` — 9 job'ов, успех |
| прогон `Image` по этой голове | `45339984849` — успех, 4 образа |
| коммит дайджестов | `69dae6d` (`build(deploy): дайджесты образов пересняты с aa24f6a …`) |
| прогон `CI` по коммиту дайджестов | `45346217357` — успех (гейт §1 п. 6) |
| прогон `Image` по коммиту дайджестов | `45346217387` — успех, **не деплоится** (следующий пуш порождает свой набор) |

Дайджесты из `45339984849`, записанные в `deploy/tbot.prod.env`:

```text
web    sha256:51e762475a0a2ae76680d48215789a74c714f7c2774d5ebb48578b8b13d02941
tgbot  sha256:02b837eccbf70da151bb0da59747a10c099ae3225a1e9782a89dfb0363a445c8
engine sha256:807899b08bfb5daf9c9f8e71768134eeb0730545a5b5a1db064f492a9708a193
jobs   sha256:d7dba51a0939a182cb81a6a3dd70639f5f491747391ea0dc9decae2e35a8969e
```

`postgres:16.4` (`sha256:e62fbf9d…334b412`) и `caddy:2` (`sha256:4851e54a…84a75b`) этим срезом
не переснимались и не пересоздавались.

Клон площадки: `bf6f557 → 69dae6d` (fast-forward, деплой-ключ
`/root/.ssh/tbot_deploy_key_20261122`, `GIT_SSH_COMMAND` с `-o IdentitiesOnly=yes`).
Прослеживаемость соблюдена:

```text
$ sudo git -C /opt/tbot diff --name-only aa24f6a..HEAD
deploy/tbot.prod.env
```

Разбор состава на этой машине зелёный: `docker compose … config --quiet` → `rc=0`
(compose на площадке `2.40.3`).

Коммит `db6da9f` (`docs(README)`) на площадку **не поднимался**: он новее коммита дайджестов,
и перенос клона на него нарушил бы пару «прогон → коммит» (в диффе появился бы `README.md`).
Клон остаётся на `69dae6d` до следующего деплой-среза.

## 3. Готовность по гейтам `stand-deploy §1`

| Гейт | Замер | Вердикт |
|---|---|---|
| п. 1–2 площадка и периметр | `sudo ufw status numbered` — 8 правил: `22/tcp`, `80/tcp`, `443/tcp`, `443/udp` (+ v6), deny incoming | зелёный, изменений не было |
| п. 3 секреты | `sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --check` | `OK` по 5 файлам: `db_password` 48 Б `640 root:tbot`, `db_url` 97 Б `640 root:tbot`, `ghcr_token` 40 Б `600 root:root`, `telegram_token` 46 Б `640 root:tbot`, `telegram_socks_pass` 24 Б `640 root:tbot` |
| п. 3.1 файл ключей | `sudo python3 /opt/tbot/deploy/vps/keys_setup.py --check` | `OK`: `kek.json` 158 Б, `640`, `0:10001`, версия ключа 1, активная 1, длина 32 Б |
| п. 4 дайджесты | §2 этой приёмки | зелёный |
| п. 5 разбор состава | `config --quiet` | `rc=0` |
| п. 6 CI | `45346217357` | успех |
| свободное место | `df -h /var/lib/docker` | `59G` свободных из `72G` (порог §4 — не меньше 15 ГиБ на два набора) |
| память | `free -m` | `total 3914`, `available 3135` |

Права секретов править не пришлось (`--remed` не запускался): `--check` был зелёный.

## 4. Вход в реестр и pull по digest

```bash
sudo sh -c "docker login ghcr.io --username rusiksoft-afk --password-stdin < /etc/tbot/secrets/ghcr_token"
```

`Login Succeeded`. Значение не поднималось в argv (`ADR-004`, `runbook secrets-on-host`).
`$COMPOSE pull` (все сервисы): `postgres`, `caddy`, `web`, `jobs`, `tgbot`, `engine` — `Pulled`.

Сверка приехавших дайджестов с пинами — совпадение по всем четырём образам (выборка
`docker images --digests`, см. §2). Прежний набор целиком остался на диске:

```text
ghcr.io/rusiksoft-afk/tbot-web sha256:db65a46b6164136320395c74158641239407f04d581ee973eca5fc033a155f67
ghcr.io/rusiksoft-afk/tbot-web sha256:5cae2cbd3e9b6cae1cd14871c33a35cc9fbd53f0e6667e9e92933e4f8210ac74
```

`docker system prune` и удаление старых образов не выполнялись (`AGENTS.md`, `ADR-002`).
Диск после pull: `58G` свободных.

## 5. Состояние схемы до миграции

```text
alembic_version                     = 0004
audit_log, count(*)                 = 0
индексы audit_log                   = ix_audit_log_actor_at, ix_audit_log_at,
                                      ix_audit_log_entity, pk_audit_log        (4)
has_schema_privilege(tbot_app,
   public, create|usage)            = f | t
состояние users                     = admin|active, operator|archived, viewer|archived
sessions, count(*)                  = 17
```

Замер владения (роль-владелец `tbot`, запрос по `pg_class`/`pg_roles`, а не по `pg_tables` —
у `pg_tables` нет колонки `table_name`): до миграции и после неё все 11 таблиц схемы `public`
принадлежат роли `tbot` (`alembic_version`, `app_meta`, `audit_log`, `backup_codes`,
`invitations`, `ip_allowlist`, `rate_buckets`, `sessions`, `totp_enrollments`, `totp_failures`,
`users`).

## 6. Миграция `0004 → 0007`

Шаг исполнен сервисом `migrate` профиля `tools` (`compose config` показывает
`TBOT_MIGRATION_DB_USER: tbot`, секрет `db_url`, `read_only`, `cap_drop ALL`,
`depends_on: postgres: service_healthy`) на новом образе `web@sha256:51e76247…`:

```text
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade 0004 -> 0007, Индекс «у записи журнала
      не может быть двух следующих»: `ix_audit_log_hash_prev_linked` (T-109, срез `R1`).
migrate rc=0
```

После: `alembic_version = 0007`, голова одна.

Дамп перед миграцией **не снимался** — решение заказчика `no_dump` (ask `0797afbe…`). Это
осознанный компромисс, а не недоделка: `upgrade()` `0007` содержит только
`op.create_index(... unique=True, postgresql_where="hash_prev IS NOT NULL")`, данных шаг не
касается (`audit_log` была пуста), а `downgrade()` идемпотентно исполняет
`op.drop_index("ix_audit_log_hash_prev_linked")` — то есть откат схемы существует и не требует
восстановления дампа. Откат приложения — прежнему набору digest (§10).

## 7. `roles.sql` ролью-владельцем и права журнала

Идемпотентный повторный прогон ролью `tbot` (запускать файл ролью приложения запрещено — в файле
стоит guard):

```bash
sudo sh -c 'docker exec -i tbot-postgres-1 psql -U tbot -d tbot -v ON_ERROR_STOP=1 -q -f - < /opt/tbot/deploy/postgres/roles.sql'
```

```text
psql:<stdin>:106: NOTICE:  role "tbot" has already been granted membership in role "tbot_app" by role "tbot"
roles.sql rc=0
```

Единственный вывод — `NOTICE` про уже выданное членство, ошибок нет.

Страж развилки после миграции (`pg_indexes.indexdef`):

```sql
CREATE UNIQUE INDEX ix_audit_log_hash_prev_linked ON public.audit_log
  USING btree (hash_prev) WHERE (hash_prev IS NOT NULL)
```

Права приложения к журналу (замер после `roles.sql`):

```text
has_table_privilege(tbot_app, audit_log, select|insert|update|delete|truncate) = t | t | f | f | f
has_schema_privilege(tbot_app, public, create|usage)                           = f | t
audit_log, count(*)                                                            = 0
```

То есть `web` умеет только читать и добавлять; правка, удаление и обрезание журнала приложению
закрыты (`ADR-018`, `ADR-025`).

## 8. Перекат приложения

```text
$COMPOSE up -d web                                  # caddy и postgres не трогались
Container tbot-postgres-1  Waiting / Healthy
Container tbot-web-1  Started                        (up rc=0)

tbot-web-1   ghcr.io/rusiksoft-afk/tbot-web@sha256:51e76247…   Up (healthy)
inspect      running, health=healthy, restarts=0
журнал       Uvicorn running on http://0.0.0.0:8080, «Application startup complete.», ошибок нет
tbot-caddy-1   Up 3 days (healthy)     tbot-postgres-1  Up 3 days (healthy)
```

Контур подтверждён самим приложением: `GET https://tbot.rusiksoft.ru/` →

```json
{"app":"web","build":{"version":"0.0.0","revision":"unknown","build_time":"unknown"},
 "contour":"sandbox","note":"веб-консоль будет добавлена на вехе M1"}
```

`contour: sandbox` — торговля этим составом не ведётся (`runbook stand-deploy §5`).

## 9. Первое на площадке: журнал пишется, цепочка читается

До этого деплоя `audit_log` на площадке была пуста: образ `db65a46b` (сборка из `adec480`)
предшествовал срезам `R2`/`R2b`, поэтому событий «кто и когда» не писал вовсе.

Проба, которая ничего не меняет в данных и не трогает счётчики неудач: `POST /login`
с чужим `Origin` (двукратно) — отказ CSRF (§8.8: ответ не должен быть оракулом состояния):

```text
http=403  {"status":"forbidden","detail":"запрос отклонён"}     (×2)
```

Состояние журнала после проб (роль-владелец `tbot`):

```text
action             | actor_null | entity  | eid_null | reason                    | hash16           | prev16
auth.csrf_rejected | t          | request | f        | Origin='https://example.com' | 4afd458e5757b76b |
auth.csrf_rejected | t          | request | f        | Origin='https://example.com' | 0e7e7c25381c07cf | 4afd458e5757b76b

(hash первой) = (hash_prev второй) = t          записей без hash_prev (генезис) = 1
```

Субъект у строк пустой намеренно: аутентифицированного субъекта у отказа CSRF до входа нет
(`ADR-025` п. 2 — «выдуманный `actor` журнал не терпит»). Звено цепи подтверждено: `hash_prev`
второй записи равен `hash` первой, генезис ровно один.

Ручной прогон разбора из клона площадки (`runbook stand-deploy §13`, `scripts/` в образ не входят —
каталог монтируется read-only, адрес базы и роль приложения берёт состав):

```text
выборка: весь журнал (хронология по id)
строк: 2, с 3 по 4
вердикт: цепочка цела; код 0
rc=0
```

`id` 3–4 при двух строках — не повреждение: `id` — идентификатор вставки, а не счётчик записей
(`identity`), разрывы остаются от откаченных транзакций (пробы с пустой формой дают `400` и
откат, «отказа без события и события без отказа» — `ADR-025` п. 2). Разбор идёт по хронологии
вставок и связывает строки по хэшу, а не по `id`, поэтому разрывы корректны (код `0`).

Строк `integrity.audit_chain` нет — их создаёт только задача процесса `jobs`, который на площадке
не поднят (`T-714`); ручной прогон журнал не дописывает намеренно.

## 10. Приёмка наружного контура (с dev-машины)

| Проба | Результат |
|---|---|
| `GET /` | `200`, JSON-заглушка каркаса (`contour: sandbox`, веха M1) |
| `GET /login`, `GET /session-expired` | `200`, страница с формой |
| `GET /metrics` | `404` (метрики — приватный порт процесса, наружу не публикуются) |
| `GET /readyz` | `200` — публичная проба готовности, принятая конфигурация периметра (`runbook postgres-roles`, `stand-deploy §6`); содержимое — статус и исправность базы, без сведений о данных |
| `GET /admin/users` без сеанса | `302 → https://tbot.rusiksoft.ru/login` |
| `POST /admin/users/<uuid>/role` без сеанса | `403` (слой допуска, отказ без деталей состояния) |
| `GET /robots.txt` | `404` |
| `http://…/` | `308 → https://tbot.rusiksoft.ru/` (не `301` — метод и тело сохраняются) |
| заголовки `https`-ответа | `strict-transport-security: max-age=63072000; includeSubDomains`, CSP из TZ §8.3, `x-content-type-options: nosniff`, `x-frame-options: DENY`, `referrer-policy: same-origin`, `permissions-policy`, `cache-control: no-store`; заголовка `Server` нет |
| `HEAD /healthz`, `HEAD /login` | `405` с `Allow: GET` — метод закрыт, сам контур отвечает |
| TLS 1.2 | handshake успешен, `Verify return code: 0 (ok)` |
| TLS 1.1 | отказ handshake (`SSL routines:tls_setup_handshake:no protocols available`) |
| сертификат | издатель `Let's Encrypt` (`CN=YE1`), `CN=tbot.rusiksoft.ru`, SAN ровно `DNS:tbot.rusiksoft.ru`, `notBefore=2026-11-20`, `notAfter=2027-02-18` |
| HTTP/3 | проба QUIC Initial с заведомо неизвестной версией: `quic_reply= 35 VN= True` (Version Negotiation) |
| слушатели на ВМ | `80/tcp`, `443/tcp`, `443/udp` (v4 и v6) — только `docker-proxy` |
| маскировка PII/токенов в журнале прокси | проба `GET /login?token=PR0BE-FIKT-9182&sig=PR0BE-SIG-9182` + заголовок `X-Api-Key: PR0BE-KEY-9182`: подстрока `PR0BE` в журнале `tbot-caddy-1` — `0` совпадений, в строке запроса — `token=REDACTED` (TZ §8.4) |

Сертификат и том `caddy_data` не трогались: выпуск не повторялся (лимит Let's Encrypt).

## 11. Что на этой приёмке сознательно не проверялось

1. **Задача `integrity-check` не запускалась** — процесс `jobs` на площадке не поднят (`T-714`).
   Проверка цепочки на площадке в этом срезе ручная (§9); после подъёма `jobs` нужно мерять и
   readiness исполнителя, и наличие строк `integrity.audit_chain` за сутки
   (`runbook audit-chain-check`).
2. **Транспорт уведомлений не проверялся** — `web_audit_outbox` не реализован (`T-116`, слот `0006`).
3. **Живого входа пользователя не выполнялось**: пароли учётных записей знает только заказчик
   (`ADR-004`), перебор паролей под чужим логином создали бы окно блокировки адреса (§8.2 — 3
   неудачи в окне 300 с). Для доказательства записи журнала выбран отказ CSRF: он пишет событие
   и не двигает счётчики неудач.
4. **Страж развилки пробой «в вторую точку» не проверялся**: вставлять дублирующий `hash_prev`
   в боевую таблицю нельзя (запись append-only, а неудачная вставка оставила бы разрыв `id` и
   требует правки данных). Проверка индекса — декларативная (`indexdef`, §7) и поведенческая —
   в CI (живые проверки `tests/integration/test_audit_*_db.py`).
5. **Устойчивость к перезапуску Docker и `reboot` ВМ не проверялись** (учения TZ §13.5 —
   отдельное согласование).
6. **Бэкапы и WAL-архив не включались** (`T-702`), контур не поднимался в `paper`/`production`.

## 12. Откат: цель и её сохранность

Приложение: прежний набор digest из commit `adec480` (прогон `45108352586`, значения закоммичены
`bf6f557`) — `web sha256:db65a46b…155f67` **на диске**, образ не удалялся; откат — вернуть
`deploy/tbot.prod.env` на значения из `bf6f557` и `$COMPOSE up -d web`. Порядок отката — обратный
установке: приложение, затем (если потребуется) `alembic downgrade 0004`.

Схема: `0007` обратима (`downgrade()` — `drop_index`), данных шаг не касался; при откате схемы
страж развилки исчезает, журнал остаётся append-only по правам.

Дампа, на который можно откатиться, намеренно нет — решение заказчика `no_dump`
(ask `0797afbe…`); цель отката по данным — сами данные (шаг `0007` их не меняет) плюс прежние
образы. `T-702` (бэкапы и WAL-архив) остаётся неоткрытым и блокирует переход в боевой контур.

Цель отката более раннего ряда (`5cae2cbd…`) на диске тоже есть, но непригодна как цель: наборы до
`d35f957` дают негодную форму DSN (`runbook stand-deploy §7`).

## 13. Отклонения и замечания

1. **`cd /opt/tbot` под `rusiksoft` запрещён** (`750 root:root`): команды площадки исполняются
   через `sudo` с абсолютными путями, `COMPOSE` задаётся как
   `sudo docker compose --env-file /opt/tbot/deploy/tbot.prod.env -f /opt/tbot/deploy/compose.yaml
   -f /opt/tbot/deploy/compose.prod.yaml`. Проектный каталог compose берёт из каталога первого
   `-f`, поэтому разбор идентичен варианту с `cd /opt/tbot` (подтверждено `config --quiet`).
2. **`curl -sSI` — это `HEAD`**, а не «GET без тела»: на этом контуре `HEAD` даёт `405`
   с `Allow: GET`. Не является признаком отказа контура; GET-пробы — отдельной строкой.
3. **Проба `https://127.0.0.1/...` внутри ВМ не попадает в site-блок Caddy** (нет SNI/Host
   домена) и даёт пустое тело/`405`: наружный контур меряется только по настоящему имени с dev-машины
   либо с явным заголовком `Host`.
4. **`pg_constraint` не содержит имён индексов**: `-Atc "select conname is null from pg_constraint
   where conname = 'ix_audit_log_hash_prev_linked'"` возвращает пустой набор, а не `t`.
   Индекс меряется по `pg_indexes.indexdef`.
5. **`pg_tables` не имеет колонки `table_name`** — только `tablename`; владение меряется по
   `pg_class`/`pg_roles` (запрос в §5).
6. **Порт healthcheck'а `web` — `8080`**, а не `9101` (`9103` — у `jobs`): проба
   `http://127.0.0.1:9101/readyz` из контейнера даёт `Connection refused` и ничего не говорит о
   готовности; штатная проба — `http://127.0.0.1:8080/readyz` (healthcheck compose).
7. **Пустой журнал до миграции — не поломка**: событий не писал образ, собранный до `R2`.
   Признак исправности — первая же строка с корректной связью `hash`/`hash_prev` и разбор с кодом `0`.
8. **`docker login` требует `sudo sh -c`** из-за прав файла `ghcr_token` (`600 root:root`) —
   поведение площадки, а не дефект набора.

## 14. Как повторить

```bash
# dev-машина
ssh -i ~/.ssh/tbot/ssh-key-1795095923419 -o IdentitiesOnly=yes rusiksoft@153.51.172.30
gh run list --repo rusiksoft-afk/tbot --branch main --limit 4
gh run view 45339984849 --repo rusiksoft-afk/tbot --log | grep -oE \
  "pushing manifest for ghcr\.io/rusiksoft-afk/tbot-[a-z]+:main@sha256:[0-9a-f]{64}" | sort -u

# площадка (COMPOSE — абсолютные пути, всё под sudo)
COMPOSE="sudo docker compose --env-file /opt/tbot/deploy/tbot.prod.env -f /opt/tbot/deploy/compose.yaml -f /opt/tbot/deploy/compose.prod.yaml"
sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --check
sudo python3 /opt/tbot/deploy/vps/keys_setup.py --check
sudo git -C /opt/tbot -c core.sshCommand="ssh -o IdentitiesOnly=yes -o BatchMode=yes -i /root/.ssh/tbot_deploy_key_20261122" fetch origin main
sudo git -C /opt/tbot merge --ff-only origin/main
sudo git -C /opt/tbot diff --name-only <коммит-сборки>..HEAD        # обязан быть только deploy/tbot.prod.env
$COMPOSE config --quiet
sudo sh -c "docker login ghcr.io --username rusiksoft-afk --password-stdin < /etc/tbot/secrets/ghcr_token"
$COMPOSE pull
sudo docker exec tbot-postgres-1 psql -U tbot -d tbot -Atc "select version_num from alembic_version"
$COMPOSE run --rm migrate                                            # без конвейера: иначе $? читается от tail
sudo sh -c 'docker exec -i tbot-postgres-1 psql -U tbot -d tbot -v ON_ERROR_STOP=1 -q -f - < /opt/tbot/deploy/postgres/roles.sql'
$COMPOSE up -d web
$COMPOSE ps
$COMPOSE run --rm -v /opt/tbot/scripts:/srv/tbot/scripts:ro web python3 scripts/audit_verify.py   # код 0 — находок нет
```

## 15. Вердикт

Деплой головы после `T-109 R2…R4b` на `153.51.172.30` **состоялся и принят**: клон на `69dae6d`,
образы — дайджесты прогона `45339984849` (сборка из `aa24f6a`, CI по обеим головам зелёные),
схема `0004 → 0007` (страж развилки `ix_audit_log_hash_prev_linked` создан, голова одна),
`roles.sql` повторён ролью-владельцем (`rc=0`, владение — `tbot`, у приложения на `audit_log`
только `SELECT`+`INSERT`, `CREATE` на схему отозвано), `web` перекатан на
`sha256:51e76247…` в `Up (healthy)`, `postgres` и `caddy` не пересоздавались, сертификат и том
`caddy_data` не трогались.

Главный результат среза — **журнал `audit_log` на площадке живой и читаемый**: две строки
`auth.csrf_rejected` с пустым субъектом, звено `hash_prev` совпало с `hash` предыдущей записи,
генезис один, ручной разбор цепочки — «цепочка цела; код 0». Прежнее состояние журнала (0 строк)
объясняется тем, что прежний образ был собран до срезов `R2`/`R2b`, а не поломкой записи.

Наружный контур принят без изменений: TLS/HSTS/HTTP/3, маскировка токенов в журнале прокси,
закрытые методы и непубличные метрики, отказ неаутентифицированному — редирект. Прежний набор
образов (`db65a46b…`) сохранён на диске как цель отката; дамп перед миграцией не снимался по
решению заказчика `no_dump`, откат схемы возможен `alembic downgrade 0004`.

Остаток, ограничивающий этот контур: `jobs`/`tgbot`/`engine` на площадке не подняты (`T-714`),
транспорт уведомлений и ревизия `0006` не реализованы (`T-116`), бэкапы и WAL-архив не закрыты
(`T-702`), планировщика для ручного разбора цепочки на ВМ нет (`ADR-003` — заводит только
заказчик).
