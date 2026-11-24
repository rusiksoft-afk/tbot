# Приёмка: подъём процесса `jobs` на `153.51.172.30` (ежедневная `integrity-check` по §8.7)

Дата: 2026-11-24. Принималось: на живой ВМ `153.51.172.30` (`tbot.rusiksoft.ru`) поднят контейнер
`tbot-jobs-1` на digest из `deploy/tbot.prod.env`, и ежедневная задача `integrity-check` (TZ §8.7,
`ADR-026`) начинает исполняться процессом, а не ручным прогоном. Проверки: разбор состава, запуск,
первый прогон задач, строка `integrity.audit_chain` в журнале, готовность исполнителей, роль БД,
отсутствие новых наружных слушателей, лимиты памяти.

Основание — решение заказчика о следующем срезе: ask
`61e259c2-6619-4b21-9fa2-1b3bc8050e44` (выбран вариант «поднять `jobs` на площадке»). Основание по
регламенту: TZ §8.7 («ежедневная задача `integrity-check`: сверка цепочки хэшей аудита, проверка
свободных мест»), `ADR-026` (задача живёт в процессе `jobs`, строка о прогоне — при каждом запуске),
`docs/runbook/stand-deploy.md §13` и `docs/runbook/audit-chain-check.md §2` (что мерять после
подъёма). Задача `T-714` этим срезом **не** закрывается: она про туннельный egress через узел B
(правила маршрутизации по пользователю, `ADR-0xx-tg-egress-via-node-b.md`), узел B в этом срезе не
тронут и входит в стоп-лист.

Значения секретов не выводились: ни одного чтения файлов секретов, только разбор состава и права.

## 1. Почему `jobs` можно поднимать уже сейчас и чего он при этом не включает

`jobs` в боевом разборе читает ровно один секрет — `db_url` (`deploy/compose.yaml`, сервис `jobs`:
`secrets: [db_url]`), секретов брокера и Telegram не требует, торговый контур не включает:
`TBOT_CONTOUR` остаётся `sandbox`, `TBOT_CONFIRM_PRODUCTION=false` (`deploy/compose.prod.yaml`,
`x-prod-app`). Наружу он ничего не публикует: публикация портов в overlay есть только у `caddy`.

Ради этого и поднимали: до подъёма §8.7 был закрыт лишь частично (рукояткой `make audit-verify`,
`runbook audit-chain-check §3`), а в журнале не было ни одной строки `integrity.audit_chain` — то
есть «проверка запускалась» было неотличимо от «цепочка целая» (`ADR-026` п. 3).

## 2. Образ: дайджесты не переснимались

Контейнер поднят на digest, который уже зафиксирован в `deploy/tbot.prod.env` и уже был загружен на
площадку деплоем `0007` (`docs/acceptance/prod-deploy-0007-audit-chain.md §4`: `pull` забрал все
шесть образов):

```text
ghcr.io/rusiksoft-afk/tbot-jobs@sha256:d7dba51a0939a182cb81a6a3dd70639f5f491747391ea0dc9decae2e35a8969e
```

Сборка — прогон `Image 45339984849` из головы `aa24f6a`, пара «прогон → коммит` не менялась: клон
площадки остаётся на коммите дайджестов `69dae6d`, `git diff --name-only aa24f6a..HEAD` — только
`deploy/tbot.prod.env`. Новая пересъёмка дайджестов не требовалась и не делалась: состав площадки
меняется списком сервисов, а не наборами образов (`runbook ghcr-pull §2`).

## 3. Разбор состава перед запуском (то, что проверялось)

`$COMPOSE config jobs` (compose `2.40.3`, абсолютные `-f`, `--env-file`):

```text
image:   ghcr.io/rusiksoft-afk/tbot-jobs@sha256:d7dba51a…8969e
env:     TBOT_CONTOUR: sandbox, TBOT_CONFIRM_PRODUCTION: "false", TBOT_LOG_JSON: "true",
         TBOT_SECRETS_DIR: /run/secrets
secrets: source db_url → target /run/secrets/db_url            (единственный)
healthcheck: CMD python -m packages.common.health_probe --liveness --url http://127.0.0.1:9103/healthz
hardening:   read_only: true, security_opt no-new-privileges:true, restart: always
limits:      mem_limit 512 MiB, cpus 0.5
ports:       (нет)
```

Состояние машины до запуска: `Mem: total 3914, available 3159` МиБ; слушателей `LISTEN` — 10
(все — `docker-proxy` на 80/443 tcp+udp и внутренние).

## 4. Запуск

```text
$COMPOSE up -d jobs        # rc=0
tbot-jobs-1  Up 40 seconds (healthy)
inspect: running, health=healthy, restarts=0, oom=false
```

Остальной состав не тронут: `web` `Up (healthy)` на `51e76247…`, `postgres` и `caddy` —
`Up 3 days (healthy)` (не пересоздавались), том `pgdata` и `caddy_data` не трогались.

## 5. Первая попытка задач — сразу после старта процесса

Планировщик отмечает попытку **до** вызова исполнителя и считает первую попытку наступившей
(`apps/jobs/main.py::due_jobs`: `previous is None or moment - previous >= interval_s`), поэтому
жду сутки не нужно:

```text
{"event":"jobs_started","health_port":9103,
 "scheduled":["rate_bucket_purge","integrity-check","history_load","instrument_catalog_sync",
              "digest_report","data_retention","backup"],
 "executors":["rate_bucket_purge","integrity-check"],
 "note":"остальные исполнители подключаются по вехам M2–M6"}
{"job":"rate_bucket_purge","detail":"окон счётчика удалено: 46","event":"job_done"}
{"run_id":"6527cffb28f5","verdict":"intact","rows":3,"findings":0,"notes":0,
 "disk_free_percent":80,"disk_state":"ok","journal_row_id":6,"event":"integrity_check"}
{"job":"integrity-check","detail":"вердикт: intact; строк 3 (id 3..5); место: 80% свободно
 (61599240192 из 76267479040 байт, ok); строка журнала: 6","event":"job_done"}
```

Число `46` удалённых окон — штатная чистка протёкших окон счётчика (регламент часа и порог 24 ч,
решение заказчика ask `abb0151c`, `ADR-007`): окна накопились за три дня без процесса `jobs`.

## 6. Журнал: строка проверки лежит в цепи

Состояние `audit_log` после прогона (роль-владелец `tbot`, чтение):

```text
id | action              | actor_null | entity    | entity_id                                          | verdict | hash12        | prev12
 3 | auth.csrf_rejected  | t          | request   | /login                                             |         | 4afd458e5757  |
 4 | auth.csrf_rejected  | t          | request   | /login                                             |         | 0e7e7c25381c  | 4afd458e5757
 5 | auth.csrf_rejected  | t          | request   | /admin/users/00000000-…-000000000000/role          |         | bbdca720175f  | 0e7e7c25381c
 6 | integrity.audit_chain | t        | audit_log | (пустой)                                           | intact  | 9331fe9dcfe9  | bbdca720175f
```

Три строки `auth.csrf_rejected` — следы неаутентифицированных проб приёмки деплоя `0007`
(`entity_id` у них — путь запроса, так журнал описывает отвергнутый запрос); строка `5` появилась
от `POST` на путь смены роли без сеанса. Она же объясняет «пропавшие» `id` в предыдущем замере:
на момент разбора цепочки в журнале лежали `id 3–4`, а `id 5` вставился позже — разрывов в смысле
повреждения не было ни разу.

Содержимое `details` строки проверки (целиком, `jsonb_pretty`):

```json
{
  "rows": 3, "check": "audit_chain", "to_id": 5, "run_id": "6527cffb28f5", "from_id": 3,
  "verdict": "intact", "disk_state": "ok", "broken_link": 0, "issue_row_ids": [],
  "missing_prefix": 0, "disk_free_bytes": 61599240192, "content_mismatch": 0,
  "disk_total_bytes": 76267479040, "duplicate_parent": 0, "disk_free_percent": 80
}
```

Форма строки совпадает с контрактом `ADR-025` п. 9 и `ADR-026` п. 2: `actor IS NULL` (субъект — не
учётная запись), `entity = 'audit_log'`, `entity_id` пустой, вердикт в `details ->> 'verdict'`,
идентификатор прогона — в `details ->> 'run_id'`. Значение самопроверки: строка `6` стала звеном
цепи (`hash_prev = bbdca720175f…` — хэш предыдущей строки), то есть проверка включена в то, что
сама защищает, а не стоит рядом.

Ручная свертка из клона (`runbook audit-chain-check §3`):

```text
выборка: весь журнал (хронология по id)
строк: 4, с 3 по 6
вердикт: цепочка цела; код 0        (rc=0)
```

## 7. Границы процесса: роль, порт, память

| Граница | Замер | Вердикт |
|---|---|---|
| роль БД | `pg_stat_activity.usename` → `tbot_app` (2 соединения приложения) и `tbot` (хозяйский `psql` замера) | `jobs` ходит ролью приложения, не владельцем схемы (`ADR-006`, `ADR-018`) |
| слушатели наружу | `LISTEN` после запуска — те же 10; `ss -lntp 'sport = :9103 or sport = :8080'` — пусто | health-порт `9103` живёт внутри контейнера, наружу не публикуется |
| готовность исполнителей | `python -m packages.common.health_probe --url http://127.0.0.1:9103/readyz` → `200`, `job_executors.ok = true`, «исполнители: [rate_bucket_purge, integrity-check]», «ожидают: history_load@M2(T-201), instrument_catalog_sync@M2(T-210), digest_report@M3(T-311), data_retention@M6(T-603), backup@M6(T-601)» | обе задачи среза объявлены и имеют исполнителей; остальные честно не объявлены |
| ретенция в readiness | `retention.ok = true` — «минутные свечи 12 мес, журнал аудита 1095 сут, бэкапов 14» | настройки ретенции применены |
| метрики | `tbot_disk_free_bytes{app="jobs"} 6.1599240192e+10`, `tbot_disk_total_bytes{app="jobs"} 7.626747904e+10` | метрики §12.4 с меткой процесса, доступны только изнутри |
| память и CPU | `docker stats --no-stream` → `tbot-jobs-1 71.82MiB / 512MiB (14.03 %)`, CPU `0.01 %`; остальные контейнеры: `web 86.67MiB/320MiB`, `postgres 74.61MiB/768MiB`, `caddy 60.08MiB/128MiB` | потолок `512 MiB` выбран с запасом ×7, машина не перегружена (`OOMKilled=false`) |
| hardening | `read_only: true`, `no-new-privileges:true`, `restart: always`, tmpfs `/tmp` | тот же профиль, что у остальных прикладных процессов |

## 8. Регламент прогона после подъёма

- интервал `integrity-check` — сутки (`INTEGRITY_CHECK_INTERVAL_S = 86_400`), интервал
  `rate_bucket_purge` — час (окна старше 24 ч);
- первая попытка — сразу после старта процесса, отметка попытки ставится до вызова исполнителя:
  падающая задача не превращает регламент в цикл каждые 15 с (`HEARTBEAT_INTERVAL_S`);
- рестарт контейнера означает новый прогон и **новую** строку `integrity.audit_chain` — это
  следствие `ADR-026` п. 3 («строка о прогоне пишется при каждом запуске»), а не дубль;
- при находке ожидается уровень/событие `integrity_chain_findings` и вердикт `findings` со
  счётчиками по четырём кодам (`content_mismatch`, `broken_link`, `duplicate_parent`,
  `missing_prefix` — последние не относятся к находкам, `packages/identity/audit.py`);
- уведомлений администраторам по-прежнему нет: транспорт `web_audit_outbox` не реализован
  (`T-116`, слот Alembic `0006`), поэтому находка видна в журнале, в событии процесса и в
  метрике, но не доставляется — это остаток §8.7, а не реализованная половина.

## 9. Что этим срезом сознательно не сделано

1. **`engine` и `tgbot` не поднимались.** Торговля не включается (контуры `paper`/`production` —
   отдельное включение с `TBOT_CONFIRM_PRODUCTION`, а T-702 — бэкапы и WAL-архив — не закрыт);
   `tgbot` упирается в дефект SOCKS и правила на узле B (`T-714`, `docs/acceptance/tg-egress.md §4.1`),
   узел B — стоп-лист.
2. **`T-714` остаётся открытой**: закрыта только часть «контейнер `jobs` на площадке». Правила
   маршрутизации на узле B, фиксированный exit и ADR по egress — не тронуты.
3. **Учения TZ §13.5 не проводились**: `systemctl restart docker` и ребут ВМ не выполнялись,
   учебный откат на другой набор digest не повторялся. Подъём `jobs` проверен на
   `restart: always` (политика в `inspect`), но не на «после перезапуска машины».
4. **Планировщик на ВМ не заводился** (`ADR-003`): cron/systemd-таймер — действие заказчика.
   Штатная периодичность теперь обеспечивается процессом, ручная команда остаётся сверткой.
5. **Доставка уведомлений о находке не проверялась** — её нет (`T-116`).
6. **Расследование содержимого окон счётчика не проводилось**: `rate_bucket_purge` удалил 46
   протёкших окон — это штатная уборка, но она первый раз исполнена на площадке, и её результат
   зафиксирован ровно одной строкой лога.

## 10. Как повторить

```bash
# dev-машина
ssh -i ~/.ssh/tbot/ssh-key-1795095923419 -o IdentitiesOnly=yes rusiksoft@153.51.172.30

# площадка: COMPOSE — абсолютные пути (каталог /opt/tbot — 750 root:root, cd под rusiksoft запрещён)
COMPOSE="sudo docker compose --env-file /opt/tbot/deploy/tbot.prod.env -f /opt/tbot/deploy/compose.yaml -f /opt/tbot/deploy/compose.prod.yaml"
$COMPOSE config jobs | sed -n '/^  jobs:/,/^  [a-z]/p'      # secrets, env, ports, лимиты
$COMPOSE up -d jobs
$COMPOSE ps
sudo docker inspect tbot-jobs-1 --format "{{.Config.Image}} {{.State.Status}} {{.State.Health.Status}} restarts={{.RestartCount}} oom={{.State.OOMKilled}}"
sudo docker logs --tail 20 tbot-jobs-1                       # jobs_started, job_done ×2, integrity_check
sudo docker exec tbot-jobs-1 python -m packages.common.health_probe --url http://127.0.0.1:9103/readyz
sudo docker exec tbot-postgres-1 psql -U tbot -d tbot -c \
  "select id, action, actor is null as actor_null, entity, details ->> 'verdict' as verdict from audit_log order by id"
$COMPOSE run --rm -v /opt/tbot/scripts:/srv/tbot/scripts:ro web python3 scripts/audit_verify.py   # код 0
```

## 11. Вердикт

Подъём `jobs` на `153.51.172.30` **принят**: контейнер на зафиксированном digest
(`d7dba51a…8969e`, сборка `Image 45339984849` из `aa24f6a`), `Up (healthy)`, `restarts=0`,
`OOMKilled=false`, профиль hardening общий с остальными процессами, наружу не публикуется ничего
(число слушателей не изменилось), к базе ходит ролью `tbot_app`.

Главный результат — **ежедневная проверка цепочки журнала исполняется, и это видно по журналу**:
первый прогон прошёл сразу после старта (`verdict: intact`, `rows: 3`, `findings: 0`, место 80 %
свободно), в `audit_log` лежит строка `integrity.audit_chain` (`actor` пустой, `entity =
audit_log`, `run_id`, счётчики по четырём кодам, замер места) и она сама стала звеном цепи;
ручная свертка тем же кодом — «цепочка цела; код 0» (4 строки, `id 3–6`). Плюс закрыт остаток
§8.3: протёкшие окна счётчика чистит процесс (46 удалённых).

Не закрыто этим срезом: доставка уведомлений о находке (`T-116`, ревизия `0006`), третий признак
§8.7 («поиск секретов в логах»), `engine`/`tgbot` на площадке и `T-714` в её основном объёме
(правила на узле B), учения TZ §13.5 и бэкапы с WAL-архивом (`T-702`).
