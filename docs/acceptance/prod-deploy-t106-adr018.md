# Приёмка: деплой головы после `T-106` на `153.51.172.30` (миграции `0003`/`0004`, роль миграций по `ADR-018`)

Дата: 2026-11-22. Принималось: деплой головы репозитория среза `T-106` на живую ВМ
`153.51.172.30` (`tbot.rusiksoft.ru`) — пересъёмка дайджестов парой «прогон → коммит», применение
ревизий `0003` и `0004`, файл ключей `kek.json`, перекат `web` на новый набор образов и приёмка
наружного контура.

Основание для работ на площадке — решения заказчика: `ADR-001` (живая ВМ вместо тестовой),
`ADR-003` (деплой разрешён, Docker через `sudo docker`, SG = 22/80/443 tcp + 443 udp), `ADR-005`
(права файлов секретов), `ADR-006` (общий пароль ролей). Отдельное основание для шага миграций —
`ADR-018` (решение заказчика от 2026-11-22, ask `c7a6830e-9722-491d-9dbf-c8b291d3e84d`).

Всё, что измерялось на площадке, измерялось командами из `docs/runbook/stand-deploy.md`,
`docs/runbook/postgres-roles.md`, `docs/runbook/kek-keys.md` и `docs/runbook/ghcr-pull.md`.
Значения секретов не выводились: только имена, размеры и права через `--check`.

## 1. Отклонение от плана: пауза на миграции и как она была снята

Первая попытка шага миграций на голове `8f37d82` (набор дайджестов из `61dbd12`) упала:

```text
sqlalchemy.exc.ProgrammingError: (psycopg.errors.InsufficientPrivilege)
  must be owner of table sessions
[SQL: ALTER TABLE sessions ADD CONSTRAINT ck_sessions_token_hash_format
       CHECK (token_hash ~ '^[0-9a-f]{64}$')]
```

Замер после падения показал, что транзакция отработала штатно: `alembic_version` осталась `0002`,
таблицы `rate_buckets` нет — то есть частичной схемы не возникло (`Will assume transactional DDL`).

Причина измерена напрямую: все 10 таблиц схемы `public` принадлежат роли `tbot`, а `migrate`
соединяется ролью `tbot_app`.

```text
alembic_version, app_meta, audit_log, backup_codes, invitations, ip_allowlist,
rate_buckets?, sessions, totp_enrollments, totp_failures, users  → tableowner = tbot
tbot:     rolcanlogin=t, rolsuper=t
tbot_app: rolcanlogin=t, rolsuper=f
```

История не случайна: `0001`/`0002` применены 2026-11-20, когда состав ходил ролью `tbot`;
переключение `migrate` на роль приложения (`ADR-006`, вариант Б, ask `8d2be9bb`) состоялось
2026-11-21 — уже после создания таблиц. Право `CREATE ON SCHEMA public` не даёт прав на чужие
объекты, и отказ повторяется на каждой ревизии, которая правит таблицу старше переключения:
`0003` (`CHECK` к `sessions`), `0004` (колонка в `totp_enrollments`), будущая схема приглашений
`T-105` (правки `users`).

В CI этот разрыв невидим по построению: job `миграции` поднимает `postgres` с
`POSTGRES_USER=tbot` и исполняет `alembic upgrade head` под ролью `tbot`, а права роли приложения
проверяет после — через `SET ROLE`. DDL ревизий ролью приложения в CI не исполняется никогда.

Заказчик решил (ask `c7a6830e-9722-491d-9dbf-c8b291d3e84d`, вопрос 1): миграции идут отдельной
ролью-владельцем схемы, приложение остаётся ограниченной ролью времени выполнения. Оформление —
`ADR-018`; от `ADR-006` меняется ровно один пункт, общий пароль и запрет второго DSN-секрета
`db_url_owner` остаются. Реализация — коммит `e96d1fb`… (`e96d6fb`), см. §2.

## 2. Пара «прогон → коммит» и дайджесты

| Коммит | Что | Прогоны |
| --- | --- | --- |
| `e96d6fb` | `fix(deploy,T-009)`: роль миграций (`ADR-018`) — код, контракты, ADR, runbook, `AGENTS.md` | CI `45018552034` (success, 3m15s), Image `45018552045` (success, 1m25s, старт 11:41:26 UTC) |
| `92767e5` | `build(deploy)`: дайджесты пересняты с Image-прогона `45018552045` | CI `45018921689` (success, 2m33s), Image `45018921636` (success) |

Деплойный набор (образы собраны из `e96d6fb`, в `deploy/tbot.prod.env`):

```text
TBOT_WEB_DIGEST     = sha256:42efdc61cb3972db582c7d0a2e76763bb0cd5a093854268ae2a34ae1642bedeb
TBOT_TGBOT_DIGEST   = sha256:cb8d438baca89c6aa1ee9e3c315904a60e9947911886d03f89376a707d5cc0bf
TBOT_ENGINE_DIGEST  = sha256:9a98baf1833111cc2d7705ce29a8b328a12df9d4b1bfbc23ffa64227de988dc3
TBOT_JOBS_DIGEST    = sha256:82e445ba318706900ea15df80cd92eda1b717a973f881926304c009c87d3a7ed
TBOT_POSTGRES_DIGEST= sha256:e62fbf9d3e2b49816a32c400ed2dba83e3b361e6833e624024309c35d334b412  (без изменений)
CADDY_DIGEST        = sha256:4851e54a46b206517c574821bb5cc67f170d2156041e9fbc4c9193b45e84a75b  (без изменений)
```

Клон площадки: `5fab972` → `8f37d82` → `e96d6fb` → `92767e5`
(`92767e5a9d215b511a09476128ded2e40de5bdc6`). Проверка разрешённого исключения
(`runbook stand-deploy §2`): `sudo git -C /opt/tbot diff --name-only e96d6fb..HEAD` даёт ровно
`deploy/tbot.prod.env`.

Разбор боевого состава: `docker compose … config --quiet` → `rc=0`;
`config --format json | sudo python3 /opt/tbot/scripts/prod_compose_check.py` → 14/14 `OK`,
«ГОТОВО: боевой состав разобран без замечаний» (в том числе `images_by_digest`,
`no_local_build`, `secrets_per_service`, `secret_paths_policy` с `kek.json` вне
`/etc/tbot/secrets`, `read_only_rootfs`).

## 3. Состояние площадки до переката

```text
контейнеры: tbot-web-1 (web@sha256:844e21f5…=набор 3ac5849, Up 34h healthy)
            tbot-postgres-1, tbot-caddy-1 — запущены 2026-11-20T17:10:55Z
alembic_version = 0002
users = 0 строк
/etc/tbot/keys — отсутствует (файла ключей до этого среза на площадке не было)
secrets-setup.sh --check — 5 файлов OK, rc=0
ufw: 22/tcp, 80/tcp, 443/tcp, 443/udp (deny incoming по умолчанию)
наружный контур до переката: /healthz 200, /readyz 200, /login 404, /session-expired 404,
                             /locked 404, /admin/users 404, http → https 308
```

Последняя строка — причина, по которой деплой нужен: авторизованные маршруты `T-101…T-106` на
стоявшем образе `3ac5849` отсутствовали.

`docker login` на площадке выполняет `sudo sh -c "docker login ghcr.io --username rusiksoft-afk
--password-stdin < /etc/tbot/secrets/ghcr_token"`. Форма без `sudo sh -c` не работает и это
стоит зафиксировать: редирект `<` раскрывает файл оболочкой пользователя `rusiksoft`, а файл
`600 root:root` → `Permission denied` ещё до обращения к реестру.

## 4. Роль миграций: чем меряется, что получилось

Замер внутри контейнера `migrate` на новом образе (роли и факт подключения, без значений):

```text
TBOT_MIGRATION_DB_USER = 'tbot'
роль в db_url = tbot_app
роль после подмены = tbot ; пароль сохранён = True
фактическая роль подключения: tbot
суперпользователь = True
```

Рантайм-роль от разделения не изменилась:

```text
web (tbot-web-1): migration_db_user = None; TBOT_MIGRATION_DB_USER в окружении = None
                  роль = tbot_app ; rolsuper = False ; alembic_version из её взгляда = 0004
```

`deploy/postgres/roles.sql` применён повторным (идемпотентным) запуском ролью-владельцем —
до миграций и после них, оба раза `rc=0` (единственный `NOTICE` про уже выданное членство).
Именно этот запуск отзывает право `CREATE`, выданное ранее по варианту Б `ADR-006`:

```text
has_schema_privilege(tbot_app, public, usage)  = t
has_schema_privilege(tbot_app, public, create) = f        (было t)
```

Поведенческая проба под ролью приложения (одна сессия, `BEGIN; SET ROLE tbot_app; …; ROLLBACK;`,
каждая попытка во вложенном блоке `plpgsql` с обработчиком `insufficient_privilege`):

```text
CREATE TABLE roles_probe_ddl        → отказ SQLSTATE=42501 (было: проходило)
UPDATE audit_log                    → отказ SQLSTATE=42501 (контроль append-only цел)
SELECT count(*) from users          → OK (DML и чтение сохранены)
роль внутри сессии                  → tbot_app
после rollback: roles_probe_ddl отсутствует (count=0)
```

Владение новой таблицей и выдача прав по ней — без ручных `GRANT`:

```text
rate_buckets → tableowner = tbot
pg_default_acl (public, owner tbot): реляции {tbot_app=arwd/tbot}, последовательности {tbot_app=U/tbot}
проба DML ролью tbot_app по rate_buckets: INSERT OK → UPDATE OK (attempts=2) → DELETE OK → ROLLBACK
после rollback: строк во всей таблице = 0
```

Владение таблицей журнала по-прежнему возвращено владельцу схемы (`ALTER TABLE audit_log OWNER TO
CURRENT_USER`), а права на неё — `INSERT, SELECT` ни больше ни меньше:

```text
audit_log  для tbot_app → INSERT,SELECT
users, sessions для tbot_app → DELETE,INSERT,SELECT,UPDATE
```

## 5. Миграции `0002 → 0004`

```text
INFO [alembic.runtime.migration] Running upgrade 0002 -> 0003, Счётчик частоты запросов …
INFO [alembic.runtime.migration] Running upgrade 0003 -> 0004, Последний принятый шаг TOTP …
```

Код возврата самого шага читался отдельно: `run --rm migrate` без конвейера (конвейер
показывает код `tail`, и в прошлый срез это уже давало ложный «зелёный»). Идемпотентность
подтверждена повторным прогоном: `alembic current` из того же контейнера даёт `0004 (head)`,
`rc=0`.

Проверки результата:

```text
alembic_version = 0004
rate_buckets (таблица)          = 1
ck_sessions_token_hash_format   = 1
last_used_step (колонок)        = 1
ck_totp_enrollments_last_used_step_not_negative = 1
таблиц схемы public             = 11, все tableowner = tbot
```

Дамп базы перед миграцией **не делался** — решение заказчика (тот же ask, вопрос 2): шифрование
дампов (`T-702`) не реализовано, а слепой дамповый файл в том же томе противоречит `ADR-002`.
Откат схемы обеспечивает ревизия `0003`/`0004` (`downgrade`), откат состава — предыдущий набор
digest (§8).

## 6. Файл ключей `kek.json`

Создан инструментом, значение в чат/argv/логи не выводилось:

```text
sudo python3 /opt/tbot/deploy/vps/keys_setup.py            → создан /etc/tbot/keys/kek.json
sudo python3 /opt/tbot/deploy/vps/keys_setup.py --check     → rc=0
OK: kek.json: 158 байт, режим 640, владелец 0:10001, формат 1, ключей 1 (версии: 1),
    активная 1, длина ключа 32 байта
```

Права на площадке:

```text
750 root:root  /etc/tbot
700 root:tbot  /etc/tbot/keys
640 root:tbot  /etc/tbot/keys/kek.json
```

Внутри `web`: `kek_file = /run/secrets/kek_file`, читается = `True`, размер = 158. То есть привязка
TOTP физически возможна с этого момента — до создания файла маршруты `R4c` работали бы с отказом
«нет файла ключей».

**Отклонение (не правилось):** `docs/runbook/kek-keys.md §4` ждёт у каталога `700 root:root`,
а инструмент создал `700 root:tbot` (gid 10001). Сам файл и его содержимое — по `ADR-005`/`ADR-014`
(именно это требует `--check` и именно это монтируется составу). Требуется решение: поправить
ранбук под поведение инструмента или инструмент под ранбук; см. `docs/HANDOFF.md §4`.

## 7. Перекат состава

```bash
$COMPOSE up -d web caddy          # список сервисов обязателен: runbook stand-deploy §7
```

```text
postgres Waiting → Healthy → web Started → Healthy
web      | tbot-web-1 | Up healthy | ghcr.io/rusiksoft-afk/tbot-web@sha256:42efdc61…bedeb
caddy    | tbot-caddy-1 | Up 43 hours (healthy) | caddy@sha256:4851e54a…84a75b
postgres | tbot-postgres-1 | Up 43 hours (healthy) | postgres@sha256:e62fbf9d…34b412
web создан: 2026-11-22T11:48:54Z; postgres и caddy не пересоздавались (2026-11-20T17:10:55Z)
```

`engine`, `jobs` и `tgbot` **не поднимались**: это прямо предписано `runbook stand-deploy §6–7`
(подъём голым `up -d` поднимает весь состав; `tgbot` к тому же начнёт опрос Telegram токеном
оператора). Их задачи — `T-714` (egress) и контуры `paper`/`production`.

Журнал `web` за время приёмки: 0 строк `error|traceback|exception`; стартовые записи штатные
(`Application startup complete`, `Uvicorn running on http://0.0.0.0:8080`). В прикладном журнале
есть `session_redirect` для `/admin/users` и `/profile/sessions` с `reason=not_explained` — то
есть отказ не объясняет причин и не перечисляет причин отказа наружу.

Версии в запущенном образе: `fastapi 0.165.0`, `starlette 1.10.0`, `uvicorn 0.32.1`,
`psycopg 3.2.13`, `alembic 1.14.1`, `argon2-cffi 25.1.0`, `segno 1.6.6`.

## 8. Приёмка наружного контура (с dev-машины)

Маршруты (было → стало):

| Маршрут | До переката | После | Комментарий |
| --- | --- | --- | --- |
| `GET /healthz` | 200 | 200 | |
| `GET /readyz` | 200 | 200 | проверка базы проходит |
| `GET /login` | 404 | **200** | страница входа появилась |
| `GET /session-expired` | 404 | **200** | |
| `GET /locked` | 404 | **200** | |
| `GET /admin/users` | 404 | **302 → `/login`** | неаутентифицированный отказ — редирект, а не 403 и не «404 с подсказкой» |
| `GET /profile/sessions` | 404 | **302 → `/login`** | |
| `GET /metrics` | 404 | 404 | отвечает Caddy (`respond 404`), наружу метрики не идут |
| `http://` | 308 → https | 308 → https | метод и тело сохраняются |

Методы и заголовки:

```text
HEAD /login                 → 405 (метод не разрешён приложением; для пробы заголовков нужен GET)
TRACE, TRACK /healthz       → 405 (Caddy, @forbidden)
OPTIONS /healthz            → 405, Allow: GET (приложение)
GET /login                  → 200
  Strict-Transport-Security: max-age=63072000; includeSubDomains
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self';
    font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';
    frame-src 'none'; object-src 'none'
  X-Content-Type-Options: nosniff · X-Frame-Options: DENY · Referrer-Policy: same-origin
  Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()
  Cache-Control: no-store
  заголовка Server нет
```

TLS и транспорт:

```text
echo | openssl s_client -tls1_2  → TLSv1.2, ECDHE-ECDSA-AES128-GCM-SHA256
echo | openssl s_client -tls1_1  → отказ (no protocols available)
сертификат: issuer = Let's Encrypt (CN=YE1), subject/SAN ровно CN=tbot.rusiksoft.ru / DNS:tbot.rusiksoft.ru
            notBefore Nov 20 2026, notAfter Feb 18 2027 (том caddy_data не трогали)
QUIC-проба (Initial с заведомо неизвестной версией): quic_reply=35 VN=True
площадка: tcp/80 и tcp/443 — слушатель только у docker-proxy (v4 и v6), udp/443 — UNCONN v4 и v6
```

Маскировка в журнале прокси (TZ §8.4) — проба `?token=…&key=…&sig=…` и заголовок `X-Api-Key`:

```text
uri: /healthz?key=REDACTED&sig=REDACTED&token=REDACTED
headers: "X-Api-Key":"REDACTED"
grep "REDACT-PROBE-7731" в docker logs tbot-caddy-1 → 0 совпадений
grep DUMMY-VALUE / acceptance-probe / REDACT-PROBE-7731 в docker logs tbot-web-1 → 0 совпадений
```

Поведение лимитатора на живой схеме (одна проба, одного прогона достаточно):

```text
POST /login (без CSRF-токена, один прогон) → 400; в ответе 816 байт, формы с csrf-полем,
  _probe-имя_в_ответе = False (нет утечки существования имени)
rate_buckets после пробы: строк=1, scope=login_ip   → счётчик действительно пишет в новую таблицу
```

## 9. Что на этой приёмке сознательно НЕ проверялось

Аутентифицированная часть приёмки на проде **не проверяется и помечена отложенной** решением
заказчика (ask `c7a6830e-9722-491d-9dbf-c8b291d3e84d`, вопрос 3): в таблице `users` 0 строк,
учётные записи появятся только со схемой приглашений `T-105`, а временные базы/роли на боевом
кластере заводить запрещено.

Не проверено на площадке (проверено в CI и на dev-стенде):

- успешный вход и выдача сеансовой куки; `POST /logout`; `GET /profile/sessions` со списком и
  отзывом сеансов;
- шаги 2FA (`/totp`…), резервные коды, отказ при исчерпании попыток;
- матрица ролей: `403` без имён и счётчиков на `/admin/users` для роли `viewer`/`operator`,
  лестница `viewer ⊂ operator ⊂ admin`, «чужой живой объект и несуществовавший — одинаковый 404»
  (`ADR-017`);
- лимиты §8.3 в натуре: достигнутый `429`, бан адреса, `/locked` как последствие.

Доказательная база этих пунктов — `tests/integration/test_web_role_matrix.py` (единственный
источник матрицы маршрутов, её импортирует `tests/contract/test_web_roles_contract.py`) и
`tests/integration/test_web_*` в job `тесты и покрытие` прогонов `45018552034` / `45018921689`.
На проде эти строки матрицы становятся проверяемы после `T-105`.

## 10. Откат: цель и её сохранность

`ADR-002` требует хранить на машине предыдущий набор. Проверено после деплоя:

```text
tbot-web@sha256:844e21f511af…f794a  (набор 3ac5849 — M0)          присутствует
tbot-web@sha256:96e4f9d98edd…28bb19 (набор 61dbd12 — предыдущий)  присутствует
итог: 2 цели отката из 2; docker system prune НЕ выполнялся, старые образы не удалялись
тома: tbot_pgdata, tbot_caddy_data, tbot_caddy_config — на месте
диск: /dev/vda1 72G, занято 11G (16%), свободно 61G
ufw после деплоя: 22/tcp, 80/tcp, 443/tcp, 443/udp — без изменений
```

Цель отката по составу — набор `61dbd12` (run `45013751296`), он же зафиксирован в истории
`git log -p deploy/tbot.prod.env`. Откат по схеме — `downgrade` ревизий `0004`/`0003`; дамп базы
на этой приёмке не создавался (см. §5).

**Учение `downgrade` на проде на этом срезе не выполнялось.** Первая попытка (`alembic
downgrade 0003` → `upgrade head`) не состоялась по причине, которую стоит знать на будущее:
при `ssh … 'bash -s' <<EOF` команда `docker compose run` читает stdin и **съедает остаток
скрипта** — следующие команды молча не исполняются, а `rc` выглядит нулевым. Тот же дефект
съел в этом срезе блок проверки сразу после `run --rm migrate` (проверки делали отдельным
заходом). Правильная форма — `< /dev/null` у `run`, либо одна команда на заход. Цепочка
`upgrade head → downgrade base → upgrade head` остаётся доказанной job `миграции` (CI
`45018552034`); учение на площадке — отдельная задача (`ADR-002 §13.5`).

## 11. Отклонения и замечания

1. ~~Каталог `/etc/tbot/keys` — `700 root:tbot`, ранбук ждёт `700 root:root`~~ (§6).
   **Закрыто 2026-11-22** (ask `11aa27b8-0034-417c-b5c1-dce0b5c006f8`): отклонением это не является — норма `0700
   root:gid 10001`, именно так каталог создаёт `ensure_directory()` инструмента;
   исправлены `docs/runbook/kek-keys.md §4`, `ADR-014` п. 2 и комментарии инструмента.
   Права на площадке не менялись, `--check` был зелёным и остался.
2. **Опечатка в сообщении коммита `92767e5`** — «с e96d1fb» вместо `e96d6fb`. Сам
   `deploy/tbot.prod.env` указывает коммит `e96d6fb` и прогон `45018552045` корректно;
   прослеживаемость держит содержимое файла, а не текст сообщения.
3. **Контейнер `rollback-probe` (`Exited (0)`)** остался от учений 2026-11-20 и не удалён:
   удаление чужих объектов на площадке в этот срез не входило.
4. **`docker login` требует `sudo sh -c`** из-за прав файла `ghcr_token` (§3) — поведение
   площадки, а не дефект набора; в ранбуке `ghcr-pull` этой формы нет.
5. **Порядок «миграции → `roles.sql` → приложение»** теперь обязателен не только из-за выдач по
   существующим таблицам, но и потому, что `ALTER DEFAULT PRIVILEGES` настроены от роли `tbot`
   (§4): при обратном порядке новая таблица журнала оказалась бы владеетелем приложения, и
   `REVOKE` по ней не работал бы.
6. **`migrate` — привилегированный процесс** (`ADR-018`): он остаётся в профиле `tools`, не
   монтирует KEK и токены, сетевого трафика не принимает; это принято осознанно, а не как
   недоделка.

## 12. Как повторить

```bash
# dev-машина
ssh -i ~/.ssh/tbot/ssh-key-1795095923419 -o IdentitiesOnly=yes rusiksoft@153.51.172.30
# площадка (COMPOSE — абсолютные пути, всё под sudo)
COMPOSE="sudo docker compose -f /opt/tbot/deploy/compose.yaml -f /opt/tbot/deploy/compose.prod.yaml --env-file /opt/tbot/deploy/tbot.prod.env"
sudo git -C /opt/tbot -c core.sshCommand="ssh -o IdentitiesOnly=yes -i /root/.ssh/tbot_deploy_key" pull --ff-only
sudo git -C /opt/tbot diff --name-only <коммит образов>..HEAD      # только deploy/tbot.prod.env
$COMPOSE config --quiet
$COMPOSE config --format json | sudo python3 /opt/tbot/scripts/prod_compose_check.py
sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --check
sudo python3 /opt/tbot/deploy/vps/keys_setup.py --check
$COMPOSE pull
$COMPOSE run --rm migrate                       # без конвейера: иначе $? читается от tail
sudo sh -c 'docker exec -i tbot-postgres-1 psql -U tbot -d tbot -v ON_ERROR_STOP=1 -q -f - < /opt/tbot/deploy/postgres/roles.sql'
$COMPOSE up -d web caddy
$COMPOSE ps
```

## 13. Вердикт

Деплой головы после `T-106` на `153.51.172.30` **состоялся**: клон на `92767e5`, образы по
digest из прогона `45018552045`, схема на `0004`, `web` healthy на новом digest, наружный контур
отвечает набором `T-106` (страницы входа/заблокировки доступны, отказ неаутентифицированному —
редирект, метрики и лишние методы закрыты, TLS/HSTS/HTTP/3 и маскировка журнала в норме),
модель ролей базы приведена к `ADR-018` и измерена, прежний набор образов и тома сохранены.

Что остаётся непроверенным на проде осознанно: аутентифицированная часть (§9) до `T-105`.
Что требовало решения заказчика: права каталога `/etc/tbot/keys` (§6, §11.1) — получено
2026-11-22 (ask `11aa27b8-0034-417c-b5c1-dce0b5c006f8`), закрыто правкой документации; ни код, ни права на
площадке не менялись.
