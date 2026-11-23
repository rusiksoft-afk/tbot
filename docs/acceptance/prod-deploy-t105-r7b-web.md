# Приёмка: деплой головы после `T-105`/`R7b` на `153.51.172.30` (слой `web`: приём ссылки и раздел администрирования)

Дата: 2026-11-22. Принималось: деплой головы `main` срез `R7b` на живую ВМ `153.51.172.30`
(`tbot.rusiksoft.ru`) — пересъёмка дайджестов парой «прогон → коммит», `pull` по digest, перекат
`web` на новый набор, подтверждение что схема не менялась, и неаутентифицированная приёмка
наружного контура (маршруты `T-105` без сеанса, отказ мутации без CSRF-токена, вымаривание
значения ссылки в журналах периметра и приложения).

Основание для работ на площадке — решения заказчика: `ADR-001` (живая ВМ вместо тестовой),
`ADR-003` (деплой разрешён, Docker через `sudo docker`, SG = 22/80/443 tcp + 443 udp), `ADR-005`
(права файлов секретов), `ADR-006`/`ADR-018` (роли базы), `ADR-019` (публичный репозиторий,
приватные пакеты GHCR), `ADR-020`/`ADR-021` (содержимое среза), `ADR-022` (слоты Alembic).
Отдельное основание этого деплой-среза — ask `6e2c3163-b402-4a45-ad00-bb9794979837`
(«деплой авторизован сейчас», `docs/HANDOFF.md` §1.54).

Замеры выполнены командами из `docs/runbook/stand-deploy.md` (§2–3, 4, 7),
`docs/runbook/ghcr-pull.md` (§2, 4) и приёма прошлого протокола
`docs/acceptance/prod-deploy-t106-adr018.md` (§3, 10, 12). Значения секретов не выводились:
только имена, размеры и права через `--check`. Значения тестовых ссылок, сгенерированных для
проб, в git, argv и логи не попадали (они не являются секретами — приглашений в базе нет, —
но в репозиторий не пишутся по `ADR-019`).

## 1. Пара «прогон → коммит» и дайджесты

| Коммит | Что | Прогоны |
| --- | --- | --- |
| `68e4663` | голова `main` на момент постановки задачи: docs-срез фиксации решений по `T-105` (последний коммит, в котором менялся код слоя `web`, — `303995f`) | CI `45056081495` (success, 2m40s), Image `45056081523` (success, 45s, `startedAt` 2026-11-22T18:36:49Z, `headSha` = `68e46637a5415901450142f9399b6857be28a667` — сверен `gh run view --json headSha`) |
| `9ced14c` | `chore(deploy)`: дайджесты пересняты с Image-прогона `45056081523` | CI `45058207725` (success, 2m15s), Image `45058207796` (success, 43s) — общий прогон с парой ниже |
| `9e45679` | `docs(HANDOFF)`: §2 — блокер завода первой учётной записи | там же; job `боевой состав: compose-overlay, digest, Caddyfile` — success, 14s |

Деплойный набор — **прогон `45056081523` / коммит `68e4663`**, то есть тот, чьи значения записаны
в `deploy/tbot.prod.env`, а не самый свежий прогон (`docs/runbook/ghcr-pull.md §2`). Пуш
документации порождает свой `Image`-прогон (`45058207796`) со следующим набором манифестов — он
не деплоится и очередной пересъёмки не требует; это ожидаемое поведение правила «сборка не
воспроизводима по digest».

| Образ | Было (цель отката, набор `e96d6fb`, run `45018552045`) | Стало (набор `68e4663`, run `45056081523`) |
| --- | --- | --- |
| `tbot-web` | `sha256:42efdc61cb39…1642bedeb` | `sha256:0ffbebe47504…d5a5b24d` |
| `tbot-tgbot` | `sha256:cb8d438baca8…7d5cc0bf` | `sha256:5e7431e04763…42c4cb861` |
| `tbot-engine` | `sha256:9a98baf18331…de988dc3` | `sha256:200dc0d3174c…94cf42b7c` |
| `tbot-jobs` | `sha256:82e445ba3187…c87d3a7ed` | `sha256:89b3ab026872…043b8d83` |
| `postgres` | `sha256:e62fbf9d3e2b…d334b412` | без изменений |
| `caddy` | `sha256:4851e54a46b2…e84a75b` | без изменений |

Клон площадки: `92767e5` → `9e45679` (`9e45679` — голова на момент деплоя; `92767e5` и `68e4663`
проверены предками `git merge-base --is-ancestor`, `9e45679` — их потомок). Разрешённое
исключение (`runbook stand-deploy §2`): `sudo git -C /opt/tbot diff --name-only 68e4663..HEAD`
даёт ровно `deploy/tbot.prod.env` и `docs/HANDOFF.md` — ни одного пути из перечня
`apps/`, `packages/`, `deploy/Dockerfile`, `pyproject.toml`, `deploy/compose*.yaml`,
`deploy/caddy/Caddyfile`, `deploy/postgres/tbot.conf`, то есть образы собраны из того же кода,
что лежит на площадке. `git status --short` на ВМ — пусто.

## 2. Состояние площадки до переката

```text
клон: 92767e5 («build(deploy): дайджесты образов пересняты с e96d6fb …»), дерево чистое
контейнеры: tbot-web-1       Up 6 hours  (healthy)  web@sha256:42efdc61…bedeb, создан 2026-11-22T11:48:54Z
            tbot-postgres-1  Up 2 days   (healthy)  postgres@sha256:e62fbf9d…34b412, создан 2026-11-20T16:55:36Z
            tbot-caddy-1     Up 2 days   (healthy)  caddy@sha256:4851e54a…84a75b, создан 2026-11-20T16:55:37Z
            rollback-probe   Exited (0) 2 days      (посторонний контейнер учений 2026-11-20)
alembic_version = 0004 ; users = 0 ; invitations = 0 ; таблиц схемы public = 11
secrets-setup.sh --check: 5 OK, rc=0 (db_password 48, db_url 97, ghcr_token 40, telegram_token 46,
                          telegram_socks_pass 24; права 640 root:tbot, ghcr_token 600 root:root)
keys_setup.py --check: OK, rc=0 (kek.json 158 байт, 640, владелец 0:10001, ключей 1, активная 1)
ufw: active, deny (incoming) + 22/tcp, 80/tcp, 443/tcp, 443/udp
диск: /dev/vda1 72G, занято 11G (16%), свободно 61G
наружный контур до переката: /healthz 200, /readyz 200, /login 200, /invite 404,
   /admin/users 302 → /login, POST /admin/users/<id>/approve 404, http → https 308, /metrics 404
```

Две детали, из-за которых деплой нужен и которые нельзя читать по коду ответа:

1. `GET /invite` отвечал `404` **и до** деплоя — но это `404` отсутствующего маршрута: тело
   `{"detail":"Not Found"}`, 22 байта, `Content-Type: application/json`. После деплоя код тот же
   (`404` — так отвечает раздел, см. `ADR-021` п. 5), а тело — страница `invite.html`
   (549/561 байт, `Content-Type: text/html`). Признак появления маршрута — тело и тип, не код.
2. `POST /admin/users/<id>/approve` до деплоя давал `404` (маршрута нет), а после — `403`
   (CSRF), то есть порядок «охрана мутации раньше разбора маршрута» виден только после переката.

## 3. Разбор состава на площадке (перед запуском)

```text
compose площадки: 2.40.3+ds1-0ubuntu1~24.04.1   (в CI — v5.1.3, правила слияния overlay различаются)
docker compose -f /opt/tbot/deploy/compose.yaml -f /opt/tbot/deploy/compose.prod.yaml \
  --env-file /opt/tbot/deploy/tbot.prod.env config --quiet                      → rc=0
config --format json | sudo python3 /opt/tbot/scripts/prod_compose_check.py     → 14/14 OK, rc=0
ГОТОВО: боевой состав разобран без замечаний
```

`OK` по всем 14 строкам, включая `images_by_digest`, `no_local_build`, `secrets_per_service`,
`secret_paths_policy` (5 файловых путей, `kek.json` вне `/etc/tbot/secrets`),
`ports_proxy_publication` (`80/tcp`, `443/tcp`, `443/udp`), `read_only_rootfs`, лимиты
2880 МиБ / 4.0 CPU.

Локально на dev-машине (Windows, без Docker и `make`) тот же снимок разбора получить нельзя:
`prod_compose_check.py` читает вывод `docker compose config --format json` и без него отвечает
«снимок разбора состава не прочитан: Expecting value…», rc=2. Проверка сделана на площадке
(этот пункт обязателен именно там, `runbook stand-deploy §3`) и дублируется job'ом
`боевой состав: compose-overlay, digest, Caddyfile` (`45058207725`, success, 14s).
`scripts/deploy_check.py` дайджестов не проверяет (ключей `*_DIGEST` в нём нет), поэтому по
поводу пересъёмки его запуск ничего не добавляет; запущен офлайн-набором проверок в CI.

Локальные проверки пересъёмки: `pytest tests/contract -k "vps or prod or compose"` — 32 passed;
`tests/integration/test_compose_prod_contract.py` + `tests/unit/test_prod_compose_check.py` —
76 passed (сред них `test_digest_в_env_файле_имеют_форму_и_не_похожи_на_секреты`,
`test_переменные_overlay_описаны…` — последний ловит неиспользуемый или потерянный ключ);
`ruff format --check` — 137 files already formatted; `ruff check` — чисто;
`scripts/count_suppressions.py` — 14 (база 14).

## 4. Перекат состава

```bash
sudo sh -c "docker login ghcr.io --username rusiksoft-afk --password-stdin < /etc/tbot/secrets/ghcr_token"
                                                              # Login Succeeded; форма только с sudo sh -c
sudo git -C /opt/tbot -c core.sshCommand="ssh -o IdentitiesOnly=yes -i /root/.ssh/tbot_deploy_key_20261122" pull --ff-only
sudo docker compose … pull                                    # rc=0
sudo docker compose … up -d web caddy                         # rc=0; список сервисов обязателен (§7)
```

```text
ps после переката:
tbot-web-1      web@sha256:0ffbebe4…5b24d      Up (healthy)         создан 2026-11-22T19:04:09Z,
                                                            запущен 19:04:13Z, health=healthy
tbot-postgres-1 postgres@sha256:e62fbf9d…      Up 2 days (healthy)  не пересоздавался
tbot-caddy-1    caddy@sha256:4851e54a…         Up 2 days (healthy)  не пересоздавался
migrate — не запускался (новой ревизии нет, §5); engine, jobs, tgbot не поднимались
```

Журнал `web`: стартовые строки штатные (`Started server process`, `Application startup complete`,
`Uvicorn running on http://0.0.0.0:8080`), совпадений `error|traceback|exception` — 0
(`docker compose logs web | grep -icE …` → 0). Строки журнала приложения — только события
прогона приёмки, разобраны в §7.

## 5. Схема: голова не изменилась

Ревизий срез `R7a`/`R7b` не добавлял: слот `0005` за `T-105` остаётся занятым и пустым,
`0006` за `T-116`, `0007` зарезервирован за журналом `T-109` (`ADR-022`, `ADR-020` п. 9).
Поэтому `migrate` не поднимался, а факт сверялся прямым замером до и после:

```text
до:    select version_num from alembic_version;  → 0004
после: select version_num from alembic_version;  → 0004
после всех проб: users = 0, invitations = 0, sessions = 0, audit_log = 0
                 rate_buckets = 2 (обе строки scope = login_ip) → счётчик частоты пишет в живую схему
```

Замер — через `exec -T postgres psql -U tbot -d tbot`, без DSN в argv и без значений паролей
(роль-владелец схемы из `ADR-018` используется только для чтения счётчиков; прав `roles.sql`
этот срез не касался).

## 6. Приёмка наружного контура (dev-машина, без сеанса)

Значения ссылок для проб генерировались локально (`base64url(32 байта)`, 43 символа — форма
действующего значения по `ADR-020` п. 3), приглашений в базе нет, поэтому ожидаемый ответ —
«выпуска нет». Значения в git не записаны.

| Запрос | До переката | После переката | Комментарий |
| --- | --- | --- | --- |
| `GET /login` | 200 | 200 | |
| `GET /healthz`, `GET /readyz` | 200 / 200 | 200 / 200 | `readyz` — проверка базы проходит |
| `GET /` | 200 | 200 | |
| `GET /session-expired`, `GET /locked` | 200 | 200 | маршруты `T-106` на месте |
| `GET /totp`, `GET /profile/sessions` | 302 → `/login` | 302 → `/login` | |
| `GET /invite` (без значения) | 404, JSON 22 б | **404, HTML 549 б** | ответ раздела, не `422` со списком ошибок поля |
| `GET /invite?token=short` (некорректная форма) | — | **404, HTML 549 б**, тело идентично предыдущей строке (`sha256 8b9fa7fb…be59cc51`) | формат значения проверяется до поиска по базе |
| `GET /invite?token=<43 символа>` (два разных значения) | — | **404, HTML 561 б**, тела двух разных значений идентичны (`sha256 f504846a…5c5a0729`) | различие «значение A / значение B» из ответа не извлекается |
| `POST /invite` с формой (`login`, `password`, повтор) без значения ссылки | — | **404, 549 б**; после пробы `users = 0` | адрес не принимает открытую регистрацию (`ADR-020` п. 2, `test_no_public_registration`) |
| `GET /admin/users` без сеанса | 302 → `/login` | **302 → `/login`** | уровень `TIER_ADMIN` в матрице `ROUTE_POLICY`: редирект — неаутентифицированному, `403` — роли ниже `admin` (`AC-identity-01`), а не `404` |
| `GET /admin/users?token=<значение>` | — | 302 → `/login` | тот же ответ, что без query (см. §7 про журнал) |
| `POST /admin/users/<uuid>/approve` без CSRF-токена | 404 (маршрута нет) | **403**, 63 б, тело `{"status":"forbidden","detail":"запрос отклонён"}` | ровно `DENIAL_BODY` (`ADR-008`, `ADR-017` п. 4); в журнале — `csrf_rejected` |
| `GET /metrics` | 404 | 404 | отвечает Caddy (`respond 404`) |
| `http://…/healthz?token=<значение>` | 308 → https | 308 → https (query сохранён) | метод и тело сохраняются |

Заголовки `GET /invite` (`404`): `strict-transport-security: max-age=63072000; includeSubDomains`,
CSP из TZ §8.3 (`default-src 'self'; …; form-action 'self'; object-src 'none'`),
`x-content-type-options: nosniff`, `x-frame-options: DENY`, `referrer-policy: same-origin`,
`permissions-policy`, `cache-control: no-store`, `x-trace-id`, заголовка `Server` нет.

Тело закрытой ссылки не содержит ни формы (`form_open = False` → `<form>` нет, `action=""`
некуда подставить), ни значения ссылки: `grep` по скачанным телам — 0 совпадений.

Где живёт ожидание ответа (чтобы приёмка не читалась по коду маршрута): уровень допуска
`(ADMIN_USERS_PATH, "GET")` — `tests/integration/test_web_role_matrix.py:251-255`
(`TIER_ADMIN`, `frozenset({200})`), уровень адреса приёма — там же, `312-318` (`TIER_CEREMONY`,
`frozenset({404})`); тело отказа допуска — `DENIAL_BODY`
(`apps/web/security/authorization.py:83`, ответ формирует там же, строка 127); маршруты
приглашения — `apps/web/routes/invitations.py`.

## 7. Значение ссылки в журналах: вымаривание доказано на самих записях

Журнал периметра (`sudo docker compose logs caddy`, фильтр из `deploy/caddy/Caddyfile` —
`request>uri query → replace token|key|sig → REDACTED`, logger `http.log.access.log0`):

```text
всего записей: 1847 ; записей с token=REDACTED: 8 (все — пробы этого среза)
  19:05:05 404 GET /invite?token=REDACTED
  19:05:05 404 GET /invite?token=REDACTED
  19:05:06 404 GET /invite?token=REDACTED
  19:05:06 404 GET /invite?token=REDACTED
  19:05:06 302 GET /admin/users?token=REDACTED
  19:05:07 200 GET /login?probe=<не секретное значение — видно целиком>
  19:05:22 404 GET /invite?token=REDACTED
  19:05:22 404 GET /invite?token=REDACTED
grep сгенерированных значений по журналу caddy: 0 совпадений
записей access-лога со значением query-ключа token во всём журнале: 14, из них 12 закрыты
(`token=REDACTED`), 2 — нет; обе обращены к `Host`, не совпадающему с именем сайта (§10 п. 1)
контрастная проба: запрос с не секретным ключом query (`probe=…`) записан открытым текстом —
   значит вымаривание работает по списку ключей, а не «режет весь query целиком»
```

То есть путь запроса виден (`/invite`, `/admin/users`), значение — нет; сравнение с запросом,
где ключ не секретный, показывает, что фильтр точечный.

Журнал приложения (`sudo docker compose logs web`, structlog):

```text
всего строк: 7 ; строк с полем "path": 3 ; полей "uri"/"url"/"query": 0
grep сгенерированных значений по журналу web: 0 совпадений
web-1 | {"path": "/admin/users", "reason": "not_explained", "clear_cookie": false,
        "event": "session_redirect", "trace_id": "…", "level": "info",
        "ts": "2026-11-22T19:05:06.850780Z"}
web-1 | {"detail": "токена нет", "event": "csrf_rejected", "trace_id": "…",
        "path": "/admin/users/00000000-0000-0000-0000-000000000000/approve", "level": "warning"}
```

Ключевое: запрос `GET /admin/users?token=<значение>` порождает запись с `"path": "/admin/users"`
— query в журнал приложения не попадает вовсе (`apps/web/main.py` логирует `request.url.path`),
а `uvicorn` запущен с `access_log=False` (`apps/web/main.py:run()`), поэтому полного URI в
журнале процесса нет ни в одной строке. Отказ CSRF уходит в журнал событием `csrf_rejected` —
без значения ссылки и без куки.

## 8. Что на этой приёмке сознательно НЕ проверялось

1. **Аутентифицированная половина приёмки** — вход и выдача сеансовой куки, `POST /logout`,
   `GET /profile/sessions` со списком и отзывом, шаги 2FA и резервные коды, матрица ролей
   (`403` без имён и счётчиков на `/admin/users` для `viewer`/`operator`), одноразовость ссылки,
   очередь одобрения, `approve`/`suspend`/`unsuspend`/`archive`, поведение заблокированной
   записи и защита последнего живого администратора. Перечень и формулировки — §9 протокола
   `docs/acceptance/prod-deploy-t106-adr018.md`; он остаётся списком отложенного.
   Причина переноса — **нет сценария завода первой учётной записи**: в `users` 0 строк, а
   приглашение выпускает только администратор с полным сеансом. Решение заказчика получено
   2026-11-22 (ask `3f998543-38fd-479f-86d2-e77ab16d014f`): путь — операторский скрипт-обёртка
   поверх доменных функций `packages/identity/users.py` (`new_user` → `enqueue_for_approval` →
   `approve_account(approved_by=<собственный id>)`), не ручные `INSERT`; задача заведена как
   **`T-112`** (`tasks/todo.md`), оформление — `ADR-023`. Пункты §9 выполняются после `T-112`.
   Проверено по коду (в том же координирующем срезе): консоль требует полный шаг входа —
   `require_full_session` вызывает `ensure_full_auth` (`apps/web/security/sessions.py:374-392`),
   а параметризованная проверка `test_route_requires_full_auth`
   (`tests/integration/test_web_backup_codes.py:859`) проходит по реальным маршрутам консоли, а
   не по тестовому щупу. Поэтому заведённая скриптом запись всё равно обязана привязать 2FA
   при первом входе: расхождения «bootstrap обходит второй фактор» нет по построению, а на проде
   оно станет проверяемым пунктом уже после `T-112`.
2. **Ничего не создавалось в базе**: `INSERT` в `users`/`invitations` не выполнялись, значения
   ссылок в базу не вносились; после всех проб счётчики остались нулевыми (§5). Проба
   `POST /invite` с формой ответа «создана учётная запись» не дала (§6).
3. **Приёмка периметра не повторялась целиком**: `Caddyfile` в срез `R7b` не входил
   (`git diff` §1), поэтому TLS/HSTS/HTTP-3/граница методов проверены только точечно
   (§6: заголовки `404`, `http → https 308`, `/metrics 404`). Основание — прежнее
   (`docs/acceptance/tls-edge.md`, `docs/acceptance/prod-firewall.md`).
4. **Лимиты §8.3 в натуре** (достигнутый `429`, бан адреса, `/locked` как следствие) не
   проверялись: подтверждено только то, что счётчик пишет в живую схему (`rate_buckets`,
   `scope = login_ip`), — как и в прошлом срезе.
5. **Аудит** (`T-109`): ни один маршрут раздела не пишет в `audit_log` — `audit_log` = 0 строк;
   перенос оформлен `ADR-022` п. 1, слот `0007` за журналом.
6. **Учение `downgrade` и замер RTO на новом наборе digest** не проводились: отдельный срез по
   `ADR-002` и учениям TZ §13.5.
7. **`engine`, `jobs`, `tgbot`** не поднимались (их задачи — `T-714`, контуры `paper`/
   `production`); голый `up -d` не выполнялся сознательно (`runbook stand-deploy §7`).
8. **Файл ключей `kek.json`** и права секретов не менялись; `--check` зелёные до переката (§2) —
   привязка TOTP физически доступна, но ни одной привязки на площадке нет (записей `users` нет).

## 9. Откат: цель и её сохранность

```text
tbot-web@sha256:42efdc61cb39…1642bedeb  (набор e96d6fb — цель отката)      присутствует
tbot-web@sha256:0ffbebe47504…d5a5b24d  (деплимый набор 68e4663)            работает
прежние наборы тоже на машине: 96e4f9d9…, 844e21f5…, b2bc564d…, 0f482651…, 4aa09b13…
итог: 2 рабочих цели отката из 2 (последний рабочий набор + предыдущий рабочий);
docker system prune НЕ выполнялся, старые образы не удалялись
tgbot/engine/jobs: оба набора тоже загружены (pull подтянул все четыре образа)
тома: tbot_pgdata, tbot_caddy_data, tbot_caddy_config — на месте (down не выполнялся, -v не used)
диск после переката: /dev/vda1 72G, занято 12G (17%), свободно 60G
docker system df: Images 28 (size 5.22GiB, reclaimable 210.9MB), Volumes 3 (48.46MB)
ufw после деплоя: без изменений (22/tcp, 80/tcp, 443/tcp, 443/udp, deny incoming)
```

Порядок отката (`runbook stand-deploy §7`, `docs/runbook/ghcr-pull.md §5`): в
`deploy/tbot.prod.env` вернуть значения из истории git (`git log -p deploy/tbot.prod.env`,
коммит перед `9ced14c`), `sudo git -C /opt/tbot … pull`/`checkout` этого коммита, затем
`sudo docker compose … pull` и `up -d web caddy` — оба набора уже скачаны, поэтому откат не
качает слои. Цель отката по схеме — не нужна: схема не менялась (`0004`), `downgrade` не
требуется. Том `pgdata` не удаляется ни при каком откате.

## 10. Отклонения и замечания

1. **Фильтр вымаривания query-ключей действует только для обращений к имени сайта.** Запрос, у
   которого `Host` не совпадает с `tbot.rusiksoft.ru` (например прямое обращение по IP),
   обслуживается дефолтным обработчиком Caddy и попадает в журнал логгером `http.log.access` —
   **без** фильтра. Проверено собственной пробой на этом срезе:

   ```bash
   curl -sS 'http://153.51.172.30/healthz?token=<любое значение>'      # 308
   ```
   в журнале — `… "logger":"http.log.access" "host":"153.51.172.30"
   "uri":"/healthz?token=<значение>"` (значение открытым текстом), тогда как тот же запрос к
   `http://tbot.rusiksoft.ru/healthz?token=<значение>` и к `https://…` записан как
   `token=REDACTED` (логгер `http.log.access.log0`). Разбор всего остающегося журнала
   (`sudo docker logs tbot-caddy-1` — 1852 записи access-лога): записей с query-ключом `token`
   — 14; из них 12 закрыты (`host=tbot.rusiksoft.ru`, логгер `…log0`), 2 — нет: `GET
   /healthz?token=…` с `host=153.51.172.30` (проба этого среза) и сканерный `POST
   /cgi-bin/api.cgi?cmd=Login&token=null` с `host=153.51.172.30:80`; обе — логгер без суффикса,
   `http.log.access`. Всего записей с `host`, равным адресу машины, — 132; записей у
   нефильтрованного логгера — 243. То есть фильтр привязан к сайту, а обращения к адресу
   машины обслуживает дефолтный обработчик Caddy.

   Граница вектора измерена той же пробой со значением, заведомо не являющимся секретом
   (`probe-ip-notsecret-20261122`, чтобы проба не оставляла в журнале ничего, похожего на
   credential):

   ```text
   http://153.51.172.30/invite?token=<probe>   → 308, в Location значение уходит дословно
   https://153.51.172.30/invite?token=<probe>  → рука TLS не складывается (у Caddy нет
                                                 сертификата на адрес): curl отдаёт status=000
   https://tbot.rusiksoft.ru/invite?token=<probe> → 404, 549 б (страница раздела)
   журнал web (structlog) на эти пробы: 0 совпадений со значением пробы
   ```

   Риск формулируется точно: одноразовое значение, затребованное по адресу машины по
   незащищённому HTTP, остаётся открытым текстом в журнале периметра и в заголовке `Location`
   ответа; по `Host`-адресу до приложения запрос не доходит (TLS-рукопожатие не проходит —
   сертификата на IP-имя нет), поэтому второй копии в журнале приложения не возникает. Путь
   браузера закрыт `HSTS` и `308`, но не путь произвольного клиента и не сканерный трафик,
   который уже сейчас приходит на `Host` = адрес машины (132 записи).

   Правка — `deploy/caddy/Caddyfile` (глобальный `log`-фильтр либо сайт-блок для несовпадающего
   `Host`), то есть отдельный деплой-срез и правка контрактного теста; список query-ключей
   (`token`/`key`/`sig`) при этом ни при чём — речь об **области действия** фильтра, а не о его
   ключах. В этот срез правка не входила (конфигурация периметра не менялась), требуется
   решение заказчика.
2. **Два разных текста при одном коде `404` на адресе приёма ссылки.** Замерено: значение
   некорректной формы → 549 байт, «Ссылка испорчена: значение в адресе не читается…»;
   корректная форма без выпуска → 561 байт, «Ссылка не найдена: возможно, она перенесена не
   целиком…». Код — `404` в обоих случаях, а строка матрицы допуска
   (`tests/integration/test_web_role_matrix.py:312-318`) даёт `TIER_CEREMONY` и
   `frozenset({404})`, поэтому проверка зелёная. Расхождение с текстом самой строки матрицы и
   с формулировкой правила: `ADR-021` п. 5 набора ответов адреса приёма (строки 124-126 —
   «одним текстом и одним `404`»), комментарий над `UNUSABLE_EXPLANATIONS`
   (`apps/web/routes/invitations.py:122-126`: «у них один текст и один код ответа») и docstring
   `_resolve_link` (там же, строки 187-195) — «один текст, один код», а словарь объяснений
   (`invitations.py:127-139`) выдаёт два разных. Оракулом существования выпуска это не
   является: форма значения проверяется до всякого обращения к базе (`ensure_invitation_secret`,
   `invitations.py:196`), поэтому по различию ответов нельзя узнать, есть ли строка в
   `invitations`. Требуется решение, что править — тексты (тогда оба случая совпадут дословно)
   или обоснование в `ADR-021`/комментарии/`_resolve_link` (тогда различие фиксируется как
   осознанное, и тогда надо править и формулировку п. 5 `ADR-021`). В этот деплой-срез правка
   не входила.
3. **`Content-Type` и размер тела — единственный признак появления маршрутов `T-105`.** Коды
   `404` у `/invite` были и до деплоя (§2). Для будущих приёмок: сравнивать тело, а не код
   ответа; иначе «маршрут появился» читается ложно-зелёно.
4. **`cd /opt/tbot` под `rusiksoft` недоступен** (`/opt/tbot` — `750 root:root`), поэтому
   `docker compose` с относительными `-f` падает на `couldn't find env file`. В
   `docs/runbook/stand-deploy.md §12` остаётся строка `cd /opt/tbot` — она работает только в
   root-сессии; рабочий порядок для не-root — абсолютные пути `-f /opt/tbot/deploy/…`
   (`runbook stand-deploy §2`, замер 2026-11-20 14:23 UTC). Проверено повторно на этом срезе.
5. **`docker login` требует `sudo sh -c`**: редирект `< /etc/tbot/secrets/ghcr_token` раскрывает
   файл оболочкой пользователя, а файл `600 root:root` → `Permission denied` до обращения к
   реестру (как в прошлом срезе; в `runbook ghcr-pull` формы нет).
6. **Посторонний контейнер `rollback-probe` (`Exited (0)`)** жив на машине со времён учений
   2026-11-20 и не удалён: удаление чужих объектов в срез не входило.
7. **Временные файлы замеров на ВМ удалены** (`/tmp/tbot-pull-20261122.log`,
   `/tmp/tbot-up-20261122.log`, `/tmp/caddy_full.log`, `/tmp/web_full.log`); значений секретов
   они не содержали. В `/tmp` площадки остались прежние операторские файлы
   (`login_probe.html`, `mig.log`) — не тронуты.
8. **Пересъёмка дайджестов и пуш документации сделаны одним пушем** (коммиты `9ced14c` и
   `9e45679`), чтобы не плодить лишнюю пару прогонов Actions (§1); это не меняет прослеживаемость:
   набор по-прежнему описан парой «run → commit» в самом файле.

## 11. Как повторить

```bash
# dev-машина
ssh -i ~/.ssh/tbot/ssh-key-1795095923419 -o IdentitiesOnly=yes rusiksoft@153.51.172.30
# площадка: COMPOSE с абсолютными путями (cd /opt/tbot под rusiksoft запрещён правами каталога)
COMPOSE="sudo docker compose -f /opt/tbot/deploy/compose.yaml -f /opt/tbot/deploy/compose.prod.yaml --env-file /opt/tbot/deploy/tbot.prod.env"
sudo git -C /opt/tbot -c core.sshCommand="ssh -o IdentitiesOnly=yes -i /root/.ssh/tbot_deploy_key_20261122" pull --ff-only
sudo git -C /opt/tbot diff --name-only 68e4663..HEAD            # только deploy/tbot.prod.env и docs/*
$COMPOSE config --quiet
$COMPOSE config --format json | sudo python3 /opt/tbot/scripts/prod_compose_check.py
sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --check
sudo python3 /opt/tbot/deploy/vps/keys_setup.py --check
sudo sh -c 'docker login ghcr.io --username rusiksoft-afk --password-stdin < /etc/tbot/secrets/ghcr_token'
$COMPOSE pull
$COMPOSE up -d web caddy                                        # список сервисов обязателен
$COMPOSE ps ; $COMPOSE logs --tail=80 web
$COMPOSE exec -T postgres psql -U tbot -d tbot -At -c "select version_num from alembic_version;"
# пробы контура (dev-машина): GET /invite, GET /invite?token=<43 символа>, GET /admin/users,
# POST без CSRF; затем $COMPOSE logs caddy | grep -E 'token=REDACTED' и grep по $COMPOSE logs web
```

## 12. Вердикт

Деплой головы после `T-105`/`R7b` на `153.51.172.30` **состоялся**: клон на `9e45679`, образы по
digest из прогона `45056081523` (коммит `68e4663`), слой `web` перекатан на
`sha256:0ffbebe4…5b24d` и находится в `Up (healthy)`, `postgres` и `caddy` не пересоздавались,
схема осталась `0004` (`migrate` не требовался), нарушений в журнале `web` нет. Неаутентифицированная
половина приёмки принята: `/invite` отвечает ответом раздела (`404`, страница, а не `422`), два
разных корректных значения ссылки дают идентичный ответ, `POST /invite` с формой учётную запись
не создаёт (`users = 0`), `GET /admin/users` без сеанса — редирект на вход по матрице допуска,
мутация без CSRF-токена — `403` телом `DENIAL_BODY`, значение ссылки отсутствует и в журнале
периметра (`token=REDACTED` при видимом пути), и в журнале приложения (`path` вместо URI,
`access_log=False`), а контрастная проба с не секретным ключом query показывает, что фильтр
точечный. Прежний набор образов и все тома сохранены, `ufw` не менялся, `docker system prune`
не выполнялся.

Что отложено осознанно: аутентифицированная половина §9 прежнего протокола — она выполняется
после `T-112` (завод первой учётной записи, решение заказчика ask `3f998543-38fd-479f-86d2-e77ab16d014f`).
Что требует решения заказчика (§10 п. 1 и 2): область действия фильтра вымаривания в `Caddyfile`
для обращений с `Host`, не совпадающим с именем сайта, и приводятся ли тексты отказа адреса
приёма ссылки к одному — обе правки означают отдельный срез (конфигурация периметра / слой
представления) и не выполнялись в этом.


## 13. Счётчики

Прогон `CI 45058207725` (голова `9e45679`): 1421 passed / 108 skipped, покрытие 93,54 %,
подавлений проверок 14 при базовом уровне 14 — то есть гейт `quality / suppress-growth` не
задет за срез; job `боевой состав: compose-overlay, digest, Caddyfile` — 14s.
Прогон `Image 45058207796` — 43s. Полный `pytest --cov` на dev-машине по этому срезу не
запускался: его делает CI, а правка среза — только `deploy/tbot.prod.env` и документы.

Локальные проверки по поводу пересъёмки дайджестов (`9ced14c`):

```text
pytest -q -p no:randomly tests/contract -k "vps or prod or compose"        32 passed
pytest -q -p no:randomly tests/integration/test_compose_prod_contract.py \
       tests/unit/test_prod_compose_check.py                               76 passed
ruff format --check .                                                     137 файлов
ruff check .                                                              чисто
scripts/count_suppressions.py                                             14 (база 14)
```

Сам `prod_compose_check.py` на dev-машине не запускается: ему нужен снимок
`docker compose config --format json`, без stdin-снимка он отдаёт rc=2
(«снимок разбора состава не прочитан»), поэтому проверка разбора сделана на площадке
(§3) и в job`е `боевой состав`. `scripts/deploy_check.py` дайджестов не проверяет — его
запуск по поводу пересъёмки ничего бы не добавил.
