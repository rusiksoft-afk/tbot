# Деплой на рабочую ВМ: порядок шагов (`T-712`, `T-713`, `ADR-001`, `ADR-003`)

Площадка одна и она боевая (`docs/adr/ADR-001-stand-is-prod-vm.md`), поэтому порядок здесь — часть
безопасности: сначала то, что можно проверить без запуска (разбор состава, digest, права секретов),
потом запуск одного среза (`postgres` + `web` + `caddy`), потом приёмок. Все команды — от `root`
через `sudo`: пользователь `rusiksoft` в группу `docker` не добавляется (`ADR-003 §3`).

Рабочий каталог: `/opt/tbot` (корень репозитория). Команды compose — из него же.

## 1. Готовность: что обязано быть зелёным до первого запуска

| # | Условие | Чем проверяется |
| --- | --- | --- |
| 1 | Площадка подготовлена (пакеты, время, диск, swap, сертификаты НУЦ) | `python3 scripts/prod_bootstrap_check.py` — `docs/acceptance/prod-bootstrap.md` |
| 2 | `ufw` = deny incoming + `22/tcp`, `80/tcp`, `443/tcp`, `443/udp` | `sudo ufw status verbose` — `docs/acceptance/prod-firewall.md` |
| 3 | Секреты лежат, права правильные | `sudo bash deploy/vps/secrets-setup.sh --check` — `docs/runbook/secrets-on-host.md §3` |
| 4 | Digest'ы в `deploy/tbot.prod.env` соответствуют последнему зелёному `Image` | `docs/runbook/ghcr-pull.md §2` |
| 5 | Разбор состава зелёный на **этой** машине (compose тут `2.40.3`, в CI `v5.1.3`) | шаги 3 и 4 ниже |
| 6 | Репозиторий разобран CI: `prod-config`, `compose-smoke`, `tests`, `quality` | `gh run list --repo rusiksoft-afk/tbot --branch main` |

Если пункт 3 или 4 красный — деплой не начинается: `up -d` с пустым секретом или без образа даёт не
ошибку подготовки, а полуживой контур.

## 2. Клон репозитория на площадку

Репозиторий приватный. Способ — SSH **deploy-key только на чтение**: свой ключ ВМ, без прав на
запись, без токена в URL (`https://<token>@github…` попал бы в `.git/config`, в argv и в логи).

```bash
sudo install -d -m 750 /opt/tbot
sudo ssh-keygen -t ed25519 -f /root/.ssh/tbot_deploy_key -N '' -C 'deploy-key/tbot-vm-2026-11-20'  # уже создан 2026-11-20 — не пересоздавать
sudo cat /root/.ssh/tbot_deploy_key.pub          # публичная часть — не секрет
# владелец репозитория добавляет её: Settings → Deploy keys → Add (не ставить write access)
sudo sh -c 'ssh-keyscan -t ed25519 github.com >> /root/.ssh/known_hosts'
sudo git clone git@github.com:rusiksoft-afk/tbot.git /opt/tbot
cd /opt/tbot && git log --oneline -1
```

**Статус на 2026-11-20:** ключ уже создан на ВМ (`/root/.ssh/tbot_deploy_key` 600 root:root,
`.pub` 644), пересоздавать его нельзя — публичная часть будет добавлена заказчиком как deploy key
и повторная генерация рассинхронизирует её с GitHub. Замеренные значения:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINLDO6mbx5f5R1gtTC3wqbVygUWDXHuUpMnRbKGe7MpX deploy-key/tbot-vm-2026-11-20
отпечаток: SHA256:bYb6ZnLlpjbjQoAG3GomNid/zWuRgL0yXvr8N6KVYxI
```

`known_hosts` для github.com на ВМ **нет** — перед клоном нужен `ssh-keyscan` (или `ssh -o
StrictHostKeyChecking=accept-new`), иначе `git clone` спросит подтверждение ключа хоста в
неинтерактивном прогоне и упадёт.

Проверка, что клон соответствует ожидаемому commit: хеш из `git log --oneline -1` обязан совпадать
с commit, из которого собраны digest'ы в `deploy/tbot.prod.env` (иначе на площадку поедет чужой
конфиг при своих образах).

Ситуация, которая возникла прямо сейчас: HEAD `main` ушёл вперёд (`d2a19fc` — правки только
документов и `deploy/tbot.prod.env`), а закреплённый набор собран из `b235d29`. Прямой проверки
«хеш == commit дайджестов» для этого не выдерживает, и правильно поступить не «закрывать глаза», а
сделать пересъёмку наборa прямо перед деплоем одним коммитом (`docs/runbook/ghcr-pull.md §2`):
клон обновляется до этого коммита, и дальше хеш снова обязан совпадать. Если пересъёмка уже
сделана и с неё не менялся код (`apps/`, `packages/`, `deploy/Dockerfile`, `pyproject.toml`,
`deploy/compose*.yaml`), деплоить можно и предыдущий закреплённый набор — он собирается из того же
кода, просто с другими метками слоёв.

## 3. Разбор состава на площадке (без запуска)

```bash
cd /opt/tbot
sudo docker compose version
sudo docker compose -f deploy/compose.yaml -f deploy/compose.prod.yaml \
  --env-file deploy/tbot.prod.env config --quiet
sudo docker compose -f deploy/compose.yaml -f deploy/compose.prod.yaml \
  --env-file deploy/tbot.prod.env config --format json | python3 scripts/prod_compose_check.py
```

`config --quiet` — проверка, что overlay в этой версии compose сливается вообще; вторая команда —
13 проверок разобранной модели (поры, digest, сети, секреты, лимиты, `read_only`). Ожидается
`OK` по всем строкам и код возврата `0`; при `FAIL` деплой останавливается, а вывод
`docker compose config` без `--quiet` прикладывается к разбору.

Проверка перед запуском обязательна именно на площадке: CI проверяет разбор своей версией compose,
а правила слияния overlay между версиями различаются (`docs/acceptance/tls-edge.md §5`).

## 4. Образы: вход в реестр и pull по digest

Логин через stdin: значение не попадает ни в argv, ни в историю, ни в лог
(`docs/runbook/secrets-on-host.md`).

```bash
sudo docker login ghcr.io --username <логин_владельца_токена> \
  --password-stdin < /etc/tbot/secrets/ghcr_token
sudo docker compose -f deploy/compose.yaml -f deploy/compose.prod.yaml \
  --env-file deploy/tbot.prod.env pull
sudo docker images --digests | grep -E 'tbot|postgres|caddy'
```

`<логин_владельца_токена>` — имя учётной записи, выпустившей токен (для пакетов организации токен
участника работает с **своим** логином, а не с именем организации). Собранный набор digest обязан
совпасть со значениями в `deploy/tbot.prod.env` — это и есть доказательство, что на площадку
приехали те же образы, что проверял CI.

Свободное место перед pull: `df -h /var/lib/docker` — не меньше 15 ГиБ свободных (два набора
образов нужны одновременно: откат по digest, `ADR-002`).

## 5. Миграция, затем запуск первого среза

```bash
cd /opt/tbot
COMPOSE="sudo docker compose -f deploy/compose.yaml -f deploy/compose.prod.yaml --env-file deploy/tbot.prod.env"
$COMPOSE up -d postgres
$COMPOSE ps postgres                      # ждать healthy, не up
$COMPOSE run --rm migrate                 # alembic upgrade head
$COMPOSE up -d web caddy
$COMPOSE ps
```

Порядок не косметический: `migrate` до `web` иначе первая же миграция накладывается поверх
одновременного старта панели, а `caddy` последним — выпуск сертификата Let's Encrypt идёт через
`http://tbot.rusiksoft.ru/.well-known/acme-challenge/`, и порт 80 обязан отвечать уже после старта.

Первый выпуск сертификата — отдельная точка риска: у Let's Encrypt лимит 5 выпусков на домен в
неделю, а сертификат живёт в томе `caddy_data`. Прежде чем удалять том, см. `ADR-002` и
`docs/acceptance/tls-edge.md`.

`engine`, `jobs` и `tgbot` в этот срез не входят: контуры `paper`/`production` включаются отдельно
(`TBOT_CONTOUR`, `TBOT_CONFIRM_PRODUCTION`), торговля — только после приёмки периметра (§14 TZ).

## 6. Приёмка периметра и TLS (снаружи, с dev-машины)

```bash
curl -sSI https://tbot.rusiksoft.ru/healthz
curl -sS -o /dev/null -w '%{http_code} -> %{redirect_url}\n' http://tbot.rusiksoft.ru/
openssl s_client -connect 153.51.172.30:443 -servername tbot.rusiksoft.ru -tls1_2 </dev/null
openssl s_client -connect 153.51.172.30:443 -servername tbot.rusiksoft.ru -tls1_1 </dev/null   # обязан отказать
sudo ss -lntp 'sport = :80 or sport = :443'      # на площадке: слушатель только у docker-proxy
```

Ожидаемый набор заголовков на `https`-ответе: `strict-transport-security: max-age=63072000;
includeSubDomains`, CSP из TZ §8.3, `x-content-type-options: nosniff`, `x-frame-options: DENY`,
`referrer-policy: same-origin`, `permissions-policy`, `cache-control: no-store`; заголовка `Server`
нет. Редирект с `http` — `308` на `https` (не `301`: метод и тело обязаны сохраниться).

Сертификат: выпускатель `Let's Encrypt`, SAN ровно `tbot.rusiksoft.ru`:

```bash
echo | openssl s_client -connect 153.51.172.30:443 -servername tbot.rusiksoft.ru 2>/dev/null \
  | openssl x509 -noout -issuer -subject -ext subjectAltName -dates
```

HTTP/3 (после того как `443/udp` подтверждён в SG и `ufw`, `ADR-003 §5`):

```bash
curl -sSI --http3 https://tbot.rusiksoft.ru/healthz     # нужен curl с nghttp3
```

Если `curl` без HTTP/3, достаточным доказательством остаётся счётчик правила `ufw`
(`docs/acceptance/tls-edge.md §3.6`).

Журнал прокси: `sudo docker logs caddy` — в строках доступа query-параметры `token`, `key`, `sig` и
заголовок `X-Api-Key` обязаны быть `REDACTED` (TZ §8.4). Проверить можно на своём же запросе с
фиктивным токеном в query: значение в логе найтись не должно.

## 7. Устойчивость и откат

- `sudo systemctl restart docker` (требует согласия оператора: контейнеры перезапустятся) — состав
  обязан подняться сам (`restart: always`), том `caddy_data` переживает перезапуск, сертификат
  остаётся.
- Ребут ВМ — только по отдельному согласованию (учения §13.5 TZ): проверить после ребута
  `sudo docker compose ... ps`, наличие слушателя на 80/443, выпуск сертификата не требуется заново.
- Откат по версии: в `deploy/tbot.prod.env` предыдущий набор digest лежит в истории git
  (`docs/runbook/ghcr-pull.md §2`), откат =checkout этих значений + `pull` + `up -d` (RTO ≤5 мин
  по `ADR-002`). Данные при этом не трогаются: том `pgdata` не удаляется ни при каком откате.
- Полная остановка контура: `$COMPOSE down` (без `-v`: `-v` удаляет тома, включая `pgdata`).

## 8. Известная особенность `scripts/deploy_check.py` на хосте

`check_secret_files` ищет в каталоге секретов имена **конфигурации** — `tg_bot_token`,
`tg_socks_password`, `db_url`, а на площадке файлы называются по TZ §14.3: `telegram_token`,
`telegram_socks_pass`, `db_url`. Поэтому запуск на хосте

```bash
sudo TBOT_SECRETS_DIR=/etc/tbot/secrets python3 scripts/deploy_check.py
```

даёт красный `secret_files: tg_bot_token: файла нет; tg_socks_password: файла нет` при полностью
готовой площадке. Это не ошибка подготовки и не повод создавать в `/etc/tbot/secrets` файлы с
именами из конфигурации — имена задаёт `deploy/compose.prod.yaml`. Задача на исправление проверки
именована в `tasks/todo.md` (`T-712`); до неё готовность секретов доказывается `--check` из
`docs/runbook/secrets-on-host.md §3` и зелёным `docker compose config`.
