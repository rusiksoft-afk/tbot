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
# Ключ назван НЕ id_ed25519 — ssh сам его не предложит (он перебирает только id_*), поэтому
# путь обязан быть указан явно и для проверки, и для клона:
KEYOPTS="-o IdentitiesOnly=yes -o BatchMode=yes -i /root/.ssh/tbot_deploy_key"
sudo ssh $KEYOPTS -T git@github.com        # ожидание: Hi rusiksoft-afk/tbot! …
sudo GIT_SSH_COMMAND="ssh $KEYOPTS -o StrictHostKeyChecking=accept-new" \
  git clone git@github.com:rusiksoft-afk/tbot.git /opt/tbot
cd /opt/tbot && git log --oneline -1
```

**Статус на 2026-11-20:** ключ уже создан на ВМ (`/root/.ssh/tbot_deploy_key` 600 root:root,
`.pub` 644), пересоздавать его нельзя — публичная часть будет добавлена заказчиком как deploy key
и повторная генерация рассинхронизирует её с GitHub. Замеренные значения:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINLDO6mbx5f5R1gtTC3wqbVygUWDXHuUpMnRbKGe7MpX deploy-key/tbot-vm-2026-11-20
отпечаток: SHA256:bYb6ZnLlpjbjQoAG3GomNid/zWuRgL0yXvr8N6KVYxI
```

`known_hosts` для `github.com` на ВМ **уже есть** — запись добавлена probe-сеансом 2026-11-20 с
`StrictHostKeyChecking=accept-new`. До этого её не было, и это была реальная причина падения
неинтерактивного клона: `git` спрашивает подтверждение ключа хоста и в неинтерактивном прогоне
отказывается. Если ключ хоста в известном каталоге появится другим (смена балансировщика GitHub),
клон упадёт с `HOST KEY CHANGE` — править запись надо вручную, а не «принимать снова вслепую».

**Замер 2026-11-20 14:05:** deploy key добавлен заказчиком и **работает** — но только при явном
`-i /root/.ssh/tbot_deploy_key -o IdentitiesOnly=yes`: без них ssh предлагает только
`/root/.ssh/id_*` (их нет) и отвечает `Permission denied (publickey)`. Первая проба без
ключей дала ложный вывод «ключ не добавлен» — это ловушка, а не состояние площадки. Порядок на этом этапе: заказчик добавляет
публичную часть как read-only deploy key → агент делает `sudo git clone` и дальше идёт по
ранбуку. Секретов на площадке тоже ещё нет (`--check` красный по четырём файлам), но скрипт
ввода уже лежит на ВМ как `/tmp/secrets-setup.sh` с совпадающей контрольной суммой
(`sha256:89005d59c960c1733b3b5dc14512bef6927443414552d30f4c98791013e3370b`), так что секреты
можно завести до клона.

**Замер 2026-11-20 14:23 UTC:** клон подтянут до `f67ab76` (`sudo git -C /opt/tbot pull --ff-only`,
дерево чистое; команда в скобках неполная — `pull` требует явного ключа, см. абзац ниже). Грабля, из-за которой первая попытка выглядела как «репозиторий сломан»:
`/opt/tbot` — 750 `root:root`, и под `rusiksoft` в него нельзя войти: `cd /opt/tbot` →
`Permission denied`, а следом `git` отвечает `not a git repository`. Правильный порядок для
не-root-сессии: `sudo git -C /opt/tbot …` и абсолютные пути ко всем файлам (`sudo bash
/opt/tbot/deploy/vps/secrets-setup.sh`, `sudo python3 /opt/tbot/scripts/…`). Git-операции на ВМ требуют того же ключа, что и клон: `sudo git -C /opt/tbot -c core.sshCommand="ssh -o
IdentitiesOnly=yes -i /root/.ssh/tbot_deploy_key" pull --ff-only` — замер 2026-11-20 15:10 UTC:
без `-c core.sshCommand` `pull` отвечает `git@github.com: Permission denied (publickey)`,
потому что в `/root/.ssh` нет `config` и ключ по умолчанию не предлагается.
`sha256sum` скрипта ввода на ВМ — `b8266865bcb5f0672224c8a4589af114f767cfa1b6afcd9b95457bed52f9191f`,
совпадает с репозиторной версией. После правки заголовка скрипта по ADR-004 (2026-11-20, только
комментарии) репозиторная версия — `5499b18679ea466aab06f23322beb17bb30dff8cff44dfcfa57adb04f7fe7f35`:
перед сверкой нужен `sudo git -C /opt/tbot -c core.sshCommand="ssh -o IdentitiesOnly=yes -i
/root/.ssh/tbot_deploy_key" pull --ff-only`.
**Замер 2026-11-20 15:10 UTC:** клон подтянут до `4f837b0`; `sha256sum` скрипта на ВМ =
`5499b18679ea466aab06f23322beb17bb30dff8cff44dfcfa57adb04f7fe7f35` — совпал с репозиторной
версией после правки заголовка по ADR-004; `--check` уже на новой версии скрипта: четыре `OK`
(`db_password` 48, `db_url` 93, `telegram_token` 46, `telegram_socks_pass` 24) и `FAIL`
по `ghcr_token`, код 1; `prod_bootstrap_check.py` → `ГОТОВО` (диск 71.03 ГиБ, свободно
63.66 ГиБ). CI на `4f837b0` — 9 job'ов `success` (run 44760258594), включая `gitleaks`.

**Актуальный `sha256sum` скрипта ввода (2026-11-20, ADR-005):**
`ee9c4b208380a67b2c89b43a5397aa5712ba4f3a075f6423e3b8fc8b8359b610` — в скрипте появились политика
прав (`CONTAINER_GID`, `apply_policy`) и режим `--remed`. Прежние значения (`b8266865…9191f` и
`5499b18679…fe7f35`) остаются в тексте как история: сверять надо актуальное, и для этого клон
обязан быть подтянут (`git pull` с явным deploy-ключом, выше).

Проверка, что клон соответствует ожидаемому commit: хеш из `git log --oneline -1` обязан совпадать
с commit, из которого собраны digest'ы в `deploy/tbot.prod.env` (иначе на площадку поедет чужой
конфиг при своих образах). Разрешённое исключение замерено 2026-11-20 14:21 UTC: набор собран из
`1ce4be6`, клон — `f67ab76`, а `git diff --name-only 1ce4be6..f67ab76` даёт только `.github`,
`deploy/tbot.prod.env`, `deploy/vps/secrets-setup.sh`, `scripts/deploy_check.py`, тесты и
документы — ни одного пути из перечня ниже, значит образы собирались из того же кода.

Если пересъёмка не делана, а различия затрагивают `apps/`, `packages/`, `deploy/Dockerfile`,
`pyproject.toml`, `deploy/compose*.yaml`, `deploy/caddy/Caddyfile` или `deploy/postgres/tbot.conf`,
деплоить такой набор нельзя: нужна пересъёмка digest'ов прямо перед деплоем.

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

**Замер 2026-11-20 14:10 (compose площадки 2.40.3):** этот шаг проходит с exit 0 и 13/13
замечаний нет даже тогда, когда `/etc/tbot/secrets` пуст. У compose v5.1.3 (CI-раннёр) поведение
другое — там `config` требует существования файлов, и в job `prod-config` создаются пустышки.
Значит зелёный `config` на площадке не заменяет проверку секретов: перед `up` обязателен
`sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --check` — с 2026-11-20 он отвечает и за форму
значений, и за пятый файл состава (`telegram_socks_pass`). Копию скрипта в `/tmp` использовать
нельзя: она старше репозитория и принимает значения любой формы (замер sha256
`89005d59…3370b` против `b8266865…9191f` в репозитории).

**Переснято 2026-11-20 14:22 UTC на HEAD `f67ab76`** (compose тот же — 2.40.3): `config --quiet` →
exit 0, `config --format json | python3 scripts/prod_compose_check.py` → 13/13 `OK`,
«ГОТОВО: боевой состав разобран без замечаний». Там же ещё раз подтверждён пункт 1 готовности:
`sudo python3 /opt/tbot/scripts/prod_bootstrap_check.py` → `ГОТОВО`, exit 0, `clock_offset`
0.000068 с. Отдельная грабля этого пункта: снимок `chronyc tracking` нельзя сохранять под
фиксированным именем `/tmp/chrony-tracking.txt` — если такой файл остался от прошлого замера,
`sudo tee` его не перезапишет, и проверка часов молча прочитает **старый** снимок (первый прогон
dал 0.001092 с именно так). Имя снимка — уникальное, например `/tmp/tbot-chrony-$(date +%s).txt`.
А вот `--check` по тому же каталогу секретов красный: четыре `FAIL` (три значения не по форме,
нет `telegram_token`) и один `OK` (`telegram_socks_pass`), код 1. При красном `--check` ранбук
останавливается здесь, а не на §5: `up` с мусорным `db_url` даёт полуживой контур вместо
отказа подготовки.

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

**До первой команды раздела — привести права файлов секретов (ADR-005).** Если каталог создан до
2026-11-20, все файлы лежат в `600 root:root`, и процесс контейнера под `uid/gid 10001` свои секреты
не прочитает: первый `run --rm migrate` даёт `PermissionError: [Errno 13] Permission denied:
'/run/secrets/db_url'` при полностью зелёном `--check`. Приводка прав ничего не меняет в значениях:

```bash
sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --remed
sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --check
```

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

**`up -d postgres` нельзя делать раньше финальных секретов.** compose передаёт базе
`POSTGRES_PASSWORD_FILE: /run/secrets/db_password` (`deploy/compose.yaml`, сервис `postgres`), а
образ читает этот файл только при `initdb` — пароль роли остаётся в томе `pgdata` навсегда.
Поднять базу с негодным паролем, а потом перезалить `db_password` — значит получить `migrate` с
отказом аутентификации; правка файла секрета ничего не меняет, а единственный ремонт — новый том,
то есть потеря данных. Поэтому `--check` (§3) обязан быть зелёным до первой команды этого раздела,
а проверку «состав поднимается после `systemctl restart docker`» делают уже на рабочей базе.

Первый выпуск сертификата — отдельная точка риска: у Let's Encrypt лимит 5 выпусков на домен в
неделю, а сертификат живёт в томе `caddy_data`. Прежде чем удалять том, см. `ADR-002` и
`docs/acceptance/tls-edge.md`.

**Контур первого среза — `sandbox`** (замер на площадке 2026-11-20 14:29 UTC, compose 2.40.3 с
`--env-file deploy/tbot.prod.env`): разобранный состав подставляет всем процессам
`TBOT_CONTOUR: sandbox` и `TBOT_CONFIRM_PRODUCTION: "false"`, потому что в
`deploy/tbot.prod.env` этих переменных нет, а `deploy/compose.prod.yaml` задаёт их как
`${TBOT_CONTOUR:-sandbox}` и `${TBOT_CONFIRM_PRODUCTION:-false}`. Следствия: (1) требование
TZ §14.7 шаг 3 — бэкапы и WAL-архив (T-702) до первого **боевого** запуска — этот срез не
блокирует, но и торговать он не будет: это панель, база и прокси; (2) включение `paper` или
`production` — отдельный шаг с явным `TBOT_CONTOUR` в env-файле, а для `production` ещё
`TBOT_CONFIRM_PRODUCTION=true` и закрытая T-702, иначе `check_contour` в образе не пропустит старт.

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

HTTP/3 (после того как `443/udp` подтверждён в SG и `ufw`, `ADR-003 §5`). Доказательство — живой
UDP-слушатель, а не заголовок `Alt-Svc`: `Alt-Svc` появляется и тогда, когда QUIC никто не слушает
(так и было на площадке до `ba6d687`, см. §11). `curl` без nghttp3 здесь бесполезен, поэтому проба —
QUIC Initial с заведомо неизвестным version: сервер обязан ответить Version Negotiation.

```bash
# площадка: слушатель обязан быть и v4, и v6
sudo ss -lntup | grep ':443'          # нужен и tcp, и udp
# dev-машина (любой python, без nghttp3): ждём ~35-байтный ответ с version_field=0
.venv/Scripts/python.exe - <<'PY'
import socket, os
dcid, scid = os.urandom(8), os.urandom(8)
pkt = bytearray([0xC0]) + (0x0a0a0a0a).to_bytes(4, 'big')
pkt += bytes([8]) + dcid + bytes([8]) + scid + b'\x00\x00\x00\x00' + os.urandom(1179)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(bytes(pkt), ('153.51.172.30', 443))
try:
    d, _ = s.recvfrom(4096)
    print('quic_reply=', len(d), 'VN=', int.from_bytes(d[1:5], 'big') == 0)
except Exception as e:
    print('quic_reply=FAIL', type(e).__name__)   # ConnectionResetError = UDP/443 не публикуется
PY
# альтернатива, если curl собран с HTTP/3:
curl -sSI --http3 https://tbot.rusiksoft.ru/healthz
```

Замер 2026-11-20 16:41 UTC: `quic_reply= 35 VN= True`; до исправления публикации —
`ConnectionResetError` (ICMP port unreachable).

Журнал прокси: `sudo docker logs tbot-caddy-1` (имя контейнера на площадке — с префиксом состава,
просто `caddy` его не находит) — в строках доступа query-параметры `token`, `key`, `sig` и
заголовок `X-Api-Key` обязаны быть `REDACTED` (TZ §8.4). Проверить можно на своём же запросе с
фиктивным токеном в query: значение в логе найтись не должно.

## 7. Устойчивость и откат

- **Список сервисов в `up` — обязателен.** Голый `docker compose … up -d` поднимает **весь** состав,
  включая `engine`, `jobs` и `tgbot`. Замер 2026-11-20 16:56 UTC: после `down` + `up -d` без списка
  сервисов `engine` и `jobs` оказались `healthy` (без секретов брокера они просто работают
  вхолостую, и это выглядит как успех), а `tgbot` ушёл в цикл рестартов из-за дефекта SOCKS-схемы
  (`docs/acceptance/tg-egress.md §4.1`). Первый срез — `up -d postgres`, потом `run --rm migrate`,
  потом `up -d web caddy`; остальные сервисы поднимаются только по своим задачам (`T-009`/`M1`,
  `T-714`) и после их приёмки.
- Замер RTO на известном хорошем наборе digest (`down` без `-v` → `up -d` → все `healthy`):
  `down_seconds=2`, `up_to_healthy_seconds=16`, `total_rto_seconds=18` — в пределах заявленных
  в `ADR-002` ≤5 мин. Том `tbot_pgdata` переживает `down` (он и после `down` в списке томов),
  `-v` не используется никогда: он удаляет тома, включая базу.
- `sudo systemctl restart docker` (требует согласия оператора: контейнеры перезапустятся) — состав
  обязан подняться сам (`restart: always`), том `caddy_data` переживает перезапуск, сертификат
  остаётся. Замер 2026-11-20 16:41 UTC: три контейнера `healthy` через 6 с, `notBefore` сертификата
  не изменился (повторного выпуска ACME не было, лимит не потрачен).
- Ребут ВМ — только по отдельному согласованию (учения §13.5 TZ). Выполнен 2026-11-20 17:09:54 UTC в
  согласованном окне (ask `5087f489`): загрузка в 17:10:33, ssh доступен в 17:10:55, простой наружного
  HTTPS ≈60 с. `docker.service` `enabled` и `restart: always` сделали своё: состав поднялся сам, `web`
  и `caddy` стали `healthy` без ручных команд, `notBefore` сертификата не изменился (ACME не
  перевыпускался), тома целы, `tbot-tunnel` `active`. Проверить после ребута
  `sudo docker compose ... ps`, наличие слушателя на 80/443 (и udp — §11), выпуск сертификата не
  требуется заново.
- **`stop` не переживает перезапуск docker и ребут:** контейнеры с `restart: always` поднимаются снова.
  После ребута 17:10 `engine`/`jobs`/`tgbot`, остановленные ранее через `compose stop`, снова работали
  (а `tgbot` — в цикле рестартов, §4.1 приёмки `tg-egress`). Если часть состава ещё не принята, её надо
  убирать (`compose rm -f -s engine jobs tgbot`), а не останавливать: убранные контейнеры не вернутся
  до следующего `up -d`.
- Границу TLS нельзя проверять «просто» `openssl s_client -tls1_1`: клиент OpenSSL 3.x отказывает сам
  (`no protocols available`), и проверка становится ложно-зелёной. Способ с `OPENSSL_CONF` — в
  `docs/acceptance/tls-edge.md §9.2`.
- Откат по версии: в `deploy/tbot.prod.env` предыдущий набор digest лежит в истории git
  (`docs/runbook/ghcr-pull.md §2`), откат = checkout этих значений + `pull` + `up -d` (RTO ≤5 мин
  по `ADR-002`). Данные при этом не трогаются: том `pgdata` не удаляется ни при каком откате.
- **Важно про цель отката (замер 2026-11-20 16:55 UTC).** Проба предыдущего набора digest
  (`1ce4be6`, Image run 44721673799) через `docker compose run` с подменой образа `web`: контейнер
  стартует, `/healthz` отвечает `200`, но `/readyz` — `503` с `postgres недоступен:
  ProgrammingError` (дефект формы DSN, исправленный только в `d35f957`), то есть healthcheck не
  проходит и `caddy` по `depends_on` не поднимется. Ретроспектива по git: `check_database` с прямым
  `psycopg.connect` есть с самого каркаса `9f55120`, значит **любой** набор digest до `d35f957`
  непригоден как цель отката на текущей площадке. Практический вывод: цель отката — последний
  заведомо рабочий набор, а не «предыдущий в истории»; учебный кросс-версионный откат становится
  возможным только тогда, когда появится второй рабочий набор (после следующего изменения кода), и
  именно тогда его надо выполнить.
- Полная остановка контура: `$COMPOSE down` (без `-v`: `-v` удаляет тома, включая `pgdata`).

## 8. Имена файлов секретов в `scripts/deploy_check.py`

Раньше `check_secret_files` искал в каталоге секретов имена **конфигурации** — `tg_bot_token`,
`tg_socks_password`, `db_url`, — а на площадке файлы названы по `deploy/compose.prod.yaml`:
`telegram_token`, `telegram_socks_pass`, `db_url`. Запуск на хосте давал красный
`secret_files: tg_bot_token: файла нет; tg_socks_password: файла нет` при полностью готовой
площадке. Это не ошибка подготовки и не повод создавать в `/etc/tbot/secrets` файлы с именами из
конфигурации.

Исправлено 2026-11-20 вместе с замером на площадке: в `scripts/deploy_check.py` появились слоты
`SECRET_SLOTS` — логический секрет, его допустимые имена (хостовое первым, имя конфигурации как
альтернатива для dev-стенда) и обязан ли он существовать в этом контуре. Боевой контур требует
`db_password`, `db_url`, `telegram_token`, `telegram_socks_pass` и `ghcr_token`; не-боевые контуры
принимают и имена конфигурации, а `ghcr_token` не требуют. Отдельная проверка `secret_shapes`
сверяет **форму** значений, печатая только имя файла, длину и подсказку формата.

Какое именно имя закрывает слот, решает `slot_names(slot, settings)`, а не порядок в кортеже:
в боевом контуре принимается только хостовое имя, а `slot_foreign_names` добавляет отдельную
претензию на лишний файл (`tg_bot_token: файл с именем контейнера, а не хоста — этот контур читает
telegram_token (deploy/compose.prod.yaml)`). Прежняя подсказка «допустимые имена: telegram_token,
tg_bot_token» звала создать в `/etc/tbot/secrets` файл, который compose не прочитает, и из-за того
же перебора обоих имён боевой контур считался готовым там, где лежали только имена конфигурации.
`secret_shapes` читает то же имя, что и проверка наличия. Это десятый случай болезни «шаг
выполняется, но проверяет не то» и первый, пойманный CI, а не dev-машиной: POSIX-ветки тестов на
Windows пропускаются (прогон `44746558946`, разбор — `docs/HANDOFF.md §1.12`).

Проверить форму на хосте можно и без python-окружения приложения — `--check` из
`docs/runbook/secrets-on-host.md §3` делает то же самое на чистом bash. `deploy-check`
(`make deploy-check`, в CI — шаг с `python scripts/deploy_check.py --json`) остаётся машиной
разработчика и CI: ему нужны зависимости приложения, которых на площадке нет.

## 9. Секрет примонтирован, но не читается: `600 root:root` + `USER 10001` (ADR-005)

Симптом: `migrate` падает с `PermissionError: [Errno 13] Permission denied: '/run/secrets/db_url'`,
при этом `--check` зелёный, состав разобран без замечаний, а файл секрета на месте. Разбор и
замеры — `docs/adr/ADR-005-secret-file-modes-for-container-readability.md`; коротко: bind-маунт
приносит хозяйские права, процесс в образе non-root (`USER 10001:10001`), а compose 2.40.3 не
принимает `uid`/`gid`/`mode` у file-секретов. Лечение на площадке — `secrets-setup.sh --remed`
(права: `640` + группа с `gid 10001` для монтируемых файлов, `600 root:root` для `ghcr_token`).
Попытка «просто сделать 644» запрещена политикой: файл секретов не обязан читаться локальными
пользователями. Проверка, что `CONTAINER_GID` в скрипте и числовая `USER` в `deploy/Dockerfile`
совпадают, закреплена контрактом `test_права_монтируемых_секретов_совпадают_с_gid_процесса_в_образе`;
факт чтения изнутри контейнера в CI проверяется задачей T-715.

## 10. `web` unhealthy, `caddy` не стартует: форма DSN и прямое подключение psycopg3

Симптом: `up -d web caddy` отвечает `dependency failed to start: container tbot-web-1 is
unhealthy`, в журнале healthcheck'а — `FAIL http://127.0.0.1:8080/readyz status=503
…"postgres недоступен: ProgrammingError"`, при этом uvicorn запущен и слушает 8080, а база
`healthy` и миграции применены.

Диагностика без вывода значения (DSN читается из секрета внутри контейнера, в вывод идут только
схема, тип ошибки и длина):

```bash
sudo sh -c "cd /opt/tbot && docker compose -f deploy/compose.yaml -f deploy/compose.prod.yaml \
  --env-file deploy/tbot.prod.env run --rm --no-deps --entrypoint python web - <<'PY' | \
  sed -E 's#(://[A-Za-z0-9_]+:)[^@[:space:]]+@#\1***@#g'
import pathlib, psycopg
dsn = pathlib.Path('/run/secrets/db_url').read_text(encoding='utf-8').strip()
print('scheme=', dsn.split('://', 1)[0], 'len=', len(dsn))
try:
    psycopg.conninfo.make_conninfo(dsn)
    print('conninfo=OK')
except Exception as exc:
    print('conninfo=FAIL', type(exc).__name__)
PY"
```

Что это значит: psycopg3 собственный парсер conninfo **не принимает** диалектную приставку, в
которой проект хранит адрес (`postgresql+psycopg://`, TZ §14.9) — ошибка
`missing "=" after "postgresql+psycopg://…" in connection info string`. Alembic и SQLAlchemy этой
проблемы не видят (для них существует `sqlalchemy_url`), а прямые подключения — `check_database` в
`apps/web/main.py` (проба `/readyz`, на которой держится healthcheck и, через `depends_on`, старт
`caddy`) и `database`-проба в `scripts/deploy_check.py` — обязаны проходить через
`packages.common.db.psycopg_dsn`. Проверено на площадке и на dev-машине с одним и тем же
пиннингом (`psycopg 3.2.13`), то есть к подготовке ВМ это отношения не имеет.

Ремонт — только через пересъёмку образов: `Image` workflow собирает образы на push в `main`, затем
`deploy/tbot.prod.env` получает новые digest'ы (пара «прогон → коммит», `AGENTS.md`), и только
потом `pull` и `up -d web caddy` на площадке. Правка «на живую» (пересборка образа руками на ВМ)
ломает прослеживаемость деплоя и приёмку по digest — так делать нельзя.

## 11. `Alt-Svc: h3` при отсутствующем UDP-слушателе: публикация `443:443/udp` (2026-11-20)

Симптом: в ответе есть `Alt-Svc: h3=":443"; ma=2592000`, `ufw` пропускает `443/udp`, в Caddyfile —
`protocols h1 h2 h3`, и при этом probe на UDP/443 получает ICMP port unreachable
(`ConnectionResetError`), а `sudo ss -lntup` не показывает ни одного udp-слушателя на 443. Браузер
после первого визита получает `Alt-Svc`, уходит в QUIC и получает тайм-аут: часть клиентов видит
нерабочий сайт при полностью «зелёной» приёмке tcp.

Причина: Docker публикует UDP **только отдельной строкой** с суффиксом `/udp`. Строка `"443:443"`
публикует tcp; UDP-публикации нет — значит docker-proxy не поднимает udp, хотя внутри контейнера
Caddy QUIC слушает. Проверки, которые это пропускали: `docker compose config --quiet` (конфиг
валиден), `prod_compose_check.py` (до `ba6d687` сводил публикации к паре `хостовый:контейнерный` без
протокола, поэтому `{80:80, 443:443}` совпадало с ожидаемым), контрактный тест `h3 ↔ ufw` (он сверяет
Caddyfile и `ufw.rules`, а не публикации) и `--check` секретов (к портам отношения не имеет).

Лечение: в `deploy/compose.prod.yaml` у `caddy` рядом с tcp-строками обязано стоять `"443:443/udp"`;
`scripts/prod_compose_check.py` требует `{80:80/tcp, 443:443/tcp, 443:443/udp}` и различает протоколы
в обеих формах записи портов; контракт `h3 ↔ ufw` дополнен проверкой публикации
(`tests/integration/test_compose_prod_contract.py`). После правки — `up -d caddy` и повторная проба
из §6 (`ss -lntup` + QUIC Version Negotiation). На площадке проба после исправления: udp 443 (v4/v6)
в `ss`, `quic_reply= 35 VN= True`.

Общий вывод для будущих проверок периметра: заголовок, правило файрвола и конфиг приложения — это
обещание транспорта; слушатель на хосте проверяется отдельной командой (`ss -lntup`, а не `ss -lntp`).
