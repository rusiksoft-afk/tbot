"""Эксплуатационные заметки по стенду и площадке (TZ §14).

Каталоги и файлы

- `compose.yaml` — базовая конфигурация: сети (backend — только внутренняя, egress — единственная
  с выходом наружу), healthchecks, ограничения CPU/памяти, монтирование секретов read-only;
- `compose.override.yaml` — локальные дополнения dev-стенда (публикация портов на loopback,
  dev-секреты);
- `postgres/tbot.conf` — параметры PostgreSQL под ограничения площадки (OQ-11);
- `ca/` — корневой сертификат НУЦ Минцифры (T-709) и порядок его проверки;
- `Dockerfile` — единый образ четырёх процессов, непривилегированный пользователь.

Секреты

Пути секретов в `compose.yaml` разрешаются относительно `deploy/compose.yaml`, поэтому каталог
лежит в `deploy/secrets/` и намеренно в `.gitignore`. Для dev-стенда:

```bash
mkdir -p deploy/secrets
printf 'dev-db-password'            > deploy/secrets/db_password
printf 'postgresql://tbot:dev-db-password@postgres:5432/tbot' > deploy/secrets/db_url
printf 'dev-not-a-real-token'       > deploy/secrets/tg_bot_token
printf 'dev-not-a-real-password'    > deploy/secrets/tg_socks_password
chmod 600 deploy/secrets/*
```

Имена файлов совпадают с именами полей конфигурации: приложение читает их из каталога
`TBOT_SECRETS_DIR` (в контейнере — `/run/secrets`). Файлы с учётными данными брокера и токен
боевого бота в этот каталог не кладутся: они существуют только на площадке
(`/etc/tbot/secrets`, права `600`).

На площадке имена другие — их задаёт `deploy/compose.prod.yaml` в секции `secrets:`:
`db_password`, `db_url`, `telegram_token`, `telegram_socks_pass` (плюс хостовый `ghcr_token`,
который в контейнеры не монтируется). Значения кладёт только заказчик — скриптом
`vps/secrets-setup.sh`, а готовность проверяется без содержимого: `sudo bash
vps/secrets-setup.sh --check` (`docs/runbook/secrets-on-host.md`). Путать два набора имён
нельзя: в `/etc/tbot/secrets` файлы с именами `tg_bot_token`/`tg_socks_password` создавать не нужно.

Запуск dev-стенда

```bash
docker compose -f deploy/compose.yaml -f deploy/compose.override.yaml up -d --build
docker compose -f deploy/compose.yaml -f deploy/compose.override.yaml run --rm migrate
curl -sS localhost:8080/readyz      # web: ready
curl -sS localhost:8080/metrics | head -20
```

Проверка, что у базы нет исходящего трафика (приёмка T-005)

В образе postgres нет `python3`, поэтому проба — на bash (`/dev/tcp` — встроенная
возможность bash, образ собран на debian-slim, где bash есть):

```bash
docker compose -f deploy/compose.yaml -f deploy/compose.override.yaml \
  exec -T postgres bash -s <<'SH'
set -u
if timeout 6 bash -c 'exec 3<>/dev/tcp/8.8.8.8/443' 2>/dev/null; then
  echo "ОШИБКА: у контейнера базы есть исходящее соединение" >&2
  exit 1
fi
echo "OK: исходящий трафик базы заблокирован"
SH
```

Runtime-профиль базы

`postgres` получает ровно пять capability сверх сброшенного списка — `CHOWN`, `DAC_OVERRIDE`,
`FOWNER`, `SETGID`, `SETUID`: без них entrypoint официального образа не может ни войти в
каталог данных (он сам же переводит его в `0700`, а владелец тома — uid 999), ни подготовить
каталоги данных и unix-сокета, ни переключиться на пользователя postgres (`gosu`). Остальное
жёстко закреплено контрактным тестом `tests/integration/test_compose_contract.py`:
`no-new-privileges`, `cap_drop: ALL`, read-only rootfs и отдельный tmpfs на
`/var/run/postgresql` сохраняются, а прикладные процессы (`web`, `engine`, `tgbot`, `jobs`,
`migrate`) не получают capability вовсе. Исключение не открывает базе доступ наружу: сеть
`tbot-backend` остаётся `internal`, а порт публикуется только в dev-дополнении и только на
127.0.0.1.

Площадка

Боевой запуск отличается от dev-стенда: образы тянутся из GHCR по digest, конфигурация и секреты
лежат в `/etc/tbot`, TLS наружу terminates Caddy, перед переключением обязательна проверка
`make deploy-check`, точка отката фиксируется до миграций (TZ §12.7). Порядок шагов —
`docs/runbook/deploy.md`; подготовка самой ВМ — `docs/research/03 §3.10`.

Боевой состав (`compose.yaml` + `compose.prod.yaml`)

Прод-файл — дополнение, а не самостоятельная конфигурация: он переопределяет образы на digest из
`tbot.prod.env`, а локальной сборки в этой паре файлов нет вовсе (`build` объявлен только в
`compose.override.yaml`): иначе `up -d` на площадке собрал бы образ из контекста вместо pull по
digest. Поэтому оба файла перечисляются явно, вместе с env-файлом дайджестов:

```bash
cd deploy
docker compose -f compose.yaml -f compose.prod.yaml --env-file tbot.prod.env config --quiet
docker compose -f compose.yaml -f compose.prod.yaml --env-file tbot.prod.env config --format json \
  | python3 ../scripts/prod_compose_check.py
docker compose -f compose.yaml -f compose.prod.yaml --env-file tbot.prod.env run --rm migrate
docker compose -f compose.yaml -f compose.prod.yaml --env-file tbot.prod.env up -d
```

(команды выполняются внутри каталога `deploy/`; из корня репозитория все три пути
пишутся с префиксом `deploy/`). Проверка состава в CI — job `prod-config`:
`scripts/prod_compose_check.py` по разобранному составу + `caddy validate` внутри образа с
закреплённым digest.

Что закреплено за этим составом (и почему это проверяется после слияния, а не по одному YAML):

- наружу публикуются только `80:80` и `443:443`, и только у `caddy`: у `postgres`, `web`, `engine`,
  `tgbot` и `jobs` ключа `ports` в бою нет (лишняя публикация появилась бы именно при слиянии —
  compose объединяет `ports` и `networks` по имени сервиса);
- секреты только файлами из `/etc/tbot/secrets`: `db_password` (база), `db_url` (`migrate`, `web`,
  `engine`, `jobs`), `tg_bot_token` и `tg_socks_password` (`tgbot`); у `caddy` секретов нет.
  `postgres` читает пароль из `POSTGRES_PASSWORD_FILE` (`/run/secrets/db_password`) — пароля в
  `environment` нет ни в базе, ни в overlay. Пароль внутри `db_url` обязан совпадать с файлом
  `db_password`: статически это не проверяется, расхождение видно только по первому коннекту
  (`password authentication failed`);
- `caddy` монит в `:ro` файлы `./caddy/Caddyfile` и `./caddy/templates`, поэтому при смене конфига
  достаточно `docker compose ... restart caddy` (или `caddy reload`); том `caddy_data` обязан
  переживать `up -d` — в нём сертификат Let's Encrypt (лимит 50 выпусков на домен в неделю);
- наружу ходят только `caddy` (ACME) и `tgbot` (Bot API через SOCKS5 туннеля T-714): у `postgres`,
  `migrate` и `jobs` в прод-дополнении только `internal`-сети;
- память всех контейнеров по ТЗ §14.6 и не более 3 ГиБ суммарно при 3.8 ГиБ хоста (OQ-11), у
  `engine` — `stop_grace_period: 60s` (graceful shutdown обязателен для записи состояния).

Журнал доступа Caddy фильтруется (`format filter`): query-параметры `token`, `key`, `sig`,
заголовок `X-Api-Key` и заголовки учётных данных пишутся как `REDACTED` — иначе одноразовая ссылка
на отчёт попадает в файл на диске (TZ §8.4). HTTP/3 включён (`protocols h1 h2 h3`): `443/udp`
открыт решением заказчика (`docs/adr/ADR-003`), правило `allow 443/udp` лежит в
`vps/ufw.rules`, а проход UDP/443 через облачную группу безопасности подтверждён счётчиком правила
`ufw` (20 датаграмм снаружи → 20 пакетов / 900 байт). Эти две правки связаны контрактом
`test_HTTP_3_объявлен_только_вместе_с_открытым_UDP_443`: снять udp-правило можно только вместе с
`h3`. Разбор и пробы — `docs/acceptance/tls-edge.md`.

Боевой запуск на площадке, порядок шагов и приёмка периметра — `docs/runbook/stand-deploy.md`
(команды только через `sudo docker`, `ADR-003 §3`).
