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

`postgres` получает ровно четыре capability сверх сброшенного списка — `CHOWN`, `FOWNER`,
`SETGID`, `SETUID`: без них entrypoint официального образа не может ни подготовить каталоги
данных и unix-сокета, ни переключиться на пользователя postgres (`gosu`). Остальное
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
