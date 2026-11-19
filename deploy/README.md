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

Каталог `secrets/` в корне репозитория намеренно в `.gitignore`. Для dev-стенда:

```bash
mkdir -p secrets
printf 'dev-db-password'            > secrets/db_password
printf 'postgresql://tbot:dev-db-password@postgres:5432/tbot' > secrets/db_url
printf 'dev-not-a-real-token'       > secrets/tg_bot_token
printf 'dev-not-a-real-password'    > secrets/tg_socks_password
chmod 600 secrets/*
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

```bash
docker compose -f deploy/compose.yaml -f deploy/compose.override.yaml \
  exec postgres python3 - <<'PY'
import socket
try:
    socket.create_connection(("8.8.8.8", 443), timeout=5)
    print("ОШИБКА: у контейнера базы есть исходящее соединение")
except OSError:
    print("OK: исходящий трафик базы заблокирован")
PY
```

Площадка

Боевой запуск отличается от dev-стенда: образы тянутся из GHCR по digest, конфигурация и секреты
лежат в `/etc/tbot`, TLS наружу terminates Caddy, перед переключением обязательна проверка
`make deploy-check`, точка отката фиксируется до миграций (TZ §12.7). Порядок шагов —
`docs/runbook/deploy.md`; подготовка самой ВМ — `docs/research/03 §3.10`.
