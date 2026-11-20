# Приёмка T-713: TLS-контур (Caddy) на `tbot.rusiksoft.ru`

Площадка: `153.51.172.30` (`compute-vm-2-4-74-ssd-1795094860175`, Ubuntu 24.04.5, 2 vCPU / 3.8 ГиБ,
OQ-11, `docs/adr/ADR-001`). Артефакты: `deploy/caddy/Caddyfile`, `deploy/compose.prod.yaml`,
`deploy/tbot.prod.env` (digest `caddy@sha256:4851e54a…`). Контракт в коде:
`tests/integration/test_compose_prod_contract.py` (25 проверок), `tests/unit/test_prod_compose_check.py`
(40 проверок разобранного состава), job `prod-config` в `.github/workflows/ci.yml`.

Статус: **не принята**. Проверено локально и на площадке без запуска контура; главная часть —
выпуск сертификата Let's Encrypt и живые ответы 80/443 — требует деплоя, а он требует решения
заказчика (см. §7).

## 1. Состояние площадки (2026-11-20 08:12 UTC, `ssh rusiksoft@153.51.172.30`)

```text
kernel 6.8.0-149-generic · up 18:39 · load 0.08
ufw: active; правила 1-6 = 22/tcp, 80/tcp, 443/tcp ALLOW IN (v4 и v6) — как принято в T-708
слушают: 127.0.0.1:10800 (xray, туннель Telegram), 127.0.0.53/:54 (resolved),
        127.0.0.1:39409 (containerd), 0.0.0.0:22 и [::]:22 (sshd)
на 80 и 443 слушателя нет — Caddy ещё не запускался
юниты active: ufw, fail2ban, chronyd, docker, tbot-tunnel
docker: 29.1.3 (docker.io) · compose: v2.40.3 → теги `!reset`/`!override` понимаются (нужно ≥2.24)
каталога репозитория нет: /opt/tbot отсутствует
/etc/tbot/secrets: telegram_socks_pass (600 root), telegram_socks_user (600 root)
docker API из-под `rusiksoft`: permission denied (пользователь не в группе `docker`)
пробы с самой машины: 80/443/8080/5432 на 127.0.0.1 — слушателя нет
```

Значимое для плана деплоя: compose **2.40.3** — то есть `build: !reset null` в
`deploy/compose.prod.yaml` на площадке разбирается корректно (на dev-машине Docker нет, и это
была единственная непроверенная часть синтаксиса overlay).

## 2. Проба периметра снаружи (рабочая машина, 2026-11-20 13:11 MSK)

| Точка | Результат | Что это значит |
|---|---|---|
| DNS `tbot.rusiksoft.ru` | `153.51.172.30` | OQ-2 закрыт: домен указывает на рабочую ВМ |
| TCP 22 | открыт, 78–94 мс | управление есть |
| TCP 80 | `Connection refused` за 2.3 с | **SG и ufw пропускают**, слушателя нет |
| TCP 443 | `Connection refused` за 2.3 с | то же: путь к порту открыт, контейнера нет |
| TLS 443 (by name / by IP+SNI) | handshake не начинается (`refused`) | проверять сертификат пока нечему |

Отличие «refused» от «timeout» — диагностически важное: отказ даёт стек хоста (порт не слушается),
тайм-аут давала бы блокировка SG/ufw. Тот же вывод, что зафиксирован в `docs/acceptance/prod-firewall.md §5`.

## 3. Конфигурация проверена тем же образом, что исполнится на площадке

`caddy` v2.11.9 (тот же мажор и минор, что у закреплённого digest: `caddy:2` на момент фиксации =
v2.11.9), бинарник с github release `v2.11.9_windows_amd64.zip`,
`h1:bhZtcRKQOq0fuLvEgCdPYvUxXyGn9kzjG4lh2332DTE=`:

```text
caddy validate → Valid configuration
caddy fmt      → файл нормализован (пробел в пустой строке перед глобальным блоком),
                 в git файл лежит LF (атрибут eol=lf), локальная копия приведена к LF
caddy adapt    → srv0: listen :443, protocols ["h1","h2"], max_header_bytes 16000,
                 read_header_timeout 10000000000 (10s)
                 handle: request_body max_size 10000000 (директива `10MB` = 10 млн байт)
                 headers: deferred delete ["Server"], set HSTS/CSP/XFO/RP/PP/Cache-Control
                 match method ["TRACE","TRACK"] → static_response 405
validate также пишет: «enabling automatic HTTP->HTTPS redirects» — редирект :80→:443 строит сам
Caddy, отдельного сайт-блока в файле нет.
Единственное предупреждение валидации: «Unnecessary header_up X-Forwarded-Proto» — строка оставлена
намеренно: проброс схемы читает приложение (uvicorn `proxy_headers`), и полагаться на дефолт
минорной версии прокси в вопросе, где аудит считает протокол, нельзя.
```

## 4. Поведенческая проба (локально, на копии Caddyfile)

Копия отличается от боевого файла ровно тремя правками (и только они): адрес сайта
`localhost:20443`, `tls internal` вместо ACME, `reverse_proxy 127.0.0.1:18080` вместо `web:8080`.
Upstream — заглушка, которая отвечает JSONом со своими входными заголовками и отдельно
публикует `Server: TbotStub/9.9` (проверка, что `-Server` снимает и чужой заголовок).

| # | Проверка | Итог |
|---|---|---|
| 1 | ответ доходит до upstream (200) | PASS |
| 2 | `Strict-Transport-Security: max-age=63072000; includeSubDomains` (TZ §8.3) | PASS |
| 3 | CSP без `unsafe-*` и без внешних хостов, `frame-ancestors 'none'` | PASS |
| 4 | `X-Content-Type-Options: nosniff` | PASS |
| 5 | `X-Frame-Options: DENY` | PASS |
| 6 | `Referrer-Policy: same-origin` (значение из TZ §8.3) | PASS |
| 7 | `Cache-Control: no-store` | PASS |
| 8 | `Server` отсутствует — и у ответа Caddy, и у ответа upstream (`-Server`) | PASS |
| 9 | `Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()` | PASS |
| 10 | upstream получил `X-Forwarded-Proto: https` | PASS |
| 11 | upstream получил `X-Real-IP` | PASS |
| 12 | upstream получил `X-Forwarded-For` | PASS |
| 13 | `TRACE` → 405, не доходит до приложения | PASS |
| 14 | `/metrics` → 404 наружу (метрики собираются по контейнерной сети) | PASS |
| 15 | тело 1 МиБ проходит | PASS |
| 16 | тело 9 999 000 байт проходит (порог `10MB` = 10 000 000) | PASS |
| 17 | тело 11 МиБ отклонено: curl получает **413**, приложение запрос не получает | PASS |
| 18 | заголовки 100 КиБ → **431 Request Header Fields Too Large** | PASS |
| 19 | TLS 1.2 работает | PASS |
| 20 | TLS 1.3 работает | PASS |
| 21 | журнал доступа пишется в stderr JSON-строками (`ts/level/request/status/size/duration`) | PASS |

Граница `max_header_size 16KB` измерена, а не принята на веру: 15 000 и 20 000 байт проходят,
22 000 и выше → 431. То есть лимит применяется, но фактический порог ≈21 КиБ, а не ровно 16 КиБ
(Go считает заголовки шагами буферизации). В приёмке фиксируем измеренное значение; заявленный
лимит — «не более ~21 КиБ», а не «16 КиБ ± байт».

Границу «TLS 1.1 не принимается» локально подтвердить не удалось: OpenSSL 3 из Python 3.12 сам
отказался предлагать TLS 1.1 (`NO_CIPHERS_AVAILABLE` на клиенте). Нижняя граница 1.2 в бою
подтверждается адаптированным конфигом (`tls.protocols` фиксируется файлом) и обязана быть
проверена на площадке `openssl s_client -tls1_1` (команда в §8).

## 5. Находки пробы и что они изменили в артефактах

1. **Журнал прокси выписывал одноразовые токены открытым текстом.** Замер «до»: в журнале
   `uri = /reports/7.csv?token=TOPSECRETTOKEN1&email=a%40b.ru`, при этом `Cookie` и
   `Authorization` Caddy v2.11.9 сам заменяет на `REDACTED`, а собственный заголовок
   `X-Api-Key` — нет. Одноразовая ссылка на отчёт (TZ §8.3, TTL 5 минут) — это полноценный доступ;
   попасть ей в файл на диске нельзя (TZ §8.4 «красное правило»).
   Исправлено в `deploy/caddy/Caddyfile`: `log { format filter { request>uri query { replace
   token|key|sig → REDACTED }, request>headers>X-Api-Key replace REDACTED, wrap json } }`.
   Замер «после»: `uri = /reports/7.csv?email=a%40b.ru&key=REDACTED&sig=REDACTED&token=REDACTED`,
   `X-Api-Key: REDACTED`, `Cookie: REDACTED`, `Authorization: REDACTED`, при этом приложение
   по-прежнему получает настоящий query (фильтр применяется при кодировании журнала, запрос он не
   меняет). Добавлены запрещённые строки: глобальная опция `log_credentials` возвращает
   Cookie/Set-Cookie/Authorization в журнал — её наличие в Caddyfile теперь ловит тест.
   **Список query-ключей обязан расти вместе с URL-поверхностью панели (M1)** — тест требует
   `token`/`key`/`sig`, новый эндпоинт с токеном в ссылке нужно добавлять сюда осознанно.
2. **Caddy сам навешивал `Alt-Svc: h3=":443"`, а UDP/443 не открыт.** Правила ufw на площадке
   пропускают только tcp 22/80/443 (T-708), TZ §8.5 наружу разрешает ровно 443 и 22. Браузер,
   поверив `Alt-Svc`, первый раз идёт по QUIC, получает тайм-аут и только потом откатывается на
   HTTP/2. Исправлено: `servers { protocols h1 h2 }` (в адаптированном конфиге видно
   `protocols: ["h1","h2"]`); проба после правки — `Alt-Svc` в ответе нет. Возврат HTTP/3 возможен
   только вместе с UDP/443 в ufw и в security group Yandex Cloud — это решение заказчика.
3. **TZ §8.3 ждёт ограничитель частоты запросов на веб-сервере («nginx `limit_req` + прикладной
   счётчик»). У официального образа Caddy встроенного `rate_limit` нет** — он существует только как
   сторонний плагин, а сборка образа с плагином означает отказ от публичного digest
   (`docs/runbook/ghcr-pull.md §1`). Вариантов два, оба требуют решения заказчика:
   (а) принять компенсацию «только прикладной счётчик» (`T-102`, веха M1: `/login` 10/мин/IP,
   `/totp` 10/мин/сессия и 5/мин/IP, mutation 60/мин/пользователь); (б) собирать образ с плагином
   и фиксировать его digest в своём реестре. Пока в файле держится то, что доступно без плагинов:
   `max_header_size`, `read_header 10s`, `request_body max_size 10MB`.
4. **Доверие к `X-Forwarded-For`.** Uvicorn по умолчанию включает `proxy_headers=True`, то есть
   принимает XFF от любого пира. Напрямую `web` снаружи недоступен (публикации порта нет,
   `deploy/compose.prod.yaml`), поэтому риск реализуем только изнутри контейнерной сети. Но
   прикладной счётчик `/login` по IP (п.3) обязан считать адрес из XFF, который проставил именно
   Caddy, а не первый попавшийся заголовок клиента — это часть `T-102`, зафиксировано комментарием
   в Caddyfile, чтобы не «починилось» молча.
5. **Проверка разобранного состава переехала из текста workflow в скрипт.** Первая версия шага CI
   содержала вложенный `python <<PY` с утверждениями: их не видел ни `mypy`, ни `pytest`, ни
   покрытие. Теперь проверки живут в `scripts/prod_compose_check.py` (stdlib, без `subprocess`,
   подавлений не добавилось — уровень 14), покрыты `tests/unit/test_prod_compose_check.py`, а
   шаг CI вызывает скрипт. Отдельный смысл именно этого разделения: `networks` и `ports` compose
   при слиянии overlay **объединяет по имени**, поэтому лишняя публикация порта или сеть с egress
   у базы могут появиться только после слияния — статический YAML-контракт их не видит.

## 6. Что не позволяет закрыть T-713 прямо сейчас

Не выполнено ровно то, что требует запущенного контура на площадке:

1. Выпуск сертификата Let's Encrypt (ACME TLS-ALPN-01 работает по 443; HTTP-01 — по 80) и
   проверка, что `caddy_data`/`caddy_config` переживают `up -d` (лимит 50 сертификатов/неделю).
2. `curl -I https://tbot.rusiksoft.ru/healthz` — 200 от панели через прокси (внешний мониторинг).
3. Редирект `http://` → `https://` живым трафиком и HSTS в ответе 443.
4. Заголовки и пределы из §4 — против **живого** `web`, а не заглушки.
5. Граница TLS 1.1 (`openssl s_client -tls1_1`) и отсутствие `Server`/`Via` с версией наружу.
6. Журнал доступа в `json-file` с ротацией 50 МБ × 10 (проверить `docker logs` и `docker inspect`),
   и то, что в `docker logs` не попадают секреты (п.5 §5 — фильтр работает, но на живом трафике).
7. Поведение после `systemctl restart docker` и после ребута площадки (TZ §13.5 учения).
8. Ограничители по частоте запросов — см. п.3 §5, решается не прокси-файлом.

Для этого нужно: клонировать репозиторий на ВМ (`/opt/tbot`), поднять `postgres` + `migrate` +
`web` + `caddy`, то есть **деплой на живую машину** и секрет `/etc/tbot/secrets/db_url`
(+ `db_password`) — см. §7.

## 7. Что нужно от заказчика

1. **Явное разрешение на деплой состава на `153.51.172.30` в этой итерации.** Формальное
   противоречие: `AGENTS.md` (стоп-лист) до сих пор запрещает «ставить Docker, открывать 80/443,
   ставить Caddy» на этой ВМ, а решение от 2026-11-20 (`docs/adr/ADR-001`) паузу T-011 снимает и
   Docker, и 80/443, и Caddy разрешает. Нужна либо правка стоп-листа, либо прямое подтверждение.
2. **Секреты площадки**: `/etc/tbot/secrets/db_password` и `/etc/tbot/secrets/db_url` (600, root) —
   их нет; `telegram_token` для `tgbot` тоже (процедура — `docs/runbook/telegram-token.md`).
   Значения в чат не нужны: заказчик кладёт файлы сам, состав читает их как файлы.
3. **Доступ к Docker API** под `rusiksoft` (группа `docker`) либо подтверждение, что деплой
   выполняется через `sudo docker compose` (иначе `docker ps`/`compose up` требуют sudo, а
   `deploy_check` и healthcheck'и это учитывают).
4. **Решение по HTTP/3**: оставить `h1/h2` (как сейчас в файле) или открывать UDP/443.
5. **Решение по ограничителю запросов** (TZ §8.3 против «Caddy без плагинов») — см. п.3 §5.
6. Решение по 80/tcp: TZ §8.5 формально разрешает наружу только 443 и 22; ACME умеет
   TLS-ALPN-01 по 443, поэтому 80 можно закрыть ценой отказа от редиректа `http://`. Сейчас 80
   открыт по приёмке T-708.

## 8. Как повторить проверки

```bash
# 1) площадка, ничего не меняя
ssh rusiksoft@153.51.172.30 'sudo ufw status numbered; sudo ss -ltnp | head -20;
  systemctl is-active ufw fail2ban chronyd docker tbot-tunnel;
  docker --version; docker compose version; sudo ls -l /etc/tbot/secrets'
# 2) снаружи (рабочая машина): путь к портам
python - <<'PY'
import socket
for port in (22, 80, 443):
    try:
        s = socket.create_connection(("153.51.172.30", port), timeout=6); s.close(); print(port, "OPEN")
    except OSError as exc:
        print(port, type(exc).__name__, exc)
PY
# 3) конфигурация — тем же образом, что исполнится на площадке (caddy 2.11.9)
#    бинарник: https://github.com/caddyserver/caddy/releases/download/v2.11.9/caddy_2.11.9_windows_amd64.zip
caddy validate --config deploy/caddy/Caddyfile --adapter caddyfile
caddy fmt --diff deploy/caddy/Caddyfile            # пусто = файл отформатирован
caddy adapt --config deploy/caddy/Caddyfile --adapter caddyfile \
  | python -c 'import json,sys; s=json.load(sys.stdin)["apps"]["http"]["servers"]["srv0"];
print(s["listen"], s["protocols"], s["max_header_bytes"], s["read_header_timeout"])'
# 4) поведенческая проба: копия Caddyfile с тремя правками + заглушка на 127.0.0.1:18080
sed -e 's/^tbot\.rusiksoft\.ru {$/localhost:20443 {/' \
    -e 's/^\ttls {$/\ttls internal {/' \
    -e 's/reverse_proxy web:8080 {/reverse_proxy 127.0.0.1:18080 {/' \
    deploy/caddy/Caddyfile > /tmp/Caddyfile.probe
caddy run --config /tmp/Caddyfile.probe --adapter caddyfile   # отдельным окном
curl -ksD- -o /dev/null https://localhost:20443/panel         # заголовки, Server отсутствует
curl -ks -o /dev/null -w '%{http_code}\n' -X TRACE https://localhost:20443/panel          # 405
curl -ks -o /dev/null -w '%{http_code}\n' https://localhost:20443/metrics                  # 404
head -c 9000000 /dev/zero | tr '\0' 'x' > /tmp/ok9.bin && curl -ks -o /dev/null -w '%{http_code}\n' \
  --data-binary @/tmp/ok9.bin https://localhost:20443/import                               # 200
head -c 11000000 /dev/zero | tr '\0' 'x' > /tmp/big.bin && curl -ks -o /dev/null -w '%{http_code}\n' \
  --data-binary @/tmp/big.bin https://localhost:20443/import                                # 413
curl -ks -o /dev/null -w '%{http_code}\n' -H "X-Big: $(printf 'a%.0s' $(seq 1 100000))" \
  https://localhost:20443/panel                                                             # 431
# журнал: маска query и заголовков (отдельным терминалом смотреть stderr caddy)
curl -ks "https://localhost:20443/reports/7.csv?token=SEC1" -H 'Cookie: tbot_session=SEC2' \
     -H 'Authorization: Bearer SEC3' -H 'X-Api-Key: SEC4' -o /dev/null
# в журнале должны быть REDACTED вместо SEC1..SEC4
```

На площадке после деплоя добавить:

```bash
curl -sSI https://tbot.rusiksoft.ru/healthz                       # 200 от панели
curl -sS -o /dev/null -w '%{http_code} -> %{redirect_url}\n' http://tbot.rusiksoft.ru/   # 308 -> https
openssl s_client -connect 153.51.172.30:443 -servername tbot.rusiksoft.ru -tls1_1 </dev/null # обязан отказать
openssl s_client -connect 153.51.172.30:443 -servername tbot.rusiksoft.ru </dev/null | \
  openssl x509 -noout -issuer -dates -ext subjectAltName   # эмитент обязан быть Let's Encrypt, SAN — ровно tbot.rusiksoft.ru
sudo docker inspect tbot-caddy --format '{{json .HostConfig.LogConfig}}'   # json-file 50m x10
```

## 9. Ссылки

TZ §8.3 (заголовки, CSP, HSTS, rate limit), §8.4 (секреты вне логов), §8.5 (периметр: 443 и 22),
§14.6 (состав и лимиты, `caddy restart always; limits 128M CPU 0.25`), §12.2 (метрики не наружу),
§12.4 (контроль срока сертификата — обязан быть алертом, задача после включения контура);
приёмка периметра: `docs/acceptance/prod-firewall.md`; подготовка машины:
`docs/acceptance/prod-bootstrap.md`; указатели образов: `docs/runbook/ghcr-pull.md`.
