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
docker: 29.1.3 (docker.io) · compose: v2.40.3 (пакет Ubuntu); синтаксис compose ≥2.24 понятен
каталога репозитория нет: /opt/tbot отсутствует
/etc/tbot/secrets: telegram_socks_pass (600 root), telegram_socks_user (600 root)
docker API из-под `rusiksoft`: permission denied (пользователь не в группе `docker`)
пробы с самой машины: 80/443/8080/5432 на 127.0.0.1 — слушателя нет
```

Значимое для плана деплоя: compose **2.40.3** из пакета дистрибутива (не docker-compose v1),
то есть compose v2 с поддержкой `develop`/`!reset`/профилей. На dev-машине Docker нет вовсе,
поэтому любой разбор состава исполняется в CI (job `prod-config`) или на самой площадке;
что CI-раннёр приносит другую версию compose — см. §5, п.7.

Изменение состояния позже того же дня (14:25 MSK): к набору T-708 добавлено правило `443/udp`
(`comment caddy-http3`, из эталона `deploy/vps/ufw.rules`) — решение заказчика по HTTP/3, §7 п.5.
Слушателя на 80/443 это не добавляет: контейнеров на площадке по-прежнему нет.

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

### 2.1 UDP/443: проходит ли транспорт для HTTP/3 (2026-11-20 14:25 MSK)

Вопрос «открыт ли udp/443» нельзя проверить CONNECT-подобной пробой: UDP без слушателя не отвечает
ничем в обоих случаях — и когда пакеты теряются в облаке, и когда они доходят до хоста. Поэтому
мера — счётчик правила фильтра на самой площадке: если он вырос ровно на число отправленных
датаграмм, путь открыт целиком (SG → ufw → интерфейс).

```bash
# 1. правило добавлено из эталона (deploy/vps/ufw.rules)
sudo ufw allow 443/udp comment caddy-http3
# 2. с рабочей машины: 20 датаграмм на 153.51.172.30:443 (socket.SOCK_DGRAM, payload 19 байт)
# 3. на площадке:
sudo iptables -L ufw-user-input -n -v | grep 'udp dpt:443'
```

Результат: `20 900 ACCEPT 17 -- * * 0.0.0.0/0 0.0.0.0/0 udp dpt:443` — до отправки счётчик был
`0 0`, стало ровно 20 пакетов / 900 байт. Вывод: облачная группа безопасности (разрешает сейчас
весь входящий трафик, TZ §14.6) и `ufw` udp/443 пропускают. Формулировка «udp закрыт» была
справедлива только для исходного набора правил T-708, где были перечислены три tcp-порта.

Порядок после этого замера обязателен: `ufw` → подтверждение счётчиком → `protocols h1 h2 h3` в
Caddyfile. Обратный порядок (сначала `h3`) даёт браузеру `Alt-Svc: h3`, которого сеть не
пропускает; об этом же напоминает контракт
`test_HTTP_3_объявлен_только_вместе_с_открытым_UDP_443`.

### 2.2 Что уже подтверждено на самой площадке (2026-11-20 14:10)

До запуска контура проверено то, что раньше подтверждалось только на CI-раннёре:

| # | Проверка | Результат замера |
| --- | --- | --- |
| 1 | Клон репозитория по read-only deploy-ключу | `git clone` в `/opt/tbot` выполнен, HEAD `5fa3d41`, рабочее дерево чистое; `git diff --stat 1ce4be6..HEAD` по путям кода пуст → закреплённый набор digest собран из того же кода |
| 2 | Разбор состава **на compose площадки** | `docker compose -f deploy/compose.yaml -f deploy/compose.prod.yaml --env-file deploy/tbot.prod.env config --quiet` → exit 0; `config --format json \| python3 scripts/prod_compose_check.py` → **13/13 OK**, «ГОТОВО: боевой состав разобран без замечаний» |
| 3 | Ключевой риск про разрыв версий compose | `no_local_build` зелёный и на **2.40.3** (площадка), и на **v5.1.3** (раннёр): перенос `build` в `compose.override.yaml` корректен для обеих реализаций |
| 4 | Публичные образы по закреплённым digest | `postgres@sha256:e62fbf9d…` и `caddy@sha256:4851e54a…` на площадке есть, `Status: Image is up to date`, `docker images --digests` показывает ровно эти digest; диск 64 ГиБ свободен |
| 5 | Чего не хватает для `pull` своих образов | нет `ghcr_token` → `docker login ghcr.io` невозможен; четыре образа приложения не тянутся |

**Важное расхождение поведения compose, найденное замером.** На площадке `config` проходит с
exit 0, хотя ни одного файла секрета в `/etc/tbot/secrets` нет, а на CI-раннёре (compose v5.1.3)
тот же шаг требует, чтобы файлы существовали, — поэтому в job `prod-config` и создаются
пустышки. Следствие для приёмки: зелёный `config` на площадке **не** означает, что секреты
заведены; готовность секретов по-прежнему проверяется только `--check` (и поведением `up`).
Ошибка придёт позже — при старте контейнера как «secret not found».

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

Переснятие после решения по HTTP/3 (тот же бинарник v2.11.9, тот же файл, 2026-11-20 14:40 MSK):

```text
caddy fmt      → различий нет (файл уже в канонической форме)
caddy validate → Valid configuration (предупреждение про X-Forwarded-Proto — то же)
caddy adapt    → srv0: listen [":443"], protocols ["h1","h2","h3"],
                 max_header_bytes 16000, read_header_timeout 10000000000
```

Значение `h3` в списке — не «разрешили QUIC», а часть связки с `allow 443/udp` (§2.1).

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
| 22 | после включения `h3`: `Alt-Svc: h3=":20443"; ma=2592000` в ответе есть (в состоянии `protocols h1 h2` строки не было) | PASS |
| 23 | UDP-слушатель на порту сайта: `Get-NetUDPEndpoint -LocalPort 20443` → `[::]:20443`, владелец — процесс caddy | PASS |
| 24 | `Strict-Transport-Security` и `Alt-Svc` сосуществуют в одном ответе | PASS |

Что проба локально не доказывает: сам QUIC-handshake. `curl 8.22.0` на рабочей машине собран без
nghttp3 (`Features: ...` без `HTTP3`), поэтому `curl --http3` здесь не работает. Доказательная база
остаточная и честная: Caddy объявляет `h3` и поднимает udp-сокет (строки 22–23), а проход udp/443
через облако и файрвол измерен счётчиком правила на площадке (§2.1). Полная проверка HTTP/3
выполняется на площадке, когда там появится слушатель (§6).

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
   **Решение получено 2026-11-20 (`docs/adr/ADR-003 §5`): udp/443 открывается, HTTP/3 включается.**
   Выполнено по порядку: правило `allow 443/udp comment caddy-http3` добавлено в
   `deploy/vps/ufw.rules` и применено на площадке → проход подтверждён счётчиком (§2.1) →
   Caddyfile переведён на `protocols h1 h2 h3` (переснятие `adapt` в §3, строки 22–24 в §4).
   Связка «правило ↔ `h3`» закреплена тестом `test_HTTP_3_объявлен_только_вместе_с_открытым_UDP_443`:
   снять udp-правило, оставив `h3`, теперь нельзя. Сузить SG облака до `22/80/443 tcp + 443 udp`
   обязан владелец аккаунта (`docs/runbook/yandex-sg.md`) — сейчас в облаке открыт весь входящий
   трафик, и это отдельный долг, а не следствие HTTP/3.
3. **TZ §8.3 ждёт ограничитель частоты запросов на веб-сервере («nginx `limit_req` + прикладной
   счётчик»). У официального образа Caddy встроенного `rate_limit` нет** — он существует только как
   сторонний плагин, а сборка образа с плагином означает отказ от публичного digest
   (`docs/runbook/ghcr-pull.md §1`). Вариантов два, оба требуют решения заказчика:
   (а) принять компенсацию «только прикладной счётчик» (`T-102`, веха M1: `/login` 10/мин/IP,
   `/totp` 10/мин/сессия и 5/мин/IP, mutation 60/мин/пользователь); (б) собирать образ с плагином
   и фиксировать его digest в своём реестре. Пока в файле держится то, что доступно без плагинов:
   `max_header_size`, `read_header 10s`, `request_body max_size 10MB`.
   **Решение получено 2026-11-20 (`docs/adr/ADR-003 §4`): вариант (а).** Формулировка ТЗ
   «nginx `limit_req` + прикладной счётчик» заменена (правка `docs/tz/08 §8.3` разрешена
   заказчиком): счётчик обязателен в приложении, прокси держит пределы размера и тайм-аутов и
   отбивает разведочные методы. Практическое следствие для плана: без `T-102` публичный вход не
   принимается по §8.3, и переносить эту задачу за пределы M1 нельзя — compensate-мера в виде
   `limit_req` недоступна в принципе.
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
6. **`build: !reset null` в overlay не отключает сборку — это нашёл первый же прогон CI.**
   Шаг «разобранный состав» упал с `FAIL no_local_build: в разобранном составе осталась сборка:
   ['engine', 'jobs', 'tgbot', 'web']` (прогон 44705278159). В выводе `docker compose config`
   видно, что после слияния у сервисов остаются `context: /home/runner/work/tbot/tbot` и
   `dockerfile: deploy/Dockerfile` из базового файла: тег не сбросил отображение.
   Это не косметика: пока `build` в разобранной модели есть, `up -d` с отсутствующим локально
   образом **соберёт его на площадке** (compose не считает это ошибкой), и связь «запустили ровно
   то, что собрали в CI» теряется молча; на 2 vCPU сборка ещё и остановит остальное.
   Полная проба форм тегов (`!reset null`, `!override null`, `!reset {}`, `!override {}`,
   `!reset []`, голый `null`) в том же прогоне не состоялась из-за собственной ошибки в шаге
   диагностики (в YAML-блоке `run:` подстановка `\n` ушла в файл литералом, и compose получал
   `docker compose n …`), но она и не нужна: решение — не подбирать тег, а убрать `build` из
   боевой пары файлов. Итог:
   * `build:` переехал из `deploy/compose.yaml` в `deploy/compose.override.yaml` (dev-дополнение,
     которое в бою не подключается; и dev-стенд, и job `compose-smoke`, и `scripts/dev.py` уже
     передают оба файла, так что поведение разработки не изменилось);
   * из `deploy/compose.prod.yaml` убраны обе строки `build: !reset null` и одноимённый ключ якоря
     `x-prod-app` — якорь больше не нужен для этого;
   * `check_no_build` в `scripts/prod_compose_check.py` отклоняет **наличие** ключа `build`
     (в том числе `build: null`): «отключить сборку» больше нельзя — её можно только не объявлять;
   * статические стражи — `test_локальная_сборка_объявлена_только_в_dev_дополнении`
     (базовый и боевой файлы) и `test_боевой_разбор_вообще_не_содержит_локальной_сборки`
     (плюс эталон: сборки объявлены ровно у web/engine/tgbot/jobs/migrate в dev-дополнении).
   Тот же класс дефекта, что «восемь причин» `compose-smoke` (HANDOFF §1.2): файл разбирается
   без ошибок, но делает не то. Отличие в том, что здесь поймал не человек, а проверка,
   написанная по разобранной модели.
7. **CI и площадка разбирают состав разными версиями compose.** Раннёр GitHub принёс
   `Docker Compose version v5.1.3`, площадка работает на 2.40.3 из пакета Ubuntu. Значит job
   `prod-config` проверяет правила слияния более новой реализации, а не той, что будет на
   площадке. Шахматного порядка это не меняет (после п.6 в боевой паре файлов нет ни `!reset`,
   ни `build` — нечего и сливать по-разному), но честная приёмка обязана включить
   `docker compose … config` на самой ВМ (шаг деплоя, §8). Версия compose теперь печатается
   в шаге разбора, чтобы расхождение было видно в каждом прогоне.

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
`web` + `caddy`. Деплой на живую машину **разрешён** заказчиком 2026-11-20 (§7,
`docs/adr/ADR-003`); команды и порядок — `docs/runbook/stand-deploy.md`. Пункт 8 списка выше из
него убран: ограничитель частоты живёт в приложении (`T-102`), и это принятое решение, а не
незакрытая часть периметра (п.3 §5).

## 7. Решения заказчика (получены 2026-11-20, `docs/adr/ADR-003`)

| # | Вопрос | Ответ | Что сделано |
| --- | --- | --- | --- |
| 1 | Деплой состава на `153.51.172.30` | **да**: клон в `/opt/tbot`, pull по digest, `migrate`, затем `up -d` | runbook `docs/runbook/stand-deploy.md`; digest'ы пересняты с зелёного прогона `Image` 44708907667 |
| 2 | Противоречие стоп-листа `AGENTS.md` и `ADR-001` | править `AGENTS.md` | стоп-лист переписан: Docker, 80/443 tcp, 443/udp, Caddy и LE разрешены; запрет на SG облака, удаление томов, ребут и `prune -a` сохранён |
| 3 | Доступ к Docker API | **через `sudo`** | все команды runbook — `sudo docker …`; в группу `docker` пользователь не добавляется |
| 4 | Ограничитель частоты запросов (TZ §8.3) | править формулировку ТЗ, Caddy остаётся без плагинов | `docs/tz/08 §8.3` переписан: счётчик обязателен в приложении (`T-102`), прокси держит пределы размера/тайм-аутов; TZ §8.5 и §14 дополнены udp/443 |
| 5 | HTTP/3 и 80/tcp | `443/udp` открыть (HTTP/3 включить), `80/tcp` оставить | правило в `deploy/vps/ufw.rules` и применено на площадке; проход udp измерен (§2.1); Caddyfile → `protocols h1 h2 h3` |
| 6 | Секреты | заказчик кладёт сам, значения в чат не попадают | новый `deploy/vps/secrets-setup.sh` (`read -s`, `600`, `root:root`, `--check`), runbook `docs/runbook/secrets-on-host.md`, прогон скрипта в job `prod-config` |

Что по-прежнему делает только владелец аккаунта и площадки (деплой без этого не завершается):

1. Выпустить и завести секреты: `bash /opt/tbot/deploy/vps/secrets-setup.sh` — четыре значения
   (`db_password`, `db_url`, `ghcr_token`, `telegram_token`). Агент запускает только `--check`.
2. Добавить публичную часть deploy-ключа ВМ в репозиторий как **deploy key только на чтение**
   (`docs/runbook/stand-deploy.md §2`). Публичная часть — не секрет, приватная с ВМ не уходит.
3. Сузить security group облака до `22/tcp`, `80/tcp`, `443/tcp`, `443/udp` (или до
   allowlist-подсетей) — сейчас в облаке открыт весь входящий трафик, это отдельный долг
   (`docs/runbook/yandex-sg.md`, TZ §14.6).
4. Согласовать `sudo systemctl restart docker` и ребут ВМ: оба шага нужны для пунктов 6–7 §6
   (перезапуск докера и учения §13.5), и оба прерывают работу контура.
5. Сообщить логин учётной записи, выпустившей `ghcr_token`: для пакетов организации вход идёт под
   **своим** логином, а не именем организации (`stand-deploy.md §4`).

### 7.1 Ответы на четыре вопроса (ask `f1d7ef9a`, 2026-11-20 13:40) и их замеренный статус

| # | Вопрос | Ответ заказчика | Замер на площадке (тот же день) |
| --- | --- | --- | --- |
| 1 | Готовы ли выполнить пять действий сейчас | **да** | **deploy key: сделано и работает** (при явном `-i`, см. `stand-deploy §2`). **Секреты: не заведены** — повторный замер 2026-11-20 14:05 даёт те же 4 × `FAIL: нет файла` + `WARN: режим каталога = 750`; `/opt/tbot` нет. Это единственный оставшийся блокатор до `pull` |
| 2 | Security group облака | **сузить до `22/tcp`, `80/tcp`, `443/tcp`, `443/udp`** (`set_4`) | **сделано заказчиком, проверено снаружи 2026-11-20 14:05**: `22` OPEN, `80/443` `Connection refused` (проходят, слушателя нет), а `8443/8080/3000/5432` — `TIMEOUT` (молча дропаются). До правки все перечисленные отвечали отказом, то есть фильтрация действительно переехала в облако |
| 3 | `systemctl restart docker` и ребут ВМ | **да, оба** | согласия достаточно, чтобы включить пункты 6–7 §6 в приёмку; факты ещё не замерялись (контура нет) |
| 4 | Логин владельца `ghcr_token` | не сообщён; предложено **извлечь из токена на площадке** (`GET /user`) | токена на площадке нет → извлекать пока не из чего. Форма команды, предложенная заказчиком, поднимает токен в argv (`-H "Authorization: Bearer $(cat …)"` видно в `ps`) — см. `docs/runbook/ghcr-pull.md §3`, там вариант, где токен не попадает ни в argv, ни в историю |

Deploy-ключ ВМ **ещё не добавлен** в репозиторий — проверка с ВМ отвечает
`git@github.com: Permission denied (publickey)`. Публичная часть и отпечаток —
`docs/runbook/stand-deploy.md §2`. Тот же замер подтвердил, что `known_hosts` для `github.com`
на ВМ теперь есть (добавлен probe-сеансом с `StrictHostKeyChecking=accept-new`), так что
предупреждение про `ssh-keyscan` в ранбуке закрывается самим ранбуком.

Чтобы заказчику не ждать клона репозитория, скрипт ввода секретов скопирован на площадку
заранее: `/tmp/secrets-setup.sh`, контрольная сумма совпадает с репозиторной —
`sha256:89005d59c960c1733b3b5dc14512bef6927443414552d30f4c98791013e3370b`
(`sha256sum` на обеих машинах совпал). Запуск: `sudo bash /tmp/secrets-setup.sh`, проверка:
`sudo bash /tmp/secrets-setup.sh --check`. Скрипт попутно ставит каталогу режим `700`
(`install -d -m 700`), то есть снимает `WARN` про `750`.

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
# 2a) udp/443: счётчик правила на площадке (см. §2.1) — слушателя нет, но пакеты должны доходить
sudo ufw allow 443/udp comment caddy-http3
python - <<'PY'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
for i in range(20):
    s.sendto(b"t713-udp-probe-%02d" % i, ("153.51.172.30", 443)); time.sleep(0.1)
PY
ssh rusiksoft@153.51.172.30 "sudo iptables -L ufw-user-input -n -v | grep 'udp dpt:443'"
#   было 0 0 → стало 20 900 ACCEPT 17 … udp dpt:443
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
curl -sSI --http3 https://tbot.rusiksoft.ru/healthz     # HTTP/3; нужен curl с nghttp3 (на dev-машине curl 8.22.0 собран без HTTP3)
# если curl без HTTP/3, доказательство остаётся то же, что в §2.1: счётчик udp-правила + Alt-Svc в ответе
curl -ksD- -o /dev/null https://localhost:20443/panel | grep -i alt-svc   # локально: Alt-Svc: h3=":20443"
```

## 9. Ссылки

TZ §8.3 (заголовки, CSP, HSTS, ограничитель запросов — с 2026-11-20 в прикладной формулировке),
§8.4 (секреты вне логов), §8.5 (периметр: `443/tcp`, `443/udp`, `80/tcp`, `22/tcp`),
§14.6 (состав и лимиты, `caddy restart always; limits 128M CPU 0.25`), §12.2 (метрики не наружу),
§12.4 (контроль срока сертификата — обязан быть алертом, задача после включения контура);
решения по деплою и периметру: `docs/adr/ADR-001-stand-is-prod-vm.md`,
`docs/adr/ADR-003-prod-deploy-edge-decisions.md`;
порядок деплоя и приёмки: `docs/runbook/stand-deploy.md`, `docs/runbook/secrets-on-host.md`;
приёмка периметра: `docs/acceptance/prod-firewall.md`; подготовка машины:
`docs/acceptance/prod-bootstrap.md`; указатели образов: `docs/runbook/ghcr-pull.md`.
