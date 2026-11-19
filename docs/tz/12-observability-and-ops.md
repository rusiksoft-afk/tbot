# 12. Наблюдаемость и эксплуатация

## 12.1 Логи

- Формат: структурированный JSON (structlog), уровни `DEBUG/INFO/WARN/ERROR`, обязательные
  поля: `ts` (UTC), `level`, `service`, `module`, `event`, `trace_id`, `user_id?`,
  `account_mask?`, `strategy_id?`, `instrument_uid?`, `code?`. Человекочитаемый вывод —
  только в dev (`make dev`), в проде — JSON в stdout, ротация через логи-драйвер
  (`max-size 50m, max-file 10`).
- Маскирование: фильтр, вырезающий значения по ключам `token/secret/password/authorization/
  kek/dek` и по шаблону токена брокера; тест «токен-канарейка не попадает в вывод».
- Отдельный **торговый** журнал (не логи!): `intents`, `risk_events`, `order_events`,
  `strategy_events` — это источник истины для разбора; логи — только диагностика кода.
- Уровень DEBUG для брокерских вызовов включается только явным флагом на ограниченное время
  (TTL 2 часа, фиксируется в `audit_log`).

## 12.2 Метрики (Prometheus, `/metrics` у каждого процесса)

| Метрика | Тип | Назначение |
|---|---|---|
| `tbot_api_requests_total{service,method,kind}` | counter | бюджет/аудит |
| `tbot_api_budget_remaining{service}` | gauge | соблюдение лимитов (`docs/tz/03 §3.2`) |
| `tbot_api_errors_total{kind,contour}` | counter | 401/403/429/5xx |
| `tbot_api_latency_seconds{method}` | histogram (buckets 0.05…5) | RTT до брокера |
| `tbot_stream_connected{type}` | gauge (0/1) | состояние стримов |
| `tbot_stream_reconnects_total{type}` | counter | деградация связи |
| `tbot_market_data_lag_ms{uid,interval}` | gauge | свежесть данных (порог `R05`) |
| `tbot_risk_denied_total{code}` | counter | все коды R01…R35 |
| `tbot_orders_total{state,contour}` | counter | заявки |
| `tbot_order_unknown_total` | counter | состояние неопределённости (критично) |
| `tbot_order_roundtrip_seconds{contour}` | histogram | соответствие §7.7 |
| `tbot_strategy_state{strategy}` | gauge (enum) | состояние стратегий |
| `tbot_position_mismatch_total` | counter | расхождения с брокером |
| `tbot_killswitch_engaged` | gauge | статус |
| `tbot_notifications_{queued,sent,failed}` | counter | Telegram |
| `tbot_http_requests_total{route,status}` / `tbot_http_latency_seconds` | counter/histogram | веб |
| `tbot_job_runs_total{job,state}` / `tbot_job_last_success_timestamp` | counter/gauge | задания |
| `tbot_db_size_bytes{table}` / `tbot_disk_free_bytes` | gauge | ёмкость |
| `tbot_build_info{version,commit,contour}` | gauge=1 | идентичность сборки |

## 12.3 Health-checks

- `GET /healthz` — процесс жив (liveness); `GET /readyz` — готовность: БД, конфиг, каталог
  инструментов, хотя бы один активный токен (для `engine`) / KEK-файл доступен (для `web`).
- `engine` дополнительно отдаёт `GET /internal/boot-state` (по шагам §2.5) — используется UI
  страницы `/admin/system`.

## 12.4 Алерты (правила, порождающие коды оповещений §10.3)

| Условие | Длительность | Код |
|---|---|---|
| `tbot_stream_connected==0` | 60 с | `STREAM_DISCONNECTED` |
| `tbot_market_data_lag_ms > 5000` | 60 с | `DATA_STALE` |
| `tbot_api_errors_total{kind="auth"} > 0` | мгновенно | `TOKEN_INVALID` |
| `tbot_api_budget_remaining < 10%` | 5 мин | `API_BUDGET_LOW` |
| `tbot_order_unknown_total` прирост > 0 | мгновенно | `ORDER_UNKNOWN` |
| `tbot_position_mismatch_total` прирост > 0 | мгновенно | `POSITION_MISMATCH` |
| `tbot_risk_denied_total` прирост > 10/мин | 1 мин | `RISK_DENIED_BURST` |
| p95 `tbot_order_roundtrip_seconds > 2` | 10 мин | `EXEC_LATENCY` |
| `tbot_disk_free_bytes < 15%` / `< 8%` | 15 мин | `SYSTEM` (warn/crit) |
| `tbot_job_last_success` просрочка > 26 ч | — | `SYSTEM` |
| отсутствие суточного дайджеста к 20:45 МСК | — | `SYSTEM` |
| расхождение часов (chrony offset > 2 с) | 5 мин | `R32/CLOCK_SKEW` |

## 12.5 Часовые пояса, календарь, торговые окна

- Все задания планируются в МСК (конфиг `TZ_OPERATIONAL=Europe/Moscow`), хранение в UTC.
- Календарь торгов берётся из `TradingSchedules` (не хардкод), обновление раз в сутки
  (и при ошибке «нет торгов»); задание `ensure_partitions` и `daily_digest` привязаны к
  календарю, а не к «20:00 каждый день».
- Обслуживание (миграции, перезапуск, обновление образов) планируется только вне торгов и
  вне клиринговых пауз инструментов стратегии; UI показывает ближайшее разрешённое окно.

## 12.6 Эксплуатационные процедуры (runbook в репозитории, обязательны)

| Процедура | Кратко |
|---|---|
| `rotate-token.md` | выпуск нового токена в терминале брокера → форма `/accounts` → проверка → отзыв старого; контрольный срок (3 месяца) и напоминания |
| `restart-engine.md` | плановый рестарт: `drain` (пауза стратегий, снятие заявок по желанию) → остановка → старт → проверка `reconcile` → возобновление |
| `emergency-flatten.md` | включение kill-switch → «отменить все заявки» → `flatten` по стратегиям → проверка портфеля в терминале брокера |
| `restore-db.md` | выбор дампа → восстановление в отдельный контейнер → проверка контрольных запросов → переключение |
| `key-rotation.md` | ротация KEK, проверка дешифрования, отзыв старых версий |
| `incident-order-unknown.md` | разбор заявки в `unknown`: что смотреть (`order_attempts`, `GetOrderState`, операции брокера), как фиксировать решение, когда изолировать инструмент |
| `compromised-token.md` | немедленный отзыв токена у брокера, отзыв в системе, остановка стратегий, аудит входа, смена паролей, проверка аудита |
| `accounting-review.md` | сверка собственных расчётов с выгрузкой брокера за месяц |

## 12.7 Обновления и откат

- Образы: тег `vX.Y.Z` + digest; деплой вручную (`make deploy`) с обязательным прогоном
  миграций `--dry-run`, затем blue/green: поднимается новая версия `web`, `engine`
  перезапускается в торговое окно только с разрешения оператора (иначе — окно вне торгов).
- Откат: образ предыдущей версии + миграция с совместимой схемой (правило: миграции M-й версии
  не должны ломать чтение предыдущей версии 1 релиз; «расширяющие» миграции, затем
  «сужающие» отдельно).
- Проверка перед боевым запуском: `make deploy-check` (версия, сертификаты, NTP offset,
  свободный диск, доступность обоих контуров, срок токенов, целостность аудита).
