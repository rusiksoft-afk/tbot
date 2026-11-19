# 04. Модель данных (PostgreSQL 16)

Общие правила: `NUMERIC(20,8)` для цен/объёмов/долей, `NUMERIC(24,2)` для сумм в валюте
(рубли/юани), `timestamptz` везде, soft-delete только там, где нужен аудит; имена таблиц —
множественное число в snake_case; у каждой таблицы бизнес-сущности — `created_at`,
`updated_at`, `version` (оптимистичная блокировка). FK с `ON DELETE RESTRICT` (удаление —
только архивированием). Миграции — только Alembic, одна миграция = один логический шаг,
обратная миграция обязательна (`downgrade`).

## 4.1 Идентичность и доступ

```
users(id uuid pk, login citext unique not null, email citext null, display_name text,
      role text check (role in ('admin','operator','viewer')) not null,
      state text check (state in ('invited','awaiting_approval','active','suspended','archived')),
      password_hash text not null, password_updated_at timestamptz,
      failed_attempts int default 0, locked_until timestamptz,
      created_at, updated_at, approved_by uuid references users, approved_at)

invitations(id uuid pk, email citext, login citext, role text, token_hash text unique,
            state text, expires_at timestamptz, created_by uuid, used_at, created_at)

totp_enrollments(id uuid pk, user_id fk, secret_enc bytea not null,        -- AES-256-GCM
                 issuer text, enrolled_at timestamptz, confirmed_at, revoked_at,
                 verify_window int default 1)
backup_codes(id uuid pk, user_id fk, code_hash text not null, used_at timestamptz, created_at)
totp_failures(id, user_id, at, ip inet, source text)                        -- для lockout

sessions(id uuid pk, user_id fk, created_at, last_seen_at, expires_at, ip inet,
         user_agent text, revoked_at, auth_step text check (auth_step in ('password','totp','full')))

ip_allowlist(id, cidr inet not null, comment text, created_by, created_at, enabled bool)
webauthn_credentials(... )                                                  -- опция M7, не M1
audit_log(id bigserial, at timestamptz, actor uuid null, action text, entity text,
          entity_id text, details jsonb, ip inet, request_id uuid, hash_prev text, hash text)
```

`REQ-identity-04` `audit_log` — append-only: права БД приложения не дают `UPDATE/DELETE`;
цепочка `hash_prev/hash` (SHA-256 от канонического JSON записи + предыдущий хэш) позволяет
обнаружить разрыв. Проверка целостности — отдельная команда `make audit-verify`.
`AC-identity-04` Тест: попытка `UPDATE audit_log` учётной записью приложения → ошибка прав;
`audit-verify` на изменённой вручную копии дампа → найден разрыв.

## 4.2 Доступы к брокеру

```
credentials(id uuid pk, owner_id fk, kind text check (kind in ('invest_prod','invest_sandbox')),
            name text, token_cipher bytea not null, key_version int not null,
            mask text not null,                       -- напр. "t.XY…9f"
            issued_hint date null, last_check_at, last_check_ok bool, check_error text,
            state text check (state in ('active','invalid','expiring','revoked')),
            created_at, rotated_at)
credential_accounts(id, credential_id fk, account_id text, account_type text, status text,
                    currency text, opened_at date, tradable bool, reason text,
                    UNIQUE(credential_id, account_id))
token_expiry_reminders(id, credential_id, sent_at, days_left int, channel text)
```

`REQ-credentials-05` Токен хранится только как `token_cipher`: AES-256-GCM, DEK на запись,
DEK обёрнут в KEK из файла ключа/внешнего хранилища (вне БД), `key_version` для ротации.
Открытый токен не попадает ни в логи, ни в stderr, ни в трейсы, ни в `repr()` моделей.
`AC-credentials-05` (1) в дампе БД нет подстроки тестового токена; (2) тест на `repr()` и
логирование: токен маскируется; (3) команда `make secret-scan` (gitleaks) в CI.

## 4.3 Инструменты и календарь

```
instruments(uid text pk, figi text, ticker text, class_code text, name text,
            instrument_type text, exchange text, real_exchange text, currency text,
            lot int not null check (lot>0), min_price_increment numeric(20,8) not null check (>0),
            price numeric(20,8), tradable bool, status text, sector text, country text,
            first_one_min_trading, is_in_default_portfolio bool, deleted_at, updated_at)
instrument_snapshots(id bigserial, uid text, captured_at, payload jsonb)      -- для бэктеста
trading_schedules(id, exchange text, day date, is_trading_day bool, start_ts, end_ts,
                  start_main, end_main, start_evening, end_evening, detail jsonb,
                  UNIQUE(exchange, day))
instrument_trading_status(uid text, ts timestamptz, status text,
                          limit_available bool, market_available bool,
                          PRIMARY KEY(uid, ts))
watchlist(user_id, uid, added_at)   -- наблюдение без стратегии
```

## 4.4 Рыночные данные (партиционирование по месяцам)

```
candles(uid text, interval text, ts timestamptz,              -- начало свечи, UTC
        open numeric(20,8) not null, high, low, close, volume bigint,
        is_complete bool not null default true, source text,
        PRIMARY KEY (uid, interval, ts)) PARTITION BY RANGE (ts)   -- помесячно
  индекс: candles_<interval>_idx ON candles (interval, ts) INCLUDE (uid)

last_prices(uid, ts, price numeric(20,8), source text)         -- актуальное состояние
orderbook_snapshots(uid, ts, depth int, bids jsonb, asks jsonb) -- только выборочно, см. ретенцию
trades_stream_summary(uid, day, count bigint, avg_spread_bps numeric)  -- агрегат для анализа слиппеджа
market_data_lag(uid, interval, ts, observed_at, lag_ms int)    -- мониторинг свежести
history_jobs(id, uid, interval, from_ts, to_ts, checkpoint_ts, state, error, updated_at)
```

`REQ-market-data-03` Первичный ключ `(uid, interval, ts)` + `ON CONFLICT DO UPDATE` — гарантия
от дублей; свеча считается «закрытой» только при подтверждении источника, незакрытая свеча
(`is_complete=false`) не участвует в сигналах и в бэктесте.
`AC-market-data-03` Тест: повторная доставка той же свечи → одна строка, значения
детерминированы; незакрытая свеча не попадает в индикаторы (тест индикаторного слоя).

## 4.5 Счета, позиции, операции, сверка

```
account_snapshots(id, account_id, ts, kind text check (kind in ('portfolio','positions','margin')),
                  payload jsonb, source text)   -- «сырые» снимки для разбора инцидентов
money_balances(account_id, currency, balance numeric(24,2), blocked numeric(24,2), ts)
positions(account_id, uid, qty numeric(24,8), lot_size int, avg_price numeric(20,8),
          exchange_qty numeric(24,8), price_update_ts, ts,
          PRIMARY KEY(account_id, uid, ts))
broker_operations(id bigserial, account_id, operation_id text unique, uid, kind text,
                  trade_ts, price numeric(20,8), volume numeric(24,8), quantity_lots int,
                  fee numeric(24,2), currency text, instrument_type text, payload jsonb)
broker_trades(id bigserial, account_id, trade_id text unique, order_id_exchange text,
              uid, side text, price numeric(20,8), qty_lots numeric(24,8), trade_ts, fee numeric(24,2))
position_mismatches(id, account_id, uid, own_qty, broker_qty, detected_at, resolved_at, note)
reconciliation_runs(id, account_id, started_at, finished_at, state, result jsonb)
```

## 4.6 Заявки, намерения, события

```
intents(id uuid pk, strategy_id fk, created_at, payload jsonb not null,   -- см. Intent
        decision text check (decision in ('approved','denied')),
        decision_code text, decision_reason text, risk_snapshot jsonb not null)
orders(id uuid pk, intent_id fk unique, strategy_id, account_id, uid,
       client_key uuid unique not null,        -- PostOrderRequest.order_id
       exchange_order_id text, order_request_id text,
       id_type text check (id_type in ('request','exchange')),
       side text, order_type text, qty_lots int, price numeric(20,8),
       filled_lots int default 0, avg_fill_price numeric(20,8),
       state text check (state in ('prepared','sent','new','partially_fill','fill',
                                   'cancelled','rejected','unknown')),
       initial_commission numeric(24,2), executed_commission numeric(24,2),
       created_at, sent_at, last_event_at, closed_at)
order_events(id bigserial, order_id fk, ts, event text, payload jsonb)     -- лента состояний
order_attempts(id, order_id, attempt_no, request_ts, response_ts, http_or_grpc_code,
               error_kind, raw_error jsonb)
stop_orders(id uuid pk, intent_id, account_id, uid, side, stop_order_type text,
            price numeric(20,8), stop_price numeric(20,8), qty_lots int,
            expiration_type text, expire_at, client_key uuid unique,
            exchange_stop_order_id text, state text, created_at, closed_at)
```

`REQ-order-executor-03` Для каждой попытки мутации создаётся строка `order_attempts` до вызова;
состояние `unknown` — обязательная промежуточная фаза при таймауте, из которой возможен только
пути «подтверждено состоянием брокера» либо «доказано непринятие» (детали `docs/tz/07`).

## 4.7 Стратегии и их состояние

```
strategies(id uuid pk, owner_id fk, name text, kind text check (kind in ('grid','ta','plugin:<id>')),
           account_id, uid, contour text check (contour in ('sandbox','paper','production')),
           state text check (state in ('draft','armed','running','paused','stopped',
                                       'blocked_by_risk','error','quarantined','archived')),
           params jsonb not null, params_hash text not null,
           capital_allocated numeric(24,2), currency text,
           risk jsonb not null,                      -- лимиты этой стратегии (в валидном диапазоне)
           created_at, started_at, stopped_at, version int,
           UNIQUE(owner_id, name))
strategy_events(id bigserial, strategy_id, ts, kind text, payload jsonb)  -- сигналы/уровни/решения
grid_levels(id uuid pk, strategy_id fk, level_no int, side text, price numeric(20,8),
            qty_lots int, state text check (state in ('planned','placed','filled','cancelled',
            'superseded')), order_id uuid null, created_at, updated_at,
            UNIQUE(strategy_id, level_no))
strategy_counters(strategy_id, open_orders int, filled_lots numeric, invested numeric,
                  avg_price numeric(20,8), realized numeric(24,2), unrealized numeric(24,2),
                  day_start_equity numeric(24,2), day_pnl numeric(24,2), updated_at)
```

`REQ-strategy-engine-01` Изменение `params` работающей стратегии запрещено: нужен перевод в
`paused`, новая версия параметров (`params_hash`) с записью в `strategy_events`, затем запуск.
`AC-strategy-engine-01` Тест: PUT параметров в `running` → 409 и объяснение в UI.

## 4.8 Риск, инциденты, уведомления

```
risk_limits(scope text check (scope in ('global','user','strategy')), ref_id, key text,
            value numeric(24,8), unit text, min_ok numeric, max_ok numeric,
            updated_by, updated_at, UNIQUE(scope, ref_id, key))
risk_events(id bigserial, ts, scope, ref_id, code text, severity text, message text, details jsonb)
kill_switch_state(id int pk check (id=1), engaged bool, reason text, engaged_by, engaged_at,
                  released_by, released_at)
alerts(id bigserial, ts, code text, severity text, dedup_key text, payload jsonb,
       acknowledged_at, acknowledged_by)
notification_outbox(id bigserial, created_at, channel text, user_id, template text,
                    payload jsonb, state text, attempts int, next_try_at, sent_at, error)
digest_runs(id, user_id, period text, at, payload jsonb, state)
```

## 4.9 Telegram

```
telegram_bindings(id uuid pk, user_id fk unique, chat_id bigint unique, bound_at,
                  confirmed_at, revoked_at, first_name text, username text)
telegram_commands(id uuid pk, user_id, chat_id, command text, args jsonb, created_at,
                  confirmed_at, executed_at, result jsonb, requires_totp bool)
telegram_messages_log(id bigserial, chat_id, direction text, template text, ts, state, error)
```

## 4.10 Бэктест

```
datasets(id uuid pk, name text, created_at, manifest jsonb,   -- список (uid, interval, период),
         row_counts jsonb, checksum text, source text)
backtests(id uuid pk, name text, strategy_kind text, params jsonb, params_hash text,
          dataset_id fk, period tstzrange, fill_model jsonb, commission_model jsonb,
          created_by, created_at, finished_at, state)
backtest_metrics(backtest_id pk fk, metric text, value numeric(24,8), unit text,
                 PRIMARY KEY(backtest_id, metric))
backtest_trades(id bigserial, backtest_id fk, uid, side, open_ts, close_ts, qty_lots,
                entry numeric(20,8), exit numeric(20,8), pnl numeric(24,2), fees, reason_exit text)
backtest_equity(backtest_id, ts, equity numeric(24,2), drawdown numeric(24,8), positions int)
optimizer_runs(id, backtest_id_parent, grid jsonb, method text, splits jsonb,
               created_at, state);  optimizer_points(id, run_id, params jsonb, metrics jsonb)
```

## 4.11 Целостность и P&L (расчётные правила)

- realized P&L по инструменту считается по «парным» сделкам FIFO/средняя цена — выбирается
  **один** метод (`avg_cost` по умолчанию, как у брокера для расчёта налоговой базы на MOEX для
  ценных бумаг) и фиксируется в `settings.calc_method`; оба метода доступны для сверки.
- комиссии: `initial_commission` — план, `executed_commission` — факт; для paper-режима —
  модель из `configs/commissions.yaml` (значения вводит оператор: API брокера комиссий не
  отдаёт). Требование: любая сумма в отчётах имеет ссылку на источник (`broker` / `model`).
- `REQ-storage-01` Таблица `position_mismatches` обязана заполняться автоматически при каждом
  `reconciliation_runs` с расхождением; UI показывает счётчик нерешённых расхождений.
- `REQ-storage-02` Все денежные суммы в БД — `NUMERIC`, никаких `DOUBLE PRECISION`/`REAL` для
  денег и цен (проверяется тестом миграции: скан колонки на тип).

## 4.12 Ретенция и объёмы (целевой масштаб 3 пользователя / ≤100 подписок)

| Данные | Глубина | Оценка объёма |
|---|---|---|
| свечи 1 мин (только подписки стратегий) | 24 месяца | ~12 млн строк на 100 инструментов за 12 мес. ≈ 2 ГБ с индексами |
| свечи 5/15/30 мин | 36 месяцев | ~0.5 ГБ |
| свечи 1 час | 5 лет | ~0.15 ГБ |
| свечи день/неделя/месяц | 6+ лет (доступно API) | ~0.1 ГБ |
| стакан (снимки) | 30 дней, 1 снимок/инструмент/мин максимум | ~0.5 ГБ |
| `order_events`, `intents`, `orders` | 36 месяцев | <0.5 ГБ |
| `audit_log` | 5 лет (appending) | <0.5 ГБ |
| «сырые» снимки портфеля/операций | 13 месяцев (дальше — агрегаты) | ~1 ГБ |

Итого на 24 месяца: **~6–8 ГБ** данных + WAL + индексные разрастания → рабочий диск 40–60 ГБ
с запасом (расчёт в `docs/tz/14`). Партиции создаются заранее задачей `ensure_partitions`
(3 месяца вперёд), старые партиции — `DETACH`+выгрузка в Parquet вместо `DELETE`.

## 4.13 Бэкапы

`pg_dump -Fc` ежедневно (в рабочее время вне торговой сессии) + WAL-архив в объектное
хранилище/второй диск каждые 15 минут; ротация: 14 ежедневных, 8 еженедельных, 6 месячных;
ежеквартальный `restore-verify` на стенде с проверкой контрольных запросов (число заявок,
сумма P&L за период, хэш `audit_log`). Требование RPO ≤15 мин, RTO ≤2 ч фиксируется в runbook.
