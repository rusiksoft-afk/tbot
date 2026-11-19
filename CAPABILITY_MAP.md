# Capability Map — Tbot (торговый бот для T‑Invest API)

Инициатива: многопользовательский торговый бот + веб-панель + Telegram-управление для
брокера Т‑Банк (T‑Invest API, MOEX). Репозиторий: приватный `rusiksoft-afk/tbot`.

Правила карты: id модулей в kebab-case, выбираются один раз и не переименовываются;
зависимости направлены в одну сторону (циклов нет); контракт между модулями описывается
в спецификации модуля-поставщика (`docs/tz/`, REQ‑id того же модуля).

| # | Module id | Ответственность | Зависит от | Веха |
|---|---|---|---|---|
| 1 | `platform-foundation` | каркас репозитория, конфигурация (pydantic-settings), DI, логирование без секретов, временные зоны, ошибки, `make`-команды, Docker/Compose, CI | — | M0 |
| 2 | `storage` | PostgreSQL 16: схема, миграции (Alembic), партиционирование свечей, ретенция, бэкап/восстановление | `platform-foundation` | M0 |
| 3 | `indicators` | чистые функции индикаторов (SMA/EMA/RSI/MACD/ATR/BB) без сети и БД, с тестами | — | M4 |
| 4 | `identity` | пользователи, роли (admin/operator/viewer), приглашения+одобрение, сессии, пароли, 2FA TOTP + резервные коды, audit log, IP-allowlist | `platform-foundation`, `storage` | M1 |
| 5 | `credentials` | зашифрованное хранилище токенов T‑Invest, проверка токена, срок жизни (3 мес.), напоминания о ротации, маскирование | `identity`, `storage` | M1 |
| 6 | `web-auth` | веб-оболочка входа: логин, TOTP, резервный код, страница статуса, смена пароля, регистрация 2FA | `identity`, `credentials` | M1 |
| 7 | `broker-gateway` | слой T‑Invest API: gRPC-клиент, цели production/sandbox, бюджет запросов (token bucket), ретраи только для read, таксономия ошибок, идемпотентность, лимиты стримов, TLS НУЦ | `platform-foundation` | M2 |
| 8 | `instrument-catalog` | метаданные инструментов: лотность, шаг цены, валюта, статус доступности, расписания/торговые сессии, кэш, поиск | `broker-gateway`, `storage` | M2 |
| 9 | `market-data` | приём данных: стримы (свечи/стакан/последняя цена/статусы), догрузка истории, нормализация в `Decimal`, лаг и разрывы, кэш | `broker-gateway`, `instrument-catalog`, `storage` | M2 |
| 10 | `portfolio-sync` | счета, портфель, позиции, деньги/блокировки, операции, маржинальные показатели, сверка (reconciliation), снимки | `broker-gateway`, `storage` | M3 |
| 11 | `risk-gate` | детерминированный риск-контроль: лимиты, проверки перед заявкой, kill-switch, аварийное закрытие, журнал событий риска | `portfolio-sync`, `instrument-catalog`, `market-data`, `storage` | M3 |
| 12 | `order-executor` | жизненный цикл заявки: клиентский ключ идемпотентности, выставление/замена/отмена, частичные исполнения, сверка после таймаута, состояние при рестарте | `risk-gate`, `broker-gateway`, `portfolio-sync`, `storage` | M3 |
| 13 | `strategy-engine` | планировщик стратегий, жизненный цикл экземпляра, контуры sandbox/paper/production, журнал сигналов, реестр стратегий (plugin registry) | `market-data`, `instrument-catalog`, `risk-gate`, `storage` | M4 |
| 14 | `strategy-grid` | стратегия «сетка с усреднением» Long/Short (уровни, шаги, множитель, подтяжка, цель по позиции) | `strategy-engine`, `indicators` | M4 |
| 15 | `strategy-ta` | стратегия по индикаторам (тренд/возврат), вход/выход, стоп-заявки брокера, фильтры | `strategy-engine`, `indicators` | M4 |
| 16 | `backtest` | загрузчик истории с бюджетом API, событийный симулятор без заглядывания вперёд, модель комиссий/ликвидности/проскальзывания, метрики, оптимизатор, walk-forward | `market-data`, `strategy-engine`, `indicators`, `storage` | M5 |
| 17 | `notifications` | правила оповещений, дедупликация, суточный дайджест, шаблоны сообщений, журнал отправки | `portfolio-sync`, `storage` | M4 |
| 18 | `telegram-bot` | привязка chat_id с подтверждением, уведомления, команды чтения, управляющие команды с TOTP-подтверждением, inline-кнопки | `notifications`, `identity`, `strategy-engine`, `order-executor` | M4/M6 |
| 19 | `web-console` | торговая консоль: стратегии, позиции, заявки, данные, портфель, отчёты/экспорт, страница состояния системы | `identity`, `credentials`, `strategy-engine`, `portfolio-sync`, `market-data`, `backtest` | M6 |
| 20 | `ops-observability` | метрики Prometheus, health/readiness, алерты инфраструктуры, бюджеты API в наблюдаемости, runbook, бэкап-драйлы | `platform-foundation`, `storage`, `broker-gateway` | M2…M7 |

## Порядок сборки

```
M0: platform-foundation → storage
M1: identity → credentials → web-auth
M2: broker-gateway → instrument-catalog → market-data   (+ ops-observability базовый)
M3: portfolio-sync → risk-gate → order-executor          (валидация в песочнице)
M4: indicators → strategy-engine → strategy-grid, strategy-ta;
    notifications → telegram-bot (чтение)                 (валидация в paper)
M5: backtest (загрузчик → симулятор → метрики → оптимизатор/walk-forward)
M6: web-console (полный контур) + telegram-bot (управление) + отчёты
M7: ops-observability (полный контур) → боевой запуск с малыми лимитами
```

Параллельно без пересечений можно: `indicators` (3) с самого начала; `web-auth` (6)
параллельно с `broker-gateway` (7); отчётность/экспорт внутри `web-console` —
параллельно с `backtest`.

## Границы, которые не пересматриваются в коде

- Стратегия не вызывает выставку заявки: только торговое намерение → `risk-gate` → `order-executor`.
- `broker-gateway` — единственная точка выхода в T‑Invest API; `notifications`/`telegram-bot`
  не имеют доступа к торговым методам.
- Контуры (`sandbox` / `paper` / `production`) — явная конфигурация экземпляра стратегии,
  не выводится из данных счёта или текста сигнала.
- Наружу не уходят: токены, ключи шифрования, ПДн, содержимое ордеров клиентов.
