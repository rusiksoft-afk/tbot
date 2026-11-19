# 03. Контракт T‑Invest API: что обязано учесть ядро

Источник — официальная документация брокера (раздел Invest API) и contract-файлы официального
Python SDK. Ниже — рабочая выжимка для реализации; при расхождении с актуальной документацией
обновляется этот файл (задача с ADR), а не «на ходу» в коде.

## 3.1 Контуры и адреса

| Контур | gRPC | REST | WS |
|---|---|---|---|
| боевой | `invest-public-api.tbank.ru:443` | `https://invest-public-api.tbank.ru/rest/tinkoff.public.invest.api.contract.v1.<Service>/<Method>` | `wss://invest-public-api.tbank.ru/ws/...` |
| песочница | `sandbox-invest-public-api.tbank.ru:443` | `https://sandbox-invest-public-api.tbank.ru/rest/...` | аналогично |

`REQ-broker-gateway-01` В проекте используется официальный пакет `t-tech-investments`
(`from t_tech.invest.grpc import AsyncClient, AsyncSandboxClient`, request-модели из
`t_tech.invest.grpc.schemas`). Устаревшие импорты (`tinkoff.invest`, `t_tech.invest.services`)
запрещены линтером.
`REQ-broker-gateway-02` TLS: образ должен содержать корневой сертификат НУЦ Минцифры **или**
использовать штатный режим SDK с поставным сертификатом (переменная окружения `SSL_TBANK_VERIFY=True`).
Отключение проверки сертификата (`InsecureChannelCredentials`, `verify=False`) — запрещено.
`AC-broker-gateway-02` В CI есть тест: контейнер без установленного сертификата и без
`SSL_TBANK_VERIFY` не может установить соединение (ошибка TLS), с ними — может (на mock/песочнице).

> **Проверено на прод-площадке 2026-11-19** (`docs/research/03 §3.3`): цепочка
> `*.tbank.ru` ← `Russian Trusted Sub CA` ← `Russian Trusted Root CA`, срок действия
> сертификата до 2027-08-24; стандартное хранилище Ubuntu 24.04 корневой сертификат **не
> содержит** (`Verify return code: 19`), то есть без установки корня НУЦ любой корректный
> клиент падает на проверке. Оба механизма (системное хранилище хоста + сертификат в образе/
> `SSL_TBANK_VERIFY`) обязательны, проверка даты сертификата — часть `make deploy-check`.

## 3.2 Лимиты (обязательны к соблюдению, защищаемы бюджетом запросов)

Рекомендация брокера — суммарно ≤50 запросов/с; жёсткий порог по IP — 1000 запросов/мин
(превышение → ошибка/блокировка). Лимиты действуют суммарно по всем счетам и токенам пользователя.

| Сервис/метод | Лимит (унарные, запросов/мин) |
|---|---|
| Instruments (суммарно) | 200 |
| Instruments: `Shares/Bonds/Options/Futures/Etfs/GetAssets` | 15 |
| Users (счета, тариф, маржа) | 100 |
| Operations (портфель, позиции, операции) | 200; формирование отчётов — 5 |
| MarketData (свечи, цены, стакан, статусы, индикаторы) | 600 |
| StopOrders | 50; `GetStopOrders` — 60 |
| Sandbox | 200 |
| Orders (суммарно) | 100 |
| `GetOrders` | 200 |
| `PostOrder` | 15/с (900/мин) |
| `PostOrderAsync` | 600 |
| `CancelOrder` / `ReplaceOrder` | по 300 |
| Signals | 100 |

Стримы: котировки — 32 соединения; ордера — 16 на каждый тип стрима; операции — 11 на каждый
тип; в одном стриме котировок — ≤300 подписок (свечи+стакан+лента, суммарно), ≤100 запросов
подписки/мин; счётчик соединений обновляется раз в 2 минуты. Активные заявки лимита не имеют.
Троттлинг доставки в стриме котировок: стакан и свечи — не чаще 1 сообщения в 100 мс на
подписку; лента сделок, последняя цена, статусы — без троттлинга.

`REQ-broker-gateway-03` Реализуется распределённый (Redis-не требуется; общий для процессов через
БД/память) бюджет запросов: token bucket на каждый сервис с запасом 20% относительно таблиц
выше; при исчерпании вызов очереди ставится в ожидание, а не «пробивает» лимит; метрика
`tbot_api_budget_exhausted_total` и алерт.
`REQ-broker-gateway-04` Глобальный бюджет подписок (`subscribable instruments × intervals`)
ведётся в реестре `market-data` с резервом: не более 200 подписок и не более 24 соединений
котировок при целевом масштабе (лимиты брокера — 300/32), то есть запас на переподключение.
`AC-broker-gateway-04` Юнит-тест: попытка превысить бюджет даёт `BudgetExhausted`, стратегии
получают `Nothing` с причиной, метрика выросла.
`REQ-broker-gateway-05` Ретраи: допустимы только для идемпотентных read-методов (экспоненциальный
backoff 0.5→8 с, ≤4 попыток, jitter). Для `PostOrder/CancelOrder/ReplaceOrder/PostStopOrder`
авторетраи запрещены — см. `docs/tz/07`.

## 3.3 Заявки: поля и смысл идентификаторов

`PostOrder` (аналогично `PostSandboxOrder`): `account_id`, `instrument_id` (принимает FIGI,
`instrument_uid` или `ticker_classcode`), `quantity` (**в лотах**), `price` (`Quotation`:
`units`+`nano`), `direction` (`BUY`/`SELL`), `order_type` (`LIMIT`/`MARKET`/`BESTPRICE`),
`order_id` (**клиентский ключ идемпотентности**, UID ≤36 симв.), `time_in_force`
(`DAY` — по умолчанию, `FILL_AND_KILL`, `FILL_OR_KILL`; `FILL_OR_KILL` недоступен на срочном
рынке и в торговлю по выходным), `price_type` (`POINT` — фьючерсы и облигации, `CURRENCY`),
`confirm_margin_trade` (согласие на непокрытую позицию; по умолчанию `false`).

В ответе: `order_id` — **биржевой** идентификатор; `order_request_id` — возвращённый клиентский
ключ. Сверка статуса: `GetOrderState(order_id, order_id_type)` с
`ORDER_ID_TYPE_REQUEST` (клиентский ключ) или `ORDER_ID_TYPE_EXCHANGE` (биржевой id).

Статус заявки (`OrderExecutionReportStatus`): `NEW`, `PARTIALLYFILL`, `FILL`,
`CANCELLED`, `REJECTED` (+ `UNSPECIFIED`). Данные заявки в стриме/ответе: `lots_requested`,
`lots_executed`, `initial_order_price`, `executed_order_price`, `total_order_amount` (со
всеми комиссиями), `average_position_price`, `initial_commission`, `executed_commission`,
`service_commission`, `currency`, `order_date` (UTC), `figi`, `instrument_uid`, `ticker`,
`direction`, `initial_security_price` (за 1 штуку — умножать на лотность).

`REQ-order-executor-01` Клиентский ключ генерируется и сохраняется в БД до сетевого вызова;
в БД хранятся оба идентификатора и их тип. `AC-order-executor-01` см. `docs/tz/07 §7.4`.
`REQ-order-executor-02` Любая цена приводится к `min_price_increment` инструмента до отправки
(округление: покупка вниз, продажа вверх); при `price_type=POINT` для фьючерсов/облигаций
цена указывается в пунктах — это отдельная ветка логики (веха фьючерсов).

## 3.4 Торговые статусы и доступность операций

Перечисление статусов (`SecurityTradingStatus`) включает: `NOT_AVAILABLE_FOR_TRADING`,
`OPENING_PERIOD`, `CLOSING_PERIOD`, `BREAK_IN_TRADING`, `NORMAL_TRADING`, `CLOSING_AUCTION`,
`DARK_POOL_AUCTION`, `DISCRETE_AUCTION`, `OPENING_AUCTION_PERIOD`,
`TRADING_AT_CLOSING_AUCTION_PRICE`, `SESSION_ASSIGNED/CLOSE/OPEN`, дилерские варианты,
`STABILIZATION_AUCTION`. В объекте статуса есть флаги `limit_order_available_flag` и
`market_order_available_flag`.

`REQ-risk-gate-01` Перед любой заявкой проверяется актуальный статус торгов и соответствующий
флаг доступности типа заявки; для статусов аукциона/паузы/недоступности заявка отклоняется с
кодом `TRADING_STATUS_FORBIDDEN`. Кэш статуса должен быть не старше 30 с (или из стрима `Info`).
`AC-risk-gate-01` Тест: статус `BREAK_IN_TRADING` → отказ; `NORMAL_TRADING` +
`limit_order_available_flag=false` → лимитная заявка отклонена, рыночная разрешена.

## 3.5 Инструменты

Из карточки инструмента обязательны: `uid`, `figi` (устаревший — поддерживать только для
обратной совместимости), `ticker`, `class_code`, `instrument_type`, `exchange`/`real_exchange`,
`currency`, `lot` (количество штук в лоте), `min_price_increment` (`Quotation`),
`first_price`/`price` (актуальная цена), статус доступности (`InstrumentStatus`),
`sector`/`country`/`liquidation` (для ETF/БПИФ), признаки делистинга/блокировки.

`REQ-instrument-catalog-02` Каталог обновляется по расписанию (раз в 6 ч) и по событию (ошибка
«инструмент не найден/недоступен»); запись с устаревшими `lot`/`min_price_increment` не должна
использоваться для расчёта заявок старше 24 ч без повторного подтверждения.
`REQ-instrument-catalog-03` В БД хранится история изменений карточки (`instrument_snapshots`),
чтобы расчёты бэктеста и разбора прошлых сделок были воспроизводимы (сплиты, изменение лотности).

## 3.6 Счета, портфель, позиции, маржа

Типы счетов (`AccountType`): `TINKOFF`, `TINKOFF_IIS`, `INVEST_BOX`, `INVEST_FUND`, `DEBIT`,
`SAVING`, `DFA`, `SHARED_SAVING`, `DEPOSIT`, `OMS`, `OFP_DEPOSIT` (+ `UNSPECIFIED`); статусы:
`NEW`, `OPEN`, `CLOSED`, `ALL`. Правила допуска типов счетов — `docs/tz/01 §1.4`.

Портфель (`GetPortfolio`): разбивка `total_amount_*` по классам (акции, облигации, ETF,
валюты, фьючерсы, опционы), `expected_yield`, `daily_yield`, `daily_yield_relative`,
`total_var_margin`, `positions[]`. Позиции (`GetPositions`): `money[]`, `blocked[]`,
`securities[]` (в т.ч. заблокированные под заявки), `futures[]`, `options[]`,
`limits_loading_in_progress`. Маржа (`GetMarginAttributes`): `liquid_portfolio`,
`starting_margin`, `minimal_margin`, `funds_sufficiency_level`, `amount_of_missing_funds`,
`corrected_margin`, `guarantee_for_futures`. Расчёт доступных лотов — `GetMaxLots`:
`buy_limits`, `buy_margin_limits`, `sell_limits`, `sell_margin_limits`
(содержат `buy_money_amount`, `buy_max_lots`, `buy_max_market_lots`, `sell_max_lots`).

`REQ-portfolio-sync-01` Собственные расчёты позиции никогда не являются источником истины для
«сколько можно купить»: всегда используется `GetMaxLots`/`GetPositions` брокера. Расхождение
собственной позиции и брокеровской > 1 лота (или > 0.01 валюта) → инцидент `POSITION_MISMATCH`,
изоляция инструмента.
`REQ-portfolio-sync-02` `daily_yield_relative` и `expected_yield` отображаются как есть, но в
отчётах помечаются как данные брокера; собственный P&L считается по сделкам и комиссиям
(`docs/tz/04`).

## 3.7 Исторические данные

Интервалы свечей: `5SEC, 10SEC, 30SEC, 1MIN, 2MIN, 3MIN, 5MIN, 10MIN, 15MIN, 30MIN, HOUR,
2HOUR, 4HOUR, DAY, WEEK, MONTH`. Ограничения запроса: максимум 2400 свечей (1min/5min/15min/
hour/2hour/day), 1200 (2min/10min/30min), 750 (3min), 700 (4hour), 300 (week), 120 (month),
2500 (5sec, глубина ≤200 минут), 1250 (10sec, ≤200 минут), 2500 (30sec, ≤20 часов);
глубина выборки: 1min — до 1 дня, 15min — до 3 недель, hour — до 3 месяцев, day — до 6 лет,
month — до 10 лет. Источник свечей: `UNSPECIFIED` (все) / `EXCHANGE` (только биржевые) /
`INCLUDE_WEEKEND` (с учётом торговли по выходным).

`REQ-market-data-02` Загрузчик истории: итеративные окна с `from/to` и `limit`, пауза между
запросами согласно бюджету сервиса котировок (600/мин), чекпойнты в БД (`history_jobs`),
устойчивость к перезапуску, дедупликация по `(instrument_uid, interval, ts)`; при загрузке
используется `candleSourceType=EXCHANGE` для торговли и `INCLUDE_WEEKEND` только если
стратегия явно работает в выходные.
`AC-market-data-02` Повторный запуск прерванной загрузки не создаёт дублей (уникальный индекс)
и продолжает с последнего чекпойнта (тест сmock-сервером).

## 3.8 Прочие методы и явные «не трогать»

Доступны и полезны: `TradingSchedules` (расписания и торги/неторги), `GetAssetReports`,
`GetAssetFundamentals`, `GetDividends`, `GetBondCoupons`, `GetNews`, `GetTechAnalysis`
(BB/EMA/RSI/MACD/SMA — использовать как кросс-чек собственных индикаторов), `SignalService`
(`GetStrategies`, `GetSignals`) — зарезервировано под будущую веху «следование сигналам»,
`GetUserTariff`, `GetInfo`, `margin_attributes`.

Явно не используются (см. `docs/tz/15`): `CurrencyTransfer`, `PayIn` (кроме `SandboxPayIn` при
подготовке песочницы), `GetBankAccounts`, операции с ДФА, редактирование избранного — если
функция не запрошена явно, вызова нет.

## 3.9 Обработка ошибок брокера

HTTP/gRPC-коды, которые обязан различать слой: `400` (валидация — не ретраить, фиксировать
баг), `401` (токен — остановить стратегии контура, алерт «токен недействителен»), `403`
(нет прав — остановить стратегию по счёту), `404` (инструмент/счёт — обновить каталог), `408`
(таймаут — режим неопределённости для мутаций), `415`, `429` (исчерпан бюджет — backoff и
сигнализация), `500/501/503/504` (брокер — деградация, см. `docs/tz/02 §2.6`).

`REQ-broker-gateway-06` Классификация ошибок единая: `BrokerError` с полями
`kind` (`validation|auth|permission|not_found|timeout|rate_limited|server|transport`),
`code`, `request_id`, `retryable`, `mutation_safe`. Ни одна ветка не должна «съедать» ошибку
молча: каждая — в журнал и в метрики.
