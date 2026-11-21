"""Единая точка доступа к времени и идентификаторам (TZ §2.7).

Правила, которые обеспечивает модуль:

* всё внутреннее время — UTC, осознанное (`tzinfo` обязателен); наивные `datetime` отбрасываются
  функцией `to_utc` с явной ошибкой;
* отображение времени для человека — Европа/Москва (биржа MOEX, в том числе вечерняя сессия);
* `datetime.now()` вне модуля запрещён линтером (правила DTZ в `pyproject.toml`, проверка —
  тест `test_clock`);
* идентификаторы — UUIDv7 (упорядоченные по времени) и ключ идемпотенности заявки ≤36 символов
  (`PostOrder.order_id`, docs/tz/07 §7.2).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, tzinfo
from zoneinfo import ZoneInfo

MSK_TZ: ZoneInfo = ZoneInfo("Europe/Moscow")
EPOCH_MS_MIN = datetime(2024, 1, 1, tzinfo=UTC)


def utc_now() -> datetime:
    """Текущий момент в UTC (осознанный). Единственный разрешённый источник «сейчас»."""
    return datetime.now(UTC)


def msk_now() -> datetime:
    """Текущий момент в европейской части РФ — только для отображения человеку."""
    return datetime.now(MSK_TZ)


def to_utc(moment: datetime) -> datetime:
    """Привести к UTC. Наивное время — ошибка: оно неопределённо и ломает границы сессий."""
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError("наивный datetime недопустим: время должно быть с tzinfo (TZ §2.7)")
    return moment.astimezone(UTC)


def ensure_aware(moment: datetime | None = None) -> datetime:
    """Переданный момент (приведённый к UTC) или «сейчас».

    Нужен доменным функциям, которые принимают `now` для проверяемости тестов: наивное значение
    отсекается здесь же, а не тогда, когда объект уже изменён (§2.7).
    """
    return utc_now() if moment is None else to_utc(moment)


def to_msk(moment: datetime) -> datetime:
    """Представление для интерфейса/дайджестов (не для вычислений)."""
    return to_utc(moment).astimezone(MSK_TZ)


def utc_month_start(moment: datetime) -> datetime:
    """Первое число месяца начала периода — для границ загрузки истории и ретенции."""
    moment_utc = to_utc(moment)
    return moment_utc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def trading_day_bounds(moment: datetime) -> tuple[datetime, datetime]:
    """Границы торгового дня по Москве: [00:00 MSK, следующие 00:00 MSK) в UTC.

    Дневной лимит убытка считается по этому окну, а не по календарному UTC-дню: иначе
    «день» смещается на три часа относительно работы MOEX (docs/tz/06 §6.5).
    """
    local = to_msk(moment)
    start_local = local.replace(hour=0, minute=0, second=0, microsecond=0)
    end_local = start_local + timedelta(days=1)
    return to_utc(start_local), to_utc(end_local)


def ms_timestamp(moment: datetime | None = None) -> int:
    """Метки в миллисекундах (метрики брокера, ключи катодов)."""
    return int((to_utc(moment) if moment is not None else utc_now()).timestamp() * 1000)


def is_utc_timezone(zone: tzinfo | None) -> bool:
    """Проверка, что часовой пояс реально является UTC (для проверок конфигурации Postgres)."""
    return zone is not None and zone.utcoffset(None) == timedelta(0)
