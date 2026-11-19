"""TZ §2.7: время — только осознанное UTC; торговый день считается по Москве."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from packages.common.clock import (
    EPOCH_MS_MIN,
    MSK_TZ,
    is_utc_timezone,
    ms_timestamp,
    msk_now,
    to_msk,
    to_utc,
    trading_day_bounds,
    utc_month_start,
    utc_now,
)


def test_источник_сейчас_возвращает_осознанный_utc() -> None:
    moment = utc_now()
    assert moment.tzinfo is not None
    assert moment.utcoffset() == timedelta(0)


def test_наивное_время_отбрасывается() -> None:
    naive = datetime.fromtimestamp(1_763_000_000, tz=UTC).replace(tzinfo=None)
    with pytest.raises(ValueError, match="наивный datetime недопустим"):
        to_utc(naive)


def test_представление_в_москве_имеет_смещение_три_часа() -> None:
    local = msk_now()
    assert local.utcoffset() == timedelta(
        hours=3
    ), "летнее время в РФ отменено, смещение постоянное"
    assert local.tzinfo is not None
    assert str(local.tzinfo) == str(MSK_TZ)


def test_преобразование_не_меняет_момент() -> None:
    moment = utc_now()
    assert to_utc(to_msk(moment)) == moment


def test_границы_торгового_дня_выровнены_по_московской_полночи() -> None:
    for hour, minute in ((0, 0), (3, 0), (12, 30), (21, 0), (23, 59)):
        moment = datetime(2026, 11, 19, hour, minute, 59, tzinfo=UTC)
        start, end = trading_day_bounds(moment)
        assert end - start == timedelta(days=1)
        assert start.astimezone(MSK_TZ).time() == datetime.min.time()
        assert start <= to_utc(moment) < end


def test_границы_торгового_дня_сдвигаются_относительно_utc_дня() -> None:
    """Дневной лимит убытка не должен съезжать на три часа (docs/tz/06 §6.5)."""
    moment = datetime(2026, 11, 19, 2, 30, tzinfo=UTC)  # 05:30 того же дня по Москве
    start, _end = trading_day_bounds(moment)
    assert start.astimezone(UTC).day == 18, "начало московского дня — 21:00 UTC предыдущих суток"


def test_начало_месяца_для_границ_загрузки_истории() -> None:
    moment = datetime(2026, 11, 19, 21, 30, tzinfo=UTC)
    start = utc_month_start(moment)
    assert (start.year, start.month, start.day) == (2026, 11, 1)
    assert start.time() == datetime.min.time()


def test_метка_времени_в_миллисекундах_монотонна_и_правдоподобна() -> None:
    first, second = ms_timestamp(), ms_timestamp()
    assert second >= first
    assert first > EPOCH_MS_MIN.timestamp() * 1000
    assert abs(ms_timestamp() - utc_now().timestamp() * 1000) < 5_000


def test_проверка_часового_пояса_базы() -> None:
    assert is_utc_timezone(UTC)
    assert is_utc_timezone(UTC)
    assert not is_utc_timezone(MSK_TZ)
    assert not is_utc_timezone(None)
