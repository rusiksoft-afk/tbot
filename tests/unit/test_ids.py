"""TZ §2.7 и docs/tz/07 §7.2: UUIDv7 и ключ идемпотенности заявки (≤36 символов)."""

from __future__ import annotations

from uuid import RFC_4122

import pytest

from packages.common.ids import (
    CLIENT_KEY_MAX_LEN,
    client_order_key,
    is_valid_client_key,
    new_correlation_id,
    new_trace_id,
    new_uuid7,
    uuid7,
)


def test_uuid7_имеет_версию_и_вариант_rfc() -> None:
    value = uuid7()
    assert value.version == 7
    assert value.variant == RFC_4122


def test_uuid7_упорядочены_по_метке_времени() -> None:
    earlier = uuid7(node_ms=1_700_000_000_000)
    later = uuid7(node_ms=1_700_000_000_001)
    assert earlier < later
    # Сортировка в Б-tree идёт по значению UUID целиком, поэтому упорядоченность обеспечивается
    # старшими битами: метка времени — первые 48 бит значения (столько же, сколько в `node_ms`).
    assert (earlier.int >> 80) < (later.int >> 80)
    # Разрыв больше 2^16 мс заметен уже в первой группе полей (time_low) — на малом шаге она
    # одинакова, и это надо помнить при попытке сортировки по отдельным полям UUID.
    far_later = uuid7(node_ms=1_700_000_000_000 + (1 << 16))
    assert earlier.fields[0] < far_later.fields[0]


def test_uuid7_метка_времени_восстанавливается() -> None:
    node_ms = 1_750_000_000_123
    value = uuid7(node_ms=node_ms)
    assert value.int >> 80 == node_ms


def test_uuid7_отказывает_за_пределами_48_бит() -> None:
    with pytest.raises(ValueError, match="вне диапазона 48 бит"):
        uuid7(node_ms=1 << 48)
    with pytest.raises(ValueError, match="вне диапазона 48 бит"):
        uuid7(node_ms=-1)


def test_уникальность_без_повторов_на_большом_объёме() -> None:
    generated = {new_uuid7() for _ in range(20_000)}
    assert len(generated) == 20_000


def test_ключ_идемпотентности_укладывается_в_потолок_поля() -> None:
    key = client_order_key()
    assert len(key) <= CLIENT_KEY_MAX_LEN
    assert is_valid_client_key(key)


def test_ключ_с_префиксом_тоже_в_потолке() -> None:
    key = client_order_key(prefix="tbot")
    assert len(key) == CLIENT_KEY_MAX_LEN
    assert key.startswith("tbot")
    assert is_valid_client_key(key)


@pytest.mark.parametrize("prefix", ["T", "tb-t", "toolong", "апп", "", "1"])
def test_недопустимый_префикс_отклоняется_или_допустим(prefix: str) -> None:
    # Правило то же, что в `ids.CLIENT_KEY_PREFIX_RE`: ASCII, нижний регистр и цифры.
    # `str.islower()` на цифрах возвращает False, поэтому сравнение идёт с `prefix.lower()`.
    allowed = prefix == "" or (
        prefix.isascii() and prefix == prefix.lower() and prefix.isalnum() and len(prefix) <= 4
    )
    if allowed:
        assert is_valid_client_key(client_order_key(prefix=prefix))
    else:
        with pytest.raises(ValueError, match="префикс ключа"):
            client_order_key(prefix=prefix)


def test_ключ_не_обрезается_до_36_символов_потерей_уникальности() -> None:
    keys = {client_order_key(prefix="tbot") for _ in range(5_000)}
    assert len(keys) == 5_000
    assert all(len(key) == CLIENT_KEY_MAX_LEN for key in keys)


@pytest.mark.parametrize(
    "bad_key",
    ["", "abc", "A" * 36, "x" * 37, "ключ_из_кириллицы", "has-dash", "has space"],
)
def test_кривые_ключи_не_проходят_проверку(bad_key: str) -> None:
    assert not is_valid_client_key(bad_key)


def test_trace_id_без_метки_времени_и_длиной_32() -> None:
    trace = new_trace_id()
    assert len(trace) == 32
    assert trace.isascii()
    assert all(char in "0123456789abcdef" for char in trace)
    assert len({new_trace_id() for _ in range(1_000)}) == 1_000


def test_correlation_id_это_uuid7() -> None:
    value = new_correlation_id()
    assert len(value) == 36
    assert value[14] == "7"
