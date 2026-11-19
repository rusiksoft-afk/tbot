"""Идентификаторы: UUIDv7, trace_id, ключ идемпотенности заявки (TZ §2.7, docs/tz/07 §7.2).

UUIDv7 (RFC 9562) выбран намеренно: значения упорядочены по времени создания, поэтому индексы
Postgres не фрагментируются случайными вставками, а сортировка по `id` совпадает с хронологией.

Ключ идемпотенности заявки ограничен 36 символами: это потолок поля `PostOrder.order_id`
(`max_len=36`), и ключ обязан помещаться целиком, без усечения.
"""

from __future__ import annotations

import re
import secrets
import uuid
from uuid import UUID

from packages.common.clock import ms_timestamp

CLIENT_KEY_MAX_LEN = 36
CLIENT_KEY_PREFIX_MAX_LEN = 4
CLIENT_KEY_RE = re.compile(r"^[a-z0-9]{4,36}$")
CLIENT_KEY_PREFIX_RE = re.compile(r"^[a-z0-9]{0,4}$")

_U48 = (1 << 48) - 1
_U12 = (1 << 12) - 1
_U62 = (1 << 62) - 1


def uuid7(node_ms: int | None = None) -> UUID:
    """UUID версии 7: 48 бит метки времени, 12 бит случайности, 62 бит случайности.

    `node_ms` передаётся только тестами, чтобы получить детерминированную упорядоченность.
    """
    timestamp = ms_timestamp() if node_ms is None else node_ms
    if not 0 <= timestamp <= _U48:
        raise ValueError(f"метка времени вне диапазона 48 бит: {timestamp}")
    value = (timestamp & _U48) << 80
    # Разметка UUIDv7 (RFC 9562): 48 бит метки, затем 12 бит случайности (rand_a), 4 бита версии,
    # 2 бита варианта и 62 бита случайности (rand_b). Позиции проверены тестами: версия читается
    # из старшего полубайта поля time_hi_and_version (биты 76..63), вариант — из битов 63..62.
    value |= 0x7 << 76  # версия 7
    value |= (secrets.randbits(12) & _U12) << 64  # rand_a
    value |= 0b10 << 62  # вариант RFC 4122
    value |= secrets.randbits(62) & _U62
    return UUID(int=value)


def new_uuid7() -> str:
    """UUIDv7 в каноническом текстовом виде (для колонок и внешних ключей)."""
    return str(uuid7())


def new_trace_id() -> str:
    """Идентификатор трассировки: 32 hex-символа, не связан с временем намеренно.

    Метка времени в trace_id не нужна: порядок событий уже обеспечен UUIDv7 и колонкой `ts`,
    а публичный «когда» в идентификаторе запроса нежелателен (docs/tz/08 §8.9).
    """
    return uuid.uuid4().hex


def client_order_key(prefix: str = "") -> str:
    """Ключ идемпотенности для `PostOrder.order_id`: не длиннее 36 символов и уникален.

    Формат: необязательный префикс до 4 символов + 32 hex-символа UUIDv7. Префикс полезен при
    разборе биржевых стаканов («tbot»), но не обязан присутствовать.
    """
    if not CLIENT_KEY_PREFIX_RE.match(prefix):
        raise ValueError(f"префикс ключа некорректен: {prefix!r} (допустимо [a-z0-9]{{0,4}})")
    key = f"{prefix}{uuid7().hex}"
    if len(key) > CLIENT_KEY_MAX_LEN:  # защита от изменений формата в будущем
        raise ValueError(f"ключ идемпотенности длиннее {CLIENT_KEY_MAX_LEN}: {len(key)}")
    return key


def is_valid_client_key(key: str) -> bool:
    """Проверка ключа перед отправкой брокеру (ошибка должна быть локальной, а не `400`)."""
    return bool(CLIENT_KEY_RE.fullmatch(key)) and len(key) <= CLIENT_KEY_MAX_LEN


def new_correlation_id() -> str:
    """Идентификатор сопоставления «намерение → заявка → сделка» (docs/tz/07 §7.4)."""
    return str(uuid7())
