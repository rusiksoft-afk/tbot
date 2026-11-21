"""Живой PostgreSQL и `totp_enrollments.secret_enc`: перенос шифртекста и границы защиты (TZ §8.4, ADR-014, `T-103` `R4b`).

Офлайн-половинка этих проверок — `tests/unit/test_totp_secret_protection.py` (шифрование, привязка
AAD, валидатор модели). Здесь то, что видно только на сервере:

* `bytea` переносит значение конверта без изменений. Шанс того, что в шифртексте окажется `0x00`,
  `\\x5c` или последовательность вида «\\x», — примерно один к четырём на строку; теряй перенос
  байты, привязка ломалась бы выборочно и только на площадке;
* открытый секрет не попадает в параметры запроса: в `INSERT` и `SELECT` уходит только шифртекст,
  поэтому журнал запросов (`pg_stat_statements`, дампы расшифровки сбоев) не содержит секрет —
  §8.4 «KEK и секреты не в БД» касается не только содержимого колонок;
* база форму шифртекста не проверяет: `bytea` принимает любые байты. Проверка фиксирует границу
  ответственности (`ADR-014` п. 6) — правка строки прямым `UPDATE` возможна, и на чтении такое
  значение обязан отклонить слой шифрования.

Запуск: та же `TBOT_DB_URL`, что у `test_identity_schema_db.py` (шаги job'а `migrations` разворачивают
схему до `upgrade head`). Без переменной группа пропускается целиком; при заданной, но недоступной
базе — падает, а не пропускается.
"""

from __future__ import annotations

import base64
import os
import uuid
from collections.abc import Iterator, Mapping, Sequence
from typing import Any, Final, Protocol

import psycopg
import pytest

from packages.common.crypto import DecryptionError, EnvelopeError, KeyRing, parse_key_ring_document
from packages.common.db import psycopg_dsn
from packages.identity.totp import decode_totp_secret, new_totp_secret
from packages.identity.totp_secret import open_totp_secret, protect_totp_secret

# Значение читается до аутофикстуры `clean_tbot_env`: на уровне модуля решается, идти ли в группу.
_DB_URL = os.environ.get("TBOT_DB_URL", "")

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="нет TBOT_DB_URL: нужны живой PostgreSQL (группа исполняется в CI job `migrations`)",
)

_ARGON2ID_SAMPLE = (
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA"
    "$6ztZ9VW1S0m1aK1P0d1kQ2w3e4r5t6y7u8i9o0p1q2s"
)
# Тестовый KEK: значения площадки в проверках не участвуют (§8.4 и ADR-004 — значения вносит только
# `deploy/vps/secrets-setup.sh`).
_KEK_B64: Final = base64.b64encode(bytes([0x2A]) * 32).decode("ascii")
_RING: Final[KeyRing] = parse_key_ring_document(
    f'{{"format_version": 1, "active_version": 1, '
    f'"keys": [{{"version": 1, "key": "{_KEK_B64}"}}]}}',
    source="живая проверка базы",
)


# Сигнатура совместима с psycopg: настоящее соединение принимает более широкий набор
# типов, поэтому оно подходит под протокол; прокси обязан принять ровно то, что дают тесты.
_Params = Sequence[Any] | Mapping[str, Any]


class _Executes(Protocol):
    """Общая сигнатура для настоящего соединения и прокси-обёртки со сбором параметров."""

    def execute(
        self, query: str, params: _Params | None = None
    ) -> psycopg.Cursor[tuple[Any, ...]]: ...


@pytest.fixture(scope="module")
def connection() -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    """Одно соединение на модуль: схему подняли шаги job'а `migrations` до запуска тестов.

    Молчаливого пропуска при недоступной базе нет: если `TBOT_DB_URL` задана, проверка обязана
    состояться — иначе зелёный шаг в CI означал бы «проверки не было».
    """
    conn = psycopg.connect(psycopg_dsn(_DB_URL), connect_timeout=10)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def _rollback_between_tests(connection: psycopg.Connection[tuple[Any, ...]]) -> Iterator[None]:
    """Каждый тест откатывается: база после прогона остаётся в состоянии `upgrade head` без данных.

    Откат нужен и потому, что часть проверок вставляет привязки намеренно «неправильной» формы, а
    следующая проверка читает ту же таблицу.
    """
    connection.rollback()
    yield
    connection.rollback()


class _RecordingConnection:
    """Прокси соединения: собирает текст запроса и параметры каждого обращения.

    Нужен ровно для одного утверждения — в параметрах запросов, которые уходят серверу (а затем в
    `pg_stat_statements` и в лог запросов), открытого секрета нет.
    """

    def __init__(self, conn: psycopg.Connection[tuple[Any, ...]]) -> None:
        self._conn = conn
        self.calls: list[tuple[str, object]] = []

    def execute(self, query: str, params: _Params | None = None) -> psycopg.Cursor[tuple[Any, ...]]:
        self.calls.append((str(query), params))
        return self._conn.execute(query, params)

    def rollback(self) -> None:
        self._conn.rollback()

    def payload(self) -> bytes:
        """Все параметры всех запросов одним потоком байтов: что в них искать — решает тест."""
        chunks: list[bytes] = []
        for _, params in self.calls:
            values = params if isinstance(params, tuple | list) else (params,)
            for value in values:
                if isinstance(value, bytes):
                    chunks.append(value)
                elif isinstance(value, str):
                    chunks.append(value.encode("utf-8"))
        return b"".join(chunks)


def _make_user(conn: _Executes, login: str) -> uuid.UUID:
    user_id = uuid.uuid4()
    conn.execute(
        "INSERT INTO users (id, login, role, state, password_hash) "
        "VALUES (%s, %s, 'operator', 'active', %s)",
        (user_id, login, _ARGON2ID_SAMPLE),
    )
    return user_id


def _save_enrollment(
    conn: _Executes, *, user_id: uuid.UUID, enrollment_id: uuid.UUID, secret_enc: bytes
) -> None:
    conn.execute(
        "INSERT INTO totp_enrollments (id, user_id, secret_enc, issuer) VALUES (%s, %s, %s, %s)",
        (enrollment_id, user_id, secret_enc, "tbot"),
    )


def _load_secret_enc(conn: _Executes, enrollment_id: uuid.UUID) -> bytes:
    row = conn.execute(
        "SELECT secret_enc FROM totp_enrollments WHERE id = %s", (enrollment_id,)
    ).fetchone()
    assert row is not None
    value = row[0]
    assert isinstance(value, bytes | memoryview)
    return bytes(value)


def test_шифртекст_привязки_проходит_через_bytea_без_изменений(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Значение, вставленное параметром, возвращается байт в байт и расшифровывается обратно.

    Проверяется весь путь, а не только шифрование: `protect_totp_secret` → `INSERT` → каталог базы →
    `SELECT` → `open_totp_secret`. Потеря одного байта на переносе дала бы отказ тега на части
    строк — самый неудобный из дефектов: работает везде, кроме площадки.
    """
    user_id = _make_user(connection, "totp.cipher.roundtrip")
    for index in range(5):
        enrollment_id = uuid.uuid4()
        text = new_totp_secret()
        expected = decode_totp_secret(text)
        envelope = protect_totp_secret(
            text, enrollment_id=enrollment_id, user_id=user_id, ring=_RING
        )
        _save_enrollment(
            connection, user_id=user_id, enrollment_id=enrollment_id, secret_enc=envelope
        )

        stored = _load_secret_enc(connection, enrollment_id)
        assert stored == envelope, f"строка №{index}: bytea изменил шифртекст"
        assert len(stored) == len(envelope)
        assert (
            open_totp_secret(stored, enrollment_id=enrollment_id, user_id=user_id, ring=_RING)
            == expected
        ), f"строка №{index}: ключ после чтения не совпал"
        assert expected not in stored


def test_bytea_переносит_любые_байты_шифртекста(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Полный диапазон байтов (включая `0x00`, `\\x5c` и переводы строк) возвращается без изменений.

    Полагаться на случайные прогоны нельзя: шанс встретить `0x00` в конкретном шифртексте — около
    одного к четырём. Здесь перенос проверяется на всём диапазоне байтов, а корректность
    шифрования — в офлайн-половинке.
    """
    user_id = _make_user(connection, "totp.cipher.allbytes")
    enrollment_id = uuid.uuid4()
    arbitrary = bytes(range(256)) * 2
    _save_enrollment(connection, user_id=user_id, enrollment_id=enrollment_id, secret_enc=arbitrary)
    assert _load_secret_enc(connection, enrollment_id) == arbitrary


def test_в_параметрах_запросов_открытого_секрета_нет(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """В параметрах обращений к базе — только шифртекст: ни ключа, ни base32-текста там нет.

    «Секреты не в БД» (§8.4) не ограничивается содержимым колонок: текст запроса и параметры уходят
    в `pg_stat_statements` и в логи. Проверка собирает параметры всех обращений и ищет в них и
    ключ, и текстовое представление привязки, и тестовый KEK.
    """
    recorder = _RecordingConnection(connection)
    user_id = uuid.uuid4()
    recorder.execute(
        "INSERT INTO users (id, login, role, state, password_hash) "
        "VALUES (%s, %s, 'operator', 'active', %s)",
        (user_id, "totp.cipher.params", _ARGON2ID_SAMPLE),
    )
    enrollment_id = uuid.uuid4()
    text = new_totp_secret()
    key = decode_totp_secret(text)
    envelope = protect_totp_secret(text, enrollment_id=enrollment_id, user_id=user_id, ring=_RING)
    _save_enrollment(recorder, user_id=user_id, enrollment_id=enrollment_id, secret_enc=envelope)
    stored = _load_secret_enc(recorder, enrollment_id)

    payload = recorder.payload()
    assert envelope in payload, "шифртекст обязан уходить в запрос — это и есть запись"
    assert key not in payload, "открытый ключ привязки ушёл в параметры запроса"
    assert text.encode("ascii") not in payload, "base32-текст привязки ушёл в параметры запроса"
    assert base64.b32encode(key) not in payload
    assert _KEK_B64.encode() not in payload, "KEK ушёл в параметры запроса"
    assert stored == envelope


def test_база_форму_шифртекста_не_проверяет_a_приложение_проверяет(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Граница ответственности: `bytea` принимает любое значение, отказывает слой шифрования.

    Это не «дырка, которую надо скорее закрыть CHECK-ограничением», а зафиксированное состояние
    (`ADR-014` п. 6): в `bytea` осмысленное ограничение на формат шифртекста не помещается (значение
    бинарное, признак формата — в первых байтах и в длине), а CHECK ради него означал бы ревизию
    схемы ради правила приложения. Проверка держит оба факта: прямой `INSERT` открытого значения
    проходит, а `open_totp_secret` на нём отказывает. Значит защита обязана жить на стороне
    приложения и не «протечёт» из-за правки строки в обход ORM.
    """
    user_id = _make_user(connection, "totp.cipher.rawwrite")

    # (1) открытое значение в bytea проходит: ограничением на форме база не прикроется.
    open_id = uuid.uuid4()
    open_value = base64.b32encode(bytes(range(1, 21))).decode("ascii").rstrip("=").encode("ascii")
    _save_enrollment(connection, user_id=user_id, enrollment_id=open_id, secret_enc=open_value)
    stored_open = _load_secret_enc(connection, open_id)
    assert stored_open == open_value, "база обязана принять значение: CHECK на форму в bytea нет"
    with pytest.raises(EnvelopeError, match="меньше минимума"):
        open_totp_secret(stored_open, enrollment_id=open_id, user_id=user_id, ring=_RING)

    # (2) корректный конверт, изменённый в полезной нагрузке: тег на месте, содержимое — нет.
    real_id = uuid.uuid4()
    envelope = protect_totp_secret(
        new_totp_secret(), enrollment_id=real_id, user_id=user_id, ring=_RING
    )
    _save_enrollment(connection, user_id=user_id, enrollment_id=real_id, secret_enc=envelope)
    stored = _load_secret_enc(connection, real_id)
    assert stored == envelope
    tampered = bytearray(stored)
    tampered[-8] ^= 0xFF
    assert bytes(tampered) != stored
    assert len(bytes(tampered)) == len(stored)
    with pytest.raises(DecryptionError):
        open_totp_secret(bytes(tampered), enrollment_id=real_id, user_id=user_id, ring=_RING)
