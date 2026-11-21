"""Защита секрета привязки TOTP: `packages/identity/totp_secret.py` + колонка `secret_enc` (TZ §8.4, ADR-014, `T-103` `R4b`).

Здесь проверяется то, чего не видно на уровне примитивов: как шифрование встроено в предметную
область привязки.

* секрет, пришедший из `new_totp_secret` (base32-текст) или из байтов, попадает в `secret_enc`
  только шифртекстом, а наружу возвращается ровно тот ключ, который принимает `verify_totp_code`;
* шифртекст принадлежит конкретной строке `totp_enrollments` и её владельцу: перенос значения между
  привязками и между учётными записями даёт отказ (`ADR-014` п. 4);
* в колонку нельзя присвоить открытое значение — даже по ошибке, обычным `TotpEnrollment(...)`
  (валидатор модели, `ADR-014` п. 6);
* длины ключа проверяются с обеих сторон: нельзя зашифровать короткое значение и нельзя принять
  шифртекст, внутри которого значение вне границ §8.2/§8.4;
* base32-представление (для QR, срез `R4d`) совместимо с декодером из `R4a`, а подтверждение
  привязки двумя кодами работает на ключе, пришедшем из хранилища;
* тексты отказов называют колонку и не содержат ни секрета, ни ключей.

Проверки идут без базы: валидатор колонки срабатывает на присваивании, а не на запросе. Перенос
шифртекста через настоящий `bytea` — в `tests/integration/test_totp_secret_storage_db.py`.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from packages.common.crypto import (
    ENVELOPE_MAGIC,
    GCM_TAG_BYTES,
    OFFSET_DEK_NONCE,
    OFFSET_PAYLOAD,
    OFFSET_PAYLOAD_NONCE,
    DecryptionError,
    EnvelopeError,
    KeyRing,
    KeyRingError,
    KeyRingFormatError,
    build_aad,
    ensure_envelope,
    open_envelope,
    parse_key_ring_document,
    seal_envelope,
)
from packages.common.ids import uuid7
from packages.identity.totp import (
    TOTP_SECRET_BYTES,
    TotpSecretError,
    decode_totp_secret,
    new_totp_secret,
    totp_code,
    totp_provisioning_uri,
    verify_totp_pair,
)
from packages.identity.totp_secret import (
    AAD_KIND_TOTP_ENROLLMENT,
    CIPHERTEXT_COLUMN,
    open_totp_secret,
    protect_totp_secret,
    totp_secret_aad,
    totp_secret_base32,
)
from packages.storage.models import TotpEnrollment

# Тестовые значения ключей: файл ключей площадки в проверках не участвует (§8.4, ADR-004).
_KEK_B64: str = base64.b64encode(bytes([0x21]) * 32).decode("ascii")
_KEK_IMPOSTOR_B64: str = base64.b64encode(bytes([0x33]) * 32).decode("ascii")


def _ring_document(active: int, keys: tuple[tuple[int, str], ...]) -> str:
    body = ", ".join(f'{{"version": {version}, "key": "{key}"}}' for version, key in keys)
    return f'{{"format_version": 1, "active_version": {active}, "keys": [{body}]}}'


_RING: KeyRing = parse_key_ring_document(_ring_document(1, ((1, _KEK_B64),)), source="тест")
_IMPOSTOR_RING: KeyRing = parse_key_ring_document(
    _ring_document(1, ((1, _KEK_IMPOSTOR_B64),)), source="тест"
)
_NO_SUCH_VERSION_RING: KeyRing = parse_key_ring_document(
    _ring_document(9, ((9, _KEK_IMPOSTOR_B64),)), source="тест"
)

_USER_ID: UUID = uuid4()
_OTHER_USER_ID: UUID = uuid4()
_ENROLLMENT_ID: UUID = uuid4()
_OTHER_ENROLLMENT_ID: UUID = uuid4()


def _protect(
    secret: str | bytes,
    *,
    enrollment_id: UUID = _ENROLLMENT_ID,
    user_id: UUID = _USER_ID,
) -> bytes:
    return protect_totp_secret(secret, enrollment_id=enrollment_id, user_id=user_id, ring=_RING)


def _open(
    secret_enc: bytes,
    *,
    enrollment_id: UUID = _ENROLLMENT_ID,
    user_id: UUID = _USER_ID,
    ring: KeyRing = _RING,
) -> bytes:
    return open_totp_secret(secret_enc, enrollment_id=enrollment_id, user_id=user_id, ring=ring)


def test_секрет_привязки_оборачивается_и_возвращается_без_изменений() -> None:
    """base32-текст из `new_totp_secret` и байты ключа дают тот же ключ после чтения.

    Границы длины (§8.2, RFC 4226 §4) — 16, 20, 32 и 64 байта: именно их принимает декодер
    привязки. Шифрование не меняет ни длину, ни содержимое ключа.
    """
    for text in (new_totp_secret(), new_totp_secret()):
        assert _open(_protect(text)) == decode_totp_secret(text)

    raw = bytes(range(1, TOTP_SECRET_BYTES + 1))
    assert _open(_protect(raw)) == raw
    # Тот же ключ, отданный текстом (его `R4d` показывает в QR), даёт идентичный ключ.
    assert _open(_protect(totp_secret_base32(raw))) == raw
    for length in (16, 20, 32, 64):
        key = bytes(range(1, length + 1))
        assert _open(_protect(key)) == key


def test_в_шифртексте_нет_ни_секрета_ни_текста_привязки() -> None:
    """Открытый ключ и его base32-текст не встречаются в значении для `secret_enc`.

    Смысл §8.4 ровно в этом: дамп таблицы, резервная копия и `pg_dump` перестают содержать секрет.
    Длина значения держится отдельно: конверт фиксированной структуры, приписки с открытым
    значением к нему нет.
    """
    text = new_totp_secret()
    key = decode_totp_secret(text)
    envelope = _protect(text)

    assert key not in envelope
    assert text.encode("ascii") not in envelope
    assert base64.b32encode(key) not in envelope
    assert envelope.startswith(ENVELOPE_MAGIC)
    assert len(envelope) == OFFSET_PAYLOAD + len(key) + GCM_TAG_BYTES
    assert ensure_envelope(envelope, column=CIPHERTEXT_COLUMN) == envelope


def test_шифртекст_принадлежит_строке_и_её_владельцу() -> None:
    """Значение одной строки `totp_enrollments` не читается в другой и у другого пользователя.

    Это и есть привязка AAD (§8.4, `ADR-014` п. 4): дамп таблицы не превращается в набор секретов,
    которые можно переставить между учётными записями.

    Отдельно держится `kind`: шифртекст привязки TOTP не сойдёт за токен брокера из `T-107`, хотя
    идентификаторы совпадают.
    """
    envelope = _protect(new_totp_secret())
    assert _open(envelope)

    with pytest.raises(DecryptionError):
        _open(envelope, enrollment_id=_OTHER_ENROLLMENT_ID)
    with pytest.raises(DecryptionError):
        _open(envelope, user_id=_OTHER_USER_ID)
    with pytest.raises(DecryptionError):
        _open(envelope, enrollment_id=_OTHER_ENROLLMENT_ID, user_id=_OTHER_USER_ID)

    foreign_aad = build_aad(kind="broker_token", record_id=_ENROLLMENT_ID, owner_id=_USER_ID)
    with pytest.raises(DecryptionError):
        open_envelope(envelope, aad=foreign_aad, ring=_RING)

    assert AAD_KIND_TOTP_ENROLLMENT == "totp_enrollment"
    assert totp_secret_aad(_ENROLLMENT_ID, _USER_ID) == build_aad(
        kind=AAD_KIND_TOTP_ENROLLMENT, record_id=_ENROLLMENT_ID, owner_id=_USER_ID
    )


def test_разные_привязки_получают_разные_dek() -> None:
    """§8.4 «отдельный DEK на каждую запись» на уровне привязок: один секрет → разные значения.

    Различается обёртка DEK, а не только nonce: компрометация DEK одной привязки не открывает
    остальные строки таблицы.
    """
    text = new_totp_secret()
    first = _protect(text, enrollment_id=_ENROLLMENT_ID)
    second = _protect(text, enrollment_id=_OTHER_ENROLLMENT_ID)
    assert first != second
    assert (
        first[OFFSET_DEK_NONCE:OFFSET_PAYLOAD_NONCE]
        != second[OFFSET_DEK_NONCE:OFFSET_PAYLOAD_NONCE]
    )
    assert _open(first) == _open(second, enrollment_id=_OTHER_ENROLLMENT_ID)
    assert _open(first) == decode_totp_secret(text)


def test_открытый_секрет_в_колонку_не_присваивается() -> None:
    """`TotpEnrollment(secret_enc=...)` с открытым base32-секретом — отказ до обращения к базе.

    Модель — единственная точка, через которую приложение создаёт привязку, поэтому проверка на
    присваивании отклоняет и «положили секрет как есть», и значение другой формы. Текст отказа
    называет колонку и признак, но не само значение (§8.4).
    """
    text = new_totp_secret()
    open_value = text.encode("ascii")
    with pytest.raises(EnvelopeError) as caught:
        TotpEnrollment(id=uuid4(), user_id=_USER_ID, secret_enc=open_value, issuer="tbot")
    message = str(caught.value)
    assert CIPHERTEXT_COLUMN in message
    assert text not in message
    assert open_value.hex() not in message

    row = TotpEnrollment(id=uuid4(), user_id=_USER_ID, secret_enc=_protect(text), issuer="tbot")
    # Присваивание после создания объекта защищено так же: длинный открытый секрет и пустое значение.
    with pytest.raises(EnvelopeError):
        row.secret_enc = base64.b32encode(bytes(range(64)))
    with pytest.raises(EnvelopeError):
        row.secret_enc = b""
    envelope = _protect(text)
    row.secret_enc = envelope
    assert row.secret_enc == envelope


def test_подделка_и_обрезка_значения_отказываются_при_чтении() -> None:
    """Изменённое или усечённое значение колонки не расшифровывается и не даёт ключ.

    Модель не мешает правке через `UPDATE` в обход ORM, поэтому проверка на чтении обязана быть
    самодостаточной: тег GCM закрывает и содержимое, и принадлежность конкретной строке.
    """
    text = new_totp_secret()
    key = decode_totp_secret(text)
    envelope = _protect(text)

    tampered = bytearray(envelope)
    tampered[OFFSET_PAYLOAD_NONCE + 1] ^= 0x40
    with pytest.raises(DecryptionError):
        _open(bytes(tampered))
    for cut in (1, 16):
        with pytest.raises((DecryptionError, EnvelopeError)):
            _open(envelope[:-cut])
    with pytest.raises(EnvelopeError, match=CIPHERTEXT_COLUMN):
        _open(base64.b32encode(key))
    assert key not in envelope


def test_чужой_ключ_и_неизвестная_версия_отказываются_различимо() -> None:
    """Потерять ключ можно двумя способами, и отказ у них разный.

    * версии ключа нет в связке → `KeyRingError` (на площадке нет файла ключей нужной версии);
    * ключ той же версии, но другой → `DecryptionError` (значение не менялось, ключ подменён);
    * файл ключей не читается как связка → `KeyRingFormatError` ещё до любой работы с данными.

    Если бы все три случая отвечали одинаково, «состав подняли без KEK» выглядело бы как
    «у пользователя неверный второй фактор».
    """
    envelope = _protect(new_totp_secret())
    with pytest.raises(KeyRingError, match="отсутствует в связке KEK"):
        _open(envelope, ring=_NO_SUCH_VERSION_RING)
    with pytest.raises(DecryptionError):
        _open(envelope, ring=_IMPOSTOR_RING)
    with pytest.raises(KeyRingFormatError):
        parse_key_ring_document("", source="тест")
    # Ключ той же версии, но другой: значение, созданное под ним, «своим» AAD не открывается.
    forged = protect_totp_secret(
        new_totp_secret(), enrollment_id=_ENROLLMENT_ID, user_id=_USER_ID, ring=_IMPOSTOR_RING
    )
    with pytest.raises(DecryptionError):
        _open(forged)


def test_длины_ключа_проверяются_на_обеих_сторонах() -> None:
    """Короткое значение не шифруется, а шифртекст с коротким ключом внутри не принимается.

    Границы §8.2/§8.4 (128…512 бит) держат и запись, и чтение: иначе «ключ из чужой системы» или
    обрезанное значение уходит в генератор кода, где привязка выглядит работающей, пока не станет
    непригодной. Символы вне алфавита base32 — тоже отказ декодера, а не «тихая починка».
    """
    for bad_text in ("AB", "A" * 8, "0189", ""):
        with pytest.raises(TotpSecretError):
            _protect(bad_text)
    for length in (0, 8, 15, 65, 128):
        with pytest.raises(TotpSecretError):
            _protect(bytes(length))

    foreign = seal_envelope(b"korotkij", aad=totp_secret_aad(_ENROLLMENT_ID, _USER_ID), ring=_RING)
    with pytest.raises(TotpSecretError) as caught:
        _open(foreign)
    assert CIPHERTEXT_COLUMN in str(caught.value)
    assert "korotkij" not in str(caught.value)


def test_base32_представление_совместимо_с_декодером_привязки() -> None:
    """`totp_secret_base32` — то, что `R4d` покажет в QR; декодер `R4a` принимает это обратно.

    Без этого шага расшифрованный ключ нельзя отдать владельцу: provisioning-URI принимает
    base32-текст, и представление обязано возвращаться в приложение тем же путём, каким ушло.
    Отдельно держится, что в URI не попадает открытый ключ из хранилища — только текстовое
    представление, которое пользователь и так получит на экране.
    """
    for length in (16, 20, 32, 64):
        key = bytes(range(1, length + 1))
        text = totp_secret_base32(key)
        assert text.isascii()
        assert text == text.upper()
        assert "=" not in text
        assert decode_totp_secret(text) == key
        uri = totp_provisioning_uri(text, account_name="ivan", issuer="tbot")
        assert f"secret={text}" in uri
        assert key not in uri.encode()


def test_код_2fa_из_расшифрованного_ключа_совпадает_с_кодом_привязки() -> None:
    """Сквозной путь среза: сгенерировали секрет → зашифровали → прочитали → подтвердили привязку.

    Проверка связывает `R4a` (коды) с `R4b` (хранение): код считается и по текстовому секрету, и по
    ключу из `secret_enc`, а подтверждение привязки двумя последовательными кодами (§8.2) проходит
    на ключе из хранилища. Иначе «шифрование не мешает работе» оставалось бы обещанием.
    """
    text = new_totp_secret()
    moment = datetime.now(UTC).replace(microsecond=0)
    key = _open(_protect(text))

    assert totp_code(key, moment) == totp_code(text, moment)
    first = totp_code(key, moment)
    second = totp_code(key, moment + timedelta(seconds=30))
    result = verify_totp_pair(key, first, second, now=moment)
    assert result.status == "accepted"
    assert result.counter is not None
    # Тот же шаг повторно не принимается (§8.2 «коды принимаются один раз») — и на ключе из базы тоже.
    again = verify_totp_pair(key, first, second, last_used_counter=result.counter, now=moment)
    assert again.status == "replay"


def test_идентификатор_привязки_известен_до_шифрования() -> None:
    """AAD строится по id строки: id генерирует вызывающий код до шифрования (`R4c`).

    Python-side default у `id` применяется при вставке, а шифрование нужно до вставки. Порядок
    «`uuid7()` → шифрование → вставка» — часть контракта; проверка держит его на объекте модели,
    чтобы `R4c` не построил привязку «сначала вставили пустое значение, потом зашифровали».
    """
    enrollment_id = uuid7()
    text = new_totp_secret()
    envelope = _protect(text, enrollment_id=enrollment_id)
    row = TotpEnrollment(id=enrollment_id, user_id=_USER_ID, secret_enc=envelope, issuer="tbot")
    assert row.id == enrollment_id
    opened = _open(row.secret_enc, enrollment_id=row.id, user_id=row.user_id)
    assert opened == decode_totp_secret(text)


def test_тексты_отказов_без_секретов_и_с_именем_колонки() -> None:
    """Ни один отказ уровня привязки не печатает секрет; отказ о форме называет колонку.

    Именно эти тексты обработчик уносит в лог (§12.2 логирует причину отказа второго фактора),
    поэтому «секрет в логе» — не гипотетика, а прямое следствие текста исключения.
    """
    text = new_totp_secret()
    key = decode_totp_secret(text)
    envelope = _protect(text)
    attempts: tuple[Callable[[], object], ...] = (
        lambda: _open(base64.b32encode(key)),
        lambda: _open(envelope, user_id=_OTHER_USER_ID),
        lambda: _open(envelope[: OFFSET_DEK_NONCE + 5]),
        lambda: open_envelope(envelope, aad=b"", ring=_RING),
        lambda: _protect(""),
        lambda: _protect(bytes(4)),
        lambda: _open(
            seal_envelope(b"x", aad=totp_secret_aad(_ENROLLMENT_ID, _USER_ID), ring=_RING)
        ),
        lambda: _open(envelope, ring=_IMPOSTOR_RING),
        lambda: _open(envelope, ring=_NO_SUCH_VERSION_RING),
    )
    for index, attempt in enumerate(attempts):
        with pytest.raises(
            (EnvelopeError, DecryptionError, TotpSecretError, KeyRingError)
        ) as caught:
            attempt()
        message = f"{caught.value!r} {caught.value}"
        assert text not in message, f"отказ №{index}: текст привязки в сообщении"
        assert key.hex() not in message, f"отказ №{index}: ключ в сообщении"
        assert _KEK_B64 not in message, f"отказ №{index}: KEK в сообщении"
        assert _KEK_IMPOSTOR_B64 not in message, f"отказ №{index}: KEK в сообщении"
    with pytest.raises(EnvelopeError) as caught:
        _open(b"")
    assert CIPHERTEXT_COLUMN in str(caught.value)
