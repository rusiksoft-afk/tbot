"""Шифрование секрета привязки TOTP (`totp_enrollments.secret_enc`) — `T-103` срез `R4b`, TZ §8.4, ADR-014.

Модуль отвечает на один вопрос: как значение поля `secret_enc` перестаёт быть открытым секретом, не
переставая быть секрете, из которого выдаётся код. Примитивы и файл ключей лежат в
`packages/common/crypto.py` (№1 Capability Map), здесь — привязка к предметной области: состав AAD,
границы длины ключа и то, что именно означает «шифртекст принадлежит этой привязке».

Решения, которые зафиксированы здесь (подробный разбор — `ADR-014`):

1. **AAD = `kind` + `enrollment_id` + `user_id`.** §8.4 требует привязки `credential_id` + `owner_id`
   + `kind`; для привязки TOTP это строка таблицы `totp_enrollments`, её владелец и `kind`
   (`AAD_KIND_TOTP_ENROLLMENT`). Шифртекст перестаёт быть переносимым: вырезанное значение из одной строки
   и вставив в другую, мы получаем отказ тега, а не «чужой секрет, который работает». Именно это и
   нужно от защиты по §8.4 — дамп таблицы остаётся бесполезным сам по себе.
2. **Порядок «сначала id строки, потом шифрование».** AAD строится по `enrollment_id`, поэтому
   идентификатор строки известен до шифрования. В модели `id` — UUID с python-side default, так что
   это естественно; но это же исключает схему «вставили строку с пустым secret_enc, потом
   обновили» — шифрование обязано быть частью создания привязки (`R4c`).
3. **Границы длины ключа проверяются с обеих сторон.** При шифровании — чтобы не зашифровать мусор;
   при расшифровании — потому что шифртекст, созданный вне приложения (или изменённый вместе с
   ключом шифрования), не должен уходить в `hotp()` с произвольной длиной.
4. **Наружу отдаётся ключ, а не «текст секрета».** `open_totp_secret` возвращает `bytes` — то, что
   принимает `code_matches`; в текст base32 значение переводится только там, где оно нужно
   пользователю (QR-ссылка provisioning, `R4d`), и только в одном локальном биндинге.
5. **Никакого секретного значения в текстах ошибок.** В исключениях — версии, длины и имена колонок.

Защита колонки `secret_enc` от открытого значения — не здесь, а в модели `TOTPEnrollment`
(`packages/storage/models.py`, валидатор `@validates` поверх `ensure_envelope` из `common.crypto`):
у правила должен быть один владелец, иначе «своё» правило в домене и правило в модели разъедутся.

Чего здесь нет: маршрутов и использования секретника (`R4c`), QR-ссылки и digest-пересъёмки (`R4d`),
ротации ключей (`T-107`), и никаких попыток «смягчить» отказ — неверный AAD или изменённое значение
означают отказ, а не «попробовать ещё раз».
"""

from __future__ import annotations

import base64
from typing import Final
from uuid import UUID

from packages.common.crypto import EnvelopeError, KeyRing, build_aad, open_envelope, seal_envelope
from packages.identity.totp import (
    TOTP_SECRET_BYTES_MAX,
    TOTP_SECRET_BYTES_MIN,
    TotpSecretError,
    decode_totp_secret,
)

#: `kind` из состава AAD (§8.4, ADR-014 п. 4). Отдельное значение на каждый вид секрета — не
#: украшение: оно и есть то, что не даёт шифртексту привязки TOTP сойти за токен брокера.
AAD_KIND_TOTP_ENROLLMENT: Final = "totp_enrollment"

#: Диагностическое имя колонки в текстах отказа (`ensure_envelope`).
CIPHERTEXT_COLUMN: Final = "totp_enrollments.secret_enc"


def totp_secret_aad(enrollment_id: UUID, user_id: UUID) -> bytes:
    """Канонический AAD шифртекста привязки: `kind` + `enrollment_id` + `user_id`.

    AAD не является секретом и нигде не хранится: он выводится из строки, которую мы и так читаем.
    Смысл в том, что без этой тройки расшифровка не получается — подставить чужое значение нельзя.
    """
    return build_aad(kind=AAD_KIND_TOTP_ENROLLMENT, record_id=enrollment_id, owner_id=user_id)


def _secret_key_bytes(secret: str | bytes) -> bytes:
    """Текст или ключ привязки → байты ключа, с проверкой границ длины (§8.4 «не короче 128 бит»)."""
    if isinstance(secret, bytes):
        if not TOTP_SECRET_BYTES_MIN <= len(secret) <= TOTP_SECRET_BYTES_MAX:
            raise TotpSecretError(
                f"длина ключа привязки {len(secret)} байт вне границ "
                f"[{TOTP_SECRET_BYTES_MIN}; {TOTP_SECRET_BYTES_MAX}] (§8.4: не короче 128 бит)"
            )
        return secret
    return decode_totp_secret(secret)


def protect_totp_secret(
    secret: str | bytes,
    *,
    enrollment_id: UUID,
    user_id: UUID,
    ring: KeyRing,
) -> bytes:
    """Зашифровать секрет привязки в значение для `secret_enc` (DEK на запись + активный KEK).

    Принимает и base32-текст (его генерирует `new_totp_secret`), и готовые байты ключа: оба варианта
    сводятся к одному и тому же ключу, и в шифртексте всегда оказываются байты нужной длины.
    Возвращаемое значение — самонесущий конверт; в нём уже есть nonce, тег и версия ключа, поэтому
    колонок рядом с `secret_enc` не появляется (`ADR-014` п. 3).
    """
    key = _secret_key_bytes(secret)
    return seal_envelope(key, aad=totp_secret_aad(enrollment_id, user_id), ring=ring)


def open_totp_secret(
    secret_enc: bytes,
    *,
    enrollment_id: UUID,
    user_id: UUID,
    ring: KeyRing,
) -> bytes:
    """Расшифровать `secret_enc` в ключ привязки для `verify_totp_code`.

    Отказывает, если значение не является конвертом (в том числе если в колонке лежит открытый
    секрет), если версия ключа неизвестна площадке, если изменено само значение и если AAD собран по
    другой строке или другому владельцу. Все четыре случая — один и тот же путь «привязки нет», и
    ни один из них не даёт секретного значения.
    """
    try:
        key = open_envelope(secret_enc, aad=totp_secret_aad(enrollment_id, user_id), ring=ring)
    except EnvelopeError as exc:
        # К колонке обращаются из маршрута, и в логе должно быть видно, где именно лежит значение
        # не той формы; сам текст признака (метка/длина/версия) добавляет слой криптографии.
        raise EnvelopeError(f"{CIPHERTEXT_COLUMN}: {exc}") from exc
    if not TOTP_SECRET_BYTES_MIN <= len(key) <= TOTP_SECRET_BYTES_MAX:
        raise TotpSecretError(
            f"в {CIPHERTEXT_COLUMN} расшифровался ключ длиной {len(key)} байт вне границ "
            f"[{TOTP_SECRET_BYTES_MIN}; {TOTP_SECRET_BYTES_MAX}] — значение создано вне приложения"
        )
    return key


def totp_secret_base32(key: bytes) -> str:
    """Ключ привязки → base32 без пробелов (для provisioning-ссылки `otpauth://`, срез `R4d`).

    Вызывать стоит только там, где значение уходит одному владельцу привязки и не сохраняется. Формат
    — верхний регистр без дополнения `=`: его принимает `decode_totp_secret`, поэтому ключ
    возвращается в приложение тем же путём, каким уходил в аутентификатор.
    """
    return base64.b32encode(key).decode("ascii").rstrip("=")
