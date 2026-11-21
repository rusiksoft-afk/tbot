"""Криптография слоя хранения: AES-256-GCM, самонесущий конверт и читалка KEK (TZ §8.4, ADR-014, `T-103` срез `R4b`).

Почему примитивы живут в `common` (№1 Capability Map), а не в `packages/credentials/vault.py`, куда их
хочет `T-107`: первым потребителем становится `identity` — её таблица `totp_enrollments.secret_enc`,
а `credentials` (№5) сам зависит от `identity` (№4), поэтому обратное ребро дало бы цикл в
декларированном графе зависимостей (`ADR-013` п. 11). `T-107` получает поверх этого модуля AAD токенов
брокера и `make rotate-keys`, ничего не перенося.

Что закреплено модулем:

1. **AES-256, а не «AES любого размера».** §8.4 называет AES-256-GCM; ключ 16 или 24 байта
   отказывает явно. Без проверки размера `AESGCM` принял бы AES-128 и AES-192 молча, а §8.4
   перестал бы выполняться ровно в тот момент, когда кто-нибудь сократит длину ключа в файле.
2. **Nonce — ровно 96 бит, каждый раз новый.** 96-битный IV — единственный, для которого GCM не
   требует внешнего счётчика и для которого есть эталонные векторы NIST (наборы с 64-битным и
   480-битным IV в SP 800-38D Appendix C нашей схемой не используются). Повтор nonce при одном и том
   же ключе в GCM — не «меньшая надёжность», а полная потеря целостности потока, поэтому nonce
   генерируется внутри операции (`secrets.token_bytes`) и не принимается от вызывающего.
3. **Конверт самонесущий: версия KEK лежит внутри значения.** Колонок `key_version` в схеме нет и
   появляться не должно (`ADR-014` п. 3): `secret_enc` уже описана как «nonce + тег + шифртекст»,
   то есть значение обязано объяснять себя само. Это же держит ротацию: старые строки остаются
   читаемыми после появления нового активного ключа, и `make rotate-keys` (`T-107`) может идти
   построчно, а не «перешифровать всё атомарно».
4. **DEK на запись, обёрнутый в KEK** (буква §8.4). Каждый вызов шифрования получает собственный
   256-битный DEK из CSPRNG, поэтому два шифртекста одной и той же привязки разные, а компрометация
   одного DEK не вскрывает остальные строки.
5. **AAD привязывает шифртекст к записи** (§8.4: `credential_id` + `owner_id` + `kind`; для
   привязки — `enrollment_id` + `user_id` + `kind`, `ADR-014` п. 4). Отдельный AAD для обёртки DEK и
   отдельный — для полезной нагрузки, и оба содержат версию KEK: перенести обёртку DEK или
   шифртекст в другую строку нельзя, не получив отказа.
6. **KEK только в файле.** §8.4: `/etc/tbot/keys/kek.json`, не в БД и не в образе; `ADR-005` решает
   вопрос прав для монтируемого в контейнер файла. Файл с правами шире `0640` отказывается быть
   прочитанным: «KEK доступен всем» — это не «меньшая аккуратность», а украденный ключ.
7. **Отказ явный и различимый.** Нет файла / не читается / права не те / JSON не тот / версия ключа
   неизвестна / тег не сошёлся — у каждого свой тип и текст. «Расшифровалось в мусор» хуже отказа:
   дальше по коду поедут коды, которые «никогда не подходят».
8. **Ни repr, ни str, ни текст исключения не содержат ключевый материал.** `KeyMaterial.__repr__`
   печатает версию и длину; в текстах исключений — только имена полей, версии и длины.

Чего здесь сознательно нет (это границы среза, а не недоделка):

- конверта DEK→KEK для токенов брокера и `make rotate-keys` — `T-107`; там же AAD с `kind` токена;
- генерации файла KEK на площадке: значения секретов пишет только `deploy/vps/secrets-setup.sh`
  (`ADR-004`), а запись в `deploy/compose.prod.yaml` и в скрипт — срез деплоя (`ADR-014` п. 7);
- обнуления буферов: `bytes` в Python неизменяем, честного `zeroize` у интерпретатора нет, поэтому
  ключевой материал не сохраняется в атрибуты и не кладётся в return-значения — это то, что реально
  достижимо, а не имитация `SecureString`;
- KDF/HKDF, PBKDF, подписей и всего, чего §8.4 не требует.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, cast
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─── параметры алгоритма (§8.4 фиксирует AES-256-GCM) ─────────────────────────────────────────

#: 32 байта — длина ключа AES-256. `AESGCM` принял бы и 16, и 24 байта (AES-128/AES-192), поэтому
#: размер проверяется здесь явно: иначе §8.4 остаётся выполненным только на словах.
AES_KEY_BYTES: Final = 32
#: 96 бит — стандартная длина IV для GCM (NIST SP 800-38D §7.1): при ней не нужен ни счётчик, ни
#: хэширование IV. Длинные и короткие IV в конверте этого формата не встречаются.
GCM_NONCE_BYTES: Final = 12
GCM_TAG_BYTES: Final = 16
#: Разрешённые биты файла KEK: чтение владельцу и группе, ничего «миру» и никакой записи группе.
#: 0400 (вариант §8.4 для файла хозяйственного процесса) и 0640 (вариант `ADR-005` для файла,
#: который compose монтирует в контейнер под uid/gid процесса) оба попадают в этот набор.
KEK_FILE_MODE_MAX: Final = 0o640

# ─── формат конверта (версия ключа внутри значения, колонок в схеме нет) ───────────────────────

#: Метка формата. Первые четыре байта значения — часть контракта: по ним отличается «шифртекст
#: этого формата» от «в колонке лежит открытый секрет», и текст отказа становится диагностикой.
ENVELOPE_MAGIC: Final = b"TBE1"
ENVELOPE_FORMAT_VERSION: Final = 1
ENVELOPE_KEY_VERSION_BYTES: Final = 2
KEY_VERSION_MIN: Final = 1
KEY_VERSION_MAX: Final = 0xFFFF
ENVELOPE_HEADER_BYTES: Final = (
    len(ENVELOPE_MAGIC) + 1 + ENVELOPE_KEY_VERSION_BYTES  # метка + версия формата + версия KEK
)
#: Обёртка DEK целиком: nonce + шифртекст DEK + тег. Длина фиксирована форматом v1, поэтому
#: длины обёртки в заголовке нет — и подменить её, не сдвинув всё остальное, нельзя.
WRAPPED_DEK_BYTES: Final = GCM_NONCE_BYTES + AES_KEY_BYTES + GCM_TAG_BYTES
#: Шифртекст обёртки DEK вместе с тегом: без nonce, который лежит отдельным полем заголовка.
#: По этой длине считается начало полезной нагрузки — отсюда и разделение двух констант.
WRAPPED_DEK_PAYLOAD_BYTES: Final = AES_KEY_BYTES + GCM_TAG_BYTES
#: Минимальная длина значения: заголовок + обёртка DEK + nonce и тег полезной нагрузки (полезная
#: нагрузка длиной 0 байт тоже зашифрована — GCM держит тег и для неё).
ENVELOPE_MIN_BYTES: Final = (
    ENVELOPE_HEADER_BYTES + WRAPPED_DEK_BYTES + GCM_NONCE_BYTES + GCM_TAG_BYTES
)

#: Смещения полей конверта. Открытые величины: по ним заголовок читают диагностика, `rotate-keys`
#: (`T-107`) и проверки формата; порядок полей — часть формата, меняется только вместе с
#: `ENVELOPE_FORMAT_VERSION`.
OFFSET_FORMAT_VERSION: Final = len(ENVELOPE_MAGIC)
OFFSET_KEY_VERSION: Final = OFFSET_FORMAT_VERSION + 1
OFFSET_DEK_NONCE: Final = OFFSET_KEY_VERSION + ENVELOPE_KEY_VERSION_BYTES
OFFSET_WRAPPED_DEK: Final = OFFSET_DEK_NONCE + GCM_NONCE_BYTES
OFFSET_PAYLOAD_NONCE: Final = OFFSET_WRAPPED_DEK + WRAPPED_DEK_PAYLOAD_BYTES
OFFSET_PAYLOAD: Final = OFFSET_PAYLOAD_NONCE + GCM_NONCE_BYTES

#: Префикс AAD. Смысл — в том, что AAD невозможно спутать с чужим контекстом: тот же UUID в другом
#: модуле даёт другую строку, и перенести шифртекст между контекстами не выйдет.
AAD_PREFIX: Final = b"tbot-aad/v1"
_AAD_PURPOSE_DEK: Final = b"dek"
_AAD_PURPOSE_PAYLOAD: Final = b"payload"
#: `kind` входит в AAD разделителем, поэтому алфавит закрыт: символ `|` внутри kind дал бы
#: коллизию («kindA|kindB» и два разных набора значений неразличимы), то есть отменил бы привязку.
AAD_KIND_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,31}")
#: Base64 ровно 32 байт (44 символа с одним дополнением). Явная форма нужна, чтобы «ключ в hex»,
#: «ключ в base64url» и «ключ в pem» не разбирались молча, а отвергались с объяснением.
_KEK_BASE64_RE: Final = re.compile(r"[A-Za-z0-9+/]{43}=")

#: Формат файла KEK (`ADR-014` п. 5): активная версия плюс набор ключей «версия → ключ».
KEY_FILE_FORMAT_VERSION: Final = 1
_KEY_FILE_FIELDS: Final[frozenset[str]] = frozenset({"format_version", "active_version", "keys"})
_KEY_FIELDS: Final[frozenset[str]] = frozenset({"version", "key"})


# ─── ошибки: различимые, без ключевого материала в тексте ─────────────────────────────────────


class CryptoError(ValueError):
    """Базовая ошибка криптографии слоя хранения. Значений ключей в тексте нет по построению."""


class KeyRingError(CryptoError):
    """Связка ключей KEK не собрана или не подходит к шифртексту."""


class KeyRingUnusableError(KeyRingError):
    """Файл KEK отсутствует, не читается или имеет права вне политики §8.4 / `ADR-005`.

    Отдельный тип держит главное различие: «ключа нет на площадке» — это не испорченные данные,
    а состояние окружения; обрабатывать его надо перезапуском/настройкой, а не отказом пользователю.
    """


class KeyRingFormatError(KeyRingError):
    """Файл KEK не соответствует формату: JSON, поля, длина или кодировка ключа."""


class EnvelopeError(CryptoError):
    """Значение не является конвертом этого формата (или повреждено в заголовке)."""


class DecryptionError(CryptoError):
    """Целостность не подтвердилась: данные изменены, AAD не тот или ключ не тот (§8.4)."""


# ─── ключ и связка ключей ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, repr=False)
class KeyMaterial:
    """Ключ KEK с версией. Сам ключ в `repr` не попадает (§8.4 «красное правило»)."""

    version: int
    #: Сравнение учитывает байты ключа: «та же версия, но другой ключ» обязано быть различимым.
    key: bytes = field(repr=False)

    def __repr__(self) -> str:
        return f"KeyMaterial(version={self.version}, key=<скрыт, {len(self.key)} байт>)"


@dataclass(frozen=True, repr=False)
class KeyRing:
    """Связка ключей KEK: активный ключ для новых записей и все известные — для чтения старых.

    Набор «версия → ключ», а не один ключ, — это следствие самонесущего конверта: строка,
    зашифрованная версией 1, обязана читаться, когда активной стала версия 2. Иначе `rotate-keys`
    превращается в операцию, во время которой половина строк недоступна.
    """

    active: KeyMaterial
    keys: Mapping[int, KeyMaterial]

    def key_for(self, version: int) -> KeyMaterial:
        """Ключ конкретной версии из шифртекста; неизвестная версия — явный отказ."""
        found = self.keys.get(version)
        if found is None:
            raise KeyRingError(
                f"версия ключа {version} отсутствует в связке KEK "
                f"(известны {sorted(self.keys)}): строка зашифрована ключом, которого нет на площадке"
            )
        return found

    def __repr__(self) -> str:
        return (
            f"KeyRing(active={self.active.version}, " f"versions={sorted(self.keys)}, key=<скрыт>)"
        )


def _key_length_ok(key: bytes) -> bool:
    return len(key) == AES_KEY_BYTES


def _check_key(key: bytes, what: str) -> AESGCM:
    """Проверить длину ключа и вернуть шифратор. §8.4 называет AES-256, поэтому 128/192 — отказ."""
    if not _key_length_ok(key):
        raise CryptoError(
            f"{what}: длина ключа {len(key)} байт, требуется AES-256 ({AES_KEY_BYTES} байта, TZ §8.4)"
        )
    return AESGCM(key)


# ─── AAD: привязка шифртекста к записи (§8.4, ADR-014 п. 4) ───────────────────────────────────


def build_aad(*, kind: str, record_id: UUID, owner_id: UUID) -> bytes:
    """Канонический AAD записи: `kind` + идентификатор записи + идентификатор владельца.

    §8.4 задаёт такой состав для токенов брокера (`credential_id` + `owner_id` + `kind`); для
    привязки TOTP тот же состав принимает `ADR-014` (`enrollment_id` + `user_id` + `kind`).
    Разделитель — `|`, а `kind` берётся из закрытого алфавита без `|`: иначе два разных набора
    значений дали бы одну и ту же строку и привязка перестала бы быть привязкой.

    UUID печатаются каноническим текстом (фиксированная длина, нижний регистр, `|` внутри не
    встречается), поэтому AAD одинаково собирается в любом процессе и в любом контейнере — его не
    нужно никуда «передавать» для расшифровки, и это принципиально: AAD не является секретом и не
    хранится отдельно.
    """
    if not AAD_KIND_RE.fullmatch(kind):
        raise CryptoError(
            f"kind {kind!r} не соответствует алфавиту "
            f"{AAD_KIND_RE.pattern!r}: разделитель AAD не должен появляться внутри kind"
        )
    return b"|".join(
        (
            AAD_PREFIX,
            kind.encode("ascii"),
            str(record_id).encode("ascii"),
            str(owner_id).encode("ascii"),
        )
    )


def _scoped_aad(aad: bytes, purpose: bytes, key_version: int) -> bytes:
    """AAD конкретного куска конверта: контекст записи + назначение + версия ключа.

    Обёртка DEK и полезная нагрузка шифруются под разными AAD намеренно: иначе шифртекст полезной
    нагрузки можно было бы переставить в конверт с другой обёрткой, не заметив этого.
    """
    return b"|".join((aad, purpose, f"v{key_version}".encode("ascii")))


# ─── примитивы AES-256-GCM ────────────────────────────────────────────────────────────────────


def new_nonce() -> bytes:
    """Новый 96-битный nonce из CSPRNG (`secrets`, не `random`).

    Повтор nonce при одном ключе в GCM обесценивает и конфиденциальность, и целостность, поэтому
    nonce не принимается параметром: вероятность случайного повторного 96-битного значения при
    отдельном DEK на запись пренебрежима, а «одолженчивый» параметр — это то место, где повтор
    появляется.
    """
    return secrets.token_bytes(GCM_NONCE_BYTES)


def new_dek() -> bytes:
    """Новый DEK на запись (§8.4): 256 бит из CSPRNG, живёт только внутри одной операции."""
    return secrets.token_bytes(AES_KEY_BYTES)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, *, nonce: bytes, aad: bytes) -> bytes:
    """Зашифровать и аутентифицировать: возврат — шифртекст || тег (порядок даёт сама GCM).

    Тег идёт последним: так устроено AEAD-представление `cryptography`/OpenSSL, и именно в таком
    виде значение уходит в `bytea`. Колонка в схеме описана как «nonce + тег + шифртекст» — перечень
    компонентов, а не порядок байтов; расхождение зафиксировано в `ADR-014` п. 3, схема под него не
    правится (правка комментария колонки = новая ревизия ради комментария).
    """
    if len(nonce) != GCM_NONCE_BYTES:
        raise CryptoError(
            f"длина nonce {len(nonce)} байт, требуется {GCM_NONCE_BYTES} (96 бит, NIST SP 800-38D §7.1)"
        )
    return _check_key(key, "ключ").encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, token: bytes, *, nonce: bytes, aad: bytes) -> bytes:
    """Расшифровать шифртекст || тег. Любое расхождение тега — `DecryptionError`, не мусор.

    Отдельно держать `InvalidTag` нельзя: вызывающий слой обязан получать один и тот же отказ и для
    изменённого байта шифртекста, и для чужого AAD, и для чужого ключа. Иначе «шифртекст принят,
    содержимое не то» становится возможным состоянием.
    """
    if len(nonce) != GCM_NONCE_BYTES:
        raise CryptoError(
            f"длина nonce {len(nonce)} байт, требуется {GCM_NONCE_BYTES} (96 бит, NIST SP 800-38D §7.1)"
        )
    cipher = _check_key(key, "ключ")
    try:
        plaintext = cipher.decrypt(nonce, token, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "тег GCM не подтвердился: значение изменено, AAD не тот или ключ не тот (§8.4)"
        ) from exc
    return plaintext


# ─── конверт: заголовок + обёртка DEK + полезная нагрузка ──────────────────────────────────────


@dataclass(frozen=True)
class EnvelopeInfo:
    """Метаданные конверта. Ни ключей, ни открытого значения здесь нет — только версии и длины."""

    format_version: int
    key_version: int
    #: Длина зашифрованной части значения (вместе с тегом GCM), без обёртки DEK и без заголовка:
    #: по ней удобно сравнивать строки при диагностике и при `rotate-keys`.
    payload_bytes: int


def _split_envelope(envelope: bytes) -> tuple[int, int, bytes, bytes, bytes, bytes]:
    """Разобрать конверт на части.

    Возврат: версия формата, версия KEK, nonce обёртки DEK, обёртка DEK, nonce полезной нагрузки,
    полезная нагрузка. Версии возвращаются числами: по ним работают `rotate-keys` и диагностика.
    """
    if len(envelope) < ENVELOPE_MIN_BYTES:
        raise EnvelopeError(
            f"длина значения {len(envelope)} байт меньше минимума конверта "
            f"({ENVELOPE_MIN_BYTES}): это не шифртекст формата {ENVELOPE_MAGIC.decode('ascii')!r} — "
            "вероятно, в колонке лежит открытое значение (TZ §8.4) или данные обрезаны"
        )
    if envelope[: len(ENVELOPE_MAGIC)] != ENVELOPE_MAGIC:
        raise EnvelopeError(
            f"нет метки формата {ENVELOPE_MAGIC.decode('ascii')!r}: значение не зашифровано "
            "средством этого модуля (TZ §8.4 требует шифртекст, а не «поле похоже на случайные байты»)"
        )
    format_version = envelope[OFFSET_FORMAT_VERSION]
    if format_version != ENVELOPE_FORMAT_VERSION:
        raise EnvelopeError(
            f"версия формата конверта {format_version} не поддерживается "
            f"(приложение умеет {ENVELOPE_FORMAT_VERSION})"
        )
    key_version = int.from_bytes(envelope[OFFSET_KEY_VERSION:OFFSET_DEK_NONCE], byteorder="big")
    if not KEY_VERSION_MIN <= key_version <= KEY_VERSION_MAX:
        raise EnvelopeError(
            f"версия ключа {key_version} вне диапазона "
            f"[{KEY_VERSION_MIN}; {KEY_VERSION_MAX}] — заголовок повреждён"
        )
    dek_nonce = envelope[OFFSET_DEK_NONCE:OFFSET_WRAPPED_DEK]
    wrapped = envelope[OFFSET_WRAPPED_DEK:OFFSET_PAYLOAD_NONCE]
    payload_nonce = envelope[OFFSET_PAYLOAD_NONCE:OFFSET_PAYLOAD]
    payload = envelope[OFFSET_PAYLOAD:]
    return format_version, key_version, dek_nonce, wrapped, payload_nonce, payload


def describe_envelope(envelope: bytes) -> EnvelopeInfo:
    """Прочитать заголовок конверта, не прикасаясь к ключам.

    Это то, по чему `make rotate-keys` (`T-107`) выбирает строки старой версии ключа, и то, чем
    диагностика отвечает на вопрос «почему эта строка не читается».
    """
    format_version, key_version, _, _, _, payload = _split_envelope(envelope)
    return EnvelopeInfo(
        format_version=format_version,
        key_version=key_version,
        payload_bytes=len(payload),
    )


def seal_envelope(plaintext: bytes, *, aad: bytes, ring: KeyRing) -> bytes:
    """Зашифровать значение: DEK на запись, обёрнутый в активный KEK (§8.4).

    Возвращается самонесущее значение: метка формата, версия формата, версия KEK, nonce и обёртка
    DEK, nonce и тело полезной нагрузки. Именно оно целиком уходит в `bytea`, и именно поэтому
    расшифровка не требует ничего, кроме самой строки, AAD и файла ключей.
    """
    kek = ring.active
    dek = new_dek()
    dek_nonce = new_nonce()
    wrapped = _check_key(kek.key, f"KEK версии {kek.version}").encrypt(
        dek_nonce, dek, _scoped_aad(aad, _AAD_PURPOSE_DEK, kek.version)
    )
    payload_nonce = new_nonce()
    payload = _check_key(dek, "DEK записи").encrypt(
        payload_nonce, plaintext, _scoped_aad(aad, _AAD_PURPOSE_PAYLOAD, kek.version)
    )
    header = (
        ENVELOPE_MAGIC
        + bytes((ENVELOPE_FORMAT_VERSION,))
        + kek.version.to_bytes(ENVELOPE_KEY_VERSION_BYTES, byteorder="big")
    )
    return header + dek_nonce + wrapped + payload_nonce + payload


def open_envelope(envelope: bytes, *, aad: bytes, ring: KeyRing) -> bytes:
    """Расшифровать конверт. AAD обязан совпасть с тем, что давали при шифровании (§8.4).

    Отказы различимы: кривой заголовок → `EnvelopeError`, неизвестная версия ключа → `KeyRingError`,
    чужой AAD/изменённое значение/чужой ключ → `DecryptionError`. Открытое значение возвращается
    только вызывающему слою — в логи, исключения и `repr` оно не попадает ни на одной ветке.
    """
    _, key_version, dek_nonce, wrapped, payload_nonce, payload = _split_envelope(envelope)
    kek = ring.key_for(key_version)
    dek = aes_gcm_decrypt(
        kek.key, wrapped, nonce=dek_nonce, aad=_scoped_aad(aad, _AAD_PURPOSE_DEK, key_version)
    )
    return aes_gcm_decrypt(
        dek, payload, nonce=payload_nonce, aad=_scoped_aad(aad, _AAD_PURPOSE_PAYLOAD, key_version)
    )


def ensure_envelope(value: bytes, *, column: str) -> bytes:
    """Проверить, что в колонке лежит конверт, а не открытое значение, и вернуть значение как есть.

    Нужно это для того, чтобы «положим секрет в `secret_enc` без шифрования» не работало даже по
    ошибке: привязка проходит через модели ORM, и проверка на присваивании отклоняет открытое
    значение до запроса, с текстом, в котором объяснён признак (`ADR-014` п. 6).
    """
    try:
        _split_envelope(value)
    except EnvelopeError as exc:
        raise EnvelopeError(f"{column}: {exc}") from exc
    return value


# ─── файл KEK (§8.4: права, формат, версии) ───────────────────────────────────────────────────


def kek_file_mode_error(mode: int) -> str | None:
    """Вернуть объяснение, если права файла KEK шире политики, иначе `None`.

    Политика — объединение §8.4 (`0400`, когда ключ читает хозяйственный процесс) и `ADR-005`
    (`640 root:gid процесса`, когда файл монтируется в контейнер: bind-маунт приносит права с хоста,
    а процесс в образе работает под uid/gid 10001, поэтому `0400 root:root` внутри контейнера
    означает нечитаемый ключ — ровно тот дефект, который ADR-005 уже разбирал на `db_url`).
    Разрешены только чтение владельцу и группе: биты записи группе и любой доступ «остальным»
    запрещены.
    """
    permissions = stat.S_IMODE(mode)
    extra = permissions & ~KEK_FILE_MODE_MAX
    if extra:
        return (
            f"права файла {oct(permissions)} дают доступ за пределами {oct(KEK_FILE_MODE_MAX)} "
            f"(лишние биты {oct(extra)}); KEK — файл из TZ §8.4: 0400 хозяйственному процессу "
            "или 640 root:gid контейнера по ADR-005"
        )
    return None


def parse_key_ring_document(raw: str, *, source: str) -> KeyRing:
    """Собрать связку ключей из текста файла KEK.

    Формат (§8.4 + `ADR-014` п. 5):

        {"format_version": 1, "active_version": 2,
         "keys": [{"version": 1, "key": "<base64 32 байт>"}, {"version": 2, "key": "…"}]}

    Активная версия ровно одна и обязана входить в набор. Неизвестные ключи JSON — ошибка, а не
    «игнорируем»: опечатка в имени поля должна быть видна сразу, иначе файл с ключом, который
    приложение не читает, выглядит рабочим. Ошибки собираются списком: чинить файл по одной
    подсказке за запуск — тот самый путь, на котором площадку перезапускают вслепую.
    """
    try:
        loaded: object = json.loads(raw)
    except ValueError as exc:
        raise KeyRingFormatError(f"{source}: файл KEK не разбирается как JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise KeyRingFormatError(f"{source}: файл KEK должен быть JSON-объектом верхнего уровня")
    document = cast("dict[str, Any]", loaded)
    reasons: list[str] = []

    unknown = sorted(key for key in document if key not in _KEY_FILE_FIELDS)
    if unknown:
        reasons.append(f"неизвестные поля {unknown}; ожидаются {sorted(_KEY_FILE_FIELDS)}")
    if document.get("format_version") != KEY_FILE_FORMAT_VERSION:
        reasons.append(
            f"format_version: ожидалось {KEY_FILE_FORMAT_VERSION}, "
            f"получено {document.get('format_version')!r}"
        )

    keys: dict[int, KeyMaterial] = {}
    raw_keys = document.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
        reasons.append("keys: ожидается непустой список ключей")
    else:
        for index, item in enumerate(raw_keys):
            slot = _parse_key_slot(item, index)
            if isinstance(slot, str):
                reasons.append(slot)
                continue
            version, material = slot
            if version in keys:
                reasons.append(f"keys[{index}]: версия {version} повторяется")
                continue
            keys[version] = material

    active_version = document.get("active_version")
    if isinstance(active_version, bool) or not isinstance(active_version, int):
        reasons.append("active_version: ожидалось целое число версии ключа")
    elif active_version not in keys:
        reasons.append(f"active_version: версии {active_version} нет среди ключей {sorted(keys)}")

    if reasons:
        raise KeyRingFormatError(f"{source}: файл KEK некорректен:\n  - " + "\n  - ".join(reasons))
    # Если причин нет, `active_version` заведомо целое и присутствует в `keys`: каждая ветка
    # проверки выше добавила бы причину в список. `assert` здесь не вариант: S101 в коде пакета
    # запрещён, а снял бы он только внутреннее условие этой функции.
    return KeyRing(active=keys[cast("int", active_version)], keys=MappingProxyType(keys))


def _parse_key_slot(item: object, index: int) -> tuple[int, KeyMaterial] | str:
    """Разобрать один элемент `keys`: пару (версия, ключ) или объяснение отказа."""
    if not isinstance(item, dict):
        return f"keys[{index}]: ожидается объект с полями {sorted(_KEY_FIELDS)}"
    document = cast("dict[str, Any]", item)
    unknown = sorted(key for key in document if key not in _KEY_FIELDS)
    if unknown:
        return f"keys[{index}]: неизвестные поля {unknown}"
    for required in sorted(_KEY_FIELDS):
        if required not in document:
            return f"keys[{index}]: нет поля {required!r}"
    version = document["version"]
    if isinstance(version, bool) or not isinstance(version, int):
        return f"keys[{index}]: version должна быть целым числом"
    if not KEY_VERSION_MIN <= version <= KEY_VERSION_MAX:
        return (
            f"keys[{index}]: версия {version} вне диапазона "
            f"[{KEY_VERSION_MIN}; {KEY_VERSION_MAX}] (в конверте версия занимает 2 байта)"
        )
    encoded = document["key"]
    if not isinstance(encoded, str) or not _KEK_BASE64_RE.fullmatch(encoded):
        return (
            f"keys[{index}]: ключ обязан быть base64 длиной 44 символа (32 байта AES-256); "
            "hex, base64url и PEM не принимаются"
        )
    # Отдельная проверка длины здесь была бы недостижимой веткой: 44 канонических символа base64
    # с одним дополнением декодируются ровно в 32 байта. Длину ключа в месте использования держит
    # `_check_key` (§8.4: AES-256), и она проверена отдельно.
    key = base64.b64decode(encoded, validate=True)
    return version, KeyMaterial(version=version, key=key)


def load_key_ring(path: Path) -> KeyRing:
    """Прочитать файл KEK (§8.4) и вернуть связку ключей.

    Порядок проверок — от окружения к содержимому: нет файла, права, чтение, разбор. Так текст
    отказа отвечает на вопрос «что делать»: доставить файл, поправить права или починить JSON.
    Проверка прав имеет смысл только там, где есть биты POSIX (на dev-машине Windows их нет —
    там остаётся проверка содержимого).
    """
    if not path.is_file():
        raise KeyRingUnusableError(
            f"нет файла ключей: {path} (§8.4: KEK лежит в файле, не в БД и не в образе)"
        )
    if os.name == "posix":
        problem = kek_file_mode_error(path.stat().st_mode)
        if problem is not None:
            raise KeyRingUnusableError(f"{path}: {problem}")
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise KeyRingUnusableError(f"{path}: файл ключей не читается: {exc}") from exc
    if not raw.strip():
        raise KeyRingFormatError(f"{path}: файл ключей пуст")
    return parse_key_ring_document(raw, source=str(path))


def describe_key_ring(path: Path) -> str:
    """Одна строка диагностики файла ключей: версии и активная версия — без значений (§8.4)."""
    ring = load_key_ring(path)
    return f"{path}: версии {sorted(ring.keys)}, активная {ring.active.version}"
