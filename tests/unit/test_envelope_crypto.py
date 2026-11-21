"""Проверки криптографии слоя хранения (`packages/common/crypto.py`) — TZ §8.4, ADR-014, `T-103` `R4b`.

Файл держит четыре независимых набора проверок, и путать их не стоит:

1. **Внешние векторы.** Примитив AES-256-GCM сверяется не с самим собой, а с чужими реализациями:
   наборы NIST CAVP (приложение C к SP 800-38D в том виде, как они лежат в тестовых данных Botan,
   файл `src/tests/data/aead/gcm.vec`, секция `AES-256/GCM`, тест-кейсы 13–16) и вектор, помеченный
   в том же файле как сгенерированный OpenSSL 3.6. Отобраны только случаи с 96-битным IV — нашей
   схемой другие nonce не производятся; случаи NIST с 64-битным (TC17) и 480-битным (TC18) IV в
   наборе есть, они отброшены фильтром по длине nonce, а не молча. Это единственная часть проверок,
   где ожидаемый шифртекст задан извне: у конверта внешней точки отсчёта нет по построению (DEK и
   nonce случайны на каждую запись), поэтому конверт проверяется свойствами — привязкой,
   целостностью и структурой, а не побайтовым совпадением.
2. **Свойства конверта.** Неверный AAD, изменённый байт, чужой ключ, неизвестная версия ключа,
   обрезанное значение, значение без метки формата — всё это отказ, а не «расшифровалось иначе».
   Плюс: DEK на каждую запись действительно разные, версия ключа читается из самого значения
   (колонок рядом с `secret_enc` нет), открытое значение в шифртекст не принимается.
3. **Файл ключей.** Отдельный тип отказа на «файла нет», «права шире политики», «не читается»,
   «JSON/ключи не по формату». Политика прав проверяется функцией без файловой системы — на любой
   платформе; сами биты POSIX — на POSIX (в CI это Linux).
4. **Отсутствие утечек.** Ключевой материал не попадает в `repr`, `str` и тексты исключений (§8.4),
   а в модуле криптографии нет логгера — значит, ему нечего вынести в лог.

Тесты `secret_enc` на уровне модели и колонки — в `tests/unit/test_totp_secret_protection.py` и
`tests/integration/test_totp_secret_storage_db.py`.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from uuid import UUID

import pytest

from packages.common import crypto
from packages.common.crypto import (
    AAD_PREFIX,
    AES_KEY_BYTES,
    ENVELOPE_FORMAT_VERSION,
    ENVELOPE_MAGIC,
    ENVELOPE_MIN_BYTES,
    GCM_NONCE_BYTES,
    GCM_TAG_BYTES,
    OFFSET_DEK_NONCE,
    OFFSET_FORMAT_VERSION,
    OFFSET_KEY_VERSION,
    OFFSET_PAYLOAD,
    OFFSET_PAYLOAD_NONCE,
    OFFSET_WRAPPED_DEK,
    WRAPPED_DEK_BYTES,
    DecryptionError,
    EnvelopeError,
    KeyMaterial,
    KeyRing,
    KeyRingError,
    KeyRingFormatError,
    KeyRingUnusableError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    build_aad,
    describe_envelope,
    describe_key_ring,
    ensure_envelope,
    kek_file_mode_error,
    load_key_ring,
    new_dek,
    new_nonce,
    open_envelope,
    parse_key_ring_document,
    seal_envelope,
)

# ─── ключи и привязки теста ────────────────────────────────────────────────────────────────────
# Значения фиксированы: проверки обязаны быть воспроизводимыми, а не «каждый прогон новые байты».
# Это тестовые значения: они не покидают репозиторий и к площадке (§8.4, ADR-004) отношения не имеют.
_KEK_V1_BYTES: Final = bytes([0x11]) * AES_KEY_BYTES
_KEK_V2_BYTES: Final = bytes([0x22]) * AES_KEY_BYTES
_KEK_V1_B64: Final = base64.b64encode(_KEK_V1_BYTES).decode("ascii")
_KEK_V2_B64: Final = base64.b64encode(_KEK_V2_BYTES).decode("ascii")
#: Ключ, в base64 которого есть `+`: проверяет, что канонический алфавит принимается, а
#: «base64url» (`-`, `_`) — нет.
_KEK_SLASH_BYTES: Final = bytes([0xFB, 0xEF, 0xBE]) * 10 + b"\xfb\xef"
_KEK_SLASH_B64: Final = base64.b64encode(_KEK_SLASH_BYTES).decode("ascii")

_ENROLLMENT_ID: Final = UUID("6f1c6a11-11a1-4a1e-9b1f-111111111111")
_OWNER_ID: Final = UUID("7d2b2b22-22b2-4b2c-8b2e-222222222222")
_OTHER_OWNER_ID: Final = UUID("8e3c3c33-33c3-4c3d-9c3f-333333333333")
_OTHER_ENROLLMENT_ID: Final = UUID("9f4d4d44-44d4-4d4e-8d40-444444444444")
_KIND: Final = "totp_enrollment"
#: 20 байт — длина ключа привязки из §8.2; для примитива это просто открытый текст.
_PLAINTEXT: Final = bytes(range(1, 21))


def _document(
    *,
    active: object = 2,
    keys: tuple[tuple[int, str], ...] = ((1, _KEK_V1_B64), (2, _KEK_V2_B64)),
) -> str:
    """Текст файла KEK: версия формата, активная версия, набор ключей (поля подменяются в тестах)."""
    return json.dumps(
        {
            "format_version": 1,
            "active_version": active,
            "keys": [{"version": version, "key": key} for version, key in keys],
        }
    )


def _ring(
    *,
    active: int = 2,
    keys: tuple[tuple[int, str], ...] = ((1, _KEK_V1_B64), (2, _KEK_V2_B64)),
) -> KeyRing:
    return parse_key_ring_document(_document(active=active, keys=keys), source="тест")


def _aad(
    *,
    kind: str = _KIND,
    record_id: UUID = _ENROLLMENT_ID,
    owner_id: UUID = _OWNER_ID,
) -> bytes:
    return build_aad(kind=kind, record_id=record_id, owner_id=owner_id)


_RING: Final = _ring()


def _sealed(aad: bytes | None = None, *, ring: KeyRing | None = None) -> bytes:
    return seal_envelope(
        _PLAINTEXT, aad=_aad() if aad is None else aad, ring=_RING if ring is None else ring
    )


def _wrapped_dek(envelope: bytes) -> bytes:
    """Обёртка DEK из конверта (её различие и есть доказательство «DEK на запись действительно новый»)."""
    return envelope[OFFSET_DEK_NONCE:OFFSET_PAYLOAD_NONCE]


# ─── 1. внешние векторы AES-256-GCM ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Vector:
    """Один случай внешнего набора: ключ, IV, AAD, открытый текст, шифртекст||тег — всё в hex."""

    name: str
    key: str
    nonce: str
    aad: str
    plaintext: str
    ciphertext: str


#: Случаи перенесены из внешнего набора один в один (см. docstring модуля): секция `AES-256/GCM`,
#: тест-кейсы NIST 13–16 и помеченный случай OpenSSL 3.6 с AAD. Все — 256-битный ключ, 96-битный
#: IV, 128-битный тег. Порядок байтов `Out` — шифртекст, затем тег: так GCM отдаёт AEAD-пару и так
#: же порядок принимает `cryptography` (и OpenSSL).
_VECTORS: Final[tuple[_Vector, ...]] = (
    _Vector(
        name="NIST-TC13-пустой-открытый-текст",
        key="0000000000000000000000000000000000000000000000000000000000000000",
        nonce="000000000000000000000000",
        aad="",
        plaintext="",
        ciphertext="530f8afbc74536b9a963b4f1c4cb738b",
    ),
    _Vector(
        name="NIST-TC14-16-байт",
        key="0000000000000000000000000000000000000000000000000000000000000000",
        nonce="000000000000000000000000",
        aad="",
        plaintext="00000000000000000000000000000000",
        ciphertext="cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
    ),
    _Vector(
        name="NIST-TC15-64-байта",
        key="feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        nonce="cafebabefacedbaddecaf888",
        aad="",
        plaintext=(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532"
            "fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        ),
        ciphertext=(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7"
            "b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c"
        ),
    ),
    _Vector(
        name="NIST-TC16-60-байт-AAD-20-байт",
        key="feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        nonce="cafebabefacedbaddecaf888",
        aad="feedfacedeadbeeffeedfacedeadbeefabaddad2",
        plaintext=(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532"
            "fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        ),
        ciphertext=(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7"
            "b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b"
        ),
    ),
    _Vector(
        name="OpenSSL3.6-1024-байта-AAD-32-байта",
        key="19A99E2FFF05CB61BBAE87026950ACAD55CED1F91683F5BFF9F6FB70CEDD456E",
        nonce="09F94CD91331E3A96D8BD9D9",
        aad="99A5B053C5BA18F0C4F639C08AB0CEBD49892BD53ED39EA985BE9C430D49C848",
        plaintext=(
            "A6376826791CAEEC7D67BE46F84176E38D7969899D6AF642B9F2D1951C817E7F971E1DD911D4143887"
            "25F2D82E209CF563225D65E2BF0A1B836EA47D6A80630AF55323F9F086DC7D235C98DD0D691871E650"
            "CD9BE6D57FFD2E9F67F847D25E45DF76C83F1FE4840D846A485F85E496547D0278B91E917B044B8C57"
            "719A02B4222660A293B99DE8AEF070C655F3E9DB3A60CD57A1BEEF28844C6F29FD141996F0A5AFEE71"
            "EC2BEC8956C51F514D8756C0FD945FDAF4FEFBF692B67404A5065C44CAE5107C5213472760ECB87602"
            "A16321353355DB669F44D29FBEC51CEFDCA6DE77AEB2FC115B33F022287CB52C031BFA9C55926FC4DA"
            "7EB30C14F515A79751C9B6FDE0C30E61F416B63247F707212BDAC8A331019CB13E740806FB477F2282"
            "0E87400FB52024668480EB7347A9102C802B2DD4CA9B609945D505BE3AB7F85EA6A8213BE103E05AD7"
            "BE5B0DD973E6BDFD8B3E71B9E63B422E15890E628F86A14DD0A4C9ED7093CC355F1CFAD4AE441B925C"
            "7C5A14B6D38B8FBE9DE125348A2403EB80C4E3A1B2A8F90290DF79F58C5AD38698E79315F533AFA45A"
            "F5B880214A8EC03A9F1293C2D770493CC0B1080B5A92A9F9FD19C8ADBDF8973C2B3EF596599C8EECAC"
            "049C3AF0B536DD225C63714A1D4A6CDB4CA811706E90218D3F405ABA76C038976CE01A465F038262CF"
            "5A9DE3E50BA1DB3F4A0F54ECAB8D8DE8EE2C5B0E4AD6E18CB429FB9BC9463AF875E6FAB30B2A4BA638"
            "64DBA5ABABDADC8FB57B74CB8BC0E7CA2C130023D81C16C9E290260F7841AF7F01979524F8A9544D1E"
            "424AA1965EE1348D1C54586E74112271D040E682794C89304C64E6CBF3B6CA9CCA7BBC01100C6D2BE0"
            "6E25D5A8A57D268A80783C8C70D5801917A5080E4090BEDFFB0D068002BC1DE2A32E65D24C434C179A"
            "0F50755887E05336DE7B3949B4A3F28D4175A639B9E84B2BF8775CE7C89215439A0A23475CC970959E"
            "341109B0070DA6A08EA4FCB5504AEB4C2E7E30447E1C0A4F1610B0AFC0F38A92FD91D5EE5BAF85AE5A"
            "CA43463F0D02119E58FD346EA8AFE3928430F21D2039E884657D63B94B5E463462F92BD292326DD1DC"
            "B1F3C4F7D1061BE972F0529AE916276A83449A3824F094D546B8ED51902CC8955A4F3E53ADC658C847"
            "7EA9C08B62A45C651442A4868114D35A4012CE02F6285BAB3EFE0F11346F3E8124173047920489105A"
            "3A789866318667843FCE4C1045AEEFA1A01F883A5854CE5B86AE6AA0FE78BE3E925C6A72842532FDE6"
            "D6CDBB285BEEDC4F0214BC44D2501149A3A8ED3FA4B65EB4FBC3403D4F49E947039ABCB74057120269"
            "62B621495C99B476F896CF50223A2B5F13FC96C1241CDBA67D0B26C95C58CB5288CBAEEA48981BDD24"
            "AC33BDB04616AD64CF71D99123F08F0CE25AA9A211BCEB745A57E6713BD6EF861F04DEFFD4F6CCFE"
        ),
        ciphertext=(
            "FEFDFE105DBC0B168A4787000130EB0146F155594C095E19BE98831F9FCF30D5A6FAC8329A8D2F022D"
            "679E532AF727200459A39515BBF34397D0B0358258579BC12D04CD6A0A25366CB14893F26DFD0DBD4D"
            "6A23073FD86C3E253DCFE5F9AAD611536CD317749D9A0AF7B7A65B30589EAFA8278EB6F1DF53DE863B"
            "7AE782D517D145EA7E5A2184FAD34061E776CA4867582444E9EE42DD89B0001B0E6897537FFE147C34"
            "646B3DABEC83D85A2C7E1E86D0AEC1A4C710B253A157B83B1F82BA476BCDC0B745561799A651EBD64B"
            "9AB1ECCE37151CFB2BF7275ED966400BA5999D2EDE7BD56D8F65FE3D3091FD47F675AA5628E1F7D232"
            "ABC27E8A4F470C0C7E443EB71EC07B22951CB43F5B9CEC88EF210DC17D10BE422E5F7ED1CC05B0D4B3"
            "A5A30B25F384B51D525E43F202FE28173D69B6639BEDB2F4745EC544F25716AC150E9CB6C2ED595EF5"
            "E163D55646021BC67799BEA578EDAF4A843ACDCEEDE544B052BA76FD8AB1811DD422E35B569007EE19"
            "8673431CB00BF664D55900BDA808C3C24DE4C7AA87169B35B400EACD35CD97866A457BC2D2C36F4F51"
            "B76C5F6D72547EEC24A19601CE9C66DE9402A54896109D681B767301EE03A919AC1317BB0C027DC3EE"
            "B4015583C1CBB29F42ABC475ECF2A33D768379B99396CD2B5DBCEADABAC27F46EB03029A5F75BF7663"
            "685A5274B7866709275879DB848D1FFD3A4EF1945E192E61DA4348AD3BDB624D378E8C1CB7805E0201"
            "F64D5D68C765DC76D33C1E64F70C0A2CEE78F3775E3E4EBBD8E4B4628712AF6CCC13FB9FE8D3120FBE"
            "CCD8629929123B49036B579A584F450835852997F4EBBABF08F2CFCB4B63A4CA1549DB17F4F1B4179E"
            "5FDB1D6D0F59200AC954C9FC9E580ADE776B994D1EDB09F9889F24FB98149A33174294CF1DBB377996"
            "4E47F6440986F9D7960F75143667F0A62123818CC95296F187FA1A9E05736F4CE7CAF300DE638E0E0F"
            "CDF4703EBBEE52189F4CF788867D5F96A578DC57447043A1C2126423035324E6393B5C5ED669768E9D"
            "111887B8BA9743A2A5CE64010A028D8AD0A5C8E38411137665F3B0E5BC310286E6F6625C87D92B510C"
            "713B365EFD310576E8208BE22ED4B4795AAB858CBAAF557F571A8021956EFD98248F35CD229FE4A599"
            "B1FA257FE4D2A89E9A41C4EC1986E95785AA0A64D5B5D23AE7DA3AEBF917B5A3D0F9DDDB7744E34973"
            "51AAF108F437E24C880FE0D83BFE289FE75B86756578CEBC2D9F7A50F0074D94483ACD9389B7F60BB7"
            "450EF1AD607B81EECF37D2A17EED44579392DE18E60F53A4E375DBDA4EDE6A627E791CD21DF24BC393"
            "D0173B75A999F56806B203AB22A5315A45D8F122D0A5AD763658A32D5E912BB8C5C92F66EF2BEB72D9"
            "BDB330EEBF30726A42415F0D43CC26CC42BD868D24F43CC186E7B4F2A4A321AA506B5C7B097F588F73"
            "52D7EFCA595E4DFD74900233BF61F9"
        ),
    ),
)


@pytest.mark.parametrize("vector", _VECTORS, ids=[vector.name for vector in _VECTORS])
def test_примитив_совпадает_с_внешними_векторами_aes_256_gcm(vector: _Vector) -> None:
    """Наш AES-256-GCM даёт тот же шифртекст и тот же тег, что внешняя реализация.

    Без этой проверки всё остальное в этом файле — «реализация сравнивается сама с собой»:
    сдвинутый GCM-счётчик, усечённый тег или неверный порядок байтов AEAD-пары не ломали бы
    round-trip и оставались бы невидимыми до самого продакшена.
    """
    key = bytes.fromhex(vector.key)
    nonce = bytes.fromhex(vector.nonce)
    aad = bytes.fromhex(vector.aad)
    plaintext = bytes.fromhex(vector.plaintext)
    expected = bytes.fromhex(vector.ciphertext)

    assert len(key) == AES_KEY_BYTES, "вектор не AES-256 — секцию набора надо перечитать"
    assert (
        len(nonce) == GCM_NONCE_BYTES
    ), "вектор не с 96-битным IV — такие nonce нашей схемой не дают"

    sealed = aes_gcm_encrypt(key, plaintext, nonce=nonce, aad=aad)
    assert sealed.hex() == vector.ciphertext.lower(), f"{vector.name}: разошёлся шифртекст или тег"
    assert sealed == expected
    assert len(sealed) == len(plaintext) + GCM_TAG_BYTES
    assert aes_gcm_decrypt(key, expected, nonce=nonce, aad=aad) == plaintext


def test_внешний_вектор_не_расшифровывается_чужим_aad() -> None:
    """Тот же внешний набор: один изменённый байт AAD — и тот же шифртекст уже не принимается.

    Проверка на чужих данных, а не на нашем конверте: привязка AAD — свойство GCM, а не свойство
    нашей надстройки, и убедительнее всего она выглядит на векторе, который мы не генерировали.
    """
    vector = _VECTORS[3]  # случай с AAD
    key, nonce, expected = (
        bytes.fromhex(vector.key),
        bytes.fromhex(vector.nonce),
        bytes.fromhex(vector.ciphertext),
    )
    aad = bytearray(bytes.fromhex(vector.aad))
    aad[0] ^= 0x01
    with pytest.raises(DecryptionError, match="тег GCM не подтвердился"):
        aes_gcm_decrypt(key, expected, nonce=bytes(nonce), aad=bytes(aad))


# ─── 2. свойства конверта ──────────────────────────────────────────────────────────────────────


def test_шифртекст_привязан_к_записи_и_чужой_aad_отказывается() -> None:
    """Конверт не открывается под другим `kind`, другим id записи и другим владельцем.

    Это и есть обещание §8.4 про привязку `credential_id` + `owner_id` + `kind`: дамп таблицы,
    перенесённый в другую строку или в другую учётную запись, бесполезен сам по себе. Основания
    отказа намеренно не различаются — иначе по различимости отказов можно было бы перебирать
    привязки, не имея ключей.
    """
    envelope = _sealed()
    assert open_envelope(envelope, aad=_aad(), ring=_RING) == _PLAINTEXT

    wrong_bases: dict[str, bytes] = {
        "kind другого вида секретов": _aad(kind="broker_token"),
        "id другой привязки": _aad(record_id=_OTHER_ENROLLMENT_ID),
        "id другого владельца": _aad(owner_id=_OTHER_OWNER_ID),
        "оба идентификатора другие": _aad(record_id=_OTHER_ENROLLMENT_ID, owner_id=_OTHER_OWNER_ID),
        "пустой AAD": b"",
        "AAD на один байт короче": _aad()[:-1],
    }
    for reason, aad in wrong_bases.items():
        with pytest.raises(DecryptionError) as caught:
            open_envelope(envelope, aad=aad, ring=_RING)
        assert "тег GCM не подтвердился" in str(caught.value), reason


def test_подделка_значения_отказывается_в_любой_его_части() -> None:
    """Изменение любого байта конверта — отказ: nonce обёртки, обёртка, тело, тег.

    Отдельно держится укороченное значение: снятые с конца байты тега меняют длину, и расшифровка
    обязана не состояться, а не «вернуть укороченный секрет».
    """
    envelope = _sealed()
    positions = {
        "nonce обёртки DEK": OFFSET_DEK_NONCE + 1,
        "обёртка DEK": OFFSET_WRAPPED_DEK + 5,
        "тег обёртки DEK": OFFSET_PAYLOAD - 1,
        "nonce полезной нагрузки": OFFSET_PAYLOAD_NONCE + 2,
        "тело полезной нагрузки": OFFSET_PAYLOAD + 1,
        "середина тега": len(envelope) - 8,
        "последний байт тега": len(envelope) - 1,
    }
    for reason, position in positions.items():
        tampered = bytearray(envelope)
        tampered[position] ^= 0x80
        with pytest.raises((DecryptionError, EnvelopeError)) as caught:
            open_envelope(bytes(tampered), aad=_aad(), ring=_RING)
        assert _PLAINTEXT not in str(caught.value).encode(), reason

    for cut in (1, 4, 16):
        with pytest.raises((DecryptionError, EnvelopeError)):
            open_envelope(envelope[:-cut], aad=_aad(), ring=_RING)


def test_чужой_kek_и_неизвестная_версия_ключа_отказываются_по_разному() -> None:
    """Версии ключа нет в связке → `KeyRingError`; ключ есть, но другой → `DecryptionError`.

    Различие нужно эксплуатации: первое лечится файлом ключей (доставить/вернуть версию), второе —
    уже следствие порчи данных или подмены, и перезапуск состав не чинит.
    """
    envelope = _sealed()  # активная версия 2
    ring_v1_only = _ring(active=1, keys=((1, _KEK_V1_B64),))
    with pytest.raises(KeyRingError, match="версия ключа 2 отсутствует"):
        open_envelope(envelope, aad=_aad(), ring=ring_v1_only)

    # Ключ версии 2 подменён на другой: версия «известна», а тег не сходится.
    impostor_b64 = base64.b64encode(bytes([0x33]) * AES_KEY_BYTES).decode("ascii")
    impostor = _ring(keys=((1, _KEK_V1_B64), (2, impostor_b64)))
    assert impostor.key_for(2).key != _KEK_V2_BYTES
    with pytest.raises(DecryptionError):
        open_envelope(envelope, aad=_aad(), ring=impostor)


def test_старая_строка_читается_когда_активный_ключ_новый() -> None:
    """Версия ключа внутри значения: строка старой версии читается и после смены активного KEK.

    Иначе ротация ключей (§8.4, `make rotate-keys` из `T-107`) обязана перешифровывать всё
    атомарно — то есть в окне ротации часть привязок недоступна.
    """
    ring_v1 = _ring(active=1, keys=((1, _KEK_V1_B64),))
    envelope = _sealed(ring=ring_v1)
    assert describe_envelope(envelope).key_version == 1
    assert open_envelope(envelope, aad=_aad(), ring=_RING) == _PLAINTEXT
    # Новый KEK активен, старая строка не перезаписана; новая запись уходит версией 2.
    assert describe_envelope(_sealed(ring=_RING)).key_version == 2


def test_каждая_запись_получает_свой_dek() -> None:
    """§8.4 «отдельный DEK на каждую запись»: два конверта одного секрета различны.

    Проверяется не только «байты разные», но и то, что различается именно обёртка DEK: иначе
    «разными» значения получились бы из-за случайного nonce при одном и том же ключе, что §8.4 не
    выполняет. Компрометация DEK одной строки не должна открывать другие.
    """
    aad = _aad()
    first, second = _sealed(aad), _sealed(aad)
    assert first != second
    assert _wrapped_dek(first) != _wrapped_dek(second)
    assert len(_wrapped_dek(first)) == WRAPPED_DEK_BYTES
    assert open_envelope(first, aad=aad, ring=_RING) == _PLAINTEXT
    assert open_envelope(second, aad=aad, ring=_RING) == _PLAINTEXT

    # Тот же секрет под другой привязкой — тоже другая обёртка.
    other = _sealed(_aad(record_id=_OTHER_ENROLLMENT_ID))
    assert _wrapped_dek(other) not in {_wrapped_dek(first), _wrapped_dek(second)}

    # DEK и nonce берутся из CSPRNG и не повторяются.
    assert len(new_dek()) == AES_KEY_BYTES
    assert new_dek() != new_dek()
    assert len(new_nonce()) == GCM_NONCE_BYTES
    assert new_nonce() != new_nonce()


def test_конверт_сам_описывает_свою_версию() -> None:
    """Заголовок читается без ключей: версия формата, версия KEK, длина payload.

    По этим полям `make rotate-keys` (`T-107`) отбирает строки старой версии, а диагностика
    отвечает на вопрос «почему строка не читается». Проверка держит и раскладку байтов: смещения —
    часть формата, колонок `key_version` в схеме нет (`ADR-014` п. 3).
    """
    envelope = _sealed()
    info = describe_envelope(envelope)
    assert info.format_version == ENVELOPE_FORMAT_VERSION
    assert info.key_version == 2
    assert info.payload_bytes == len(envelope) - OFFSET_PAYLOAD

    assert envelope[: len(ENVELOPE_MAGIC)] == ENVELOPE_MAGIC
    assert envelope[OFFSET_FORMAT_VERSION] == ENVELOPE_FORMAT_VERSION
    assert OFFSET_PAYLOAD == OFFSET_PAYLOAD_NONCE + GCM_NONCE_BYTES
    assert envelope[OFFSET_KEY_VERSION:OFFSET_DEK_NONCE] == bytes((0, 2))  # версия KEK = 2
    assert len(envelope) == ENVELOPE_MIN_BYTES + len(_PLAINTEXT)


def test_открытое_значение_или_чужой_формат_в_шифртекст_не_принимаются() -> None:
    """`ensure_envelope` — точка, через которую открытое значение в колонку не проходит.

    Отдельно проверяется текст отказа: в нём есть имя колонки и признак (нет метки / длина /
    неподдерживаемая версия), но нет байтов значения — отказ уходит в лог (§12.2 логирует причину),
    а секрет в логе оказаться не должен.
    """
    open_secret = base64.b32encode(_PLAINTEXT).decode("ascii").rstrip("=").encode("ascii")
    # Секрет в 512 бит (base32 — 104 символа) длиннее минимума конверта: у него проверяется
    # следующий признак — отсутствие метки формата.
    long_open_secret = (
        base64.b32encode(bytes(range(64))).decode("ascii").rstrip("=").encode("ascii")
    )
    cases: tuple[tuple[bytes, str], ...] = (
        (open_secret, "меньше минимума"),
        (long_open_secret, "нет метки формата"),
        (b"", "меньше минимума"),
        (b"\x00" * 30, "меньше минимума"),
        (b"TBE2" + b"\x00" * 100, "нет метки формата"),
        (
            ENVELOPE_MAGIC + b"\x02" + b"\x00\x02" + b"\x00" * (ENVELOPE_MIN_BYTES - 7),
            "не поддерживается",
        ),
    )
    for value, hint in cases:
        with pytest.raises(EnvelopeError) as caught:
            ensure_envelope(value, column="totp_enrollments.secret_enc")
        text = str(caught.value)
        assert "totp_enrollments.secret_enc" in text
        assert hint in text, f"{hint!r}: текст отказа не объясняет признак: {text}"
        if value:
            assert value.hex() not in text
            assert open_secret.decode() not in text
    envelope = _sealed()
    assert ensure_envelope(envelope, column="totp_enrollments.secret_enc") == envelope


def test_размер_ключа_и_длина_nonce_вне_схемы_отказываются() -> None:
    """§8.4 называет AES-256 и 96-битный IV: AES-128/AES-192 и IV другой длины — явный отказ.

    `AESGCM` принимает 16- и 24-байтные ключи молча; без отказа разница между §8.4 и кодом
    перестала бы быть заметной, а сокращение длины ключа в файле KEK осталось бы незамеченным.
    """
    aad, nonce = _aad(), new_nonce()
    for wrong_key in (b"", b"\x00" * 16, b"\x00" * 24, b"\x00" * 31, b"\x00" * 64):
        with pytest.raises(crypto.CryptoError, match="AES-256"):
            aes_gcm_encrypt(wrong_key, _PLAINTEXT, nonce=nonce, aad=aad)
        with pytest.raises(crypto.CryptoError, match="AES-256"):
            aes_gcm_decrypt(wrong_key, b"\x00" * 32, nonce=nonce, aad=aad)
    for wrong_nonce in (b"", b"\x00" * 8, b"\x00" * 11, b"\x00" * 13, b"\x00" * 60):
        with pytest.raises(crypto.CryptoError, match="длина nonce"):
            aes_gcm_encrypt(_KEK_V2_BYTES, _PLAINTEXT, nonce=wrong_nonce, aad=aad)
        with pytest.raises(crypto.CryptoError, match="длина nonce"):
            aes_gcm_decrypt(_KEK_V2_BYTES, b"\x00" * 32, nonce=wrong_nonce, aad=aad)


def test_aad_каноничен_и_алфавит_kind_закрыт() -> None:
    """Канонический состав AAD зафиксирован байтами: `T-107` собирает свой AAD по той же схеме.

    Проверка держит префикс, разделитель и канонический текст UUID (нижний регистр, тире). Если
    состав поедет, шифртексты, созданные сегодня, перестанут читаться завтра — а чинить это
    придётся по дампу, которого у пользователя нет.
    """
    expected = (
        b"tbot-aad/v1|totp_enrollment|6f1c6a11-11a1-4a1e-9b1f-111111111111"
        b"|7d2b2b22-22b2-4b2c-8b2e-222222222222"
    )
    built = _aad()
    assert built == expected
    assert built.startswith(AAD_PREFIX)

    # `kind` с разделителем, в верхнем регистре или с пробелом — отказ: два разных набора значений
    # дали бы один AAD, и привязка перестала бы различать строки.
    for bad_kind in (
        "TOTP",
        "totp|enrollment",
        "totp enrollment",
        "",
        "9totp",
        "x" * 33,
        "totp-ena",
    ):
        with pytest.raises(crypto.CryptoError, match="не соответствует алфавиту"):
            build_aad(kind=bad_kind, record_id=_ENROLLMENT_ID, owner_id=_OWNER_ID)


# ─── 3. файл KEK (§8.4: путь, права, формат) ──────────────────────────────────────────────────


def _write_key_file(
    directory: Path,
    payload: str | bytes,
    *,
    mode: int | None = 0o600,
    name: str = "kek.json",
) -> Path:
    # Имя параметризовано: второй `_write_key_file` в том же каталоге обязан создавать новый файл,
    # иначе на POSIX он пытается перезаписать файл, которому только что выставили 0400, и падает
    # с PermissionError вместо проверки политики прав.
    path = directory / name
    if isinstance(payload, bytes):
        path.write_bytes(payload)
    else:
        path.write_text(payload, encoding="utf-8")
    if mode is not None and os.name == "posix":
        path.chmod(mode)
    return path


def test_файл_ключей_читается_и_держит_связку_версий(tmp_path: Path) -> None:
    path = _write_key_file(tmp_path, _document())
    ring = load_key_ring(path)
    assert ring.active.version == 2
    assert sorted(ring.keys) == [1, 2]
    assert ring.key_for(1).key == _KEK_V1_BYTES
    assert ring.key_for(2).key == _KEK_V2_BYTES
    # Диагностика: версии и активная версия — без значений (§8.4).
    diagnostic = describe_key_ring(path)
    assert "версии [1, 2]" in diagnostic
    assert "активная 2" in diagnostic
    assert _KEK_V1_B64 not in diagnostic
    assert _KEK_V2_B64 not in diagnostic


def test_файл_ключей_принимает_base64_с_плюсом_и_отвергает_base64url() -> None:
    """Канон base64 в файле ключей — стандартный алфавит (`+`, `/`), а не «url-safe».

    Ключ в base64url (`-`, `_`) выглядит как «почти тот же ключ» и расшифровать им ничего нельзя:
    такой файл обязан быть отвергнут на чтении, а не на первой же попытке открыть привязку.
    """
    assert "+" in _KEK_SLASH_B64 or "/" in _KEK_SLASH_B64
    ring = _ring(active=1, keys=((1, _KEK_SLASH_B64),))
    assert ring.key_for(1).key == _KEK_SLASH_BYTES

    urlsafe = base64.urlsafe_b64encode(_KEK_SLASH_BYTES).decode("ascii")
    assert "-" in urlsafe or "_" in urlsafe  # PT018 не трогает `or`: это одна проверка
    with pytest.raises(KeyRingFormatError, match="base64"):
        _ring(active=1, keys=((1, urlsafe),))


def test_политика_прав_файла_ключей() -> None:
    """Права файла ключей: §8.4 (0400) и ADR-005 (640 для монтируемого файла) проходят, всё шире — нет.

    Проверка без файловой системы, то есть работает на любой платформе — в том числе на dev-машине
    Windows, где бит POSIX неоткуда взять.
    """
    for allowed in (0o400, 0o600, 0o640, 0o000):
        assert kek_file_mode_error(allowed) is None, f"{oct(allowed)} должна проходить"
    for mode in (0o644, 0o666, 0o755, 0o244, 0o622, 0o004, 0o066, 0o777, 0o1000 | 0o400):
        problem = kek_file_mode_error(mode)
        assert problem is not None, f"права {oct(mode)} не должны проходить"
        assert "§8.4" in problem or "ADR-005" in problem


@pytest.mark.skipif(
    os.name != "posix",
    reason="биты POSIX существуют только на POSIX; сама политика прав проверена отдельной проверкой",
)
def test_файл_ключей_с_правами_группы_или_мира_не_читается(tmp_path: Path) -> None:
    """На POSIX-машине (CI — Linux) файл ключей с правами «читают все» не используется вовсе.

    Такой файл уже означает скомпрометированный ключ: §8.4 требует 0400 (или 640 root:gid процесса
    по ADR-005), и поднимать приложение с ним нельзя — отказ, а не предупреждение в лог.
    """
    loose = _write_key_file(tmp_path, _document(), mode=0o644, name="kek-loose.json")
    with pytest.raises(KeyRingUnusableError, match="за пределами"):
        load_key_ring(loose)
    for mode in (0o400, 0o600, 0o640):
        ok = _write_key_file(tmp_path, _document(), mode=mode, name=f"kek-{oct(mode)[2:]}.json")
        assert load_key_ring(ok).active.version == 2


def test_отсутствие_или_недоступность_файла_ключей_отказывается_явно(tmp_path: Path) -> None:
    """«Ключа нет» — не «расшифровать не удалось»: отдельный тип отказа и объяснение пути.

    Три способа не получить ключ: файла нет, вместо файла каталог, файл не декодируется как текст.
    В текстах — путь и отсылка к §8.4; ключевого материала там нет ни в одном случае.
    """
    missing = tmp_path / "kek.json"
    with pytest.raises(KeyRingUnusableError, match="нет файла ключей") as caught:
        load_key_ring(missing)
    assert str(missing) in str(caught.value)
    assert "§8.4" in str(caught.value)

    directory = tmp_path / "keys"
    directory.mkdir()
    with pytest.raises(KeyRingUnusableError, match="нет файла ключей"):
        load_key_ring(directory)

    _write_key_file(tmp_path, b"\xff\xfe\xa4 not utf-8")
    with pytest.raises(KeyRingUnusableError, match="не читается"):
        load_key_ring(tmp_path / "kek.json")

    _write_key_file(tmp_path, "   \n")
    with pytest.raises(KeyRingFormatError, match="пуст"):
        load_key_ring(tmp_path / "kek.json")


_BAD_KEY_FILES: Final[tuple[tuple[str, str, tuple[str, ...]], ...]] = (
    ("не-JSON", "trailing comma,{", ("не разбирается как JSON",)),
    ("массив-вместо-объекта", "[]", ("JSON-объектом верхнего уровня",)),
    (
        "неизвестные-поля-и-всё-сразу",
        json.dumps({"kek": _KEK_V1_B64, "format_version": 9}),
        ("неизвестные поля", "format_version", "keys", "active_version"),
    ),
    ("ключей-нет", json.dumps({"format_version": 1, "active_version": 1, "keys": []}), ("keys",)),
    (
        "ключ-в-hex",
        json.dumps(
            {
                "format_version": 1,
                "active_version": 1,
                "keys": [{"version": 1, "key": _KEK_V1_BYTES.hex()}],
            }
        ),
        ("base64",),
    ),
    (
        # Ключ 16 байт (AES-128) в файле отсекается уже формой: base64 от 16 байт — 24 символа,
        # а не 44. §8.4 требует AES-256, и файл с ключом другого размера должен быть отвергнут
        # на чтении, а не на первой попытке открыть привязку.
        "ключ-16-байт-по-форме",
        json.dumps(
            {
                "format_version": 1,
                "active_version": 1,
                "keys": [{"version": 1, "key": base64.b64encode(b"\x00" * 16).decode("ascii")}],
            }
        ),
        ("base64",),
    ),
    (
        # 31 байт дают 44 символа base64, но с двумя дополнениями `==`. Каноническая форма
        # (44 символа с одним дополнением) декодируется ровно в 32 байта AES-256, поэтому
        # ключ другого размера отсекается формой, а не отдельной проверкой длины.
        "ключ-31-байт-по-форме",
        json.dumps(
            {
                "format_version": 1,
                "active_version": 1,
                "keys": [{"version": 1, "key": base64.b64encode(bytes(31)).decode("ascii")}],
            }
        ),
        ("base64",),
    ),
    (
        "версии-ключей-повторяются",
        json.dumps(
            {
                "format_version": 1,
                "active_version": 1,
                "keys": [{"version": 1, "key": _KEK_V1_B64}, {"version": 1, "key": _KEK_V2_B64}],
            }
        ),
        ("повторяется",),
    ),
    (
        "активной-версии-нет-среди-ключей",
        json.dumps(
            {"format_version": 1, "active_version": 7, "keys": [{"version": 1, "key": _KEK_V1_B64}]}
        ),
        ("active_version", "нет среди ключей"),
    ),
    (
        "версия-ключа-вне-2-байт",
        json.dumps(
            {
                "format_version": 1,
                "active_version": 1,
                "keys": [{"version": 70000, "key": _KEK_V1_B64}],
            }
        ),
        ("вне диапазона",),
    ),
    (
        "у-ключа-нет-поля-version",
        json.dumps({"format_version": 1, "active_version": 1, "keys": [{"key": _KEK_V1_B64}]}),
        ("нет поля 'version'",),
    ),
    (
        "ключ-не-строка",
        json.dumps(
            {"format_version": 1, "active_version": 1, "keys": [{"version": 1, "key": 12345}]}
        ),
        ("base64",),
    ),
)


@pytest.mark.parametrize("case", _BAD_KEY_FILES, ids=[case[0] for case in _BAD_KEY_FILES])
def test_файл_ключей_описывает_все_найденные_дефекты_сразу(
    case: tuple[str, str, tuple[str, ...]],
) -> None:
    """Формат файла ключей разбирается целиком: в тексте отказа — все причины, а не первая (ADR-014 п. 5).

    Файл с ключами правят на площадке; ходить кругами «починили одно — вылезло другое» означает
    несколько перезапусков состава подряд. И ни в одном тексте не должно быть значения ключа.
    """
    title, raw, hints = case
    with pytest.raises(KeyRingFormatError) as caught:
        parse_key_ring_document(raw, source="/etc/tbot/keys/kek.json")
    text = str(caught.value)
    assert "/etc/tbot/keys/kek.json" in text
    for hint in hints:
        assert hint in text, f"{title}: подсказка {hint!r} не в тексте: {text}"
    assert _KEK_V1_B64 not in text, "файл с ключами не печатает ключи"
    assert _KEK_V2_B64 not in text
    assert _KEK_V1_BYTES.hex() not in text


# ─── 4. ключевой материал не утекает в repr, str и тексты исключений ──────────────────────────


def test_ключ_и_связка_в_repr_и_str_не_показывают_ключевой_материал() -> None:
    """§8.4 «красное правило»: `repr`/`str` объекта с ключом — версия и длина, не значение.

    Лог (structlog), упавший тест, `assert` в отладке и текст исключения печатают объекты через
    repr. Если ключ попадёт в repr, он утекает одним из этих путей сразу.
    """
    material = KeyMaterial(version=1, key=_KEK_V1_BYTES)
    for rendered in (repr(material), str(material), f"{material}", f"{material!r}"):
        assert _KEK_V1_B64 not in rendered
        assert _KEK_V1_BYTES.hex() not in rendered
        assert "скрыт" in rendered

    for rendered in (repr(_RING), str(_RING), f"{_RING}"):
        assert _KEK_V1_B64 not in rendered
        assert _KEK_V2_B64 not in rendered
        assert _KEK_V1_BYTES.hex() not in rendered
        assert _KEK_V2_BYTES.hex() not in rendered
        assert "active=2" in rendered

    # Сравнение ключей работает (иначе «подменный ключ» не отличился бы в проверках выше):
    # равенство учитывает байты, а не только версию.
    assert material == KeyMaterial(version=1, key=_KEK_V1_BYTES)
    assert material != KeyMaterial(version=1, key=_KEK_V2_BYTES)


def test_тексты_всех_отказов_без_секретного_материала() -> None:
    """Ни один текст исключения криптографии не содержит KEK, DEK или открытый секрет.

    Проверяется полный набор отказов: неверный AAD, подделка, чужой ключ, неизвестная версия,
    кривой заголовок, неверный размер ключа и nonce, кривой файл ключей, отсутствующий файл.
    Именно эти тексты обработчик уносит в лог (§12.2 логирует причину отказа).
    """
    secret_text = base64.b32encode(_PLAINTEXT).decode("ascii").rstrip("=")
    envelope = _sealed()
    ring_v1_only = _ring(active=1, keys=((1, _KEK_V1_B64),))
    attempts: tuple[Callable[[], object], ...] = (
        lambda: open_envelope(envelope, aad=_aad(owner_id=_OTHER_OWNER_ID), ring=_RING),
        lambda: open_envelope(envelope, aad=_aad(), ring=ring_v1_only),
        lambda: open_envelope(bytes(bytearray(envelope)[::-1]), aad=_aad(), ring=_RING),
        lambda: open_envelope(envelope[:-9], aad=_aad(), ring=_RING),
        lambda: open_envelope(secret_text.encode("ascii"), aad=_aad(), ring=_RING),
        lambda: open_envelope(envelope, aad=b"", ring=_RING),
        lambda: seal_envelope(_PLAINTEXT, aad=_aad(kind="плохой вид"), ring=_RING),
        lambda: seal_envelope(
            _PLAINTEXT, aad=_aad(), ring=_ring(active=9, keys=((1, _KEK_V1_B64),))
        ),
        lambda: aes_gcm_encrypt(b"\x00" * 17, _PLAINTEXT, nonce=new_nonce(), aad=_aad()),
        lambda: aes_gcm_encrypt(_KEK_V2_BYTES, _PLAINTEXT, nonce=b"\x00" * 16, aad=_aad()),
        lambda: _ring(keys=((1, _KEK_V1_BYTES.hex()),)),
        lambda: load_key_ring(Path("/nonexistent-tbot-keys/kek.json")),
    )
    for index, attempt in enumerate(attempts):
        with pytest.raises(crypto.CryptoError) as caught:
            attempt()
        text = f"{caught.value!r} {caught.value}"
        assert _KEK_V1_B64 not in text, f"отказ №{index}: в тексте KEK"
        assert _KEK_V2_B64 not in text, f"отказ №{index}: в тексте KEK"
        assert _KEK_V1_BYTES.hex() not in text, f"отказ №{index}: в тексте KEK"
        assert _KEK_V2_BYTES.hex() not in text, f"отказ №{index}: в тексте KEK"
        assert _PLAINTEXT.hex() not in text, f"отказ №{index}: секрет в тексте"
        assert secret_text not in text, f"отказ №{index}: секрет в тексте"


def test_модуль_криптографии_не_пишет_лог() -> None:
    """В модуле нет логгера: ему нечего вынести в лог, а значит секрету там неоткуда взяться (§8.4).

    Проверка исходника, а не поведения: `structlog` в модуле криптографии — и значение ключа
    рискует оказаться в записи лога вместе с текстом отказа.
    """
    source = Path(crypto.__file__).read_text(encoding="utf-8")
    assert "structlog" not in source
    assert "import logging" not in source
    assert "logger" not in source


def test_метаданные_конверта_не_несут_ни_ключа_ни_значения() -> None:
    """`EnvelopeInfo` — только версии и длина: ни DEK, ни открытого значения.

    Это то, что держат в руках диагностика и `rotate-keys`; понеси туда ключ или секрет — они
    поехали бы по процессу мимо вызывающего кода.
    """
    info = describe_envelope(_sealed())
    assert sorted(vars(info)) == ["format_version", "key_version", "payload_bytes"]
    assert _PLAINTEXT.hex() not in repr(info)
    assert _KEK_V2_BYTES.hex() not in repr(info)
