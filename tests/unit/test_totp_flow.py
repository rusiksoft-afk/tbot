"""Юнит-поток кодов 2FA (TZ §8.2, задача `T-103`, срез `R4a`; обязательная проверка `test_totp_flow`).

Здесь проверяется то, что живая база доказать не может: математика кода по RFC 6238/4226, границы
окна допуска, «код принимается один раз», требование двух **последовательных** кодов при
подтверждении привязки и порог «5 неудачных кодов → блокировка входа на 15 минут».

Разделение половин намеренное: `tests/integration/*_db.py` (срез `R4b`) доказывает, что привязка
переживает перезапуск и видна другому соединению, а маршрутная половина `T-103` («только страница
кода доступна на шаге `password`», обязательная `test_route_requires_full_auth`) появляется со срезом
`R4c`, когда появятся сами маршруты.

Опорные значения кода взяты из RFC 4226 Appendix D (секрет `12345678901234567890`, счётчики 0…9) —
это те же 6 цифр, что фиксирует §8.2, и те же 30 секунд, что фиксирует §5.1 RFC 6238: шаг TOTP есть
счётчик HOTP, привязанный к времени, поэтому векторы применимы напрямую.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from datetime import UTC, datetime, timedelta

import pytest

from packages.identity.totp import (
    TOTP_ALGORITHM,
    TOTP_DIGITS,
    TOTP_FAILURE_HORIZON,
    TOTP_MAX_FAILED_CODES,
    TOTP_PERIOD_SECONDS,
    TOTP_SECRET_BYTES,
    TOTP_SOURCE_WEB,
    TOTP_SOURCES,
    TOTP_WINDOW_DEFAULT_STEPS,
    TOTP_WINDOW_MAX_STEPS,
    TotpCheck,
    TotpSecretError,
    TotpSourceError,
    count_recent_totp_failures,
    decode_totp_secret,
    new_totp_failure,
    new_totp_secret,
    normalize_totp_secret,
    register_totp_code_failure,
    totp_code,
    totp_provisioning_uri,
    totp_step,
    verify_totp_code,
    verify_totp_pair,
)
from packages.identity.users import LOCK_DURATION, new_user
from packages.storage.models import TOTP_WINDOW_MAX, TotpFailure, User

#: Фиксированное «сейчас» ровно на границе шага: `43200 % 30 == 0`, поэтому полдень по UTC —
#: начало шага, и смещения на ±1, ±2 шага получают адресно, без «примерно за 30 секунд».
NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)

#: Секрет RFC 4226 §5.4 (ASCII «12345678901234567890») — тот, для которого в Appendix D напечатаны
#: эталонные коды.
RFC_KEY = b"12345678901234567890"
RFC_SECRET_B32 = base64.b32encode(RFC_KEY).decode("ascii").rstrip("=")

#: RFC 4226 Appendix D: счётчики 0…9 → 6-значные коды (значения из RFC, не из реализации).
RFC_4226_VECTORS: tuple[str, ...] = (
    "755224",
    "287082",
    "359152",
    "969429",
    "338314",
    "254676",
    "287922",
    "162583",
    "399871",
    "520489",
)

#: RFC 6238 Appendix B, строки SHA-1: штамп, значение `T` как напечатано в RFC (16-ричные цифры) и
#: код из 8 цифр. Секрет тот же, что у RFC 4226, поэтому обе таблицы проверяют один ключ.
RFC_6238_VECTORS: tuple[tuple[int, str, str], ...] = (
    (59, "0000000000000001", "94287082"),
    (1111111109, "00000000023523EC", "07081804"),
    (1111111111, "00000000023523ED", "14050471"),
    (1234567890, "000000000273EF07", "89005924"),
    (2000000000, "0000000003F940AA", "69279037"),
    (20000000000, "0000000027BC86AA", "65353130"),
)


#: Секрет привязки в проверках — фиксированный, а не сгенерированный: эталонные коды должны быть
#: воспроизводимы, а случайный секрет превращает проверку в «что-то совпало с чем-то».
SECRET_B32 = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
SECRET_KEY = decode_totp_secret(SECRET_B32)
STEP = totp_step(NOW)


def _шаг(code: int) -> datetime:
    """Момент начала шага с номером `code` (относительно текущего шага — отрицательные тоже)."""
    return NOW + timedelta(seconds=TOTP_PERIOD_SECONDS * code)


def _код(code: int, secret: str = SECRET_B32) -> str:
    """Код на шаге `code` — сторона генератора (то, что показывает аутентикатор)."""
    return totp_code(secret, _шаг(code))


def _код_по_формуле_рфк(key: bytes, counter: int) -> str:
    """Формула RFC 4226 §5.3, записанная в проверке независимо от модуля.

    Нужна одному: поймать ветку, где старший бит усечённого 4-байтного значения (знак) потерян, —
    для эталонного секрета RFC такой ситуации нет, а без неё реализация проходит половину
    реальных значений.
    """
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    window = digest[offset : offset + 4]
    combined = int.from_bytes(window, "big") & 0x7FFFFFFF
    return f"{combined % 10**TOTP_DIGITS:0{TOTP_DIGITS}d}"


# ─── параметры зафиксированы ТЗ и схемой, а не настройкой ──────────────────────────────────────


def test_параметры_кода_закреплены_тз_8_2() -> None:
    assert TOTP_DIGITS == 6
    assert TOTP_PERIOD_SECONDS == 30
    assert TOTP_ALGORITHM == "SHA1"
    assert TOTP_WINDOW_DEFAULT_STEPS == 1


def test_окно_в_коде_не_может_быть_шире_окна_в_схеме() -> None:
    """Граница окна приходит из схемы: CHECK-ограничение `verify_window` и константа кода не разъезжаются."""
    assert TOTP_WINDOW_MAX_STEPS == TOTP_WINDOW_MAX == 2


def test_пороги_неудач_и_срок_блокировки_закреплены_тз_8_2() -> None:
    assert TOTP_MAX_FAILED_CODES == 5
    assert TOTP_FAILURE_HORIZON == LOCK_DURATION == timedelta(minutes=15)


# ─── математика кода: RFC 4226 / RFC 6238 ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("counter", "expected"),
    list(enumerate(RFC_4226_VECTORS)),
)
def test_код_совпадает_с_эталоном_rfc_4226(counter: int, expected: str) -> None:
    """Эталон RFC, а не «сверка с самой собой»: шаг TOTP = счётчик HOTP, момент = 30·counter."""
    moment = datetime.fromtimestamp(TOTP_PERIOD_SECONDS * counter, tz=UTC)
    assert totp_step(moment) == counter
    assert totp_code(RFC_SECRET_B32, moment) == expected
    assert totp_code(RFC_KEY, moment) == expected


def test_шаг_меняется_ровно_на_границе_30_секунд() -> None:
    """RFC 6238 §5.1: `T = floor(unix/X)`. Граница окна — место, где чаще всего ломается приём."""
    assert totp_step(_шаг(0)) == STEP
    assert totp_step(_шаг(0) + timedelta(seconds=29)) == STEP
    assert totp_step(_шаг(1)) == STEP + 1
    assert totp_step(_шаг(0) - timedelta(seconds=1)) == STEP - 1


@pytest.mark.parametrize(
    ("unix_time", "t_hex", "eight_digits"),
    list(RFC_6238_VECTORS),
)
def test_код_совпадает_с_эталоном_rfc_6238(unix_time: int, t_hex: str, eight_digits: str) -> None:
    """Таблица RFC 6238 Appendix B (SHA-1) — она же покрывает §4.2: `T` за 2038 годом не обрезается.

    RFC печатает 8 цифр, а §8.2 фиксирует 6. Сравнение законно: и то, и другое — одно усечённое
    значение, взятое по модулю 10^8 и 10^6 соответственно, а 10^6 делит 10^8 без остатка. Если
    модуль или усечка съедут, равенство перестанет держаться хотя бы на одной строке таблицы.
    """
    moment = datetime.fromtimestamp(unix_time, tz=UTC)
    assert totp_step(moment) == int(t_hex, 16)
    expected = f"{int(eight_digits) % 10**TOTP_DIGITS:0{TOTP_DIGITS}d}"
    assert totp_code(RFC_KEY, moment) == expected
    assert totp_code(RFC_SECRET_B32, moment) == expected


def test_код_всегда_из_шести_ascii_цифр() -> None:
    for offset in (-3, -1, 0, 1, 7, 12345):
        value = _код(offset)
        assert len(value) == 6
        assert value.isascii()
        assert value.isdecimal()


def test_дополнение_секрета_не_влияет_на_код() -> None:
    """base32 без `=` и с `=` — один и тот же ключ: аутентикаторы печатают оба варианта."""
    padded = RFC_SECRET_B32 + "=" * (-len(RFC_SECRET_B32) % 8)
    assert totp_code(padded, NOW) == totp_code(RFC_SECRET_B32, NOW)


def test_ключ_и_текст_секрета_дают_один_код() -> None:
    """Хранилище отдаёт `bytes` (расшифрованный `secret_enc`), генерация — строку: код обязан совпасть."""
    assert totp_code(SECRET_KEY, NOW) == totp_code(SECRET_B32, NOW)


def test_старший_бит_усечки_не_теряется() -> None:
    """Ветка знака из RFC 4226 §5.3: для эталонного секрета RFC её нет, а ломается она молча."""
    checked = 0
    for counter in range(4000):
        digest = hmac.new(SECRET_KEY, struct.pack(">Q", counter), hashlib.sha1).digest()
        if digest[digest[-1] & 0x0F] & 0x80:
            moment = datetime.fromtimestamp(TOTP_PERIOD_SECONDS * counter, tz=UTC)
            assert totp_code(SECRET_KEY, moment) == _код_по_формуле_рфк(SECRET_KEY, counter)
            checked += 1
            if checked >= 3:
                break
    assert checked >= 3


def test_чужой_секрет_не_принимает_чужой_код() -> None:
    other = new_totp_secret()
    result = verify_totp_code(other, _код(0), now=NOW)
    assert result.status == "mismatch"


# ─── окно допуска (§8.2: ±1 шаг, максимум ±2) ──────────────────────────────────────────────────


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_окно_по_умолчанию_принимает_плюс_минус_1_шаг(offset: int) -> None:
    result = verify_totp_code(SECRET_B32, _код(offset), now=NOW)
    assert result.status == "accepted"
    assert result.counter == STEP + offset
    assert result.step_offset == offset


@pytest.mark.parametrize("offset", [-2, 2, 3])
def test_окно_по_умолчанию_не_принимает_плюс_минус_2_шага(offset: int) -> None:
    assert verify_totp_code(SECRET_B32, _код(offset), now=NOW).status == "mismatch"


@pytest.mark.parametrize("offset", [-2, -1, 0, 1, 2])
def test_окно_плюс_минус_2_принимается_когда_разрешено_схемой(offset: int) -> None:
    result = verify_totp_code(SECRET_B32, _код(offset), window=TOTP_WINDOW_MAX_STEPS, now=NOW)
    assert result.status == "accepted"


@pytest.mark.parametrize("offset", [-3, 3])
def test_окно_не_расширяется_сверх_границы_схемы(offset: int) -> None:
    """`window=9` не даёт девять шагов допуска: окно сжимается до границы CHECK-ограничения."""
    result = verify_totp_code(SECRET_B32, _код(offset), window=9, now=NOW)
    assert result.status == "mismatch"


def test_окно_в_ноль_принимает_только_текущий_шаг() -> None:
    assert verify_totp_code(SECRET_B32, _код(0), window=0, now=NOW).status == "accepted"
    assert verify_totp_code(SECRET_B32, _код(1), window=0, now=NOW).status == "mismatch"
    assert verify_totp_code(SECRET_B32, _код(0), window=-4, now=NOW).status == "accepted"


def test_опоздавший_на_два_шага_код_не_принимается_вообще() -> None:
    """Смысл окна — «пользователь опоздал на шаг», а не «у него есть пять минут форы»."""
    assert verify_totp_code(
        SECRET_B32, _код(-2), window=TOTP_WINDOW_MAX_STEPS, now=_шаг(4)
    ).status == ("mismatch")


# ─── «коды принимаются один раз» (§8.2) и правило монотонности RFC 6238 §5.2 ──────────────────


def test_тот_же_шаг_повторно_не_принимается() -> None:
    result = verify_totp_code(SECRET_B32, _код(0), last_used_counter=STEP, now=NOW)
    assert result.status == "replay"
    assert result.counter == STEP


def test_код_более_старого_шага_не_принимается() -> None:
    result = verify_totp_code(SECRET_B32, _код(-1), last_used_counter=STEP, now=NOW)
    assert result.status == "replay"
    assert result.counter == STEP - 1


def test_код_следующего_шага_после_принятого_принимается() -> None:
    """Ровно то, что даёт «принять один раз»: следующий шаг обязан пройти, иначе привязка ломается."""
    result = verify_totp_code(SECRET_B32, _код(1), last_used_counter=STEP, now=NOW)
    assert result.status == "accepted"
    assert result.counter == STEP + 1


def test_защита_от_повтора_не_работает_без_известного_последнего_шага() -> None:
    """Домен не помнит состояние: без переданного счётчика он не знает, что уже принято (ADR-013 п. 3)."""
    first = verify_totp_code(SECRET_B32, _код(0), now=NOW)
    again = verify_totp_code(SECRET_B32, _код(0), now=NOW)
    assert first.status == "accepted"
    assert again.status == "accepted"


# ─── синтаксис предъявленного значения ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "presented",
    [
        "",
        "12345",
        "1234567",
        "abcdef",
        "12345 6",
        "123-456",
        "١٢٣٤٥٦",  # арбано-индийские цифры: isdigit() истинен, кода из них не будет
        "٦٧٨٩٠١",
        "１２３４５６",  # полноширинные цифры
        "000000 ",
    ],
)
def test_значение_не_похожее_на_код_отличается_от_неверного_кода(presented: str) -> None:
    assert verify_totp_code(SECRET_B32, presented, now=NOW).status == "malformed"


def test_верный_код_с_пробелом_всё_равно_malformed_а_не_mismatch() -> None:
    """Веб-слой обязан убрать пробелы сам: домен не «додумывает» ввод, иначе границы съезжают."""
    assert verify_totp_code(SECRET_B32, f" {_код(0)}", now=NOW).status == "malformed"


def test_причина_отказа_не_раскрывает_ни_код_ни_секрет() -> None:
    """§8.4: материал доступа не попадает в лог. Итог проверки печатается в лог обработчиком."""
    presented = _код(5)
    result = verify_totp_code(SECRET_B32, presented, now=NOW)
    assert result.status == "mismatch"
    rendered = repr(result)
    assert presented not in rendered
    assert SECRET_B32 not in rendered


def test_итог_проверки_не_содержит_поля_с_кодом() -> None:
    assert not any("code" in field.name for field in TotpCheck.__dataclass_fields__.values())


# ─── подтверждение привязки: два последовательных кода (§8.2) ──────────────────────────────────


def test_пара_последовательных_кодов_подтверждает_привязку() -> None:
    result = verify_totp_pair(SECRET_B32, _код(0), _код(1), now=NOW)
    assert result.status == "accepted"
    assert result.counter == STEP + 1


def test_один_и_тот_же_код_дважды_привязку_не_подтверждает() -> None:
    """Главная ветка этого требования: «ввёл один код дважды» не должно проходить."""
    assert verify_totp_pair(SECRET_B32, _код(0), _код(0), now=NOW).status == "replay"


def test_коды_через_шаг_привязку_не_подтверждают() -> None:
    """Пропущенный шаг = пользователь подсмотрел одно значение и не показал следующий."""
    result = verify_totp_pair(SECRET_B32, _код(-2), _код(0), window=TOTP_WINDOW_MAX_STEPS, now=NOW)
    assert result.status == "not_consecutive"
    assert result.counter == STEP


def test_коды_в_обратном_порядке_привязку_не_подтверждают() -> None:
    assert verify_totp_pair(SECRET_B32, _код(1), _код(0), now=NOW).status == "replay"


def test_подтверждение_привязки_не_принимает_уже_израсходованный_код() -> None:
    """Код шага, который уже ушёл на вход, не подтверждает новую привязку (§8.2 «один раз»)."""
    spent = verify_totp_pair(SECRET_B32, _код(0), _код(1), last_used_counter=STEP, now=NOW)
    assert spent.status == "replay"
    assert spent.counter == STEP
    free = verify_totp_pair(SECRET_B32, _код(0), _код(1), last_used_counter=STEP - 1, now=NOW)
    assert free.status == "accepted"
    assert free.counter == STEP + 1


@pytest.mark.parametrize("presented", ["", "123456", "abcdef"])
def test_подтверждение_привязки_с_битым_кодом_не_проходит(presented: str) -> None:
    assert verify_totp_pair(SECRET_B32, _код(0), presented, now=NOW).status in {
        "malformed",
        "mismatch",
    }


def test_подтверждение_привязки_в_окне_плюс_минус_2_тоже_требует_соседних_шагов() -> None:
    result = verify_totp_pair(SECRET_B32, _код(-2), _код(-1), window=TOTP_WINDOW_MAX_STEPS, now=NOW)
    assert result.status == "accepted"
    assert result.counter == STEP - 1


# ─── секрет привязки: генерация и ручной ввод ──────────────────────────────────────────────────


def test_сгенерированный_секрет_каноничен_и_достаточной_длины() -> None:
    secret = new_totp_secret()
    assert len(secret) == 32
    assert secret.isupper()
    assert decode_totp_secret(secret) == decode_totp_secret(normalize_totp_secret(secret))
    assert len(decode_totp_secret(secret)) == TOTP_SECRET_BYTES


def test_секреты_не_повторяются() -> None:
    assert len({new_totp_secret() for _ in range(64)}) == 64


def test_нижняя_граница_длины_секрета_ровно_128_бит() -> None:
    """26 символов base32 — это ровно 128 бит: RFC 4226 §4 (R6) их требует, отвергать их нельзя."""
    assert len(decode_totp_secret("A" * 26)) == 16
    with pytest.raises(TotpSecretError):
        decode_totp_secret("A" * 24)


def test_верхняя_граница_длины_секрета_512_бит() -> None:
    """Длиннее 512 бит аутентикаторы сохраняют укороченно: принять такой секрет — значит выдать
    привязку, которая «никогда не подходит», и оставить пользователя разбираться одному."""
    assert len(decode_totp_secret("A" * 103)) == 64
    with pytest.raises(TotpSecretError):
        decode_totp_secret("A" * 104)


@pytest.mark.parametrize(
    "as_typed",
    [
        "jbswy3dpehpk3pxpjbswy3dpehpk3pxp",
        "JBSWY3DP EHPK3PXP JBSWY3DP EHPK3PXP",
        "jbsw-y3dp-ehpk-3pxp-jbsw-y3dp-ehpk-3pxp",
        " JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP ",
    ],
)
def test_ручной_ввод_секрета_нормализуется(as_typed: str) -> None:
    """Экран аутентикатора печатает секрет блоками с пробелами — это не ошибка пользователя."""
    assert decode_totp_secret(as_typed) == SECRET_KEY


def test_сообщение_о_битом_секрете_не_печатает_сам_секрет() -> None:
    """§8.4: обработчик уносит текст отказа в лог, поэтому в нём только символы вне base32."""
    with pytest.raises(TotpSecretError) as refusal:
        decode_totp_secret("JBSWY3DPEHPK3PXP!0Q")
    assert "JBSWY3DPEHPK3PXP" not in str(refusal.value)
    assert "Q" not in str(refusal.value)
    assert "0" in str(refusal.value)


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "S3CR3T!KEY", "1111111", "AAAA", "AA", "0OQ", "ЯПБСВЫЗДПЕ", "A" * 200],
)
def test_секрет_вне_алфавита_или_неподходящей_длины_отвергается(bad: str) -> None:
    with pytest.raises(TotpSecretError):
        decode_totp_secret(bad)


def test_короткий_секрет_отвергается_явно_а_не_тихо_дополняется() -> None:
    """Ключ в 5 байт перебирается: принять его «раз пользователь так ввёл» — значит сделать вид."""
    with pytest.raises(TotpSecretError) as refusal:
        decode_totp_secret("ABCDEFGH")
    assert "длиной" in str(refusal.value) or "длина" in str(refusal.value)


# ─── URI привязки (то, что кладётся в QR; картинка — отдельное решение) ────────────────────────


def test_uri_привязки_содержит_параметры_протокола() -> None:
    uri = totp_provisioning_uri(SECRET_B32, account_name="ivan.petrov", issuer="Tbot")
    assert uri.startswith("otpauth://totp/")
    assert "secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" in uri
    assert "issuer=Tbot" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri


def test_uri_экранирует_двоеточие_в_метке() -> None:
    """:keyauth-профиль разрезает метку по первому `:` — незаэкранированный логин с `:` ломает привязку."""
    uri = totp_provisioning_uri(SECRET_B32, account_name="ivan:petrov", issuer="Тбот консоль")
    label = uri.split("?", 1)[0].removeprefix("otpauth://totp/")
    assert "%3A" in label
    assert label.count(":") == 1  # единственный разделитель — между издателем и логином
    assert "issuer=%D0%A2%D0%B1%D0%BE%D1%82%20%D0%BA%D0%BE%D0%BD%D1%81%D0%BE%D0%BB%D1%8C" in uri


def test_uri_переносит_секрет_в_верхний_регистр() -> None:
    uri = totp_provisioning_uri("jbswy3dpehpk3pxpjbswy3dpehpk3pxp", account_name="u", issuer="T")
    assert "secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" in uri


# ─── лента неудач и блокировка входа (§8.2) ───────────────────────────────────────────────────


@pytest.fixture
def account() -> User:
    return new_user(
        login="ivan.petrov", password="правильная-лошадь-2026", role="operator", now=NOW
    )


def _лента(
    account: User, count: int, *, gap: timedelta = timedelta(minutes=1)
) -> list[TotpFailure]:
    """Неудачи в окне: `gap` между попытками, все раньше текущей, все ближе горизонта."""
    return [
        new_totp_failure(account.id, ip="2001:db8::1", at=NOW - gap * (index + 1))
        for index in range(count)
    ]


def test_строка_ленты_несёт_время_адрес_и_источник(account: User) -> None:
    row = new_totp_failure(account.id, ip="192.0.2.10", at=NOW)
    assert row.user_id == account.id
    assert row.at == NOW
    assert row.ip == "192.0.2.10"
    assert row.source == TOTP_SOURCE_WEB


def test_источник_попытки_вне_перечня_отвергается(account: User) -> None:
    with pytest.raises(TotpSourceError):
        new_totp_failure(account.id, ip=None, source="csv-import", at=NOW)
    assert TOTP_SOURCES == ("web", "telegram")


def test_счёт_неудач_видит_только_окно(account: User) -> None:
    fresh = _лента(account, 3)
    stale = [
        new_totp_failure(account.id, ip=None, at=NOW - TOTP_FAILURE_HORIZON - timedelta(minutes=1))
    ]
    assert count_recent_totp_failures([*fresh, *stale], now=NOW) == 3


@pytest.mark.parametrize("prior", [0, 1, 2, 3])
def test_нехватка_до_порога_вход_не_закрывает(account: User, prior: int) -> None:
    row, lock = register_totp_code_failure(account, _лента(account, prior), ip=None, now=NOW)
    assert row.at == NOW
    assert lock is None
    assert account.locked_until is None


def test_пятая_неудача_закрывает_вход_на_15_минут(account: User) -> None:
    """Порог считается **включая** текущую попытку: иначе «5 подряд» блокировало бы с шестой."""
    row, lock = register_totp_code_failure(account, _лента(account, 4), ip="2001:db8::2", now=NOW)
    assert row.user_id == account.id
    assert lock == NOW + LOCK_DURATION == NOW + timedelta(minutes=15)
    assert account.locked_until == NOW + timedelta(minutes=15)


def test_неудача_кода_не_трогает_счётчик_неудач_пароля(account: User) -> None:
    """§8.1 и §8.2 считаются раздельно: «неверный код» не должен влиять на блокировку от подбора пароля."""
    account.failed_attempts = 2
    register_totp_code_failure(account, _лента(account, 4), ip=None, now=NOW)
    assert account.failed_attempts == 2


def test_пять_неудач_за_пределами_окна_вход_не_закрывают(account: User) -> None:
    stale = [
        new_totp_failure(
            account.id, ip=None, at=NOW - TOTP_FAILURE_HORIZON - timedelta(minutes=2 * index)
        )
        for index in range(4)
    ]
    _, lock = register_totp_code_failure(account, stale, ip=None, now=NOW)
    assert lock is None


def test_к_моменту_разблокировки_лента_успевает_устареть(account: User) -> None:
    """Горизонт ленты = срок блокировки: иначе первая же попытка после разблокировки стала бы шестой."""
    prior = _лента(account, 4)
    row, lock = register_totp_code_failure(account, prior, ip=None, now=NOW)
    assert lock == NOW + LOCK_DURATION
    assert count_recent_totp_failures([*prior, row], now=lock) == 0
    assert count_recent_totp_failures([*prior, row], now=NOW) == 5


# ─── время: наивное значение не должно просачиваться в вычисления шага ─────────────────────────


@pytest.mark.parametrize("moment", [NOW.replace(tzinfo=None)])
def test_наивное_время_отвергается_во_всех_точках_лет_кода(moment: datetime) -> None:
    with pytest.raises(ValueError, match="наивный datetime"):
        totp_step(moment)
    with pytest.raises(ValueError, match="наивный datetime"):
        totp_code(SECRET_B32, moment)
    with pytest.raises(ValueError, match="наивный datetime"):
        verify_totp_code(SECRET_B32, _код(0), now=moment)
    with pytest.raises(ValueError, match="наивный datetime"):
        verify_totp_pair(SECRET_B32, _код(0), _код(1), now=moment)
    with pytest.raises(ValueError, match="наивный datetime"):
        count_recent_totp_failures([], now=moment)
    with pytest.raises(ValueError, match="наивный datetime"):
        register_totp_code_failure(new_account(), [], ip=None, now=moment)


def new_account() -> User:
    return new_user(login="anna.sidorova", password="правильная-лошадь-2026", role="operator")
