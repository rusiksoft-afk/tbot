"""Юнит-логика резервных кодов входа (TZ §8.2, задача `T-104`, срез `R5a`).

Здесь проверяется то, что живая база доказать не может: состав алфавита и стойкость одного кода,
канон формы (регистр и разделители), совпадение хэша с фиксированным вектором, отказ по формату без
утечки значения в текст и правило семидневного срока перевыпуска — включая границу, ничью выпуска с
расходом и «расход из новой пачки отсчитывает срок заново».

Разделение половин намеренное. `test_backup_code_single_use` (одноразовость под параллельными
входами — guarded-`UPDATE` в слое доступа) появляется вместе с живой проверкой в срезе `R5b`, а
`test_backup_code_flow` (пачка показана один раз, предупреждение после расхода, отказ на шаге
`password`) — вместе с маршрутами в срезе `R5c`. Оба правила вне
`packages/identity/backup_codes.py`: одноразовость — свойство перехода «нашёл → пометил», а не
свойство значения, и ни один из них нельзя доказать на объектах в памяти.

Фикстуры строк `backup_codes` собираются в памяти: модуль работает с моделью, а не с соединением, и
проверяемые ниже правила не требуют, чтобы значение лежало в таблице.
"""

from __future__ import annotations

import hashlib
import math
import re
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

import pytest

from packages.identity import backup_codes as backup_codes_module
from packages.identity.backup_codes import (
    BACKUP_CODE_ALPHABET,
    BACKUP_CODE_ALPHABET_SIZE,
    BACKUP_CODE_COUNT,
    BACKUP_CODE_ENTROPY_BITS,
    BACKUP_CODE_LENGTH,
    RECOVERY_REGENERATION_WINDOW,
    BackupCodeError,
    BackupCodeFormatError,
    BackupCodeGenerationError,
    RecoveryState,
    backup_code_matches,
    display_backup_code,
    hash_backup_code,
    is_sha256_hex,
    new_backup_codes,
    normalize_backup_code,
    recovery_state,
)
from packages.storage.models import BackupCode

#: Форма хэша, которую принимает колонка `code_hash` (`ck_backup_codes_code_hash_sha256`).
#: Шаблон повторён здесь намеренно: проверка обязана ловить расхождение кода со схемой, а не
#: подстраиваться под него, импортируя константу модели.
SCHEMA_HASH_PATTERN: str = "^[0-9a-f]{64}$"

#: Опорное значение: 10 знаков алфавита в канонической форме, хэш зафиксирован вектором. Если
#: изменится канон (регистр, разделители) или алгоритм, живые строки перестанут совпадать — и этот
#: тест упадёт раньше, чем пользователь увидит «кода нет».
CANONICAL_CODE: str = "ABCDEFGHJK"
CANONICAL_HASH: str = "f57cbf1e3e471b25db4b8ad0844df41b2dae9c7d1944944d128e49294d412f66"

#: Момент, от которого считаются сроки: стабильный, без `datetime.now`, чтобы границу можно было
#: ставить стрелками вида «на секунду позже границы».
T0: datetime = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)

#: Наборы значений для отказов по формату: пустое, другая длина, знак вне алфавита.
BAD_FORMATS: tuple[str, ...] = (
    "",
    "   ",
    "ABCDEFGHI",  # 9 знаков
    "ABCDEFGHIJK",  # 11 знаков
    "AB CD EF GH",  # 8 знаков после уборки пробелов
    "ABCDEFÖHGJK",  # символ вне латиницы
    "ABCDÉFGHIJK",  # акцент
    "ABCDEFGHI0",  # цифра 0 убрана из алфавита
    "ABCDEFGHIL",  # буква L убрана из алфавита
    "AAAABBBBBO",  # буква O убрана из алфавита
    "AAAABBBBB0",  # цифра 0 убрана из алфавита
)

#: Мусор, который обязан быть отвергнут без исключения: свёртка не должна уметь «падать».
GARBAGE: tuple[str, ...] = ("", " ", "\n", "\U0001f525" * 10, "<script>x</script>", "0" * 10)


def _row(*, created_at: datetime, used_at: datetime | None = None) -> BackupCode:
    """Строка `backup_codes` в памяти: своя учётная запись, свой хэш, отмеченные моменты."""
    return BackupCode(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        code_hash=hashlib.sha256(uuid.uuid4().hex.encode()).hexdigest(),
        created_at=created_at,
        used_at=used_at,
    )


def _batch(
    issued_at: datetime,
    *,
    used: int = 0,
    spent_at: datetime | None = None,
    count: int = BACKUP_CODE_COUNT,
) -> list[BackupCode]:
    """Пачка строк, выпущенная в `issued_at`, где `used` первых помечены израсходованными.

    Момент расхода задаётся явно (`spent_at`), по умолчанию — на минуту позже выпуска. Граница
    семидневного срока проверяется по секундам, поэтому «примерно та же дата» в фикстуре недопустима:
    сдвиг фикстуры на сутки сделал бы проверку границы зелёной при неверном правиле. Строка,
    израсходованная ровно в тот же миг, что выпущена, — отдельный случай (ничья), он задаётся явно.
    """
    rows: list[BackupCode] = []
    for index in range(count):
        used_at = None
        if index < used:
            начало = spent_at if spent_at is not None else issued_at + timedelta(minutes=1)
            used_at = начало + timedelta(minutes=index)
        rows.append(_row(created_at=issued_at, used_at=used_at))
    return rows


def _state_of(rows: Iterable[BackupCode], *, now: datetime = T0) -> RecoveryState:
    return recovery_state(rows, now=now)


# ─── выдача: сколько, какие знаки, откуда значения ────────────────────────────────────────────


def test_пачка_содержит_десять_разных_кодов_длиной_в_десять_знаков() -> None:
    for _ in range(20):
        пакет = new_backup_codes()
        assert len(пакет) == BACKUP_CODE_COUNT
        assert len(set(пакет)) == BACKUP_CODE_COUNT, "повторы внутри пачки"
        for код in пакет:
            assert len(код) == BACKUP_CODE_LENGTH


def test_два_выпуска_подряд_не_пересекаются() -> None:
    первый = set(new_backup_codes())
    второй = set(new_backup_codes())
    assert первый.isdisjoint(второй), "пересечение выпусков: источник значений не случайный"


def test_алфавит_без_похожих_знаков_задан_прямо() -> None:
    assert BACKUP_CODE_ALPHABET == "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    assert BACKUP_CODE_ALPHABET_SIZE == 31
    # Убрано ровно то, что сливается при чтении с экрана и при наборе: I≡l≡1 и O≡0.
    for запретный in "ILOilo01":
        assert запретный not in BACKUP_CODE_ALPHABET
    ожидаемый = (set("ABCDEFGHIJKLMNOPQRSTUVWXYZ") - set("ILO")) | set("23456789")
    assert set(BACKUP_CODE_ALPHABET) == ожидаемый


def test_выданные_коды_состоят_только_из_знаков_алфавита() -> None:
    допустимо = set(BACKUP_CODE_ALPHABET)
    for код in new_backup_codes(count=100):
        assert set(код) <= допустимо, f"знак вне алфавита в значении с длиной {len(код)}"


def test_стойкость_одного_кода_не_меньше_сорока_девяти_бит() -> None:
    # Число считается из констант, а не записано магической цифрой: сузить алфавит на два знака —
    # значит потерять ~7 бит, и проверка обязана стать красной.
    ожидаемо = math.log2(float(BACKUP_CODE_ALPHABET_SIZE) ** BACKUP_CODE_LENGTH)
    assert ожидаемо == BACKUP_CODE_ENTROPY_BITS
    assert BACKUP_CODE_ENTROPY_BITS >= 49.0


@pytest.mark.parametrize("запрошено", [0, -1, 1001])
def test_число_кодов_в_пачке_ограничено(запрошено: int) -> None:
    with pytest.raises(BackupCodeGenerationError):
        new_backup_codes(count=запрошено)


def test_вырожденный_алфавит_даёт_отказ_а_не_зависание(monkeypatch: pytest.MonkeyPatch) -> None:
    # Петля сборки пачки ограничена сверху намеренно: если алфавит когда-нибудь сузится до
    # одного-двух знаков, запрос обязан отказать, а не зависить внутри HTTP-обработчика. Проверка
    # ломает алфавит намеренно — это единственный способ увидеть сам отказ, и он же страховка от
    # «исправной» на вид петли без границы попыток.
    monkeypatch.setattr(backup_codes_module, "BACKUP_CODE_ALPHABET", "A")
    with pytest.raises(BackupCodeGenerationError) as ошибка:
        new_backup_codes(count=10)
    assert "10" in str(ошибка.value)


def test_отказ_в_числе_кодов_называет_запрошенное_число() -> None:
    with pytest.raises(BackupCodeGenerationError) as ошибка:
        new_backup_codes(count=0)
    assert "0" in str(ошибка.value)


# ─── канон формы: хэш считается по нему, а не по предъявленной строке ─────────────────────────


def test_канон_опорного_значения_совпадает_с_ним_самим() -> None:
    assert normalize_backup_code(CANONICAL_CODE) == CANONICAL_CODE


@pytest.mark.parametrize(
    "предъявлено",
    [
        "abcdefghjk",  # строчные буквы
        "ABCDE-FGHJK",  # перенесено из показа с дефисом
        "ABCDE\u2013FGHJK",  # короткое тире
        "ABCDE\u2014FGHJK",  # длинное тире
        " abc def gh jk ",  # пробелы, в том числе по краям
        "ABCD\tEFGHJK\n",  # таб и перевод строки из буфера обмена
    ],
)
def test_форма_ввода_не_важна_хэш_один_и_тот_же(предъявлено: str) -> None:
    assert normalize_backup_code(предъявлено) == CANONICAL_CODE
    assert hash_backup_code(предъявлено) == CANONICAL_HASH


@pytest.mark.parametrize("предъявлено", BAD_FORMATS)
def test_отказ_по_формату_без_утечки_значения(предъявлено: str) -> None:
    with pytest.raises(BackupCodeFormatError) as ошибка:
        normalize_backup_code(предъявлено)
    сообщение = str(ошибка.value)
    # Значение кода — секрет входа: в сообщении об отказе его быть не может (тот же порядок, что
    # с секретом привязки в ADR-014 п. 6). Пустые и пробельные наборы в тексте совпадают тривиально,
    # поэтому для них проверка не ставится.
    if предъявлено.strip():
        assert предъявлено not in сообщение


def test_похожие_знаки_не_подставляются_молча() -> None:
    # «O» вместо «0» и наоборот: автозамена исправила бы опечатку молча, и приложение приняло бы
    # код не так, как показывает. Отказ по формату обязателен.
    for предъявлено in ("AAAABBBBBO", "AAAABBBBB0"):
        with pytest.raises(BackupCodeFormatError):
            normalize_backup_code(предъявлено)


def test_хэш_фиксирован_вектором() -> None:
    assert hash_backup_code(CANONICAL_CODE) == CANONICAL_HASH
    assert hash_backup_code(CANONICAL_CODE.lower()) == CANONICAL_HASH


def test_форма_хэша_проходит_ограничение_схемы() -> None:
    шаблон = re.compile(SCHEMA_HASH_PATTERN)
    for код in new_backup_codes():
        хэш = hash_backup_code(код)
        assert шаблон.fullmatch(хэш), "форма хэша разошлась с CHECK колонки code_hash"
        assert is_sha256_hex(хэш)


def test_хэши_разных_кодов_различаются() -> None:
    хэши = {hash_backup_code(код) for код in new_backup_codes(count=100)}
    assert len(хэши) == 100, "хэши совпали: колонка code_hash перестала различать коды"


@pytest.mark.parametrize(
    "битая_строка",
    [
        "",
        "f57cbf1e",
        CANONICAL_HASH.upper(),
        CANONICAL_HASH[:-1],
        CANONICAL_HASH + "0",
        "z" * 64,
        " " + CANONICAL_HASH,
    ],
)
def test_битая_строка_хэша_не_считается_совпадением(битая_строка: str) -> None:
    assert not is_sha256_hex(битая_строка)
    assert not backup_code_matches(битая_строка, CANONICAL_CODE)


# ─── сверка значения ──────────────────────────────────────────────────────────────────────────


def test_значение_узнаётся_по_хэшу_в_любой_из_форм_ввода() -> None:
    хэш = hash_backup_code(CANONICAL_CODE)
    for форма in (CANONICAL_CODE, CANONICAL_CODE.lower(), display_backup_code(CANONICAL_CODE)):
        assert backup_code_matches(хэш, форма), f"форма {форма!r} не распознана"


def test_чужое_значение_и_некорректная_форма_не_дают_совпадения() -> None:
    хэш = hash_backup_code(CANONICAL_CODE)
    assert not backup_code_matches(хэш, "ABCDEFGHJJ")
    assert not backup_code_matches(хэш, "AB")


@pytest.mark.parametrize("мусор", GARBAGE)
def test_сверка_не_поднимает_исключение_на_мусоре(мусор: str) -> None:
    хэш = hash_backup_code(CANONICAL_CODE)
    assert backup_code_matches(хэш, мусор) is False


# ─── показ ─────────────────────────────────────────────────────────────────────────────────────


def test_формат_показа_обратим_в_канон() -> None:
    for код in new_backup_codes():
        показано = display_backup_code(код)
        assert показано.count("-") == 1
        assert len(показано) == BACKUP_CODE_LENGTH + 1
        assert normalize_backup_code(показано) == код


@pytest.mark.parametrize("ширина", [0, -3])
def test_ширина_группы_показа_проверяется(ширина: int) -> None:
    with pytest.raises(BackupCodeError):
        display_backup_code(CANONICAL_CODE, group_size=ширина)


# ─── семидневный срок (§8.2: расход → предупреждение → блокировка входа) ──────────────────────


def test_без_кодов_требования_нет_и_вход_не_заблокирован() -> None:
    assert _state_of([]) == RecoveryState(
        unused=0,
        used=0,
        last_used_at=None,
        regeneration_deadline=None,
        needs_regeneration=False,
        login_blocked=False,
    )


def test_выпущенные_и_непотраченные_коды_не_требуют_перевыпуска() -> None:
    состояние = _state_of(_batch(T0 - timedelta(days=30)), now=T0)
    assert состояние.unused == BACKUP_CODE_COUNT
    assert состояние.used == 0
    assert состояние.last_used_at is None
    assert not состояние.needs_regeneration
    assert not состояние.login_blocked


def test_расход_порождает_требование_и_назначает_срок() -> None:
    выпущено = T0 - timedelta(days=1)
    израсходовано = T0 - timedelta(hours=6)
    пакет = _batch(выпущено, used=1, spent_at=израсходовано)
    состояние = _state_of(пакет, now=T0)
    assert состояние.used == 1
    assert состояние.unused == BACKUP_CODE_COUNT - 1
    assert состояние.last_used_at == израсходовано
    assert состояние.needs_regeneration, "потрачен код — обязано требоваться перевыпуск"
    assert состояние.regeneration_deadline == израсходовано + RECOVERY_REGENERATION_WINDOW
    assert not состояние.login_blocked, "шесть часов после расхода вход ещё разрешён"


@pytest.mark.parametrize(
    ("назад", "заблокирован"),
    [
        (RECOVERY_REGENERATION_WINDOW - timedelta(seconds=1), False),
        (RECOVERY_REGENERATION_WINDOW, False),  # граница входит в «в течение 7 дней»
        (RECOVERY_REGENERATION_WINDOW + timedelta(seconds=1), True),
        (timedelta(days=30), True),
    ],
)
def test_просрочка_срока_блокирует_вход(назад: timedelta, заблокирован: bool) -> None:
    израсходовано = T0 - назад
    пакет = _batch(израсходовано - timedelta(days=1), used=1, spent_at=израсходовано)
    состояние = _state_of(пакет, now=T0)
    assert состояние.login_blocked is заблокирован
    assert состояние.needs_regeneration


def test_новый_выпуск_после_расхода_снимает_требование() -> None:
    израсходовано = T0 - timedelta(days=6)
    старый = _batch(израсходовано - timedelta(days=20), used=1, spent_at=израсходовано)
    assert _state_of(старый, now=T0).needs_regeneration
    новый = _batch(израсходовано + timedelta(minutes=5))
    # Из старой пачки в набор попадают только израсходованные строки: повторная генерация
    # аннулирует прежние коды (§8.2), и удаляет их слой доступа. Живая проверка того, что
    # аннулирование действительно происходит, появляется со срезом `R5b`; здесь важно, чтобы
    # правило срока не считало уцелевший остаток прежней пачки новым выпуском.
    состояние = _state_of(
        [*(строка for строка in старый if строка.used_at is not None), *новый], now=T0
    )
    assert not состояние.needs_regeneration
    assert not состояние.login_blocked
    assert состояние.unused == BACKUP_CODE_COUNT
    assert состояние.used == 1


def test_расход_из_новой_пачки_отсчитывает_срок_заново() -> None:
    первый_расход = T0 - timedelta(days=20)
    второй_расход = T0 - timedelta(days=1)
    старая = _batch(первый_расход - timedelta(days=10), used=1, spent_at=первый_расход)
    новая = _batch(первый_расход + timedelta(hours=1), used=1, spent_at=второй_расход)
    состояние = _state_of([*старая, *новая], now=T0)
    assert состояние.last_used_at == второй_расход
    assert состояние.needs_regeneration, "расход из перевыпущенной пачки обязан требовать перевод"
    assert состояние.regeneration_deadline == второй_расход + RECOVERY_REGENERATION_WINDOW


def test_срок_определяется_по_последнему_расходу() -> None:
    пакет = _batch(T0 - timedelta(days=40), used=3, spent_at=T0 - timedelta(minutes=5))
    состояние = _state_of(пакет, now=T0)
    assert состояние.last_used_at == T0 - timedelta(minutes=3)
    assert состояние.regeneration_deadline == T0 + RECOVERY_REGENERATION_WINDOW - timedelta(
        minutes=3
    )
    assert not состояние.login_blocked


def test_израсходованные_строки_не_считаются_остатком() -> None:
    состояние = _state_of(_batch(T0 - timedelta(days=2), used=BACKUP_CODE_COUNT), now=T0)
    assert состояние.unused == 0
    assert состояние.used == BACKUP_CODE_COUNT
    assert состояние.needs_regeneration


def test_ничья_выпуска_и_расхода_трактуется_в_пользу_входа() -> None:
    момент = T0 - timedelta(days=6)
    пакет = _batch(момент, used=1, spent_at=момент)  # расход в тот же миг, что и выпуск
    состояние = _state_of(пакет, now=T0)
    assert not состояние.needs_regeneration, "равенство моментов обязано считаться перевыпуском"
    assert состояние.unused == BACKUP_CODE_COUNT - 1


def test_одноразовый_итератор_не_ломает_правило() -> None:
    израсходовано = T0 - timedelta(days=3)
    пакет = _batch(израсходовано - timedelta(days=1), used=1, spent_at=израсходовано)
    по_списку = _state_of(пакет, now=T0)
    по_генератору = recovery_state((строка for строка in пакет), now=T0)
    assert по_генератору == по_списку, "правило потеряло второй проход по строкам"


def test_состояние_не_зависит_от_порядка_строк() -> None:
    израсходовано = T0 - timedelta(days=8)
    пакет = _batch(израсходовано - timedelta(days=1), used=2, spent_at=израсходовано)
    прямой = _state_of(пакет, now=T0)
    обратный = _state_of(list(reversed(пакет)), now=T0)
    assert прямой == обратный
    assert прямой.login_blocked, "восемь дней без перевыпуска — вход блокируется"
