"""Политика и хэширование паролей (TZ §8.1, `REQ-identity-01`, задача `T-101`).

Что закреплено этим модулем:

* алгоритм один — Argon2id с параметрами ТЗ (`m=64 MiB, t=3, p=4`); другие параметры и другие
  алгоритмы не принимаются: схема `0002` проверяет префикс `$argon2id$` CHECK-ограничением
  (`packages/storage/models.py`), а несовпадение параметров внутри `$argon2id$...` база не
  заметит — это заметит только сравнение хэшей при входе, то есть живой пользователь;
* минимальная длина — 12 символов (§8.1);
* пароль не должен совпадать с типовым слабым (набор `WEAK_PASSWORDS`) и не должен совпадать с
  логином или доменом (§8.1);
* сравнение пароля делает `argon2.verify` (сравнение постоянной длительности внутри библиотеки),
  сам модуль побайтового сравнения не реализует.

Чего здесь сознательно нет:

* верхней границы длины: §8.1 её не задаёт, а Argon2 платит за длину пароля линейно и недорого
  (замер на машине проекта — 25 мс на хэш при 64 MiB), поэтому выдумывать ограничение, которое
  отвергнет длинную passphrase, нельзя. При появлении требования — правка ТЗ;
* срок жизни пароля и запрет повторной установки прежнего пароля: в §8.1 этого нет;
* проверка «пароль содержит логин подстрокой»: §8.1 формулирует правило как совпадение.

Набор слабых значений строится из короткого авторского перечня оснований (`_WEAK_BASE`): к каждому
добавляются числовые хвосты и перекладки раскладки EN↔RU по физическим клавишам. Без этого
«password» отклонялся бы, а «зфыыцщкв» (то же слово в русской раскладке) и «password12345» —
проходили, и это ровно те обходы, из-за которых словарь бесполезен.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# ─── параметры Argon2id (TZ §8.1: m=64 MiB, t=3, p=4) ────────────────────────────────────────

#: §8.1 требует 64 MiB; Argon2 принимает память в КиБ, поэтому 64 · 1024, а не 64_000_000.
ARGON2_MEMORY_COST_KIB: Final = 64 * 1024
ARGON2_TIME_COST: Final = 3
ARGON2_PARALLELISM: Final = 4
#: 32 байта выхода и 16 байт соли — каноническая пара референсной реализации. Одностороннее
#: изменение ломает сверку с ожиданиями приёмки (§8.1) и стоимость проверки.
ARGON2_HASH_LEN: Final = 32
ARGON2_SALT_LEN: Final = 16

#: Канонический префикс кодировки PHC. Совпадает с CHECK-ограничением схемы `0002`
#: (`users.password_hash`); связь проверяет контрактный тест
#: `tests/contract/test_identity_passwords.py` — иначе смена алгоритма здесь стала бы тихой
#: ошибкой на площадке: база пропустила бы хэш другого вида.
ARGON2_HASH_PREFIX: Final = "$argon2id$"

#: §8.1: «длина пароля ≥12 символов».
MIN_PASSWORD_LENGTH: Final = 12

_HASHER: Final = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST_KIB,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN,
    type=Type.ID,
)


# ─── список типовых слабых паролей ────────────────────────────────────────────────────────────

#: Авторское основание списка: то, что читает и правит человек. Полный набор (`WEAK_PASSWORDS`)
#: строится из оснований автоматически — так в словаре не появляется шва, где «password» есть, а
#: «password12345» нет.
_WEAK_BASE: Final[tuple[str, ...]] = (
    # глобальная классика, служебные слова и слова из дампов
    "password",
    "passwort",
    "passwd",
    "pass",
    "admin",
    "administrator",
    "root",
    "toor",
    "login",
    "user",
    "guest",
    "system",
    "server",
    "database",
    "secret",
    "access",
    "master",
    "change",
    "changeme",
    "default",
    "temp",
    "test",
    "welcome",
    "letmein",
    "iloveyou",
    "sunshine",
    "monkey",
    "dragon",
    "princess",
    "football",
    "baseball",
    "hockey",
    "soccer",
    "batman",
    "superman",
    "spiderman",
    "computer",
    "internet",
    "google",
    "firefox",
    "wordpress",
    "whatever",
    "starwars",
    "chocolate",
    "banana",
    "cheese",
    "hunter",
    "killer",
    "michael",
    "jennifer",
    "jordan",
    # последовательности клавиатуры и цифр (в обеих раскладках)
    "qwerty",
    "asdfgh",
    "zxcvbn",
    "qazwsx",
    "qwertyuiop",
    "asdfghjkl",
    "abc",
    "abcd",
    "abcde",
    "abcdef",
    "aaaa",
    "1234",
    "12345",
    "123456",
    # проект, домен и брокер: пароль не бывает названием системы или конторы
    "tbot",
    "rusiksoft",
    "tinkoff",
    "tbank",
    "invest",
    "broker",
    "trader",
    "trading",
    "money",
    "profit",
    "bitcoin",
    "moex",
    # русские основания: словарь обязан работать для кириллицы
    "пароль",
    "привет",
    "любимый",
    "люблю",
    "счастье",
    "здоровье",
    "работа",
    "москва",
    "победа",
    "собака",
    "кошка",
    "курица",
    "огурец",
    "бутерброд",
    "шоколад",
    "лимонад",
    "клавиатура",
    "телефон",
    "велосипед",
    "супермен",
    "бэтмен",
    "колбаса",
    "повар",
    "год",
    "лето",
    "зима",
    "весна",
    "осень",
    "2024",
    "2025",
    "2026",
    "2027",
)

#: Числовые хвосты к основанию. Отдельного правила «нельзя цифры в конце» в §8.1 нет, поэтому
#: хвосты расширяют словарь, а не политику.
_WEAK_SUFFIXES: Final[tuple[str, ...]] = ("", "123", "1234", "12345", "123456")

#: Буквы и знаки на одних и тех же физических клавишах раскладок EN (QWERTY) и RU (ЙЦУКЕН).
_EN_TO_RU_KEYS: Final[Mapping[str, str]] = {
    "q": "й",
    "w": "ц",
    "e": "у",
    "r": "к",
    "t": "е",
    "y": "н",
    "u": "г",
    "i": "ш",
    "o": "щ",
    "p": "з",
    "[": "х",
    "]": "ъ",
    "a": "ф",
    "s": "ы",
    "d": "в",
    "f": "а",
    "g": "п",
    "h": "р",
    "j": "о",
    "k": "л",
    "l": "д",
    ";": "ж",
    "'": "э",
    "z": "я",
    "x": "ч",
    "c": "с",
    "v": "м",
    "b": "и",
    "n": "т",
    "m": "ь",
    ",": "б",
    ".": "ю",
}

_RU_TO_EN_KEYS: Final[Mapping[str, str]] = {_ru: _en for _en, _ru in _EN_TO_RU_KEYS.items()}


def _shift_layout(token: str, table: Mapping[str, str]) -> str:
    """Переложить строку в другую раскладку по физическим клавишам; незнакомое остаётся как есть."""
    return "".join(table.get(char, char) for char in token)


def _build_weak_lookup() -> frozenset[str]:
    lookup: set[str] = set()
    for base in _WEAK_BASE:
        normalized = base.casefold()
        forms = {
            normalized,
            _shift_layout(normalized, _EN_TO_RU_KEYS),
            _shift_layout(normalized, _RU_TO_EN_KEYS),
        }
        for form in forms:
            for suffix in _WEAK_SUFFIXES:
                if form + suffix:
                    lookup.add(form + suffix)
    return frozenset(lookup)


#: Полный набор проверяемых значений; сравнение — по `casefold()` набираемого пароля.
WEAK_PASSWORDS: Final[frozenset[str]] = _build_weak_lookup()

#: Домены, совпадать с которыми паролю нельзя (§8.1 «пароль = логин/домен»). Взяты из TZ §14:
#: рабочая ВМ работает на `tbot.rusiksoft.ru`. При смене домена меняются и это значение, и запись
#: в ТЗ — контрактная проверка сверяет домен из ТЗ с перечисленными здесь.
SERVICE_DOMAINS: Final[frozenset[str]] = frozenset(
    {"tbot", "rusiksoft", "rusiksoft.ru", "tbot.rusiksoft.ru"}
)


# ─── ошибки ──────────────────────────────────────────────────────────────────────────────────


class PasswordPolicyError(ValueError):
    """Пароль не проходит §8.1.

    `reasons` — формулировки правил для интерфейса (TZ §9: причину отказа показывать, счётчик
    попыток — нет). Открытый пароль в причины не попадает: в сообщении только имя правила.
    """

    def __init__(self, reasons: Sequence[str]) -> None:
        detail = "; ".join(reasons) or "пароль не проходит политику (§8.1)"
        super().__init__(detail)
        self.reasons: tuple[str, ...] = tuple(reasons)


class MalformedPasswordHashError(ValueError):
    """Хэш в базе не является корректной кодировкой Argon2id.

    Схема `0002` не пропускает такой хэш (`CHECK left(password_hash, 10) = '$argon2id$'`), поэтому
    ошибка означает одно из двух: строку изменили мимо приложения (ручная правка базы или дамп,
    который восстановили с нарушенной цепочкой) или код пишет не тот формат. Молча считать такой
    пароль «неверным» нельзя: пользователь не сможет войти, а причина исчезнет.
    """


# ─── политика ────────────────────────────────────────────────────────────────────────────────


def _identity_values(login: str | None, email: str | None) -> frozenset[str]:
    """Значения, с которыми пароль не имеет права совпадать (§8.1 «логин/домен»)."""
    values: set[str] = set(SERVICE_DOMAINS)
    if login:
        values.add(login.strip().casefold())
    if email:
        cleaned = email.strip().casefold()
        values.add(cleaned)
        local, separator, domain = cleaned.partition("@")
        if separator:
            values.add(local)
            values.add(domain)
            values.add(domain.split(".", 1)[0])
    return frozenset(value for value in values if value)


def policy_violations(
    password: str, *, login: str | None = None, email: str | None = None
) -> tuple[str, ...]:
    """Нарушения §8.1 одним списком — чтобы интерфейс показал все сразу, а не по одному.

    Возвращает пустой кортеж, если пароль проходит политику. Открытое значение в ответе не
    участвует: только названия правил.
    """
    reasons: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        reasons.append(f"длина меньше {MIN_PASSWORD_LENGTH} символов (§8.1)")
    if password.casefold() in WEAK_PASSWORDS:
        reasons.append("пароль совпадает с типовым слабым, в том числе в другой раскладке (§8.1)")
    identity = _identity_values(login, email)
    if password and password.casefold() in identity:
        reasons.append("пароль совпадает с логином или доменом (§8.1)")
    return tuple(reasons)


def check_password_policy(
    password: str, *, login: str | None = None, email: str | None = None
) -> None:
    """Проверить пароль по §8.1. Бросает `PasswordPolicyError` со всеми нарушениями сразу."""
    reasons = policy_violations(password, login=login, email=email)
    if reasons:
        raise PasswordPolicyError(reasons)


# ─── хэширование и сравнение ─────────────────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    """Хэш Argon2id с параметрами §8.1.

    Политику **не** проверяет: у вызывающего свои обстоятельства (сброс администратором,
    миграция старых значений), и решение о том, проходит ли пароль §8.1, принимается слоем
    выше. Для учётной записи приложения вход — `users.apply_new_password`, который политику
    применяет обязательно.
    """
    return _HASHER.hash(password)


def verify_password(*, password: str, stored_hash: str) -> bool:
    """Сравнить набираемый пароль с хэшем из базы: `True` — совпал, `False` — нет.

    Исключение бросает только одно — `MalformedPasswordHashError`, если хэш в базе не является
    корректной кодировкой Argon2id. Ошибки `argon2.exceptions` наружу не выпускаются: слой входа
    (`T-102`) не должен знать про библиотеку хэширования, ему достаточно «да/нет» плюс вызова
    `users.register_login_failure`.

    Аргументы — только по именам: переставленные местами `password` и `stored_hash` дали бы вечное
    «неверный пароль», и по логам это неотличимо от реальной ошибки пользователя.
    """
    if not stored_hash.startswith(ARGON2_HASH_PREFIX):
        raise MalformedPasswordHashError(
            f"хэш пароля не начинается с {ARGON2_HASH_PREFIX!r}: ожидаем кодировку Argon2id (§8.1)"
        )
    try:
        return _HASHER.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
    except InvalidHashError as exc:
        raise MalformedPasswordHashError(
            "хэш пароля не разбирается как Argon2id: строка изменена мимо приложения либо код "
            "пишет не тот формат (§8.1)"
        ) from exc
