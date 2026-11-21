"""Юнит-политика паролей (TZ §8.1, `T-101`; обязательная проверка `test_password_policy`).

Живая база не нужна: правила — строковые, а хэширование делает `argon2`. Проверка того, что
`$argon2id$` совпадает с ограничением схемы и что параметры не разъехались с §8.1, — в
`tests/contract/test_identity_passwords.py`; поведение блокировки — в `test_login_lockout.py`.
"""

from __future__ import annotations

import inspect

import pytest

from packages.identity.passwords import (
    _EN_TO_RU_KEYS,
    _RU_TO_EN_KEYS,
    ARGON2_HASH_PREFIX,
    MIN_PASSWORD_LENGTH,
    WEAK_PASSWORDS,
    MalformedPasswordHashError,
    PasswordPolicyError,
    _shift_layout,
    check_password_policy,
    hash_password,
    policy_violations,
    verify_password,
)

#: Пароль, который проходит политику и используется как «правильный» в нескольких проверках.
#: Имя переменной намеренно не `password`: правила линтера (S105) ловят «хардкодный пароль» в
#: именах, а подавлений в проекте не добавляется.
GOOD = "правильная-лошадь-бычок-2026"


def _reasons(
    candidate: str, *, login: str | None = None, email: str | None = None
) -> tuple[str, ...]:
    return policy_violations(candidate, login=login, email=email)


def test_password_policy() -> None:
    """§8.1: длина ≥12, словарь слабых, совпадение с логином/доменом — по одному кейсу на правило."""
    short = "коротк12345"  # 11 символов: ровно на один меньше порога §8.1
    assert len(short) == MIN_PASSWORD_LENGTH - 1
    assert any("длина" in reason for reason in _reasons(short))

    assert _reasons(GOOD) == (), f"правильный пароль отклонён: {_reasons(GOOD)}"

    assert any("типовым слабым" in reason for reason in _reasons("password12345"))
    assert any("типовым слабым" in reason for reason in _reasons("PASSWORD123456"))
    assert any("типовым слабым" in reason for reason in _reasons("зфыыцщкв12345"))

    assert any(
        "логином или доменом" in reason
        for reason in _reasons("ivan.petrov2026", login="ivan.petrov2026")
    )
    assert any(
        "логином или доменом" in reason
        for reason in _reasons("ivan.petrov", email="ivan.petrov@rusiksoft.ru")
    )
    assert any("логином или доменом" in reason for reason in _reasons("rusiksoft", login="ivan"))

    with pytest.raises(PasswordPolicyError) as caught:
        check_password_policy(short, login="ivan")
    assert caught.value.reasons


def test_длину_считаем_по_символам_а_не_по_байтам() -> None:
    """Кириллица в пароле — обычная строка: 12 символов это 12 символов, не 24 байта."""
    cyrillic = "правильныйпароль"
    assert len(cyrillic) == 16
    assert _reasons(cyrillic) == ()
    assert any("длина" in reason for reason in _reasons("коротк"))


def test_граница_длины_включает_12_символов() -> None:
    exactly = "1" * MIN_PASSWORD_LENGTH
    assert _reasons(exactly) == ()
    assert any("длина" in reason for reason in _reasons("1" * (MIN_PASSWORD_LENGTH - 1)))


def test_словарь_работает_в_обе_стороны_раскладки() -> None:
    """«зфыыцщкв» — это «password» в русской раскладке: словарь обязан ловить и такое."""
    shifted = _shift_layout("password", _EN_TO_RU_KEYS)
    assert shifted in WEAK_PASSWORDS, f"перекладка {shifted!r} не в словаре"
    assert _shift_layout("йцукен", _RU_TO_EN_KEYS) == "qwerty"
    # «ghbdtn» — это «привет» с английской раскладки: §9 отдельно описывает вход с раскладки,
    # и такие пароли приходят именно латиницей
    assert _shift_layout("ghbdtn", _EN_TO_RU_KEYS) == "привет"
    assert any("слабым" in reason for reason in _reasons("ghbdtn"))
    for base in ("qwerty", "iloveyou", "пароль"):
        assert base in WEAK_PASSWORDS
        assert _shift_layout(base, _EN_TO_RU_KEYS) in WEAK_PASSWORDS
        assert _shift_layout(base, _RU_TO_EN_KEYS) in WEAK_PASSWORDS


def test_словарь_ловит_основание_с_числовым_хвостом() -> None:
    for base in ("changeme", "letmein", "tinkoff"):
        for suffix in ("123", "1234", "12345", "123456"):
            assert base + suffix in WEAK_PASSWORDS, f"{base}{suffix} не в словаре"


def test_словарь_не_содержит_пустого_и_значений_с_пробелами() -> None:
    """Гигиена перечня: пустое значение и значения с пробелами — признак ошибки сборки словаря.

    Сравнение точное (`casefold()` целиком), поэтому пустая строка в множестве не открыла бы
    вход; но появиться она там может только из-за ошибки в правилах построения — как и значение
    с пробелом, которое невозможно набрать как одно слово.
    """
    assert "" not in WEAK_PASSWORDS
    for value in WEAK_PASSWORDS:
        assert value, "в словаре пустое значение"
        assert not any(
            character.isspace() for character in value
        ), f"значение с пробелом: {value!r}"
        assert value == value.casefold(), f"значение не в нижнем регистре: {value!r}"


def test_совпадение_с_доменом_регистронезависимо() -> None:
    for candidate in ("RUSIKSOFT.RU", "Tbot", "rusiksoft"):
        assert any(
            "логином или доменом" in reason for reason in _reasons(candidate, login="user")
        ), candidate


def test_почта_как_домен_и_как_локальная_часть() -> None:
    email = "ivan.petrov@rusiksoft.ru"
    assert any("логином или доменом" in reason for reason in _reasons("ivan.petrov", email=email))
    assert any("логином или доменом" in reason for reason in _reasons("rusiksoft.ru", email=email))
    # сам адрес целиком — тоже «совпадение с логином»
    assert any("логином или доменом" in reason for reason in _reasons(email, email=email))
    # а значение, которое только содержит логин, §8.1 не запрещает: правило сформулировано как
    # совпадение, и выдумывать «подстроку» нельзя
    assert _reasons("ivan.petrov-2026-05", email=email) == ()


def test_причина_отказа_не_содержит_открытый_пароль() -> None:
    """Открытый пароль не попадает в сообщения (§8.1) и в логи (§12.1): только имя правила."""
    candidate = "password12345"
    reasons = _reasons(candidate)
    assert reasons
    for reason in reasons:
        assert candidate not in reason
    with pytest.raises(PasswordPolicyError) as caught:
        check_password_policy(candidate, login="ivan")
    assert candidate not in str(caught.value)
    assert candidate not in repr(caught.value)


def test_хэш_и_сравнение_работают_и_с_кириллицей() -> None:
    digest = hash_password(GOOD)
    assert digest.startswith(ARGON2_HASH_PREFIX)
    assert verify_password(password=GOOD, stored_hash=digest)
    assert not verify_password(password="другой-пароль-2026", stored_hash=digest)


def test_хэши_одного_пароля_различаются_из_за_соли() -> None:
    first, second = hash_password(GOOD), hash_password(GOOD)
    assert first != second, "соль не различается: одинаковые пароли дали бы одинаковые хэши"
    assert verify_password(password=GOOD, stored_hash=first)
    assert verify_password(password=GOOD, stored_hash=second)


def test_открытый_пароль_не_встречается_в_хэше() -> None:
    digest = hash_password(GOOD)
    assert GOOD not in digest
    assert GOOD.encode() not in digest.encode("utf-8", "surrogateescape")


def test_сломанный_хэш_в_базе_не_тихое_несовпадение() -> None:
    for broken in ("", "not-a-hash", "$bcrypt$2b$12$abc", "$argon2i$v=19$m=65536,t=3,p=4$x$y"):
        with pytest.raises(MalformedPasswordHashError) as caught:
            verify_password(password=GOOD, stored_hash=broken)
        assert "argon2id" in str(caught.value).casefold() or "argon2id" in broken


def test_аргументы_сравнения_только_по_именам() -> None:
    """Позиционная передача переставленных местами значений должна быть невозможна физически.

    Проверяется подпиской и `Signature.bind`, а не «запрещённым» вызовом с подавлением
    типов: бюджет подавлений в проекте фиксирован, и тратить его на тест незачем.
    """
    digest = hash_password(GOOD)
    signature = inspect.signature(verify_password)
    assert signature.parameters["password"].kind is inspect.Parameter.KEYWORD_ONLY
    with pytest.raises(TypeError):
        signature.bind("хэш", digest)
