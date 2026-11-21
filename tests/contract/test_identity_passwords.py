"""Контракт политики паролей: код не должен разъезжаться с ТЗ, схемой и списком зависимостей.

Зачем это офлайн (без сервера): расхождение параметров Argon2 с §8.1, другой префикс хэша, чем
требует CHECK-ограничение `0002`, или «случайная» новая зависимость — всё это на живой площадке
выглядит не как ошибка конфигурации, а как пользователь, который не может войти. Проверки читают
текст ТЗ, ORM-описание таблицы и `pyproject.toml`.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Final, cast

from sqlalchemy import Table
from sqlalchemy.schema import CheckConstraint

from packages.identity.passwords import (
    _WEAK_BASE,
    ARGON2_HASH_LEN,
    ARGON2_HASH_PREFIX,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_SALT_LEN,
    ARGON2_TIME_COST,
    MIN_PASSWORD_LENGTH,
    SERVICE_DOMAINS,
    WEAK_PASSWORDS,
    hash_password,
)
from packages.storage.models import User

ROOT = Path(__file__).resolve().parents[2]
TZ_SECURITY: Final = ROOT / "docs" / "tz" / "08-security-auth-2fa.md"
TZ_DEPLOY: Final = ROOT / "docs" / "tz" / "14-deployment-and-servers.md"
PYPROJECT: Final = ROOT / "pyproject.toml"

#: Разрешённые внешние (не stdlib и не проекта) импорты в `packages/identity`. `argon2` —
#: единственная зависимость, согласованная заказчиком как стоп-точка TZ §15 (ask `633f8d2b`).
_ALLOWED_THIRD_PARTY: Final[frozenset[str]] = frozenset({"argon2"})


def _tz_text(path: Path) -> str:
    assert path.is_file(), f"нет секции техзадания: {path}"
    return path.read_text(encoding="utf-8")


def test_параметры_argon2_совпадают_с_техзаданием() -> None:
    """§8.1: «Argon2id (m=64 MiB, t=3, p=4), длина пароля ≥12 символов»."""
    line = _tz_text(TZ_SECURITY)
    match = re.search(r"Argon2id\s*\(m=(\d+)\s*MiB,\s*t=(\d+),\s*p=(\d+)\)", line)
    assert match, "в §8.1 не найдена строка с параметрами Argon2 — проверка потеряла смысл"
    memory_mib, time_cost, parallelism = (int(value) for value in match.groups())

    assert (
        memory_mib * 1024 == ARGON2_MEMORY_COST_KIB
    ), f"§8.1 требует {memory_mib} MiB, код задаёт {ARGON2_MEMORY_COST_KIB} КиБ"
    assert time_cost == ARGON2_TIME_COST, "time_cost не совпадает с §8.1"
    assert parallelism == ARGON2_PARALLELISM, "parallelism не совпадает с §8.1"

    length_match = re.search(r"длина пароля\s*[≥>]=?\s*(\d+)\s*символов", line)
    assert length_match, "в §8.1 не найдена минимальная длина пароля"
    assert (
        int(length_match.group(1)) == MIN_PASSWORD_LENGTH
    ), f"минимальная длина в коде ({MIN_PASSWORD_LENGTH}) не совпадает с §8.1"

    # Длина выхода и соли — не из ТЗ, а из референсной кодировки: их изменение молча меняет
    # стоимость проверки и уникальность хэшей, поэтому фиксированы явно.
    assert (
        ARGON2_HASH_LEN == 32
    ), "длина выхода хэша: 256 бит, как требует §8.3/§8.5 для токенов и кодов"
    assert (
        ARGON2_SALT_LEN == 16
    ), "соль 128 бит — иначе хэши одинаковых паролей совпадают слишком легко"


def test_префикс_хэша_совпадает_с_ограничением_схемы() -> None:
    """CHECK в `users` требует префикс `$argon2id$`; код обязан выдавать ровно его.

    Если эти два значения разъедутся, база пропустит хэши другого вида (или не пропустит наши), и
    узнаем мы об этом на миграции либо на входе пользователя.
    """
    # `__table__` на классе mypy видит как FromClause: cast фиксирует, что это Table,
    # а не обход проверки типов.
    table = cast("Table", User.__table__)
    journal = [
        str(constraint.sqltext)
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint) and "password_hash" in str(constraint.sqltext)
    ]
    assert journal, "в таблице users нет CHECK-ограничения на формат хэша пароля"
    literals: set[tuple[str, str]] = set()
    for sql in journal:
        literals.update(re.findall(r"left\(password_hash,\s*(\d+)\)\s*=\s*'([^']+)'", sql))
    assert (
        literals
    ), "CHECK-ограничение хэша не сравнивает префикс — проверка ссылки на него теряет смысл"
    for length, prefix in sorted(literals):
        assert (
            prefix == ARGON2_HASH_PREFIX
        ), f"схема требует префикс {prefix!r}, код выдаёт {ARGON2_HASH_PREFIX!r}"
        assert len(prefix) == int(
            length
        ), f"длина префикса в CHECK ({length}) не совпадает с самим префиксом {prefix!r}"


def test_хэш_кодирует_параметры_из_техзадания() -> None:
    """Parametr-строка внутри хэша обязана соответствовать константам: её читает и база, и человек."""
    digest = hash_password("контрактный-пароль-2026")
    assert digest.startswith(ARGON2_HASH_PREFIX)
    expected = f"m={ARGON2_MEMORY_COST_KIB},t={ARGON2_TIME_COST},p={ARGON2_PARALLELISM}"
    assert (
        expected in digest
    ), f"в хэше нет ожидаемого набора параметров {expected!r}: {digest[:60]}…"


def test_словарь_слабых_построен_из_оснований_и_покрывает_кириллицу() -> None:
    """Авторский перечень короткий, рабочий набор — произведение оснований на раскладки и хвосты."""
    assert len(_WEAK_BASE) >= 60, "оснований словаря слишком мало, чтобы называться списком §8.1"
    assert (
        len(WEAK_PASSWORDS) >= 300
    ), f"построенный словарь подозрительно мал: {len(WEAK_PASSWORDS)}"
    assert (
        len(WEAK_PASSWORDS) > len(_WEAK_BASE) * 2
    ), "правила построения не работают: набор равен основанию"

    cyrillic = [
        base for base in _WEAK_BASE if any("а" <= char <= "я" or char == "ё" for char in base)
    ]
    assert len(cyrillic) >= 15, "в словаре нет русских оснований: §8.1 не выполняется для кириллицы"

    for base in _WEAK_BASE:
        assert base == base.casefold(), f"основание не в нижнем регистре: {base!r}"
        assert base not in ("",), "пустое основание недопустимо"

    # основания обязаны входить в итоговый набор, и вместе с числовыми хвостами
    for base in _WEAK_BASE:
        assert base in WEAK_PASSWORDS, f"основание {base!r} пропало из итогового словаря"


def test_словарь_не_содержит_значений_с_пробелами_и_пустых() -> None:
    for value in WEAK_PASSWORDS:
        assert value, "пустое значение в словаре"
        assert not any(
            character.isspace() for character in value
        ), f"значение с пробелом: {value!r}"


def test_домены_из_техзадания_запрещены_как_пароль() -> None:
    """§8.1 «пароль = логин/домен»: домен площадки из §14 обязан быть в перечне проверяемых."""
    deploy_text = _tz_text(TZ_DEPLOY)
    hosts = set(re.findall(r"\b([a-z0-9](?:[a-z0-9-]*\.)?rusiksoft\.ru)\b", deploy_text))
    assert hosts, "в §14 не найден домен рабочей ВМ"
    for host in sorted(hosts):
        assert host in SERVICE_DOMAINS, f"домен {host!r} из §14 не запрещён как пароль"
        labels = {label for label in host.split(".") if label != "ru"}
        assert labels <= SERVICE_DOMAINS, f"метки домена {sorted(labels)} не запрещены как пароль"


def test_зависимость_argon2_зафиксирована_с_обоснованием() -> None:
    """Стоп-точка TZ §15: новая зависимость — с обоснованием и проверкой лицензии (ask `633f8d2b`)."""
    text = PYPROJECT.read_text(encoding="utf-8")
    assert '"argon2-cffi>=25.1,<26"' in text, (
        "в pyproject нет зафиксированного диапазона argon2-cffi: зависимость разъедется с той, "
        "лицензию и advisory которой согласовал заказчик"
    )
    note = text[text.index("# Argon2id") : text.index('"argon2-cffi>=25.1,<26"')]
    for marker in ("633f8d2b", "MIT", "OSV", "TZ §15"):
        assert (
            marker in note
        ), f"в обосновании зависимости нет маркера {marker!r} — запись об осознанности теряется"


def test_identity_не_тянет_несогласованных_зависимостей() -> None:
    """Любая новая зависимость — стоп-точка TZ §15, поэтому её появление ловит этот тест.

    Разрешены только стандартная библиотека, модули проекта и `argon2` (согласовано заказчиком).
    """
    offenders: list[str] = []
    stdlib: frozenset[str] = sys.stdlib_module_names
    for path in (ROOT / "packages" / "identity").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                top = name.split(".", 1)[0]
                if top in _ALLOWED_THIRD_PARTY or top == "packages" or top in stdlib:
                    continue
                offenders.append(f"{path.relative_to(ROOT)}: {top}")
    assert not offenders, (
        "в packages/identity появился несогласованный импорт — нужна стоп-точка TZ §15 "
        "(обоснование + лицензия + advisory): " + "; ".join(sorted(set(offenders)))
    )
