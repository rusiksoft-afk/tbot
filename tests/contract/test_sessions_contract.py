"""Контракт сессий: код не должен разъезжаться с ТЗ и со схемой (§8.3, §4.1, задача `T-102`).

Эти проверки не требуют ни базы, ни HTTP. Они нужны ровно за то же, за что и остальные
контракты проекта: срок сессии, набор шагов входа и перечень критичных действий записаны в ТЗ
человекочитаемо, а живут числами и строками в коде. Расхождение обнаруживается не заказчиком на
приёмке, а здесь — например, когда «12 часов» тихо превращаются в 120 минут или когда в схему
добавляют шаг входа, не сказав слою входа.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Final, cast

from sqlalchemy import Table
from sqlalchemy.schema import CheckConstraint, UniqueConstraint

from packages.identity import sessions
from packages.identity.sessions import (
    ABSOLUTE_TIMEOUT,
    AUTH_STEP_ORDER,
    CRITICAL_ACTIONS,
    IDLE_TIMEOUT,
    SESSION_REASON_CODES,
    SESSION_TOKEN_BITS,
    SessionDescriptor,
    SessionInvalidError,
)
from packages.storage.models import UserSession

ROOT = Path(__file__).resolve().parents[2]
TZ_SECURITY: Final = ROOT / "docs" / "tz" / "08-security-auth-2fa.md"
MODULE_PATH: Final = ROOT / "packages" / "identity" / "sessions.py"

#: Уровень домена не имеет права знать ни про HTTP, ни про шаблонизатор, ни про драйвер базы:
#: куки/CSRF/CSP — `apps/web` (следующий срез `T-102`), транзакции — вызывающий слой.
FORBIDDEN_IMPORTS: Final = frozenset(
    {"fastapi", "starlette", "jinja2", "httpx", "requests", "uvicorn", "sqlalchemy"}
)

#: Формулировка §8.3 → идентификатор причины пересоздания. Ключи обязаны покрыть перечень ТЗ:
#: если заказчик допишет в скобки четвёртое действие, тест потребует завести и идентификатор.
#: Символы, которые сломали бы Set-Cookie или заголовок, попав в значение куки (список задан
#: через chr(), чтобы не ловить приключения экранирования в самом тесте).
_COOKIE_UNSAFE: Final = ("=", ";", ",", chr(34), " ", chr(92), chr(13), chr(10))

CRITICAL_ACTION_NAMES: Final[dict[str, str]] = {
    "смена пароля": "password_change",
    "подключение токена": "token_connect",
    "запуск в `production`": "production_launch",
}


def _tz_text() -> str:
    return TZ_SECURITY.read_text(encoding="utf-8")


def _table() -> Table:
    # mypy видит `__table__` на классе как FromClause: cast фиксирует, что это Table
    return cast("Table", UserSession.__table__)


def test_таймауты_сессии_совпадают_с_техзаданием() -> None:
    """§8.3: «случайный id 256 бит; idle-таймаут 30 минут, абсолютный — 12 часов»."""
    text = _tz_text()

    idle_match = re.search(r"idle-таймаут\s+(\d+)\s*минут", text)
    assert idle_match, "в §8.1/§8.3 не найден idle-таймаут — проверка теряет смысл"
    assert (
        IDLE_TIMEOUT.total_seconds() == int(idle_match.group(1)) * 60
    ), f"§8.3 требует {idle_match.group(1)} минут idle, код задаёт {IDLE_TIMEOUT}"

    abs_match = re.search(r"абсолютный\s+[—-]\s*(\d+)\s+часов", text)
    assert abs_match, "в §8.3 не найден абсолютный срок сессии"
    assert (
        ABSOLUTE_TIMEOUT.total_seconds() == int(abs_match.group(1)) * 3600
    ), f"§8.3 требует {abs_match.group(1)} часов, код задаёт {ABSOLUTE_TIMEOUT}"

    bits_match = re.search(r"случайный id (\d+) бит", text)
    assert bits_match, "в §8.3 не найдена длина значения куки в битах"
    assert (
        int(bits_match.group(1)) == SESSION_TOKEN_BITS
    ), f"§8.3 требует {bits_match.group(1)} бит, код выдаёт {SESSION_TOKEN_BITS}"


def test_шаги_входа_совпадают_с_ограничением_схемы() -> None:
    """`ck_sessions_auth_step` и порядок шагов в коде — один и тот же набор значений."""
    constraints = [
        constraint
        for constraint in _table().constraints
        if isinstance(constraint, CheckConstraint) and "auth_step" in str(constraint.sqltext)
    ]
    assert constraints, "в таблице sessions нет CHECK-ограничения на шаг входа"
    domains: set[str] = set()
    for constraint in constraints:
        domains.update(re.findall(r"auth_step\s+IN\s*\(([^)]*)\)", str(constraint.sqltext)))
    assert domains, "CHECK шага входа не перечисляет значения через IN — проверка теряет смысл"
    for domain in domains:
        allowed = {value.strip().strip("'") for value in domain.split(",")}
        assert allowed == set(
            AUTH_STEP_ORDER
        ), f"схема разрешает {sorted(allowed)}, код знает шаги {sorted(AUTH_STEP_ORDER)}"
        assert len(AUTH_STEP_ORDER) == len(
            allowed
        ), "число шагов входа в коде и в схеме различается: порядок переходов непонятен"


def test_критичные_действия_совпадают_с_перечнем_8_3() -> None:
    """§8.3: «после критичных действий (смена пароля, подключение токена, запуск в production)»."""
    match = re.search(r"после критичных действий \(([^)]*)\)", _tz_text())
    assert match, "в §8.3 не найден перечень критичных действий"
    listed = [item.strip() for item in match.group(1).split(",") if item.strip()]
    assert listed, "перечень критичных действий пуст — проверка теряет смысл"

    missing = [item for item in listed if item not in CRITICAL_ACTION_NAMES]
    assert not missing, (
        f"§8.3 перечисляет действия {missing}, а кодов пересоздания для них нет: "
        "идентификатор обязан быть заведён явно"
    )
    assert set(CRITICAL_ACTION_NAMES.values()) == set(CRITICAL_ACTIONS), (
        f"коды пересоздания {sorted(CRITICAL_ACTIONS)} не совпадают с отображением "
        f"{sorted(CRITICAL_ACTION_NAMES.values())}"
    )


def test_значение_куки_в_базе_не_хранится() -> None:
    """В `sessions` есть только `token_hash`: ни значения, ни второго материала сессии."""
    columns = {column.name for column in _table().columns}
    assert "token_hash" in columns
    forbidden = {
        name for name in columns if re.search(r"token|secret|cookie", name) and name != "token_hash"
    }
    assert (
        not forbidden
    ), f"в схеме sessions появились колонки материала сессии: {sorted(forbidden)}"

    token_column = _table().c.token_hash
    assert token_column.nullable is False, "token_hash обязан быть NOT NULL (§8.3: поиск по нему)"

    uniques = [
        constraint
        for constraint in _table().constraints
        if isinstance(constraint, UniqueConstraint)
        and [col.name for col in constraint.columns] == ["token_hash"]
    ]
    assert (
        uniques
    ), "у token_hash нет уникальности: два значения куки не должны указывать на разные сессии"


def test_коды_причин_недействительности_закрыты_и_уникальны() -> None:
    """Интерфейс (§9: `/session-expired`) и журнал (§8.7) опираются на коды: набор закрытый."""

    def descendants(cls: type[SessionInvalidError]) -> list[type[SessionInvalidError]]:
        found: list[type[SessionInvalidError]] = []
        for subclass in cls.__subclasses__():
            if issubclass(subclass, SessionInvalidError):
                found.append(subclass)
                found.extend(descendants(subclass))
        return found

    classes = descendants(SessionInvalidError)
    assert classes, "у SessionInvalidError нет подклассов — кодов причин нет"
    codes = [subclass.code for subclass in classes]
    assert set(codes) == set(SESSION_REASON_CODES), (
        f"коды причин {sorted(set(codes))} не совпадают с закрытым набором "
        f"{sorted(SESSION_REASON_CODES)}"
    )
    assert len(codes) == len(set(codes)), f"коды причин повторяются: {codes}"


def test_описание_сессии_не_содержит_материала_сессии() -> None:
    """Страница «мои устройства» (§8.3) рисуется шаблономизатором: материал сессии там не нужен."""
    names = set(SessionDescriptor.__dataclass_fields__)
    assert names.isdisjoint(
        {"token", "token_hash", "secret", "secret_hash", "cookie"}
    ), f"в описание сессии попали поля материала: {sorted(names)}"
    for required in (
        "id",
        "created_at",
        "last_seen_at",
        "expires_at",
        "auth_step",
        "ip",
        "user_agent",
    ):
        assert required in names, f"в описании нет поля {required!r}, которое требует §8.3"


def test_sessions_не_тянет_http_шаблонизатор_или_базу() -> None:
    """Домен сессий остаётся доменом: куки/CSRF/CSP — `apps/web`, транзакции — вызывающий слой."""
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        for name in names:
            top = name.split(".", 1)[0]
            if top in FORBIDDEN_IMPORTS:
                offenders.append(top)
    assert not offenders, (
        "packages/identity/sessions.py импортирует "
        f"{sorted(set(offenders))} — куки, CSRF, CSP, HTTP и соединения с базой относятся "
        "к apps/web (следующий срез T-102), а не к домену сессий"
    )


def test_константы_сроков_не_являются_настройкой() -> None:
    """Сроки §8.3 — константы домена, а не конфиг: выключить idle-таймаут конфигом нельзя.

    Проверка механическая: в модуле нет импорта конфигурации проекта и нет чтения окружения.
    """
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        else:
            continue
        for name in names:
            assert not name.startswith(
                "packages.common.config"
            ), f"срок сессии нельзя перенастраивать конфигом: найден импорт {name!r}"
    assert "os.environ" not in source
    assert "getenv" not in source


def test_значение_куки_в_формате_без_символов_куки() -> None:
    """Форма значения не должна требовать экранирования в Set-Cookie и в заголовке."""
    for _ in range(16):
        value = sessions.token_secret()
        assert re.fullmatch(
            r"[A-Za-z0-9_-]{43}", value
        ), f"неожиданная форма значения куки: {value!r}"
        dangerous = {ch for ch in _COOKIE_UNSAFE if ch in value}
        assert (
            not dangerous
        ), f"в значении куки есть символы, опасные для Set-Cookie: {sorted(dangerous)}"
