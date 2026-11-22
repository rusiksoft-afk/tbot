"""Юнит-матрица ролей уровня сервиса (`REQ-identity-01`, TZ §1.1; `T-106`, `ADR-017`).

База не нужна: набор значений, лестница наследования и форма отказа — это арифметика домена.
Что здесь дорого:

1. **Набор значений сверяется с исходниками схемы**, а не с ещё одним списком в тесте. Роль
   определена в трёх местах — `packages/identity/authorization.py`, `CheckConstraint` модели и
   CHECK ревизии `0002` (плюс `ck_invitations_role`: приглашение называет роль, которую выдадут).
   Расхождение означает либо «код пускает роль, которую база отвергает», либо «база принимает
   роль, о которой сервис не знает» — и то, и другое становится видно только на `INSERT` на
   площадке, то есть в самый дорогой момент.
2. **Отказ от нормализации.** `Admin`, `ADMIN`, `admin ` — база отвергает их CHECK-ограничением,
   поэтому домен обязан отвергать их тоже, иначе права имеют два источника правды.
3. **Значение вне набора не получает прав и не получает отдельного ответа** («отказ по
   умолчанию», `ADR-017` п. 4): ни исключения с другим кодом, ни ранга по умолчанию.
4. **Отказ обязана порождать одна причина** (закрытый набор), иначе будущее различие причин
   просочится в ответ.

Живая половина держит `ck_users_role` как ограничение площадки
(`tests/integration/test_identity_schema_db.py`) и индекс `ix_users_role`; поведение маршрутов под
ролью — `tests/integration/test_web_role_matrix.py`.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Final
from uuid import UUID, uuid4

import pytest

from packages.identity.authorization import (
    ADMIN_TIER,
    CONSOLE_TIER,
    DENIAL_NO_ACCOUNT,
    DENIAL_REASONS,
    DENIAL_ROLE,
    DENIAL_ROLE_OUTSIDE_DOMAIN,
    ROLE_ADMIN,
    ROLE_LADDER,
    ROLE_OPERATOR,
    ROLE_RANK,
    ROLE_VIEWER,
    ROLES,
    AccessDeniedError,
    RoleOutsideDomainError,
    ensure_account_role,
    ensure_role,
    ensure_role_at_least,
    owner_matches,
    role_allows,
    role_rank,
)
from packages.identity.users import new_user
from packages.storage.models import User

_ROOT: Final = Path(__file__).resolve().parents[2]
_MIGRATION: Final = _ROOT / "migrations" / "versions" / "0002_identity_access.py"
_MODEL: Final = _ROOT / "packages" / "storage" / "models.py"

#: Ожидание приёмки: ровно эти три значения (§1.1). Единственный случай в файле, где набор
#: назван руками, — дальше он сверяется с исходниками схемы, поэтому опечатка здесь падает красным
#: в трёх проверках сразу, а не пропускается.
EXPECTED_ROLES: Final[frozenset[str]] = frozenset({"admin", "operator", "viewer"})

PASSWORD: Final = "sTr0ng-pass-2026"


def _значения(check_text: str) -> list[str]:
    """Значения из `role IN ('a', 'b', 'c')` — порядок исходника сохранён."""
    found = re.findall(r"'([^']*)'", check_text)
    assert found, f"в тексте ограничения нет literal-значений: {check_text!r}"
    return found


def _текст_ограничения_из_модели() -> str:
    """Текст CHECK по роли из `packages/storage/models.py` через AST, а не регуляркой по файлу.

    Строка ограничения лежит внутри `__table_args__` в виде positional-аргумента
    `CheckConstraint(..., name="role")`; поиск по тексту файла спотыкается о перенос строки и о
    том, что в модели имя ограничения — `role`, а не `ck_users_role` (префикс добавляет
    ` naming_convention`, иначе получилось бы `ck_users_ck_users_role`).
    """
    дерево = ast.parse(_MODEL.read_text(encoding="utf-8"))
    for узел in ast.walk(дерево):
        if not isinstance(узел, ast.Call) or not isinstance(узел.func, ast.Name):
            continue
        if узел.func.id != "CheckConstraint" or not узел.args:
            continue
        первый = узел.args[0]
        текст = первый.value if isinstance(первый, ast.Constant) else ""
        if isinstance(текст, str) and текст.startswith("role IN"):
            return текст
    raise AssertionError("в модели `User` не найдено CHECK-ограничение по роли")


def _константа_из_ревизии(имя: str) -> str:
    """Значение модульной константы ревизии `0002` (там CHECK по роли объявлен один раз и
    переиспользуется для `users` и `invitations`)."""
    дерево = ast.parse(_MIGRATION.read_text(encoding="utf-8"))
    for узел in дерево.body:
        if not isinstance(узел, ast.Assign):
            continue
        for цель in узел.targets:
            if isinstance(цель, ast.Name) and цель.id == имя:
                значение = узел.value
                if isinstance(значение, ast.Constant) and isinstance(значение.value, str):
                    return значение.value
    raise AssertionError(f"в ревизии `0002` нет строковой константы {имя!r}")


# ─── закрытый набор значений (§1.1: «ровно три роли») ────────────────────────────────────────


def test_ролей_ровно_три_и_это_значения_из_схемы() -> None:
    """Код, модель и ревизия называют одни и те же три значения (`ADR-017` п. 1)."""
    assert ROLES == EXPECTED_ROLES, f"набор ролей расходится с ожиданием: {sorted(ROLES)}"
    assert len(ROLE_LADDER) == 3, "лестница ролей обязана содержать ровно три уровня"
    assert set(ROLE_LADDER) == ROLES, "лестница и набор ролей разошлись"

    из_модели = _значения(_текст_ограничения_из_модели())
    из_ревизии = _значения(_константа_из_ревизии("_ROLE_CHECK"))
    assert (
        set(из_модели) == ROLES
    ), f"CHECK модели ({sorted(из_модели)}) ≠ набор ролей сервиса ({sorted(ROLES)})"
    assert (
        set(из_ревизии) == ROLES
    ), f"CHECK ревизии `0002` ({sorted(из_ревизии)}) ≠ набор ролей сервиса ({sorted(ROLES)})"
    assert из_модели == из_ревизии, (
        "модель и ревизия перечисляют роли в разном порядке: порядок перечисления в CHECK не "
        "влияет на права, но разнобой — признак того, что правки вносили в одно место"
    )


def test_лестница_ролей_повторяет_наследование_из_тз() -> None:
    """`viewer ⊂ operator ⊂ admin` — порядок `ROLE_LADDER` и `ROLE_RANK` считаются по нему."""
    assert ROLE_LADDER == (ROLE_VIEWER, ROLE_OPERATOR, ROLE_ADMIN)
    ожидаемый_ранг: dict[str, int] = {role: rank for rank, role in enumerate(ROLE_LADDER)}
    assert (
        ожидаемый_ранг == ROLE_RANK
    ), f"`ROLE_RANK` не считается индексом по лестнице: {ROLE_RANK}"
    assert role_rank(ROLE_VIEWER) < role_rank(ROLE_OPERATOR) < role_rank(ROLE_ADMIN)
    # Порядок лестницы — не косметика: перестановка местами меняет права, поэтому она обязана
    # оставаться ровно такой, как включение множеств из `REQ-identity-01`.
    assert ROLE_RANK[ROLE_ADMIN] == len(ROLE_LADDER) - 1


def test_требования_разделов_входят_в_набор_ролей() -> None:
    """Уровень раздела — имя роли из набора, а не отдельное слово (`ADR-017` п. 2)."""
    assert CONSOLE_TIER in ROLES
    assert ADMIN_TIER in ROLES
    assert ROLE_LADDER[0] == CONSOLE_TIER, (
        "уровень раздела профиля обязан быть младшей ролью: «любая роль» означает «не ниже "
        "`viewer`», и старшее здесь имя сделало бы `viewer` бесправным"
    )
    assert (
        ROLE_LADDER[-1] == ADMIN_TIER
    ), "раздел администрирования обязан требовать старшую ступень лестницы"


# ─── наследование (`REQ-identity-01`) ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("actual", sorted(ROLES))
@pytest.mark.parametrize("required", sorted(ROLES))
def test_наследование_проверяется_рангом_a_не_списком_ролей(actual: str, required: str) -> None:
    """Матрица «фактическая роль × требуемый уровень»: старшая роль проходит всю лестницу вниз.

    Это и есть включение множеств возможностей: `admin` годится для уровня `viewer`, `viewer` не
    годится для уровня `admin`. Сравнение — единственная форма, которая не требует перечня
    возможностей, которого у проекта ещё нет.
    """
    ожидалось = ROLE_RANK[actual] >= ROLE_RANK[required]
    assert (
        role_allows(actual, required) is ожидалось
    ), f"{actual} для уровня {required}: ожидалось {ожидалось}"
    if ожидалось:
        ensure_role_at_least(actual, required=required)
    else:
        with pytest.raises(AccessDeniedError) as ошибка:
            ensure_role_at_least(actual, required=required)
        assert ошибка.value.reason == DENIAL_ROLE


def test_администратор_проходит_оба_уровня_разделов_плюс_свой_уровень() -> None:
    """Проверка «сверху вниз»: `admin` проходит и профиль, и админку; `viewer` — только профиль."""
    assert role_allows(ROLE_ADMIN, ADMIN_TIER)
    assert role_allows(ROLE_ADMIN, CONSOLE_TIER)
    assert role_allows(ROLE_OPERATOR, CONSOLE_TIER)
    assert role_allows(ROLE_VIEWER, CONSOLE_TIER)
    assert not role_allows(ROLE_OPERATOR, ADMIN_TIER)
    assert not role_allows(ROLE_VIEWER, ADMIN_TIER)


# ─── «отказ по умолчанию»: значение вне закрытого набора ──────────────────────────────────────


@pytest.mark.parametrize(
    "значение",
    [
        "",
        " ",
        "admin ",
        "Admin",
        "ADMIN",
        "root",
        "superuser",
        "tbot_app",
        "viewеr",  # кириллическая «е»: внешнее совпадение права не даёт
        "viewer\n",  # хвост переноса строки не отбрасывается
    ],
)
def test_роль_вне_набора_не_получает_ни_прав_ни_ранга_по_умолчанию(значение: str) -> None:
    """Ни ранга по умолчанию, ни молчаливого спуска к младшей роли (`ADR-017` п. 4).

    Отсутствующее и постороннее значение не получает уровня: `ensure_role` и `role_rank` падают,
    `role_allows` отвечает `False`. Разница между ними принципиальна: предикат обязан отказать, а
    о порче значения обязано говориться прямо.

    `tbot_app` в перечне — не причуда: это имя роли группы базы (`ADR-006`, `ADR-017` п. 10). Если
    оно когда-нибудь окажется в колонке `role`, домен обязан не принять его, а не решить, что это
    наблюдатель.
    """
    with pytest.raises(RoleOutsideDomainError):
        ensure_role(значение)
    with pytest.raises(RoleOutsideDomainError):
        role_rank(значение)
    assert role_allows(значение, CONSOLE_TIER) is False
    assert role_allows(значение, ADMIN_TIER) is False
    assert role_allows(ROLE_ADMIN, значение) is False, (
        "уровень вне набора не должен пропускать администратора: сравнение обязано быть "
        "закрывающим с обеих сторон"
    )
    with pytest.raises(AccessDeniedError) as ошибка:
        ensure_role_at_least(значение, required=CONSOLE_TIER)
    assert ошибка.value.reason == DENIAL_ROLE_OUTSIDE_DOMAIN
    # Требуемый уровень — константа кода, а не данные посетителя: его порча —
    # программная ошибка, и она обязана остаться различимой. Неотличимость нужна
    # для отказа человека, но не для бага маршрута (`ADR-017` п. 4).
    with pytest.raises(RoleOutsideDomainError):
        ensure_role_at_least(ROLE_ADMIN, required=значение)


def test_домен_роли_проверяется_при_создании_учётной_записи() -> None:
    """`new_user` не допускает роль, которую база отвергла бы на `INSERT` (`ADR-017` п. 1)."""
    for роль in sorted(ROLES):
        учётка = new_user(login=f"р6.{роль}", password=PASSWORD, role=роль, state="active")
        assert учётка.role == роль
    with pytest.raises(RoleOutsideDomainError):
        new_user(login="р6.лишняя", password=PASSWORD, role="superuser", state="active")


# ─── единый отказ и закрытый набор причин ─────────────────────────────────────────────────────


def test_причины_отказа_закрыты_и_их_три() -> None:
    """Набор причин конечен: расширять его можно только вместе с проверкой одинаковости ответа."""
    закрыто: frozenset[str] = frozenset(
        {DENIAL_ROLE, DENIAL_ROLE_OUTSIDE_DOMAIN, DENIAL_NO_ACCOUNT}
    )
    assert закрыто == DENIAL_REASONS, f"набор причин отказа изменён: {sorted(DENIAL_REASONS)}"
    for причина in sorted(DENIAL_REASONS):
        assert AccessDeniedError(причина).reason == причина
    with pytest.raises(ValueError, match="вне закрытого набора"):
        AccessDeniedError("роль_не_та")


def test_три_разных_обстоятельства_дают_один_класс_отказа() -> None:
    """Ответ не должен сообщать, что именно не так: различие живёт только в причине.

    Разбор (`ADR-017` п. 4) строится по журналу процесса, где причина есть; наружу выходит один и
    тот же ответ. Поэтому здесь проверяются и класс, и причина, и то, что все три обстоятельства
    сводятся к одному классу.
    """
    случаи: list[tuple[str, User | None]] = [
        (DENIAL_NO_ACCOUNT, None),
        (DENIAL_ROLE_OUTSIDE_DOMAIN, _учётка("хакер")),
        (DENIAL_ROLE, _учётка(ROLE_VIEWER)),
    ]
    for ожидаемая, учётка in случаи:
        with pytest.raises(AccessDeniedError) as ошибка:
            ensure_account_role(учётка, required=ADMIN_TIER)
        assert ошибка.value.reason == ожидаемая
        assert ожидаемая in DENIAL_REASONS
        # В тексте исключения нет ни требуемой роли, ни имени учётной записи: сообщение читают
        # разработчики и журнал, а не посетитель.
        assert ADMIN_TIER not in str(ошибка.value)
        assert "хакер" not in str(ошибка.value)


@pytest.mark.parametrize("роль", sorted(ROLES))
def test_любая_из_трёх_ролей_проходит_уровень_раздела_профиля(роль: str) -> None:
    """§9.3 п. 4–5: «Профиль и безопасность (любая роль)» — отказ наступает только за пределами."""
    assert ensure_account_role(_учётка(роль), required=CONSOLE_TIER) == роль


def test_учётной_записи_нет_это_не_пустая_роль() -> None:
    """`None` — состояние «строчки нет», и проверяется оно раньше роли.

    Порядок принципиален: если бы отсутствующая учётная запись получала отказ по роли, по различию
    причин можно было бы отличить «сеанс живой, а учётку удалили» от «роль не та» — а это ровно та
    утечка, которую запрещают §8.8 и `AC-identity-01`.
    """
    with pytest.raises(AccessDeniedError) as ошибка:
        ensure_account_role(None, required=CONSOLE_TIER)
    assert ошибка.value.reason == DENIAL_NO_ACCOUNT


def test_возвращаемое_значение_роли_нужно_обработчику_а_не_охране() -> None:
    """`ensure_account_role` возвращает роль: её печатают человеку (§9.3 п. 4), решения она не меняет."""
    учётка = _учётка(ROLE_OPERATOR)
    assert ensure_account_role(учётка, required=CONSOLE_TIER) == ROLE_OPERATOR


# ─── предикат владения (§8.8: «доступ `operator` к чужим данным → 403/404 без утечки») ────────


def test_владение_совпадает_и_не_совпадает_без_исключений() -> None:
    владелец, чужой = uuid4(), uuid4()
    assert owner_matches(владелец, владелец) is True
    assert owner_matches(владелец, чужой) is False


@pytest.mark.parametrize("левое", [None, uuid4()])
@pytest.mark.parametrize("правое", [None, uuid4()])
def test_пустое_значение_означает_отказ_a_не_пропуск_сверки(
    левое: UUID | None, правое: UUID | None
) -> None:
    """`None` с любой стороны — отказ, а не пропуск сверки (`ADR-017` п. 5).

    Колонка `user_id` в схеме `NOT NULL`, поэтому пустое значение в этом предикате — испорченные
    данные или неполная выборка. Смолчать и пропустить означало бы открыть чужой объект ровно в
    том случае, когда выборка сломалась.
    """
    assert owner_matches(левое, правое) is (левое is not None and левое == правое)


# ─── помощники ────────────────────────────────────────────────────────────────────────────────


def _учётка(роль: str) -> User:
    """Учётная запись с указанным значением роли, включая значения вне набора.

    Значение вне набора невозможно получить через `new_user` (он проверяет роль), поэтому здесь
    `User(...)` напрямую: проверка обязана ловить состояние «строка есть, роль посторонняя»,
    которое возникает при правке таблицы руками или при ревизии с новой ролью раньше сервиса.
    """
    return User(
        login=f"р6.{роль or 'пусто'}",
        role=роль,
        state="active",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$" + "a" * 43,
        failed_attempts=0,
    )
