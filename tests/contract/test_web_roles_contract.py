"""Контракт ролей и допуска (`T-106`, `ADR-017`).

Проверяется соответствие между таблицей уровней допуска, деревом зависимостей реальных
маршрутов и текстом обоснования. Типовая дыра этого дизайна — та же, о которой прямо
предупреждает `ADR-008` про CSRF: **маршрут, у которого «просто нет проверки»**. Ни один
тест не замечает отсутствующую проверку — замечает только отсутствие ответа; поэтому
покрытие проверяется статически, по коду, а не по поведению.

Второй объект проверки — таблица уровней. Она одна, в
`tests/integration/test_web_role_matrix.py`: там по ней гоняется поведение (матрица
«маршрут × роль»), здесь она сверяется с кодом. Две копии таблицы разошлись бы при первой
же правке маршрута, и «забытая охрана» снова стала бы невидимой.

Третье — границы, которые этот срез не переступает: роли групп базы (`ADR-006`) остаются в
своих файлах, и текст обоснования (`ADR-017`) обязан оставаться обоснованием.
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.routing import APIRoute

from apps.web.main import create_app
from packages.common.config import Settings
from tests.integration import test_web_role_matrix as матрица

_ROOT: Final = Path(__file__).resolve().parents[2]
#: Обоснование уровней допуска и политики отказа (`ADR-017`).
_ADR_ROLES: Final = _ROOT / "docs" / "adr" / "ADR-017-service-roles-and-denial-policy.md"
#: Файл-источник таблицы уровней допуска (он же прогоняет матрицу «маршрут × роль»).
_ROLE_MATRIX: Final = _ROOT / "tests" / "integration" / "test_web_role_matrix.py"

#: HTTP-методы, для которых объявляется уровень допуска (служебный `HEAD` наследует `GET`).
_METHODS: Final = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    """Боевое приложение без тестовых щупов.

    Проверяется тот же список маршрутов, который уедет на площадку, а не сборка с
    прикрученными маршрутами: проверка покрытия допуска бессмысленна на подмене.
    """
    return create_app(settings)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _dependency_names(route: APIRoute) -> set[str]:
    """Имена вызываемых объектов всего дерева зависимостей маршрута.

    Обход идёт по объектам `Dependant`, а не по их `.call`: рекурсия по `.call` теряет и
    имена, и вложенность, и оставляет видимость только верхнего уровня. Именно вложенность
    здесь и нужна: страж роли стоит внутри цепочки (`require_full_mutation` → `require_csrf`
    → счётчик частоты), и проверка «у маршрута нет охраны» обязана смотреть всю цепочку, а не
    первый слой. `__wrapped__` разбирается ради `Annotated`-посредников, обёрнутых
    `functools.wraps`: без них имя зависимости в дереве было бы нечитаемым.
    """

    def walk(dependant: object) -> Iterator[object]:
        yield dependant
        for sub in getattr(dependant, "dependencies", []) or []:
            yield from walk(sub)

    имена: set[str] = set()
    for узел in walk(route.dependant):
        вызов = getattr(узел, "call", None)
        for имя in (
            getattr(вызов, "__name__", ""),
            getattr(getattr(вызов, "__wrapped__", None), "__name__", ""),
        ):
            if имя:
                имена.add(имя)
    return имена


def _route_entries(app: FastAPI) -> Iterator[APIRoute]:
    """Маршруты приложения: обход пакета `apps/web/routes` плюс объявленные в фабрике.

    Две половины нужны по разным причинам. `app.include_router` в этой версии FastAPI не
    расплющивает маршруты в `app.routes` — там лежат объекты включения, поэтому список
    маршрутизаторов строится обходом пакета (тот же приём, что в проверке покрытия CSRF):
    модуль с маршрутами, добавленный в пакет, обязан попасть в проверку, даже если его
    забудут поименовать здесь. Маршруты, объявленные прямо на фабрике (`/healthz`, `/readyz`,
    `/metrics`, корневая заглушка), наоборот, в `app.routes` видны — и они обязаны попадать в
    проверку, иначе уровень «каркас» никто не сверяет.
    """
    увидено: set[int] = set()
    for path in sorted((_ROOT / "apps" / "web" / "routes").glob("*.py")):
        if path.name == "__init__.py":
            continue
        module = importlib.import_module(f"apps.web.routes.{path.stem}")
        for value in vars(module).values():
            if not isinstance(value, APIRouter):
                continue
            for route in value.routes:
                if isinstance(route, APIRoute) and id(route) not in увидено:
                    увидено.add(id(route))
                    yield route
    for route in app.routes:
        if isinstance(route, APIRoute) and id(route) not in увидено:
            увидено.add(id(route))
            yield route


def _declared_routes(app: FastAPI) -> set[tuple[str, str]]:
    """Перечень маршрутов по OpenAPI-схеме — тот же способ, что и у проверки покрытия CSRF."""
    schema = app.openapi()
    return {
        (path, method.upper())
        for path, operations in schema["paths"].items()
        for method in operations
        if method.upper() in _METHODS
    }


#: Таблица уровней допуска импортируется из интеграционного
#: файла на уровне модуля и одной ссылкой: вторая копия таблицы
#: разошлась бы при первой же правке маршрута, а импорт
#: «по надобности внутри функции» лишил бы типов — а именно тип
#: держит эту проверку чистой по строкам таблицы.


def test_таблица_допуска_покрывает_каждый_маршрут_приложения(app: FastAPI) -> None:
    """Каждый маршрут приложения — строка таблицы, и наоборот.

    Обе стороны обязательны: лишняя строка опасна так же, как отсутствующая, — она
    доказывает допуск маршрута, которого больше нет, и перестаёт замечать следующее
    изменение.
    """
    заявлено = set(матрица.ROUTE_POLICY)
    реально = _declared_routes(app)
    assert заявлено == реально, (
        "таблица допуска разошлась с перечнем маршрутов: без строк "
        f"{sorted(реально - заявлено)}, лишние строки {sorted(заявлено - реально)}; "
        "маршрут без строки — это маршрут без объявленного уровня допуска"
    )
    assert заявлено, "таблица допуска пуста: проверка перестала что-либо замечать"


def test_уровень_допуска_совпадает_со_стражем_маршрута(app: FastAPI) -> None:
    """Уровень с ролью обязан показывать стража, уровень без роли — не показывать ни одного.

    Проверять «хоть какой-нибудь страж» недостаточно: маршрут раздела администратора,
    помеченный зависимостью профиля, прошёл бы зелёным и открыл бы админку оператору.
    Ожидание вычисляется по тому же справочнику «уровень → страж», что и матрица
    «маршрут × роль», поэтому расходится с кодом, а не с намерением.
    """
    стражи = матрица.ALL_GUARDS
    посмотрено: set[tuple[str, str]] = set()
    for route in _route_entries(app):
        имена = _dependency_names(route)
        встреченные = стражи & имена
        for метод in sorted(set(route.methods or ()) & _METHODS):
            ключ = (route.path, метод)
            if ключ not in матрица.ROUTE_POLICY:
                continue
            посмотрено.add(ключ)
            уровень = матрица.ROUTE_POLICY[ключ].tier
            справочник = матрица.MUTATION_GUARDS if метод != "GET" else матрица.GET_GUARDS
            ожидаемый = справочник.get(уровень)
            if ожидаемый is not None:
                assert ожидаемый in имена, (
                    f"{метод} {route.path}: уровень допуска {уровень!r} объявлен, а зависимости "
                    f"{ожидаемый!r} у маршрута нет — допуск существует только на бумаге"
                )
            else:
                assert not встреченные, (
                    f"{метод} {route.path}: страж {sorted(встреченные)} стоит при уровне "
                    f"{уровень!r} без роли: таблица и код разошлись, и кто принимал эту охрану — "
                    "неизвестно"
                )
    assert посмотрено == set(матрица.ROUTE_POLICY), (
        "часть строк таблицы не сопоставлена ни с одним маршрутом приложения: "
        f"{sorted(set(матрица.ROUTE_POLICY) - посмотрено)}"
    )


def test_каждый_объявленный_уровень_допуска_кем_то_охраняется(app: FastAPI) -> None:
    """Уровни с ролью не пустуют: у каждого уровня есть хотя бы один охраняемый маршрут.

    Проверка парная к предыдущей. Перечень стражей, которые ни у одного маршрута не
    встречаются, — это та же дыра в охране, помеченная на бумаге, только наоборот: страж
    есть, а маршрутов под ним нет, и матрица «маршрут × роль» начинает что-то утверждать
    про уровень, который никто не применяет.
    """
    уровни = {policy.tier for policy in матрица.ROUTE_POLICY.values()}
    for уровень in (матрица.TIER_ANY_ROLE, матрица.TIER_ADMIN):
        assert уровень in уровни, f"уровень {уровень!r} исчез из таблицы допуска"
        страж = матрица.GET_GUARDS[уровень]
        найдено = [
            (route.path, метод)
            for route in _route_entries(app)
            for метод in sorted(set(route.methods or ()) & _METHODS)
            if страж in _dependency_names(route)
        ]
        assert найдено, f"страж {страж!r} не стоит больше ни у одного маршрута"


def test_ответ_отказа_допуска_не_содержит_ролей_и_чисел() -> None:
    """Статическая половинка `AC-identity-01`: в теле отказа нет ни имён, ни счётчиков.

    Поведенческая проверка смотрит ответ конкретного маршрута; здесь держится само
    значение как константа — перечисление ролей или числовой код причины появились бы в
    отказе на любом маршруте сразу после правки тела, и ждать прогона матрицы не нужно.
    """
    from apps.web.security.authorization import DENIAL_BODY
    from packages.identity.authorization import ROLES

    текст = " ".join(str(значение) for значение in DENIAL_BODY.values()).lower()
    for роль in sorted(ROLES):
        assert роль not in текст, f"в теле отказа названа роль {роль!r}"
    assert not any(символ.isdigit() for символ in текст), "в теле отказа есть цифры"
    assert set(DENIAL_BODY) == {"status", "detail"}, (
        "тело отказа допуска получило новое поле: проверьте, что оно не выдаёт состояние "
        "данных — причину отказа, число объектов, требуемую роль"
    )


def test_обработчик_отказа_допуска_зарегистрирован_в_приложении(app: FastAPI) -> None:
    """Без обработчика исключения отказ роли превратился бы в `500`.

    Зависимости-стражи поднимают исключение до тела обработчика, поэтому единственная
    точка превращения его в ответ — обработчик исключений фабрики. Приём тот же, что у
    проверки middleware с заголовками: связность проверяется статически, потому что
    поведение показало бы её только на приёмке.
    """
    исходник = _read(_ROOT / "apps" / "web" / "main.py")
    assert "@app.exception_handler(AccessDeniedError)" in исходник
    assert "handle_access_denied(request, exc)" in исходник
    обработчики = getattr(app, "exception_handlers", {})
    assert any(
        getattr(ключ, "__name__", "") == "AccessDeniedError" for ключ in обработчики
    ), "обработчик AccessDeniedError не зарегистрирован: отказ роли даст 500"


def _строки_кода(путь: Path) -> list[str]:
    """Строковые константы и имена файла — без docstring.

    Разделение нужно, потому что запрет касается того, чем правило пользуется, а не того, что
    о нём сказано: `apps/web/security/authorization.py` обязан иметь возможность сослаться на
    `ADR-006` и `roles.sql`, чтобы читатель знал про границу.
    """
    дерево = ast.parse(_read(путь))
    пропущенные: set[int] = set()
    блок: list[ast.stmt] = list(дерево.body)
    if блок and isinstance(блок[0], ast.Expr):
        пропущенные.add(id(блок[0].value))
    # `docstring` — первое выражение модуля, функции, метода или класса; он пропускается,
    # потому что запрет касается кода, а не текста об этом коде.
    for объявление in блок:
        if (
            isinstance(объявление, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            and объявление.body
            and isinstance(объявление.body[0], ast.Expr)
        ):
            пропущенные.add(id(объявление.body[0].value))
    значения: list[str] = []
    for потомок in ast.walk(дерево):
        if isinstance(потомок, ast.Constant):
            if id(потомок) in пропущенные or not isinstance(потомок.value, str):
                continue
            значения.append(потомок.value)
        elif isinstance(потомок, ast.Name):
            значения.append(потомок.id)
        elif isinstance(потомок, ast.Attribute):
            значения.append(потомок.attr)
    return значения


def test_файлы_допуска_не_содержат_имён_ролей_групп_базы() -> None:
    """Роли приложения и привилегии групп базы — разные множества (`ADR-006`, п. 10 `ADR-017`).

    Совпадение слова «роль» наводит на мысль, что право приложения можно выдать привилегией
    базы; это не так: `web`, `engine`, `jobs` и `migrate` ходят ролью `tbot_app` под общим
    паролем, и смена этой модели — отдельное решение заказчика, а не следствие этого среза.
    Проверка держит границу файлов: если имена из `deploy/postgres` заберутся в код допуска,
    это станет видно по имени, а не по внезапному `GRANT`.
    """
    запрещены = ("roles.sql", "tbot_app", "tbot_owner", "tbot_migrate", "GRANT")
    for путь in (
        _ROOT / "packages" / "identity" / "authorization.py",
        _ROOT / "apps" / "web" / "security" / "authorization.py",
    ):
        найдено = [
            значение
            for значение in _строки_кода(путь)
            if any(слово in значение for слово in запрещены)
        ]
        assert not найдено, (
            f"{путь.name}: в коде допуска встречаются имена ролей групп базы {найдено} — роли "
            "приложения и привилегии базы путаются в одном месте"
        )


def test_adr_017_держит_обоснование_уровней_допуска() -> None:
    """Решения по ролям оформлены и не меняются молча.

    Тот же приём, что у проверок `ADR-007` и `ADR-008`: маркеры решения ищутся в тексте
    документа, потому что уровень допуска раздела и правило «403 без утечки» — решения
    заказчика по тексту ТЗ, а не детали оформления.
    """
    assert _ADR_ROLES.exists(), "обоснование уровней допуска обязано быть оформлено ADR"
    assert _ROLE_MATRIX.exists(), "источник таблицы уровней допуска потерян"
    adr = _read(_ADR_ROLES)
    for маркер in (
        "viewer ⊂ operator ⊂ admin",
        "любая роль",
        "403",
        "403/404",
        "`T-105`",
        "`ADR-006`",
        "state",
        "T-109",
        "отказ по умолчанию",
    ):
        assert маркер in adr, f"`ADR-017` обязан содержать маркер {маркер!r}"
