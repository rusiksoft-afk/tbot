"""Контракт слоя входа: покрытие мутаций CSRF, атрибуты куки, шаблоны и границы среза (`T-102`).

Офлайновая проверка без базы и без HTTP-запросов: она держит то, что иначе расходится молча.

1. **Покрытие мутационных маршрутов.** ADR-008 прямо называет типовую дыру этого дизайна — эндпоинт,
   который «принимает `X-CSRF-Token`, но не проверяет его». Проверка по таблице маршрутов
   боевого приложения обязывает каждый маршрут с мутационным методом либо зависеть от
   `require_csrf`, либо быть поименованным исключением с обоснованием. Исключений ровно одно —
   `/login` (сессии ещё нет, токен выводить не из чего; `ADR-009`), и за него отвечает проверка
   источника.
2. **Тестовые маршруты не должны утечь в боевое приложение.** Щуп `probe_router()` появляется только
   в сборке тестов; маршрут без CSRF-зависимости в производственном списке — ровно та дыра, которую
   п. 1 и ищет.
3. **Атрибуты куки и метки токена сверяются с текстом ТЗ и ADR** — так решение заказчика из §4 не
   «уплывает» вместе с кодом: маркеры ищутся в источнике документа.
4. **Шаблоны** обязаны рендериться с `autoescape` и `StrictUndefined`, а в самих шаблонах не должно
   быть `|safe` и печати материала сессии (§8.8 «XSS в полях не исполняется», §8.4 «материал доступа
   не попадает в логи»).
5. **Разбор формы без новой зависимости времени исполнения.** `ADR-009` фиксирует, что
   `python-multipart` не добавляется (TZ §15 — про новые зависимости нужна остановка заказчика), и
   держит это проверкой: если зависимость всё-таки появится, проверка потребует пересматривать
   решение, а не тихо переписать слой разбора.

Живое поведение (кука, `403`, объясняющие страницы) — в `tests/integration/test_web_session_cookie.py`,
`tests/integration/test_web_csrf.py` и `tests/integration/test_web_identity_db.py`.
"""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import re
from collections.abc import Iterator
from typing import Final

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.routing import APIRoute
from jinja2 import StrictUndefined
from pydantic import SecretStr

from apps.web.main import create_app
from apps.web.routes.sessions import EXPLANATIONS
from apps.web.security.csrf import CSRF_FORM_FIELD, CSRF_HEADER, CSRF_LABEL, CSRF_META_NAME
from apps.web.security.headers import HSTS_POLICY, SECURITY_HEADERS
from apps.web.security.sessions import (
    COOKIE_HTTP_ONLY,
    COOKIE_PATH,
    COOKIE_SAMESITE,
    COOKIE_SECURE,
    LOCKED_PATH,
    SESSION_COOKIE_NAME,
    SESSION_EXPIRED_PATH,
    display_reason_codes,
)
from apps.web.store import USER_AGENT_MAX_LEN
from packages.common.config import Settings
from packages.identity.sessions import ABSOLUTE_TIMEOUT, IDLE_TIMEOUT

_ROOT: Final = pathlib.Path(__file__).resolve().parents[2]
_TZ_SECURITY: Final = _ROOT / "docs" / "tz" / "08-security-auth-2fa.md"
_ADR_CSRF: Final = _ROOT / "docs" / "adr" / "ADR-008-csrf-token-derived-from-session.md"
_ADR_LIMITS: Final = _ROOT / "docs" / "adr" / "ADR-007-rate-limit-counter-table.md"
_ADR_FORMS: Final = _ROOT / "docs" / "adr" / "ADR-009-form-parsing-without-multipart.md"
_TEMPLATES: Final = _ROOT / "apps" / "web" / "templates"
_MUTATION_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Мутационные маршруты без зависимости от `require_csrf`. Обоснование у каждого — своё, и оно
#: обязано быть в ADR: «появился новый POST без токена» не может быть решением по умолчанию.
#: `/login` — сессии ещё нет, вывод токена не определён; его держит проверка источника (`ADR-009`).
_MUTATION_EXEMPT: Final = frozenset({"/login"})


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return create_app(settings)


def _router_routes() -> Iterator[APIRoute]:
    """Маршруты всех маршрутизаторов пакета `apps.web.routes`.

    Приложение собирается из этих маршрутизаторов, а список строится обходом пакета: маршрут,
    добавленный в пакет, обязан попасть в проверку, даже если его забудут поименовать здесь. Иначе
    «забытый POST без токена» (типовая дыра, о которой предупреждает ADR-008) остаётся невидимым.
    """
    package = _ROOT / "apps" / "web" / "routes"
    for path in sorted(package.glob("*.py")):
        if path.name == "__init__.py":
            continue
        module = importlib.import_module(f"apps.web.routes.{path.stem}")
        for value in vars(module).values():
            if isinstance(value, APIRouter):
                yield from (route for route in value.routes if isinstance(route, APIRoute))


def _app_paths(app: FastAPI) -> dict[str, set[str]]:
    """Что приложение реально отдаёт наружу (схема OpenAPI строится по тем же маршрутам).

    `openapi_url=None` отключает документацию для посетителей, но не схему: сборка схемы —
    единственный публичный способ спросить у приложения перечень его маршрутов, не залезая во
    внутренности `_IncludedRouter` (в Starlette 0.48 включённые маршрутизаторы не раскладываются в
    `app.routes`).
    """
    schema = app.openapi()
    return {path: set(item.keys()) for path, item in schema.get("paths", {}).items()}


def _dependency_names(route: APIRoute) -> set[str]:
    """Имена всех вызываемых зависимостей маршрута, включая вложенные."""

    def walk(dependant: object) -> Iterator[str]:
        call = getattr(dependant, "call", None)
        if call is not None and callable(call):
            yield getattr(call, "__name__", "")
        for child in getattr(dependant, "dependencies", []) or []:
            yield from walk(child)

    return {name for name in walk(route.dependant) if name}


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


# ─── покрытие мутаций CSRF (ADR-008) ───────────────────────────────────────────────────────────


def test_каждый_мутационный_маршрут_защищён_или_поименован() -> None:
    mutations = [
        route for route in _router_routes() if _MUTATION_METHODS & set(route.methods or ())
    ]
    assert mutations, "в `apps/web` нет ни одной мутации — проверка стала бы пустой"
    unprotected = [
        route.path for route in mutations if "require_csrf" not in _dependency_names(route)
    ]
    assert not set(unprotected) - _MUTATION_EXEMPT, (
        f"мутационные маршруты без CSRF-зависимости: {sorted(set(unprotected) - _MUTATION_EXEMPT)}; "
        "ADR-008: каждый POST/PUT/PATCH/DELETE обязан проверять токен"
    )
    assert set(unprotected) == _MUTATION_EXEMPT, (
        "список исключений устарел: исчерпание токеном больше не нужно — решение меняется "
        "новым ADR, а не молча"
    )


def test_исключение_из_проверки_токена_держит_проверку_источника() -> None:
    """/login лишён токена сессии, но обязан проверять источник (§8.3 «проверка origin»)."""
    source = _read(_ROOT / "apps" / "web" / "routes" / "login.py")
    assert "ensure_same_origin" in source, (
        "без проверки источника исключение из CSRF-требования означает «вход без защиты от "
        "подделки запроса вовсе»"
    )
    assert _ADR_FORMS.exists(), "обоснование исключения — отдельное решение (ADR-009)"


def test_приложение_не_добавляет_своих_мутаций_мимо_маршрутизаторов(app: FastAPI) -> None:
    """Маршрут, объявленный прямо в `create_app`, обязан пройти ту же проверку.

    Проверка сверяет перечень приложения с перечнем маршрутизаторов пакета: иначе мутация,
    объявленная внутри фабрики приложения, остаётся вне покрытия, а ADR-008 требует покрытия
    всех мутаций.
    """
    router_paths = {
        (route.path, method) for route in _router_routes() for method in set(route.methods or ())
    }
    app_mutations = {
        (path, method)
        for path, methods in _app_paths(app).items()
        for method in methods
        if method in _MUTATION_METHODS
    }
    assert (
        app_mutations <= router_paths
    ), f"мутации вне маршрутизаторов пакета: {sorted(app_mutations - router_paths)}"


def test_боевое_приложение_не_содержит_тестовых_маршрутов(app: FastAPI) -> None:
    """Щуп полной сессии живёт только в сборке тестов: в производственном перечне он — дыра."""
    assert not [path for path in _app_paths(app) if path.startswith("/probe")]


# ─── метки решений и константы кода ───────────────────────────────────────────────────────────


def test_атрибуты_куки_совпадают_с_8_3() -> None:
    tz = _read(_TZ_SECURITY)
    assert "HttpOnly" in tz, "§8.3 обязан требовать HttpOnly"
    assert "SameSite=Lax" in tz, "§8.3 обязан требовать SameSite=Lax"
    assert f"{SESSION_COOKIE_NAME}" in _read(_ROOT / "apps" / "web" / "security" / "sessions.py")
    assert COOKIE_SECURE is True, "§8.3: Secure"
    assert COOKIE_HTTP_ONLY is True, "§8.3: HttpOnly"
    assert COOKIE_SAMESITE == "lax", "§8.3: SameSite=Lax"
    assert COOKIE_PATH == "/", "§8.3: путь /"


def test_метки_токена_совпадают_с_adr_008() -> None:
    adr = _read(_ADR_CSRF)
    assert CSRF_LABEL.decode() in adr, "метка вывода токена закреплена решением"
    assert CSRF_FORM_FIELD in adr
    assert CSRF_HEADER in adr
    assert "compare_digest" in adr
    assert "не хранится" in adr or "не хранят" in adr, "ADR-008: токен выводится, а не хранится"


def test_сроки_сессии_из_tz_не_переопределены_в_вебе() -> None:
    """Веб-слой не имеет своих сроков: idle 30 минут и абсолютные 12 часов — из §8.3."""
    assert IDLE_TIMEOUT.total_seconds() == 1800
    assert ABSOLUTE_TIMEOUT.total_seconds() == 43200


def test_набор_объяснений_совпадает_с_закрытым_набором_причин() -> None:
    assert set(EXPLANATIONS) == set(display_reason_codes())


def test_граница_размера_формы_в_коде() -> None:
    """`user_agent` ограничивается приложением: колонка `TEXT` без CHECK, значение виден пользователю."""
    assert USER_AGENT_MAX_LEN == 256


# ─── шаблоны: автоэкранирование и запрет печати материала сессии ───────────────────────────────


def test_шаблоны_рендеряруются_с_autoescape_и_strict_undefined(app: FastAPI) -> None:
    templates = app.state.templates
    assert templates.env.autoescape is True, "§8.8: XSS в полях не должен исполняться"
    assert templates.env.undefined is StrictUndefined, "опечатка в имени переменной не должна молча"
    assert list(templates.env.list_templates()), "каталог шаблонов пуст"


def test_в_шаблонах_нет_отключения_экранирования_и_материала_сессии() -> None:
    names = [path.name for path in _TEMPLATES.glob("*.html")]
    assert names, "каталог шаблонов пуст"
    for name in names:
        text = _read(_TEMPLATES / name)
        assert "|safe" not in text, f"{name}: `|safe` отключает экранирование (§8.8)"
        assert "autoescape" not in text, f"{name}: локальное решение про экранирование (§8.8)"
        for marker in ("request.cookies", "token_hash", "csrf_secret"):
            assert marker not in text, f"{name}: {marker} — материал доступа на странице (§8.4)"


def test_каждый_шаблон_наследуется_от_базы_и_несёт_meta_токена() -> None:
    base = _read(_TEMPLATES / "base.html")
    assert f'name="{CSRF_META_NAME}"' in base, '§8.3: HTMX берёт токен из <meta name="csrf-token">'
    assert (
        "{{ csrf_token }}" in base
    ), "значение обязано подставляться из контекста, а не печататься"
    for path in _TEMPLATES.glob("*.html"):
        if path.name == "base.html":
            continue
        text = _read(path)
        assert "{% extends" in text, f"{path.name}: разметка без наследования от базы"
        assert "{% block" in text, f"{path.name}: страница без блоков базы"


# ─── разбор формы без новой зависимости (ADR-009, TZ §15) ──────────────────────────────────────


def test_зависимость_разбора_формы_не_добавлена() -> None:
    """`multipart` нет ни в зависимостях, ни в окружении: TZ §15 требует остановки заказчика на
    новую зависимость времени исполнения, а `ADR-009` фиксирует разбор urlencoded своим кодом.

    Проверка двусторонняя: отсутствие пакета в окружении означает, что `request.form()` в этом
    слое физически не заработает (ошибка возникла бы в рантайме на первом же запросе), а отсутствие
    в `pyproject.toml` — что решение не изменено молча. Отдельно держится запрет на `request.form()`:
    именно он «самочувствует себя» без пакета до первого обращения к форме."""
    assert importlib.util.find_spec("multipart") is None, (
        "пакет появился в окружении: решение `ADR-009` пересматривается заказчиком (TZ §15), "
        "а не молча"
    )
    pyproject = _read(_ROOT / "pyproject.toml")
    assert "python-multipart" not in pyproject, "зависимость добавлена в `pyproject.toml`"
    for name in ("login.py", "sessions.py"):
        source = _read(_ROOT / "apps" / "web" / "routes" / name)
        assert ".form()" not in source, (
            f"{name}: вызов `request.form()` без пакета — рантайм-ошибка" ""
        )


def test_adr_009_держит_обоснование_исключений() -> None:
    adr = _read(_ADR_FORMS)
    for marker in (
        "python-multipart",
        "x-www-form-urlencoded",
        "/login",
        "Sec-Fetch-Site",
        "413",
        "T-109",
    ):
        assert marker in adr, f"`ADR-009` обязан содержать маркер {marker!r}"


def test_adr_007_и_adr_008_не_переписаны_под_срез() -> None:
    """Решения заказчика остаются в силе: срез `R3a`/`R3b` их не отменяет, а ссылается на них."""
    limits, csrf = _read(_ADR_LIMITS), _read(_ADR_CSRF)
    assert "rate_buckets" in limits
    assert "X-Forwarded-For" in limits
    assert "15" in limits
    assert "Retry-After" in limits
    assert "HMAC" in csrf
    assert "csrf" in csrf.lower()


def test_адрес_базы_в_форме_psycopg(settings: Settings) -> None:
    """Веб-слой подключается через `packages/common/db.py` (HANDOFF §2: DSN только `+psycopg`).

    Проверяется код без модульного докстринга: в нём прямая форма `postgresql://…` названа
    намеренно — как ошибка, которую нельзя повторять (замер 2026-11-20 на площадке).
    """
    source = _read(_ROOT / "apps" / "web" / "store.py")
    module = ast.parse(source)
    lines = source.splitlines()
    docstring = module.body[0]
    assert isinstance(docstring, ast.Expr)
    assert isinstance(docstring.value, ast.Constant)
    code = chr(10).join(lines[docstring.end_lineno :])
    assert "sqlalchemy_url" in code
    assert "sqlalchemy_url" in source
    assert "postgresql+psycopg" in source
    assert "create_engine(" in code
    assert "postgresql://" not in code
    assert settings.db_url is None or isinstance(settings.db_url, SecretStr)


# ─── заголовки безопасности: три артефакта обязаны совпадать (§8.3, срез `R3c`) ────────────────

_CADDYFILE: Final = _ROOT / "deploy" / "caddy" / "Caddyfile"


def _caddy_header_values() -> dict[str, str]:
    """Значения заголовков из блока `header { … }` файла Caddy.

    Разбор ручной и намеренно строгий: без него приложение и периметр живут каждая со своей
    политикой, а браузер при двух `Content-Security-Policy` берёт пересечение — то есть эффект,
    который никто не проектировал (§8.3).
    """
    lines = _read(_CADDYFILE).splitlines()
    values: dict[str, str] = {}
    inside = False
    for raw in lines:
        line = raw.strip()
        if line.startswith("header {"):
            inside = True
            continue
        if not inside:
            continue
        if line == "}":
            break
        match = re.match(r'^(?P<name>[-A-Za-z]+)\s+"(?P<value>[^"]*)"', line)
        if match:
            values[match.group("name")] = match.group("value")
    assert values, f"в {_CADDYFILE.name} не найден блок заголовков"
    return values


def test_значения_заголовков_совпадают_с_8_3() -> None:
    tz = _read(_TZ_SECURITY)
    for marker in (
        "default-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "Referrer-Policy: same-origin",
        "X-Content-Type-Options",
        "nosniff",
        "max-age=63072000; includeSubDomains",
        "Permissions-Policy",
    ):
        assert marker in tz, f"§8.3 обязан содержать {marker!r}"


def test_значения_приложения_и_caddy_не_расходятся() -> None:
    """Одно значение на заголовок в двух артефактах: приложение и периметр.

    Приложение обязано уметь отдавать политики само (job `compose-smoke` и отладка внутри сети
    состава ходят в `web` напрямую, минуя Caddy), и тогда два набора обязаны совпадать побайтово.
    """
    caddy = _caddy_header_values()
    for name, value in SECURITY_HEADERS.items():
        assert caddy.get(name) == value, (
            f"{name}: значение приложения не совпадает со значением в `Caddyfile` — правка "
            "обязана пройти по обоим артефактам, иначе браузер получит две политики"
        )


def test_набор_заголовков_приложения_закрыт() -> None:
    """Никаких `Cross-Origin-*` и `X-XSS-Protection`: консоль одноисточниковая (§8.3)."""
    assert set(SECURITY_HEADERS) == {
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Permissions-Policy",
    }
    assert "preload" not in HSTS_POLICY.lower(), "HSTS `preload` — решение заказчика, не оформителя"
    for value in SECURITY_HEADERS.values():
        assert "unsafe-inline" not in value
        assert "unsafe-eval" not in value


def test_заголовки_ставит_middleware_а_не_маршруты(app: FastAPI) -> None:
    """Обработчики исключений создают ответы вне маршрутов: заголовки навешивает middleware.

    Проверка по исходнику фабрики приложения: без вызова `apply_security_headers` в middleware
    отказ `403`/`413`/`503` и редирект «сессия не подходит» остаются без политики, а увидеть это
    можно только на живом ответе — то есть на приёмке.
    """
    source = _read(_ROOT / "apps" / "web" / "main.py")
    assert '@app.middleware("http")' in source
    assert "apply_security_headers(await call_next(request))" in source
    assert app.state.templates.env.autoescape is True


def test_страницы_состояний_из_9_остаются_в_приложении(app: FastAPI) -> None:
    """`docs/tz/09-web-ui-and-design.md` §9: `/session-expired`, `/locked` — обязательные адреса."""
    paths = _app_paths(app)
    for path in (SESSION_EXPIRED_PATH, LOCKED_PATH):
        assert path in paths, f"адрес {path} исчез из перечня приложения: §9 требует страницы"
        methods = {method.lower() for method in paths[path]}
        assert "get" in methods, f"{path}: страница состояния не отдаётся методом GET"
    for name in ("session_expired.html", "locked.html", "login.html", "base.html"):
        assert (_TEMPLATES / name).exists(), f"шаблон {name} удалён — страница состояния пропала"
