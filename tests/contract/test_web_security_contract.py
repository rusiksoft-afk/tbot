"""Контракт слоя входа: покрытие мутаций CSRF, атрибуты куки, шаблоны и границы среза (`T-102`).

Офлайновая проверка без базы и без HTTP-запросов: она держит то, что иначе расходится молча.

1. **Покрытие мутационных маршрутов.** ADR-008 прямо называет типовую дыру этого дизайна — эндпоинт,
   который «принимает `X-CSRF-Token`, но не проверяет его». Проверка по таблице маршрутов
   боевого приложения обязывает каждый маршрут с мутационным методом либо зависеть от
   `require_csrf`, либо быть поименованным исключением с обоснованием. Исключения перечислены в
   `_MUTATION_EXEMPT`: это адреса церемонии, где сеанса ещё нет и вывод токена не определён
   (`ADR-009` для `/login`, `ADR-021` для `/invite`); вместо токена у обоих работает проверка
   источника, и за это отвечает отдельная проверка ниже.
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
    INVITE_PATH,
    LOCKED_PATH,
    LOGIN_PATH,
    SESSION_COOKIE_NAME,
    SESSION_EXPIRED_PATH,
    display_reason_codes,
)
from apps.web.store import USER_AGENT_MAX_LEN
from packages.common.config import Settings
from packages.identity.audit import AUDIT_ACTIONS
from packages.identity.sessions import ABSOLUTE_TIMEOUT, IDLE_TIMEOUT

_ROOT: Final = pathlib.Path(__file__).resolve().parents[2]
_TZ_SECURITY: Final = _ROOT / "docs" / "tz" / "08-security-auth-2fa.md"
_ADR_CSRF: Final = _ROOT / "docs" / "adr" / "ADR-008-csrf-token-derived-from-session.md"
_ADR_LIMITS: Final = _ROOT / "docs" / "adr" / "ADR-007-rate-limit-counter-table.md"
_ADR_FORMS: Final = _ROOT / "docs" / "adr" / "ADR-009-form-parsing-without-multipart.md"
_ADR_INVITE: Final = _ROOT / "docs" / "adr" / "ADR-021-invitation-ceremony-without-session.md"
_TEMPLATES: Final = _ROOT / "apps" / "web" / "templates"
_MUTATION_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Мутационные маршруты без зависимости от `require_csrf`. Обоснование у каждого — своё, и оно
#: обязано быть в ADR: «появился новый POST без токена» не может быть решением по умолчанию.
#: `/login` — сессии ещё нет, вывод токена не определён; его держит проверка источника (`ADR-009`).
#: `/invite` — та же причина в другом месте: приглашённый человек ещё не вошёл, а токен `ADR-008`
#: выводится из пары «значение куки + `id` сеанса», поэтому вывод токена для него не определён;
#: вместо токена — проверка источника и предел частоты по адресу (`ADR-021` п. 2). Расширять этот
#: список «ещё одним POST без токена» можно только вместе с новым ADR — проверка ниже требует
#: обоснования у каждого адреса списка.
_MUTATION_EXEMPT: Final = frozenset({LOGIN_PATH, INVITE_PATH})

#: Чем обосновано каждое исключение и в каком модуле обязана жить проверка источника:
#: адрес → (маршрутный модуль, ADR). Перечень сверяется с `_MUTATION_EXEMPT`, поэтому «поставили
#: исключение и забыли защиту» через эту проверку не проходит: исключение обязано иметь и
#: обоснование, и проверку источника, и предел частоты внутри обработчика.
_MUTATION_EXEMPT_EVIDENCE: Final[dict[str, tuple[str, pathlib.Path]]] = {
    LOGIN_PATH: ("login.py", _ADR_FORMS),
    INVITE_PATH: ("invitations.py", _ADR_INVITE),
}


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


def test_каждая_мутация_учтена_счётчиком_частоты_или_поименована() -> None:
    """§8.3: «все mutation-эндпоинты — 60 запросов/мин/пользователь» (срез `R3d`, `ADR-007`).

    Проверка парная к проверке токена и построена на том же перечне маршрутов: счётчик обязан
    накрывать мутации целиком, иначе он закрывает половину поверхности, а «забытый POST без
    лимита» — типовая дыра того же рода, что и «забытый POST без токена».

    Исключение одно и то же, что у токена, и обоснование у него другое: `/login` считает частоту
    **по адресу** внутри обработчика (`login_ip`), потому что пользовательской сессии до входа нет,
    а ключ `user_id` был бы подделываемым. Отдельного списка исключений для счётчика поэтому нет:
    если маршрут выпадает из обоих перечней одновременно, это замечает проверка токена.
    `/invite` — второе значение списка по той же причине: сессии у приглашённого ещё нет, а
    предел по адресу (`login_ip`) считается внутри обработчика, поэтому счётчика пользователя
    у маршрута нет не «по забывчивости», а по тем же основаниям, что у входа (§8.3, `ADR-021` п. 2).
    """
    mutations = [
        route for route in _router_routes() if _MUTATION_METHODS & set(route.methods or ())
    ]
    assert mutations, "в `apps/web` нет ни одной мутации — проверка стала бы пустой"
    counted = {
        route.path
        for route in mutations
        if "require_mutation_rate_limit" in _dependency_names(route)
    }
    uncounted = {route.path for route in mutations} - counted
    assert uncounted == _MUTATION_EXEMPT, (
        f"мутации без счётчика частоты: {sorted(uncounted)} — §8.3 требует предела на каждую "
        "мутацию пользователя"
    )
    assert counted, (
        "ни одна мутация не зависит от счётчика частоты: зависимость `RateLimitedMutation` "
        "пропала из маршрутов, и лимит пользователя не работает"
    )


def test_исключение_из_проверки_токена_держит_проверку_источника() -> None:
    """У каждого исключения из токена обязана быть проверка источника, частоты и обоснование.

    `/login` лишён токена сессии, но обязан проверять источник (§8.3 «проверка origin»): без него
    исключение означает «мутация вовсе без защиты от подделки запроса». У `/invite` причина
    исключения та же (сеанса ещё нет, вывод токена `ADR-008` не определён), и следствия те же —
    источник и предел частоты по адресу считаются внутри обработчика (`ADR-021` п. 2).

    Проверка перебирает перечень исключений вместе с его доказательствами, поэтому новое
    исключение требует ADR, проверку источника и предел частоты, а не молчаливую строчку в
    списке: ровно тот же приём, что у сверки уровней допуска с деревом зависимостей.
    """
    assert set(_MUTATION_EXEMPT) == set(_MUTATION_EXEMPT_EVIDENCE), (
        "перечень исключений из проверки токена разошёлся с перечнем обоснований: у каждого "
        "исключения обязан быть ADR и маршрутный модуль с проверкой источника"
    )
    for адрес, (модуль, обоснование) in sorted(_MUTATION_EXEMPT_EVIDENCE.items()):
        исходник = _read(_ROOT / "apps" / "web" / "routes" / модуль)
        assert "ensure_same_origin" in исходник, (
            f"{адрес}: без проверки источника исключение из CSRF-требования означает «мутация "
            "без защиты от подделки запроса вовсе»"
        )
        assert "enforce_scope" in исходник, (
            f"{адрес}: мутация без токена обязана считать частоту внутри обработчика, иначе "
            "исключение остаётся дырой, а не заменой защиты (§8.3)"
        )
        assert (
            обоснование.exists()
        ), f"обоснование исключения {адрес} обязано быть оформлено ADR: {обоснование.name}"


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


def test_секрет_привязки_выводится_один_раз_и_только_в_шаге_подтверждения() -> None:
    """Материал привязки (§8.2, `ADR-014` п. 6): точка вывода одна, и она не повторяется.

    §8.2 разрешает показать секрет при первичной привязке и запрещает показывать его повторно.
    Слово «повторно» в тексте ТЗ означает не «один раз за запрос», а «один раз за привязку», поэтому
    договорённость держится статически: переменная секрета печатается в одном шаблоне, в одном
    месте, внутри ветки состояния `confirm`, и только когда значение непустое (а непустым его
    делает единственный обработчик `POST /mfa-enroll/start`).

    Это та граница, которую поведение поймать не может полностью: офлайн-проверка видит, что
    `GET /mfa-enroll` секрета не выдаёт, но не видит, что где-то в разметке завёлся второй вывод
    «для удобства» — например блок «показать секрет ещё раз». Второй вывод означает и второе
    расшифровывание `secret_enc`, и вторую точку утечки в журнал/скриншот.

    Отдельно держится запрет на сборку `otpauth://` в шаблонах: URI собирает серверный код среза
    `R4d` из того же значения, что показывает выдача секрета, а не из повторного
    расшифровывания колонки.
    """
    привязка = _read(_TEMPLATES / "mfa_enroll.html")
    # `<code>` в шаблоне ровно два: вывод секрета и единственный элемент цикла пачки резервных
    # кодов (`<li><code>{{ value }}</code></li>` — один литерал на десять значений). Число держится
    # константой, а не «не больше двух», потому что второй блок «показать секрет ещё раз» — это
    # ровно ещё один `<code>`: при нём счётчик становится 3, и проверка краснеет (§8.2). Сам вывод
    # секрета держится ниже отдельно: `{{ secret }}` один раз и внутри ветки `confirm`.
    assert привязка.count("<code>") == 2, (
        "материал привязки обязан занимать ровно один вывод: второй блок «показать ещё раз» "
        "означает вторую точку утечки (§8.2); исключение — цикл пачки резервных кодов, у него "
        "один литерал `<code>` и десять значений, показанных один раз (`ADR-016` п. 2)"
    )
    assert привязка.count("{{ secret }}") == 1, "переменная секрета печатается не один раз"

    начало_подтверждения = '{% elif state == "confirm" %}'
    дальше = '{% elif state == "stale" %}'
    assert (
        начало_подтверждения in привязка
    ), "ветки `confirm` нет: контракт перестаёт отличать вывод от повтора"
    assert дальше in привязка, "ветки `stale` нет: контракт не видит границы вывода"
    вывод = привязка.index("{{ secret }}")
    assert (
        привязка.index(начало_подтверждения) < вывод < привязка.index(дальше)
    ), "секрет печатается вне ветки `confirm` — состояние страницы перестаёт управлять выводом"
    assert "{% if secret %}" in привязка, (
        "вывод не обёрнут в проверку непустого значения: страница привязки без выдачи печатала бы "
        "пустой блок как настоящий секрет"
    )

    for path in _TEMPLATES.glob("*.html"):
        if path.name == "mfa_enroll.html":
            continue
        разметка = _read(path)
        assert (
            "{{ secret" not in разметка
        ), f"{path.name}: материал привязки на чужой странице (§8.2: «в UI больше не показывается»)"
        assert (
            "otpauth://" not in разметка
        ), f"{path.name}: URI генератора собран в разметке — значит секрет расшифрован повторно"

    обработчик = _read(_ROOT / "apps" / "web" / "routes" / "totp.py")
    assert обработчик.count('"secret":') == 1, (
        "ключ контекста `secret` заведён больше одного раза: вывод секрета появляется в нескольких "
        "состояниях страницы"
    )
    assert (
        обработчик.count("secret=created.secret") == 1
    ), "значение секрета передают не из одного места — «показывается один раз» перестаёт держаться"


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


def _audit_calls(path: pathlib.Path) -> int:
    """Число вызовов `<объект>.append_audit(...)` в файле.

    Считается по AST, а не по тексту: комментарий или докстринг со словом `append_audit` не
    должен создавать ложный вызов — иначе проверка начала бы ловить собственное обоснование.
    """
    дерево = ast.parse(path.read_text(encoding="utf-8"))
    return sum(
        1
        for узел in ast.walk(дерево)
        if isinstance(узел, ast.Call)
        and isinstance(узел.func, ast.Attribute)
        and узел.func.attr == "append_audit"
    )


def _function_source(path: pathlib.Path, *, name: str) -> str:
    """Исходник одной модульной функции: соседние функции и комментарии к ней не входят.

    Нужен с среза `R3.2` задачи `T-109`: протокол добавления записи журнала больше не живёт внутри
    метода `SqlStore`, он исполняется одной функцией общего слоя, потому что писателей журнала два
    процесса (`web` и ежедневная `integrity-check` в `jobs`), а процессам запрещено импортировать
    друг друга (`ADR-025` п. 6 и п. 9). Проверка обязана смотреть на код функции, а не на её
    обоснование: рядом стоит разбор того, почему `ON CONFLICT` запрещён.
    """
    source = path.read_text(encoding="utf-8")
    for узел in ast.walk(ast.parse(source)):
        if isinstance(узел, ast.FunctionDef | ast.AsyncFunctionDef) and узел.name == name:
            отрезок = ast.get_source_segment(source, узел)
            assert отрезок is not None, f"{path.name}: не удалось выделить {name}"
            # Докстринг функции отсекается: объяснение («почему `ON CONFLICT` на журнале запрещён»)
            # живёт внутри функции, а проверка обязана касаться кода, иначе текст обоснования
            # ловился бы как нарушение того же запрета.
            if узел.body and isinstance(узел.body[0], ast.Expr):
                докстринг = ast.get_source_segment(source, узел.body[0])
                if докстринг is not None:
                    отрезок = отрезок.replace(докстринг, "", 1)
            return отрезок
    raise AssertionError(f"в {path.name} нет функции {name}")


def _method_source(path: pathlib.Path, *, klass: str, name: str) -> str:
    """Исходник одного метода одного класса: комментарий рядом с ним и соседние методы не входят.

    Класс указывается обязательно: в `apps/web/store.py` метод объявлен дважды — узкий протокол
    `Store` (объявление с докстрингом) и реализация `SqlStore`. Проверка протокола добавления
    обязана смотреть на реализацию, иначе она проверяла бы заглушку.

    Нужен ровно для того, чтобы проверка относилась к коду протокола, а не к его обоснованию:
    рядом с методом стоит разбор того, почему `ON CONFLICT` запрещён, и текстовая проверка по
    всему файлу ловила бы это объяснение вместо нарушения.
    """
    source = path.read_text(encoding="utf-8")
    for узел in ast.walk(ast.parse(source)):
        if not isinstance(узел, ast.ClassDef) or узел.name != klass:
            continue
        for item in узел.body:
            if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef) and item.name == name:
                отрезок = ast.get_source_segment(source, item)
                assert отрезок is not None, f"{path.name}: не удалось выделить {klass}.{name}"
                return отрезок
        break
    raise AssertionError(f"в {path.name} нет метода {klass}.{name}")


def test_события_журнала_пишет_протокол_а_их_точки_в_маршрутах_закрыты() -> None:
    """Точка добавления журнала — слой доступа; маршруты журнала не касаются (`ADR-025` п. 6).

    Опасность ровно одна, и по одному ответу её не видно: строка, записанная мимо протокола,
    лишена `hash_prev` из хвоста, и весь журнал перестаёт быть доказательством. Найти разрыв
    способен только разбор (`make audit-verify` — срез `R3`), да и то после того, как событие
    легло в неизменяемую таблицу. Поэтому проверяется форма слоя, а не один ответ:

    * события мутаций добавляют маршруты — и это не обход протокола: у них нет точки в слое
    безопасности, потому что причину перехода решает обработчик (чьё решение привело к переходу,
    какое состояние было до него, сколько сеансов закрыл `suspend`). Срез `R2b` задачи `T-109`
    перенёс эти события из «остатка задачи» в обработчики и оформил `ADR-025` п. 6; число точек
    держится закрытым перечнем ниже, поэтому новая точка в маршруте требует правки проверки;
    * ни один маршрутный модуль **не строит строку журнала сам**: `AuditLogEntry`,
    `build_audit_entry`, `make_record` и `audit_row_values` в маршрутах не вызываются. Строка,
    собранная мимо `Store.append_audit`, лишена `hash_prev` из хвоста и блокировки хвоста, и весь
    журнал перестаёт быть доказательством — найти разрыв способен только разбор (`R3`), да и то
    после того, как событие легло в неизменяемую таблицу;
    * события отказов по-прежнему пишутся в слое безопасности, где решается причина (лимиты
    частоты, бан адреса, CSRF, отказ допуска): к моменту, когда `apps/web/main.py` получает
    `403`/`429`, слой доступа запроса уже закрыт;
    * в слое безопасности вызовов ровно по одному на каждое место, где причина решается: лимиты
      (отказ частоты и бан адреса — два разных события), CSRF, отказ допуска (одна точка на обе
      причины, иначе «учётной записи нет» записывается дважды);
    * признаки протокола держат внутри **одной** функции общего слоя —
      `packages/storage/audit_store.py::append_audit_record` (срез `R3.2` задачи `T-109`):
      блокировка хвоста берётся до его чтения, хвост читается как `hash` последней строки в
      порядке `id`,
      отличие конфликта цепочки по **коду состояния**, а не по тексту сообщения, откат и проверка
      числа вставленных строк по `RETURNING`, а не по `Result.rowcount`, потому что вставка без
      ошибки и без строки — это молча потерянное событие (`ADR-025` п. 6, замеры прогонов
      `45163930282` и `45165930936`, а `-1` у `rowcount` на ORM-вставке — прогон `45182752079`);
    * форм `ON CONFLICT` в слое доступа нет: `DO NOTHING` на журнале не конфликтует, а теряет
      событие, превращая его в `broken_link` (`ADR-025` п. 4).
    """
    routes = _ROOT / "apps" / "web" / "routes"
    modules = [path for path in sorted(routes.glob("*.py")) if path.name != "__init__.py"]
    written = {path.name: _audit_calls(path) for path in modules}
    assert written == ROUTE_AUDIT_CALLS, (
        "число точек добавления журнала в маршрутах разошлось с закрытым перечнем: "
        f"ожидалось {ROUTE_AUDIT_CALLS}, получено {written}. Одна точка на событие — часть "
        "`ADR-025` п. 6: вторая копия события искажает счётчик при разборе, а удалённая точка "
        "означает событие §8.7 без носителя (перечень меняется только вместе с правкой ADR)",
    )
    builders = {path.name: _journal_row_builders(path) for path in modules}
    assert not any(builders.values()), (
        f"маршрут строит строку журнала в обход протокола ({builders}): точку имеет "
        "`Store.append_audit` — только она читает хвост цепочки и берёт блокировку (`ADR-025` "
        "п. 6)",
    )

    security = _ROOT / "apps" / "web" / "security"
    assert (
        _audit_calls(security / "rate_limit.py") == 2
    ), "у механизма лимитов должно быть по одному вызову на отказ частоты и на бан адреса"
    assert _audit_calls(security / "csrf.py") == 1, "у отказа CSRF обязан быть ровно один вызов"
    assert _audit_calls(security / "authorization.py") == 1, (
        "отказ допуска пишется в одной точке: вызов внутри проверки роли записал бы причину "
        "«учётной записи нет» дважды"
    )

    store_path = _ROOT / "apps" / "web" / "store.py"
    journal_path = _ROOT / "packages" / "storage" / "audit_store.py"
    protocol = _function_source(journal_path, name="append_audit_record")
    assert "lock_audit_chain(session)" in protocol, (
        "из протокола исчезла блокировка хвоста: два писателя прочитают один хвост, а индекс-страж "
        "`ix_audit_log_hash_prev_linked` отклонит вторую запись (`ADR-025` п. 6)"
    )
    assert "tail_hash(session)" in protocol, (
        "протокол перестал читать хвост цепочки: запись ушла бы без `hash_prev`, и цепочка "
        "распалась бы на независимые ветки"
    )
    # Порядок внутри функции зафиксирован и значит больше стиля: `FOR UPDATE` последней строки на
    # пустой таблице ничего не держит, а advisory-замок, взятый после чтения хвоста, защищает уже
    # прочитанное значение — то есть ровно ту гонку, из-за которой он и введён.
    assert protocol.index("lock_audit_chain(session)") < protocol.index(
        "tail_hash(session)"
    ), "замок цепочки обязан браться до чтения хвоста (`ADR-025` п. 6)"
    locking = _function_source(journal_path, name="lock_audit_chain")
    assert "pg_advisory_xact_lock(AUDIT_CHAIN_LOCK_KEY)" in locking, (
        "замок перестал быть advisory-транзакционным по ключу журнала: два процесса с разными"
        " замками пишут в одну цепочку (`ADR-025` п. 6)"
    )
    tail = _function_source(journal_path, name="tail_hash")
    assert "select(AuditLogEntry.hash)" in tail, (
        "хвост цепочки больше не читается из колонки `hash`: привязка строки перестала бы быть"
        " частью протокола"
    )
    assert "AuditLogEntry.id.desc()" in tail, (
        "хвост читается не по `id`: порядок задаёт колонка, которую выдаёт база (§4.1), а не `at`"
        " — моменты двух процессов могут прийти вразнобой"
    )
    assert "sqlstate" in protocol, (
        "конфликт цепочки снова определяется по тексту сообщения: psycopg в сообщении код "
        "`23505` не дублирует (прогон `45165930936`)"
    )
    assert "rollback" in protocol, (
        "при конфликте цепочки перестали откатывать транзакцию целиком: изменение осталось бы "
        "зафиксированным без события (`ADR-025` п. 6)"
    )
    assert ".returning(AuditLogEntry.id)" in protocol, (
        "вставка журнала перестала требовать `RETURNING id`: без неё число вставленных строк "
        "спрашивается у `Result.rowcount`, а ORM-выполнение через `Session` отдаёт `-1` "
        "(замер `CI 45182752079`) — корректная запись отклонялась бы как несостоявшаяся"
    )
    assert "len(inserted) != 1" in protocol, (
        "проверка «ровно одна строка» из протокола исчезла: `ON CONFLICT DO NOTHING` вернулся бы "
        "без исключения и без строки, то есть молча потерял бы событие (`ADR-025` п. 4)"
    )
    for form in ("on_conflict_do_nothing", "on_conflict_do_update"):
        assert form not in protocol, f"форма {form} на журнале запрещена (`ADR-025` п. 4)"
    assert "ON CONFLICT" not in protocol, "прямая форма ON CONFLICT на журнале запрещена (п. 4)"

    # Писатели журнала — два процесса, протокол один. Проверка держит именно форму вызова:
    # второй слой, который сам берёт замок и сам читает хвост, разошёлся бы с первым при первой
    # же правке, а следом разошёлся бы и ключ замка (`ADR-025` п. 6 и п. 9).
    web_writer = _method_source(store_path, klass="SqlStore", name="append_audit")
    assert "append_audit_record(self._session, record)" in web_writer, (
        "слой входа `web` перестал вызывать общий протокол: у него появилась собственная копия"
        " добавления записи"
    )
    jobs_writer = (_ROOT / "apps" / "jobs" / "integrity.py").read_text(encoding="utf-8")
    assert "append_audit_record(writer, record)" in jobs_writer, (
        "ежедневная `integrity-check` перестала вызывать общий протокол: вторая реализация порядка"
        " «замок → хвост → вставка» — это будущий `broken_link` в журнале (`ADR-025` п. 9)"
    )
    for own_copy in ("pg_advisory_xact_lock(", "AUDIT_CHAIN_LOCK_KEY", "hash_prev="):
        assert own_copy not in web_writer, (
            f"в слое входа `web` появилась копия протокола ({own_copy}):"
            " замок и хвост обязана читать одна функция общего слоя"
        )
        assert own_copy not in jobs_writer, (
            f"в процессе `jobs` появилась копия протокола ({own_copy}):"
            " порядок «замок → хвост → вставка» держит одна функция общего слоя"
        )
    key_files = sorted(
        str(p.relative_to(_ROOT))
        for p in (_ROOT / "apps").rglob("*.py")
        if "AUDIT_CHAIN_LOCK_KEY: Final" in p.read_text(encoding="utf-8")
    )
    assert key_files == [], (
        f"ключ замка цепочки определён в слое приложения ({key_files}): у двух процессов обязаны"
        " быть один и тот же ключ (`ADR-025` п. 6)"
    )


#: Число вызовов протокола добавления журнала в каждом маршрутном модуле. Перечень закрыт и
#: назван по модулям: «одна точка на событие» (`ADR-025` п. 6) без перечня не проверялась бы
#: ничем, а удвоенное событие искажает счётчик при разборе так же, как отсутствующее.
#:
#: `admin_users.py` — выпуск и отзыв приглашения, одобрение, закрытие доступа (`suspend`/
#: `archive`), снятие блокировки и смена роли (§9.3 п. 6, срез `R4` задачи `T-109`);
#: `invitations.py` — принятая ссылка, созданная по ней учётная запись и отказ приёма;
#: `login.py` — выпуск сеанса и два отказа входа; `profile.py` — смена пароля; `sessions.py` —
#: выход, отзыв сеанса и отзыв всех сеансов; `totp.py` — привязка, подтверждение, выпуск и
#: аннулирование пачки, расход кода, неудачная попытка кода и два перехода на шаг `full`.
ROUTE_AUDIT_CALLS: Final[dict[str, int]] = {
    "admin_users.py": 6,
    "invitations.py": 3,
    "login.py": 3,
    "profile.py": 1,
    "sessions.py": 3,
    "totp.py": 9,
}

#: Имена событий раздела identity, у которых пока нет производителя: маршрут, обязанный их
#: писать, не построен. Перечень закрыт и назван с причиной — иначе «имя в реестре есть, а
#: события нет» превращается в тихую дыру §8.7, и следующий срез не узнает, что уже сделано.
#:
#: * `totp.revoked` — сброс второго фактора администратором (`T-103`, §8.2 случай 2, §9.3 п. 6).
#:
#: `account.role_changed` из этого перечня убран срезом `R4` задачи `T-109`: маршрут смены роли
#: стоит в разделе администратора (§9.3 п. 6), и число его точек журнала держит перечень выше.
#:
#: Прочие имена групп `session`/`account`/`invitation`/`totp`/`backup_code`/`auth` производителя
#: имеют, и проверка это держит.
IDENTITY_EVENTS_WITHOUT_PRODUCER: Final[frozenset[str]] = frozenset(
    {
        "totp.revoked",
    }
)

#: Группы имён, относящиеся к разделу identity. Остальные (`token` — `T-108`, `risk` — M3,
#: `strategy` — M4, `ip_allowlist` — `T-110`, отчёты и деплой) к этому срезу не относятся и не
#: сверяются: требовать их производителя значило бы писать события будущих срезов сейчас.
IDENTITY_EVENT_PREFIXES: Final[tuple[str, ...]] = (
    "session.",
    "account.",
    "invitation.",
    "totp.",
    "backup_code",
    "auth.",
)


def _audit_actions(path: pathlib.Path) -> list[str]:
    """Значения `action=` у вызовов `append_audit` в файле (по AST, только литералы).

    Нужен литерал, а не переменная: проверка обязана видеть, **какое** имя порождает файл, а не
    только то, что вызов был.
    """
    дерево = ast.parse(path.read_text(encoding="utf-8"))
    имена: list[str] = []
    for узел in ast.walk(дерево):
        if not (
            isinstance(узел, ast.Call)
            and isinstance(узел.func, ast.Attribute)
            and узел.func.attr == "append_audit"
        ):
            continue
        for кт in узел.keywords:
            if кт.arg == "action" and isinstance(кт.value, ast.Constant):
                имена.append(str(кт.value.value))
    return имена


def _journal_row_builders(path: pathlib.Path) -> int:
    """Число попыток собрать строку журнала мимо протокола (`AuditLogEntry` и функции сборки)."""
    строители = {"AuditLogEntry", "build_audit_entry", "make_record", "audit_row_values"}
    дерево = ast.parse(path.read_text(encoding="utf-8"))
    return sum(
        1
        for узел in ast.walk(дерево)
        if isinstance(узел, ast.Call)
        and (
            (isinstance(узел.func, ast.Name) and узел.func.id in строители)
            or (isinstance(узел.func, ast.Attribute) and узел.func.attr in строители)
        )
    )


def test_имена_событий_identity_группы_имеют_производителя() -> None:
    """Каждое имя реестра identity-группы порождается кодом, кроме названных с причиной.

    Реестр `AUDIT_ACTIONS` закрыт за §8.7 (`ADR-025` п. 2), и «имя есть» само по себе ничего не
    значит: событие §8.7 выполнено, только когда у него есть носитель. Без этой проверки
    недоделанная половина перечня выглядит сделанной — ровно та ошибка, из-за которой
    `REQ-identity-03` и переносили в `T-109`.
    """
    слой = _ROOT / "apps" / "web"
    порождаемые: set[str] = set()
    for подкаталог in ("routes", "security"):
        for путь in sorted((слой / подкаталог).glob("*.py")):
            if путь.name == "__init__.py":
                continue
            порождаемые.update(_audit_actions(путь))

    assert (
        порождаемые <= AUDIT_ACTIONS
    ), f"код порождает имена вне закрытого реестра §8.7: {sorted(порождаемые - AUDIT_ACTIONS)}"

    группа = {имя for имя in AUDIT_ACTIONS if имя.startswith(IDENTITY_EVENT_PREFIXES)}
    ожидаемое = группа - IDENTITY_EVENTS_WITHOUT_PRODUCER
    assert порождаемые == ожидаемое, (
        "набор порождаемых событий identity разошёлся с реестром: "
        f"не порождается {sorted(ожидаемое - порождаемые)}, "
        f"порождается сверх ожидаемого {sorted(порождаемые - ожидаемое)}"
    )


def test_страницы_состояний_из_9_остаются_в_приложении(app: FastAPI) -> None:
    """`docs/tz/09-web-ui-and-design.md` §9: `/session-expired`, `/locked` — обязательные адреса."""
    paths = _app_paths(app)
    for path in (SESSION_EXPIRED_PATH, LOCKED_PATH):
        assert path in paths, f"адрес {path} исчез из перечня приложения: §9 требует страницы"
        methods = {method.lower() for method in paths[path]}
        assert "get" in methods, f"{path}: страница состояния не отдаётся методом GET"
    for name in ("session_expired.html", "locked.html", "login.html", "base.html"):
        assert (_TEMPLATES / name).exists(), f"шаблон {name} удалён — страница состояния пропала"


def _импортирует(path: pathlib.Path, пакет: str) -> bool:
    """Импортирует ли файл пакет (по AST: упоминание в докстринге или комментарии — не импорт)."""
    for узел in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(узел, ast.Import):
            корни = [импорт.name.split(".")[0] for импорт in узел.names]
        elif isinstance(узел, ast.ImportFrom) and узел.module is not None:
            корни = [узел.module.split(".")[0]]
        else:
            continue
        if пакет in корни:
            return True
    return False


def test_qr_привязки_выводится_один_раз_и_рядом_с_секретом() -> None:
    """Картинка привязки: одна точка вывода, то же состояние страницы, что у ключа, и без ссылок.

    `ADR-015` п. 6 держит правило «материал привязки имеет ровно одну точку вывода». QR — это тот
    же материал, только в форме, которую генератор считывает за секунду, поэтому он обязан
    появляться ровно там же, где ключ: внутри ветки `confirm`, при непустом значении и ровно один
    раз. Второй вывод означал бы и повторный показ (§8.2: «в UI больше не показывается»), и
    повторное расшифровывание `secret_enc` — обе проверки тогда приходится держать поведенчески.

    Отдельно держится форма доставки. `img-src 'self'` из CSP (§8.3, значение совпадает с
    `Caddyfile`) не пропускает `data:`-изображения, а `<img src=…>` с адресом означал бы второй
    HTTP-вход за секретом и след в access-логе прокси. Значит картинка может быть только
    встроенной геометрией, и ослабления политики этот срез не требует.
    """
    разметка = _read(_TEMPLATES / "mfa_enroll.html")
    assert разметка.count("<svg") == 1, "картинка привязки выведена больше одного раза"
    assert разметка.count("{{ qr_path }}") == 1, "геометрия QR печатается не один раз"
    assert (
        "{{ qr_modules }}" in разметка
    ), "размер холста не приходит из кода: `viewBox` рисуется самой разметкой"
    подтверждение = '{% elif state == "confirm" %}'
    дальше = '{% elif state == "stale" %}'
    assert подтверждение in разметка, "контракт не видит ветку `confirm`"
    assert дальше in разметка, "контракт не видит границу после ветки `confirm`"
    вывод = разметка.index("{{ qr_path }}")
    assert разметка.index(подтверждение) < вывод < разметка.index(дальше), (
        "картинка печатается вне ветки `confirm`: вывод материала привязки перестал управляться "
        "состоянием страницы"
    )
    assert "{% if qr_path %}" in разметка, (
        "вывод не обёрнут в проверку непустого значения: страница без выдачи рисовала бы пустой "
        "квадрат как настоящий QR"
    )

    for path in sorted(_TEMPLATES.glob("*.html")):
        текст = _read(path)
        for marker in ("otpauth://", "data:", "<img", "xlink:href"):
            assert (
                marker not in текст
            ), f"{path.name}: появился {marker} — второй путь вывода секрета"

    обработчик = _read(_ROOT / "apps" / "web" / "routes" / "totp.py")
    assert обработчик.count('"qr_path":') == 1, (
        "ключ контекста `qr_path` заведён больше одного раза: картинка появляется в нескольких "
        "состояниях страницы"
    )
    assert (
        обработчик.count("qr=_qr_of_enrollment(") == 1
    ), "картинку собирают не из одного места — «показывается один раз» перестаёт держаться"
    assert обработчик.count("totp_provisioning_uri(") == 1, (
        "`otpauth://`-ссылка собирается в нескольких местах: у картинки и у ручного ключа "
        "появились бы разные источники"
    )


def test_qr_кодировщик_зафиксирован_и_импортируется_одним_модулем() -> None:
    """Зависимость-кодировщик: зафиксированный диапазон, обоснование и ровно один импорт.

    `ADR-013` п. 10 разрешает QR-зависимость решением заказчика — тем же порядком, что когда-то с
    `argon2-cffi`: пин диапазона, номер версии, лицензия и снимок OSV на дату. Иначе «обновилось до
    2.x, у сериализаторов поменялся API» обнаруживается на площадке, а не в CI.

    Импорт обязан оставаться в одном модуле слоя представления. Домен `packages/identity` держит
    закрытый перечень сторонних импортов (`tests/contract/test_identity_passwords.py`), а QR — не
    дело домена: это вывод HTML со своей границей. Плюс один импорт — один модуль, который нужно
    перечитывать, меняя картинку.
    """
    pyproject = _read(_ROOT / "pyproject.toml")
    assert '"segno>=1.6.6,<2"' in pyproject, (
        "в pyproject нет зафиксированного диапазона segno: зависимость разъедется с той, что "
        "проверена в CI и на площадке"
    )
    начало = pyproject.index("# QR-код привязки TOTP")
    обоснование = pyproject[начало : pyproject.index('"segno>=1.6.6,<2"')]
    for marker in ("ADR-013", "BSD-3-Clause", "OSV", "apps/web/qrcode.py"):
        assert marker in обоснование, f"в pyproject про segno нет обоснования {marker!r}"

    единственный = (_ROOT / "apps" / "web" / "qrcode.py").resolve()
    use = [
        path.resolve()
        for base in (_ROOT / "apps", _ROOT / "packages")
        for path in base.rglob("*.py")
        if _импортирует(path, "segno")
    ]
    assert use == [
        единственный
    ], f"segno импортируют вне apps/web/qrcode.py: {[str(path.relative_to(_ROOT)) for path in use]}"

    csp = SECURITY_HEADERS["Content-Security-Policy"]
    assert (
        "img-src 'self'" in csp
    ), "значение `img-src` изменилось: картинка привязки не имеет права на собственний источник (§8.3)"
    assert "data:" not in csp, (
        "значение CSP изменилось: если `img-src` расширили `data:`, это решение заказчика по §8.3, "
        "а не следствие картинки — проверьте, что ADR и `Caddyfile` обновлены вместе"
    )
