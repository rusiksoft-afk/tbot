"""Заголовки безопасности ответа и страница `«вход заблокирован»` (TZ §8.3, §8.4, §9; `T-102`, `R3c`).

Проверяется то, чего не видно в тексте шаблона: что заголовок действительно доезжает до ответа на
каждой ветке — страница, отказ `403`, отказ `413`, редирект «сессия не подходит», `503` без базы.
Отказные ответы создают обработчики исключений, а не маршрут, и именно ради них заголовки
навешивает middleware (`apps/web/security/headers.py`).

Сверка значений с текстом ТЗ и со строками `deploy/caddy/Caddyfile` — в
`tests/contract/test_web_security_contract.py`: два артефакта с двумя разными политиками браузер
пересёк бы, а не выбрал, поэтому расхождение ловится контрактом, а не приёмкой.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from apps.web.main import create_app
from apps.web.security.csrf import CSRF_FORM_FIELD, CSRF_HEADER
from apps.web.security.headers import (
    CSP_POLICY,
    HSTS_POLICY,
    PERMISSIONS_POLICY,
    REFERRER_POLICY,
    SECURITY_HEADERS,
)
from apps.web.security.sessions import (
    LOCKED_PATH,
    LOGIN_PATH,
    POST_LOGIN_REDIRECT,
    SESSION_COOKIE_NAME,
)
from packages.common.config import Settings
from tests.integration.web_support import (
    TEST_LOGIN,
    TEST_PASSWORD,
    MemoryStore,
    build_client,
    login,
)

EXTERNAL_MARKERS = ("unsafe-inline", "unsafe-eval", "data:", "http://", "https://", "//cdn")


@pytest.fixture
def store() -> MemoryStore:
    memory = MemoryStore()
    memory.seed_user()
    return memory


@pytest.fixture
def client(store: MemoryStore, settings: Settings) -> Iterator[TestClient]:
    with build_client(store, settings, with_probe=True) as test_client:
        yield test_client


def _values(response: TestClient) -> dict[str, list[str]]:
    """Все значения заголовков ответа: дубликат заголовка — тоже дефект, а не «то же самое»."""
    collected: dict[str, list[str]] = {}
    for name, value in response.headers.multi_items():
        collected.setdefault(name.lower(), []).append(value)
    return collected


def test_страница_входа_отдаёт_весь_набор_заголовков(client: TestClient) -> None:
    response = client.get(LOGIN_PATH)
    assert response.status_code == 200
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, f"{name}: заголовок не доехал до ответа"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("content-security-policy", CSP_POLICY),
        ("strict-transport-security", HSTS_POLICY),
        ("referrer-policy", REFERRER_POLICY),
        ("permissions-policy", PERMISSIONS_POLICY),
    ],
)
def test_значения_не_дублируются(client: TestClient, name: str, expected: str) -> None:
    """Один заголовок — одно значение.

    Дубликат `Content-Security-Policy` браузер трактует как пересечение политик: две «разные, но
    похожие» политики дают эффект, который никто не проектировал, и отличить его от «политики нет»
    по приёмке нельзя.
    """
    values = _values(client.get(LOGIN_PATH)).get(name, [])
    assert values == [expected], f"{name}: ожидался ровно один заголовок, получено {values}"


def test_csp_без_внешних_источников_и_без_послаблений(client: TestClient) -> None:
    """§8.3: внешние CDN запрещены, `unsafe-inline`/`unsafe-eval` в политике нет."""
    policy = client.get(LOGIN_PATH).headers["content-security-policy"]
    for marker in EXTERNAL_MARKERS:
        assert marker not in policy, f"CSP содержит внешний или послабляющий источник {marker!r}"
    for directive in ("default-src 'self'", "frame-ancestors 'none'", "base-uri 'self'"):
        assert directive in policy, f"§8.3: директивы {directive} нет"
    assert "upgrade-insecure-requests" not in policy, (
        "TLS заканчивается на Caddy, а `web` слушает 127.0.0.1: политика не может знать о схеме "
        "наружу и не должна ничего «повышать»"
    )


def test_hsts_без_preload(client: TestClient) -> None:
    """§8.3 требует ровно `max-age=63072000; includeSubDomains`.

    `preload` означает попадание в браузерный список и невозможность вернуть http когда-либо —
    это решение заказчика, а не оформителя, и добавляться «по ходу» оно не имеет права.
    """
    value = client.get(LOGIN_PATH).headers["strict-transport-security"]
    assert value == "max-age=63072000; includeSubDomains"
    assert "preload" not in value.lower()


def test_отказ_csrf_тоже_несёт_политику(client: TestClient, store: MemoryStore) -> None:
    """`403` создаёт обработчик исключения — заголовок обязан поставить middleware."""
    login(client)
    before = store.commits
    response = client.post("/logout", data={"любое": "поле"}, follow_redirects=False)
    assert response.status_code == 403
    assert store.commits == before, "отклонённый запрос не должен ничего записать"
    for name in SECURITY_HEADERS:
        assert name in response.headers, f"{name}: отказ `403` отдан без политики"


def test_отказ_по_размеру_тела_несёт_nosniff(client: TestClient, store: MemoryStore) -> None:
    login(client)
    before = store.commits
    response = client.post(
        "/logout",
        data={"любое": "д" * 40000},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 413
    assert response.headers["x-content-type-options"] == "nosniff"
    assert store.commits == before, "слишком большое тело не должно ничего записать"


def test_редирект_сессии_несёт_заголовки(client: TestClient, store: MemoryStore) -> None:
    """Перенаправление — тоже ответ: страница состояния открывается после него."""
    client.cookies.set(SESSION_COOKIE_NAME, "cut-cookie")
    response = client.get("/probe-full", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["content-security-policy"] == CSP_POLICY
    assert store.commits == 0, "редирект «сессия не подходит» не продлевает и не пишет сеанс"


def test_ответ_без_базы_несёт_заголовки(settings: Settings) -> None:
    """`503` от обработчика `StoreUnavailableError` (адрес базы не настроен)."""
    # Без подмены репозитория: `build_client` её делает всегда, а здесь нужен боевой путь
    # `get_store` — он и обязан ответить 503, когда адрес базы не настроен.
    client = TestClient(create_app(settings), base_url="https://testserver")
    response = client.post(
        LOGIN_PATH,
        data={"login": TEST_LOGIN, "password": TEST_PASSWORD},
        headers={"Origin": "https://testserver"},
    )
    assert response.status_code == 503
    for name in SECURITY_HEADERS:
        assert name in response.headers, f"{name}: `503` отдан без политики"


def test_обработчик_со_своим_csp_не_затирается(settings: Settings) -> None:
    """Свой `Content-Security-Policy` у ответа сохраняется.

    Иначе постановщик заголовков молча подменял бы политику, выбранную для конкретного ответа
    (будущая страница отчёта из §8.3 про файлы отчётов), и «политика в коде есть» перестало бы
    значить что-либо.
    """
    router = APIRouter()

    @router.get("/strict-csp")
    def strict() -> HTMLResponse:
        return HTMLResponse(
            "<p>страница</p>", headers={"Content-Security-Policy": "default-src 'none'"}
        )

    app = create_app(settings)
    app.include_router(router)
    client = TestClient(app, base_url="https://testserver")
    response = client.get("/strict-csp")
    assert response.headers["content-security-policy"] == "default-src 'none'"
    # остальные заголовки при этом доезжают: частная политика не отменяет весь набор
    assert response.headers["x-content-type-options"] == "nosniff"


# ─── страница «вход заблокирован» (§9) ────────────────────────────────────────────────────────


def test_страница_блокировки_отдаётся_без_сессии(client: TestClient) -> None:
    response = client.get(LOCKED_PATH)
    assert response.status_code == 200
    assert "заблокирован" in response.text
    assert not [
        value
        for value in response.headers.get_list("set-cookie")
        if value.startswith(f"{SESSION_COOKIE_NAME}=")
    ], "страница состояния не выдаёт и не стирает материал сессии"


@pytest.mark.parametrize(
    ("reason", "marker"),
    [("attempts", "учётную запись"), ("rate", "адресе")],
    ids=["по_учётной_записи", "по_адресу"],
)
def test_каждая_причина_блокировки_объяснена(client: TestClient, reason: str, marker: str) -> None:
    """§9: состояние объясняется словами, а не кодом, и объяснение соответствует причине."""
    response = client.get(f"{LOCKED_PATH}?reason={reason}")
    assert response.status_code == 200
    assert marker in response.text, f"{reason}: объяснение не описывает свою причину"
    assert "внутренн" not in response.text.lower()


def test_страницы_причин_различаются_текстом(client: TestClient) -> None:
    """Блокировка по учётной записи и по адресу — разные состояния, и текст обязан это показывать."""
    attempts = client.get(f"{LOCKED_PATH}?reason=attempts").text
    rate = client.get(f"{LOCKED_PATH}?reason=rate").text
    assert attempts != rate


def test_чужая_причина_не_подставляется_в_текст(client: TestClient) -> None:
    response = client.get(f"{LOCKED_PATH}?reason=%3Cscript%3Eподозрительное%3C%2Fscript%3E")
    assert response.status_code == 200
    assert "подозрительное" not in response.text
    assert "<script>" not in response.text


def test_страница_входа_даёт_ссылку_на_состояние_только_при_блокировке(
    client: TestClient, store: MemoryStore
) -> None:
    """§9: у состояния есть отдельный адрес.

    Ссылка появляется на `429` («вход заблокирован») и отсутствует на `401` («пароль не тот»):
    иначе страница входа подсказывала бы пользователю неверный диагноз — а блокировку и неверный
    пароль различает уже сам код ответа.
    """
    blocked = None
    for _ in range(5):
        blocked = client.post(
            LOGIN_PATH,
            data={"login": TEST_LOGIN, "password": "не-тот-пароль-12345"},
            headers={"Origin": "https://testserver"},
        )
    assert blocked is not None
    assert blocked.status_code == 429
    assert f'href="{LOCKED_PATH}?reason=attempts"' in blocked.text

    client.cookies.clear()
    wrong = client.post(
        LOGIN_PATH,
        data={"login": TEST_LOGIN, "password": "снова-не-тот-пароль-12"},
        headers={"Origin": "https://testserver"},
    )
    assert wrong.status_code in (401, 429)
    if wrong.status_code == 401:
        assert LOCKED_PATH not in wrong.text
    blocked_user = store.user_by_login(TEST_LOGIN)
    assert blocked_user is not None, "та же запись пользователя, что и у страницы отказа"
    assert (
        blocked_user.locked_until is not None
    ), "ссылка на состояние ведёт к блокировке, которая действительно стоит в базе"


def test_редирект_после_входа_ведёт_на_стартовую(client: TestClient, store: MemoryStore) -> None:
    """Неожиданная проверка этого среза: набор заголовков не должен ломать выдачу куки."""
    response = login(client)
    assert response.status_code == 302
    assert response.headers["location"] == POST_LOGIN_REDIRECT
    assert store.commits == 1, "редирект выдаётся уже после записи сеанса"
    assert CSRF_HEADER not in response.headers
    assert f"{CSRF_FORM_FIELD}=" not in response.headers.get("location", "")
