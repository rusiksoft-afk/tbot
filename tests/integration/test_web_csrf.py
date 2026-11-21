"""CSRF обязателен для мутаций (TZ §8.3, §8.8; `docs/adr/ADR-008`; задача `T-102`, срез `R3b`).

Матрица §8.8 требует проверку «запрос мутации без токена → `403`», и имя `test_csrf_required`
зафиксировано в `tasks/todo.md` как приёмка задачи — оно латиницей намеренно, как `test_session_matrix`
и `test_session_revoke`.

Что проверяется, помимо обязательной строки матрицы:

* токен принимается из скрытого поля `csrf_token` и из заголовка `X-CSRF-Token` (HTMX — §8.3
  называет его явно), и не принимается из строки запроса (ADR-008: секрет не должен утекать в
  `Referer`, историю браузера и логи Caddy);
* токен другой сессии не подходит; вывод меняется вместе с сессией, поэтому `rotate_session`
  делает старый токен недействительным без всякого «пересчёта CSRF»;
* `Origin`/`Sec-Fetch-Site` — второй слой: при чужом источнике отказ, а при отсутствии заголовков
  отказ всё равно наступает по токену (проверка источника не заменяет токен);
* отказ `403` не различает причины: по разным ответам подбором находилось бы, где живёт запрошенный
  контур (ADR-008);
* порядок проверок: мутация с токеном, но с мёртвой сессией, попадает на объясняющую страницу (§9),
  а мутация без куки вообще — остаёт `403`: объяснять нечего, а состояние не менялось;
* ответ на слишком большое тело формы — `413`, а не `403`: превышение размера не является
  подозрением в подделке токена.

Контракт «все мутационные маршруты приложения покрыты этой проверкой» живёт в
`tests/contract/test_web_security_contract.py`: ADR-008 предупреждает, что типовая дыра этого
дизайна — забыть эндпоинт, который принимает `X-CSRF-Token`, но не проверяет его.
"""

from __future__ import annotations

from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from apps.web.security.csrf import (
    CSRF_FORM_FIELD,
    CSRF_HEADER,
    CSRF_LABEL,
    CSRF_META_NAME,
    csrf_token_for,
    expected_token,
)
from apps.web.security.sessions import SESSION_COOKIE_NAME, Principal
from packages.common.config import Settings
from packages.identity.sessions import revoke_session, rotate_session, token_secret
from packages.storage.models import UserSession
from tests.integration.web_support import (
    TEST_LOGIN,
    TEST_PASSWORD,
    MemoryStore,
    build_client,
    session_cookie,
)

ORIGIN_OURS = "https://testserver"


@pytest.fixture
def store() -> MemoryStore:
    memory = MemoryStore()
    memory.seed_user()
    return memory


@pytest.fixture
def client(store: MemoryStore, settings: Settings) -> TestClient:
    return build_client(store, settings)


def _войти(client: TestClient, store: MemoryStore) -> tuple[str, UserSession]:
    response = client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": TEST_PASSWORD},
        headers={"Origin": ORIGIN_OURS},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    secret = session_cookie(client)
    record = store.find_by_secret(secret)
    assert record is not None
    return secret, record


def _logout(
    client: TestClient,
    *,
    token: str | None = None,
    in_header: bool = False,
    headers: dict[str, str] | None = None,
    body: dict[str, str] | None = None,
) -> Response:
    """Отправить `/logout` — единственную мутацию этого среза, кроме самого `/login`."""
    sent_headers = dict(headers or {})
    sent_body = dict(body or {})
    if token is not None:
        if in_header:
            sent_headers[CSRF_HEADER] = token
        else:
            sent_body[CSRF_FORM_FIELD] = token
    posted: Response = client.post(
        "/logout", data=sent_body, headers=sent_headers, follow_redirects=False
    )
    return posted


# ─── обязательная проверка матрицы §8.8 ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "with_cookie",
    [True, False],  # живая сессия есть, токена нет / ни сессии, ни токена
    ids=["сессия_без_токена", "ни_сессии_ни_токена"],
)
def test_csrf_required(client: TestClient, store: MemoryStore, with_cookie: bool) -> None:
    """§8.8: «CSRF обязателен для всех POST/PUT/DELETE (тест «без токена → 403»)».

    Оба случая обязаны дать `403`, а не `200` с текстом и не `302` на страницу входа: страница,
    которая «вежливо» отправляет не прошедший проверку запрос на вход, превращает отказ в
    «попробуй ещё раз», и проверка перестает быть проверкой.
    """
    if with_cookie:
        _войти(client, store)
    else:
        client.cookies.clear()
    response = _logout(client, body={"любое": "поле"})
    assert response.status_code == 403, response.text


# ─── перенос токена (§8.3: скрытое поле и `X-CSRF-Token`) ─────────────────────────────────────


def test_токен_со_скрытым_полем_принимается(client: TestClient, store: MemoryStore) -> None:
    secret, record = _войти(client, store)
    token = expected_token(Principal(session=record, secret=secret))
    response = _logout(client, token=token, headers={"Origin": ORIGIN_OURS})
    assert response.status_code == 302
    assert response.headers["location"] == "/login"


def test_токен_в_заголовке_htmx_принимается(client: TestClient, store: MemoryStore) -> None:
    """§8.3 называет заголовок явно: HTMX досылает токен без формы."""
    secret, record = _войти(client, store)
    token = expected_token(Principal(session=record, secret=secret))
    response = _logout(client, token=token, in_header=True, headers={"Origin": ORIGIN_OURS})
    assert response.status_code == 302


def test_пустое_значение_токена_не_считается_предъявленным(
    client: TestClient, store: MemoryStore
) -> None:
    """Пустая строка в поле — это «токена нет», а не «токен не совпал».

    Разница важна для формы входа: она рендерится с пустым значением поля (ADR-009), и такой же
    пустой value в мутации обязан вести себя как отсутствующий токен, а не как попытка подбора.
    """
    secret, record = _войти(client, store)
    assert expected_token(Principal(session=record, secret=secret))
    response = _logout(client, headers={"Origin": ORIGIN_OURS}, body={CSRF_FORM_FIELD: ""})
    assert response.status_code == 403


def test_токен_в_строке_запроса_не_читается(client: TestClient, store: MemoryStore) -> None:
    """ADR-008: токен не передаётся строкой запроса — он утёк бы в `Referer` и в логи Caddy."""
    secret, record = _войти(client, store)
    token = expected_token(Principal(session=record, secret=secret))
    response = client.post(
        f"/logout?{CSRF_FORM_FIELD}={token}",
        headers={"Origin": ORIGIN_OURS},
        follow_redirects=False,
    )
    assert response.status_code == 403


# ─── вывод токена и его привязка к сессии (ADR-008) ───────────────────────────────────────────


def test_токен_выводится_из_пары_значение_куки_и_id_сессии() -> None:
    from uuid import UUID

    first_secret = token_secret()
    second_secret = token_secret()
    first_id = UUID(int=1)
    second_id = UUID(int=2)

    token = csrf_token_for(first_secret, first_id)
    assert len(token) == 43, "32 байта HMAC в base64url без «=»"
    assert token.isascii()
    assert all(
        char not in token for char in "+/="
    ), "base64url: значения не портятся экранированием"
    assert csrf_token_for(first_secret, first_id) == token, "вывод детерминирован"
    assert csrf_token_for(second_secret, first_id) != token
    assert csrf_token_for(first_secret, second_id) != token
    assert CSRF_LABEL == b"tbot-csrf-v1", "метку вывода меняет только отдельное решение (ADR-008)"


def test_чужой_токен_не_подходит(client: TestClient, store: MemoryStore) -> None:
    """Токен, выведенный из другой сессии, — отказ: привязка к паре (кука, `id`) работает."""
    secret, record = _войти(client, store)
    foreign = Principal(session=UserSession(id=record.id), secret=token_secret())
    response = _logout(client, token=expected_token(foreign), headers={"Origin": ORIGIN_OURS})
    assert response.status_code == 403


def test_пересоздание_сессии_делает_старый_токен_недействительным(
    client: TestClient, store: MemoryStore
) -> None:
    """ADR-008: `rotate_session` создаёт новую строку с новым `id`, и токен меняется сам."""
    secret, record = _войти(client, store)
    old_token = expected_token(Principal(session=record, secret=secret))
    issued = rotate_session(record, reason="password_change")
    store.add(issued.record)

    client.cookies.set(SESSION_COOKIE_NAME, issued.secret)
    stale = client.post(
        "/logout",
        data={CSRF_FORM_FIELD: old_token},
        headers={"Origin": ORIGIN_OURS},
        follow_redirects=False,
    )
    assert stale.status_code == 403, "старый токен не должен подходить к новой сессии"

    fresh = expected_token(Principal(session=issued.record, secret=issued.secret))
    ok = client.post(
        "/logout",
        data={CSRF_FORM_FIELD: fresh},
        headers={"Origin": ORIGIN_OURS},
        follow_redirects=False,
    )
    assert ok.status_code == 302


# ─── проверка источника (§8.3: «проверка origin») ─────────────────────────────────────────────


def test_чужой_origin_отклоняется_даже_с_верным_токеном(
    client: TestClient, store: MemoryStore
) -> None:
    secret, record = _войти(client, store)
    token = expected_token(Principal(session=record, secret=secret))
    response = _logout(client, token=token, headers={"Origin": "https://example.com"})
    assert response.status_code == 403, "§8.3: проверка origin"


def test_sec_fetch_site_чужой_источник_отклоняется(client: TestClient, store: MemoryStore) -> None:
    secret, record = _войти(client, store)
    token = expected_token(Principal(session=record, secret=secret))
    response = _logout(
        client,
        token=token,
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert response.status_code == 403


def test_одинаковый_origin_и_sec_fetch_site_не_противоречат_друг_другу(
    client: TestClient, store: MemoryStore
) -> None:
    secret, record = _войти(client, store)
    token = expected_token(Principal(session=record, secret=secret))
    response = _logout(
        client,
        token=token,
        headers={"Origin": ORIGIN_OURS, "Sec-Fetch-Site": "same-origin"},
    )
    assert response.status_code == 302


def test_без_заголовков_источника_токен_всё_равно_обязателен(
    client: TestClient, store: MemoryStore
) -> None:
    """Отсутствие `Origin`/`Sec-Fetch-Site` отключает второй слой, но не отменяет токен."""
    _войти(client, store)
    response = client.post("/logout", data={"любое": "поле"}, follow_redirects=False)
    assert response.status_code == 403


# ─── порядок: объяснение вместо отказа, если сессия была и умерла (§9) ────────────────────────


def test_мутация_с_мёртвой_сессией_ведёт_на_страницу_состояния(
    client: TestClient, store: MemoryStore
) -> None:
    """Токен предъявлен, сессия найдена, но она отозвана: пользователь обязан увидеть причину.

    Это не противоречит §8.8: там требуется `403` для запроса **без токена**. Когда токен есть, а
    сессия умерла, приложение знает причину и обязано её объяснить (§9), а не отвечать одно и то же
    и на подбор токена, и на собственную просрочку.
    """
    secret, record = _войти(client, store)
    token = expected_token(Principal(session=record, secret=secret))
    revoke_session(record)
    response = _logout(client, token=token, headers={"Origin": ORIGIN_OURS})
    assert response.status_code == 302
    assert response.headers["location"] == "/session-expired?reason=revoked"


def test_мутация_без_куки_но_с_токеном_остаётся_отказом(
    client: TestClient, store: MemoryStore
) -> None:
    """Без куки нечего сверять: объяснять нечего, поэтому `403`, а не редирект."""
    _войти(client, store)
    client.cookies.clear()
    response = _logout(client, token="z" * 43, headers={"Origin": ORIGIN_OURS})
    assert response.status_code == 403


def test_ответы_отказа_не_различаются_по_содержимому(
    client: TestClient, store: MemoryStore
) -> None:
    """Все отказные ветки CSRF дают одно и то же тело (ADR-008: «403 без подробностей»)."""
    secret, record = _войти(client, store)
    good_token = expected_token(Principal(session=record, secret=secret))

    no_token = _logout(client, headers={"Origin": ORIGIN_OURS})
    bad_token = _logout(client, token="z" * 43, headers={"Origin": ORIGIN_OURS})
    bad_origin = _logout(client, token=good_token, headers={"Origin": "https://evil.example"})

    bodies = {response.text for response in (no_token, bad_token, bad_origin)}
    assert {response.status_code for response in (no_token, bad_token, bad_origin)} == {403}
    assert (
        len(bodies) == 1
    ), "причина отказа не должна различаться по ответу: по ней ищут живой контур"
    for text in bodies:
        assert "csrf" not in text.lower()
        assert CSRF_HEADER.lower() not in text.lower()


# ─── безопасные методы и размер тела ──────────────────────────────────────────────────────────


def test_безопасные_методы_токена_не_требуют(client: TestClient) -> None:
    """GET не является мутацией: §8.3 требует токен на mutation-запросы."""
    assert client.get("/login").status_code == 200
    assert client.get("/session-expired").status_code == 200
    assert client.get("/healthz").status_code == 200


def test_слишком_большое_тело_даёт_413_а_не_403(client: TestClient, store: MemoryStore) -> None:
    """Превышение размера — не подозрение в подделке токена: коды разные по смыслу."""
    _войти(client, store)
    response = client.post(
        "/logout",
        data={"любое": "д" * 40000},
        headers={"Origin": ORIGIN_OURS},
        follow_redirects=False,
    )
    assert response.status_code == 413


def test_страница_входа_несёт_мета_токен_пустым(settings: Settings) -> None:
    """Форма входа не имеет токена сессии: мета и скрытое поле присутствуют, но пустые (ADR-009)."""
    client = build_client(MemoryStore(), settings)
    page = client.get("/login").text
    assert f'name="{CSRF_META_NAME}"' in page
    assert 'content=""' in page, "до входа токена нет, и шаблон обязан это показывать пустым value"
    assert 'name="csrf_token" value=""' in page


def test_мета_и_поле_для_активной_сессии_содержат_один_тот_же_токен() -> None:
    """`csrf_context` — единственный источник значения и для `<meta>`, и для скрытого поля."""
    from apps.web.security.csrf import csrf_context

    secret = token_secret()
    record = UserSession(id=UUID(int=7), token_hash="0" * 64, auth_step="full")
    principal = Principal(session=record, secret=secret)
    context = csrf_context(principal)
    assert context == {"csrf_token": expected_token(principal)}
    assert csrf_context(None) == {"csrf_token": ""}
