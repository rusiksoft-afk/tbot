"""Куки сессии, отзыв и страница состояния на HTTP-уровне (TZ §8.3, §9; `T-102`, срез `R3a`).

Половинка в памяти: приложение боевое (`create_app`), репозиторий — `MemoryStore`. Набор проверяет
решения слоя входа: атрибуты куки, направления редиректов, коды причин, немедленный отзыв, продление
idle, охрану шага входа. Живая база (поиск по `token_hash`, `CHECK` формата хэша, `INET`, фиксация
транзакции) — `tests/integration/test_web_identity_db.py`, который исполняется только в job
`migrations`.

Кука разбирается из заголовка `Set-Cookie`, а не только из cookie-хранилища клиента: TestClient
приводит куки к своему виду и прячет атрибуты, а §8.3 требует именно атрибутов (`HttpOnly`,
`Secure`, `SameSite=Lax`, путь `/`). Проверка, которая флага не видит, флаг и не проверяет.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from apps.web.routes.sessions import EXPLANATIONS, GENERIC_EXPLANATION
from apps.web.security.csrf import CSRF_FORM_FIELD, expected_token
from apps.web.security.sessions import (
    CONSOLE_PATH,
    COOKIE_PATH,
    COOKIE_SAMESITE,
    LOGIN_PATH,
    POST_LOGIN_REDIRECT,
    SESSION_COOKIE_NAME,
    TOTP_CODE_PATH,
    Principal,
    display_reason_codes,
)
from packages.common.clock import utc_now
from packages.common.config import Settings
from packages.identity.sessions import (
    SESSION_TOKEN_RE,
    advance_auth_step,
    token_hash_of,
    token_secret,
)
from packages.identity.users import LOCK_DURATION, MAX_FAILED_ATTEMPTS
from packages.storage.models import UserSession
from tests.integration.web_support import (
    TEST_LOGIN,
    TEST_PASSWORD,
    MemoryStore,
    build_client,
    login,
    session_cookie,
    timing_spy,
)

#: Признаки «кука живёт до закрытия браузера». Их отсутствие — часть решения §8.3: срок держит база.
LIFETIME_MARKERS = ("max-age", "expires=")


@pytest.fixture
def store() -> MemoryStore:
    memory = MemoryStore()
    memory.seed_user()
    return memory


@pytest.fixture
def client(store: MemoryStore, settings: Settings) -> Iterator[TestClient]:
    with build_client(store, settings, with_probe=True) as test_client:
        yield test_client


def _session_set_cookie(response: Response) -> str:
    """Полный `Set-Cookie` куки сессии: проверяем атрибуты, а не только значение."""
    headers = [
        value
        for value in response.headers.get_list("set-cookie")
        if value.startswith(f"{SESSION_COOKIE_NAME}=")
    ]
    assert headers, f"в ответе нет куки {SESSION_COOKIE_NAME}"
    return headers[0]


def _войти(client: TestClient, store: MemoryStore) -> str:
    """Войти маршрутом входа и вернуть выданное значение куки."""
    response = client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": TEST_PASSWORD},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    secret = session_cookie(client)
    assert secret, "после входа куки нет"
    assert store.find_by_secret(secret) is not None
    return secret


# ─── форма и атрибуты куки (§8.3) ──────────────────────────────────────────────────────────────


def test_кука_выдаётся_с_атрибутами_из_8_3(client: TestClient) -> None:
    response = login(client)
    assert response.status_code == 302, response.text
    header = _session_set_cookie(response).lower()
    assert "httponly" in header, "§8.3: кука обязана быть HttpOnly"
    assert "secure" in header, "§8.3: кука обязана быть Secure"
    assert f"samesite={COOKIE_SAMESITE}" in header, "§8.3: SameSite=Lax"
    assert f"path={COOKIE_PATH}" in header, "§8.3: путь /"
    for marker in LIFETIME_MARKERS:
        assert marker not in header, (
            "у куки сессии не должно быть Max-Age/Expires: срок держит база "
            "(`expires_at`, `created_at`, `revoked_at`), а долговременная кука переживает "
            "мёртвую сессию"
        )


def test_значение_куки_256_бит_а_в_репозитории_только_хэш(
    client: TestClient, store: MemoryStore
) -> None:
    secret = _войти(client, store)
    assert SESSION_TOKEN_RE.fullmatch(secret), "§8.3: 43 символа base64url без «=»"
    record = store.find_by_secret(secret)
    assert record is not None
    assert record.token_hash == token_hash_of(secret)
    assert record.token_hash != secret, "в репозитории не должно быть значения куки"
    # значение куки никогда не уходит в поиск: следующий аутентифицированный запрос смотрит по хэшу
    assert client.get("/probe-full", follow_redirects=False).status_code == 302
    assert store.hash_lookups == [token_hash_of(secret)]
    assert secret not in store.hash_lookups


def test_после_входа_сессия_на_шаге_password(client: TestClient, store: MemoryStore) -> None:
    """§8.2: парольный шаг полного доступа не даёт. Редирект — на `POST_LOGIN_REDIRECT`."""
    response = login(client)
    assert response.headers["location"] == POST_LOGIN_REDIRECT
    records = store.sessions()
    assert len(records) == 1
    assert records[0].auth_step == "password"


def test_адрес_из_x_forwarded_for_правый_элемент_и_user_agent_с_ограничением(
    client: TestClient, store: MemoryStore
) -> None:
    """ADR-007: адрес — правый элемент `X-Forwarded-For`, который добавил наш Caddy.

    Левый элемент присылает клиент, и он подделываем. Заодно проверяется ограничение длины
    `user_agent`: значение показывают пользователю в списке устройств (§8.3), и «как прислал
    клиент» означало бы неограниченную строку в базе.
    """
    client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": TEST_PASSWORD},
        headers={
            "Origin": "https://testserver",
            "X-Forwarded-For": "203.0.113.66, 198.51.100.7",
            "User-Agent": "a" * 900,
        },
        follow_redirects=False,
    )
    record = store.sessions()[0]
    assert record.ip == "198.51.100.7"
    assert record.user_agent is not None
    assert len(record.user_agent) == 256


# ─── отказ входа и перебор (§8.1, §9) ─────────────────────────────────────────────────────────


def test_неверный_пароль_и_неизвестный_логин_отвечают_одинаково(client: TestClient) -> None:
    wrong_password = client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": "не-тот-пароль-12345"},
        headers={"Origin": "https://testserver"},
    )
    unknown_login = client.post(
        "/login",
        data={"login": "нет-такой-учётки", "password": "какой-нибудь-пароль-12"},
        headers={"Origin": "https://testserver"},
    )
    assert wrong_password.status_code == 401
    assert unknown_login.status_code == 401
    assert wrong_password.text == unknown_login.text, (
        "ответ не должен различать «нет логина» и «неверный пароль»: страница входа публичная, "
        "а закрытый допуск (§1.2) не позволяет проверять существование учётной записи"
    )


def test_неизвестный_логин_тратит_стоимость_хэширования(client: TestClient) -> None:
    """Ветка «логина нет» обязана тратить стоимость Argon2id (§8.1).

    Иначе существование учётной записи определяется по времени ответа — а это ровно тот контур,
    который §8.1 закрывает блокировкой перебора. Замер времени в тесте нестабилен, поэтому
    проверяется сам факт обращения (`LoginTiming` подменён шпионом в `build_client`).
    """
    client.post(
        "/login",
        data={"login": "вочно-нет-такого", "password": "какой-то-пароль-1234"},
        headers={"Origin": "https://testserver"},
    )
    assert timing_spy(client).burned == ["какой-то-пароль-1234"]


def test_пять_неудач_блокируют_вход_с_объяснением_и_retry_after(
    client: TestClient, store: MemoryStore
) -> None:
    """§8.1 на HTTP-уровне: пять неудач → блокировка, объяснение и `Retry-After` (§9).

    Главное следствие блокировки проверяется отдельно: верный пароль во время блокировки вход всё
    равно не даёт, потому что `ensure_login_allowed` стоит до сравнения пароля.
    """
    user = store.user_by_login(TEST_LOGIN)
    assert user is not None
    response = None
    for _ in range(MAX_FAILED_ATTEMPTS):
        response = client.post(
            "/login",
            data={"login": TEST_LOGIN, "password": "не-тот-пароль-12345"},
            headers={"Origin": "https://testserver"},
        )
    assert response is not None
    assert response.status_code == 429
    retry_after = int(response.headers["retry-after"])
    assert 0 < retry_after <= int(LOCK_DURATION.total_seconds())
    assert "заблокирован" in response.text, "§9: блокировка объясняется, а не показывается кодом"

    with_correct_password = login(client)
    assert (
        with_correct_password.status_code == 429
    ), "пока блокировка активна, пароль не сравнивается вообще (`T-101`)"
    assert user.locked_until is not None
    assert user.failed_attempts < MAX_FAILED_ATTEMPTS, (
        "наступившая блокировка обнуляет счётчик: иначе после разблокировки одна неудача "
        "блокировала бы вход снова"
    )


def test_пустая_форма_не_двигает_счётчик_неудач(client: TestClient, store: MemoryStore) -> None:
    user = store.user_by_login(TEST_LOGIN)
    assert user is not None
    response = client.post(
        "/login", data={"login": "", "password": ""}, headers={"Origin": "https://testserver"}
    )
    assert response.status_code == 400
    assert user.failed_attempts == 0
    assert user.locked_until is None


# ─── сессия не подходит: направления и причины (§8.3, §9) ─────────────────────────────────────


def test_без_куки_охраняемый_маршрут_ведёт_на_вход(client: TestClient) -> None:
    response = client.get("/probe-full", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/login"
    assert not [
        value
        for value in response.headers.get_list("set-cookie")
        if value.startswith(f"{SESSION_COOKIE_NAME}=")
    ], "стирать нечего: куки не было"


def test_испорченную_куку_стирают(client: TestClient) -> None:
    """Значение не разбирается как выпущенное → на вход и стереть.

    Без стирания объяснение показывалось бы бесконечно, пока пользователь не удалит куку руками.

    Заголовок `Cookie` — ASCII, поэтому значение берётся корректной кодировки, но неверной формы:
    10 символов вместо 43 base64url-символов.
    """
    client.cookies.set(SESSION_COOKIE_NAME, "cut-cookie")
    response = client.get("/probe-full", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/login"
    header = _session_set_cookie(response)
    assert "cut-cookie" not in header
    assert "max-age=0" in header.lower()


def test_кука_корректной_формы_без_записи_даёт_причину_unknown(client: TestClient) -> None:
    """Значение куки разобрано, а записи сессии нет: причина `unknown` (её нет в доменных кодах)."""
    client.cookies.set(SESSION_COOKIE_NAME, token_secret())
    response = client.get("/probe-full", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/session-expired?reason=unknown"


def test_отзыв_отражается_немедленно(client: TestClient, store: MemoryStore) -> None:
    """§8.3: «отзыв отражается немедленно» — `revoked_at` проверяется на каждом запросе."""
    secret = _войти(client, store)
    assert client.get("/probe-full", follow_redirects=False).status_code == 302  # шаг 'password'

    record = store.find_by_secret(secret)
    assert record is not None
    advance_auth_step(record, step="full")
    assert client.get("/probe-full", follow_redirects=False).status_code == 200

    record.revoked_at = utc_now()
    after = client.get("/probe-full", follow_redirects=False)
    assert after.status_code == 302
    assert after.headers["location"] == "/session-expired?reason=revoked"


@pytest.mark.parametrize(
    ("reason", "created_shift", "expires_shift"),
    [
        ("idle", timedelta(hours=-1), timedelta(minutes=-5)),
        ("absolute", timedelta(hours=-13), timedelta(hours=-2)),
        ("not_yet", timedelta(minutes=5), timedelta(minutes=35)),
    ],
)
def test_границы_сроков_называют_свою_причину(
    client: TestClient,
    store: MemoryStore,
    reason: str,
    created_shift: timedelta,
    expires_shift: timedelta,
) -> None:
    """Каждая граница (§8.3) называется своей причиной, а не общей «сессии нет».

    `idle` — просрочка скользящей границы при живом абсолютном сроке; `absolute` — просрочка
    абсолютного срока; `not_yet` — запись «из будущего» (расхождение часов приложения и базы).
    Порядок проверок в домене именно такой, поэтому у сессии с просроченными обоими сроками
    показывается `absolute`, а не `idle`: продлить такую сессию нельзя.
    """
    secret = _войти(client, store)
    record = store.find_by_secret(secret)
    assert record is not None
    advance_auth_step(record, step="full")
    moment = utc_now()
    record.created_at = moment + created_shift
    record.expires_at = moment + expires_shift
    client.cookies.set(SESSION_COOKIE_NAME, secret)

    response = client.get("/probe-full", follow_redirects=False)
    assert response.status_code == 302, f"{reason}: ожидался редирект, получено {response.text}"
    assert response.headers["location"] == f"/session-expired?reason={reason}"


def test_сессии_с_истёкшими_обоими_сроками_показывают_absolute(
    client: TestClient, store: MemoryStore
) -> None:
    """Порядок проверок закреплён: у «мёртвой по обоим срокам» сессии причина — абсолютный срок."""
    secret = _войти(client, store)
    record = store.find_by_secret(secret)
    assert record is not None
    moment = utc_now()
    record.created_at = moment - timedelta(hours=20)
    record.expires_at = moment - timedelta(minutes=5)
    client.cookies.set(SESSION_COOKIE_NAME, secret)
    response = client.get("/probe-full", follow_redirects=False)
    assert response.headers["location"] == "/session-expired?reason=absolute"


def test_охраняемый_маршрут_не_пускает_сессию_на_шаге_password(
    client: TestClient, store: MemoryStore
) -> None:
    """§8.2: шага `'password'` мало (проверка на маршруте-щупе, см. `probe_router`).

    Ведёт на страницу кода: с `T-103` она существует, и это единственное, что доступно шагу
    пароля (кроме `/logout`). Прежняя цель — `/login` — была заменой отсутствующей страницы;
    теперь возврат на вход создал бы вторую сессию у человека, который уже ввёл верный пароль.
    """
    _войти(client, store)
    response = client.get("/probe-full", follow_redirects=False)
    assert response.status_code == 302
    assert (
        response.headers["location"] == TOTP_CODE_PATH
    ), "шаг 'password' обязан вести на страницу кода (§8.2)"
    assert response.headers["location"] not in {
        CONSOLE_PATH,
        LOGIN_PATH,
    }, "охраняемый маршрут нельзя ни открывать шагу пароля, ни откатывать в начало входа"


def test_шаг_full_открывает_охраняемый_маршрут(client: TestClient, store: MemoryStore) -> None:
    secret = _войти(client, store)
    record = store.find_by_secret(secret)
    assert record is not None
    advance_auth_step(record, step="full")
    response = client.get("/probe-full", follow_redirects=False)
    assert response.status_code == 200
    assert response.json()["session_id"] == str(record.id)


def test_охраняемый_маршрут_продлевает_idle(client: TestClient, store: MemoryStore) -> None:
    """§8.3: idle считается от последней активности; охраняемый запрос продлевает границу."""
    secret = _войти(client, store)
    record = store.find_by_secret(secret)
    assert record is not None
    advance_auth_step(record, step="full")
    record.expires_at = utc_now() + timedelta(minutes=2)
    response = client.get("/probe-full", follow_redirects=False)
    assert response.status_code == 200
    assert record.expires_at > utc_now() + timedelta(minutes=29)


def test_продление_одним_обращением_и_одним_коммитом(
    client: TestClient, store: MemoryStore
) -> None:
    """Защищённый маршрут ищет сессию один раз и фиксирует продление одним коммитом.

    ADR-007 предупреждает: каждый лимитируемый запрос стоит запись в базу. Здесь проверяется, что
    слой входа не превращает один запрос в серию обращений — иначе лимиты и нагрузка расходятся.
    """
    secret = _войти(client, store)
    record = store.find_by_secret(secret)
    assert record is not None
    advance_auth_step(record, step="full")
    store.commits = 0
    store.hash_lookups.clear()
    response = client.get("/probe-full", follow_redirects=False)
    assert response.status_code == 200
    assert store.commits == 1
    assert len(store.hash_lookups) == 1


# ─── выход (§8.3) ──────────────────────────────────────────────────────────────────────────────


def test_выход_отзывает_сессию_и_стирает_куку(client: TestClient, store: MemoryStore) -> None:
    secret = _войти(client, store)
    record = store.find_by_secret(secret)
    assert record is not None
    token = expected_token(Principal(session=record, secret=secret))

    response = client.post(
        "/logout",
        data={CSRF_FORM_FIELD: token},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/login"
    assert record.revoked_at is not None, (
        "выход обязан отозвать сессию в базе, а не только стереть куку: §8.3 требует немедленной "
        "видимости отзыва, и запрос с сохранённой копией куки обязан быть отклонён"
    )
    assert "max-age=0" in _session_set_cookie(response).lower()

    client.cookies.set(SESSION_COOKIE_NAME, secret)
    again = client.get("/probe-full", follow_redirects=False)
    assert again.status_code == 302
    assert again.headers["location"] == "/session-expired?reason=revoked"


# ─── страница состояния (§9) ───────────────────────────────────────────────────────────────────


def test_страница_состояния_объясняет_каждую_причину() -> None:
    """Каждая причина из закрытого набора имеет объяснение (§9: состояния внятные)."""
    codes = display_reason_codes()
    assert codes == {*EXPLANATIONS}, "набор объяснений обязан совпадать с закрытым набором причин"
    for code in sorted(codes):
        assert EXPLANATIONS[code] != GENERIC_EXPLANATION
        assert len(EXPLANATIONS[code]) > 40


def test_неизвестная_причина_не_подставляется_в_текст(settings: Settings) -> None:
    """Значение `reason` вне закрытого набора не попадает в страницу.

    Иначе страница состояния стала бы каналом для чужого текста, а проверка §8.8 «XSS в полях не
    исполняется» ломалась бы об собственный шаблон.
    """
    client = build_client(MemoryStore(), settings)
    response = client.get("/session-expired?reason=%3Cscript%3Eподозрительное%3C/script%3E")
    assert response.status_code == 200
    assert "подозрительное" not in response.text
    assert "<script>" not in response.text


def test_страница_входа_отдаётся_без_сессии_и_содержит_скрытое_поле(settings: Settings) -> None:
    client = build_client(MemoryStore(), settings)
    response = client.get("/login")
    assert response.status_code == 200
    assert 'name="csrf_token"' in response.text, "скрытое поле токена (§8.3) должно быть в форме"
    assert 'name="login"' in response.text
    assert 'name="password"' in response.text


def test_страницы_не_печатают_материал_сессии(client: TestClient, store: MemoryStore) -> None:
    """Ни страница входа, ни страница состояния не печатают значение куки и его хэш."""
    secret = _войти(client, store)
    record = store.find_by_secret(secret)
    assert record is not None
    page = client.get("/session-expired?reason=revoked").text
    assert secret not in page
    assert record.token_hash not in page


def test_у_записи_сессии_нет_колонки_для_csrf_токена(
    client: TestClient, store: MemoryStore
) -> None:
    """ADR-008: токен выводится из сессии и нигде не хранится."""
    _войти(client, store)
    columns = {column.name for column in UserSession.__table__.columns}
    assert not any("csrf" in name for name in columns), "токен выводится, а не хранится"
    assert "token_hash" in columns
