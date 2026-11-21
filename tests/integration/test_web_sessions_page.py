"""Список сессий и отзыв по одной/всех на HTTP-уровне (TZ §8.3, §9; `T-102`, срез `R3e`).

Половинка в памяти, как у остальных проверок слоя входа: приложение боевое (`create_app`),
репозиторий — `MemoryStore`. Живая база (ограничение `user_id` внутри SQL, чтение `INET`,
предикат `expires_at >` по индексу, фиксация отзыва в таблице) —
`tests/integration/test_web_sessions_db.py`, который исполняется только в job `миграции`.

Что проверяется и почему это важно:

* **шаг входа охраняет и просмотр, и отзыв** (§8.2). Тот, кто знает только пароль, не должен уметь
  выгнать все живые входы владельца: отзыв чужих сессий — это отказ в обслуживании, а не «меню»;
* **список показывает ровно тот набор, который можно отозвать**, и не показывает ни отозванного,
  ни просроченного, ни «сессии из будущего» — при этом кандидатами запрос считает одно и то же, что
  и страница отзыва (иначе ссылка вела бы на строку, которую отзыв отказывается видеть);
* **чужой, кривой и уже завершившийся `id` отвечают одним и тем же `404`** (§8.8: «чужие данные →
  403/404 без утечки»);
* **чужую сессию отозвать нельзя, и её состояние не меняется** — проверка не только ответа, но и
  состояния той самой чужой сессии в репозитории;
* **`GET` подтверждения ничего не меняет**, отзыв делает только `POST` с CSRF-токеном (§9.1, §8.8);
* **«отозвать все» включает текущую сессию**: ответ — страница состояния с причиной `revoked`, кука
  стёрта, чужие сессии не затронуты, уже завершённые не помечаются отозванными задним числом;
* **материала сессии на странице нет** (§8.4): ни значения куки, ни его хэша; `user_agent`
  экранируется (§8.8 «XSS в полях не исполняется»), а адрес печатается каноническим текстом
  (`ADR-009`).

Момент времени заморожен (`FROZEN`), а границы выводятся из него — тот же канон, что у проверок
лимитов: границы обязан задавать тест, а не секунда запуска прогона.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from httpx import Response

import apps.web.routes.login as login_routes
import apps.web.routes.sessions as session_routes
import apps.web.security.rate_limit as rate_limit_module
import apps.web.security.sessions as security_sessions
from apps.web.routes.sessions import (
    CURRENT_SESSION_LABEL,
    GENERIC_EXPLANATION,
    GONE_DETAIL,
    REVOKE_ALL_NOTE,
    REVOKE_ALL_WARNING,
    REVOKE_CURRENT_WARNING,
    REVOKE_OTHER_WARNING,
    UNKNOWN_ADDRESS_LABEL,
    UNKNOWN_DEVICE_LABEL,
    _human_moment,
)
from apps.web.security.csrf import CSRF_FORM_FIELD, expected_token
from apps.web.security.sessions import (
    LOGIN_PATH,
    POST_LOGIN_REDIRECT,
    REASON_QUERY,
    SESSION_COOKIE_NAME,
    SESSION_EXPIRED_PATH,
    SESSIONS_PATH,
    SESSIONS_REVOKE_ALL_PATH,
    Principal,
)
from packages.common.config import Settings
from packages.identity.sessions import (
    IDLE_TIMEOUT,
    advance_auth_step,
    create_session,
    revoke_session,
    token_hash_of,
)
from packages.identity.users import new_user
from packages.storage.models import User, UserSession
from tests.integration.web_support import (
    TEST_LOGIN,
    TEST_PASSWORD,
    MemoryStore,
    build_client,
    session_cookie,
)

#: Замороженный «сейчас» (см. модульный докстринг). Основой служит реальное время: доменные функции,
#: которые тест вызывает напрямую, сравнивают `created_at` с настоящими часами.
FROZEN = datetime.now(UTC).replace(microsecond=0)

#: Живая сессия из фикстуры: срок = `FROZEN + idle`, то есть живая при замороженном моменте.
LIVE_UNTIL = FROZEN + IDLE_TIMEOUT

#: Устройства-маркеры: по ним проверка узнаёт строки списка. Значение `user_agent` приходит из
#: заголовка и печатается как есть (с ограничением длины), поэтому оно удобно в качестве маркера.
DEVICE_OWN = "laptop-dev"
DEVICE_FOREIGN = "other-account-device"
DEVICE_OTHER = "phone-dev"


class Clock:
    """Подменённое «сейчас»: тест сдвигает время сам и знает, что он при этом проверяет."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def move_to(self, moment: datetime) -> None:
        self.now = moment


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Замораживает `utc_now()` во всех модулях среза, где он вызывается.

    Подменяются маршруты входа и сессий, слой сессий и механизм лимитов: пропуск любого из них
    означал бы, что часть проверок живёт в реальном времени, а часть — в замороженном, и вывод по
    ним был бы неотличим от случайности.
    """
    fake = Clock(FROZEN)
    for module in (login_routes, session_routes, security_sessions, rate_limit_module):
        monkeypatch.setattr(module, "utc_now", fake)
    return fake


@pytest.fixture
def store() -> MemoryStore:
    memory = MemoryStore()
    owner = memory.seed_user()
    # Первичный ключ обязан быть заполнен явно: в памяти нет `INSERT`, поэтому `DEFAULT` движка
    # не срабатывает, и `user.id` остался бы `None` (тот же урок, что с `failed_attempts` в `T-101`
    # и с `id` сессии в `create_session`). Без ключа проверка изоляции (§8.8) сравнивала бы `None`
    # с `None` и проходила бы молча.
    owner.id = uuid.uuid4()
    return memory


@pytest.fixture
def client(store: MemoryStore, settings: Settings, clock: Clock) -> Iterator[TestClient]:
    # Замороженный момент обязан совпадать с ожиданиями модуля: если фикстура сдвинула время,
    # а тест ждёт `FROZEN`, вывод перестает быть проверяемым.
    assert clock() == FROZEN
    with build_client(store, settings, with_probe=True) as test_client:
        yield test_client


# ─── помощники ────────────────────────────────────────────────────────────────────────────────


def _user(store: MemoryStore, *, login: str) -> User:
    """Вторая учётная запись: нужна проверкам изоляции (§8.8). Ключ — явно, см. фикстуру `store`."""
    user = new_user(login=login, password=TEST_PASSWORD, role="operator", state="active")
    user.id = uuid.uuid4()
    store.add(user)
    return user


def _issue(
    store: MemoryStore,
    user_id: uuid.UUID,
    *,
    device: str,
    ip: str | None = "198.51.100.7",
    created: datetime = FROZEN,
    expires: datetime = LIVE_UNTIL,
) -> UserSession:
    """Выпустить сессию мимо HTTP и положить её в репозиторий.

    Так сессию выпустит `T-117` (включение Telegram) и так же она появляется при входе: набор
    правил живости от способа выпуска не зависит. `created`/`expires` задаёт тест, чтобы границы
    «жива / не жива» были задаваемыми, а не следованием секунде запуска.
    """
    issued = create_session(user_id, ip=ip, user_agent=device, auth_step="full", now=created)
    issued.record.expires_at = expires
    store.seed_session(issued)
    return issued.record


def _login(client: TestClient, *, device: str = DEVICE_OWN) -> str:
    """Войти маршрутом входа и вернуть значение куки (шаг `'password'`, §8.2)."""
    response = client.post(
        "/login",
        data={"login": TEST_LOGIN, "password": TEST_PASSWORD},
        headers={"Origin": "https://testserver", "User-Agent": device},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    secret = session_cookie(client)
    assert secret, "после входа куки нет"
    return secret


def _record(store: MemoryStore, secret: str) -> UserSession:
    record = store.find_by_secret(secret)
    assert record is not None, "сессия входа не найдена в репозитории"
    return record


def _full(store: MemoryStore, secret: str) -> UserSession:
    """Поднять шаг до `'full'`: страница кода появляется в `T-103`.

    Правка идёт по объекту в репозитории, а не маршрутом: маршрута кода в этом срезе нет, и
    поднимать шаг «как получится» значило бы писать проверку несуществующего маршрута.
    """
    record = _record(store, secret)
    advance_auth_step(record, step="full", now=FROZEN)
    return record


def _token(secret: str, record: UserSession) -> str:
    """CSRF-токен предъявителя (§8.3, ADR-008): выводится из пары «значение куки, `id` сессии»."""
    return expected_token(Principal(session=record, secret=secret))


def _revoke_url(session_id: uuid.UUID | str) -> str:
    return f"{SESSIONS_PATH}/{session_id}/revoke"


def _post_revoke(
    client: TestClient,
    secret: str,
    record: UserSession,
    target: uuid.UUID | str,
    *,
    present: bool = True,
) -> Response:
    """POST отзыва с CSRF-токеном (`present=False` — «токена нет», проверка матрицы §8.8).

    Имя параметра — `present`, а не «токен со значением по умолчанию»: анализатор читает параметр
    вида `token="auto"` как жёстко заданный секрет (S107), а секреты в этом файле — как раз токены.
    """
    headers = {"Origin": "https://testserver"}
    data: dict[str, str] = {}
    if present:
        data[CSRF_FORM_FIELD] = _token(secret, record)
    response: Response = client.post(
        _revoke_url(target), data=data, headers=headers, follow_redirects=False
    )
    return response


def _session_set_cookies(response: Response) -> list[str]:
    return [
        value
        for value in response.headers.get_list("set-cookie")
        if value.startswith(f"{SESSION_COOKIE_NAME}=")
    ]


def _rows(html: str) -> list[str]:
    """Метки устройств, попавшие в список, в порядке разметки.

    Разбор наивный и это осознанно: проверке нужно «какие строки напечатаны», а не валидатор HTML.
    """
    return [device for device in (DEVICE_OWN, DEVICE_FOREIGN, DEVICE_OTHER) if device in html]


# ─── доступ к списку (§8.2, §8.3) ────────────────────────────────────────────────────────────


def test_список_требует_полного_входа(client: TestClient, store: MemoryStore) -> None:
    """§8.2: на шаге `'password'` доступны страница кода и `/logout`, остальное — нет.

    Здесь же — проверка, что отказ не изменил состояние: страница, которая отказывает, но уже
    что-то отозвала, была бы хуже отсутствия страницы.
    """
    secret = _login(client)
    other = _issue(store, _record(store, secret).user_id, device=DEVICE_OTHER)

    response = client.get(SESSIONS_PATH, follow_redirects=False)
    assert response.status_code == 302
    assert (
        response.headers["location"] == LOGIN_PATH
    ), "шаг 'password' ведёт на страницу входа (§8.2)"
    assert (
        response.headers["location"] != POST_LOGIN_REDIRECT
    ), "список не должен пускать шаг 'password' дальше страницы входа"
    assert other.revoked_at is None
    assert _record(store, secret).revoked_at is None


def test_список_отдаётся_при_полном_входе(client: TestClient, store: MemoryStore) -> None:
    secret = _login(client)
    _full(store, secret)

    response = client.get(SESSIONS_PATH)
    assert response.status_code == 200, response.text
    assert "Живые сеансы этой учётной записи" in response.text
    assert DEVICE_OWN in response.text


def test_чужие_сессии_в_список_не_попадают(client: TestClient, store: MemoryStore) -> None:
    """§8.3 показывает пользователю его собственные сессии; `REQ-web-02` — чужих данных нет."""
    secret = _login(client)
    _full(store, secret)
    foreign = _user(store, login="chuzhaya-uchetka")
    _issue(store, foreign.id, device=DEVICE_FOREIGN)

    response = client.get(SESSIONS_PATH)
    assert response.status_code == 200, response.text
    assert _rows(response.text) == [DEVICE_OWN]
    assert DEVICE_FOREIGN not in response.text


def test_на_странице_нет_значения_куки_и_его_хэша(client: TestClient, store: MemoryStore) -> None:
    """§8.4: материал доступа не попадает ни в вывод, ни в логи.

    Хэш — тоже материал: по нему ищут сессию (`§8.3`), поэтому «в списке только хэш» защитой не
    является.
    """
    secret = _login(client)
    _full(store, secret)
    record = _record(store, secret)

    html = client.get(SESSIONS_PATH).text
    confirm = client.get(_revoke_url(record.id)).text
    for page in (html, confirm):
        assert secret not in page
        assert record.token_hash not in page
        assert token_hash_of(secret) not in page
        assert SESSION_COOKIE_NAME not in page


def test_отозванная_и_просроченная_сессии_не_показываются(
    client: TestClient, store: MemoryStore
) -> None:
    """Список держит набор «что можно отозвать» (§9.3 п. 4: «список активных сессий … с отзывом»)."""
    secret = _login(client)
    _full(store, secret)
    user_id = _record(store, secret).user_id

    stale = _issue(store, user_id, device="старый-телефон", expires=FROZEN - timedelta(minutes=1))
    dead = _issue(store, user_id, device="уже-отозванный")
    revoke_session(dead, now=FROZEN)

    response = client.get(SESSIONS_PATH)
    assert response.status_code == 200, response.text
    for device in ("старый-телефон", "уже-отозванный"):
        assert device not in response.text, "список показал сеанс, который нельзя отозвать"
    # обе строки в репозитории остаются: страница их не показывает, а не удаляет
    assert stale.revoked_at is None
    assert dead.revoked_at is not None


def test_сессия_из_будущего_не_показывается_но_остаётся_кандидатом(
    client: TestClient, store: MemoryStore
) -> None:
    """Расхождение часов (`not_yet`): показывать нельзя, отзывать — можно.

    Репозиторий возвращает такую строку (её `expires_at` в будущем), а живость отвергает домен
    (§8.3). Если бы страница полагалась только на запрос, сеанс с «отметкой из будущего» появился
    бы в списке как живой.
    """
    secret = _login(client)
    _full(store, secret)
    user_id = _record(store, secret).user_id
    future = FROZEN + timedelta(minutes=5)
    _issue(store, user_id, device="кривые-часы", created=future, expires=future + IDLE_TIMEOUT)

    assert "кривые-часы" not in client.get(SESSIONS_PATH).text
    assert store.user_sessions(
        user_id, not_expired_before=FROZEN
    ), "кандидатом остаётся: отзыв всех обязан убрать и такую строку"

    # §9.1: подтверждение обязано называть объект. Спрятанная в списке строка на странице
    # подтверждения видна: показанное совпадает с отзываемым, а не «показали одно, отозвали другое».
    confirm = client.get(SESSIONS_REVOKE_ALL_PATH)
    assert confirm.status_code == 200, confirm.text
    assert (
        "кривые-часы" in confirm.text
    ), "страница «отзыв всех» перечисляет только отображаемый список, хотя отзыв снимет шире набор"


def test_текущая_сессия_помечена(client: TestClient, store: MemoryStore) -> None:
    secret = _login(client)
    _full(store, secret)
    other = _issue(store, _record(store, secret).user_id, device=DEVICE_OTHER)

    html = client.get(SESSIONS_PATH).text
    assert html.count(CURRENT_SESSION_LABEL) == 1
    assert _revoke_url(other.id) in html, "у другой сессии обязан быть отзыв по одной (§8.3)"


def test_адрес_устройство_и_время_подписаны(client: TestClient, store: MemoryStore) -> None:
    """§9.1: время по Москве с подписью; `ADR-009`: адрес — канонический текст, а не объект."""
    secret = _login(client)
    _full(store, secret)
    record = _record(store, secret)
    record.ip = "198.51.100.7"
    record.created_at = FROZEN
    record.last_seen_at = FROZEN
    record.expires_at = LIVE_UNTIL

    html = client.get(SESSIONS_PATH).text
    assert "198.51.100.7" in html
    assert _human_moment(FROZEN) in html
    assert "МСК" in html
    assert FROZEN.isoformat() not in html, "в списке не должно быть сырых ISO-меток без подписи"


def test_пустые_поля_подписываются_a_не_пустотой(client: TestClient, store: MemoryStore) -> None:
    """`user_agent` и адрес могут отсутствовать: пустая ячейка неотличима от потери значения."""
    secret = _login(client, device="")
    _full(store, secret)
    record = _record(store, secret)
    record.user_agent = None
    record.ip = None

    html = client.get(SESSIONS_PATH).text
    assert UNKNOWN_DEVICE_LABEL in html
    assert UNKNOWN_ADDRESS_LABEL in html


def test_user_agent_экранируется(client: TestClient, store: MemoryStore) -> None:
    """§8.8: «XSS в полях (name, comment, reason) не исполняется» — поле устройства то же самое.

    Значение присылает клиент; ограничено оно по длине, но не по содержанию, поэтому проверка
    обязана видеть и экранирование, и отсутствие сырого тега.
    """
    secret = _login(client)
    _full(store, secret)
    record = _record(store, secret)
    record.user_agent = "<script>alert(1)</script>"

    html = client.get(SESSIONS_PATH).text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>" not in html, "страница не должна добавлять скрипты сама (§8.3 CSP)"


def test_ссылки_отзыва_ведут_на_подтверждение(client: TestClient, store: MemoryStore) -> None:
    """Ссылка из списка ведёт на страницу подтверждения, а не на мутацию (§9.1)."""
    secret = _login(client)
    _full(store, secret)
    other = _issue(store, _record(store, secret).user_id, device=DEVICE_OTHER)

    html = client.get(SESSIONS_PATH).text
    assert f'href="{_revoke_url(other.id)}"' in html
    assert f'href="{SESSIONS_REVOKE_ALL_PATH}"' in html


# ─── страница подтверждения (§9.1: подтверждение с указанием объекта) ────────────────


def test_подтверждение_ничего_не_отзывает(client: TestClient, store: MemoryStore) -> None:
    """Безопасный метод обязан уметь открывать страницу отзыва без последствия.

    Ссылку подтверждения открывают повторно, по истории браузера, prefetch-ом бота. Если бы
    `GET` отзывал, страница подтверждения стала бы каналом отзыва: достаточно, чтобы кто-то
    открыл ссылку.
    """
    secret = _login(client)
    _full(store, secret)
    other = _issue(store, _record(store, secret).user_id, device=DEVICE_OTHER)

    page = client.get(_revoke_url(other.id))
    assert page.status_code == 200, page.text
    assert other.revoked_at is None, "`GET` подтверждения не имеет права менять состояние"

    # повторное открытие страницы тоже ничего не меняет
    client.get(_revoke_url(other.id))
    assert other.revoked_at is None


def test_подтверждение_называет_объект_и_последствие(
    client: TestClient, store: MemoryStore
) -> None:
    """§9.1: подтверждение обязано указывать объект; здесь объект назван полностью."""
    secret = _login(client)
    _full(store, secret)
    other = _issue(store, _record(store, secret).user_id, device=DEVICE_OTHER)
    other.ip = "203.0.113.9"
    other.created_at = FROZEN
    other.last_seen_at = FROZEN

    page = client.get(_revoke_url(other.id))
    assert page.status_code == 200, page.text
    assert DEVICE_OTHER in page.text
    assert "203.0.113.9" in page.text
    assert _human_moment(FROZEN) in page.text
    assert REVOKE_OTHER_WARNING in page.text
    assert REVOKE_CURRENT_WARNING not in page.text
    assert f'action="{_revoke_url(other.id)}"' in page.text, "отзыв делает форма `POST`"
    assert _token(secret, _record(store, secret)) in page.text, "форма обязана нести CSRF-токен"


def test_подтверждение_отзыва_своей_сессии_объясняет_последствие(
    client: TestClient, store: MemoryStore
) -> None:
    """Отозвать сеанс, с которого работаешь, — это выход; текст обязан это называть."""
    secret = _login(client)
    record = _full(store, secret)

    page = client.get(_revoke_url(record.id))
    assert page.status_code == 200, page.text
    assert REVOKE_CURRENT_WARNING in page.text
    assert CURRENT_SESSION_LABEL in page.text


def test_подтверждение_отзыва_всех_называет_весь_набор(
    client: TestClient, store: MemoryStore
) -> None:
    """«Отзыв всех» подтверждается списком объектов, а не абстрактным «вы уверены?» (§9.1)."""
    secret = _login(client)
    _full(store, secret)
    other = _issue(store, _record(store, secret).user_id, device=DEVICE_OTHER)

    page = client.get(SESSIONS_REVOKE_ALL_PATH)
    assert page.status_code == 200, page.text
    assert REVOKE_ALL_WARNING in page.text
    assert (
        REVOKE_ALL_NOTE in page.text
    ), "подпись над перечнем на подтверждении обязана объяснять, что перечень шире списка"
    assert DEVICE_OWN in page.text
    assert DEVICE_OTHER in page.text
    assert f'action="{SESSIONS_REVOKE_ALL_PATH}"' in page.text
    assert _token(secret, _record(store, secret)) in page.text
    assert other.revoked_at is None


# ─── отказ по идентификатору: один ответ на четыре случая (§8.8) ───────────────────


def test_чужой_кривой_и_пропавший_id_отвечают_одинаково(
    client: TestClient, store: MemoryStore
) -> None:
    """«Есть, но не твоё», «уже завершилось», «нет такого» и «не UUID» — одно и то же `404`.

    Различие ответов выдало бы перечень существующих идентификаторов перебором; §8.8 требует
    «403/404 без утечки», и здесь утечки нет ни ответом, ни текстом.
    """
    secret = _login(client)
    _full(store, secret)
    foreign = _user(store, login="chuzhaya-uchetka-2")
    foreign_session = _issue(store, foreign.id, device=DEVICE_FOREIGN)
    gone = uuid.uuid4()

    answers = [
        client.get(_revoke_url(foreign_session.id)),
        client.get(_revoke_url(gone)),
        client.get(_revoke_url("ne-identifikator")),
    ]
    for response in answers:
        assert response.status_code == 404, response.text
        assert response.json()["detail"] == GONE_DETAIL
    unique = {response.text for response in answers}
    assert len(unique) == 1, "ответы обязаны совпасть побайтово"
    assert foreign_session.revoked_at is None


def test_подтверждение_чужого_id_тоже_отвечает_404(client: TestClient, store: MemoryStore) -> None:
    """Страница подтверждения не должна становиться способом разглядеть чужую сессию."""
    secret = _login(client)
    _full(store, secret)
    foreign = _user(store, login="chuzhaya-uchetka-3")
    foreign_session = _issue(store, foreign.id, device=DEVICE_FOREIGN)

    page = client.get(_revoke_url(foreign_session.id))
    assert page.status_code == 404, page.text
    assert DEVICE_FOREIGN not in page.text


# ─── отзыв по одной (§8.3 «отзыв по одной») ────────────────────────────────────────


def test_отзыв_без_токена_отказывается_и_ничего_не_меняет(
    client: TestClient, store: MemoryStore
) -> None:
    """Матрица §8.8: «CSRF обязателен для всех POST/PUT/DELETE (тест без токена → 403)»."""
    secret = _login(client)
    record = _full(store, secret)
    other = _issue(store, record.user_id, device=DEVICE_OTHER)

    response = _post_revoke(client, secret, record, other.id, present=False)
    assert response.status_code == 403, response.text
    assert other.revoked_at is None
    assert record.revoked_at is None


def test_отзыв_чужой_сессии_невозможен_и_её_состояние_не_меняется(
    client: TestClient, store: MemoryStore
) -> None:
    """Ограничение `user_id` в поиске (§8.8).

    Проверяется не только код ответа, но и состояние чужой сессии: ответ `404` при уже отозванной
    чужой строке означал бы, что «защита» работает как точка отказа.
    """
    secret = _login(client)
    record = _full(store, secret)
    foreign = _user(store, login="chuzhaya-uchetka-4")
    foreign_session = _issue(store, foreign.id, device=DEVICE_FOREIGN)

    response = _post_revoke(client, secret, record, foreign_session.id)
    assert response.status_code == 404, response.text
    assert foreign_session.revoked_at is None, "чужая сессия не должна быть отозвана"
    assert record.revoked_at is None, "и своя сессия при отказе не пострадала"
    html = client.get(SESSIONS_PATH)
    assert html.status_code == 200, "свой вход после отказа остался живым"


def test_отзыв_другой_сессии_оставляет_текущую_живой(
    client: TestClient, store: MemoryStore
) -> None:
    """Отзыв по другой сессии (§8.3) не имеет права завершать текущий вход."""
    secret = _login(client)
    record = _full(store, secret)
    other = _issue(store, record.user_id, device=DEVICE_OTHER)

    response = _post_revoke(client, secret, record, other.id)
    assert response.status_code == 302, response.text
    assert response.headers["location"] == SESSIONS_PATH, "после отзыва — обратно к списку"
    assert not _session_set_cookies(response), "куку текущей сессии стирать нельзя"
    assert other.revoked_at == FROZEN, "отзыв обязан быть зафиксирован моментом запроса"

    html = client.get(SESSIONS_PATH)
    assert html.status_code == 200, response.text
    assert DEVICE_OTHER not in html.text, "отозванная сессия исчезает из списка немедленно"
    assert DEVICE_OWN in html.text


def test_отзыв_текущей_сессии_ведёт_на_страницу_состояния(
    client: TestClient, store: MemoryStore
) -> None:
    """Если ушла текущая сессия — ответ объяснение, а не форма входа (§9).

    Направление обязано совпасть с тем, что дала бы охрана маршрута: у неё тот же адрес и та же
    причина (`SessionRedirect(SESSION_EXPIRED_PATH, reason='revoked')`). Разошедшиеся направления
    дали бы два разных объяснения одного состояния.
    """
    secret = _login(client)
    record = _full(store, secret)

    response = _post_revoke(client, secret, record, record.id)
    assert response.status_code == 302, response.text
    expected = f"{SESSION_EXPIRED_PATH}?{REASON_QUERY}=revoked"
    assert response.headers["location"] == expected
    cookies = _session_set_cookies(response)
    assert cookies, "кука обязана быть стёрта"
    name, _, value = cookies[0].split(";", 1)[0].partition("=")
    assert name == SESSION_COOKIE_NAME
    assert value.strip('"') == "", "значение обязано стать пустым"
    assert "max-age=0" in cookies[0].lower(), "отзыв обязан удалить куку из браузера"

    # охрана маршрута с той же кукой отвечает тем же адресом: направления не расходятся
    client.cookies.set(SESSION_COOKIE_NAME, secret)
    guard = client.get("/probe-full", follow_redirects=False)
    assert guard.status_code == 302
    assert guard.headers["location"] == expected

    page = client.get(SESSIONS_PATH, follow_redirects=True)
    assert page.status_code == 200
    assert "Этот сеанс отозван" in page.text
    assert GENERIC_EXPLANATION not in page.text


def test_повторный_отзыв_отвечает_404_и_не_перетирает_момент(
    client: TestClient, store: MemoryStore, clock: Clock
) -> None:
    """Момент первого отзыва разбирают инцидент (`T-109`), поэтому он не перетирается.

    Второй отзыв той же сессии — это «такого живого сеанса нет»: она уже не попадает в перечень
    кандидатов, и ответ обязан совпасть с отказом для чужого идентификатора (§8.8).
    """
    secret = _login(client)
    record = _full(store, secret)
    other = _issue(store, record.user_id, device=DEVICE_OTHER)

    first = _post_revoke(client, secret, record, other.id)
    assert first.status_code == 302
    assert other.revoked_at == FROZEN

    clock.move_to(FROZEN + timedelta(minutes=2))
    second = _post_revoke(client, secret, record, other.id)
    assert second.status_code == 404, second.text
    assert second.json()["detail"] == GONE_DETAIL
    assert other.revoked_at == FROZEN, "момент первого отзыва перетёрт"


def test_шаг_password_не_отзывает_даже_с_верным_токеном(
    client: TestClient, store: MemoryStore
) -> None:
    """§8.2 и отказ в обслуживании: знание пароля без кода 2FA не выгоняет чужие входы.

    Токен на шаге `'password'` выводится (сессия есть), поэтому отказ не может держаться на CSRF:
    нужен именно шаг входа. Иначе «знаю пароль» означает «могу устроить владельцу отказ на всех
    устройствах».
    """
    secret = _login(client)
    record = _record(store, secret)
    other = _issue(store, record.user_id, device=DEVICE_OTHER)

    response = _post_revoke(client, secret, record, other.id)
    assert response.status_code == 302, response.text
    assert response.headers["location"] == LOGIN_PATH
    assert other.revoked_at is None

    all_response = client.post(
        SESSIONS_REVOKE_ALL_PATH,
        data={CSRF_FORM_FIELD: _token(secret, record)},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert all_response.status_code == 302
    assert all_response.headers["location"] == LOGIN_PATH
    assert other.revoked_at is None


# ─── отзыв всех (§8.3 «отзыв по …всех») ──────────────────────────────────────────


def test_отзыв_всех_без_токена_отказывается(client: TestClient, store: MemoryStore) -> None:
    """Мутация «отзыв всех» без токена — `403`, и ни одна сессия не отозвана (матрица §8.8)."""
    secret = _login(client)
    record = _full(store, secret)
    other = _issue(store, record.user_id, device=DEVICE_OTHER)

    response = client.post(
        SESSIONS_REVOKE_ALL_PATH,
        data={},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 403, response.text
    assert record.revoked_at is None
    assert other.revoked_at is None


def test_отзыв_всех_отзывает_все_живые_сессии_включая_текущую(
    client: TestClient, store: MemoryStore
) -> None:
    """«Все» включает текущую сессию, а ответ — страница состояния с причиной `revoked`.

    Отзыв, который бережёт ровно тот вход, с которого его делают, не является ответом на
    подозрение в компрометации: украденный вход мог быть именно этим.
    """
    secret = _login(client)
    record = _full(store, secret)
    user_id = record.user_id
    other = _issue(store, user_id, device=DEVICE_OTHER)
    future = FROZEN + timedelta(minutes=5)
    skewed = _issue(
        store, user_id, device="кривые-часы", created=future, expires=future + IDLE_TIMEOUT
    )

    response = client.post(
        SESSIONS_REVOKE_ALL_PATH,
        data={CSRF_FORM_FIELD: _token(secret, record)},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    assert response.headers["location"] == f"{SESSION_EXPIRED_PATH}?{REASON_QUERY}=revoked"
    assert _session_set_cookies(
        response
    ), "кука текущей сессии стёрта: пользователь уходит и отсюда"

    for row in (record, other, skewed):
        assert row.revoked_at == FROZEN, "отзыв всех обязан зафиксировать каждую живую сессию"

    # следующий запрос с прежней кукой обязан быть отклонён (§8.3: немедленная видимость отзыва)
    client.cookies.set(SESSION_COOKIE_NAME, secret)
    assert client.get("/probe-full", follow_redirects=False).status_code == 302


def test_отзыв_всех_не_трогает_чужие_сессии_и_уже_завершившиеся(
    client: TestClient, store: MemoryStore
) -> None:
    """Границы набора: только живые сессии этой учётной записи (§8.8, §8.3).

    Чужие строки не отзываются вообще; свои уже завершённые по сроку тоже не помечаются
    отозванными задним числом: `revoked_at` у них остаётся пустым, и разбор инцидента (`T-109`)
    не начинает видеть отзыв там, где его не было.
    """
    secret = _login(client)
    record = _full(store, secret)
    foreign = _user(store, login="chuzhaya-uchetka-5")
    foreign_live = _issue(store, foreign.id, device=DEVICE_FOREIGN)
    foreign_other = _issue(store, foreign.id, device="чужой-телефон")
    stale = _issue(
        store, record.user_id, device="старый-телефон", expires=FROZEN - timedelta(minutes=1)
    )

    response = client.post(
        SESSIONS_REVOKE_ALL_PATH,
        data={CSRF_FORM_FIELD: _token(secret, record)},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text

    for row in (foreign_live, foreign_other, stale):
        assert row.revoked_at is None, "отзыв всех касается только живых сессий этой учётки"
    assert record.revoked_at == FROZEN


def test_отзыв_всех_не_оставляет_пользователя_внутри(
    client: TestClient, store: MemoryStore
) -> None:
    """После отзыва всех список недоступен: пользователь обязан увидеть объяснение (§9).

    Проверка идёт через `follow_redirects`: редирект на список с отозванной кукой ведёт на страницу
    состояния, и именно её видит человек. Оставить его «внутри консоли» после отзыва всех значило
    бы показать список, собранный по мёртвой сессии.
    """
    secret = _login(client)
    record = _full(store, secret)

    response = client.post(
        SESSIONS_REVOKE_ALL_PATH,
        data={CSRF_FORM_FIELD: _token(secret, record)},
        headers={"Origin": "https://testserver"},
        follow_redirects=True,
    )
    assert response.status_code == 200, response.text
    assert "Этот сеанс отозван" in response.text
    assert SESSIONS_PATH not in str(response.url)


# ─── пределы частоты (§8.3: 60 мутаций в минуту на пользователя) ────────────────────


def test_отзывы_учтены_счётчиком_и_упираются_в_предел(
    client: TestClient, store: MemoryStore
) -> None:
    """Счётчик стоит до обработчика: 61-я попытка получает `429` и ничего не отзывает.

    Поток набивается отзывами несуществующего идентификатора: так видно, что лимит считается на
    всём маршруте, а не только в удачной ветке, и что отказ по лимиту наступает раньше отзыва.
    """
    secret = _login(client)
    record = _full(store, secret)
    other = _issue(store, record.user_id, device=DEVICE_OTHER)
    token = _token(secret, record)
    gone = uuid.uuid4()

    for _ in range(60):
        response = client.post(
            _revoke_url(gone),
            data={CSRF_FORM_FIELD: token},
            headers={"Origin": "https://testserver"},
            follow_redirects=False,
        )
        assert response.status_code == 404, response.text

    limited = client.post(
        _revoke_url(other.id),
        data={CSRF_FORM_FIELD: token},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert limited.status_code == 429, limited.text
    assert int(limited.headers["retry-after"]) >= 1
    assert other.revoked_at is None, "отказ по лимиту не должен ничего менять"
    assert record.revoked_at is None


def test_просмотр_списка_не_тратит_счётчик_частоты(client: TestClient, store: MemoryStore) -> None:
    """§8.3 ограничивает мутации: лимит на просмотр страницы дал бы отказ человеку с страницы."""
    secret = _login(client)
    _full(store, secret)

    for _ in range(70):
        assert client.get(SESSIONS_PATH).status_code == 200
    assert client.get(SESSIONS_PATH).status_code == 200
