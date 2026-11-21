"""Список сессий и отзыв поверх живого PostgreSQL 16 (CI job `миграции`, `T-102`, срез `R3e`).

Офлайновая половинка — `tests/integration/test_web_sessions_page.py`: то же боевое приложение на
`MemoryStore`, оно запускается на dev-машине, где PostgreSQL нет. Здесь проверяется ровно то, чего
память не показывает:

* **ограничение `user_id` и предикат живости уходят в SQL**, а не отфильтровываются потом:
  проверяется текст запроса, который приложение реально отправило в базу (слушатель `Engine`).
  Именно это делает чужую сессию недоступной, а список — ограниченным по числу прочитанных строк
  (§8.8, `ADR-007`);
* **чужую сессию нельзя отозвать, и её строка в таблице остаётся нетронутой** — по перечитыванию
  другим соединением, а не по объекту текущего запроса;
* **отзыв виден новому соединению** (§8.3 «отзыв отражается немедленно»): `revoked_at` зафиксирован
  в таблице, а не только в identity map запроса;
* **отзыв всех не оставляет живых строк у этого пользователя и не трогает чужие**;
* **просроченная сессия не отзываем**: она не входит в набор кандидатов, и `revoked_at` у неё не
  появляется задним числом — разбор инцидента (`T-109`) не должен видеть отзыв там, где его не было;
* **адрес на странице — канонический текст колонки `INET`** (`ADR-009`): psycopg3 читает её
  объектом `ipaddress`, и страница обязана напечатать ровно ту форму, которая является значением
  колонки и ключом счётчика лимитов;
* **сессия, выпущенная вне HTTP** (так её выпустит `T-117` при включении Telegram), видна в списке и
  отзывается наравне с остальными.

Запуск: `TBOT_DB_URL` на базу, развёрнутую до `upgrade head` (так и стоит в job'е `migrations`). Без
переменной группа пропускается целиком (на dev-машине базы нет), при заданной, но недоступной базе —
падает, а не пропускается.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine, create_engine, delete, event, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from apps.web.main import create_app
from apps.web.security.csrf import CSRF_FORM_FIELD, expected_token
from apps.web.security.sessions import (
    SESSION_COOKIE_NAME,
    SESSIONS_PATH,
    SESSIONS_REVOKE_ALL_PATH,
    Principal,
)
from packages.common.clock import utc_now
from packages.common.config import Settings
from packages.common.db import sqlalchemy_url
from packages.identity.sessions import IDLE_TIMEOUT, create_session, token_hash_of
from packages.identity.users import new_user
from packages.storage.models import User, UserSession
from tests.integration.web_support import TEST_PASSWORD, probe_router, session_cookie

# Читается до аутофикстуры `clean_tbot_env` (она убирает TBOT_* внутри теста): на уровне модуля
# решается, идти ли в группу целиком или пропустить её.
_DB_URL = os.environ.get("TBOT_DB_URL", "")

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="нет TBOT_DB_URL: нужны живой PostgreSQL (группа исполняется в CI job `migrations`)",
)

#: Учётки создаются на каждый тест со своим суффиксом: `users.login` уникален (а `citext` делает
#: уникальность ещё и регистронезависимой), а повторный прогон job'а идёт по той же базе.
_LOGIN_PREFIX = "t102r3e"

#: Маркеры устройств: `user_agent` печатается в списке как есть (с ограничением длины).
DEVICE_OWN = "laptop-live"
DEVICE_OTHER = "phone-live"
DEVICE_FOREIGN = "foreign-live"
DEVICE_LINK = "telegram-link-live"


@pytest.fixture(scope="module")
def engine() -> Iterator[Engine]:
    """Движок тестового чтения: отдельный от приложения, чтобы видеть зафиксированное.

    Адрес обязательно прогоняется через `sqlalchemy_url`: в job'е `migrations` переменная стоит в
    прямой форме `postgresql://…`, а SQLAlchemy искала бы `psycopg2` (драйвер в проекте один —
    psycopg3, `packages/common/db.py`).
    """
    created = create_engine(sqlalchemy_url(_DB_URL), pool_pre_ping=True)
    yield created
    created.dispose()


@pytest.fixture
def db(engine: Engine) -> Iterator[Session]:
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    # `user_id` — `ON DELETE RESTRICT`: сначала сессии, потом учётка.
    ids = list(session.scalars(select(User.id).where(User.login.like(f"{_LOGIN_PREFIX}%"))).all())
    if ids:
        session.execute(delete(UserSession).where(UserSession.user_id.in_(ids)))
        session.execute(delete(User).where(User.id.in_(ids)))
        session.commit()
    session.close()


@pytest.fixture
def app_settings(tmp_path: Path) -> Settings:
    return Settings(
        db_url=SecretStr(_DB_URL),
        secrets_dir=tmp_path / "secrets",
        instance_name="test",
        log_level="WARNING",
    )


@pytest.fixture
def app_client(app_settings: Settings) -> Iterator[tuple[TestClient, list[str], list[str]]]:
    """Клиент боевого приложения и накопитель отправленного им SQL.

    Слушатель навешивается на движок самого приложения (`app.state.engine`), потому что утверждения
    «чужая строка не может найтись» и «список читает только живые строки» держатся текстом
    отправленного запроса. В памяти тот же код проходит с фильтрацией циклом в Python, и проверка
    по поведению слоя этого не различает.
    """
    app = create_app(app_settings)
    app.include_router(probe_router())
    app_engine: Engine | None = app.state.engine
    assert app_engine is not None, "без адреса базы живая проверка списка бессмысленна"
    statements: list[str] = []
    bound: list[str] = []

    def _collect(
        _conn: object, _cursor: object, statement: str, parameters: object, *_rest: object
    ) -> None:
        statements.append(statement)
        bound.append(repr(parameters))

    event.listen(app_engine, "before_cursor_execute", _collect)
    try:
        with TestClient(app, base_url="https://testserver") as test_client:
            yield test_client, statements, bound
    finally:
        event.remove(app_engine, "before_cursor_execute", _collect)


@pytest.fixture
def client(app_client: tuple[TestClient, list[str], list[str]]) -> TestClient:
    return app_client[0]


@pytest.fixture
def captured_sql(app_client: tuple[TestClient, list[str], list[str]]) -> list[str]:
    """Тексты запросов, отправленных приложением: фильтрация обязана быть здесь."""
    return app_client[1]


@pytest.fixture
def captured_params(app_client: tuple[TestClient, list[str], list[str]]) -> list[str]:
    """Значения, связанные с этими запросами: по ним проверяется поиск по хэшу (§8.3)."""
    return app_client[2]


@pytest.fixture
def login_name() -> str:
    return f"{_LOGIN_PREFIX}{uuid.uuid4().hex[:10]}"


@pytest.fixture
def seeded(db: Session, login_name: str) -> User:
    user = new_user(login=login_name, password=TEST_PASSWORD, role="operator", state="active")
    db.add(user)
    db.commit()
    return user


# ─── помощники ────────────────────────────────────────────────────────────────────────────────


def _учётка(db: Session, *, suffix: str) -> User:
    """Вторая учётная запись (проверки изоляции, §8.8)."""
    user = new_user(
        login=f"{_LOGIN_PREFIX}{suffix}", password=TEST_PASSWORD, role="operator", state="active"
    )
    db.add(user)
    db.commit()
    return user


def _войти(client: TestClient, login_name: str, *, xff: str | None = None) -> str:
    """Войти и вернуть значение куки (шаг `'password'`, §8.2)."""
    headers = {"Origin": "https://testserver", "User-Agent": DEVICE_OWN}
    if xff is not None:
        headers["X-Forwarded-For"] = xff
    response = client.post(
        "/login",
        data={"login": login_name, "password": TEST_PASSWORD},
        headers=headers,
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    secret = session_cookie(client)
    assert secret, "после входа куки нет"
    return secret


def _сессии(db: Session, user_id: uuid.UUID) -> list[UserSession]:
    """Перечитать строки другим соединением: состояние обязано быть в таблице, а не в запросе."""
    db.expire_all()
    return list(db.execute(select(UserSession).where(UserSession.user_id == user_id)).scalars())


def _полная_сессия(db: Session, user_id: uuid.UUID) -> UserSession:
    """Поднять шаг текущей сессии до `full` правкой в базе: страницы кода — за `T-103`."""
    row = next(row for row in _сессии(db, user_id) if row.revoked_at is None)
    db.execute(update(UserSession).where(UserSession.id == row.id).values(auth_step="full"))
    db.commit()
    db.expire_all()
    return row


def _выпустить(
    db: Session,
    user_id: uuid.UUID,
    *,
    device: str,
    ip: str | None = "198.51.100.7",
    created_ago: timedelta = timedelta(minutes=5),
    expires_in: timedelta = IDLE_TIMEOUT,
    revoked_ago: timedelta | None = None,
) -> UserSession:
    """Выпустить сессию мимо HTTP и зафиксировать её в таблице.

    Границы задаёт тест: «живая», «просроченная» и «отозванная» строки обязан различать именно
    набор полей, а не момент запуска проверки.
    """
    moment = utc_now()
    issued = create_session(
        user_id,
        ip=ip,
        user_agent=device,
        auth_step="full",
        now=moment - created_ago,
    )
    record = issued.record
    record.expires_at = moment + expires_in
    if revoked_ago is not None:
        record.revoked_at = moment - revoked_ago
    db.add(record)
    db.commit()
    return record


def _токен(secret: str, row: UserSession) -> str:
    return expected_token(Principal(session=row, secret=secret))


def _адреса_строк(statements: list[str]) -> list[str]:
    """Текст запросов к таблице `sessions`, которые приложение реально отправило."""
    return [
        statement
        for statement in statements
        if "FROM sessions" in statement and "WHERE" in statement
    ]


# ─── набор списка и его граница (§9.3 п. 4: «список активных сессий») ──────────────


def test_запрос_списка_фильтрует_в_sql_a_не_в_python(
    client: TestClient,
    captured_sql: list[str],
    captured_params: list[str],
    seeded: User,
    login_name: str,
    db: Session,
) -> None:
    """Ограничения `user_id`, `revoked_at IS NULL` и `expires_at >` обязаны быть в запросе.

    Причина не в стиле: если фильтр делает Python, то «чужая строка не найдётся» держится только
    внимательностью вызывающего кода, а «список читает только живые строки» вообще ничем не
    держится — на площадке с накопленными строками страница начала бы вычитывать все сессии
    пользователя.
    """
    secret = _войти(client, login_name)
    _полная_сессия(db, seeded.id)
    captured_sql.clear()

    response = client.get(SESSIONS_PATH)
    assert response.status_code == 200, response.text
    selects = _адреса_строк(captured_sql)
    assert selects, "приложение не отправило ни одного запроса к таблице `sessions`"
    scoped = [
        statement
        for statement in selects
        if "sessions.user_id" in statement
        and "sessions.revoked_at IS NULL" in statement
        and "sessions.expires_at >" in statement
    ]
    assert scoped, (
        "запрос списка не содержит хотя бы одного из ограничений "
        f"(`user_id`, `revoked_at IS NULL`, `expires_at >`): {selects}"
    )
    joined = "\n".join(captured_sql)
    assert "sessions.token_hash" in joined, (
        "обращение ищется не по колонке хэша (§8.3: «в SQL обращаются по token_hash, а не по "
        "значению куки»)"
    )
    values = "\n".join(captured_params)
    assert token_hash_of(secret) in values, (
        "среди связанных значений нет хэша значения куки: сравнение идёт не по колонке "
        "`token_hash`"
    )
    assert secret not in values, "значение куки не участвует в обращении к базе (§8.3)"


def test_список_не_показывает_отозванные_и_просроченные_строки(
    client: TestClient, seeded: User, login_name: str, db: Session
) -> None:
    """Живой набор: отзыв и просрочек не печатаются, но строки остаются в таблице."""
    _войти(client, login_name)
    _полная_сессия(db, seeded.id)
    _выпустить(db, seeded.id, device=DEVICE_OTHER)
    dead = _выпустить(db, seeded.id, device="dead-live", revoked_ago=timedelta(minutes=10))
    stale = _выпустить(
        db,
        seeded.id,
        device="stale-live",
        created_ago=timedelta(hours=2),
        expires_in=-timedelta(minutes=30),
    )

    html = client.get(SESSIONS_PATH).text
    assert DEVICE_OWN in html
    assert DEVICE_OTHER in html
    for device in ("dead-live", "stale-live"):
        assert device not in html, "список показал сеанс, который нельзя отозвать"

    # строки остаются: страница их не показывает, а не удаляет и не «дочитывает потом»
    states = {row.user_agent: row.revoked_at for row in _сессии(db, seeded.id)}
    assert "dead-live" in states
    assert "stale-live" in states
    assert dead.revoked_at is not None
    assert stale.revoked_at is None


def test_адрес_на_странице_каноническим_текстом_из_INET(
    client: TestClient, seeded: User, login_name: str, db: Session
) -> None:
    """`ADR-009`: psycopg3 читает `INET` объектом `ipaddress`, а наружу обязан идти каноника.

    Тот же канонический текст является ключом счётчика лимитов и значением колонки, поэтому
    «красивое» представление (`2001:0DB8::…`) здесь не подходит: сравнение окна счётчика с адресом
    перестало бы работать.
    """
    _войти(client, login_name, xff="2001:db8:0:0:0:0:0:1, 2001:db8::2")
    _полная_сессия(db, seeded.id)

    html = client.get(SESSIONS_PATH).text
    assert "2001:db8::2" in html
    assert "2001:0db8" not in html.lower()
    row = next(row for row in _сессии(db, seeded.id) if row.revoked_at is None)
    assert str(row.ip) == "2001:db8::2"


def test_сессия_выпущенная_вне_http_видна_и_подтверждается(
    client: TestClient, seeded: User, login_name: str, db: Session
) -> None:
    """Так сессию выпустит `T-117` (включение Telegram): список обязан её показать (§8.3)."""
    _войти(client, login_name)
    _полная_сессия(db, seeded.id)
    link = _выпустить(db, seeded.id, device=DEVICE_LINK, ip=None, created_ago=timedelta(minutes=1))

    html = client.get(SESSIONS_PATH).text
    assert DEVICE_LINK in html
    assert f'href="{SESSIONS_PATH}/{link.id}/revoke"' in html
    confirm = client.get(f"{SESSIONS_PATH}/{link.id}/revoke")
    assert confirm.status_code == 200, confirm.text
    assert DEVICE_LINK in confirm.text
    assert link.revoked_at is None, "`GET` подтверждения ничего не меняет"


# ─── отзыв по одной (§8.3 «отзыв по одной», §8.8 изоляция) ────────────────────────


def test_отзыв_одной_сессии_виден_новому_соединению(
    client: TestClient, seeded: User, login_name: str, db: Session
) -> None:
    """§8.3: «отзыв отражается немедленно» — видимость обязана быть табличной, а не объектной."""
    secret = _войти(client, login_name)
    current = _полная_сессия(db, seeded.id)
    other = _выпустить(db, seeded.id, device=DEVICE_OTHER)

    response = client.post(
        f"{SESSIONS_PATH}/{other.id}/revoke",
        data={CSRF_FORM_FIELD: _токен(secret, current)},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    assert response.headers["location"] == SESSIONS_PATH

    fresh = next(row for row in _сессии(db, seeded.id) if row.id == other.id)
    assert fresh.revoked_at is not None, "отзыв обязан быть зафиксирован в таблице"

    # страница больше не показывает отозванную сессию
    assert DEVICE_OTHER not in client.get(SESSIONS_PATH).text


def test_чужую_сессию_нельзя_отозвать_и_её_строка_не_меняется(
    client: TestClient, seeded: User, login_name: str, db: Session
) -> None:
    """§8.8: «доступ к чужим данным → 403/404 без утечки», и состояние чужой строки важно.

    Проверка держится на живой базе намеренно: только здесь видно, что ограничение `user_id` стоит
    в условии `SELECT`, а не в сравнении после находки.
    """
    secret = _войти(client, login_name)
    current = _полная_сессия(db, seeded.id)
    foreign = _учётка(db, suffix=f"f{uuid.uuid4().hex[:8]}")
    foreign_row = _выпустить(db, foreign.id, device=DEVICE_FOREIGN)
    assert foreign_row.id is not None

    page = client.get(f"{SESSIONS_PATH}/{foreign_row.id}/revoke")
    assert page.status_code == 404, page.text
    posted = client.post(
        f"{SESSIONS_PATH}/{foreign_row.id}/revoke",
        data={CSRF_FORM_FIELD: _токен(secret, current)},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert posted.status_code == 404, posted.text

    after = next(row for row in _сессии(db, foreign.id) if row.id == foreign_row.id)
    assert after.revoked_at is None, "чужая сессия осталась живой в таблице"
    assert DEVICE_FOREIGN not in client.get(SESSIONS_PATH).text


def test_просроченную_сессию_не_отзывают_и_она_остаётся_без_revoked_at(
    client: TestClient, seeded: User, login_name: str, db: Session
) -> None:
    """Мёртвую по сроку строку отзыв не помечает: `revoked_at` остаётся пустым (§8.3, `T-109`).

    Иначе разбор инцидента начал бы видеть «отзыв» там, где сеанс просто завершился по сроку, а
    страница отзыва предлагала бы действие над строкой, которой нет в наборе.
    """
    secret = _войти(client, login_name)
    current = _полная_сессия(db, seeded.id)
    stale = _выпустить(
        db,
        seeded.id,
        device="stale-live",
        created_ago=timedelta(hours=3),
        expires_in=-timedelta(minutes=10),
    )

    posted = client.post(
        f"{SESSIONS_PATH}/{stale.id}/revoke",
        data={CSRF_FORM_FIELD: _токен(secret, current)},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert posted.status_code == 404, posted.text
    after = next(row for row in _сессии(db, seeded.id) if row.id == stale.id)
    assert after.revoked_at is None, "просроченную сессию нельзя пометить отозванной задним числом"


def test_повторный_отзыв_не_перетирает_момент_первого(
    client: TestClient, seeded: User, login_name: str, db: Session
) -> None:
    """Момент первого отзыва — доказательство для `T-109`; второй отзыв отвечает `404`."""
    secret = _войти(client, login_name)
    current = _полная_сессия(db, seeded.id)
    other = _выпустить(db, seeded.id, device=DEVICE_OTHER)

    first = client.post(
        f"{SESSIONS_PATH}/{other.id}/revoke",
        data={CSRF_FORM_FIELD: _токен(secret, current)},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert first.status_code == 302, first.text
    stamped = next(row for row in _сессии(db, seeded.id) if row.id == other.id).revoked_at
    assert stamped is not None

    second = client.post(
        f"{SESSIONS_PATH}/{other.id}/revoke",
        data={CSRF_FORM_FIELD: _токен(secret, current)},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert second.status_code == 404, second.text
    again = next(row for row in _сессии(db, seeded.id) if row.id == other.id)
    assert again.revoked_at == stamped, "момент первого отзыва перетёрт"


# ─── отзыв всех (§8.3 «отзыв по …всех») ──────────────────────────────────────────


def test_отзыв_всех_не_оставляет_живых_строк_у_пользователя(
    client: TestClient, seeded: User, login_name: str, db: Session
) -> None:
    """Ни своей, ни выпущенной вне HTTP живой строки не остаётся (§8.3 «отзыв по …всех»)."""
    secret = _войти(client, login_name)
    current = _полная_сессия(db, seeded.id)
    _выпустить(db, seeded.id, device=DEVICE_OTHER)
    _выпустить(db, seeded.id, device=DEVICE_LINK, ip=None)

    response = client.post(
        SESSIONS_REVOKE_ALL_PATH,
        data={CSRF_FORM_FIELD: _токен(secret, current)},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert location.startswith(
        "/session-expired"
    ), f"ушла и текущая сессия — ответ обязан быть страницей состояния, а не списком: {location}"
    assert "reason=" in location, "причина отзыва обязана быть в адресе переходного ответа"
    assert any(
        value.startswith(f"{SESSION_COOKIE_NAME}=")
        for value in response.headers.get_list("set-cookie")
    ), "кука текущей сессии обязана быть стёрта"

    moment = utc_now()
    alive = int(
        db.scalar(
            select(func.count())
            .select_from(UserSession)
            .where(
                UserSession.user_id == seeded.id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > moment,
            )
        )
        or 0
    )
    assert alive == 0, "после «отзыв всех» у пользователя остались живые сессии"
    states = {row.user_agent: row.revoked_at for row in _сессии(db, seeded.id)}
    assert states.get(DEVICE_LINK) is not None, "сессия, выпущенная вне HTTP, тоже отозвана"


def test_отзыв_всех_не_трогает_чужие_сессии(
    client: TestClient, seeded: User, login_name: str, db: Session
) -> None:
    """Граница набора по учётной записи держится и на живой базе (§8.8).

    Без этой проверки оставалась бы вероятность, что «отзыв всех» соберёт сессии по таблице, а не
    по пользователю: память её не заметит, потому что ключ `user_id` в ней сравнивает Python.
    """
    secret = _войти(client, login_name)
    current = _полная_сессия(db, seeded.id)
    foreign = _учётка(db, suffix=f"g{uuid.uuid4().hex[:8]}")
    foreign_live = _выпустить(db, foreign.id, device=DEVICE_FOREIGN)
    stale = _выпустить(
        db,
        seeded.id,
        device="stale-live",
        created_ago=timedelta(hours=4),
        expires_in=-timedelta(minutes=20),
    )

    response = client.post(
        SESSIONS_REVOKE_ALL_PATH,
        data={CSRF_FORM_FIELD: _токен(secret, current)},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text

    after = {row.user_agent: row.revoked_at for row in _сессии(db, foreign.id)}
    assert after.get(DEVICE_FOREIGN) is None, "чужая сессия отозвана не была"
    still_alive = next(row for row in _сессии(db, foreign.id) if row.id == foreign_live.id)
    assert still_alive.revoked_at is None
    mine = next(row for row in _сессии(db, seeded.id) if row.id == stale.id)
    assert mine.revoked_at is None, "завершившуюся по сроку свою сессию тоже не помечают отзывом"
