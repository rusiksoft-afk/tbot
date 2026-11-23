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
from httpx import Response
from pydantic import SecretStr
from sqlalchemy import Engine, create_engine, delete, event, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from apps.web.main import create_app
from apps.web.routes.profile import (
    FIELD_CURRENT_PHRASE,
    FIELD_NEW_PHRASE,
    FIELD_REPEAT_PHRASE,
)
from apps.web.security.csrf import CSRF_FORM_FIELD, expected_token
from apps.web.security.sessions import (
    SECURITY_PATH,
    SESSION_COOKIE_NAME,
    SESSION_EXPIRED_PATH,
    SESSIONS_PATH,
    SESSIONS_REVOKE_ALL_PATH,
    Principal,
)
from packages.common.clock import utc_now
from packages.common.config import Settings
from packages.common.db import sqlalchemy_url
from packages.identity.passwords import verify_password
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
    # `user_id` — `ON DELETE RESTRICT`: сначала сессии, потом учётка.    #
    # Учётка при этом не удаляется, а закрывается состоянием `archived`: с событием §8.7 (срез
    # `R2b` задачи `T-109`) на ней висит ещё и `audit_log.actor` (`fk_audit_log_actor_users`,
    # тоже `ON DELETE RESTRICT`), а журнал append-only: его очистка была бы ровно тем ручным
    # `DELETE`, который `ADR-017` требует оформлять находкой, а не уборкойтеста. Удаление учётки
    # вместе с её событиями означало бы «действие было, а субъекта нет».
    ids = list(session.scalars(select(User.id).where(User.login.like(f"{_LOGIN_PREFIX}%"))).all())
    if ids:
        session.execute(delete(UserSession).where(UserSession.user_id.in_(ids)))
        session.execute(
            update(User)
            .where(User.id.in_(ids))
            .values(state="archived")
            .execution_options(synchronize_session=False)
        )
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


# ─── смена пароля (§8.1 «после смены все сессии, кроме текущей, отзываются», §8.3, §8.8) ─────
#
# Офлайновая половинка этих же сценариев — `tests/integration/test_web_password_change.py`
# (репозиторий в памяти). Здесь проверяется ровно то, чего память не знает: что
# `revoked_at` и новый `password_hash` **зафиксированы в таблице** и их видит другое соединение,
# что поиск учётной записи уходит в SQL по `id` (имя из формы в запросе не участвует), что в
# связанных значениях запросов нет ни значения куки, ни нового пароля, и что новая строка сеанса
# получает адрес как значение колонки `INET`.

#: Новый пароль смены. Проходит §8.1 и обязан отличаться от пароля фикстуры: иначе проверка
#: «старый пароль в строке больше не подходит» была бы пустой.
NEW_PASSWORD = "Новый-рабочий-пароль-2026A"

#: Заведомо короткий пароль (§8.1: минимум 12 символов) — для проверки «отказ ничего не пишет».
SHORT_PASSWORD = "коротко-9"

#: Адрес входа смены: проверяется и как значение колонки `INET`, и как канонический текст на
#: странице списка сеансов после пересоздания (тот же сюжет, что у `ADR-009` в списке).
V6_ENTRY = "2001:db8::2"


def _смена_пароля(
    client: TestClient, secret: str, row: UserSession, *, current: str, new: str, repeat: str
) -> Response:
    """POST формы смены пароля: токен выводится из предъявленной куки и `id` сеанса (ADR-008)."""
    ответ: Response = client.post(
        SECURITY_PATH,
        data={
            CSRF_FORM_FIELD: _токен(secret, row),
            FIELD_CURRENT_PHRASE: current,
            FIELD_NEW_PHRASE: new,
            FIELD_REPEAT_PHRASE: repeat,
        },
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    return ответ


def _учётка_из_таблицы(db: Session, user_id: uuid.UUID) -> User:
    """Перечитать строку `users` другим соединением: хэш и счётчик обязаны быть в таблице."""
    db.expire_all()
    row = db.execute(select(User).where(User.id == user_id)).scalar_one()
    db.expunge(row)
    return row


def test_смена_пароля_отзывает_остальные_сессии_в_таблице(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    """Строка матрицы §8.8 «смена пароля отзывает сессии» — интеграционный уровень.

    Память показывает тот же набор кандидатов и то же поведение слоя, но не показывает главное:
    что `revoked_at` зафиксирован в таблице и что новому соединению видно «входа больше нет».
    Поэтому здесь всё перечитывается заново, а не по объектам текущего запроса.
    """
    secret = _войти(client, login_name)
    current = _полная_сессия(db, seeded.id)
    other = _выпустить(db, seeded.id, device=DEVICE_OTHER)
    foreign = _учётка(db, suffix=f"p{uuid.uuid4().hex[:8]}")
    foreign_live = _выпустить(db, foreign.id, device=DEVICE_FOREIGN)
    hash_before = seeded.password_hash

    response = _смена_пароля(
        client, secret, current, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )
    assert response.status_code == 302, response.text
    assert response.headers["location"] == SESSIONS_PATH, "результат — на списке сеансов (§8.3)"

    rows = {row.id: row for row in _сессии(db, seeded.id)}
    assert rows[current.id].revoked_at is not None, "прежняя запись отзывается пересозданием (§8.3)"
    assert rows[other.id].revoked_at is not None, "прочие живые сеансы отозваны (§8.1)"
    чужие = {row.id: row.revoked_at for row in _сессии(db, foreign.id)}
    assert чужие.get(foreign_live.id) is None, "чужая учётная запись не затронута (§8.8)"

    живые = [row for row in _сессии(db, seeded.id) if row.revoked_at is None]
    assert len(живые) == 1, f"живой сеанс обязан остаться ровно один: {len(живые)}"

    account = _учётка_из_таблицы(db, seeded.id)
    assert account.password_hash != hash_before, "хэш в строке обязан измениться (§8.1)"
    assert verify_password(password=NEW_PASSWORD, stored_hash=account.password_hash)
    assert not verify_password(password=TEST_PASSWORD, stored_hash=account.password_hash)
    assert account.password_updated_at is not None, "момент смены фиксируется в строке (§8.1)"


def test_новая_строка_сеанса_живая_с_шагом_full_и_адресом_INET(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    """Пересоздание (§8.3) обязано дать в таблице живую строку, а не только новую куку.

    Адрес проверяется дважды: как значение колонки `INET` (psycopg3 читает её объектом `ipaddress`)
    и как канонический текст на странице списка — иначе список устройств показал бы адрес в форме,
    которая не является значением колонки и не совпадает с ключом счётчика лимитов (`ADR-009`).
    """
    secret = _войти(client, login_name, xff=V6_ENTRY)
    current = _полная_сессия(db, seeded.id)
    response = _смена_пароля(
        client, secret, current, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )
    assert response.status_code == 302, response.text

    новая_кука = session_cookie(client)
    assert новая_кука != secret, "значение куки обязано смениться (§8.3)"
    rows = {row.token_hash: row for row in _сессии(db, seeded.id)}
    новая = rows[token_hash_of(новая_кука)]
    assert новая.revoked_at is None
    assert новая.auth_step == "full", "шаг входа сохраняется: критичное действие подтверждено"
    assert новая.expires_at > utc_now()
    assert str(новая.ip) == V6_ENTRY, f"колонка INET вернула {новая.ip!r}"

    page = client.get(SESSIONS_PATH)
    assert page.status_code == 200
    assert V6_ENTRY in page.text, "страница печатает канонический текст колонки адреса"


def test_старое_значение_куки_не_находит_живой_строки(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    """§8.3: прежнее значение не должно пережить смену пароля — проверка охраной маршрута на базе.

    Щуп `probe-full` идёт через тот же слой входа, что и боевые маршруты консоли: направление
    отказа задаёт общий механизм, а не обработчик смены пароля.
    """
    secret = _войти(client, login_name)
    current = _полная_сессия(db, seeded.id)
    _смена_пароля(
        client, secret, current, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )

    client.cookies.set(SESSION_COOKIE_NAME, secret)
    guard = client.get("/probe-full", follow_redirects=False)
    assert guard.status_code == 302
    assert SESSION_EXPIRED_PATH in guard.headers["location"]
    assert "reason=revoked" in guard.headers["location"], "причина — отзыв, а не срок (§8.3)"


def test_учётка_ищётся_по_id_а_значений_куки_и_пароля_в_запросах_нет(
    client: TestClient,
    db: Session,
    seeded: User,
    login_name: str,
    captured_sql: list[str],
    captured_params: list[str],
) -> None:
    """§8.8 и §8.4: смена относится к учётке живой сессии, а материал сеанса в SQL не уходит.

    Форма смены пароля имени учётной записи не содержит вовсе, поэтому «подставить чужое имя»
    нечем — и это видно по тексту запроса: условие поиска строится по `users.id`, а `users.login`
    в `WHERE` не встречается. Отдельно держится §8.4: ни значение куки, ни новый пароль, ни имя
    учётной записи не попадают ни в текст запроса, ни в связанные значения (второй аргумент
    слушателя `before_cursor_execute`).

    Список очищается после входа: вход ищет учётку по `login` — это другой маршрут, и его запрос
    здесь только мешал бы.
    """
    secret = _войти(client, login_name)
    current = _полная_сессия(db, seeded.id)
    captured_sql.clear()
    captured_params.clear()

    response = _смена_пароля(
        client, secret, current, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )
    assert response.status_code == 302, response.text

    выборки = [sql for sql in captured_sql if "FROM users" in sql]
    assert выборки, "учётка не читалась из таблицы `users`"
    обновлении = [sql for sql in captured_sql if "UPDATE users" in sql]
    assert обновлении, "новый хэш не зафиксирован `UPDATE`-ом строки учётки"
    for sql in выборки + обновлении:
        условие = sql.split("WHERE", 1)[1] if "WHERE" in sql else ""
        assert "users.id" in условие, f"в условии запроса нет `id` строки: {sql}"
        assert "users.login" not in условие, f"запрос ищет учётку по имени: {sql}"

    for значение in (secret, NEW_PASSWORD, login_name):
        assert значение not in "".join(captured_sql), "значение попало в текст запроса"
        assert значение not in "".join(captured_params), "значение попало в связанные значения"


def test_неверный_текущий_пароль_фиксирует_неудачу_в_таблице(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    """§8.1 и `T-101` на материале базы: подбор текущего пароля ограничен так же, как вход.

    Счётчик неудач обязан быть в строке, а не только в объекте запроса: иначе он живёт до конца
    обработчика, а форма остаётся не ограниченным нигде способом подбора текущего пароля. Хэш при
    отказе не меняется, сеансы не отзываются.
    """
    secret = _войти(client, login_name)
    current = _полная_сессия(db, seeded.id)
    hash_before = seeded.password_hash
    updated_before = seeded.password_updated_at

    отказ = _смена_пароля(
        client,
        secret,
        current,
        current="заведомо-не-этот-пароль",
        new=NEW_PASSWORD,
        repeat=NEW_PASSWORD,
    )
    assert отказ.status_code == 401, отказ.text

    account = _учётка_из_таблицы(db, seeded.id)
    assert account.failed_attempts == 1, f"неудача не зафиксирована: {account.failed_attempts}"
    assert account.locked_until is None
    assert account.password_hash == hash_before, "отказ не имеет права менять хэш"
    assert next(r for r in _сессии(db, seeded.id) if r.user_agent == DEVICE_OWN).revoked_at is None
    assert (
        account.password_updated_at == updated_before
    ), "момент смены пароля фиксируется только при успехе (§8.1)"


def test_блокировка_закрывает_и_смену_пароля_а_верный_пароль_не_спасает(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    """`T-101` на материале смены пароля: при активной блокировке сравнения нет вообще.

    Порядок держится тот же, что на входе: `ensure_login_allowed` до сравнения. Проверка обязана
    увидеть состояние в таблице (`locked_until` — состояние учётки, а не запроса) и то, что попытка
    с **верным** текущим паролем в закрытое окно тоже `429`: иначе блокировка оставляла бы канал
    для проверки угаданных паролей.
    """
    secret = _войти(client, login_name)
    current = _полная_сессия(db, seeded.id)

    for попытка in range(4):
        ответ = _смена_пароля(
            client,
            secret,
            current,
            current="заведомо-не-тот",
            new=NEW_PASSWORD,
            repeat=NEW_PASSWORD,
        )
        assert ответ.status_code == 401, f"запирается раньше: попытка {попытка + 1}"

    до_запирания = _учётка_из_таблицы(db, seeded.id)
    assert (
        до_запирания.failed_attempts == 4
    ), f"неудачи не накапливаются в строке: {до_запирания.failed_attempts}"
    assert до_запирания.locked_until is None

    пятая = _смена_пароля(
        client,
        secret,
        current,
        current="заведомо-не-тот",
        new=NEW_PASSWORD,
        repeat=NEW_PASSWORD,
    )
    assert пятая.status_code == 429, пятая.text
    assert "Retry-After" in пятая.headers, "ADR-007: срок ожидания — часть ответа"

    account = _учётка_из_таблицы(db, seeded.id)
    assert account.locked_until is not None, "блокировка не зафиксирована в строке"
    assert account.failed_attempts == 0, (
        "наступление блокировки обнуляет счётчик намеренно (`T-101`): иначе после истечения "
        "срока ровно одна неудачная попытка закрыла бы вход снова"
    )
    hash_before = account.password_hash

    верная = _смена_пароля(
        client, secret, current, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )
    assert верная.status_code == 429, "пока блокировка активна, смена недоступна"
    assert _учётка_из_таблицы(db, seeded.id).password_hash == hash_before, "хэш не изменился"


def test_отказ_политики_не_меняет_строку_учётки_и_сеансы(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    """§8.1: отказ политики нового пароля — отказ без побочных эффектов.

    Сверяются поля учётки (`password_hash`, `password_updated_at`, `failed_attempts`) и `revoked_at`
    строк сеанса: форма не имеет права ничего записать, даже «предварительно» подняв счётчик
    перебора или прикрыв чужой вход.
    """
    secret = _войти(client, login_name)
    current = _полная_сессия(db, seeded.id)
    other = _выпустить(db, seeded.id, device=DEVICE_OTHER)
    account = _учётка_из_таблицы(db, seeded.id)
    hash_before = account.password_hash
    attempts_before = account.failed_attempts

    response = _смена_пароля(
        client, secret, current, current=TEST_PASSWORD, new=SHORT_PASSWORD, repeat=SHORT_PASSWORD
    )
    assert response.status_code == 400, response.text

    после = _учётка_из_таблицы(db, seeded.id)
    assert после.password_hash == hash_before
    assert после.failed_attempts == attempts_before, "отказ политики не двигает счётчик перебора"
    assert после.password_updated_at == account.password_updated_at
    отзыв = {row.id: row.revoked_at for row in _сессии(db, seeded.id)}
    assert отзыв.get(other.id) is None, "отказ политики не отзывает сеансы"


def test_смена_пароля_не_обнуляет_счётчик_неудач_в_таблице(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    """`T-101`: блокировка перебора не снимается сменой пароля.

    Неудачи выставляются `UPDATE`-ом по строке **после входа**: маршрута ручного сброса нет, а
    окно блокировки снимать нельзя (иначе маршрут ответил бы `429`, и проверять было бы нечего).
    До входа выставлять счётчик бессмысленно: успешный вход сам снимает неудачи
    (`register_login_success`), и проверка утверждала бы «0 == 2», то есть проверяла сброс входа,
    а не свойство смены пароля. Счётчик после успешной смены обязан остаться прежним:
    «разблокировался сменой пароля» означало бы, что перебор можно чередовать со сменой пароля.
    """
    secret = _войти(client, login_name)
    db.execute(update(User).where(User.id == seeded.id).values(failed_attempts=2))
    db.commit()

    # Хэш снимается до смены и именно значением: `seeded` — объект из identity map того же
    # `Session`, и сравнение «`account.password_hash != seeded.password_hash`» после `expire_all`
    # сравнивало бы строку саму с собой (оба объекта перечитаны одним запросом) и проходило бы
    # молча даже при unchanged-значении.
    hash_before = _учётка_из_таблицы(db, seeded.id).password_hash

    current = _полная_сессия(db, seeded.id)
    response = _смена_пароля(
        client, secret, current, current=TEST_PASSWORD, new=NEW_PASSWORD, repeat=NEW_PASSWORD
    )
    assert response.status_code == 302, response.text

    account = _учётка_из_таблицы(db, seeded.id)
    assert account.failed_attempts == 2, f"счётчик неудач обнулили: {account.failed_attempts}"
    assert account.password_hash != hash_before, "смена пароля обязана отразиться в строке"
