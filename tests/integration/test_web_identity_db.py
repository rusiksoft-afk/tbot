"""Слой входа поверх живого PostgreSQL 16 (CI job `migrations`, `T-102`, срез `R3a`).

Офлайн-половинка — `tests/integration/test_web_session_cookie.py` и
`tests/integration/test_web_csrf.py`: они гоняют то же приложение на `MemoryStore` и запускаются на
dev-машине, где PostgreSQL нет. Здесь проверяется ровно то, чего память не показывает:

* вход создаёт строку в `sessions`, и она находится по `token_hash`, а не по значению куки (§8.3);
* `CHECK token_hash_format` (ревизия `0003`) отклоняет запись значения куки вместо хэша — иначе
  такая ошибка выглядит как «сессии нет», то есть неотличимо от чужой куки;
* адрес из `X-Forwarded-For` доезжает до колонки `INET` в каноническом виде и IPv4, и IPv6
  (ADR-007, ADR-007-пункт про `XFF`): текст адреса становится ключом счётчика лимитов, и
  нормализация базы здесь заметна;
* продление idle и отзыв видны **следующему** обращению к базе, а не только объекту текущего
  запроса (§8.3: «отзыв отражается немедленно»);
* отзыв одной сессии не задевает остальные (§8.3, список устройств — `R3e`);
* сессия, выпущенная вне HTTP (`create_session` напрямую — так её выпустит `T-117` при включении
  Telegram), принимается тем же слоем входа: вывод значения куки и его хэша не расходится с
  проверяющей стороной.

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
from sqlalchemy import Engine, create_engine, delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from apps.web.main import create_app
from apps.web.security.csrf import CSRF_FORM_FIELD, expected_token
from apps.web.security.sessions import SESSION_COOKIE_NAME, Principal
from apps.web.store import USER_AGENT_MAX_LEN
from packages.common.clock import utc_now
from packages.common.config import Settings
from packages.identity.sessions import (
    ABSOLUTE_TIMEOUT,
    IDLE_TIMEOUT,
    create_session,
    token_hash_of,
)
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
_LOGIN_PREFIX = "t102r3a"


@pytest.fixture(scope="module")
def engine() -> Iterator[Engine]:
    """Движок тестового чтения: отдельный от приложения, чтобы видеть зафиксированное."""
    created = create_engine(_DB_URL, pool_pre_ping=True)
    yield created
    created.dispose()


@pytest.fixture
def db(engine: Engine) -> Iterator[Session]:
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    # `user_id` — `ON DELETE RESTRICT`: сначала сессии, потом учётка. Удаление «пользователя вместе
    # с сессиями» сломало бы ссылочную целостность журнала, который на этом же ключе строит `T-109`.
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
def login_name() -> str:
    return f"{_LOGIN_PREFIX}{uuid.uuid4().hex[:10]}"


@pytest.fixture
def seeded(db: Session, login_name: str) -> User:
    # `state="active"`: срез состояния учётных записей проверяет позже (`T-105`/`T-106`),
    # но тест обязан моделировать рабочую учётную запись, чтобы проверка не потеряла
    # смысл в тот момент, когда состояние начнёт учитываться.
    user = new_user(login=login_name, password=TEST_PASSWORD, role="operator", state="active")
    db.add(user)
    db.commit()
    return user


@pytest.fixture
def client(app_settings: Settings) -> Iterator[TestClient]:
    """Боевое приложение с реальной фабрикой сессий; щуп полной сессии — из `web_support`."""
    app = create_app(app_settings)
    app.include_router(probe_router())
    with TestClient(app, base_url="https://testserver") as test_client:
        yield test_client


def _войти(client: TestClient, login_name: str, *, xff: str | None = None) -> str:
    headers = {"Origin": "https://testserver"}
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
    db.expire_all()
    return list(db.execute(select(UserSession).where(UserSession.user_id == user_id)).scalars())


def _стать_полной(db: Session, record: UserSession) -> None:
    """Поднять шаг до `full` правкой в базе: страницы кода появляются только в `T-103`."""
    db.execute(update(UserSession).where(UserSession.id == record.id).values(auth_step="full"))
    db.commit()
    db.expire_all()


# ─── строка в таблице и поиск по хэшу (§8.3) ──────────────────────────────────────────────────


def test_вход_создаёт_строку_и_она_находится_по_token_hash(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    secret = _войти(client, login_name)
    rows = _сессии(db, seeded.id)
    assert len(rows) == 1
    row = rows[0]
    assert row.token_hash == token_hash_of(secret)
    assert row.auth_step == "password", "§8.2: парольный шаг полного доступа не даёт"
    assert row.revoked_at is None
    # границы считает приложение (idle 30 минут, абсолютные 12 часов), база держит только порядок
    assert row.expires_at <= row.created_at + ABSOLUTE_TIMEOUT
    assert row.expires_at >= row.created_at + IDLE_TIMEOUT - timedelta(minutes=5)

    # поиск по значению куки ничего не находит: ключ запроса — хэш (§8.3)
    by_value = (
        db.execute(select(UserSession).where(UserSession.token_hash == secret)).scalars().all()
    )
    assert not by_value


def test_значение_куки_не_попадает_ни_в_одну_колонку(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    secret = _войти(client, login_name)
    assert len(secret) == 43
    for row in _сессии(db, seeded.id):
        for column in UserSession.__table__.columns:
            assert secret not in str(
                getattr(row, column.name)
            ), f"значение куки оказалось в колонке {column.name}"


def test_кривой_token_hash_отвергает_база(db: Session, seeded: User) -> None:
    """`CHECK token_hash_format` из ревизии `0003` ловит запись значения куки вместо хэша.

    Проверка идёт по живой базе намеренно: офлайн её повторяет
    `tests/integration/test_rate_buckets_db.py`, но именно здесь видно, что приложение, сохранившее
    значение куки, не получает состояние «сессия есть, но не находится».
    """
    moment = utc_now()
    db.add(
        UserSession(
            user_id=seeded.id,
            token_hash="не-канонический-хэш",
            auth_step="password",
            created_at=moment,
            last_seen_at=moment,
            expires_at=moment + IDLE_TIMEOUT,
        )
    )
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


# ─── адрес (ADR-007) ───────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("xff", "expected"),
    [
        # правый элемент списка, добавленный нашим Caddy: левый присылает клиент
        ("203.0.113.66, 198.51.100.7", "198.51.100.7"),
        ("192.0.2.1", "192.0.2.1"),
        ("2001:db8:0:0:0:0:0:1, 2001:db8::2", "2001:db8::2"),
    ],
    ids=["v4_два_элемента", "v4_один_элемент", "v6_через_caddy"],
)
def test_адрес_ложится_в_inet_каноническим_текстом(
    client: TestClient, db: Session, seeded: User, login_name: str, xff: str, expected: str
) -> None:
    """Текст адреса, который станет ключом счётчика лимитов, обязан совпасть с чтением из `INET`."""
    _войти(client, login_name, xff=xff)
    row = _сессии(db, seeded.id)[0]
    assert row.ip == expected


def test_без_x_forwarded_for_адрес_не_придумывается(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    """TestClient не поднимает соединения: адрес отсутствует, и приложение его не выдумывает.

    Иначе в счётчике появился бы ключ «пустой адрес», общий для всех, у кого не было заголовка, а
    это ровно то, что ADR-007 запрещает: бан по такому ключу закрыл бы вход всем сразу.
    """
    _войти(client, login_name)
    row = _сессии(db, seeded.id)[0]
    assert row.ip is None


def test_user_agent_обрезается_до_границы_колонки(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    _войти(client, login_name)
    client.post(
        "/login",
        data={"login": login_name, "password": TEST_PASSWORD},
        headers={"Origin": "https://testserver", "User-Agent": "a" * (USER_AGENT_MAX_LEN * 3)},
        follow_redirects=False,
    )
    lengths = [len(row.user_agent or "") for row in _сессии(db, seeded.id)]
    assert USER_AGENT_MAX_LEN in lengths
    assert max(lengths) == USER_AGENT_MAX_LEN


# ─── состояние видно следующему обращению (§8.3) ──────────────────────────────────────────────


def test_продление_idle_видно_следующему_запросу(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    # кука остаётся в клиенте: вход возвращает значение только для проверок поиска по хэшу
    _войти(client, login_name)
    row = _сессии(db, seeded.id)[0]
    _стать_полной(db, row)

    # Границы сдвигаются так, чтобы продление было видно следующему обращению: сессия живая
    # (`expires_at` в будущем, но ближе, чем полное окно idle), а `last_seen_at` и `created_at`
    # уезжают в прошлое вместе — иначе ограничение схемы `last_seen_not_before_created`
    # отклонило бы саму правку, а не продление.
    past_seen = utc_now() - timedelta(minutes=20)
    stale = utc_now() + timedelta(minutes=5)
    db.execute(
        update(UserSession)
        .where(UserSession.id == row.id)
        .values(created_at=past_seen, last_seen_at=past_seen, expires_at=stale)
    )
    db.commit()

    response = client.get("/probe-full", follow_redirects=False)
    assert response.status_code == 200, response.text

    after = _сессии(db, seeded.id)[0]
    assert (
        after.expires_at > stale
    ), "продление обязано быть зафиксировано в базе, а не жить в объекте текущего запроса"
    assert after.last_seen_at > past_seen


def test_выход_фиксирует_отзыв_в_базе(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    secret = _войти(client, login_name)
    row = _сессии(db, seeded.id)[0]
    token = expected_token(Principal(session=row, secret=secret))

    response = client.post(
        "/logout",
        data={CSRF_FORM_FIELD: token},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text

    after = _сессии(db, seeded.id)[0]
    assert after.revoked_at is not None, (
        "§8.3: отзыв обязан быть виден следующему запросу другого процесса, а не только тому, "
        "который его выполнил"
    )

    client.cookies.set(SESSION_COOKIE_NAME, secret)
    again = client.get("/probe-full", follow_redirects=False)
    assert again.status_code == 302
    assert again.headers["location"] == "/session-expired?reason=revoked"


def test_отзыв_одной_сессии_не_трогает_другие(
    client: TestClient, db: Session, seeded: User, login_name: str
) -> None:
    first = _войти(client, login_name)
    client.cookies.clear()
    second = _войти(client, login_name)
    rows = _сессии(db, seeded.id)
    assert len(rows) == 2

    target = next(row for row in rows if row.token_hash == token_hash_of(first))
    client.cookies.set(SESSION_COOKIE_NAME, first)
    response = client.post(
        "/logout",
        data={CSRF_FORM_FIELD: expected_token(Principal(session=target, secret=first))},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 302

    states = {row.token_hash: row.revoked_at for row in _сессии(db, seeded.id)}
    assert states[token_hash_of(first)] is not None
    assert (
        states[token_hash_of(second)] is None
    ), "список устройств (§8.3) предполагает отзыв по одной: отзыв всех, кроме текущей, — `R3e`"


def test_сессия_выпущенная_вне_http_принимается_тем_же_слоем(
    client: TestClient, db: Session, seeded: User
) -> None:
    """Так сессию выпустит `T-117` при включении Telegram: вывод и проверка не должны разойтись."""
    issued = create_session(seeded.id, ip=None, user_agent="telegram-link")
    db.add(issued.record)
    db.commit()

    client.cookies.set(SESSION_COOKIE_NAME, issued.secret)
    assert (
        client.get("/probe-full", follow_redirects=False).status_code == 302
    ), "шаг 'password' полного доступа не даёт (§8.2)"

    row = _сессии(db, seeded.id)[0]
    _стать_полной(db, row)
    assert client.get("/probe-full", follow_redirects=False).status_code == 200


def test_база_не_даёт_удалить_учётку_пока_есть_сессии(db: Session, login_name: str) -> None:
    """`ON DELETE RESTRICT` на `user_id` (§4 «общие правила»).

    Держится здесь, а не только в `test_identity_schema_db.py`, потому что именно слой входа создаёт
    сессии: если бы каскад появился вместе с `R3a`, журнал `T-109` потерял бы ссылку на учётку.
    """
    user = new_user(login=f"{login_name}x", password=TEST_PASSWORD, role="operator")
    db.add(user)
    db.commit()
    issued = create_session(user.id, ip=None, user_agent="probe")
    db.add(issued.record)
    db.commit()

    db.delete(user)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
