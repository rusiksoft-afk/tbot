"""Счётчик частоты запросов и формат хэша значения куки на живом PostgreSQL 16 (T-102, §8.3).

Офлайн-половинка — `tests/contract/test_rate_limits_schema.py` (она сверяет модели, ревизию, текст
ТЗ и ADR, не поднимая базу). Здесь проверяется то, что видит только сервер:

* `PRIMARY KEY (scope, bucket_key, window_start)` действительно не даёт второй строки на то же
  окно — иначе лимит «10 запросов/мин/IP» превращается в «сколько процессов успели вставить»;
* проверки `CHECK` кусаются: неизвестная область, окно 300 секунд (его вводит не решение
  заказчика — `docs/HANDOFF.md §4`), отрицательный счётчик, слишком длинный ключ субъекта;
* серверные `DEFAULT` (окно 60, счётчик 0) работают на вставке из чистого SQL — это путь
  восстановления из дампа и ручных правок, где приложения нет;
* CHECK формата `sessions.token_hash`, добавленный ревизией `0003` к уже существующей таблице,
  отклоняет обрезанный хэш и пропускает тот, что выдаёт приложение;
* роль приложения (`tbot_app`) получает доступ к счётчику без изменений в `deploy/postgres/roles.sql`
  — иначе переключение из `ADR-006` молча оставило бы слой входа без права `UPDATE attempts`.

Запуск: та же `TBOT_DB_URL`, что у `test_identity_schema_db.py`. Без переменной группа пропускается
(на dev-машине PostgreSQL нет), в CI job `migrations` — исполняется.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

import psycopg
import pytest

from packages.common.db import psycopg_dsn
from packages.identity.sessions import token_hash_of, token_secret

_DB_URL = os.environ.get("TBOT_DB_URL", "")
_ROLES_SQL: Final = (
    Path(__file__).resolve().parents[2] / "deploy" / "postgres" / "roles.sql"
).read_text(encoding="utf-8")
_APP_ROLE: Final = "tbot_app"
_CHECK_VIOLATION: Final = "23514"
_UNIQUE_VIOLATION: Final = "23505"
_ARGON2ID: Final = (
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb29sZA"
    "$0k3Z0m1aK1P0d1kQ2w3e4r5t6y7u8i9o0p1q2r3s4t5u"
)
_WINDOW_START: Final = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
# Просрочок сессии в проверке формата хэша: `expires_at > created_at` — ограничение схемы,
# оно не должно мешать проверке именно формата.
_SESSION_EXPIRES: Final = _WINDOW_START + timedelta(minutes=30)

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="нет TBOT_DB_URL: нужны живой PostgreSQL (группа исполняется в CI job `migrations`)",
)


@pytest.fixture(scope="module")
def connection() -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    """Одно соединение владельца схемы: схема поднята шагами job'а `migrations` до тестов."""
    conn = psycopg.connect(psycopg_dsn(_DB_URL), connect_timeout=10)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def _rollback_between_tests(connection: psycopg.Connection[tuple[Any, ...]]) -> Iterator[None]:
    """Каждый тест откатывается: счётчик не копит строки, иначе следующая проверка увидит чужие."""
    connection.rollback()
    yield
    connection.rollback()


def _rejected(
    connection: psycopg.Connection[tuple[Any, ...]],
    sql: str,
    what: str,
    sqlstate: str,
    params: tuple[object, ...] = (),
) -> None:
    """Ожидаем отказ ровно ожидаемого рода, а не «какую-нибудь ошибку».

    Разбор по `sqlstate` принципиален: `CHECK` и нарушенный `PRIMARY KEY` — разные причины, и
    перепутать их значит оставить проверку зелёной при сломанной схеме. Попытка идёт внутри
    `SAVEPOINT`, чтобы неудача не отменила весь тестовый транзакт.
    """
    connection.execute("SAVEPOINT rejected_probe")
    captured: psycopg.Error | None = None
    try:
        connection.execute(sql, params)
    except psycopg.Error as error:
        captured = error
    finally:
        connection.execute("ROLLBACK TO SAVEPOINT rejected_probe")
        connection.execute("RELEASE SAVEPOINT rejected_probe")

    assert captured is not None, f"{what}: ожидание не исполнилось — запрос выполнился успешно"
    actual = getattr(captured, "sqlstate", None)
    assert (
        actual == sqlstate
    ), f"{what}: ожидался sqlstate {sqlstate}, получено {actual}: {captured}"


def _insert_bucket(
    connection: psycopg.Connection[tuple[Any, ...]],
    *,
    scope: str = "login_ip",
    key: str = "203.0.113.7",
    attempts: int = 1,
) -> None:
    connection.execute(
        "INSERT INTO rate_buckets (scope, bucket_key, window_start, attempts) "
        "VALUES (%s, %s, %s, %s)",
        (scope, key, _WINDOW_START, attempts),
    )


def _user_id(connection: psycopg.Connection[tuple[Any, ...]]) -> uuid.UUID:
    user_id = uuid.uuid4()
    connection.execute(
        "INSERT INTO users (id, login, role, state, password_hash) "
        "VALUES (%s, %s, 'operator', 'active', %s)",
        (user_id, f"rl-{user_id.hex[:12]}", _ARGON2ID),
    )
    return user_id


def _scalar(
    connection: psycopg.Connection[tuple[Any, ...]], sql: str, params: tuple[object, ...] = ()
) -> str:
    row = connection.execute(sql, params).fetchone()
    assert row is not None, f"запрос не вернул ни строки: {sql}"
    value = row[0]
    assert isinstance(value, str | int), f"неожиданный тип скаляра: {type(value).__name__}"
    return str(value)


def test_таблица_счётчика_в_каталоге_и_ключ_в_нужном_порядке(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """PG принял DDL и держит порядок ключевых колонок — путь поиска слоя входа."""
    assert (
        _scalar(
            connection,
            "select count(*)::text from information_schema.tables "
            "where table_schema = 'public' and table_name = 'rate_buckets'",
        )
        == "1"
    ), "ревизия 0003 не создала таблицу rate_buckets"

    pk_columns = [
        str(row[0])
        for row in connection.execute(
            "select a.attname "
            "from pg_constraint c "
            "join pg_attribute a on a.attrelid = c.conrelid and a.attnum = any(c.conkey) "
            "where c.conname = 'pk_rate_buckets' "
            "order by array_position(c.conkey, a.attnum)"
        ).fetchall()
    ]
    assert pk_columns == [
        "scope",
        "bucket_key",
        "window_start",
    ], f"порядок колонок первичного ключа изменился: {pk_columns}"

    indexes = {
        str(row[0])
        for row in connection.execute(
            "select indexname from pg_indexes where schemaname = 'public' and tablename = "
            "'rate_buckets'"
        ).fetchall()
    }
    assert indexes == {
        "pk_rate_buckets",
        "ix_rate_buckets_window_start",
    }, f"индексы счётчика разошлись с ревизией: {sorted(indexes)}"

    types = {
        str(row[0]): str(row[1])
        for row in connection.execute(
            "select column_name, data_type from information_schema.columns "
            "where table_schema = 'public' and table_name = 'rate_buckets'"
        ).fetchall()
    }
    assert types == {
        "scope": "text",
        "bucket_key": "text",
        "window_start": "timestamp with time zone",
        "window_seconds": "smallint",
        "attempts": "integer",
    }, f"типы колонок счётчика: {types}"


def test_вторая_строка_на_то_же_окно_отвергается(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Окно живёт в первичном ключ: иначе два процесса заведут по счётчику и лимит размывается."""
    _insert_bucket(connection)
    _rejected(
        connection,
        "INSERT INTO rate_buckets (scope, bucket_key, window_start, attempts) "
        "VALUES (%s, %s, %s, %s)",
        "повторная строка на то же окно",
        _UNIQUE_VIOLATION,
        ("login_ip", "203.0.113.7", _WINDOW_START, 1),
    )
    # Тот же IP в другое окно — законная строка: лимит считает окна, а не «одна строка на IP».
    connection.execute(
        "INSERT INTO rate_buckets (scope, bucket_key, window_start, attempts) "
        "VALUES (%s, %s, %s, %s)",
        ("login_ip", "203.0.113.7", datetime(2026, 11, 21, 12, 1, tzinfo=UTC), 1),
    )
    assert (
        _scalar(
            connection,
            "select count(*)::text from rate_buckets where scope = 'login_ip' and bucket_key = %s",
            ("203.0.113.7",),
        )
        == "2"
    )


def test_неизвестная_область_отвергается(connection: psycopg.Connection[tuple[Any, ...]]) -> None:
    """Закрытый перечень областей §8.3 держит база, а не только кортеж в моделях."""
    for scope in ("login_session", "mutation_ip", "", "LOGIN_IP"):
        _rejected(
            connection,
            "INSERT INTO rate_buckets (scope, bucket_key, window_start, attempts) "
            "VALUES (%s, %s, %s, %s)",
            f"область {scope!r}",
            _CHECK_VIOLATION,
            (scope, "203.0.113.7", _WINDOW_START, 1),
        )
    for scope in ("login_ip", "totp_session", "totp_ip", "mutation_user"):
        _insert_bucket(connection, scope=scope)


def test_окно_вне_минутного_отвергается_в_том_числе_пятиминутное(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """`window_seconds = 60` закреплено базой: пятиминутное окно из §8.2 в схему не заходило."""
    for window in (300, 30, 600):
        _rejected(
            connection,
            "INSERT INTO rate_buckets (scope, bucket_key, window_start, window_seconds, attempts) "
            "VALUES (%s, %s, %s, %s, %s)",
            f"окно {window} секунд",
            _CHECK_VIOLATION,
            ("login_ip", "203.0.113.7", _WINDOW_START, window, 1),
        )
    connection.execute(
        "INSERT INTO rate_buckets (scope, bucket_key, window_start, attempts) "
        "VALUES (%s, %s, %s, %s)",
        ("login_ip", "203.0.113.7", _WINDOW_START, 1),
    )
    assert (
        _scalar(
            connection,
            "select window_seconds::text from rate_buckets "
            "where scope = 'login_ip' and bucket_key = '203.0.113.7'",
        )
        == "60"
    ), "серверный default окна не подставил 60 секунд"


def test_счётчик_не_уходит_в_отрицательные_значения(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """`attempts` — счётчик запросов: отрицательное значение означало бы «лимит уже исчерпан зря»."""
    _rejected(
        connection,
        "INSERT INTO rate_buckets (scope, bucket_key, window_start, attempts) "
        "VALUES (%s, %s, %s, %s)",
        "отрицательный счётчик",
        _CHECK_VIOLATION,
        ("login_ip", "203.0.113.7", _WINDOW_START, -1),
    )
    connection.execute(
        "INSERT INTO rate_buckets (scope, bucket_key, window_start) VALUES (%s, %s, %s)",
        ("login_ip", "203.0.113.8", _WINDOW_START),
    )
    assert (
        _scalar(
            connection,
            "select attempts::text from rate_buckets where bucket_key = '203.0.113.8'",
        )
        == "0"
    ), "у счётчика нет серверного default 0"


def test_длина_ключа_субъекта_в_пределах_и_не_больше(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """IPv6 (45 символов) проходит, произвольный длинный текст — нет: ключ обязан быть адресом."""
    ipv6 = "2001:0db8:0000:0000:0000:0000:0000:0001"
    connection.execute(
        "INSERT INTO rate_buckets (scope, bucket_key, window_start, attempts) "
        "VALUES (%s, %s, %s, %s)",
        ("totp_ip", ipv6, _WINDOW_START, 1),
    )
    _rejected(
        connection,
        "INSERT INTO rate_buckets (scope, bucket_key, window_start, attempts) "
        "VALUES (%s, %s, %s, %s)",
        f"ключ субъекта длиной {len(ipv6) + 20} символов",
        _CHECK_VIOLATION,
        ("totp_ip", ipv6 + "x" * 20, _WINDOW_START, 1),
    )


def test_хэш_значения_куки_в_сессии_проверяется_базой(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """CHECK из ревизии 0003: обрезанный или «не hex» хэш не должен стать сессией."""
    user_id = _user_id(connection)
    columns = (
        "INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, expires_at) "
        "VALUES (%s, %s, %s, %s, %s, %s)"
    )
    for bad in ("abc", "A" * 64, "a" * 63, "z" * 64):
        _rejected(
            connection,
            columns,
            f"хэш значения куки {bad[:16]!r}",
            _CHECK_VIOLATION,
            (uuid.uuid4(), user_id, bad, _WINDOW_START, _WINDOW_START, _SESSION_EXPIRES),
        )
    # Корректное значение из приложения обязано приниматься: иначе CHECK кусается не на мусоре,
    # а на рабочих сессиях (в офлайне это сверяет contract-тест, здесь — живой сервер).
    connection.execute(
        columns,
        (
            uuid.uuid4(),
            user_id,
            token_hash_of(token_secret()),
            _WINDOW_START,
            _WINDOW_START,
            _SESSION_EXPIRES,
        ),
    )


def test_роль_приложения_работает_со_счётчиком_без_правок_файла_прав(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """`ADR-006` не оставил слой входа без права двигать счётчик.

    `roles.sql` применяется так же, как на площадке (шаг после миграций). Проверка нужна, потому
    что счётчик — изменяемая таблица: случайный `REVOKE UPDATE` или попадание в реестр
    append-only дали бы `42501` на первом же запросе `/login`, и выяснилось бы это на проде.
    """
    connection.commit()  # права из файла должны быть видны новому соединению
    admin = connection
    admin.execute(_ROLES_SQL)

    for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        assert (
            _scalar(
                admin,
                "select has_table_privilege(%s, 'rate_buckets', %s)::text",
                (_APP_ROLE, privilege),
            )
            == "true"
        ), f"роли {_APP_ROLE} не выдано право {privilege} на rate_buckets"

    session = psycopg.connect(psycopg_dsn(_DB_URL), connect_timeout=10)
    try:
        session.execute(f'SET ROLE "{_APP_ROLE}"')
        session.execute(
            "INSERT INTO rate_buckets (scope, bucket_key, window_start, attempts) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (scope, bucket_key, window_start) DO UPDATE "
            "SET attempts = rate_buckets.attempts + 1",
            ("login_ip", "203.0.113.9", _WINDOW_START, 1),
        )
        row = session.execute(
            "select attempts::text from rate_buckets "
            "where scope = 'login_ip' and bucket_key = '203.0.113.9'"
        ).fetchone()
        assert row is not None, "строка счётчика не вернулась из под ролью приложения"
        assert row[0] == "1", f"счётчик под ролью приложения не работает: attempts={row[0]}"
        session.rollback()
    finally:
        session.close()
    admin.rollback()
