"""Поведение схемы идентичности на живом PostgreSQL 16 (CI job `migrations`, T-009).

Офлайн-половинка этих проверок — `tests/contract/test_identity_schema.py`: она сверяет модели и
ревизию, не поднимая базу (на dev-машине ни Docker, ни Postgres нет). Здесь проверяется то, что
видно только на сервере:

* PostgreSQL принял DDL целиком — ошибку в выражении частичного индекса офлайн-генерация не
  видит, её видит только исполнение;
* `citext` действительно регистронезависим (§4.1): иначе «Ivan» и «ivan» — две учётные записи, и
  подбор логина обходит `uq_users_login`;
* частичный уникальный индекс держит ровно одну активную привязку TOTP (§8.2);
* проверки `CHECK` кусаются, а не висят для красоты: неверный хэш цепочки, окно TOTP вне ±2,
  не-Argon2id хэш пароля, сессия с просрочком в прошлом (§8.1–8.2, `REQ-identity-04`);
* `ON DELETE RESTRICT` не даёт удалить пользователя, у которого есть сессии (§4 «общие
  правила»), а «удалить» по-прежнему можно состоянием `state='archived'`;
* `audit_log.id` выдаётся базой (identity-эквивалент `bigserial` из §4.1) без явного значения;
* `last_used_step` (ревизия `0004`): база держает `NULL` и диапазон, но НЕ держит монотонность —
  ровно наполовину выполнено §8.2 «коды принимаются один раз», вторую половину держит форма
  запроса приложения (`ADR-013` п. 4, `docs/HANDOFF.md §1.38`).

Права роли приложения (append-only на `audit_log`) проверяются не здесь, а в
`test_audit_append_only_role` — после `deploy/postgres/roles.sql`, следующего шага T-009.

Запуск: `TBOT_DB_URL` должна указывать на базу, развёрнутую до `upgrade head` (так и стоит в
job'е `migrations`). Без переменной группа пропускается целиком (локально — пропущена, в CI —
исполняется); при заданной переменной, но недоступной базе тесты падают, а не пропускаются.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from typing import Any, Final

import psycopg
import pytest

from packages.common.db import psycopg_dsn
from packages.storage.base import Base

# Значение читается до аутофикстуры `clean_tbot_env` (она убирает TBOT_* внутри теста): на уровне
# модуля решается, идти ли в эту группу тестов вообще или пропустить её целиком.
_DB_URL = os.environ.get("TBOT_DB_URL", "")

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="нет TBOT_DB_URL: нужны живой PostgreSQL (группа исполняется в CI job `migrations`)",
)

_ARGON2ID_SAMPLE = (
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA"
    "$6ztZ9VW1S0m1aK1P0d1kQ2w3e4r5t6y7u8i9o0p1q2s"
)
_SHA256_A = "a" * 64
_SHA256_B = "b" * 64
# Таблицы берём у моделей: тест сверяет каталог базы с тем, что объявляет слой `storage`
# (соответствие_models_и_TZ закреплено офлайн-контрактом, дублировать перечень здесь незачем).
_EXPECTED_TABLES = sorted(Base.metadata.tables)

# Как тип ORM-колонки выглядит в каталоге PostgreSQL (`information_schema.columns.data_type`).
# Перечень намеренно ручной: если в схеме появится новый тип, проверка обязана спросить, чем он
# становится в базе, а не угадать по диалекту (диалект ещё и не типизирован в mypy --strict).
_PG_TYPE_NAMES: Final[dict[str, str]] = {
    "Uuid": "uuid",
    "CITEXT": "citext",
    "Text": "text",
    "DateTime": "timestamp with time zone",
    "Integer": "integer",
    "SmallInteger": "smallint",
    "BigInteger": "bigint",
    "LargeBinary": "bytea",
    "INET": "inet",
    "JSONB": "jsonb",
    "Boolean": "boolean",
}


@pytest.fixture(scope="module")
def connection() -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    """Одно соединение на модуль: схему подняли шаги job'а `migrations` до запуска тестов.

    Молчаливого пропуска при недоступной базе нет: если `TBOT_DB_URL` задана, проверка обязана
    состояться — иначе зелёный шаг в CI означал бы «проверки не было».
    """
    conn = psycopg.connect(psycopg_dsn(_DB_URL), connect_timeout=10)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def _rollback_between_tests(connection: psycopg.Connection[tuple[Any, ...]]) -> Iterator[None]:
    """Каждый тест откатывается: база после прогона остаётся в состоянии `upgrade head` без данных.

    Это не косметика: тесты ниже вставляют пользователей и сессии, а следующий тест проверяет
    уникальность — чужие неоткатанные строки дали бы ложное падение.
    """
    connection.rollback()
    yield
    connection.rollback()


def _insert_user(connection: psycopg.Connection[tuple[Any, ...]], login: str) -> uuid.UUID:
    user_id = uuid.uuid4()
    connection.execute(
        "INSERT INTO users (id, login, role, state, password_hash) "
        "VALUES (%s, %s, 'operator', 'active', %s)",
        (user_id, login, _ARGON2ID_SAMPLE),
    )
    return user_id


def _scalar(
    connection: psycopg.Connection[tuple[Any, ...]],
    sql: str,
    params: tuple[object, ...] = (),
) -> int | str:
    """Одно скалярное значение: счётчик (`count(*)`) или текст колонки — других здесь нет."""
    row = connection.execute(sql, params).fetchone()
    assert row is not None, f"запрос не вернул ни строки: {sql}"
    value = row[0]
    assert isinstance(value, int | str), f"скаляр имеет неожиданный тип {type(value).__name__}"
    return value


def test_таблицы_идентичности_на_месте(connection: psycopg.Connection[tuple[Any, ...]]) -> None:
    found = {
        str(row[0])
        for row in connection.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = ANY(%s)",
            (_EXPECTED_TABLES,),
        ).fetchall()
    }
    missing = set(_EXPECTED_TABLES) - found
    assert not missing, f"в базе нет таблиц, которые объявляет слой storage: {sorted(missing)}"


def test_колонки_базы_совпадают_с_моделями_storage(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Точная сверка каталога базы с ORM-моделями: колонки, типы, допустимость NULL.

    Это единственная проверка, которая ловит «модель поменяли, а ревизию не сделали»:
    офлайн-контракт сравнивает модели с текстом ревизии, а здесь сравнивается сама база.
    Заменить шаг на `alembic check` нельзя: сравнение `server_default` у Alembic на PostgreSQL
    эвристическое и даёт фантомные различия на приводимых типах (`'invited'::text`), то есть
    `alembic check` остаётся инструментом `make revision`, а не приёмкой.
    """
    rows = connection.execute(
        "SELECT table_name, column_name, data_type, is_nullable FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = ANY(%s) ORDER BY 1, 2",
        (_EXPECTED_TABLES,),
    ).fetchall()
    actual = {(str(row[0]), str(row[1])): (str(row[2]), str(row[3]) == "YES") for row in rows}
    expected: dict[tuple[str, str], tuple[str, bool]] = {}
    for table_name, table in Base.metadata.tables.items():
        for column in table.columns:
            type_class = type(column.type).__name__
            assert type_class in _PG_TYPE_NAMES, (
                f"{table_name}.{column.name}: тип {type_class} не описан в _PG_TYPE_NAMES — "
                "нужно решить, как он выглядит в каталоге базы"
            )
            if type_class == "DateTime":
                timezone_aware = getattr(column.type, "timezone", False)
                assert timezone_aware, f"{table_name}.{column.name}: время без пояса (TZ §4)"
            expected[(table_name, column.name)] = (
                _PG_TYPE_NAMES[type_class],
                bool(column.nullable),
            )
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    mismatched = {
        key: {"в базе": actual[key], "в модели": expected[key]}
        for key in expected
        if key in actual and actual[key] != expected[key]
    }
    details = f"нет в базе: {missing}; лишнее в базе: {extra}; различия: {mismatched}"
    assert not missing, f"моделей storage нет в каталоге базы — {details}"
    assert not extra, f"в базе есть колонки, которых нет в моделях storage — {details}"
    assert not mismatched, f"колонки разошлись по типу или допустимости NULL — {details}"


def test_ограничения_базы_совпадают_с_моделями_storage(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Имена ограничений читаются из `pg_constraint`: конвенция должна работать и на площадке.

    Имя ограничения — часть контракта (см. `packages/storage/base.py`): обратная миграция ищет
    его по шаблону, а проверка прав (`roles.sql`) оперирует таблицами и ограничениями по именам.
    """
    rows = connection.execute(
        "SELECT t.relname, c.conname, c.contype FROM pg_constraint c "
        "JOIN pg_class t ON t.oid = c.conrelid "
        "JOIN pg_namespace n ON n.oid = t.relnamespace "
        "WHERE n.nspname = 'public' AND t.relname = ANY(%s)",
        (_EXPECTED_TABLES,),
    ).fetchall()
    actual: dict[str, set[str]] = {}
    for table_name, constraint_name, _kind in rows:
        actual.setdefault(str(table_name), set()).add(str(constraint_name))
    for table_name in sorted(Base.metadata.tables):
        table = Base.metadata.tables[table_name]
        expected = {str(constraint.name) for constraint in table.constraints}
        assert actual.get(table_name, set()) == expected, (
            f"{table_name}: ограничения в базе и в модели различаются — "
            f"в базе только: {sorted(actual.get(table_name, set()) - expected)}, "
            f"в модели только: {sorted(expected - actual.get(table_name, set()))}"
        )


def test_индексы_базы_совпадают_с_моделями_storage(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Индексы из `pg_indexes`: частичные уникальные индексы схемы не должны «потеряться».

    Ожидаемый набор = индексы модели + индексы, которые PostgreSQL создаёт под PK и UNIQUE
    (они носят имена этих ограничений, см. конвенцию `pk_`/`uq_`).
    """
    rows = connection.execute(
        "SELECT tablename, indexname FROM pg_indexes "
        "WHERE schemaname = 'public' AND tablename = ANY(%s)",
        (_EXPECTED_TABLES,),
    ).fetchall()
    actual: dict[str, set[str]] = {}
    for table_name, index_name in rows:
        actual.setdefault(str(table_name), set()).add(str(index_name))
    for table_name in sorted(Base.metadata.tables):
        table = Base.metadata.tables[table_name]
        expected = {str(index.name) for index in table.indexes}
        expected |= {
            str(constraint.name)
            for constraint in table.constraints
            if str(constraint.name).startswith(("pk_", "uq_"))
        }
        assert actual.get(table_name, set()) == expected, (
            f"{table_name}: индексы разошлись — в базе только: "
            f"{sorted(actual.get(table_name, set()) - expected)}, "
            f"в модели только: {sorted(expected - actual.get(table_name, set()))}"
        )


def test_citext_логин_регистронезависим(connection: psycopg.Connection[tuple[Any, ...]]) -> None:
    _insert_user(connection, "Ivan")
    with pytest.raises(psycopg.errors.UniqueViolation), connection.transaction():
        _insert_user(connection, "ivan")
    found = _scalar(connection, "SELECT login FROM users WHERE login = %s", ("IVAN",))
    assert str(found).lower() == "ivan", "логин, записанный как 'Ivan', не находится по 'IVAN'"


def test_проверки_базы_отклоняют_недопустимые_значения(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    user_id = _insert_user(connection, "checks.user")

    # §8.1: хэш обязан быть Argon2id — bcrypt (ниже) означает, что приложение сбило алгоритм.
    with pytest.raises(psycopg.errors.CheckViolation), connection.transaction():
        connection.execute(
            "INSERT INTO users (id, login, role, state, password_hash) "
            "VALUES (%s, 'bcrypt.user', 'operator', 'active', %s)",
            (uuid.uuid4(), "$2b$12$.etprvilas.dopustim.dlinnaya.stroka.hasha"),
        )

    # §8.2: окно ±1 по умолчанию, максимум ±2.
    with pytest.raises(psycopg.errors.CheckViolation), connection.transaction():
        connection.execute(
            "INSERT INTO totp_enrollments (id, user_id, secret_enc, issuer, verify_window) "
            "VALUES (%s, %s, %s, 'tbot', 5)",
            (uuid.uuid4(), user_id, b"\x01\x02\x03"),
        )

    # `REQ-identity-04`: запись цепочки без SHA-256 не проходит.
    with pytest.raises(psycopg.errors.CheckViolation), connection.transaction():
        connection.execute(
            "INSERT INTO audit_log (action, hash, hash_prev) VALUES (%s, %s, NULL)",
            ("audit.bad_hash", "ne-hash"),
        )

    # §8.3: срок сессии не может лежать в прошлом относительно создания.
    with pytest.raises(psycopg.errors.CheckViolation), connection.transaction():
        connection.execute(
            "INSERT INTO sessions (id, user_id, token_hash, expires_at) "
            "VALUES (%s, %s, %s, now() - interval '1 hour')",
            (uuid.uuid4(), user_id, _SHA256_A),
        )


def test_аудит_пишется_без_явного_id_и_держит_цепочку(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    first = connection.execute(
        "INSERT INTO audit_log (action, hash, hash_prev) VALUES ('login.ok', %s, NULL) "
        "RETURNING id",
        (_SHA256_A,),
    ).fetchone()
    assert first is not None
    second = connection.execute(
        "INSERT INTO audit_log (action, hash, hash_prev) VALUES ('logout', %s, %s) RETURNING id",
        (_SHA256_B, _SHA256_A),
    ).fetchone()
    assert second is not None
    assert int(second[0]) > int(first[0]), "identity у audit_log.id не выдаёт возрастание"


def test_одна_активная_привязка_totp_на_пользователя(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    user_id = _insert_user(connection, "totp.user")
    connection.execute(
        "INSERT INTO totp_enrollments (id, user_id, secret_enc, issuer) VALUES (%s, %s, %s, 'tbot')",
        (uuid.uuid4(), user_id, b"\x01\x02\x03"),
    )
    with pytest.raises(psycopg.errors.UniqueViolation), connection.transaction():
        connection.execute(
            "INSERT INTO totp_enrollments (id, user_id, secret_enc, issuer) "
            "VALUES (%s, %s, %s, 'tbot')",
            (uuid.uuid4(), user_id, b"\x04\x05\x06"),
        )
    # После отзыва вторая привязка законна: перевод «повторной привязки» (§8.1) в тупик был бы
    # ошибкой схемы, а не policy.
    connection.execute(
        "UPDATE totp_enrollments SET revoked_at = now() WHERE user_id = %s", (user_id,)
    )
    connection.execute(
        "INSERT INTO totp_enrollments (id, user_id, secret_enc, issuer) VALUES (%s, %s, %s, 'tbot')",
        (uuid.uuid4(), user_id, b"\x07\x08\x09"),
    )
    active = int(
        _scalar(
            connection,
            "SELECT count(*) FROM totp_enrollments WHERE user_id = %s AND revoked_at IS NULL",
            (user_id,),
        )
    )
    assert active == 1, f"активных привязок должно быть одна, получено {active}"


def test_последний_принятый_шаг_база_держит_диапазон_а_монотонность_нет(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Граница ответственности схемы по `last_used_step` (ревизия `0004`, §8.2, ADR-013 п. 4).

    Проверяется ровно то, что база по правилу «коды принимаются один раз» делает и чего она сделать
    не может:

    * `NULL` = «ни один код ещё не принят»: строка привязки появляется без значения
      (`server_default` намеренно нет — `0` означал бы, что окно 1970 года уже израсходовано);
    * `CHECK` отклоняет отрицательный шаг: `-1` как «sentinel» выглядел бы как «значение есть» и
      стёр различие с `NULL`, на котором держится вся одноразовость;
    * `BIGINT` подтверждается значением за пределами `int4`;
    * монотонности в базе нет: безусловный `UPDATE` откатывает шаг назад без ошибки. Сравнение со
      значением этой же строки декларативным ограничением не выражается, а триггер здесь
      противоречил бы решению «append-only держат права, а не триггеры» (ревизия `0002` п. 3) и
      кусался бы при любой правке строки. Поэтому страж — форма запроса среза `R4c`, и она же
      проверяется ниже: `rowcount = 0` означает «этот код уже израсходован».
    """
    user_id = _insert_user(connection, "totp.step")
    enrollment_id = uuid.uuid4()
    connection.execute(
        "INSERT INTO totp_enrollments (id, user_id, secret_enc, issuer) VALUES (%s, %s, %s, 'tbot')",
        (enrollment_id, user_id, b"\x10\x11\x12"),
    )
    fresh = connection.execute(
        "SELECT last_used_step IS NULL FROM totp_enrollments WHERE id = %s", (enrollment_id,)
    ).fetchone()
    assert fresh is not None, "запрос состояния шага не вернул ни строки"
    assert fresh[0] is True, "у новой привязки last_used_step обязан быть NULL"

    # Ограничение обязано существовать в каталоге: офлайн-генерация DDL не проверяет, что
    # PostgreSQL принял выражение CHECK (тот же раздел, что и с частичным индексом).
    constraints = {
        str(row[0])
        for row in connection.execute(
            "SELECT conname FROM pg_constraint WHERE conrelid = 'totp_enrollments'::regclass"
        )
    }
    assert (
        "ck_totp_enrollments_last_used_step_not_negative" in constraints
    ), "в каталоге нет CHECK диапазона шага, добавленного ревизией 0004"

    # Шаг за пределами int4 сохраняется числом: форма BIGINT выбрана заказчиком (ADR-013 п. 4), и
    # она же переживает 2038 год (RFC 6238 §4.2 требует держать T шире 32 бит).
    connection.execute(
        "UPDATE totp_enrollments SET last_used_step = %s WHERE id = %s",
        (4_000_000_000, enrollment_id),
    )
    stored = int(
        _scalar(
            connection,
            "SELECT last_used_step FROM totp_enrollments WHERE id = %s",
            (enrollment_id,),
        )
    )
    assert stored == 4_000_000_000, f"шаг за пределами int4 не сохранился: {stored}"

    with pytest.raises(psycopg.errors.CheckViolation), connection.transaction():
        connection.execute(
            "UPDATE totp_enrollments SET last_used_step = %s WHERE id = %s", (-1, enrollment_id)
        )

    # Монотонности база не держит — это граница, а не дефект: шаг уехал назад без единой ошибки.
    connection.execute(
        "UPDATE totp_enrollments SET last_used_step = %s WHERE id = %s", (10_000, enrollment_id)
    )
    rewound = int(
        _scalar(
            connection,
            "SELECT last_used_step FROM totp_enrollments WHERE id = %s",
            (enrollment_id,),
        )
    )
    assert rewound == 10_000, f"безусловный UPDATE не откатил шаг ({rewound}) — проверка устарела"

    # Форма запроса, которую обязан использовать срез `R4c`: меньше ранее принятого — не записывается.
    guard = (
        "UPDATE totp_enrollments SET last_used_step = %s WHERE id = %s "
        "AND (last_used_step IS NULL OR last_used_step < %s)"
    )
    behind = connection.execute(guard, (9_999, enrollment_id, 9_999))
    assert behind.rowcount == 0, f"шаг меньше ранее принятого записан ({behind.rowcount} строк)"
    repeat = connection.execute(guard, (10_000, enrollment_id, 10_000))
    assert (
        repeat.rowcount == 0
    ), f"повтор кода того же шага записан ({repeat.rowcount} строк) — §8.2 нарушен и базой, и формой"
    forward = connection.execute(guard, (10_001, enrollment_id, 10_001))
    assert forward.rowcount == 1, f"шаг вперёд не записан ({forward.rowcount} строк)"


def test_fk_restrict_не_даёт_удалить_пользователя_со_сессией(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    user_id = _insert_user(connection, "restrict.user")
    connection.execute(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) "
        "VALUES (%s, %s, %s, now() + interval '30 minutes')",
        (uuid.uuid4(), user_id, _SHA256_B),
    )
    # PostgreSQL для `RESTRICT` поднимает то `foreign_key_violation`, то `restrict_violation` —
    # зависит от того, есть ли отложенная альтернатива, поэтому принимаем оба варианта.
    with (
        pytest.raises((psycopg.errors.ForeignKeyViolation, psycopg.errors.RestrictViolation)),
        connection.transaction(),
    ):
        connection.execute("DELETE FROM users WHERE id = %s", (user_id,))
    # Предусмотренный способ «удалить» — состояние, а не DELETE (TZ §4.1).
    connection.execute("UPDATE users SET state = 'archived' WHERE id = %s", (user_id,))
    assert (
        str(_scalar(connection, "SELECT state FROM users WHERE id = %s", (user_id,))) == "archived"
    )
