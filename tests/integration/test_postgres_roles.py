"""Права роли приложения на живой PostgreSQL (T-009, `AC-identity-04`).

Здесь проверяется то, что нельзя проверить офлайн: сервер действительно отказывает роли
приложения в правке журнала (`REQ-identity-04`) и при этом обычный DML остаётся доступен —
иначе «append-only» означал бы «приложению вообще не выдали прав».

Порядок такой же, как на площадке: база развёрнута до `upgrade head`, затем применяется
`deploy/postgres/roles.sql`. В CI роль приложения существует только для этой проверки, поэтому её
создаёт сам тест (файл прав идемпотентен).

Что закреплено:

* `INSERT` в `audit_log` ролью приложения проходит, `UPDATE`/`DELETE`/`TRUNCATE` — отказ `42501`;
* у журнала решений порога уведомлений `web_audit_outbox` (`T-116`, `ADR-028`, ревизия `0006`) та же
  граница: `SELECT`+`INSERT` проходят, правка и отзыв — `42501`, владение — у роли-владельца схемы,
  а страж повторной рассылки (`ix_web_audit_outbox_dedup_key`) отклоняет второй тот же ключ и под
  ролью приложения (`23505`) — иначе «append-only» новой таблицы зависел бы от кода приложения;
* счётчик `audit_log.id` выдаётся базой без прав на последовательность: у identity-колонки
  PostgreSQL проверяет право `INSERT` на таблицу (у `serial` пришлось бы выдавать
  `USAGE ON SEQUENCE` — различие закреплено поведенчески, потому что прав на последовательности
  файлом прав не выдаётся);
* отзыв точечный: на `users` роль приложения по-прежнему делает `INSERT`/`UPDATE`/`DELETE`;
* у роли приложения нет прав уровня кластера и нет права `CREATE` на схему `public`: DDL делает
  роль-мигратор (`ADR-018`, решение заказчика от 2026-11-22, ask `c7a6830e-9722-491d-9dbf-
  c8b291d3e84d`), а раньше он шел ролью приложения по варианту Б `ADR-006`. Отдельно держится
  то, что `ALTER TABLE`/`DROP TABLE`/`CREATE INDEX` по чужим объектам — отказ `42501`;
* таблица журнала принадлежит роли-владельцу, а не приложению, и возвращается ей после того, как
  журнал временно переходил приложению: у владельца отзыв прав не действует, поэтому право
  `CREATE` на схеме не должно приводить к владению журналом;
* таблицы будущих ревизий получают DML автоматически (`ALTER DEFAULT PRIVILEGES`), иначе следующая
  миграция «забудет» выдать права, и приложение упадёт на площадке;
* файл прав можно запускать повторно.

Запуск: та же `TBOT_DB_URL`, что у `test_identity_schema_db.py`. Без переменной группа пропускается
(на dev-машине PostgreSQL нет), в CI job `migrations` — исполняется.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

import psycopg
import pytest

from packages.common.db import psycopg_dsn

_DB_URL = os.environ.get("TBOT_DB_URL", "")
_ROLES_SQL: Final = (
    Path(__file__).resolve().parents[2] / "deploy" / "postgres" / "roles.sql"
).read_text(encoding="utf-8")
_APP_ROLE: Final = "tbot_app"
_INSUFFICIENT_PRIVILEGE: Final = "42501"
_UNIQUE_VIOLATION: Final = "23505"
_HASH: Final = "c" * 64
_ARGON2ID: Final = (
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb29sZA"
    "$0k3Z0m1aK1P0d1kQ2w3e4r5t6y7u8i9o0p1q2r3s4t5u"
)

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="нет TBOT_DB_URL: нужны живой PostgreSQL (группа исполняется в CI job `migrations`)",
)


@pytest.fixture(scope="module")
def admin_connection() -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    """Соединение владельца схемы: применяет права и читает каталог.

    `autocommit=True` обязателен: у файла прав собственные `BEGIN`/`COMMIT`. Без autocommit
    psycopg открыл бы свой транзакт, вложенный `BEGIN` дал бы только предупреждение, и выданные
    права могли бы не дожить до следующей сессии — тест остался бы зелёным в одном соединении и
    красным на площадке.
    """
    connection = psycopg.connect(psycopg_dsn(_DB_URL), autocommit=True, connect_timeout=10)
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture(scope="module", autouse=True)
def app_role(admin_connection: psycopg.Connection[tuple[Any, ...]]) -> str:
    """Роль приложения создана и получила права — так же, как это делает runbook на площадке."""
    admin_connection.execute(_ROLES_SQL)
    return _APP_ROLE


@pytest.fixture
def app_session(
    app_role: str,
) -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    """Сессия, в которой текущая роль — приложение: `SET ROLE`, а не вход с паролем.

    Отдельный вход не используется намеренно: пароля у роли приложения в тестовой базе нет
    (значения — секреты, ADR-004), а `SET ROLE` проверяет ровно те же объектные права.
    Членство «владелец → приложение» выдаёт сам `roles.sql`.
    """
    connection = psycopg.connect(psycopg_dsn(_DB_URL), connect_timeout=10)
    try:
        connection.execute(f'SET ROLE "{app_role}"')
        yield connection
    finally:
        connection.rollback()
        connection.close()


def _denied(
    connection: psycopg.Connection[tuple[Any, ...]],
    sql: str,
    what: str,
    params: tuple[object, ...] = (),
    expected: str = _INSUFFICIENT_PRIVILEGE,
) -> None:
    """Ожидаем отказ ровно ожидаемого класса (`42501` по умолчанию), а не по синтаксису.

    Код ошибки принципиален: при пустом или кривом файле прав запрос мог бы упасть по другой
    причине, и проверка осталась бы зелёной, не проверяя ничего.

    Попытка оборачивается в `SAVEPOINT`, а не в откат транзакта: откат транзакта в PostgreSQL
    отменяет и `SET ROLE` (выполненный в этом транзакте), и вторая попытка ушла бы уже под
    ролью владельца — отказ перестал бы проверяться.
    """
    connection.execute("SAVEPOINT denied_probe")
    captured: psycopg.Error | None = None
    try:
        connection.execute(sql, params)
    except psycopg.Error as error:
        captured = error
    finally:
        connection.execute("ROLLBACK TO SAVEPOINT denied_probe")
        connection.execute("RELEASE SAVEPOINT denied_probe")

    assert captured is not None, f"{what}: отказ не получен — запрос выполнился без ошибки"
    sqlstate = getattr(captured, "sqlstate", None)
    assert sqlstate == expected, (
        f"{what}: ожидался код {expected}, получено {type(captured).__name__} "
        f"sqlstate={sqlstate}: {captured}"
    )


def _audit_row_id(connection: psycopg.Connection[tuple[Any, ...]]) -> int:
    """Одна строка журнала, вставленная текущей ролью: возвращает выданный базой id."""
    row = connection.execute(
        "INSERT INTO audit_log (at, action, entity, entity_id, details, ip, request_id, "
        "hash_prev, hash) VALUES (now(), %s, %s, %s, %s::jsonb, %s::inet, %s, NULL, %s) "
        "RETURNING id",
        (
            "session.login",
            "session",
            str(uuid.uuid4()),
            '{"reason": "append-only"}',
            "10.0.0.1",
            uuid.uuid4(),
            _HASH,
        ),
    ).fetchone()
    assert row is not None, "вставка в audit_log не вернула строку"
    record_id = row[0]
    assert isinstance(record_id, int), f"audit_log.id имеет неожиданный тип {type(row[0])}"
    return record_id


def test_audit_append_only_role(app_session: psycopg.Connection[tuple[Any, ...]]) -> None:
    """Проверка из задачи T-009: журнал дописывается, но не правится ролью приложения."""
    record_id = _audit_row_id(app_session)
    assert record_id > 0, "audit_log.id обязан выдаваться базой"

    _denied(
        app_session,
        "UPDATE audit_log SET action = 'poddelka' WHERE id = %s",
        "UPDATE audit_log ролью приложения",
        (record_id,),
    )
    _denied(
        app_session,
        "DELETE FROM audit_log WHERE id = %s",
        "DELETE FROM audit_log ролью приложения",
        (record_id,),
    )
    _denied(app_session, "TRUNCATE audit_log", "TRUNCATE audit_log ролью приложения")

    # Отказ не должен «съедать» и чтение: журнал остаётся видимым для приложения.
    readable = app_session.execute("SELECT count(*) FROM audit_log").fetchone()
    assert readable is not None, "счётчик журнала не вернул строку"
    assert isinstance(readable[0], int), "count(*) имеет неожиданный тип"
    assert readable[0] >= 1, "приложение обязано читать журнал после отказов на правку"


def _notify_row_id(
    connection: psycopg.Connection[tuple[Any, ...]], *, audit_id: int, dedup_key: str
) -> int:
    """Одна строка решений порога, вставленная текущей ролью: возвращает выданный базой `id`.

    `user_id` — `NULL`: решение входа привязано к учётной записи полем `user_id`, но для проверки
    прав эта колонка не важна, а выдуманный идентификатор отклонился бы внешним ключом (`23503`),
    и проверка разбирала бы не то.
    """
    row = connection.execute(
        "INSERT INTO web_audit_outbox (at, ground, outcome, reason, audit_id, user_id, dedup_key, "
        "details) VALUES (now(), 'session.login', 'notify', 'new_pair', %s, NULL, %s, "
        "'{}'::jsonb) RETURNING id",
        (audit_id, dedup_key),
    ).fetchone()
    assert row is not None, "вставка в web_audit_outbox не вернула строку"
    record_id = row[0]
    assert isinstance(record_id, int), f"web_audit_outbox.id имеет неожиданный тип {type(row[0])}"
    return record_id


def test_счётчик_журнала_выдаёт_база_без_прав_на_последовательность(
    app_session: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Права на последовательности приложению не выданы — и всё же строки получают id по порядку.

    Это не косметика: если бы `audit_log.id` был `serial` (default `nextval()`), вставка под
    ролью приложения упала бы с `42501` на последовательности, и файл прав пришлось бы
    дополнять `USAGE ON SEQUENCE` — то есть приложению стало бы доступно движение счётчика.
    """
    denied = app_session.execute(
        "SELECT has_sequence_privilege(%s, 'audit_log_id_seq'::regclass, 'USAGE')",
        (_APP_ROLE,),
    ).fetchone()
    assert denied is not None, "has_sequence_privilege не вернул строку"
    assert not denied[0], (
        "роли приложения выдано право на последовательность журнала: файл прав "
        "deploy/postgres/roles.sql не должен его выдавать"
    )
    first, second = _audit_row_id(app_session), _audit_row_id(app_session)
    assert second > first, f"identity журнала не растёт: {first} → {second}"


def test_outbox_решений_порога_append_only_ролью_приложения(
    app_session: psycopg.Connection[tuple[Any, ...]],
    admin_connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Та же граница, что у журнала, у новой таблицы ревизии `0006` (`T-116`, `ADR-028`).

    Обязательный шаг прав после ревизии с новой журнальной таблицей (`AGENTS.md`, `ADR-022` п. 3,
    признак — `op.create_table` в `upgrade()`) состоит из трёх мест: имя в `APPEND_ONLY_TABLES`,
    `ALTER TABLE … OWNER TO CURRENT_USER` (п. 2.1) и `REVOKE` (п. 4). Контрактная проверка
    `tests/contract/test_db_roles.py` сверяет перечень с текстом файла, а здесь измеряется
    поведение: приложение способно только дописать строку решения и прочитать её.

    Без этой проверки «append-only» новой таблицы зависел бы от кода приложения: тот же процесс,
    который пишет решения, смог бы их и править — в частности стереть строку `muted`, чтобы скрыть
    что порог промолчал (§8.7 сверяется по таблице решений, а не по памяти приложения).

    Отдельно держится страж повторной рассылки под ролью приложения: отказ `23505`, а не `42501`,
    то есть частичный уникальный индекс `ix_web_audit_outbox_dedup_key` работает для той роли,
    которая пишет. Если бы индекс потерял уникальность или предикат, второй вызов того же писателя
    дал бы второе уведомление на одно сочетание, и приложение обнаружило бы это только на площадке.
    """
    # Ключ строится по тому же формату, что и в `packages/identity/notify.py` (литерал здесь без
    # импорта домена: файл проверяет права базы, а не коды приложения, и связывать их нечем).
    key = f"session.login:{uuid.uuid4().hex}:{'a' * 32}"
    first_audit = _audit_row_id(app_session)
    decision_id = _notify_row_id(app_session, audit_id=first_audit, dedup_key=key)
    assert decision_id > 0, "web_audit_outbox.id обязан выдавать база"

    second_audit = _audit_row_id(app_session)
    _denied(
        app_session,
        "INSERT INTO web_audit_outbox (at, ground, outcome, reason, audit_id, user_id, dedup_key, "
        "details) VALUES (now(), 'session.login', 'notify', 'new_pair', %s, NULL, %s, '{}'::jsonb)",
        "повтор ключа деидентификации ролью приложения",
        (second_audit, key),
        expected=_UNIQUE_VIOLATION,
    )

    _denied(
        app_session,
        "UPDATE web_audit_outbox SET outcome = 'muted' WHERE id = %s",
        "UPDATE web_audit_outbox ролью приложения",
        (decision_id,),
    )
    _denied(
        app_session,
        "DELETE FROM web_audit_outbox WHERE id = %s",
        "DELETE FROM web_audit_outbox ролью приложения",
        (decision_id,),
    )
    _denied(app_session, "TRUNCATE web_audit_outbox", "TRUNCATE web_audit_outbox ролью приложения")
    _denied(
        app_session,
        "ALTER TABLE web_audit_outbox OWNER TO tbot_app",
        "смена владельца журнала решений порога",
    )

    granted_sequence = app_session.execute(
        "SELECT has_sequence_privilege(%s, 'web_audit_outbox_id_seq'::regclass, 'USAGE')",
        (_APP_ROLE,),
    ).fetchone()
    assert granted_sequence is not None, "has_sequence_privilege не вернул строку"
    assert not granted_sequence[0], (
        "роли приложения выдано право на последовательность журнала решений: файл прав не должен "
        "его выдавать, identity-колонка проверяет право INSERT на таблицу"
    )

    closed = [
        privilege
        for privilege in ("update", "delete", "truncate", "references", "trigger")
        if _has_table_privilege(admin_connection, "web_audit_outbox", privilege)
    ]
    assert not closed, f"роли приложения не отозваны права {closed} на web_audit_outbox"
    for privilege in ("select", "insert"):
        assert _has_table_privilege(admin_connection, "web_audit_outbox", privilege), (
            f"приложению не выдано право {privilege} на web_audit_outbox: раздел администратора "
            "или писатель решений не работают"
        )

    owner = admin_connection.execute(
        "SELECT tableowner FROM pg_tables WHERE tablename = 'web_audit_outbox'"
    ).fetchone()
    assert owner is not None, "в базе нет таблицы web_audit_outbox"
    assert owner[0] != _APP_ROLE, (
        f"журнал решений принадлежит роли {owner[0]}: приложение стало владельцем таблицы, "
        "и append-only снова стал текстом, а не правом базы"
    )

    readable = app_session.execute("SELECT count(*) FROM web_audit_outbox").fetchone()
    assert readable is not None, "счётчик решений не вернул строку"
    assert isinstance(readable[0], int), "count(*) имеет неожиданный тип"
    assert readable[0] >= 1, "приложение обязано читать решения после отказов на правку"


def test_обычные_таблицы_доступны_роли_приложения_на_полный_dml(
    app_session: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Отзыв точечный: на `users` разрешены и вставка, и правка, и удаление.

    Без этой проверки «append-only» мог бы означать, что приложению просто ничего не выдали.
    """
    user_id = uuid.uuid4()
    login = f"roles-{user_id.hex[:12]}@example.test"
    inserted = app_session.execute(
        "INSERT INTO users (id, login, role, state, password_hash) "
        "VALUES (%s, %s, 'operator', 'active', %s) RETURNING id",
        (user_id, login, _ARGON2ID),
    ).fetchone()
    assert inserted is not None, "приложение не может создать учётку"
    assert inserted[0] == user_id, "учётка создалась под другим идентификатором"
    app_session.execute("UPDATE users SET display_name = 'roles' WHERE id = %s", (user_id,))
    app_session.execute("DELETE FROM users WHERE id = %s", (user_id,))


def test_роль_приложения_без_привилегий_кластера(
    admin_connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Ни суперпользователя, ни создания баз и ролей, ни обхода RLS, ни репликации."""
    row = admin_connection.execute(
        "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolreplication "
        "FROM pg_roles WHERE rolname = %s",
        (_APP_ROLE,),
    ).fetchone()
    assert row is not None, f"роль {_APP_ROLE} не создана — файл прав не применён"
    can_login, superuser, createdb, createrole, bypassrls, replication = row
    assert not can_login, (
        "у роли приложения нет пароля, значит и права входа быть не должно: "
        "LOGIN включается только шагом переключения на площадке (runbook §переключение)"
    )
    granted = [
        name
        for name, flag in zip(
            ("rolsuper", "rolcreatedb", "rolcreaterole", "rolbypassrls", "rolreplication"),
            (superuser, createdb, createrole, bypassrls, replication),
            strict=True,
        )
        if flag
    ]
    assert not granted, f"у роли приложения появились права кластера: {granted}"


def test_приложение_не_делает_ddl_в_схеме(
    app_session: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Рантайм-роль не создаёт объектов в схеме: DDL делает роль-мигратор (`ADR-018`).

    Замер 2026-11-21 показал обратное (`CREATE TABLE` проходил под ролью приложения): тогда
    миграции шли той же ролью, что и приложение (`ADR-006`, вариант Б). Срез деплоя 2026-11-22
    нашел цену этого решения: `ALTER TABLE` по таблице, созданной ролью-владельцем, под ролью
    приложения отказывает (`42501 must be owner of table sessions`, ревизия `0003`), и заказчик
    вернул миграции роли-владельцу. Право `CREATE`, выданное ранее, отзывает `roles.sql`;
    проверка обязана это измерить, а не поверить комментарию файла прав.

    Код отказа — `42501`, а не «нет прав на отношение»: отказ даёт сама схема, и подмена кода
    ошибки означала бы, что проверка зелёная при другом дефекте.
    """
    _denied(app_session, "CREATE TABLE roles_probe_ddl (id integer)", "CREATE TABLE в схеме public")
    allowed = app_session.execute(
        "SELECT has_schema_privilege(current_user, 'public', 'create'), "
        "has_schema_privilege(current_user, 'public', 'usage')"
    ).fetchone()
    assert allowed is not None
    create_ok, usage_ok = allowed
    assert not create_ok, (
        f"у роли приложения есть право CREATE на схему public ({create_ok!r}):"
        " `ADR-018` относит DDL к роли-мигратору"
    )
    assert (
        usage_ok
    ), f"у роли приложения отозвано и право USAGE ({usage_ok!r}): DML без него невозможен"


def test_приложение_не_правит_чужие_объекты(
    app_session: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Роль приложения не делает DDL ни по чужим, ни по своим объектам.

    Граница перестала быть владенческой: с `ADR-018` у рантайм-роли нет и права создавать объекты
    в схеме. Код отказа принципиален — `42501`, а не «нет такой таблицы» или «нет такого
    столбца»: иначе проверка зелёная, ничего не проверяя.
    """
    _denied(app_session, "ALTER TABLE audit_log ADD COLUMN probe text", "ALTER TABLE audit_log")
    _denied(app_session, "CREATE INDEX ix_audit_log_probe ON audit_log (action)", "CREATE INDEX")
    _denied(app_session, "DROP TABLE audit_log", "DROP TABLE audit_log")
    _denied(app_session, "ALTER TABLE audit_log OWNER TO tbot_app", "смена владельца журнала")


def test_таблицы_будущих_ревизий_получают_права_автоматически(
    admin_connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Работает ли `ALTER DEFAULT PRIVILEGES`: новая таблица видима приложению сразу.

    Таблица создаётся и удаляется здесь же. Смысл проверки в том, что следующая ревизия не
    оставит новую таблицу без прав: на площадке это выглядело бы как `42501` в момент первого
    запроса приложения к новой таблице.
    """
    admin_connection.execute("CREATE TABLE roles_probe_future (id integer)")
    try:
        missing = [
            privilege
            for privilege in ("select", "insert", "update", "delete")
            if not _has_table_privilege(admin_connection, "roles_probe_future", privilege)
        ]
        assert not missing, (
            f"новая таблица не получила прав {missing}: ALTER DEFAULT PRIVILEGES в "
            "deploy/postgres/roles.sql не применяется к таблицам текущего владельца"
        )
    finally:
        admin_connection.execute("DROP TABLE roles_probe_future")


def test_права_переустанавливаются_повторно(
    admin_connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Файл прав идемпотентен: runbook допускает повторный запуск после каждой ревизии."""
    admin_connection.execute(_ROLES_SQL)
    still_open = any(
        _has_table_privilege(admin_connection, "audit_log", privilege)
        for privilege in ("update", "delete", "truncate")
    )
    assert (
        not still_open
    ), "после повторного применения прав приложению снова доступны правка или очистка журнала"


def test_владелец_журнала_не_роль_приложения(
    admin_connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Смысл отзыва прав в том, что приложение — не владелец таблицы.

    У владельца `REVOKE` не отнимает неявные права, поэтому проверка «владелец сильнее» — это
    честность самой модели прав: если таблицы когда-нибудь перейдут роли приложения,
    `test_audit_append_only_role` надо будет не чинить, а менять модель.
    """
    owner = admin_connection.execute(
        "SELECT tableowner FROM pg_tables WHERE tablename = 'audit_log'"
    ).fetchone()
    assert owner is not None, "в базе нет таблицы audit_log"
    assert owner[0] != _APP_ROLE, (
        f"журнал принадлежит роли {owner[0]}: приложение стало владельцем таблицы, "
        "и append-only перестал быть правом базы"
    )


def test_журнал_возвращается_владельцу_схемы(
    admin_connection: psycopg.Connection[tuple[Any, ...]],
) -> None:
    """Право `CREATE` на схеме не должно приводить к владению журналом.

    Моделируем ситуацию следующей ревизии: приложение создаёт таблицу журнала и становится её
    владельцем (замер: таблицы, созданные ролью приложения, принадлежат ей). У владельца отзыв
    прав не действует, поэтому `deploy/postgres/roles.sql` возвращает таблицы реестра
    append-only текущему владельцу — проверка это и фиксирует.
    """
    admin_connection.execute(f"ALTER TABLE audit_log OWNER TO {_APP_ROLE}")
    handed = admin_connection.execute(
        "SELECT tableowner FROM pg_tables WHERE tablename = 'audit_log'"
    ).fetchone()
    assert handed is not None, "в базе нет таблицы audit_log"
    assert handed[0] == _APP_ROLE, (
        f"владение журналом не перешло приложению (владелец {handed[0]}): проверка ничего "
        "не моделирует"
    )
    assert _has_table_privilege(admin_connection, "audit_log", "update"), (
        "у владельца журнала права не отзовёшь — именно поэтому файл прав обязан вернуть "
        "владение владельцу схемы"
    )

    admin_connection.execute(_ROLES_SQL)

    back = admin_connection.execute(
        "SELECT tableowner FROM pg_tables WHERE tablename = 'audit_log'"
    ).fetchone()
    assert back is not None, "в базе нет таблицы audit_log"
    assert back[0] != _APP_ROLE, (
        f"журнал остался в руках приложения (владелец {back[0]}): append-only снова стал "
        "текстом, а не правом базы"
    )
    open_privileges = [
        privilege
        for privilege in ("update", "delete", "truncate", "references", "trigger")
        if _has_table_privilege(admin_connection, "audit_log", privilege)
    ]
    assert not open_privileges, f"после возврата владения не отозваны права {open_privileges}"
    for privilege in ("select", "insert"):
        assert _has_table_privilege(admin_connection, "audit_log", privilege), (
            f"после возврата владения у приложения пропало право {privilege.upper()}: "
            "журнал обязан читаться и дописываться"
        )


def _has_table_privilege(
    connection: psycopg.Connection[tuple[Any, ...]], table: str, privilege: str
) -> bool:
    row = connection.execute(
        "SELECT has_table_privilege(%s, %s::regclass, %s)", (_APP_ROLE, table, privilege)
    ).fetchone()
    assert row is not None, f"has_table_privilege по таблице {table} не вернул строку"
    value = row[0]
    assert isinstance(value, bool), f"ожидался логический результат, получено {type(value)}"
    return value
