"""Протокол добавления записи журнала поверх живой базы (TZ §4.1 `REQ-identity-04`, §8.7, `T-109`, срез `R2`).

Оффлайновая половинка — `tests/unit/test_audit_chain.py` (векторы хэшей, каноничность, разбор) и
`tests/integration/test_audit_events_web.py` (какие события порождает слой входа). Здесь проверяется
ровно то, чего память показать не может, потому что протокол добавления (`ADR-025` п. 6) живёт на
стыке приложения и базы:

* **хвост читается в той же транзакции, что и вставка.** `SqlStore.append_audit` берёт
  `pg_advisory_xact_lock` по ключу журнала **до** чтения хвоста, затем читает
  `SELECT hash … ORDER BY id DESC LIMIT 1` и вставляет строку с этим `hash_prev`. Порядок
  «замок → чтение» принципиален: блокировать последнюю строку через `FOR UPDATE` на пустой
  таблице нечем, и два процесса вставили бы по первой записи цепочки (обе с `hash_prev IS NULL`,
  а частичный индекс `ix_audit_log_hash_prev_linked` исключает `NULL` и такие пары не отклоняет);
* **два процесса не читают один хвост.** Второй писатель замок не получает, пока первый не
  зафиксировался, а после фиксации привязывается к **новому** хвосту — развилки нет, и страж п. 4
  не срабатывает. Ожидание проверяется запросом `pg_try_advisory_xact_lock` из второго
  соединения, а не сном и не опросом `pg_locks`: «поспали и подождали, пока второй встанет в
  очередь» дало бы проверке два состояния, из которых ложнозелёное — «не успел дойти до замка»;
  без замка вторая вставка получила бы `23505` ценой откатанной бизнес-транзакции;
* **конфликт цепочки отличается от прочего нарушения по коду состояния.** `psycopg` поднимает
  `psycopg.errors.UniqueViolation`, и в его сообщении кода `23505` нет (замер `CI 45165930936`:
  проверка ждала подстроку в тексте и падала на правильном отказе). Слой доступа читает
  `error.orig.sqlstate`, и только этот случай превращается в `AuditChainConflictError`;
  например нарушение внешнего ключа `actor` (`23503`) остаётся своим `IntegrityError`;
* **отказ вставки откатывает транзакцию целиком.** «Изменение зафиксировано, а события нет» —
  ровно то состояние, из-за которого журнал перестаёт быть доказательством (§8.7), поэтому
  вместе с журнальной строкой откатывается и бизнес-изменение того же запроса, и только его:
  запись конкурента, зафиксированная параллельно, обязана остаться на месте. Проверить это можно
  только перечитав базу **другим** соединением: сессия, выполнившая правку, отдаёт прежние атрибуты
  из identity map (замер `CI 45163930282`);
* **`ip` и `request_id` строки берутся из контекста запроса, а не из воли маршрута** (§8.7
  требует IP и `request_id` в строке; `ADR-009` требует, чтобы адрес события и адрес счётчика
  считались одной функцией): IPv4-mapped-форма, которую даёт Caddy, обязана лечь в колонку
  каноническим IPv4 — той же формой, которой он участвует в материале хэша (`ADR-025` п. 2).

Чего здесь сознательно нет: `ON CONFLICT DO NOTHING` на журнале запрещён (`ADR-025` п. 4), и
живая проверка «обход через `ON CONFLICT DO NOTHING` не создаёт строку» уже есть в срезе `R1`
(`tests/integration/test_audit_chain_db.py`) — дублировать её здесь значило бы иметь два файла,
из которых один когда-нибудь ослабнут.

Запуск: `TBOT_DB_URL` на базу, развёрнутую до `upgrade head` (так и стоит в job'е `миграции`).
Без переменной группа пропускается целиком (на dev-машине базы нет), при заданной, но недоступной
базе — падает, а не пропускается. Уборка — по маркеру в `entity_id`; строки журнала удаляются
только ролью-владельцем схемы, у роли приложения `DELETE` отозван (`ADR-018`).
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import timedelta
from typing import Final
from uuid import UUID

import pytest
from sqlalchemy import Engine, create_engine, delete, select, text
from sqlalchemy.engine.interfaces import IsolationLevel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from apps.web.security.rate_limit import LOGIN_IP_SCOPE
from apps.web.store import JournalContext, SqlStore
from packages.common.clock import utc_now
from packages.common.db import sqlalchemy_url
from packages.common.ids import uuid7
from packages.identity.audit import AuditRecordError, record_of_entry
from packages.storage.audit_store import AUDIT_CHAIN_LOCK_KEY, AuditChainConflictError
from packages.storage.models import RATE_WINDOW_SECONDS, AuditLogEntry, RateBucket

# Читается до аутофикстуры `clean_tbot_env`: на уровне модуля решается, идти ли в группу целиком.
_DB_URL = os.environ.get("TBOT_DB_URL", "")

#: Код состояния, по которому слой доступа отличает конфликт цепочки от прочих нарушений
#: (`ADR-025` п. 6). Держится отдельной константой, а не импортом из `apps.web.store`: проверка
#: обязана сверять ожидание с самим кодом PostgreSQL, а не с тем, что слой доступа посчитал нужным
#: сравнить.
_UNIQUE_VIOLATION: Final = "23505"
#: Нарушение внешнего ключа — «прочее нарушение», которое конвертируется не должно.
_FOREIGN_KEY_VIOLATION: Final = "23503"

#: Уровень изоляции для проверки «устаревший хвост»: читатель видит снимок на момент начала
#: транзакции, то есть ровно то поведение, из-за которого в бою возможен повтор `hash_prev`.
_REPEATABLE_READ: Final[IsolationLevel] = "REPEATABLE READ"

#: Маркер строк этого файла (`entity_id` — текст, §4.1). Отличается от `t109r1`: уборка одного
#: файла не обязана знать про строки другого.
_MARKER_PREFIX: Final = "t109r2"

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="нет TBOT_DB_URL: нужны живой PostgreSQL (группа исполняется в CI job `migrations`)",
)


@pytest.fixture(scope="module")
def engine() -> Iterator[Engine]:
    """Движок владельца схемы: адрес прогоняется через `sqlalchemy_url` (`ADR-018`)."""
    created = create_engine(sqlalchemy_url(_DB_URL), pool_pre_ping=True)
    yield created
    created.dispose()


def _open(engine: Engine, *, isolation: IsolationLevel | None = None) -> Session:
    """Отдельная сессия того же движка.

    `isolation` задаёт уровень изоляции транзакции: проверка «устаревший хвост» требует
    `REPEATABLE READ`, то есть ровно того поведения, которое даёт читателю устаревший снимок и в
    бою (два процесса, один из которых начал транзакцию раньше).

    Уровень задаётся производному движку (`engine.execution_options`), а не сеансу и не соединению:
    у `Session.connection(execution_options=...)` момент применения уровня зависит от того, началась
    ли уже транзакция, и проверка в какой-то момент стала бы зависеть от порядка вызовов, а не от
    настраиваемого поведения базы.
    """
    bind = engine if isolation is None else engine.execution_options(isolation_level=isolation)
    return sessionmaker(bind=bind, expire_on_commit=False)()


def _marker() -> str:
    return f"{_MARKER_PREFIX}-{uuid.uuid4().hex[:10]}"


def _read(bind: Engine | Session, marker: str) -> list[AuditLogEntry]:
    """Прочитать строки маркера по `id` — так же, как их читает разбор цепочки.

    `Engine` читается отдельным сеансом, а не «сырым» соединением, и это не стилистическая мелочь:
    `Connection.scalars(select(Модель))` на соединении из пула отдаёт **первый столбец** строки —
    целые `id` вместо объектов модели (замер `CI 45183773961`:
    `AttributeError: 'int' object has no attribute 'entity_id'`). Отдельный сеанс — это и есть
    отдельное соединение, и он не разделяет identity map с пишущим сеансом, что обязательно для
    проверок отката (замер `CI 45163930282`): чтение тем же сеансом, который правил, показало бы
    прежние атрибуты вместо состояния базы.
    """
    statement = (
        select(AuditLogEntry)
        .where(AuditLogEntry.entity_id.like(f"{marker}%"))
        .order_by(AuditLogEntry.id)
    )
    if isinstance(bind, Engine):
        with Session(bind) as session:
            return list(session.scalars(statement).all())
    return list(bind.scalars(statement).all())


def _tail(session: Session) -> str | None:
    """Хвост цепочки так, как его читает слой доступа (тот же запрос, что в `SqlStore`)."""
    return session.execute(
        select(AuditLogEntry.hash).order_by(AuditLogEntry.id.desc()).limit(1)
    ).scalar_one_or_none()


def _count(bind: Engine | Session, marker: str) -> int:
    return len(_read(bind, marker))


def _cleanup(bind: Engine, marker: str) -> None:
    """Убрать строки маркера. Откат перед чисткой обязателен: упавшая ассертом транзакция оставила
    бы сессию в состоянии «откатить», и финализор выдал бы `PendingRollbackError` вместо настоящей
    причины (замер `CI 45165930936`)."""
    with bind.begin() as connection:
        connection.execute(delete(AuditLogEntry).where(AuditLogEntry.entity_id.like(f"{marker}%")))


def _try_chain_lock(engine: Engine) -> bool:
    """Получился ли замок цепочки журнала прямо сейчас, без ожидания.

    Отдельное соединение, и только `pg_try_`-форма: блокирующая форма (`pg_advisory_xact_lock`)
    подвесила бы проверочное соединение ровно на тот замок, наличие которого проверяется. Замок
    transaction-scoped, поэтому проверочное соединение отпускает его при закрытии и не мешает
    следующим шагам.

    `CAST(:key AS BIGINT)` обязателен: у функции две формы — одна с `bigint` и две с парой `int`, а
    ключ журнала (`AUDIT_CHAIN_LOCK_KEY`) в диапазон 32 бит не помещается. Без явного типа разбор
    перегрузки зависел бы от того, как драйвер объявит параметр.
    """
    statement = text("SELECT pg_try_advisory_xact_lock(CAST(:key AS BIGINT))")
    with engine.connect() as connection:
        return bool(connection.execute(statement, {"key": AUDIT_CHAIN_LOCK_KEY}).scalar_one())


# ─── порядок «замок → хвост → вставка» ───────────────────────────────────────────────────────


def test_протокол_подставляет_хвост_а_следующая_запись_идёт_за_ней(engine: Engine) -> None:
    """Две записи, добавленные протоколом, связаны: `hash_prev` второй равен `hash` первой.

    Проверка относительная: первая запись привязывается к тому хвосту, который был в таблице до
    теста (другие шаги job'а ведут свою цепочку), а не к `NULL`. Именно так протокол и обязан
    работать на площадке, где журнал уже наполнен.
    """
    marker = _marker()
    session = _open(engine)
    try:
        store = SqlStore(session)
        before = _tail(session)
        moment = utc_now()
        store.append_audit(
            action="session.login",
            at=moment,
            entity="session",
            entity_id=f"{marker}-1",
            details={"шаг": 1},
            commit_now=True,
        )
        store.append_audit(
            action="session.logout",
            at=moment + timedelta(seconds=1),
            entity="session",
            entity_id=f"{marker}-2",
            details={"шаг": 2},
            commit_now=True,
        )

        rows = _read(session, marker)
        assert [row.action for row in rows] == ["session.login", "session.logout"]
        assert rows[0].hash_prev == before
        assert rows[1].hash_prev == rows[0].hash
        # Хэш пересчитывается из колонок, а не из памяти приложения: иначе разбор по дампу
        # показывал бы находку на каждой корректной строке (`ADR-025` п. 2).
        for row in rows:
            assert record_of_entry(row).record.content_hash() == row.hash
    finally:
        session.rollback()
        session.close()
        _cleanup(engine, marker)


def test_запись_журнала_и_бизнес_изменение_фиксруются_одной_транзакцией(engine: Engine) -> None:
    """`commit_now=False` — тот же транзакт, что у маршрута: либо видны оба, либо ничего.

    Порядок «бизнес-изменение → журнал в той же транзакции» выбран осознанно (`ADR-025` п. 6):
    журнал обязан отражать состоявшиеся факты. Проверка читает результат новым соединением:
    до фиксации другой connection не видит ни строку журнала, ни строку счётчика.
    """
    marker = _marker()
    session = _open(engine)
    fresh = _open(engine)
    window_start = utc_now().replace(microsecond=0)
    try:
        store = SqlStore(session)
        store.bump_rate_bucket(
            scope=LOGIN_IP_SCOPE,
            bucket_key=marker,
            window_start=window_start,
            window_seconds=RATE_WINDOW_SECONDS,
        )
        store.append_audit(
            action="session.login",
            at=window_start,
            entity="session",
            entity_id=marker,
            details={"шаг": 1},
        )
        assert (
            _count(fresh, marker) == 0
        ), "незафиксированная транзакция не должна быть видна снаружи"
        session.commit()

        assert _count(fresh, marker) == 1
        bucket = fresh.execute(
            select(RateBucket.attempts).where(RateBucket.bucket_key == marker)
        ).scalar_one()
        assert bucket == 1
    finally:
        session.rollback()
        session.close()
        fresh.close()
        _cleanup(engine, marker)
        with engine.begin() as connection:
            connection.execute(delete(RateBucket).where(RateBucket.bucket_key == marker))


# ─── блокировка хвоста ───────────────────────────────────────────────────────────────────────


def test_второй_писатель_не_получит_замок_а_после_фиксации_читает_новый_хвост(
    engine: Engine,
) -> None:
    """Замок цепочки держится транзакцией, а следующая запись привязывается к новому хвосту.

    Сценарий, из-за которого замок существует: первый писатель вставил запись и ещё не
    зафиксировался. Второй замок не получает — значит две ветки одновременно они не строят. После
    фиксации первого замок свободен, и вторая запись идёт **за** первой, а не рядом с ней. Без
    замка второй прочитал бы тот же хвост, что и первый, и его вставка отклонилась бы
    `23505` (`ix_audit_log_hash_prev_linked`) — отказ ценой откатанной бизнес-транзакции.

    Ожидание проверяется `pg_try_advisory_xact_lock` из отдельного соединения, а не потоком и не
    сном: «поспали и подождали, пока второй встанет в очередь» оставило бы проверке два
    состояния, и «не дошёл до замка» выглядело бы зелёным. Проверка от начала до конца
    однопоточная — флукать в job'е `миграции` ей нечем.
    """
    marker = _marker()
    first = _open(engine)
    second = _open(engine)
    try:
        SqlStore(first).append_audit(
            action="session.login",
            at=utc_now(),
            entity="session",
            entity_id=f"{marker}-A",
            details={"писатель": 1},
        )
        assert _try_chain_lock(engine) is False, (
            "второй писатель получил замок цепочки, который держит незафиксированная транзакция "
            "первого: протокол не берёт `pg_advisory_xact_lock` до чтения хвоста, и две ветки "
            "цепочки строятся одновременно (`ADR-025` п. 6)"
        )

        first.commit()

        assert _try_chain_lock(engine) is True, (
            "замок не освободился после фиксации: он не транзакционный и пережил бы конец "
            "запроса, оставив журнал недоступным для всех остальных писателей"
        )

        SqlStore(second).append_audit(
            action="session.logout",
            at=utc_now(),
            entity="session",
            entity_id=f"{marker}-B",
            details={"писатель": 2},
            commit_now=True,
        )

        rows = _read(engine, marker)
        assert [row.entity_id for row in rows] == [f"{marker}-A", f"{marker}-B"]
        assert rows[1].hash_prev == rows[0].hash, (
            "второй писатель привязался к хвосту, который был до фиксации первого: замок не "
            "заставил прочитать новый хвост, и цепочка расходится на две ветки"
        )
    finally:
        first.rollback()
        first.close()
        second.rollback()
        second.close()
        _cleanup(engine, marker)


# ─── отличие конфликта цепочки и откат ───────────────────────────────────────────────────────


def test_устаревший_хвост_отклоняется_по_коду_23505_и_откатывает_всё_вместе(
    engine: Engine,
) -> None:
    """Снимок с устаревшим хвостом: отказ по `sqlstate`, бизнес-изменение откатано, чужое — нет.

    Уровень `REPEATABLE READ` здесь — не экзотика, а тот же механизм, который в бою даёт
    устаревший хвост: транзакция видит снимок на момент начала и обязана привязываться к тому
    хвосту, который был виден, даже если конкурент уже зафиксировал следующую запись. Задача
    среза — не допустить такого в нормальном потоке (замок), а при появлении — откатить
    транзакцию целиком и назвать отказ по коду состояния.

    Порядок проверки принципиален и собран из замера прогона `45163930282`:

    1. базовая запись `-0` коммитится **заранее**: без неё хвост пуст, а две строки с
       `hash_prev IS NULL` законны — частичный индекс исключает `NULL` и конфликтной пары не
       даёт (первая версия проверки ждала `23505` от законной пары и не получала его);
    2. транзакция `stale` заводит бизнес-изменение — этим первым оператором фиксируется снимок;
    3. конкурент добавляет `-1` и фиксируется: её `hash_prev` — хэш записи `-0`;
    4. та же транзакция `stale` пытается добавить `-2` и читает устаревший хвост (`-0`) —
       та же `hash_prev`, что у `-1`, поэтому страж отклоняет вставку.

    Своя строка в хвосте не участвовала бы: транзакция видит собственные записи, и вторая попытка
    той же транзакции привязалась бы к первой — законно, без отказа. Поэтому конфликт намеренно
    создаёт **другой** писатель.
    """
    marker = _marker()
    base = _open(engine)
    stale = _open(engine, isolation=_REPEATABLE_READ)
    rival = _open(engine)
    fresh = _open(engine)
    window_start = utc_now().replace(microsecond=0)
    try:
        SqlStore(base).append_audit(
            action="session.login",
            at=window_start,
            entity="session",
            entity_id=f"{marker}-0",
            details={"шаг": 0},
            commit_now=True,
        )

        store = SqlStore(stale)
        # Бизнес-изменение того же запроса; оно же — первый оператор транзакции, фиксирующий
        # снимок. Именно он в бою читает хвост, и именно этот снимок обязан устареть.
        store.bump_rate_bucket(
            scope=LOGIN_IP_SCOPE,
            bucket_key=marker,
            window_start=window_start,
            window_seconds=RATE_WINDOW_SECONDS,
        )

        SqlStore(rival).append_audit(
            action="session.logout",
            at=window_start + timedelta(seconds=1),
            entity="session",
            entity_id=f"{marker}-1",
            details={"шаг": 1},
            commit_now=True,
        )

        with pytest.raises(AuditChainConflictError) as caught:
            store.append_audit(
                action="session.revoke",
                at=window_start + timedelta(seconds=2),
                entity="session",
                entity_id=f"{marker}-2",
                details={"шаг": 2},
            )
        assert _UNIQUE_VIOLATION in str(caught.value), (
            "в сообщении об отказе цепочки нет кода состояния: разбор не отличит конфликт "
            "цепочки от прочего нарушения целостности"
        )

        # Видимое снаружи состояние: `-0` и `-1` на месте, попытки `stale` нет ни в журнале, ни
        # в счётчике. Откатана обязана быть только транзакция отказавшего писателя — иначе отказ
        # одного запроса отменял бы уже состоявшиеся события других.
        assert [row.entity_id for row in _read(fresh, marker)] == [
            f"{marker}-0",
            f"{marker}-1",
        ], "откат задел чужую зафиксированную запись или оставил отказавшуюся"
        assert (
            fresh.execute(
                select(RateBucket.attempts).where(RateBucket.bucket_key == marker)
            ).scalar_one_or_none()
            is None
        ), "бизнес-изменение не откатилось вместе с отказом вставки в журнал (`ADR-025` п. 6)"
    finally:
        base.close()
        stale.rollback()
        stale.close()
        rival.rollback()
        rival.close()
        fresh.close()
        _cleanup(engine, marker)
        with engine.begin() as connection:
            connection.execute(delete(RateBucket).where(RateBucket.bucket_key == marker))


def test_прочее_нарушение_не_выдаётся_за_конфликт_цепочки(engine: Engine) -> None:
    """Нарушение внешнего ключа `actor` (`23503`) остаётся своим `IntegrityError`.

    Если слой доступа будет конвертировать в `AuditChainConflictError` любое нарушение
    уникальности или целостности, оператор получит «цепочка журнала разошлась» там, где цепочка
    цела, и начнет разбирать не то событие. Отсюда требование читать код состояния, а не текст
    (`ADR-025` п. 6, замер `CI 45165930936`).
    """
    marker = _marker()
    session = _open(engine)
    try:
        store = SqlStore(session)
        stranger: UUID = uuid7()
        with pytest.raises(IntegrityError) as caught:
            store.append_audit(
                action="session.login",
                at=utc_now(),
                actor=stranger,
                entity="session",
                entity_id=f"{marker}-1",
            )
        error = caught.value
        assert not isinstance(
            error, AuditChainConflictError
        ), "прочее нарушение целостности выдано за конфликт цепочки журнала"
        assert str(getattr(error.orig, "sqlstate", "")) == _FOREIGN_KEY_VIOLATION, (
            "код состояния нарушения не внешний ключ: проверка перестала различать, что именно "
            "отклонила база"
        )
        assert _count(session, marker) == 0
        session.rollback()
    finally:
        session.rollback()
        session.close()
        _cleanup(engine, marker)


# ─── контекст запроса в колонках строки ──────────────────────────────────────────────────────


def test_адрес_и_request_id_строки_берутся_из_контекста_запроса(engine: Engine) -> None:
    """`ip` и `request_id` заполняет слой доступа, а не каждый маршрут (§8.7, `ADR-009`).

    Форма адреса проверяется отдельно: наружный TLS приходит IPv4-mapped-значением
    (`::ffff:203.0.113.7`), колонка `INET` хранит его IPv4-адресом, и та же форма обязана входить
    в материал хэша (`ADR-025` п. 2). Иначе одна и та же строка пересчитывалась бы в два разных
    хэша в зависимости от того, как её притащил прокси.
    """
    marker = _marker()
    session = _open(engine)
    fresh = _open(engine)
    link_id = uuid7()
    try:
        store = SqlStore(session, JournalContext(request_id=link_id, address="::ffff:203.0.113.7"))
        store.append_audit(
            action="auth.csrf_rejected",
            at=utc_now(),
            entity="request",
            entity_id=f"{marker}-csrf",
            details={"reason": "токена нет"},
            commit_now=True,
        )
        rows = _read(fresh, marker)
        assert len(rows) == 1
        row = rows[0]
        assert str(row.ip) == "203.0.113.7"
        assert row.request_id == link_id
        assert row.details == {"reason": "токена нет"}
        assert record_of_entry(row).record.content_hash() == row.hash
    finally:
        session.rollback()
        session.close()
        fresh.close()
        _cleanup(engine, marker)


def test_имя_вне_закрытого_реестра_не_попадает_в_базу(engine: Engine) -> None:
    """Запись с именем вне `AUDIT_ACTIONS` отклоняется до обращения к базе.

    Проверка стоит и здесь, потому что путь в базу у неё один: если бы реестр проверялся только
    оффлайн, строка с выдуманным именем всё равно легла бы в `audit_log` через слой доступа, и
    сверка «события §8.7 ↔ реестр» превратилась бы в пожелание (`ADR-025` п. 10).
    """
    marker = _marker()
    session = _open(engine)
    try:
        store = SqlStore(session)
        with pytest.raises(AuditRecordError, match="реестр"):
            store.append_audit(
                action="session.something_new",
                at=utc_now(),
                entity="session",
                entity_id=f"{marker}-1",
            )
        assert _count(session, marker) == 0
    finally:
        session.rollback()
        session.close()
        _cleanup(engine, marker)
