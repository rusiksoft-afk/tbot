"""Журнал решений порога уведомлений поверх живой базы (§8.7, `T-116`, `ADR-028`).

Оффлайновые половинки — `tests/unit/test_audit_notify.py` (пороги, ключи, коды причин) и
`tests/integration/test_audit_notify_web.py` (маршрут → решение → строка в памяти). Здесь
проверяется ровно то, чего память показать не может, потому что живая `web_audit_outbox` —
настоящая схема ревизии `0006`:

* **страж повторной рассылки держит база, а не «проверка перед вставкой»**: частичный уникальный
  индекс `ix_web_audit_outbox_dedup_key` отклоняет второй такой же ключ кодом `23505` — и для
  роли-владельца схемы тоже, в отличие от append-only прав из `deploy/postgres/roles.sql`,
  которые у владельца не действуют (тот же порядок, что у `ix_audit_log_hash_prev_linked`);
* **`ON CONFLICT DO NOTHING` на этом индексе — разрешённый способ погасить повтор**: второй вызов
  того же писателя не создаёт строку и не возвращает идентификатор (`append_notify_decision`
  отвечает `None`). На журнале такой обход запрещён (`ADR-025` п. 4), потому что там потерянная
  строка — это дыра в доказательстве, а здесь — требуемое поведение порога: одного уведомления на
  сочетание;
* **`muted`-строки индексу не подпадают** (`dedup_key IS NULL` вне предиката): иначе на одно
  основание существовало бы одно молчание за всё время, и порог превратился бы в выключатель;
* **ссылка на журнал настоящая**: `audit_id → audit_log.id` с `ON DELETE RESTRICT` — выдуманный
  идентификатор отклоняется `23503` (писатель превращает это в `NotifyAuditLinkError`), а удаление
  строки журнала под решением отклоняется тем же кодом: порядок уборки — сначала решения, потом
  журнал (`ADR-028` п. 7);
* **домены замкнуты базой**: `ground`, `outcome`, форма `reason`, форма `dedup_key` и «notify без
  ключа» — отказ `23514`, а не «приложение не пропустил бы»;
* **момент решения не подменяется моментом базы**: колонка имеет `server_default now()`, но код
  порога передаёт момент события, и база обязана сохранить его ровно (`ADR-025` п. 2: решение не
  должно отставать от события, которое его породило);
* **решение не производит событие журнала**: строки `audit_log` не прибавляется, хэш хвоста не
  двигается — иначе «порог спрошен» оставлял бы два следа и разбор цепочки видел бы расхождение.

Права роли приложения (`INSERT`+`SELECT` проходят, `UPDATE`/`DELETE`/`TRUNCATE` — `42501`,
владение таблицей — у роли-владельца схемы) проверяются в `tests/integration/test_postgres_roles.py`:
там есть сессия под ролью приложения, и эти проверки стоят рядом с такими же для `audit_log`.

Запуск: `TBOT_DB_URL` на базу, развёрнутую до `upgrade head` (шаг job'а `миграции`). Без
переменной группа пропускается (на dev-машине базы нет), при заданной, но недоступной базе —
падает. Строки этого файла убираются уборкой по маркеру в `details` (для журнала — по
`entity_id`) и в обратном порядке: сначала решения, потом строки журнала, потом учётные записи —
иначе `RESTRICT` не отпускает.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import UUID

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from packages.common.clock import utc_now
from packages.common.db import sqlalchemy_url
from packages.identity.audit import build_audit_entry, make_record
from packages.identity.notify import (
    AUTH_STEP_FULL,
    GROUND_BACKUP_CODE_SPENT,
    GROUND_LOGIN,
    REASON_BACKUP_CODE_SPENT,
    REASON_KNOWN_PAIR,
    REASON_LOGIN_COOLDOWN,
    REASON_NEW_PAIR,
    NotifyDecision,
    backup_code_dedup_key,
    decide_login_notice,
    login_pair,
)
from packages.storage.audit_store import (
    SQLSTATE_FOREIGN_KEY_VIOLATION,
    NotifyAuditLinkError,
    append_notify_decision,
    read_login_notice_state,
    read_notify_decisions,
)
from packages.storage.models import AuditLogEntry

# Читается до аутофикстуры `clean_tbot_env` (она убирает TBOT_* внутри теста): на уровне модуля
# решается, идти ли в группу целиком или пропустить её.
_DB_URL = os.environ.get("TBOT_DB_URL", "")

_UNIQUE_VIOLATION: Final = "23505"
_CHECK_VIOLATION: Final = "23514"

#: Argon2id-хэш фиктивной учётной записи. Значение не проверяется (в этом файле никто не входит),
#: но обязано проходить ограничение формата колонки — иначе отказ пришёл бы не из того, что
#: проверяется.
_ARGON2ID: Final = (
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb29sZA"
    "$0k3Z0m1aK1P0d1kQ2w3e4r5t6y7u8i9o0p1q2r3s4t5u"
)

#: Маркер строк этого файла. Для журнала маркер живёт в `entity_id` (§4.1 — текст), для решений —
#: в `details->>'probe'`: отдельной колонки «кто это посадил» в таблице нет намеренно (`ADR-028`
#: п. 2), и выдумывать её ради уборки было бы правкой схемы.
_MARKER_PREFIX: Final = "t116live"

pytestmark = pytest.mark.skipif(
    not _DB_URL,
    reason="нет TBOT_DB_URL: нужны живой PostgreSQL (группа исполняется в CI job `миграции`)",
)


@pytest.fixture(scope="module")
def engine() -> Iterator[Engine]:
    """Движок владельца схемы: адрес обязан быть прогнан через `sqlalchemy_url` (`ADR-018`).

    В job'е `миграции` переменная стоит в прямой форме `postgresql://…`, а SQLAlchemy искала бы
    `psycopg2` — драйвер в проекте один, psycopg3 (`packages/common/db.py`).
    """
    created = create_engine(sqlalchemy_url(_DB_URL), pool_pre_ping=True)
    yield created
    created.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    """Сессия владельца схемы и уборка по маркеру после теста.

    Порядок уборки обязателен обратный записи: `RESTRICT` на `audit_id` и `user_id` не отпускает
    строку журнала и учётную запись, пока на них ссылается решение. Та же последовательность
    действует для регламентной очистки (`ADR-028` п. 7: горячее окно 90 суток — сначала решения,
    потом журнал), поэтому уборка проверяет её постольку, поскольку может.

    Откат перед чисткой нужен по той же причине, что у `test_audit_chain_db.py`: если проверка
    упала ассертом внутри `pytest.raises(IntegrityError)`, транзакт остаётся в состоянии «откатить»,
    и финализор выдал бы `PendingRollbackError` вместо настоящей причины.
    """
    opened = sessionmaker(bind=engine, expire_on_commit=False)()
    yield opened
    opened.rollback()
    opened.execute(
        text("DELETE FROM web_audit_outbox WHERE details->>'probe' LIKE :prefix"),
        {"prefix": f"{_MARKER_PREFIX}%"},
    )
    opened.execute(
        text("DELETE FROM audit_log WHERE entity_id LIKE :prefix"),
        {"prefix": f"{_MARKER_PREFIX}%"},
    )
    opened.execute(
        text("DELETE FROM users WHERE login LIKE :prefix"),
        {"prefix": f"{_MARKER_PREFIX}%"},
    )
    opened.commit()
    opened.close()


def _marker() -> str:
    return f"{_MARKER_PREFIX}-{uuid.uuid4().hex[:10]}"


def _probe_user(session: Session, marker: str) -> UUID:
    """Учётная запись-проба: на неё ссылается `web_audit_outbox.user_id`.

    Вставка сырым SQL, а не `new_user`: хэш пароля здесь не проверяется никто, а доменный
    конструктор заставил бы генерировать Argon2id на каждую проверку (минуты на файл при
    параметрах §8.1). Формат значения проходит ограничение колонки, поэтому отказ приходит из
    того, что проверяется, а не из формата.
    """
    user_id = uuid.uuid4()
    session.execute(
        text(
            "INSERT INTO users (id, login, role, state, password_hash) "
            "VALUES (:id, :login, 'operator', 'active', :hash)"
        ),
        {
            "id": user_id,
            "login": f"{marker}-{user_id.hex[:8]}@example.test",
            "hash": _ARGON2ID,
        },
    )
    session.flush()
    return user_id


def _probe_audit(
    session: Session,
    marker: str,
    *,
    action: str = "session.login",
    index: int = 1,
    at: datetime | None = None,
    actor: UUID | None = None,
) -> AuditLogEntry:
    """Строка журнала по протоколу добавления: хэш посчитан, `id` выдаёт база.

    `hash_prev` — `None`: несколько строк с `NULL` предком законны (страж `0007` покрывает только
    непустые значения), а читать «хвост» таблицы значило бы зависеть от строк других шагов job'а.
    """
    record = make_record(
        action=action,
        at=at if at is not None else utc_now(),
        actor=actor,
        entity="session",
        entity_id=f"{marker}-{index}",
        details={"probe": marker},
        hash_prev=None,
    )
    entry = build_audit_entry(record)
    session.add(entry)
    session.flush()
    return entry


def _decision(
    marker: str,
    *,
    user_id: UUID | None,
    ground: str = GROUND_LOGIN,
    outcome: str = "notify",
    reason: str = REASON_NEW_PAIR,
    dedup_key: str | None = None,
) -> NotifyDecision:
    return NotifyDecision(
        ground=ground,
        outcome=outcome,
        reason=reason,
        dedup_key=dedup_key,
        user_id=user_id,
        details={"probe": marker},
    )


def _insert_raw(
    session: Session,
    *,
    audit_id: int,
    user_id: UUID | None,
    marker: str,
    ground: str = GROUND_LOGIN,
    outcome: str = "notify",
    reason: str = REASON_NEW_PAIR,
    dedup_key: str | None = None,
    at: datetime | None = None,
) -> int:
    """Вставить решение прямым SQL, минуя домен и писателя: так проверяются ограничения базы.

    `marker` обязателен: уборка файла ищет строки по `details->>'probe'`, и решение без маркера
    осталось бы в базе для следующих шагов job'а — то есть следующий файл увидел бы чужие строки
    в «последних решениях» страницы.

    Возвращает выданный базой `id`. `flush()` внутри помощника: отказ ограничения обязан приходить
    на строке вызова, а не отдельным оператором внутри `pytest.raises` (`PT012`).
    """
    statement = text(
        "INSERT INTO web_audit_outbox (at, ground, outcome, reason, audit_id, user_id, dedup_key, "
        "details) "
        "VALUES (:at, :ground, :outcome, :reason, :audit_id, :user_id, :dedup_key, "
        "CAST(:details AS jsonb)) "
        "RETURNING id"
    )
    row = session.execute(
        statement,
        {
            "at": at if at is not None else utc_now(),
            "ground": ground,
            "outcome": outcome,
            "reason": reason,
            "audit_id": audit_id,
            "user_id": user_id,
            "dedup_key": dedup_key,
            "details": json.dumps({"probe": marker}),
        },
    ).first()
    session.flush()
    assert row is not None, "вставка решения не вернула строку"
    record_id = row[0]
    assert isinstance(record_id, int), f"web_audit_outbox.id имеет неожиданный тип {type(row[0])}"
    return record_id


def _delete_audit(session: Session, audit_id: int) -> None:
    """Удаление строки журнала под решением — одной операцией.

    Блок `pytest.raises` обязан содержать единственное простое выражение: иначе в него
    попадают соседние операторы, и отказ можно приписать не тому шагу. По существу здесь важно
    другое: проверяется ровно один оператор `DELETE`, и `flush` обязана войти в тот же вызов,
    иначе отказ внешнего ключа не возник бы к моменту проверки.
    """
    session.execute(text("DELETE FROM audit_log WHERE id = :id"), {"id": audit_id})
    session.flush()


def _sqlstate(error: IntegrityError) -> str | None:
    orig = error.orig
    return getattr(orig, "sqlstate", None)


# ─── страж повторной рассылки (`ix_web_audit_outbox_dedup_key`) ───────────────────────────────


def test_страж_деидентификации_отклоняет_второй_ключ_кодом_23505(
    session: Session,
) -> None:
    """Двух строк `notify` на один ключ не существует — и отклоняет это база, а не код порога.

    Смысл проверки в том, кто именно отказывает: путь записи один (`append_notify_decision`), и
    если бы защиту держала только «проверка перед вставкой», два процесса (`web` и будущая
    рассылка) или повтор запроса породили бы два уведомления на одно сочетание — ровно тот дефект,
    ради которого §8.7 требует порога. Отказ приходит и под ролью-владельцем схемы: append-only
    права из `roles.sql` у владельца не действуют, поэтому это проверка индекса, а не прав.
    """
    marker = _marker()
    user_id = _probe_user(session, marker)
    audit = _probe_audit(session, marker, actor=user_id)
    other = _probe_audit(session, marker, action="session.login", index=2, actor=user_id)
    key = f"{GROUND_LOGIN}:{user_id}:{'d' * 32}"

    first = _insert_raw(session, audit_id=audit.id, user_id=user_id, dedup_key=key, marker=marker)
    assert first > 0, "первое решение не получило идентификатор базы"

    with pytest.raises(IntegrityError) as captured:
        _insert_raw(session, audit_id=other.id, user_id=user_id, dedup_key=key, marker=marker)
    assert _sqlstate(captured.value) == _UNIQUE_VIOLATION, (
        f"ожидался отказ уникальности ({_UNIQUE_VIOLATION}), получено "
        f"{_sqlstate(captured.value)}: {captured.value}"
    )


def test_молчание_без_ключа_не_ограничено_индексом(session: Session) -> None:
    """Несколько `muted`-строк на одно основание существуют: предикат индекса их не покрывает.

    Это вторая половина того же индекса, и она важнее первой: если бы частичность убрали (или
    ключ давал `muted`-строкам), первая же строка молчания приклеила бы молчание к основанию
    навсегда, и новое сочетание не получило бы уведомления никогда. Проверка держит и то, что
    `NULL` в уникальном индексе не конфликтует сам с собой — тот же приём, что у
    `ix_audit_log_hash_prev_linked` в `0007`.
    """
    marker = _marker()
    user_id = _probe_user(session, marker)
    first = _probe_audit(session, marker)
    second = _probe_audit(session, marker, index=2)
    third = _probe_audit(session, marker, index=3)

    ids = [
        _insert_raw(
            session,
            audit_id=entry.id,
            user_id=user_id,
            outcome="muted",
            reason=REASON_KNOWN_PAIR,
            dedup_key=None,
            marker=marker,
        )
        for entry in (first, second, third)
    ]
    assert len(set(ids)) == 3, f"молчания склеились: {ids}"
    count = session.execute(
        text("SELECT count(*) FROM web_audit_outbox WHERE details->>'probe' = :marker"),
        {"marker": marker},
    ).first()
    assert count is not None, "подсчёт строк молчания не вернул строку"
    assert count[0] == 3, f"строк молчания не три: {count}"


def test_ON_CONFLICT_DO_NOTHING_гасит_повтор_без_строки_и_без_идентификатора(
    session: Session,
) -> None:
    """Боевой писатель: первый вызов возвращает `id`, повтор — `None`, строка одна.

    Проверяется именно общий слой записи (`packages/storage/audit_store.py`), а не похожий на него
    запрос: на площадке решения пишут два процесса, и «кто-то вставил повторно» обязано гаситься
    базой без исключения и без второй строки. Здесь же держится обратное различие с журналом:
    на `audit_log` такой обход запрещён (`ADR-025` п. 4), потому что там несозданная строка — это
    дыра в доказательстве, а здесь — требуемое поведение порога.
    """
    marker = _marker()
    user_id = _probe_user(session, marker)
    audit = _probe_audit(session, marker, actor=user_id)
    key = f"{GROUND_LOGIN}:{user_id}:{'e' * 32}"

    decision = _decision(marker, user_id=user_id, dedup_key=key)
    first = append_notify_decision(session, decision=decision, audit_id=audit.id, at=utc_now())
    assert first is not None, "первое решение не записалось"
    assert isinstance(first, int), "идентификатор решения не целочисленный"
    assert first > 0, "идентификатор решения нулевой или отрицательный"

    again = append_notify_decision(
        session,
        decision=_decision(marker, user_id=user_id, dedup_key=key),
        audit_id=audit.id,
        at=utc_now(),
    )
    assert again is None, (
        f"повтор вернул идентификатор {again!r}: `ON CONFLICT DO NOTHING` не отработал, "
        "и на одно сочетание пришлось бы два уведомления"
    )
    rows = session.execute(
        text("SELECT id FROM web_audit_outbox WHERE dedup_key = :key"),
        {"key": key},
    ).all()
    assert len(rows) == 1, f"строк с одним ключом не одна: {[row[0] for row in rows]}"


# ─── ссылка на журнал (`fk_web_audit_outbox_audit_id_audit_log`) ──────────────────────────────


def test_решение_не_ссылается_на_несуществующую_строку_журнала(
    session: Session,
) -> None:
    """Выдуманный `audit_id` отклоняется `23503`, а писатель превращает это в `NotifyAuditLinkError`.

    Ссылка — единственный носитель адреса, субъекта и `request_id` разбора (`ADR-028` п. 2):
    решение без неё нельзя ни подтвердить, ни опровергнуть, и раздел администрирования показал бы
    строку, которую нечем разобрать. Класс исключения обязан быть доменным: вызывающий слой не
    должен разбирать код состояния psycopg.
    """
    marker = _marker()
    user_id = _probe_user(session, marker)
    used = session.execute(text("SELECT COALESCE(max(id), 0) + 1000 FROM audit_log")).first()
    assert used is not None, "запрос максимального идентификатора не вернул строку"
    absent_id = int(used[0])

    # Ключ на этой вставке обязателен, и это не придирка, а замер CI `45373614300`: `CHECK`
    # (`ck_web_audit_outbox_notify_has_dedup_key`) исполняется раньше внешнего ключа, поэтому
    # `notify` без ключа отвечает `23514`, и проверка `23503` просто не наступила бы — пал бы не
    # тот контроль, а сама проверка ссылки исчезла бы молча.
    broken_link_key = f"{GROUND_LOGIN}:{user_id}:{'a' * 32}"

    with pytest.raises(IntegrityError) as captured:
        _insert_raw(
            session,
            audit_id=absent_id,
            user_id=user_id,
            dedup_key=broken_link_key,
            marker=marker,
        )
    assert _sqlstate(captured.value) == SQLSTATE_FOREIGN_KEY_VIOLATION, (
        f"ожидался отказ внешнего ключа ({SQLSTATE_FOREIGN_KEY_VIOLATION}), получено "
        f"{_sqlstate(captured.value)}: {captured.value}"
    )
    session.rollback()

    writer_key = f"{GROUND_LOGIN}:{user_id}:{'f' * 32}"
    with pytest.raises(NotifyAuditLinkError):
        append_notify_decision(
            session,
            decision=_decision(marker, user_id=user_id, dedup_key=writer_key),
            audit_id=absent_id,
            at=utc_now(),
        )


def test_строка_журнала_под_решением_не_удаляется(session: Session) -> None:
    """`ON DELETE RESTRICT` держит ссылку: сначала убирают решения, потом журнал.

    Если бы удаление отпускало ссылку, вырезка строки журнала оставляла бы «висячее» решение:
    раздел показывал бы повод, а разобрать его было бы нечем — и это выглядело бы как подделка
    журнала, обнаруженная задним числом. Порядок обратного хода (`ADR-028` п. 7) обязана соблюдать
    и регламентная очистка: горячее окно 90 суток снимают с решений раньше, чем с журнала.
    """
    marker = _marker()
    user_id = _probe_user(session, marker)
    audit = _probe_audit(session, marker, actor=user_id)
    key = f"{GROUND_LOGIN}:{user_id}:{'0' * 32}"
    decision_id = _insert_raw(
        session, audit_id=audit.id, user_id=user_id, dedup_key=key, marker=marker
    )

    with pytest.raises(IntegrityError) as captured:
        _delete_audit(session, audit.id)
    assert _sqlstate(captured.value) == SQLSTATE_FOREIGN_KEY_VIOLATION, (
        f"ожидался отказ внешнего ключа ({SQLSTATE_FOREIGN_KEY_VIOLATION}), получено "
        f"{_sqlstate(captured.value)}: {captured.value}"
    )
    session.rollback()

    # Та же строка журнала удаляется, когда ссылка снята: порядок уборки выполним, а не вечен.
    session.execute(text("DELETE FROM web_audit_outbox WHERE id = :id"), {"id": decision_id})
    session.execute(text("DELETE FROM audit_log WHERE id = :id"), {"id": audit.id})
    session.flush()
    left = session.execute(
        text("SELECT count(*) FROM audit_log WHERE entity_id LIKE :prefix"),
        {"prefix": f"{marker}%"},
    ).first()
    assert left is not None, "подсчёт строк журнала не вернул строку"
    assert left[0] == 0, f"строки журнала остались: {left}"


# ─── домены и формы (`ck_web_audit_outbox_*`) ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("ground", "outcome", "reason", "dedup_key", "ожидание"),
    [
        ("session.password_changed", "notify", REASON_NEW_PAIR, "session.login:x:y", "основание"),
        ("totp.revoked", "notify", REASON_NEW_PAIR, "session.login:x:y", "основание"),
        ("session.login", "sent", REASON_NEW_PAIR, "session.login:x:y", "вердикт"),
        ("session.login", "delivered", REASON_NEW_PAIR, "session.login:x:y", "вердикт"),
        ("session.login", "muted", "new pair", None, "форма причины"),
        ("session.login", "muted", "Новая_пара", None, "форма причины"),
        ("session.login", "notify", REASON_NEW_PAIR, "Session.Login:x", "форма ключа"),
        ("session.login", "notify", REASON_NEW_PAIR, "session.login:x y", "форма ключа"),
        ("session.login", "notify", REASON_NEW_PAIR, None, "notify без ключа"),
    ],
)
def test_ограничения_базы_отклоняют_значения_вне_домена(
    session: Session,
    ground: str,
    outcome: str,
    reason: str,
    dedup_key: str | None,
    ожидание: str,
) -> None:
    """Каждое ограничение из ревизии `0006` отказывает по своему, а не «что-то одно».

    Проверка параметризована ровно потому, что разные ограничения дают один и тот же код `23514`:
    если бы в файле прав или в ревизии пропало одно из них, общая проверка «база ругается» осталась
    бы зелёной. Отдельно держится «`notify` без ключа»: без него стражу повтора нечего проверять, и
    база обязана не принимать такое решение, даже если приложение его не производит.

    Порядок отказа заметен и сам по себе (замер CI `45373614300`): строка, которая нарушает и
    `CHECK`, и ссылку на журнал, отвечает `23514`, а не `23503`. Значит, проверка внешнего ключа
    обязана давать корректный остальной набор полей — иначе вместо ожидаемого отказа ссылки
    приходит отказ домена, и проверка ссылки превращается в проверку `CHECK`.
    """
    marker = _marker()
    user_id = _probe_user(session, marker)
    audit = _probe_audit(session, marker, actor=user_id)
    session.commit()

    with pytest.raises(IntegrityError) as captured:
        _insert_raw(
            session,
            audit_id=audit.id,
            user_id=user_id,
            marker=marker,
            ground=ground,
            outcome=outcome,
            reason=reason,
            dedup_key=dedup_key,
        )
    assert _sqlstate(captured.value) == _CHECK_VIOLATION, (
        f"{ожидание}: ожидался отказ ограничения ({_CHECK_VIOLATION}), получено "
        f"{_sqlstate(captured.value)}: {captured.value}"
    )
    session.rollback()


def test_момент_решения_остаётся_моментом_события(session: Session) -> None:
    """Колонка имеет `server_default now()`, но база обязана сохранить переданный момент.

    Порог сравнивает «уведомляли ли в окне» по моменту решения, а решение обязано оставаться
    привязанным к событию, которое его породило (`ADR-025` п. 2: момент, который хэшировали в
    журнале, и момент колонки не должны расходиться). Подмена на `now()` означала бы, что при
    разборе окна считаются не тем числом, а ошибка была бы видна только на площадке — колонка-то
    заполнена.
    """
    marker = _marker()
    user_id = _probe_user(session, marker)
    moment = datetime.now(UTC).replace(microsecond=0) - timedelta(days=1)
    audit = _probe_audit(session, marker, actor=user_id, at=moment)
    key = f"{GROUND_LOGIN}:{user_id}:{'1' * 32}"

    decision_id = append_notify_decision(
        session,
        decision=_decision(marker, user_id=user_id, dedup_key=key),
        audit_id=audit.id,
        at=moment,
    )
    assert decision_id is not None, "решение не записалось"
    row = session.execute(
        text("SELECT at, audit_id FROM web_audit_outbox WHERE id = :id"),
        {"id": decision_id},
    ).first()
    assert row is not None, "решение не читается"
    stored_at, stored_audit_id = row
    assert stored_at.utcoffset() is not None, "момент решения вернулся без признака часового пояса"
    assert (
        stored_at.astimezone(UTC) == moment
    ), f"база подменила момент решения: {stored_at} вместо {moment}"
    assert stored_audit_id == audit.id, "ссылка на строку журнала разошлась с вставленной"


# ─── что читают порог и раздел: состояние и последние строки ──────────────────────────────────


def test_состояние_порога_видит_ключ_и_последний_прогон(session: Session) -> None:
    """`read_login_notice_state`: «ключ уже занят» и «когда уведомляли в последний раз».

    Оба значения читаются **до** решения одним обращением (`ADR-026` п. 4). Проверка обязана быть
    живой, потому что в памяти нет полутора вещей: `known_pair` выводится из частичного индекса
    (строки `muted` ключа не имеют, и «было молчание» не должно считаться встречей сочетания), а
    `last_notify_at` — максимум `at` только по основаниям входа с вердиктом `notify`, из всех
    строк учётной записи, включая строки другого повода.

    Третья половина проверки — поведение после второй строки: окно обязано сдвигаться по
    последнему уведомлению, иначе молчание считалось бы по самому первому событию.
    """
    marker = _marker()
    user_id = _probe_user(session, marker)
    pair = login_pair(user_id=user_id, address="198.51.100.77", user_agent="notify-live-device")

    initial = read_login_notice_state(session, user_id=user_id, dedup_key=pair.dedup_key)
    assert not initial.known_pair, "сочетание объявлено встречавшимся до первой строки"
    assert initial.last_notify_at is None, "окно посчитано по чужим строкам таблицы"

    audit = _probe_audit(session, marker, actor=user_id)
    first_moment = utc_now()
    decision = decide_login_notice(
        initial, pair=pair, user_id=user_id, now=first_moment, auth_step=AUTH_STEP_FULL
    )
    assert (decision.outcome, decision.reason) == ("notify", REASON_NEW_PAIR)
    assert (
        append_notify_decision(session, decision=decision, audit_id=audit.id, at=first_moment)
        is not None
    )

    after = read_login_notice_state(session, user_id=user_id, dedup_key=pair.dedup_key)
    assert after.known_pair, "строка `notify` с тем же ключом не опознана: второе уведомление"
    assert after.last_notify_at is not None
    assert after.last_notify_at.astimezone(UTC) == first_moment.astimezone(
        UTC
    ), "последний прогон прочитан не по строке решения"

    other = login_pair(user_id=user_id, address="198.51.100.78", user_agent="notify-live-device")
    inside = read_login_notice_state(session, user_id=user_id, dedup_key=other.dedup_key)
    assert not inside.known_pair, "новое сочетание опознано как известное: окно и ключ склеились"
    assert inside.last_notify_at is not None, (
        "окно не видит уведомление по другому сочетанию той же учётной записи: порог шумит при "
        "сменах адреса"
    )
    decision_inside = decide_login_notice(
        inside,
        pair=other,
        user_id=user_id,
        now=first_moment + timedelta(minutes=2),
        auth_step=AUTH_STEP_FULL,
    )
    assert (decision_inside.outcome, decision_inside.reason) == ("muted", REASON_LOGIN_COOLDOWN)
    assert (
        decision_inside.dedup_key is None
    ), "у молчания появился ключ: следующее новое сочетание было бы объявлено уже уведомлённым"

    spend_audit = _probe_audit(session, marker, action="backup_code.spent", index=2, actor=user_id)
    spend = append_notify_decision(
        session,
        decision=NotifyDecision(
            ground=GROUND_BACKUP_CODE_SPENT,
            outcome="notify",
            reason=REASON_BACKUP_CODE_SPENT,
            dedup_key=backup_code_dedup_key(uuid.uuid4()),
            user_id=user_id,
            details={"probe": marker},
        ),
        audit_id=spend_audit.id,
        at=first_moment + timedelta(minutes=3),
    )
    assert spend is not None, "решение о расходе кода не записалось"
    window = read_login_notice_state(session, user_id=user_id, dedup_key=other.dedup_key)
    assert window.last_notify_at is not None
    assert window.last_notify_at.astimezone(UTC) == first_moment.astimezone(UTC), (
        "окно входа сдвинулось строкой другого основания: порог входа стал бы зависеть от "
        "расхода резервных кодов"
    )


def test_раздел_читает_свежие_строки_по_границе_и_учётную_запись(
    session: Session,
) -> None:
    """`read_notify_decisions`: newest-first, граница по `limit`, логин по join'у.

    Страница раздела администрирования обязана видеть те же колонки, что читает разбор: «раздел
    сказал „пусто“, а разбор нашёл строки» — расхождение двух путей чтения (`ADR-025` п. 7 для
    журнала). Отдельно держится `outerjoin` по учётной записи: основания общего уровня
    (`risk.*`, `token.revoked`) существуют в домене без учётной записи, и внутреннее соединение
    молча выбросило бы их со страницы.
    """
    marker = _marker()
    user_id = _probe_user(session, marker)
    older = _probe_audit(session, marker, actor=user_id)
    newer = _probe_audit(session, marker, action="backup_code.spent", index=2, actor=user_id)
    base = utc_now()

    first_id = _insert_raw(
        session,
        audit_id=older.id,
        user_id=user_id,
        at=base,
        dedup_key=f"{GROUND_LOGIN}:{user_id}:{'2' * 32}",
        marker=marker,
    )
    second_id = _insert_raw(
        session,
        audit_id=newer.id,
        user_id=user_id,
        ground=GROUND_BACKUP_CODE_SPENT,
        reason=REASON_BACKUP_CODE_SPENT,
        at=base + timedelta(minutes=1),
        dedup_key=backup_code_dedup_key(uuid.uuid4()),
        marker=marker,
    )
    session.commit()

    rows = read_notify_decisions(session, limit=5000)
    probe_rows = [row for row in rows if row.audit_id in (older.id, newer.id)]
    assert [row.id for row in probe_rows] == [
        second_id,
        first_id,
    ], f"строки идут не от свежих к старым: {[(row.id, row.ground) for row in probe_rows]}"
    assert all(
        row.login is not None for row in probe_rows
    ), "учётная запись повода не прочитана: страница показала бы пустое место вместо логина"

    limited = read_notify_decisions(session, limit=1)
    assert len(limited) == 1, f"граница выборки не соблюдена: {len(limited)} строк"
    assert [row.id for row in limited] == [row.id for row in rows][
        :1
    ], "граница отсекла не старые строки: страница показала бы самое старое вместо свежего"


def test_решение_не_пишет_строку_журнала_и_не_двигает_цепочку(session: Session) -> None:
    """Вопрос порога не создаёт событие журнала: след один, цепочка одна.

    У входа две строки `session.login` (шаг пароля и шаг `full`), и каждая уже является событием
    §8.4. Если бы писатель решений дописывал и журнал, «порог спрошен» оставлял бы второй след,
    разбор цепочки видел бы строки, которых приложение не собиралось писать, а счётчик поводов
    §8.7 перестал бы совпадать с числом событий. Отдельно держится, что хэш хвоста не меняется:
    журнал остаётся той же цепочкой (`ADR-025` п. 3 — второй цепочки здесь нет намеренно).
    """
    marker = _marker()
    user_id = _probe_user(session, marker)
    audit = _probe_audit(session, marker, actor=user_id)
    session.commit()

    tail_before = session.execute(text("SELECT count(*), max(hash) FROM audit_log")).first()
    assert tail_before is not None, "счётчик журнала не вернул строку"

    decision_id = append_notify_decision(
        session,
        decision=_decision(
            marker, user_id=user_id, dedup_key=f"{GROUND_LOGIN}:{user_id}:{'3' * 32}"
        ),
        audit_id=audit.id,
        at=utc_now(),
    )
    session.commit()
    assert decision_id is not None, "решение не записалось"

    tail_after = session.execute(text("SELECT count(*), max(hash) FROM audit_log")).first()
    assert tail_after is not None, "счётчик журнала не вернул строку"
    assert (
        tail_after[0] == tail_before[0]
    ), f"запись решения добавила строку журнала: {tail_before[0]} → {tail_after[0]}"
    assert (
        tail_after[1] == tail_before[1]
    ), "хэш последней строки журнала изменился: решение затронуло цепочку"
