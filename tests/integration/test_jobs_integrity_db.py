"""Ежедневная `integrity-check` поверх живой схемы (TZ §8.7, `ADR-025` п. 6 и п. 9, `T-109` `R3.2`).

Живая половинка проверяет то, чего память не показывает: строка проверки привязывается к
**настоящему** хвосту цепочки (`hash_prev` из колонки `hash` последней строки журнала), `details`
возвращаются из `jsonb` в той же форме, которую отхэшировало приложение, а правка и вырез строки
ролью-владельцем схемы находятся прогоном с тем же вердиктом, что у ручной команды.

Оффлайновая половинка — `tests/integration/test_jobs_integrity.py` (вердикты по четырём кодам,
содержимое `details`, порядок «чтение → запись», пороги §12.4).

Что здесь держится и почему именно так:

* **прочитанная выборка ограничена интервалом `id`** (`read_audit_journal(from_id=…, to_id=…)`):
  в таблице к этому шагу уже лежат строки других живых проверок, часть из них намеренно порчена
  (шаг «разбор цепочки инструментом»), поэтому полная выборка давала бы находки по чужим строкам.
  Границы по `id` — тот же механизм выборки, что у `make audit-verify` при разборе копии дампа, и
  он же показывает `missing_prefix` пометкой, а не находкой;
* **строка проверки обязана продолжать цепочку**: `hash_prev` новой строки равен `hash`
  предшественницы, иначе ежедневная проверка сама создала бы `broken_link` и `duplicate_parent`, а
  страж `ix_audit_log_hash_prev_linked` отклонил бы второй прогон с `23505`;
* **строка пишется при каждом прогоне** (ask `e98befe2-…`): и при «цепочка цела», и при находке —
  иначе «проверка не запускалась» неотличима от «всё в порядке»;
* **`actor` пустой** (там же): `audit_log.actor` ссылается на `users.id` с `RESTRICT`, и живой FK
  отклонил бы произвольного «системного агента» с `23503` — проверка держит факт пустого значения
  в колонке, а не намерение кода;
* **отказ базы не оставляет строки о проверке**: тот же смысл, что у кода возврата `3` у ручной
  команды (`ADR-025` п. 7).

Уборка — по маркеру `entity_id` посевных строк и по `details ->> 'run_id'` у строк проверки:
чужие строки job'а не удаляются, строки пользователей не удаляются вовсе (§4.1: удаление учётной
записи — только архивированием).
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Final

import pytest
from sqlalchemy import Engine, create_engine, delete, func, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from apps.jobs.integrity import (
    CHECK_ACTION,
    DISK_OK,
    ENTITY_AUDIT_LOG,
    VERDICT_EMPTY,
    VERDICT_FINDINGS,
    VERDICT_INTACT,
    DiskUsage,
    RowsReader,
    run_integrity_check,
)
from packages.common import metrics
from packages.common.db import sqlalchemy_url
from packages.identity.audit import (
    AUDIT_ACTIONS,
    StoredRecord,
    make_record,
    verify_chain,
)
from packages.storage.audit_store import append_audit_record, read_audit_journal
from packages.storage.models import AuditLogEntry

# Читается до аутофикстуры `clean_tbot_env`: на уровне модуля решается, идти ли в группу целиком.
_DB_URL = os.environ.get("TBOT_DB_URL", "")

#: Маркер строк этого файла (`entity_id` — текст, §4.1). Отличается от `t109r1` и `t109r2`.
_MARKER_PREFIX: Final = "t109r32"

_ACTIONS: Final = ("session.login", "session.logout", "session.revoke", "backup_code.spent")

#: Момент прогона фиксирован: `at` входит в материал хэша, и проверка не должна зависеть от часов
#: раннера (`ADR-025` п. 2).
_MOMENT: Final = datetime(2026, 11, 23, 13, 0, 0, tzinfo=UTC)

#: Замер места подставляется: живой прогон проверяет цепочку, а не размер диска раннера. Значение
#: выбрано так, чтобы состояние свободного места было `ok` и не влияло на вердикт.
_DISK: Final = DiskUsage(path="/ci", total_bytes=100_000, free_bytes=90_000)

#: Адрес, до которого нельзя достучаться: состояние «база недоступна» (смысл кода `3`, `ADR-025`
#: п. 7). `connect_timeout=2` обязателен: там, где файрвол молча держит соединение вместо отказа
#: (замер на Windows — 130.03 с на тот же адрес без параметра), проверка не должна ждать.
_UNREACHABLE_DSN: Final = "postgresql://tbot:ci-only-password@127.0.0.1:1/tbot_ci?connect_timeout=2"

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


def _marker() -> str:
    return f"{_MARKER_PREFIX}-{uuid.uuid4().hex[:10]}"


def _seed(engine: Engine, marker: str, count: int) -> list[int]:
    """Добавить `count` строк журнала общим протоколом; вернуть выданные базой `id`.

    Именно `append_audit_record`, а не прямая `INSERT`: посев обязан оставлять корректную
    цепочку, иначе находка разрыва в проверке означала бы «мы сами её испортили», а не «проверка
    нашла подделку».
    """
    ids: list[int] = []
    with Session(engine) as session:
        for index in range(count):
            record = make_record(
                action=_ACTIONS[index % len(_ACTIONS)],
                at=_MOMENT + timedelta(minutes=index),
                entity="session",
                entity_id=f"{marker}-{index}",
                details={"index": index},
            )
            ids.append(append_audit_record(session, record))
        session.commit()
    return ids


def _window_reader(lo: int, hi: int) -> RowsReader:
    """Читатель ограниченной выборки: те же границы по `id`, что у `make audit-verify`.

    Ограничение нужно, чтобы разбор касался только посева этого файла: в таблице к шагу уже лежат
    строки других живых проверок, часть из них намеренно порчена.
    """

    def read(session: Session) -> list[StoredRecord]:
        return read_audit_journal(session, from_id=lo, to_id=hi)

    return read


def _run(engine: Engine, *, lo: int, hi: int, run_id: str) -> None:
    """Один прогон ежедневной задачи на ограниченной выборке."""
    run_integrity_check(
        engine,
        app="jobs",
        rows_reader=_window_reader(lo, hi),
        disk_reader=lambda _path: _DISK,
        moment=_MOMENT,
        run_id=run_id,
    )


def _total_rows(engine: Engine) -> int:
    """Сколько строк в журнале сейчас: нужно для сверки с полной выборкой."""
    with Session(engine) as session:
        return int(session.scalar(select(func.count()).select_from(AuditLogEntry)) or 0)


def _check_rows(engine: Engine, run_id: str) -> list[AuditLogEntry]:
    """Строки `integrity.audit_chain` этого прогона: их идентификатор — только в `details`.

    `entity_id` у строки проверки пуст (у журнала как объекта нет одного `id`), поэтому маркер
    прогона читается из `details`: `run_id` заведён ровно для того, чтобы строку проверки можно
    было найти, не выдумывая ей объект.
    """
    statement = (
        select(AuditLogEntry)
        .where(
            AuditLogEntry.action == CHECK_ACTION,
            text("details ->> 'run_id' = :run_id"),
        )
        .order_by(AuditLogEntry.id)
    )
    with Session(engine) as session:
        return list(session.execute(statement, {"run_id": run_id}).scalars().all())


def _hash_of(engine: Engine, row_id: int) -> str | None:
    with Session(engine) as session:
        return session.scalar(select(AuditLogEntry.hash).where(AuditLogEntry.id == row_id))


def _details_of(engine: Engine, row_id: int) -> dict[str, object]:
    """`details` прочитанной строки: psycopg отдаёт `jsonb` словарём, форма проверяется как есть."""
    with Session(engine) as session:
        value = session.scalar(select(AuditLogEntry.details).where(AuditLogEntry.id == row_id))
    assert isinstance(value, dict)
    return {str(key): item for key, item in value.items()}


def _window_rows(engine: Engine, lo: int, hi: int) -> list[StoredRecord]:
    """Прочитать выборку так же, как её читает разбор (`read_audit_journal`)."""
    with Session(engine) as session:
        return read_audit_journal(session, from_id=lo, to_id=hi)


def _cleanup(engine: Engine, marker: str, run_ids: tuple[str, ...]) -> None:
    """Убрать посев по маркеру и строки проверки по `run_id`.

    Уборка обязана быть в `finally`: упавший ассерт оставил бы строки, и следующая проверка
    читала бы чужие находки. Строки пользователей не удаляются: §4.1 разрешает убирать учётную
    запись только архивированием.
    """
    with engine.begin() as connection:
        connection.execute(delete(AuditLogEntry).where(AuditLogEntry.entity_id.like(f"{marker}%")))
        for run_id in run_ids:
            connection.execute(
                delete(AuditLogEntry).where(
                    AuditLogEntry.action == CHECK_ACTION,
                    text("details ->> 'run_id' = :run_id"),
                ),
                {"run_id": run_id},
            )


# ─── строка проверки как часть цепочки ─────────────────────────────────────────────────────


def test_прогон_дописывает_строку_в_хвост_цепочки(engine: Engine) -> None:
    """Вердикт «цело» остаётся записью в журнале, и эта запись продолжает цепочку.

    Три вещи, которые показывает только база: `hash_prev` строки проверки равен `hash` последней
    посеянной строки (порядок «сначала разбор, потом строка» — `ADR-025` п. 9), `actor` в колонке
    пуст (живой FK на `users.id` отклонил бы выдуманного агента с `23503`), и `details`
    возвращаются из `jsonb` счётчиками ровно теми числами, которые отхэшировало приложение.
    """
    marker = _marker()
    run_id = f"{marker}-run1"
    ids = _seed(engine, marker, 3)
    lo, hi = min(ids), max(ids)
    try:
        _run(engine, lo=lo, hi=hi, run_id=run_id)
        rows = _check_rows(engine, run_id)
        assert len(rows) == 1, "прогон обязан оставить ровно одну строку"
        check = rows[0]
        assert check.actor is None, "актор проверки — не учётная запись (`ADR-026` п. 2)"
        assert check.entity == ENTITY_AUDIT_LOG
        assert check.entity_id is None, "у журнала как объекта нет одного `id`"
        assert check.hash_prev == _hash_of(engine, hi), "строка не привязана к хвосту цепочки"
        details = _details_of(engine, int(check.id))
        assert details["run_id"] == run_id
        assert details["verdict"] == VERDICT_INTACT
        assert details["rows"] == 3
        assert details["missing_prefix"] == 1, "начало выборки помечается, но вердикт не меняет"
        assert details["content_mismatch"] == 0
        assert details["broken_link"] == 0
        assert details["duplicate_parent"] == 0
        assert details["disk_state"] == DISK_OK
        assert details["issue_row_ids"] == []
    finally:
        _cleanup(engine, marker, (run_id,))


def test_повторный_прогон_не_разрывает_цепочку(engine: Engine) -> None:
    """Два прогона задают две строки подряд: страж развилки не должен отклонить вторую.

    Если бы чекер вставлял строку до пересчёта (или читал хвост до замка), второй прогон упёрся бы
    в `ix_audit_log_hash_prev_linked` с `23505`, а разбор показал бы `broken_link` там, где
    приложение само нарушило порядок (`ADR-025` п. 6 и п. 9).
    """
    marker = _marker()
    first = f"{marker}-run1"
    second = f"{marker}-run2"
    ids = _seed(engine, marker, 2)
    lo, hi = min(ids), max(ids)
    try:
        _run(engine, lo=lo, hi=hi, run_id=first)
        _run(engine, lo=lo, hi=hi, run_id=second)
        rows = sorted(
            [*_check_rows(engine, first), *_check_rows(engine, second)],
            key=lambda row: row.id,
        )
        assert len(rows) == 2
        assert rows[1].hash_prev == _hash_of(engine, int(rows[0].id))
        # Строки проверки читаются разбором как обычные строки журнала: пересчёт по их колонкам
        # совпадает с сохранённым `hash`, иначе ежедневная проверка ломает то, что проверяет.
        report = verify_chain(_window_rows(engine, lo, int(rows[1].id)), expect_genesis=False)
        kinds = {issue.kind for issue in report.issues}
        assert "content_mismatch" not in kinds
        assert "broken_link" not in kinds
        assert "duplicate_parent" not in kinds
    finally:
        _cleanup(engine, marker, (first, second))


# ─── находки: правка и вырез строки ролью-владельцем схемы ─────────────────────────────────


def test_ручная_правка_строки_даёт_вердикт_findings(engine: Engine) -> None:
    """Правка `details` правами владельца схемы меняет содержимое и находится прогоном.

    Роль приложения правку не сделала бы (append-only, `deploy/postgres/roles.sql`), а владелец
    может — ровно ради этого цепочка и заведена (`AC-identity-04`: изменённая вручную копия дампа
    должна быть найдена). Строка о прогоне при этом всё равно появляется: вердикт «нарушено» —
    тоже результат проверки.
    """
    marker = _marker()
    run_id = f"{marker}-edit"
    ids = _seed(engine, marker, 3)
    lo, hi = min(ids), max(ids)
    victim = ids[1]
    try:
        with engine.begin() as connection:
            connection.execute(
                text("""update audit_log set details = '{"index": 424}'::jsonb where id = :vid"""),
                {"vid": victim},
            )
        _run(engine, lo=lo, hi=hi, run_id=run_id)
        rows = _check_rows(engine, run_id)
        assert len(rows) == 1
        details = _details_of(engine, int(rows[0].id))
        assert details["verdict"] == VERDICT_FINDINGS
        assert details["content_mismatch"] == 1
        assert details["issue_row_ids"] == [victim]
        assert details["broken_link"] == 0
    finally:
        _cleanup(engine, marker, (run_id,))


def test_вырез_строки_даёт_broken_link(engine: Engine) -> None:
    """Вырез средней строки: связь следующей строки с предыдущей рвётся, и это видно в `details`.

    Удаление строки — тот же класс поломки, что и правка: журнал теряет доказательство, а не
    «становится короче». Порядок чтения задаёт `id`, поэтому разрыв обнаруживается без знания о
    том, какая именно строка пропала.
    """
    marker = _marker()
    run_id = f"{marker}-cut"
    ids = _seed(engine, marker, 3)
    lo, hi = min(ids), max(ids)
    victim = ids[1]
    try:
        with engine.begin() as connection:
            connection.execute(delete(AuditLogEntry).where(AuditLogEntry.id == victim))
        _run(engine, lo=lo, hi=hi, run_id=run_id)
        rows = _check_rows(engine, run_id)
        assert len(rows) == 1
        details = _details_of(engine, int(rows[0].id))
        assert details["verdict"] == VERDICT_FINDINGS
        assert details["broken_link"] == 1
        assert details["rows"] == 2
    finally:
        _cleanup(engine, marker, (run_id,))


# ─── прогон против журнала целиком и отказ базы ────────────────────────────────────────────


def test_прогон_всей_выборки_читает_столько_же_строк_сколько_в_журнале(engine: Engine) -> None:
    """Ежедневный прогон читает журнал целиком — так, как он будет читать на площадке.

    В таблице к этому шагу лежат строки других живых проверок (часть намеренно порченная), поэтому
    проверяется не «вердикт целый», а согласованность: число разобранных строк равно числу строк
    таблицы **до** вставки строки проверки (порядок `ADR-025` п. 9), вердикт определён, и
    идентификаторы находок непусты, если находки есть.
    """
    marker = _marker()
    run_id = f"{marker}-full"
    _seeded = _seed(engine, marker, 2)
    before = _total_rows(engine)
    try:
        run_integrity_check(
            engine,
            app="jobs",
            disk_reader=lambda _path: _DISK,
            moment=_MOMENT,
            run_id=run_id,
        )
        rows = _check_rows(engine, run_id)
        assert len(rows) == 1
        details = _details_of(engine, int(rows[0].id))
        assert details["rows"] == before, "разбор прочитал не весь журнал"
        assert details["verdict"] in {VERDICT_INTACT, VERDICT_FINDINGS, VERDICT_EMPTY}
        findings_total = (
            int(str(details["content_mismatch"]))
            + int(str(details["broken_link"]))
            + int(str(details["duplicate_parent"]))
        )
        assert details["issue_row_ids"] or findings_total == 0
    finally:
        _cleanup(engine, marker, (run_id,))


def test_отказ_базы_не_оставляет_строку_о_проверке(engine: Engine) -> None:
    """Недоступная база: исключение уходит в `run_job` (`job_failed`), журнал не тронут.

    Проверка живая, потому что отказ даёт настоящий драйвер: строки `integrity.audit_chain` нет ни
    при каком коде ошибки. Тот же смысл, что у кода возврата `3` у `make audit-verify`: сломанный
    чекер не должен выглядеть как корректный журнал (`ADR-025` п. 7).
    """
    marker = _marker()
    run_id = f"{marker}-broken"
    _seed(engine, marker, 1)
    broken = create_engine(sqlalchemy_url(_UNREACHABLE_DSN), pool_pre_ping=True)
    try:
        with pytest.raises(OperationalError):
            run_integrity_check(broken, app="jobs", moment=_MOMENT, run_id=run_id)
        assert _check_rows(engine, run_id) == [], "отказ базы оставил строку о проверке"
    finally:
        broken.dispose()
        _cleanup(engine, marker, (run_id,))


def test_метрики_свободного_места_заполняются_живым_прогоном(engine: Engine) -> None:
    """Метрики §12.4 выставляются настоящим прогоном, а не только оффлайновой подстановкой.

    Проверка читает текст `/metrics`: именно его заберёт Prometheus, и имя метрики с меткой `app`
    обязано совпадать с перечнем §12.2/§12.4 (`tbot_disk_free_bytes`).
    """
    marker = _marker()
    run_id = f"{marker}-metrics"
    ids = _seed(engine, marker, 1)
    lo, hi = min(ids), max(ids)
    try:
        _run(engine, lo=lo, hi=hi, run_id=run_id)
        body = metrics.render().decode("utf-8")
        assert 'tbot_disk_free_bytes{app="jobs"} 90000.0' in body
        assert 'tbot_disk_total_bytes{app="jobs"} 100000.0' in body
    finally:
        _cleanup(engine, marker, (run_id,))


def test_посев_использует_имена_из_закрытого_реестра() -> None:
    """Синтетические строки живут на именах из `AUDIT_ACTIONS`: реестр §8.7 закрыт.

    Имя вне реестра отклоняется при записи (`make_record`), поэтому проверка нужна затем, чтобы
    посев не «починили» свободной строкой и живая половинка не потеряла смысл.
    """
    assert set(_ACTIONS) <= set(AUDIT_ACTIONS)
