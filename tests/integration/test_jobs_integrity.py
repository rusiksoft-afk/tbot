"""Ежедневная `integrity-check`: вердикты, содержимое строки и порядок «чтение → запись» (TZ §8.7,
`ADR-025` п. 7 и п. 9 с поправками `ADR-026`, `T-109` срез `R3.2`).

Половинка без базы: `run_integrity_check` вызывается с подставным читателем строк и подставным
замером места, а добавление записи подменяется наблюдателем. Проверяется то, что живая база в
одиночку не покажет: какие вердикты рождают четыре кода находок, что уходит в `details`, что
строка пишется **при каждом** прогоне и что чтение заканчивается раньше вставки.

Живая половинка — `tests/integration/test_jobs_integrity_db.py` (шаг job'а `миграции`): там
настоящая привязка строки проверки к хвосту цепочки, `jsonb` и `INET`, отказ при недоступной базе
и то, что прогон не разрывает цепочку, о которой сам же и докладывает.

Что держится этими проверками и почему именно так:

* **вердикт меняют три кода, а `missing_prefix` — нет** (`ADR-025` п. 7 и п. 8): после первой же
  уборки журнала по §2.8 ежедневная проверка иначе стала бы красной навсегда, и её перестали бы
  читать;
* **набор кодов один для ручной команды и для ежедневной задачи**
  (`packages.identity.audit:FINDING_KINDS`): расхождение выглядит как «команда сказала „цело“,
  задача сказала „нарушено“» на одних и тех же строках — худший исход для инструмента поиска
  подделки;
* **строка о прогоне пишется всегда** (решение заказчика от 2026-11-23, ask
  `e98befe2-db98-499b-9307-4094e5114e75`): без строки «проверка не запускалась» неотличима от
  «цепочка целая»;
* **`actor` пустой** (там же): `audit_log.actor` ссылается на `users.id` с `RESTRICT`, а проверка —
  не учётная запись; идентификатор проверки живёт в `action`, `entity` и `details`;
* **сломанный чекер не докладывает о целом журнале**: при отказе базы исключение уходит в `run_job`
  (`job_failed`), и ни одной строки `integrity.audit_chain` не появляется — тот же смысл, что у
  отдельного кода возврата `3` у `make audit-verify` (`ADR-025` п. 7);
* **свободное место считается по порогам §12.4** (15 % и 8 %) и выкладывается обеими метриками:
  порог задан долей, поэтому одной цифры «свободно» недостаточно.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Final

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

import apps.jobs.integrity as integrity
from apps.jobs.integrity import (
    CHECK_ACTION,
    CHECK_NAME,
    DISK_CRIT,
    DISK_OK,
    DISK_WARN,
    ENTITY_AUDIT_LOG,
    INTEGRITY_CHECK_INTERVAL_S,
    INTEGRITY_JOB_NAME,
    MAX_ISSUE_ROWS,
    VERDICT_EMPTY,
    VERDICT_FINDINGS,
    VERDICT_INTACT,
    DiskUsage,
    IntegrityOutcome,
    build_check_record,
    publish_disk_usage,
    verdict_of,
)
from packages.common import metrics
from packages.common.db import sqlalchemy_url
from packages.identity.audit import (
    AUDIT_ACTIONS,
    FINDING_KINDS,
    INFORMATIONAL_KINDS,
    AuditRecord,
    AuditRecordError,
    StoredRecord,
    chain_from_drafts,
    findings_of,
    make_record,
    verify_chain,
)
from packages.storage.audit_store import append_audit_record, read_audit_journal
from tests.paths import load_script

audit_verify = load_script("audit_verify")

#: Метка первой строки синтетической цепочки. Даты фиксированы: разбираем цепочку, а не часы.
_T0: Final = datetime(2026, 11, 23, 12, 0, 0, tzinfo=UTC)

_ACTIONS: Final = ("session.login", "session.logout", "session.revoke", "backup_code.spent")

#: Движок «без подключения»: `create_engine` соединение не открывает, а чтение строк и вставка в
#: этой половинке подставлены. Тот же приём, что у `tests/unit/test_jobs_registry.py`.
_DSN: Final = "postgresql+psycopg://tbot:ci-only@127.0.0.1:5432/tbot_integrity_check"

#: Адрес, до которого нельзя достучаться: состояние «база недоступна» для проверки смысла кода `3`
#: (`ADR-025` п. 7). `connect_timeout=2` обязателен: на Windows файрвол не отказывает в соединении,
#: а молча держит его, и психологический таймаут psycopg по умолчанию — 130 с (замер локального
#: прогона: 130.03 с на тот же адрес без параметра). На Linux отказ мгновенный, но проверка не
#: должна зависеть от платформы прогоняющей машины.
_UNREACHABLE_DSN: Final = (
    "postgresql://tbot:ci-only@127.0.0.1:1/tbot_integrity_check?connect_timeout=2"
)

#: Замер места вместо настоящего: пороги §12.4 читаются из байтов, а не из диска машины, на
#: которой идёт прогон.
_DISK_TOTAL: Final = 100_000
_DISK_FREE: Final = 60_000


def _draft(index: int) -> AuditRecord:
    """Черновик записи журнала: имя из закрытого реестра, метка — своя у каждой строки."""
    return AuditRecord(
        at=_T0 + timedelta(minutes=index),
        action=_ACTIONS[index % len(_ACTIONS)],
        entity="session",
        entity_id=f"t109r32-{index}",
        details={"index": index},
    )


def _chain(count: int) -> list[StoredRecord]:
    """Корректная цепочка из `count` строк: `hash_prev` и `hash` достроены по канону."""
    return chain_from_drafts(_draft(index) for index in range(count))


def _reworded(row: StoredRecord) -> StoredRecord:
    """Строка с изменённым содержимым и **прежним** `hash`: ровно то, что делает ручная правка.

    Хэш не пересчитан намеренно: `content_mismatch` рождается из несовпадения пересчёта с колонкой
    `hash`, а не из «странного содержимого» (`ADR-025` п. 7).
    """
    record = dataclasses.replace(row.record, details={**dict(row.record.details or {}), "edit": 1})
    return dataclasses.replace(row, record=record)


def _reworded_all(count: int) -> list[StoredRecord]:
    """Весь журнал изменён, хэши прежние: подделка всех строк подряд."""
    return [_reworded(row) for row in _chain(count)]


def _forked(row: StoredRecord, *, row_id: int) -> StoredRecord:
    """Строка-близнец на того же предка: та же `hash_prev`, другое содержимое и другой `hash`.

    Хэш пересчитан честно, поэтому единственная находка — `duplicate_parent`, а не подделка
    содержимого. Та же форма, что у оффлайновой половинки `make audit-verify`.
    """
    record = dataclasses.replace(row.record, entity="token")
    return dataclasses.replace(row, row_id=row_id, record=record, stored_hash=record.content_hash())


def _cut_middle(count: int) -> list[StoredRecord]:
    """Цепочка без средней строки: вырез, который обязано увидеть `broken_link`."""
    journal = _chain(count)
    return journal[:1] + journal[2:]


class _AppendSpy:
    """Наблюдатель за вставкой: запоминает сессию и запись, настоящую вставку не выполняет.

    Живая вставка проверяется во второй половинке; здесь важно, что модуль вызывает **общий**
    протокол добавления, а не заводит свою копию порядка «замок → хвост → вставка»: вторая копия
    разошлась бы с первой при первой же правке (`ADR-025` п. 6).
    """

    def __init__(self) -> None:
        self.calls: list[tuple[Session, AuditRecord]] = []

    def __call__(self, session: Session, record: AuditRecord) -> int:
        self.calls.append((session, record))
        return 900_001

    @property
    def records(self) -> list[AuditRecord]:
        return [record for _session, record in self.calls]


class _ReaderSpy:
    """Наблюдатель за чтением: возвращает подставные строки, запоминает сессию и порядок вызовов."""

    def __init__(self, rows: Sequence[StoredRecord], *, calls: list[str]) -> None:
        self.rows = list(rows)
        self.sessions: list[Session] = []
        self._calls = calls

    def __call__(self, session: Session) -> list[StoredRecord]:
        self._calls.append("read")
        self.sessions.append(session)
        return list(self.rows)


def _disk(free: int = _DISK_FREE, total: int = _DISK_TOTAL) -> DiskUsage:
    return DiskUsage(path="/fake", total_bytes=total, free_bytes=free)


def _run(
    rows: Sequence[StoredRecord],
    monkeypatch: pytest.MonkeyPatch,
    *,
    disk: DiskUsage | None = None,
    app: str = "jobs",
    run_id: str = "r32-offline",
) -> tuple[IntegrityOutcome, _AppendSpy, _ReaderSpy, list[str]]:
    """Прогнать ежедневную задачу на подставном журнале; вернуть итог и наблюдателей."""
    calls: list[str] = []
    appender = _AppendSpy()
    reader = _ReaderSpy(rows, calls=calls)
    monkeypatch.setattr(integrity, "append_audit_record", appender)
    engine = create_engine(sqlalchemy_url(_DSN))
    try:
        outcome = integrity.run_integrity_check(
            engine,
            app=app,
            rows_reader=reader,
            disk_reader=lambda _path: disk or _disk(),
            moment=_T0,
            run_id=run_id,
        )
    finally:
        engine.dispose()
    return outcome, appender, reader, calls


# ─── вердикт прогона и его связь с ручной командой ──────────────────────────────────────────


def test_целая_цепочка_это_intact() -> None:
    report = verify_chain(_chain(4), expect_genesis=True)
    assert verdict_of(report) == VERDICT_INTACT
    assert not findings_of(report)


def test_пустой_журнал_это_empty_а_не_отказ(monkeypatch: pytest.MonkeyPatch) -> None:
    """Пустая таблица — не ошибка: на свежей площадке до первых событий так и есть.

    `empty` отделён от `intact`: «проверили ноль строк» и «проверили сорок тысяч строк» — разные
    факты для человека, который читает журнал через полгода.
    """
    outcome, appender, _reader, _calls = _run((), monkeypatch)
    assert outcome.verdict == VERDICT_EMPTY
    assert len(appender.calls) == 1, "прогон пустого журнала обязан оставить строку о себе"


def test_правка_содержимого_это_content_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    journal = _reworded_all(4)
    outcome, appender, _reader, _calls = _run(journal, monkeypatch)
    assert outcome.verdict == VERDICT_FINDINGS
    details = appender.records[0].details
    assert details is not None
    assert details["content_mismatch"] == 4


def test_вырез_строки_это_broken_link(monkeypatch: pytest.MonkeyPatch) -> None:
    journal = _cut_middle(4)
    outcome, appender, _reader, _calls = _run(journal, monkeypatch)
    assert outcome.verdict == VERDICT_FINDINGS
    details = appender.records[0].details
    assert details is not None
    assert details["broken_link"] == 1


def test_развилка_цепочки_это_duplicate_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    journal = _chain(3)
    journal = [*journal, _forked(journal[1], row_id=9)]
    outcome, appender, _reader, _calls = _run(journal, monkeypatch)
    assert outcome.verdict == VERDICT_FINDINGS
    details = appender.records[0].details
    assert details is not None
    assert details["duplicate_parent"] == 1


def test_убранное_начало_цепочки_вердикт_не_меняет(monkeypatch: pytest.MonkeyPatch) -> None:
    """`missing_prefix` — пометка, а не находка (уборка §2.8, `ADR-025` п. 7 и п. 8)."""
    tail = _chain(4)[1:]
    report = verify_chain(tail, expect_genesis=True)
    assert not findings_of(report)
    assert verdict_of(report) == VERDICT_INTACT
    _outcome, appender, _reader, _calls = _run(tail, monkeypatch)
    details = appender.records[0].details
    assert details is not None
    assert details["missing_prefix"] == 1, "пометка обязана быть видна в details"
    assert details["verdict"] == VERDICT_INTACT


def test_вердикт_прогона_не_расходится_с_кодами_ручной_команды() -> None:
    """Один и тот же журнал: ручная команда и ежедневная задача согласны в вердикте.

    Сверка с кодами возврата `make audit-verify` (`ADR-025` п. 7): `0` — находок нет, `1` —
    находки есть. Расхождение здесь означает «проверка сказала „цело“, а команда — „нарушено“» на
    одних и тех же строках; чинить его пришлось бы по журналу инцидента.
    """
    journals = (
        _chain(3),
        _cut_middle(3),
        _reworded_all(3),
        [*_chain(2), _forked(_chain(2)[0], row_id=7)],
    )
    for journal in journals:
        report = verify_chain(list(journal), expect_genesis=True)

        # `rows_in` — параметр со значением по умолчанию: замыкание на переменную цикла
        # читалось бы после итерации, а вызов происходит внутри той же итерации.
        def _rows(
            _session: Session,
            _bounds: object,
            *,
            rows_in: Sequence[StoredRecord] = journal,
        ) -> list[StoredRecord]:
            return list(rows_in)

        code = audit_verify.main([], session_factory=lambda: Session(), rows_reader=_rows)
        verdict = verdict_of(report)
        assert (code == audit_verify.EXIT_FINDINGS) == (
            verdict == VERDICT_FINDINGS
        ), f"ручная команда вернула {code}, задача — вердикт {verdict}"


# ─── содержимое строки `integrity.audit_chain` ─────────────────────────────────────────────


def test_строка_проверки_имеет_имя_из_реестра_и_пустой_актор(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`action` — из закрытого перечня §8.7, `actor` — пустой (решение заказчика, ask `e98befe2`).

    `audit_log.actor` ссылается на `users.id` с `RESTRICT`: служебная учётка проверки накрутила бы
    счётчик живых администраторов (гейт «не закрыть последнего администратора», `ADR-020` п. 6) и
    осталась бы неудаляемой. Идентичность проверки — в `action`, `entity` и `details`.
    """
    _outcome, appender, _reader, _calls = _run(_chain(3), monkeypatch, run_id="r32-actor")
    record = appender.records[0]
    assert record.action == CHECK_ACTION
    assert record.action in AUDIT_ACTIONS, "имя события вне закрытого реестра §8.7"
    assert record.actor is None
    assert record.entity == ENTITY_AUDIT_LOG
    assert record.entity_id is None, "у журнала как объекта нет одного `id`"
    assert record.ip is None, "у процесса нет адреса запроса"
    assert record.request_id is None, "у процесса нет идентификатора запроса"
    details = record.details
    assert details is not None
    assert details["check"] == CHECK_NAME
    assert details["run_id"] == "r32-actor"


def test_в_деталях_счётчики_по_всем_четырём_кодам(monkeypatch: pytest.MonkeyPatch) -> None:
    """`details` держит все четыре кода признака нулями: «ключа нет» и «кода не было» — разные вещи.

    Набор выводится из общих `FINDING_KINDS | INFORMATIONAL_KINDS`, поэтому новый код находки
    обязан появиться здесь сам, а не завестись пятым перечнем в задаче.
    """
    _outcome, appender, _reader, _calls = _run(_chain(2), monkeypatch)
    details = appender.records[0].details
    assert details is not None
    kinds: set[str] = {str(kind) for kind in FINDING_KINDS | INFORMATIONAL_KINDS}
    assert kinds == {"content_mismatch", "broken_link", "duplicate_parent", "missing_prefix"}
    assert kinds <= set(details), "код признака пропал из details"
    assert all(details[kind] == 0 for kind in kinds)


def test_строка_пишется_и_при_находке_и_при_чистом_прогоне(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Политика «строка при каждом прогоне» (ask `e98befe2`): иначе пропуск неотличим от «цело».

    Счётчик прогонов читается числом строк `integrity.audit_chain` за период, поэтому и чистый
    прогон обязан оставлять строку.
    """
    clean, appender_clean, _reader, _calls = _run(_chain(3), monkeypatch)
    bad, appender_bad, _reader2, _calls2 = _run(_cut_middle(3), monkeypatch)
    assert clean.verdict == VERDICT_INTACT
    assert len(appender_clean.calls) == 1
    assert bad.verdict == VERDICT_FINDINGS
    assert len(appender_bad.calls) == 1


def test_список_строк_находок_ограничен_а_счётчики_полные(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Массовая подделка не вытесняет из строки остальные поля: `issue_row_ids` — первые N.

    Счётчик по кодам обязан остаться полным: по нему судят о размере поломки, когда идентификаторы
    строк уже не помещаются.
    """
    journal = _reworded_all(MAX_ISSUE_ROWS + 10)
    _outcome, appender, _reader, _calls = _run(journal, monkeypatch)
    details = appender.records[0].details
    assert details is not None
    assert details["content_mismatch"] == MAX_ISSUE_ROWS + 10
    assert len(details["issue_row_ids"]) == MAX_ISSUE_ROWS


def test_чтение_заканчивается_до_вставки_строки(monkeypatch: pytest.MonkeyPatch) -> None:
    """Порядок «сначала разбор, потом строка о проверке» (`ADR-025` п. 9).

    Строка, вставленная до пересчёта, оборвала бы цепочку, которую чекер сам же и проверяет:
    ежедневная проверка стала бы источником собственных ложных находок. Отдельно проверяется, что
    вставка идёт **другой** сессией: та же сессия отдала бы атрибуты из identity map (замер первого
    красного прогона `CI 45163930282`).
    """
    _outcome, appender, reader, calls = _run(_chain(3), monkeypatch)
    assert calls == ["read"], "чтение обязано произойти ровно один раз и до вставки"
    assert appender.calls[0][0] is not reader.sessions[0]


def test_используется_общий_протокол_добавления_записи() -> None:
    """Второй писатель журнала обязан идти через общий протокол, а не через свою копию.

    Проверка держит то, что не видно по поведению: задача вызывает
    `packages.storage.audit_store.append_audit_record` и тот же читатель журнала, что и ручная
    команда: advisory-замок, чтение хвоста и откат целиком — одно определение (`ADR-025` п. 6).
    """
    assert integrity.append_audit_record is append_audit_record
    assert integrity.read_audit_journal is read_audit_journal


def test_провал_базы_не_пишет_строку_о_целом_журнале(monkeypatch: pytest.MonkeyPatch) -> None:
    """Недоступная база — исключение в `run_job`, а не строка «цепочка цела».

    Тот же смысл, что у кода возврата `3` у `make audit-verify` (`ADR-025` п. 7): сломанный чекер
    не должен выглядеть как корректный журнал. `run_job` пишет `job_failed` в журнал процесса, а в
    журнале аудита строк не появляется вовсе.
    """
    appender = _AppendSpy()
    monkeypatch.setattr(integrity, "append_audit_record", appender)
    engine = create_engine(sqlalchemy_url(_UNREACHABLE_DSN))
    try:
        with pytest.raises(OperationalError):
            integrity.run_integrity_check(engine, app="jobs", moment=_T0, run_id="r32-broken-db")
    finally:
        engine.dispose()
    assert appender.calls == [], "отказ базы не должен сопровождаться записью о проверке"


# ─── свободное место (§8.7 «проверка свободных мест», §12.4) ───────────────────────────────


@pytest.mark.parametrize(
    ("free", "total", "ожидаемое_состояние"),
    [
        (15_000, 100_000, DISK_OK),
        (14_999, 100_000, DISK_WARN),
        (800, 10_000, DISK_WARN),
        (799, 10_000, DISK_CRIT),
        (60_000, 100_000, DISK_OK),
    ],
    ids=["ровно_15_процентов", "чуть_ниже_15", "ровно_8_процентов", "чуть_ниже_8", "много_места"],
)
def test_пороги_свободного_места_по_12_4(free: int, total: int, ожидаемое_состояние: str) -> None:
    """Пороги §12.4 (`< 15 %` — warn, `< 8 %` — crit): граница «меньше», считается от байтов.

    15 % свободного — ещё нормально, 14.99 % — уже предупреждение. Округление вверх сдвигало бы
    порог позже, чем обещает ТЗ, и алерт приходил бы поздно.
    """
    disk = DiskUsage(path="/fake", total_bytes=total, free_bytes=free)
    assert disk.severity == ожидаемое_состояние


def test_процент_округляется_вниз_а_не_вверх() -> None:
    """15.9 % свободного — это 15 %; нулевая ёмкость не делится на ноль."""
    assert DiskUsage(path="/f", total_bytes=1000, free_bytes=159).free_percent == 15
    assert DiskUsage(path="/f", total_bytes=0, free_bytes=0).free_percent == 0


def test_замер_места_выкладывается_обеими_метриками() -> None:
    """`tbot_disk_free_bytes` и `tbot_disk_total_bytes` — парой (§12.4: порог задан долей).

    Значение читается из текста `/metrics`, а не из внутреннего поля метрики: проверке важно то же
    число, которое увидит Prometheus.
    """
    publish_disk_usage("jobs", _disk(free=42_000, total=80_000))
    body = metrics.render().decode("utf-8")
    assert 'tbot_disk_free_bytes{app="jobs"} 42000.0' in body
    assert 'tbot_disk_total_bytes{app="jobs"} 80000.0' in body


def test_замер_места_настоящего_корня_правдоподобен() -> None:
    """`shutil.disk_usage` по корню процесса: числа должны быть осмысленными.

    Проверка не знает размера диска прогоняющей машины: она смотрит, что замер не нулевой и что
    доля остаётся в границах. Настоящий корень контейнера (оверлей поверх диска ВМ, `ADR-002`)
    разбирается в живой половинке.
    """
    disk = integrity.read_disk_usage()
    assert disk.total_bytes > 0
    assert disk.free_bytes >= 0
    assert 0 <= disk.free_percent <= 100
    assert disk.severity in {DISK_OK, DISK_WARN, DISK_CRIT}


def test_итог_прогона_описывает_вердикт_и_место() -> None:
    """Текст уходит в `job_done`: по нему «цепочка цела» и «цепочка нарушена» различимы в логе.

    Формулирует итог задача, а не `ChainReport.summary()`: библиотека считает любое обращение
    нарушением цепочки, а `missing_prefix` находкой вердикта не является (`ADR-025` п. 7).
    """
    report = verify_chain(_chain(5), expect_genesis=True)
    outcome = IntegrityOutcome(
        verdict=verdict_of(report),
        report=report,
        disk=_disk(free=1_200, total=10_000),
        record=build_check_record(report, _disk(), at=_T0, run_id="r32-summary"),
        journal_row_id=777,
    )
    summary = outcome.summary()
    assert "вердикт: intact" in summary
    assert "строк 5" in summary
    assert "12% свободно" in summary
    assert DISK_WARN in summary
    assert "строка журнала: 777" in summary


def test_регламент_задачи_сутки_и_имя_из_тз() -> None:
    """§8.7 называет задачу `integrity-check` и требует ежедневности: имя и интервал — контракт.

    Интервал — сутки, а не «рабочий день»: подделка не выбирает дату, и цепочка обязана
    пересчитываться в выходные так же, как в будни.
    """
    assert INTEGRITY_JOB_NAME == "integrity-check"
    assert INTEGRITY_CHECK_INTERVAL_S == 86_400.0


def test_детали_прогона_проходят_политики_журнала() -> None:
    """Политики `details` применяются и к записи проверки: ключ-секрет отклоняется.

    Значений учётных данных в журнале быть не может ни у какой записи, и запись ежедневной
    проверки — не исключение (`ADR-004`, публичный репозиторий по `ADR-019`).
    """
    with pytest.raises(AuditRecordError, match="db_url"):
        make_record(
            action=CHECK_ACTION,
            at=_T0,
            entity=ENTITY_AUDIT_LOG,
            details={"check": CHECK_NAME, "db_url": "postgresql://tbot:example@localhost/db"},
        )


def test_тип_читателя_строк_совпадает_с_общим_читателем() -> None:
    """Шов `rows_reader` принимает общий читатель журнала: подпись не должна разъехаться.

    Иначе ежедневная задача получила бы собственный запрос с другим набором колонок, и ручная
    сверка копии дампа стала бы видеть не то же самое, что автоматическая проверка.
    """
    reader: Callable[[Session], Sequence[StoredRecord]] = read_audit_journal
    assert reader is read_audit_journal
