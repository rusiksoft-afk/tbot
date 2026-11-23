"""Ежедневная `integrity-check` процесса `jobs` (TZ §8.7, `ADR-025` п. 7 и п. 9 с
поправками `ADR-026`, `T-109` `R3.2`).

Задача делает ровно две вещи §8.7 и делает их в одном порядке: **сначала читает журнал и выносит
вердикт, потом дописывает строку о проверке**. Порядок жёсткий (`ADR-025` п. 9): строка,
вставленная до пересчёта, оборвала бы цепочку, которую проверяет сам чекер, и ежедневная проверка
стала бы единственным источником ложных срабатываний.

Что читается и что происходит при отказе:

* **разбор цепочки** — тот же запрос и те же наборы кодов находок, что у ручной
  `make audit-verify` (`packages.storage.audit_store:read_audit_journal`,
  `packages.identity.audit:FINDING_KINDS`). Ручная сверка копии дампа и автоматическая проверка
  обязаны видеть один и тот же набор колонок и одинаково трактовать `missing_prefix`: иначе
  «проверка сказала „цело“, а команда — „нарушено“» на одних и тех же строках. Чтение идёт
  отдельным соединением вне любой писавшей транзакции: ORM-сессия отдаёт атрибуты из identity map,
  и проверка «цепочка цела» на уже испорченной строке ничего бы не проверяла (`ADR-025` п. 7,
  замер `CI 45163930282`);
* **свободное место** — `shutil.disk_usage` по корню файловой системы процесса и две метрики
  (§12.4: `tbot_disk_free_bytes < 15%` / `< 8%` → `SYSTEM`). Пороги §12.4 выражены процентами и
  относятся к алертам, а не к журналу: нового имени события в закрытом реестре §8.7 задача не
  заводила, поэтому след находки цепочки — `integrity.audit_chain`, а след нехватки места —
  метрика и уровень логирования. Внутри контейнера `jobs` корень смонтирован read-only поверх
  диска ВМ, и `statvfs` отдаёт статистику этого диска: цифры описывают машину, а не «слои
  контейнера»;
* **строка о прогоне пишется при каждом запуске**, а не только при находке (решение заказчика от
  2026-11-23, ask `e98befe2-db98-499b-9307-4094e5114e75`). Иначе «проверка не запускалась»
  неотличима от «цепочка целая» — ровно ту опасность называет `ADR-025` п. 7. Вердикт лежит в
  `details`: `intact`, `empty` (журнал пуст — до первых событий так и есть) или `findings`.

**«Проверка не исполнилась» — не строка в журнале.** Если база недоступна или схема не развёрнута,
исключение уходит в `run_job` (`apps/jobs/main.py`), и в журнале появляется `job_failed`, а не
запись о целом журнале. Тот же смысл, что у кодов возврата `make audit-verify` (`ADR-025` п. 7):
сломанный чекер не должен выглядеть как корректный журнал. Находка цепочки при этом провалом
задачи не считается: задача исполнена, её результат — «цепочка нарушена», и он виден в
`integrity.audit_chain` и в тексте `job_done`.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import uuid4

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from packages.common import metrics
from packages.common.clock import utc_now
from packages.common.logging import get_logger
from packages.identity.audit import (
    FINDING_KINDS,
    INFORMATIONAL_KINDS,
    AuditRecord,
    ChainReport,
    IssueKind,
    StoredRecord,
    findings_of,
    informational_of,
    make_record,
    verify_chain,
)
from packages.storage.audit_store import append_audit_record, read_audit_journal

log = get_logger("jobs.integrity")

#: Имя задачи: оно же — в `/readyz`, в логах и в тексте §8.7 («Ежедневная задача
#: `integrity-check`»). Менять можно только вместе с проверками реестра.
INTEGRITY_JOB_NAME: Final = "integrity-check"

#: Регламент §8.7: «ежедневная задача». Интервал — сутки, а не «раз в рабочий день»: цепочка
#: обязана пересчитываться и в выходные, потому что подделка не выбирает дату.
INTEGRITY_CHECK_INTERVAL_S: Final = 24 * 3600.0

#: Имя проверки в `details` и в `action` строки журнала. Имя события взято из закрытого реестра
#: §8.7 (`ADR-025` п. 10): имя вне реестра не записывается вовсе.
CHECK_NAME: Final = "audit_chain"
CHECK_ACTION: Final = "integrity.audit_chain"

#: Объект строки журнала: описывается журнал целиком, а не отдельная его строка, поэтому
#: `entity_id` остаётся пустым (§4.1: `entity`/`entity_id` — пара «тип объекта»/`id`).
ENTITY_AUDIT_LOG: Final = "audit_log"

#: Вердикты прогона. `empty` отделён от `intact` намеренно: «проверили пустой журнал» и
#: «проверили 40 тысяч строк, нарушений нет» — разные факты для человека, читающего журнал.
VERDICT_EMPTY: Final = "empty"
VERDICT_INTACT: Final = "intact"
VERDICT_FINDINGS: Final = "findings"

#: Состояния свободного места по порогам §12.4 (проценты занятого/свободного).
DISK_OK: Final = "ok"
DISK_WARN: Final = "warn"
DISK_CRIT: Final = "crit"

#: Что измеряется из свободного места: корень файловой системы процесса. В составе это
#: оверлейный слой поверх диска ВМ, поэтому цифра описывает диск машины (§12.4, `ADR-002`).
DISK_PATH: Final = "/"
DISK_WARN_PERCENT: Final = 15
DISK_CRIT_PERCENT: Final = 8

#: Сколько идентификаторов строк уходит в `details`. Смысл ограничить — не экономия байт:
#: при массовой подделке длинный список вытеснил бы из строки остальные поля, а полное
#: число находок уже лежит счётчиками по кодам.
MAX_ISSUE_ROWS: Final = 20

#: Порядок и состав ключей-счётчиков в `details`: ровно четыре признака `IssueKind`, выведенные
#: из общих наборов (`ADR-025` п. 7). Новый код находки обязан попасть в один из наборов в
#: общем слое — и тогда он появится здесь сам, а не заведётся четвёртым перечнем в этом файле.
_KIND_ORDER: Final[tuple[IssueKind, ...]] = tuple(sorted(FINDING_KINDS | INFORMATIONAL_KINDS))

RowsReader = Callable[[Session], Sequence[StoredRecord]]

#: Явный список того, что модуль отдаёт наружу. Он нужен не ради `import *`: при `strict` mypy
#: не считает молча импортированное имя экспортом модуля, а оффлайновая проверка сверяет,
#: что задача вызывает **общий** протокол добавления записи и общий читатель журнала
#: (`packages.storage.audit_store`), а не завела копию порядка «замок → хвост → вставка».
__all__ = [
    "CHECK_ACTION",
    "CHECK_NAME",
    "DISK_CRIT",
    "DISK_OK",
    "DISK_PATH",
    "DISK_WARN",
    "ENTITY_AUDIT_LOG",
    "INTEGRITY_CHECK_INTERVAL_S",
    "INTEGRITY_JOB_NAME",
    "MAX_ISSUE_ROWS",
    "VERDICT_EMPTY",
    "VERDICT_FINDINGS",
    "VERDICT_INTACT",
    "DiskUsage",
    "IntegrityOutcome",
    "RowsReader",
    "append_audit_record",
    "build_check_record",
    "publish_disk_usage",
    "read_audit_journal",
    "read_disk_usage",
    "run_integrity_check",
    "verdict_of",
]


@dataclass(frozen=True)
class DiskUsage:
    """Свободное место на файловой системе: пара байтов, а не процент.

    Проценты считаются от пары, поэтому держатся байты: порог §12.4 — про долю, а метрика
    Prometheus — про байты, и одно не должно терять другое из-за округления.
    """

    path: str
    total_bytes: int
    free_bytes: int

    @property
    def free_percent(self) -> int:
        """Целое вниз: 15.9 % свободного — это ещё 15 %, то есть не ниже порога §12.4."""
        if self.total_bytes <= 0:
            return 0
        return int(self.free_bytes * 100 // self.total_bytes)

    @property
    def severity(self) -> str:
        """Состояние по порогам §12.4; уровень алерта даёт Prometheus, здесь — только слово."""
        percent = self.free_percent
        if percent < DISK_CRIT_PERCENT:
            return DISK_CRIT
        if percent < DISK_WARN_PERCENT:
            return DISK_WARN
        return DISK_OK


def read_disk_usage(path: str = DISK_PATH) -> DiskUsage:
    """Замер свободного места (`shutil.disk_usage`).

    Та же функция, что в хозяйской проверке `scripts/prod_bootstrap_check.py`: размер берётся из
    `statvfs`, а не из `du` — проверка остаётся запускаемой без привилегий и без обхода дерева.
    """
    usage = shutil.disk_usage(path)
    return DiskUsage(path=path, total_bytes=int(usage.total), free_bytes=int(usage.free))


def publish_disk_usage(app: str, disk: DiskUsage) -> None:
    """Выложить замер в метрики §12.4.

    Метка `app` обязана быть: процессы поднимают общий реестр метрик, и число «свободно на диске»
    без метки приписывалось бы любому из них.
    """
    metrics.DISK_FREE_BYTES.labels(app=app).set(float(disk.free_bytes))
    metrics.DISK_TOTAL_BYTES.labels(app=app).set(float(disk.total_bytes))


def verdict_of(report: ChainReport) -> str:
    """Вердикт разбора: находками считаются три кода, `missing_prefix` вердикт не меняет.

    `missing_prefix` — норма после уборки по §2.8 и у ограниченной выборки (`ADR-025` п. 7 и
    п. 8): называть потерянное начало «цепочка нарушена» значило бы сделать ежедневную проверку
    красной навсегда сразу после первого служебного выреза.
    """
    if findings_of(report):
        return VERDICT_FINDINGS
    if report.rows == 0:
        return VERDICT_EMPTY
    return VERDICT_INTACT


def build_check_record(
    report: ChainReport,
    disk: DiskUsage,
    *,
    at: datetime,
    run_id: str,
) -> AuditRecord:
    """Собрать запись `integrity.audit_chain` по итогам прогона.

    `actor` остаётся пустым, и это не недосмотр: колонка `audit_log.actor` ссылается на `users.id`
    с `RESTRICT` (`0002`), а проверки — не учётная запись. Служебная учётка в `users`
    накрутила бы счётчик живых администраторов (гейт «не закрыть последнего администратора», `ADR-020` п. 6) и
    показалась бы в `/admin/users`; решение заказчика от 2026-11-23 (ask
    `e98befe2-db98-499b-9307-4094e5114e75`) — `actor IS NULL`, а идентификатор проверки живёт в
    `action`, `entity` и `details` (`ADR-026` п. 2 — поправка к `ADR-025` п. 9).

    Значений учётных данных в `details` нет, как и везде: политики `packages/identity/audit.py`
    отклоняют ключи, похожие на секреты, и нецелые числа (нецелое число вернулось бы из `jsonb`
    другой строкой, и канонический JSON перестал бы совпадать с отхэшированным).
    """
    counts: dict[IssueKind, int] = {kind: 0 for kind in _KIND_ORDER}
    for issue in report.issues:
        counts[issue.kind] = counts.get(issue.kind, 0) + 1

    details: dict[str, object] = {
        "check": CHECK_NAME,
        "run_id": run_id,
        "verdict": verdict_of(report),
        "rows": report.rows,
        "from_id": report.first_row_id,
        "to_id": report.last_row_id,
        "issue_row_ids": [issue.row_id for issue in findings_of(report)][:MAX_ISSUE_ROWS],
        "disk_free_bytes": disk.free_bytes,
        "disk_total_bytes": disk.total_bytes,
        "disk_free_percent": disk.free_percent,
        "disk_state": disk.severity,
    }
    for kind in _KIND_ORDER:
        details[str(kind)] = counts.get(kind, 0)

    return make_record(
        action=CHECK_ACTION,
        at=at,
        entity=ENTITY_AUDIT_LOG,
        details=details,
    )


@dataclass(frozen=True)
class IntegrityOutcome:
    """Итог прогона: вердикт, разбор, замер места и строка, которая была добавлена."""

    verdict: str
    report: ChainReport
    disk: DiskUsage
    record: AuditRecord
    journal_row_id: int

    def summary(self) -> str:
        """Одна строка в журнал процесса (`job_done` в `apps/jobs/main.py`)."""
        parts: list[str] = [f"вердикт: {self.verdict}"]
        if self.report.rows:
            parts.append(
                f"строк {self.report.rows} (id {self.report.first_row_id}."
                f".{self.report.last_row_id})"
            )
        else:
            parts.append("строк 0 (журнал пуст)")
        findings = findings_of(self.report)
        if findings:
            kinds = ", ".join(sorted({str(issue.kind) for issue in findings}))
            parts.append(f"находок {len(findings)} ({kinds})")
        notes = informational_of(self.report)
        if notes:
            parts.append("начало цепи не прочитано (норма для уборки §2.8 и выборки за период)")
        parts.append(
            f"место: {self.disk.free_percent}% свободно "
            f"({self.disk.free_bytes} из {self.disk.total_bytes} байт, {self.disk.severity})"
        )
        parts.append(f"строка журнала: {self.journal_row_id}")
        return "; ".join(parts)


def _log_outcome(outcome: IntegrityOutcome, run_id: str) -> None:
    """Записать итог в журнал процесса.

    Уровень выбирается по смыслу, а не по факту исключения: находка цепочки — `warning` (задача
    исполнилась, результат плохой), нехватка места по порогам §12.4 — `warning`/`error`, целый
    журнал — `info`. Отдельная запись про находку нужна потому, что алерты §12.4 читают метрики,
    а журнал `audit_log` человек читает руками.
    """
    findings = findings_of(outcome.report)
    fields = {
        "run_id": run_id,
        "verdict": outcome.verdict,
        "rows": outcome.report.rows,
        "findings": len(findings),
        "notes": len(informational_of(outcome.report)),
        "disk_free_percent": outcome.disk.free_percent,
        "disk_state": outcome.disk.severity,
        "journal_row_id": outcome.journal_row_id,
    }
    if outcome.verdict == VERDICT_FINDINGS:
        kinds = sorted({str(issue.kind) for issue in findings})
        log.warning("integrity_chain_findings", kinds=kinds, **fields)
    else:
        log.info("integrity_check", **fields)
    if outcome.disk.severity == DISK_CRIT:
        log.error("integrity_disk_low", threshold_percent=DISK_CRIT_PERCENT, **fields)
    elif outcome.disk.severity == DISK_WARN:
        log.warning("integrity_disk_low", threshold_percent=DISK_WARN_PERCENT, **fields)


def run_integrity_check(
    engine: Engine,
    *,
    app: str,
    rows_reader: RowsReader = read_audit_journal,
    disk_reader: Callable[[str], DiskUsage] = read_disk_usage,
    moment: datetime | None = None,
    run_id: str | None = None,
) -> IntegrityOutcome:
    """Один прогон: разбор цепочки, замер места, строка `integrity.audit_chain`.

    `rows_reader` и `disk_reader` — швы оффлайновой половинки (`tests/integration/
    test_jobs_integrity.py`): коды вердикта, набор `details` и порядок «чтение → запись»
    проверяются без базы, а живая половинка (`tests/integration/test_jobs_integrity_db.py`)
    проверяет то, чего память не показывает: пересчёт по `jsonb` и `INET`, привязку строки
    проверки к настоящему хвосту цепочки и отсутствие записи при недоступной базе.

    Сессия чтения закрывается **до** открытия пишущей: так гарантирован порядок `ADR-025` п. 9 и
    исключён соблазн дочитать изменённые тем же прогоном строки из identity map.

    `expect_genesis=True`: выборка не ограничена, значит начало цепи обязано быть внутри неё, и
    `missing_prefix` — находка, которая печатается, но вердикт не меняет (уборка §2.8).
    """
    at = moment if moment is not None else utc_now()
    marker = run_id if run_id is not None else uuid4().hex[:12]

    with Session(engine) as reader:
        records = list(rows_reader(reader))
    report = verify_chain(records, expect_genesis=True)

    disk = disk_reader(DISK_PATH)
    publish_disk_usage(app, disk)

    record = build_check_record(report, disk, at=at, run_id=marker)

    with Session(engine) as writer:
        journal_row_id = append_audit_record(writer, record)
        writer.commit()

    outcome = IntegrityOutcome(
        verdict=verdict_of(report),
        report=report,
        disk=disk,
        record=record,
        journal_row_id=journal_row_id,
    )
    _log_outcome(outcome, marker)
    return outcome
