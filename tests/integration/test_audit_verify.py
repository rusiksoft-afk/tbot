"""Оффлайновая половинка `make audit-verify` (TZ §8.7, `AC-identity-04`, `ADR-025` п. 7, `T-109` `R3.1`).

Живая половинка — `tests/integration/test_audit_verify_db.py` (её шаг стоит в job'е `миграции`).
Здесь базы нет: строки подставляет `rows_reader`, собранный по тому же канону, что и живые
проверки (`chain_from_drafts` достраивает `hash_prev` и `hash`, потому что иначе корректной
цепочки не построить вовсе). Раздел сознательный: тут проверяется **решение инструмента** —
какой код возврата даёт какой разбор, какие коды находок вообще меняют вердикт, как трактуются
границы выборки и что вывод не содержит адреса базы. Саму схему, `jsonb`, `INET`, `identity` у
`id` и то, что чтение идёт действительно отдельным соединением, проверяет живая половинка:
в памяти это не изобразить (тот же довод, что у пары `test_audit_chain_db.py` и
`tests/unit/test_audit_chain.py`).

Что держат эти проверки и почему это дороже «просто запустить скрипт на стенде»:

* **единственный код — единственные находки.** `ADR-025` п. 7 закрепляет `0`/`1`, и `1` занята
  нарушением цепочки. Значит сбой инструмента (нет адреса, нет схемы, пустой интервал) обязан
  иметь другой код: иначе ежедневная `integrity-check` на сломанном чекере выглядела бы как
  «цепочка цела» — ровно тот вид молчаливой лжи, ради которого журнал и заводят;
* **`missing_prefix` вердикт не меняет**, но печатается: норма для уборки §2.8 и для любой
  ограниченной выборки. Если бы он считался находкой, разбор копии дампа и плановая проверка
  краснели бы на корректных данных, а настоящая подделка утонула бы в шуме;
* **замкнутость признаков находок.** Объединение «инцидентных» и «информационных» кодов обязано
  оставлять ровно четыре признака `IssueKind`: появится пятый — проверка потребует решить,
  меняет ли он вердикт, вместо того чтобы молча его игнорировать;
* **выборка не может быть пустой по ошибке** (`--since` позже `--until`, `--from-id` больше
  `--to-id`): «проверил и молча ничего не нашёл» — худший из исходов для инструмента поиска
  подделки;
* **начала цепи нет только у отсечения слева**: `--until`/`--to-id` начала не касаются, и
  `expect_genesis` обязан остаться `True`, иначе ложный `missing_prefix` превратился бы в
  вердикт для корректного журнала.
"""

from __future__ import annotations

import dataclasses
import io
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Final, Protocol

import pytest
from sqlalchemy.orm import Session

from packages.identity.audit import (
    AUDIT_ACTIONS,
    FINDING_KINDS,
    INFORMATIONAL_KINDS,
    AuditRecord,
    IssueKind,
    StoredRecord,
    chain_from_drafts,
)
from tests.paths import load_script

audit_verify = load_script("audit_verify")

#: Метка первой строки синтетической цепочки. Даты фиксированы: проверяем разбор, а не часы.
_T0: Final = datetime(2026, 11, 20, 12, 0, 0, tzinfo=UTC)

_ACTIONS: Final = ("session.login", "session.logout", "session.revoke", "backup_code.spent")


def _draft(index: int) -> AuditRecord:
    """Черновик записи журнала (§8.7: имя из закрытого реестра, метка — своя у каждой строки)."""
    return AuditRecord(
        at=_T0.replace(minute=_T0.minute + index),
        action=_ACTIONS[index % len(_ACTIONS)],
        actor=None,
        entity="session",
        entity_id=f"t109r31-{index}",
        details={"index": index},
        ip=None,
        request_id=None,
        hash_prev=None,
    )


def _chain(count: int) -> list[StoredRecord]:
    """Корректная цепочка из `count` строк: `hash_prev` и `hash` достроены по канону."""
    return chain_from_drafts(_draft(index) for index in range(count))


def _fork(row: StoredRecord, *, row_id: int) -> StoredRecord:
    """Строка-близнец на того же предка: `hash_prev` тот же, а содержимое и `hash` — другие.

    Ровно та форма, которую держит частичный уникальный индекс `ix_audit_log_hash_prev_linked`
    (ревизия `0007`): узел «родитель → потомок» конфликтом не является, а две строки с одним
    `hash_prev` — являются (`ADR-025` п. 4). Хэш пересчитан честно, поэтому единственная
    находка — развилка, а не подделка содержимого.
    """
    record = dataclasses.replace(row.record, entity="token")
    return dataclasses.replace(row, row_id=row_id, record=record, stored_hash=record.content_hash())


class _Bounds(Protocol):
    """Форма границы выборки (`Bounds` из скрипта) без импорта модуля скрипта.

    Тип из `scripts/` тест статически не видит (`load_script` возвращает модуль как `Any`),
    поэтому форма описана протоколом: проверка всё равно сверяет фактические значения, а
    mypy не даёт обратиться к полю, которого у `Bounds` нет.
    """

    since: datetime | None
    until: datetime | None
    from_id: int | None
    to_id: int | None

    @property
    def starts_at_genesis(self) -> bool: ...


class _Rows:
    """Наблюдатель за чтением: возвращает подставные строки и запоминает переданную выборку."""

    def __init__(self, rows: Sequence[StoredRecord]) -> None:
        self.rows = list(rows)
        self.bounds: list[_Bounds] = []
        self.sessions: int = 0

    def __call__(self, session: Session, bounds: _Bounds) -> list[StoredRecord]:
        self.sessions += 1
        self.bounds.append(bounds)
        return list(self.rows)


def _run(
    argv: Sequence[str],
    rows: Sequence[StoredRecord],
) -> tuple[int, str, str, _Rows]:
    """Прогнать точку входа инструмента на подставных строках; вернуть коды и вывод."""
    out = io.StringIO()
    err = io.StringIO()
    reader = _Rows(rows)
    code = audit_verify.main(
        list(argv),
        session_factory=lambda: Session(),
        rows_reader=reader,
        stdout=out,
        stderr=err,
    )
    return code, out.getvalue(), err.getvalue(), reader


# ─── вердикт и коды возврата ─────────────────────────────────────────────────────────────────


def test_целая_цепочка_это_ноль() -> None:
    code, printed, errors, _reader = _run([], _chain(4))
    assert code == audit_verify.EXIT_OK
    assert "цепочка цела" in printed
    assert f"код {audit_verify.EXIT_OK}" in printed
    assert errors == ""


def test_пустой_журнал_это_ноль_а_не_отказ() -> None:
    """На площадке `audit_log` пуст: пустой журнал — состояние, а не поломка инструмента."""
    code, printed, _errors, _reader = _run([], [])
    assert code == audit_verify.EXIT_OK
    assert "цепочка пуста" in printed


def test_правка_содержимого_без_пересчёта_хэша_даёт_единицу() -> None:
    rows = _chain(3)
    forged = dataclasses.replace(rows[1], record=dataclasses.replace(rows[1].record, entity="user"))
    tampered = [*rows[:1], forged, *rows[2:]]
    code, printed, _errors, _reader = _run([], tampered)
    assert code == audit_verify.EXIT_FINDINGS
    assert "content_mismatch" in printed
    assert f"строка {rows[1].row_id}" in printed


def test_вырез_строки_из_середины_даёт_единицу() -> None:
    rows = _chain(4)
    cut = [rows[0], rows[2], rows[3]]
    code, printed, _errors, _reader = _run([], cut)
    assert code == audit_verify.EXIT_FINDINGS
    assert "broken_link" in printed
    assert f"строка {rows[2].row_id}" in printed


def test_развилка_цепочки_даёт_единицу() -> None:
    """Две строки на одного предка.

    На живой базе эту форму держит частичный уникальный индекс `ix_audit_log_hash_prev_linked`
    (ревизия `0007`) — см. живую половинку; здесь она нужна потому, что разбор запускают и на
    копии дампа, где индекс мог не восстановиться (`ADR-025` п. 7).
    """
    rows = _chain(3)
    fork = _fork(rows[2], row_id=rows[-1].row_id + 1)
    assert fork.record.hash_prev == rows[2].record.hash_prev
    assert fork.row_id not in {row.row_id for row in rows}
    code, printed, _errors, _reader = _run([], [*rows, fork])
    assert code == audit_verify.EXIT_FINDINGS
    assert "duplicate_parent" in printed


def test_признаки_находок_разделены_явно() -> None:
    """Каждый признак находки отнесён явно: пятого кода, «не замеченного молча», не бывает.

    Наборы читаются из общего слоя (`packages.identity.audit`), а не из инструмента: срез `R3.2`
    сделал их общими для ручной команды и для ежедневной `integrity-check`, и проверка обязана
    чинить тот источник, который правят, а не его копию.
    """
    kinds: frozenset[IssueKind] = frozenset(
        {"content_mismatch", "broken_link", "missing_prefix", "duplicate_parent"}
    )
    assert kinds == FINDING_KINDS | INFORMATIONAL_KINDS
    assert not (FINDING_KINDS & INFORMATIONAL_KINDS)


# ─── `missing_prefix`: печатается, но вердикт не меняет ──────────────────────────────────────


def test_убранное_начало_журнала_это_ноль_с_пометкой() -> None:
    """Полная выборка, а начала цепи в журнале нет: уборка §2.8 или копия дампа.

    Разбор обязан показать `missing_prefix` и не испортить вердикт (`ADR-025` п. 7 и п. 8):
    после первого служебного выреза журнал физически теряет начало, и называть это
    «цепочка нарушена» значит сделать плановую проверку красной навсегда.
    """
    rows = _chain(4)
    code, printed, _errors, _reader = _run([], rows[2:])
    assert code == audit_verify.EXIT_OK
    assert "missing_prefix" in printed
    assert "цепочка цела" in printed
    assert "нарушена" not in printed
    assert "норма" in printed


def test_ограниченная_слева_выборка_ложной_находки_не_выдаёт() -> None:
    """Инструмент сам сказал «смотри с этой метки»: `missing_prefix` не появляется вовсе."""
    rows = _chain(4)
    code, printed, _errors, _reader = _run(["--from-id", str(rows[2].row_id)], rows[2:])
    assert code == audit_verify.EXIT_OK
    assert "missing_prefix" not in printed
    assert "цепочка цела" in printed


def test_интервал_по_id_и_по_метке_отсекают_только_нужное() -> None:
    rows = _chain(3)
    code, _printed, _errors, reader = _run(["--from-id", "7"], rows)
    assert code == audit_verify.EXIT_OK
    bounds = reader.bounds[0]
    assert (bounds.from_id, bounds.to_id) == (7, None)
    assert bounds.starts_at_genesis is False

    code, _printed, _errors, reader = _run(["--to-id", "9"], rows)
    assert code == audit_verify.EXIT_OK
    assert reader.bounds[0].to_id == 9
    assert reader.bounds[0].starts_at_genesis is True

    code, _printed, _errors, reader = _run(["--since", "2026-11-20", "--until", "2026-11-21"], rows)
    assert code == audit_verify.EXIT_OK
    bounds = reader.bounds[0]
    assert (bounds.since, bounds.until) == (
        datetime(2026, 11, 20, tzinfo=UTC),
        datetime(2026, 11, 21, tzinfo=UTC),
    )
    assert bounds.starts_at_genesis is False


def test_весь_журнал_требует_начала_цепи() -> None:
    """Без ограничений `expect_genesis` обязан быть `True`: иначе пропадёт `missing_prefix`.

    Ложь тут дороже шума: строка с `hash_prev IS NULL` в журнале есть всегда, пока журнал не
    чистили, и отсутствие начала — ровно то, что отличает полный разбор от выборки.
    """
    code, printed, _errors, reader = _run([], _chain(2))
    assert code == audit_verify.EXIT_OK
    assert reader.bounds[0].starts_at_genesis is True
    assert "missing_prefix" not in printed


# ─── отказ выборки: код отдельный, «находка» при этом не ставится ────────────────────────────


@pytest.mark.parametrize(
    ("argv", "ожидание"),
    [
        (["--since", "2026-11-21", "--until", "2026-11-20"], "интервал пуст"),
        (["--from-id", "9", "--to-id", "3"], "интервал пуст"),
        (["--since", "вчера"], "не является датой"),
        (["--from-id", "0"], "положительным"),
        (["--to-id", "-5"], "положительным"),
    ],
    ids=["период_наоборот", "id_наоборот", "не_дата", "id_ноль", "id_отрицательный"],
)
def test_некорректная_выборка_это_ошибка_употребления(argv: list[str], ожидание: str) -> None:
    code, _printed, errors, reader = _run(argv, _chain(3))
    assert code == audit_verify.EXIT_USAGE
    assert ожидание in errors
    # Разбор при отказе вообще не запускается: «находок нет» из такой проверки не следует.
    assert reader.sessions == 0


def test_адрес_базы_не_принимается_аргументами() -> None:
    """Ловушка для привычки передавать DSN флагом: аргументы видны в `ps` (`ADR-004`)."""
    with pytest.raises(SystemExit) as stop:
        _run(["--dsn", "postgresql://tbot:pwd@localhost:5432/tbot"], _chain(2))
    assert stop.value.code == 2


def test_вывод_ошибки_не_содержит_адрес_базы() -> None:
    """`safe_text` вычищает строку подключения: исключение драйвера её содержит."""
    text = audit_verify.safe_text(
        "(psycopg.OperationalError) connection failed at "
        '"postgresql+psycopg://tbot_app:secretpwd@153.51.172.30:5432/tbot"'
    )
    assert "secretpwd" not in text
    assert "tbot_app:secretpwd" not in text
    assert "<адрес-базы-скрыт>" in text


# ─── имена событий и реестр: инструмент их не изобретает ────────────────────────────────────


def test_синтетические_строки_используют_имена_из_реестра() -> None:
    """Подставные строки собраны из закрытого реестра §8.7: оффлайн не живёт на выдуманных именах."""
    for action in _ACTIONS:
        assert action in AUDIT_ACTIONS


def test_тексты_вердикта_соответствуют_кодам_возврата() -> None:
    """Вывод обязан называть тот код, которым он заканчивается: в cron читают текст, а не число."""
    rows = _chain(3)
    code, printed, _errors, _reader = _run([], rows)
    assert printed.rstrip().endswith(f"код {code}")

    tampered = dataclasses.replace(rows[2], stored_hash="0" * 64)
    code, printed, _errors, _reader = _run([], [*rows[:2], tampered])
    assert code == audit_verify.EXIT_FINDINGS
    assert printed.rstrip().endswith(f"код {code}")
