#!/usr/bin/env python3
"""Разбор цепочки хэшей журнала аудита: `make audit-verify` (TZ §8.7, `AC-identity-04`, `ADR-025` п. 7).

Назначение — вторая половина `AC-identity-04`: на копии дампа, строку в которой правили правами
владельца схемы, найти подделку. Приложение прав на `UPDATE`/`DELETE` журнала не имеет
(`deploy/postgres/roles.sql`, `ADR-006`), поэтому единственный способ обнаружить ручную правку —
пересчитать цепочку: `hash` каждой строки сверяется с её содержимым, `hash_prev` — с хэшем
предыдущей строки в порядке `id`.

Инструмент **только читает**. Он не оставляет следа о собственном прогоне: событием находки
является `integrity.audit_chain` (§8.7, `ADR-025` п. 9), и пишет его ежедневная `integrity-check`,
а не ручной запуск, — иначе чекер дописывал бы строку до пересчёта и обрывал бы цепочку, которую
проверяет сам.

Три решения, закреплённые здесь явно:

* **коды возврата различают «найдено» и «не исполнилось».** `0` — находок нет, `1` — есть
  находки трёх кодов (`content_mismatch`, `broken_link`, `duplicate_parent`), `2` — неверная
  выборка, `3` — база недоступна или схема не развёрнута. `1` занят находками намеренно
  (`ADR-025` п. 7), поэтому упавший чекер не может выглядеть как целый журнал: для ежедневной
  `integrity-check` код `3` — это «проверка не исполнилась», отдельный повод, а не «всё чисто»;
* **`missing_prefix` находкой вердикта не является.** Начало цепи отсутствует после законной
  уборки по §2.8 и у любой выборки «за период» или «по интервалу id» — ложный вердикт «цепочка
  нарушена» обесценил бы и ежедневную проверку, и разбор копии дампа. Находка печатается, но код
  возврата не меняет;
* **чтение идёт отдельным соединением**, а не сессией, которая могла менять строки: ORM-сессия
  возвращает прежние атрибуты из identity map, и проверка «цепочка цела» на уже испорченной строке
  ничего бы не проверяла (замер первого красного прогона `CI 45163930282`, разбор —
  `docs/HANDOFF.md §1.61` п. 6).

Запуск: адрес базы берётся только из конфигурации процесса (`TBOT_DB_URL` или файл секрета
`db_url`), из аргументов командной строки — никогда: строка процесса видна в `ps` и в журналах
сессии (`ADR-004`).
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import IO, Final

from _bootstrap import ensure_repo_root_on_path
from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from packages.common.config import ConfigError, load_settings
from packages.common.db import sqlalchemy_url
from packages.identity.audit import (
    ChainReport,
    StoredRecord,
    findings_of,
    informational_of,
    verify_chain,
)
from packages.storage.audit_store import read_audit_journal

ROOT = ensure_repo_root_on_path()

# ─── коды возврата ───────────────────────────────────────────────────────────────────────────

EXIT_OK: Final = 0
#: Находки трёх «инцидентных» кодов (`ADR-025` п. 7). Единственный смысл единицы — цепочка
#: нарушена; поэтому сбой самого инструмента обязан иметь другой код.
EXIT_FINDINGS: Final = 1
EXIT_USAGE: Final = 2
#: База недоступна, адрес не настроен, схема не развёрнута: вердикт не вынесен.
EXIT_ENV: Final = 3
EXIT_UNEXPECTED: Final = 4

# ─── коды находок ─────────────────────────────────────────────────────────────────────────────

# Наборы кодов (`FINDING_KINDS`, `INFORMATIONAL_KINDS`) и две функции вердикта с среза `R3.2`
# определены в общем слое — `packages.identity.audit`. Здесь они только импортируются: их читает
# и эта команда, и ежедневная `integrity-check` процесса `jobs`, а два перечня «что делает
# вердикт нарушенным» разошлись бы при первой же правке (`ADR-025` п. 7).

# Формы, в которых адрес базы может просочиться в текст исключения драйвера. Строка подключения
# с паролем не имеет права появиться ни в выводе, ни в журнале cron.
_URL_RE: Final = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"']+")
_CREDENTIALS_RE: Final = re.compile(r"[^\s:@/,]+:[^\s@/,]+@")
#: Потолок текста ошибки наружу: сообщения драйвера многострочные, вывод читает человек.
_DETAIL_LIMIT: Final = 300


def safe_text(value: object) -> str:
    """Вычистить адрес базы и учётные данные из текста ошибки, затем обрезать.

    Повторяет правило `scripts/first_account.py`: исключение драйвера содержит строку
    подключения, а она — секрет (`ADR-005`, `ADR-004`).
    """
    text = str(value)
    # Заполнители пишутся без пробелов: вывод собирается склейкой «|» из непустых строк,
    # и вставленный в середину пробел превратился бы в разорванную фразу.
    text = _URL_RE.sub("<адрес-базы-скрыт>", text)
    text = _CREDENTIALS_RE.sub("<учётные-данные-скрыты>", text)
    return " | ".join(text.split())[:_DETAIL_LIMIT]


class VerifyError(RuntimeError):
    """Штатный отказ с объяснением; код возврата держится в атрибуте `code`."""

    def __init__(self, code: int, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


# ─── границы выборки ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Bounds:
    """Ограничения выборки журнала. Без ограничений — весь журнал, от начала цепи.

    `since`/`until` фильтруют по колонке `at` (`ix_audit_log_at`), `from_id`/`to_id` — по
    `id`: именно `id` задаёт хронологию журнала (колонку выдаёт база, §4.1), и интервал по
    `id` — то, чем разбирают путь восстановления дампа, где метки времени двух процессов
    могли прийти вразнобой.
    """

    since: datetime | None = None
    until: datetime | None = None
    from_id: int | None = None
    to_id: int | None = None

    @property
    def starts_at_genesis(self) -> bool:
        """Начало цепи заведомо внутри выборки.

        Ложь ровно тогда, когда начало отсечено слева (`since` или `from_id`): у первой
        строки такой выборки `hash_prev` есть по построению, и находка «начала нет» была бы
        ложной (`ADR-025` п. 7). Отсечение справа (`until`/`to_id`) начала не касается.

        Разница с «начало убрано» (§2.8, копия дампа) существенна: там выборка полная, а начала
        цепи в журнале нет физически, и разбор обязан показать `missing_prefix` без изменения
        вердикта. Здесь же инструмент сам сказал «смотри с этой метки», поэтому ложной находки
        не появляется вовсе.
        """
        return self.since is None and self.from_id is None

    def describe(self) -> str:
        parts: list[str] = []
        if self.since is not None:
            parts.append(f"at >= {self.since.isoformat()}")
        if self.until is not None:
            parts.append(f"at <= {self.until.isoformat()}")
        if self.from_id is not None:
            parts.append(f"id >= {self.from_id}")
        if self.to_id is not None:
            parts.append(f"id <= {self.to_id}")
        return "весь журнал (хронология по id)" if not parts else ", ".join(parts)


def parse_moment(value: str, *, option: str) -> datetime:
    """Разобрать метку времени аргумента: `ГГГГ-ММ-ДД` или ISO-8601.

    Значение без смещения трактуется как UTC — иначе «--since 2026-11-23» означало бы разный
    интервал на dev-машине и на площадке, а интервал выборки должен быть одинаковым везде.
    """
    try:
        moment = datetime.fromisoformat(value)
    except ValueError as error:
        msg = f"{option}: значение не является датой или датой-временем ({value!r})"
        raise VerifyError(EXIT_USAGE, msg) from error
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def build_bounds(
    *,
    since: str | None,
    until: str | None,
    from_id: int | None,
    to_id: int | None,
) -> Bounds:
    """Собрать и проверить границы выборки. Пустой интервал — отказ, а не «пустая проверка»."""
    left_at = parse_moment(since, option="--since") if since is not None else None
    right_at = parse_moment(until, option="--until") if until is not None else None
    if left_at is not None and right_at is not None and left_at > right_at:
        msg = "--since позже --until: интервал пуст, проверять нечего"
        raise VerifyError(EXIT_USAGE, msg)
    if from_id is not None and to_id is not None and from_id > to_id:
        msg = f"--from-id ({from_id}) больше --to-id ({to_id}): интервал пуст"
        raise VerifyError(EXIT_USAGE, msg)
    return Bounds(since=left_at, until=right_at, from_id=from_id, to_id=to_id)


# ─── чтение журнала ──────────────────────────────────────────────────────────────────────────


def read_journal(session: Session, bounds: Bounds) -> list[StoredRecord]:
    """Прочитать строки журнала колонками §4.1 в порядке `id`.

    Запрос один на двоих с ежедневной `integrity-check`: читает общий слой
    (`packages.storage.audit_store:read_audit_journal`). Ручная сверка копии дампа и
    автоматическая проверка обязаны видеть ровно тот же набор колонок и ровно тот же порядок,
    иначе «проверка сказала „цело“, а команда — „нарушено“» на одних и тех же строках
    (`ADR-025` п. 7).

    Порядок задаёт `id`, а не `at`: моменты двух процессов могут прийти вразнобой, а хэш
    считается без `id` (колонку база выдаёт уже после расчёта), поэтому переставить чтение по
    `at` — значит получить ложные `broken_link`.
    """
    return read_audit_journal(
        session,
        since=bounds.since,
        until=bounds.until,
        from_id=bounds.from_id,
        to_id=bounds.to_id,
    )


# ─── вердикт ─────────────────────────────────────────────────────────────────────────────────


def print_report(report: ChainReport, bounds: Bounds, out: IO[str]) -> None:
    """Печать разбора и вердикта с кодом возврата.

    Вердикт формулируется здесь, а не берётся из `ChainReport.summary()` намеренно: библиотека
    считает любое обращение «нарушением цепочки», а `missing_prefix` находкой вердикта не является
    (`ADR-025` п. 7) — печать её суммарной строкой дала бы вывод «цепочка нарушена» рядом с
    кодом `0`. Сами тексты находок берутся из `ChainIssue.describe()`: тот же текст, что
    показывают живые проверки, поэтому вывод инструмента и вывод проверки схемы не разойдутся.
    """
    print(f"выборка: {bounds.describe()}", file=out)
    if report.rows == 0:
        print("цепочка пуста: строк журнала не прочитано", file=out)
    else:
        print(f"строк: {report.rows}, с {report.first_row_id} по {report.last_row_id}", file=out)
    for issue in report.issues:
        print(f"  {issue.kind}: {issue.describe()}", file=out)
    findings = findings_of(report)
    notes = informational_of(report)
    if findings:
        kinds = ", ".join(sorted({str(issue.kind) for issue in findings}))
        print(
            f"вердикт: цепочка нарушена — находок {len(findings)} ({kinds}); код {EXIT_FINDINGS}",
            file=out,
        )
    elif notes:
        print(
            f"вердикт: цепочка цела; начало цепи не прочитано (норма для уборки §2.8 и "
            f"копии дампа); код {EXIT_OK}",
            file=out,
        )
    else:
        print(f"вердикт: цепочка цела; код {EXIT_OK}", file=out)


def run(
    *,
    session: Session,
    bounds: Bounds,
    out: IO[str],
    rows_reader: Callable[[Session, Bounds], list[StoredRecord]] = read_journal,
) -> int:
    """Разобрать выборку и вернуть код. `rows_reader` подставляют оффлайновые проверки."""
    report = verify_chain(rows_reader(session, bounds), expect_genesis=bounds.starts_at_genesis)
    print_report(report, bounds, out)
    return EXIT_FINDINGS if findings_of(report) else EXIT_OK


# ─── конфигурация и соединение ───────────────────────────────────────────────────────────────


def build_engine(out: IO[str]) -> Engine | None:
    """Движок из конфигурации процесса; `None` — адрес недоступен или настроен криво.

    Роль — из `db_url`, то есть роль приложения (`ADR-006`): разбор читает журнал, а
    `SELECT` приложению выдан. Права роли-владельца здесь нет намеренно: проверка
    append-only-состояния не должна требовать привилегированного доступа и не может получить его
    молча (`ADR-018`: владелец нужен только миграциям).
    """
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"конфигурация отклонена: {safe_text('; '.join(exc.reasons))}", file=out)
        return None
    if settings.db_url is None:
        print(
            f"адрес базы не настроен: нужен TBOT_DB_URL или файл db_url в secrets_dir "
            f"({settings.secrets_dir})",
            file=out,
        )
        return None
    try:
        return create_engine(sqlalchemy_url(settings.db_url.get_secret_value()), pool_pre_ping=True)
    except ValueError as exc:
        # `sqlalchemy_url` печатает разобранный адрес в сообщении — наружу он не идёт.
        print(f"адрес базы разобран неправильно: {safe_text(exc)}", file=out)
        return None


@contextmanager
def fresh_session(engine: Engine) -> Iterator[Session]:
    """Сессия на отдельном соединении: `engine.connect()` вне любой писавшей транзакции.

    Разбор обязан видеть состояние журнала, зафиксированное на момент запуска, а не атрибуты
    из identity map сессии, которая эти строки меняла (`ADR-025` п. 7).
    """
    connection = engine.connect()
    session = Session(bind=connection, expire_on_commit=False)
    try:
        yield session
    finally:
        session.close()
        connection.close()


# ─── командная строка ────────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit_verify.py",
        description=(
            "разбор цепочки хэшей журнала аудита: пересчёт hash по колонкам каждой строки и "
            "сверка hash_prev с хэшем предыдущей строки (TZ §8.7, AC-identity-04, ADR-025 п. 7)"
        ),
        epilog=(
            "коды: 0 — находок нет, 1 — цепочка нарушена, 2 — неверная выборка, "
            "3 — база недоступна или схема не развёрнута; адрес базы — из TBOT_DB_URL или "
            "файла db_url, из аргументов не берётся"
        ),
    )
    group = parser.add_argument_group(
        "выборка", "без ограничений разбирается весь журнал; пустой журнал — код 0"
    )
    group.add_argument(
        "--since",
        default=None,
        metavar="МЕТКА",
        help="разобрать с метки включительно (ГГГГ-ММ-ДД или ISO-8601; без смещения — UTC)",
    )
    group.add_argument(
        "--until", default=None, metavar="МЕТКА", help="разобрать по метку включительно"
    )
    group.add_argument(
        "--from-id", type=int, default=None, metavar="ID", help="разобрать с идентификатора"
    )
    group.add_argument(
        "--to-id", type=int, default=None, metavar="ID", help="разобрать по идентификатор"
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    session_factory: Callable[[], Session] | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
    rows_reader: Callable[[Session, Bounds], list[StoredRecord]] = read_journal,
) -> int:
    """Точка входа.

    `session_factory`, `rows_reader` и потоки подставляются проверками; в бою — конфигурация
    приложения, чтение отдельным соединением и стандартные потоки процесса. Подстановка нужна,
    чтобы оффлайновая половинка (`tests/integration/test_audit_verify.py`) исполняла тот же код
    решения без базы; живая половинка — `tests/integration/test_audit_verify_db.py`.
    """
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    for name, value in (("--from-id", args.from_id), ("--to-id", args.to_id)):
        if value is not None and value < 1:
            print(f"{name}: идентификатор обязан быть положительным, получено {value}", file=err)
            return EXIT_USAGE
    try:
        bounds = build_bounds(
            since=args.since, until=args.until, from_id=args.from_id, to_id=args.to_id
        )
    except VerifyError as exc:
        print(exc.detail, file=err)
        return exc.code

    if session_factory is not None:
        # Проверки держат соединение сами: сессия им и закрывается.
        session = session_factory()
        try:
            return run(session=session, bounds=bounds, out=out, rows_reader=rows_reader)
        except SQLAlchemyError as exc:
            print(f"база недоступна или схема не развёрнута: {safe_text(exc)}", file=err)
            return EXIT_ENV
        finally:
            session.close()

    engine = build_engine(out)
    if engine is None:
        return EXIT_ENV
    try:
        with fresh_session(engine) as session:
            return run(session=session, bounds=bounds, out=out, rows_reader=rows_reader)
    except SQLAlchemyError as exc:
        print(
            f"база недоступна или схема не развёрнута: {safe_text(exc)} — сверьте адрес базы и "
            "что миграции выполнены (docs/runbook/stand-deploy.md §5)",
            file=err,
        )
        return EXIT_ENV
    except VerifyError as exc:
        print(exc.detail, file=err)
        return exc.code
    except Exception as exc:
        # Последний барьер: текст вычищен (`safe_text`) — сообщение драйвера может содержать
        # параметры запроса. Лога у инструмента нет: вывод и есть единственный след прогона.
        print(f"непредвиденная ошибка: {safe_text(exc)}", file=err)
        return EXIT_UNEXPECTED
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
