"""Контракт схемы идентичности и доступа: TZ §4.1, §8.1–8.5, §4.11 (`REQ-storage-02`).

Проверки намеренно не требуют живой базы. Полный цикл `upgrade head → downgrade base →
upgrade head` на настоящем PostgreSQL делает CI job `migrations` (на dev-машине ни Docker, ни
Postgres нет), но почти все ошибки схемы видно и без сервера: Alembic умеет *генерировать* SQL
в офлайн-режиме (`--sql`), и это ровно тот DDL, который уйдёт на площадку. Здесь следят за тем,
что:

* модели (`packages/storage/models.py`) и ревизия `0002` не разъехались — таблицы, колонки,
  имена ограничений и индексов совпадают;
* обратная миграция снимает всё, что создала прямая (иначе `downgrade base` оставит мусор, а
  приёмка T-009 требует обратимости);
* в схеме нет вещественных типов и «наивного» времени (§4 «общие правила», `REQ-storage-02`);
* у каждой ревизии есть непустой `downgrade` — пустой `downgrade` не ловит ни одна другая
  проверка, он просто молча делает вид, что откатился;
* имя файла ревизии совпадает с её `revision`, а цепочка обязана быть одиночной линией: `0004`
  идёт прямо за `0003`, `0006` — прямо за `0004`, `0007` — прямо за `0006` (слоты цепи зафиксированы решениями заказчика и
  больше ничем не держатся; разрыв имён `0004 → 0007` легален, `ADR-022`);
* каждая колонка, которую ревизия добавляет к уже созданной таблице, обоснована ADR: таблица из
  §4.1 не оправдание для колонки, которой в модели данных ТЗ нет.

Ограничение метода: офлайн-SQL не проверяет, что PostgreSQL примет DDL (например, опечатку в
выражении частичного индекса поймает только CI). Это осознанный раздел: быстрые структурные
проверки здесь, исполнение — там.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Final

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory

from packages.common.ids import uuid7
from packages.storage.base import NAMING_CONVENTION, Base
from packages.storage.models import (
    AUDIT_NOTIFY_GROUNDS,
    AUDIT_NOTIFY_OUTCOMES,
    INVITATION_STATES,
    SESSION_AUTH_STEPS,
    USER_ROLES,
    USER_STATES,
)

ROOT = Path(__file__).resolve().parents[2]

# Таблицы, которые создаёт ревизия 0002, — перечень из TZ §4.1 «Идентификация и доступ».
# `webauthn_credentials` в списке нет намеренно: §4.1 помечает её как «опция M7, не M1».
IDENTITY_TABLES: frozenset[str] = frozenset(
    {
        "users",
        "invitations",
        "totp_enrollments",
        "backup_codes",
        "totp_failures",
        "sessions",
        "ip_allowlist",
        "audit_log",
    }
)
# Ревизия 0001 (`app_meta`) и служебная таблица Alembic — не часть схемы идентичности.
_NON_IDENTITY_TABLES: frozenset[str] = frozenset({"app_meta", "alembic_version"})

# Таблицы схемы, которых нет в перечне §4.1, но которые появились по решению заказчика и
# обоснованы в ADR: имя таблицы → файл обоснования. Пустой словарь — правильное состояние для
# всего, что описано в §4.1; каждая новая «лишняя» таблица обязана появиться здесь вместе с ADR,
# иначе следующая ревизия тихо расширит схему без решения заказчика (проверка ниже читает файлы).
_OPERATIONAL_TABLES: Final[dict[str, str]] = {
    "rate_buckets": "docs/adr/ADR-007-rate-limit-counter-table.md",  # TZ §8.3, ask `fe0b025e`
    # Журнал решений порога уведомлений: таблица вне перечня §4.1, обоснование — ADR задачи
    # `T-116` (TZ §8.7, второй абзац; слот `0006` закреплён `ADR-022` п. 3).
    "web_audit_outbox": "docs/adr/ADR-028-audit-notification-outbox.md",
}

# Колонки, добавленные ревизиями к уже существующей таблице: «таблица.колонка» → файл обоснования.
# Аналог `_OPERATIONAL_TABLES`, но для колонок: таблица из §4.1 не оправдание для колонки, которой в
# модели данных ТЗ нет (проверка ниже читает этот перечень вместе с офлайн-DDL).
_COLUMN_EXTENSIONS: Final[dict[str, str]] = {
    # TZ §8.2 «коды принимаются один раз», ADR-013 п. 4 (ask `865f677f-46b6-4acd-ae9c-40c522ab9b1d`);
    # слот цепи `0004` — ask `a4f68e3c-9dfb-4941-ad2d-34575db67415`.
    "totp_enrollments.last_used_step": (
        "docs/adr/ADR-013-totp-own-implementation-and-replay-guard.md"
    ),
}

# Всё, что создаёт история миграций кроме служебных таблиц: перечни §4.1 плюс обоснованные
# добавления. Сверки «модели ↔ ревизия» идут по этому множеству, а сверки «схема ↔ §4.1» —
# строго по `IDENTITY_TABLES`: иначе «лишняя» таблица прикрывала бы отсутствие таблиц из ТЗ.
_SCHEMA_TABLES: frozenset[str] = IDENTITY_TABLES | frozenset(_OPERATIONAL_TABLES)

# `postgresql+psycopg://` — форма площадки (TZ §14.9); без пароля: строка подключения с
# учётными данными в репозитории запрещает `tests/contract/test_no_forbidden_references.py`.
# База при этом не открывается: `--sql` только генерирует текст.
_FAKE_DB_URL = "postgresql+psycopg://tbot@127.0.0.1:5432/tbot_offline"

_CREATE_TABLE_RE = re.compile(r"^CREATE TABLE (?P<name>\w+) \($")
_CONSTRAINT_RE = re.compile(r"^CONSTRAINT (?P<name>\w+) ")
# Ограничение, добавленное к уже существующей таблице (ревизия `0003` так добавляет CHECK формата
# `sessions.token_hash`): в офлайн-SQL это отдельная строка `ALTER TABLE … ADD CONSTRAINT …`,
# внутри блока `CREATE TABLE` её нет.
_ALTER_ADD_CONSTRAINT_RE = re.compile(r"^ALTER TABLE (\w+) ADD CONSTRAINT (\w+) ", re.M)
# Колонка, добавленная более поздней ревизией к уже созданной таблице (ревизия `0004` так добавляет
# `totp_enrollments.last_used_step`). Без этого разбора офлайн-DDL видит только `CREATE TABLE`, и
# сверка «модели ↔ ревизия» расходится в одну сторону: в модели колонка есть, в тексте DDL её нет.
_ALTER_ADD_COLUMN_RE = re.compile(r"^ALTER TABLE (\w+) ADD COLUMN (\w+)", re.M)
_INDEX_RE = re.compile(r"^CREATE (?:UNIQUE )?INDEX (?P<name>\w+) ON (?P<table>\w+) ", re.M)
_FORBIDDEN_TYPES: tuple[str, ...] = (
    "DOUBLE PRECISION",
    "REAL",
    "FLOAT",
    "MONEY",
)


@lru_cache(maxsize=4)
def _offline_sql(*args: str) -> str:
    """Сгенерировать SQL ревизий без подключения к базе (`alembic … --sql`).

    `cwd` — корень репозитория, чтобы Alembic нашёл `alembic.ini`; вывод декодируется из UTF-8
    явно: на Windows у дочернего процесса локальная кода страницы, а в DDL есть кириллические
    комментарии (`COMMENT ON TABLE`).
    """
    with tempfile.TemporaryDirectory(prefix="tbot-offline-secrets-") as secrets:
        completed = subprocess.run(
            [sys.executable, "-m", "alembic", *args, "--sql"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            env={
                **os.environ,
                "TBOT_DB_URL": _FAKE_DB_URL,
                "TBOT_SECRETS_DIR": secrets,
                "PYTHONUTF8": "1",
                "PYTHONIOENCODING": "utf-8",
            },
        )
    if completed.returncode != 0:
        tail = (completed.stderr or "").strip().splitlines()[-8:]
        msg = f"alembic {' '.join(args)} --sql завершился кодом {completed.returncode}: {'; '.join(tail)}"
        raise AssertionError(msg)
    return completed.stdout.replace("\r\n", "\n")


def _parse_tables(sql: str) -> dict[str, dict[str, list[str]]]:
    """Разобрать `CREATE TABLE … ( … );` на колонки и именованные ограничения.

    Отдельно собираются ограничения, добавленные `ALTER TABLE … ADD CONSTRAINT` к таблице,
    созданной более ранней ревизией: без них офлайн-разбор «не видит» половину схемы, и
    последующие проверки сравнивали бы модели с недополученным набором ограничений.
    """
    tables: dict[str, dict[str, list[str]]] = {}
    current: dict[str, list[str]] | None = None
    for raw in sql.splitlines():
        line = raw.strip()
        if current is None:
            match = _CREATE_TABLE_RE.match(line)
            if match:
                tables[match.group("name")] = {"columns": [], "constraints": []}
                current = tables[match.group("name")]
            continue
        if line.startswith(");"):
            current = None
            continue
        constraint = _CONSTRAINT_RE.match(line)
        if constraint:
            current["constraints"].append(constraint.group("name"))
        elif line:
            current["columns"].append(line.split()[0])
    for table_name, constraint_name in _ALTER_ADD_CONSTRAINT_RE.findall(sql):
        entry = tables.setdefault(table_name, {"columns": [], "constraints": []})
        entry["constraints"].append(constraint_name)
    for table_name, column_name in _ALTER_ADD_COLUMN_RE.findall(sql):
        entry = tables.setdefault(table_name, {"columns": [], "constraints": []})
        entry["columns"].append(column_name)
    return tables


def _index_names(sql: str) -> dict[str, set[str]]:
    """Индексы офлайн-SQL: {таблица: {имя_индекса}}."""
    found: dict[str, set[str]] = {}
    for match in _INDEX_RE.finditer(sql):
        found.setdefault(match.group("table"), set()).add(match.group("name"))
    return found


def _index_names_from_models(tables: set[str]) -> dict[str, set[str]]:
    return {
        name: {index.name or "" for index in Base.metadata.tables[name].indexes} for name in tables
    }


def _constraint_names_from_models(table_name: str) -> set[str]:
    """Имена ограничений из моделей — те же требования, что и в конвенции имён `base.py`."""
    names: set[str] = set()
    for constraint in Base.metadata.tables[table_name].constraints:
        assert isinstance(constraint.name, str), f"{table_name}: у ограничения нет имени"
        names.add(constraint.name)
    return names


@pytest.fixture(scope="module")
def upgrade_sql() -> str:
    return _offline_sql("upgrade", "head")


@pytest.fixture(scope="module")
def downgrade_sql() -> str:
    return _offline_sql("downgrade", "head:base")


def test_цепочка_ревизий_линейна_и_без_развилок() -> None:
    """Одна линия истории и известный состав ревизий (приёмка T-009, продолжение `T-102`).

    `heads` обязан быть одиночным: развилка означает, что две сессии завели соседние ревизии и
    `upgrade head` на площадке начнёт падать с «multiple heads».
    """
    script = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))
    heads = script.get_heads()
    assert heads == ["0007"], f"ожидалась одна линия истории, получено: {heads}"
    walked = [rev.revision for rev in script.walk_revisions()]
    assert set(walked) == {
        "0001",
        "0002",
        "0003",
        "0004",
        "0006",
        "0007",
    }, f"состав ревизий изменился: {walked}"

    # Имя файла и id ревизии обязан сходиться: слот цепи — договорённость, зафиксированная в ADR
    # (`0004` занят `T-103`, `0005` отдан `T-105` решением ask `11aa27b8-0034-417c-b5c1-dce0b5c006f8`,
    # `T-116` — `0006` (файл есть с 2026-11-24), `audit_log` и `T-109` — `0007` решением ask
    # `6e2c3163-b402-4a45-ad00-bb9794979837`, `ADR-022`),
    # а Alembic читает id из содержимого файла.
    # Расхождение «файл `0005_…`, а внутри revision = "0004"» не ловит больше ничего.
    parents: dict[str, object] = {}
    for path in sorted((ROOT / "migrations" / "versions").glob("*.py")):
        values = _revision_ids(path)
        assert values["revision"] == path.name.split("_", 1)[0], (
            f"{path.name}: id {values['revision']!r} не совпадает с префиксом имени файла — "
            "слот цепи и имя обязаны сходиться"
        )
        parents[str(values["revision"])] = values["down_revision"]
    assert parents["0004"] == "0003", (
        f"ревизия 0004 обязана следовать прямо за 0003 (слот занят `T-103`, ask "
        "`a4f68e3c-9dfb-4941-ad2d-34575db67415`), получено: "
        f"down_revision = {parents['0004']!r}"
    )
    # Отдельное утверждение о паре `0007 → 0004`: слот журнала закреплён заказчиком
    # (`ADR-022`), и «следующая ревизия завелась бы как `0005`» — ровно тот риск, который этот
    # раздел ADR называет признаком поломки. Разрыв имён при этом легален: история линейна.
    assert parents["0006"] == "0004", (
        f"ревизия 0006 обязана следовать прямо за 0004 (слот `web_audit_outbox` за `T-116`, "
        "`ADR-022` п. 3, `ADR-028`), получено: "
        f"down_revision = {parents['0006']!r}"
    )
    # Ревизия журнала перерождена: родство `0004 → 0006 → 0007`, а не `0004 → 0007`
    # (`ADR-026` п. 6, решение заказчика ask `cc2cfb78-b5bf-4ca2-9ac3-459de2b9b4a4`). Порядок
    # обязателен: база площадки уже прошла `0007`, и если бы `0006` встала после неё, следующий
    # `upgrade head` искал бы неприменённую ступень под пройденной головой (`ADR-028`, «риски»).
    assert parents["0007"] == "0006", (
        f"ревизия 0007 обязана следовать прямо за 0004 (слот журнала за `T-109`, `ADR-022`, ask "
        "`6e2c3163-b402-4a45-ad00-bb9794979837`), получено: "
        f"down_revision = {parents['0007']!r}"
    )


def _revision_ids(path: Path) -> dict[str, object]:
    """`revision` и `down_revision` из файла ревизии (без импорта модуля миграций)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: dict[str, object] = {}
    for node in tree.body:
        item = _literal_assignment(node)
        if item is None:
            continue
        name, literal = item
        if name in {"revision", "down_revision"}:
            found[name] = literal
    assert "revision" in found, f"{path.name}: у ревизии нет литерала revision"
    return found


def _literal_assignment(node: ast.stmt) -> tuple[str, object] | None:
    """Присваивание `имя = <литерал>` (с аннотацией или без) → (имя, значение).

    Разбор без импорта модулей миграций: нужно прочитать id, а не исполнять чужой код.
    """
    target: ast.expr
    value: ast.expr
    if isinstance(node, ast.AnnAssign):
        if node.value is None:  # аннотация `x: int` без значения — присваивания нет
            return None
        target, value = node.target, node.value
    elif isinstance(node, ast.Assign) and len(node.targets) == 1:
        target, value = node.targets[0], node.value
    else:
        return None
    if not isinstance(target, ast.Name) or not isinstance(value, ast.Constant):
        return None
    return target.id, value.value


def test_каждая_ревизия_умеет_откатываться_не_пустышкой() -> None:
    """`downgrade` без тела — самая дешёвая имитация обратимости (приёмка T-009)."""
    for path in sorted((ROOT / "migrations" / "versions").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        assert {"upgrade", "downgrade"} <= set(functions), f"{path.name}: нет upgrade/downgrade"
        for name in ("upgrade", "downgrade"):
            calls = [node for node in ast.walk(functions[name]) if isinstance(node, ast.Call)]
            assert calls, f"{path.name}: {name}() не делает ничего — это пустышка, а не миграция"


def test_схема_идентичности_соответствует_перечню_тз_4_1() -> None:
    """Таблицы §4.1 обязаны быть все; сверх §4.1 — только обоснованные ADR добавлением.

    Проверка намеренно не «равно», а «⊆ + список лишнего»: иначе новая таблица вне ТЗ
    (счётчик частоты, §8.3) выглядела бы как нарушение §4.1, и следующая сессия удалила бы её
    «для соответствия». Но и произвольным добавлением это быть не может: каждая лишняя таблица обязана
    быть перечислена с файлом обоснования, и этот файл обязан существовать.
    """
    modelled = set(Base.metadata.tables)
    missing = IDENTITY_TABLES - modelled
    assert not missing, f"в модели нет таблиц из TZ §4.1: {sorted(missing)}"
    extra = modelled - IDENTITY_TABLES - _NON_IDENTITY_TABLES
    assert extra == set(_OPERATIONAL_TABLES), (
        "в models.py появились таблицы вне перечня §4.1 и без обоснования: "
        f"{sorted(extra - set(_OPERATIONAL_TABLES))}; обоснование — ADR и перечень в этом тесте"
    )
    for table, adr in sorted(_OPERATIONAL_TABLES.items()):
        assert (ROOT / adr).exists(), f"{table}: обоснование {adr} не найдено"
        text = (ROOT / adr).read_text(encoding="utf-8")
        assert (
            f"`{table}`" in text or table in text
        ), f"{adr} не упоминает {table}: обоснование должно объяснять именно эту таблицу"


def test_колонки_добавленные_ревизиями_к_готовым_таблицам_обоснованы(upgrade_sql: str) -> None:
    """Колонка, добавленная ревизией к уже существующей таблице, обязана иметь обоснование.

    Таблица из перечня §4.1 не оправдание для колонки, которой в модели данных ТЗ нет: именно так
    схема и разъезжается с техзаданием — по одному «незначительному» добавлению за срез. Поэтому
    каждая такая колонка перечислена в `_COLUMN_EXTENSIONS` с файлом обоснования, файл обязан
    существовать и упоминать колонку, а сама колонка — быть в моделях (перечень не обязан
    переживать собственную отмену).
    """
    added = {(table, column) for table, column in _ALTER_ADD_COLUMN_RE.findall(upgrade_sql)}
    modelled = {
        f"{table}.{column.name}"
        for table in sorted(_SCHEMA_TABLES)
        for column in Base.metadata.tables[table].columns
    }
    for table, column in sorted(added):
        key = f"{table}.{column}"
        assert key in _COLUMN_EXTENSIONS, (
            f"{key}: колонка добавлена ревизией к существующей таблице без обоснования — "
            "добавьте её в `_COLUMN_EXTENSIONS` с файлом ADR или решения заказчика"
        )
        adr = _COLUMN_EXTENSIONS[key]
        assert (ROOT / adr).exists(), f"{key}: обоснование {adr} не найдено"
        assert f"`{column}`" in (ROOT / adr).read_text(
            encoding="utf-8"
        ), f"{adr} не упоминает {column}: обоснование должно объяснять именно эту колонку"
    for key in sorted(_COLUMN_EXTENSIONS):
        assert key in modelled, (
            f"{key}: числится как добавленная ревизией, но в моделях её нет — перечень устарел "
            "(колонку убрали или переименовали, не сняв обоснование)"
        )


def test_модели_и_ревизия_создают_одни_те_же_таблицы(upgrade_sql: str) -> None:
    tables = _parse_tables(upgrade_sql)
    created = set(tables) - _NON_IDENTITY_TABLES
    assert created == _SCHEMA_TABLES, f"ревизия создаёт не те таблицы: {sorted(created)}"
    for name in sorted(_SCHEMA_TABLES):
        modelled = {column.name for column in Base.metadata.tables[name].columns}
        actual = set(tables[name]["columns"])
        assert modelled == actual, (
            f"{name}: модель и ревизия разошлись по колонкам — "
            f"в модели только: {sorted(modelled - actual)}, "
            f"в ревизии только: {sorted(actual - modelled)}"
        )


def test_имена_ограничений_совпадают_с_конвенцией_и_между_собой(upgrade_sql: str) -> None:
    tables = _parse_tables(upgrade_sql)
    prefixes = ("pk_", "fk_", "ck_", "uq_", "ix_")
    for name in sorted(_SCHEMA_TABLES):
        expected = _constraint_names_from_models(name)
        actual = set(tables[name]["constraints"])
        assert expected == actual, (
            f"{name}: ограничения разошлись — в модели только: {sorted(expected - actual)}, "
            f"в ревизии только: {sorted(actual - expected)}"
        )
        for constraint in expected:
            assert constraint.startswith(
                prefixes
            ), f"{name}: имя {constraint} вне конвенции {sorted(prefixes)}"
    # PK у каждой таблицы обязан быть (иначе `pg_dump` и репликация теряют строку).
    for name in sorted(_SCHEMA_TABLES):
        assert f"pk_{name}" in set(tables[name]["constraints"]), f"{name}: нет первичного ключа"


def test_индексы_модели_и_ревизии_совпадают(upgrade_sql: str) -> None:
    expected = _index_names_from_models(set(_SCHEMA_TABLES))
    actual = _index_names(upgrade_sql)
    assert set(actual) <= _SCHEMA_TABLES, f"лишние индексы: {sorted(set(actual) - _SCHEMA_TABLES)}"
    for name in sorted(_SCHEMA_TABLES):
        assert expected[name] == actual.get(name, set()), (
            f"{name}: индексы разошлись — модель: {sorted(expected[name])}, "
            f"ревизия: {sorted(actual.get(name, set()))}"
        )


def test_обратная_миграция_снимает_всё_созданное_ревизиями(downgrade_sql: str) -> None:
    """`downgrade head:base` обязан убрать всё, что создали ревизии, — включая счётчик частоты.

    Отдельно проверяется снятие `CHECK`, добавленного ревизией `0003` к чужой таблице: такие
    ограничения не видны в `DROP TABLE`, и их потеря означает, что «чистая» база после отката
    всё ещё несёт часть схемы, а повторный `upgrade head` упадёт на существующем ограничении.
    """
    dropped_tables = set(re.findall(r"^DROP TABLE (\w+);", downgrade_sql, re.M))
    assert (
        dropped_tables >= _SCHEMA_TABLES
    ), f"downgrade не снимает таблицы: {sorted(_SCHEMA_TABLES - dropped_tables)}"
    expected_indexes = _index_names_from_models(set(_SCHEMA_TABLES))
    dropped_indexes = set(re.findall(r"^DROP INDEX (\w+);", downgrade_sql, re.M))
    for table in sorted(_SCHEMA_TABLES):
        missing = expected_indexes[table] - dropped_indexes
        assert not missing, f"{table}: downgrade не снимает индексы {sorted(missing)}"
    # citext создаётся прямой миграцией — обязан сниматься обратной, иначе в базе остаётся
    # расширение, которое больше никто не создаёт и не удаляет осознанно.
    assert "DROP EXTENSION IF EXISTS citext;" in downgrade_sql, "downgrade не снимает citext"
    # CHECK формата хэша значения куки добавлен к уже существующей таблице — его снятие обязано
    # быть видно в обратном DDL (см. docstring выше).
    assert (
        "ALTER TABLE sessions DROP CONSTRAINT ck_sessions_token_hash_format;" in downgrade_sql
    ), "downgrade не снимает CHECK формата sessions.token_hash, добавленный ревизией 0003"
    # Колонка и CHECK к ней, добавленные ревизией 0004 к уже существующей таблице: их снятие видно
    # только в обратном DDL (в `DROP TABLE` оно не «само бы образовалось» — таблица снимается
    # ревизией 0002, а откатиться на 0003 надо уметь отдельно).
    assert (
        "ALTER TABLE totp_enrollments DROP CONSTRAINT "
        "ck_totp_enrollments_last_used_step_not_negative;" in downgrade_sql
    ), "downgrade не снимает CHECK диапазона шага, добавленный ревизией 0004"
    assert (
        "ALTER TABLE totp_enrollments DROP COLUMN last_used_step;" in downgrade_sql
    ), "downgrade не снимает колонку last_used_step, добавленную ревизией 0004"
    # Порядок: таблицы снимаются до расширения (колонки citext блокируют DROP EXTENSION).
    assert downgrade_sql.index("DROP TABLE users;") < downgrade_sql.index(
        "DROP EXTENSION IF EXISTS citext;"
    ), "расширение citext снимается до таблиц — PostgreSQL такой откат не примет"


def test_расширение_citext_создаётся_до_первой_колонки_citext(upgrade_sql: str) -> None:
    assert "CREATE EXTENSION IF NOT EXISTS citext;" in upgrade_sql, "нет создания citext"
    first_use = upgrade_sql.index("CITEXT")
    assert upgrade_sql.index("CREATE EXTENSION IF NOT EXISTS citext;") < first_use, (
        "ревизия создаёт колонку citext раньше расширения: на чистой базе `upgrade head` "
        "упадёт с «type citext does not exist»"
    )


def test_в_схеме_нет_вещественных_типов_и_денег(upgrade_sql: str) -> None:
    """`REQ-storage-02`: деньги и цены — только NUMERIC; здесь — всего одна ревизия.

    Проверка идёт по сгенерированному DDL, а не только по моделям: тип мог появиться и в
    ревизии, и в будущем — в любой следующей, поэтому текст SQL проверяется целиком.
    """
    for forbidden in _FORBIDDEN_TYPES:
        assert not re.search(
            rf"\b{forbidden}\b", upgrade_sql
        ), f"в DDL встречается запрещённый тип {forbidden} (TZ §4.11, REQ-storage-02)"
    floats = [
        f"{table_name}.{column.name}: {type(column.type).__name__}"
        for table_name in sorted(_SCHEMA_TABLES)
        for column in Base.metadata.tables[table_name].columns
        # `sa.Float` покрывает и `postgresql.DOUBLE_PRECISION` (его потомок).
        if isinstance(column.type, sa.Float)
    ]
    assert not floats, "вещественный тип в таблицах схемы: " + "; ".join(floats)


def test_время_везде_с_часовым_поясом(upgrade_sql: str) -> None:
    """TZ §4 «общие правила»: `timestamptz` везде; `timestamp` без пояса — ошибка TZ §2.7."""
    naive = re.findall(r"\bTIMESTAMP\b(?! WITH TIME ZONE)", upgrade_sql)
    assert not naive, f"в DDL найдено время без пояса: {len(naive)} колонок"


def test_внешние_ключи_запрещают_каскадное_удаление(upgrade_sql: str) -> None:
    """§4 «общие правила»: FK с `ON DELETE RESTRICT` — удаление только архивированием."""
    fk_lines = [
        line.strip()
        for line in upgrade_sql.splitlines()
        if line.strip().startswith("CONSTRAINT fk_")
    ]
    assert fk_lines, "во всей ревизии нет ни одного внешнего ключа — подозрительно"
    broken = [line for line in fk_lines if "ON DELETE RESTRICT" not in line]
    assert not broken, "FK без ON DELETE RESTRICT: " + "; ".join(broken)


def test_домены_перечислений_совпадают_с_тз_и_записаны_в_ddl(upgrade_sql: str) -> None:
    assert set(USER_ROLES) == {"admin", "operator", "viewer"}, "роли разошлись с TZ §1.1"
    assert "awaiting_approval" in USER_STATES, "из состояний исчез шаг одобрения (TZ §1.2)"
    assert set(SESSION_AUTH_STEPS) == {"password", "totp", "full"}, "шаги входа (§8.2)"
    assert "used" in INVITATION_STATES, "приглашение должно отмечаться использованным (§1.2)"
    # Домен закреплён базой: в DDL обязан быть полный перечень значений, а не «частичный».
    for state in USER_STATES:
        assert f"'{state}'" in upgrade_sql, f"состояние {state} не закреплено проверкой в DDL"
    for step in SESSION_AUTH_STEPS:
        assert f"'{step}'" in upgrade_sql, f"шаг входа {step} не закреплено проверкой в DDL"
    # Основания уведомлений §8.7 (второй абзац) и решения порога закреплены базой: домен
    # `web_audit_outbox` шире множества производителей намеренно (`ADR-028` п. 3) — имена
    # `risk.*` и `token.revoked` стоят в схеме, хотя производителей у них пока нет.
    for ground in AUDIT_NOTIFY_GROUNDS:
        assert f"'{ground}'" in upgrade_sql, (
            f"основание уведомления {ground} не закреплено проверкой в DDL: домен оснований §8.7 "
            "не должен сужаться до уже написанного"
        )
    for outcome in AUDIT_NOTIFY_OUTCOMES:
        assert (
            f"'{outcome}'" in upgrade_sql
        ), f"решение порога {outcome} не закреплено проверкой в DDL (`ADR-028` п. 4)"


def test_окружение_alembic_использует_метаданные_моделей() -> None:
    """Без `target_metadata` от моделей `alembic check` и `make revision` слепы."""
    env_source = (ROOT / "migrations" / "env.py").read_text(encoding="utf-8")
    assert "target_metadata = Base.metadata" in env_source, (
        "env.py не подключает метаданные слоя storage: автосгенерированная ревизия "
        "предложила бы удалить таблицы, которых «не видно»"
    )
    assert (
        "from packages.storage.base import" in env_source
    ), "env.py обязан брать конвенцию имён из слоя storage, а не заводить свою копию"
    assert "NAMING_CONVENTION: dict" not in env_source, (
        "в env.py появилась вторая копия конвенции имён: модели и ревизии начнут называть "
        "ограничения по-разному"
    )


def test_конвенция_имён_покрывает_все_типы_ограничений() -> None:
    assert set(NAMING_CONVENTION) == {"ix", "uq", "ck", "fk", "pk"}, (
        "конвенция имён должна оставаться полной: без `ck`/`fk` имена ограничений "
        "генерирует PostgreSQL, и их нельзя найти в обратных миграциях"
    )


def test_аудит_обязан_иметь_цепочку_хэшей_и_время(upgrade_sql: str) -> None:
    """REQ-identity-04: колонки цепочки — часть схемы, а не соглашение приложения."""
    audit = Base.metadata.tables["audit_log"]
    for column in ("at", "action", "hash_prev", "hash"):
        assert column in audit.c, f"в audit_log нет колонки {column}"
    assert not audit.c["hash"].nullable, "hash записи цепочки обязан быть заполнен"
    assert audit.c[
        "hash_prev"
    ].nullable, "у первой записи цепочки предыдущего хэша нет — колонка обязана допускать NULL"
    for constraint in ("ck_audit_log_hash_sha256", "ck_audit_log_hash_prev_sha256"):
        assert constraint in _constraint_names_from_models("audit_log"), f"в схеме нет {constraint}"
    assert (
        "BIGINT GENERATED BY DEFAULT AS IDENTITY" in upgrade_sql
    ), "audit_log.id обязан быть identity (эквивалент bigserial из TZ §4.1)"


def test_аудит_не_позволяет_развилку_цепочки(upgrade_sql: str) -> None:
    """У записи журнала не может быть двух следующих (TZ §4.1 `REQ-identity-04`, `ADR-025` п. 4).

    Само по себе наличие колонок цепочки ничего не стоит, если два процесса вставили две строки
    с одним `hash_prev`: развилка не видна ни в одной колонке и делает «разрыв цепочки» шумом.
    Поэтому страж обязан быть базовым объектом, и проверка держит три его свойства сразу:
    уникальность (иначе «две следующие» проходят), частичность (у первой записи `hash_prev` нет,
    и `NULL` в индексе участвовать не должен) и наличие в DDL ревизии `0007` — иначе индекс
    остался бы в моделях, а площадка про него бы не узнала.
    """
    fork_guard = next(
        (
            index
            for index in Base.metadata.tables["audit_log"].indexes
            if index.name == "ix_audit_log_hash_prev_linked"
        ),
        None,
    )
    assert fork_guard is not None, (
        "в audit_log нет индекса `ix_audit_log_hash_prev_linked`: развилку цепочки держал бы "
        "только протокол добавления в приложении (ADR-025 п. 4, 6)"
    )
    assert fork_guard.unique, "индекс по hash_prev обязан быть уникальным"
    where = fork_guard.dialect_options["postgresql"].get("where")
    assert where is not None, (
        "индекс по hash_prev обязан быть частичным (`WHERE hash_prev IS NOT NULL`): у записи "
        "начала цепочки предыдущего хэша нет"
    )
    assert "hash_prev IS NOT NULL" in str(
        where
    ), f"предикат индекса обязан исключать NULL у записи начала, получено: {where}"
    assert "CREATE UNIQUE INDEX ix_audit_log_hash_prev_linked" in upgrade_sql, (
        "индекса нет в DDL: ревизия `0007` его не создаёт, и на площадке развилку держит "
        "только приложение"
    )


def test_первичные_ключи_выдаёт_приложение_и_это_uuidv7() -> None:
    """UUIDv7 вместо v4: индексы не фрагментируются случайными вставками, а `ORDER BY id` —
    это хронология появления строк (TZ §2.7, `packages/common/ids.py`).

    `audit_log.id` — исключение: там счётчик ведёт база (identity, §4.1), потому что журнал
    пишется из разных процессов, а порядок вставок в нём важнее идентификатора.

    Проверяется договор «id выдаёт приложение», а не конкретная функция: ORM при конфигурации
    маппера оборачивает column-default в свой вызываемый объект (в него подмешивается контекст
    вставки), поэтому сравнение `is` и вызов `arg()` падают на обёртке, а не на ошибке схемы.
    """
    stamps = [uuid7().int >> 80 for _ in range(3)]
    assert stamps == sorted(stamps), "метка времени в UUIDv7 не возрастает — порядок сломан"

    for table_name in sorted(IDENTITY_TABLES - {"audit_log"}):
        pk_columns = list(Base.metadata.tables[table_name].primary_key.columns)
        assert len(pk_columns) == 1, f"{table_name}: ожидался одиночный PK, найдено {pk_columns}"
        primary_key = pk_columns[0]
        assert (
            primary_key.default is not None
        ), f"{table_name}: у PK нет прикладного генератора — ORM вставит NULL"
        assert primary_key.server_default is None, (
            f"{table_name}: у PK появился серверный генератор: id начнёт выдавать база, "
            "а упорядоченность UUIDv7 (TZ §2.7) потеряется"
        )

    audit_pk_columns = list(Base.metadata.tables["audit_log"].primary_key.columns)
    assert len(audit_pk_columns) == 1, f"у audit_log ожидался одиночный PK: {audit_pk_columns}"
    audit_pk = audit_pk_columns[0]
    assert audit_pk.identity is not None, "audit_log.id обязан быть identity (TZ §4.1 bigserial)"
    assert audit_pk.identity.always is False, (
        "identity обязан быть `BY DEFAULT`, а не `ALWAYS`: pg_dump при восстановлении вставляет "
        "свои значения id, и ALWAYS без OVERRIDING SYSTEM VALUE такой дамп не примет"
    )
