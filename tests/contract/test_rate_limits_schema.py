"""Контракт счётчика частоты запросов и формата хэша значения куки (`T-102`, ТЗ §8.3, ADR-007).

Живой базы не нужен: проверяется офлайн-DDL (`alembic upgrade head --sql`) против моделей, текста
техзадания и двух ADR. Это ровно тот слой, который тихо уезжает при правке «по ходу дела»:

* перечень областей счётчика (§8.3 перечисляет четыре лимита) кто-нибудь расширяет «чтобы
  заработало», и лимит перестаёт соответствовать ТЗ;
* длительность окна переезжает в приложение, и база перестаёт видеть, что окно минутное;
* счётчик попадает в реестр append-only — и тогда `UPDATE attempts` падает с `42501` на первом
  же запросе входа;
* CHECK формата `sessions.token_hash` разъезжается с тем, что реально выдаёт `token_hash_of()`:
  база тогда кусается не на мусоре, а на корректных значениях.

Отдельно держится граница «решение записано, но не реализовано молча»: пятиминутное окно из §8.2
в DDL отсутствовать обязан (вопрос про него открыт в `docs/HANDOFF.md §4`).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Final

import pytest

from packages.identity.sessions import token_hash_of, token_secret
from packages.storage.base import APPEND_ONLY_TABLES, Base
from packages.storage.models import RATE_SCOPES, RATE_WINDOW_SECONDS

ROOT = Path(__file__).resolve().parents[2]
TZ_SECURITY: Final = ROOT / "docs" / "tz" / "08-security-auth-2fa.md"
ADR_RATE: Final = ROOT / "docs" / "adr" / "ADR-007-rate-limit-counter-table.md"
ADR_CSRF: Final = ROOT / "docs" / "adr" / "ADR-008-csrf-token-derived-from-session.md"
MIGRATION: Final = ROOT / "migrations" / "versions" / "0003_rate_counters.py"
ROLES_SQL: Final = ROOT / "deploy" / "postgres" / "roles.sql"

# Фиктивная база: офлайн-генерация (`--sql`) соединения не открывает, но `migrations/env.py`
# требует, чтобы источник данных был указан, иначе отказывается работать вообще.
_FAKE_DB_URL = "postgresql+psycopg://tbot@127.0.0.1:5432/tbot_offline"

TABLE: Final = "rate_buckets"
_INDEX: Final = "ix_rate_buckets_window_start"
_TOKEN_HASH_CONSTRAINT: Final = "ck_sessions_token_hash_format"
_SHA256_HEX: Final = "^[0-9a-f]{64}$"


@lru_cache(maxsize=1)
def _offline_sql(args: tuple[str, ...]) -> str:
    with tempfile.TemporaryDirectory() as secrets:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                str(ROOT / "alembic.ini"),
                *args,
                "--sql",
            ],
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
        raise AssertionError(f"alembic {' '.join(args)} --sql код {completed.returncode}: {tail}")
    return completed.stdout.replace("\r\n", "\n")


@pytest.fixture(scope="module")
def upgrade_sql() -> str:
    return _offline_sql(("upgrade", "head"))


@pytest.fixture(scope="module")
def downgrade_sql() -> str:
    return _offline_sql(("downgrade", "head:base"))


def _table_block(sql: str) -> str:
    match = re.search(rf"^CREATE TABLE {TABLE} \($.*?^\);$", sql, re.M | re.S)
    assert match, f"в DDL нет блока CREATE TABLE {TABLE} — ревизия 0003 не сгенерировала таблицу"
    return match.group(0)


def test_области_счётчика_совпадают_с_перечнем_лимитов_8_3(upgrade_sql: str) -> None:
    """§8.3: `/login` 10/мин/IP, `/totp` 10/мин/сессия и 5/мин/IP, мутации 60/мин/пользователь."""
    tz = TZ_SECURITY.read_text(encoding="utf-8")
    line = re.search(r"Rate limit:(.*?)Счётчик обязателен", tz, re.S)
    assert line, "в §8.3 не найден абзац Rate limit — проверка теряет смысл"
    listed = re.findall(r"\d+\s*/?\s*(?:запросов/мин|мин/)", line.group(1))
    assert len(listed) == 4, f"в §8.3 ожидалось четыре лимита, найдено {len(listed)}: {listed}"
    assert (
        len(RATE_SCOPES) == 4
    ), f"областей счётчика {len(RATE_SCOPES)} ({RATE_SCOPES}), а лимитов в §8.3 четыре"

    ddl = _table_block(upgrade_sql)
    scope_check = re.search(r"CONSTRAINT ck_rate_buckets_scope CHECK \(scope IN \(([^)]*)\)\)", ddl)
    assert scope_check, f"в {TABLE} нет CHECK перечня областей"
    allowed = {value.strip().strip("'") for value in scope_check.group(1).split(",")}
    assert allowed == set(
        RATE_SCOPES
    ), f"CHECK разрешает области {sorted(allowed)}, модель знает {sorted(RATE_SCOPES)}"


def test_окно_счётчика_зафиксировано_базой_а_не_приложением(upgrade_sql: str) -> None:
    """Все лимиты §8.3 заданы «в минуту»: окно живёт в базе и равно `RATE_WINDOW_SECONDS`."""
    assert RATE_WINDOW_SECONDS == 60, "§8.3 задаёт лимиты в минутах, окно обязано быть 60 секунд"
    ddl = _table_block(upgrade_sql)
    assert (
        f"CONSTRAINT ck_rate_buckets_window_seconds CHECK (window_seconds = {RATE_WINDOW_SECONDS})"
        in ddl
    ), "длительность окна не закреплена базой: приложение сможет менять её молча"
    column = Base.metadata.tables[TABLE].c.window_seconds
    assert not column.nullable, f"{TABLE}.window_seconds обязана быть заполнена"
    assert column.server_default is not None, (
        f"у {TABLE}.window_seconds нет серверного default: вставка без явного значения из "
        "чистого SQL (восстановление из дампа, ручная правка) упадёт"
    )
    assert (
        f"window_seconds SMALLINT DEFAULT {RATE_WINDOW_SECONDS} NOT NULL" in ddl
    ), f"DDL {TABLE} не закрепляет default окна {RATE_WINDOW_SECONDS}"


def test_окно_пяти_минут_из_8_2_в_схеме_не_появляется(upgrade_sql: str) -> None:
    """§8.2 (3 неудачи с IP за 5 минут → бан IP) — вопрос открыт, поэтому 300 секунд в DDL нет.

    Проверка держит границу «решение заказчиком не принято → в схему не заходит»: ADR обязан
    обсуждать пятиминутное окно, а DDL — обязано его не содержать.
    """
    ddl = _table_block(upgrade_sql)
    assert "300" not in ddl, (
        f"в {TABLE} появилось пятиминутное окно: его вводит не решение заказчика "
        "(docs/HANDOFF.md §4, docs/adr/ADR-007)"
    )
    adr = ADR_RATE.read_text(encoding="utf-8")
    assert "300" in adr, "ADR-007 обязан описывать пятиминутное окно как открытый вопрос"
    assert "X-Forwarded-For" in adr, "ADR-007 обязан фиксировать источник адреса клиента (§8.3)"


def test_первичный_ключ_счётчика_это_ключ_поиска_слоя_входа(upgrade_sql: str) -> None:
    """`(scope, bucket_key, window_start)` — и первичный ключ, и форма запроса «счётчик сейчас»."""
    modelled = [column.name for column in Base.metadata.tables[TABLE].primary_key.columns]
    assert modelled == [
        "scope",
        "bucket_key",
        "window_start",
    ], f"первичный ключ счётчика изменился: {modelled}; порядок колонок — это путь поиска"
    ddl = _table_block(upgrade_sql)
    assert (
        "CONSTRAINT pk_rate_buckets PRIMARY KEY (scope, bucket_key, window_start)" in ddl
    ), f"DDL {TABLE} разошёлся с моделью по первичному ключу"


def test_внешних_ключей_у_счётчика_нет_и_это_задокументировано(upgrade_sql: str) -> None:
    """Счётчик не удерживает удаление учётной записи: FK здесь нет намеренно (ADR-007)."""
    ddl = _table_block(upgrade_sql)
    assert "CONSTRAINT fk_" not in ddl, (
        f"у {TABLE} появились внешние ключи: с ON DELETE RESTRICT удаление учётной записи "
        "упрётся в её же счётчики (docs/adr/ADR-007)"
    )
    adr = ADR_RATE.read_text(encoding="utf-8")
    assert "ON DELETE RESTRICT" in adr, "ADR-007 обязан объяснять отсутствие внешних ключей"
    assert "счётчик" in adr


def test_индекс_под_чистку_окон_есть_и_снимается_обратно(
    upgrade_sql: str, downgrade_sql: str
) -> None:
    """Без чистки «временные» строки остаются навсегда: индекс по `window_start` для неё и заведён."""
    assert re.search(
        rf"^CREATE INDEX {_INDEX} ON {TABLE} \(window_start\);", upgrade_sql, re.M
    ), f"нет индекса {_INDEX} — чистка старых окон сканировала бы таблицу целиком"
    assert f"DROP INDEX {_INDEX};" in downgrade_sql, f"downgrade не снимает {_INDEX}"
    assert f"DROP TABLE {TABLE};" in downgrade_sql, f"downgrade не снимает таблицу {TABLE}"
    declared = {index.name for index in Base.metadata.tables[TABLE].indexes if index.name}
    assert declared == {_INDEX}, f"модель объявляет индексы {sorted(declared)}"


def test_формат_хэша_значения_куки_в_базе_и_в_приложении_совпадают(upgrade_sql: str) -> None:
    """CHECK из ревизии 0003 обязан подпускать всё, что выдаёт `token_hash_of()`, и никого больше."""
    alter = re.search(
        rf"^ALTER TABLE sessions ADD CONSTRAINT {_TOKEN_HASH_CONSTRAINT} "
        r"CHECK \(token_hash ~ '(\^\[0-9a-f\]\{64\}\$)'\);$",
        upgrade_sql,
        re.M,
    )
    assert alter, (
        f"ревизия не добавила CHECK {_TOKEN_HASH_CONSTRAINT}: формат хэша держит только приложение "
        "(решение заказчика ask `fe0b025e`)"
    )
    assert alter.group(1) == _SHA256_HEX, "шаблон формата в DDL разошёлся с ожидаемым"

    pattern = re.compile(_SHA256_HEX)
    for _ in range(20):
        digest = token_hash_of(token_secret())
        assert pattern.fullmatch(
            digest
        ), f"приложение выдало хэш, который база отвергнет: {digest!r}"
        assert len(digest) == 64

    rejected = ("A" * 64, "a" * 63, "a" * 64 + "g", "z" * 64, "")
    bad = [value for value in rejected if pattern.fullmatch(value)]
    assert not bad, f"шаблон пропускает мусор: {bad}"

    sessions_model = Base.metadata.tables["sessions"]
    names = {
        constraint.name
        for constraint in sessions_model.constraints
        if type(constraint).__name__ == "CheckConstraint"
    }
    assert (
        _TOKEN_HASH_CONSTRAINT in names
    ), f"в модели sessions нет ограничения {_TOKEN_HASH_CONSTRAINT}: модель и ревизия разошлись"


def test_счётчик_не_журнал_и_отдельных_прав_из_roles_sql_не_требует() -> None:
    """Append-only сломает счётчик: `UPDATE attempts` под ролью приложения получит `42501`."""
    assert TABLE not in APPEND_ONLY_TABLES, (
        f"{TABLE} попала в реестр append-only ({sorted(APPEND_ONLY_TABLES)}): счётчик "
        "изменяемый, и права журнала его убьют"
    )
    roles = ROLES_SQL.read_text(encoding="utf-8")
    assert TABLE not in roles, (
        f"в deploy/postgres/roles.sql появился {TABLE}: права даёт владение (таблицу создаёт "
        "миграция ролью приложения, ADR-006), а файл прав здесь ни при чём"
    )
    migration = MIGRATION.read_text(encoding="utf-8")
    assert "GRANT" not in migration, "ревизия не должна выдавать права — это зона roles.sql"


def test_adr_007_и_adr_008_существуют_и_держат_принятые_решения() -> None:
    """Оба ADR — часть контракта: удалить их или обесцветить нельзя молча."""
    rate = ADR_RATE.read_text(encoding="utf-8")
    for marker in (
        "rate_buckets",
        "ADR-003",
        "APPEND_ONLY_TABLES",
        "fe0b025e",
        "X-Forwarded-For",
        "window_start",
    ):
        assert marker in rate, f"в ADR-007 не осталось маркера {marker!r}"

    csrf = ADR_CSRF.read_text(encoding="utf-8")
    for marker in (
        "HMAC",
        "compare_digest",
        "HttpOnly",
        "X-CSRF-Token",
        "csrf_token",
        "fe0b025e",
    ):
        assert marker in csrf, f"в ADR-008 не осталось маркера {marker!r}"
