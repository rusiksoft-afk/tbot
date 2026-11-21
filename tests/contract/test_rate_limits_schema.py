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

Отдельно держится граница «в схеме только то, что решено заказчиком»: набор окон счётчика —
ровно пара 60 и 300 секунд (§8.3 и §8.2, решение ask `abb0151c`), и в таблице не появляется
длительность самого бана — её в хранении держать нечего, это константа прикладного слоя.
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
from packages.storage.models import (
    RATE_BAN_WINDOW_SECONDS,
    RATE_SCOPES,
    RATE_WINDOW_SECONDS,
    RATE_WINDOWS,
)

ROOT = Path(__file__).resolve().parents[2]
TZ_SECURITY: Final = ROOT / "docs" / "tz" / "08-security-auth-2fa.md"
ADR_RATE: Final = ROOT / "docs" / "adr" / "ADR-007-rate-limit-counter-table.md"
ADR_CSRF: Final = ROOT / "docs" / "adr" / "ADR-008-csrf-token-derived-from-session.md"
MIGRATION: Final = ROOT / "migrations" / "versions" / "0003_rate_counters.py"
HANDOFF: Final = ROOT / "docs" / "HANDOFF.md"
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


def test_области_счётчика_совпадают_с_лимитами_8_3_и_окном_перебора_8_2(upgrade_sql: str) -> None:
    """§8.3: `/login` 10/мин/IP, `/totp` 10/мин/сессия и 5/мин/IP, мутации 60/мин/пользователь.

    Пятая область — `ip_ban`: §8.2 требует считать «3 неудачные попытки с одного IP за 5 минут»,
    и с 2026-11-21 этот учёт держит приложение (ask `abb0151c`).
    """
    tz = TZ_SECURITY.read_text(encoding="utf-8")
    line = re.search(r"Rate limit:(.*?)Счётчик обязателен", tz, re.S)
    assert line, "в §8.3 не найден абзац Rate limit — проверка теряет смысл"
    listed = re.findall(r"\d+\s*/?\s*(?:запросов/мин|мин/)", line.group(1))
    assert len(listed) == 4, f"в §8.3 ожидалось четыре лимита, найдено {len(listed)}: {listed}"
    assert re.search(
        r"3 неудачные попытки с одного IP за 5 минут", tz
    ), "в §8.2 не найдено правило перебора по IP — проверка теряет смысл"
    assert len(RATE_SCOPES) == 5, f"областей счётчика {len(RATE_SCOPES)} ({RATE_SCOPES})"
    assert "ip_ban" in RATE_SCOPES, f"в {RATE_SCOPES} нет области окна перебора ip_ban (§8.2)"

    ddl = _table_block(upgrade_sql)
    scope_check = re.search(r"CONSTRAINT ck_rate_buckets_scope CHECK \(scope IN \(([^)]*)\)\)", ddl)
    assert scope_check, f"в {TABLE} нет CHECK перечня областей"
    allowed = {value.strip().strip("'") for value in scope_check.group(1).split(",")}
    assert allowed == set(
        RATE_SCOPES
    ), f"CHECK разрешает области {sorted(allowed)}, модель знает {sorted(RATE_SCOPES)}"


def test_окна_счётчика_зафиксированы_базой_а_не_приложением(upgrade_sql: str) -> None:
    """§8.3 задаёт лимиты «в минуту» (60 с), §8.2 считает перебор «за 5 минут» (300 с).

    Окно живёт в строке, а не в коде приложения: иначе сдвиг лимита («поднимем до 15 в минуту»)
    превратился бы в правку одного числа без следа в схеме. Третьего окна база не допускает.
    """
    assert RATE_WINDOW_SECONDS == 60, "§8.3 задаёт лимиты в минутах, окно обязано быть 60 секунд"
    assert RATE_BAN_WINDOW_SECONDS == 300, "§8.2 считает перебор за 5 минут — окно 300 секунд"
    assert RATE_WINDOWS == (60, 300), f"набор окон в моделях: {RATE_WINDOWS}"

    ddl = _table_block(upgrade_sql)
    window_check = re.search(
        r"CONSTRAINT ck_rate_buckets_window_seconds CHECK \(window_seconds IN \(([^)]*)\)\)",
        ddl,
    )
    assert window_check, f"в {TABLE} нет CHECK набора окон"
    values = [int(value.strip()) for value in window_check.group(1).split(",")]
    assert values == [60, 300], f"DDL допускает окна {values}, а решено (60, 300)"

    column = Base.metadata.tables[TABLE].c.window_seconds
    assert not column.nullable, f"{TABLE}.window_seconds обязана быть заполнена"
    assert column.server_default is not None, (
        f"у {TABLE}.window_seconds нет серверного default: вставка без явного значения из "
        "чистого SQL (восстановление из дампа, ручная правка) упадёт"
    )
    assert (
        f"window_seconds SMALLINT DEFAULT {RATE_WINDOW_SECONDS} NOT NULL" in ddl
    ), f"DDL {TABLE} не закрепляет default окна {RATE_WINDOW_SECONDS}"


def test_окно_перебора_из_8_2_введено_решением_заказчика_а_не_молча(upgrade_sql: str) -> None:
    """Цепочка «правило в ТЗ → решение заказчика → значение в DDL» обязана быть прослеживаемой.

    Держится и обратное: длительность бана в таблице не появляется. В хранении ей делать нечего —
    окно отвечает за интервал подсчёта, а «сколько держать IP закрытым» решает прикладной слой
    вместе с механизмом отказа (T-102, `apps/web`).
    """
    ddl = _table_block(upgrade_sql)
    assert "'ip_ban'" in ddl, f"в {TABLE} нет области ip_ban: перебору §8.2 негде считаться"

    adr = ADR_RATE.read_text(encoding="utf-8")
    assert "abb0151c" in adr, "ADR-007 обязан ссылаться на решение заказчика о владельце бана IP"

    columns = {column.name for column in Base.metadata.tables[TABLE].columns}
    assert columns == {
        "scope",
        "bucket_key",
        "window_start",
        "window_seconds",
        "attempts",
    }, f"в {TABLE} появились лишние колонки {sorted(columns)}: срок бана — не колонка счётчика"


def test_чистка_окон_и_источник_адреса_описаны_и_не_противоречат_техзаданию() -> None:
    """«Временные» строки обязаны умирать: индекс по `window_start` заведён именно под чистку.

    Сам механизм — следующий срез, поэтому проверка держит договорённость (ADR + требование ТЗ об
    источнике адреса), а не код. Оставить таблицу без чистки или начать брать адрес из
    соединения — значит нарушить §8.3: в боевом стенде за Caddy это адрес Caddy, и все лимиты
    сливаются в один «IP».
    """
    adr = ADR_RATE.read_text(encoding="utf-8")
    for marker in ("раз в час", "24 часов", "X-Forwarded-For", "Caddy", "jobs"):
        assert marker in adr, f"в ADR-007 не осталось маркера чистки/адреса {marker!r}"

    tz = TZ_SECURITY.read_text(encoding="utf-8")
    assert "X-Forwarded-For" in tz, "§8.3 обязан требовать адрес клиента из X-Forwarded-For"

    comment = Base.metadata.tables[TABLE].c.bucket_key.comment or ""
    assert "X-Forwarded-For" in comment, (
        f"пояснение bucket_key потеряло источник адреса: {comment!r} — приложение начнёт брать "
        "адрес TCP-соединения, а в проде это адрес Caddy"
    )


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


def test_политика_отказа_зафиксирована_решением_заказчика_а_не_ходом_реализации() -> None:
    """Срок бана, зона отказа и форма ответа решены заказчиком (ask `ba6a9076`).

    Кода лимитов ещё нет, поэтому проверка держит решение: 15 минут, только `/login` и `/totp`,
    `429` с `Retry-After` и запись в журнал, срок — константа кода, отдельная от `LOCK_DURATION`
    блокировки учётной записи. Иначе по ходу реализации «проще» сделать бан на весь `web`,
    молча уронить `403` вместо `429` или взять один срок на два разных правила.
    """
    adr = ADR_RATE.read_text(encoding="utf-8")
    for marker in (
        "ba6a9076",
        "15 минут",
        "только слой входа",
        "IP_BAN_DURATION",
        "LOCK_DURATION",
        "429",
        "Retry-After",
        "audit_log",
        "а не настройкой",
    ):
        assert marker in adr, f"в ADR-007 не осталось маркера политики отказа {marker!r}"

    handoff = HANDOFF.read_text(encoding="utf-8")
    assert "ba6a9076" in handoff, (
        "в docs/HANDOFF.md §4 не осталось ответа заказчика про срок и зону бана: "
        "следующая сессия прочитает этот раздел как открытый вопрос"
    )


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
        "abb0151c",
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
