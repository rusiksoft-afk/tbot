"""Контракт на файл прав `deploy/postgres/roles.sql` (T-009, `REQ-identity-04`).

Поведение прав проверяет `tests/integration/test_postgres_roles.py` на живой базе в CI. Здесь —
то, что можно проверить без сервера и что иначе уехало бы красным CI или, хуже того, тихим
несоответствием на площадке:

* реестр «только дописываемых» таблиц (`packages/storage/base.py`) и перечень `REVOKE` в SQL-файле
  обязаны совпадать: иначе новая таблица журнала оказывается защищённой только в комментарии;
* каждая таблица реестра действительно существует в схеме (реестр не должен обрасти призраками);
* файл не содержит секретов и не выдаёт прав уровня кластера (ADR-004: значения живут в
  `secrets-setup.sh`, здесь — только имена ролей и права);
* есть `ALTER DEFAULT PRIVILEGES`: иначе следующая ревизия создаст таблицу, которой прав не хватит;
* право `CREATE` на схему выдано явно (миграции идут ролью приложения — решение заказчика,
  вариант Б), и каждая таблица реестра append-only возвращается роли-владельцу: иначе следующая
  таблица журнала, созданная приложением, оказалась бы защищённой только комментарием;
* файл отказывается работать, если его запускает роль приложения (`OWNER TO CURRENT_USER`
  иначе передал бы владение журналу самому приложению);
* проверки прав не исчезли из CI (шаги job'а `migrations`).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import yaml

from packages.storage.base import APPEND_ONLY_TABLES, Base
from packages.storage.models import AuditLogEntry

ROOT = Path(__file__).resolve().parents[2]
ROLES_SQL: Final = ROOT / "deploy" / "postgres" / "roles.sql"
CI_FILE: Final = ROOT / ".github" / "workflows" / "ci.yml"

_APP_ROLE: Final = "tbot_app"

# Оператор REVOKE по одной таблице: имена перечислений и целевая таблица.
_REVOKE_ON_TABLE: Final = re.compile(
    r"REVOKE\s+(?P<privileges>[A-Z, ]+?)\s+ON\s+TABLE\s+(?P<table>[a-z_]+)\s+FROM\s+tbot_app",
    re.IGNORECASE,
)


def _sql() -> str:
    assert ROLES_SQL.is_file(), f"нет файла прав: {ROLES_SQL}"
    return ROLES_SQL.read_text(encoding="utf-8")


def test_файл_прав_существует_и_не_пуст() -> None:
    body = _sql()
    assert len(body) > 500, "deploy/postgres/roles.sql подозрительно короткий"
    assert "BEGIN" in body, "в файле нет начала транзакта"
    assert "COMMIT" in body, (
        "права обязаны применяться одним транзактом: половину выданных прав невозможно "
        "отследить по половинчатому запуску"
    )


def test_реестр_append_only_и_revoke_в_sql_совпадают() -> None:
    sql = _sql()
    revoked: dict[str, set[str]] = {}
    for match in _REVOKE_ON_TABLE.finditer(sql):
        table = match.group("table")
        privileges = {item.strip().upper() for item in match.group("privileges").split(",")}
        revoked.setdefault(table, set()).update(privileges)

    extra = sorted(set(revoked) - set(APPEND_ONLY_TABLES))
    assert not extra, (
        f"в deploy/postgres/roles.sql отзываются права на таблицы вне реестра "
        f"APPEND_ONLY_TABLES: {extra} — либо таблица удалена из схемы, либо её нужно добавить "
        "в реестр (packages/storage/base.py)"
    )

    missing_tables = sorted(set(APPEND_ONLY_TABLES) - set(revoked))
    assert (
        not missing_tables
    ), f"для таблиц реестра {missing_tables} в SQL нет отзыва прав: приложение сможет их править"

    for table in sorted(APPEND_ONLY_TABLES):
        required = {"UPDATE", "DELETE"}
        absent = required - revoked[table]
        assert not absent, (
            f"{table}: не отозваны права {sorted(absent)} — требование REQ-identity-04 "
            "выполняется только текстом ТЗ, а не базой"
        )


def test_таблицы_реестра_существуют_в_схеме() -> None:
    """Модели слоя импортированы: сверка идёт по метаданным схемы, а не по перечню в тесте."""
    assert AuditLogEntry.__tablename__ in Base.metadata.tables, (
        "ORM-модели не зарегистрированы в метаданных: импорт models обязателен, иначе "
        "проверка ниже сравнивает пустое множество таблиц"
    )
    ghost = sorted(APPEND_ONLY_TABLES - set(Base.metadata.tables))
    assert not ghost, (
        f"в реестр append-only попали таблицы, которых нет в слое storage: {ghost} — "
        "SQL-файл с REVOKE по несуществующей таблице падает на площадке"
    )


def test_в_файле_прав_нет_секретов() -> None:
    sql = _sql()
    forbidden = [token for token in ("PASSWORD", "IDENTIFIED BY") if token in sql.upper()]
    assert not forbidden, (
        f"в deploy/postgres/roles.sql появились значения секретов ({forbidden}): "
        "по ADR-004 их вносит deploy/vps/secrets-setup.sh, а в git попадать не должны"
    )


def test_роль_приложения_лишается_прав_уровня_кластера() -> None:
    sql = _sql()
    assert re.search(rf"CREATE ROLE\s+{_APP_ROLE}\s+NOLOGIN", sql, re.IGNORECASE), (
        "роль приложения обязана создаваться без права входа: пароля у неё нет, "
        "и вход включается только явным шагом переключения"
    )
    alter = re.search(rf"ALTER ROLE\s+{_APP_ROLE}[\s\S]{{0,200}}?;", sql, re.IGNORECASE)
    assert alter is not None, "нет ALTER ROLE по роли приложения: права кластера не закреплены"
    block = alter.group(0).upper()
    required = ("NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOBYPASSRLS")
    absent = [name for name in required if name not in block]
    assert not absent, f"в ALTER ROLE нет {absent}: роль может получить права сверх DML"
    assert "LOGIN" not in block.replace("NOLOGIN", ""), (
        "ALTER ROLE не должен включать LOGIN: это право выдаёт шаг переключения на площадке, "
        "и повторный запуск файла прав не должен его отзывать или добавлять"
    )


def test_права_выдаются_по_таблицам_и_на_будущие_таблицы() -> None:
    sql = _sql().upper()
    assert (
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA PUBLIC" in sql
    ), "нет выдачи полного DML по существующим таблицам"
    assert "ALTER DEFAULT PRIVILEGES" in sql, (
        "нет прав по умолчанию: таблица из следующей ревизии останется без прав, и приложение "
        "упадёт с 42501 на первом же запросе к ней"
    )
    assert re.search(
        r"GRANT\s+USAGE[^;]*?ON\s+SCHEMA\s+public\s+TO\s+tbot_app", sql, re.IGNORECASE
    ), "нет USAGE на схему: запросы приложения упадут"
    assert "REVOKE CREATE ON SCHEMA PUBLIC FROM PUBLIC" in sql, (
        "право CREATE на public должно быть явно снято с PUBLIC: иначе любой вход в базу "
        "смог бы создать таблицу-двойник в той же схеме"
    )


def test_права_не_выдаются_публично_и_не_оптом() -> None:
    sql = _sql()
    grants_to_public = [
        line.strip()
        for line in sql.splitlines()
        if line.strip().upper().startswith("GRANT") and " TO PUBLIC" in line.upper()
    ]
    assert (
        not grants_to_public
    ), f"правы выданы роли PUBLIC ({grants_to_public}): права обязано получать конкретная роль"
    assert (
        "GRANT ALL" not in sql.upper()
    ), "`GRANT ALL` скрывает, какие именно права выданы: перечень должен быть явным"
    revoke_all_tables = re.search(r"REVOKE[^;]*ON\s+ALL\s+TABLES[^;]*;", sql, re.IGNORECASE)
    assert revoke_all_tables is None, (
        "отзыв по всем таблицам сразу делает исключение для журнала недостижимой: "
        "исключение задаётся оператором REVOKE по конкретной таблице"
    )


def test_право_create_на_схему_выдано_явно_и_только_роли_приложения() -> None:
    """Миграции идут ролью приложения: без `CREATE` на схему следующая ревизия падает.

    Основание — замер на площадке 2026-11-21: под ролью приложения `CREATE TABLE` даёт
    `42501 permission denied for schema public`. Право выдано по решению заказчика
    (ask `8d2be9bb`, вариант Б), поэтому проверяется и наличие, и то, что оно не превратилось
    в выдачу всей схемы оптом.
    """
    sql = _sql()
    assert re.search(
        r"GRANT\s+USAGE,\s*CREATE\s+ON\s+SCHEMA\s+public\s+TO\s+tbot_app", sql, re.IGNORECASE
    ), (
        "в deploy/postgres/roles.sql нет явной выдачи USAGE + CREATE на public роли приложения: "
        "alembic (его запускает та же роль) упадёт на CREATE TABLE, а право должно быть "
        "перечислено явно, а не через GRANT ALL"
    )
    assert not re.search(
        r"GRANT\s+ALL(\s+ON\s+SCHEMA)?\s+ON?\s*SCHEMA", sql, re.IGNORECASE
    ), "права на схему не должны выдаваться оптом: перечень обязан быть явным"


def test_таблицы_append_only_возвращаются_владельцу_схемы() -> None:
    """Владение таблицами реестра — у роли-владельца: у владельца `REVOKE` не работает.

    Право `CREATE` на схеме (предыдущая проверка) нужно миграциям, а созданную таблицу
    миграция и владеет. Если следующей таблицей журнала окажется таблица приложения, отзыв
    прав на неё ничего не отнимет — поэтому файл прав обязан вернуть владение каждой таблице
    реестра `APPEND_ONLY_TABLES`.
    """
    sql = _sql()
    missing = [
        table
        for table in sorted(APPEND_ONLY_TABLES)
        if not re.search(
            rf"ALTER\s+TABLE\s+{table}\s+OWNER\s+TO\s+CURRENT_USER", sql, re.IGNORECASE
        )
    ]
    assert not missing, (
        f"для таблиц {missing} нет возврата владения владельцу схемы: приложение создаст их "
        "самой и станет владельцем, а у владельца отзыв прав не действует (REQ-identity-04)"
    )
    guard = re.search(r"IF\s+current_user\s*=\s*'tbot_app'", sql, re.IGNORECASE)
    assert guard is not None, (
        "нет проверки текущей роли: если файл прав запустит роль приложения, `OWNER TO "
        "CURRENT_USER` передал бы владение журналу самому приложению"
    )
    assert (
        "RAISE EXCEPTION" in sql.upper()
    ), "нарушение роли запуска должно прерывать выполнение, а не выводиться предупреждением"


def test_журнал_получает_явную_выдачу_select_и_insert() -> None:
    """После возврата владения журнал обязан явно получить `SELECT` и `INSERT`.

    Без явной выдачи прав на журнал он мог бы остаться только у прежнего владельца: п. 3
    раздачи DML выдает права по таблицам текущего владельца, а журнал после возврата владения
    — ровно тот случай, когда выдача должна быть проговорена отдельно.
    """
    sql = _sql()
    assert re.search(
        r"GRANT\s+SELECT,\s*INSERT\s+ON\s+TABLE\s+audit_log\s+TO\s+tbot_app", sql, re.IGNORECASE
    ), "нет явной выдачи SELECT/INSERT на audit_log: приложение не сможет дописывать журнал"


def test_проверки_прав_не_исчезли_из_ci() -> None:
    jobs = yaml.safe_load(CI_FILE.read_text(encoding="utf-8"))["jobs"]
    steps = jobs["migrations"]["steps"]
    runs = [str(step.get("run", "")) for step in steps]
    for target in (
        "tests/integration/test_postgres_roles.py",
        "tests/integration/test_identity_schema_db.py",
    ):
        assert any(target in run for run in runs), (
            f"в job'е `migrations` не осталось шага, который исполняет {target}: "
            "проверка схемы или прав молча перестала запускаться"
        )
    assert any('-e ".[dev]"' in run for run in runs), (
        "в job'е `migrations` должен ставиться dev-экстра: pytest не является "
        "рантайм-зависимостью проекта, и шаг с тестами упадёт с «No module named pytest»"
    )
