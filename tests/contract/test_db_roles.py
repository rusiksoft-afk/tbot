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
* право `USAGE` на схему выдано явно, а `CREATE` у рантайм-роли отозван: DDL делает
  роль-мигратор (`ADR-018`), и каждая таблица реестра append-only возвращается роли-владельцу —
  иначе следующая таблица журнала оказалась бы защищённой только комментарием;
* файл отказывается работать, если его запускает роль приложения (`OWNER TO CURRENT_USER`
  иначе передал бы владение журналу самому приложению);
* проверки прав не исчезли из CI (шаги job'а `migrations`);
* модель ролей и общий пароль роли приложения закреплены решением заказчика в ADR-006, а роль
  миграций — решением от 2026-11-22 в ADR-018; в стоп-листе `AGENTS.md` есть напоминание, что
  менять их молча нельзя: иначе следующий контекст «чинит» компромисс, не зная, что он выбран
  сознательно.
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
ADR_006: Final = ROOT / "docs" / "adr" / "ADR-006-db-app-role-shared-password.md"
ADR_018: Final = ROOT / "docs" / "adr" / "ADR-018-migration-role-schema-owner.md"
AGENTS: Final = ROOT / "AGENTS.md"

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


def test_рантайм_роль_пользуется_схемой_но_не_создаёт_в_ней_объектов() -> None:
    """`USAGE` есть, `CREATE` отозван: DDL относится к роли-мигратору (`ADR-018`).

    Право `CREATE` на `public` выдавалось по варианту Б `ADR-006` (ask `8d2be9bb`), когда
    миграции шли ролью приложения. Срез деплоя 2026-11-22 меряет цену этого решения: `ALTER
    TABLE sessions ADD CONSTRAINT ck_sessions_token_hash_format` под ролью приложения даёт
    `42501 must be owner of table sessions`, и заказчик вернул миграции роли-владельцем
    (ask `c7a6830e-9722-491d-9dbf-c8b291d3e84d`). Значит проверка держит оба факта: выдача
    `USAGE` (без неё невозможен DML) и явный отзыв `CREATE` (на площадке право уже выдано,
    и без отзыва повторный запуск файла прав не вернул бы модель к норме).
    """
    sql = _sql()
    assert re.search(r"GRANT\s+USAGE\s+ON\s+SCHEMA\s+public\s+TO\s+tbot_app", sql, re.IGNORECASE), (
        "в deploy/postgres/roles.sql нет явной выдачи USAGE на public роли приложения: "
        "без права USAGE недоступен любой DML по схемам"
    )
    assert re.search(
        r"REVOKE\s+CREATE\s+ON\s+SCHEMA\s+public\s+FROM\s+tbot_app", sql, re.IGNORECASE
    ), (
        "нет явного отзыва CREATE у роли приложения: право выдавалось по ADR-006 и на площадке "
        "оно уже есть, поэтому без отзыва идемпотентный запуск файла прав оставил бы "
        "рантайм-роль с DDL в схеме"
    )
    assert not re.search(
        r"GRANT\s+[^;]*CREATE[^;]*ON\s+SCHEMA\s+public\s+TO\s+tbot_app", sql, re.IGNORECASE
    ), "право CREATE на схему не должно возвращаться роли приложения: DDL делает роль-мигратор"
    assert not re.search(
        r"GRANT\s+ALL(\s+ON\s+SCHEMA)?\s+ON?\s*SCHEMA", sql, re.IGNORECASE
    ), "права на схему не должны выдаваться оптом: перечень обязан быть явным"


def test_роль_мигратора_выделена_только_процессу_миграций() -> None:
    """`TBOT_MIGRATION_DB_USER` обязана быть у `migrate` и не должна быть у рантайм-процессов.

    Смысл разделения ролей (`ADR-018`) в том, что ограниченный процесс не выбирает себе роль
    сам: если переменная появится у `web`, `engine`, `jobs` или `tgbot`, процесс, знающий из
    своего DSN общий пароль (`ADR-006`), получит роль-владельца прямо из окружения.
    """
    compose = yaml.safe_load((ROOT / "deploy" / "compose.yaml").read_text(encoding="utf-8"))
    assert isinstance(compose, dict), "deploy/compose.yaml обязан разбираться как YAML"
    services = compose["services"]
    migrate_env = services["migrate"].get("environment") or {}
    assert migrate_env.get("TBOT_MIGRATION_DB_USER") == "tbot", (
        "у сервиса migrate нет TBOT_MIGRATION_DB_USER=tbot: alembic пойдёт ролью из db_url, "
        "и ревизия, правящая таблицу роли-владельца, откажет по правам (замер площадки 2026-11-22)"
    )
    for service in ("web", "engine", "jobs", "tgbot", "postgres"):
        env = services[service].get("environment")
        # форма «КЛЮЧ=значение» (список) тоже должна проверяться
        keys = {item.split("=", 1)[0] for item in env} if isinstance(env, list) else set(env or {})
        assert "TBOT_MIGRATION_DB_USER" not in keys, (
            f"роль-мигратор объявлена процессу {service}: рантайм-процесс получает DDL-права "
            "роли-владельца схемы"
        )


# Файлы, которым разрешено знать про роль-мигратора: описание поля, разбор адреса и Alembic.
# Рантайм-процессы (`apps/`, `packages/storage`, остальные `packages/*`) знать о ней не должны.
_MIGRATION_ROLE_FILES: Final[frozenset[str]] = frozenset(
    {"packages/common/config.py", "packages/common/db.py"}
)


def test_роль_мигратора_читает_только_alembic() -> None:
    """Про роль-мигратора знают только конфигурация, разбор адреса и `migrations/env.py`.

    Проверка парная к предыдущей: compose не выдаёт переменную лишним сервисам, но и код не
    должен читать её сам. Иначе ограниченный процесс получает роль-владельца без всякого compose:
    пароль общий (`ADR-006`), поэтому достаточно одного `os.environ` в неизвестном месте.

    Последняя проверка держит деталь, на которой миграции падали бы молча: `str(URL)` в
    SQLAlchemy печатает пароль как `***`, поэтому разбор обязан идти через
    `render_as_string(hide_password=False)`.
    """
    needles = ("migration_db_user", "migration_url", "TBOT_MIGRATION_DB_USER")
    offenders: list[str] = []
    for path in [*(ROOT / "apps").rglob("*.py"), *(ROOT / "packages").rglob("*.py")]:
        rel = path.relative_to(ROOT).as_posix()
        if rel in _MIGRATION_ROLE_FILES:
            continue
        body = path.read_text(encoding="utf-8")
        if any(needle in body for needle in needles):
            offenders.append(rel)
    assert not offenders, (
        f"о роли-миграторе знают вне конфигурации и Alembic: {sorted(offenders)} — "
        "рантайм-процесс не должен выбирать себе роль-владельца схемы"
    )

    env_src = (ROOT / "migrations" / "env.py").read_text(encoding="utf-8")
    assert "migration_url(" in env_src, (
        "migrations/env.py обязан строить адрес через migration_url: это единственное место, "
        "где роль-мигратор применяется к адресу Alembic"
    )
    assert "settings.migration_db_user" in env_src, (
        "migrations/env.py обязан читать TBOT_MIGRATION_DB_USER (settings.migration_db_user): "
        "без этого ревизии идут ролью из db_url и падают на ALTER чужой таблицы"
    )
    db_src = (ROOT / "packages" / "common" / "db.py").read_text(encoding="utf-8")
    assert "render_as_string(hide_password=False)" in db_src, (
        "migration_url обязан рендерить адрес с паролем: str(URL) в SQLAlchemy маскирует "
        "пароль как `***`, и миграции получили бы адрес без учётных данных"
    )


def test_модель_миграций_закреплена_в_adr_018() -> None:
    """Смена роли миграций — решение заказчика, и оно обязано быть описано.

    ADR-006 оставлен и не переписывается: он объясняет общий пароль. Новый ADR обязан назвать
    замер, после которого модель поменялась, и второго DSN-секрета (`db_url_owner`) не вводить.
    """
    assert ADR_018.is_file(), f"нет ADR о роли миграций: {ADR_018}"
    body = ADR_018.read_text(encoding="utf-8")
    for marker in (
        "`c7a6830e-9722-491d-9dbf-c8b291d3e84d`",
        "must be owner of table sessions",
        "`TBOT_MIGRATION_DB_USER`",
        "`db_url_owner`",
        "`ADR-006`",
        "`REVOKE CREATE ON SCHEMA public FROM tbot_app`",
    ):
        assert marker in body, f"ADR-018 потерял обязательную часть решения: {marker!r}"


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


def test_модель_ролей_и_общий_пароль_закреплены_в_adr_006() -> None:
    """ADR-006 обязан остаться и описывать суть компромисса, а не только факт переключения.

    Общий пароль `tbot_app` и `tbot` выглядит как дефект, но это выбор заказчика (ask `8d2be9bb`):
    жёсткая граница требовала бы второго DSN-секрета и отдельного пароля. Пока этот выбор действует,
    его нельзя отменять молча — поэтому текст решения и перечень альтернатив под контрактной
    защитой: при удалении или выхолащивании ADR проверка падает красным, а не тихой правкой docs.
    """

    assert ADR_006.is_file(), f"нет ADR о модели ролей: {ADR_006}"
    body = ADR_006.read_text(encoding="utf-8")
    for marker in (
        "общий пароль",
        "`db_url_owner`",
        "`APPEND_ONLY_TABLES`",
        "OWNER TO CURRENT_USER",
        "`8d2be9bb`",
        "AC-identity-04",
    ):
        assert marker in body, f"ADR-006 потерял обязательную часть решения: {marker!r}"
    link_reason = (
        "ADR-006 обязан ссылаться на ADR-004 (кто вносит значения секретов) и ADR-005 (права "
        "файлов секретов): иначе новые пароли и новые секреты площадки поедут в обход уже "
        "принятых режимов"
    )
    assert "ADR-004" in body, link_reason
    assert "ADR-005" in body, link_reason


def test_стоп_лист_напоминает_что_модель_ролей_менять_молча_нельзя() -> None:
    """`AGENTS.md` — первое, что читает сессия: запрет «починить» общий пароль обязан быть там."""

    body = AGENTS.read_text(encoding="utf-8")
    assert "ADR-006" in body, (
        "из стоп-листа пропала ссылка на ADR-006: сессия увидит общий пароль роли приложения как "
        "дефект и поправит его без решения заказчика"
    )
    assert "ADR-018" in body, (
        "из стоп-листа пропала ссылка на ADR-018: сессия увидит, что `migrate` ходит ролью-"
        "владельцем, и «починит» её на роль приложения — следующая ревизия упадёт на ALTER чужой "
        "таблицы"
    )
    assert "`TBOT_MIGRATION_DB_USER`" in body, (
        "в стоп-листе обязано быть имя переменной, которой migrate выбирает роль: без неё "
        "разделение ролей выглядит случайностью, а не решением"
    )
    assert "`db_url_owner`" in body, (
        "в стоп-листе обязан быть назван отклонённый вариант (второй DSN-секрет) — иначе он "
        "выглядит очевидным исправлением"
    )
    assert "APPEND_ONLY_TABLES" in body, (
        "в стоп-листе обязан быть обязательный шаг для новой таблицы журнала (реестр + владение + "
        "REVOKE + повторный запуск файла прав): без него append-only тихо теряется на первой же "
        "ревизии M1"
    )
