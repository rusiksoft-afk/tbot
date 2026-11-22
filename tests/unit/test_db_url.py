"""Адрес базы данных: три формы, и все три обязаны быть правильными.

Ошибочная схема для SQLAlchemy проявляется в Alembic (по умолчанию берётся `psycopg2`, которого в
образе нет — это нашли на job'е `migrations`). Ошибочная схема для **прямого** `psycopg.connect`
проявляется иначе и дороже: psycopg3 собственный парсер conninfo отвергает собственную же
диалектную приставку, поэтому `check_database` в web падал ещё до соединения с сервером
(замер 2026-11-20 на площадке: `/readyz` → 503 «postgres недоступен: ProgrammingError»,
healthcheck `web` → unhealthy, `caddy` не поднят, потому что зависит от здорового `web`).
Текст ошибки на psycopg 3.2.13 и на площадке, и на dev-машине:
`ProgrammingError: missing "=" after "postgresql+psycopg://…" in connection info string`.
"""

from __future__ import annotations

import psycopg
import pytest
from sqlalchemy.engine import make_url

from packages.common.db import migration_url, psycopg_dsn, sqlalchemy_url


@pytest.mark.parametrize(
    ("dsn", "expected"),
    [
        (
            "postgresql://tbot:p@localhost:5432/tbot",
            "postgresql+psycopg://tbot:p@localhost:5432/tbot",
        ),
        (
            "postgresql+psycopg://tbot:p@postgres:5432/tbot?sslmode=require",
            "postgresql+psycopg://tbot:p@postgres:5432/tbot?sslmode=require",
        ),
        (
            "postgresql+psycopg2://tbot:p@localhost:5432/tbot",
            "postgresql+psycopg://tbot:p@localhost:5432/tbot",
        ),
        # Unix-сокет и «голый» путь без хоста: меняется только схема.
        (
            "postgresql:///tbot?host=/var/run/postgresql",
            "postgresql+psycopg:///tbot?host=/var/run/postgresql",
        ),
    ],
)
def test_схема_приводится_к_драйверу_проекта(dsn: str, expected: str) -> None:
    assert sqlalchemy_url(dsn) == expected


def test_пробелы_отбрасываются() -> None:
    assert sqlalchemy_url("  postgresql://tbot:p@localhost:5432/tbot\n") == (
        "postgresql+psycopg://tbot:p@localhost:5432/tbot"
    )


@pytest.mark.parametrize(
    "dsn",
    [
        "mysql://tbot:p@localhost:3306/tbot",
        "sqlite:///tbot.db",
        "postgresql+asyncpg://tbot:p@localhost:5432/tbot",
        "не адрес вовсе",
        "",
    ],
)
def test_чужие_схемы_отклоняются(dsn: str) -> None:
    with pytest.raises(ValueError, match="неподдерживаемая схема|не является URI"):
        sqlalchemy_url(dsn)


@pytest.mark.parametrize(
    ("dsn", "expected"),
    [
        (
            "postgresql+psycopg://tbot:p@postgres:5432/tbot",
            "postgresql://tbot:p@postgres:5432/tbot",
        ),
        (
            "postgresql://tbot:p@localhost:5432/tbot",
            "postgresql://tbot:p@localhost:5432/tbot",
        ),
        (
            "postgresql+psycopg://tbot:p@/tbot?host=/var/run/postgresql",
            "postgresql://tbot:p@/tbot?host=/var/run/postgresql",
        ),
    ],
)
def test_форма_для_прямого_psycopg(dsn: str, expected: str) -> None:
    assert psycopg_dsn(dsn) == expected


def test_пробелы_отбрасываются_и_здесь() -> None:
    assert psycopg_dsn("  postgresql+psycopg://tbot:p@postgres:5432/tbot\n") == (
        "postgresql://tbot:p@postgres:5432/tbot"
    )


def test_обе_формы_не_противоречат_друг_другу() -> None:
    """Хранилище — форма SQLAlchemy, подключение напрямую — форма psycopg3.

    Если кто-то сведёт обе функции к одной форме, тест поймает: `sqlalchemy_url` обязан
    вернуть диалектную приставку, `psycopg_dsn` — убрать её.
    """
    хранимая = sqlalchemy_url("postgresql://tbot:p@postgres:5432/tbot")
    assert "+psycopg" in хранимая
    прямой = psycopg_dsn(хранимая)
    assert "+" not in прямой.split("://", 1)[0]
    assert sqlalchemy_url(прямой) == хранимая


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql+psycopg2://tbot:p@localhost:5432/tbot",
        "postgresql+asyncpg://tbot:p@localhost:5432/tbot",
        "sqlite:///tbot.db",
        "",
    ],
)
def test_для_прямого_подключения_чужие_схемы_отклоняются(dsn: str) -> None:
    with pytest.raises(ValueError, match="неподдерживаемая схема|не является URI"):
        psycopg_dsn(dsn)


def test_хранимая_форма_не_читается_самим_psycopg_а_исправленная_читается() -> None:
    """Регресс на площадку 2026-11-20: `psycopg.connect` на DSN из секретного файла падал.

    Проверка без сервера: разбирается только conninfo. Именно этот разбор и давал
    `ProgrammingError` у `check_database`, из-за чего весь периметр не поднимался.
    """
    хранимая = "postgresql+psycopg://tbot:s3cr3t@postgres:5432/tbot"
    with pytest.raises(psycopg.ProgrammingError):
        psycopg.conninfo.make_conninfo(хранимая)
    исправленная = psycopg_dsn(хранимая)
    # Разбор обязан пройти (на площадке та же проверка на уровне C-слоя падала прямо в
    # psycopg.connect — см. докстринг модуля и замер `HANDOFF §1.16`).
    assert psycopg.conninfo.make_conninfo(исправленная)


# ─── роль-мигратор (`ADR-018`) ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("dsn", "user", "expected"),
    [
        # Площадка: в `db_url` роль приложения, миграции идут ролью-владельцем схемы.
        (
            "postgresql+psycopg://tbot_app:s3cr3t@postgres:5432/tbot",
            "tbot",
            "postgresql+psycopg://tbot:s3cr3t@postgres:5432/tbot",
        ),
        # Dev-стенд и CI: роль в адресе уже владелец, подмена ничего не портит.
        (
            "postgresql+psycopg://tbot:ci-stand-db-password@postgres:5432/tbot",
            "tbot",
            "postgresql+psycopg://tbot:ci-stand-db-password@postgres:5432/tbot",
        ),
        # Форма из `sqlalchemy_url` принимается и без диалектной приставки.
        (
            "postgresql://tbot_app:p@localhost:5432/tbot?sslmode=require",
            "tbot",
            "postgresql+psycopg://tbot:p@localhost:5432/tbot?sslmode=require",
        ),
    ],
)
def test_роль_мигратора_подменяется_без_потери_остальных_частей(
    dsn: str, user: str, expected: str
) -> None:
    assert migration_url(dsn, user) == expected


def test_без_роли_адрес_остаётся_формой_sqlalchemy() -> None:
    """`TBOT_MIGRATION_DB_USER` не задан — поведение прежнее (`sqlalchemy_url`).

    Так ведут себя job `миграции` в CI и dev-команда `make migrate`: там роль в адресе уже
    владелец, и переменная не нужна.
    """
    assert migration_url("postgresql://tbot:p@localhost:5432/tbot", None) == (
        "postgresql+psycopg://tbot:p@localhost:5432/tbot"
    )


def test_пароль_не_маскируется_при_подмене_роли() -> None:
    """Регресс на собственный экран SQLAlchemy: `str(URL)` печатает `***` вместо пароля.

    Если бы разбор возвращал `str(url)`, миграции получили бы адрес без учётных данных и
    падали бы на аутентификации — причём только там, где подмена роли вообще применяется,
    то есть на площадке.
    """
    result = migration_url("postgresql+psycopg://tbot_app:s3cr3t-42@postgres:5432/tbot", "tbot")
    assert "s3cr3t-42" in result, f"пароль потерян при разборе: {result}"
    assert "***" not in result
    assert result.startswith("postgresql+psycopg://tbot:")


def test_спецсимволы_пароля_переживают_разбор() -> None:
    """Пароль из `secrets-setup.sh` может содержать не-алфавитные знаки.

    Разбор через `make_url` декодирует userinfo и перекодирует его обратно; проверка держит
    round-trip, иначе сгенерированный машиной пароль дал бы `password authentication failed`
    уже на площадке.
    """
    dsn = "postgresql+psycopg://tbot_app:p%40ss%2Fword%3Ax@postgres:5432/tbot"
    result = migration_url(dsn, "tbot")
    assert migration_url(result, "tbot") == result, "разбор не идемпотентен"
    assert make_url(result).password == "p@ss/word:x"
    assert make_url(result).username == "tbot"


def test_unix_сокет_и_параметры_сохраняются_при_подмене_роли() -> None:
    """Форма с unix-сокетом разбирается без потери пути и параметров.

    Замер поведения SQLAlchemy: `render_as_string` экранирует косые черты в значении параметра,
    поэтому адрес выглядит как `…?host=%2Fvar%2Frun%2Fpostgresql`. Это не потеря: Alembic и
    SQLAlchemy читают адрес через тот же разбор query-строки и получают исходный путь. Проверка
    и фиксирует смысл, а не побайтовое сходство: побайтовое здесь держал бы только наивный
    перенос строки, который ломается на паролях с `@` и `:`.
    """
    result = migration_url("postgresql:///tbot?host=/var/run/postgresql", "tbot")
    assert result.startswith("postgresql+psycopg://tbot@")
    assert make_url(result).query == {"host": "/var/run/postgresql"}
    assert make_url(result).database == "tbot"
    assert make_url(result).drivername == "postgresql+psycopg"


@pytest.mark.parametrize("dsn", ["mysql://t:p@localhost:3306/t", "не адрес вовсе", ""])
def test_чужие_схемы_отклоняются_и_в_форме_для_миграций(dsn: str) -> None:
    with pytest.raises(ValueError, match="неподдерживаемая схема|не является URI"):
        migration_url(dsn, "tbot")
