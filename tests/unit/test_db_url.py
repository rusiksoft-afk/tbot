"""Адрес базы данных: две формы, и обе обязаны быть правильными.

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

from packages.common.db import psycopg_dsn, sqlalchemy_url


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
