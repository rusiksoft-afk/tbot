"""Адрес базы для SQLAlchemy: диалект обязан быть указан явно (psycopg3).

Ошибочная схема проявляется не в вебе (там `psycopg` используется напрямую), а в Alembic:
SQLAlchemy по умолчанию берёт драйвер `psycopg2`, которого в образе нет. Проверяется здесь,
потому что в CI это обнаружилось только на job'е `migrations`, где базы уже были подняты.
"""

from __future__ import annotations

import pytest

from packages.common.db import sqlalchemy_url


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
