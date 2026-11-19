"""Адрес базы данных для SQLAlchemy: единое место перевода DSN в нужный диалект.

Драйвер в проекте один — `psycopg` (версия 3). В конфигурации адрес хранится в обычной форме
`postgresql://…`, а SQLAlchemy 2 требует явного указания диалекта: `postgresql+psycopg://…`.
Разбор сделан в одном месте, потому что расхождение проявляется не в вебе (там psycopg
используется напрямую), а в Alembic и будущих SQL-слойных тестах — то есть в CI.
"""

from __future__ import annotations

# Драйвер один; другие схемы отклоняются явно, а не «тихо» подменяются: случайный `mysql://`
# или `sqlite://` в конфиге площадки означает ошибку развёртывания, и молча строить из него
# engine нельзя.
_ALLOWED_SCHEMES: frozenset[str] = frozenset(
    {"postgresql", "postgresql+psycopg", "postgresql+psycopg2"}
)
_TARGET_SCHEME = "postgresql+psycopg"


def sqlalchemy_url(dsn: str) -> str:
    """Вернуть адрес, пригодный для `sqlalchemy.create_engine` (диалект psycopg3).

    Сохраняются путь/сокет, параметры запроса и фрагменты: меняется только схема.
    """
    cleaned = dsn.strip()
    if "://" not in cleaned:
        msg = f"адрес базы не является URI: {cleaned!r}"
        raise ValueError(msg)
    scheme, rest = cleaned.split("://", 1)
    if scheme.lower() not in _ALLOWED_SCHEMES:
        msg = (
            f"неподдерживаемая схема адреса базы: {scheme!r} "
            f"(допустимо: {', '.join(sorted(_ALLOWED_SCHEMES))})"
        )
        raise ValueError(msg)
    return f"{_TARGET_SCHEME}://{rest}"
