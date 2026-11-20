"""Адрес базы данных: единое место перевода DSN между двумя формами.

Драйвер в проекте один — `psycopg` (версия 3). Две формы нужны в разных местах:

* SQLAlchemy 2 и Alembic требуют явного диалекта: `postgresql+psycopg://…` — в этой форме
  адрес хранится на площадке (`docs/tz/14-deployment-and-servers.md` §14.9, `AGENTS.md`) и в
  секретном файле `db_url`;
* сам psycopg3 свою же диалектную приставку не понимает: собственный парсер conninfo на
  `postgresql+psycopg://…` отвечает `ProgrammingError: missing "=" after …`, поэтому прямые
  подключения (health-check `/readyz` в web, `deploy-check`) обязаны пользоваться
  `psycopg_dsn` — замер 2026-11-20 на площадке и на dev-машине с psycopg 3.2.13.

Разбор сделан в одном месте, потому что расхождение проявляется не в Alembic (там всё работает),
а в готовности процесса: нездоровый `web` влечёт падение healthcheck'а, а `caddy` зависит от
здорового `web` — то есть весь периметр не поднимается.
"""

from __future__ import annotations

# Драйвер один; другие схемы отклоняются явно, а не «тихо» подменяются: случайный `mysql://`
# или `sqlite://` в конфиге площадки означает ошибку развёртывания, и молча строить из него
# engine нельзя.
_ALLOWED_SCHEMES: frozenset[str] = frozenset(
    {"postgresql", "postgresql+psycopg", "postgresql+psycopg2"}
)
_TARGET_SCHEME = "postgresql+psycopg"
# Форма, которую принимает собственный парсер conninfo psycopg3.
_DIRECT_SCHEME = "postgresql"
# Для прямых подключений `psycopg2` не является допустимой декларацией: драйвер один — psycopg3,
# и адрес, объявленный как `+psycopg2`, нельзя молча соединять с другим драйвером.
_DIRECT_SCHEMES: frozenset[str] = frozenset({"postgresql", "postgresql+psycopg"})


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


def psycopg_dsn(dsn: str) -> str:
    """Вернуть адрес в форме, которую принимает сам psycopg3 (`postgresql://…`).

    Сохраняются путь/сокет, параметры запроса и фрагменты: меняется только схема. Без этого
    `psycopg.connect` из секретного `db_url` падает ещё до соединения с сервером —
    `ProgrammingError: missing "=" after "postgresql+psycopg://…" in connection info string`
    (замер 2026-11-20: healthcheck `web` не проходил, `caddy` не запускался).
    """
    cleaned = dsn.strip()
    if "://" not in cleaned:
        msg = f"адрес базы не является URI: {cleaned!r}"
        raise ValueError(msg)
    scheme, rest = cleaned.split("://", 1)
    if scheme.lower() not in _DIRECT_SCHEMES:
        msg = (
            f"для прямого подключения psycopg3 неподдерживаемая схема адреса базы: {scheme!r} "
            f"(допустимо: {', '.join(sorted(_DIRECT_SCHEMES))}; драйвер в проекте один — psycopg3)"
        )
        raise ValueError(msg)
    return f"{_DIRECT_SCHEME}://{rest}"
