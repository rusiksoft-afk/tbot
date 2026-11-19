"""Окружение Alembic (TZ §4 `make migrate` / `make revision`).

Строка подключения берётся из конфигурации приложения: `TBOT_DB_URL` или файл секрета `db_url`
в `secrets_dir`. Без явно указанной базы миграции отказываются выполняться — «угадать» адрес
нельзя, потому что одна и та же команда запускается и на dev-машине, и на площадке.

`target_metadata` сейчас пустой: ORM-модели слоя хранения подключаются в задаче T-009. Пока их
нет, автосгенерированная ревизия намеренно запрещена — иначе она предложила бы удалить всё, чего
«не видно» в метаданных.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import MetaData, engine_from_config, pool
from sqlalchemy.engine import Connection

from packages.common.config import ConfigError, load_settings

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Каталог колонок и индексов, общий для всех миграций: имена ограничений задаются по шаблону,
# чтобы их можно было предсказуемо находить и удалять в обратных миграциях.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

target_metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _database_url() -> str:
    try:
        settings = load_settings()
    except ConfigError as exc:
        raise RuntimeError(f"миграции не запускаются: конфигурация отклонена ({exc})") from exc
    if settings.db_url is None:
        raise RuntimeError(
            "миграции не запускаются: не задана база данных "
            "(TBOT_DB_URL или файл db_url в secrets_dir)"
        )
    return settings.db_url.get_secret_value()


def run_migrations_offline() -> None:
    """Режим «сгенерировать SQL, не подключаясь к базе»."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        url=_database_url(),
    )
    with connectable.connect() as connection:
        do_run_migrations(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
