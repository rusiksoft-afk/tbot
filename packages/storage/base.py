"""Основа слоя `storage`: метаданные схемы и одно имя для каждого ограничения.

Конвенция имён одна и та же в трёх местах — в ORM-отображениях (`packages/storage/models.py`),
в ревизиях Alembic и в `migrations/env.py`, который читает её отсюда. Имена задаются явно, а не
«как получится у драйвера», потому что:

* обратная миграция обязана найти ограничение по предсказуемому имени (`drop_constraint`),
  иначе `downgrade base` падает на первой же ревизии;
* `alembic revision --autogenerate` сравнивает схему базы с моделями: расхождение в имени
  выглядит как «удалить одно ограничение, создать другое»;
* проверка прав и инспекция схемы на площадке (`psql \\d+`) читаются по смыслу, а не по хэшу.

Шаблоны совпадают с теми, что были в `migrations/env.py` до появления моделей: числа и состав
не менялись, изменился только владелец определения.
"""

from __future__ import annotations

from typing import Final

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Префиксы pk_/fk_/ck_/uq_/ix_ закреплены как часть контракта схемы (TZ §4 «общие правила»).
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Базовый класс ORM-отображений таблиц слоя `storage`.

    Отдельный `metadata` с конвенцией нужен, чтобы `alembic revision --autogenerate` и
    `alembic check` видели ровно те имена ограничений, что записаны в моделях и ревизиях.
    """

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# Таблицы, которым запрещены правки и удаление строк (TZ §4.1, `REQ-identity-04`). Единственный
# источник списка: `deploy/postgres/roles.sql` обязан отозвать `UPDATE`/`DELETE`/`TRUNCATE` на
# каждой из них, а `tests/contract/test_db_roles.py` сверяет список с SQL-файлом — иначе новая
# таблица журнала окажется защищённой только в комментариях.
APPEND_ONLY_TABLES: Final[frozenset[str]] = frozenset({"audit_log"})
