"""`storage` — слой схемы данных PostgreSQL 16 (CAPABILITY_MAP №2, TZ §4).

Ответственность модуля одна: описание схемы (ORM-отображения таблиц, ограничения, имена) и
миграции Alembic. Бизнес-правила живут в модулях, которые стоят над `storage` (`identity`,
`credentials`, …), поэтому здесь их нет и быть не должно — импорт разрешён только «вниз» по
Capability Map (контракт `tests/contract/test_repo_layout.py`).

Одно исключение оформлено явно — `packages/storage/audit_store.py`. Это не бизнес-правило, а
единственный SQL-путь к append-only таблице `audit_log` (добавление записи по протоколу цепочки и
чтение журнала колонок §4.1): TZ §8.7, `ADR-025` п. 6 и п. 9, срез `T-109` `R3.2`. Он общий для
двух процессов — `web` и `jobs`, которым контракт `test_repo_layout.py` запрещает импортировать
друг друга, — и стоит рядом с описанием той самой таблицы. Импорт «вверх» (`identity.audit`:
нормализация записи, канонический JSON, политики `details`) относится только к этому файлу и
означает, что правила цепочки по-прежнему живут в идентичности, а не здесь.
"""

from __future__ import annotations

from packages.storage.base import APPEND_ONLY_TABLES, NAMING_CONVENTION, Base

__all__ = ("APPEND_ONLY_TABLES", "NAMING_CONVENTION", "Base")
