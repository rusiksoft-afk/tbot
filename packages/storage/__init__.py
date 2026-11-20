"""`storage` — слой схемы данных PostgreSQL 16 (CAPABILITY_MAP №2, TZ §4).

Ответственность модуля одна: описание схемы (ORM-отображения таблиц, ограничения, имена) и
миграции Alembic. Бизнес-правила живут в модулях, которые стоят над `storage` (`identity`,
`credentials`, …), поэтому здесь их нет и быть не должно — импорт разрешён только «вниз» по
Capability Map (контракт `tests/contract/test_repo_layout.py`).
"""

from __future__ import annotations

from packages.storage.base import NAMING_CONVENTION, Base

__all__ = ("NAMING_CONVENTION", "Base")
