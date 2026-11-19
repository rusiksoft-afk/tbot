"""${message}

Идентификатор ревизии: ${up_revision}
Заменяет: ${down_revision | comma,n}
Создана: ${create_date}

Признаки для ревью обратимости: у каждой ревизии обязан заполниться `downgrade`, а проверка
`upgrade head → downgrade base → upgrade head` выполняется в CI (docs/tz/13, приёмка T-009).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = ${repr(up_revision)}
down_revision: str | None = ${repr(down_revision)}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
