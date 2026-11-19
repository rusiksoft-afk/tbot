"""Базовая таблица служебных метаданных схемы.

Смысл ревизии: с неё начинается схема, и она же даёт месту под схемой минимальный
«самоописывающийся» объект — до появления бизнес-таблиц (T-009) по нему видно, что миграции
прошли и в каком контуре была установка.

Проверка обратимости: `upgrade head → downgrade base → upgrade head` (CI job `migrations`).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "app_meta",
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("key", name=op.f("pk_app_meta")),
        comment="Служебные метаданные установки: контур, версия схемы, отметки приёмки",
    )
    op.execute(
        "INSERT INTO app_meta (key, value) VALUES "
        "('schema_baseline', '0001'), ('time_basis', 'UTC')"
    )


def downgrade() -> None:
    op.drop_table("app_meta")
