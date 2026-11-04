"""Личная панель «Быстрый доступ»: столбец users.quick_prefs.

Revision ID: 0027_quick_prefs
"""
from alembic import op
import sqlalchemy as sa

revision = "0027_quick_prefs"
down_revision = "0026_hier"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from sqlalchemy.dialects.postgresql import JSONB  # noqa: PLC0415

    op.add_column("users", sa.Column("quick_prefs", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "quick_prefs")
