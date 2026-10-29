"""Тип совпадения имени в сопоставлении BI и KSC (точное, точное с конкурентами, короткое имя ↔ FQDN) — для массового подтверждения точных совпадений.

Revision ID: 0023_bi_name_match
"""
from alembic import op
import sqlalchemy as sa

revision = "0023_bi_name_match"
down_revision = "0022_theme"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("bi_matches", sa.Column("name_match", sa.String(10), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("bi_matches", "name_match")
