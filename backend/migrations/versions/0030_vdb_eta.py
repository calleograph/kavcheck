"""Оценка оставшегося времени расчёта по недавней скорости: vdb_analysis.eta_s.

Revision ID: 0030_vdb_eta
"""
from alembic import op
import sqlalchemy as sa

revision = "0030_vdb_eta"
down_revision = "0029_vdb_journal"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("vdb_analysis", sa.Column("eta_s", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("vdb_analysis", "eta_s")
