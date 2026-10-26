"""EOL: время запуска расчёта источника (состояние «Выполняется» и восстановление после падения worker).

Revision ID: 0012_eol_run_state
Revises: 0011_hardware
Create Date: 2026-10-27
"""
from alembic import op
import sqlalchemy as sa

revision = "0012_eol_run_state"
down_revision = "0011_hardware"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("eol_state", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("eol_state", "started_at")
