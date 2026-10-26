"""EOL: время последней попытки расчёта, техническая причина ошибки и сведения о расчёте (диагностика).

Revision ID: 0014_eol_diag
Revises: 0013_vdb_plan
Create Date: 2026-10-27
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0014_eol_diag"
down_revision = "0013_vdb_plan"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("eol_state", sa.Column("attempt_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("eol_state", sa.Column("error_detail", sa.Text(), nullable=True))
    op.add_column("eol_state", sa.Column("diag", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=True))


def downgrade() -> None:
    op.drop_column("eol_state", "diag")
    op.drop_column("eol_state", "error_detail")
    op.drop_column("eol_state", "attempt_at")
