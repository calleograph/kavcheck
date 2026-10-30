"""Активность компьютера KSC в сопоставлении BI и KSC: дата последнего подключения и состояние (active | stale | none | future).

Revision ID: 0025_bi_activity
"""
from alembic import op
import sqlalchemy as sa

revision = "0025_bi_activity"
down_revision = "0024_job_progress"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("bi_matches", sa.Column("host_last_connected", sa.DateTime(timezone=True), nullable=True))
    op.add_column("bi_matches", sa.Column("activity", sa.String(8), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("bi_matches", "activity")
    op.drop_column("bi_matches", "host_last_connected")
