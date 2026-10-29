"""Ход выполнения заданий отдельно от продления аренды: job_leases.progress_at, queued_at; job_runs.waited_ms (раздел «Техническое состояние»)."""
import sqlalchemy as sa
from alembic import op

revision = "0024_job_progress"
down_revision = "0023_bi_name_match"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("job_leases", sa.Column("progress_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("job_leases", sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("job_runs", sa.Column("waited_ms", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("job_runs", "waited_ms")
    op.drop_column("job_leases", "queued_at")
    op.drop_column("job_leases", "progress_at")
