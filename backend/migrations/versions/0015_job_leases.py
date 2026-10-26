"""Аренды и история фоновых заданий (восстановление после сбоя без ожидания и ручной правки базы); версия приложения в состоянии EOL.

Revision ID: 0015_job_leases
Revises: 0014_eol_diag
Create Date: 2026-10-27
"""
from alembic import op
import sqlalchemy as sa

revision = "0015_job_leases"
down_revision = "0014_eol_diag"
branch_labels = None
depends_on = None


def upgrade() -> None:
    dt = sa.DateTime(timezone=True)
    op.create_table(
        "job_leases",
        sa.Column("kind", sa.String(32), primary_key=True), sa.Column("scope", sa.String(80), primary_key=True, server_default=""),
        sa.Column("run_id", sa.Uuid(), nullable=False), sa.Column("owner", sa.String(160), nullable=False),
        sa.Column("started_at", dt, nullable=False), sa.Column("heartbeat_at", dt, nullable=False), sa.Column("lease_until", dt, nullable=False),
        sa.Column("stage", sa.String(160), nullable=False, server_default=""), sa.Column("progress", sa.String(300)), sa.Column("app_version", sa.String(40), nullable=False, server_default=""),
    )
    op.create_index("ix_job_leases_lease_until", "job_leases", ["lease_until"])
    op.create_table(
        "job_runs",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=True),
        sa.Column("kind", sa.String(32), nullable=False), sa.Column("scope", sa.String(80), nullable=False, server_default=""), sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("owner", sa.String(160), nullable=False, server_default=""), sa.Column("app_version", sa.String(40), nullable=False, server_default=""),
        sa.Column("started_at", dt, nullable=False), sa.Column("finished_at", dt), sa.Column("status", sa.String(14), nullable=False),
        sa.Column("stage", sa.String(160), nullable=False, server_default=""), sa.Column("error", sa.Text()), sa.Column("duration_ms", sa.Integer()),
    )
    op.create_index("ix_job_runs_scope", "job_runs", ["kind", "scope", "finished_at"])
    op.add_column("eol_state", sa.Column("app_version", sa.String(40), nullable=True))


def downgrade() -> None:
    op.drop_column("eol_state", "app_version")
    op.drop_index("ix_job_runs_scope", table_name="job_runs")
    op.drop_table("job_runs")
    op.drop_index("ix_job_leases_lease_until", table_name="job_leases")
    op.drop_table("job_leases")
