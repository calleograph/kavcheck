"""CVE Hunt: результаты целевого поиска уязвимостей и ПО (совпадения по компьютерам и критериям).

Revision ID: 0020_hunt
Revises: 0019_diagnostics
Create Date: 2026-10-28
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0020_hunt"
down_revision = "0019_diagnostics"
branch_labels = None
depends_on = None


def upgrade() -> None:
    js = sa.JSON().with_variant(JSONB(), "postgresql")
    dt = sa.DateTime(timezone=True)
    big = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
    op.create_table(
        "hunt_hits", sa.Column("id", big, primary_key=True, autoincrement=True), sa.Column("job_id", sa.Uuid(), sa.ForeignKey("pt_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("crit_key", sa.String(80), nullable=False), sa.Column("vuln_key", sa.String(80), nullable=False, server_default=""), sa.Column("ip", sa.String(45), nullable=False, server_default=""),
        sa.Column("port", sa.Integer(), nullable=True), sa.Column("source_id", sa.Uuid(), nullable=True), sa.Column("host_id", sa.BigInteger(), nullable=True),
        sa.Column("host_name", sa.String(300), nullable=False, server_default=""), sa.Column("os", sa.String(200), nullable=False, server_default=""),
        sa.Column("user_name", sa.String(256), nullable=False, server_default=""), sa.Column("user_kind", sa.String(16), nullable=False, server_default=""),
        sa.Column("zone", sa.String(120), nullable=False, server_default=""), sa.Column("group_name", sa.String(300), nullable=False, server_default=""),
        sa.Column("product", sa.String(200), nullable=False, server_default=""), sa.Column("version", sa.String(120), nullable=False, server_default=""),
        sa.Column("status", sa.String(14), nullable=False), sa.Column("basis", sa.String(8), nullable=False, server_default="network"), sa.Column("evidence", js, nullable=False),
        sa.Column("data_at", dt, nullable=True), sa.Column("last_connected", dt, nullable=True), sa.Column("ambiguous", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("diff", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index("ix_hunt_hits_job", "hunt_hits", ["job_id", "status"])
    op.create_index("ix_hunt_hits_ip", "hunt_hits", ["job_id", "ip"])


def downgrade() -> None:
    op.drop_table("hunt_hits")
