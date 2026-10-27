"""Главная: лицензии Kaspersky (записи, состояние чтения, общие пулы) и ежедневные срезы показателей.

Revision ID: 0016_overview_licenses
Revises: 0015_job_leases
Create Date: 2026-10-27
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0016_overview_licenses"
down_revision = "0015_job_leases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    dt = sa.DateTime(timezone=True)
    js = sa.JSON().with_variant(JSONB(), "postgresql")
    src = lambda: sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)  # noqa: E731
    op.create_table("lic_state", src(), sa.Column("polled_at", dt), sa.Column("error", sa.Text()), sa.Column("error_at", dt), sa.Column("requested_at", dt),
                    sa.Column("records_n", sa.Integer(), nullable=False, server_default="0"), sa.Column("diag", js))
    op.create_table("lic_records", src(), sa.Column("lic_key", sa.String(40), primary_key=True), sa.Column("origin", sa.String(6), nullable=False, server_default="ksc"),
                    sa.Column("product", sa.String(200), nullable=False, server_default=""), sa.Column("kind", sa.String(80), nullable=False, server_default=""),
                    sa.Column("expires_at", dt), sa.Column("limit_n", sa.Integer()), sa.Column("used_n", sa.Integer()), sa.Column("state", sa.String(10), nullable=False, server_default="unknown"),
                    sa.Column("fp", sa.String(40), nullable=False, server_default=""), sa.Column("note", sa.String(300), nullable=False, server_default=""), sa.Column("updated_at", dt, nullable=False))
    op.create_table("lic_overrides", src(), sa.Column("lic_key", sa.String(40), primary_key=True), sa.Column("pool", sa.String(120), nullable=False),
                    sa.Column("set_by", sa.String(300), nullable=False, server_default=""), sa.Column("set_at", dt, nullable=False))
    op.create_table("ov_daily", src(), sa.Column("day", sa.Date(), primary_key=True), sa.Column("data", js, nullable=False), sa.Column("taken_at", dt, nullable=False))


def downgrade() -> None:
    for t in ("ov_daily", "lic_overrides", "lic_records", "lic_state"):
        op.drop_table(t)
