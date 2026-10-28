"""Pentest: диагностика заданий (структура событий, состояния этапов, сводка причин) и кэш проверки версий компонентов.

Revision ID: 0019_diagnostics
Revises: 0018_pentest_engines
Create Date: 2026-10-28
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0019_diagnostics"
down_revision = "0018_pentest_engines"
branch_labels = None
depends_on = None


def upgrade() -> None:
    js = sa.JSON().with_variant(JSONB(), "postgresql")
    dt = sa.DateTime(timezone=True)
    op.add_column("pt_jobs", sa.Column("stages", js, nullable=False, server_default="{}"))
    op.add_column("pt_jobs", sa.Column("diag", js, nullable=False, server_default="{}"))
    for name, col in (("engine", sa.String(10)), ("kind", sa.String(10)), ("check_id", sa.String(160)), ("retry", sa.String(8)), ("detail", sa.Text())):
        op.add_column("pt_events", sa.Column(name, col, nullable=False, server_default=""))
    for name in ("port", "rc", "ms", "attempt"):
        op.add_column("pt_events", sa.Column(name, sa.Integer(), nullable=True))
    op.add_column("pt_events", sa.Column("incomplete", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        "comp_checks", sa.Column("key", sa.String(60), primary_key=True), sa.Column("latest", sa.String(80), nullable=False, server_default=""), sa.Column("url", sa.String(300), nullable=False, server_default=""),
        sa.Column("published_at", dt, nullable=True), sa.Column("checked_at", dt, nullable=True), sa.Column("error", sa.String(300), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_table("comp_checks")
    for name in ("incomplete", "attempt", "ms", "rc", "port", "detail", "retry", "check_id", "kind", "engine"):
        op.drop_column("pt_events", name)
    op.drop_column("pt_jobs", "diag")
    op.drop_column("pt_jobs", "stages")
