"""Журнал базы уязвимостей (кольцевой), ход расчёта, версия данных источника.

Revision ID: 0029_vdb_journal
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0029_vdb_journal"
down_revision = "0028_vdb_hits"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vdb_journal",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("level", sa.String(5), nullable=False, server_default="info"),
        sa.Column("kind", sa.String(16), nullable=False, server_default=""),
        sa.Column("source_id", sa.Uuid(), nullable=True),
        sa.Column("vdb_key", sa.String(16), nullable=False, server_default=""),
        sa.Column("message", sa.String(600), nullable=False, server_default=""),
        sa.Column("details", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=True),
        sa.Column("size", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_vdb_journal_at", "vdb_journal", ["at"])
    op.create_index("ix_vdb_journal_kind", "vdb_journal", ["kind", "id"])
    op.create_index("ix_vdb_journal_level", "vdb_journal", ["level", "id"])
    op.add_column("vdb_analysis", sa.Column("stage", sa.String(80), nullable=False, server_default=""))
    op.add_column("vdb_analysis", sa.Column("done", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("vdb_analysis", sa.Column("total", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("vdb_analysis", sa.Column("progress_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("vdb_sources", sa.Column("data_ver", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    op.drop_column("vdb_sources", "data_ver")
    for c in ("progress_at", "total", "done", "stage"):
        op.drop_column("vdb_analysis", c)
    op.drop_index("ix_vdb_journal_level", table_name="vdb_journal")
    op.drop_index("ix_vdb_journal_kind", table_name="vdb_journal")
    op.drop_index("ix_vdb_journal_at", table_name="vdb_journal")
    op.drop_table("vdb_journal")
