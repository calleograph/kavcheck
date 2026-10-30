"""Раздел «Иерархия. Предприятие»: снимки выгрузки адресной книги.

Revision ID: 0026_hier
"""
from alembic import op
import sqlalchemy as sa

revision = "0026_hier"
down_revision = "0025_bi_activity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from sqlalchemy.dialects.postgresql import JSONB  # noqa: PLC0415

    dt = sa.DateTime(timezone=True)
    js = sa.JSON().with_variant(JSONB(), "postgresql")                    # как в модели: JSONB в PostgreSQL
    op.create_table(
        "hier_snapshots",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("started_at", dt, nullable=False), sa.Column("finished_at", dt),
        sa.Column("status", sa.String(10), nullable=False), sa.Column("trigger", sa.String(10), nullable=False), sa.Column("by", sa.String(160), nullable=False, server_default=""),
        sa.Column("source", sa.String(10), nullable=False, server_default=""), sa.Column("source_name", sa.String(300), nullable=False, server_default=""),
        sa.Column("raw_n", sa.Integer(), nullable=False, server_default="0"), sa.Column("errors_n", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("message", sa.String(1000), nullable=False, server_default=""),
        sa.Column("warnings", js, nullable=False), sa.Column("stats", js, nullable=False),
        sa.Column("content_hash", sa.String(40), nullable=False, server_default=""),
        sa.Column("records", js, nullable=True), sa.Column("same_as_id", sa.Uuid(), nullable=True),
    )
    op.create_index("ix_hier_snapshots_status", "hier_snapshots", ["status", "finished_at"])


def downgrade() -> None:
    op.drop_index("ix_hier_snapshots_status", table_name="hier_snapshots")
    op.drop_table("hier_snapshots")
