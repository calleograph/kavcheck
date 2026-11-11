"""Подготовленные результаты сопоставления с базами уязвимостей: vdb_version_hits, vdb_analysis.

Revision ID: 0028_vdb_hits
"""
from alembic import op
import sqlalchemy as sa

revision = "0028_vdb_hits"
down_revision = "0027_quick_prefs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vdb_version_hits",
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("product_key", sa.String(160), primary_key=True),
        sa.Column("version", sa.String(200), primary_key=True),
        sa.Column("vuln_key", sa.String(80), primary_key=True),
        sa.Column("status", sa.String(14), nullable=False, server_default=""),
        sa.Column("basis", sa.String(400), nullable=False, server_default=""),
    )
    op.create_index("ix_vdb_hits_vuln", "vdb_version_hits", ["source_id", "vuln_key"])
    op.create_table(
        "vdb_analysis",
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("rev", sa.String(40), nullable=False, server_default=""),
        sa.Column("built_at", sa.DateTime(timezone=True)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(10), nullable=False, server_default="none"),
        sa.Column("error", sa.String(400), nullable=False, server_default=""),
        sa.Column("hits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("vdb_analysis")
    op.drop_index("ix_vdb_hits_vuln", table_name="vdb_version_hits")
    op.drop_table("vdb_version_hits")
