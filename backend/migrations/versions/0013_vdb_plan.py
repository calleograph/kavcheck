"""План устранения: находки по продуктам с категориями и решения администратора о категории продукта.

Revision ID: 0013_vdb_plan
Revises: 0012_eol_run_state
Create Date: 2026-10-27
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0013_vdb_plan"
down_revision = "0012_eol_run_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    js = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table(
        "vdb_finding_products",
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("vuln_key", sa.String(80), primary_key=True),
        sa.Column("product_key", sa.String(160), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False, server_default=""),
        sa.Column("category", sa.String(12), nullable=False, server_default="unclassified"),
        sa.Column("status", sa.String(14), nullable=False, server_default=""),
        sa.Column("sev_rank", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("exploited", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("installs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hosts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("versions", js, nullable=False, server_default="[]"),
    )
    op.create_index("ix_vdb_fp_product", "vdb_finding_products", ["source_id", "product_key"])
    op.create_index("ix_vdb_fp_category", "vdb_finding_products", ["source_id", "category"])
    op.create_table(
        "product_classes",
        sa.Column("catalog_key", sa.String(160), primary_key=True),
        sa.Column("category", sa.String(12), nullable=False),
        sa.Column("note", sa.String(300), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(300), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("product_classes")
    op.drop_index("ix_vdb_fp_category", table_name="vdb_finding_products")
    op.drop_index("ix_vdb_fp_product", table_name="vdb_finding_products")
    op.drop_table("vdb_finding_products")
