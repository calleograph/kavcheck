"""Портал ответственных за зоны: доступ учётных записей и групп AD к зонам (zone_access).

Revision ID: 0031_zone_access
"""
from alembic import op
import sqlalchemy as sa

revision = "0031_zone_access"
down_revision = "0030_vdb_eta"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "zone_access",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("zone_id", sa.Uuid(), sa.ForeignKey("zones.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("value", sa.String(500), nullable=False),
        sa.Column("label", sa.String(300), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(300)),
    )
    op.create_index("ix_zone_access_zone_id", "zone_access", ["zone_id"])
    op.create_index("ux_zone_access", "zone_access", ["zone_id", "kind", "value"], unique=True)
    op.add_column("users", sa.Column("upn", sa.String(300), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "upn")
    op.drop_index("ux_zone_access", table_name="zone_access")
    op.drop_index("ix_zone_access_zone_id", table_name="zone_access")
    op.drop_table("zone_access")
