"""Сетевые наблюдения и правила инвентаризации, учётная зона и теги."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0040_inventory_geo"
down_revision = "0039_adaudit_ou"
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(JSONB(), "postgresql")
BigIntPK = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    with op.batch_alter_table("inv_assets") as b:
        b.add_column(sa.Column("zone_id", sa.Uuid()))
        b.create_foreign_key("fk_inv_assets_zone", "zones", ["zone_id"], ["id"], ondelete="SET NULL")
        b.create_index("ix_inv_assets_zone_id", ["zone_id"])
        b.add_column(sa.Column("tags", JSONType, nullable=False, server_default="[]"))
    op.create_table(
        "inv_geo",
        sa.Column("id", BigIntPK, sa.ForeignKey("inv_assets.id", ondelete="CASCADE"), primary_key=True, autoincrement=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.BigInteger(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True)),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence", JSONType, nullable=False),
        sa.Column("result", JSONType, nullable=False),
    )
    op.create_index("ix_inv_geo_source_id", "inv_geo", ["source_id"])
    op.create_table("inv_geo_rules", sa.Column("id", BigIntPK, primary_key=True, autoincrement=True), sa.Column("data", JSONType, nullable=False))


def downgrade() -> None:
    op.drop_table("inv_geo_rules")
    op.drop_table("inv_geo")
    with op.batch_alter_table("inv_assets") as b:
        b.drop_index("ix_inv_assets_zone_id")
        b.drop_constraint("fk_inv_assets_zone", type_="foreignkey")
        b.drop_column("zone_id")
        b.drop_column("tags")
