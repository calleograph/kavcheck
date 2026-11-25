"""Учётный тип собственности оборудования."""
from alembic import op
import sqlalchemy as sa

revision = "0044_inventory_ownership"
down_revision = "0043_verified_observations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("inv_assets", sa.Column("ownership", sa.String(10)))


def downgrade() -> None:
    with op.batch_alter_table("inv_assets") as batch:
        batch.drop_column("ownership")
