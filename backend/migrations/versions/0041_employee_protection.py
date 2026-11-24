"""Подготовленная аналитика защиты сотрудников."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0041_employee_protection"
down_revision = "0040_inventory_geo"
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("dev_users", sa.Column("identity_verified", sa.Boolean(), server_default=sa.false(), nullable=False))
    for name in ("people", "devices"):
        columns = [sa.Column("search", sa.Text(), nullable=False), sa.Column("data", JSONType, nullable=False)]
        if name == "devices":
            columns.append(sa.Column("zone_keys", sa.Text(), nullable=False))
        op.create_table(f"employee_protection_{name}",
                        sa.Column("generation", sa.Uuid(), primary_key=True),
                        sa.Column("id", sa.String(120), primary_key=True), *columns)
    op.create_table("employee_protection_links",
                    sa.Column("generation", sa.Uuid(), primary_key=True),
                    sa.Column("person_id", sa.String(120), primary_key=True),
                    sa.Column("device_id", sa.String(120), primary_key=True),
                    sa.Column("evidence", JSONType, nullable=False))
    op.create_index("ix_employee_protection_link_device", "employee_protection_links", ["generation", "device_id"])


def downgrade() -> None:
    for name in ("links", "devices", "people"):
        op.drop_table(f"employee_protection_{name}")
    with op.batch_alter_table("dev_users") as batch:
        batch.drop_column("identity_verified")
