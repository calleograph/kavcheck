"""Оценки и ручные решения о рабочих местах."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0042_workplace_review"
down_revision = "0041_employee_protection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    data = sa.JSON().with_variant(JSONB(), "postgresql")
    op.add_column("employee_protection_links", sa.Column("assessment", data, nullable=False, server_default="{}"))
    op.create_table("employee_workplace_decisions",
                    sa.Column("person_id", sa.String(120), primary_key=True),
                    sa.Column("device_id", sa.String(120), primary_key=True),
                    sa.Column("decision", sa.String(10), nullable=False),
                    sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False))


def downgrade() -> None:
    op.drop_table("employee_workplace_decisions")
    with op.batch_alter_table("employee_protection_links") as batch:
        batch.drop_column("assessment")
