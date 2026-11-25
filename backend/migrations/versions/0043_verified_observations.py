"""Подтверждённые наблюдения доменной учётной записи."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0043_verified_observations"
down_revision = "0042_workplace_review"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("dev_users", sa.Column("verified_observations", sa.JSON().with_variant(JSONB(), "postgresql")))


def downgrade() -> None:
    with op.batch_alter_table("dev_users") as batch:
        batch.drop_column("verified_observations")
