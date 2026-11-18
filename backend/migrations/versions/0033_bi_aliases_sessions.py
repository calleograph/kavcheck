"""Псевдонимы имени устройства BI (bi_devices.aliases) и наблюдаемые сеансы пользователей (dev_sessions).

Revision ID: 0033_bi_aliases_sessions
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0033_bi_aliases_sessions"
down_revision = "0032_access_rule_users_roles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    json_t = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.add_column("bi_devices", sa.Column("aliases", json_t, nullable=False, server_default="[]"))
    op.create_table(
        "dev_sessions",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=True),
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host_id", sa.BigInteger(), nullable=False),
        sa.Column("user_key", sa.String(80), nullable=False),
        sa.Column("start_after", sa.DateTime(timezone=True)),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_active_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_dev_sessions_host", "dev_sessions", ["source_id", "host_id", "started_at"])
    op.create_index("ix_dev_sessions_open", "dev_sessions", ["source_id", "ended_at"])


def downgrade() -> None:
    op.drop_table("dev_sessions")
    op.drop_column("bi_devices", "aliases")
