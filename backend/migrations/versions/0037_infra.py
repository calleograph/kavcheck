"""Серверная и сетевая инфраструктура: источники (только чтение), объекты источников и история их конфигурации, расхождения сверки;
назначение, сервис и размещение в стойке у учётной единицы.

Revision ID: 0037_infra
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0037_infra"
down_revision = "0036_inv_counts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    json_t = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    big_pk = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
    op.add_column("inv_assets", sa.Column("purpose", sa.String(500), nullable=False, server_default=""))
    op.add_column("inv_assets", sa.Column("service", sa.String(300), nullable=False, server_default=""))
    op.add_column("inv_assets", sa.Column("rack_unit", sa.Integer()))
    op.add_column("inv_assets", sa.Column("rack_units", sa.Integer()))
    op.create_table(
        "infra_sources",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('kind', sa.String(10), nullable=False),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('url', sa.String(500), nullable=False, server_default=""),
        sa.Column('username', sa.String(200), nullable=False, server_default=""),
        sa.Column('secret_enc', sa.Text(), nullable=False, server_default=""),
        sa.Column('verify_tls', sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column('every_min', sa.Integer(), nullable=False, server_default="60"),
        sa.Column('options', json_t, nullable=False, server_default="{}"),
        sa.Column('requested', sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column('last_try_at', sa.DateTime(timezone=True)),
        sa.Column('last_ok_at', sa.DateTime(timezone=True)),
        sa.Column('last_error', sa.Text(), nullable=False, server_default=""),
        sa.Column('last_stats', json_t, nullable=False, server_default="{}"),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "infra_objects",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('source_id', sa.BigInteger(), sa.ForeignKey("infra_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column('ext_id', sa.String(200), nullable=False),
        sa.Column('kind', sa.String(12), nullable=False),
        sa.Column('name', sa.String(300), nullable=False, server_default=""),
        sa.Column('fqdn', sa.String(300), nullable=False, server_default=""),
        sa.Column('ips', json_t, nullable=False, server_default="[]"),
        sa.Column('macs', json_t, nullable=False, server_default="[]"),
        sa.Column('bios_uuid', sa.String(64), nullable=False, server_default=""),
        sa.Column('serial', sa.String(120), nullable=False, server_default=""),
        sa.Column('parent_ext', sa.String(200), nullable=False, server_default=""),
        sa.Column('attrs', json_t, nullable=False, server_default="{}"),
        sa.Column('present', sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('asset_id', sa.BigInteger(), sa.ForeignKey("inv_assets.id", ondelete="SET NULL")),
        sa.Column('match', sa.String(10), nullable=False, server_default="none"),
        sa.Column('match_basis', sa.String(300), nullable=False, server_default=""),
        sa.Column('search', sa.String(1500), nullable=False, server_default=""),
    )
    op.create_index("ix_infra_objects_asset", "infra_objects", ['asset_id'])
    op.create_index("ix_infra_objects_kind", "infra_objects", ['kind', 'present'])
    op.create_index("ux_infra_objects", "infra_objects", ['source_id', 'ext_id'], unique=True)
    op.create_table(
        "infra_changes",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('object_id', sa.BigInteger(), sa.ForeignKey("infra_objects.id", ondelete="CASCADE"), nullable=False),
        sa.Column('at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('field', sa.String(40), nullable=False),
        sa.Column('old', sa.String(1000), nullable=False, server_default=""),
        sa.Column('new', sa.String(1000), nullable=False, server_default=""),
    )
    op.create_index("ix_infra_changes_at", "infra_changes", ['at'])
    op.create_index("ix_infra_changes_obj", "infra_changes", ['object_id', 'at'])
    op.create_table(
        "infra_findings",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('key', sa.String(200), unique=True, nullable=False),
        sa.Column('code', sa.String(24), nullable=False),
        sa.Column('severity', sa.String(8), nullable=False, server_default="medium"),
        sa.Column('status', sa.String(10), nullable=False, server_default="attention"),
        sa.Column('asset_id', sa.BigInteger(), sa.ForeignKey("inv_assets.id", ondelete="CASCADE")),
        sa.Column('object_id', sa.BigInteger(), sa.ForeignKey("infra_objects.id", ondelete="CASCADE")),
        sa.Column('title', sa.String(300), nullable=False, server_default=""),
        sa.Column('found', sa.String(1000), nullable=False, server_default=""),
        sa.Column('expected', sa.String(1000), nullable=False, server_default=""),
        sa.Column('source', sa.String(200), nullable=False, server_default=""),
        sa.Column('action', sa.String(500), nullable=False, server_default=""),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('closed_at', sa.DateTime(timezone=True)),
        sa.Column('comment', sa.String(2000), nullable=False, server_default=""),
        sa.Column('owner', sa.String(200), nullable=False, server_default=""),
        sa.Column('due', sa.Date()),
        sa.Column('decided_by', sa.String(160), nullable=False, server_default=""),
        sa.Column('decided_at', sa.DateTime(timezone=True)),
        sa.Column('history', json_t, nullable=False, server_default="[]"),
    )
    op.create_index("ix_infra_findings_asset", "infra_findings", ['asset_id'])
    op.create_index("ix_infra_findings_status", "infra_findings", ['status', 'code'])


def downgrade() -> None:
    for t in ("infra_findings", "infra_changes", "infra_objects", "infra_sources"):
        op.drop_table(t)
    for c in ("rack_units", "rack_unit", "service", "purpose"):
        op.drop_column("inv_assets", c)
