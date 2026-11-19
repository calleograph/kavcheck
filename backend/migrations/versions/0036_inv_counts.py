"""Инвентаризация со сканированием: документы инвентаризации и их строки; признак «не подлежит инвентаризации» у учётной единицы.

Revision ID: 0036_inv_counts
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0036_inv_counts"
down_revision = "0035_inventory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    json_t = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    big_pk = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
    op.add_column("inv_assets", sa.Column("no_count", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.create_table(
        "inv_counts",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('no', sa.String(40), unique=True, nullable=False),
        sa.Column('title', sa.String(300), nullable=False, server_default=""),
        sa.Column('status', sa.String(10), nullable=False, server_default="draft"),
        sa.Column('location_id', sa.BigInteger(), sa.ForeignKey("inv_locations.id", ondelete="RESTRICT")),
        sa.Column('cls', sa.String(200), nullable=False, server_default=""),
        sa.Column('resp_id', sa.BigInteger(), sa.ForeignKey("inv_people.id", ondelete="RESTRICT")),
        sa.Column('note', sa.Text(), nullable=False, server_default=""),
        sa.Column('stats', json_t, nullable=False, server_default="{}"),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by', sa.String(160), nullable=False, server_default=""),
        sa.Column('started_at', sa.DateTime(timezone=True)),
        sa.Column('closed_at', sa.DateTime(timezone=True)),
        sa.Column('closed_by', sa.String(160), nullable=False, server_default=""),
    )
    op.create_index("ix_inv_counts_status", "inv_counts", ['status', 'created_at'])
    op.create_table(
        "inv_count_items",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('count_id', sa.BigInteger(), sa.ForeignKey("inv_counts.id", ondelete="CASCADE"), nullable=False),
        sa.Column('asset_id', sa.BigInteger(), sa.ForeignKey("inv_assets.id", ondelete="CASCADE")),
        sa.Column('code', sa.String(200), nullable=False, server_default=""),
        sa.Column('expected', sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column('exp_location_id', sa.BigInteger()),
        sa.Column('exp_user_id', sa.BigInteger()),
        sa.Column('snap', json_t, nullable=False, server_default="{}"),
        sa.Column('state', sa.String(10), nullable=False, server_default="pending"),
        sa.Column('found_location_id', sa.BigInteger()),
        sa.Column('found_user_id', sa.BigInteger()),
        sa.Column('found_at', sa.DateTime(timezone=True)),
        sa.Column('found_by', sa.String(160), nullable=False, server_default=""),
        sa.Column('found_via', sa.String(10), nullable=False, server_default=""),
        sa.Column('decision', sa.String(10), nullable=False, server_default=""),
        sa.Column('decided_by', sa.String(160), nullable=False, server_default=""),
        sa.Column('decided_at', sa.DateTime(timezone=True)),
        sa.Column('note', sa.String(500), nullable=False, server_default=""),
    )
    op.create_index("ux_inv_count_items", "inv_count_items", ['count_id', 'asset_id'], unique=True)
    op.create_index("ix_inv_count_items_state", "inv_count_items", ['count_id', 'state'])
    op.create_index("ix_inv_count_items_loc", "inv_count_items", ['count_id', 'exp_location_id'])


def downgrade() -> None:
    op.drop_table("inv_count_items")
    op.drop_table("inv_counts")
    op.drop_column("inv_assets", "no_count")
