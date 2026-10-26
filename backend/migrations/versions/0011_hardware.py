"""Контроль аппаратных ресурсов Linux-серверов: признаки проблем в подготовленных данных зон.

Revision ID: 0011_hardware
Revises: 0010_eol_users
Create Date: 2026-10-27
"""
from alembic import op
import sqlalchemy as sa

revision = "0011_hardware"
down_revision = "0010_eol_users"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for c in ("p_hwc", "p_hwr", "hw_crit"):
        op.add_column("zc_hosts", sa.Column(c, sa.Boolean(), nullable=False, server_default=sa.text("false")))


def downgrade() -> None:
    for c in ("hw_crit", "p_hwr", "p_hwc"):
        op.drop_column("zc_hosts", c)
