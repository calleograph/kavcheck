"""Лицензии: вместо ключа активации — ссылка на запись в парольном менеджере (key_ref). Прежние зашифрованные ключи остаются до удаления.

Revision ID: 0038_lic_key_ref
"""
from alembic import op
import sqlalchemy as sa

revision = "0038_lic_key_ref"
down_revision = "0037_infra"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("inv_licenses", sa.Column("key_ref", sa.String(500), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("inv_licenses", "key_ref")
