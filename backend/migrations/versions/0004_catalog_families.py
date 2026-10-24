"""0.2.2: семейства продуктов каталога — основной продукт и связанные компоненты (php-xml, php-pear → PHP; Proofing Tools → Microsoft Office).

Семейства вычисляются при построении каталога (ksc/catalog_build.families); существующие каталоги помечаются к перестроению,
чтобы семейства появились сразу после обновления. Данные KSC не затрагиваются.

Revision ID: 0004_catalog_families
Revises: 0003_ldap_2fa_system
Create Date: 2026-10-24
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_catalog_families"
down_revision = "0003_ldap_2fa_system"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("catalog_products") as b:
        b.add_column(sa.Column("family_key", sa.String(160), nullable=False, server_default=""))
        b.add_column(sa.Column("family_size", sa.Integer(), nullable=False, server_default="1"))
        b.create_index("ix_catalog_products_family", ["source_id", "family_key"])
    op.execute(sa.text("UPDATE catalog_state SET requested_at = CURRENT_TIMESTAMP WHERE built_at IS NOT NULL"))


def downgrade() -> None:
    with op.batch_alter_table("catalog_products") as b:
        b.drop_index("ix_catalog_products_family")
        b.drop_column("family_size")
        b.drop_column("family_key")
