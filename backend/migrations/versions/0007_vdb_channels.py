"""Каналы загрузки источников базы уязвимостей: канал и попытки последней загрузки (диагностика), история загрузок с каналом; триграммные индексы поиска (PostgreSQL).

Revision ID: 0007_vdb_channels
Revises: 0006_cvss_scores
Create Date: 2026-10-25
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0007_vdb_channels"
down_revision = "0006_cvss_scores"
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("vdb_sources", sa.Column("channel", sa.String(24), nullable=False, server_default=""))
    op.add_column("vdb_sources", sa.Column("diag", JSONB))
    op.add_column("vdb_runs", sa.Column("channel", sa.String(24), nullable=False, server_default=""))
    op.add_column("vdb_runs", sa.Column("attempts", JSONB))
    if op.get_bind().dialect.name == "postgresql":
        # поиск по части строки (`LIKE '%…%'`) по сотням тысяч уязвимостей: триграммные индексы; без прав на расширение поиск остаётся рабочим, но медленнее
        op.execute("""DO $$ BEGIN
            CREATE EXTENSION IF NOT EXISTS pg_trgm;
            CREATE INDEX IF NOT EXISTS ix_vdb_vulns_ids_trgm ON vdb_vulns USING gin (ids_text gin_trgm_ops);
            CREATE INDEX IF NOT EXISTS ix_vdb_vulns_products_trgm ON vdb_vulns USING gin (products_text gin_trgm_ops);
            CREATE INDEX IF NOT EXISTS ix_vdb_vulns_title_trgm ON vdb_vulns USING gin (lower(title) gin_trgm_ops);
            CREATE INDEX IF NOT EXISTS ix_vdb_vulns_desc_trgm ON vdb_vulns USING gin (lower(description) gin_trgm_ops);
        EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'pg_trgm недоступен: %', SQLERRM; END $$;""")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for ix in ("ix_vdb_vulns_ids_trgm", "ix_vdb_vulns_products_trgm", "ix_vdb_vulns_title_trgm", "ix_vdb_vulns_desc_trgm"):
            op.execute(f"DROP INDEX IF EXISTS {ix}")
    op.drop_column("vdb_runs", "attempts")
    op.drop_column("vdb_runs", "channel")
    op.drop_column("vdb_sources", "diag")
    op.drop_column("vdb_sources", "channel")
