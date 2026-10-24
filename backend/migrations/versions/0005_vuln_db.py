"""0.4.0: база уязвимостей — внешние источники (NVD, CISA KEV, OSV, БДУ ФСТЭК), записи, затронутые продукты, сводка, сопоставления и находки по инфраструктуре.

Данные KSC не затрагиваются. Строки источников создаются выключенными (кроме CISA KEV): администратор включает их в разделе «Администрирование → База уязвимостей».

Revision ID: 0005_vuln_db
Revises: 0004_catalog_families
Create Date: 2026-10-24
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005_vuln_db"
down_revision = "0004_catalog_families"
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
BIGPK = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
TS = sa.DateTime(timezone=True)


def str_col(name: str, n: int, default: str = "") -> sa.Column:
    return sa.Column(name, sa.String(n), nullable=False, server_default=default)


def upgrade() -> None:
    op.create_table("vdb_sources",
        sa.Column("key", sa.String(16), primary_key=True), sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("interval_hours", sa.Integer(), nullable=False, server_default="24"), sa.Column("settings", JSONB, nullable=False),
        sa.Column("secret_enc", sa.Text()), sa.Column("active_generation", sa.Integer(), nullable=False, server_default="1"), sa.Column("prev_generation", sa.Integer()),
        str_col("status", 10, "never"), sa.Column("progress", sa.String(300)), sa.Column("requested_at", TS), sa.Column("last_started_at", TS), sa.Column("last_ok_at", TS),
        sa.Column("last_duration_ms", sa.Integer()), sa.Column("last_error", sa.Text()), sa.Column("records", sa.Integer(), nullable=False, server_default="0"), sa.Column("cursor", JSONB))
    op.create_table("vdb_runs",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True), sa.Column("source", sa.String(16), nullable=False, index=True), sa.Column("started_at", TS, nullable=False),
        sa.Column("finished_at", TS), str_col("trigger", 10, "schedule"), str_col("mode", 12), str_col("status", 10, "running"),
        sa.Column("fetched", sa.Integer(), nullable=False, server_default="0"), sa.Column("changed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer()), sa.Column("error", sa.Text()))
    op.create_table("vdb_records",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True), sa.Column("source", sa.String(16), nullable=False), sa.Column("generation", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("ext_id", sa.String(80), nullable=False), sa.Column("vuln_key", sa.String(80), nullable=False, index=True), sa.Column("aliases", JSONB, nullable=False),
        str_col("title", 500), sa.Column("description", sa.Text(), nullable=False, server_default=""), str_col("severity", 10), sa.Column("score", sa.Float()), str_col("vector", 200),
        sa.Column("published", TS), sa.Column("modified", TS), sa.Column("exploited", sa.Boolean(), nullable=False, server_default=sa.text("false")), sa.Column("fix_available", sa.Boolean()),
        sa.Column("fix_text", sa.Text(), nullable=False, server_default=""), str_col("status", 80), sa.Column("refs", JSONB, nullable=False), sa.Column("extra", JSONB, nullable=False),
        sa.Column("fetched_at", TS, nullable=False))
    op.create_index("ux_vdb_records_ext", "vdb_records", ["source", "generation", "ext_id"], unique=True)
    op.create_index("ix_vdb_records_mod", "vdb_records", ["source", "generation", "modified"])
    op.create_table("vdb_affected",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True), sa.Column("source", sa.String(16), nullable=False), sa.Column("generation", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("ext_id", sa.String(80), nullable=False), sa.Column("vuln_key", sa.String(80), nullable=False), str_col("vendor", 200), str_col("product", 300), str_col("vendor_key", 200),
        str_col("product_key", 300), str_col("cpe", 400), str_col("purl", 400), str_col("ecosystem", 60), str_col("pkg_name", 300), str_col("platform", 80), str_col("exact", 120),
        str_col("v_start", 120), sa.Column("v_start_incl", sa.Boolean(), nullable=False, server_default=sa.text("true")), str_col("v_end", 120),
        sa.Column("v_end_incl", sa.Boolean(), nullable=False, server_default=sa.text("false")), str_col("fixed", 120),
        sa.Column("versions_all", sa.Boolean(), nullable=False, server_default=sa.text("false")), str_col("version_text", 300),
        sa.Column("conditional", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.create_index("ix_vdb_affected_product_key", "vdb_affected", ["product_key"])
    op.create_index("ix_vdb_affected_pkg_name", "vdb_affected", ["pkg_name"])
    op.create_index("ix_vdb_aff_rec", "vdb_affected", ["source", "generation", "ext_id"])
    op.create_index("ix_vdb_aff_key", "vdb_affected", ["vuln_key"])
    op.create_table("vdb_vulns",
        sa.Column("vuln_key", sa.String(80), primary_key=True), str_col("title", 500), sa.Column("sev_rank", sa.Integer(), nullable=False, server_default="0", index=True), sa.Column("score", sa.Float()),
        sa.Column("exploited", sa.Boolean(), nullable=False, server_default=sa.text("false"), index=True), sa.Column("has_fix", sa.Boolean()), sa.Column("published", TS, index=True),
        sa.Column("modified", TS, index=True), str_col("sources", 80), sa.Column("ids_text", sa.Text(), nullable=False, server_default=""),
        sa.Column("products_text", sa.Text(), nullable=False, server_default=""), sa.Column("description", sa.Text(), nullable=False, server_default=""))
    op.create_index("ix_vdb_vulns_priority", "vdb_vulns", [sa.text("exploited DESC"), sa.text("sev_rank DESC"), sa.text("published DESC")])   # порядок списка по умолчанию
    op.create_table("vdb_mappings",
        sa.Column("id", sa.Uuid(), primary_key=True), str_col("vendor_key", 200), sa.Column("product_key", sa.String(300), nullable=False), sa.Column("catalog_key", sa.String(160), nullable=False),
        str_col("action", 8, "map"), sa.Column("note", sa.Text()), sa.Column("created_by", sa.String(300)), sa.Column("created_at", TS, nullable=False))
    op.create_index("ix_vdb_mappings_key", "vdb_mappings", ["vendor_key", "product_key"])
    op.create_table("vdb_findings",
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True), sa.Column("vuln_key", sa.String(80), primary_key=True),
        sa.Column("first_seen_at", TS, nullable=False, index=True), sa.Column("updated_at", TS, nullable=False), str_col("status", 14), sa.Column("sev_rank", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("exploited", sa.Boolean(), nullable=False, server_default=sa.text("false")), sa.Column("products", JSONB, nullable=False),
        sa.Column("installs", sa.Integer(), nullable=False, server_default="0"), sa.Column("hosts_max", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("seen_by", sa.String(300)), sa.Column("seen_at", TS))
    sources = sa.table("vdb_sources", sa.column("key", sa.String), sa.column("enabled", sa.Boolean), sa.column("interval_hours", sa.Integer), sa.column("settings", JSONB))
    op.bulk_insert(sources, [
        {"key": "kev", "enabled": True, "interval_hours": 12, "settings": {}},
        {"key": "nvd", "enabled": False, "interval_hours": 6, "settings": {"history_days": 365}},
        {"key": "osv", "enabled": False, "interval_hours": 24, "settings": {"ecosystems": ["Debian"], "enrich": True}},
        {"key": "bdu", "enabled": False, "interval_hours": 24, "settings": {"url": "https://bdu.fstec.ru/files/documents/vulxml.zip", "verify_tls": True}}])


def downgrade() -> None:
    for t in ("vdb_findings", "vdb_mappings", "vdb_vulns", "vdb_affected", "vdb_records", "vdb_runs", "vdb_sources"):
        op.drop_table(t)
