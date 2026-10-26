"""Жизненный цикл ПО (endoflife.date): продукты, ветки, решения администратора, результаты сопоставления; наблюдения за пользователями устройств; устройства с EOL.

Revision ID: 0010_eol_users
Revises: 0009_zone_cache
Create Date: 2026-10-27
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0010_eol_users"
down_revision = "0009_zone_cache"
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table("eol_products",
        sa.Column("name", sa.String(120), primary_key=True), sa.Column("label", sa.String(200), nullable=False, server_default=""), sa.Column("category", sa.String(40), nullable=False, server_default=""),
        sa.Column("tags", JSONB, nullable=False, server_default="[]"), sa.Column("aliases", JSONB, nullable=False, server_default="[]"), sa.Column("identifiers", JSONB, nullable=False, server_default="[]"),
        sa.Column("labels", JSONB, nullable=False, server_default="{}"), sa.Column("links", JSONB, nullable=False, server_default="{}"), sa.Column("search", sa.Text(), nullable=False, server_default=""),
        sa.Column("releases_n", sa.Integer(), nullable=False, server_default="0"), sa.Column("digest", sa.String(32), nullable=False, server_default=""), sa.Column("updated_at", TS, nullable=False))
    op.create_table("eol_releases",
        sa.Column("product", sa.String(120), sa.ForeignKey("eol_products.name", ondelete="CASCADE"), primary_key=True), sa.Column("name", sa.String(80), primary_key=True),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"), sa.Column("label", sa.String(200), nullable=False, server_default=""), sa.Column("codename", sa.String(80)),
        sa.Column("release_date", sa.Date()), sa.Column("is_lts", sa.Boolean(), nullable=False, server_default=sa.text("false")), sa.Column("lts_from", sa.Date()), sa.Column("eoas_from", sa.Date()),
        sa.Column("eol_from", sa.Date()), sa.Column("eoes_from", sa.Date()), sa.Column("eol_flag", sa.Boolean()), sa.Column("eoes_flag", sa.Boolean()), sa.Column("discontinued_from", sa.Date()),
        sa.Column("latest_name", sa.String(80)), sa.Column("latest_date", sa.Date()), sa.Column("latest_link", sa.String(400)), sa.Column("custom", JSONB))
    op.create_table("eol_mappings",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("catalog_key", sa.String(160), nullable=False), sa.Column("eol_product", sa.String(120)), sa.Column("action", sa.String(8), nullable=False, server_default="map"),
        sa.Column("note", sa.String(300), nullable=False, server_default=""), sa.Column("created_by", sa.String(300), nullable=False, server_default=""), sa.Column("created_at", TS, nullable=False))
    op.create_index("ux_eol_mappings_key", "eol_mappings", ["catalog_key"], unique=True)
    op.create_table("eol_findings",
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True), sa.Column("kind", sa.String(3), primary_key=True), sa.Column("subject", sa.String(200), primary_key=True),
        sa.Column("version", sa.String(120), primary_key=True), sa.Column("title", sa.String(300), nullable=False, server_default=""), sa.Column("publisher", sa.String(300), nullable=False, server_default=""),
        sa.Column("eol_product", sa.String(120), nullable=False, server_default=""), sa.Column("eol_release", sa.String(80), nullable=False, server_default=""), sa.Column("status", sa.String(12), nullable=False, server_default="unknown"),
        sa.Column("severity", sa.String(10), nullable=False, server_default=""), sa.Column("confidence", sa.String(8), nullable=False, server_default=""), sa.Column("confirmed", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("eol_from", sa.Date()), sa.Column("eoas_from", sa.Date()), sa.Column("eoes_from", sa.Date()), sa.Column("condition", sa.String(600), nullable=False, server_default=""), sa.Column("link", sa.String(400), nullable=False, server_default=""),
        sa.Column("os_key", JSONB), sa.Column("product_ids", JSONB, nullable=False, server_default="[]"), sa.Column("hosts_all", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hosts_active", sa.Integer(), nullable=False, server_default="0"), sa.Column("installs_active", sa.Integer(), nullable=False, server_default="0"), sa.Column("computed_at", TS, nullable=False))
    op.create_index("ix_eol_findings_status", "eol_findings", ["source_id", "status"])
    op.create_index("ix_eol_findings_product", "eol_findings", ["eol_product"])
    op.create_table("eol_state",
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True), sa.Column("rev", sa.String(64), nullable=False, server_default=""), sa.Column("inputs", sa.String(64), nullable=False, server_default=""),
        sa.Column("computed_at", TS), sa.Column("duration_ms", sa.Integer()), sa.Column("items", sa.Integer(), nullable=False, server_default="0"), sa.Column("error", sa.Text()),
        sa.Column("error_at", TS), sa.Column("progress", sa.String(200)))
    op.create_table("eol_hosts",
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True), sa.Column("kind", sa.String(3), primary_key=True), sa.Column("subject", sa.String(200), primary_key=True),
        sa.Column("version", sa.String(120), primary_key=True), sa.Column("host_id", sa.BigInteger(), primary_key=True))
    op.create_index("ix_eol_hosts_host", "eol_hosts", ["source_id", "host_id"])
    op.create_table("dev_users",
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True), sa.Column("host_id", sa.BigInteger(), primary_key=True), sa.Column("user_key", sa.String(80), primary_key=True),
        sa.Column("login", sa.String(256), nullable=False, server_default=""), sa.Column("domain", sa.String(256), nullable=False, server_default=""), sa.Column("kind", sa.String(8), nullable=False, server_default="user"),
        sa.Column("resolved", sa.Boolean(), nullable=False, server_default=sa.text("true")), sa.Column("first_seen_at", TS, nullable=False), sa.Column("last_seen_at", TS, nullable=False), sa.Column("last_session_at", TS),
        sa.Column("session_now", sa.Boolean(), nullable=False, server_default=sa.text("false")), sa.Column("seen_n", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("initial", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.create_table("dev_state",
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True), sa.Column("polled_at", TS), sa.Column("first_poll_at", TS), sa.Column("duration_ms", sa.Integer()),
        sa.Column("rows_seen", sa.Integer(), nullable=False, server_default="0"), sa.Column("users_n", sa.Integer(), nullable=False, server_default="0"), sa.Column("error", sa.Text()), sa.Column("error_at", TS), sa.Column("requested_at", TS))
    op.create_index("ix_dev_users_login", "dev_users", ["login"])
    op.create_index("ix_dev_users_host", "dev_users", ["source_id", "host_id", "last_seen_at"])
    op.create_index("ix_zc_hosts_ip", "zc_hosts", ["source_id", "gen", "ip_num"])
    if op.get_bind().dialect.name == "postgresql":
        has = op.get_bind().execute(sa.text("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'")).scalar()
        if has:
            op.execute("CREATE INDEX ix_eol_products_search_trgm ON eol_products USING gin (search gin_trgm_ops)")
            op.execute("CREATE INDEX ix_dev_users_login_trgm ON dev_users USING gin (lower(login) gin_trgm_ops)")
            op.execute("CREATE INDEX ix_zc_hosts_search_trgm ON zc_hosts USING gin (search gin_trgm_ops)")


def downgrade() -> None:
    op.drop_index("ix_zc_hosts_ip", "zc_hosts")
    for t in ("dev_state", "dev_users", "eol_hosts", "eol_state", "eol_findings", "eol_mappings", "eol_releases", "eol_products"):
        op.drop_table(t)
