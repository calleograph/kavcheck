"""Подготовленные данные зон ответственности (ночной расчёт): снимки компьютеров и обнаружений по источникам, готовые сводки зон, задания расчёта.

Revision ID: 0009_zone_cache
Revises: 0008_zones_mail_triage
Create Date: 2026-10-26
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0009_zone_cache"
down_revision = "0008_zones_mail_triage"
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
BIGPK = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
TS = sa.DateTime(timezone=True)


def _i(name: str, **kw) -> sa.Column:
    return sa.Column(name, sa.Integer(), nullable=False, server_default="0", **kw)


def upgrade() -> None:
    op.create_table("zc_sources",
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True), _i("gen"), sa.Column("status", sa.String(12), nullable=False, server_default="empty"),
        sa.Column("built_at", TS), sa.Column("finished_at", TS), sa.Column("started_at", TS), sa.Column("duration_ms", sa.Integer()), sa.Column("progress", sa.String(300)), sa.Column("error", sa.Text()),
        _i("hosts_n"), _i("detections_n"), sa.Column("agg_only", sa.Boolean(), nullable=False, server_default=sa.text("false")), sa.Column("notes", JSONB, nullable=False, server_default="[]"),
        sa.Column("stamp", sa.String(200), nullable=False, server_default=""), sa.Column("probe_stamp", sa.String(200), nullable=False, server_default=""), sa.Column("probe_at", TS),
        sa.Column("vdb_rev", sa.String(64), nullable=False, server_default=""), sa.Column("vdb_rev_now", sa.String(64), nullable=False, server_default=""))
    flags = [sa.Column(n, sa.Boolean(), nullable=False, server_default=sa.text("false")) for n in ("active", "has_av", "p_no_av", "p_rtp", "p_inf", "p_lic", "p_reb", "conflict", "pinned")]
    counters = [_i(n) for n in ("k_crit", "k_high", "k_warn", "k_total", "k_acc", "k_exc", "k_rev", "e_crit", "e_high", "e_warn", "e_total", "e_kev", "e_conf", "e_acc", "e_exc")]
    op.create_table("zc_hosts",
        sa.Column("source_id", sa.Uuid(), primary_key=True), sa.Column("host_id", sa.BigInteger(), primary_key=True), sa.Column("gen", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False, server_default=""), sa.Column("search", sa.String(800), nullable=False, server_default=""), sa.Column("ip_num", sa.BigInteger()),
        sa.Column("os", sa.String(200), nullable=False, server_default=""), sa.Column("last_connected", TS), sa.Column("days_since", sa.Float()), sa.Column("online", sa.Boolean()),
        sa.Column("bases_age", sa.Float()), sa.Column("scan_age", sa.Float()), *flags, *counters, sa.Column("data", JSONB, nullable=False, server_default="{}"), *[sa.Column(n, sa.Text(), nullable=False, server_default="") for n in ("kk", "ke", "pk", "pe")])
    op.create_index("ix_zc_hosts_gen", "zc_hosts", ["source_id", "gen"])
    op.create_table("zc_hostzones",
        sa.Column("source_id", sa.Uuid(), primary_key=True), sa.Column("host_id", sa.BigInteger(), primary_key=True), sa.Column("gen", sa.Integer(), primary_key=True), sa.Column("zone_id", sa.String(40), primary_key=True))
    op.create_index("ix_zc_hostzones_zone", "zc_hostzones", ["zone_id", "source_id", "gen"])
    op.create_table("zc_detections",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True), sa.Column("source_id", sa.Uuid(), nullable=False), sa.Column("gen", sa.Integer(), nullable=False), sa.Column("host_id", sa.BigInteger(), nullable=False),
        sa.Column("origin", sa.String(4), nullable=False), sa.Column("vuln_key", sa.String(80), nullable=False, server_default=""), sa.Column("keys", sa.String(600), nullable=False, server_default=""),
        sa.Column("prod", sa.String(300), nullable=False, server_default=""), _i("severity"), sa.Column("bucket", sa.String(8), nullable=False, server_default="current"),
        sa.Column("tstatus", sa.String(16), nullable=False, server_default=""), _i("flags"), sa.Column("row", JSONB, nullable=False, server_default="{}"))
    op.create_index("ix_zc_det_host", "zc_detections", ["source_id", "gen", "host_id"])
    op.create_index("ix_zc_det_vuln", "zc_detections", ["source_id", "gen", "vuln_key"])
    op.create_table("zc_dashboards",
        sa.Column("zone_id", sa.String(40), primary_key=True), sa.Column("kind", sa.String(12), primary_key=True, server_default="default"), sa.Column("payload", JSONB, nullable=False, server_default="{}"),
        sa.Column("built_at", TS, nullable=False), sa.Column("data_at", TS), sa.Column("duration_ms", sa.Integer()), sa.Column("status", sa.String(8), nullable=False, server_default="ok"),
        sa.Column("error", sa.Text()), sa.Column("failed_at", TS))
    op.create_table("zc_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("kind", sa.String(8), nullable=False), sa.Column("zone_id", sa.String(40)), sa.Column("dedupe_key", sa.String(60), nullable=False),
        sa.Column("trigger", sa.String(10), nullable=False, server_default="manual"), sa.Column("status", sa.String(10), nullable=False, server_default="queued"),
        sa.Column("requested_by", sa.String(120), nullable=False, server_default=""), sa.Column("requested_at", TS, nullable=False), sa.Column("started_at", TS), sa.Column("finished_at", TS),
        sa.Column("heartbeat_at", TS), sa.Column("progress", sa.String(300)), _i("pct"), _i("attempts"), sa.Column("error", sa.Text()))
    op.create_index("ix_zc_jobs_requested_at", "zc_jobs", ["requested_at"])
    op.create_index("ux_zc_jobs_active", "zc_jobs", ["dedupe_key"], unique=True, postgresql_where=sa.text("status IN ('queued','running')"), sqlite_where=sa.text("status IN ('queued','running')"))
    if op.get_bind().dialect.name == "postgresql":
        # поиск по идентификатору уязвимости и программе (подстрока) в списках компьютера — триграммные индексы; расширение необязательно: без него поиск работает, но медленнее
        op.execute("""DO $$ BEGIN CREATE EXTENSION IF NOT EXISTS pg_trgm; EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'pg_trgm недоступно: поиск по обнаружениям без триграммных индексов'; END $$""")
        has = op.get_bind().execute(sa.text("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'")).scalar()
        if has:
            for c in ("kk", "ke", "pk", "pe"):
                op.execute(f"CREATE INDEX ix_zc_hosts_{c}_trgm ON zc_hosts USING gin ({c} gin_trgm_ops)")


def downgrade() -> None:
    for t in ("zc_jobs", "zc_dashboards", "zc_detections", "zc_hostzones", "zc_hosts", "zc_sources"):
        op.drop_table(t)
