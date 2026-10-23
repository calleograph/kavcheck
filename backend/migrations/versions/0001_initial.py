"""Начальная схема внутренней базы KAV Checker.

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-23
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
BIGPK = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table("users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("username", sa.String(256), nullable=False, unique=True),
        sa.Column("display_name", sa.String(300), nullable=False),
        sa.Column("email", sa.String(320)),
        sa.Column("auth_source", sa.String(8), nullable=False, server_default="local"),
        sa.Column("ldap_guid", sa.String(64), unique=True),
        sa.Column("password_hash", sa.Text()),
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("role", sa.String(16), nullable=False, server_default="viewer"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("all_sources", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("source_ids", JSONB),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("sessions",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("csrf", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip", sa.String(64)), sa.Column("user_agent", sa.String(300)), sa.Column("current_source_id", sa.Uuid()))
    op.create_table("login_failures",
        sa.Column("key", sa.String(64), primary_key=True), sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("first_at", sa.DateTime(timezone=True), nullable=False), sa.Column("locked_until", sa.DateTime(timezone=True)))
    op.create_table("app_settings",
        sa.Column("group", sa.String(40), primary_key=True), sa.Column("value", JSONB, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_by", sa.String(300)))
    op.create_table("ksc_sources",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("name", sa.String(120), nullable=False, unique=True),
        sa.Column("host", sa.String(253), nullable=False), sa.Column("port", sa.Integer(), nullable=False), sa.Column("database", sa.String(128), nullable=False),
        sa.Column("auth_type", sa.String(16), nullable=False, server_default="sql"), sa.Column("username", sa.String(256), nullable=False), sa.Column("password_enc", sa.Text()),
        sa.Column("tls_mode", sa.String(16), nullable=False, server_default="require"), sa.Column("trust_server_cert", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("connect_timeout_s", sa.Integer(), nullable=False), sa.Column("query_timeout_s", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")), sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("last_check_at", sa.DateTime(timezone=True)), sa.Column("last_check_ok", sa.Boolean()), sa.Column("last_check", JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("grouping_rules",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("key", sa.String(64), nullable=False, unique=True), sa.Column("name", sa.String(120), nullable=False),
        sa.Column("name_like", sa.String(200), nullable=False), sa.Column("name_regex", sa.Text(), nullable=False), sa.Column("branch_regex", sa.Text()),
        sa.Column("branch_parts", sa.Integer(), nullable=False), sa.Column("exclude_regex", sa.Text()), sa.Column("description", sa.Text()),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default=sa.text("false")), sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("audit_checks",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(200), nullable=False), sa.Column("selection", JSONB, nullable=False), sa.Column("cve", sa.String(300)),
        sa.Column("severity", sa.String(16), nullable=False, server_default="medium"), sa.Column("description", sa.Text()), sa.Column("comment", sa.Text()),
        sa.Column("created_by", sa.String(300)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("report_templates",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("name", sa.String(200), nullable=False), sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("params", JSONB, nullable=False), sa.Column("source_id", sa.Uuid()), sa.Column("owner_id", sa.Uuid()),
        sa.Column("shared", sa.Boolean(), nullable=False, server_default=sa.text("true")), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("report_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("source_name", sa.String(120), nullable=False), sa.Column("kind", sa.String(40), nullable=False), sa.Column("title", sa.String(300), nullable=False),
        sa.Column("params", JSONB, nullable=False), sa.Column("status", sa.String(16), nullable=False, server_default="queued", index=True), sa.Column("progress", sa.String(300)),
        sa.Column("created_by", sa.String(300)), sa.Column("created_by_id", sa.Uuid()), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("started_at", sa.DateTime(timezone=True)), sa.Column("finished_at", sa.DateTime(timezone=True)), sa.Column("data_fetched_at", sa.DateTime(timezone=True)),
        sa.Column("rows", sa.Integer()), sa.Column("summary", JSONB), sa.Column("error", sa.Text()),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.text("false")), sa.Column("worker", sa.String(120)))
    op.create_table("audit_log",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True), sa.Column("at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("actor_user_id", sa.Uuid()), sa.Column("actor", sa.String(300), nullable=False), sa.Column("action", sa.String(80), nullable=False, index=True),
        sa.Column("target_type", sa.String(40), nullable=False), sa.Column("target_id", sa.String(200), nullable=False), sa.Column("source_id", sa.Uuid()),
        sa.Column("details", JSONB), sa.Column("result", sa.String(16), nullable=False, server_default="success"), sa.Column("ip", sa.String(64)),
        sa.Column("duration_ms", sa.Integer()), sa.Column("request_id", sa.String(64)))
    op.create_table("event_log",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True), sa.Column("at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("level", sa.String(8), nullable=False, index=True), sa.Column("category", sa.String(24), nullable=False, index=True), sa.Column("event", sa.String(64), nullable=False),
        sa.Column("user", sa.String(256), index=True), sa.Column("source", sa.String(120)), sa.Column("message", sa.String(600)), sa.Column("data", JSONB),
        sa.Column("duration_ms", sa.Integer()), sa.Column("ip", sa.String(64)), sa.Column("request_id", sa.String(64)))
    op.create_table("ksc_cache",
        sa.Column("source_id", sa.Uuid(), primary_key=True), sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False), sa.Column("payload", JSONB, nullable=False))


def downgrade() -> None:
    for t in ("ksc_cache", "event_log", "audit_log", "report_jobs", "report_templates", "audit_checks", "grouping_rules", "ksc_sources", "app_settings", "login_failures", "sessions", "users"):
        op.drop_table(t)
