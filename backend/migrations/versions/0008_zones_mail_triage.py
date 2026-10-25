"""Зоны ответственности, получатели, рассылки отчётов (устойчивая очередь) и обработка уязвимостей (ложные срабатывания, принятие риска).

Revision ID: 0008_zones_mail_triage
Revises: 0007_vdb_channels
Create Date: 2026-10-26
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0008_zones_mail_triage"
down_revision = "0007_vdb_channels"
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
BIGPK = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table("zones",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("name", sa.String(120), nullable=False, unique=True), sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("purpose", sa.String(300), nullable=False, server_default=""), sa.Column("priority", sa.Integer(), nullable=False, server_default="100"), sa.Column("activity_days", sa.Integer()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")), sa.Column("created_at", TS, nullable=False), sa.Column("updated_at", TS, nullable=False), sa.Column("updated_by", sa.String(300)))
    op.create_table("zone_rules",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("zone_id", sa.Uuid(), sa.ForeignKey("zones.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("kind", sa.String(8), nullable=False), sa.Column("value", sa.String(300), nullable=False), sa.Column("note", sa.String(200), nullable=False, server_default=""),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"))
    op.create_table("zone_contacts",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("zone_id", sa.Uuid(), sa.ForeignKey("zones.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(200), nullable=False, server_default=""), sa.Column("position", sa.String(200), nullable=False, server_default=""), sa.Column("email", sa.String(254), nullable=False),
        sa.Column("role", sa.String(12), nullable=False, server_default="responsible"), sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")), sa.Column("created_at", TS, nullable=False))
    op.create_table("zone_pins",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host_id", sa.BigInteger(), nullable=False), sa.Column("host_name", sa.String(300), nullable=False, server_default=""),
        sa.Column("zone_id", sa.Uuid(), sa.ForeignKey("zones.id", ondelete="CASCADE"), nullable=False), sa.Column("created_by", sa.String(300)), sa.Column("created_at", TS, nullable=False))
    op.create_index("ux_zone_pins_host", "zone_pins", ["source_id", "host_id"], unique=True)
    op.create_table("report_schedules",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("name", sa.String(160), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("zone_ids", JSONB, nullable=False), sa.Column("include_unassigned", sa.Boolean(), nullable=False, server_default=sa.text("false")), sa.Column("sections", JSONB, nullable=False),
        sa.Column("filters", JSONB, nullable=False), sa.Column("level", sa.String(12), nullable=False, server_default="management"), sa.Column("frequency", sa.String(8), nullable=False, server_default="weekly"),
        sa.Column("weekday", sa.Integer(), nullable=False, server_default="0"), sa.Column("monthday", sa.Integer(), nullable=False, server_default="1"), sa.Column("at_time", sa.String(5), nullable=False, server_default="08:00"),
        sa.Column("tz", sa.String(64), nullable=False, server_default="UTC"), sa.Column("attach_html", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("attach_xlsx", sa.Boolean(), nullable=False, server_default=sa.text("false")), sa.Column("skip_empty", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("next_run_at", TS), sa.Column("last_run_at", TS), sa.Column("last_period", sa.String(32)), sa.Column("created_by", sa.String(300)), sa.Column("created_at", TS, nullable=False), sa.Column("updated_at", TS, nullable=False))
    op.create_index("ix_report_schedules_next_run_at", "report_schedules", ["next_run_at"])
    op.create_table("mail_outbox",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("schedule_id", sa.Uuid(), sa.ForeignKey("report_schedules.id", ondelete="SET NULL")),
        sa.Column("zone_id", sa.Uuid(), sa.ForeignKey("zones.id", ondelete="SET NULL")), sa.Column("zone_name", sa.String(120), nullable=False, server_default=""), sa.Column("period_key", sa.String(40), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False, server_default="schedule"), sa.Column("status", sa.String(10), nullable=False, server_default="queued"), sa.Column("subject", sa.String(300), nullable=False, server_default=""),
        sa.Column("to_addrs", JSONB, nullable=False), sa.Column("cc_addrs", JSONB, nullable=False), sa.Column("body_path", sa.String(400)), sa.Column("stats", JSONB, nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"), sa.Column("last_error", sa.Text()), sa.Column("refused", JSONB, nullable=False), sa.Column("message_id", sa.String(200)),
        sa.Column("created_at", TS, nullable=False), sa.Column("next_attempt_at", TS), sa.Column("sent_at", TS))
    op.create_index("ix_mail_outbox_schedule_id", "mail_outbox", ["schedule_id"]); op.create_index("ix_mail_outbox_created_at", "mail_outbox", ["created_at"]); op.create_index("ix_mail_outbox_next_attempt_at", "mail_outbox", ["next_attempt_at"])
    op.create_index("ux_mail_outbox_period", "mail_outbox", ["schedule_id", "zone_id", "period_key"], unique=True)
    op.create_table("vuln_triage",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scope", sa.String(8), nullable=False, server_default="host"), sa.Column("host_id", sa.BigInteger()), sa.Column("host_name", sa.String(300), nullable=False, server_default=""),
        sa.Column("zone_id", sa.Uuid(), sa.ForeignKey("zones.id", ondelete="CASCADE")), sa.Column("vuln_key", sa.String(80), nullable=False, index=True), sa.Column("origin", sa.String(4), nullable=False, server_default="ksc"),
        sa.Column("product", sa.String(300), nullable=False, server_default=""), sa.Column("version", sa.String(120), nullable=False, server_default=""), sa.Column("status", sa.String(10), nullable=False),
        sa.Column("reason", sa.String(40), nullable=False, server_default=""), sa.Column("comment", sa.Text(), nullable=False, server_default=""), sa.Column("review_until", TS),
        sa.Column("recheck", sa.Boolean(), nullable=False, server_default=sa.text("false")), sa.Column("recheck_reason", sa.String(200), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(300), nullable=False, server_default=""), sa.Column("created_at", TS, nullable=False), sa.Column("updated_at", TS, nullable=False))
    op.create_index("ix_vuln_triage_host", "vuln_triage", ["source_id", "host_id", "vuln_key"])
    op.create_table("vuln_triage_events",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True), sa.Column("triage_id", sa.Uuid(), sa.ForeignKey("vuln_triage.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("at", TS, nullable=False), sa.Column("actor", sa.String(300), nullable=False, server_default=""), sa.Column("action", sa.String(16), nullable=False),
        sa.Column("from_status", sa.String(10), nullable=False, server_default=""), sa.Column("to_status", sa.String(10), nullable=False, server_default=""), sa.Column("comment", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    for t in ("vuln_triage_events", "vuln_triage", "mail_outbox", "report_schedules", "zone_pins", "zone_contacts", "zone_rules", "zones"):
        op.drop_table(t)
