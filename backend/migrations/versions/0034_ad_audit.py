"""Аудит домена Active Directory: проверки (снимки), учётные записи и замечания проверки, решения по замечаниям, ручная классификация, события смены и сброса пароля.

Revision ID: 0034_ad_audit
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0034_ad_audit"
down_revision = "0033_bi_aliases_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    json_t = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table(
        "ad_audit_runs",
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True)),
        sa.Column('status', sa.String(10), nullable=False),
        sa.Column('kind', sa.String(10), nullable=False),
        sa.Column('by', sa.String(160), nullable=False),
        sa.Column('period', sa.String(7), nullable=False),
        sa.Column('domain', sa.String(300), nullable=False),
        sa.Column('message', sa.String(1000), nullable=False),
        sa.Column('stats', json_t, nullable=False, server_default="{}"),
        sa.Column('coverage', json_t, nullable=False, server_default="{}"),
        sa.Column('notes', json_t, nullable=False, server_default="[]"),
        sa.Column('policy', json_t, nullable=False, server_default="{}"),
    )
    op.create_index("ix_ad_audit_runs_status", "ad_audit_runs", ['status', 'started_at'])
    op.create_table(
        "ad_audit_accounts",
        sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=True),
        sa.Column('run_id', sa.Uuid(), sa.ForeignKey("ad_audit_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column('guid', sa.String(40), nullable=False),
        sa.Column('sid', sa.String(190), nullable=False),
        sa.Column('login', sa.String(256), nullable=False),
        sa.Column('name', sa.String(300), nullable=False),
        sa.Column('upn', sa.String(300), nullable=False),
        sa.Column('mail', sa.String(300), nullable=False),
        sa.Column('dn', sa.Text(), nullable=False),
        sa.Column('description', sa.String(500), nullable=False),
        sa.Column('title', sa.String(300), nullable=False),
        sa.Column('department', sa.String(300), nullable=False),
        sa.Column('manager', sa.String(300), nullable=False),
        sa.Column('category', sa.String(12), nullable=False),
        sa.Column('category_basis', json_t, nullable=False, server_default="[]"),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('locked', sa.Boolean(), nullable=False),
        sa.Column('pne', sa.Boolean(), nullable=False),
        sa.Column('must_change', sa.Boolean(), nullable=False),
        sa.Column('pwd_expired', sa.Boolean(), nullable=False),
        sa.Column('pwd_last_set', sa.DateTime(timezone=True)),
        sa.Column('pwd_age', sa.Integer()),
        sa.Column('pwd_bucket', sa.String(8), nullable=False),
        sa.Column('expires', sa.DateTime(timezone=True)),
        sa.Column('last_logon', sa.DateTime(timezone=True)),
        sa.Column('last_logon_src', sa.String(6), nullable=False),
        sa.Column('idle_days', sa.Integer()),
        sa.Column('created', sa.DateTime(timezone=True)),
        sa.Column('privileged', json_t, nullable=False, server_default="[]"),
        sa.Column('protected', sa.Boolean()),
        sa.Column('spn', sa.Boolean(), nullable=False),
        sa.Column('workstations', sa.String(300), nullable=False),
        sa.Column('groups', json_t, nullable=False, server_default="[]"),
        sa.Column('pwd_op', json_t, nullable=False, server_default="{}"),
        sa.Column('uac', sa.Integer(), nullable=False),
        sa.Column('findings_n', sa.Integer(), nullable=False),
        sa.Column('max_sev', sa.Integer(), nullable=False),
    )
    op.create_index("ix_ad_audit_accounts_login", "ad_audit_accounts", ['run_id', 'login'])
    op.create_index("ix_ad_audit_accounts_run", "ad_audit_accounts", ['run_id', 'guid'])
    op.create_table(
        "ad_audit_findings",
        sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=True),
        sa.Column('run_id', sa.Uuid(), sa.ForeignKey("ad_audit_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column('key', sa.String(80), nullable=False),
        sa.Column('guid', sa.String(40), nullable=False),
        sa.Column('login', sa.String(256), nullable=False),
        sa.Column('name', sa.String(300), nullable=False),
        sa.Column('category', sa.String(12), nullable=False),
        sa.Column('code', sa.String(24), nullable=False),
        sa.Column('severity', sa.String(10), nullable=False),
        sa.Column('sev_rank', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(10), nullable=False),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('basis', sa.Text(), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('runs_n', sa.Integer(), nullable=False),
    )
    op.create_index("ix_ad_audit_findings_key", "ad_audit_findings", ['run_id', 'key'])
    op.create_index("ix_ad_audit_findings_run", "ad_audit_findings", ['run_id', 'code'])
    op.create_table(
        "ad_audit_decisions",
        sa.Column('key', sa.String(80), primary_key=True),
        sa.Column('guid', sa.String(40), nullable=False),
        sa.Column('code', sa.String(24), nullable=False),
        sa.Column('login', sa.String(256), nullable=False),
        sa.Column('state', sa.String(12), nullable=False),
        sa.Column('comment', sa.Text(), nullable=False),
        sa.Column('owner', sa.String(200), nullable=False),
        sa.Column('due', sa.Date()),
        sa.Column('by', sa.String(160), nullable=False),
        sa.Column('at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('history', json_t, nullable=False, server_default="[]"),
    )
    op.create_table(
        "ad_class_overrides",
        sa.Column('guid', sa.String(40), primary_key=True),
        sa.Column('login', sa.String(256), nullable=False),
        sa.Column('category', sa.String(12), nullable=False),
        sa.Column('note', sa.String(300), nullable=False),
        sa.Column('by', sa.String(160), nullable=False),
        sa.Column('at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "ad_event_imports",
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('by', sa.String(160), nullable=False),
        sa.Column('file_name', sa.String(300), nullable=False),
        sa.Column('events', sa.Integer(), nullable=False),
        sa.Column('added', sa.Integer(), nullable=False),
        sa.Column('skipped', sa.Integer(), nullable=False),
        sa.Column('dcs', json_t, nullable=False, server_default="[]"),
    )
    op.create_table(
        "ad_pwd_events",
        sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=True),
        sa.Column('dc', sa.String(255), nullable=False),
        sa.Column('record_id', sa.BigInteger(), nullable=False),
        sa.Column('kind', sa.String(8), nullable=False),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('target_sid', sa.String(190), nullable=False),
        sa.Column('target', sa.String(256), nullable=False),
        sa.Column('target_domain', sa.String(256), nullable=False),
        sa.Column('by', sa.String(256), nullable=False),
        sa.Column('by_domain', sa.String(256), nullable=False),
        sa.Column('by_sid', sa.String(190), nullable=False),
        sa.Column('import_id', sa.Uuid()),
    )
    op.create_index("ix_ad_pwd_events_target", "ad_pwd_events", ['target_sid', 'at'])
    op.create_index("ux_ad_pwd_events_rec", "ad_pwd_events", ['dc', 'record_id'], unique=True)
    op.create_index("ix_ad_pwd_events_at", "ad_pwd_events", ['kind', 'at'])


def downgrade() -> None:
    op.drop_table("ad_pwd_events")
    op.drop_table("ad_event_imports")
    op.drop_table("ad_class_overrides")
    op.drop_table("ad_audit_decisions")
    op.drop_table("ad_audit_findings")
    op.drop_table("ad_audit_accounts")
    op.drop_table("ad_audit_runs")
