"""0.2.0: несколько подключений LDAPS, доверенные сертификаты, правила доступа по группам, второй фактор (TOTP), пульс служб.

Прежние настройки LDAP (группа app_settings «ldap») переносятся в новые таблицы при запуске приложения (services/ldap_store.migrate_legacy):
для этого нужен APP_MASTER_KEY, которого у миграции может не быть.

Revision ID: 0003_ldap_2fa_system
Revises: 0002_catalog_audit
Create Date: 2026-10-24
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003_ldap_2fa_system"
down_revision = "0002_catalog_audit"
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
BIGPK = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    with op.batch_alter_table("users") as b:
        b.add_column(sa.Column("ldap_connection_id", sa.Uuid()))
        b.add_column(sa.Column("ldap_groups", JSONB))
        b.add_column(sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))
        b.add_column(sa.Column("totp_secret_enc", sa.Text()))
        b.add_column(sa.Column("totp_last_step", sa.BigInteger()))
        b.add_column(sa.Column("totp_enabled_at", sa.DateTime(timezone=True)))
    with op.batch_alter_table("sessions") as b:
        b.add_column(sa.Column("must_totp", sa.Boolean(), nullable=False, server_default=sa.text("false")))
        b.add_column(sa.Column("second_factor", sa.String(16)))
    op.create_table("user_backup_codes",
        sa.Column("id", BIGPK, primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("code_hash", sa.String(64), nullable=False), sa.Column("used_at", sa.DateTime(timezone=True)))
    op.create_table("auth_challenges",
        sa.Column("key", sa.String(64), primary_key=True), sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("data", JSONB), sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("ldap_connections",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("name", sa.String(120), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False), sa.Column("is_primary", sa.Boolean(), nullable=False),
        sa.Column("protocol", sa.String(10), nullable=False), sa.Column("host", sa.String(253), nullable=False), sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("ldap_version", sa.Integer(), nullable=False), sa.Column("timeout_s", sa.Integer(), nullable=False),
        sa.Column("base_dn", sa.String(500), nullable=False), sa.Column("domain_dns", sa.String(253), nullable=False), sa.Column("netbios", sa.String(64), nullable=False),
        sa.Column("bind_dn", sa.String(500), nullable=False), sa.Column("bind_password_enc", sa.Text()),
        sa.Column("login_attribute", sa.String(64), nullable=False), sa.Column("display_name_attribute", sa.String(64), nullable=False),
        sa.Column("email_attribute", sa.String(64), nullable=False), sa.Column("user_filter", sa.String(1000), nullable=False),
        sa.Column("nested_groups", sa.Boolean(), nullable=False), sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("last_check_at", sa.DateTime(timezone=True)), sa.Column("last_check_ok", sa.Boolean()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True)))
    op.create_table("ca_certificates",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("label", sa.String(200), nullable=False),
        sa.Column("subject", sa.String(1000), nullable=False), sa.Column("issuer", sa.String(1000), nullable=False), sa.Column("serial", sa.String(100), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False, unique=True), sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False), sa.Column("is_ca", sa.Boolean(), nullable=False), sa.Column("self_signed", sa.Boolean(), nullable=False),
        sa.Column("pem", sa.Text(), nullable=False), sa.Column("added_by", sa.String(300)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("access_rules",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("connection_id", sa.Uuid(), sa.ForeignKey("ldap_connections.id", ondelete="CASCADE")),
        sa.Column("group_dn", sa.String(1000), nullable=False), sa.Column("role", sa.String(16), nullable=False),
        sa.Column("all_sources", sa.Boolean(), nullable=False), sa.Column("source_ids", JSONB), sa.Column("note", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("service_heartbeats",
        sa.Column("name", sa.String(40), primary_key=True), sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)), sa.Column("data", JSONB))


def downgrade() -> None:
    for t in ("service_heartbeats", "access_rules", "ca_certificates", "ldap_connections", "auth_challenges", "user_backup_codes"):
        op.drop_table(t)
    with op.batch_alter_table("sessions") as b:
        b.drop_column("second_factor")
        b.drop_column("must_totp")
    with op.batch_alter_table("users") as b:
        for c in ("totp_enabled_at", "totp_last_step", "totp_secret_enc", "totp_enabled", "ldap_groups", "ldap_connection_id"):
            b.drop_column(c)
