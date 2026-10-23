"""0.2.0: каталог продуктов, проверки версий по нескольким источникам, источник пользователя, порог активности 30 суток.

Revision ID: 0002_catalog_audit
Revises: 0001_initial
Create Date: 2026-10-24
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_catalog_audit"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("users", sa.Column("current_source_id", sa.Uuid()))

    # отчёты: несколько источников; удаление источника не удаляет отчёт по нескольким источникам
    with op.batch_alter_table("report_jobs") as b:
        b.add_column(sa.Column("source_ids", JSONB))
        b.alter_column("source_id", existing_type=sa.Uuid(), nullable=True)
        b.alter_column("source_name", existing_type=sa.String(120), type_=sa.String(600))
    if op.get_bind().dialect.name == "postgresql":
        op.drop_constraint("report_jobs_source_id_fkey", "report_jobs", type_="foreignkey")
        op.create_foreign_key("report_jobs_source_id_fkey", "report_jobs", "ksc_sources", ["source_id"], ["id"], ondelete="SET NULL")
    op.execute("UPDATE report_jobs SET source_ids = json_build_array(source_id::text)::jsonb WHERE source_id IS NOT NULL" if op.get_bind().dialect.name == "postgresql"
               else "UPDATE report_jobs SET source_ids = json_array(source_id) WHERE source_id IS NOT NULL")

    # сохранённые проверки версий (прежние сценарии остаются с kind = legacy)
    with op.batch_alter_table("audit_checks") as b:
        b.add_column(sa.Column("kind", sa.String(20), nullable=False, server_default="legacy"))
        b.add_column(sa.Column("params", JSONB))
        b.add_column(sa.Column("source_ids", JSONB))
        b.add_column(sa.Column("owner_id", sa.Uuid()))
        b.add_column(sa.Column("shared", sa.Boolean(), nullable=False, server_default=sa.text("true")))
        b.add_column(sa.Column("updated_at", sa.DateTime(timezone=True)))
        b.add_column(sa.Column("last_run_at", sa.DateTime(timezone=True)))
        b.add_column(sa.Column("last_job_id", sa.Uuid()))
        b.alter_column("source_id", existing_type=sa.Uuid(), nullable=True)
        b.alter_column("selection", existing_type=JSONB, nullable=True)

    op.create_table("catalog_products",
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("key", sa.String(160), primary_key=True),
        sa.Column("name", sa.String(300), nullable=False), sa.Column("publisher", sa.String(300), nullable=False),
        sa.Column("publisher_key", sa.String(160), nullable=False, index=True), sa.Column("origin", sa.String(10), nullable=False),
        sa.Column("component", sa.Boolean(), nullable=False), sa.Column("platforms", sa.Integer(), nullable=False), sa.Column("note", sa.Text()),
        sa.Column("names", JSONB, nullable=False), sa.Column("versions", JSONB, nullable=False), sa.Column("branches", JSONB, nullable=False),
        sa.Column("versions_count", sa.Integer(), nullable=False), sa.Column("latest_version", sa.String(200), nullable=False),
        sa.Column("scheme", sa.String(10), nullable=False), sa.Column("transform", sa.String(20)),
        sa.Column("hosts_all", sa.Integer(), nullable=False), sa.Column("hosts_active", sa.Integer(), nullable=False),
        sa.Column("installs_all", sa.Integer(), nullable=False), sa.Column("installs_active", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True)), sa.Column("search", sa.Text(), nullable=False),
        sa.Column("built_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_catalog_products_hosts", "catalog_products", ["source_id", "hosts_active"])
    op.create_table("catalog_state",
        sa.Column("source_id", sa.Uuid(), sa.ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("status", sa.String(12), nullable=False), sa.Column("built_at", sa.DateTime(timezone=True)), sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("requested_at", sa.DateTime(timezone=True)), sa.Column("checked_at", sa.DateTime(timezone=True)), sa.Column("signature", sa.String(200)),
        sa.Column("activity_days", sa.Integer()), sa.Column("overrides_rev", sa.String(64)), sa.Column("progress", sa.String(300)), sa.Column("error", sa.Text()),
        sa.Column("stats", JSONB), sa.Column("duration_ms", sa.Integer()))
    op.create_table("catalog_overrides",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("kind", sa.String(10), nullable=False), sa.Column("from_key", sa.String(160)),
        sa.Column("match_name", sa.String(300)), sa.Column("to_key", sa.String(160), nullable=False), sa.Column("to_name", sa.String(300)),
        sa.Column("to_publisher", sa.String(300)), sa.Column("note", sa.Text()), sa.Column("created_by", sa.String(300)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))

    # порог активности: 7 суток (значение по умолчанию 0.1.0) → 30 суток (глобальный фильтр «Показывать компьютеры, активные за последние»)
    if op.get_bind().dialect.name == "postgresql":
        op.execute("""UPDATE app_settings SET value = jsonb_set(value::jsonb, '{activity_days}', '30')
                      WHERE "group" = 'general' AND (value::jsonb ->> 'activity_days') = '7'""")


def downgrade() -> None:
    op.drop_table("catalog_overrides")
    op.drop_table("catalog_state")
    op.drop_index("ix_catalog_products_hosts", table_name="catalog_products")
    op.drop_table("catalog_products")
    op.execute("DELETE FROM audit_checks WHERE kind <> 'legacy'")
    with op.batch_alter_table("audit_checks") as b:
        for c in ("kind", "params", "source_ids", "owner_id", "shared", "updated_at", "last_run_at", "last_job_id"):
            b.drop_column(c)
    op.execute("DELETE FROM report_jobs WHERE source_id IS NULL")
    if op.get_bind().dialect.name == "postgresql":
        op.drop_constraint("report_jobs_source_id_fkey", "report_jobs", type_="foreignkey")
        op.create_foreign_key("report_jobs_source_id_fkey", "report_jobs", "ksc_sources", ["source_id"], ["id"], ondelete="CASCADE")
    with op.batch_alter_table("report_jobs") as b:
        b.drop_column("source_ids")
    op.drop_column("users", "current_source_id")
