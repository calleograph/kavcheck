"""Оценки CVSS: все оценки записи с версией методики, источником и датой (vdb_records.scores), основная оценка сводки (версия и источник).

Существующие записи получают оценки при первом запуске воркера (VdbSync.upgrade_scores), а отсутствующие у NVD — дозагружаются при ближайшей загрузке источника.

Revision ID: 0006_cvss_scores
Revises: 0005_vuln_db
Create Date: 2026-10-25
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0006_cvss_scores"
down_revision = "0005_vuln_db"
branch_labels = None
depends_on = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("vdb_records", sa.Column("scores", JSONB, nullable=False, server_default="[]"))
    op.add_column("vdb_records", sa.Column("scores_at", sa.DateTime(timezone=True)))
    op.add_column("vdb_vulns", sa.Column("score_version", sa.String(4), nullable=False, server_default=""))
    op.add_column("vdb_vulns", sa.Column("score_source", sa.String(16), nullable=False, server_default=""))
    op.create_index("ix_vdb_vulns_score", "vdb_vulns", ["score"])


def downgrade() -> None:
    op.drop_index("ix_vdb_vulns_score", table_name="vdb_vulns")
    op.drop_column("vdb_vulns", "score_source")
    op.drop_column("vdb_vulns", "score_version")
    op.drop_column("vdb_records", "scores_at")
    op.drop_column("vdb_records", "scores")
