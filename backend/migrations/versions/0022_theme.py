"""Тема оформления в профиле пользователя (одна из четырёх; пусто — тема по умолчанию системы, «Тёмный профессиональный»);
частичный индекс критических уязвимостей KSC в подготовленных данных зон (показатель главной читается по индексу, без чтения всех обнаружений).

Revision ID: 0022_theme
"""
from alembic import op
import sqlalchemy as sa

revision = "0022_theme"
down_revision = "0021_bi"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("theme", sa.String(16), nullable=True))
    op.create_index("ix_zc_det_crit", "zc_detections", ["source_id", "gen", "host_id"], postgresql_include=["vuln_key"],
                    postgresql_where=sa.text("origin = 'ksc' AND severity = 3 AND bucket = 'current'"))


def downgrade() -> None:
    op.drop_index("ix_zc_det_crit", table_name="zc_detections")
    op.drop_column("users", "theme")
