"""Аудит домена: подразделение (OU) учётной записи — для отбора, группировки и отчётов. Сохранённые проверки заполняются по DN.

Revision ID: 0039_adaudit_ou
"""
import re

from alembic import op
import sqlalchemy as sa

revision = "0039_adaudit_ou"
down_revision = "0038_lic_key_ref"
branch_labels = None
depends_on = None


def _ou(dn: str) -> str:            # копия app.ad.filters.ou_path: миграция не зависит от кода приложения
    parts = re.findall(r"(?:\\.|[^,])+", dn)[1:]
    return "/".join(re.sub(r"\\(.)", r"\1", p.split("=", 1)[1]).strip() for p in reversed(parts) if "=" in p and not p.strip().lower().startswith("dc="))[:1000]


def upgrade() -> None:
    op.add_column("ad_audit_accounts", sa.Column("ou", sa.String(1000), nullable=False, server_default=""))
    conn = op.get_bind()
    last = 0
    while True:                                                    # порциями по id: проверки бывают по сотням тысяч учётных записей
        rows = conn.execute(sa.text("SELECT id, dn FROM ad_audit_accounts WHERE id > :last ORDER BY id LIMIT 5000"), {"last": last}).all()
        if not rows:
            break
        last = rows[-1][0]
        upd = [{"i": i, "ou": _ou(dn or "")} for i, dn in rows if dn]
        if upd:
            conn.execute(sa.text("UPDATE ad_audit_accounts SET ou = :ou WHERE id = :i"), upd)


def downgrade() -> None:
    op.drop_column("ad_audit_accounts", "ou")
