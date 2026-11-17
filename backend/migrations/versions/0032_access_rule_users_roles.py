"""Правила доступа для отдельных учётных записей (access_rules.kind); раздел «Иерархия» по умолчанию открыт всем ролям.

Revision ID: 0032_access_rule_users_roles
"""
import json

from alembic import op
import sqlalchemy as sa

revision = "0032_access_rule_users_roles"
down_revision = "0031_zone_access"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("access_rules", sa.Column("kind", sa.String(8), nullable=False, server_default="group"))
    # структура организации — всем ролям: прежнее значение по умолчанию (аналитик и администратор) расширяется; осознанно изменённый список не трогаем
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    row = bind.execute(sa.text('SELECT value FROM app_settings WHERE "group" = \'hier\'')).first()
    if row is not None:
        val = row[0] if isinstance(row[0], dict) else json.loads(row[0] or "{}")
        if sorted(val.get("roles") or []) == ["admin", "analyst"]:
            val["roles"] = ["viewer", "analyst", "security", "admin"]
            bind.execute(sa.text('UPDATE app_settings SET value = CAST(:v AS jsonb) WHERE "group" = \'hier\''), {"v": json.dumps(val)})


def downgrade() -> None:
    op.drop_column("access_rules", "kind")
