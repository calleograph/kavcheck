"""Роли KAV Checker по возрастанию возможностей. zone — ответственный за зону (портал своих зон, zones/portal.py)."""
ROLE_RANK = {"zone": 0, "viewer": 1, "analyst": 2, "security": 3, "admin": 4}
ROLE_RU = {"zone": "ответственный за зону", "viewer": "просмотр", "analyst": "аналитик", "security": "специалист по ИБ", "admin": "администратор"}
ASSIGNABLE = ("viewer", "analyst", "security", "admin")           # роли, которые назначаются правилами и локальным пользователям
ROLE_PATTERN = r"^(" + "|".join(ASSIGNABLE) + r")$"
