"""Выборки журнала событий и журнала действий с фильтрами страницы: общие для API (таблицы администрирования) и отчётов, чтобы отчёт содержал ровно то, что видно на странице."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import Select, select

from ..models import AuditLog, EventLog, utcnow
from ..search import any_of

SPANS = {"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30}


def journal_stmt(q: str = "", level: str = "", category: str = "", range_: str = "24h", since: datetime | None = None, until: datetime | None = None) -> Select:
    """Журнал событий: текст, уровень («warn» — предупреждения и ошибки), компонент, период (готовый или произвольный since/until)."""
    stmt = select(EventLog)
    if (cond := any_of(q, EventLog.message, EventLog.user, EventLog.event, EventLog.source)) is not None:
        stmt = stmt.where(cond)
    if level == "warn":
        stmt = stmt.where(EventLog.level.in_(("warn", "error")))
    elif level:
        stmt = stmt.where(EventLog.level == level)
    if category:
        stmt = stmt.where(EventLog.category == category)
    if since or until:
        if since:
            stmt = stmt.where(EventLog.at >= since)
        if until:
            stmt = stmt.where(EventLog.at <= until)
    elif span := SPANS.get(range_):
        stmt = stmt.where(EventLog.at >= utcnow() - timedelta(hours=span))
    return stmt


def audit_stmt(q: str = "", action: str = "", since: datetime | None = None, until: datetime | None = None) -> Select:
    """Журнал действий: текст (кто, действие, объект), начало кода действия, период."""
    stmt = select(AuditLog)
    if (cond := any_of(q, AuditLog.actor, AuditLog.action, AuditLog.target_id)) is not None:
        stmt = stmt.where(cond)
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    if since:
        stmt = stmt.where(AuditLog.at >= since)
    if until:
        stmt = stmt.where(AuditLog.at <= until)
    return stmt
