"""Журнал действий пользователей (audit_log) и журнал событий (event_log). Секреты в подробности не попадают (scrub)."""
from __future__ import annotations

import contextvars
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..logging_setup import request_id_var, scrub
from ..models import AuditLog, EventLog, utcnow

log = logging.getLogger("app.audit")
audit_ctx: contextvars.ContextVar[dict[str, str | None]] = contextvars.ContextVar("audit_ctx", default={})


def _rid() -> str | None:
    rid = request_id_var.get()
    return None if rid == "-" else rid


def write_audit(db: AsyncSession, *, actor_user_id, actor: str, action: str, target_type: str, target_id: str, details: dict | None = None,
                source_id=None, result: str = "success", duration_ms: int | None = None) -> None:
    ctx = audit_ctx.get()
    db.add(AuditLog(at=utcnow(), actor_user_id=actor_user_id, actor=actor[:300], action=action, target_type=target_type, target_id=str(target_id)[:200],
                    source_id=source_id, details=scrub(details or {}), result=result if result in ("success", "denied", "failure") else "failure",
                    ip=ctx.get("ip"), duration_ms=duration_ms, request_id=_rid()))


class Journal:
    """Запись событий отдельной короткой транзакцией: сбой журнала не ломает запрос."""

    def __init__(self, session_maker: async_sessionmaker[AsyncSession]):
        self._sm = session_maker

    async def emit(self, category: str, event: str, *, level: str = "info", user: str | None = None, source: str | None = None, message: str | None = None,
                   data: dict | None = None, duration_ms: int | None = None, ip: str | None = None) -> None:
        ctx = audit_ctx.get()
        try:
            async with self._sm() as db:
                db.add(EventLog(at=utcnow(), level=level if level in ("debug", "info", "warn", "error") else "info", category=category[:24], event=event[:64],
                                user=(user or "")[:256] or None, source=(source or "")[:120] or None, message=(message or "")[:600] or None,
                                data=scrub(data) if data else None, duration_ms=duration_ms, ip=ip or ctx.get("ip"), request_id=_rid()))
                await db.commit()
        except Exception:  # noqa: BLE001
            log.warning("Не удалось записать событие журнала", extra={"event": event})


async def audit_now(session_maker: async_sessionmaker[AsyncSession], **kw: Any) -> None:
    """Запись аудита в отдельной транзакции (для отказов, после которых запрос завершается исключением)."""
    try:
        async with session_maker() as db:
            write_audit(db, **kw)
            await db.commit()
    except Exception:  # noqa: BLE001
        log.exception("Не удалось записать событие аудита", extra={"action": kw.get("action")})
