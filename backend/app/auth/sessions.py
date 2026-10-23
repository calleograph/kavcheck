"""Серверные сессии во внутренней базе. В cookie — только случайный идентификатор; в таблице — его sha256."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings
from ..models import Session, User, utcnow


def _key(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


class SessionStore:
    def __init__(self, settings: Settings):
        self._s = settings

    async def create(self, db: AsyncSession, user: User, *, ip: str, ua: str) -> str:
        sid = secrets.token_urlsafe(32)
        db.add(Session(key=_key(sid), user_id=user.id, csrf=secrets.token_urlsafe(24), ip=ip[:64], user_agent=ua[:300]))
        await db.commit()
        return sid

    async def get(self, db: AsyncSession, session_id: str | None) -> tuple[Session, User] | None:
        if not session_id or len(session_id) > 200:
            return None
        row = (await db.execute(select(Session, User).join(User, User.id == Session.user_id).where(Session.key == _key(session_id)))).first()
        if row is None:
            return None
        sess, user = row
        now = utcnow()
        if now - sess.created_at > timedelta(seconds=self._s.session_absolute_timeout_seconds) or now - sess.last_seen > timedelta(seconds=self._s.session_idle_timeout_seconds) or not user.is_active:
            await db.execute(delete(Session).where(Session.key == sess.key))
            await db.commit()
            return None
        if (now - sess.last_seen).total_seconds() > 30:
            await db.execute(update(Session).where(Session.key == sess.key).values(last_seen=now))
            await db.commit()
        return sess, user

    async def set_source(self, db: AsyncSession, session_id: str, source_id: uuid.UUID | None) -> None:
        await db.execute(update(Session).where(Session.key == _key(session_id)).values(current_source_id=source_id))
        await db.commit()

    async def destroy(self, db: AsyncSession, session_id: str | None) -> None:
        if session_id:
            await db.execute(delete(Session).where(Session.key == _key(session_id)))
            await db.commit()

    async def destroy_user(self, db: AsyncSession, user_id: uuid.UUID, *, keep: str | None = None) -> int:
        stmt = delete(Session).where(Session.user_id == user_id)
        if keep:
            stmt = stmt.where(Session.key != _key(keep))
        n = (await db.execute(stmt)).rowcount
        await db.commit()
        return n

    async def purge_expired(self, db: AsyncSession) -> int:
        now = utcnow()
        n = (await db.execute(delete(Session).where((Session.last_seen < now - timedelta(seconds=self._s.session_idle_timeout_seconds))
                                                   | (Session.created_at < now - timedelta(seconds=self._s.session_absolute_timeout_seconds))))).rowcount
        await db.commit()
        return n
