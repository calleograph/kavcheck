"""FastAPI-зависимости: сессия, роли, CSRF, IP клиента, доступ к источникам KSC."""
from __future__ import annotations

import hmac
import ipaddress
import logging
import re
import uuid
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, origin_allowed
from ..models import KscSource, Session, User

log = logging.getLogger("app.auth")
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_ALLOWED_WHILE_CHANGING = {"/api/v1/auth/me", "/api/v1/auth/logout", "/api/v1/auth/change-password"}
_IP_RE = re.compile(r"^[0-9a-fA-F:.]{2,45}$")
ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


@dataclass(frozen=True)
class SessionUser:
    session_id: str
    user_id: uuid.UUID
    username: str
    display_name: str
    role: str
    csrf: str
    local: bool
    must_change: bool
    all_sources: bool
    source_ids: frozenset[str]
    current_source_id: uuid.UUID | None

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def can_use_source(self, source_id: uuid.UUID) -> bool:
        return self.is_admin or self.all_sources or str(source_id) in self.source_ids

    @classmethod
    def build(cls, sid: str, s: Session, u: User) -> "SessionUser":
        return cls(sid, u.id, u.username, u.display_name, u.role, s.csrf, u.auth_source == "local", u.must_change_password, u.all_sources,
                   frozenset(str(x) for x in (u.source_ids or [])), s.current_source_id)


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


async def get_db(request: Request):
    async with request.app.state.session_maker() as session:
        yield session


def pick_client_ip(xff: str, peer: str | None, hops: int = 1) -> str:
    chain = [p.strip() for p in (xff or "").split(",") if p.strip() and _IP_RE.match(p.strip())]
    valid = []
    for p in chain:
        try:
            ipaddress.ip_address(p)
            valid.append(p)
        except ValueError:
            continue
    if not valid:
        return peer or "unknown"
    return valid[-hops] if len(valid) >= hops else valid[0]


def client_ip(request: Request) -> str:
    settings: Settings = request.app.state.settings
    return pick_client_ip(request.headers.get("x-forwarded-for", ""), request.client.host if request.client else None, settings.trusted_proxy_hops)


def _origin_ok(request: Request) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        return True
    if origin_allowed(origin, request.app.state.settings):
        return True
    log.warning("Origin отклонён", extra={"origin": origin[:200], "path": request.url.path})
    return False


async def current_session(request: Request, db: AsyncSession = Depends(get_db)) -> SessionUser | None:
    settings: Settings = request.app.state.settings
    sid = request.cookies.get(settings.cookie_name)
    got = await request.app.state.sessions.get(db, sid)
    if got is None or sid is None:
        return None
    return SessionUser.build(sid, got[0], got[1])


async def require_user(request: Request, su: SessionUser | None = Depends(current_session)) -> SessionUser:
    if su is None:
        raise HTTPException(status_code=401, detail="Требуется вход")
    if su.must_change and request.url.path not in _ALLOWED_WHILE_CHANGING:
        raise HTTPException(status_code=403, detail={"code": "password_change_required", "message": "Сначала смените пароль."})
    if request.method not in _SAFE_METHODS:
        if not _origin_ok(request):
            raise HTTPException(status_code=403, detail="Недопустимый Origin")
        token = request.headers.get("x-csrf-token", "")
        if not token or not hmac.compare_digest(token, su.csrf):
            raise HTTPException(status_code=403, detail="Неверный CSRF-токен")
    return su


async def require_analyst(su: SessionUser = Depends(require_user)) -> SessionUser:
    if ROLE_RANK.get(su.role, 0) < ROLE_RANK["analyst"]:
        raise HTTPException(status_code=403, detail="Нужны права аналитика")
    return su


async def require_admin(su: SessionUser = Depends(require_user)) -> SessionUser:
    if not su.is_admin:
        raise HTTPException(status_code=403, detail="Требуются права администратора")
    return su


async def current_source(request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)) -> KscSource:
    """Выбранный в сессии источник KSC (проверка права доступа — на каждом запросе). Заголовок X-Source-Id имеет приоритет над сессией."""
    raw = request.headers.get("x-source-id") or (str(su.current_source_id) if su.current_source_id else "")
    try:
        sid = uuid.UUID(raw)
    except ValueError:
        raise HTTPException(status_code=409, detail={"code": "no_source", "message": "Источник KSC не выбран."}) from None
    src = await db.get(KscSource, sid)
    if src is None or not src.is_active:
        raise HTTPException(status_code=409, detail={"code": "no_source", "message": "Источник не найден или выключен."})
    if not su.can_use_source(src.id):
        raise HTTPException(status_code=403, detail="Нет доступа к этому источнику KSC")
    return src
