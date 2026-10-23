"""События безопасности: сводка за период (кэш) и постраничный список с фильтрами."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request

from ..auth.deps import SessionUser, current_source, require_user
from ..ksc import events as E
from ..ksc.driver import KscError
from ..models import KscSource
from .vulns import _ksc, unsupported

router = APIRouter(prefix="/events", tags=["events"])
DAYS = Query(7, ge=1, le=90)


@router.get("/summary")
async def summary(request: Request, days: int = DAYS, refresh: bool = False, su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source)):
    miss = unsupported(src, "events")
    if miss:
        return {"unsupported": miss}
    client = request.app.state.sources.client(src)
    try:
        data, at = await request.app.state.cache.get((str(src.id), "events", days), request.app.state.settings.cache_ttl_seconds,
                                                     lambda: E.summary(client, days=days), refresh=refresh)
    except KscError as exc:
        raise _ksc(exc) from None
    return {**data, "fetched_at": datetime.fromtimestamp(at, timezone.utc)}


@router.get("")
async def events(request: Request, days: int = DAYS, type_: str = Query("", alias="type", max_length=200), host_id: int | None = Query(None, ge=1),
                 q_: str = Query("", alias="q", max_length=200), threat: str = Query("", max_length=300), offset: int = Query(0, ge=0, le=100_000),
                 limit: int = Query(50, ge=1, le=200), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source)):
    """События обнаружений за период: новые сверху. type — ключи из ksc.events.TYPES через запятую, threat — точное имя угрозы или атаки."""
    miss = unsupported(src, "events")
    if miss:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "unsupported": miss}
    try:
        return await E.page(request.app.state.sources.client(src), days=days, types=[t.strip() for t in type_.split(",") if t.strip()], host_id=host_id, qtext=q_, threat=threat, offset=offset, limit=limit)
    except KscError as exc:
        raise _ksc(exc) from None
