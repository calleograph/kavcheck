from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, current_source, get_db, require_user
from ..ksc import dashboard as D
from ..ksc import vulns as V
from ..ksc.driver import KscError
from ..models import KscSource, ReportJob

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard")
async def dashboard(request: Request, refresh: bool = False, su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Сводка по выбранному источнику. Показатели берутся из кэша (срок актуальности — настройка); пока данных нет — состояние «не получено»."""
    settings = request.app.state.settings
    general = await request.app.state.settings_svc.get(db, "general")
    key = f"summary:{general.activity_days}"
    data = None if refresh else await D.cached(db, src.id, key, settings.cache_ttl_seconds)
    error = None
    if data is None:
        try:
            payload = await D.summary(request.app.state.sources.client(src), activity_days=general.activity_days, features=(src.last_check or {}).get("features") or {})
            data = await D.store(db, src.id, key, payload)
        except KscError as exc:
            error = exc.message
            data = await D.cached(db, src.id, key, 10**9)   # устаревший кэш лучше пустоты, с пометкой времени
    reports_total = (await db.execute(select(func.count()).select_from(ReportJob).where(ReportJob.source_id == src.id))).scalar_one()
    recent = (await db.execute(select(ReportJob).where(ReportJob.source_id == src.id).order_by(ReportJob.created_at.desc()).limit(5))).scalars().all()
    return {"source": {"id": str(src.id), "name": src.name, "last_check_at": src.last_check_at, "last_check_ok": src.last_check_ok, "ksc_version": (src.last_check or {}).get("ksc_version"),
                       "features": {k: v.get("ok") for k, v in ((src.last_check or {}).get("features") or {}).items()}},
            "summary": data, "error": error, "reports_total": reports_total,
            "recent_reports": [{"id": str(j.id), "title": j.title, "status": j.status, "created_at": j.created_at, "rows": j.rows} for j in recent]}


@router.get("/vulnerabilities")
async def vulnerabilities(request: Request, host: str = Query("", max_length=200), cve: str = Query("", max_length=100), product: str = Query("", max_length=200),
                          severity: int | None = Query(None), offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500),
                          su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source)):
    """Уязвимости, подтверждённые KSC (действующие обнаружения)."""
    feats = (src.last_check or {}).get("features") or {}
    if feats and not feats.get("vulnerabilities", {}).get("ok", True):
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "unsupported": feats["vulnerabilities"].get("missing")}
    try:
        return await V.page(request.app.state.sources.client(src), offset=offset, limit=limit, host=host, cve=cve, product=product, severity=severity)
    except KscError as exc:
        from fastapi import HTTPException  # noqa: PLC0415

        raise HTTPException(status_code=502, detail={"code": exc.code, "message": exc.message}) from None
