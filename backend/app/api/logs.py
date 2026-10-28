"""Журналы и хранение (Администрирование): реестр журналов, настройки ротации, архивы, квота. Только для администратора: обычные пользователи видят журналы, но не меняют хранение."""
from __future__ import annotations

import re
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_admin
from ..services import retention as R
from ..services.audit import write_audit
from ..services.settings import SettingsError
from ..models import utcnow

router = APIRouter(prefix="/admin/logs", tags=["admin-logs"])


@router.get("")
async def overview(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    s = request.app.state.settings
    cfg = await request.app.state.settings_svc.get(db, "logs")
    d = R.archive_dir(s.reports_dir)
    arcs = R.list_archives(d)
    items = []
    for key, t in R.TYPES.items():
        st = await R.table_stats(db, key)
        a = [x for x in arcs if x["type"] == key]
        items.append({"key": key, "title": t["title"], "owner": t["owner"], "location": t["location"], "format": t["format"], "purpose": t["purpose"], "kind": t["kind"], "tab": t["tab"],
                      "days": getattr(cfg, t["days"]), "max_mb": getattr(cfg, t["max"]), "archive": True if key == "audit" else bool(getattr(cfg, t["archive"])),
                      "mandatory": key == "audit", "rows": st["rows"], "bytes": st["bytes"], "oldest": st["oldest"], "archives": len(a), "archive_bytes": sum(x["bytes"] for x in a)})
    state = await R.get_state(request.app.state.session_maker)
    used = sum(i["bytes"] + i["archive_bytes"] for i in items)
    return {"items": items, "external": R.EXTERNAL, "settings": cfg.model_dump(), "archives": sorted(arcs, key=lambda a: a["at"], reverse=True)[:500],
            "totals": {"logs_bytes": sum(i["bytes"] for i in items), "archive_bytes": sum(x["bytes"] for x in arcs), "files": len(arcs), "quota_bytes": cfg.quota_mb * 1048576 if cfg.quota_mb else None, "used_bytes": used,
                       "oldest": min([i["oldest"] for i in items if i["oldest"]], default=None)},
            "disk": R.disk_info(s.reports_dir, cfg.disk_warn_free_mb), "last_run": state.get("last_run"), "next_run": state.get("next_run"), "requested": bool(state.get("requested")), "report": state.get("last_report")}


@router.put("/settings")
async def save(request: Request, body: dict, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    try:
        changed = await request.app.state.settings_svc.update(db, "logs", body, actor=su.display_name)
    except SettingsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="logs.settings", target_type="settings", target_id="logs", details={"changed": changed})
    await db.commit()
    return {"changed": changed}


@router.post("/run", status_code=202)
async def run_now(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Запрос ротации: её выполняет worker в течение минуты."""
    await R.set_state(request.app.state.session_maker, requested=True)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="logs.run", target_type="settings", target_id="logs", details={})
    await db.commit()
    return {"requested": True}


def _path(request: Request, name: str):
    if not R.ARCHIVE_RE.match(name):
        raise HTTPException(status_code=404, detail="Архив не найден")
    p = R.archive_dir(request.app.state.settings.reports_dir) / name
    if not p.is_file():
        raise HTTPException(status_code=404, detail="Архив не найден")
    return p


@router.get("/archives/{name}")
async def download(name: str, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    p = _path(request, name)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="logs.archive_download", target_type="log_archive", target_id=name, details={})
    await db.commit()
    return FileResponse(p, media_type="application/gzip" if name.endswith(".gz") else "application/x-ndjson", filename=name)


@router.delete("/archives/{name}", status_code=204)
async def remove(name: str, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    p = _path(request, name)
    if name.startswith("audit-") and (await request.app.state.settings_svc.get(db, "logs")).audit_days == 0:
        raise HTTPException(status_code=409, detail="Архивы журнала действий не удаляются, пока срок его хранения не ограничен")
    p.unlink()
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="logs.archive_delete", target_type="log_archive", target_id=name, details={})
    await db.commit()
