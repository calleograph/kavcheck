"""Реестр компонентов (Администрирование) и сведения об инструментах сканирования (Pentest → Обзор)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_admin
from ..services import components as C
from ..services.audit import write_audit

router = APIRouter(prefix="/admin/components", tags=["admin-components"])


@router.get("")
async def overview(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    return await C.table(db, request.app.state.settings)


@router.post("/check", status_code=202)
async def check_now(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Запрос проверки доступных версий: выполняет worker в течение минуты (страница внешних сервисов не опрашивает)."""
    await C.set_state(request.app.state.session_maker, requested=True)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="components.check", target_type="components", target_id="all", details={})
    await db.commit()
    return {"requested": True}


@router.get("/{key}")
async def one(key: str, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    t = await C.table(db, request.app.state.settings)
    row = next((r for r in t["items"] if r["key"] == key), None)
    if row is None:
        raise HTTPException(status_code=404, detail="Компонент не найден")
    return {**row, "reviewed_for": t["reviewed_for"], "reviewed_at": t["reviewed_at"]}
