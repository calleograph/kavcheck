"""Готовая аналитика из внутренней базы для специалистов с полным доступом."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_admin, require_user
from ..employee_protection import read, service
from ..employee_protection.filters import Filters
from ..inventory.core import access_for
from ..services.audit import write_audit

router = APIRouter(prefix="/employee-protection", tags=["employee-protection"])
DENIED = "Нужны права специалиста по ИБ, доступ ко всем источникам KSC и полная область просмотра инвентаризации и иерархии."


class PageFilters(Filters):
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=500)


async def allowed(request, db, su) -> bool:
    if su.is_admin:
        return True
    if not su.is_security or not su.all_sources:
        return False
    settings = request.app.state.settings_svc
    if su.role not in (await settings.get(db, "hier")).roles:
        return False
    acc = await access_for(db, su, await settings.get(db, "inventory"))
    return acc.can("view") and not acc.scopes


async def require_allowed(request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)) -> None:
    if not await allowed(request, db, su):
        raise HTTPException(status_code=403, detail=DENIED)


@router.get("/access")
async def access(request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    return {"allowed": await allowed(request, db, su), "can_refresh": su.is_admin}


@router.get("/summary", dependencies=[Depends(require_allowed)])
async def summary(filters: Annotated[Filters, Query()], db: AsyncSession = Depends(get_db)):
    return await read.summary(db, filters)


@router.get("/employees", dependencies=[Depends(require_allowed)])
async def employees(filters: Annotated[PageFilters, Query()], db: AsyncSession = Depends(get_db)):
    return await read.page(db, filters, "employees", filters.offset, filters.limit)


@router.get("/devices", dependencies=[Depends(require_allowed)])
async def devices(filters: Annotated[PageFilters, Query()], db: AsyncSession = Depends(get_db)):
    return await read.page(db, filters, "devices", filters.offset, filters.limit)


@router.post("/refresh", status_code=202)
async def refresh(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    queued = await service.queue(db)
    if queued:
        write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="employee_protection.refresh", target_type="employee_protection", target_id="snapshot")
        await db.commit()
    return {"queued": queued}
