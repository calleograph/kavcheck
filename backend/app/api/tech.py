"""Администрирование → «Техническое состояние»: сводка исправности, ресурсы, службы, задания, PostgreSQL, источники, компоненты; диагностический отчёт.
Только чтение и только администратору: команд ОС, произвольного SQL, перезапуска служб и снятия заданий здесь нет."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_admin
from ..services.audit import write_audit
from ..tech import collect as TC
from ..tech import report as TR

router = APIRouter(prefix="/admin/tech", tags=["admin-tech"])


@router.get("")
async def state(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    data, at = await TC.cached(request.app, db)
    return {**data, "cached_at": at}


@router.post("/refresh")
async def refresh(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Пересчитать сводку сейчас (PostgreSQL и проверка web — заново). Не чаще раза в 10 с; одновременные нажатия ждут один расчёт."""
    data, at = await TC.cached(request.app, db, refresh=True)
    return {**data, "cached_at": at}


@router.get("/report")
async def report(request: Request, fmt: Literal["json", "txt", "html"] = Query("html", alias="format"), external: bool = False,
                 su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    data, _ = await TC.cached(request.app, db)
    rep = TR.build(data, external=external)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="tech.report", target_type="system", target_id="tech", details={"format": fmt, "external": external})
    await db.commit()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    body, media = ((TR.to_text(rep), "text/plain; charset=utf-8") if fmt == "txt" else (TR.to_html(rep), "text/html; charset=utf-8") if fmt == "html"
                   else (json.dumps(rep, ensure_ascii=False, indent=1), "application/json"))
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="kavcheck-diagnostics-{stamp}{"-external" if external else ""}.{fmt}"', "Cache-Control": "no-store"})
