from __future__ import annotations

import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

router = APIRouter(tags=["health"])


@router.get("/health/live")
async def live():
    return {"status": "ok"}


@router.get("/health/ready")
async def ready(request: Request):
    try:
        async with request.app.state.session_maker() as db:
            await asyncio.wait_for(db.execute(text("SELECT 1")), 4)
        pg = {"ok": True}
    except Exception as exc:  # noqa: BLE001
        pg = {"ok": False, "error": type(exc).__name__}
    return JSONResponse({"status": "ready" if pg["ok"] else "unavailable", "postgres": pg}, status_code=200 if pg["ok"] else 503)


@router.get("/version")
async def version(request: Request):
    s = request.app.state.settings
    return {"version": s.app_version, "commit": s.app_git_commit, "built_at": s.app_built_at}
