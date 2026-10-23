"""Обновления, откат и резервные копии из веб-интерфейса: backend передаёт запрос помощнику на хосте (scripts/updater.sh)."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_admin
from ..services import updates as upd
from ..services.audit import write_audit

router = APIRouter(prefix="/admin/updates", tags=["admin-updates"])


def channel(request: Request) -> upd.Channel:
    return upd.Channel(f"{request.app.state.settings.data_dir}/updater")


@router.get("")
async def overview(request: Request, su: SessionUser = Depends(require_admin)):
    s = request.app.state.settings
    ch = channel(request)
    st = ch.status()
    remote = ch.remote()
    reasons = []
    if not st["available"]:
        reasons.append("Помощник обновлений на сервере не запущен: выполните на сервере sudo ./scripts/updater.sh install --yes")
    if st.get("state") in upd.BUSY_STATES:
        reasons.append("Сейчас уже выполняется обновление, откат или резервное копирование.")
    if st["request_pending"]:
        reasons.append("Запрос уже передан помощнику и ожидает выполнения.")
    return {"installed": {"version": s.app_version, "commit": s.app_git_commit, "built_at": s.app_built_at},
            "updater": {k: st.get(k) for k in ("available", "heartbeat_age_s", "state", "action", "request_id", "step_no", "step_total", "step_name", "started_at", "finished_at", "exit_code", "result", "request_pending", "by", "target")},
            "remote": remote, "history": ch.history(), "backups": ch.backups(), "can_act": not reasons, "reasons": reasons,
            "commands": {"install": "sudo ./scripts/updater.sh install --yes", "manual": "sudo ./scripts/update.sh", "rollback": "sudo ./scripts/rollback.sh"}}


async def _request(request: Request, su: SessionUser, db: AsyncSession, action: str, target: str = "", details: dict | None = None) -> dict:
    ch = channel(request)
    st = ch.status()
    if not st["available"]:
        raise HTTPException(status_code=409, detail="Помощник обновлений на сервере не запущен — выполните действие на сервере командой из раздела «Обновления»")
    if st.get("state") in upd.BUSY_STATES or st["request_pending"]:
        raise HTTPException(status_code=409, detail="Другое действие уже выполняется или ожидает запуска")
    try:
        rid = ch.request(action, by=su.username, target=target)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"Не удалось передать запрос помощнику ({getattr(exc, 'strerror', None) or exc})") from None
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action=f"system.{action}", target_type="system", target_id=target or action, details={**(details or {}), "request_id": rid})
    await db.commit()
    await request.app.state.journal.emit("system", f"{action}_requested", level="warn", user=su.username, message=f"запрошено: {action} {target}".strip(), data={"request_id": rid})
    return {"request_id": rid}


@router.post("/check")
async def check(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    return await _request(request, su, db, "check")


@router.post("/run")
async def run(request: Request, body: dict = Body(default_factory=dict), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if body.get("confirm") is not True:
        raise HTTPException(status_code=422, detail="Нужно подтверждение (confirm=true)")
    target = str(body.get("target") or "")
    return await _request(request, su, db, "update", target, {"target": target or "latest"})


@router.post("/rollback")
async def rollback(request: Request, body: dict = Body(default_factory=dict), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if body.get("confirm") is not True:
        raise HTTPException(status_code=422, detail="Нужно подтверждение (confirm=true)")
    return await _request(request, su, db, "rollback")


@router.post("/backup")
async def backup(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    return await _request(request, su, db, "backup")


@router.get("/log")
async def log(request: Request, offset: int = Query(0, ge=-1), su: SessionUser = Depends(require_admin)):
    ch = channel(request)
    st = ch.status()
    out = ch.read_log(offset)
    out.update({k: st.get(k) for k in ("state", "action", "step_no", "step_total", "step_name", "exit_code", "result", "finished_at")})
    out["available"] = st["available"]
    return out
