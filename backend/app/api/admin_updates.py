"""Обновления, откат и резервные копии из веб-интерфейса: backend передаёт запрос помощнику на хосте (scripts/updater.sh)."""
from __future__ import annotations

import time

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
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
    reasons = []      # одна понятная причина, без противоречий: недоступен помощник ИЛИ идёт операция ИЛИ запрос ждёт
    if not st["available"]:
        reasons.append(st["down_reason"])
    elif st.get("state") in upd.BUSY_STATES:
        reasons.append("Сейчас выполняется обновление, откат или резервное копирование — дождитесь завершения.")
    elif st["request_pending"]:
        reasons.append("Запрос уже передан помощнику и ожидает выполнения.")
    return {"installed": {"version": s.app_version, "commit": s.app_git_commit, "built_at": s.app_built_at},
            "updater": {k: st.get(k) for k in ("available", "heartbeat_age_s", "state", "action", "request_id", "step_no", "step_total", "step_name", "started_at", "finished_at", "exit_code", "result", "request_pending", "by", "target",
                                               "last_output_at", "stalled_s", "interrupted", "api_outdated", "updater_api", "mode", "op_id", "phase", "down_reason", "boot_changed", "helper_pid", "operation_alive")} | {"api_expected": upd.UPDATER_API, "now": int(time.time())},
            "system": {k: (ch._json("system.json") or {}).get(k) for k in ("update_mode", "registry", "allow_build", "npm_mirror", "pip_mirror", "helper_unit")},  # noqa: SLF001
            "remote": remote, "history": ch.history(), "backups": ch.backups(), "can_act": not reasons, "reasons": reasons,
            "preflight": ch.preflight(), "report": ch.report(), "doctor": ch.doctor(),
            "commands": {"install": "sudo ./scripts/updater.sh install --yes", "manual": "sudo ./scripts/update.sh", "rollback": "sudo ./scripts/rollback.sh"}}


async def _request(request: Request, su: SessionUser, db: AsyncSession, action: str, target: str = "", details: dict | None = None, mode: str = "") -> dict:
    ch = channel(request)
    st = ch.status()
    if not st["available"]:
        raise HTTPException(status_code=409, detail="Помощник обновлений на сервере не запущен — выполните действие на сервере командой из раздела «Обновления»")
    if st.get("state") in upd.BUSY_STATES or st["request_pending"]:
        raise HTTPException(status_code=409, detail="Другое действие уже выполняется или ожидает запуска")
    try:
        rid = ch.request(action, by=su.username, target=target, mode=mode)
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
    mode = str(body.get("mode") or "")
    if mode not in ("", "pull", "build"):
        raise HTTPException(status_code=422, detail="Способ обновления: pull или build")
    if mode == "build" and body.get("confirm_build") is not True:
        raise HTTPException(status_code=422, detail="Локальная сборка долгая и требует доступа к npm, pip и Docker Hub: нужно отдельное подтверждение (confirm_build=true)")
    return await _request(request, su, db, "update", target, {"target": target or "latest", "mode": mode or "pull"}, mode=mode)


@router.post("/rollback")
async def rollback(request: Request, body: dict = Body(default_factory=dict), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if body.get("confirm") is not True:
        raise HTTPException(status_code=422, detail="Нужно подтверждение (confirm=true)")
    return await _request(request, su, db, "rollback")


@router.post("/preflight")
async def preflight(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Проверки перед обновлением: свободное место, доступность GitHub и реестра образов (или npm/pip при локальной сборке), состояние базы, возможность отката."""
    return await _request(request, su, db, "preflight")


@router.post("/restore")
async def restore(request: Request, body: dict = Body(default_factory=dict), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Восстановление внутренней базы из резервной копии — изменяет пользовательские данные, поэтому требует ввода слова ВОССТАНОВИТЬ.
    Перед восстановлением помощник снимает копию текущей базы."""
    if str(body.get("confirm") or "").strip().upper() != "ВОССТАНОВИТЬ":
        raise HTTPException(status_code=422, detail="Для подтверждения введите слово ВОССТАНОВИТЬ")
    name = str(body.get("name") or "")
    if name not in {b.get("name") for b in channel(request).backups()}:
        raise HTTPException(status_code=404, detail="Резервная копия не найдена")
    return await _request(request, su, db, "restore", name, {"backup": name})


@router.post("/backup")
async def backup(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    return await _request(request, su, db, "backup")


@router.get("/log/download")
async def log_download(request: Request, which: str = Query("last", pattern=r"^(last|prev)$"), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Журнал последнего (или предыдущего) обновления файлом для диагностики: итог, причина, проверки и полный журнал; пароли и адреса с учётными данными маскируются."""
    text = channel(request).download_text(which)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="system.update_log_download", target_type="system", target_id=which, details={"bytes": len(text)})
    await db.commit()
    name = f"kavcheck-update-{request.app.state.settings.app_version}-{time.strftime('%Y%m%d-%H%M%S')}.log"
    return PlainTextResponse(text, headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


@router.get("/log")
async def log(request: Request, offset: int = Query(0, ge=-1), su: SessionUser = Depends(require_admin)):
    ch = channel(request)
    st = ch.status()
    out = ch.read_log(offset)
    out.update({k: st.get(k) for k in ("state", "action", "step_no", "step_total", "step_name", "exit_code", "result", "finished_at")})
    out["available"] = st["available"]
    return out
