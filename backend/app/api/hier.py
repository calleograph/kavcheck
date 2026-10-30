"""Раздел «Иерархия. Предприятие»: структура организации по адресной книге почты. Роли, которым раздел доступен, задаёт администратор (настройки группы `hier`; администратор имеет доступ всегда);
права проверяются здесь, на сервере, до выдачи данных. Каждое открытие раздела и каждый запуск сбора пишутся в журнал действий."""
from __future__ import annotations

import asyncio
import gzip
import json
import logging
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_admin, require_user
from ..hier import process as P
from ..hier import service as HS
from ..hier import sources as S
from ..models import HierSnapshot, utcnow
from ..services.audit import write_audit

log = logging.getLogger("app.hier")
router = APIRouter(prefix="/hier", tags=["hier"])
_CACHE: dict[tuple, P.Result] = {}                                       # обработанный снимок: (снимок, правила) → результат; не больше нескольких штук
MAX_UPLOAD = 40_000_000


async def _cfg(request: Request, db: AsyncSession):
    return await request.app.state.settings_svc.get(db, "hier")


def allowed(su: SessionUser, cfg) -> bool:
    return su.is_admin or su.role in cfg.roles


async def hier_user(request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    cfg = await _cfg(request, db)
    if not allowed(su, cfg):
        raise HTTPException(status_code=403, detail="Раздел «Иерархия. Предприятие» недоступен для вашей роли")
    return su, cfg


async def processed(db: AsyncSession, snap: HierSnapshot, cfg) -> P.Result:
    rules = HS.rules_of(cfg)
    key = (str(snap.id), rules.signature())
    if key not in _CACHE:
        recs = await HS.records_of(db, snap)
        res = await asyncio.to_thread(P.build, recs, rules)
        if len(_CACHE) >= 4:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = res
    return _CACHE[key]


def snap_out(s: HierSnapshot) -> dict:
    st = dict(s.stats or {})
    return {"id": str(s.id), "started_at": s.started_at, "finished_at": s.finished_at, "status": s.status, "trigger": s.trigger, "by": s.by, "source": s.source, "source_name": s.source_name,
            "raw_n": s.raw_n, "errors_n": s.errors_n, "message": s.message, "warnings": s.warnings or [], "kept": st.get("kept"), "excluded": st.get("excluded") or {}, "errors": st.get("errors") or []}


def _payload(request: Request, out: dict) -> Response:
    """Снимок на тысячи человек — сотни килобайт повторяющегося JSON: сжимается только этот ответ (в нём нет введённого пользователем текста, который отражался бы рядом с секретами — риск BREACH исключён)."""
    raw = json.dumps(jsonable_encoder(out), ensure_ascii=False, separators=(",", ":")).encode()
    if "gzip" in request.headers.get("accept-encoding", "") and len(raw) > 4096:
        return Response(gzip.compress(raw, 5), media_type="application/json", headers={"Content-Encoding": "gzip", "Vary": "Accept-Encoding", "Cache-Control": "no-store"})
    return Response(raw, media_type="application/json", headers={"Cache-Control": "no-store"})


@router.get("/access")
async def access(request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Показывать ли пункт меню (сами данные отдаёт /hier/data после проверки прав)."""
    cfg = await _cfg(request, db)
    return {"allowed": allowed(su, cfg), "admin": su.is_admin}


@router.get("/data")
async def data(request: Request, ctx=Depends(hier_user), db: AsyncSession = Depends(get_db)):
    su, cfg = ctx
    snap = await HS.latest_ok(db)
    last = (await db.execute(select(HierSnapshot).order_by(HierSnapshot.started_at.desc()).limit(1))).scalar_one_or_none()
    running = (await db.execute(select(func.count()).select_from(HierSnapshot).where(HierSnapshot.status == "running"))).scalar_one() > 0
    st = await HS.get_state(request.app.state.session_maker)
    warning = None
    if snap is not None and last is not None and last.status in ("failed", "rejected") and last.started_at > snap.started_at:
        warning = {"status": last.status, "message": last.message, "at": last.finished_at or last.started_at, "last_ok_at": snap.finished_at}
    elif snap is not None and cfg.enabled and cfg.source == "ldap" and utcnow() - snap.finished_at > timedelta(hours=36):
        warning = {"status": "stale", "message": "Плановое обновление не выполнялось больше 36 часов.", "at": None, "last_ok_at": snap.finished_at}
    out = {"can_admin": su.is_admin, "running": running, "enabled": cfg.enabled, "source": cfg.source, "next_run": st.get("next_run") if cfg.enabled else None, "warning": warning, "snapshot": None, "people": [], "depts": []}
    if snap is None:
        out["state"] = "failed" if last is not None and last.status in ("failed", "rejected") else "empty"
        out["last_error"] = last.message if last is not None and last.status in ("failed", "rejected") else ""
        write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="hier.open", target_type="hier", target_id="", details={"snapshot": None})
        await db.commit()
        return out
    res = await processed(db, snap, cfg)
    ex = sum(res.excluded.values())
    out.update(state="ok", snapshot={"id": str(snap.id), "at": snap.finished_at, "raw_n": res.raw_n, "kept": len(res.people), "excluded": ex, "excluded_by": res.excluded, "source": snap.source,
                                    "source_name": snap.source_name if su.is_admin else "", "errors_n": snap.errors_n},
               depts=res.depts, heads=len(res.heads), lone=len(res.lone), warnings=res.warnings if su.is_admin else [],
               people=[[p["id"], p["name"], p["email"], p["title"], p["dept"], p["mgr"], p["mgr_text"], int(p["inh"]), (1 if p["self"] else 0) | (2 if p["reach"] else 0) | (4 if p["head"] else 0), p["why"], p["size"]]
                       for p in res.people], why=P.WHY_RU)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="hier.open", target_type="hier", target_id=str(snap.id), details={"people": len(res.people)})
    await db.commit()
    return _payload(request, out)


# ------------------------------------------------------------------------------------------------ администратор
async def _connections(request: Request, db: AsyncSession, cfg) -> list:
    return [c for c in await request.app.state.ldap.connections(db) if c.enabled and (not cfg.ldap_connections or str(c.id) in cfg.ldap_connections)]


@router.get("/admin")
async def admin(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    cfg = await _cfg(request, db)
    snaps = (await db.execute(select(HierSnapshot).order_by(HierSnapshot.started_at.desc()).limit(40))).scalars().all()
    snap = await HS.latest_ok(db)
    res = await processed(db, snap, cfg) if snap is not None else None
    conns = await request.app.state.ldap.connections(db)
    st = await HS.get_state(request.app.state.session_maker)
    return {"settings": await request.app.state.settings_svc.public(db, "hier"), "state": {"next_run": st.get("next_run"), "requested": bool(st.get("requested")), "retry_n": st.get("retry_n") or 0},
            "snapshots": [snap_out(s) for s in snaps], "connections": [{"id": str(c.id), "name": c.name, "enabled": c.enabled, "host": c.host} for c in conns],
            "depts": [{"raw": d, "n": n, "shown": cfg.dept_map.get(d, "")} for d, n in (res.raw_depts[:400] if res else [])], "domains": [{"domain": d, "n": n} for d, n in (res.domains if res else [])],
            "running": any(s.status == "running" for s in snaps), "last_ok": snap_out(snap) if snap is not None else None,
            "people_n": len(res.people) if res else 0, "stats": res.stats() if res else None}


@router.post("/admin/check")
async def check(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Что доступно клиенту: подключение LDAPS, права сервисной учётной записи, поле «Руководитель». Только чтение, не больше 200 записей."""
    cfg = await _cfg(request, db)
    if cfg.source != "ldap":
        return {"ok": False, "items": [], "message": "Выбран источник «файл»: проверка подключения не нужна."}
    conns = await _connections(request, db, cfg)
    if not conns:
        return {"ok": False, "items": [], "message": "Подключение LDAPS не настроено или выключено: Администрирование → LDAPS. Раздел использует его же, отдельные логин и пароль не нужны. "
                                                      "Почтовое подключение SMTP для этого не подходит: оно не отдаёт поле «Руководитель»."}
    bundle = await request.app.state.ldap.ca_bundle(db)
    items = [await asyncio.to_thread(S.check_ldap, request.app.state.ldap.config(c, bundle), cfg.ldap_filter) for c in conns]
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="hier.check", target_type="hier", target_id="", details={"ok": all(i["ok"] for i in items)})
    await db.commit()
    return {"ok": all(i["ok"] for i in items), "items": items, "message": ""}


@router.post("/admin/run", status_code=202)
async def run_now(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """«Обновить сейчас»: запрос выполняет worker в течение минуты; два сбора одновременно не запускаются."""
    cfg = await _cfg(request, db)
    if cfg.source != "ldap":
        raise HTTPException(status_code=409, detail="Выбран источник «файл»: загрузите файл выгрузки.")
    if (await db.execute(select(func.count()).select_from(HierSnapshot).where(HierSnapshot.status == "running"))).scalar_one():
        raise HTTPException(status_code=409, detail="Сбор уже выполняется — дождитесь его завершения.")
    await HS.set_state(request.app.state.session_maker, requested=su.display_name)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="hier.run", target_type="hier", target_id="", details={})
    await db.commit()
    return {"requested": True}


@router.post("/admin/upload")
async def upload(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Загрузка файла выгрузки (JSON-массив записей): те же очистка и публикация, что и у сбора из каталога; порог сокращения для ручной загрузки не применяется."""
    if (await db.execute(select(func.count()).select_from(HierSnapshot).where(HierSnapshot.status == "running"))).scalar_one():
        raise HTTPException(status_code=409, detail="Сбор уже выполняется — дождитесь его завершения.")
    if int(request.headers.get("content-length") or 0) > MAX_UPLOAD:
        raise HTTPException(status_code=413, detail="Файл больше 40 МБ.")
    body = await request.body()
    try:
        coll = await asyncio.to_thread(S.parse_file, body)
    except S.SourceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    snap = HierSnapshot(started_at=utcnow(), status="running", trigger="upload", by=su.display_name[:160], source="file")
    db.add(snap)
    await db.commit()
    done = await HS.publish(request.app.state.session_maker, request.app.state.settings_svc, snap.id, coll, "upload", request.app.state.journal, su.display_name)
    async with request.app.state.session_maker() as db2:
        write_audit(db2, actor_user_id=su.user_id, actor=su.display_name, action="hier.upload", target_type="hier", target_id=str(snap.id), details={"records": len(coll.records), "status": done.status})
        await db2.commit()
    return snap_out(done)
