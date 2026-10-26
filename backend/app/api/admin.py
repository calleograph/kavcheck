"""Административная панель: пользователи, источники KSC, настройки, LDAP, правила группировки, журналы, состояние системы. Только администратор; изменения — в аудит."""
from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_admin
from ..ksc import schema as ksc_schema
from ..ksc.grouping import BUILTIN_RULES, validate_rule
from ..search import any_of
from ..models import AuditLog, EventLog, GroupingRule, KscSource, ReportJob, User, utcnow
from ..services import local_admin as la
from ..services.audit import write_audit
from ..services.settings import GROUPS, SettingsError
from ..services.sources import source_out
from .schemas import RuleIn, SourceIn, UserIn, UserPatch

router = APIRouter(prefix="/admin", tags=["admin"])


def user_out(u: User) -> dict:
    return {"id": str(u.id), "username": u.username, "display_name": u.display_name, "email": u.email, "auth_source": u.auth_source, "role": u.role, "is_active": u.is_active,
            "all_sources": u.all_sources, "source_ids": [str(x) for x in (u.source_ids or [])], "must_change_password": u.must_change_password, "last_login_at": u.last_login_at,
            "created_at": u.created_at, "totp_enabled": u.totp_enabled, "totp_enabled_at": u.totp_enabled_at}


# ----------------------------------------------------------------------------------------------- пользователи
@router.get("/users")
async def users(q: str = Query("", max_length=100), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    stmt = select(User).order_by(User.display_name)
    if any_of(q, User.display_name, User.username) is not None:
        stmt = stmt.where(any_of(q, User.display_name, User.username))
    return {"items": [user_out(u) for u in (await db.execute(stmt)).scalars().all()]}


@router.post("/users", status_code=201)
async def create_user(body: UserIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if not body.password:
        raise HTTPException(status_code=422, detail="Для локального пользователя нужен пароль")
    try:
        la.validate_new_password(body.password, body.username)
        u = await la.create_local(db, body.username, body.password, role=body.role, display_name=body.display_name, must_change=body.must_change_password)
    except la.LocalAdminError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    u.email, u.is_active, u.all_sources, u.source_ids = body.email, body.is_active, body.all_sources, body.source_ids
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="user.create", target_type="user", target_id=str(u.id), details={"username": u.username, "role": u.role})
    await db.commit()
    return user_out(u)


@router.patch("/users/{user_id}")
async def patch_user(user_id: uuid.UUID, body: UserPatch, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    u = await db.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    changes = body.model_dump(exclude_none=True)
    if u.id == su.user_id and (changes.get("is_active") is False or (changes.get("role") and changes["role"] != "admin")):
        raise HTTPException(status_code=409, detail="Нельзя лишить себя прав администратора или отключить себя")
    pw = changes.pop("password", None)
    if pw is not None:
        if u.auth_source != "local":
            raise HTTPException(status_code=422, detail="Пароль доменного пользователя меняется в каталоге")
        try:
            la.validate_new_password(pw, u.username)
        except la.LocalAdminError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        await la.set_password(db, u, pw, must_change=changes.pop("must_change_password", True))
    for k, v in changes.items():
        setattr(u, k, v)
    if changes.get("is_active") is False or pw is not None:
        await request.app.state.sessions.destroy_user(db, u.id)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="user.update", target_type="user", target_id=str(u.id), details={"changed": sorted(changes) + (["password"] if pw else [])})
    await db.commit()
    return user_out(u)


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(user_id: uuid.UUID, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    u = await db.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if u.id == su.user_id:
        raise HTTPException(status_code=409, detail="Нельзя удалить себя")
    await db.delete(u)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="user.delete", target_type="user", target_id=str(user_id), details={"username": u.username})
    await db.commit()


# ----------------------------------------------------------------------------------------------- источники KSC
@router.get("/sources")
async def sources(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(KscSource).order_by(KscSource.position, KscSource.name))).scalars().all()
    return {"items": [source_out(s, full=True) for s in rows]}


def _apply_source(src: KscSource, body: SourceIn, svc) -> None:
    for k in ("name", "host", "port", "database", "auth_type", "username", "tls_mode", "trust_server_cert", "connect_timeout_s", "query_timeout_s", "is_active"):
        setattr(src, k, getattr(body, k))
    if body.password is not None:
        src.password_enc = svc.encrypt(body.password, f"source.{src.id}") if body.password else None


@router.post("/sources", status_code=201)
async def create_source(body: SourceIn, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if (await db.execute(select(KscSource).where(KscSource.name == body.name))).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Источник с таким названием уже есть")
    src = KscSource(id=uuid.uuid4(), name=body.name, host=body.host, database=body.database, username=body.username)
    try:
        _apply_source(src, body, request.app.state.settings_svc)
    except SettingsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    src.position = int((await db.execute(select(func.coalesce(func.max(KscSource.position), 0)))).scalar_one()) + 1
    db.add(src)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="source.create", target_type="source", target_id=str(src.id), details={"name": src.name, "host": src.host, "database": src.database})
    await db.commit()
    return source_out(src, full=True)


@router.put("/sources/{source_id}")
async def update_source(source_id: uuid.UUID, body: SourceIn, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    src = await db.get(KscSource, source_id)
    if src is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    try:
        _apply_source(src, body, request.app.state.settings_svc)
    except SettingsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    request.app.state.sources.forget(src.id)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="source.update", target_type="source", target_id=str(src.id), details={"name": src.name, "password_changed": body.password is not None})
    await db.commit()
    return source_out(src, full=True)


@router.delete("/sources/{source_id}", status_code=204)
async def delete_source(source_id: uuid.UUID, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    src = await db.get(KscSource, source_id)
    if src is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    await db.delete(src)
    request.app.state.sources.forget(source_id)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="source.delete", target_type="source", target_id=str(source_id), details={"name": src.name})
    await db.commit()


@router.post("/sources/{source_id}/test")
async def test_source(source_id: uuid.UUID, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Проверка подключения: версия SQL Server, база, объекты KSC, права, версия KSC. Результат сохраняется у источника."""
    src = await db.get(KscSource, source_id)
    if src is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    reg = request.app.state.sources
    started = utcnow()
    result = await asyncio.to_thread(ksc_schema.diagnose, reg.params(src))
    src.last_check_at, src.last_check_ok, src.last_check = utcnow(), result["ok"], result
    ms = int((utcnow() - started).total_seconds() * 1000)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="source.test", target_type="source", target_id=str(src.id), source_id=src.id, result="success" if result["ok"] else "failure", duration_ms=ms)
    await db.commit()
    await request.app.state.journal.emit("ksc", "source_test", level="info" if result["ok"] else "warn", user=su.username, source=src.name, duration_ms=ms,
                                         message="; ".join(f"{s['stage']}: {s['message']}" for s in result["stages"])[:600])
    return result


# ----------------------------------------------------------------------------------------------- настройки и LDAP
@router.get("/settings/{group}")
async def get_settings(group: str, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if group not in GROUPS:
        raise HTTPException(status_code=404, detail="Неизвестная группа настроек")
    return await request.app.state.settings_svc.public(db, group)


@router.put("/settings/{group}")
async def put_settings(group: str, request: Request, body: dict[str, Any] = Body(...), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if group not in GROUPS:
        raise HTTPException(status_code=404, detail="Неизвестная группа настроек")
    svc = request.app.state.settings_svc
    try:
        changed = await svc.update(db, group, body, actor=su.display_name)
    except SettingsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action=f"settings.{group}.update", target_type="settings", target_id=group, details={"changed": changed})
    await db.commit()
    return await svc.public(db, group)


# ----------------------------------------------------------------------------------------------- правила группировки
def rule_out(r: GroupingRule) -> dict:
    return {"id": str(r.id), "key": r.key, "name": r.name, "name_like": r.name_like, "name_regex": r.name_regex, "branch_regex": r.branch_regex, "branch_parts": r.branch_parts,
            "exclude_regex": r.exclude_regex, "description": r.description, "builtin": r.builtin, "enabled": r.enabled}


@router.get("/rules")
async def rules(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    return {"items": [rule_out(r) for r in (await db.execute(select(GroupingRule).order_by(GroupingRule.builtin.desc(), GroupingRule.name))).scalars().all()]}


@router.post("/rules", status_code=201)
async def create_rule(body: RuleIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    try:
        validate_rule(body.name_regex, body.branch_regex, body.exclude_regex)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if (await db.execute(select(GroupingRule).where(GroupingRule.key == body.key))).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Правило с таким ключом уже есть")
    r = GroupingRule(**body.model_dump())
    db.add(r)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="rule.create", target_type="rule", target_id=body.key, details={"name": body.name})
    await db.commit()
    return rule_out(r)


@router.put("/rules/{key}")
async def update_rule(key: str, body: RuleIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = (await db.execute(select(GroupingRule).where(GroupingRule.key == key))).scalar_one_or_none()
    if r is None:
        raise HTTPException(status_code=404, detail="Правило не найдено")
    try:
        validate_rule(body.name_regex, body.branch_regex, body.exclude_regex)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    for k, v in body.model_dump().items():
        if k != "key":
            setattr(r, k, v)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="rule.update", target_type="rule", target_id=key)
    await db.commit()
    return rule_out(r)


@router.delete("/rules/{key}", status_code=204)
async def delete_rule(key: str, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = (await db.execute(select(GroupingRule).where(GroupingRule.key == key))).scalar_one_or_none()
    if r is None:
        raise HTTPException(status_code=404, detail="Правило не найдено")
    if r.builtin:
        raise HTTPException(status_code=409, detail="Встроенное правило удалить нельзя (можно выключить)")
    await db.delete(r)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="rule.delete", target_type="rule", target_id=key)
    await db.commit()


@router.post("/rules/reset-builtin")
async def reset_builtin(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Вернуть встроенные правила к значениям из поставки."""
    for b in BUILTIN_RULES:
        r = (await db.execute(select(GroupingRule).where(GroupingRule.key == b["key"]))).scalar_one_or_none()
        if r is None:
            db.add(GroupingRule(**b, builtin=True, enabled=True))
        else:
            for k, v in b.items():
                setattr(r, k, v)
            r.builtin = True
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="rule.reset_builtin", target_type="rule", target_id="builtin")
    await db.commit()
    return {"ok": True}


# ----------------------------------------------------------------------------------------------- каталог программ
@router.get("/catalog")
async def catalog_states(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Состояние каталога по каждому источнику: когда построен, сколько продуктов, сколько длилась сборка, ошибки."""
    from ..models import CatalogState  # noqa: PLC0415
    from ..services import catalog as csvc  # noqa: PLC0415

    srcs = (await db.execute(select(KscSource).order_by(KscSource.position, KscSource.name))).scalars().all()
    out = []
    for s in srcs:
        out.append({"source_id": str(s.id), "source": s.name, "is_active": s.is_active, **csvc.state_out(await db.get(CatalogState, s.id))})
    return {"items": out}


@router.post("/catalog/{source_id}/rebuild")
async def catalog_rebuild(source_id: uuid.UUID, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    from ..services import catalog as csvc  # noqa: PLC0415

    if await db.get(KscSource, source_id) is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    st = await csvc.request_rebuild(db, source_id)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="catalog.rebuild", target_type="catalog", target_id=str(source_id), source_id=source_id)
    await db.commit()
    return csvc.state_out(st)


# ----------------------------------------------------------------------------------------------- журналы
@router.get("/audit")
async def audit(q: str = Query("", max_length=200), action: str = Query("", max_length=80), since: datetime | None = None, until: datetime | None = None,
                offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    stmt = select(AuditLog)
    if any_of(q, AuditLog.actor, AuditLog.action, AuditLog.target_id) is not None:
        stmt = stmt.where(any_of(q, AuditLog.actor, AuditLog.action, AuditLog.target_id))
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    if since:
        stmt = stmt.where(AuditLog.at >= since)
    if until:
        stmt = stmt.where(AuditLog.at <= until)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(AuditLog.id.desc()).offset(offset).limit(limit))).scalars().all()
    return {"total": total, "items": [{"id": r.id, "at": r.at, "actor": r.actor, "action": r.action, "target_type": r.target_type, "target_id": r.target_id, "source_id": str(r.source_id) if r.source_id else None,
                       "details": r.details, "result": r.result, "ip": r.ip, "duration_ms": r.duration_ms} for r in rows]}


@router.get("/journal")
async def journal(q: str = Query("", max_length=200), level: str = Query("", pattern=r"^(|debug|info|warn|error)$"), category: str = Query("", max_length=24), range_: str = Query("24h", alias="range"),
                  since: datetime | None = None, until: datetime | None = None,
                  offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Журнал событий с фильтрами: период (готовый или произвольный since/until), уровень, компонент (category), текст."""
    stmt = select(EventLog)
    if any_of(q, EventLog.message, EventLog.user, EventLog.event, EventLog.source) is not None:
        stmt = stmt.where(any_of(q, EventLog.message, EventLog.user, EventLog.event, EventLog.source))
    if level == "warn":
        stmt = stmt.where(EventLog.level.in_(("warn", "error")))
    elif level:
        stmt = stmt.where(EventLog.level == level)
    if category:
        stmt = stmt.where(EventLog.category == category)
    span = {"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30}.get(range_)
    if since or until:
        if since:
            stmt = stmt.where(EventLog.at >= since)
        if until:
            stmt = stmt.where(EventLog.at <= until)
    elif span:
        stmt = stmt.where(EventLog.at >= utcnow() - timedelta(hours=span))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(EventLog.id.desc()).offset(offset).limit(limit))).scalars().all()
    errors24 = (await db.execute(select(func.count()).select_from(EventLog).where(EventLog.level == "error", EventLog.at >= utcnow() - timedelta(hours=24)))).scalar_one()
    return {"items": [{"id": r.id, "at": r.at, "level": r.level, "category": r.category, "event": r.event, "user": r.user, "source": r.source, "message": r.message, "data": r.data,
                       "duration_ms": r.duration_ms, "ip": r.ip, "request_id": r.request_id} for r in rows], "total": total, "errors_24h": errors24}


@router.get("/journal/export.csv")
async def journal_export(range_: str = Query("24h", alias="range"), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    import csv  # noqa: PLC0415
    import io  # noqa: PLC0415

    span = {"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30}.get(range_, 24)
    rows = (await db.execute(select(EventLog).where(EventLog.at >= utcnow() - timedelta(hours=span)).order_by(EventLog.id.desc()).limit(100_000))).scalars().all()
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["Время (UTC)", "Уровень", "Категория", "Событие", "Пользователь", "Источник", "Сообщение", "Длительность, мс", "IP"])
    for r in rows:
        w.writerow([r.at.strftime("%Y-%m-%d %H:%M:%S"), r.level, r.category, r.event, r.user or "", r.source or "", r.message or "", r.duration_ms or "", r.ip or ""])
    return StreamingResponse(iter(["﻿" + buf.getvalue()]), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=kavcheck-journal.csv"})


@router.post("/journal/purge")
async def journal_purge(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    keep = (await request.app.state.settings_svc.get(db, "general")).journal_keep_days
    n = (await db.execute(delete(EventLog).where(EventLog.at < utcnow() - timedelta(days=keep)))).rowcount
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="journal.purge", target_type="journal", target_id="event_log", details={"deleted": n, "keep_days": keep})
    await db.commit()
    return {"deleted": n}


# ----------------------------------------------------------------------------------------------- состояние системы
def _worker_mem(hb) -> str:
    """Память фоновой службы из её пульса: текущая, пик, пределы ограничителя (подробнее — Администрирование → Расчёт данных зон)."""
    r = ((hb.data or {}) if hb is not None else {}).get("resources") or {}
    return f"; память {r['rss_mb']} МБ (пик {r.get('peak_mb', '?')}, предел {r.get('soft_mb', '?')}/{r.get('hard_mb', '?')}), тяжёлых задач {r.get('used', 0)}" if r.get("rss_mb") is not None else ""


@router.get("/system")
async def system(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Состояние компонентов (backend, worker, web, PostgreSQL, помощник обновлений), источников KSC, ресурсов сервера и данных; история обновлений, ошибки фоновых задач."""
    import httpx  # noqa: PLC0415

    from ..models import CatalogState, ServiceHeartbeat  # noqa: PLC0415
    from ..services import system as sysmod  # noqa: PLC0415
    from ..services.updates import Channel  # noqa: PLC0415

    s = request.app.state.settings
    ch = Channel(f"{s.data_dir}/updater")
    out: dict[str, Any] = {"version": s.app_version, "commit": s.app_git_commit, "built_at": s.app_built_at, "public_url": s.app_public_url, "checks": {},
                           "master_key_ok": request.app.state.settings_svc.box is not None, "uptime_s": sysmod.uptime_s()}
    comps: list[dict] = [{"key": "backend", "title": "Backend (API)", "ok": True, "detail": f"работает {sysmod.uptime_s() // 60} мин, версия {s.app_version}"}]
    hb = await db.get(ServiceHeartbeat, "worker")
    age = (utcnow() - hb.at).total_seconds() if hb else None
    running = (await db.execute(select(func.count()).select_from(ReportJob).where(ReportJob.status == "running"))).scalar_one()
    queued = (await db.execute(select(func.count()).select_from(ReportJob).where(ReportJob.status == "queued"))).scalar_one()
    oldest = (await db.execute(select(func.min(ReportJob.created_at)).where(ReportJob.status == "queued"))).scalar_one()
    stuck = bool(queued and oldest and oldest < utcnow() - timedelta(minutes=5))
    w_ok = age is not None and age < 120 and not stuck
    comps.append({"key": "worker", "title": "Worker (отчёты и каталог)", "ok": w_ok,
                  "detail": ("нет сигнала от службы — проверьте контейнер worker" if age is None or age >= 120 else
                             "задания не берутся в работу дольше 5 минут" if stuck else f"сигнал {int(age)} с назад; отчётов в работе {running}, в очереди {queued}" + _worker_mem(hb))})
    out["checks"]["worker"] = {"ok": w_ok, "running": running, "queued": queued, "last_done": (await db.execute(select(func.max(ReportJob.finished_at)).where(ReportJob.status == "done"))).scalar_one()}
    try:
        async with httpx.AsyncClient(timeout=2.5) as cl:
            r = await cl.get(os.environ.get("WEB_HEALTH_URL", "http://web:8080/healthz"))
        comps.append({"key": "web", "title": "Web (интерфейс и прокси)", "ok": r.status_code == 200, "detail": "отвечает" if r.status_code == 200 else f"ответ {r.status_code}"})
    except Exception as exc:  # noqa: BLE001
        comps.append({"key": "web", "title": "Web (интерфейс и прокси)", "ok": None, "detail": f"не проверен изнутри ({type(exc).__name__})"})
    pg: dict[str, Any] = {"ok": False}
    try:
        await db.execute(text("SELECT 1"))
        pg["ok"] = True
        if db.bind.dialect.name == "postgresql":
            pg["version"] = (await db.execute(text("SHOW server_version"))).scalar_one()
            pg["size"] = int((await db.execute(text("SELECT pg_database_size(current_database())"))).scalar_one())
            pg["connections"] = int((await db.execute(text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"))).scalar_one())
    except Exception as exc:  # noqa: BLE001
        pg["error"] = type(exc).__name__
    out["checks"]["postgres"] = pg
    comps.append({"key": "postgres", "title": "PostgreSQL", "ok": pg["ok"], "detail": f"версия {pg.get('version', '?')}, подключений {pg.get('connections', '?')}" if pg["ok"] else pg.get("error")})
    upd = ch.status()
    out["checks"]["updater"] = {"ok": upd["available"], "optional": True}
    comps.append({"key": "updater", "title": "Помощник обновлений (на сервере)", "ok": True if upd["available"] else None,
                  "detail": f"сигнал {upd.get('heartbeat_age_s')} с назад" if upd["available"] else "не запущен: обновление из браузера недоступно (необязательно)"})
    out["components"] = comps
    srcs = (await db.execute(select(KscSource).order_by(KscSource.position))).scalars().all()
    out["sources"] = []
    for x in srcs:
        cs = await db.get(CatalogState, x.id)
        out["sources"].append({"id": str(x.id), "name": x.name, "is_active": x.is_active, "last_check_at": x.last_check_at, "last_check_ok": x.last_check_ok,
                               "ksc_version": (x.last_check or {}).get("ksc_version"), "catalog_status": cs.status if cs else "empty", "catalog_built_at": cs.built_at if cs else None})
    out["counts"] = {"users": (await db.execute(select(func.count()).select_from(User))).scalar_one(), "sources": len(srcs),
                     "reports": (await db.execute(select(func.count()).select_from(ReportJob))).scalar_one(),
                     "events_24h": (await db.execute(select(func.count()).select_from(EventLog).where(EventLog.at >= utcnow() - timedelta(hours=24)))).scalar_one(),
                     "errors_24h": (await db.execute(select(func.count()).select_from(EventLog).where(EventLog.level == "error", EventLog.at >= utcnow() - timedelta(hours=24)))).scalar_one()}
    out["resources"] = sysmod.resources(s.data_dir)
    host = ch._json("system.json") or {}  # noqa: SLF001
    out["storage"] = {"database": pg.get("size"), "reports": await asyncio.to_thread(sysmod.dir_size, s.reports_dir), "backups": host.get("backups_bytes"),
                      "images": host.get("images_bytes"), "images_list": host.get("images", [])[:20], "docker_free": host.get("docker_free_bytes"),
                      "data_free": host.get("data_free_bytes"), "host_checked_at": host.get("checked_at")}
    out["disk_free_bytes"] = (out["resources"].get("disk_data") or {}).get("free")
    errs = (await db.execute(select(EventLog).where(EventLog.level == "error").order_by(EventLog.id.desc()).limit(10))).scalars().all()
    out["recent_errors"] = [{"at": e.at, "category": e.category, "event": e.event, "source": e.source, "message": e.message} for e in errs]
    checks = (await db.execute(select(EventLog).where(EventLog.event.in_(("source_test", "catalog_failed", "catalog_built"))).order_by(EventLog.id.desc()).limit(10))).scalars().all()
    out["recent_checks"] = [{"at": e.at, "level": e.level, "event": e.event, "source": e.source, "message": e.message} for e in checks]
    out["update_history"] = ch.history(10)
    sec = await request.app.state.settings_svc.get(db, "auth_security")
    out["security"] = {"https": s.app_public_url.lower().startswith("https://"), "secure_cookie": s.secure_cookie(request.headers.get("x-forwarded-proto")),
                       "cookie_mode": str(s.cookie_secure), "totp_policy": sec.totp_policy}
    return out


@router.post("/sources/{source_id}/ping")
async def ping_source(source_id: uuid.UUID, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Лёгкая проверка доступности источника (SELECT 1): для страницы состояния системы, без нагрузки на SQL Server."""
    src = await db.get(KscSource, source_id)
    if src is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    from ..ksc.driver import KscError  # noqa: PLC0415

    started = utcnow()
    try:
        await request.app.state.sources.client(src).run("SELECT 1 AS n", max_rows=1)
        return {"ok": True, "ms": int((utcnow() - started).total_seconds() * 1000)}
    except KscError as exc:
        return {"ok": False, "ms": int((utcnow() - started).total_seconds() * 1000), "error": exc.message}
