"""Административная панель: пользователи, источники KSC, настройки, LDAP, правила группировки, журналы, состояние системы. Только администратор; изменения — в аудит."""
from __future__ import annotations

import asyncio
import shutil
import uuid
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import ldap as ldapmod
from ..auth.deps import SessionUser, get_db, require_admin
from ..ksc import schema as ksc_schema
from ..ksc.grouping import BUILTIN_RULES, validate_rule
from ..models import AuditLog, EventLog, GroupingRule, KscSource, ReportJob, User, utcnow
from ..services import local_admin as la
from ..services.audit import write_audit
from ..services.settings import GROUPS, SettingsError
from ..services.sources import source_out
from .schemas import RuleIn, SourceIn, UserIn, UserPatch

router = APIRouter(prefix="/admin", tags=["admin"])


def user_out(u: User) -> dict:
    return {"id": str(u.id), "username": u.username, "display_name": u.display_name, "email": u.email, "auth_source": u.auth_source, "role": u.role, "is_active": u.is_active,
            "all_sources": u.all_sources, "source_ids": [str(x) for x in (u.source_ids or [])], "must_change_password": u.must_change_password, "last_login_at": u.last_login_at, "created_at": u.created_at}


# ----------------------------------------------------------------------------------------------- пользователи
@router.get("/users")
async def users(q: str = Query("", max_length=100), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    stmt = select(User).order_by(User.display_name)
    if q.strip():
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(func.lower(User.display_name).like(like) | func.lower(User.username).like(like))
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


@router.post("/ldap/test")
async def ldap_test(request: Request, body: dict[str, Any] = Body(default_factory=dict), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Проверка СОХРАНЁННЫХ настроек LDAP: соединение → вход сервисной записи → Base DN → (необязательно) тестовый вход пользователя. Пароли не сохраняются."""
    cfg = await request.app.state.settings_svc.ldap_config(db)
    if not cfg.host:
        return {"ok": False, "stages": [{"stage": "config", "ok": False, "message": "Сервер LDAP не задан", "ms": 0}]}
    cfg.enabled = True
    login, password = str(body.get("test_login") or "")[:256], str(body.get("test_password") or "")[:512]
    result = await asyncio.to_thread(ldapmod.diagnose, cfg, login, password)
    if login:
        try:
            ident = await asyncio.to_thread(ldapmod.authenticate, cfg, login, password)
            from ..auth.service import role_from_groups  # noqa: PLC0415

            result["test_user"] = {"display_name": ident.display_name, "username": ident.username, "email": ident.email, "groups": sorted(ident.groups)[:50], "role": role_from_groups(cfg, ident.groups)}
        except ldapmod.LdapError:
            pass
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="ldap.test", target_type="settings", target_id="ldap", result="success" if result["ok"] else "failure", details={"test_login": login or None})
    await db.commit()
    return result


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


# ----------------------------------------------------------------------------------------------- журналы
@router.get("/audit")
async def audit(q: str = Query("", max_length=200), action: str = Query("", max_length=80), since: datetime | None = None, until: datetime | None = None,
                offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).offset(offset).limit(limit)
    if q.strip():
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(func.lower(AuditLog.actor).like(like) | func.lower(AuditLog.action).like(like) | func.lower(AuditLog.target_id).like(like))
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    if since:
        stmt = stmt.where(AuditLog.at >= since)
    if until:
        stmt = stmt.where(AuditLog.at <= until)
    rows = (await db.execute(stmt)).scalars().all()
    return {"items": [{"id": r.id, "at": r.at, "actor": r.actor, "action": r.action, "target_type": r.target_type, "target_id": r.target_id, "source_id": str(r.source_id) if r.source_id else None,
                       "details": r.details, "result": r.result, "ip": r.ip, "duration_ms": r.duration_ms} for r in rows]}


@router.get("/journal")
async def journal(q: str = Query("", max_length=200), level: str = Query("", pattern=r"^(|debug|info|warn|error)$"), category: str = Query("", max_length=24), range_: str = Query("24h", alias="range"),
                  offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    stmt = select(EventLog).order_by(EventLog.id.desc()).offset(offset).limit(limit)
    if q.strip():
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(func.lower(func.coalesce(EventLog.message, "")).like(like) | func.lower(func.coalesce(EventLog.user, "")).like(like) | func.lower(EventLog.event).like(like) | func.lower(func.coalesce(EventLog.source, "")).like(like))
    if level == "warn":
        stmt = stmt.where(EventLog.level.in_(("warn", "error")))
    elif level:
        stmt = stmt.where(EventLog.level == level)
    if category:
        stmt = stmt.where(EventLog.category == category)
    span = {"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30}.get(range_)
    if span:
        stmt = stmt.where(EventLog.at >= utcnow() - timedelta(hours=span))
    rows = (await db.execute(stmt)).scalars().all()
    errors24 = (await db.execute(select(func.count()).select_from(EventLog).where(EventLog.level == "error", EventLog.at >= utcnow() - timedelta(hours=24)))).scalar_one()
    return {"items": [{"id": r.id, "at": r.at, "level": r.level, "category": r.category, "event": r.event, "user": r.user, "source": r.source, "message": r.message, "data": r.data,
                       "duration_ms": r.duration_ms, "ip": r.ip, "request_id": r.request_id} for r in rows], "errors_24h": errors24}


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
@router.get("/system")
async def system(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    s = request.app.state.settings
    out: dict[str, Any] = {"version": s.app_version, "commit": s.app_git_commit, "built_at": s.app_built_at, "public_url": s.app_public_url, "checks": {}, "master_key_ok": request.app.state.settings_svc.box is not None}
    try:
        await db.execute(text("SELECT 1"))
        out["checks"]["postgres"] = {"ok": True}
    except Exception as exc:  # noqa: BLE001
        out["checks"]["postgres"] = {"ok": False, "error": type(exc).__name__}
    running = (await db.execute(select(func.count()).select_from(ReportJob).where(ReportJob.status == "running"))).scalar_one()
    queued = (await db.execute(select(func.count()).select_from(ReportJob).where(ReportJob.status == "queued"))).scalar_one()
    last_done = (await db.execute(select(func.max(ReportJob.finished_at)).where(ReportJob.status == "done"))).scalar_one()
    stuck = queued > 0 and (await db.execute(select(func.min(ReportJob.created_at)).where(ReportJob.status == "queued"))).scalar_one() < utcnow() - timedelta(minutes=5)
    out["checks"]["worker"] = {"ok": not stuck, "running": running, "queued": queued, "last_done": last_done, "error": "задания не берутся в работу дольше 5 минут: проверьте контейнер worker" if stuck else None}
    srcs = (await db.execute(select(KscSource).order_by(KscSource.position))).scalars().all()
    out["sources"] = [{"id": str(x.id), "name": x.name, "is_active": x.is_active, "last_check_at": x.last_check_at, "last_check_ok": x.last_check_ok, "ksc_version": (x.last_check or {}).get("ksc_version")} for x in srcs]
    out["counts"] = {"users": (await db.execute(select(func.count()).select_from(User))).scalar_one(), "sources": len(srcs),
                     "reports": (await db.execute(select(func.count()).select_from(ReportJob))).scalar_one(),
                     "events_24h": (await db.execute(select(func.count()).select_from(EventLog).where(EventLog.at >= utcnow() - timedelta(hours=24)))).scalar_one(),
                     "errors_24h": (await db.execute(select(func.count()).select_from(EventLog).where(EventLog.level == "error", EventLog.at >= utcnow() - timedelta(hours=24)))).scalar_one()}
    try:
        out["disk_free_bytes"] = shutil.disk_usage(s.data_dir).free
    except OSError:
        out["disk_free_bytes"] = None
    from ..services.updates import Channel  # noqa: PLC0415

    out["checks"]["updater"] = {"ok": Channel(f"{s.data_dir}/updater").status()["available"], "optional": True}
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
