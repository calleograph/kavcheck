"""Администрирование входа через каталог: подключения LDAPS, доверенные сертификаты CA, правила доступа по группам, проверка доступа пользователя."""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import ldap as L
from ..auth.deps import SessionUser, get_db, require_admin
from ..models import AccessRule, CaCertificate, KscSource, LdapConnection, utcnow
from ..security import certs
from ..services.audit import write_audit
from ..services.ldap_store import cert_out, conn_out, rule_out
from ..services.settings import SettingsError

router = APIRouter(prefix="/admin/ldap", tags=["admin-ldap"])
ROLE_RU = {"admin": "администратор", "analyst": "аналитик", "viewer": "просмотр"}


def store(request: Request):
    return request.app.state.ldap


async def _conn(db: AsyncSession, cid: uuid.UUID) -> LdapConnection:
    c = await db.get(LdapConnection, cid)
    if c is None:
        raise HTTPException(status_code=404, detail="Подключение не найдено")
    return c


# ------------------------------------------------------------------------------------------------ подключения
@router.get("/connections")
async def connections(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    return {"items": [conn_out(c) for c in await store(request).connections(db)]}


@router.post("/connections", status_code=201)
async def create(request: Request, body: dict[str, Any] = Body(...), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    try:
        c = await store(request).save(db, body, body.get("bind_password") or None)
    except SettingsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="ldap.connection_create", target_type="ldap", target_id=str(c.id), details={"name": c.name, "host": c.host})
    await db.commit()
    return conn_out(c)


@router.put("/connections/{cid}")
async def update(cid: uuid.UUID, request: Request, body: dict[str, Any] = Body(...), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    await _conn(db, cid)
    pw = body.get("bind_password")
    try:
        c = await store(request).save(db, body, pw if pw else None, cid)
    except SettingsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="ldap.connection_update", target_type="ldap", target_id=str(c.id), details={"name": c.name, "password_changed": bool(pw)})
    await db.commit()
    return conn_out(c)


@router.delete("/connections/{cid}", status_code=204)
async def remove(cid: uuid.UUID, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    c = await _conn(db, cid)
    await db.delete(c)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="ldap.connection_delete", target_type="ldap", target_id=str(cid), details={"name": c.name})
    await db.commit()


@router.delete("/connections/{cid}/secret")
async def remove_secret(cid: uuid.UUID, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Удалить сохранённые учётные данные сервисной записи. Подключение выключается: без них поиск пользователей невозможен."""
    c = await _conn(db, cid)
    c.bind_password_enc, c.enabled, c.updated_at = None, False, utcnow()
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="ldap.secret_delete", target_type="ldap", target_id=str(cid), details={"name": c.name})
    await db.commit()
    return conn_out(c)


class TestIn(BaseModel):
    test_login: str = Field(default="", max_length=256)
    test_password: str = Field(default="", max_length=512)


@router.post("/connections/{cid}/test")
async def test(cid: uuid.UUID, request: Request, body: TestIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Пошаговая проверка: DNS, TCP, TLS и цепочка сертификатов, вход сервисной записи, Base DN, поиск пользователя, группы, роль по правилам. Пароли не сохраняются."""
    c = await _conn(db, cid)
    st = store(request)
    cfg = st.config(c, await st.ca_bundle(db))
    started = utcnow()
    result = await asyncio.to_thread(L.diagnose, cfg, body.test_login.strip(), body.test_password)
    tu = result.get("test_user")
    if tu:
        ident = L.LdapIdentity(guid="", dn="", username=tu["username"], upn=None, display_name=tu["display_name"], email=tu.get("email"),
                               groups=frozenset(tu["groups"]), connection_id=str(c.id), connection=c.name)
        d = st.decide(await st.rules(db), ident)
        names = await st.source_names(db)
        tu["role"] = d.role
        tu["sources"] = "все" if d.all_sources else ", ".join(names.get(s, s) for s in d.source_ids) or "нет"
        tu["rules"] = [r.group_dn for r in d.rules]
        result["stages"].append({"stage": "access", "ok": d.role is not None,
                                 "message": f"Роль в KAV Checker: {ROLE_RU.get(d.role, d.role)}; источники: {tu['sources']}." if d.role else "Ни одно правило доступа не подходит: вход будет отклонён.", "ms": 0})
    c.last_check_at, c.last_check_ok = utcnow(), result["ok"]
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="ldap.test", target_type="ldap", target_id=str(c.id), result="success" if result["ok"] else "failure",
                details={"test_login": body.test_login or None}, duration_ms=int((utcnow() - started).total_seconds() * 1000))
    await db.commit()
    return result


@router.get("/groups")
async def groups(request: Request, q: str = Query("", max_length=100), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    d = await store(request).directory(db)
    out: list[dict] = []
    errors: list[str] = []
    for cfg in d.configs:
        try:
            out += await asyncio.to_thread(L.search_groups, cfg, q, 20)
        except L.LdapError as exc:
            errors.append(f"{cfg.name}: {exc.message}")
    return {"items": out[:40], "errors": errors}


# ------------------------------------------------------------------------------------------------ сертификаты
@router.get("/certs")
async def list_certs(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(CaCertificate).order_by(CaCertificate.created_at))).scalars().all()
    return {"items": [cert_out(r) for r in rows]}


@router.post("/certs/preview")
async def preview_certs(request: Request, body: dict[str, Any] = Body(...), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Разбор перед сохранением: Subject, Issuer, серийный номер, SHA-256, срок действия, тип (Root/Intermediate CA). Ничего не сохраняется."""
    try:
        added, existing = await store(request).add_certs(db, certs.decode_body(body), "", su.display_name, preview=True)
    except certs.CertError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    await db.rollback()
    return {"new": [i.public() for i in added], "existing": [i.public() for i in existing]}


@router.post("/certs", status_code=201)
async def add_certs(request: Request, body: dict[str, Any] = Body(...), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    try:
        added, existing = await store(request).add_certs(db, certs.decode_body(body), str(body.get("label") or ""), su.display_name, confirm_non_ca=bool(body.get("confirm_non_ca")))
    except certs.CertError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="ldap.cert_add", target_type="ldap", target_id="ca",
                details={"added": [i.sha256[:16] for i in added], "subjects": [i.subject[:120] for i in added]})
    await db.commit()
    return {"added": [i.public() for i in added], "existing": [i.public() for i in existing]}


@router.delete("/certs/{cert_id}", status_code=204)
async def delete_cert(cert_id: uuid.UUID, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.get(CaCertificate, cert_id)
    if r is None:
        raise HTTPException(status_code=404, detail="Сертификат не найден")
    await db.delete(r)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="ldap.cert_delete", target_type="ldap", target_id=str(cert_id), details={"subject": r.subject[:200]})
    await db.commit()


# ------------------------------------------------------------------------------------------------ правила доступа
class RuleIn(BaseModel):
    connection_id: uuid.UUID | None = None
    group_dn: str = Field(min_length=3, max_length=1000)
    role: str = Field(pattern=r"^(admin|analyst|viewer)$")
    all_sources: bool = True
    source_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    note: str | None = Field(default=None, max_length=500)


@router.get("/rules")
async def rules(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    names = {str(c.id): c.name for c in await store(request).connections(db)}
    return {"items": [rule_out(r, names) for r in await store(request).rules(db)]}


async def _rule_apply(db: AsyncSession, r: AccessRule, body: RuleIn) -> None:
    if body.connection_id and await db.get(LdapConnection, body.connection_id) is None:
        raise HTTPException(status_code=422, detail="Подключение не найдено")
    if "=" not in body.group_dn:
        raise HTTPException(status_code=422, detail="Укажите DN группы, например CN=KAV-Admins,OU=Groups,DC=example,DC=local")
    for sid in body.source_ids:
        if await db.get(KscSource, sid) is None:
            raise HTTPException(status_code=422, detail="Источник KSC не найден")
    r.connection_id, r.group_dn, r.role, r.all_sources = body.connection_id, body.group_dn.strip(), body.role, body.all_sources
    r.source_ids, r.note = [str(x) for x in body.source_ids], body.note


@router.post("/rules", status_code=201)
async def create_rule(request: Request, body: RuleIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = AccessRule(id=uuid.uuid4())
    await _rule_apply(db, r, body)
    db.add(r)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="ldap.rule_create", target_type="ldap", target_id=str(r.id), details={"group": r.group_dn, "role": r.role})
    await db.commit()
    names = {str(c.id): c.name for c in await store(request).connections(db)}
    return rule_out(r, names)


@router.put("/rules/{rule_id}")
async def update_rule(rule_id: uuid.UUID, request: Request, body: RuleIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.get(AccessRule, rule_id)
    if r is None:
        raise HTTPException(status_code=404, detail="Правило не найдено")
    await _rule_apply(db, r, body)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="ldap.rule_update", target_type="ldap", target_id=str(r.id), details={"group": r.group_dn, "role": r.role})
    await db.commit()
    names = {str(c.id): c.name for c in await store(request).connections(db)}
    return rule_out(r, names)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: uuid.UUID, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.get(AccessRule, rule_id)
    if r is None:
        raise HTTPException(status_code=404, detail="Правило не найдено")
    await db.delete(r)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="ldap.rule_delete", target_type="ldap", target_id=str(rule_id), details={"group": r.group_dn})
    await db.commit()


@router.post("/check-user")
async def check_user(request: Request, body: dict[str, Any] = Body(...), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Что получит пользователь при входе: найден ли в каталоге, его группы, подходящие правила, роль и источники. Пароль не нужен."""
    login = str(body.get("login") or "").strip()[:256]
    if not login:
        raise HTTPException(status_code=422, detail="Укажите логин")
    st = store(request)
    d = await st.directory(db)
    if not d.configs:
        raise HTTPException(status_code=409, detail="Нет включённых подключений к каталогу")
    try:
        ident = await asyncio.to_thread(d.lookup, login)
    except L.LdapError as exc:
        return {"found": False, "message": exc.message}
    dec = st.decide(await st.rules(db), ident)
    names = await st.source_names(db)
    return {"found": True, "display_name": ident.display_name, "username": ident.username, "email": ident.email, "connection": ident.connection, "disabled": ident.disabled,
            "groups": sorted(ident.groups)[:200], "role": dec.role, "all_sources": dec.all_sources, "sources": [names.get(s, s) for s in dec.source_ids],
            "rules": [r.group_dn for r in dec.rules]}
