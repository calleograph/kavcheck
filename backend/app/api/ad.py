"""Active Directory в разделе «Иерархия. Предприятие»: поиск и карточки пользователей и групп, членство, сопоставление с сотрудниками Exchange. Только чтение; пароль сервисной учётной записи остаётся на сервере.
Доступ — по ролям раздела («Иерархия») и отдельному списку ролей для AD (настройки); каждое открытие карточки и поиск пишутся в журнал действий."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..ad import client as C
from ..ad import filters as F
from ..auth.deps import SessionUser, get_db, require_user
from ..auth.ldap import LdapError
from ..hier import service as HS
from ..search import MaskError
from ..services.audit import write_audit
from .hier import allowed as hier_allowed

log = logging.getLogger("app.ad")
router = APIRouter(prefix="/ad", tags=["ad"])


def ad_allowed(su: SessionUser, cfg) -> bool:
    return su.is_admin or (su.role in cfg.roles and su.role in cfg.ad_roles)


async def ad_user(request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    cfg = await request.app.state.settings_svc.get(db, "hier")
    if not ad_allowed(su, cfg):
        raise HTTPException(status_code=403, detail="Вкладка «Active Directory» недоступна для вашей роли")
    return su, cfg


def _svc(request: Request):
    return request.app.state.ad


async def _run(request: Request, db: AsyncSession, cfg, key: tuple, fn, refresh: bool = False, ttl: float | None = None):
    """Выполнить запрос к каталогу через кэш; ошибки каталога — в понятные HTTP-ответы."""
    try:
        ad = _svc(request)
        lcfg = await ad.config(db, cfg)
        return await ad.call((lcfg.id, *key), ttl if ttl is not None else cfg.ad_cache_seconds, lambda: fn(lcfg), refresh)
    except F.AdQueryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except MaskError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except LdapError as exc:
        log.warning("Каталог AD: %s", exc.code)
        raise HTTPException(status_code=503 if exc.code in ("server_unavailable", "tls_error", "service_account_error", "config_error", "not_configured") else 502, detail=exc.message) from None


def _page(rows: list[dict], offset: int, limit: int, truncated: bool, cfg) -> dict:
    return {"items": rows[offset:offset + limit], "total": len(rows), "has_more": offset + limit < len(rows), "truncated": truncated, "max": cfg.ad_max_results}


def _audit(db, su, action: str, target: str, details: dict) -> None:
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action=action, target_type="ad", target_id=target[:120], details=details)


@router.get("/status")
async def status(request: Request, refresh: bool = False, ctx=Depends(ad_user), db: AsyncSession = Depends(get_db)):
    su, cfg = ctx
    try:
        out = await _run(request, db, cfg, ("status",), C.status, refresh, ttl=30)
    except HTTPException as exc:
        return {"ok": False, "message": exc.detail, "name": "", "url": "", "base_dn": ""}
    return out


@router.get("/users")
async def users(request: Request, q: str = Query("", max_length=200), offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100), refresh: bool = False,
                ctx=Depends(ad_user), db: AsyncSession = Depends(get_db)):
    su, cfg = ctx
    rows, trunc = await _run(request, db, cfg, ("users", q.strip().lower()), lambda lc: C.search_users(lc, q, cfg.ad_max_results), refresh)
    if offset == 0:
        _audit(db, su, "ad.search", q.strip(), {"kind": "users", "found": len(rows)})
        await db.commit()
    return _page(rows, offset, limit, trunc, cfg)


@router.get("/groups")
async def groups(request: Request, q: str = Query("", max_length=200), offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100), refresh: bool = False,
                 ctx=Depends(ad_user), db: AsyncSession = Depends(get_db)):
    su, cfg = ctx
    rows, trunc = await _run(request, db, cfg, ("groups", q.strip().lower()), lambda lc: C.search_groups(lc, q, cfg.ad_max_results), refresh)
    if offset == 0:
        _audit(db, su, "ad.search", q.strip(), {"kind": "groups", "found": len(rows)})
        await db.commit()
    return _page(rows, offset, limit, trunc, cfg)


async def _exchange_link(db: AsyncSession, cfg, emails: list[str]) -> dict:
    """Сотрудник Exchange для учётной записи: только по адресу (mail, UPN, адреса Exchange); совпадение одно — связь установлена."""
    snap = await HS.latest_ok(db)
    if snap is None or not emails:
        return {"status": "none"}
    res = await HS.processed(db, snap, cfg)
    want = set(emails)
    hits = [p for p in res.people if p["email"] in want]
    if len(hits) == 1:
        p = hits[0]
        return {"status": "linked", "person": {"id": p["id"], "name": p["name"], "title": p["title"], "email": p["email"]}}
    return {"status": "multiple" if hits else "none", "persons": [{"id": p["id"], "name": p["name"]} for p in hits[:5]]}


@router.get("/users/{ref}")
async def user(ref: str, request: Request, refresh: bool = False, ctx=Depends(ad_user), db: AsyncSession = Depends(get_db)):
    su, cfg = ctx
    card = await _run(request, db, cfg, ("user", ref), lambda lc: C.user_card(lc, ref), refresh, ttl=min(cfg.ad_cache_seconds, 120))
    mgr = None
    if card["manager_dn"]:
        try:
            m = await _run(request, db, cfg, ("mgr", card["manager_dn"].lower()), lambda lc: C.user_row(C.entry_by_ref(lc, "d:" + F.b64(card["manager_dn"]), ["cn", "displayName", "objectGUID", "sAMAccountName"])))
            mgr = {"ref": m["ref"], "name": m["name"], "dn": card["manager_dn"]}
        except HTTPException:
            mgr = {"ref": "", "name": F.cn_of(card["manager_dn"]), "dn": card["manager_dn"]}
    out = {**card, "manager": mgr, "exchange": await _exchange_link(db, cfg, card["emails"])}
    _audit(db, su, "ad.open", ref, {"kind": "user", "login": card["main"]["login"]})
    await db.commit()
    return out


@router.get("/users/{ref}/groups")
async def user_groups(ref: str, request: Request, nested: bool = False, refresh: bool = False, ctx=Depends(ad_user), db: AsyncSession = Depends(get_db)):
    _su, cfg = ctx
    direct = await _run(request, db, cfg, ("ug", ref), lambda lc: C.user_groups(lc, ref), refresh)
    out = {**direct, "nested": None}
    if nested:
        nest = await _run(request, db, cfg, ("ugn", ref), lambda lc: C.nested_groups(lc, ref), refresh)
        have = {g["dn"].lower() for g in direct["direct"]} | ({direct["primary"]["dn"].lower()} if direct["primary"] else set())
        out["nested"] = {**nest, "items": [g for g in nest["items"] if g["dn"].lower() not in have]}      # отдельный список: без непосредственных и первичной
    return out


@router.get("/groups/{ref}")
async def group(ref: str, request: Request, refresh: bool = False, ctx=Depends(ad_user), db: AsyncSession = Depends(get_db)):
    su, cfg = ctx
    card = await _run(request, db, cfg, ("group", ref), lambda lc: C.group_card(lc, ref), refresh, ttl=min(cfg.ad_cache_seconds, 120))
    _audit(db, su, "ad.open", ref, {"kind": "group", "cn": card["cn"]})
    await db.commit()
    return {k: v for k, v in card.items() if k != "member_dns"}


@router.get("/groups/{ref}/members")
async def members(ref: str, request: Request, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100), refresh: bool = False,
                  ctx=Depends(ad_user), db: AsyncSession = Depends(get_db)):
    _su, cfg = ctx
    got = await _run(request, db, cfg, ("members", ref), lambda lc: C.group_members(lc, ref, cfg.ad_max_results), refresh)
    page = _page(got["items"], offset, limit, got["truncated"], cfg)
    return {**page, "basis": got["basis"], "primary_exists": got["primary_exists"]}


@router.get("/match/{pid}")
async def match(pid: str, request: Request, refresh: bool = False, ctx=Depends(ad_user), db: AsyncSession = Depends(get_db)):
    """Сотрудник Exchange → учётная запись AD: точная / несколько / только по логину (ручной выбор) / нет. По ФИО не сопоставляется."""
    _su, cfg = ctx
    snap = await HS.latest_ok(db)
    res = await HS.processed(db, snap, cfg) if snap is not None else None
    p = next((x for x in (res.people if res else []) if x["id"] == pid), None)
    if p is None:
        raise HTTPException(status_code=404, detail="Сотрудник не найден в последней выгрузке")
    login = p["email"].split("@", 1)[0]
    return await _run(request, db, cfg, ("match", p["email"]), lambda lc: C.find_accounts(lc, p["email"], login), refresh)
