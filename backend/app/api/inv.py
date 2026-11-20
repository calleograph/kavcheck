"""Раздел «Инвентаризация»: реестр учётных единиц, карточка, история и состояние на дату, массовые операции, поиск по коду (сканер, QR), связь с компьютерами KSC,
сводка раздела, сохранённые фильтры, вложения. Справочники и местоположения — api/inv_dirs.py, документы и печать — api/inv_docs.py, лицензии — api/inv_lic.py.

Учётные сведения меняются только здесь (через inventory/core.apply_changes) — с историей карточки и записью в журнал действий. Данные KSC только читаются."""
from __future__ import annotations

import asyncio
import hashlib
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_user
from ..inventory import core as C
from ..inventory import model as M
from ..inventory.query import Filters, where_of
from ..models import (InvAsset, InvDoc, InvDocItem, InvFile, InvHistory, InvLicense, InvLocation, InvPerson, InvProp, InvRef, InvView, KscSource, ZcHost, ZcSource, utcnow)
from ..search import column_like
from ..services.audit import write_audit
from ..services.settings import InventorySettings

router = APIRouter(prefix="/inv", tags=["inventory"])


@dataclass
class Ix:
    su: SessionUser
    acc: C.Access
    cfg: InventorySettings


async def inv_ctx(request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)) -> Ix:
    """Пользователь раздела: права (роль + личные права из настроек) и область учёта. Ответственному за зону раздел закрыт."""
    if su.is_zone:
        raise HTTPException(status_code=403, detail="Раздел недоступен")
    cfg = await request.app.state.settings_svc.get(db, "inventory")
    acc = await C.access_for(db, su, cfg)
    acc.need("view")
    await C.ensure_seed(db)
    return Ix(su, acc, cfg)


def audit(db: AsyncSession, ix: Ix, action: str, target: str, details: dict) -> None:
    write_audit(db, actor_user_id=ix.su.user_id, actor=ix.su.display_name, action=f"inv.{action}", target_type="inventory", target_id=str(target)[:120], details=details)


def bad(exc: C.Invalid) -> HTTPException:
    return HTTPException(status_code=422, detail={"message": "Проверьте значения полей", "errors": exc.errors})


async def get_asset(db: AsyncSession, ix: Ix, aid: int, *, lock: bool = False) -> InvAsset:
    stmt = select(InvAsset).where(InvAsset.id == aid)
    if (f := ix.acc.asset_filter()) is not None:
        stmt = stmt.where(f)
    if lock:
        stmt = stmt.with_for_update()
    a = (await db.execute(stmt)).scalar_one_or_none()
    if a is None:
        raise HTTPException(status_code=404, detail="Карточка не найдена или вне вашей области учёта")
    return a


def doc_filter(ix: Ix):
    """Условие на InvDoc для пользователя с областью учёта: все строки — карточки его области; документ без строк — по местоположениям «откуда/куда» или свой. Без области — None."""
    af = ix.acc.asset_filter()
    if af is None:
        return None
    items = select(InvDocItem.id).where(InvDocItem.doc_id == InvDoc.id)
    locs = ix.acc.loc_ids()
    return or_(and_(items.exists(), ~items.where(InvDocItem.asset_id.not_in(select(InvAsset.id).where(af))).exists()),
               and_(~items.exists(), or_(InvDoc.from_location_id.in_(locs), InvDoc.to_location_id.in_(locs), InvDoc.created_by == ix.su.display_name)))


async def get_doc_row(db: AsyncSession, ix: Ix, did: int, *, lock: bool = False) -> InvDoc:
    d = await db.get(InvDoc, did, with_for_update=lock)
    if d is None or ((f := doc_filter(ix)) is not None and not (await db.execute(select(InvDoc.id).where(InvDoc.id == did, f))).first()):
        raise HTTPException(status_code=404, detail="Документ не найден или вне вашей области учёта")
    return d


# ------------------------------------------------------------------------------------------------ сводные сведения раздела
@router.get("/meta")
async def meta(ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Справочники, свойства, словари и права текущего пользователя — одним запросом при входе в раздел."""
    refs = (await db.execute(select(InvRef).order_by(InvRef.kind, InvRef.sort, InvRef.name))).scalars().all()
    props = (await db.execute(select(InvProp).order_by(InvProp.sort, InvProp.id))).scalars().all()
    return {"refs": [{"id": r.id, "kind": r.kind, "name": r.name, "code": r.code, "parent_id": r.parent_id, "data": r.data or {}, "active": r.active} for r in refs],
            "props": [prop_out(p) for p in props], "perms": sorted(ix.acc.perms), "scoped": bool(ix.acc.scopes), "scope_ids": list(ix.acc.scope_ids),
            "cls": M.CLS_RU, "st": M.ST_RU, "loc_kinds": M.LOC_RU, "ref_kinds": M.REF_RU, "prop_types": M.PROP_TYPES, "roles": M.ROLES_RU, "rels": M.REL_RU, "metrics": M.METRIC_RU,
            "doc_kinds": M.DOC_RU, "doc_short": M.DOC_SHORT, "doc_status": M.DOC_STATUS_RU, "work_kinds": M.WORK_KINDS, "doc_columns": M.DOC_COLUMNS,
            "settings": {k: getattr(ix.cfg, k) for k in ("inv_prefix", "inv_digits", "warranty_days", "license_days", "transit_days", "repair_days", "stale_days", "label_code", "label_sheet")}}


def prop_out(p: InvProp) -> dict:
    return {"id": p.id, "code": p.code, "name": p.name, "descr": p.descr, "type": p.type, "options": p.options or [], "default": (p.default or {}).get("v"), "required": p.required,
            "type_ids": p.type_ids or [], "in_list": p.in_list, "sort": p.sort, "active": p.active}


@router.get("/overview")
async def overview(ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Главная раздела: состав по классам и состояниям, сроки (гарантия, лицензии), связь с KSC, незавершённые документы, последние изменения. Каждое число открывает список."""
    f = ix.acc.asset_filter()
    base = [f] if f is not None else []
    today = date.today()
    by_cls = dict((await db.execute(select(InvAsset.cls, func.count()).where(*base, InvAsset.st_cls.in_(M.ST_ACTIVE)).group_by(InvAsset.cls))).all())
    by_st = dict((await db.execute(select(InvAsset.st_cls, func.count()).where(*base).group_by(InvAsset.st_cls))).all())
    total = sum(by_st.values())
    cost = (await db.execute(select(func.coalesce(func.sum(InvAsset.cost), 0)).where(*base, InvAsset.st_cls.in_(M.ST_ACTIVE)))).scalar_one()

    async def cnt(*w) -> int:
        return (await db.execute(select(func.count()).select_from(InvAsset).where(*base, *w))).scalar_one()

    warn = await cnt(InvAsset.st_cls.in_(M.ST_ACTIVE), InvAsset.warranty_until.is_not(None), InvAsset.warranty_until >= today, InvAsset.warranty_until <= today + timedelta(days=ix.cfg.warranty_days))
    comp = InvAsset.cls.in_(M.COMPUTERS)
    act = InvAsset.st_cls.in_(M.ST_ACTIVE)
    stats = {"total": total, "active": sum(by_st.get(s, 0) for s in M.ST_ACTIVE), "cost": int(cost or 0), "cost_text": C.money_str(int(cost or 0)), "warranty_soon": warn,
             "no_owner": await cnt(act, InvAsset.st_cls == "use", InvAsset.user_id.is_(None), InvAsset.owner_id.is_(None)),
             "no_location": await cnt(act, InvAsset.location_id.is_(None)), "no_resp": await cnt(act, InvAsset.resp_id.is_(None)),
             "computers": await cnt(act, comp), "ksc_linked": await cnt(act, comp, InvAsset.ksc_host_id.is_not(None), InvAsset.ksc_link != "lost"),
             "ksc_unlinked": await cnt(act, comp, InvAsset.ksc_host_id.is_(None)), "ksc_lost": await cnt(InvAsset.ksc_link == "lost"),
             "in_transit": await cnt(InvAsset.transit_doc_id.is_not(None)),
             "stale": await cnt(act, InvAsset.updated_at < utcnow() - timedelta(days=ix.cfg.stale_days))}
    lic_soon = (await db.execute(select(func.count()).select_from(InvLicense).where(InvLicense.active.is_(True), InvLicense.valid_until.is_not(None),
                                                                                       InvLicense.valid_until <= today + timedelta(days=ix.cfg.license_days)))).scalar_one()
    docs_open = dict((await db.execute(select(InvDoc.kind, func.count()).where(InvDoc.status.not_in(("done", "cancelled"))).group_by(InvDoc.kind))).all())
    rep_long = (await db.execute(select(func.count()).select_from(InvDoc).where(InvDoc.kind == "repair", InvDoc.status == "sent", InvDoc.doc_date < today - timedelta(days=ix.cfg.repair_days)))).scalar_one()
    transit_late = (await db.execute(select(func.count()).select_from(InvDoc).where(InvDoc.kind == "move", InvDoc.status == "sent", InvDoc.doc_date < today - timedelta(days=ix.cfg.transit_days)))).scalar_one()
    hq = select(InvHistory, InvAsset.inv_no, InvAsset.name).join(InvAsset, InvAsset.id == InvHistory.asset_id).where(*base).order_by(InvHistory.at.desc()).limit(12)
    recent = [{"at": C._iso(h.at), "by": h.by, "kind": h.kind, "title": h.title, "asset_id": h.asset_id, "inv_no": no, "name": nm, "doc_id": h.doc_id} for h, no, nm in (await db.execute(hq)).all()]
    sources = (await db.execute(select(func.count()).select_from(KscSource))).scalar_one()
    from ..models import InvCount  # noqa: PLC0415

    counts_open = (await db.execute(select(func.count()).select_from(InvCount).where(InvCount.status == "active"))).scalar_one()
    return {"stats": stats, "by_cls": [{"cls": k, "name": M.CLS_RU.get(k, k), "n": v} for k, v in sorted(by_cls.items(), key=lambda x: -x[1])],
            "by_st": [{"st": k, "name": M.ST_RU.get(k, k), "n": by_st.get(k, 0)} for k in M.ST_RU if by_st.get(k)], "licenses_soon": lic_soon,
            "docs_open": [{"kind": k, "name": M.DOC_SHORT.get(k, k), "n": v} for k, v in docs_open.items()], "repair_long": rep_long, "transit_late": transit_late,
            "recent": recent, "ksc_sources": sources, "counts_open": counts_open, "cfg": {"warranty_days": ix.cfg.warranty_days, "license_days": ix.cfg.license_days, "stale_days": ix.cfg.stale_days}}


# ------------------------------------------------------------------------------------------------ реестр
SORT = {"inv_no": InvAsset.inv_no, "name": InvAsset.name, "hostname": InvAsset.hostname, "serial": InvAsset.serial, "updated": InvAsset.updated_at, "created": InvAsset.created_at,
        "warranty": InvAsset.warranty_until, "cost": InvAsset.cost, "purchase": InvAsset.purchase_date, "cls": InvAsset.cls, "status": InvAsset.st_cls}


def filters_from(request: Request) -> Filters:
    qp = request.query_params
    data: dict = {}
    for k, fld in Filters.model_fields.items():
        if k in ("ids", "props"):
            continue
        v = qp.get(k)
        if v in (None, ""):
            continue
        data[k] = v.lower() in ("1", "true", "yes") if fld.annotation is bool else v
    if qp.get("ids"):
        data["ids"] = [int(x) for x in qp["ids"].split(",") if x.strip().isdigit()][:5000]
    data["props"] = {k[2:]: v for k, v in qp.items() if k.startswith("p.") and v}
    try:
        return Filters(**data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Неверный отбор: {exc}") from None


async def page(db: AsyncSession, ix: Ix, f: Filters, sort: str, desc: bool, offset: int, limit: int) -> dict:
    w = await where_of(db, f, ix.acc, ix.cfg)
    total = (await db.execute(select(func.count()).select_from(InvAsset).where(*w))).scalar_one()
    col = SORT.get(sort, InvAsset.inv_no)
    rows = (await db.execute(select(InvAsset).where(*w).order_by(col.desc().nulls_last() if desc else col.asc().nulls_last(), InvAsset.id).offset(offset).limit(limit))).scalars().all()
    n = await C.names_for(db, list(rows))
    return {"items": [C.asset_row(a, n) for a in rows], "total": total, "offset": offset, "limit": limit}


@router.get("/assets")
async def assets(request: Request, sort: str = Query("inv_no", max_length=20), desc: bool = False, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
                 ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    return await page(db, ix, filters_from(request), sort, desc, offset, limit)


GROUP = {"cls": (InvAsset.cls, None), "type": (InvAsset.type_id, "ref"), "manufacturer": (InvAsset.manufacturer_id, "ref"), "model": (InvAsset.model_id, "ref"),
         "status": (InvAsset.status_id, "ref"), "dept": (InvAsset.dept_id, "ref"), "branch": (InvAsset.branch_id, "ref"), "location": (InvAsset.location_id, "loc"),
         "user": (InvAsset.user_id, "person"), "owner": (InvAsset.owner_id, "person"), "resp": (InvAsset.resp_id, "person"), "mol": (InvAsset.mol_id, "person"), "supplier": (InvAsset.supplier_id, "ref")}


@router.get("/assets/groups")
async def groups(request: Request, by: str = Query("type", pattern=r"^(" + "|".join(GROUP) + ")$"), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Группировка текущей выборки: значение, число единиц, сумма стоимости. Значение открывает отфильтрованный список."""
    w = await where_of(db, filters_from(request), ix.acc, ix.cfg)
    col, kind = GROUP[by]
    rows = (await db.execute(select(col, func.count(), func.coalesce(func.sum(InvAsset.cost), 0)).where(*w).group_by(col).order_by(func.count().desc()).limit(500))).all()
    ids = [r[0] for r in rows if r[0] is not None]
    names: dict = {}
    if kind == "ref" and ids:
        names = dict((await db.execute(select(InvRef.id, InvRef.name).where(InvRef.id.in_(ids)))).all())
    elif kind == "loc" and ids:
        names = dict((await db.execute(select(InvLocation.id, InvLocation.path).where(InvLocation.id.in_(ids)))).all())
    elif kind == "person" and ids:
        names = dict((await db.execute(select(InvPerson.id, InvPerson.name).where(InvPerson.id.in_(ids)))).all())
    elif kind is None:
        names = M.CLS_RU
    return {"by": by, "items": [{"id": k, "name": names.get(k, k) if k is not None else "Не указано", "n": n, "cost": int(c or 0), "cost_text": C.money_str(int(c or 0))} for k, n, c in rows]}


class AssetBody(BaseModel):
    data: dict = Field(default_factory=dict)
    comment: str = Field(default="", max_length=2000)
    basis: str = Field(default="", max_length=500)
    version: int | None = None
    force: bool = False                                          # создать, несмотря на совпадение серийного номера


@router.post("/assets", status_code=201)
async def create(body: AssetBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("create")
    data = dict(body.data)
    if not str(data.get("inv_no") or "").strip():
        data["inv_no"] = await C.next_inv_no(db, ix.cfg)
    if (await db.execute(select(InvAsset.id).where(func.lower(InvAsset.inv_no) == str(data["inv_no"]).strip().casefold()))).first():
        raise HTTPException(status_code=409, detail=f"Инвентарный номер {data['inv_no']} уже занят")
    serial = str(data.get("serial") or "").strip()
    if serial and not body.force:
        dup = (await db.execute(select(InvAsset).where(func.lower(InvAsset.serial) == serial.casefold()).limit(1))).scalar_one_or_none()
        if dup is not None:
            raise HTTPException(status_code=409, detail={"message": f"Серийный номер уже есть в карточке {dup.inv_no}. Если это другое устройство, подтвердите создание.", "duplicate": dup.id})
    if data.get("model_id"):                                       # модель подсказывает тип и значения свойств по умолчанию
        mdl = await db.get(InvRef, int(data["model_id"]))
        if mdl is not None and mdl.kind == "model":
            if not data.get("type_id") and (mdl.data or {}).get("type_id"):
                data["type_id"] = mdl.data["type_id"]
            if (mdl.data or {}).get("defaults"):
                data["props"] = {**mdl.data["defaults"], **(data.get("props") or {})}
    if not data.get("status_id"):
        st = await C.default_status(db, "stock")
        data["status_id"] = st.id if st else None
    a = InvAsset(uid=uuid.uuid4(), inv_no="-", created_by=ix.su.display_name, updated_by=ix.su.display_name, version=1)
    db.add(a)
    try:
        ch = await C.apply_changes(db, a, data, ix.acc, creating=True)
    except C.Invalid as exc:
        raise bad(exc) from None
    if not a.location_id and ix.acc.scopes:
        raise HTTPException(status_code=422, detail="Укажите местоположение в пределах вашей области учёта")
    await db.flush()
    await C.record(db, a, "create", ch, ix.su.display_name, comment=body.comment, basis=body.basis, title="Создание карточки")
    audit(db, ix, "asset.create", a.inv_no, {"id": a.id})
    await db.commit()
    return await card(a.id, ix, db)


@router.get("/assets/{aid}")
async def card(aid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Карточка: учётные сведения, состав и связи, документы, лицензии, вложения. Технические сведения — отдельно (/tech), история — /history."""
    a = await get_asset(db, ix, aid)
    n = await C.names_for(db, [a])
    kids = (await db.execute(select(InvAsset).where(InvAsset.parent_id == a.id).order_by(InvAsset.inv_no).limit(300))).scalars().all()
    kn = await C.names_for(db, list(kids), props=False)
    docs = (await db.execute(select(InvDoc).join(InvDocItem, InvDocItem.doc_id == InvDoc.id).where(InvDocItem.asset_id == a.id).order_by(InvDoc.doc_date.desc(), InvDoc.id.desc()).limit(200))).scalars().all()
    from ..models import InvLicAssign  # noqa: PLC0415

    lics = (await db.execute(select(InvLicense, InvLicAssign).join(InvLicAssign, InvLicAssign.license_id == InvLicense.id).where(InvLicAssign.asset_id == a.id))).all()
    files = (await db.execute(select(InvFile.id, InvFile.name, InvFile.size, InvFile.at, InvFile.by).where(InvFile.owner == "asset", InvFile.owner_id == a.id).order_by(InvFile.at.desc()))).all()
    src = await db.get(KscSource, a.ksc_source_id) if a.ksc_source_id else None
    return {**C.asset_row(a, n), "children": [C.asset_row(k, kn) for k in kids],
            "docs": [doc_brief(d) for d in docs], "licenses": [{"id": lc.id, "name": lc.name, "assign_id": asg.id, "at": C._iso(asg.at), "by": asg.by} for lc, asg in lics],
            "files": [{"id": i, "name": nm, "size": sz, "at": C._iso(at), "by": by} for i, nm, sz, at, by in files],
            "ksc_source": src.name if src else "", "ksc_source_ok": bool(src and ix.su.can_use_source(src.id)),
            "can": {p: ix.acc.can(p) for p in ("edit", "location", "people", "docs", "repair", "writeoff", "create")}}


def doc_brief(d: InvDoc) -> dict:
    return {"id": d.id, "no": d.no, "kind": d.kind, "kind_ru": M.DOC_SHORT.get(d.kind, d.kind), "status": d.status, "status_ru": M.DOC_STATUS_RU.get(d.status, d.status), "date": d.doc_date.isoformat()}


@router.put("/assets/{aid}")
async def update(aid: int, body: AssetBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    a = await get_asset(db, ix, aid, lock=True)
    if body.version is not None and body.version != a.version:
        raise HTTPException(status_code=409, detail=f"Карточку уже изменил {a.updated_by} ({a.updated_at:%d.%m.%Y %H:%M} UTC). Обновите страницу и повторите изменение.")
    data = {k: v for k, v in body.data.items() if k not in ("ksc_source_id", "ksc_host_id", "ksc_link", "uid", "id", "version")}
    if "inv_no" in data and str(data["inv_no"]).strip().casefold() != a.inv_no.casefold():
        if (await db.execute(select(InvAsset.id).where(func.lower(InvAsset.inv_no) == str(data["inv_no"]).strip().casefold(), InvAsset.id != a.id))).first():
            raise HTTPException(status_code=409, detail=f"Инвентарный номер {data['inv_no']} уже занят")
    try:
        ch = await C.apply_changes(db, a, data, ix.acc)
    except C.Invalid as exc:
        raise bad(exc) from None
    if ch:
        await C.record(db, a, C.kind_of(ch), ch, ix.su.display_name, comment=body.comment, basis=body.basis)
        audit(db, ix, "asset.update", a.inv_no, {"id": a.id, "fields": [c["f"] for c in ch][:40]})
        await db.commit()
    return await card(a.id, ix, db)


class BulkBody(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=5000)
    data: dict = Field(default_factory=dict)
    comment: str = Field(default="", max_length=2000)
    basis: str = Field(default="", max_length=500)
    dry_run: bool = False


BULK_FIELDS = {"no_count", "status_id", "location_id", "loc_detail", "dept_id", "branch_id", "supplier_id", "warranty_until", "purchase_date", "received_date", "commissioned_date", "props", "type_id", "model_id",
               *M.PEOPLE_FIELDS}


@router.post("/assets/bulk")
async def bulk(body: BulkBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Массовое изменение выбранных карточек: статус, местоположение, ответственные, подразделение, даты, свойства. dry_run — сколько карточек изменится, без записи.
    Каждая карточка получает своё событие истории; списание и выдачу оформляйте документом (так получится печатный акт)."""
    bad_f = set(body.data) - BULK_FIELDS
    if bad_f:
        raise HTTPException(status_code=422, detail=f"Массово эти поля не меняются: {', '.join(sorted(bad_f))}")
    if not body.data:
        raise HTTPException(status_code=422, detail="Не выбрано, что изменить")
    if "status_id" in body.data and body.data["status_id"]:
        st = await db.get(InvRef, int(body.data["status_id"]))
        if st is not None and (st.data or {}).get("cls") in ("writeoff",):
            ix.acc.need("writeoff")
    stmt = select(InvAsset).where(InvAsset.id.in_(body.ids))
    if (af := ix.acc.asset_filter()) is not None:
        stmt = stmt.where(af)
    rows = (await db.execute(stmt.with_for_update())).scalars().all()
    n = await C.names_for(db, list(rows))                          # имена всех карточек одной выборкой — дальше без запросов на каждую
    changed, errors = 0, []
    for a in rows:
        data = dict(body.data)
        if "props" in data:
            data["props"] = {**(a.props or {}), **(data["props"] or {})}
        try:
            ch = await C.apply_changes(db, a, data, ix.acc, names=n)          # при ошибке карточка возвращается в прежнее состояние (частичные значения без истории не сохраняются)
        except C.Invalid as exc:
            errors.append({"id": a.id, "inv_no": a.inv_no, "error": str(exc)})
            continue
        if ch:
            changed += 1
            if not body.dry_run:
                await C.record(db, a, C.kind_of(ch), ch, ix.su.display_name, comment=body.comment, basis=body.basis, title="Массовое изменение: " + ", ".join(dict.fromkeys(c["label"] for c in ch)), names=n)
    if body.dry_run:
        await db.rollback()
        return {"found": len(rows), "would_change": changed, "errors": errors[:50]}
    audit(db, ix, "asset.bulk", f"{changed} карточек", {"ids": body.ids[:100], "n": len(body.ids), "fields": sorted(body.data)})
    await db.commit()
    return {"found": len(rows), "changed": changed, "errors": errors[:50], "missing": len(body.ids) - len(rows)}


@router.get("/assets/{aid}/history")
async def history(aid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    a = await get_asset(db, ix, aid)
    rows = (await db.execute(select(InvHistory).where(InvHistory.asset_id == a.id).order_by(InvHistory.at.desc(), InvHistory.id.desc()).limit(2000))).scalars().all()
    docs = {d.id: d.no for d in (await db.execute(select(InvDoc).where(InvDoc.id.in_({h.doc_id for h in rows} - {None})))).scalars()} if rows else {}
    return {"items": [hist_out(h, docs) for h in rows]}


def hist_out(h: InvHistory, docs: dict | None = None) -> dict:
    return {"id": h.id, "at": C._iso(h.at), "by": h.by, "kind": h.kind, "kind_ru": M.HIST_RU.get(h.kind, h.kind), "title": h.title, "changes": h.changes, "state": h.state,
            "comment": h.comment, "basis": h.basis, "doc_id": h.doc_id, "doc_no": (docs or {}).get(h.doc_id, "")}


@router.get("/assets/{aid}/asof")
async def as_of(aid: int, on: date, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Учётное состояние на конец указанной даты: статус, местоположение, пользователь, владелец, ответственные — по последнему событию истории не позже даты."""
    a = await get_asset(db, ix, aid)
    end = datetime(on.year, on.month, on.day, tzinfo=timezone.utc) + timedelta(days=1)
    h = (await db.execute(select(InvHistory).where(InvHistory.asset_id == a.id, InvHistory.at < end).order_by(InvHistory.at.desc(), InvHistory.id.desc()).limit(1))).scalar_one_or_none()
    if h is None:
        return {"on": on.isoformat(), "exists": False, "state": None, "note": "На эту дату карточки ещё не было."}
    return {"on": on.isoformat(), "exists": True, "state": h.state, "event": hist_out(h)}


@router.get("/lookup")
async def lookup(code: str = Query(min_length=1, max_length=500), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Отсканированный код (QR со ссылкой на карточку, инвентарный или серийный номер) → карточка."""
    a = await C.asset_by_code(db, code)
    if a is None or ((af := ix.acc.asset_filter()) is not None and not (await db.execute(select(InvAsset.id).where(InvAsset.id == a.id, af))).first()):
        raise HTTPException(status_code=404, detail=f"Карточка по коду «{code[:60]}» не найдена")
    n = await C.names_for(db, [a], props=False)
    return C.asset_row(a, n)


@router.get("/a/{uid}")
async def by_uid(uid: uuid.UUID, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    a = (await db.execute(select(InvAsset.id).where(InvAsset.uid == uid))).scalar_one_or_none()
    if a is None:
        raise HTTPException(status_code=404, detail="Карточка не найдена")
    return {"id": a}


# ------------------------------------------------------------------------------------------------ связь с KSC
async def zc_host(db: AsyncSession, sid: uuid.UUID, hid: int) -> ZcHost | None:
    gen = (await db.execute(select(ZcSource.gen).where(ZcSource.source_id == sid))).scalar()
    if not gen:
        return None
    return (await db.execute(select(ZcHost).where(ZcHost.source_id == sid, ZcHost.host_id == hid, ZcHost.gen == gen))).scalars().first()


@router.get("/by-host")
async def by_host(source: uuid.UUID, host: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Учётные сведения для карточки компьютера KSC: связанная учётная карточка или предложения (карточки с тем же именем, ещё не связанные)."""
    if not ix.su.can_use_source(source):
        raise HTTPException(status_code=403, detail="Нет доступа к источнику")
    a = (await db.execute(select(InvAsset).where(InvAsset.ksc_source_id == source, InvAsset.ksc_host_id == host))).scalar_one_or_none()
    can_link = ix.acc.can("edit") or ix.acc.can("create")
    if a is not None:
        if (af := ix.acc.asset_filter()) is not None and not (await db.execute(select(InvAsset.id).where(InvAsset.id == a.id, af))).first():
            return {"asset": None, "hidden": True, "candidates": [], "can_link": False, "can_create": False}
        n = await C.names_for(db, [a])
        return {"asset": C.asset_row(a, n), "candidates": [], "can_link": can_link, "can_create": False}
    h = await zc_host(db, source, host)
    cands = []
    if h is not None and h.name:
        short = h.name.split(".")[0].casefold()
        stmt = select(InvAsset).where(InvAsset.ksc_host_id.is_(None), or_(InvAsset.hostname == short, InvAsset.hostname == h.name.casefold(), func.lower(InvAsset.name) == short))
        if (af := ix.acc.asset_filter()) is not None:
            stmt = stmt.where(af)
        rows = (await db.execute(stmt.limit(10))).scalars().all()
        n = await C.names_for(db, list(rows), props=False)
        cands = [C.asset_row(x, n) for x in rows]
    return {"asset": None, "candidates": cands, "can_link": can_link, "can_create": ix.acc.can("create"), "host_name": h.name if h else ""}


class LinkBody(BaseModel):
    source_id: uuid.UUID | None = None
    host_id: int | None = None
    comment: str = Field(default="", max_length=500)


@router.put("/assets/{aid}/ksc")
async def link(aid: int, body: LinkBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Связать карточку с компьютером KSC (решение пользователя — «подтверждено») или снять связь (source_id = null). Данные KSC не меняются."""
    ix.acc.need("edit")
    a = await get_asset(db, ix, aid, lock=True)
    old = f"{a.ksc_name} ({a.ksc_host_id})" if a.ksc_host_id else ""
    if body.source_id is None or body.host_id is None:
        a.ksc_source_id = a.ksc_host_id = None
        a.ksc_link, a.ksc_name, a.linked_at = "", "", None
        ch = [{"f": "ksc", "label": "Компьютер KSC", "old": old, "new": ""}]
    else:
        if not ix.su.can_use_source(body.source_id):
            raise HTTPException(status_code=403, detail="Нет доступа к источнику")
        other = (await db.execute(select(InvAsset).where(InvAsset.ksc_source_id == body.source_id, InvAsset.ksc_host_id == body.host_id, InvAsset.id != a.id))).scalar_one_or_none()
        if other is not None:
            raise HTTPException(status_code=409, detail=f"Компьютер уже связан с карточкой {other.inv_no}")
        h = await zc_host(db, body.source_id, body.host_id)
        a.ksc_source_id, a.ksc_host_id, a.ksc_link, a.linked_at = body.source_id, body.host_id, "confirmed", utcnow()
        a.ksc_name = (h.name if h else "")[:300]
        if h is not None and not a.hostname:
            a.hostname = h.name.split(".")[0].lower()[:255]
        ch = [{"f": "ksc", "label": "Компьютер KSC", "old": old, "new": f"{a.ksc_name} ({body.host_id})"}]
    await C.record(db, a, "link", ch, ix.su.display_name, comment=body.comment)
    audit(db, ix, "asset.link", a.inv_no, {"source": str(body.source_id) if body.source_id else None, "host": body.host_id})
    await db.commit()
    return {"ok": True}


@router.get("/ksc/hosts")
async def ksc_hosts(source: str = Query("", max_length=2000), q: str = Query("", max_length=200), unlinked: bool = True, days: int | None = Query(None, ge=1, le=3650),
                    offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Компьютеры источников из подготовленных данных (KSC не опрашивается): для создания карточек и ручного сопоставления.
    source — один или несколько источников через запятую (пусто — все доступные); unlinked — только без учётной карточки; days — только выходившие на связь за столько суток."""
    want = [x.strip() for x in source.split(",") if x.strip()]
    try:
        ids = [uuid.UUID(x) for x in want]
    except ValueError:
        raise HTTPException(status_code=422, detail="Неверный идентификатор источника") from None
    srcs = {s.id: s for s in (await db.execute(select(KscSource))).scalars() if ix.su.can_use_source(s.id) and (not ids or s.id in ids)}
    if ids and set(ids) - set(srcs):
        raise HTTPException(status_code=403, detail="Нет доступа к источнику")
    gens = {sid: g for sid, g in (await db.execute(select(ZcSource.source_id, ZcSource.gen).where(ZcSource.source_id.in_(list(srcs)), ZcSource.gen > 0))).all()} if srcs else {}
    missing = [srcs[x].name for x in srcs if x not in gens]
    note = f"Подготовленные данные ещё не рассчитаны: {', '.join(missing)} (Администрирование → Расчёт данных зон)." if missing else ""
    if not gens:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "note": note}
    w = [or_(*[and_(ZcHost.source_id == sid, ZcHost.gen == g) for sid, g in gens.items()])]
    if (c := column_like(ZcHost.search, q.strip())) is not None:
        w.append(c)
    if unlinked:                                                   # NOT EXISTS, а не список: десятки тысяч связанных карточек не упираются в предел параметров
        w.append(~select(InvAsset.id).where(InvAsset.ksc_source_id == ZcHost.source_id, InvAsset.ksc_host_id == ZcHost.host_id).exists())
    old = None
    if days:                                                       # скрытые фильтром активности — при тех же остальных условиях
        fresh = ZcHost.last_connected >= utcnow() - timedelta(days=days)
        old = (await db.execute(select(func.count()).select_from(ZcHost).where(*w, or_(ZcHost.last_connected.is_(None), ~fresh)))).scalar_one()
        w.append(fresh)
    total = (await db.execute(select(func.count()).select_from(ZcHost).where(*w))).scalar_one()
    rows = (await db.execute(select(ZcHost).where(*w).order_by(ZcHost.name, ZcHost.source_id).offset(offset).limit(limit))).scalars().all()
    linked = {(str(a), h): i for a, h, i in (await db.execute(select(InvAsset.ksc_source_id, InvAsset.ksc_host_id, InvAsset.id).where(InvAsset.ksc_host_id.in_([r.host_id for r in rows])))).all()} if rows else {}
    return {"items": [{"source_id": str(r.source_id), "source": srcs[r.source_id].name, "host_id": r.host_id, "name": r.name, "os": r.os, "ip": (r.data or {}).get("ip", ""),
                       "group": (r.data or {}).get("group", ""), "last_connected": C._iso(r.last_connected), "active": r.active, "asset_id": linked.get((str(r.source_id), r.host_id))} for r in rows],
            "total": total, "offset": offset, "limit": limit, "note": note, "hidden_old": old}


class HostRef(BaseModel):
    source_id: uuid.UUID
    host_id: int


class ImportBody(BaseModel):
    source_id: uuid.UUID | None = None
    host_ids: list[int] = Field(default_factory=list, max_length=1000)
    hosts: list[HostRef] = Field(default_factory=list, max_length=1000)          # из нескольких источников сразу
    status_id: int | None = None
    location_id: int | None = None


def cls_from(os_name: str, name: str, group: str = "") -> str:
    """Класс новой карточки по сведениям KSC: серверная ОС или группа администрирования «Серверы» — физический сервер, иначе рабочая станция (меняется массово)."""
    o = (os_name or "").casefold()
    g = (group or "").casefold()
    if "server" in o or "сервер" in o or "сервер" in g or "server" in g or any(x in o for x in ("centos", "red hat", "rhel", "astra linux se", "debian", "ubuntu server", "alt server", "oracle linux", "rocky", "almalinux")):
        return "server"
    return "workstation"


@router.post("/ksc/import")
async def ksc_import(body: ImportBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Создать учётные карточки для компьютеров KSC (из подготовленных данных) одного или нескольких источников: имя, тип по ОС и группе, связь «подтверждено».
    Повторный запуск не создаёт дублей: уже связанные компьютеры пропускаются (уникальность «источник + компьютер»). Порция — до 1000 компьютеров."""
    ix.acc.need("create")
    pairs = [(h.source_id, h.host_id) for h in body.hosts] + ([(body.source_id, i) for i in body.host_ids] if body.source_id else [])
    if not pairs or len(pairs) > 1000:
        raise HTTPException(status_code=422, detail="Выберите от 1 до 1000 компьютеров")
    if ix.acc.scopes and not body.location_id:
        raise HTTPException(status_code=422, detail="Укажите местоположение в пределах вашей области учёта")
    types = {c: await C.type_for_cls(db, c) for c in ("server", "workstation")}
    st = body.status_id or ((await C.default_status(db, "use")) or InvRef(id=None)).id
    created, skipped = [], 0
    n = C.Names()                                                  # общий кэш имён на всю порцию
    by_src: dict = {}
    for sid, hid in pairs:
        by_src.setdefault(sid, []).append(hid)
    for sid, hids in by_src.items():
        if not ix.su.can_use_source(sid):
            raise HTTPException(status_code=403, detail="Нет доступа к источнику")
        gen = (await db.execute(select(ZcSource.gen).where(ZcSource.source_id == sid))).scalar()
        if not gen:
            skipped += len(hids)
            continue
        hosts = (await db.execute(select(ZcHost).where(ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.host_id.in_(hids)))).scalars().all()
        have = {h for (h,) in (await db.execute(select(InvAsset.ksc_host_id).where(InvAsset.ksc_source_id == sid, InvAsset.ksc_host_id.in_(hids))))}
        nos = iter(await C.next_inv_nos(db, ix.cfg, sum(h.host_id not in have for h in hosts)))
        for h in hosts:
            if h.host_id in have:
                skipped += 1
                continue
            cls = cls_from(h.os, h.name, (h.data or {}).get("group", ""))
            a = InvAsset(uid=uuid.uuid4(), inv_no=next(nos), created_by=ix.su.display_name, updated_by=ix.su.display_name, version=1,
                         ksc_source_id=sid, ksc_host_id=h.host_id, ksc_link="confirmed", ksc_name=h.name[:300], linked_at=utcnow())
            db.add(a)
            data = {"name": h.name.split(".")[0][:300], "hostname": h.name.split(".")[0].lower(), "type_id": types[cls].id if types[cls] else None, "status_id": st}
            if body.location_id:
                data["location_id"] = body.location_id
            try:
                ch = await C.apply_changes(db, a, data, ix.acc, creating=True, names=n)
            except C.Invalid as exc:
                raise bad(exc) from None
            await db.flush()
            await C.record(db, a, "import", ch, ix.su.display_name, title=f"Создание карточки по компьютеру KSC {h.name}", names=n)
            created.append(a.id)
        skipped += len(set(hids) - {h.host_id for h in hosts})
    audit(db, ix, "ksc.import", ",".join(str(x) for x in by_src)[:120], {"created": len(created), "requested": len(pairs)})
    await db.commit()
    return {"created": len(created), "skipped": len(pairs) - len(created), "ids": created}


@router.get("/assets/{aid}/tech")
async def tech(aid: int, request: Request, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Технические сведения связанного компьютера (из KSC, только чтение): ОС, адрес, связь с KSC, аппаратная часть, идентификаторы, установленное ПО, владелец по BI.
    Расхождения с учётной карточкой (серийный номер, имя) показываются, но не исправляются автоматически."""
    from ..bi import read as BR  # noqa: PLC0415
    from ..ksc import hardware as HW  # noqa: PLC0415
    from ..ksc import queries as q  # noqa: PLC0415
    from ..ksc.driver import KscError  # noqa: PLC0415

    a = await get_asset(db, ix, aid)
    if not a.ksc_source_id or a.ksc_host_id is None:
        return {"linked": False}
    src = await db.get(KscSource, a.ksc_source_id)
    if src is None:
        return {"linked": True, "error": "Источник KSC удалён"}
    if not ix.su.can_use_source(src.id):
        return {"linked": True, "error": "Нет доступа к источнику KSC этой карточки", "source": src.name}
    out: dict = {"linked": True, "source": src.name, "source_id": str(src.id), "host_id": a.ksc_host_id, "fetched_at": utcnow().isoformat()}
    zh = await zc_host(db, src.id, a.ksc_host_id)
    if zh is not None:
        d = zh.data or {}
        out["prepared"] = {"name": zh.name, "os": zh.os, "ip": d.get("ip", ""), "group": d.get("group", ""), "last_connected": C._iso(zh.last_connected), "active": zh.active, "has_av": zh.has_av}
    client = request.app.state.sources.client(src)
    try:
        host = await client.run(q.HOST_ONE, {"id": a.ksc_host_id}, max_rows=1)
        if not host:
            out["missing"] = True
            return out
        rows = await client.run(q.HW_HOST, {"id": a.ksc_host_id}, max_rows=2000)
        sw = await client.run(q.SOFTWARE_ON_HOST, {"id": a.ksc_host_id}, max_rows=20_000)
    except KscError as exc:
        out["error"] = f"KSC недоступен: {exc}"
        return out
    h = host[0]
    hw = HW.finish(HW.summarize(rows))
    board_serial = next((str(r.get("serial") or "").strip() for r in rows if int(r.get("dev_type") or -1) == 0 and str(r.get("serial") or "").strip()), "")
    macs = sorted({n["mac"] for n in hw.get("nics", []) if n.get("mac")})
    out.update(host={"name": h.get("name") or "", "fqdn": h.get("dns_name") or h.get("fqdn") or "", "os": h.get("os") or h.get("os_name") or "", "last_connected": C._iso(h.get("last_connected"))},
               hw=hw, ids={"board_serial": board_serial, "macs": macs},
               software=[{"name": s.get("name") or "", "version": s.get("version") or "", "publisher": s.get("publisher") or "", "install_date": C._iso(s.get("install_date"))} for s in sw])
    issues = []
    if a.serial and board_serial and a.serial.casefold() != board_serial.casefold():
        issues.append(f"Серийный номер в карточке ({a.serial}) отличается от сведений KSC ({board_serial})")
    nm = (h.get("name") or "").split(".")[0].casefold()
    if a.hostname and nm and a.hostname.casefold() != nm:
        issues.append(f"Имя компьютера в карточке ({a.hostname}) отличается от KSC ({nm})")
    out["issues"] = issues
    owners = await BR.owners_for(db, src.id, [a.ksc_host_id], pd=ix.su.is_analyst, inv=False)
    out["bi_owner"] = owners.get(a.ksc_host_id)
    return out


# ------------------------------------------------------------------------------------------------ сохранённые фильтры
class ViewBody(BaseModel):
    page: str = Field(pattern=r"^[a-z_]{2,20}$")
    name: str = Field(min_length=1, max_length=100)
    params: dict = Field(default_factory=dict)
    shared: bool = False


@router.get("/views")
async def views(page_: str = Query(alias="page", pattern=r"^[a-z_]{2,20}$"), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(InvView).where(InvView.page == page_, or_(InvView.user_id == ix.su.user_id, InvView.shared.is_(True))).order_by(InvView.name))).scalars().all()
    return {"items": [{"id": v.id, "name": v.name, "params": v.params, "shared": v.shared, "mine": v.user_id == ix.su.user_id} for v in rows]}


@router.post("/views", status_code=201)
async def add_view(body: ViewBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    if len(str(body.params)) > 4000:
        raise HTTPException(status_code=422, detail="Слишком большой фильтр")
    v = InvView(user_id=ix.su.user_id, page=body.page, name=body.name.strip(), params=body.params, shared=body.shared and ix.acc.can("edit"))
    db.add(v)
    await db.commit()
    return {"id": v.id}


@router.delete("/views/{vid}")
async def del_view(vid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    v = await db.get(InvView, vid)
    if v is None or (v.user_id != ix.su.user_id and not ix.su.is_admin):
        raise HTTPException(status_code=404, detail="Фильтр не найден")
    await db.delete(v)
    await db.commit()
    return {"ok": True}


# ------------------------------------------------------------------------------------------------ вложения
MAX_FILE = 15 * 1024 * 1024
OWNER_PERM = {"asset": "edit", "doc": "docs", "license": "edit"}


async def _owner_ok(db: AsyncSession, ix: Ix, owner: str, oid: int) -> None:
    if owner == "asset":
        await get_asset(db, ix, oid)
    elif owner == "doc":
        await get_doc_row(db, ix, oid)
    elif owner == "license":
        if await db.get(InvLicense, oid) is None:
            raise HTTPException(status_code=404, detail="Лицензия не найдена")
    else:
        raise HTTPException(status_code=422, detail="Неизвестный владелец вложения")


@router.post("/files", status_code=201)
async def upload(request: Request, owner: str = Query(pattern=r"^(asset|doc|license)$"), oid: int = Query(ge=1), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Вложение (тело — файл, имя — заголовок X-File-Name). Не больше 15 МБ; хранится в базе — попадает в резервные копии."""
    ix.acc.need(OWNER_PERM[owner])
    await _owner_ok(db, ix, owner, oid)
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > MAX_FILE:
            raise HTTPException(status_code=413, detail="Файл больше 15 МБ")
    if not buf:
        raise HTTPException(status_code=422, detail="Пустой файл")
    name = unquote(request.headers.get("x-file-name", "") or "file").replace("/", "_").replace("\\", "_")[:300]
    f = InvFile(owner=owner, owner_id=oid, name=name, mime=(request.headers.get("content-type") or "application/octet-stream")[:120], size=len(buf),
                sha256=hashlib.sha256(buf).hexdigest(), data=bytes(buf), by=ix.su.display_name)
    db.add(f)
    if owner == "asset":
        a = await get_asset(db, ix, oid)
        await C.record(db, a, "update", [{"f": "file", "label": "Вложение", "old": "", "new": name}], ix.su.display_name, title="Добавлено вложение")
    audit(db, ix, "file.add", f"{owner}:{oid}", {"name": name, "size": len(buf)})
    await db.commit()
    return {"id": f.id}


@router.get("/files/{fid}")
async def download(fid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    f = await db.get(InvFile, fid)
    if f is None:
        raise HTTPException(status_code=404, detail="Вложение не найдено")
    await _owner_ok(db, ix, f.owner, f.owner_id)
    from urllib.parse import quote  # noqa: PLC0415

    return Response(content=f.data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(f.name)}", "X-Content-Type-Options": "nosniff"})


@router.delete("/files/{fid}")
async def del_file(fid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    f = await db.get(InvFile, fid)
    if f is None:
        raise HTTPException(status_code=404, detail="Вложение не найдено")
    ix.acc.need(OWNER_PERM[f.owner])
    await _owner_ok(db, ix, f.owner, f.owner_id)
    if f.owner == "asset":
        a = await get_asset(db, ix, f.owner_id)
        await C.record(db, a, "update", [{"f": "file", "label": "Вложение", "old": f.name, "new": ""}], ix.su.display_name, title="Удалено вложение")
    audit(db, ix, "file.delete", f"{f.owner}:{f.owner_id}", {"name": f.name})
    await db.delete(f)
    await db.commit()
    return {"ok": True}


# ------------------------------------------------------------------------------------------------ импорт Excel / CSV
async def _body(request: Request, limit: int) -> bytes:
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > limit:
            raise HTTPException(status_code=413, detail="Файл больше 30 МБ")
    return bytes(buf)


@router.get("/import/template")
async def import_template(fmt: str = Query("xlsx", pattern=r"^(xlsx|csv)$"), example: bool = False, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Шаблон файла импорта (пустой или с вымышленным примером): столбцы совпадают с полями сопоставления."""
    from ..inventory import importer as IM  # noqa: PLC0415

    ix.acc.need("import")
    props = list((await db.execute(select(InvProp).where(InvProp.active.is_(True)).order_by(InvProp.id))).scalars())
    name = f"inventory-import-{'example' if example else 'template'}.{fmt}"
    media = "text/csv; charset=utf-8" if fmt == "csv" else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return Response(IM.template(fmt, example, props), media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.post("/import/preview")
async def import_preview(request: Request, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Разбор файла (тело — XLSX или CSV, имя — X-File-Name): заголовки, предложенное сопоставление столбцов, первые строки. Ничего не записывается."""
    from ..inventory import importer as IM  # noqa: PLC0415

    ix.acc.need("import")
    data = await _body(request, IM.MAX_BYTES)
    try:
        hdr, rows = await asyncio.to_thread(IM.read_table, data, unquote(request.headers.get("x-file-name", "") or "file.csv"))   # разбор большого файла не останавливает остальные запросы
    except IM.ImportError_ as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    props = list((await db.execute(select(InvProp).where(InvProp.active.is_(True)))).scalars())
    return {"headers": hdr, "rows": rows[:20], "total": len(rows), "mapping": IM.suggest(hdr, props), "fields": IM.FIELDS, "props": {p.code: p.name for p in props}}


@router.post("/import/run")
async def import_run(request: Request, mode: str = Query("upsert", pattern=r"^(create|upsert)$"), create_refs: bool = True, dry_run: bool = True,
                     ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Проверка (dry_run=true — сколько будет создано и изменено, ошибки по строкам, без записи) или импорт. Сопоставление столбцов — заголовок X-Mapping (JSON, URL-кодированный)."""
    import json  # noqa: PLC0415

    from ..inventory import importer as IM  # noqa: PLC0415

    ix.acc.need("import")
    if mode == "upsert":
        ix.acc.need("edit")
    try:
        mapping = json.loads(unquote(request.headers.get("x-mapping", "") or "{}"))
        assert isinstance(mapping, dict)
    except (ValueError, AssertionError):
        raise HTTPException(status_code=422, detail="Неверное сопоставление столбцов") from None
    data = await _body(request, IM.MAX_BYTES)
    name = unquote(request.headers.get("x-file-name", "") or "file.csv")
    try:
        hdr, rows = await asyncio.to_thread(IM.read_table, data, name)
        st = await IM.run(db, hdr, rows, {str(k): str(v) for k, v in mapping.items()}, mode=mode, create_refs=create_refs, acc=ix.acc, cfg=ix.cfg, by=ix.su.display_name, dry_run=dry_run)
    except IM.ImportError_ as exc:
        await db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if dry_run:
        await db.rollback()
        return {**st, "dry_run": True}
    audit(db, ix, "import", name[:120], {k: st[k] for k in ("rows", "created", "updated", "skipped")})
    await db.commit()
    return {**st, "dry_run": False}


# ------------------------------------------------------------------------------------------------ склад
@router.get("/stock")
async def stock(ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Склад: единицы по состояниям учёта, свободное на складе по моделям, резерв, комплектующие (установлены / на складе), последние поступления."""
    f = ix.acc.asset_filter()
    base = [f] if f is not None else []
    by_st = dict((await db.execute(select(InvAsset.st_cls, func.count()).where(*base).group_by(InvAsset.st_cls))).all())
    q = (select(InvAsset.type_id, InvAsset.manufacturer_id, InvAsset.model_id, InvAsset.st_cls, func.count(), func.coalesce(func.sum(InvAsset.cost), 0))
         .where(*base, InvAsset.st_cls.in_(("stock", "reserve"))).group_by(InvAsset.type_id, InvAsset.manufacturer_id, InvAsset.model_id, InvAsset.st_cls))
    rows = (await db.execute(q)).all()
    ids = {x for r in rows for x in r[:3]} - {None}
    names = dict((await db.execute(select(InvRef.id, InvRef.name).where(InvRef.id.in_(ids)))).all()) if ids else {}
    agg: dict = {}
    for t, m, mo, st, n, cost in rows:
        k = (t, m, mo)
        a = agg.setdefault(k, {"type_id": t, "type": names.get(t, ""), "model_id": mo, "model": " ".join(x for x in (names.get(m, ""), names.get(mo, "")) if x), "stock": 0, "reserve": 0, "cost": 0})
        a[st] += n
        a["cost"] += int(cost or 0)
    comp = select(func.count()).select_from(InvAsset).where(*base, InvAsset.cls == "component", InvAsset.st_cls.in_(M.ST_ACTIVE))
    comp_in = (await db.execute(comp.where(InvAsset.parent_id.is_not(None)))).scalar_one()
    comp_free = (await db.execute(comp.where(InvAsset.parent_id.is_(None)))).scalar_one()
    rec = (await db.execute(select(InvDoc).where(InvDoc.kind == "receipt").order_by(InvDoc.doc_date.desc(), InvDoc.id.desc()).limit(15))).scalars().all()
    return {"by_st": {k: by_st.get(k, 0) for k in M.ST_RU}, "models": sorted(agg.values(), key=lambda x: -(x["stock"] + x["reserve"])),
            "components": {"installed": comp_in, "free": comp_free},
            "receipts": [{**doc_brief(d), "lines": len((d.data or {}).get("lines") or []), "qty": sum(int(x.get("qty") or 1) for x in (d.data or {}).get("lines") or []),
                          "created": len((d.data or {}).get("created") or [])} for d in rec]}


@router.post("/notify/test")
async def notify_test(request: Request, ix: Ix = Depends(inv_ctx)):
    """Отправить сводку сроков сейчас (проверка получателей и SMTP). Только администратор."""
    from ..inventory import service as SV  # noqa: PLC0415

    if not ix.su.is_admin:
        raise HTTPException(status_code=403, detail="Только администратор")
    r = await SV.send_digest(request.app.state.session_maker, request.app.state.settings_svc, by=ix.su.display_name)
    return r


@router.get("/notify/preview")
async def notify_preview(ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    from ..inventory import service as SV  # noqa: PLC0415

    return {"sections": await SV.digest(db, ix.cfg)}
