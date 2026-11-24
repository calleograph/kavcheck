"""Отбор реестра учётных единиц — общий для списка, группировки, массовых операций и отчётов (тот же набор параметров передаётся в конструктор отчёта)."""
from __future__ import annotations

import uuid
from datetime import date, timedelta

from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import InvAsset, InvLocation, InvProp, utcnow
from ..search import column_like
from ..services.settings import InventorySettings
from . import core as C
from . import model as M


class Filters(BaseModel):
    """Отбор реестра — общий для списка, группировки, массовых операций и отчётов (тот же набор параметров передаётся в конструктор отчёта)."""
    q: str = Field(default="", max_length=300)
    cls: str = Field(default="", max_length=200)                # через запятую
    type_id: int | None = None
    model_id: int | None = None
    manufacturer_id: int | None = None
    status_id: int | None = None
    st: str = Field(default="", max_length=100)                 # active | состояния через запятую
    location: int | None = None                                  # поддерево
    no_location: bool = False
    person: int | None = None
    role: str = Field(default="", pattern=r"^(|user|owner|resp|mol|it)$")
    dept_id: int | None = None
    branch_id: int | None = None
    zone_id: uuid.UUID | None = None
    supplier_id: int | None = None
    ksc: str = Field(default="", pattern=r"^(|linked|unlinked|lost|auto)$")
    warranty: str = Field(default="", pattern=r"^(|soon|expired|none|valid)$")
    transit: bool = False
    no_owner: bool = False
    no_resp: bool = False
    stale: bool = False
    parent: int | None = None
    ids: list[int] = Field(default_factory=list, max_length=5000)
    props: dict[str, str] = Field(default_factory=dict)          # код свойства → значение (для текста — вхождение)



async def where_of(db: AsyncSession, f: Filters, acc: C.Access, cfg: InventorySettings) -> list:
    """Условия отбора карточек: область учёта пользователя и параметры отбора."""
    w = []
    if (af := acc.asset_filter()) is not None:
        w.append(af)
    for word in f.q.split()[:8]:
        if (c := column_like(InvAsset.search, word)) is not None:
            w.append(c)
    if f.cls:
        w.append(InvAsset.cls.in_([x for x in f.cls.split(",") if x in M.CLS_RU]))
    for col, v in ((InvAsset.type_id, f.type_id), (InvAsset.model_id, f.model_id), (InvAsset.manufacturer_id, f.manufacturer_id), (InvAsset.status_id, f.status_id),
                   (InvAsset.dept_id, f.dept_id), (InvAsset.branch_id, f.branch_id), (InvAsset.zone_id, f.zone_id), (InvAsset.supplier_id, f.supplier_id), (InvAsset.parent_id, f.parent)):
        if v is not None:
            w.append(col == v)
    if f.st == "active":
        w.append(InvAsset.st_cls.in_(M.ST_ACTIVE))
    elif f.st:
        w.append(InvAsset.st_cls.in_([x for x in f.st.split(",") if x in M.ST_RU]))
    if f.location is not None:
        loc = await db.get(InvLocation, f.location)
        w.append(InvAsset.location_id.in_(select(InvLocation.id).where(InvLocation.ids_path.like((loc.ids_path if loc else "/-/") + "%"))))
    if f.no_location:
        w.append(InvAsset.location_id.is_(None))
    if f.person is not None:
        cols = [getattr(InvAsset, f"{f.role}_id")] if f.role else [getattr(InvAsset, x) for x in M.PEOPLE_FIELDS]
        w.append(or_(*[c == f.person for c in cols]))
    if f.ksc == "linked":
        w.append(and_(InvAsset.ksc_host_id.is_not(None), InvAsset.ksc_link != "lost"))
    elif f.ksc == "unlinked":
        w.append(and_(InvAsset.ksc_host_id.is_(None), InvAsset.cls.in_(M.COMPUTERS)))
    elif f.ksc:
        w.append(InvAsset.ksc_link == f.ksc)
    today = date.today()
    if f.warranty == "soon":
        w.append(and_(InvAsset.warranty_until >= today, InvAsset.warranty_until <= today + timedelta(days=cfg.warranty_days)))
    elif f.warranty == "expired":
        w.append(InvAsset.warranty_until < today)
    elif f.warranty == "valid":
        w.append(InvAsset.warranty_until >= today)
    elif f.warranty == "none":
        w.append(InvAsset.warranty_until.is_(None))
    if f.transit:
        w.append(InvAsset.transit_doc_id.is_not(None))
    if f.no_owner:
        w.append(and_(InvAsset.user_id.is_(None), InvAsset.owner_id.is_(None)))
    if f.no_resp:
        w.append(InvAsset.resp_id.is_(None))
    if f.stale:
        w.append(InvAsset.updated_at < utcnow() - timedelta(days=cfg.stale_days))
    if f.ids:
        w.append(InvAsset.id.in_(f.ids))
    if f.props:
        defs = {p.code: p for p in (await db.execute(select(InvProp))).scalars()}
        for code, v in list(f.props.items())[:10]:
            p = defs.get(code)
            if p is None:
                continue
            el = InvAsset.props[code].as_string()
            if p.type in ("text", "multiline", "url", "multiselect"):
                w.append(func.lower(func.coalesce(el, "")).like(f"%{v.casefold().replace('%', '').replace('_', '')}%"))
            elif p.type == "bool":
                w.append(InvAsset.props[code].as_boolean().is_(v.lower() in ("1", "true", "да")))
            else:
                w.append(el == v)
    return w
