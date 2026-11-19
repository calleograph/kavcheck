"""Справочники раздела «Инвентаризация»: местоположения (дерево с числом единиц), справочники (типы, производители, модели, статусы, поставщики, подразделения, филиалы,
типы лицензий, категории программ), дополнительные свойства, сотрудники учёта (свои и перенесённые из BI и адресной книги)."""
from __future__ import annotations

import re
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_db
from ..inventory import core as C
from ..inventory import model as M
from ..models import BiPerson, HierSnapshot, InvAsset, InvDoc, InvHistory, InvLicense, InvLocation, InvPerson, InvProp, InvRef
from ..search import column_like
from .inv import Ix, audit, inv_ctx, prop_out

router = APIRouter(prefix="/inv", tags=["inventory"])


# ------------------------------------------------------------------------------------------------ местоположения
def loc_out(x: InvLocation, direct: int = 0, total: int = 0, cost: int = 0) -> dict:
    return {"id": x.id, "parent_id": x.parent_id, "kind": x.kind, "kind_ru": M.LOC_RU.get(x.kind, x.kind), "name": x.name, "code": x.code, "note": x.note, "path": x.path,
            "data": x.data or {}, "active": x.active, "sort": x.sort, "n": direct, "total": total, "cost": cost}


@router.get("/locations")
async def locations(ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Всё дерево местоположений с числом действующих единиц: прямо в узле и во всём поддереве (для карты площадок). Пользователь с ограничением видит свои поддеревья и их предков."""
    rows = (await db.execute(select(InvLocation).order_by(InvLocation.sort, InvLocation.name))).scalars().all()
    direct = dict((await db.execute(select(InvAsset.location_id, func.count()).where(InvAsset.st_cls.in_(M.ST_ACTIVE)).group_by(InvAsset.location_id))).all())
    by_cls: dict[int, dict] = defaultdict(dict)
    for lid, cls, n in (await db.execute(select(InvAsset.location_id, InvAsset.cls, func.count()).where(InvAsset.st_cls.in_(M.ST_ACTIVE)).group_by(InvAsset.location_id, InvAsset.cls))).all():
        by_cls[lid][cls] = n
    total: dict[int, int] = defaultdict(int)
    cls_total: dict[int, dict] = defaultdict(lambda: defaultdict(int))
    for x in rows:
        ids = [int(i) for i in x.ids_path.strip("/").split("/") if i]
        for anc in ids:
            total[anc] += direct.get(x.id, 0)
            for c, n in by_cls.get(x.id, {}).items():
                cls_total[anc][c] += n
    vis = rows
    if ix.acc.scopes:
        vis = [x for x in rows if any(x.ids_path.startswith(p) or p.startswith(x.ids_path) for p in ix.acc.scopes)]
    return {"items": [{**loc_out(x, direct.get(x.id, 0), total.get(x.id, 0)), "by_cls": dict(cls_total.get(x.id, {})), "in_scope": ix.acc.loc_ok(x)} for x in vis],
            "unplaced": direct.get(None, 0)}


class LocBody(BaseModel):
    parent_id: int | None = None
    kind: str = Field(default="room", max_length=12)
    name: str = Field(min_length=1, max_length=200)
    code: str = Field(default="", max_length=60)
    note: str = Field(default="", max_length=1000)
    data: dict = Field(default_factory=dict)
    active: bool = True
    sort: int = 0


async def _repath(db: AsyncSession, x: InvLocation) -> None:
    """Путь узла и всего поддерева (после создания, переименования, переноса)."""
    parent = await db.get(InvLocation, x.parent_id) if x.parent_id else None
    x.path = f"{parent.path} / {x.name}" if parent else x.name
    x.ids_path = f"{parent.ids_path if parent else '/'}{x.id}/"
    kids = (await db.execute(select(InvLocation).where(InvLocation.parent_id == x.id))).scalars().all()
    for k in kids:
        await _repath(db, k)


@router.post("/locations", status_code=201)
async def add_location(body: LocBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("refs")
    if body.kind not in M.LOC_RU:
        raise HTTPException(status_code=422, detail="Неизвестный вид местоположения")
    parent = await db.get(InvLocation, body.parent_id) if body.parent_id else None
    if body.parent_id and parent is None:
        raise HTTPException(status_code=404, detail="Родительский узел не найден")
    if ix.acc.scopes and not ix.acc.loc_ok(parent):
        raise HTTPException(status_code=403, detail="Узел вне вашей области учёта")
    if (await db.execute(select(InvLocation.id).where(InvLocation.parent_id.is_(body.parent_id) if body.parent_id is None else InvLocation.parent_id == body.parent_id,
                                                       func.lower(InvLocation.name) == body.name.strip().casefold()))).first():
        raise HTTPException(status_code=409, detail=f"«{body.name}» здесь уже есть")
    x = InvLocation(parent_id=body.parent_id, kind=body.kind, name=body.name.strip(), code=body.code.strip(), note=body.note, data=body.data, active=body.active, sort=body.sort)
    db.add(x)
    await db.flush()
    await _repath(db, x)
    audit(db, ix, "location.add", x.path[:120], {"id": x.id})
    await db.commit()
    return loc_out(x)


@router.put("/locations/{lid}")
async def edit_location(lid: int, body: LocBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Изменение узла; смена родителя переносит поддерево (с оборудованием). Пути карточек пересчитываются в строке поиска."""
    ix.acc.need("refs")
    x = await db.get(InvLocation, lid)
    if x is None:
        raise HTTPException(status_code=404, detail="Местоположение не найдено")
    if ix.acc.scopes and not ix.acc.loc_ok(x):
        raise HTTPException(status_code=403, detail="Узел вне вашей области учёта")
    if body.parent_id:
        p = await db.get(InvLocation, body.parent_id)
        if p is None:
            raise HTTPException(status_code=404, detail="Новый родительский узел не найден")
        if p.ids_path.startswith(x.ids_path):
            raise HTTPException(status_code=422, detail="Нельзя перенести узел внутрь самого себя")
    if body.kind not in M.LOC_RU:
        raise HTTPException(status_code=422, detail="Неизвестный вид местоположения")
    renamed = x.name != body.name.strip() or x.parent_id != body.parent_id
    x.parent_id, x.kind, x.name, x.code, x.note, x.data, x.active, x.sort = body.parent_id, body.kind, body.name.strip(), body.code.strip(), body.note, body.data, body.active, body.sort
    await _repath(db, x)
    if renamed:                                                   # строка поиска карточек содержит путь местоположения
        await db.flush()
        sub = select(InvLocation.id).where(InvLocation.ids_path.like(x.ids_path + "%"))
        assets = (await db.execute(select(InvAsset).where(InvAsset.location_id.in_(sub)).limit(20000))).scalars().all()
        for i in range(0, len(assets), 500):
            part = assets[i:i + 500]
            n = await C.names_for(db, part)
            for a in part:
                a.search = C.search_text(a, n)
    audit(db, ix, "location.edit", x.path[:120], {"id": x.id})
    await db.commit()
    return loc_out(x)


@router.delete("/locations/{lid}")
async def del_location(lid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("refs")
    x = await db.get(InvLocation, lid)
    if x is None:
        raise HTTPException(status_code=404, detail="Местоположение не найдено")
    if (await db.execute(select(InvLocation.id).where(InvLocation.parent_id == lid).limit(1))).first():
        raise HTTPException(status_code=409, detail="Сначала удалите или перенесите вложенные местоположения")
    used = (await db.execute(select(func.count()).select_from(InvAsset).where(InvAsset.location_id == lid))).scalar_one()
    used_docs = (await db.execute(select(func.count()).select_from(InvDoc).where(or_(InvDoc.from_location_id == lid, InvDoc.to_location_id == lid)))).scalar_one()
    if used or used_docs:
        x.active = False
        audit(db, ix, "location.deactivate", x.path[:120], {"id": lid})
        await db.commit()
        return {"deleted": False, "deactivated": True, "note": f"Местоположение используется ({used} карточек, {used_docs} документов) — оно скрыто из выбора, история сохранена"}
    audit(db, ix, "location.delete", x.path[:120], {"id": lid})
    await db.delete(x)
    await db.commit()
    return {"deleted": True}


# ------------------------------------------------------------------------------------------------ справочники
class RefBody(BaseModel):
    kind: str = Field(pattern=r"^(" + "|".join(M.REF_RU) + ")$")
    name: str = Field(min_length=1, max_length=300)
    code: str = Field(default="", max_length=60)
    parent_id: int | None = None
    data: dict = Field(default_factory=dict)
    active: bool = True
    sort: int = 0


def _ref_data(kind: str, data: dict) -> dict:
    if kind == "type":
        if data.get("cls") not in M.CLS_RU:
            raise HTTPException(status_code=422, detail="Для типа укажите класс оборудования")
        return {"cls": data["cls"], "prefix": str(data.get("prefix") or "")[:20]}
    if kind == "status":
        if data.get("cls") not in M.ST_RU:
            raise HTTPException(status_code=422, detail="Для статуса укажите состояние учёта")
        return {"cls": data["cls"]}
    if kind == "supplier":
        return {"service": bool(data.get("service")), "contacts": str(data.get("contacts") or "")[:500], "inn": str(data.get("inn") or "")[:20]}
    if kind == "model":
        out = {"type_id": int(data["type_id"]) if data.get("type_id") else None}
        if isinstance(data.get("defaults"), dict):                  # значения свойств по умолчанию для модели (подставляются при создании карточки)
            out["defaults"] = {str(k)[:40]: v for k, v in list(data["defaults"].items())[:30]}
        return out
    return {}


@router.post("/refs", status_code=201)
async def add_ref(body: RefBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("refs")
    if body.kind == "model" and not body.parent_id:
        raise HTTPException(status_code=422, detail="Для модели укажите производителя")
    if (await db.execute(select(InvRef.id).where(InvRef.kind == body.kind, func.lower(InvRef.name) == body.name.strip().casefold(),
                                                 InvRef.parent_id == body.parent_id if body.parent_id else InvRef.parent_id.is_(None)))).first():
        raise HTTPException(status_code=409, detail=f"«{body.name}» уже есть в справочнике")
    r = InvRef(kind=body.kind, name=body.name.strip(), code=body.code.strip(), parent_id=body.parent_id, data=_ref_data(body.kind, body.data), active=body.active, sort=body.sort)
    db.add(r)
    await db.flush()
    audit(db, ix, "ref.add", f"{body.kind}:{r.name}"[:120], {"id": r.id})
    await db.commit()
    return {"id": r.id, "kind": r.kind, "name": r.name, "code": r.code, "parent_id": r.parent_id, "data": r.data, "active": r.active}


REF_USE = {"type": [InvAsset.type_id], "manufacturer": [InvAsset.manufacturer_id], "model": [InvAsset.model_id], "status": [InvAsset.status_id], "dept": [InvAsset.dept_id],
           "branch": [InvAsset.branch_id], "supplier": [InvAsset.supplier_id, InvLicense.supplier_id], "license_type": [InvLicense.type_id], "sw_category": [InvLicense.category_id]}


@router.put("/refs/{rid}")
async def edit_ref(rid: int, body: RefBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Изменение значения справочника. Переименование видно во всех карточках; в истории остаются прежние названия (история хранит имена на момент события)."""
    ix.acc.need("refs")
    r = await db.get(InvRef, rid)
    if r is None or r.kind != body.kind:
        raise HTTPException(status_code=404, detail="Значение не найдено")
    r.name, r.code, r.parent_id, r.data, r.active, r.sort = body.name.strip(), body.code.strip(), body.parent_id, _ref_data(body.kind, body.data), body.active, body.sort
    if body.kind in ("type", "status"):                            # класс и состояние денормализованы в карточках: пересчитываются
        col, val = (InvAsset.type_id, {"cls": r.data["cls"]}) if body.kind == "type" else (InvAsset.status_id, {"st_cls": r.data["cls"]})
        await db.execute(update(InvAsset).where(col == rid).values(**val))
    audit(db, ix, "ref.edit", f"{body.kind}:{r.name}"[:120], {"id": rid})
    await db.commit()
    return {"ok": True}


@router.delete("/refs/{rid}")
async def del_ref(rid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("refs")
    r = await db.get(InvRef, rid)
    if r is None:
        raise HTTPException(status_code=404, detail="Значение не найдено")
    used = 0
    for col in REF_USE.get(r.kind, []):
        used += (await db.execute(select(func.count()).select_from(col.class_).where(col == rid))).scalar_one()
    used += (await db.execute(select(func.count()).select_from(InvRef).where(InvRef.parent_id == rid))).scalar_one()
    if used:
        r.active = False
        await db.commit()
        return {"deleted": False, "deactivated": True, "note": f"Значение используется ({used}) — скрыто из выбора, в карточках сохранено"}
    audit(db, ix, "ref.delete", f"{r.kind}:{r.name}"[:120], {"id": rid})
    await db.delete(r)
    await db.commit()
    return {"deleted": True}


# ------------------------------------------------------------------------------------------------ дополнительные свойства
class PropBody(BaseModel):
    code: str = Field(default="", max_length=40)
    name: str = Field(min_length=1, max_length=200)
    descr: str = Field(default="", max_length=500)
    type: str = Field(pattern=r"^(" + "|".join(M.PROP_TYPES) + ")$")
    options: list[str] = Field(default_factory=list, max_length=200)
    default: object = None
    required: bool = False
    type_ids: list[int] = Field(default_factory=list, max_length=100)
    in_list: bool = False
    sort: int = 0
    active: bool = True


def _code(name: str) -> str:
    tr = str.maketrans("абвгдеёжзийклмнопрстуфхцчшщъыьэюя", "abvgdeejziiklmnoprstufhccss_y_eua")
    c = re.sub(r"[^a-z0-9_]+", "_", name.casefold().translate(tr)).strip("_")[:36]
    return c or "prop"


@router.post("/props", status_code=201)
async def add_prop(body: PropBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("refs")
    code = (body.code.strip() or _code(body.name)).lower()
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", code):
        raise HTTPException(status_code=422, detail="Код свойства: латинские буквы, цифры и «_», начинается с буквы")
    base, i = code, 2
    while (await db.execute(select(InvProp.id).where(InvProp.code == code))).first():
        if body.code.strip():
            raise HTTPException(status_code=409, detail=f"Код «{code}» уже занят")
        code, i = f"{base[:36]}_{i}", i + 1
    p = InvProp(code=code, name=body.name.strip(), descr=body.descr, type=body.type, options=[o.strip() for o in body.options if o.strip()], required=body.required,
                type_ids=body.type_ids, in_list=body.in_list, sort=body.sort, active=body.active)
    if body.type in ("select", "multiselect") and not p.options:
        raise HTTPException(status_code=422, detail="Для списка задайте варианты значений")
    try:
        p.default = {"v": C.prop_value(p, body.default)} if body.default not in (None, "") else {}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Значение по умолчанию: {exc}") from None
    db.add(p)
    await db.flush()
    audit(db, ix, "prop.add", code, {"name": p.name, "type": p.type})
    await db.commit()
    return prop_out(p)


@router.put("/props/{pid}")
async def edit_prop(pid: int, body: PropBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Код свойства не меняется (значения карточек хранятся по коду); тип менять можно — значения, не подходящие новому типу, остаются и показываются как текст."""
    ix.acc.need("refs")
    p = await db.get(InvProp, pid)
    if p is None:
        raise HTTPException(status_code=404, detail="Свойство не найдено")
    p.name, p.descr, p.type, p.options, p.required, p.type_ids, p.in_list, p.sort, p.active = (body.name.strip(), body.descr, body.type, [o.strip() for o in body.options if o.strip()],
                                                                                         body.required, body.type_ids, body.in_list, body.sort, body.active)
    try:
        p.default = {"v": C.prop_value(p, body.default)} if body.default not in (None, "") else {}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Значение по умолчанию: {exc}") from None
    audit(db, ix, "prop.edit", p.code, {"name": p.name})
    await db.commit()
    return prop_out(p)


@router.delete("/props/{pid}")
async def del_prop(pid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Свойство скрывается (значения в карточках и истории сохраняются): удаление определения не уничтожает данные."""
    ix.acc.need("refs")
    p = await db.get(InvProp, pid)
    if p is None:
        raise HTTPException(status_code=404, detail="Свойство не найдено")
    p.active = False
    audit(db, ix, "prop.deactivate", p.code, {})
    await db.commit()
    return {"ok": True}


# ------------------------------------------------------------------------------------------------ сотрудники
def person_out(p: InvPerson, counts: dict | None = None) -> dict:
    return {"id": p.id, "name": p.name, "login": p.login, "email": p.email, "dept": p.dept, "title": p.title, "phone": p.phone, "source": p.source, "active": p.active, "note": p.note,
            "counts": counts or {}}


def person_search(p: InvPerson) -> str:
    return " ".join(x for x in (p.name, p.login, p.email, p.dept, p.title) if x).casefold()[:1300]


@router.get("/people")
async def people(q: str = Query("", max_length=200), with_bi: bool = True, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500),
                 ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Сотрудники учёта с числом закреплённых единиц по ролям. При поиске — также сотрудники BI, ещё не перенесённые в учёт (можно выбрать — запись создастся)."""
    w = [c for word in q.split()[:5] if (c := column_like(InvPerson.search, word)) is not None]
    total = (await db.execute(select(func.count()).select_from(InvPerson).where(*w))).scalar_one()
    rows = (await db.execute(select(InvPerson).where(*w).order_by(InvPerson.active.desc(), InvPerson.name).offset(offset).limit(limit))).scalars().all()
    counts: dict[int, dict] = defaultdict(dict)
    if rows:
        ids = [p.id for p in rows]
        for f in M.PEOPLE_FIELDS:
            col = getattr(InvAsset, f)
            for pid, n in (await db.execute(select(col, func.count()).where(col.in_(ids), InvAsset.st_cls.in_(M.ST_ACTIVE)).group_by(col))).all():
                counts[pid][f[:-3]] = n
    bi = []
    if q.strip() and with_bi and ix.su.is_analyst and offset == 0:
        have = {(p.email or "").casefold() for p in rows if p.email}
        bw = [c for word in q.split()[:5] if (c := column_like(BiPerson.search, word)) is not None]
        for b in (await db.execute(select(BiPerson).where(*bw, BiPerson.present.is_(True)).order_by(BiPerson.full_name).limit(15))).scalars():
            if b.email and b.email.casefold() in have:
                continue
            if (await db.execute(select(InvPerson.id).where(InvPerson.ext_key == f"bi:{b.id}"))).first():
                continue
            bi.append({"bi_id": b.id, "name": b.full_name or b.email, "email": b.email, "dept": b.department, "source": "bi"})
    return {"items": [person_out(p, counts.get(p.id)) for p in rows], "total": total, "offset": offset, "limit": limit, "bi": bi}


class PersonBody(BaseModel):
    name: str = Field(default="", max_length=300)
    login: str = Field(default="", max_length=256)
    email: str = Field(default="", max_length=320)
    dept: str = Field(default="", max_length=300)
    title: str = Field(default="", max_length=300)
    phone: str = Field(default="", max_length=60)
    note: str = Field(default="", max_length=1000)
    active: bool = True
    bi_id: int | None = None                                        # перенести сотрудника из BI


@router.post("/people", status_code=201)
async def add_person(body: PersonBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Новый сотрудник учёта или перенос из BI (bi_id): ФИО, почта, подразделение берутся из выгрузки. Повторный перенос возвращает уже созданную запись."""
    if not (ix.acc.can("people") or ix.acc.can("create") or ix.acc.can("docs")):
        ix.acc.need("people")
    if body.bi_id:
        if not ix.su.is_analyst:
            raise HTTPException(status_code=403, detail="Сведения BI доступны аналитику и выше")
        b = await db.get(BiPerson, body.bi_id)
        if b is None:
            raise HTTPException(status_code=404, detail="Сотрудник BI не найден")
        ex = (await db.execute(select(InvPerson).where(or_(InvPerson.ext_key == f"bi:{b.id}", func.lower(InvPerson.email) == (b.email or "-").casefold())).limit(1))).scalar_one_or_none()
        if ex is not None:
            return person_out(ex)
        p = InvPerson(name=(b.full_name or b.email)[:300], email=b.email, dept=b.department, source="bi", ext_key=f"bi:{b.id}", login=(b.email.split("@")[0] if b.email else "")[:256])
    else:
        if not body.name.strip():
            raise HTTPException(status_code=422, detail="Укажите ФИО")
        if body.email and (await db.execute(select(InvPerson.id).where(func.lower(InvPerson.email) == body.email.strip().casefold()))).first():
            raise HTTPException(status_code=409, detail="Сотрудник с такой почтой уже есть")
        p = InvPerson(name=body.name.strip(), login=body.login.strip(), email=body.email.strip(), dept=body.dept.strip(), title=body.title.strip(), phone=body.phone.strip(), note=body.note,
                      active=body.active, source="manual")
    p.search = person_search(p)
    db.add(p)
    await db.flush()
    audit(db, ix, "person.add", p.name[:120], {"id": p.id, "source": p.source})
    await db.commit()
    return person_out(p)


@router.put("/people/{pid}")
async def edit_person(pid: int, body: PersonBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("people")
    p = await db.get(InvPerson, pid)
    if p is None:
        raise HTTPException(status_code=404, detail="Сотрудник не найден")
    if not body.name.strip():
        raise HTTPException(status_code=422, detail="Укажите ФИО")
    p.name, p.login, p.email, p.dept, p.title, p.phone, p.note, p.active = (body.name.strip(), body.login.strip(), body.email.strip(), body.dept.strip(), body.title.strip(),
                                                                            body.phone.strip(), body.note, body.active)
    p.search = person_search(p)
    audit(db, ix, "person.edit", p.name[:120], {"id": pid, "active": p.active})
    await db.commit()
    return person_out(p)


@router.get("/people/{pid}")
async def person_card(pid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Сотрудник: закреплённое оборудование по ролям (только действующее) и история — какие единицы и когда закреплялись за ним или снимались."""
    p = await db.get(InvPerson, pid)
    if p is None:
        raise HTTPException(status_code=404, detail="Сотрудник не найден")
    cols = [getattr(InvAsset, f) for f in M.PEOPLE_FIELDS]
    stmt = select(InvAsset).where(or_(*[c == pid for c in cols]))
    if (af := ix.acc.asset_filter()) is not None:
        stmt = stmt.where(af)
    rows = (await db.execute(stmt.order_by(InvAsset.inv_no).limit(2000))).scalars().all()
    n = await C.names_for(db, list(rows))
    items = []
    for a in rows:
        r = C.asset_row(a, n)
        r["roles"] = [M.ROLES_RU[f[:-3]] for f in M.PEOPLE_FIELDS if getattr(a, f) == pid]
        items.append(r)
    hq = (select(InvHistory, InvAsset.inv_no, InvAsset.name).join(InvAsset, InvAsset.id == InvHistory.asset_id).where(InvHistory.people.like(f"%,{pid},%"))
          .order_by(InvHistory.at.desc()).limit(300))
    hist = []
    for h, no, nm in (await db.execute(hq)).all():
        for c in h.changes or []:
            if c.get("f") in M.PEOPLE_FIELDS and pid in (c.get("oid"), c.get("nid")):
                hist.append({"at": C._iso(h.at), "by": h.by, "asset_id": h.asset_id, "inv_no": no, "name": nm, "role": c["label"], "action": "закреплено" if c.get("nid") == pid else "снято",
                             "title": h.title, "doc_id": h.doc_id})
    return {**person_out(p), "assets": items, "history": hist}


@router.post("/people/import-hier")
async def import_hier(request: Request, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Перенести сотрудников из последней успешной выгрузки адресной книги (раздел «Иерархия»): ФИО, почта, должность, подразделение. Совпадение — по почте; существующие записи
    обновляются, новые создаются; никто не удаляется (уволенных отмечают «не работает» вручную)."""
    ix.acc.need("refs")
    from ..hier.service import records_of  # noqa: PLC0415

    snap = (await db.execute(select(HierSnapshot).where(HierSnapshot.status == "ok").order_by(HierSnapshot.finished_at.desc()).limit(1))).scalar_one_or_none()
    if snap is None:
        raise HTTPException(status_code=409, detail="Выгрузки адресной книги ещё нет (раздел «Иерархия предприятия»)")
    recs = await records_of(db, snap)
    have = {(p.email or "").casefold(): p for p in (await db.execute(select(InvPerson).where(InvPerson.email != ""))).scalars()}
    added = updated = 0
    for r in recs[:200_000]:
        name, email, title, dept = (r + [""] * 8)[:4]
        email = (email or "").strip()
        if not email or not name:
            continue
        p = have.get(email.casefold())
        if p is None:
            p = InvPerson(name=name[:300], email=email[:320], title=(title or "")[:300], dept=(dept or "")[:300], source="hier", ext_key=f"mail:{email.casefold()}"[:400], login=email.split("@")[0][:256])
            db.add(p)
            have[email.casefold()] = p
            added += 1
        elif p.source in ("hier", "bi") and (p.title != (title or "")[:300] or p.dept != (dept or "")[:300]):
            p.title, p.dept = (title or "")[:300], (dept or "")[:300]
            updated += 1
        p.search = person_search(p)
    audit(db, ix, "person.import_hier", "адресная книга", {"added": added, "updated": updated})
    await db.commit()
    return {"added": added, "updated": updated}
