"""Ядро учёта: права и область учёта, встроенные справочники, номера, проверка и применение изменений карточки, история с состоянием «после» (для просмотра на дату), вывод карточки.

Все изменения карточек идут через `apply_changes` + `record`: так в истории всегда есть кто, когда, было/стало, основание и документ, а в журнале действий — запись об операции."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal, InvalidOperation

from fastapi import HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import xact_lock
from ..models import InvAsset, InvHistory, InvLocation, InvPerson, InvProp, InvRef, utcnow
from ..roles import ROLE_RANK
from ..services.settings import INV_PERMS, InventorySettings
from . import model as M


# ------------------------------------------------------------------------------------------------ права
@dataclass
class Access:
    """Права пользователя в разделе: набор прав (роль + личные права из настроек) и область учёта — поддеревья местоположений (пусто — без ограничения)."""
    perms: frozenset[str]
    scopes: tuple[str, ...] = ()                    # ids_path разрешённых узлов
    scope_ids: tuple[int, ...] = ()

    def can(self, p: str) -> bool:
        return p in self.perms

    def need(self, p: str) -> None:
        if p not in self.perms:
            raise HTTPException(status_code=403, detail=f"Недостаточно прав в разделе «Инвентаризация»: {PERM_RU.get(p, p)}")

    def asset_filter(self):
        """Условие на InvAsset: карточки в разрешённых местоположениях (пользователь с ограничением карточки без местоположения не видит)."""
        if not self.scopes:
            return None
        return InvAsset.location_id.in_(select(InvLocation.id).where(or_(*[InvLocation.ids_path.like(p + "%") for p in self.scopes])))

    def loc_ok(self, loc: InvLocation | None) -> bool:
        return not self.scopes or (loc is not None and any(loc.ids_path.startswith(p) for p in self.scopes))


PERM_RU = {"view": "просмотр", "create": "создание карточек", "edit": "изменение учётных сведений", "location": "изменение местоположения", "people": "изменение владельцев и ответственных",
           "docs": "оформление документов", "repair": "оформление ремонтов", "writeoff": "списание", "count": "проведение инвентаризации", "import": "импорт",
           "refs": "управление справочниками", "keys": "просмотр ключей лицензий", "templates": "печатные формы и этикетки"}


async def access_for(db: AsyncSession, su, cfg: InventorySettings) -> Access:
    if su.is_admin:
        return Access(frozenset(INV_PERMS))
    rank = ROLE_RANK.get(su.role, 0)
    perms = {p for p in INV_PERMS if rank >= ROLE_RANK.get(cfg.roles.get(p, "admin"), 9)}
    ids: list[int] = []
    for g in cfg.grants:
        if g.login.casefold() == su.username.casefold():
            perms |= set(g.perms)
            ids += g.location_ids
    if perms - {"view"}:
        perms.add("view")
    scopes: tuple[str, ...] = ()
    if ids:
        scopes = tuple(p for (p,) in (await db.execute(select(InvLocation.ids_path).where(InvLocation.id.in_(ids)))).all())
        if not scopes:
            scopes = ("/-/",)                     # узлы удалены — ничего не видно, а не всё
    return Access(frozenset(perms), scopes, tuple(ids))


# ------------------------------------------------------------------------------------------------ справочники
async def ensure_seed(db: AsyncSession) -> None:
    """Встроенные типы, статусы, типы лицензий и категории программ — если справочника этого вида ещё нет (дальше справочники ведёт администратор)."""
    have = {k for (k,) in (await db.execute(select(InvRef.kind).distinct())).all()}
    if {"type", "status", "license_type", "sw_category"} <= have:
        return
    await xact_lock(db, "inv_seed")
    have = {k for (k,) in (await db.execute(select(InvRef.kind).distinct())).all()}
    rows = []
    if "type" not in have:
        rows += [InvRef(kind="type", name=n, data={"cls": c}, sort=i) for i, (n, c) in enumerate(M.SEED_TYPES)]
    if "status" not in have:
        rows += [InvRef(kind="status", name=n, data={"cls": c}, sort=i) for i, (n, c) in enumerate(M.SEED_STATUSES)]
    if "license_type" not in have:
        rows += [InvRef(kind="license_type", name=n, sort=i) for i, n in enumerate(M.SEED_LICENSE_TYPES)]
    if "sw_category" not in have:
        rows += [InvRef(kind="sw_category", name=n, sort=i) for i, n in enumerate(M.SEED_SW_CATEGORIES)]
    if rows:
        db.add_all(rows)
        await db.commit()


async def default_status(db: AsyncSession, cls: str) -> InvRef | None:
    return (await db.execute(select(InvRef).where(InvRef.kind == "status", InvRef.active.is_(True)).order_by(InvRef.sort, InvRef.id))).scalars().first() if not cls else \
        next((r for r in (await db.execute(select(InvRef).where(InvRef.kind == "status").order_by(InvRef.sort, InvRef.id))).scalars() if (r.data or {}).get("cls") == cls), None)


async def type_for_cls(db: AsyncSession, cls: str) -> InvRef | None:
    return next((r for r in (await db.execute(select(InvRef).where(InvRef.kind == "type", InvRef.active.is_(True)).order_by(InvRef.sort, InvRef.id))).scalars()
                 if (r.data or {}).get("cls") == cls), None)


# ------------------------------------------------------------------------------------------------ номера
async def next_number(db: AsyncSession, col, prefix: str, digits: int) -> str:
    """Следующий номер «префикс + N цифр» (под блокировкой транзакции: два одновременных создания не получат один номер)."""
    await xact_lock(db, f"inv_no:{prefix}")
    rows = (await db.execute(select(col).where(col.like(prefix.replace("%", r"\%").replace("_", r"\_") + "_" * digits, escape="\\")).order_by(col.desc()).limit(20))).scalars().all()
    n = next((int(v[len(prefix):]) for v in rows if v[len(prefix):].isdigit()), 0)
    return f"{prefix}{n + 1:0{digits}d}"


async def next_inv_no(db: AsyncSession, cfg: InventorySettings) -> str:
    return await next_number(db, InvAsset.inv_no, cfg.inv_prefix, cfg.inv_digits)


# ------------------------------------------------------------------------------------------------ значения
def parse_money(v) -> int | None:
    """«12 345,67» / 12345.67 → копейки; пусто → None."""
    if v is None or v == "":
        return None
    if isinstance(v, int):
        return v * 100
    try:
        d = Decimal(re.sub(r"[\s ₽]|руб\.?", "", str(v)).replace(",", "."))
    except InvalidOperation:
        raise ValueError("сумма: ожидается число, например 12345,67") from None
    if d < 0 or d > Decimal("1e12"):
        raise ValueError("сумма вне допустимого диапазона")
    return int((d * 100).to_integral_value())


def money_str(k: int | None) -> str:
    if k is None:
        return ""
    r, c = divmod(int(k), 100)
    return f"{r:,}".replace(",", " ") + f",{c:02d}"


def parse_date(v) -> date | None:
    if v in (None, ""):
        return None
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    s = str(v).strip()
    for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%d.%m.%y", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s[:19] if "T" in s else s, fmt).date()
        except ValueError:
            continue
    raise ValueError(f"дата «{s}»: ожидается ДД.ММ.ГГГГ")


def prop_value(p: InvProp, v):
    """Значение дополнительного свойства по его типу; пусто → None. Ошибка — ValueError с понятным текстом."""
    if v is None or v == "" or v == []:
        return None
    t = p.type
    if t in ("text", "url"):
        s = str(v).strip()[:1000]
        if t == "url" and not re.match(r"^(https?://|mailto:)", s, re.I):
            raise ValueError(f"{p.name}: ссылка должна начинаться с http:// или https://")
        return s
    if t == "multiline":
        return str(v)[:8000]
    if t == "number":
        try:
            f = float(str(v).replace(",", ".").replace(" ", ""))
        except ValueError:
            raise ValueError(f"{p.name}: ожидается число") from None
        return int(f) if f.is_integer() else f
    if t == "money":
        return parse_money(v)
    if t == "date":
        return parse_date(v).isoformat()
    if t == "bool":
        if isinstance(v, bool):
            return v
        return str(v).strip().casefold() in ("1", "да", "true", "yes", "+")
    opts = [str(o) for o in (p.options or [])]
    if t == "select":
        s = str(v)
        if s not in opts:
            raise ValueError(f"{p.name}: значения «{s}» нет в списке")
        return s
    if t == "multiselect":
        vals = [str(x) for x in (v if isinstance(v, list) else str(v).split(";"))]
        bad = [x for x in vals if x.strip() and x.strip() not in opts]
        if bad:
            raise ValueError(f"{p.name}: значений {', '.join(bad)} нет в списке")
        return [x.strip() for x in vals if x.strip()]
    return str(v)


def prop_text(p: InvProp | None, v) -> str:
    if v is None:
        return ""
    t = p.type if p else "text"
    if t == "bool":
        return "да" if v else "нет"
    if t == "money":
        return money_str(v)
    if t == "date":
        try:
            return date.fromisoformat(v).strftime("%d.%m.%Y")
        except (TypeError, ValueError):
            return str(v)
    if isinstance(v, list):
        return "; ".join(map(str, v))
    return str(v)


def props_for(defs: list[InvProp], type_id: int | None) -> list[InvProp]:
    return [p for p in defs if p.active and (not p.type_ids or (type_id is not None and type_id in p.type_ids))]


# ------------------------------------------------------------------------------------------------ имена (одна выборка на список карточек)
@dataclass
class Names:
    refs: dict[int, InvRef] = field(default_factory=dict)
    people: dict[int, InvPerson] = field(default_factory=dict)
    locs: dict[int, InvLocation] = field(default_factory=dict)
    parents: dict[int, InvAsset] = field(default_factory=dict)
    props: list[InvProp] = field(default_factory=list)

    def ref(self, i) -> str:
        return self.refs[i].name if i in self.refs else ""

    def person(self, i) -> str:
        return self.people[i].name if i in self.people else ""

    def loc(self, i) -> str:
        return self.locs[i].path if i in self.locs else ""


async def names_for(db: AsyncSession, assets: list[InvAsset], *, props: bool = True) -> Names:
    n = Names()
    ref_ids = {getattr(a, f) for a in assets for f in M.REF_FIELDS} - {None}
    ppl = {getattr(a, f) for a in assets for f in M.PEOPLE_FIELDS} - {None}
    locs = {a.location_id for a in assets} - {None}
    par = {a.parent_id for a in assets} - {None}
    if ref_ids:
        n.refs = {r.id: r for r in (await db.execute(select(InvRef).where(InvRef.id.in_(ref_ids)))).scalars()}
    if ppl:
        n.people = {p.id: p for p in (await db.execute(select(InvPerson).where(InvPerson.id.in_(ppl)))).scalars()}
    if locs:
        n.locs = {x.id: x for x in (await db.execute(select(InvLocation).where(InvLocation.id.in_(locs)))).scalars()}
    if par:
        n.parents = {x.id: x for x in (await db.execute(select(InvAsset).where(InvAsset.id.in_(par)))).scalars()}
    if props:
        n.props = list((await db.execute(select(InvProp).order_by(InvProp.sort, InvProp.id))).scalars())
    return n


def label(a: InvAsset, n: Names | None = None) -> str:
    """Подпись карточки: наименование (или тип и модель) и инвентарный номер."""
    nm = a.name or (" ".join(x for x in ((n.ref(a.manufacturer_id) if n else ""), (n.ref(a.model_id) if n else "")) if x)) or M.CLS_RU.get(a.cls, "")
    return f"{nm} ({a.inv_no})" if nm else a.inv_no


def state_of(a: InvAsset, n: Names) -> dict:
    """Учётное состояние после события: для ленты истории и просмотра на дату (имена сохраняются — переименование справочника историю не меняет)."""
    return {"status": n.ref(a.status_id), "st_cls": a.st_cls, "location_id": a.location_id, "location": n.loc(a.location_id), "loc_detail": a.loc_detail,
            **{f[:-3]: n.person(getattr(a, f)) for f in M.PEOPLE_FIELDS}, "dept": n.ref(a.dept_id), "branch": n.ref(a.branch_id), "hostname": a.hostname, "name": a.name, "serial": a.serial}


def search_text(a: InvAsset, n: Names) -> str:
    parts = [a.inv_no, a.acc_no, a.serial, a.name, a.hostname, a.ksc_name, n.ref(a.type_id), n.ref(a.manufacturer_id), n.ref(a.model_id), n.ref(a.status_id), n.ref(a.dept_id),
             n.ref(a.branch_id), n.loc(a.location_id), a.loc_detail, *[n.person(getattr(a, f)) for f in M.PEOPLE_FIELDS],
             *[(n.people[getattr(a, f)].login if getattr(a, f) in n.people else "") for f in M.PEOPLE_FIELDS], a.purchase_doc]
    pdefs = {p.code: p for p in n.props}
    parts += [prop_text(pdefs.get(k), v) for k, v in (a.props or {}).items()]
    parts += [str(v) for v in (a.ext_ids or {}).values() if isinstance(v, (str, int))]
    return " ".join(p for p in parts if p).casefold()[:3000]


def asset_row(a: InvAsset, n: Names) -> dict:
    """Строка списка и основа карточки."""
    pdefs = {p.code: p for p in n.props}
    return {"id": a.id, "uid": str(a.uid), "inv_no": a.inv_no, "acc_no": a.acc_no, "serial": a.serial, "name": a.name, "hostname": a.hostname, "label": label(a, n),
            "type_id": a.type_id, "type": n.ref(a.type_id), "cls": a.cls, "cls_ru": M.CLS_RU.get(a.cls, a.cls), "model_id": a.model_id, "model": n.ref(a.model_id),
            "manufacturer_id": a.manufacturer_id, "manufacturer": n.ref(a.manufacturer_id), "status_id": a.status_id, "status": n.ref(a.status_id), "st_cls": a.st_cls,
            "st_ru": M.ST_RU.get(a.st_cls, ""), "location_id": a.location_id, "location": n.loc(a.location_id), "loc_detail": a.loc_detail,
            **{f: getattr(a, f) for f in M.PEOPLE_FIELDS}, **{f[:-3]: n.person(getattr(a, f)) for f in M.PEOPLE_FIELDS},
            "dept_id": a.dept_id, "dept": n.ref(a.dept_id), "branch_id": a.branch_id, "branch": n.ref(a.branch_id),
            "purchase_date": _d(a.purchase_date), "received_date": _d(a.received_date), "commissioned_date": _d(a.commissioned_date), "warranty_until": _d(a.warranty_until),
            "cost": a.cost, "cost_text": money_str(a.cost), "supplier_id": a.supplier_id, "supplier": n.ref(a.supplier_id), "purchase_doc": a.purchase_doc,
            "parent_id": a.parent_id, "parent": label(n.parents[a.parent_id], n) if a.parent_id in n.parents else "", "rel": a.rel, "rel_ru": M.REL_RU.get(a.rel, ""),
            "props": a.props or {}, "props_text": {k: prop_text(pdefs.get(k), v) for k, v in (a.props or {}).items()}, "note": a.note,
            "ksc_source_id": str(a.ksc_source_id) if a.ksc_source_id else None, "ksc_host_id": a.ksc_host_id, "ksc_link": a.ksc_link, "ksc_name": a.ksc_name,
            "ext_ids": a.ext_ids or {}, "in_transit": a.transit_doc_id is not None, "transit_doc_id": a.transit_doc_id,
            "created_at": _iso(a.created_at), "created_by": a.created_by, "updated_at": _iso(a.updated_at), "updated_by": a.updated_by, "version": a.version}


def _d(v) -> str | None:
    return v.isoformat() if v else None


def _iso(v) -> str | None:
    return v.isoformat() if v else None


# ------------------------------------------------------------------------------------------------ изменения
class Invalid(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__("; ".join(errors.values()))
        self.errors = errors


async def apply_changes(db: AsyncSession, a: InvAsset, data: dict, acc: Access, *, creating: bool = False) -> list[dict]:
    """Проверяет и применяет изменения учётных полей. Возвращает список изменений [{f, label, old, new}] (имена — читаемые). Поля, на которые нет права, — 403.
    Ошибки значений собираются все сразу (Invalid) — форма подсвечивает каждое поле."""
    errors: dict[str, str] = {}
    changes: list[dict] = []
    keys = set(data)
    if not creating:
        if keys & {"location_id", "loc_detail"}:
            acc.need("location")
        if keys & set(M.PEOPLE_FIELDS):
            acc.need("people")
        if keys - {"location_id", "loc_detail", *M.PEOPLE_FIELDS}:
            acc.need("edit")
    ref_ids = {data[f] for f in M.REF_FIELDS if data.get(f)}
    refs = {r.id: r for r in (await db.execute(select(InvRef).where(InvRef.id.in_(ref_ids)))).scalars()} if ref_ids else {}
    ppl_ids = {data[f] for f in M.PEOPLE_FIELDS if data.get(f)}
    ppl = {p.id: p for p in (await db.execute(select(InvPerson).where(InvPerson.id.in_(ppl_ids)))).scalars()} if ppl_ids else {}
    old_names = await names_for(db, [a], props=False)

    def put(f: str, new, old_txt: str, new_txt: str) -> None:
        if getattr(a, f) != new:
            c = {"f": f, "label": M.FIELD_RU.get(f, f), "old": old_txt, "new": new_txt}
            if f in M.PEOPLE_FIELDS:
                c["oid"], c["nid"] = getattr(a, f), new
            changes.append(c)
            setattr(a, f, new)

    for f, ln in M.TEXT_FIELDS.items():
        if f in data:
            v = str(data[f] or "").strip()
            if len(v) > ln:
                errors[f] = f"{M.FIELD_RU[f]}: не длиннее {ln} символов"
                continue
            if f == "inv_no" and not v:
                errors[f] = "Инвентарный номер обязателен"
                continue
            if f == "hostname":
                v = v.lower()
            put(f, v, getattr(a, f) or "", v)
    if "note" in data:
        v = str(data["note"] or "")[:20000]
        if v != (a.note or ""):
            changes.append({"f": "note", "label": "Примечание", "old": (a.note or "")[:200], "new": v[:200]})
            a.note = v
    for f, kind in M.REF_FIELDS.items():
        if f not in data:
            continue
        v = data[f] or None
        if v is not None and (v not in refs or refs[v].kind != kind):
            errors[f] = f"{M.FIELD_RU[f]}: значение не найдено в справочнике"
            continue
        put(f, v, old_names.ref(getattr(a, f)), refs[v].name if v else "")
    if a.type_id and ("type_id" in data or creating):
        t = refs.get(a.type_id) or await db.get(InvRef, a.type_id)
        if t is not None:
            a.cls = (t.data or {}).get("cls") or "other"
    if "model_id" in data and a.model_id and refs.get(a.model_id) is not None and refs[a.model_id].parent_id and "manufacturer_id" not in data:
        mid = refs[a.model_id].parent_id
        if a.manufacturer_id != mid:
            m = await db.get(InvRef, mid)
            put("manufacturer_id", mid, old_names.ref(a.manufacturer_id), m.name if m else "")
    if "status_id" in data and a.status_id:
        a.st_cls = (refs[a.status_id].data or {}).get("cls") or "use"
    for f in M.PEOPLE_FIELDS:
        if f not in data:
            continue
        v = data[f] or None
        if v is not None and v not in ppl:
            errors[f] = f"{M.FIELD_RU[f]}: сотрудник не найден"
            continue
        put(f, v, old_names.person(getattr(a, f)), ppl[v].name if v else "")
    if "location_id" in data:
        v = data["location_id"] or None
        loc = await db.get(InvLocation, v) if v else None
        if v and loc is None:
            errors["location_id"] = "Местоположение не найдено"
        elif v and not acc.loc_ok(loc):
            errors["location_id"] = "Местоположение вне вашей области учёта"
        elif not v and acc.scopes:
            errors["location_id"] = "Укажите местоположение в пределах вашей области учёта"
        else:
            put("location_id", v, old_names.loc(a.location_id), loc.path if loc else "")
    for f in M.DATE_FIELDS:
        if f in data:
            try:
                v = parse_date(data[f])
            except ValueError as exc:
                errors[f] = f"{M.FIELD_RU[f]}: {exc}"
                continue
            put(f, v, _ru_date(getattr(a, f)), _ru_date(v))
    if "cost" in data:
        try:
            v = parse_money(data["cost"])
            put("cost", v, money_str(a.cost), money_str(v))
        except ValueError as exc:
            errors["cost"] = f"Стоимость: {exc}"
    if "parent_id" in data or "rel" in data:
        pid = data.get("parent_id", a.parent_id) or None
        rel = data.get("rel", a.rel) or ""
        if pid is not None:
            if pid == a.id:
                errors["parent_id"] = "Карточка не может входить сама в себя"
            else:
                p = await db.get(InvAsset, pid)
                seen, cur = set(), p
                while cur is not None and cur.parent_id and cur.parent_id not in seen:   # цикл «A в B, B в A» запрещён
                    seen.add(cur.id)
                    if cur.parent_id == a.id:
                        errors["parent_id"] = "Связь образует цикл"
                        break
                    cur = await db.get(InvAsset, cur.parent_id)
                if p is None:
                    errors["parent_id"] = "Связанная карточка не найдена"
                elif "parent_id" not in errors:
                    put("parent_id", pid, label(old_names.parents[a.parent_id]) if a.parent_id in old_names.parents else "", label(p))
                    rel = rel or ("vm" if a.cls == "vm" else "part" if a.cls == "component" else "attached")
        if rel not in ("", *M.REL_RU):
            errors["rel"] = "Неизвестный вид связи"
        elif "parent_id" not in errors:
            put("rel", rel if pid else "", M.REL_RU.get(a.rel, ""), M.REL_RU.get(rel, "") if pid else "")
    if "props" in data or creating:
        defs = list((await db.execute(select(InvProp).where(InvProp.active.is_(True)))).scalars())
        allowed = {p.code: p for p in props_for(defs, a.type_id)}
        cur = dict(a.props or {})
        incoming = data.get("props") or {}
        if not isinstance(incoming, dict):
            errors["props"] = "Дополнительные свойства: ожидается объект"
            incoming = {}
        if creating:
            for code, p in allowed.items():
                if code not in incoming and (p.default or {}).get("v") not in (None, ""):
                    incoming[code] = p.default["v"]
        for code, v in incoming.items():
            p = allowed.get(code) or next((d for d in defs if d.code == code), None)
            if p is None:
                errors[f"props.{code}"] = f"Свойство «{code}» не найдено"
                continue
            try:
                nv = prop_value(p, v)
            except ValueError as exc:
                errors[f"props.{code}"] = str(exc)
                continue
            if cur.get(code) != nv:
                changes.append({"f": f"props.{code}", "label": p.name, "old": prop_text(p, cur.get(code)), "new": prop_text(p, nv)})
                if nv is None:
                    cur.pop(code, None)
                else:
                    cur[code] = nv
        for code, p in allowed.items():
            if p.required and cur.get(code) in (None, "", []):
                errors[f"props.{code}"] = f"{p.name}: обязательное свойство"
        a.props = cur
    if errors:
        raise Invalid(errors)
    return changes


def _ru_date(d: date | None) -> str:
    return d.strftime("%d.%m.%Y") if d else ""


def kind_of(changes: list[dict]) -> str:
    fs = {c["f"] for c in changes}
    if fs <= {"location_id", "loc_detail"}:
        return "move"
    if fs <= set(M.PEOPLE_FIELDS):
        return "assign"
    if fs == {"status_id"}:
        return "status"
    return "update"


async def record(db: AsyncSession, a: InvAsset, kind: str, changes: list[dict], by: str, *, comment: str = "", basis: str = "", doc_id: int | None = None, title: str = "",
                 at: datetime | None = None) -> InvHistory:
    """Событие истории с состоянием после него; обновляет строку поиска и отметку изменения карточки."""
    n = await names_for(db, [a])
    a.search = search_text(a, n)
    if kind != "create":
        a.updated_at, a.updated_by = at or utcnow(), by
        a.version = (a.version or 0) + 1
    h = InvHistory(asset_id=a.id, at=at or utcnow(), by=by, kind=kind, title=(title or M.HIST_RU.get(kind, kind))[:300], changes=changes[:200], state=state_of(a, n),
                   comment=comment[:2000], basis=basis[:500], doc_id=doc_id)
    ids = {x for c in changes if c.get("f") in M.PEOPLE_FIELDS for x in (c.get("oid"), c.get("nid")) if x}
    h.people = ("," + ",".join(str(i) for i in sorted(ids)) + ",")[:300] if ids else ""
    db.add(h)
    return h


async def asset_by_code(db: AsyncSession, code: str) -> InvAsset | None:
    """Поиск по отсканированному коду: ссылка на карточку (…/inventory/a/<uid>), uid, инвентарный номер, серийный номер (только если однозначен)."""
    code = code.strip()
    m = re.search(r"/inventory/a/([0-9a-f-]{36})", code, re.I) or re.fullmatch(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", code, re.I)
    if m:
        import uuid  # noqa: PLC0415

        a = (await db.execute(select(InvAsset).where(InvAsset.uid == uuid.UUID(m.group(1))))).scalar_one_or_none()
        if a is not None:
            return a
    a = (await db.execute(select(InvAsset).where(or_(InvAsset.inv_no == code, func.lower(InvAsset.inv_no) == code.casefold())).limit(1))).scalar_one_or_none()
    if a is not None:
        return a
    rows = (await db.execute(select(InvAsset).where(or_(InvAsset.serial == code, func.lower(InvAsset.serial) == code.casefold())).limit(2))).scalars().all()
    return rows[0] if len(rows) == 1 else None
