"""Лицензии ПО в разделе «Инвентаризация»: приобретённые лицензии (количество, срок, поставщик, ответственный), назначения карточкам и сотрудникам, фактические установки по KSC
(подсчёт — worker, список компьютеров — по запросу), расхождения «установлено больше, чем куплено» и «установлено без назначения». Ключ активации здесь не хранится — только ссылка на запись в парольном менеджере (ключи прежних версий — зашифрованы до удаления),
выдаётся отдельным запросом с правом «просмотр ключей» и записью в журнал действий."""
from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_db
from ..inventory import core as C
from ..inventory import model as M
from ..inventory import service as S
from ..models import InvAsset, InvFile, InvLicAssign, InvLicense, InvPerson, InvRef, KscSource
from ..search import column_like, mssql_like
from .inv import Ix, audit, inv_ctx

router = APIRouter(prefix="/inv", tags=["inventory"])



def _n(v: int) -> str:
    return f"{v:,}".replace(",", "\u00a0")

def lic_state(lc: InvLicense, assigned: int, today: date, soon_days: int) -> dict:
    u = lc.usage or {}
    inst = u.get("installs")
    issues = []
    if lc.valid_until and lc.valid_until < today:
        issues.append("срок действия истёк")
    elif lc.valid_until and lc.valid_until <= today + timedelta(days=soon_days):
        issues.append(f"срок истекает {lc.valid_until:%d.%m.%Y}")
    if lc.qty is not None and assigned > lc.qty:
        issues.append(f"назначено больше, чем куплено ({_n(assigned)} из {_n(lc.qty)})")
    if lc.qty is not None and inst is not None and inst > lc.qty and lc.metric == "device":
        issues.append(f"установлено больше, чем куплено ({_n(inst)} из {_n(lc.qty)})")
    if inst is not None and lc.metric == "device" and inst > assigned and assigned:
        issues.append(f"установлено без назначения: {inst - assigned}")
    return {"installs": inst, "assigned": assigned, "free": (lc.qty - assigned) if lc.qty is not None else None, "issues": issues, "usage_at": u.get("at"), "usage_errors": u.get("errors") or []}


def lic_out(lc: InvLicense, refs: dict, people: dict, assigned: int, cfg) -> dict:
    return {"id": lc.id, "name": lc.name, "vendor": lc.vendor, "version": lc.version, "edition": lc.edition, "type_id": lc.type_id, "type": refs.get(lc.type_id, ""), "category_id": lc.category_id,
            "category": refs.get(lc.category_id, ""), "metric": lc.metric, "metric_ru": M.METRIC_RU.get(lc.metric, lc.metric), "qty": lc.qty, "match": lc.match or [],
            "purchase_date": C._d(lc.purchase_date), "valid_until": C._d(lc.valid_until), "supplier_id": lc.supplier_id, "supplier": refs.get(lc.supplier_id, ""), "cost": lc.cost,
            "cost_text": C.money_str(lc.cost), "purchase_doc": lc.purchase_doc, "resp_id": lc.resp_id, "resp": people.get(lc.resp_id, ""), "note": lc.note, "key_set": bool(lc.key_enc), "key_ref": lc.key_ref,
            "active": lc.active, "updated_at": C._iso(lc.updated_at), "updated_by": lc.updated_by, **lic_state(lc, assigned, date.today(), cfg.license_days)}


async def _ctx(db: AsyncSession, lics: list[InvLicense]) -> tuple[dict, dict, dict]:
    rids = {x for lc in lics for x in (lc.type_id, lc.category_id, lc.supplier_id)} - {None}
    pids = {lc.resp_id for lc in lics} - {None}
    refs = dict((await db.execute(select(InvRef.id, InvRef.name).where(InvRef.id.in_(rids)))).all()) if rids else {}
    people = dict((await db.execute(select(InvPerson.id, InvPerson.name).where(InvPerson.id.in_(pids)))).all()) if pids else {}
    assigned = dict((await db.execute(select(InvLicAssign.license_id, func.count()).where(InvLicAssign.license_id.in_([lc.id for lc in lics])).group_by(InvLicAssign.license_id))).all()) if lics else {}
    return refs, people, assigned


@router.get("/licenses")
async def licenses(request: Request, q: str = Query("", max_length=200), state: str = Query("", pattern=r"^(|soon|expired|issues|inactive)$"), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    w = [InvLicense.active.is_(state != "inactive")]
    for word in q.split()[:5]:
        conds = [c for c in (column_like(InvLicense.name, word), column_like(InvLicense.vendor, word)) if c is not None]
        if conds:
            from sqlalchemy import or_  # noqa: PLC0415

            w.append(or_(*conds))
    today = date.today()
    if state == "soon":
        w += [InvLicense.valid_until.is_not(None), InvLicense.valid_until >= today, InvLicense.valid_until <= today + timedelta(days=ix.cfg.license_days)]
    elif state == "expired":
        w += [InvLicense.valid_until < today]
    rows = (await db.execute(select(InvLicense).where(*w).order_by(InvLicense.name).limit(2000))).scalars().all()
    refs, people, assigned = await _ctx(db, list(rows))
    items = [lic_out(lc, refs, people, assigned.get(lc.id, 0), ix.cfg) for lc in rows]
    if state == "issues":
        items = [i for i in items if i["issues"]]
    st = await S.get_state(request.app.state.session_maker)
    return {"items": items, "total": len(items), "usage_at": st.get("lic_at"), "usage_requested": bool(st.get("lic_requested"))}


class LicBody(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    vendor: str = Field(default="", max_length=200)
    version: str = Field(default="", max_length=100)
    edition: str = Field(default="", max_length=100)
    type_id: int | None = None
    category_id: int | None = None
    metric: str = Field(default="device", pattern=r"^(device|user|site)$")
    qty: int | None = Field(default=None, ge=0, le=10_000_000)
    match: list[str] = Field(default_factory=list, max_length=10)
    purchase_date: date | None = None
    valid_until: date | None = None
    supplier_id: int | None = None
    cost: str | int | None = None
    purchase_doc: str = Field(default="", max_length=300)
    resp_id: int | None = None
    note: str = Field(default="", max_length=8000)
    key_ref: str = Field(default="", max_length=500)                      # где хранится ключ: ссылка на запись в парольном менеджере
    key: str | None = Field(default=None, max_length=0)                    # только "" — удалить ключ, сохранённый прежней версией; новые ключи не принимаются
    active: bool = True


async def _apply(db: AsyncSession, request: Request, lc: InvLicense, body: LicBody, by: str) -> None:
    for f, kind in (("type_id", "license_type"), ("category_id", "sw_category"), ("supplier_id", "supplier")):
        v = getattr(body, f)
        if v:
            r = await db.get(InvRef, v)
            if r is None or r.kind != kind:
                raise HTTPException(status_code=422, detail="Значение справочника не найдено")
    if body.resp_id and await db.get(InvPerson, body.resp_id) is None:
        raise HTTPException(status_code=422, detail="Ответственный не найден")
    for m in body.match:
        try:
            mssql_like(m)
        except Exception as exc:  # noqa: BLE001 — MaskError с понятным текстом
            raise HTTPException(status_code=422, detail=f"Маска «{m}»: {exc}") from None
    try:
        cost = C.parse_money(body.cost)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Стоимость: {exc}") from None
    lc.name, lc.vendor, lc.version, lc.edition = body.name.strip(), body.vendor.strip(), body.version.strip(), body.edition.strip()
    lc.type_id, lc.category_id, lc.metric, lc.qty, lc.match = body.type_id, body.category_id, body.metric, body.qty, [m.strip() for m in body.match if m.strip()]
    lc.purchase_date, lc.valid_until, lc.supplier_id, lc.cost, lc.purchase_doc, lc.resp_id, lc.note, lc.active = (body.purchase_date, body.valid_until, body.supplier_id, cost, body.purchase_doc,
                                                                                                                   body.resp_id, body.note, body.active)
    lc.key_ref = body.key_ref.strip()
    if body.key is not None:
        lc.key_enc = ""
    lc.updated_at, lc.updated_by = C.utcnow(), by


@router.post("/licenses", status_code=201)
async def add_license(body: LicBody, request: Request, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("create")
    lc = InvLicense(name=body.name)
    db.add(lc)
    await db.flush()
    await _apply(db, request, lc, body, ix.su.display_name)
    audit(db, ix, "license.add", lc.name[:120], {"id": lc.id, "qty": lc.qty, "key_ref": bool(lc.key_ref)})
    await db.commit()
    if lc.match:
        await S.set_state(request.app.state.session_maker, lic_requested=True)
    return {"id": lc.id}


@router.put("/licenses/{lid}")
async def edit_license(lid: int, body: LicBody, request: Request, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("edit")
    lc = await db.get(InvLicense, lid)
    if lc is None:
        raise HTTPException(status_code=404, detail="Лицензия не найдена")
    old_match = list(lc.match or [])
    await _apply(db, request, lc, body, ix.su.display_name)
    audit(db, ix, "license.edit", lc.name[:120], {"id": lid, "key_ref": lc.key_ref[:200], "old_key_removed": body.key is not None})
    await db.commit()
    if lc.match != old_match:
        await S.set_state(request.app.state.session_maker, lic_requested=True)
    return {"ok": True}


@router.get("/licenses/{lid}")
async def license_card(lid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    lc = await db.get(InvLicense, lid)
    if lc is None:
        raise HTTPException(status_code=404, detail="Лицензия не найдена")
    refs, people, assigned = await _ctx(db, [lc])
    rows = (await db.execute(select(InvLicAssign).where(InvLicAssign.license_id == lid).order_by(InvLicAssign.at.desc()))).scalars().all()
    assets = {a.id: a for a in (await db.execute(select(InvAsset).where(InvAsset.id.in_({r.asset_id for r in rows} - {None})))).scalars()} if rows else {}
    ppl = dict((await db.execute(select(InvPerson.id, InvPerson.name).where(InvPerson.id.in_({r.person_id for r in rows} - {None})))).all()) if rows else {}
    files = (await db.execute(select(InvFile.id, InvFile.name, InvFile.size, InvFile.at, InvFile.by).where(InvFile.owner == "license", InvFile.owner_id == lid))).all()
    return {**lic_out(lc, refs, people, assigned.get(lc.id, 0), ix.cfg),
            "assignments": [{"id": r.id, "asset_id": r.asset_id, "asset": f"{assets[r.asset_id].name or assets[r.asset_id].hostname} ({assets[r.asset_id].inv_no})" if r.asset_id in assets else "",
                             "ksc": bool(r.asset_id in assets and assets[r.asset_id].ksc_host_id), "person_id": r.person_id, "person": ppl.get(r.person_id, ""), "at": C._iso(r.at), "by": r.by, "note": r.note}
                            for r in rows],
            "files": [{"id": i, "name": nm, "size": sz, "at": C._iso(at), "by": by} for i, nm, sz, at, by in files], "usage": lc.usage or {}, "can_key": ix.acc.can("keys")}


@router.get("/licenses/{lid}/installs")
async def license_installs(lid: int, request: Request, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Компьютеры, где установлена программа по маскам лицензии (запрос к KSC по каждому доступному источнику, до 2000 на маску), и есть ли у компьютера назначение лицензии."""
    from ..ksc import queries as q  # noqa: PLC0415
    from ..ksc.driver import KscError  # noqa: PLC0415

    lc = await db.get(InvLicense, lid)
    if lc is None:
        raise HTTPException(status_code=404, detail="Лицензия не найдена")
    if not lc.match:
        return {"items": [], "note": "Не заданы маски названия программы — установки не считаются."}
    general = await request.app.state.settings_svc.get(db, "general")
    since = C.utcnow() - timedelta(days=general.activity_days)
    assigned_hosts = {(str(s), h) for s, h in (await db.execute(select(InvAsset.ksc_source_id, InvAsset.ksc_host_id).join(InvLicAssign, InvLicAssign.asset_id == InvAsset.id)
                                                               .where(InvLicAssign.license_id == lid, InvAsset.ksc_host_id.is_not(None)))).all()}
    items, errors = {}, []
    for s in (await db.execute(select(KscSource))).scalars().all():
        if not ix.su.can_use_source(s.id):
            continue
        client = request.app.state.sources.client(s)
        for m in lc.match[:10]:
            try:
                rows = await client.run(q.LIC_HOSTS, {"p": mssql_like(m), "since": since, "n": 2000}, max_rows=2000)
            except KscError as exc:
                errors.append(f"{s.name}: {exc}")
                break
            for r in rows:
                k = (str(s.id), int(r["host_id"]))
                items.setdefault(k, {"source_id": k[0], "source": s.name, "host_id": k[1], "name": r.get("name") or "", "product": r.get("product") or "", "version": r.get("version") or "",
                                     "assigned": k in assigned_hosts})
    linked = {(str(s), h): (aid, no) for aid, no, s, h in (await db.execute(select(InvAsset.id, InvAsset.inv_no, InvAsset.ksc_source_id, InvAsset.ksc_host_id).where(InvAsset.ksc_host_id.in_([k[1] for k in items])))).all()} if items else {}
    for k, it in items.items():
        aid = linked.get(k)
        it["asset_id"], it["inv_no"] = (aid[0], aid[1]) if aid else (None, "")
    return {"items": sorted(items.values(), key=lambda x: x["name"].casefold()), "errors": errors, "days": general.activity_days}


class AssignBody(BaseModel):
    asset_ids: list[int] = Field(default_factory=list, max_length=5000)
    person_ids: list[int] = Field(default_factory=list, max_length=5000)
    note: str = Field(default="", max_length=500)


@router.post("/licenses/{lid}/assign")
async def assign(lid: int, body: AssignBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Назначить лицензию карточкам и/или сотрудникам (повторное назначение пропускается). Превышение количества не запрещается, а показывается как расхождение."""
    ix.acc.need("edit")
    lc = await db.get(InvLicense, lid)
    if lc is None:
        raise HTTPException(status_code=404, detail="Лицензия не найдена")
    have_a = {a for (a,) in (await db.execute(select(InvLicAssign.asset_id).where(InvLicAssign.license_id == lid, InvLicAssign.asset_id.is_not(None))))}
    have_p = {p for (p,) in (await db.execute(select(InvLicAssign.person_id).where(InvLicAssign.license_id == lid, InvLicAssign.person_id.is_not(None))))}
    sa = select(InvAsset).where(InvAsset.id.in_(body.asset_ids))
    if (af := ix.acc.asset_filter()) is not None:
        sa = sa.where(af)
    ok_a = {a.id: a for a in (await db.execute(sa)).scalars()} if body.asset_ids else {}
    nm = await C.names_for(db, list(ok_a.values()))                # имена всех карточек одной выборкой
    ok_p = {p for (p,) in (await db.execute(select(InvPerson.id).where(InvPerson.id.in_(body.person_ids))))} if body.person_ids else set()
    n = 0
    for aid in dict.fromkeys(body.asset_ids):
        if aid in ok_a and aid not in have_a:
            db.add(InvLicAssign(license_id=lid, asset_id=aid, by=ix.su.display_name, note=body.note))
            await C.record(db, ok_a[aid], "update", [{"f": "license", "label": "Лицензия", "old": "", "new": lc.name}], ix.su.display_name, title=f"Назначена лицензия «{lc.name}»", names=nm)
            n += 1
    for pid in dict.fromkeys(body.person_ids):
        if pid in ok_p and pid not in have_p:
            db.add(InvLicAssign(license_id=lid, person_id=pid, by=ix.su.display_name, note=body.note))
            n += 1
    audit(db, ix, "license.assign", lc.name[:120], {"id": lid, "added": n})
    await db.commit()
    return {"added": n}


@router.delete("/licenses/{lid}/assign/{aid}")
async def unassign(lid: int, aid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("edit")
    r = await db.get(InvLicAssign, aid)
    if r is None or r.license_id != lid:
        raise HTTPException(status_code=404, detail="Назначение не найдено")
    lc = await db.get(InvLicense, lid)
    if r.asset_id:
        sa = select(InvAsset).where(InvAsset.id == r.asset_id)
        if (af := ix.acc.asset_filter()) is not None:
            sa = sa.where(af)
        a = (await db.execute(sa)).scalar_one_or_none()
        if a is None and af is not None:
            raise HTTPException(status_code=404, detail="Назначение не найдено или вне вашей области учёта")
        if a is not None:
            await C.record(db, a, "update", [{"f": "license", "label": "Лицензия", "old": lc.name, "new": ""}], ix.su.display_name, title=f"Снято назначение лицензии «{lc.name}»")
    audit(db, ix, "license.unassign", lc.name[:120], {"id": lid, "assign": aid})
    await db.delete(r)
    await db.commit()
    return {"ok": True}


@router.get("/licenses/{lid}/key")
async def license_key(lid: int, request: Request, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Ключ активации: только с правом «просмотр ключей лицензий»; каждое открытие — запись в журнале действий."""
    ix.acc.need("keys")
    lc = await db.get(InvLicense, lid)
    if lc is None or not lc.key_enc:
        raise HTTPException(status_code=404, detail="Ключ не сохранён")
    svc = request.app.state.settings_svc
    if svc.box is None:
        raise HTTPException(status_code=409, detail="Не задан APP_MASTER_KEY")
    key = svc.decrypt(lc.key_enc, f"inv.lic.{lc.id}")
    audit(db, ix, "license.key_view", lc.name[:120], {"id": lid})
    await db.commit()
    return {"key": key}


@router.post("/licenses/recount")
async def recount(request: Request, ix: Ix = Depends(inv_ctx)):
    """Пересчитать использование лицензий (worker, в течение минуты)."""
    ix.acc.need("edit")
    await S.set_state(request.app.state.session_maker, lic_requested=True)
    return {"queued": True}
