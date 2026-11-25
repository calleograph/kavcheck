"""Готовая аналитика из внутренней базы для специалистов с полным доступом."""
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_admin, require_user
from ..db import xact_lock
from ..inventory.model import COMPUTERS, ST_ACTIVE
from ..inventory import core as inventory, geography as geo
from ..models import (EmployeeProtectionDevice as D, EmployeeProtectionPerson as P, EmployeeWorkplaceDecision,
                      InvAsset, InvGeo, KscSource, ZcHost, ZcSource, utcnow)
from ..search import any_of, column_like
from ..services.settings import InventorySettings
from ..employee_protection import read, service
from ..employee_protection.filters import Filters
from ..inventory.core import access_for
from ..services.audit import write_audit

router = APIRouter(prefix="/employee-protection", tags=["employee-protection"])
DENIED = "Нужны права специалиста по ИБ, доступ ко всем источникам KSC и полная область просмотра инвентаризации и иерархии."


class PageFilters(Filters):
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=500)


async def allowed(request, db, su) -> bool:
    if su.is_admin:
        return True
    if not su.is_security or not su.all_sources:
        return False
    settings = request.app.state.settings_svc
    if su.role not in (await settings.get(db, "hier")).roles:
        return False
    acc = await access_for(db, su, await settings.get(db, "inventory"))
    return acc.can("view") and not acc.scopes


async def require_allowed(request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)) -> None:
    if not await allowed(request, db, su):
        raise HTTPException(status_code=403, detail=DENIED)


@router.get("/access")
async def access(request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    return {"allowed": await allowed(request, db, su), "can_refresh": su.is_admin}


@router.get("/summary", dependencies=[Depends(require_allowed)])
async def summary(filters: Annotated[Filters, Query()], db: AsyncSession = Depends(get_db)):
    return await read.summary(db, filters)


@router.get("/employees", dependencies=[Depends(require_allowed)])
async def employees(filters: Annotated[PageFilters, Query()], db: AsyncSession = Depends(get_db)):
    return await read.page(db, filters, "employees", filters.offset, filters.limit)


@router.get("/devices", dependencies=[Depends(require_allowed)])
async def devices(filters: Annotated[PageFilters, Query()], db: AsyncSession = Depends(get_db)):
    return await read.page(db, filters, "devices", filters.offset, filters.limit)


@router.get("/diagnostics", dependencies=[Depends(require_allowed)])
async def diagnostics(source_id: UUID | None = None, q: Annotated[str, Query(max_length=200)] = "",
                      offset: Annotated[int, Query(ge=0)] = 0, limit: Annotated[int, Query(ge=1, le=500)] = 100,
                      db: AsyncSession = Depends(get_db)):
    return await read.diagnostics(db, source_id=str(source_id) if source_id else "", q=q, offset=offset, limit=limit)


@router.get("/workplaces", dependencies=[Depends(require_allowed)])
async def workplaces(filters: Annotated[PageFilters, Query()], db: AsyncSession = Depends(get_db),
                     su: SessionUser = Depends(require_user)):
    current = await service.state(db)
    generation, meta = await read.snapshot(db, current=current)
    items, total = [], 0
    if generation:
        selection = read.Selection(generation, filters, workplaces=True)
        items = await read.workplace_rows(db, selection, filters.offset, filters.limit)
        total = await read.workplace_count(db, selection)
    pending = await service.request_at(db) > current.get("request", "")
    return {**meta, "generation": generation, "items": items, "total": total, "pending": pending, "can_edit": su.is_admin,
            "apply_blocked": pending or not _proposals_current(current), "snapshot_error": current.get("error")}


def _proposals_current(current):
    return not current.get("error") and current.get("inputs", {}).get("policy") == service.POLICY_VERSION


@router.get("/workplaces/people", dependencies=[Depends(require_allowed)])
async def workplace_people(q: Annotated[str, Query(max_length=200)] = "", limit: Annotated[int, Query(ge=1, le=50)] = 25,
                           db: AsyncSession = Depends(get_db)):
    generation, _ = await read.snapshot(db)
    if generation is None or len(q.strip()) < 2:
        return {"items": []}
    query = select(P.id, P.data).where(P.generation == generation, column_like(P.search, q)).order_by(P.search, P.id).limit(limit)
    return {"items": [{"id": pid, "name": data["name"], "detail": data.get("login", "")} for pid, data in await db.execute(query)]}


def _hosts():
    return (select(ZcHost.source_id, ZcHost.host_id, ZcHost.name, KscSource.name)
            .join(ZcSource, and_(ZcSource.source_id == ZcHost.source_id, ZcSource.gen == ZcHost.gen))
            .join(KscSource, KscSource.id == ZcHost.source_id)
            .where(KscSource.is_active.is_(True), ZcSource.gen > 0))


def _assets():
    return select(InvAsset).where(InvAsset.st_cls.in_(ST_ACTIVE), InvAsset.cls.in_(COMPUTERS))


def _asset_device(asset):
    if asset.ksc_link in ("auto", "confirmed") and asset.ksc_source_id and asset.ksc_host_id is not None:
        return f"ksc:{asset.ksc_source_id}:{asset.ksc_host_id}"
    return f"inv:{asset.id}"


@router.get("/workplaces/targets", dependencies=[Depends(require_allowed)])
async def workplace_targets(q: Annotated[str, Query(max_length=200)] = "", limit: Annotated[int, Query(ge=1, le=50)] = 25,
                             inventory: bool = False, asset_id: Annotated[int | None, Query(gt=0, le=2**63 - 1)] = None,
                             db: AsyncSession = Depends(get_db)):
    if not asset_id and len(q.strip()) < 2:
        return {"items": []}
    items = {}
    if not inventory and not asset_id:
        query = _hosts().where(column_like(ZcHost.name, q)).order_by(ZcHost.name, ZcHost.source_id, ZcHost.host_id).limit(limit)
        for sid, hid, name, source in await db.execute(query):
            items[f"ksc:{sid}:{hid}"] = {"name": name, "detail": f"{source} · {hid}"}
    active = select(KscSource.id).where(KscSource.is_active.is_(True))
    assets = _assets().where(or_(InvAsset.ksc_source_id.is_(None), InvAsset.ksc_source_id.in_(active)))
    assets = assets.where(InvAsset.id == asset_id) if asset_id else assets.where(any_of(q, InvAsset.hostname, InvAsset.name, InvAsset.inv_no))
    for asset in await db.scalars(assets.order_by(InvAsset.name, InvAsset.id).limit(limit)):
        items[_asset_device(asset)] = {"name": asset.name or asset.hostname or asset.inv_no, "detail": asset.inv_no}
    return {"items": [{"id": key, **v} for key, v in list(items.items())[:limit]]}


class Decision(BaseModel):
    employee_id: str = Field(min_length=1, max_length=120)
    device_id: str = Field(min_length=1, max_length=120)
    decision: Literal["confirmed", "rejected", "reset"]


class Decisions(BaseModel):
    generation: UUID
    items: list[Decision] = Field(min_length=1, max_length=100)
    comment: str = Field(default="", max_length=500)


async def _valid_targets(db, generation, ids):
    known = set(await db.scalars(select(D.id).where(D.generation == generation, D.id.in_(ids))))
    hosts, assets = set(), set()
    for item in ids - known:
        try:
            parts = item.split(":")
            if len(parts) == 3 and parts[0] == "ksc" and 0 < int(parts[2]) < 2**63:
                hosts.add((UUID(parts[1]), int(parts[2])))
            elif len(parts) == 2 and parts[0] == "inv" and 0 < int(parts[1]) < 2**63:
                assets.add(int(parts[1]))
        except ValueError:
            continue
    if hosts:
        for sid, hid, _, _ in await db.execute(_hosts().where(tuple_(ZcHost.source_id, ZcHost.host_id).in_(hosts))):
            known.add(f"ksc:{sid}:{hid}")
        for a in await db.scalars(_assets().where(tuple_(InvAsset.ksc_source_id, InvAsset.ksc_host_id).in_(hosts),
                                                  InvAsset.ksc_source_id.in_(select(KscSource.id).where(KscSource.is_active.is_(True))))):
            known.add(_asset_device(a))
    if assets:
        for a in await db.scalars(_assets().where(InvAsset.id.in_(assets))):
            known.add(_asset_device(a))
    return known == ids


@router.post("/workplaces/decide")
async def decide(body: Decisions, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    await xact_lock(db, "employee_workplace_decisions")
    generation, _ = await read.snapshot(db)
    if generation != body.generation:
        raise HTTPException(409, "Срез рабочих мест обновился. Обновите список и повторите действие.")
    keys = [(item.employee_id, item.device_id) for item in body.items]
    if len(keys) != len(set(keys)):
        raise HTTPException(422, "Для каждой пары сотрудника и компьютера допустимо одно решение.")
    people = {pid for pid, _ in keys}
    known = set(await db.scalars(select(P.id).where(P.generation == generation, P.id.in_(people))))
    if known != people or not await _valid_targets(db, generation, {did for _, did in keys}):
        raise HTTPException(409, "Сотрудник или компьютер отсутствует в актуальных источниках.")
    aliases = await service.device_aliases(db, {did for _, did in keys})
    if {(pid, aliases.get(did, did)) for pid, did in keys} != set(keys):
        raise HTTPException(409, "Связь учётной карточки с KSC обновилась. Обновите список.")
    old_ids = {canonical: previous for previous, canonical in aliases.items()}
    equivalent = [(pid, old_ids.get(did, did)) for pid, did in keys]
    existing = {(row.person_id, row.device_id): row for row in await db.scalars(select(EmployeeWorkplaceDecision).where(
        tuple_(EmployeeWorkplaceDecision.person_id, EmployeeWorkplaceDecision.device_id).in_([*keys, *equivalent])))}
    changed = 0
    for item in body.items:
        row = existing.get((item.employee_id, item.device_id))
        previous = existing.get((item.employee_id, old_ids.get(item.device_id, "")))
        effective = max(filter(None, (row, previous)), key=lambda x: x.decided_at, default=None)
        before = effective.decision if effective else None
        after = None if item.decision == "reset" else item.decision
        if before == after:
            continue
        if previous is not None:
            await db.delete(previous)
        if after is None:
            if row is not None:
                await db.delete(row)
        elif row:
            row.decision, row.decided_at = after, utcnow()
        else:
            db.add(EmployeeWorkplaceDecision(person_id=item.employee_id, device_id=item.device_id, decision=after, decided_at=utcnow()))
        write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="employee_protection.workplace",
                    target_type="employee_protection", target_id=item.device_id,
                    details={"employee_id": item.employee_id, "before": before, "after": after, "comment": body.comment.strip()})
        changed += 1
    if changed:
        await service.request_refresh(db)
        await db.commit()
    return {"changed": changed}


class Proposal(BaseModel):
    pair: str = Field(pattern=r"^[^|]{1,120}\|[^|]{1,120}$")
    version: int = Field(ge=1)
    values: dict[Literal["user_id", "dept_id", "location_id", "resp_id"], Annotated[int, Field(gt=0, le=2**63-1)]] = Field(min_length=1)


class Proposals(BaseModel):
    generation: UUID
    items: list[Proposal] = Field(min_length=1, max_length=100)


@router.post("/workplaces/apply")
async def apply_proposals(body: Proposals, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    await xact_lock(db, "employee_workplace_decisions")
    current = await service.state(db, lock=True)
    generation, _ = await read.snapshot(db, current=current)
    if generation != body.generation or not _proposals_current(current) or await service.request_at(db) > current.get("request", ""):
        raise HTTPException(409, "Срез рабочих мест меняется. Дождитесь пересчёта и обновите список.")
    items = {item.pair: item for item in body.items}
    selection = read.Selection(generation, Filters(inventory=True), workplaces=True, pairs=items)
    rows = await read.workplace_rows(db, selection, 0, len(items))
    ids = {row["device"]["asset_id"] for row in rows}
    if len(rows) != len(body.items) or len(ids) != len(rows):
        raise HTTPException(422, "Выберите по одной связи на каждую действующую карточку.")
    assets = {a.id: a for a in await db.scalars(_assets().where(InvAsset.id.in_(ids)).order_by(InvAsset.id)
              .with_for_update().execution_options(populate_existing=True))}
    rules = None
    now = utcnow()
    acc = await access_for(db, su, InventorySettings())
    for row in rows:
        item = items[row["id"]]
        asset = assets.get(row["device"]["asset_id"])
        changed = "Карточка или предложение изменились. Обновите список."
        if not asset or asset.version != item.version:
            raise HTTPException(409, changed)
        fields = row.get("proposals", {})
        if any(getattr(asset, k) is not None or fields.get(k, {}).get("id") != v for k, v in item.values.items()):
            raise HTTPException(409, changed)
        network = {k: v for k, v in item.values.items() if fields[k]["basis"] == "geo"}
        if network:
            obs = await db.get(InvGeo, asset.id)
            if not obs or not geo.fresh(obs.observed_at, now):
                raise HTTPException(409, changed)
            if rules is None:
                rules = await geo.rules_for(db)
            fresh = geo.locate(obs.evidence, obs.source_id, asset.type_id, rules, lambda _ip: {})["proposals"]
            if any(fresh.get(k) != v for k, v in network.items()):
                raise HTTPException(409, changed)
        try:
            changes = await inventory.apply_changes(db, asset, item.values, acc, infer_manufacturer=False)
        except inventory.Invalid as exc:
            raise HTTPException(409, changed) from exc
        await inventory.record(db, asset, inventory.kind_of(changes), changes, su.display_name, basis="Предложения по рабочему месту")
        write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="employee_protection.workplace_apply",
                    target_type="inventory", target_id=asset.id, details={"fields": list(item.values)})
    await service.request_refresh(db)
    await db.commit()
    return {"changed": len(rows)}


@router.post("/refresh", status_code=202)
async def refresh(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    queued = await service.queue(db)
    if queued:
        write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="employee_protection.refresh", target_type="employee_protection", target_id="snapshot")
        await db.commit()
    return {"queued": queued}
