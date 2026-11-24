"""Подготовленные сетевые наблюдения, карта и правила принадлежности."""
from __future__ import annotations

from datetime import datetime
from math import hypot
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_db
from ..db import xact_lock
from ..inventory import core as C
from ..inventory import geography as G
from ..inventory.geo_service import REQUEST, request_refresh, state_key
from ..inventory import geo_updater
from ..inventory.query import where_of
from ..models import AppSetting, InfraSource, InvAsset, InvGeo, InvGeoRule, InvLocation, InvPerson, InvRef, KscSource, Zone, utcnow
from ..services.sources import visible_sources
from .inv import Ix, audit, bad, filters_from, get_asset, inv_ctx

router = APIRouter(prefix="/inv/geography", tags=["inventory"])
MAX_RULES = 200


def allowed_sources(su) -> list[UUID] | None:
    return None if su.is_admin or su.all_sources else [UUID(s) for s in su.source_ids]


def observation(row: InvGeo | None, now: datetime) -> dict:
    return {**(row.result if row else {"status": "unknown"}), "observed_at": C._iso(row.observed_at) if row else None,
            "checked_at": C._iso(row.checked_at) if row else None, "fresh": bool(row and G.fresh(row.observed_at, now)),
            "source_id": str(row.source_id) if row else None}


async def query_conditions(db, request, filters, ctx, now):
    return await where_of(db, filters_from(request), ctx.acc, ctx.cfg) + G.geo_where(filters, now)


class GeoPage(G.GeoFilters):
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)
    overview: bool = True


@router.get("")
async def geography(request: Request, filters: Annotated[GeoPage, Query()], ctx: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    now = utcnow()
    w = await query_conditions(db, request, filters, ctx, now)
    join = G.selection(allowed_sources(ctx.su))
    base = select(InvAsset, InvGeo).outerjoin(InvGeo, join).where(*w)
    total = (await db.scalar(select(func.count()).select_from(InvAsset).outerjoin(InvGeo, join).where(*w))) or 0
    page = (await db.execute(base.order_by(InvAsset.inv_no, InvAsset.id).offset(filters.offset).limit(filters.limit))).all()
    names = await C.names_for(db, [a for a, _ in page], props=False)
    items = [{"id": a.id, "inv_no": a.inv_no, "name": a.name or a.hostname, "account_location": names.loc(a.location_id),
              **observation(g, now)} for a, g in page]
    if not filters.overview:
        locations = {k: v for k, v in (await db.execute(select(InvLocation.id, InvLocation.path).where(
            InvLocation.id.in_({i["site_id"] for i in items if i.get("site_id")})))).all()}
        for row in items:
            row["site"] = locations.get(row.get("site_id"), "")
        return {"items": items, "total": total}
    r = InvGeo.result
    keys = [r[k].as_string() for k in ("country", "region", "city")] + [r["site_id"].as_integer(), r["status"].as_string()]
    lat, lon = r["lat"].as_float(), r["lon"].as_float()
    count = func.count()
    grouped = (await db.execute(select(*keys, count, func.avg(lat), func.avg(lon), func.max(lat) - func.min(lat), func.max(lon) - func.min(lon),
                                       func.max(r["radius_km"].as_float()), func.sum(case((InvGeo.observed_at >= now - G.FRESH, 1), else_=0)))
                                .select_from(InvAsset).outerjoin(InvGeo, join).where(*w).group_by(*keys).order_by(count.desc(), *keys).limit(501))).all()
    groups = []
    for country, region, city, site_id, status, n, y, x, dlat, dlon, radius, fresh_n in grouped[:500]:
        groups.append({"country": country or "", "region": region or "", "city": city or "", "site_id": site_id, "status": status or "unknown",
                       "n": n, "lat": y, "lon": x, "fresh_n": fresh_n,
                       "radius_km": round(radius + 112 * hypot(dlat or 0, dlon or 0)) if radius is not None else None})
    srcs = await visible_sources(db, ctx.su)
    states = {x.group: x.value for x in (await db.scalars(select(AppSetting).where(AppSetting.group.in_([state_key(s.id) for s in srcs])))).all()}
    locations = {k: v for k, v in (await db.execute(select(InvLocation.id, InvLocation.path).where(
        InvLocation.id.in_({g["site_id"] for g in groups if g["site_id"]} | {i["site_id"] for i in items if i.get("site_id")})))).all()}
    for row in groups + items:
        row["site"] = locations.get(row.get("site_id"), "")
    return {"items": items, "total": total, "groups": groups, "groups_limited": len(grouped) > len(groups),
            "sources": [{"id": str(s.id), "name": s.name, **(states.get(state_key(s.id)) or {})} for s in srcs]}


async def current(db, aid, ctx, *, lock=False):
    asset = await get_asset(db, ctx, aid, lock=lock)
    obs = await db.get(InvGeo, aid)
    if not obs or asset.ksc_link not in ("auto", "confirmed") or (asset.ksc_source_id, asset.ksc_host_id) != (obs.source_id, obs.host_id) \
            or not ctx.su.can_use_source(obs.source_id):
        return asset, None
    return asset, obs


@router.get("/assets/{aid}")
async def asset_observation(aid: int, ctx: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    asset, obs = await current(db, aid, ctx)
    out = observation(obs, utcnow())
    if obs:
        src = await db.get(KscSource, obs.source_id)
        site = await db.get(InvLocation, out["site_id"]) if out.get("site_id") else None
        evidence = obs.evidence
        addresses = [{**a, "scope": G.address_scope(a["ip"])} for a in evidence.get("addresses", [])]
        out.update(source=src.name if src else "", site=site.path if site else "", evidence={**evidence, "addresses": addresses},
                   connection_ip=G.connection_observation(evidence))
        values = out.get("proposals", {})
        display = {}
        for field, model in (("location_id", InvLocation), ("dept_id", InvRef), ("branch_id", InvRef), ("resp_id", InvPerson), ("zone_id", Zone)):
            if values.get(field) and (row := await db.get(model, UUID(values[field]) if field == "zone_id" else values[field])):
                display[field] = {"label": C.M.FIELD_RU[field], "value": row.path if field == "location_id" else row.name,
                                  "empty": not getattr(asset, field)}
        out["fields"] = display
    return out


@router.post("/assets/{aid}/apply")
async def apply(aid: int, checked_at: Annotated[datetime, Body(embed=True)], ctx: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    asset, obs = await current(db, aid, ctx, lock=True)
    if not obs or obs.checked_at != checked_at or not G.fresh(obs.observed_at, utcnow()):
        raise HTTPException(status_code=409, detail="Наблюдение устарело. Обновите карточку")
    # Правило или тип оборудования могли измениться после расчёта.
    current_result = G.locate(obs.evidence, obs.source_id, asset.type_id, await G.rules_for(db), lambda _ip: {})
    proposed = current_result["proposals"]
    if proposed != obs.result.get("proposals"):
        raise HTTPException(status_code=409, detail="Правило изменилось. Дождитесь обновления наблюдений")
    data = {k: UUID(v) if k == "zone_id" else v for k, v in proposed.items() if v and getattr(asset, k) is None}
    if not data:
        return {"changed": []}
    try:
        changes = await C.apply_changes(db, asset, data, ctx.acc)
    except C.Invalid as exc:
        raise bad(exc) from exc
    if changes:
        await C.record(db, asset, C.kind_of(changes), changes, ctx.su.display_name, basis="Правило сетевой принадлежности")
        audit(db, ctx, "geo.apply", str(aid), {"fields": list(data)})
    await db.commit()
    return {"changed": changes}


def admin(ctx: Ix):
    if not ctx.su.is_admin:
        raise HTTPException(status_code=403, detail="Настройка сетевых правил доступна администратору")


@router.post("/refresh")
async def refresh(ctx: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    admin(ctx)
    await xact_lock(db, REQUEST)
    await request_refresh(db)
    audit(db, ctx, "geo.refresh", "", {})
    await db.commit()
    return {"requested": True}


@router.get("/geoip")
async def geoip_status(request: Request, ctx: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    admin(ctx)
    return await geo_updater.info(db, request.app.state.settings_svc)


@router.post("/geoip/refresh", status_code=202)
async def geoip_refresh(request: Request, ctx: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    admin(ctx)
    outcome = await geo_updater.queue(db, request.app.state.settings_svc)
    if outcome is None:
        raise HTTPException(status_code=422, detail="Сохраните номер учётной записи и ключ MaxMind")
    if outcome:
        audit(db, ctx, "geoip.refresh", "", {})
    await db.commit()
    return await geo_updater.info(db, request.app.state.settings_svc)


@router.get("/rules")
async def rules(ctx: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    admin(ctx)
    rows = await G.rules_for(db)
    infra = (await db.execute(select(InfraSource.id, InfraSource.name).order_by(InfraSource.name))).all()
    return {"items": [{"id": r.id, **r.rule.model_dump(mode="json")} for r in rows],
            "infra_sources": [{"id": sid, "name": name} for sid, name in infra]}


async def check_rule(db, body: G.Rule):
    for key in ("source_id", "infra_source_id", "site_id", "location_id", "branch_id", "dept_id", "type_id", "resp_id", "zone_id"):
        value = getattr(body, key)
        if value is None:
            continue
        model = {"source_id": KscSource, "infra_source_id": InfraSource, "site_id": InvLocation, "location_id": InvLocation,
                 "branch_id": InvRef, "dept_id": InvRef, "type_id": InvRef, "resp_id": InvPerson, "zone_id": Zone}[key]
        row = await db.get(model, value)
        if row is None or (model is InvRef and row.kind != key.removesuffix("_id")) or (model is InvLocation and not row.active):
            raise HTTPException(status_code=422, detail=f"Проверьте значение поля {key}")


class Preview(BaseModel):
    id: int | None = None
    rule: G.Rule


@router.post("/rules/preview")
async def preview(body: Preview, ctx: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    admin(ctx)
    await check_rule(db, body.rule)
    proposed = G.Compiled(body.id or -1, body.rule)
    rules = [r for r in await G.rules_for(db) if r.id != proposed.id] + [proposed]
    now = utcnow()
    q = select(InvAsset, InvGeo).join(InvGeo, G.selection(allowed_sources(ctx.su))).order_by(InvAsset.id)
    if (scope := ctx.acc.asset_filter()) is not None:
        q = q.where(scope)
    counts = dict(matched=0, effective=0, conflicts=0, would_fill=0, stale=0)
    sample = []
    async for a, g in await db.stream(q.execution_options(yield_per=500)):
        addresses = [(ip, r["kind"]) for r in g.evidence.get("addresses", []) if (ip := G.ip_int(r["ip"])) is not None]
        if proposed.match(g.evidence, g.source_id, a.type_id, addresses) is None:
            continue
        counts["matched"] += 1
        res = G.locate(g.evidence, g.source_id, a.type_id, rules, lambda _ip: {})
        effective = proposed.id in {r["id"] for r in res["rules"]}
        is_fresh = G.fresh(g.observed_at, now)
        counts["effective"] += effective and res["status"] != "conflict"
        counts["conflicts"] += effective and res["status"] == "conflict"
        counts["stale"] += not is_fresh
        counts["would_fill"] += bool(effective and is_fresh and any(getattr(a, field) is None for field in res["proposals"]))
        if len(sample) < 20:
            sample.append({"id": a.id, "inv_no": a.inv_no, "name": a.name or a.hostname, "status": res["status"], "effective": effective, "fresh": is_fresh})
    return {**counts, "items": sample}


@router.post("/rules", status_code=201)
@router.put("/rules/{rid}")
async def save_rule(body: G.Rule, rid: int | None = None, ctx: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    admin(ctx)
    await xact_lock(db, REQUEST)
    await check_rule(db, body)
    if rid is None:
        if (await db.scalar(select(func.count()).select_from(InvGeoRule)) or 0) >= MAX_RULES:
            raise HTTPException(status_code=409, detail=f"Достигнут предел в {MAX_RULES} правил")
        row = InvGeoRule()
        db.add(row)
    else:
        row = await db.get(InvGeoRule, rid, with_for_update=True)
        if row is None:
            raise HTTPException(status_code=404, detail="Правило не найдено")
    row.data = body.model_dump(mode="json")
    await db.flush()
    await request_refresh(db)
    audit(db, ctx, "geo.rule.save", str(row.id), {"name": body.name})
    await db.commit()
    return {"id": row.id, **row.data}


@router.delete("/rules/{rid}", status_code=204)
async def delete_rule(rid: int, ctx: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    admin(ctx)
    await xact_lock(db, REQUEST)
    row = await db.get(InvGeoRule, rid, with_for_update=True)
    if row is None:
        raise HTTPException(status_code=404, detail="Правило не найдено")
    await db.delete(row)
    await request_refresh(db)
    audit(db, ctx, "geo.rule.delete", str(rid), {})
    await db.commit()
