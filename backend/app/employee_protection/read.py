"""Одинаковый отбор для сводки, детализации и Excel."""
from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from sqlalchemy import BigInteger, and_, cast, func, or_, select, tuple_

from ..models import EmployeeProtectionDevice as D
from ..models import EmployeeProtectionLink as L
from ..models import EmployeeProtectionPerson as P
from ..models import InvAsset, InvGeo, InvPerson, InvRef, KscSource, utcnow
from ..inventory import geography as geo
from ..inventory.model import FIELD_RU, ST_ACTIVE
from ..search import any_field, column_like
from . import classify, service
from .filters import Filters

INSUFFICIENT = frozenset({"stale", "outside_ksc", "no_devices", "unknown"})
FRESHNESS = {"fresh": "Актуальные", "stale": "Устарели", "unknown": "Недостаточно данных"}
OWNERSHIP = {"corporate": "Корпоративное", "personal": "Личное", "unknown": "Не определено"}
EMPTY = "_none"
CONFIDENCE = {"confirmed": "Подтверждённая", "likely": "Высокая вероятность",
              "possible": "Предполагаемая", "rejected": "Отклонена"}
ACCOUNT_FIELDS = frozenset({"user_id", "dept_id", "location_id", "resp_id"})


def _val(table, key):
    return func.coalesce(table.data[key].as_string(), "")


def _match(field, value):
    return field == ("" if value == EMPTY else value)


class Selection:
    def __init__(self, generation: uuid.UUID, f: Filters, *, workplaces=False, pairs=(), asset_ids=None):
        p = [P.generation == generation]
        d = [D.generation == generation]
        for key in ("organization", "department", "division", "status"):
            if value := getattr(f, key):
                p.append(_match(_val(P, key), value))
        for key in ("kind", "ownership", "os", "freshness"):
            if value := getattr(f, key):
                d.append(_match(_val(D, key), value))
        if f.zone:
            d.append(column_like(D.zone_keys, f"|{f.zone.lower()}|"))
        if f.device_status:
            d.append(_val(D, "status") == f.device_status)
        if f.employee_id:
            p.append(P.id == f.employee_id)
        if f.device_id:
            d.append(D.id == f.device_id)
        if f.metric in ("protected", "partial", "no_av"):
            p.append(_val(P, "status") == f.metric)
        elif f.metric == "uses_av":
            p.append(P.data["uses_av"].as_boolean().is_(True))
        elif f.metric == "insufficient":
            p.append(_val(P, "status").in_(INSUFFICIENT))
        elif f.metric in ("corporate", "personal"):
            d.append(_val(D, "ownership") == f.metric)
        pq, dq = column_like(P.search, f.q), column_like(D.search, f.q)
        match_search = [] if pq is None else [or_(pq, dq)]
        counted = func.coalesce(L.assessment["counted"].as_boolean(), True)
        self.confidence = func.coalesce(L.assessment["confidence"].as_string(), "likely")
        if workplaces:
            counted = self.confidence == f.confidence if f.confidence else True
            if pairs:
                match_search.append(tuple_(L.person_id, L.device_id).in_([tuple(key.split("|", 1)) for key in pairs]))
            if asset_ids is not None:
                d.append(cast(D.data["asset_id"].as_string(), BigInteger).in_(asset_ids))
                d.append(D.data["shared_count"].as_integer() == 1)
            if f.asset_id or f.inventory:
                asset = cast(D.data["asset_id"].as_string(), BigInteger)
                active = select(InvAsset.id).where(InvAsset.st_cls.in_(ST_ACTIVE))
                if f.asset_id:
                    active = active.where(InvAsset.id == f.asset_id)
                d.append(asset.in_(active))
        self.pairs = (select(L.person_id, L.device_id, L.evidence, L.assessment)
                      .join(P, and_(P.generation == L.generation, P.id == L.person_id))
                      .join(D, and_(D.generation == L.generation, D.id == L.device_id))
                      .where(L.generation == generation, counted, *p, *d, *match_search).cte("matched_pairs"))
        person_eq = P.id.in_(select(self.pairs.c.person_id))
        if len(d) > 1 or f.metric == "devices":
            p.append(person_eq)
        elif pq is not None:
            p.append(or_(pq, person_eq))
        self.people = p
        self.devices = [D.generation == generation, D.id.in_(select(self.pairs.c.device_id))]
        self.generation = generation


async def snapshot(db, *, current=None):
    meta = await service.state(db) if current is None else current
    out = {key: meta.get(key) for key in ("built_at", "census_at", "census_source", "activity_days")}
    out["warnings"] = list(meta.get("warnings") or [])
    if meta.get("error"):
        out["warnings"].append(meta["error"])
    census_at = service.stamp(meta.get("census_at"))
    generation = None
    if meta.get("ready") and census_at and utcnow() - census_at <= service.CENSUS_MAX_AGE:
        generation = uuid.UUID(meta["generation"])
    if not generation and not out["warnings"]:
        out["warnings"].append("Для сводки нужна успешная актуальная проверка в разделе «Аудит домена».")
    return generation, {**out, "ready": generation is not None}


async def diagnostics(db, *, source_id="", q="", offset=0, limit=None):
    current = await service.state(db)
    _, meta = await snapshot(db, current=current)
    by_source = {row["source_id"]: row for row in current.get("source_diagnostics", [])}
    active = await db.execute(select(KscSource.id, KscSource.name).where(KscSource.is_active.is_(True)).order_by(KscSource.name, KscSource.id))
    hit = any_field(q)
    rows = []
    for sid, name in active:
        key = str(sid)
        if source_id and key != source_id:
            continue
        row = {"source_id": key, "source_name": name, "polled_at": None, "snapshot_at": None, "status": "pending",
               "reason": "Ожидается расчёт диагностики", "observed": None, "matched": None, "eligible": None,
               "possible": None, "current": None, "av_known": None, **by_source.get(key, {})}
        row["source_name"] = name
        if hit is None or hit(name, row["reason"]):
            rows.append(row)
    return {**meta, "total": len(rows), "items": rows[offset: offset + limit] if limit is not None else rows[offset:]}


def _option(value, label=None):
    return {"value": value or EMPTY, "label": label or value or "Не указано"}


async def _options(db, generation):
    out = {"ownership": [_option(k, v) for k, v in OWNERSHIP.items()]}
    for table, keys in ((P, ("organization", "department", "division")), (D, ("kind", "os"))):
        for key in keys:
            value = _val(table, key)
            values = list(await db.scalars(select(value).where(table.generation == generation).distinct().order_by(value).limit(1000)))
            out[key] = [_option(v) for v in values]
    zones = {}
    async for items in await db.stream_scalars(select(D.data["zones"]).where(D.generation == generation).distinct()):
        for zone in (items or []):
            zones[zone["id"]] = zone["name"]
    out["zone"] = [_option(k, v) for k, v in sorted(zones.items(), key=lambda p: p[1].casefold())]
    if await db.scalar(select(D.id).where(D.generation == generation, D.zone_keys == "|none|").limit(1)) is not None and "none" not in zones:
        out["zone"].append(_option("none", "Без зоны ответственности"))
    return out


async def summary(db, filters: Filters, *, prepared=None) -> dict:
    generation, meta = prepared or await snapshot(db)
    if prepared is None:
        pending = await service.request_at(db) > (await service.state(db)).get("request", "")
        meta.update(running=await service.running(db) or pending)
    totals = dict.fromkeys(("employees", "uses_av", "protected", "partial", "no_av", "insufficient", "devices", "corporate", "personal"), 0)
    labels = {"employee_status": classify.EMPLOYEE_LABELS, "device_status": classify.DEVICE_LABELS, "freshness": FRESHNESS, "reason": classify.REASON_LABELS}
    if generation is None:
        return {**meta, "totals": totals, "statuses": [], "by_department": [], "by_os": [], "options": {}, "labels": labels}
    selected = Selection(generation, filters)
    dep, ps, used = _val(P, "department"), _val(P, "status"), P.data["uses_av"].as_boolean()
    pcounts = (await db.execute(select(dep, ps, used, func.count()).where(*selected.people).group_by(dep, ps, used))).all()
    statuses, departments = Counter(), defaultdict(Counter)
    for name, status, uses_av, count in pcounts:
        statuses[status] += count
        departments[name][status] += count
        totals["employees"] += count
        departments[name]["total"] += count
        if uses_av:
            totals["uses_av"] += count
            departments[name]["uses_av"] += count
        if status in INSUFFICIENT:
            departments[name]["insufficient"] += count
    for key in ("protected", "partial", "no_av"):
        totals[key] = statuses[key]
    totals["insufficient"] = sum(statuses[k] for k in INSUFFICIENT)
    by_department = [{**_option(name), **{k: counts[k] for k in ("total", "uses_av", "protected", "partial", "no_av", "insufficient")}}
                     for name, counts in sorted(departments.items(), key=lambda e: (-e[1]["total"], e[0].casefold()))]
    os_name, ds, own = _val(D, "os"), _val(D, "status"), _val(D, "ownership")
    dcounts = (await db.execute(select(os_name, ds, own, func.count()).where(*selected.devices).group_by(os_name, ds, own))).all()
    systems = defaultdict(Counter)
    for name, status, ownership, count in dcounts:
        totals["devices"] += count
        if ownership in ("corporate", "personal"):
            totals[ownership] += count
        systems[name][status] += count
        systems[name]["total"] += count
    by_os = [{**_option(name), **{k: counts[k] for k in ("total", "protected", "problems", "no_av")}}
             for name, counts in sorted(systems.items(), key=lambda e: (-e[1]["total"], e[0].casefold()))]
    return {**meta, "totals": totals, "labels": labels,
            "statuses": [{"id": k, "label": label, "count": statuses[k]} for k, label in classify.EMPLOYEE_LABELS.items()],
            "by_department": by_department, "by_os": by_os, "options": await _options(db, generation) if prepared is None else {}}


async def count(db, selection: Selection, view: str) -> int:
    table, where = (P, selection.people) if view == "employees" else (D, selection.devices)
    return await db.scalar(select(func.count()).select_from(table).where(*where)) or 0


async def rows(db, selection: Selection, view: str, offset: int, limit: int) -> list[dict]:
    table, where = (P, selection.people) if view == "employees" else (D, selection.devices)
    ordered = select(table.data).where(*where).order_by(func.lower(_val(table, "name")), table.id).offset(offset).limit(limit)
    out = list(await db.scalars(ordered))
    if view == "employees" or not out:
        return out
    p = selection.pairs.c
    linked = (select(p.device_id, P.data, p.evidence).select_from(selection.pairs)
              .join(P, P.id == p.person_id).where(P.generation == selection.generation, p.device_id.in_([item["id"] for item in out]))
              .order_by(func.lower(_val(P, "name")), P.id))
    people = defaultdict(list)
    for did, person, evidence in (await db.execute(linked)).all():
        people[did].append({**{k: person[k] for k in ("id", "name", "login")}, "evidence": evidence})
    return [{**row, "employees": people[row["id"]]} for row in out]


async def page(db, filters: Filters, view: str, offset: int, limit: int) -> dict:
    generation, _ = await snapshot(db)
    if generation is None:
        return {"items": [], "total": 0}
    selection = Selection(generation, filters)
    return {"items": await rows(db, selection, view, offset, limit), "total": await count(db, selection, view)}


async def workplace_count(db, selection):
    return await db.scalar(select(func.count()).select_from(selection.pairs)) or 0


async def workplace_rows(db, selection, offset, limit, *, include_network=True):
    pairs = selection.pairs.c
    q = (select(P.data, D.data, pairs.evidence, pairs.assessment).select_from(selection.pairs)
         .join(P, and_(P.id == pairs.person_id, P.generation == selection.generation))
         .join(D, and_(D.id == pairs.device_id, D.generation == selection.generation))
         .order_by(func.lower(_val(P, "name")), P.id, func.lower(_val(D, "name")), D.id).offset(offset).limit(limit))
    rows = [{"id": f"{person['id']}|{device['id']}", "employee": person, "device": device, "evidence": evidence, "confidence": "likely",
             "primary": person.get("primary_device_id") == device["id"],
             "decision": None, **assessment} for person, device, evidence, assessment in await db.execute(q)]
    await _proposals(db, rows, include_network=include_network)
    return rows


async def _proposals(db, rows, *, include_network=True):
    ids = {r["device"]["asset_id"] for r in rows if r["device"].get("asset_id")}
    if not ids:
        return
    assets = {a.id: a for a in await db.scalars(select(InvAsset).where(InvAsset.id.in_(ids)))}
    observations = {}
    if include_network:
        observations = {obs.asset_id: obs for obs in await db.scalars(select(InvGeo).where(
            InvGeo.asset_id.in_(ids), InvGeo.observed_at >= utcnow() - geo.FRESH))}
    emails = {r["employee"]["email"] for r in rows if r["employee"].get("email_verified") and r["employee"].get("email")}
    people = defaultdict(list)
    if emails:
        for pid, name, email in await db.execute(select(InvPerson.id, InvPerson.name, func.lower(InvPerson.email)).where(
                InvPerson.active.is_(True), func.lower(InvPerson.email).in_(emails))):
            people[email].append((pid, name))
    names = {r["employee"]["department"].casefold() for r in rows if r["employee"].get("department")}
    departments = defaultdict(list)
    if names:
        for did, name in await db.execute(select(InvRef.id, func.lower(InvRef.name)).where(
                InvRef.kind == "dept", InvRef.active.is_(True), func.lower(InvRef.name).in_(names))):
            departments[name].append(did)
    network = {}
    for aid, obs in observations.items():
        a = assets.get(aid)
        if a and a.ksc_link in ("auto", "confirmed") and (obs.source_id, obs.host_id) == (a.ksc_source_id, a.ksc_host_id):
            network[aid] = (a, {k: v for k, v in (obs.result.get("proposals") or {}).items() if k in ACCOUNT_FIELDS})
    groups = await geo.proposal_fields_for(db, network)
    proposals = {aid: {k: {**v, "id": network[aid][1][k], "basis": "geo"} for k, v in data.items() if v["empty"]}
                 for aid, data in groups.items()}
    for item in rows:
        device, employee = item["device"], item["employee"]
        asset = assets.get(device.get("asset_id"))
        if not asset:
            continue
        item["asset_version"] = asset.version
        fields = dict(proposals.get(asset.id, {}))
        if item["confidence"] in ("confirmed", "likely") and device.get("shared_count") == 1 and not item.get("shared"):
            matches = people.get(employee.get("email"), []) if employee.get("email_verified") else ()
            if asset.user_id is None and len(matches) == 1:
                pid, name = matches[0]
                fields["user_id"] = {"label": FIELD_RU["user_id"], "value": name, "id": pid, "basis": "workplace"}
            dept = employee.get("department", "")
            matching_depts = departments[dept.casefold()]
            if asset.dept_id is None and "dept_id" not in fields and len(matching_depts) == 1:
                fields["dept_id"] = {"label": FIELD_RU["dept_id"], "value": dept, "id": matching_depts[0], "basis": "workplace"}
        item["proposals"] = fields
