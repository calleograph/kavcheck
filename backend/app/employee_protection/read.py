"""Одинаковый отбор для сводки, детализации и Excel."""
from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from sqlalchemy import BigInteger, and_, cast, func, or_, select, tuple_

from ..models import EmployeeProtectionDevice as D
from ..models import EmployeeProtectionLink as L
from ..models import EmployeeProtectionPerson as P
from ..models import InvAsset, InvPerson, InvRef, KscSource, utcnow
from ..inventory import geography as geo
from ..inventory.model import AUTO_FILL_FIELDS, FIELD_RU, OWNERSHIP_RU, ST_ACTIVE
from ..search import any_field, column_like
from . import classify, service
from .filters import Filters
from .workplace import CURRENT_AGE, SERVER

INSUFFICIENT = frozenset({"stale", "outside_ksc", "no_devices", "unknown"})
FRESHNESS = {"fresh": "Актуальные", "stale": "Устарели", "unknown": "Недостаточно данных"}
OWNERSHIP = {**OWNERSHIP_RU, "unknown": "Не определено"}
OWNERSHIP_BASIS = {"inventory": "Карточка учёта", "bi": "Выгрузка BI", "accounting": "Бухгалтерский номер", "conflict": "Противоречивые данные BI"}
EMPTY = "_none"
CONFIDENCE = {"confirmed": "Подтверждённая", "likely": "Высокая вероятность",
              "possible": "Предполагаемая", "rejected": "Отклонена"}
ASSIGNMENT = {"manual": "Назначен вручную", "inventory": "По инвентаризации", "bi": "По выгрузке BI",
              "observed": "По доменным сеансам", "unassigned": "Сотрудник не закреплён"}


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
        if f.assignment:
            basis = D.data["assignment"]["basis"].as_string()
            d.append(func.coalesce(basis, "unassigned") == f.assignment)
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
                match_search.append(or_(L.assessment["assignment_basis"].as_string().is_not(None),
                                        and_(D.data["assignment"]["basis"].as_string().is_(None),
                                             D.data["shared_count"].as_integer() == 1, self.confidence == "confirmed")))
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
    out = {"ownership": [_option(k, v) for k, v in OWNERSHIP.items()],
           "assignment": [_option(k, v) for k, v in ASSIGNMENT.items()]}
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
    now = utcnow()
    assets = {a.id: a for a in await db.scalars(select(InvAsset).where(InvAsset.id.in_(ids)))}
    emails = {r["employee"]["email"] for r in rows if r["employee"].get("email_verified") and r["employee"].get("email")}
    logins = {}
    for row in rows:
        p = row["employee"]
        if p.get("login_verified") and "@" in p["login"]:
            username, domain = p["login"].lower().rsplit("@", 1)
            logins[p["id"]] = (p["login"].lower(), f"{domain}\\{username}")
    people = defaultdict(list)
    for_login = defaultdict(list)
    if emails or logins:
        mail, login = func.lower(func.trim(InvPerson.email)), func.lower(func.trim(InvPerson.login))
        expr = or_(mail.in_(emails), login.in_({v for pair in logins.values() for v in pair}))
        for pid, name, email, account in await db.execute(select(InvPerson.id, InvPerson.name, mail, login)
                                                          .where(InvPerson.active.is_(True), expr)):
            people[email].append((pid, name))
            for_login[account].append((pid, name))
    names = {r["employee"]["department"].casefold() for r in rows if r["employee"].get("department")}
    departments = defaultdict(list)
    if names:
        for did, name in await db.execute(select(InvRef.id, func.lower(InvRef.name)).where(
                InvRef.kind == "dept", InvRef.active.is_(True), func.lower(InvRef.name).in_(names))):
            departments[name].append(did)
    placement = await geo.placement_proposals(db, assets, now, AUTO_FILL_FIELDS) if include_network else {}
    network = {aid: (assets[aid], {key: val for key, (val, _) in group.items()}) for aid, group in placement.items()}
    groups = await geo.proposal_fields_for(db, network)
    proposals = {aid: {k: {**v, "id": placement[aid][k][0], "basis": placement[aid][k][1]} for k, v in data.items() if v["empty"]}
                 for aid, data in groups.items()}
    for item in rows:
        device, employee = item["device"], item["employee"]
        asset = assets.get(device.get("asset_id"))
        if not asset:
            continue
        if device["id"].startswith("ksc:"):
            if asset.ksc_link not in ("auto", "confirmed") or (device.get("source_id"), device.get("host_id")) != (str(asset.ksc_source_id), asset.ksc_host_id):
                continue
        if device["id"].startswith("inv:") and asset.ksc_link == "confirmed" and asset.ksc_source_id and asset.ksc_host_id is not None:
            continue
        item["asset_version"] = asset.version
        fields = dict(proposals.get(asset.id, {}))
        basis = item.get("assignment_basis")
        assigned = bool(basis and device.get("shared_reason") != SERVER)
        if basis == "observed":
            stamps = (item.get("last_verified_at"), device.get("snapshot_at"), device.get("last_connected"))
            assigned = assigned and all(value and now - CURRENT_AGE <= service.stamp(value) <= now for value in stamps)
        candidate = (not basis and item["confidence"] in ("confirmed", "likely")
                     and device.get("shared_count") == 1 and not item.get("shared"))
        if assigned or candidate:
            mail_matches = set(people[employee["email"]]) if employee.get("email_verified") and employee.get("email") else set()
            login_matches = {p for login in logins.get(employee["id"], ()) for p in for_login[login]}
            matches = (login_matches & mail_matches) if login_matches and mail_matches else (login_matches or mail_matches)
            matched = next(iter(matches)) if len(matches) == 1 else None
            if asset.user_id is None and matched:
                pid, name = matched
                fields["user_id"] = {"label": FIELD_RU["user_id"], "value": name, "id": pid, "basis": "workplace"}
            dept = employee.get("department", "")
            matching_depts = departments[dept.casefold()]
            current_user_matches = asset.user_id is None or (matched and asset.user_id == matched[0])
            if current_user_matches and asset.dept_id is None and "dept_id" not in fields and len(matching_depts) == 1:
                fields["dept_id"] = {"label": FIELD_RU["dept_id"], "value": dept, "id": matching_depts[0], "basis": "workplace"}
        item["proposals"] = fields
