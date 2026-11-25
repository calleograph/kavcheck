"""Заполнение пустых полей по включённым администратором источникам."""
from __future__ import annotations

import asyncio
import logging
from collections import Counter
from datetime import timedelta

from sqlalchemy import exists, or_, select

from ..db import xact_lock
from ..employee_protection import read, service
from ..employee_protection.filters import Filters
from ..models import AppSetting, InvAsset, InvDoc, InvDocItem, JobLease, KscSource, utcnow
from ..services.audit import write_audit
from ..services.jobs import JOBS
from ..services.resources import RES
from ..services.settings import INV_PERMS
from . import core as C, geography as G, model as M

KIND = "inv_auto_fill"
STATE = "inv_auto_fill_state"
REQUEST = "inv_auto_fill_request"
INTERVAL = timedelta(minutes=15)
BATCH = 100
ACTOR = "KAV Checker (автозаполнение)"
log = logging.getLogger(__name__)


async def _info(db, svc):
    cfg = await svc.get(db, "inventory")
    previous = await db.get(AppSetting, STATE)
    requested = await db.get(AppSetting, REQUEST)
    last = dict(previous.value) if previous else {}
    request = requested.value["at"] if requested else ""
    return sorted(set(cfg.auto_fill_fields)), last, request


def _due(fields, last, request, now) -> bool:
    last_at = service.stamp(last.get("last_at"))
    return bool(fields and (fields != last.get("fields") or request > last.get("request", "")
                            or not last_at or last_at + INTERVAL <= now))


async def info(db, svc) -> dict:
    fields, last, request = await _info(db, svc)
    now = utcnow()
    lease = await db.get(JobLease, (KIND, ""))
    running = bool(lease and lease.lease_until > now)
    return {**last, "fields": fields, "running": running, "pending": not running and _due(fields, last, request, now)}


async def queue(db, svc) -> bool:
    await xact_lock(db, REQUEST)
    current = await info(db, svc)
    if not current["fields"] or current["pending"] or current["running"]:
        return False
    row = await db.get(AppSetting, REQUEST)
    value = {"at": utcnow().isoformat()}
    if row:
        row.value = value
    else:
        db.add(AppSetting(group=REQUEST, value=value))
    return True


async def _workplaces(db, assets):
    current = await service.state(db)
    if (current.get("error") or current.get("inputs", {}).get("policy") != service.POLICY_VERSION
            or await service.request_at(db) > current.get("request", "")):
        return {}
    generation, meta = await read.snapshot(db, current=current)
    built_at = service.stamp(meta.get("built_at"))
    if not generation or not built_at or not G.fresh(built_at, utcnow()):
        return {}
    ids = {a.id: (str(a.ksc_source_id), a.ksc_host_id) for a in assets}
    selection = read.Selection(generation, Filters(), workplaces=True, asset_ids=ids)
    out = {}
    for row in await read.workplace_rows(db, selection, 0, len(ids), include_network=False):
        d = row["device"]
        if ids[d["asset_id"]] == (d.get("source_id"), d.get("host_id")):
            out[d["asset_id"]] = {key: value["id"] for key, value in row.get("proposals", {}).items() if value["basis"] == "workplace"}
    return out


async def fill(sm, svc, lease, fields, totals, by_field):
    cursor = 0
    allowed = set(fields)
    access = C.Access(frozenset(INV_PERMS))
    open_doc = (select(1).select_from(InvDocItem).join(InvDoc, InvDoc.id == InvDocItem.doc_id)
                .where(InvDocItem.asset_id == InvAsset.id, InvDoc.status.not_in(("done", "cancelled"))))
    stmt = (select(InvAsset).where(InvAsset.st_cls.in_(M.ST_ACTIVE), InvAsset.ksc_link == "confirmed",
                                  InvAsset.ksc_source_id.in_(select(KscSource.id).where(KscSource.is_active.is_(True))),
                                  InvAsset.ksc_host_id.is_not(None), InvAsset.transit_doc_id.is_(None), ~exists(open_doc),
                                  or_(*(getattr(InvAsset, key).is_(None) for key in fields)))
            .order_by(InvAsset.id).limit(BATCH).with_for_update())
    while True:
        batch_totals, batch_fields = Counter(), Counter()
        async with sm() as db:
            await xact_lock(db, "inventory")
            active, _, _ = await _info(db, svc)
            if active != fields:
                return
            await xact_lock(db, "employee_workplace_decisions")
            assets = list(await db.scalars(stmt.where(InvAsset.id > cursor)))
            if not assets:
                return
            cursor = assets[-1].id
            now = utcnow()
            people = await _workplaces(db, assets) if allowed & {"user_id", "dept_id"} else {}
            placement = await G.placement_proposals(db, {a.id: a for a in assets}, now, allowed)
            names = await C.names_for(db, assets)
            for asset in assets:
                batch_totals["checked"] += 1
                data = dict(people.get(asset.id, {}))
                if asset.st_cls != "use":
                    data.pop("user_id", None)
                data.update({field: value for field, (value, _basis) in placement.get(asset.id, {}).items()})
                patch = {k: v for k, v in data.items() if k in allowed and getattr(asset, k) is None}
                if not patch:
                    continue
                try:
                    changes = await C.apply_changes(db, asset, patch, access, names=names, infer_manufacturer=False)
                except C.Invalid:
                    batch_totals["invalid"] += 1
                    continue
                if changes:
                    await C.record(db, asset, C.kind_of(changes), changes, ACTOR, basis="Действующее правило или закреплённое рабочее место", names=names)
                    write_audit(db, actor_user_id=None, actor=ACTOR, action="inv.auto_fill", target_type="inventory", target_id=str(asset.id),
                                details={"fields": [c["f"] for c in changes]})
                    batch_totals["changed"] += 1
                    batch_fields.update(c["f"] for c in changes)
            await lease.fence(db)
            await db.commit()
        totals.update(batch_totals)
        by_field.update(batch_fields)
        await lease.stage("заполнение пустых полей", str(totals["checked"]))
        await RES.breathe("автозаполнение карточек")


async def tick(sm, svc, journal):
    async with sm() as db:
        fields, last, request = await _info(db, svc)
        if not _due(fields, last, request, utcnow()):
            return
    async with JOBS.run_heavy(KIND, task="автозаполнение карточек") as lease:
        if lease is None:
            return
        async with sm() as db:
            fields, last, request = await _info(db, svc)
            if not _due(fields, last, request, utcnow()):
                return
        totals, by_field = Counter(), Counter()
        error = ""
        try:
            await fill(sm, svc, lease, fields, totals, by_field)
        except Exception as exc:
            error = f"Проход автозаполнения прерван ({type(exc).__name__})"
        async with sm() as db:
            await lease.fence(db)
            row = await db.get(AppSetting, STATE)
            value = {"last_at": utcnow().isoformat(), "request": request, "fields": fields, "checked": totals["checked"],
                     "changed": totals["changed"], "skipped": totals["checked"] - totals["changed"], "by_field": dict(by_field),
                     "error": error or (f"Проверку полей не прошли {totals['invalid']} карточек" if totals["invalid"] else "")}
            if row:
                row.value = value
            else:
                db.add(AppSetting(group=STATE, value=value))
            if by_field:
                await service.request_refresh(db)
            await db.commit()
        await journal.emit("inventory", KIND, level="warn" if value["error"] else "info",
                           message=value["error"] or f"Обновлено карточек: {value['changed']}")


async def loop(sm, svc, journal):
    while True:
        try:
            await tick(sm, svc, journal)
        except Exception:
            log.exception("Не удалось выполнить автозаполнение инвентаризации")
        await asyncio.sleep(30)
