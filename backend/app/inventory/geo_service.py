"""Пакетный сбор сетевых наблюдений в worker по устойчивой связи источник + компьютер KSC."""
from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import batched
from pathlib import Path
from tempfile import TemporaryFile

from sqlalchemy import exists, select

from ..db import xact_lock
from ..ksc import hosts, network
from ..models import AppSetting, InfraObject, InfraSource, InvAsset, InvGeo, KscSource, utcnow
from ..services.jobs import JOBS
from ..services.resources import RES
from .geography import FRESH, GeoIP, locate, rules_for, site_fields, time_of

log = logging.getLogger(__name__)
REQUEST = "inv_geo_request"
BATCH = 500
EVERY = timedelta(hours=6)
RETRY = timedelta(minutes=10)


def state_key(source_id) -> str:
    return "inv_geo_" + source_id.hex


async def request_refresh(db):
    await xact_lock(db, REQUEST)
    row = await db.get(AppSetting, REQUEST, with_for_update=True)
    value = {"at": utcnow().isoformat()}
    if row is None:
        db.add(AppSetting(group=REQUEST, value=value))
    else:
        row.value = value


def linked(source_id):
    return (InvAsset.ksc_source_id == source_id, InvAsset.ksc_host_id.is_not(None), InvAsset.ksc_link.in_(("confirmed", "auto")))


async def infra_evidence(db, ids: list[int], since: datetime) -> dict:
    q = (select(InfraObject.asset_id, InfraObject.source_id, InfraSource.name, InfraObject.attrs, InfraObject.last_seen)
         .join(InfraSource, InfraSource.id == InfraObject.source_id)
         .where(InfraObject.asset_id.in_(ids), InfraObject.present.is_(True), InfraObject.match.in_(("confirmed", "auto")),
                InfraSource.enabled.is_(True), InfraObject.last_seen >= since)
         .order_by(InfraObject.last_seen.desc()))
    out = defaultdict(list)
    for aid, sid, name, attrs, observed in (await db.execute(q)).all():
        if len(out[aid]) < 12:
            out[aid].append({"source_id": sid, "source": name, "site": str((attrs or {}).get("site") or "")[:200], "at": observed.isoformat()})
    return out


async def collect(sm, source_id, client, geo: GeoIP, lease):
    caps = await network.capabilities(client)
    groups = await hosts.groups_map(client) if "groups" in caps else {}
    checked = utcnow()
    async with sm() as db:
        rules = await rules_for(db)
        sites = await site_fields(db, rules)
    with TemporaryFile(mode="w+t", encoding="utf-8") as spool:
        cursor, n = 0, 0
        while True:
            async with sm() as db:
                page = (await db.execute(select(InvAsset.id, InvAsset.ksc_host_id, InvAsset.type_id)
                                         .where(*linked(source_id), InvAsset.id > cursor).order_by(InvAsset.id).limit(BATCH))).all()
                if not page:
                    break
                aux = await infra_evidence(db, [a for a, _, _ in page], checked - FRESH)
            cursor = page[-1][0]
            evidence = await network.read(client, [hid for _, hid, _ in page], caps, groups)
            for aid, hid, tid in page:
                item = evidence.get(hid)
                if item is None:
                    continue
                item["infra"] = aux.get(aid, [])
                observed = time_of(item)
                result = locate(item, source_id, tid, rules, geo.lookup)
                if result.get("site_id") in sites:
                    result.update(sites[result["site_id"]])
                spool.write(json.dumps([aid, hid, observed.isoformat() if observed else None, item, result], ensure_ascii=False) + "\n")
                n += 1
            await lease.stage("чтение сетевых наблюдений", str(n))
            await RES.breathe("сетевые наблюдения")
        spool.seek(0)
        async with sm() as db:
            for chunk in batched(map(json.loads, spool), BATCH):
                ids = [row[0] for row in chunk]
                live = dict((await db.execute(select(InvAsset.id, InvAsset.ksc_host_id).where(*linked(source_id), InvAsset.id.in_(ids))
                                              .order_by(InvAsset.id).with_for_update())).all())
                previous = {r.asset_id: r for r in (await db.scalars(select(InvGeo).where(InvGeo.asset_id.in_(ids)))).all()}
                for aid, hid, observed, evidence, result in chunk:
                    if live.get(aid) != hid:
                        continue
                    row = previous.get(aid)
                    if row is None:
                        row = InvGeo(asset_id=aid)
                        db.add(row)
                    row.source_id, row.host_id = source_id, hid
                    row.checked_at, row.observed_at = checked, datetime.fromisoformat(observed) if observed else None
                    row.evidence, row.result = evidence, result
                await db.flush()
                await lease.stage("публикация сетевых наблюдений")
            await lease.fence(db)
            await db.commit()
    return {"count": n, "capabilities": sorted(caps), "geoip": bool(geo.city), "asn": bool(geo.asn), "geo_errors": geo.errors}


async def status(sm, sid, data):
    async with sm() as db:
        key = state_key(sid)
        row = await db.get(AppSetting, key, with_for_update=True)
        if row is None:
            db.add(AppSetting(group=key, value=data))
        else:
            row.value = {**(row.value or {}), **data}
        await db.commit()


async def tick(sm, sources, manual: Path, managed: Path, managed_enabled: bool, journal) -> None:
    from .geo_download import database_directory

    async with sm() as db:
        targets = list((await db.scalars(select(KscSource).where(KscSource.is_active.is_(True), exists(select(InvAsset.id).where(*linked(KscSource.id)))))).all())
        keys = [REQUEST, *(state_key(s.id) for s in targets)]
        state = {r.group: r.value for r in (await db.scalars(select(AppSetting).where(AppSetting.group.in_(keys)))).all()}
    request = (state.get(REQUEST) or {}).get("at", "")
    now = utcnow()
    for src in targets:
        before = state.get(state_key(src.id)) or {}
        at = before.get("attempt_at")
        due = not at or datetime.fromisoformat(at) < now - (RETRY if before.get("error") else EVERY)
        if not due and request <= before.get("request", ""):
            continue
        try:
            async with JOBS.run_heavy("inv_geo", str(src.id), task="сетевые наблюдения инвентаризации") as lease:
                if lease is None:
                    continue
                directory = database_directory(managed, managed=True)
                if directory == managed or (not managed_enabled and any(manual.glob("GeoLite2-*.mmdb"))):
                    directory = manual
                with GeoIP(directory) as geo:
                    result = await collect(sm, src.id, sources.client(src), geo, lease)
                await status(sm, src.id, {**result, "attempt_at": utcnow().isoformat(), "finished_at": utcnow().isoformat(), "request": request, "error": ""})
                await journal.emit("inventory", "geo_done", source=src.name, message=f"Сетевых наблюдений: {result['count']}")
        except Exception as exc:  # сбой источника сохраняет его последний снимок
            name = type(exc).__name__
            await status(sm, src.id, {"attempt_at": utcnow().isoformat(), "request": request, "error": name})
            await journal.emit("inventory", "geo_failed", level="warn", source=src.name, message=f"Не удалось обновить сетевые наблюдения ({name})")


async def loop(sm, sources, settings, svc, journal) -> None:
    manual = Path(settings.data_dir) / "geoip"
    managed = Path(settings.data_dir) / "geoip-managed"
    while True:
        try:
            async with sm() as db:
                cfg = await svc.get(db, "geoip")
            await tick(sm, sources, manual, managed, cfg.enabled, journal)
        except Exception:
            log.exception("Не удалось запустить обновление сетевых наблюдений")
        await asyncio.sleep(60)
