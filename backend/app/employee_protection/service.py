"""Публикация подготовленной сводки из локальных источников."""
from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import batched

from fastapi.encoders import jsonable_encoder
from sqlalchemy import delete, func, insert, select, text

from ..db import xact_lock
from ..models import AdAuditRun, AppSetting, EmployeeProtectionDevice, EmployeeProtectionLink, EmployeeProtectionPerson, JobLease, KscSource, ZcSource, utcnow
from ..services.jobs import JOBS
from ..services.resources import RES
from . import classify, sources

log = logging.getLogger(__name__)
KIND = "employee_protection"
STATE = "employee_protection_state"
REQUEST = "employee_protection_request"
BATCH = 500
INTERVAL = timedelta(hours=6)
CENSUS_MAX_AGE = timedelta(days=45)
PERSON_FIELDS = ("id", "name", "login", "email", "organization", "department", "division", "title", "account_created")
DEVICE_FIELDS = ("id", "source_id", "host_id", "asset_id", "name", "ip", "os", "os_version", "kind", "ownership", "zones", "av_product", "av_version", "last_connected", "snapshot_at")


def stamp(value):
    return datetime.fromisoformat(value) if isinstance(value, str) and value else value or None


async def state(db) -> dict:
    row = await db.get(AppSetting, STATE)
    return dict(row.value) if row else {}


async def request_at(db) -> str:
    row = await db.get(AppSetting, REQUEST)
    return row.value["at"] if row else ""


async def running(db) -> bool:
    lease = await db.get(JobLease, (KIND, ""))
    return bool(lease and lease.lease_until > utcnow())


async def queue(db) -> bool:
    await xact_lock(db, REQUEST)
    row = await db.get(AppSetting, REQUEST)
    if await running(db) or (row and row.value["at"] > (await state(db)).get("request", "")):
        return False
    value = {"at": utcnow().isoformat()}
    if row:
        row.value = value
    else:
        db.add(AppSetting(group=REQUEST, value=value))
    return True


async def _inputs(db):
    census = await db.scalar(select(func.max(AdAuditRun.finished_at)).where(AdAuditRun.status == "ok"))
    ids = list(await db.scalars(select(KscSource.id).where(KscSource.is_active.is_(True)).order_by(KscSource.id)))
    return ids, {"audit": census.isoformat() if census else "", "sources": [str(sid) for sid in ids]}


def _due(current: dict, request: str, signature: dict, now: datetime) -> bool:
    if not current and not signature["audit"] and not request:
        return False
    checked = stamp(current.get("checked_at"))
    return request > current.get("request", "") or signature != current.get("inputs") or not checked or checked + INTERVAL <= now


def _row(fields, row, **extra):
    return jsonable_encoder({**{k: row.get(k) for k in fields}, **extra})


def _search(row, keys) -> str:
    return " ".join(str(row.get(key) or "").lower() for key in keys)


async def _save(db, lease, values):
    await lease.fence(db)
    row = await db.get(AppSetting, STATE, with_for_update=True)
    if row:
        row.value = values
    else:
        db.add(AppSetting(group=STATE, value=values))
    await db.commit()


async def build(sm, ids, now, activity_days, bases_days, previous, common, lease) -> dict:
    generation = uuid.uuid4()
    per_person = defaultdict(list)
    async with sm() as source, sm() as target:
        if source.bind.dialect.name == "postgresql":
            await source.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
        people, meta = await sources.employees(source, now)
        if not meta.get("ready"):
            await _save(target, lease, {**previous, **common, **jsonable_encoder(meta)})
            return meta
        prepared = await source.scalar(select(func.count()).select_from(ZcSource).where(
            ZcSource.source_id.in_(ids), ZcSource.gen > 0, ZcSource.built_at >= now - timedelta(days=activity_days)))
        if not ids or prepared < len(ids):
            meta["warnings"].append(f"Актуальные подготовленные сведения о защите есть по {prepared} из {len(ids)} источников KSC.")
        await lease.stage("сопоставление оборудования и состояния защиты", str(len(people)))
        seen = set()
        known = {p["id"] for p in people}
        devices, links = [], []
        async for device, evidence in sources.devices(source, ids, people, now):
            key = device["id"]
            pairs = {pid: sorted(set(info)) for pid, info in evidence.items() if pid in known and info}
            if not pairs:
                continue
            if key in seen:
                raise ValueError("Повтор устройства в срезе защиты сотрудников")
            seen.add(key)
            status = classify.device_status(device.get("protection"), now, activity_days=activity_days, bases_days=bases_days,
                                            matched_ksc=device.get("host_id") is not None and bool(device.get("source_id")),
                                            snapshot_at=stamp(device.get("snapshot_at")))
            zones = device.get("zones") or []
            row = _row(DEVICE_FIELDS, device, **status, zones=zones, shared_count=len(pairs))
            zone_keys = "|" + "|".join(sorted({z["id"] for z in zones} or {"none"})) + "|"
            devices.append({"generation": generation, "id": key, "search": _search(row, ("name", "ip", "os", "av_product")), "zone_keys": zone_keys, "data": row})
            summary = {**status, "key": key, "last_connected": row["last_connected"]}
            for pid, info in pairs.items():
                per_person[pid].append(summary)
                links.append({"generation": generation, "person_id": pid, "device_id": key, "evidence": jsonable_encoder(info)})
            if len(devices) >= BATCH or len(links) >= BATCH:
                await _write_devices(target, devices, links)
                await lease.stage("сопоставление оборудования и состояния защиты", str(len(seen)))
                await RES.breathe("защита сотрудников")
        await _write_devices(target, devices, links)
        for group in batched(people, BATCH):
            rows = []
            for person in group:
                related = per_person.pop(person["id"], [])
                status = classify.employee_status(related)
                last_seen = max((stamp(d["last_connected"]) for d in related if d["last_connected"]), default=None)
                row = _row(PERSON_FIELDS, person, **status, last_seen=last_seen)
                rows.append({"generation": generation, "id": person["id"], "search": _search(row, ("name", "login", "email", "department", "title")), "data": row})
            await target.execute(insert(EmployeeProtectionPerson), rows)
            await RES.breathe("защита сотрудников")
        retired = {key: at for key, at in (previous.get("retired") or {}).items() if stamp(at) > now - timedelta(minutes=10)}
        if previous.get("generation"):
            retired[previous["generation"]] = now.isoformat()
        keep = [generation, *map(uuid.UUID, retired)]
        for table in (EmployeeProtectionLink, EmployeeProtectionDevice, EmployeeProtectionPerson):
            await target.execute(delete(table).where(table.generation.not_in(keep)))
        meta = {**jsonable_encoder(meta), "generation": str(generation), "built_at": now.isoformat(), "activity_days": activity_days, "retired": retired}
        await _save(target, lease, {**common, **meta})
    return meta


async def _write_devices(db, devices, links):
    if devices:
        await db.execute(insert(EmployeeProtectionDevice), devices)
        devices.clear()
    for group in batched(links, BATCH):
        await db.execute(insert(EmployeeProtectionLink), list(group))
    links.clear()


async def tick(sm, svc, journal):
    async with sm() as db:
        _, signature = await _inputs(db)
        if not _due(await state(db), await request_at(db), signature, utcnow()):
            return
    async with JOBS.run_heavy(KIND, task="защита сотрудников") as lease:
        if lease is None:
            return
        now = utcnow()
        async with sm() as db:
            ids, signature = await _inputs(db)
            previous, request = await state(db), await request_at(db)
            if not _due(previous, request, signature, now):
                return
            cfg = await svc.get(db, "general")
        common = {"inputs": signature, "request": request, "checked_at": now.isoformat()}
        try:
            result = await build(sm, ids, now, int(cfg.activity_days), 3, previous, common, lease)
        except Exception as exc:
            async with sm() as db:
                await _save(db, lease, {**previous, **common, "error": "Не удалось обновить сводку защиты сотрудников"})
            log.warning("Не удалось обновить сводку защиты сотрудников (%s)", type(exc).__name__)
            await journal.emit("employee_protection", "employee_protection_failed", level="warn", message="Не удалось обновить сводку")
        else:
            message = "Сводка защиты сотрудников обновлена" if result.get("ready") else "Сводка ожидает актуальной проверки домена"
            await journal.emit("employee_protection", "employee_protection_checked", message=message)


async def loop(sm, svc, journal):
    while True:
        try:
            await tick(sm, svc, journal)
        except Exception as exc:
            log.warning("Сводка защиты сотрудников недоступна (%s)", type(exc).__name__)
        await asyncio.sleep(60)
