"""Публикация подготовленной сводки из локальных источников."""
from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import batched

from fastapi.encoders import jsonable_encoder
from sqlalchemy import delete, func, insert, or_, select, text, tuple_

from ..db import xact_lock
from ..inventory.model import COMPUTERS, ST_ACTIVE
from ..models import (AdAuditRun, AppSetting, DevicesState, EmployeeProtectionDevice, EmployeeProtectionLink,
                      EmployeeProtectionPerson, EmployeeWorkplaceDecision, InvAsset, JobLease, KscSource, ZcSource, utcnow)
from ..services.jobs import JOBS
from ..services.resources import RES
from . import classify, sources
from .workplace import SERVER

log = logging.getLogger(__name__)
KIND = "employee_protection"
STATE = "employee_protection_state"
REQUEST = "employee_protection_request"
POLICY_VERSION = 3
BATCH = 500
INTERVAL = timedelta(hours=6)
CENSUS_MAX_AGE = timedelta(days=45)
PERSON_FIELDS = ("id", "name", "login", "email", "organization", "department", "division", "title", "account_created")
DEVICE_FIELDS = ("id", "source_id", "host_id", "asset_id", "name", "ip", "os", "os_version", "kind", "ownership", "zones", "av_product", "av_version", "last_connected", "snapshot_at", "shared_reason")


def stamp(value):
    return datetime.fromisoformat(value) if isinstance(value, str) and value else value or None


async def state(db, *, lock=False) -> dict:
    row = await db.get(AppSetting, STATE, with_for_update=lock)
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
    _request(db, row)
    return True


async def request_refresh(db):
    await xact_lock(db, REQUEST)
    _request(db, await db.get(AppSetting, REQUEST))


def _request(db, row):
    value = {"at": utcnow().isoformat()}
    if row:
        row.value = value
    else:
        db.add(AppSetting(group=REQUEST, value=value))


async def _inputs(db):
    census = await db.scalar(select(func.max(AdAuditRun.finished_at)).where(AdAuditRun.status == "ok"))
    rows = (await db.execute(select(KscSource.id, DevicesState.polled_at, ZcSource.built_at)
                            .outerjoin(DevicesState, DevicesState.source_id == KscSource.id)
                            .outerjoin(ZcSource, ZcSource.source_id == KscSource.id)
                            .where(KscSource.is_active.is_(True)).order_by(KscSource.id))).all()
    # Новый опрос или срез запускает расчёт максимум один раз в час.
    hours = lambda dt: dt.replace(minute=0, second=0, microsecond=0).isoformat() if dt else ""
    return [sid for sid, _, _ in rows], {"audit": census.isoformat() if census else "", "policy": POLICY_VERSION,
                                        "sources": [[str(sid), hours(poll), hours(built)] for sid, poll, built in rows]}


def _due(current: dict, request: str, signature: dict, now: datetime) -> bool:
    if not current and not signature["audit"] and not request:
        return False
    checked = stamp(current.get("checked_at"))
    interval = timedelta(minutes=5) if current.get("error") else INTERVAL
    return request > current.get("request", "") or signature != current.get("inputs") or not checked or checked + interval <= now


async def device_aliases(db, device_ids):
    """Решение по карточке применимо к компьютеру после подтверждения её связи с KSC."""
    assets, hosts = set(), set()
    for key in device_ids:
        parts = key.split(":")
        try:
            if len(parts) == 2 and parts[0] == "inv" and 0 < int(parts[1]) < 2**63:
                assets.add(int(parts[1]))
            elif len(parts) == 3 and parts[0] == "ksc" and 0 < int(parts[2]) < 2**63:
                hosts.add((uuid.UUID(parts[1]), int(parts[2])))
        except ValueError:
            continue
    aliases = {}
    if assets or hosts:
        query = (select(InvAsset.id, InvAsset.ksc_source_id, InvAsset.ksc_host_id)
                 .join(KscSource, KscSource.id == InvAsset.ksc_source_id)
                 .where(InvAsset.ksc_link == "confirmed", InvAsset.cls.in_(COMPUTERS), InvAsset.st_cls.in_(ST_ACTIVE),
                        KscSource.is_active.is_(True), InvAsset.ksc_host_id.is_not(None),
                        or_(InvAsset.id.in_(assets), tuple_(InvAsset.ksc_source_id, InvAsset.ksc_host_id).in_(hosts))))
        for aid, sid, hid in await db.execute(query):
            aliases[f"inv:{aid}"] = f"ksc:{sid}:{hid}"
    return aliases


def _row(fields, row, **extra):
    return jsonable_encoder({**{k: row.get(k) for k in fields}, **extra})


def _search(row, keys) -> str:
    return " ".join(str(row.get(key) or "").lower() for key in keys)


def _finalize_diagnostics(diagnostics):
    for diagnostic in diagnostics.values():
        if diagnostic["status"] != "ready":
            continue
        if diagnostic["eligible"] and not diagnostic["av_known"]:
            diagnostic.update(status="av_missing", reason="Устройства сопоставлены. Достоверных сведений о защите пока нет.")
        elif not diagnostic["eligible"]:
            if diagnostic["possible"]:
                diagnostic.update(status="review", reason="Есть возможные связи. Для автоматической оценки защиты пока недостаточно оснований.")
            elif diagnostic["observed"]:
                diagnostic.update(status="unmatched", reason="Наблюдения пользователей есть. Подходящих связей с записями AD нет.")
            else:
                diagnostic.update(status="no_observations", reason="На подготовленных компьютерах нет распознанных наблюдений пользователей.")
    return list(diagnostics.values())


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
    pending = defaultdict(int)
    primary = defaultdict(list)
    async with sm() as source, sm() as target:
        if source.bind.dialect.name == "postgresql":
            await source.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
        people, meta = await sources.employees(source, now)
        meta["source_diagnostics"] = []
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
        decisions = defaultdict(dict)
        stored = [row async for row in await source.stream_scalars(select(EmployeeWorkplaceDecision).order_by(
            EmployeeWorkplaceDecision.decided_at, EmployeeWorkplaceDecision.device_id)) if row.person_id in known]
        aliases = {}
        for group in batched({row.device_id for row in stored if row.device_id.startswith("inv:")}, BATCH):
            aliases.update(await device_aliases(source, group))
        for row in stored:
            decisions[aliases.get(row.device_id, row.device_id)][row.person_id] = row
        diagnostics = {}
        devices, links = [], []
        async for device, evidence in sources.devices(source, ids, people, now, manual=decisions,
                                                     diagnostics=diagnostics, activity_days=activity_days):
            key = device["id"]
            pairs = {pid: dict(info) for pid, info in evidence.items() if pid in known and info}
            for pid, decision in decisions.get(key, {}).items():
                info = pairs.setdefault(pid, {"evidence": []})
                info.update(confidence=decision.decision, decision=decision.decision, decided_at=decision.decided_at)
                message = "Подтверждено администратором" if decision.decision == "confirmed" else "Отклонено администратором"
                info["evidence"] = [message, *info["evidence"]]
            if not pairs:
                continue
            if key in seen:
                raise ValueError("Повтор устройства в срезе защиты сотрудников")
            seen.add(key)
            status = classify.device_status(device.get("protection"), now, activity_days=activity_days, bases_days=bases_days,
                                            matched_ksc=device.get("host_id") is not None and bool(device.get("source_id")),
                                            snapshot_at=stamp(device.get("snapshot_at")))
            zones = device.get("zones") or []
            row = _row(DEVICE_FIELDS, device, **status, zones=zones,
                       shared_count=sum(info["confidence"] != "rejected" for info in pairs.values()))
            zone_keys = "|" + "|".join(sorted({z["id"] for z in zones} or {"none"})) + "|"
            devices.append({"generation": generation, "id": key, "search": _search(row, ("name", "ip", "os", "av_product")), "zone_keys": zone_keys, "data": row})
            summary = {**status, "key": key, "last_connected": row["last_connected"]}
            counted_host, review_host = False, False
            for pid, info in pairs.items():
                evidence = list(dict.fromkeys(info.pop("evidence")))
                counted = info["confidence"] == "confirmed" or (info["confidence"] == "likely" and device.get("shared_reason") != SERVER)
                if counted:
                    counted_host = True
                    per_person[pid].append(summary)
                    if not info.get("shared") and not device.get("shared_reason") and row["shared_count"] == 1:
                        if info.get("decision") == "confirmed":
                            primary[pid].append(((1, 0), key))
                        elif info.get("regular"):
                            primary[pid].append(((0, info["observed_days"]), key))
                elif info["confidence"] != "rejected":
                    review_host = True
                    pending[pid] += 1
                links.append({"generation": generation, "person_id": pid, "device_id": key,
                              "evidence": evidence, "assessment": jsonable_encoder({**info, "counted": counted})})
            diagnostic = diagnostics.get(device.get("source_id"))
            if diagnostic is not None and device.get("protection") is not None:
                diagnostic["matched"] += int(counted_host or review_host)
                diagnostic["eligible"] += int(counted_host)
                diagnostic["possible"] += int(review_host and not counted_host)
                diagnostic["av_known"] += int(counted_host and status["status"] in ("protected", "problems", "no_av"))
            if len(devices) >= BATCH or len(links) >= BATCH:
                await _write_devices(target, devices, links)
                await lease.stage("сопоставление оборудования и состояния защиты", str(len(seen)))
                await RES.breathe("защита сотрудников")
        await _write_devices(target, devices, links)
        meta["source_diagnostics"] = _finalize_diagnostics(diagnostics)
        for group in batched(people, BATCH):
            rows = []
            for person in group:
                related = per_person.pop(person["id"], [])
                status = classify.employee_status(related)
                candidates = pending.pop(person["id"], 0)
                if candidates and not related:
                    status["reason"] = "workplace_review"
                last_seen = max((stamp(d["last_connected"]) for d in related if d["last_connected"]), default=None)
                ranked = sorted(primary.pop(person["id"], []), reverse=True)
                main_device = ranked[0][1] if ranked and (len(ranked) == 1 or ranked[0][0] > ranked[1][0]) else None
                row = _row(PERSON_FIELDS, person, **status, last_seen=last_seen, pending_device_count=candidates,
                           primary_device_id=main_device, email_verified=person.get("email") in person.get("_emails", ()))
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
