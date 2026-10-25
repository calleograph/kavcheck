"""Зоны ответственности в базе KAV Checker: чтение, индекс принадлежности, атомарное применение импорта CSV."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import MailOutbox, ReportSchedule, VulnTriage, Zone, ZoneContact, ZonePin, ZoneRule
from . import csv_io
from .match import ZoneDef, ZoneIndex, normalize_rule

UNASSIGNED = "none"
UNASSIGNED_TITLE = "Без ответственного"


async def load_defs(db: AsyncSession) -> list[ZoneDef]:
    zones = (await db.execute(select(Zone).order_by(Zone.priority, Zone.name))).scalars().all()
    rules: dict[uuid.UUID, list[tuple[str, str]]] = {}
    for r in (await db.execute(select(ZoneRule).order_by(ZoneRule.position))).scalars():
        rules.setdefault(r.zone_id, []).append((r.kind, r.value))
    return [ZoneDef(str(z.id), z.name, z.priority, rules.get(z.id, []), z.enabled) for z in zones]


async def load_pins(db: AsyncSession) -> dict[tuple[str, int], str]:
    return {(str(p.source_id), int(p.host_id)): str(p.zone_id) for p in (await db.execute(select(ZonePin))).scalars()}


async def index(db: AsyncSession) -> ZoneIndex:
    return ZoneIndex(await load_defs(db), await load_pins(db))


async def existing(db: AsyncSession) -> list[csv_io.Existing]:
    zones = (await db.execute(select(Zone).order_by(Zone.name))).scalars().all()
    rules: dict[uuid.UUID, list] = {}
    for r in (await db.execute(select(ZoneRule).order_by(ZoneRule.position))).scalars():
        rules.setdefault(r.zone_id, []).append((r.kind, r.value))
    cons: dict[uuid.UUID, list] = {}
    for c in (await db.execute(select(ZoneContact).order_by(ZoneContact.created_at))).scalars():
        cons.setdefault(c.zone_id, []).append({"email": c.email, "name": c.name, "position": c.position, "role": c.role, "enabled": c.enabled})
    return [csv_io.Existing(str(z.id), z.name, z.description, z.purpose, z.priority, rules.get(z.id, []), cons.get(z.id, [])) for z in zones]


async def apply_plan(db: AsyncSession, plan: csv_io.Plan, actor: str) -> dict:
    """Применяет план одной транзакцией (вызывающий коммитит; при исключении откат полный). Возвращает счётчики сделанного."""
    if not plan.ok:
        raise ValueError("план содержит ошибки")
    now = datetime.now(timezone.utc)
    done = {"created": 0, "updated": 0, "deleted": 0, "rules_added": 0, "rules_removed": 0, "contacts_added": 0, "contacts_updated": 0, "contacts_removed": 0}
    in_file = set()
    for key, d in plan.desired.items():
        ex = d["existing"]
        if ex is None:
            z = Zone(id=uuid.uuid4(), name=d["name"], description=d["description"] or "", purpose=d["purpose"] or "", priority=d["priority"] or 100, updated_by=actor, created_at=now, updated_at=now)
            db.add(z)
            await db.flush()
            for i, (k, v) in enumerate(d["rules"]):
                db.add(ZoneRule(zone_id=z.id, kind=k, value=v, note=d.get("rule_notes", {}).get((k, v), ""), position=i))
            for c in d["contacts"].values():
                db.add(ZoneContact(zone_id=z.id, name=c["name"], position=c["position"], email=c["email"], role=c["role"], enabled=c["enabled"], created_at=now))
            done["created"] += 1
            done["rules_added"] += len(d["rules"])
            done["contacts_added"] += len(d["contacts"])
            continue
        in_file.add(ex.id)
        if plan.mode == "add_only":
            continue
        z = await db.get(Zone, uuid.UUID(ex.id))
        changed = False
        for fld in ("description", "purpose", "priority"):
            if d[fld] is not None and d[fld] != getattr(z, fld):
                setattr(z, fld, d[fld])
                changed = True
        if d["name"] != z.name:
            z.name = d["name"]
            changed = True
        zr = (await db.execute(select(ZoneRule).where(ZoneRule.zone_id == z.id).order_by(ZoneRule.position))).scalars().all()
        have = {(r.kind, r.value): r for r in zr}
        want = set(d["rules"])
        if plan.mode == "replace":
            for kv, r in have.items():
                if kv not in want:
                    await db.delete(r)
                    done["rules_removed"] += 1
                    changed = True
        pos = max([r.position for r in zr], default=-1) + 1
        for kv in d["rules"]:
            if kv not in have:
                db.add(ZoneRule(zone_id=z.id, kind=kv[0], value=kv[1], note=d.get("rule_notes", {}).get(kv, ""), position=pos))
                pos += 1
                done["rules_added"] += 1
                changed = True
        zc = {c.email.lower(): c for c in (await db.execute(select(ZoneContact).where(ZoneContact.zone_id == z.id))).scalars()}
        for em, c in d["contacts"].items():
            old = zc.get(em)
            if old is None:
                db.add(ZoneContact(zone_id=z.id, name=c["name"], position=c["position"], email=em, role=c["role"], enabled=c["enabled"], created_at=now))
                done["contacts_added"] += 1
                changed = True
            else:
                upd = False
                for k in ("name", "position", "role", "enabled"):
                    if c[k] not in ("", None) and c[k] != getattr(old, k):
                        setattr(old, k, c[k])
                        upd = True
                if upd:
                    done["contacts_updated"] += 1
                    changed = True
        if plan.mode == "replace":
            for em, old in zc.items():
                if em not in d["contacts"]:
                    await db.delete(old)
                    done["contacts_removed"] += 1
                    changed = True
        if changed:
            z.updated_at, z.updated_by = now, actor
            done["updated"] += 1
    if plan.mode == "replace":
        for z in plan.zones:
            if z["action"] == "delete":
                await delete_zone(db, uuid.UUID(z["id"]))
                done["deleted"] += 1
    await db.flush()
    return done


def check_rules(rules: list[dict]) -> list[tuple[str, str, str]]:
    """Список признаков из формы → [(вид, значение, комментарий)] с проверкой; ошибка — ValueError с номером признака."""
    out, seen = [], set()
    for i, r in enumerate(rules, 1):
        try:
            k, v = normalize_rule(r.get("kind", "net"), r.get("value", ""))
        except ValueError as e:
            raise ValueError(f"Признак {i}: {e}") from None
        if (k, v) not in seen:
            seen.add((k, v))
            out.append((k, v, (r.get("note") or "")[:200]))
    return out


async def delete_zone(db: AsyncSession, zid: uuid.UUID) -> None:
    """Удаляет зону со всем, что на неё ссылается (не полагаясь на каскады БД): признаки, получатели, закрепления, решения по зоне; историю рассылок сохраняет.
    Расписание, в котором осталась только эта зона, отключается: пустой список означал бы «все зоны»."""
    for model in (ZoneRule, ZoneContact, ZonePin, VulnTriage):
        await db.execute(delete(model).where(model.zone_id == zid))
    await db.execute(update(MailOutbox).where(MailOutbox.zone_id == zid).values(zone_id=None))
    for sch in (await db.execute(select(ReportSchedule))).scalars():
        ids = [str(i) for i in sch.zone_ids or []]
        if str(zid) in ids:
            sch.zone_ids = [i for i in ids if i != str(zid)]
            if not sch.zone_ids:
                sch.enabled, sch.next_run_at = False, None
    await db.execute(delete(Zone).where(Zone.id == zid))
