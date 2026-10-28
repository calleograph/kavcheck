"""Результаты CVE Hunt: объединение данных KSC и сети, связь с устройствами KSC, список с серверной пагинацией, сравнение повторных проверок."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ksc import versions as V
from ..models import HuntHit, PtHost, PtJob, utcnow
from ..search import any_of
from . import enrich as E

RANK = {"confirmed": 0, "probable": 1, "needs_check": 2, "failed": 3}
STATUS_RU = {"confirmed": "Подтверждено", "probable": "Вероятно", "needs_check": "Требует проверки", "failed": "Не удалось проверить"}
BASIS_RU = {"ksc": "KSC", "network": "Сеть", "both": "KSC и сеть"}
KEEP = ("confirmed", "probable", "needs_check")


def ev(kind: str, text: str, at: datetime | None = None) -> dict:
    return {"kind": kind, "text": text[:600], "at": (at or utcnow()).isoformat(timespec="seconds")}


async def finalize(db: AsyncSession, job_id: uuid.UUID, logic: str = "any", n_crit: int = 1) -> dict:
    """После сетевого этапа: связать сетевые находки с устройствами KSC, добавить зону и пользователя, объединить с данными KSC (одна строка на компьютер и критерий)."""
    rows = list((await db.execute(select(HuntHit).where(HuntHit.job_id == job_id))).scalars())
    net = [r for r in rows if r.basis == "network"]
    ksc = [r for r in rows if r.basis == "ksc"]
    cands = await E.by_ip(db, sorted({r.ip for r in net if r.ip}))
    for r in net:
        c = cands.get(r.ip) or []
        if len(c) == 1:
            d = c[0]
            r.source_id, r.host_id, r.host_name, r.os, r.last_connected, r.group_name = d["source_id"], d["host_id"], d["name"], d["os"], d["last_connected"], d["group"]
        elif len(c) > 1:
            r.ambiguous = True
            r.evidence = [*r.evidence, ev("ksc", f"Адрес совпал с несколькими устройствами KSC ({len(c)}): " + "; ".join(f"{x['name']} ({x['source']})" for x in c[:5]) + ". Устройства разных источников не объединяются.")]
    ksc_by = {(r.crit_key, r.ip): r for r in ksc if r.ip}
    merged = 0
    for r in net:
        k = ksc_by.get((r.crit_key, r.ip))
        if k is None:
            continue
        r.basis = "both"
        r.evidence = [*r.evidence, *k.evidence]
        r.diff = bool(k.version and r.version and V.compare(V.upstream(k.version), V.upstream(r.version)) != 0)
        if r.diff:
            r.evidence = [*r.evidence, ev("diff", f"Версии различаются: KSC — {k.version}, сеть — {r.version}")]
        if RANK[k.status] < RANK[r.status] and r.status == "needs_check":
            r.status = k.status
        r.source_id, r.host_id = r.source_id or k.source_id, r.host_id or k.host_id
        r.data_at = k.data_at
        await db.delete(k)
        merged += 1
    left = [r for r in [*net, *[k for k in ksc if not (k.crit_key, k.ip) in {(n.crit_key, n.ip) for n in net}]] if r.source_id and r.host_id]
    det = await E.details(db, sorted({(r.source_id, r.host_id) for r in left}))
    for r in left:
        d = det.get((r.source_id, r.host_id))
        if d:
            r.zone, r.user_name, r.user_kind = d["zone"], d["user"], d["user_kind"]
    for r in [*net, *ksc]:
        r.zone = r.zone or E.NO_ZONE
        r.user_name = r.user_name or E.NO_USER
    await db.flush()
    if logic == "all" and n_crit > 1:                              # «все критерии»: компьютер остаётся, только если совпал с каждым выбранным критерием
        alive = [r for r in [*net, *ksc] if r in db and r.status != "failed"]
        keys: dict[str, set] = {}
        for r in alive:
            keys.setdefault(r.ip or f"{r.source_id}:{r.host_id}", set()).add(r.crit_key)
        for r in alive:
            if len(keys[r.ip or f"{r.source_id}:{r.host_id}"]) < n_crit:
                await db.delete(r)
        await db.flush()
    return {"merged": merged}


def _filters(job_id: uuid.UUID, status: str, q: str, basis: str, crit: str, zone: str):
    w = [HuntHit.job_id == job_id]
    if status:
        w.append(HuntHit.status.in_([s for s in status.split(",") if s in RANK]))
    if basis:
        w.append(HuntHit.basis.in_([b for b in basis.split(",") if b in BASIS_RU]))
    if crit:
        w.append(HuntHit.crit_key == crit)
    if zone:
        w.append(HuntHit.zone == zone)
    if q:
        cond = any_of(q, HuntHit.host_name, HuntHit.ip, HuntHit.user_name, HuntHit.zone, HuntHit.product, HuntHit.version, HuntHit.vuln_key)
        if cond is not None:
            w.append(cond)
    return w


SORTS = {"status": None, "host": HuntHit.host_name, "ip": HuntHit.ip, "user": HuntHit.user_name, "zone": HuntHit.zone, "product": HuntHit.product, "version": HuntHit.version}


def hit_out(h: HuntHit, full: bool = False) -> dict:
    o = {"id": h.id, "crit_key": h.crit_key, "vuln_key": h.vuln_key, "ip": h.ip, "port": h.port, "host_name": h.host_name or "", "os": h.os, "user": h.user_name, "user_kind": h.user_kind, "zone": h.zone, "product": h.product,
         "version": h.version, "status": h.status, "status_ru": STATUS_RU.get(h.status, h.status), "basis": h.basis, "basis_ru": BASIS_RU.get(h.basis, h.basis), "source_id": str(h.source_id) if h.source_id else None, "host_id": h.host_id,
         "data_at": h.data_at, "last_connected": h.last_connected, "ambiguous": h.ambiguous, "diff": h.diff, "group": h.group_name, "evidence_short": (h.evidence[0]["text"] if h.evidence else "")[:160]}
    if full:
        o["evidence"] = h.evidence
    return o


async def page(db: AsyncSession, job_id: uuid.UUID, *, status: str = "", q: str = "", basis: str = "", crit: str = "", zone: str = "", sort: str = "status", desc: bool = False, offset: int = 0, limit: int = 50) -> dict:
    w = _filters(job_id, status, q, basis, crit, zone)
    total = int((await db.execute(select(func.count()).select_from(HuntHit).where(*w))).scalar_one())
    from sqlalchemy import case  # noqa: PLC0415

    rank = case(*[(HuntHit.status == k, v) for k, v in RANK.items()], else_=9)
    col = SORTS.get(sort)
    order = [rank.desc() if desc else rank, func.lower(HuntHit.host_name), HuntHit.ip, HuntHit.id] if col is None else [func.lower(col).desc() if desc else func.lower(col), rank, HuntHit.id]
    rows = (await db.execute(select(HuntHit).where(*w).order_by(*order).offset(offset).limit(limit))).scalars().all()
    by = {k: n for k, n in (await db.execute(select(HuntHit.status, func.count()).where(HuntHit.job_id == job_id).group_by(HuntHit.status))).all()}
    return {"items": [hit_out(h) for h in rows], "total": total, "offset": offset, "limit": limit, "counts": {k: by.get(k, 0) for k in RANK}}


async def zones_of(db: AsyncSession, job_id: uuid.UUID) -> list[str]:
    return [z for z in (await db.execute(select(HuntHit.zone).where(HuntHit.job_id == job_id).distinct().order_by(HuntHit.zone))).scalars() if z]


def _key(h: HuntHit) -> tuple:
    return (h.crit_key, h.ip or f"{h.source_id}:{h.host_id}")


async def compare(db: AsyncSession, job: PtJob) -> dict | None:
    """Сравнение с прежней проверкой: новые, сохранившиеся, больше не соответствующие, не удалось перепроверить. Недоступность компьютера не объявляет проблему исправленной."""
    if not job.base_job_id:
        return None
    base = {_key(h): h for h in (await db.execute(select(HuntHit).where(HuntHit.job_id == job.base_job_id, HuntHit.status.in_(KEEP)))).scalars()}
    cur = {_key(h): h for h in (await db.execute(select(HuntHit).where(HuntHit.job_id == job.id, HuntHit.status.in_(KEEP)))).scalars()}
    states = {ip: st for ip, st in (await db.execute(select(PtHost.ip, PtHost.state).where(PtHost.job_id == job.id))).all()}
    mode = (job.options or {}).get("hunt", {}).get("mode", "combined")
    new, kept, gone, unknown = [], [], [], []
    for k, h in cur.items():
        (kept if k in base else new).append(hit_out(h))
    for k, h in base.items():
        if k in cur:
            continue
        rechecked = (h.ip and states.get(h.ip) == "done") or (h.basis == "ksc" and mode in ("ksc", "combined") and not h.ip)
        (gone if rechecked else unknown).append(hit_out(h))
    return {"base_job_id": str(job.base_job_id), "new": new[:500], "kept": kept[:500], "gone": gone[:500], "unknown": unknown[:500], "counts": {"new": len(new), "kept": len(kept), "gone": len(gone), "unknown": len(unknown)},
            "note": "«Больше не соответствуют» — только компьютеры, которые повторная проверка достоверно просмотрела. Недоступные и не проверенные не считаются исправленными."}
