"""Общие для страницы и отчёта расчёты главной: состав источников (без повторных подключений одного KSC) и лицензии с общими пулами."""
from __future__ import annotations

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..licensing import pools as LP
from ..ksc.hosts import ip_str
from ..models import EolFinding, KscSource, LicenseOverride, LicenseRecord, LicenseState, ZcHost, ZcSource, utcnow
from ..services.sources import find_overlaps

DB_METRICS = {"crit_vuln": "Устройства с критическими уязвимостями", "eol_os": "Устройства с ОС, поддержка которой закончилась", "eol_apps": "Устройства с программами без поддержки"}


def _scope(srcs: list[KscSource]) -> tuple[list[KscSource], dict[str, str]]:
    """Источники, входящие в итоги: полный дубль другого подключения исключается (id дубля → имя исходного)."""
    skip: dict[str, str] = {}
    pos = {str(s.id): i for i, s in enumerate(srcs)}
    for sid, items in find_overlaps(srcs).items():
        for it in items:
            if it["level"] == "exact" and pos[sid] > pos[it["other_id"]]:
                skip[sid] = it["other"]
    return [s for s in srcs if str(s.id) not in skip], skip


async def licenses_block(db: AsyncSession, srcs: list[KscSource]) -> dict:
    ids = [s.id for s in srcs]
    names = {s.id: s.name for s in srcs}
    rows = (await db.execute(select(LicenseRecord).where(LicenseRecord.source_id.in_(ids)))).scalars().all()
    ov = {(str(o.source_id), o.lic_key): o.pool for o in (await db.execute(select(LicenseOverride).where(LicenseOverride.source_id.in_(ids)))).scalars()}
    states = {st.source_id: st for st in (await db.execute(select(LicenseState).where(LicenseState.source_id.in_(ids)))).scalars()}
    recs = [{"source_id": r.source_id, "source_name": names.get(r.source_id, ""), "lic_key": r.lic_key, "origin": r.origin, "product": r.product, "kind": r.kind, "expires_at": r.expires_at,
             "limit_n": r.limit_n, "used_n": r.used_n, "state": _state(r), "fp": r.fp, "note": r.note, "updated_at": r.updated_at} for r in rows]
    groups = LP.merge(recs, ov)
    tot = LP.totals(groups)
    by_src = {}
    for s in srcs:
        mine = [g for g in LP.merge([r for r in recs if r["source_id"] == s.id], ov)]
        t = LP.totals(mine)
        st = states.get(s.id)
        by_src[str(s.id)] = {"limit": t["limit"], "used": t["used"], "free": t["free"], "groups": t["groups"], "expired": t["expired"], "unknown": t["unknown"], "unknown_limit": t["unknown_limit"], "polled_at": st.polled_at if st else None, "error": st.error if st else None,
                             "note": ((st.diag or {}).get("note") if st and st.diag else None) or None}
    return {"totals": tot, "groups": groups, "by_source": by_src}


def _state(r: LicenseRecord) -> str:
    """Состояние на сегодня: срок считается заново при каждом запросе, сохранённое значение нужно только для «бессрочной» (в базе она без даты)."""
    if r.expires_at is None:
        return "perpetual" if r.state == "perpetual" else "unknown"
    now = utcnow()
    return "expired" if r.expires_at <= now else "expiring" if (r.expires_at - now).days <= 60 else "active"




async def _db_hosts(db: AsyncSession, srcs: list[KscSource], metric: str, days: int, q: str, sort: str, desc: bool, offset: int, limit: int) -> dict:
    scope, _ = _scope(srcs)
    names = {s.id: s.name for s in scope}
    gens = {sid: int(g) for sid, g in (await db.execute(select(ZcSource.source_id, ZcSource.gen).where(ZcSource.source_id.in_(list(names)), ZcSource.gen > 0))).all()}
    if not gens:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "title": DB_METRICS[metric]}
    H = ZcHost
    cond = [or_(*[and_(H.source_id == s, H.gen == g) for s, g in gens.items()]), H.days_since.is_not(None), H.days_since <= days]
    cols = (H.source_id, H.host_id, H.name, H.ip_num, H.os, H.last_connected, H.days_since, H.online, H.data)
    if metric == "crit_vuln":
        base = select(*cols).where(H.k_crit > 0)
    else:
        from ..models import EolHost  # noqa: PLC0415

        sub = (select(EolHost.source_id, EolHost.host_id).join(EolFinding, and_(EolFinding.source_id == EolHost.source_id, EolFinding.kind == EolHost.kind, EolFinding.subject == EolHost.subject,
                                                                              EolFinding.version == EolHost.version))
               .where(EolHost.kind == ("os" if metric == "eol_os" else "app"), EolFinding.status == "eol", EolHost.source_id.in_(list(names))).distinct().subquery())
        base = select(*cols).select_from(H.__table__.join(sub, and_(H.source_id == sub.c.source_id, H.host_id == sub.c.host_id)))
    cond_all = cond
    if q:
        needle = f"%{q.lower().replace('%', '').replace('_', '')}%"
        cond_all = cond + [or_(func.lower(H.name).like(needle), H.search.like(needle))]
    cnt = select(func.count()).select_from(base.where(*cond_all).order_by(None).subquery())
    total = int((await db.execute(cnt)).scalar_one())
    order = {"name": func.lower(H.name), "ip": H.ip_num, "os": func.lower(H.os), "last_connected": H.last_connected, "group": func.lower(H.name)}[sort]
    rows = (await db.execute(base.where(*cond_all).order_by(order.desc() if desc else order.asc(), H.host_id).offset(offset).limit(limit))).all()
    items = [{"host_id": r.host_id, "name": r.name, "ip": ip_str(r.ip_num), "os": r.os, "group": (r.data or {}).get("group", ""), "last_connected": r.last_connected, "days_since_connection": r.days_since,
              "online": r.online, "source_id": str(r.source_id), "source": names.get(r.source_id, "")} for r in rows]
    return {"items": items, "total": total, "offset": offset, "limit": limit, "title": DB_METRICS[metric]}


