"""Чтение списка «Устройства и пользователи» из подготовленных данных зон, наблюдений за пользователями и результатов EOL. KSC не затрагивается."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, case, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..eol import read as EOLR
from ..models import DeviceUser, EolFinding, EolHost, ZcHost, ZcHostZone, ZcSource
from ..netsearch import parse
from ..search import any_of, column_like

WEEK = timedelta(days=7)


def seen_week(cut: datetime):
    """Пользователь «за 7 суток»: замечен в списке вошедших за этот срок либо впервые появился в списках после начала наблюдений (не при первом опросе)."""
    return or_(DeviceUser.last_session_at >= cut, and_(DeviceUser.initial.is_(False), DeviceUser.first_seen_at >= cut))


def search_condition(text: str, sids: list[uuid.UUID]):
    """Единый поиск: имя, FQDN, адрес (число — по диапазону) или логин; несколько значений — любое подходит."""
    toks = parse(text)
    if not toks:
        return None
    conds = []
    for t in toks:
        if t.is_net:
            conds.append(and_(ZcHost.ip_num >= t.lo, ZcHost.ip_num <= t.hi))
        else:
            login = column_like(DeviceUser.login, t.text)
            conds.append(or_(any_of(t.text, ZcHost.search, ZcHost.name),
                             exists(select(1).where(DeviceUser.source_id == ZcHost.source_id, DeviceUser.host_id == ZcHost.host_id, login))))
    return or_(*conds)


async def list_devices(db: AsyncSession, sids: list[uuid.UUID], src_names: dict, *, q: str = "", zone: str = "", os_q: str = "", user_q: str = "", group_q: str = "", eol: str = "",
                       all_hosts: bool = False, show_service: bool = False, sort: str = "name", desc: bool = False, offset: int = 0, limit: int = 50, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    cut = now - WEEK
    H = ZcHost
    users_vis = [DeviceUser.kind == "user"] if not show_service else []
    eol_agg = (select(EolHost.source_id.label("sid"), EolHost.host_id.label("hid"), func.count().label("n"), func.max(case((EolFinding.status == "eol", 3), (EolFinding.status == "extended", 2), else_=1)).label("w"))
               .select_from(EolHost.__table__.join(EolFinding.__table__, and_(EolFinding.source_id == EolHost.source_id, EolFinding.kind == EolHost.kind, EolFinding.subject == EolHost.subject, EolFinding.version == EolHost.version)))
               .where(EolHost.source_id.in_(sids), EolFinding.status.in_(EOLR.PROBLEM_STATUSES)).group_by(EolHost.source_id, EolHost.host_id).subquery())
    wk = (select(DeviceUser.source_id.label("sid"), DeviceUser.host_id.label("hid"), func.count().label("n")).where(DeviceUser.source_id.in_(sids), DeviceUser.kind == "user", seen_week(cut))
          .group_by(DeviceUser.source_id, DeviceUser.host_id).subquery())
    j = (H.__table__.join(ZcSource.__table__, and_(ZcSource.source_id == H.source_id, ZcSource.gen == H.gen, ZcSource.gen > 0))
         .outerjoin(eol_agg, and_(eol_agg.c.sid == H.source_id, eol_agg.c.hid == H.host_id)).outerjoin(wk, and_(wk.c.sid == H.source_id, wk.c.hid == H.host_id)))
    if zone:
        j = j.join(ZcHostZone.__table__, and_(ZcHostZone.source_id == H.source_id, ZcHostZone.host_id == H.host_id, ZcHostZone.gen == H.gen, ZcHostZone.zone_id == zone))
    where = [H.source_id.in_(sids)]
    if not all_hosts:
        where.append(H.active.is_(True))
    s = search_condition(q, sids)
    if s is not None:
        where.append(s)
    if os_q:
        where.append(any_of(os_q, H.os))
    if user_q:
        where.append(exists(select(1).where(DeviceUser.source_id == H.source_id, DeviceUser.host_id == H.host_id, column_like(DeviceUser.login, user_q), *users_vis)))
    if eol == "any":
        where.append(eol_agg.c.n > 0)
    elif eol == "eol":
        where.append(eol_agg.c.w == 3)
    elif eol == "none":
        where.append(eol_agg.c.n.is_(None))
    order = {"name": func.lower(H.name), "ip": H.ip_num, "os": func.lower(H.os), "last_connected": H.last_connected, "eol": func.coalesce(eol_agg.c.n, 0), "users": func.coalesce(wk.c.n, 0)}.get(sort, func.lower(H.name))
    total = int((await db.execute(select(func.count()).select_from(j).where(*where))).scalar_one())
    rows = (await db.execute(select(H.source_id, H.host_id, H.name, H.os, H.ip_num, H.last_connected, H.active, H.online, H.data, func.coalesce(eol_agg.c.n, 0).label("eol_n"), eol_agg.c.w.label("eol_w"),
                                    func.coalesce(wk.c.n, 0).label("week_n")).select_from(j).where(*where)
                             .order_by((order.desc() if desc else order.asc()).nulls_last(), func.lower(H.name), H.host_id).offset(offset).limit(limit))).all()
    keys = [(r.source_id, r.host_id) for r in rows]
    users: dict[tuple, list[DeviceUser]] = {}
    if keys:
        for sid in {k[0] for k in keys}:
            ids = [k[1] for k in keys if k[0] == sid]
            for u in (await db.execute(select(DeviceUser).where(DeviceUser.source_id == sid, DeviceUser.host_id.in_(ids), *users_vis).order_by(DeviceUser.last_session_at.desc().nulls_last(), DeviceUser.login))).scalars():
                users.setdefault((sid, u.host_id), []).append(u)
    items = []
    for r in rows:
        us = users.get((r.source_id, r.host_id), [])
        d = r.data or {}
        cur = [u for u in us if u.session_now]                       # список уже без служебных записей, если они скрыты
        last = next((u for u in us if u.last_session_at and u.kind == "user"), None)
        week = [u for u in us if u.kind == "user" and seen_week_py(u, cut)]
        items.append({"source_id": str(r.source_id), "source": src_names.get(r.source_id, ""), "host_id": int(r.host_id), "name": r.name, "ip": d.get("ip", ""), "os": r.os or "", "group": d.get("group", ""),
                      "zones": d.get("zones") or [], "last_connected": r.last_connected, "active": r.active, "online": r.online, "eol": int(r.eol_n),
                      "eol_level": {3: "eol", 2: "extended", 1: "upcoming"}.get(r.eol_w or 0, ""),
                      "current": [user_out(u) for u in cur], "last_user": user_out(last) if last else None, "week": [user_out(u) for u in week], "week_n": int(r.week_n),
                      "history": [user_out(u) for u in us if u not in cur][:50]})
    return {"total": total, "items": items}


def seen_week_py(u: DeviceUser, cut: datetime) -> bool:
    ls = u.last_session_at
    fs = u.first_seen_at
    ls = ls.replace(tzinfo=timezone.utc) if ls and ls.tzinfo is None else ls
    fs = fs.replace(tzinfo=timezone.utc) if fs and fs.tzinfo is None else fs
    return bool((ls and ls >= cut) or (not u.initial and fs and fs >= cut))


def user_out(u: DeviceUser) -> dict:
    return {"login": u.login if u.resolved else "", "domain": u.domain, "resolved": u.resolved, "kind": u.kind, "now": u.session_now, "last_session_at": u.last_session_at, "first_seen_at": u.first_seen_at,
            "initial": u.initial}
