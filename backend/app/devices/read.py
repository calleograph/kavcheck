"""Чтение списка «Устройства и пользователи» из подготовленных данных зон, наблюдений за пользователями и результатов EOL. KSC не затрагивается."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, exists, func, or_, select, tuple_, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import DeviceUser, EolHostStat, ZcHost, ZcHostZone, ZcSource
from ..netsearch import parse
from ..search import any_of, column_like, local_like

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
            p = local_like(t.text)                          # `search` хранится строчными (имя, FQDN, адрес): без lower() работает триграммный индекс
            by_login = tuple_(ZcHost.source_id, ZcHost.host_id).in_(select(DeviceUser.source_id, DeviceUser.host_id).where(DeviceUser.source_id.in_(sids), func.lower(DeviceUser.login).like(p, escape="\\")))
            conds.append(or_(func.lower(ZcHost.name).like(p, escape="\\"), ZcHost.search.like(p, escape="\\"), by_login))
    return or_(*conds)


async def list_devices(db: AsyncSession, sids: list[uuid.UUID], src_names: dict, *, q: str = "", zone: str = "", os_q: str = "", user_q: str = "", group_q: str = "", eol: str = "",
                       all_hosts: bool = False, show_service: bool = False, sort: str = "name", desc: bool = False, offset: int = 0, limit: int = 50, now: datetime | None = None) -> dict:
    """Страница устройств. Отбор и сортировка — по подготовленным данным зон (индексы PostgreSQL); итоги EOL и пользователи читаются только для устройств страницы, а не агрегируются по всему источнику."""
    now = now or datetime.now(timezone.utc)
    cut = now - WEEK
    H, S = ZcHost, EolHostStat
    users_vis = [DeviceUser.kind == "user"] if not show_service else []
    gens = {sid: int(gen) for sid, gen in (await db.execute(select(ZcSource.source_id, ZcSource.gen).where(ZcSource.source_id.in_(sids), ZcSource.gen > 0))).all()}
    if not gens:
        return {"total": 0, "items": []}
    sc = search_condition(q, sids)
    order = {"name": func.lower(H.name), "ip": H.ip_num, "os": func.lower(H.os), "last_connected": H.last_connected, "eol": func.coalesce(S.n, 0)}.get(sort, func.lower(H.name))
    use_eol = bool(eol) or sort == "eol"

    def conds(sid: uuid.UUID, gen: int) -> tuple:
        j = H.__table__
        if use_eol:
            j = j.outerjoin(S.__table__, and_(S.source_id == H.source_id, S.host_id == H.host_id))
        if zone:
            j = j.join(ZcHostZone.__table__, and_(ZcHostZone.source_id == H.source_id, ZcHostZone.host_id == H.host_id, ZcHostZone.gen == H.gen, ZcHostZone.zone_id == zone))
        w = [H.source_id == sid, H.gen == gen]
        if not all_hosts:
            w.append(H.active.is_(True))
        if sc is not None:
            w.append(sc)
        if os_q:
            w.append(any_of(os_q, H.os))
        if user_q:
            w.append(exists(select(1).where(DeviceUser.source_id == H.source_id, DeviceUser.host_id == H.host_id, column_like(DeviceUser.login, user_q), *users_vis)))
        if eol == "any":
            w.append(S.n > 0)
        elif eol == "eol":
            w.append(S.w == 3)
        elif eol == "none":
            w.append(S.n.is_(None))
        return j, w

    # итог — по всем источникам; страница — объединение «первые offset+limit строк каждого источника» (по индексам имени и адреса, без сортировки всего источника) с общей сортировкой
    total = 0
    members = []
    cols = (H.source_id, H.host_id, H.name, H.os, H.ip_num, H.last_connected, H.active, H.online, H.data)
    for sid, gen in gens.items():
        j, w = conds(sid, gen)
        total += int((await db.execute(select(func.count()).select_from(j).where(*w))).scalar_one())
        sq = (select(*cols, order.label("k")).select_from(j).where(*w).order_by((order.desc() if desc else order.asc()).nulls_last(), H.host_id).limit(offset + limit).subquery())
        members.append(select(sq))
    u = (members[0] if len(members) == 1 else union_all(*members)).subquery()
    page = select(u).order_by((u.c.k.desc() if desc else u.c.k.asc()).nulls_last(), u.c.host_id).offset(offset).limit(limit)
    rows = (await db.execute(page)).all()
    users: dict[tuple, list[DeviceUser]] = {}
    stat: dict[tuple, tuple[int, int, int]] = {}
    for sid in {r.source_id for r in rows}:
        ids = [r.host_id for r in rows if r.source_id == sid]
        for u in (await db.execute(select(DeviceUser).where(DeviceUser.source_id == sid, DeviceUser.host_id.in_(ids), *users_vis).order_by(DeviceUser.last_session_at.desc().nulls_last(), DeviceUser.login))).scalars():
            users.setdefault((sid, u.host_id), []).append(u)
        for r in (await db.execute(select(S.host_id, S.n, S.n_crit, S.w).where(S.source_id == sid, S.host_id.in_(ids)))).all():
            stat[(sid, r.host_id)] = (int(r.n), int(r.n_crit), int(r.w))
    items = []
    for r in rows:
        us = users.get((r.source_id, r.host_id), [])
        d = r.data or {}
        cur = [u for u in us if u.session_now]                       # список уже без служебных записей, если они скрыты
        last = next((u for u in us if u.last_session_at and u.kind == "user"), None)
        week = [u for u in us if u.kind == "user" and seen_week_py(u, cut)]
        n, nc, w = stat.get((r.source_id, r.host_id), (0, 0, 0))
        items.append({"source_id": str(r.source_id), "source": src_names.get(r.source_id, ""), "host_id": int(r.host_id), "name": r.name, "ip": d.get("ip", ""), "os": r.os or "", "group": d.get("group", ""),
                      "zones": d.get("zones") or [], "last_connected": r.last_connected, "active": r.active, "online": r.online, "eol": n, "eol_crit": nc, "eol_level": {3: "eol", 2: "extended", 1: "upcoming"}.get(w, ""),
                      "current": [user_out(u) for u in cur], "last_user": user_out(last) if last else None, "week": [user_out(u) for u in week], "week_n": len(week),
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
