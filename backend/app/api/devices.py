"""Устройства и пользователи: единая таблица (имя, IP, ОС, источник, группа, зона, подключение, пользователи, EOL), карточка и состояние опроса пользователей.
Данные — из подготовленных данных зон, накопленных наблюдений за пользователями и результатов EOL; страницы KSC не опрашивают. Режим «Все источники» — заголовок X-Source-Id: all."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, is_all, require_analyst, require_user, source_scope
from ..devices import read as R
from ..devices.service import supported
from ..eol import read as EOLR
from ..models import DevicesState, DeviceUser, KscSource, ZcHost, ZcSource
from ..services.audit import write_audit

router = APIRouter(prefix="/devices", tags=["devices"])

LIMITS = ("KSC хранит только два списка: пользователи, вошедшие сейчас, и пользователи, входившие ранее — без даты и времени входа. Поэтому «последний пользователь» и «пользователи за 7 суток» "
          "строятся по наблюдениям KAV Checker: он опрашивает списки по расписанию. Показывается дата наблюдения, а не точное время входа; короткие сеансы между опросами не видны; история начинается "
          "с первого опроса источника. Записи, существовавшие при первом опросе, без даты в «7 суток» не входят. Служебные и системные учётные записи по умолчанию скрыты.")


def _ids(srcs: list[KscSource], source_id: str) -> list[uuid.UUID]:
    ids = [s.id for s in srcs]
    if not source_id:
        return ids
    try:
        one = uuid.UUID(source_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="source_id") from None
    if one not in ids:
        raise HTTPException(status_code=403, detail="Нет доступа к этому источнику KSC")
    return [one]


@router.get("")
async def devices(request: Request, q: str = Query("", max_length=400), zone: str = Query("", max_length=40), os_q: str = Query("", max_length=120, alias="os"), user: str = Query("", max_length=120),
                  eol: str = Query("", pattern=r"^(any|eol|none)?$"), source_id: str = Query("", max_length=40), all_hosts: bool = False, show_service: bool = False,
                  sort: str = Query("name", pattern=r"^(name|ip|os|last_connected|eol)$"), desc: bool = False, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                  su: SessionUser = Depends(require_user), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    """Таблица устройств с пользователями. Поиск `q` — имя, FQDN, IP (адрес, сеть CIDR, диапазон, маска по октетам) или логин; несколько значений через пробел или запятую."""
    sids = _ids(srcs, source_id)
    out = await R.list_devices(db, sids, {s.id: s.name for s in srcs}, q=q, zone=zone, os_q=os_q, user_q=user, eol=eol, all_hosts=all_hosts, show_service=show_service, sort=sort, desc=desc,
                               offset=offset, limit=limit)
    out["all_sources"] = is_all(request)
    out["limits"] = LIMITS
    ready = {r for (r,) in (await db.execute(select(ZcSource.source_id).where(ZcSource.source_id.in_(sids), ZcSource.gen > 0))).all()}
    out["not_ready"] = [s.name for s in srcs if s.id in sids and s.id not in ready]            # источники, для которых подготовленные данные зон ещё не рассчитаны
    return out


@router.get("/status")
async def status(request: Request, su: SessionUser = Depends(require_user), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    """Состояние опроса пользователей по источникам: последний опрос, начало наблюдений, ошибка, поддерживается ли источником."""
    cfg = await request.app.state.settings_svc.get(db, "devices")
    states = {s.source_id: s for s in (await db.execute(select(DevicesState).where(DevicesState.source_id.in_([x.id for x in srcs])))).scalars()}
    items = []
    for src in srcs:
        st = states.get(src.id)
        items.append({"source_id": str(src.id), "source": src.name, "supported": supported(src), "polled_at": st.polled_at if st else None, "first_poll_at": st.first_poll_at if st else None,
                      "rows_seen": st.rows_seen if st else 0, "error": st.error if st else None, "queued": bool(st and st.requested_at)})
    return {"enabled": bool(cfg.enabled), "interval_minutes": int(cfg.interval_minutes), "hide_service": bool(cfg.hide_service), "items": items, "limits": LIMITS}


@router.post("/poll", status_code=202)
async def poll(su: SessionUser = Depends(require_analyst), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    """Опросить списки пользователей сейчас (фоновая служба подхватит в течение минуты)."""
    ids = [s.id for s in srcs if supported(s)]
    for sid in ids:
        st = await db.get(DevicesState, sid)
        if st is None:
            db.add(DevicesState(source_id=sid, requested_at=datetime.now(timezone.utc)))
        else:
            st.requested_at, st.error_at = datetime.now(timezone.utc), None
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="devices.poll", target_type="devices", target_id=",".join(str(i) for i in ids))
    await db.commit()
    return {"queued": len(ids)}


@router.get("/{source_id}/{host_id}")
async def card(source_id: str, host_id: int, su: SessionUser = Depends(require_user), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db),
               show_service: bool = False):
    """Карточка устройства: пользователи (сейчас, последний замеченный, за 7 суток, ранее) и программы и ОС с EOL."""
    sid = _ids(srcs, source_id)[0]
    gen = (await db.get(ZcSource, sid))
    row = None
    if gen is not None and gen.gen:
        row = (await db.execute(select(ZcHost).where(ZcHost.source_id == sid, ZcHost.host_id == host_id, ZcHost.gen == gen.gen))).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Устройство не найдено в подготовленных данных")
    cut = datetime.now(timezone.utc) - timedelta(days=7)
    us = (await db.execute(select(DeviceUser).where(DeviceUser.source_id == sid, DeviceUser.host_id == host_id).order_by(DeviceUser.last_session_at.desc().nulls_last(), DeviceUser.login))).scalars().all()
    vis = [u for u in us if show_service or u.kind == "user"]
    d = row.data or {}
    zn = await R.zone_names(db)
    return {"source_id": str(sid), "source": next((s.name for s in srcs if s.id == sid), ""), "host_id": host_id, "name": row.name, "ip": d.get("ip", ""), "os": row.os, "group": d.get("group", ""),
            "zones": [zn.get(str(z), str(z)) for z in d.get("zones") or []], "last_connected": row.last_connected, "active": row.active, "online": row.online,
            "current": [R.user_out(u) for u in vis if u.session_now], "last_user": next((R.user_out(u) for u in vis if u.last_session_at), None),
            "week": [R.user_out(u) for u in vis if u.kind == "user" and R.seen_week_py(u, cut)], "history": [R.user_out(u) for u in vis if not u.session_now][:200],
            "hidden_service": sum(1 for u in us if u.kind != "user") if not show_service else 0, "eol": await EOLR.host_items(db, sid, host_id), "limits": LIMITS}


