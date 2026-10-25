from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, current_source, get_db, require_user
from ..ksc import hosts as H
from ..ksc import protection as P
from ..ksc import queries as q
from ..ksc.driver import KscError
from ..models import KscSource

router = APIRouter(prefix="/hosts", tags=["hosts"])



def _ksc(exc: KscError) -> HTTPException:
    return HTTPException(status_code=502 if exc.code in ("connect", "auth", "query") else 422, detail={"code": exc.code, "message": exc.message})


@router.get("")
async def hosts(request: Request, q_: str = Query("", alias="q", max_length=200), group: str = Query("", max_length=200), os: str = Query("", max_length=200),
                activity: str = Query("active", pattern=r"^(all|active|inactive)$"), days: int | None = Query(None, ge=1, le=3650), sort: str = "name", desc: bool = False, zone: str = Query("", max_length=40),
                offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Компьютеры источника: имя, IP, ОС, группа, последнее подключение к KSC и статус активности.
    По умолчанию (activity=active) — только подключавшиеся к KSC за порог глобального фильтра; hidden — сколько при этом скрыто."""
    client = request.app.state.sources.client(src)
    general = await request.app.state.settings_svc.get(db, "general")
    rcfg = await request.app.state.settings_svc.get(db, "reports")
    active_days = days or general.activity_days
    where, params = H.hosts_where(qtext=q_, group_contains=group, os_contains=os, active_days=active_days if activity != "all" else None, inactive_only=activity == "inactive",
                                  exclude_slaves=rcfg.exclude_slave_servers)
    zsql = ""
    if zone:        # фильтр «Зона ответственности»: компьютеры зоны по сетям, группам и закреплениям
        from .zones import zone_host_ids  # noqa: PLC0415

        zids = sorted(await zone_host_ids(request, db, src, zone))
        if len(zids) > 30_000:
            raise HTTPException(status_code=422, detail="В зоне больше 30 000 компьютеров: сузьте зону или используйте отчёт")
        zsql = f" AND h.nId IN ({q.ids_list(zids)})" if zids else " AND 1 = 0"
    try:
        rows = await client.run(q.HOSTS_PAGE.format(where=where + zsql, order=H.hosts_order(sort, desc)), {**params, "offset": offset, "limit": limit}, max_rows=limit)
        total = int((await client.run(q.HOSTS_COUNT.format(where=where + zsql), params, max_rows=1))[0]["n"])
        hidden = 0
        if activity == "active":
            w_all, p_all = H.hosts_where(qtext=q_, group_contains=group, os_contains=os, exclude_slaves=rcfg.exclude_slave_servers)
            w_all += zsql
            hidden = int((await client.run(q.HOSTS_COUNT.format(where=w_all), p_all, max_rows=1))[0]["n"]) - total
    except KscError as exc:
        raise _ksc(exc) from None
    now = datetime.now(timezone.utc)
    return {"items": [H.host_row(h, None, now) for h in rows], "total": total, "hidden": hidden, "offset": offset, "limit": limit, "activity_days": active_days, "fetched_at": now}


@router.get("/{host_id}")
async def host(host_id: int, request: Request, su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    client = request.app.state.sources.client(src)
    feats = (src.last_check or {}).get("features") or {}
    try:
        rows = await client.run(q.HOST_ONE, {"id": host_id}, max_rows=1)
        if not rows:
            raise HTTPException(status_code=404, detail="Устройство не найдено")
        groups = await H.groups_map(client)
        software = await client.run(q.SOFTWARE_ON_HOST, {"id": host_id}, max_rows=20_000)
        kaspersky = await client.run(q.KASPERSKY_ON_HOST, {"id": host_id}, max_rows=100) if feats.get("protection", {}).get("ok", True) else []
        status = await client.run(q.HOST_STATUS, {"id": host_id}, max_rows=1) if feats.get("protection", {}).get("ok", True) else []
    except KscError as exc:
        raise _ksc(exc) from None
    now = datetime.now(timezone.utc)
    h = H.host_row(rows[0], groups, now)
    h["rtp_state_label"] = P.RTP.get(h.get("rtp_state"), "")
    st = status[0] if status else None
    h["ksc_status"] = {"status": P.KSC_STATUS.get(st["status"], str(st["status"])), "reasons": [t for b, t in P.STATUS_MASK.items() if int(st["mask"] or 0) & b]} if st else None
    h["protection"] = P.host_protection(rows[0], kaspersky, st, now) if feats.get("protection", {}).get("ok", True) else None
    general = await request.app.state.settings_svc.get(db, "general")
    return {"host": h, "activity_days": general.activity_days, "fetched_at": now,
            "software": [{"install_id": int(s["install_id"]), "product_id": int(s["product_id"]), "name": s.get("name") or "", "version": s.get("version") or "", "publisher": s.get("publisher") or "",
                          "install_date": s.get("install_date"), "is_msi": bool(s.get("is_msi"))} for s in software],
            "kaspersky": [{"product_code": k.get("product_code"), "product": k.get("product") or k.get("product_code"), "build": k.get("build"), "state": P.PRODUCT_STATE.get(k.get("state"), str(k.get("state"))),
                           "av_bases_date": k.get("av_bases_date"), "is_av": bool(k.get("is_av")), "has_rtp": bool(k.get("has_rtp"))} for k in kaspersky]}
