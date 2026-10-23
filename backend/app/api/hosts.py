from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, current_source, get_db, require_user
from ..ksc import hosts as H
from ..ksc import queries as q
from ..ksc.driver import KscError
from ..models import KscSource

router = APIRouter(prefix="/hosts", tags=["hosts"])
STATUS_MASK = {1: "Агент в сети, но неактивен", 2: "постоянная защита не запущена", 4: "антивирус не запущен", 8: "слишком много вирусов", 16: "состояние постоянной защиты не соответствует заданному",
               32: "антивирус не установлен", 64: "полная проверка давно не выполнялась", 128: "базы давно не обновлялись", 256: "Агент неактивен слишком долго", 512: "лицензия истекла",
               1024: "много невылеченных объектов", 2048: "требуется перезагрузка", 4096: "несовместимые программы", 8192: "есть неустранённая уязвимость",
               16384: "поиск обновлений Windows давно не запускался", 32768: "шифрование не соответствует требованиям", 131072: "есть необработанный инцидент", 524288: "мало места на диске"}
RTP = {0: "неизвестно", 1: "остановлена", 2: "приостановлена", 3: "запускается", 4: "выполняется", 5: "максимальная защита", 6: "максимальная скорость", 7: "рекомендуемые параметры", 8: "пользовательские параметры", 9: "сбой"}
PRODUCT_STATE = {0: "не запущен", 1: "только что запущен", 2: "инициализация", 3: "запущен", 4: "приостановлен", 5: "деинициализация", 6: "критическая ошибка", 7: "завершает работу", 8: "удаляется"}


def _ksc(exc: KscError) -> HTTPException:
    return HTTPException(status_code=502 if exc.code in ("connect", "auth", "query") else 422, detail={"code": exc.code, "message": exc.message})


@router.get("")
async def hosts(request: Request, q_: str = Query("", alias="q", max_length=200), group: str = Query("", max_length=200), os: str = Query("", max_length=200),
                activity: str = Query("all", pattern=r"^(all|active|inactive)$"), days: int | None = Query(None, ge=1, le=3650), sort: str = "name", desc: bool = False,
                offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Компьютеры источника: имя, IP, ОС, группа, последнее подключение к KSC и статус активности (порог — из настроек или параметра days)."""
    client = request.app.state.sources.client(src)
    general = await request.app.state.settings_svc.get(db, "general")
    rcfg = await request.app.state.settings_svc.get(db, "reports")
    active_days = days or general.activity_days
    where, params = H.hosts_where(qtext=q_, group_contains=group, os_contains=os, active_days=active_days if activity != "all" else None, inactive_only=activity == "inactive",
                                  exclude_slaves=rcfg.exclude_slave_servers)
    try:
        rows = await client.run(q.HOSTS_PAGE.format(where=where, order=H.hosts_order(sort, desc)), {**params, "offset": offset, "limit": limit}, max_rows=limit)
        total = int((await client.run(q.HOSTS_COUNT.format(where=where), params, max_rows=1))[0]["n"])
    except KscError as exc:
        raise _ksc(exc) from None
    now = datetime.now(timezone.utc)
    return {"items": [H.host_row(h, None, now) for h in rows], "total": total, "offset": offset, "limit": limit, "activity_days": active_days, "fetched_at": now}


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
    h["rtp_state_label"] = RTP.get(h.get("rtp_state"), "")
    st = status[0] if status else None
    h["ksc_status"] = {"status": {0: "OK", 1: "критический", 2: "предупреждение"}.get(st["status"], str(st["status"])), "reasons": [t for b, t in STATUS_MASK.items() if int(st["mask"] or 0) & b]} if st else None
    general = await request.app.state.settings_svc.get(db, "general")
    return {"host": h, "activity_days": general.activity_days, "fetched_at": now,
            "software": [{"install_id": int(s["install_id"]), "product_id": int(s["product_id"]), "name": s.get("name") or "", "version": s.get("version") or "", "publisher": s.get("publisher") or "",
                          "install_date": s.get("install_date"), "is_msi": bool(s.get("is_msi"))} for s in software],
            "kaspersky": [{"product_code": k.get("product_code"), "product": k.get("product") or k.get("product_code"), "build": k.get("build"), "state": PRODUCT_STATE.get(k.get("state"), str(k.get("state"))),
                           "av_bases_date": k.get("av_bases_date"), "is_av": bool(k.get("is_av")), "has_rtp": bool(k.get("has_rtp"))} for k in kaspersky]}
