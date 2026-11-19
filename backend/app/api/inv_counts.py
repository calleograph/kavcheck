"""Инвентаризация со сканированием: документы инвентаризации, ожидаемый список, отметка найденного (в том числе пакетом из автономного режима), статистика по помещениям,
расхождения и решения. Логика — inventory/counting.py; право — «проведение инвентаризации» (count)."""
from __future__ import annotations

from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_db
from ..inventory import core as C
from ..inventory import counting as K
from ..inventory import model as M
from ..models import InvAsset, InvCount, InvCountItem, InvLocation, InvPerson, utcnow
from .inv import Ix, audit, inv_ctx

router = APIRouter(prefix="/inv", tags=["inventory"])


async def _count(db: AsyncSession, ix: Ix, cid: int, *, lock: bool = False) -> InvCount:
    c = await db.get(InvCount, cid, with_for_update=lock)
    if c is None or (ix.acc.scopes and not ix.acc.loc_ok(await db.get(InvLocation, c.location_id) if c.location_id else None)):
        raise HTTPException(status_code=404, detail="Инвентаризация не найдена или вне вашей области учёта")
    return c


async def count_out(db: AsyncSession, c: InvCount, with_stats: bool = False) -> dict:
    loc = await db.get(InvLocation, c.location_id) if c.location_id else None
    resp = await db.get(InvPerson, c.resp_id) if c.resp_id else None
    out = {"id": c.id, "no": c.no, "title": c.title, "status": c.status, "status_ru": M.COUNT_STATUS_RU.get(c.status, c.status), "location_id": c.location_id,
           "location": loc.path if loc else "все местоположения", "cls": c.cls, "resp_id": c.resp_id, "resp": resp.name if resp else "", "note": c.note,
           "created_at": C._iso(c.created_at), "created_by": c.created_by, "started_at": C._iso(c.started_at), "closed_at": C._iso(c.closed_at), "closed_by": c.closed_by, "stats": c.stats or {}}
    if with_stats and c.status in ("active", "closed"):
        out["stats"] = await K.stats(db, c)
    return out


@router.get("/counts")
async def counts(status: str = Query("", max_length=40), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    w = [InvCount.status.in_(status.split(","))] if status else []
    if ix.acc.scopes:                                              # только инвентаризации в пределах области учёта (по всем местоположениям — нет)
        w.append(InvCount.location_id.in_(ix.acc.loc_ids()))
    rows = (await db.execute(select(InvCount).where(*w).order_by(InvCount.created_at.desc()).limit(500))).scalars().all()
    return {"items": [await count_out(db, c) for c in rows]}


class CountBody(BaseModel):
    title: str = Field(default="", max_length=300)
    location_id: int | None = None
    cls: str = Field(default="", max_length=200)
    resp_id: int | None = None
    note: str = Field(default="", max_length=4000)
    start: bool = True


@router.post("/counts", status_code=201)
async def create(body: CountBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Новая инвентаризация: область (узел местоположений с вложенными, классы). start — сразу зафиксировать ожидаемый список и начать сканирование."""
    ix.acc.need("count")
    loc = await db.get(InvLocation, body.location_id) if body.location_id else None
    if body.location_id and loc is None:
        raise HTTPException(status_code=422, detail="Местоположение не найдено")
    if ix.acc.scopes and not ix.acc.loc_ok(loc):
        raise HTTPException(status_code=403, detail="Выберите местоположение в пределах вашей области учёта")
    no = await C.next_number(db, InvCount.no, f"ИН-{date.today().year}-", 5)
    c = InvCount(no=no, title=(body.title or (f"Инвентаризация: {loc.path}" if loc else "Инвентаризация"))[:300], location_id=body.location_id,
                 cls=",".join(x for x in body.cls.split(",") if x in M.CLS_RU), resp_id=body.resp_id, note=body.note, created_by=ix.su.display_name)
    db.add(c)
    await db.flush()
    if body.start:
        await K.start(db, c, ix.acc)
    audit(db, ix, "count.create", c.no, {"id": c.id, "location": body.location_id, "expected": (c.stats or {}).get("expected")})
    await db.commit()
    return await count_out(db, c)


@router.get("/counts/{cid}")
async def card(cid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    return await count_out(db, await _count(db, ix, cid), with_stats=True)


@router.post("/counts/{cid}/start")
async def start(cid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("count")
    c = await _count(db, ix, cid, lock=True)
    n = await K.start(db, c, ix.acc)
    audit(db, ix, "count.start", c.no, {"expected": n})
    await db.commit()
    return {"expected": n}


@router.get("/counts/{cid}/items")
async def items(cid: int, state: str = Query("", max_length=80), location: int | None = None, diff: bool = False, q: str = Query("", max_length=200),
                offset: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=2000), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Строки: по состоянию, по ожидаемому местоположению (location), только расхождения (diff)."""
    c = await _count(db, ix, cid)
    w = [InvCountItem.count_id == c.id]
    if state:
        w.append(InvCountItem.state.in_(state.split(",")))
    if location is not None:
        w.append((InvCountItem.exp_location_id == location) | (InvCountItem.found_location_id == location))
    if diff:
        w.append(InvCountItem.state.in_(("moved", "extra", "unknown", "missing")) | ((InvCountItem.found_user_id.is_not(None)) & ((InvCountItem.exp_user_id.is_(None)) | (InvCountItem.found_user_id != InvCountItem.exp_user_id))))
    if q.strip():
        from ..search import column_like  # noqa: PLC0415

        conds = [x for x in (column_like(InvCountItem.code, q.strip()),) if x is not None]
        conds.append(InvCountItem.asset_id.in_(select(InvAsset.id).where(column_like(InvAsset.search, q.strip()))))
        from sqlalchemy import or_  # noqa: PLC0415

        w.append(or_(*conds))
    total = (await db.execute(select(func.count()).select_from(InvCountItem).where(*w))).scalar_one()
    rows = list((await db.execute(select(InvCountItem).where(*w).order_by(InvCountItem.found_at.desc().nulls_last(), InvCountItem.id).offset(offset).limit(limit))).scalars())
    locs, people = await K.names(db, rows)
    return {"items": [K.item_out(it, locs, people) for it in rows], "total": total, "offset": offset, "limit": limit}


class ScanBody(BaseModel):
    code: str = Field(min_length=1, max_length=500)
    location_id: int | None = None
    user_id: int | None = None
    at: datetime | None = None


@router.post("/counts/{cid}/scan")
async def scan(cid: int, body: ScanBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("count")
    c = await _count(db, ix, cid, lock=True)
    r = await K.scan(db, c, body.code, body.location_id, ix.su.display_name, user_id=body.user_id, at=body.at if body.at and body.at <= utcnow() else None)
    await db.commit()
    return r


class SyncBody(BaseModel):
    scans: list[ScanBody] = Field(min_length=1, max_length=5000)


@router.post("/counts/{cid}/sync")
async def sync(cid: int, body: SyncBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Загрузка отметок, собранных без связи (автономный режим): по порядку, с исходным временем; повтор не дублирует."""
    ix.acc.need("count")
    c = await _count(db, ix, cid, lock=True)
    out = []
    for s in body.scans:
        try:
            r = await K.scan(db, c, s.code, s.location_id, ix.su.display_name, user_id=s.user_id, at=s.at if s.at and s.at <= utcnow() else None)
            out.append({"code": s.code, "result": r["result"]})
        except HTTPException as exc:
            out.append({"code": s.code, "result": "error", "error": str(exc.detail)})
    audit(db, ix, "count.sync", c.no, {"n": len(body.scans)})
    await db.commit()
    return {"results": out}


@router.delete("/counts/{cid}/items/{iid}")
async def unscan(cid: int, iid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Отменить ошибочную отметку: ожидаемая строка возвращается в «Ожидается», лишняя и неизвестная удаляются."""
    ix.acc.need("count")
    c = await _count(db, ix, cid, lock=True)
    if c.status != "active":
        raise HTTPException(status_code=409, detail="Инвентаризация не активна")
    it = await db.get(InvCountItem, iid)
    if it is None or it.count_id != c.id:
        raise HTTPException(status_code=404, detail="Строка не найдена")
    if it.expected:
        it.state, it.found_location_id, it.found_user_id, it.found_at, it.found_by, it.found_via = "pending", None, None, None, "", ""
    else:
        await db.delete(it)
    await db.commit()
    return {"ok": True}


@router.post("/counts/{cid}/close")
async def close(cid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("count")
    c = await _count(db, ix, cid, lock=True)
    await K.close(db, c, ix.su.display_name)
    audit(db, ix, "count.close", c.no, {k: v for k, v in (c.stats or {}).items() if k in ("expected", "checked", "by_state")})
    await db.commit()
    return await count_out(db, c, with_stats=True)


@router.post("/counts/{cid}/cancel")
async def cancel(cid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("count")
    c = await _count(db, ix, cid, lock=True)
    if c.status == "closed":
        raise HTTPException(status_code=409, detail="Завершённую инвентаризацию отменить нельзя")
    c.status = "cancelled"
    audit(db, ix, "count.cancel", c.no, {})
    await db.commit()
    return {"ok": True}


class DecideBody(BaseModel):
    item_ids: list[int] = Field(min_length=1, max_length=5000)
    decision: str = Field(pattern=r"^(apply|keep|lost|ignore)$")
    note: str = Field(default="", max_length=500)


@router.post("/counts/{cid}/decide")
async def decide(cid: int, body: DecideBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Решение по расхождениям (выбранным строкам). Обнаружение само по себе учёт не меняет — только это решение."""
    ix.acc.need("count")
    if body.decision == "lost":
        ix.acc.need("writeoff")
    c = await _count(db, ix, cid, lock=True)
    if c.status not in ("active", "closed"):
        raise HTTPException(status_code=409, detail="Инвентаризация не начата или отменена")
    n = await K.decide(db, c, body.item_ids, body.decision, ix.acc, ix.su.display_name, body.note)
    audit(db, ix, "count.decide", c.no, {"decision": body.decision, "items": len(body.item_ids), "changed": n})
    await db.commit()
    return {"changed": n}


@router.get("/counts/{cid}/offline")
async def offline(cid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Пакет для работы без связи: ожидаемые единицы (коды и место) и местоположения области — телефон распознаёт коды сам, отметки загружаются позже."""
    c = await _count(db, ix, cid)
    rows = (await db.execute(select(InvCountItem).where(InvCountItem.count_id == c.id, InvCountItem.asset_id.is_not(None)))).scalars().all()
    lw = []
    if c.location_id:
        root = await db.get(InvLocation, c.location_id)
        lw.append(InvLocation.ids_path.like((root.ids_path if root else "/-/") + "%"))
    locs = (await db.execute(select(InvLocation.id, InvLocation.path).where(*lw).order_by(InvLocation.path).limit(20000))).all()
    return {"count": {"id": c.id, "no": c.no, "status": c.status}, "items": [{"asset_id": it.asset_id, "inv_no": (it.snap or {}).get("inv_no", ""), "serial": (it.snap or {}).get("serial", ""),
            "uid": (it.snap or {}).get("uid", ""), "name": (it.snap or {}).get("name", ""), "exp_location_id": it.exp_location_id, "state": it.state} for it in rows],
            "locations": [{"id": i, "path": p} for i, p in locs], "at": utcnow().isoformat()}
