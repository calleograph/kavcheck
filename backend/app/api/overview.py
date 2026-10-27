"""Главная страница: активные компьютеры за 7/30/60/90 суток, серверы и станции, защита, лицензии, безопасность, источники данных и динамика.

Всё считается по готовым данным (кэш записей защиты в памяти процесса, подготовленные данные зон, результаты EOL, лицензии из внутренней базы); к KSC страница обращается так же, как раздел
«Состояние защиты» (один кэшируемый набор на источник). Для режима «Все источники» источник считается один раз; повторное подключение одного и того же KSC (совпадают сервер, порт и база)
в итоги не входит, чтобы не удваивать числа. Нет данных — `null` и пояснение, а не ноль."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_admin, require_analyst, require_user, source_scope
from ..ksc.driver import KscError
from ..ksc.hosts import ip_str
from ..licensing import pools as LP
from ..models import (EolFinding, EolState, KscSource, LicenseOverride, LicenseRecord, LicenseState, OverviewDaily, ZcDetection, ZcHost, ZcSource, utcnow)
from ..overview import calc as C
from ..overview import snapshots as SN
from ..search import any_field
from ..services.audit import write_audit
from ..services.sources import find_overlaps
from ..overview.service import DB_METRICS, _db_hosts, _scope, licenses_block
from .protection import protection_base

router = APIRouter(prefix="/overview", tags=["overview"])
lic_router = APIRouter(prefix="/licenses", tags=["licenses"])
log = logging.getLogger("app.overview")
KEEP_DAYS = 400


async def _records(request: Request, db: AsyncSession, src: KscSource, refresh: bool = False) -> tuple[list[dict] | None, datetime | None, str | None]:
    feats = (src.last_check or {}).get("features") or {}
    if feats and not feats.get("protection", {}).get("ok", True):
        return None, None, "в этом KSC нет объектов состояния защиты"
    try:
        recs, at = await protection_base(request, db, src, refresh=refresh)
        return recs, datetime.fromtimestamp(at, timezone.utc), None
    except KscError as exc:
        return None, None, exc.message
    except Exception as exc:  # noqa: BLE001 — один недоступный источник не должен ронять главную
        log.warning("Источник недоступен для главной: %s", src.name, exc_info=True)
        return None, None, f"{type(exc).__name__}: {str(exc)[:200]}"


# ------------------------------------------------------------------------------------------------ безопасность (из подготовленных данных)
async def _security(db: AsyncSession, sids: list[uuid.UUID], days: int, eol_cfg) -> dict:
    gens = {sid: int(g) for sid, g, st in (await db.execute(select(ZcSource.source_id, ZcSource.gen, ZcSource.status).where(ZcSource.source_id.in_(sids), ZcSource.gen > 0))).all()}
    out: dict = {"vulns": None, "hosts_crit": None, "ext_crit_hosts": None, "eol": None}
    if gens:
        cond = or_(*[and_(ZcHost.source_id == s, ZcHost.gen == g) for s, g in gens.items()])
        act = and_(ZcHost.days_since.is_not(None), ZcHost.days_since <= days)
        out["hosts_crit"] = int((await db.execute(select(func.count()).select_from(ZcHost).where(cond, act, ZcHost.k_crit > 0))).scalar_one())
        out["ext_crit_hosts"] = int((await db.execute(select(func.count()).select_from(ZcHost).where(cond, act, ZcHost.e_crit > 0))).scalar_one())
        dc = or_(*[and_(ZcDetection.source_id == s, ZcDetection.gen == g) for s, g in gens.items()])
        j = ZcDetection.__table__.join(ZcHost.__table__, and_(ZcHost.source_id == ZcDetection.source_id, ZcHost.gen == ZcDetection.gen, ZcHost.host_id == ZcDetection.host_id))
        out["vulns"] = int((await db.execute(select(func.count(func.distinct(ZcDetection.vuln_key))).select_from(j).where(dc, ZcDetection.origin == "ksc", ZcDetection.severity == 3,
                                                                                                                               ZcDetection.bucket == "current", act))).scalar_one())
        out["snapshot_missing"] = len(sids) - len(gens)
    if eol_cfg is not None and not eol_cfg.include_in_analytics:
        out["eol"] = {"excluded": True}
    else:
        ready = (await db.execute(select(func.count()).select_from(EolState).where(EolState.source_id.in_(sids), EolState.computed_at.is_not(None)))).scalar_one()
        if ready:
            q = select(EolFinding.kind, func.count(), func.coalesce(func.sum(EolFinding.hosts_active), 0)).where(EolFinding.source_id.in_(sids), EolFinding.status == "eol", EolFinding.hosts_active > 0).group_by(EolFinding.kind)
            got = {k: (int(n), int(h)) for k, n, h in (await db.execute(q)).all()}
            out["eol"] = {"os_items": got.get("os", (0, 0))[0], "os_devices": got.get("os", (0, 0))[1], "app_items": got.get("app", (0, 0))[0], "app_devices": got.get("app", (0, 0))[1],
                          "not_ready": len(sids) - int(ready)}
    return out


# ------------------------------------------------------------------------------------------------ динамика
async def _trend(db: AsyncSession, sids: list[uuid.UUID], key: str) -> dict:
    cutoff = date.today() - timedelta(days=KEEP_DAYS)
    rows = (await db.execute(select(OverviewDaily.source_id, OverviewDaily.day, OverviewDaily.data).where(OverviewDaily.source_id.in_(sids), OverviewDaily.day >= cutoff).order_by(OverviewDaily.day))).all()
    per: dict[date, dict] = {}
    for sid, day, data in rows:
        d = per.setdefault(day, {"n": 0, "active": 0, "total": 0})
        d["n"] += 1
        d["active"] += int(data.get(key) or 0)
        d["total"] += int(data.get("total") or 0)
    pts = [{"day": d.isoformat(), "active": v["active"], "total": v["total"]} for d, v in sorted(per.items()) if v["n"] == len(sids)]      # неполные дни (не по всем источникам) не рисуются
    return {"points": pts[-120:], "since": pts[0]["day"] if pts else None}


# ------------------------------------------------------------------------------------------------ сводка
@router.get("")
async def overview(request: Request, days: int = Query(30, ge=1, le=365), refresh: bool = False, su: SessionUser = Depends(require_user),
                   srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    """Показатели главной: сводка по выбранному источнику или по всем доступным. days — период активности (7, 30, 60, 90; допустим любой)."""
    scope, skipped = _scope(srcs)
    now = datetime.now(timezone.utc)
    results = await asyncio.gather(*[_records(request, db, s, refresh) for s in scope])
    rows, totals, ok_ids = [], {k: 0 for k in C.METRICS}, []
    periods = {d: {"days": d, "connected": 0, "visible": 0, "av_installed": 0, "av_running": 0, "servers": 0, "workstations": 0} for d in C.PERIODS}
    extra = {"agent_installed": 0, "av_any": 0}
    daily: list[tuple[uuid.UUID, dict]] = []
    for s, (recs, at, err) in zip(scope, results):
        row = {"id": str(s.id), "name": s.name, "error": err, "synced_at": at, "ksc_version": (s.last_check or {}).get("ksc_version"), "last_check_ok": s.last_check_ok}
        if recs is not None:
            sm = C.summarize(recs, days, now)
            row.update({k: sm[k] for k in C.METRICS})
            ok_ids.append(s.id)
            for k in C.METRICS:
                totals[k] += sm[k]
            for p in sm["periods"]:
                for k in periods[p["days"]]:
                    if k != "days":
                        periods[p["days"]][k] += p[k]
            extra["agent_installed"] += sm["agent_installed"]
            extra["av_any"] += sm["av_any"]
            daily.append((s.id, recs))
        rows.append(row)
    for s in srcs:
        if str(s.id) in skipped:
            rows.append({"id": str(s.id), "name": s.name, "duplicate_of": skipped[str(s.id)], "error": None, "synced_at": None})
    lic = await licenses_block(db, scope)
    for r in rows:
        r["license"] = lic["by_source"].get(r["id"])
    eol_cfg = await request.app.state.settings_svc.get(db, "eol")
    sec = await _security(db, [s.id for s in scope], days, eol_cfg)
    key = f"a{days}" if days in C.PERIODS else "a30"
    trend = await _trend(db, [s.id for s in scope if s.id in ok_ids], key) if ok_ids else {"points": [], "since": None}
    for sid, recs in daily:                                    # сегодняшний срез — после чтения динамики
        try:
            await SN.store(db, sid, SN.payload(recs, now))
        except IntegrityError:
            await db.rollback()                                # параллельный запрос записал срез дня раньше — достаточно
        except Exception:  # noqa: BLE001 — срез не обязателен для ответа
            await db.rollback()
            log.warning("Срез главной не записан", exc_info=True)
    rows += await _snapshot_rows(db, su, scope, srcs, days)
    pentest = await _pentest_block(db) if su.role != "viewer" else None        # результаты сканирования — аналитику и администратору
    ok = bool(ok_ids)
    return {"days": days, "periods_available": list(C.PERIODS), "scope": {"all": len(srcs) > 1, "sources": len(scope), "ok": len(ok_ids), "duplicates": skipped},
            "totals": totals if ok else None, "periods": list(periods.values()) if ok else [], "extra": extra if ok else None, "sources": rows, "licenses": lic, "security": sec,
            "trend": trend, "trend_key": key, "pentest": pentest, "stale_days": C.STALE_DAYS, "bases_days": C.BASES_DAYS, "generated_at": now,
            "labels": {k: v[0] for k, v in C.METRICS.items()} | DB_METRICS}


async def _snapshot_rows(db: AsyncSession, su: SessionUser, scope: list[KscSource], srcs: list[KscSource], days: int) -> list[dict]:
    """Источники вне выбранной области: сводка по последнему ежедневному срезу (без чтения их KSC); срез помечен временем получения."""
    from ..services.sources import visible_sources  # noqa: PLC0415

    inside = {s.id for s in srcs}
    out = []
    for s in await visible_sources(db, su):
        if s.id in inside:
            continue
        row = (await db.execute(select(OverviewDaily).where(OverviewDaily.source_id == s.id).order_by(OverviewDaily.day.desc()).limit(1))).scalar_one_or_none()
        item = {"id": str(s.id), "name": s.name, "error": None, "synced_at": row.taken_at if row else None, "snapshot": True, "ksc_version": (s.last_check or {}).get("ksc_version"), "last_check_ok": s.last_check_ok}
        if row is not None:
            item.update((row.data.get("by") or {}).get(str(days if days in C.PERIODS else 30), {}))
        out.append(item)
    return out


async def _pentest_block(db: AsyncSession) -> dict | None:
    try:
        from ..pentest import read as PR  # noqa: PLC0415
    except ImportError:
        return None
    return await PR.overview_block(db)


@router.get("/hosts")
async def overview_hosts(request: Request, metric: str = Query(..., max_length=20), days: int = Query(30, ge=1, le=365), q: str = Query("", max_length=200),
                         sort: str = Query("name", pattern=r"^(name|ip|os|group|last_connected)$"), desc: bool = False, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
                         su: SessionUser = Depends(require_user), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    """Устройства показателя главной для боковой панели: те же предикаты, что и в числах (серверная сортировка, поиск и страницы)."""
    if metric in DB_METRICS:
        return await _db_hosts(db, srcs, metric, days, q, sort, desc, offset, limit)
    if metric not in C.METRICS:
        raise HTTPException(status_code=422, detail="Неизвестный показатель")
    scope, _skipped = _scope(srcs)
    now = datetime.now(timezone.utc)
    results = await asyncio.gather(*[_records(request, db, s) for s in scope])
    items = []
    for s, (recs, _at, _err) in zip(scope, results):
        for r in C.pick(recs or [], metric, days, now):
            items.append({**r, "source_id": str(s.id), "source": s.name})
    f = any_field(q)
    if f:
        items = [r for r in items if f(r["name"], r["fqdn"], r["ip"])]
    items.sort(key=C.sort_key(sort), reverse=desc)
    page = [{"host_id": r["host_id"], "name": r["name"], "ip": r["ip"], "os": r["os"], "group": r["group"], "last_connected": r["last_connected"], "days_since_connection": r["days_since_connection"],
             "online": r.get("online"), "source_id": r["source_id"], "source": r["source"]} for r in items[offset:offset + limit]]
    return {"items": page, "total": len(items), "offset": offset, "limit": limit, "title": C.METRICS[metric][0]}


# ------------------------------------------------------------------------------------------------ лицензии: администрирование
class ManualIn(BaseModel):
    source_id: uuid.UUID
    product: str = Field(min_length=1, max_length=200)
    kind: str = Field(default="", max_length=80)
    expires_at: datetime | None = None
    limit_n: int | None = Field(default=None, ge=0, le=10**8)
    used_n: int | None = Field(default=None, ge=0, le=10**8)
    pool: str = Field(default="", max_length=120)
    note: str = Field(default="", max_length=300)


class PoolIn(BaseModel):
    source_id: uuid.UUID
    lic_key: str = Field(min_length=1, max_length=40)
    pool: str = Field(default="", max_length=120)           # пусто — убрать из пула


@lic_router.get("")
async def licenses(su: SessionUser = Depends(require_user), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    scope, _ = _scope(srcs)
    lic = await licenses_block(db, scope)
    if not su.is_admin:                                        # сведения о диагностике чтения — только администратору
        for v in lic["by_source"].values():
            v["note"] = None
    return lic


@lic_router.get("/all")
async def licenses_all(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Все лицензии всех источников (администрирование): записи, пулы, диагностика чтения."""
    from ..services.sources import visible_sources  # noqa: PLC0415

    scope, _ = _scope(await visible_sources(db, su))
    return await licenses_block(db, scope)


@lic_router.get("/diag")
async def diag(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Что найдено в базе KSC по лицензиям: таблицы и сопоставление столбцов — для проверки и ручного ввода, если лицензии не прочитаны."""
    from ..services.sources import visible_sources  # noqa: PLC0415

    out = []
    for s in await visible_sources(db, su):
        st = await db.get(LicenseState, s.id)
        out.append({"source_id": str(s.id), "source": s.name, "polled_at": st.polled_at if st else None, "error": st.error if st else None, "records": st.records_n if st else 0,
                    "diag": st.diag if st else None})
    return {"items": out}


@lic_router.post("/refresh", status_code=202)
async def refresh(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    from ..services.sources import visible_sources  # noqa: PLC0415

    srcs = await visible_sources(db, su)
    for s in srcs:
        st = await db.get(LicenseState, s.id)
        if st is None:
            db.add(LicenseState(source_id=s.id, requested_at=utcnow()))
        else:
            st.requested_at = utcnow()
    await db.commit()
    return {"requested": len(srcs)}


@lic_router.post("/manual")
async def add_manual(body: ManualIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Лицензия, внесённая вручную (когда KSC не отдаёт сведения): показывается с пометкой «внесено вручную» и не заменяется чтением KSC."""
    if await db.get(KscSource, body.source_id) is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    key = "m" + hashlib.sha1(f"{body.source_id}{body.product}{utcnow().isoformat()}".encode()).hexdigest()[:20]
    now = utcnow()
    rec = LicenseRecord(source_id=body.source_id, lic_key=key, origin="manual", product=body.product.strip(), kind=body.kind.strip(), expires_at=body.expires_at, limit_n=body.limit_n,
                        used_n=body.used_n, state="unknown", fp="", note=body.note.strip(), updated_at=now)
    db.add(rec)
    if body.pool.strip():
        db.add(LicenseOverride(source_id=body.source_id, lic_key=key, pool=body.pool.strip(), set_by=su.display_name))
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="license.manual_add", target_type="license", target_id=key, source_id=body.source_id,
                details={"product": rec.product, "limit": body.limit_n, "used": body.used_n, "pool": body.pool})
    await db.commit()
    return {"lic_key": key}


@lic_router.delete("/manual/{source_id}/{lic_key}", status_code=204)
async def delete_manual(source_id: uuid.UUID, lic_key: str, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    rec = await db.get(LicenseRecord, (source_id, lic_key))
    if rec is None or rec.origin != "manual":
        raise HTTPException(status_code=404, detail="Ручная запись не найдена (записи из KSC не удаляются)")
    ov = await db.get(LicenseOverride, (source_id, lic_key))
    if ov is not None:
        await db.delete(ov)
    await db.delete(rec)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="license.manual_delete", target_type="license", target_id=lic_key, source_id=source_id, details={"product": rec.product})
    await db.commit()


@lic_router.put("/pool", status_code=204)
async def set_pool(body: PoolIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Отнести лицензию к общему пулу (или убрать из него). Данные KSC не меняются; лицензии одного пула считаются один раз."""
    if await db.get(LicenseRecord, (body.source_id, body.lic_key)) is None:
        raise HTTPException(status_code=404, detail="Лицензия не найдена")
    ov = await db.get(LicenseOverride, (body.source_id, body.lic_key))
    pool = body.pool.strip()
    if not pool:
        if ov is not None:
            await db.delete(ov)
    elif ov is None:
        db.add(LicenseOverride(source_id=body.source_id, lic_key=body.lic_key, pool=pool, set_by=su.display_name))
    else:
        ov.pool, ov.set_by, ov.set_at = pool, su.display_name, utcnow()
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="license.pool", target_type="license", target_id=body.lic_key, source_id=body.source_id, details={"pool": pool})
    await db.commit()
