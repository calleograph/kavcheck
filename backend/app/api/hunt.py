"""CVE Hunt — целевой поиск уязвимостей и программ. Задания выполняет сканер Pentest (профиль «hunt»); права — аналитик и администратор, область — как у Pentest."""
from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_analyst
from ..hunt import criteria as C
from ..hunt import kb as KB
from ..hunt import results as RS
from ..hunt import scope as SC
from ..hunt import service as HS
from ..models import CatalogProduct, HuntHit, KscSource, PtHost, PtJob, VdbVuln, utcnow
from ..pentest import read as R
from ..pentest import service as S
from ..search import any_of
from ..services.audit import write_audit

router = APIRouter(prefix="/hunt", tags=["hunt"])


class ProductIn(BaseModel):
    name: str = Field(default="", max_length=300)
    source_id: uuid.UUID | None = None
    product_key: str = Field(default="", max_length=160)
    kb: str = Field(default="", max_length=20)
    mode: Literal["any", "exact", "range", "below", "above"] = "any"
    versions: list[str] = Field(default_factory=list, max_length=50)
    v_min: str = Field(default="", max_length=100)
    v_max: str = Field(default="", max_length=100)
    below: str = Field(default="", max_length=100)
    above: str = Field(default="", max_length=100)
    only_vulnerable: bool = False
    only_eol: bool = False


class ScopeIn(BaseModel):
    kind: Literal["all", "sources", "zones", "groups", "custom"] = "custom"
    sources: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    zones: list[str] = Field(default_factory=list, max_length=100)
    group: str = Field(default="", max_length=200)
    text: str = Field(default="", max_length=20000)
    exclude: str = Field(default="", max_length=5000)
    active_days: int | None = Field(default=None, ge=1, le=3650)


class CriteriaIn(BaseModel):
    cves: list[str] = Field(default_factory=list, max_length=20)
    products: list[ProductIn] = Field(default_factory=list, max_length=20)


class PreviewIn(CriteriaIn):
    scope: ScopeIn = Field(default_factory=ScopeIn)
    ports: str = Field(default="", max_length=500)


class HuntIn(PreviewIn):
    title: str = Field(default="", max_length=200)
    logic: Literal["any", "all"] = "any"
    mode: Literal["ksc", "network", "combined"] = "combined"
    force: bool = False
    confirm_scope: bool = False
    confirm_large: bool = False
    base_job_id: uuid.UUID | None = None


def _prod(p: ProductIn) -> dict:
    d = p.model_dump()
    d["source_id"] = str(p.source_id) if p.source_id else ""
    return d


async def _job(db: AsyncSession, job_id: uuid.UUID) -> PtJob:
    j = await db.get(PtJob, job_id)
    if j is None or j.profile != "hunt":
        raise HTTPException(status_code=404, detail="Задание не найдено")
    return j


async def _activity(request: Request, db: AsyncSession) -> int:
    return (await request.app.state.settings_svc.get(db, "general")).activity_days


@router.get("/options")
async def options(request: Request, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Источники, зоны и подсказки для мастера."""
    s = await request.app.state.settings_svc.get(db, "pentest")
    srcs = [{"id": str(x.id), "name": x.name} for x in (await db.execute(select(KscSource).where(KscSource.is_active.is_(True)).order_by(KscSource.position))).scalars() if su.can_use_source(x.id)]
    return {"sources": srcs, "zones": await SC.zone_options(db), "hunt_networks": s.hunt_networks if su.is_admin else None, "enabled": s.enabled,
            "products": [{"key": k, "title": v["title"], "ports": v["ports"]} for k, v in KB.KB.items()]}


@router.get("/suggest")
async def suggest(q: str = Query("", max_length=100), su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Автоподстановка: CVE по идентификатору, названию и описанию; продукты каталога программ и известные продукты."""
    q = q.strip()
    if len(q) < 2:
        return {"cves": [], "products": []}
    cond = any_of(q, VdbVuln.vuln_key, VdbVuln.title, VdbVuln.description, VdbVuln.products_text)
    cves = (await db.execute(select(VdbVuln.vuln_key, VdbVuln.title, VdbVuln.sev_rank, VdbVuln.exploited).where(cond).order_by(VdbVuln.exploited.desc(), VdbVuln.sev_rank.desc(), VdbVuln.published.desc()).limit(10))).all() if cond is not None else []
    like = f"%{q.lower().replace('%', '').replace('_', '')}%"
    cat = (await db.execute(select(CatalogProduct.source_id, CatalogProduct.key, CatalogProduct.name, func.max(CatalogProduct.hosts_active)).where(func.lower(CatalogProduct.search).like(like)).group_by(CatalogProduct.source_id, CatalogProduct.key, CatalogProduct.name)
                            .order_by(func.max(CatalogProduct.hosts_active).desc()).limit(40))).all()
    prods, seen = [], set()
    for k, v in KB.KB.items():
        if q.lower() in v["title"].lower() or q.lower() in k:
            prods.append({"name": v["title"], "kb": k, "source_id": "", "product_key": "", "hosts": None})
    for sid, key, name, hosts in cat:
        if su.can_use_source(sid) and name.lower() not in seen:
            seen.add(name.lower())
            prods.append({"name": name, "kb": KB.kb_for_text(name) or "", "source_id": str(sid), "product_key": key, "hosts": int(hosts or 0)})
    return {"cves": [{"id": r.vuln_key, "title": r.title, "sev": r.sev_rank, "exploited": r.exploited} for r in cves], "products": prods[:12]}


@router.post("/resolve")
async def resolve(body: CriteriaIn, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    try:
        return {"criteria": await HS.resolve(db, body.cves, [_prod(p) for p in body.products])}
    except HS.HuntError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@router.post("/preview")
async def preview(body: PreviewIn, request: Request, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    s = await request.app.state.settings_svc.get(db, "pentest")
    try:
        crits = await HS.resolve(db, body.cves, [_prod(p) for p in body.products])
        return await HS.preview(db, crits, body.scope.model_dump(mode="json"), body.ports, s, su.can_use_source, await _activity(request, db))
    except (HS.HuntError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except Exception as exc:  # noqa: BLE001 — ошибки цели (область разрешений) — сообщением оператору
        if type(exc).__name__ in ("TargetError", "NmapError", "JobError"):
            raise HTTPException(status_code=422, detail=str(exc)) from None
        raise


@router.post("/jobs", status_code=201)
async def create(body: HuntIn, request: Request, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    s = await request.app.state.settings_svc.get(db, "pentest")
    try:
        crits = await HS.resolve(db, body.cves, [_prod(p) for p in body.products])
        job = await HS.create(db, request.app, title=body.title, crits=crits, logic=body.logic, mode=body.mode, scope=body.scope.model_dump(mode="json"), extra_ports=body.ports, force=body.force,
                              confirm_scope=body.confirm_scope, confirm_large=body.confirm_large, user=su, base_job_id=body.base_job_id, settings=s, allowed=su.can_use_source, activity_days=await _activity(request, db))
    except (HS.HuntError, ValueError, S.JobError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except Exception as exc:  # noqa: BLE001
        if type(exc).__name__ in ("TargetError", "NmapError"):
            raise HTTPException(status_code=422, detail=str(exc)) from None
        raise
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="hunt.create", target_type="pentest_job", target_id=str(job.id),
                details={"title": job.title, "mode": body.mode, "criteria": [c["key"] for c in crits], "targets": job.targets_n, "logic": body.logic})
    await db.commit()
    return R.job_out(job, full=True)


@router.get("/jobs")
async def jobs(offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), q: str = Query("", max_length=200), su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    w = [PtJob.profile == "hunt"]
    if q:
        cond = any_of(q, PtJob.title, PtJob.created_by)
        if cond is not None:
            w.append(cond)
    total = int((await db.execute(select(func.count()).select_from(PtJob).where(*w))).scalar_one())
    rows = (await db.execute(select(PtJob).where(*w).order_by(PtJob.created_at.desc()).offset(offset).limit(limit))).scalars().all()
    counts: dict = {}
    if rows:
        for jid, st, n in (await db.execute(select(HuntHit.job_id, HuntHit.status, func.count()).where(HuntHit.job_id.in_([r.id for r in rows])).group_by(HuntHit.job_id, HuntHit.status))).all():
            counts.setdefault(jid, {})[st] = n
    out = []
    for j in rows:
        h = (j.options or {}).get("hunt", {})
        out.append({**R.job_out(j), "mode": h.get("mode"), "logic": h.get("logic"), "criteria": [{"key": c["key"], "title": c["title"]} for c in h.get("criteria", [])], "counts": counts.get(j.id, {})})
    return {"items": out, "total": total, "offset": offset, "limit": limit}


@router.get("/jobs/{job_id}")
async def get_job(job_id: uuid.UUID, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    j = await _job(db, job_id)
    out = R.job_out(j, full=True)
    h = (j.options or {}).get("hunt", {})
    cnt = {k: n for k, n in (await db.execute(select(HuntHit.status, func.count()).where(HuntHit.job_id == job_id).group_by(HuntHit.status))).all()}
    out.update({"events": await R.events(db, job_id), "log": await R.log_counts(db, job_id), "hunt": {"mode": h.get("mode"), "logic": h.get("logic"), "ports": h.get("ports", []), "scope": h.get("scope", {}),
                "criteria": [{k: c.get(k) for k in ("key", "kind", "title", "cve", "product", "mode", "versions", "v_min", "v_max", "below", "above", "ports", "warnings", "kb")} | {"condition": C.describe_condition(c), "checks": [x["id"] for x in c.get("checks", [])]} for c in h.get("criteria", [])],
                "counts": {k: cnt.get(k, 0) for k in RS.RANK}, "checked": j.hosts_done, "total": j.targets_n}})
    return out


@router.get("/jobs/{job_id}/results")
async def results(job_id: uuid.UUID, status: str = Query("confirmed,probable,needs_check", max_length=80), q: str = Query("", max_length=200), basis: str = Query("", max_length=40), crit: str = Query("", max_length=80),
                  zone: str = Query("", max_length=120), sort: str = Query("status", pattern="^(status|host|ip|user|zone|product|version)$"), desc: bool = False, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500),
                  su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    await _job(db, job_id)
    r = await RS.page(db, job_id, status=status, q=q, basis=basis, crit=crit, zone=zone, sort=sort, desc=desc, offset=offset, limit=limit)
    r["zones"] = await RS.zones_of(db, job_id)
    return r


@router.get("/jobs/{job_id}/results/{hit_id}")
async def result_detail(job_id: uuid.UUID, hit_id: int, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    await _job(db, job_id)
    h = await db.get(HuntHit, hit_id)
    if h is None or h.job_id != job_id:
        raise HTTPException(status_code=404, detail="Запись не найдена")
    return RS.hit_out(h, full=True)


@router.get("/jobs/{job_id}/coverage")
async def coverage(job_id: uuid.UUID, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500), su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Охват проверки: все адреса задания и итог по каждому (журнал охвата)."""
    await _job(db, job_id)
    total = int((await db.execute(select(func.count()).select_from(PtHost).where(PtHost.job_id == job_id))).scalar_one())
    rows = (await db.execute(select(PtHost).where(PtHost.job_id == job_id).order_by(PtHost.ip).offset(offset).limit(limit))).scalars().all()
    return {"items": [{"ip": h.ip, "state": h.state, "ports": h.ports_n, "error": h.error, "stage": h.error_stage, "notes": h.notes or []} for h in rows], "total": total}


@router.get("/jobs/{job_id}/compare")
async def compare(job_id: uuid.UUID, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    j = await _job(db, job_id)
    return await RS.compare(db, j)


@router.post("/jobs/{job_id}/repeat", status_code=201)
async def repeat(job_id: uuid.UUID, request: Request, force: bool = False, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Повторная проверка с теми же критериями и областью; сравнение с прежней — `GET /hunt/jobs/{id}/compare`."""
    j = await _job(db, job_id)
    h = (j.options or {}).get("hunt", {})
    s = await request.app.state.settings_svc.get(db, "pentest")
    try:
        crits = await HS.resolve(db, [c["cve"] for c in h["criteria"] if c["kind"] == "cve"], [{k: c.get(k) for k in ("name", "kb", "mode", "versions", "v_min", "v_max", "below", "above", "only_vulnerable", "only_eol")} | {"name": c["product"]} for c in h["criteria"] if c["kind"] == "product"])
        job = await HS.create(db, request.app, title=f"{j.title} (повтор)", crits=crits, logic=h["logic"], mode=h["mode"], scope=h["scope"], extra_ports="", force=force, confirm_scope=True, confirm_large=True, user=su,
                              base_job_id=j.id, settings=s, allowed=su.can_use_source, activity_days=await _activity(request, db))
    except (HS.HuntError, ValueError, S.JobError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="hunt.repeat", target_type="pentest_job", target_id=str(job.id), details={"base": str(j.id)})
    await db.commit()
    _ = or_, utcnow
    return R.job_out(job, full=True)
