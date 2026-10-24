"""База уязвимостей: состояние и настройки источников (админ), поиск и карточка уязвимости, находки по инфраструктуре, решения по сопоставлению продуктов.

Загрузка данных выполняется воркером по расписанию; API только ставит запрос на запуск и показывает состояние. Проверка инфраструктуры — быстрый отчёт `quick_extvulns`."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import case, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, current_source, get_db, require_admin, require_analyst, require_user
from ..models import CatalogProduct, KscSource, VdbAffected, VdbFinding, VdbMapping, VdbRecord, VdbRun, VdbSource, VdbVuln, utcnow
from ..services.audit import write_audit
from ..vdb import match as M
from ..vdb import sources as S
from ..vdb import store
from ..vdb.normalize import SEV_RANK, SEV_RU, norm
from ..reports.quick_ext import like_escape
from ..vdb.sync import analyze, upload_path

router = APIRouter(prefix="/vdb", tags=["vdb"])
ECOSYSTEMS = ("Debian", "Ubuntu", "Alpine", "AlmaLinux", "Rocky Linux", "Red Hat", "SUSE", "openSUSE", "Mageia", "Chainguard", "Wolfi")
MAX_UPLOAD = 400 * 1024 * 1024


def _iso(d: datetime | None) -> str | None:
    return (d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)).isoformat() if d else None


# ------------------------------------------------------------------------------------------------ источники
def source_out(r: VdbSource, runs: list[VdbRun] | None = None) -> dict:
    info = S.INFO[r.key]
    st = dict(r.settings or {})
    return {"key": r.key, "title": info["title"], "url": info["url"], "terms": info["terms"], "mode": info["mode"], "enabled": r.enabled, "interval_hours": r.interval_hours,
            "settings": st, "secret_set": bool(r.secret_enc), "status": r.status, "progress": r.progress, "last_started_at": _iso(r.last_started_at), "last_ok_at": _iso(r.last_ok_at),
            "last_duration_ms": r.last_duration_ms, "last_error": r.last_error, "records": r.records, "requested": r.requested_at is not None, "can_restore": r.prev_generation is not None,
            "upload": r.key == "bdu", "runs": [{"started_at": _iso(x.started_at), "finished_at": _iso(x.finished_at), "trigger": x.trigger, "status": x.status, "fetched": x.fetched,
                                                "changed": x.changed, "duration_ms": x.duration_ms, "error": x.error} for x in (runs or [])]}


@router.get("/sources")
async def sources(su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(VdbSource).order_by(VdbSource.key))).scalars().all()
    out = []
    for r in rows:
        if r.key not in S.INFO:
            continue
        runs = (await db.execute(select(VdbRun).where(VdbRun.source == r.key).order_by(VdbRun.id.desc()).limit(8))).scalars().all()
        out.append(source_out(r, list(runs)))
    total = int((await db.execute(select(func.count()).select_from(VdbVuln))).scalar_one())
    return {"items": out, "vulns": total, "ecosystems": list(ECOSYSTEMS)}


class SourceIn(BaseModel):
    enabled: bool | None = None
    interval_hours: int | None = Field(default=None, ge=1, le=24 * 30)
    settings: dict | None = None
    api_key: str | None = Field(default=None, max_length=200)      # NVD: None — не менять, "" — удалить


def _clean_settings(key: str, cur: dict, new: dict) -> dict:
    out = dict(cur)
    if key == "nvd" and "history_days" in new:
        out["history_days"] = max(7, min(3650, int(new["history_days"])))
    if key == "osv":
        if "ecosystems" in new:
            out["ecosystems"] = [e for e in new["ecosystems"] if e in ECOSYSTEMS][:10]
        if "enrich" in new:
            out["enrich"] = bool(new["enrich"])
        if "max_per_run" in new:
            out["max_per_run"] = max(10, min(3000, int(new["max_per_run"])))
    if key == "bdu":
        if "url" in new:
            u = str(new["url"]).strip()
            if not u.lower().startswith("https://") or len(u) > 400:
                raise HTTPException(status_code=422, detail="Адрес выгрузки БДУ должен начинаться с https://")
            out["url"] = u
        if "verify_tls" in new:
            out["verify_tls"] = bool(new["verify_tls"])
    if key == "kev" and "url" in new and str(new["url"]).strip():
        u = str(new["url"]).strip()
        if not u.lower().startswith("https://"):
            raise HTTPException(status_code=422, detail="Адрес каталога KEV должен начинаться с https://")
        out["url"] = u
    return out


@router.put("/sources/{key}")
async def update_source(key: str, body: SourceIn, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.get(VdbSource, key)
    if r is None or key not in S.INFO:
        raise HTTPException(status_code=404, detail="Источник не найден")
    changed = []
    if body.enabled is not None and body.enabled != r.enabled:
        r.enabled = body.enabled
        changed.append("enabled")
    if body.interval_hours is not None:
        r.interval_hours = body.interval_hours
        changed.append("interval_hours")
    if body.settings is not None:
        r.settings = _clean_settings(key, r.settings or {}, body.settings)
        changed.append("settings")
    if body.api_key is not None and key == "nvd":
        r.secret_enc = request.app.state.settings_svc.encrypt(body.api_key, f"vdb.{key}") if body.api_key else None
        changed.append("api_key")
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="vdb.source.update", target_type="vdb_source", target_id=key, details={"changed": changed})
    await db.commit()
    return source_out(r)


@router.post("/sources/{key}/sync", status_code=202)
async def sync_source(key: str, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.get(VdbSource, key)
    if r is None or key not in S.INFO:
        raise HTTPException(status_code=404, detail="Источник не найден")
    if r.status == "running":
        raise HTTPException(status_code=409, detail="Загрузка уже выполняется")
    r.requested_at = utcnow()
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="vdb.source.sync", target_type="vdb_source", target_id=key)
    await db.commit()
    return {"requested": True}


@router.post("/sources/{key}/restore")
async def restore_source(key: str, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    r = await db.get(VdbSource, key)
    if r is None or key not in S.INFO:
        raise HTTPException(status_code=404, detail="Источник не найден")
    try:
        keys = await store.restore_previous(db, r)
    except store.IntegrityError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    await store.refresh_vulns(db, keys)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="vdb.source.restore", target_type="vdb_source", target_id=key)
    await db.commit()
    return source_out(r)


@router.post("/sources/bdu/upload", status_code=202)
async def upload_bdu(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Загрузка выгрузки БДУ вручную (XML или ZIP) — когда сервер не может скачать её сам. Тело запроса — содержимое файла."""
    r = await db.get(VdbSource, "bdu")
    if r is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    if r.status == "running":
        raise HTTPException(status_code=409, detail="Загрузка уже выполняется")
    path = upload_path(request.app.state.settings, "bdu")
    size = 0
    with path.open("wb") as f:
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_UPLOAD:
                f.close()
                path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="Файл больше допустимого размера")
            f.write(chunk)
    if size < 100:
        path.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail="Файл пуст")
    r.requested_at = utcnow()
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="vdb.source.upload", target_type="vdb_source", target_id="bdu", details={"bytes": size})
    await db.commit()
    return {"requested": True, "bytes": size}


# ------------------------------------------------------------------------------------------------ поиск
def _vuln_out(v: VdbVuln, f: VdbFinding | None = None) -> dict:
    out = {"key": v.vuln_key, "title": v.title, "severity": next((k for k, r in SEV_RANK.items() if r == v.sev_rank), ""), "severity_ru": SEV_RU[next((k for k, r in SEV_RANK.items() if r == v.sev_rank), "")],
           "sev_rank": v.sev_rank, "score": v.score, "exploited": v.exploited, "has_fix": v.has_fix, "published": _iso(v.published), "modified": _iso(v.modified),
           "sources": [s for s in v.sources.split(",") if s], "ids": [i.upper() for i in v.ids_text.split()][:8], "products": v.products_text.split("; ")[:6] if v.products_text else [],
           "description": v.description[:400]}
    if f is not None:
        out["finding"] = {"status": f.status, "status_ru": M.STATUS_RU.get(f.status, f.status), "installs": f.installs, "hosts_max": f.hosts_max, "new": f.seen_at is None,
                          "first_seen_at": _iso(f.first_seen_at), "products": f.products[:5]}
    return out


@router.get("/vulns")
async def vulns(q: str = Query("", max_length=200), min_severity: str = Query("", pattern=r"^(|critical|high|medium|low)$"), exploited: bool = False, has_fix: bool | None = None,
                source: str = Query("", pattern=r"^(|nvd|kev|osv|bdu)$"), published_from: str = Query("", max_length=10), published_to: str = Query("", max_length=10),
                modified_from: str = Query("", max_length=10), affects: bool = False,
                sort: str = Query("priority", pattern=r"^(priority|published|modified|score|key)$"), desc: bool = True, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Поиск по CVE, идентификатору БДУ/OSV, названию и производителю программы, версии и тексту описания; по умолчанию — подтверждённая эксплуатация и самые опасные сверху."""
    sid = su.current_source_id
    stmt = select(VdbVuln, VdbFinding).outerjoin(VdbFinding, (VdbFinding.vuln_key == VdbVuln.vuln_key) & (VdbFinding.source_id == sid))     # sid=None: соединение пусто
    for term in q.lower().split()[:6]:
        like = "%" + like_escape(term) + "%"
        stmt = stmt.where(or_(VdbVuln.ids_text.like(like, escape="\\"), func.lower(VdbVuln.title).like(like, escape="\\"), VdbVuln.products_text.like(like, escape="\\"), func.lower(VdbVuln.description).like(like, escape="\\")))
    if min_severity:
        stmt = stmt.where(VdbVuln.sev_rank >= SEV_RANK[min_severity])
    if exploited:
        stmt = stmt.where(VdbVuln.exploited.is_(True))
    if has_fix is not None:
        stmt = stmt.where(VdbVuln.has_fix.is_(True) if has_fix else or_(VdbVuln.has_fix.is_(False), VdbVuln.has_fix.is_(None)))
    if source:
        stmt = stmt.where(VdbVuln.sources.like(f"%{source}%"))
    for col, val, op in ((VdbVuln.published, published_from, ">="), (VdbVuln.published, published_to, "<="), (VdbVuln.modified, modified_from, ">=")):
        if val:
            try:
                d = datetime.fromisoformat(val).replace(tzinfo=timezone.utc)
            except ValueError:
                raise HTTPException(status_code=422, detail="Дата должна быть в формате ГГГГ-ММ-ДД") from None
            stmt = stmt.where(col >= d if op == ">=" else col < d.replace(hour=23, minute=59, second=59))
    if affects:
        if not sid:
            raise HTTPException(status_code=409, detail="Источник KSC не выбран")
        stmt = stmt.where(VdbFinding.vuln_key.is_not(None))
    total = int((await db.execute(select(func.count()).select_from(stmt.order_by(None).subquery()))).scalar_one())
    d = (lambda c: c.desc()) if desc else (lambda c: c.asc())
    order = {"priority": [VdbVuln.exploited.desc(), VdbVuln.sev_rank.desc(), VdbVuln.published.desc()], "published": [d(VdbVuln.published)], "modified": [d(VdbVuln.modified)],
             "score": [d(VdbVuln.score)], "key": [d(VdbVuln.vuln_key)]}[sort]
    rows = (await db.execute(stmt.order_by(*order, VdbVuln.vuln_key).offset(offset).limit(limit))).all()
    items = [_vuln_out(v, f if isinstance(f, VdbFinding) else None) for v, f in rows]
    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.get("/vulns/{key}")
async def vuln_card(key: str, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Общая карточка: сводка, данные каждого источника отдельно, различия между источниками, затронутые продукты и сопоставление с каталогом выбранного источника KSC."""
    from ..reports.quick_ext import resolve_keys  # noqa: PLC0415

    found, _ = await resolve_keys(db, [key])
    if not found:
        raise HTTPException(status_code=404, detail="Уязвимость не найдена в локальной базе")
    k = found[0]
    v = await db.get(VdbVuln, k)
    recs = (await db.execute(select(VdbRecord).join(VdbSource, store.active(VdbRecord)).where(VdbRecord.vuln_key == k))).scalars().all()
    affs = (await db.execute(select(VdbAffected).join(VdbSource, store.active(VdbAffected)).where(VdbAffected.vuln_key == k).limit(600))).scalars().all()
    by_src: dict[str, list] = {}
    for a in affs:
        by_src.setdefault(a.source, []).append({"vendor": a.vendor, "product": a.product or a.pkg_name, "ecosystem": a.ecosystem, "cpe": a.cpe, "purl": a.purl, "platform": a.platform,
                                                 "exact": a.exact, "from": a.v_start, "from_incl": a.v_start_incl, "to": a.v_end, "to_incl": a.v_end_incl, "fixed": a.fixed, "all_versions": a.versions_all,
                                                 "version_text": a.version_text, "conditional": a.conditional})
    records = [{"source": r.source, "title": S.INFO[r.source]["title"], "ext_id": r.ext_id, "aliases": r.aliases, "severity": r.severity, "severity_ru": SEV_RU.get(r.severity, ""), "score": r.score,
                "vector": r.vector, "published": _iso(r.published), "modified": _iso(r.modified), "exploited": r.exploited, "fix_available": r.fix_available, "fix_text": r.fix_text,
                "status": r.status, "title_text": r.title, "description": r.description, "refs": r.refs[:25], "extra": r.extra, "affected": by_src.get(r.source, [])[:150],
                "affected_total": len(by_src.get(r.source, []))} for r in sorted(recs, key=lambda r: S.INFO[r.source]["title"])]
    diffs = []
    for field, label in (("severity", "Уровень опасности"), ("score", "Оценка CVSS")):
        vals = {r["source"]: (r["severity_ru"] if field == "severity" else r["score"]) for r in records if (r[field] not in (None, ""))}
        if len(set(vals.values())) > 1:
            diffs.append({"field": label, "values": vals})
    fixes = {r["source"]: r["fix_available"] for r in records if r["fix_available"] is not None}
    if len(set(fixes.values())) > 1:
        diffs.append({"field": "Наличие исправления", "values": {s: ("есть" if x else "нет") for s, x in fixes.items()}})
    sid = su.current_source_id
    infra = None
    if sid:
        prods, maps = await M.load_context(db, sid)
        if prods:
            ms = M.matches_from(M.Matcher(prods, maps), await M.affected_for(db, [k]), only_active=False)
            infra = {"catalog": True, "matches": sorted(({"product_key": m.product_key, "product": m.product_name, "version": m.version, "status": m.status, "status_ru": M.STATUS_RU[m.status],
                                                         "basis": m.basis, "confidence": m.confidence, "hosts": m.hosts_active, "installs": m.installs_active,
                                                         "claims": [{"source": c.source, "status_ru": M.STATUS_RU[c.status], "basis": c.basis} for c in m.claims]} for m in ms),
                                                        key=lambda x: (-M.STATUS_RANK[x["status"]], -x["installs"]))[:300]}
        else:
            infra = {"catalog": False, "matches": []}
    return {**_vuln_out(v), "description": v.description, "records": records, "differences": diffs, "infrastructure": infra}


# ------------------------------------------------------------------------------------------------ находки для специалиста ИБ
@router.get("/findings")
async def findings(new_only: bool = False, min_severity: str = Query("", pattern=r"^(|critical|high|medium|low)$"), exploited: bool = False,
                   offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source),
                   db: AsyncSession = Depends(get_db)):
    """Уязвимости из внешних баз, потенциально затрагивающие установленное ПО выбранного источника KSC (оценка по каталогу): новые и ранее просмотренные."""
    stmt = select(VdbFinding, VdbVuln).join(VdbVuln, VdbVuln.vuln_key == VdbFinding.vuln_key).where(VdbFinding.source_id == src.id)
    if new_only:
        stmt = stmt.where(VdbFinding.seen_at.is_(None))
    if min_severity:
        stmt = stmt.where(VdbVuln.sev_rank >= SEV_RANK[min_severity])
    if exploited:
        stmt = stmt.where(VdbVuln.exploited.is_(True))
    total = int((await db.execute(select(func.count()).select_from(stmt.order_by(None).subquery()))).scalar_one())
    rows = (await db.execute(stmt.order_by(VdbVuln.exploited.desc(), VdbVuln.sev_rank.desc(), VdbFinding.first_seen_at.desc()).offset(offset).limit(limit))).all()
    counts = await finding_counts(db, src.id)
    return {"items": [_vuln_out(v, f) for f, v in rows], "total": total, "offset": offset, "limit": limit, "summary": counts}


async def finding_counts(db: AsyncSession, source_id: uuid.UUID) -> dict:
    new = VdbFinding.seen_at.is_(None)
    c = lambda cond: func.coalesce(func.sum(case((cond, 1), else_=0)), 0)  # noqa: E731
    r = (await db.execute(select(func.count(), c(new), c(new & VdbFinding.exploited.is_(True)), c(new & (VdbFinding.sev_rank >= 4)),
                                 c(new & (VdbFinding.exploited.is_(True) | (VdbFinding.sev_rank >= 3)))).where(VdbFinding.source_id == source_id))).one()
    return dict(zip(("total", "new", "new_exploited", "new_critical", "new_serious"), (int(x) for x in r)))


@router.get("/findings/summary")
async def findings_summary(su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    return await finding_counts(db, src.id)


class SeenIn(BaseModel):
    keys: list[str] = Field(default_factory=list, max_length=500)
    all: bool = False


@router.post("/findings/seen")
async def mark_seen(body: SeenIn, su: SessionUser = Depends(require_analyst), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    stmt = update(VdbFinding).where(VdbFinding.source_id == src.id, VdbFinding.seen_at.is_(None))
    if not body.all:
        if not body.keys:
            raise HTTPException(status_code=422, detail="Выберите уязвимости")
        stmt = stmt.where(VdbFinding.vuln_key.in_(body.keys))
    await db.execute(stmt.values(seen_at=utcnow(), seen_by=su.display_name))
    await db.commit()
    return await finding_counts(db, src.id)


# ------------------------------------------------------------------------------------------------ каталог программ, карточка компьютера
@router.get("/catalog-counts")
async def catalog_counts(request: Request, keys: str = Query("", max_length=4000), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Число известных уязвимостей (по внешним базам) для продуктов каталога: по находкам источника KSC. Подтверждённые KSC уязвимости — отдельно, в разделе «Уязвимости»."""
    want = [k for k in keys.split(",") if k][:200]
    rev = await store.revision(db, src.id)

    async def make() -> dict:
        out: dict[str, dict] = {}
        for f, v in (await db.execute(select(VdbFinding, VdbVuln).join(VdbVuln, VdbVuln.vuln_key == VdbFinding.vuln_key).where(VdbFinding.source_id == src.id))).all():
            for p in f.products:
                c = out.setdefault(p["key"], {"total": 0, "kev": 0, "critical": 0, "confirmed": 0})
                c["total"] += 1
                c["kev"] += 1 if v.exploited else 0
                c["critical"] += 1 if v.sev_rank >= 4 else 0
                c["confirmed"] += 1 if f.status == "confirmed" else 0
        return out

    allc, _ = await request.app.state.cache.get((str(src.id), "vdb_counts", rev), request.app.state.settings.cache_ttl_seconds, make)
    return {"items": {k: allc.get(k, {"total": 0, "kev": 0, "critical": 0, "confirmed": 0}) for k in want}}


@router.get("/products/{key:path}")
async def product_vulns(key: str, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source),
                        db: AsyncSession = Depends(get_db)):
    """Известные уязвимости продукта каталога (по внешним базам) для установленных версий выбранного источника KSC."""
    rows = (await db.execute(select(VdbFinding, VdbVuln).join(VdbVuln, VdbVuln.vuln_key == VdbFinding.vuln_key).where(VdbFinding.source_id == src.id)
                             .order_by(VdbVuln.exploited.desc(), VdbVuln.sev_rank.desc()))).all()
    sel = [(f, v) for f, v in rows if any(p["key"] == key for p in f.products)]
    return {"items": [{**_vuln_out(v, f), "versions": next((p["versions"] for p in f.products if p["key"] == key), [])} for f, v in sel[offset:offset + limit]], "total": len(sel)}


@router.get("/hosts/{host_id}")
async def host_vulns(host_id: int, request: Request, su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Независимая проверка компьютера: установленное ПО компьютера (записи реестра KSC) сопоставляется с внешними базами. Результат — потенциальные уязвимости, не подтверждённые KSC."""
    from ..ksc import queries as q  # noqa: PLC0415

    client = request.app.state.sources.client(src)
    soft = await client.run(q.SOFTWARE_ON_HOST, {"id": host_id}, max_rows=20_000)
    ids = {int(s["product_id"]) for s in soft}
    prods, maps = await M.load_context(db, src.id)
    mine = [p for p in prods if any(set(v.get("product_ids") or []) & ids for v in p.versions)]
    if not mine:
        return {"items": [], "catalog": bool(prods)}
    for p in mine:
        p.versions = [v for v in p.versions if set(v.get("product_ids") or []) & ids]
    affs = await M.reverse_affected(db, mine, maps)
    ms = [m for m in M.matches_from(M.Matcher(mine, maps), affs, only_active=False) if m.status in M.AFFECTED]
    meta = {v.vuln_key: v for i in range(0, len(ms), 400) for v in (await db.execute(select(VdbVuln).where(VdbVuln.vuln_key.in_({m.vuln_key for m in ms[i:i + 400]})))).scalars().all()}
    items = [{"key": m.vuln_key, "title": meta[m.vuln_key].title if m.vuln_key in meta else "", "severity_ru": SEV_RU[next((k for k, r in SEV_RANK.items() if r == (meta[m.vuln_key].sev_rank if m.vuln_key in meta else 0)), "")],
              "sev_rank": meta[m.vuln_key].sev_rank if m.vuln_key in meta else 0, "exploited": bool(meta.get(m.vuln_key) and meta[m.vuln_key].exploited), "product": m.product_name, "version": m.version,
              "status": m.status, "status_ru": M.STATUS_RU[m.status], "basis": m.basis} for m in ms]
    items.sort(key=lambda x: (not x["exploited"], -x["sev_rank"], -M.STATUS_RANK[x["status"]]))
    return {"items": items[:500], "total": len(items), "catalog": True}


# ------------------------------------------------------------------------------------------------ решения по сопоставлению
class MappingIn(BaseModel):
    vendor_key: str = Field(default="", max_length=200)
    product: str = Field(min_length=1, max_length=300)
    catalog_key: str = Field(min_length=1, max_length=160)
    action: str = Field(default="map", pattern=r"^(map|exclude)$")
    note: str | None = Field(default=None, max_length=500)


@router.get("/mappings")
async def mappings(su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(VdbMapping).order_by(VdbMapping.created_at.desc()))).scalars().all()
    return {"items": [{"id": str(m.id), "vendor_key": m.vendor_key, "product_key": m.product_key, "catalog_key": m.catalog_key, "action": m.action, "note": m.note, "created_by": m.created_by,
                       "created_at": _iso(m.created_at)} for m in rows]}


@router.post("/mappings", status_code=201)
async def add_mapping(body: MappingIn, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Решение администратора: считать продукт из базы уязвимостей (производитель + название) продуктом каталога либо исключить ложное совпадение. Сохраняется при обновлении базы и приложения."""
    m = VdbMapping(vendor_key=norm(body.vendor_key), product_key=norm(body.product), catalog_key=body.catalog_key, action=body.action, note=body.note, created_by=su.display_name)
    db.add(m)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="vdb.mapping.add", target_type="vdb_mapping", target_id=str(m.id), details={"product": m.product_key, "catalog": m.catalog_key, "action": m.action})
    await db.flush()
    if su.current_source_id:      # находки выбранного источника пересчитываются сразу, остальных — фоновой службой
        await analyze(db, su.current_source_id, keys=None)
    await db.commit()
    return {"id": str(m.id)}


@router.delete("/mappings/{mid}", status_code=204)
async def delete_mapping(mid: uuid.UUID, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    r = await db.execute(delete(VdbMapping).where(VdbMapping.id == mid))
    if not r.rowcount:
        raise HTTPException(status_code=404, detail="Решение не найдено")
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="vdb.mapping.delete", target_type="vdb_mapping", target_id=str(mid))
    if su.current_source_id:
        await analyze(db, su.current_source_id, keys=None)
    await db.commit()


@router.get("/suggest-products")
async def suggest(q: str = Query("", max_length=100), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Подсказка продуктов каталога для ручного сопоставления."""
    stmt = select(CatalogProduct.key, CatalogProduct.name, CatalogProduct.publisher).where(CatalogProduct.source_id == src.id).order_by(CatalogProduct.hosts_active.desc()).limit(15)
    if q.strip():
        stmt = stmt.where(CatalogProduct.search.like(f"%{q.strip().lower()}%"))
    return {"items": [{"key": k, "name": n, "publisher": p} for k, n, p in (await db.execute(stmt)).all()]}

