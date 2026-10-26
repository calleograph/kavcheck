"""База уязвимостей: состояние и настройки источников (админ), поиск и карточка уязвимости, находки по инфраструктуре, решения по сопоставлению продуктов.

Загрузка данных выполняется воркером по расписанию; API только ставит запрос на запуск и показывает состояние. Проверка инфраструктуры — быстрый отчёт `quick_extvulns`."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import case, delete, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, current_source, get_db, require_admin, require_analyst, require_user
from ..models import CatalogProduct, KscSource, VdbAffected, VdbFinding, VdbMapping, VdbRecord, VdbRun, VdbSource, VdbVuln, utcnow
from ..services.audit import write_audit
from ..vdb import match as M
from ..vdb import sources as S
from ..vdb import store
from ..vdb.normalize import SEV_RANK, SEV_RU, norm, pick_primary, score_key
from ..search import clean, is_mask, local_like
from ..services.catalog import text_conds
from ..vdb.sync import analyze, upload_path

router = APIRouter(prefix="/vdb", tags=["vdb"])
ECOSYSTEMS = S.OSV_ECOSYSTEMS
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
            "upload": r.key == "bdu", "channel": r.channel, "channels": info["channels"], "attempts": r.diag or [],
            "runs": [{"started_at": _iso(x.started_at), "finished_at": _iso(x.finished_at), "trigger": x.trigger, "status": x.status, "fetched": x.fetched, "changed": x.changed,
                      "duration_ms": x.duration_ms, "error": x.error, "channel": x.channel, "attempts": x.attempts or []} for x in (runs or [])]}


@router.get("/sources")
async def sources(request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(VdbSource).order_by(VdbSource.key))).scalars().all()
    out = []
    for r in rows:
        if r.key not in S.INFO:
            continue
        runs = (await db.execute(select(VdbRun).where(VdbRun.source == r.key).order_by(VdbRun.id.desc()).limit(8))).scalars().all()
        out.append(source_out(r, list(runs)))
    total = int((await db.execute(select(func.count()).select_from(VdbVuln))).scalar_one())
    return {"items": out, "vulns": total, "ecosystems": list(ECOSYSTEMS), "storage": await _storage(db, request)}


async def _storage(db: AsyncSession, request: Request) -> dict:
    """Занятое место: таблицы базы уязвимостей (PostgreSQL), временные файлы загрузок, свободно на томе данных."""
    import shutil  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    data = Path(request.app.state.settings.data_dir)
    db_bytes = None
    if db.bind.dialect.name == "postgresql":
        db_bytes = int((await db.execute(text("SELECT COALESCE(SUM(pg_total_relation_size(c.oid)), 0) FROM pg_class c WHERE c.relkind = 'r' AND c.relname LIKE 'vdb\\_%'"))).scalar_one())
    tmp = data / "vdb" / "tmp"
    tmp_bytes = sum(f.stat().st_size for f in tmp.rglob("*") if f.is_file()) if tmp.is_dir() else 0
    return {"db_bytes": db_bytes, "tmp_bytes": tmp_bytes, "free_bytes": shutil.disk_usage(data).free}


@router.post("/sync-all", status_code=202)
async def sync_all(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """«Обновить все сейчас»: ставит в очередь все включённые источники, которые не загружаются в данный момент."""
    rows = (await db.execute(select(VdbSource).where(VdbSource.enabled.is_(True)))).scalars().all()
    queued = []
    for r in rows:
        if r.key in S.INFO and r.status != "running":
            r.requested_at = utcnow()
            queued.append(r.key)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="vdb.source.sync_all", target_type="vdb_source", target_id="*", details={"sources": queued})
    await db.commit()
    return {"queued": queued}


class SourceIn(BaseModel):
    enabled: bool | None = None
    interval_hours: int | None = Field(default=None, ge=1, le=24 * 30)
    settings: dict | None = None
    api_key: str | None = Field(default=None, max_length=200)      # NVD: None — не менять, "" — удалить


def _clean_settings(key: str, cur: dict, new: dict) -> dict:
    out = dict(cur)
    if key == "nvd":
        if "years_back" in new:
            out["years_back"] = max(1, min(30, int(new["years_back"])))
        if "history_days" in new:
            out["history_days"] = max(7, min(3650, int(new["history_days"])))
    if key == "osv":
        if "ecosystems" in new:
            out["ecosystems"] = [e for e in dict.fromkeys(new["ecosystems"]) if e in ECOSYSTEMS][:20]
        if "all_ecosystems" in new:
            out["all_ecosystems"] = bool(new["all_ecosystems"])
    if key == "bdu":
        if "url" in new:
            u = str(new["url"]).strip()
            if not u.lower().startswith("https://") or len(u) > 400:
                raise HTTPException(status_code=422, detail="Адрес выгрузки БДУ должен начинаться с https://")
            out["url"] = u
        for flag in ("verify_tls", "builtin_ca"):
            if flag in new:
                out[flag] = bool(new[flag])
    if key == "eol" and "url" in new and str(new["url"]).strip():
        u = str(new["url"]).strip()
        if not u.lower().startswith("https://") or len(u) > 300:
            raise HTTPException(status_code=422, detail="Адрес API endoflife.date должен начинаться с https://")
        out["url"] = u.rstrip("/")
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
        if r.enabled and r.last_ok_at is None and r.status != "running":
            r.requested_at = utcnow()                    # включение — одна кнопка: первая загрузка ставится в очередь сразу
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
    sev = "none" if v.score == 0 else next((k for k, r in SEV_RANK.items() if r == v.sev_rank), "")
    out = {"key": v.vuln_key, "title": v.title, "severity": sev, "severity_ru": SEV_RU[sev], "severity_basis": "cvss" if v.score is not None else "source" if v.sev_rank else "",
           "sev_rank": v.sev_rank, "score": v.score, "score_version": v.score_version, "score_source": v.score_source, "exploited": v.exploited, "has_fix": v.has_fix, "published": _iso(v.published), "modified": _iso(v.modified),
           "sources": [s for s in v.sources.split(",") if s], "ids": [i.upper() for i in v.ids_text.split()][:8], "products": v.products_text.split("; ")[:6] if v.products_text else [],
           "description": v.description[:400]}
    if f is not None:
        out["finding"] = {"status": f.status, "status_ru": M.STATUS_RU.get(f.status, f.status), "installs": f.installs, "hosts_max": f.hosts_max, "new": f.seen_at is None,
                          "first_seen_at": _iso(f.first_seen_at), "products": f.products[:5]}
    return out


def _score_filter(stmt, score_min: float | None, score_max: float | None, no_score: bool):
    """Диапазон оценки CVSS (границы включены); уязвимости без оценки в диапазон не попадают, а отбираются отдельно (no_score)."""
    if no_score:
        return stmt.where(VdbVuln.score.is_(None))
    if score_min is not None or score_max is not None:
        stmt = stmt.where(VdbVuln.score.is_not(None))
        if score_min is not None:
            stmt = stmt.where(VdbVuln.score >= score_min)
        if score_max is not None:
            stmt = stmt.where(VdbVuln.score <= score_max)
    return stmt


def _text_cond(term: str):
    """Слово или маска: идентификаторы (каждый — отдельно, по границам пробелов), название, продукты и описание. Звёздочка — любое число символов."""
    p = local_like(term)
    ids = VdbVuln.ids_text
    cond = [func.lower(VdbVuln.title).like(p, escape="\\"), VdbVuln.products_text.like(p, escape="\\"), func.lower(VdbVuln.description).like(p, escape="\\")]
    if is_mask(term):
        cond += [ids.like(x, escape="\\") for x in (p, f"% {p}", f"{p} %", f"% {p} %")]
    else:
        cond.append(ids.like(p, escape="\\"))
    return or_(*cond)


@router.get("/vulns")
async def vulns(q: str = Query("", max_length=200), min_severity: str = Query("", pattern=r"^(|critical|high|medium|low)$"), exploited: bool = False, has_fix: bool | None = None,
                score_min: float | None = Query(None, ge=0, le=10), score_max: float | None = Query(None, ge=0, le=10), no_score: bool = False,
                version: str = Query("", max_length=60), source: str = Query("", pattern=r"^(|nvd|kev|osv|bdu)$"), published_from: str = Query("", max_length=10), published_to: str = Query("", max_length=10),
                modified_from: str = Query("", max_length=10), affects: bool = False,
                sort: str = Query("priority", pattern=r"^(priority|published|modified|score|key)$"), desc: bool = True, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Поиск по CVE, идентификатору БДУ/OSV, названию и производителю программы, версии и тексту описания; по умолчанию — подтверждённая эксплуатация и самые опасные сверху."""
    sid = su.current_source_id
    stmt = select(VdbVuln, VdbFinding).outerjoin(VdbFinding, (VdbFinding.vuln_key == VdbVuln.vuln_key) & (VdbFinding.source_id == sid))     # sid=None: соединение пусто
    q = clean(q)
    for term in [q] if is_mask(q) else q.split()[:6]:      # маска со звёздочкой — вся строка целиком; обычный текст — все слова
        stmt = stmt.where(_text_cond(term))
    if min_severity:
        stmt = stmt.where(VdbVuln.sev_rank >= SEV_RANK[min_severity])
    if exploited:
        stmt = stmt.where(VdbVuln.exploited.is_(True))
    stmt = _score_filter(stmt, score_min, score_max, no_score)
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
    d = (lambda c: c.desc()) if desc else (lambda c: c.asc())
    order = {"priority": [VdbVuln.exploited.desc(), VdbVuln.sev_rank.desc(), VdbVuln.published.desc()], "published": [d(VdbVuln.published)], "modified": [d(VdbVuln.modified)],
             "score": [d(VdbVuln.score).nulls_last()], "key": [d(VdbVuln.vuln_key)]}[sort]
    if version.strip():
        return await _by_version(db, stmt.order_by(*order, VdbVuln.vuln_key), q, version.strip(), offset, limit)
    total = int((await db.execute(select(func.count()).select_from(stmt.order_by(None).subquery()))).scalar_one())
    rows = (await db.execute(stmt.order_by(*order, VdbVuln.vuln_key).offset(offset).limit(limit))).all()
    items = [_vuln_out(v, f if isinstance(f, VdbFinding) else None) for v, f in rows]
    return {"items": items, "total": total, "offset": offset, "limit": limit}


def _score_out(s: dict, ext: dict[str, str]) -> dict:
    """Оценка для показа: источник, происхождение значения (кто выставил), ссылка на первоисточник и дата обновления записи."""
    src, kind, org = s.get("source"), s.get("kind"), s.get("origin") or ""
    origin = {"nvd": "NVD (NIST)" if kind == "primary" else f"CNA: {org}" if org else "CNA (поставщик)", "bdu": "БДУ ФСТЭК России",
              "osv": "Вычислено по вектору из записи OSV"}.get(src, org)
    eid = ext.get(src, "")
    url = {"nvd": f"https://nvd.nist.gov/vuln/detail/{eid}", "bdu": f"https://bdu.fstec.ru/vul/{eid.split(':', 1)[-1]}", "osv": f"https://osv.dev/vulnerability/{eid}"}.get(src, "") if eid else ""
    return {**s, "severity_ru": SEV_RU.get(s["severity"], ""), "source_title": S.INFO[src]["title"] if src in S.INFO else src, "origin_label": origin, "url": url}


VERSION_CANDIDATES = 2000


async def _by_version(db: AsyncSession, stmt, q: str, version: str, offset: int, limit: int) -> dict:
    """Какие уязвимости программы затрагивают указанную версию: кандидаты по названию (самые приоритетные, до 2000) → диапазоны версий источников (те же правила, что при сопоставлении
    с KSC). «yes» — версия в затронутом диапазоне; «unknown» — границы источника нельзя сравнить (потенциальное совпадение, требуется уточнение)."""
    if not any(c.isdigit() for c in version):
        raise HTTPException(status_code=422, detail="Версия должна содержать цифры, например 1.18.0")
    words = [w for w in (norm(x) for x in clean(q).replace("*", " ").split()) if w][:4]
    if not words:
        raise HTTPException(status_code=422, detail="Версию можно проверить только вместе с названием программы: введите его в поле поиска")
    cands = (await db.execute(stmt.limit(VERSION_CANDIDATES))).all()
    affs = await M.affected_for(db, [v.vuln_key for v, _ in cands])
    best: dict[str, str] = {}
    rank = {"yes": 2, "unknown": 1}
    for a in affs:
        hay = " ".join((a.vendor_key, a.product_key, norm(a.pkg_name)))
        if not all(w in hay for w in words):
            continue
        res, _why = M.verdict(version, "dpkg" if a.ecosystem.startswith(("Debian", "Ubuntu")) else "numeric", a)
        if rank.get(res, 0) > rank.get(best.get(a.vuln_key, ""), 0):
            best[a.vuln_key] = res
    hits = [(v, f) for v, f in cands if v.vuln_key in best]
    hits.sort(key=lambda x: -rank[best[x[0].vuln_key]])
    items = [{**_vuln_out(v, f if isinstance(f, VdbFinding) else None), "version_match": best[v.vuln_key]} for v, f in hits[offset:offset + limit]]
    return {"items": items, "total": len(hits), "offset": offset, "limit": limit, "approximate": len(cands) >= VERSION_CANDIDATES, "version": version}


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
    ext = {r.source: r.ext_id for r in recs}
    all_scores = [s for r in recs for s in store.record_scores(r)]
    main = pick_primary(all_scores)
    cvss = {"primary": _score_out(main, ext), "all": [_score_out(s, ext) | {"primary": s is main} for s in sorted(all_scores, key=score_key)]} if main else None
    records = [{"source": r.source, "scores": [_score_out(s, ext) for s in sorted(store.record_scores(r), key=score_key)], "title": S.INFO[r.source]["title"], "ext_id": r.ext_id, "aliases": r.aliases, "severity": r.severity, "severity_ru": SEV_RU.get(r.severity, ""), "score": r.score,
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
    return {**_vuln_out(v), "description": v.description, "cvss": cvss, "records": records, "differences": diffs, "infrastructure": infra}


# ------------------------------------------------------------------------------------------------ находки для специалиста ИБ
@router.get("/findings")
async def findings(new_only: bool = False, min_severity: str = Query("", pattern=r"^(|critical|high|medium|low)$"), exploited: bool = False,
                   score_min: float | None = Query(None, ge=0, le=10), score_max: float | None = Query(None, ge=0, le=10), no_score: bool = False,
                   sort: str = Query("priority", pattern=r"^(priority|score)$"), desc: bool = True,
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
    stmt = _score_filter(stmt, score_min, score_max, no_score)
    total = int((await db.execute(select(func.count()).select_from(stmt.order_by(None).subquery()))).scalar_one())
    order = [(VdbVuln.score.desc() if desc else VdbVuln.score.asc()).nulls_last()] if sort == "score" else [VdbVuln.exploited.desc(), VdbVuln.sev_rank.desc()]
    rows = (await db.execute(stmt.order_by(*order, VdbFinding.first_seen_at.desc(), VdbFinding.vuln_key).offset(offset).limit(limit))).all()
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
async def catalog_counts(request: Request, keys: str = Query("", max_length=12000), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
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


async def host_ext_items(db: AsyncSession, client, source_id: uuid.UUID, host_id: int) -> tuple[list[dict], bool]:
    """Потенциальные уязвимости компьютера по внешним базам: установленное ПО (записи реестра KSC) сопоставляется с каталогом и внешними базами.
    Возвращает (элементы по убыванию важности, построен ли каталог)."""
    from ..ksc import queries as q  # noqa: PLC0415

    soft = await client.run(q.SOFTWARE_ON_HOST, {"id": host_id}, max_rows=20_000)
    ids = {int(s["product_id"]) for s in soft}
    prods, maps = await M.load_context(db, source_id)
    mine = [p for p in prods if any(set(v.get("product_ids") or []) & ids for v in p.versions)]
    if not mine:
        return [], bool(prods)
    for p in mine:
        p.versions = [v for v in p.versions if set(v.get("product_ids") or []) & ids]
    matcher = M.Matcher(mine, maps)
    ms: list[M.Match] = []
    async for _part, rows in M.iter_affected(db, await M.reverse_keys(db, mine, maps), 200):       # порциями: память не зависит от числа уязвимостей
        ms += [m for m in M.matches_from(matcher, rows, only_active=False) if m.status in M.AFFECTED]
        if len(ms) > 20_000:
            break
    meta = {v.vuln_key: v for i in range(0, len(ms), 400) for v in (await db.execute(select(VdbVuln).where(VdbVuln.vuln_key.in_({m.vuln_key for m in ms[i:i + 400]})))).scalars().all()}
    items = []
    for m in ms:
        v = meta.get(m.vuln_key)
        rank = v.sev_rank if v else 0
        items.append({"key": m.vuln_key, "title": v.title if v else "", "severity_ru": SEV_RU[next((k for k, r in SEV_RANK.items() if r == rank), "")], "sev_rank": rank, "exploited": bool(v and v.exploited),
                      "product": m.product_name, "version": m.version, "status": m.status, "status_ru": M.STATUS_RU[m.status], "basis": m.basis,
                      "sources": [x for x in (v.sources.split(",") if v else []) if x], "ids": [x.upper() for x in (v.ids_text.split() if v else [])][:20]})
    items.sort(key=lambda x: (not x["exploited"], -x["sev_rank"], -M.STATUS_RANK[x["status"]]))
    return items, True


@router.get("/hosts/{host_id}")
async def host_vulns(host_id: int, request: Request, su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Независимая проверка компьютера по внешним базам. Результат — потенциальные уязвимости, не подтверждённые KSC (общий список вместе с данными KSC — `/hosts/{id}/vulnerabilities`)."""
    items, catalog = await host_ext_items(db, request.app.state.sources.client(src), src.id, host_id)
    return {"items": [{k: v for k, v in i.items() if k not in ("sources", "ids")} for i in items[:500]], "total": len(items), "catalog": catalog}


# ------------------------------------------------------------------------------------------------ решения по сопоставлению
class MappingIn(BaseModel):
    vendor_key: str = Field(default="", max_length=200)
    product: str = Field(min_length=1, max_length=300)
    catalog_key: str = Field(min_length=1, max_length=160)
    action: str = Field(default="map", pattern=r"^(map|exclude)$")
    note: str | None = Field(default=None, max_length=500)


async def _recheck(db: AsyncSession, su: SessionUser, product_key: str) -> None:
    """Пересчёт находок только по уязвимостям названного продукта (до 3000): быстро и без нагрузки на память; остальное сверит фоновая служба по отпечатку данных."""
    if not su.current_source_id:
        return
    keys = (await db.execute(select(VdbAffected.vuln_key).where(VdbAffected.product_key == product_key).distinct().limit(3000))).scalars().all()
    if keys:
        await analyze(db, su.current_source_id, keys=list(keys))


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
    await db.commit()
    await _recheck(db, su, m.product_key)          # затронутые решением уязвимости пересчитываются сразу, полный пересчёт по всему каталогу — фоновая служба
    return {"id": str(m.id)}


@router.delete("/mappings/{mid}", status_code=204)
async def delete_mapping(mid: uuid.UUID, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    pk = (await db.execute(select(VdbMapping.product_key).where(VdbMapping.id == mid))).scalar_one_or_none()
    r = await db.execute(delete(VdbMapping).where(VdbMapping.id == mid))
    if not r.rowcount:
        raise HTTPException(status_code=404, detail="Решение не найдено")
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="vdb.mapping.delete", target_type="vdb_mapping", target_id=str(mid))
    await db.commit()
    if pk:
        await _recheck(db, su, pk)


@router.get("/suggest-products")
async def suggest(q: str = Query("", max_length=100), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Подсказка продуктов каталога для ручного сопоставления."""
    stmt = select(CatalogProduct.key, CatalogProduct.name, CatalogProduct.publisher).where(CatalogProduct.source_id == src.id).order_by(CatalogProduct.hosts_active.desc()).limit(15)
    stmt = stmt.where(*text_conds(q))
    return {"items": [{"key": k, "name": n, "publisher": p} for k, n, p in (await db.execute(stmt)).all()]}

