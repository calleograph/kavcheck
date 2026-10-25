"""Каталог продуктов и быстрая проверка версий.

Каталог строится фоновой задачей из реестра ПО KSC (см. services/catalog.py); здесь — выборки, карточка продукта, компьютеры с выбранными
версиями (живой запрос к KSC по идентификаторам записей), ручные корректировки и предварительный просмотр проверки по нескольким источникам."""
from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, current_source, get_db, require_analyst, require_user
from ..ksc import catalog as C
from ..ksc.driver import KscError, Session
from ..ksc.grouping import Rule
from ..models import CatalogOverride, GroupingRule, KscSource
from ..reports import audit
from ..reports.runner import conn_params
from ..services import catalog as svc
from ..services.audit import write_audit
from .schemas import OverrideIn, PreviewIn

router = APIRouter(tags=["catalog"])


def _ksc(exc: KscError) -> HTTPException:
    return HTTPException(status_code=502 if exc.code in ("connect", "auth", "query") else 422, detail={"code": exc.code, "message": exc.message})


async def _state(db: AsyncSession, source_id: uuid.UUID) -> dict:
    from ..models import CatalogState  # noqa: PLC0415

    return svc.state_out(await db.get(CatalogState, source_id))


@router.get("/catalog")
async def catalog(q: str = Query("", max_length=200), publisher: str = Query("", max_length=160), platform: str = Query("", pattern=r"^(windows|linux)?$"),
                  sort: str = Query("hosts", pattern=r"^(hosts|name|publisher|versions|first_seen)$"), desc: bool = True, all_hosts: bool = False, components: bool = False,
                  offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), roots: bool = False, family: str = Query("", max_length=160),
                  su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Продукты источника: название, производитель, версии, ветки, компьютеры (только активные — если не запрошен показ всех).
    roots — только основные продукты семейств; family — компоненты одного семейства."""
    out = await svc.query(db, src.id, q=q, publisher_key=publisher, platform=platform, sort=sort, desc=desc, all_hosts=all_hosts, components=components, offset=offset,
                          limit=limit, roots=roots, family=family)
    out["state"] = await _state(db, src.id)
    return out


@router.get("/catalog/publishers")
async def publishers(q: str = Query("", max_length=200), all_hosts: bool = False, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                     su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    return await svc.publishers(db, src.id, q=q, all_hosts=all_hosts, offset=offset, limit=limit)


@router.get("/catalog/state")
async def state(su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    return await _state(db, src.id)


@router.post("/catalog/rebuild")
async def rebuild(su: SessionUser = Depends(require_analyst), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Запросить пересборку каталога источника: выполняет фоновая задача (обычно в течение минуты)."""
    st = await svc.request_rebuild(db, src.id)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="catalog.rebuild", target_type="catalog", target_id=str(src.id), source_id=src.id)
    await db.commit()
    return svc.state_out(st)


@router.get("/catalog/search")
async def search(q: str = Query("", max_length=200), source_ids: str = Query("", max_length=2000), limit: int = Query(20, ge=1, le=50),
                 su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Поиск программы для конструктора отчётов сразу по нескольким источникам."""
    ids = []
    for raw in [x for x in source_ids.split(",") if x.strip()] or ([str(su.current_source_id)] if su.current_source_id else []):
        try:
            sid = uuid.UUID(raw.strip())
        except ValueError:
            continue
        if su.can_use_source(sid):
            ids.append(sid)
    if not ids:
        return {"items": []}
    return {"items": await svc.search_keys(db, ids, q, limit)}


@router.get("/catalog/products/{key:path}/hosts")
async def product_hosts(key: str, request: Request, version: str = Query("", max_length=200), branch: str | None = Query(None, max_length=60), all_hosts: bool = False, zone: str = Query("", max_length=40),
                        offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source),
                        db: AsyncSession = Depends(get_db)):
    """Компьютеры с продуктом (всеми версиями, одной версией или веткой) — живой запрос к KSC по записям реестра продукта."""
    p = await svc.product(db, src.id, key)
    if p is None:
        raise HTTPException(status_code=404, detail="Продукт не найден в каталоге источника")
    item = {"kind": "product", "product_key": key, "product_name": p.name, "op": "eq" if version else "any", "value": version or None,
            "branches": [branch] if branch is not None else []}
    if version:          # версия из каталога — уже приведённая: отбираем записи по ней точно (по списку записей реестра этой версии)
        ids = sorted({pid for v in p.versions if v["version"] == version for pid in v["product_ids"]})
        item = {**item, "op": "any", "product_ids": ids}
    else:
        item["product_ids"] = sorted({pid for v in p.versions for pid in v["product_ids"]})
    async def make() -> tuple[list[dict], dict]:
        rows, summ = await run_one(request, db, src, [item], all_hosts=all_hosts, max_rows=20_000)
        by_host: dict[int, dict] = {}
        for r in rows:
            h = by_host.setdefault(r["host_id"], {**{k: r.get(k) for k in ("host_id", "name", "fqdn", "ip", "os", "group", "last_connected", "days_since_connection", "activity",
                                                                           "linux_release", "online")}, "versions": []})
            h["versions"].append({"app_name": r["app_name"], "app_version": r["app_version"], "compared_version": r["compared_version"], "branch": r["branch"]})
        return sorted(by_host.values(), key=lambda h: h["name"].lower()), summ

    # список собирается одним запросом к KSC и кэшируется: порции бесконечной прокрутки берутся из кэша, а не повторяют запрос
    (items, summ), _at = await request.app.state.cache.get((str(src.id), "product_hosts", key, version, branch, all_hosts, p.built_at.isoformat() if p.built_at else ""),
                                                           request.app.state.settings.cache_ttl_seconds, make)
    if zone:
        from .zones import zone_host_ids  # noqa: PLC0415

        zids = await zone_host_ids(request, db, src, zone)
        items = [h for h in items if h["host_id"] in zids]
    return {"items": items[offset:offset + limit], "total": len(items), "offset": offset, "limit": limit, "hidden_hosts": summ["hidden_inactive_hosts"],
            "fetched_at": summ["fetched_at"]}


@router.get("/catalog/products/{key:path}")
async def product(key: str, all_hosts: bool = False, su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    p = await svc.product(db, src.id, key)
    if p is None:
        raise HTTPException(status_code=404, detail="Продукт не найден в каталоге источника")
    out = svc.product_out(p, all_hosts=all_hosts, full=True)
    d = C.BUILTIN_BY_KEY.get(key)
    out["builtin"] = bool(d)
    out["overrides"] = [svc.override_out(o) for o in (await db.execute(select(CatalogOverride).where((CatalogOverride.to_key == key) | (CatalogOverride.from_key == key)))).scalars().all()]
    out["state"] = await _state(db, src.id)
    return out


# ------------------------------------------------------------------------------------------------ ручные корректировки
@router.get("/catalog/overrides")
async def overrides(su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(CatalogOverride).order_by(CatalogOverride.created_at.desc()))).scalars().all()
    return {"items": [svc.override_out(r) for r in rows]}


@router.post("/catalog/overrides", status_code=201)
async def add_override(body: OverrideIn, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Объединить продукты (merge), выделить записи с указанными названиями в отдельный продукт (split), переименовать продукт (rename).
    Корректировки общие для всех источников и сохраняются при обновлении приложения; каталог перестраивается автоматически."""
    created = []
    if body.kind == "merge":
        if not body.from_key or not body.to_key or body.from_key == body.to_key:
            raise HTTPException(status_code=422, detail="Укажите два разных продукта")
        created.append(CatalogOverride(kind="merge", from_key=body.from_key, to_key=body.to_key, note=body.note, created_by=su.display_name))
    elif body.kind == "split":
        names = [n.strip() for n in body.match_names if n.strip()]
        if not names or not (body.to_name or "").strip():
            raise HTTPException(status_code=422, detail="Выберите названия записей и укажите название нового продукта")
        key = body.to_key or ("manual:" + C.slug(body.to_name or ""))
        for n in names:
            created.append(CatalogOverride(kind="split", from_key=body.from_key, match_name=n[:300], to_key=key, to_name=body.to_name.strip(), note=body.note,
                                           created_by=su.display_name))
    else:
        if not body.to_key or not ((body.to_name or "").strip() or body.to_publisher is not None):
            raise HTTPException(status_code=422, detail="Укажите продукт и новое название или производителя")
        created.append(CatalogOverride(kind="rename", to_key=body.to_key, to_name=(body.to_name or "").strip() or None, to_publisher=body.to_publisher, note=body.note,
                                       created_by=su.display_name))
    for c in created:
        db.add(c)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action=f"catalog.{body.kind}", target_type="catalog", target_id=body.to_key or body.from_key or "-",
                details={"from": body.from_key, "names": body.match_names[:20], "to": body.to_key, "to_name": body.to_name})
    await db.commit()
    return {"items": [svc.override_out(c) for c in created]}


@router.delete("/catalog/overrides/{override_id}", status_code=204)
async def delete_override(override_id: uuid.UUID, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    r = await db.get(CatalogOverride, override_id)
    if r is None:
        raise HTTPException(status_code=404, detail="Корректировка не найдена")
    await db.delete(r)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="catalog.override_delete", target_type="catalog", target_id=str(override_id),
                details={"kind": r.kind, "to": r.to_key})
    await db.commit()


# ------------------------------------------------------------------------------------------------ быстрая проверка версий
async def run_one(request: Request, db: AsyncSession, src: KscSource, items: list[dict], *, all_hosts: bool, max_rows: int, active_days: int | None = None,
                  group_contains: str = "", online_only: bool = False) -> tuple[list[dict], dict]:
    general = await request.app.state.settings_svc.get(db, "general")
    rcfg = await request.app.state.settings_svc.get(db, "reports")
    rules = {r.key: Rule(r.key, r.name, r.name_like, r.name_regex, r.branch_regex, r.branch_parts, r.exclude_regex)
             for r in (await db.execute(select(GroupingRule).where(GroupingRule.enabled.is_(True)))).scalars().all()} if any(i.get("kind") == "rule" for i in items) else {}
    params = conn_params(src, request.app.state.settings_svc.decrypt(src.password_enc, f"source.{src.id}"))
    client = request.app.state.sources.client(src)

    def work():
        with Session(params) as conn:
            return audit.build_source(conn, source_name=src.name, items=items, rules=rules, active_days=active_days or general.activity_days, include_inactive=all_hosts,
                                      group_contains=group_contains, exclude_slaves=rcfg.exclude_slave_servers, max_rows=max_rows, progress=lambda _t: None,
                                      cancelled=lambda: False, online_only=online_only)

    try:
        async with client._sem:  # noqa: SLF001 — один слот источника на всё построение
            return await asyncio.to_thread(work)
    except KscError as exc:
        raise _ksc(exc) from None


@router.post("/audit/preview")
async def preview(body: PreviewIn, request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """«Найти устаревшие версии»: та же проверка, что и в отчёте, по нескольким источникам сразу; в ответе — итоги и первые строки.
    Полный список и XLSX — фоновым отчётом (предел строк просмотра ограничен)."""
    merged, rows_all = await audit_preview(request, db, su, body.params.model_dump(), body.source_ids)
    return {"summary": merged, "items": rows_all[:body.limit], "total": len(rows_all)}


async def audit_preview(request: Request, db: AsyncSession, su: SessionUser, params: dict, source_ids: list) -> tuple[dict, list[dict]]:
    """Проверка версий для просмотра (одна и та же функция у «Найти устаревшие версии» и быстрого отчёта): (сводка, все строки)."""
    ids = source_ids or ([su.current_source_id] if su.current_source_id else [])
    if not ids:
        raise HTTPException(status_code=409, detail={"code": "no_source", "message": "Источник KSC не выбран."})
    sources = []
    for i in dict.fromkeys(ids):
        s = await db.get(KscSource, i)
        if s is None or not s.is_active or not su.can_use_source(s.id):
            raise HTTPException(status_code=403, detail="Нет доступа к одному из источников")
        sources.append(s)
    items = params["items"]
    not_ready, notes = [], []
    plans = []
    for s in sources:
        if any((it.get("kind") or "product") == "product" for it in items) and not await svc.catalog_ready(db, s.id):
            not_ready.append(s.name)
            await svc.request_rebuild(db, s.id)
            continue
        resolved, missing = await svc.resolve_items(db, s.id, items)
        try:
            audit.check_conditions(items, resolved)
        except KscError as exc:
            raise _ksc(exc) from None
        if missing:
            notes.append(f"{s.name}: нет в каталоге — {', '.join(missing)}")
        plans.append((s, resolved))
    await db.commit()
    if not_ready and not plans:
        raise HTTPException(status_code=409, detail={"code": "catalog_building", "message": f"Каталог программ ещё строится: {', '.join(not_ready)}. Повторите через минуту."})
    rcfg_max = (await request.app.state.settings_svc.get(db, "reports")).max_rows    # тот же предел, что у отчёта: просмотр и отчёт считают одно и то же
    results = await asyncio.gather(*[run_one(request, db, s, resolved, all_hosts=params["include_inactive"], active_days=params.get("active_days"),
                                             group_contains=params.get("group_contains") or "", max_rows=rcfg_max, online_only=params.get("online_only", False)) for s, resolved in plans],
                                   return_exceptions=True)
    rows_all, per_source, errors = [], [], []
    for (s, _r), res in zip(plans, results):
        if isinstance(res, BaseException):
            msg = res.detail.get("message") if isinstance(res, HTTPException) and isinstance(res.detail, dict) else str(getattr(res, "detail", res))
            errors.append({"source": s.name, "message": msg})
            continue
        rows, summ = res
        rows_all += rows
        per_source.append(summ)
    general = await request.app.state.settings_svc.get(db, "general")
    merged = audit.merge_summaries(per_source, items, active_days=params.get("active_days") or general.activity_days, include_inactive=params["include_inactive"], rows=rows_all, online_only=params.get("online_only", False))
    merged["notes"] = notes + ([f"Каталог ещё строится: {', '.join(not_ready)} — источники пропущены"] if not_ready else [])
    merged["errors"] = errors
    rows_all.sort(key=lambda r: (r["program"].lower(), r["source"], r["name"].lower()))
    return merged, rows_all
