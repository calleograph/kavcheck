"""Жизненный цикл ПО и ОС (EOL): весь каталог endoflife.date, EOL в инфраструктуре, устройства находки, ручные соответствия и пересчёт.
Данные считает worker (eol/service.py) и хранит в PostgreSQL; страницы читают готовое и к KSC не обращаются. Поддерживается режим «Все источники» (заголовок X-Source-Id: all)."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, case, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, is_all, require_analyst, require_user, source_scope
from ..eol import compute as C
from ..eol import read as R
from ..eol.classify import STATUS_RU, classify
from ..models import CatalogProduct, EolFinding, EolHost, EolHostStat, EolMapping, EolProduct, EolRelease, EolState, KscSource, VdbSource
from ..search import any_of
from ..services.audit import write_audit

router = APIRouter(prefix="/eol", tags=["eol"])


def _names(srcs: list[KscSource]) -> dict:
    return {s.id: s.name for s in srcs}


def _opt_source(srcs: list[KscSource], source_id: str) -> list[uuid.UUID]:
    ids = [s.id for s in srcs]
    if not source_id:
        return ids
    try:
        sid = uuid.UUID(source_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="source_id") from None
    if sid not in ids:
        raise HTTPException(status_code=403, detail="Нет доступа к этому источнику KSC")
    return [sid]


# ------------------------------------------------------------------------------------------------ сводка
@router.get("/summary")
async def summary(request: Request, zone: str = Query("", max_length=40), source_id: str = Query("", max_length=40), su: SessionUser = Depends(require_user),
                  srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    """Показатели раздела: состояние базы EOL, число проблемных программ и ОС, устройств, расчёт по источникам. source_id — только этот источник (страницы одного источника)."""
    sids = _opt_source(srcs, source_id)
    srcs = [s for s in srcs if s.id in sids]
    vs = await db.get(VdbSource, "eol")
    n_prod, n_rel = int((await db.execute(select(func.count()).select_from(EolProduct))).scalar_one()), int((await db.execute(select(func.count()).select_from(EolRelease))).scalar_one())
    cfg = await request.app.state.settings_svc.get(db, "eol")
    base = {"include_in_analytics": bool(cfg.include_in_analytics), "soon_days": int(cfg.soon_days), "products": n_prod, "releases": n_rel, "enabled": bool(vs and vs.enabled), "status": vs.status if vs else "never", "last_ok_at": vs.last_ok_at if vs else None, "error": vs.last_error if vs else None}
    items = {"eol": 0, "extended": 0, "upcoming": 0}
    kinds = {"app": 0, "os": 0}
    if zone:
        got = [(f, na) for f, _n, na in await R.zone_findings(db, sids, zone, q="", kind="", product="", publisher="", severity="", status="") if f.status in R.PROBLEM_STATUSES and na > 0]
    else:
        got = [(f, f.hosts_active) for f in (await db.execute(select(EolFinding).where(EolFinding.source_id.in_(sids), EolFinding.status.in_(R.PROBLEM_STATUSES), EolFinding.hosts_active > 0))).scalars()]
    for f, _na in got:
        items[f.status] += 1
        kinds[f.kind] += 1
    if zone:
        zc = await R.zone_counts(db, sids, zone)
        z = {k: sum(v[k] for v in zc.values()) for k in ("hosts", "eol", "extended", "upcoming")} if zc else {"hosts": 0, "eol": 0, "extended": 0, "upcoming": 0}
    else:                                         # устройство может входить в несколько зон: общий итог считается отдельно, без повторов
        z = await _distinct_hosts(db, sids)
    unknown = int((await db.execute(select(func.count()).select_from(EolFinding).where(EolFinding.source_id.in_(sids), EolFinding.status == "unknown"))).scalar_one())
    states = {st.source_id: st for st in (await db.execute(select(EolState).where(EolState.source_id.in_(sids)))).scalars()}
    soon = int(cfg.soon_days)
    current = {}
    for src in srcs:
        st = states.get(src.id)
        state = await _calc_state(db, src.id, st, soon, bool(n_prod))
        item = {"source": src.name, "computed_at": st.computed_at if st else None, "error": st.error if st else None, "error_at": st.error_at if st else None,
                "attempt_at": st.attempt_at if st else None, "progress": st.progress if st else None, "started_at": st.started_at if st else None, "items": st.items if st else 0,
                "ready": bool(st and st.computed_at), "state": state, "state_ru": STATE_RU[state]}
        if su.is_admin and st is not None:                                    # техническая причина и сведения расчёта — только администратору
            item["error_detail"], item["diag"] = st.error_detail, st.diag
        current[str(src.id)] = item
    incomplete = [v["source"] for v in current.values() if v["state"] in ("none", "error", "running")]
    return {"base": base, "all_sources": is_all(request), "findings": items, "kinds": kinds, "devices": z, "ambiguous": unknown, "sources": current, "complete": not incomplete, "incomplete": incomplete}


STATE_RU = {"none": "Не рассчитано", "running": "Выполняется", "error": "Ошибка", "ready": "Готово", "stale": "Данные устарели"}
RUN_LIMIT = timedelta(hours=3)          # дольше — расчёт считается зависшим (процесс упал); worker сбрасывает такие при запуске
STALE_AFTER = timedelta(days=7)


async def _calc_state(db: AsyncSession, source_id: uuid.UUID, st: EolState | None, soon: int, base_loaded: bool) -> str:
    """none — результата нет; running — расчёт идёт; error — последний расчёт не удался (если результат раньше был, он остаётся, но состояние — ошибка); stale — исходные данные
    (база EOL, каталог, решения) изменились после расчёта или он старше недели; ready — актуально."""
    now = datetime.now(timezone.utc)
    if st is not None and st.started_at and now - st.started_at < RUN_LIMIT:
        return "running"
    if st is not None and st.error and (st.error_at or now) >= (st.computed_at or datetime.min.replace(tzinfo=timezone.utc)):
        return "error"
    if st is None or not st.computed_at:
        return "none"
    if now - st.computed_at > STALE_AFTER or (base_loaded and st.inputs and st.inputs != await C.current_inputs(db, source_id, None, soon)):
        return "stale"
    return "ready"


async def _distinct_hosts(db: AsyncSession, sids: list[uuid.UUID]) -> dict:
    S = EolHostStat
    q = (select(S.w, func.count()).where(S.source_id.in_(sids), S.active.is_(True)).group_by(S.w))
    got = {w: int(n) for w, n in (await db.execute(q)).all()}
    return {"hosts": sum(got.values()), "eol": got.get(3, 0), "extended": got.get(2, 0), "upcoming": got.get(1, 0)}


# ------------------------------------------------------------------------------------------------ все продукты
@router.get("/products")
async def products(q: str = Query("", max_length=200), category: str = Query("", max_length=40), vendor: str = Query("", max_length=80), state: str = Query("", pattern=r"^(supported|eol|installed)?$"),
                   sort: str = Query("name", pattern=r"^(name|category|releases|installed)$"), desc: bool = False, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                   su: SessionUser = Depends(require_user), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    """Все продукты базы endoflife.date: название, категория, число веток, сколько из них поддерживается, есть ли в инфраструктуре."""
    sids = [s.id for s in srcs]
    P = EolProduct
    today = date.today()
    cond = []
    if q:
        cond.append(any_of(q, P.search, P.label, P.name))
    if category:
        cond.append(P.category == category)
    if vendor:
        cond.append(P.search.like(f"%:{vendor.lower().replace('%', '').replace('_', '')}:%"))                       # производитель — из идентификаторов CPE «cpe:2.3:a:<производитель>:…»
    inst = (select(EolFinding.eol_product.label("p"), func.count().label("cnt"), func.coalesce(func.sum(EolFinding.hosts_active), 0).label("hosts")).where(EolFinding.source_id.in_(sids), EolFinding.eol_product != "",
            EolFinding.status.in_(R.PROBLEM_STATUSES)).group_by(EolFinding.eol_product).subquery())
    sup = (select(EolRelease.product.label("p"), func.count().label("n"), func.sum(case((func.coalesce(EolRelease.eol_from, date(9999, 1, 1)) > today, 1), else_=0)).label("supported")).group_by(EolRelease.product).subquery())
    j = P.__table__.outerjoin(inst, inst.c.p == P.name).outerjoin(sup, sup.c.p == P.name)
    if state == "installed":
        cond.append(inst.c.cnt > 0)
    elif state == "supported":
        cond.append(sup.c.supported > 0)
    elif state == "eol":
        cond.append(func.coalesce(sup.c.supported, 0) == 0)
    order = {"name": func.lower(P.label), "category": P.category, "releases": P.releases_n, "installed": func.coalesce(inst.c.hosts, 0)}[sort]
    total = int((await db.execute(select(func.count()).select_from(j).where(*cond))).scalar_one())
    rows = (await db.execute(select(P, inst.c.cnt, inst.c.hosts, sup.c.supported).select_from(j).where(*cond).order_by(order.desc() if desc else order.asc(), P.name).offset(offset).limit(limit))).all()
    cats = [c for (c,) in (await db.execute(select(P.category).distinct().order_by(P.category))).all() if c]
    return {"total": total, "categories": cats, "items": [
        {"name": p.name, "label": p.label or p.name, "category": p.category, "tags": p.tags, "releases": p.releases_n, "supported": int(sp or 0), "link": (p.links or {}).get("html", ""),
         "installed_items": int(it or 0), "installed_hosts": int(h or 0), "updated_at": p.updated_at} for p, it, h, sp in rows]}


@router.get("/products/{name}")
async def product(name: str, su: SessionUser = Depends(require_user), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    """Продукт: ветки с датами поддержки (как их публикует endoflife.date), состояние на сегодня, что из этого есть в инфраструктуре."""
    p = await db.get(EolProduct, name)
    if p is None:
        raise HTTPException(status_code=404, detail="Продукт не найден в базе EOL")
    today = date.today()
    rels = (await db.execute(select(EolRelease).where(EolRelease.product == name).order_by(EolRelease.position))).scalars().all()
    sids = [s.id for s in srcs]
    found = {}
    for f in (await db.execute(select(EolFinding).where(EolFinding.source_id.in_(sids), EolFinding.eol_product == name))).scalars():
        found.setdefault(f.eol_release, []).append(f)
    out = []
    for r in rels:
        lc = classify(r, p.labels, today)
        fs = found.get(r.name, [])
        out.append({"name": r.name, "label": r.label, "codename": r.codename, "release_date": r.release_date, "lts": r.is_lts, "eoas_from": r.eoas_from, "eol_from": r.eol_from, "eoes_from": r.eoes_from,
                    "discontinued_from": r.discontinued_from, "latest": r.latest_name, "status": lc.status, "status_ru": STATUS_RU.get(lc.status, lc.status), "severity": lc.severity, "condition": lc.condition,
                    "installed_hosts": sum(f.hosts_active for f in fs), "installed_items": len(fs)})
    return {"name": p.name, "label": p.label or p.name, "category": p.category, "tags": p.tags, "labels": p.labels, "links": p.links, "identifiers": p.identifiers, "aliases": p.aliases, "releases": out,
            "updated_at": p.updated_at}


# ------------------------------------------------------------------------------------------------ EOL в инфраструктуре
@router.get("/infra")
async def infra(q: str = Query("", max_length=200), kind: str = Query("", pattern=r"^(app|os)?$"), product: str = Query("", max_length=120), publisher: str = Query("", max_length=200),
                severity: str = Query("", pattern=r"^(critical|high|warning)?$"), status: str = Query("", pattern=r"^(eol|extended|upcoming|unknown)?$"), zone: str = Query("", max_length=40),
                source_id: str = Query("", max_length=40), all_hosts: bool = False, sort: str = Query("hosts", pattern=r"^(hosts|severity|eol_from|title|release)$"), desc: bool = True,
                offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), su: SessionUser = Depends(require_user), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    """Программы и ОС инфраструктуры с закончившейся или приближающейся датой окончания поддержки (по каждому источнику отдельно; в режиме «Все источники» у каждой записи указан источник)."""
    sids = _opt_source(srcs, source_id)
    out = await R.list_findings(db, sids, _names(srcs), q=q, kind=kind, product=product, publisher=publisher, severity=severity, status=status, zone=zone, all_hosts=all_hosts, sort=sort, desc=desc,
                                offset=offset, limit=limit)
    states = (await db.execute(select(func.min(EolState.computed_at)).where(EolState.source_id.in_(sids)))).scalar_one()
    out["computed_at"] = states
    pubs = (await db.execute(select(EolFinding.publisher).where(EolFinding.source_id.in_(sids), EolFinding.publisher != "").distinct().order_by(EolFinding.publisher).limit(300))).scalars().all()
    out["publishers"] = list(pubs)
    return out


@router.get("/infra/hosts")
async def infra_hosts(source_id: str = Query(..., max_length=40), kind: str = Query(..., pattern=r"^(app|os)$"), subject: str = Query(..., max_length=200), version: str = Query("", max_length=120),
                      q: str = Query("", max_length=200), zone: str = Query("", max_length=40), all_hosts: bool = False, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
                      su: SessionUser = Depends(require_user), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    """Устройства, на которых найдена программа или ОС с EOL (из подготовленных данных; переход в карточку — по source_id и host_id)."""
    sid = _opt_source(srcs, source_id)[0]
    return await R.finding_hosts(db, sid, kind, subject, version, q=q, zone=zone, active_only=not all_hosts, offset=offset, limit=limit)


@router.get("/hosts/{source_id}/{host_id}")
async def host_eol(source_id: str, host_id: int, su: SessionUser = Depends(require_user), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    sid = _opt_source(srcs, source_id)[0]
    return {"items": await R.host_items(db, sid, host_id)}


# ------------------------------------------------------------------------------------------------ соответствия
class MappingIn(BaseModel):
    catalog_key: str = Field(min_length=1, max_length=160)
    eol_product: str | None = Field(default=None, max_length=120)
    action: str = Field(default="map", pattern=r"^(map|exclude)$")
    note: str = Field(default="", max_length=300)


@router.get("/mappings")
async def mappings(su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(EolMapping).order_by(EolMapping.created_at.desc()))).scalars().all()
    names = {}
    if rows:
        cp = (await db.execute(select(CatalogProduct.key, func.max(CatalogProduct.name)).where(CatalogProduct.key.in_([m.catalog_key for m in rows])).group_by(CatalogProduct.key))).all()
        names = dict(cp)
    labels = await R.labels_for(db, {m.eol_product for m in rows if m.eol_product})
    return {"items": [{"id": str(m.id), "catalog_key": m.catalog_key, "catalog_name": names.get(m.catalog_key, m.catalog_key), "eol_product": m.eol_product, "eol_label": labels.get(m.eol_product or "", ""),
                       "action": m.action, "note": m.note, "created_by": m.created_by, "created_at": m.created_at} for m in rows]}


@router.post("/mappings", status_code=201)
async def set_mapping(body: MappingIn, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Решение: программе каталога соответствует продукт endoflife.date (map) либо EOL ей не присваивается (exclude). Сохраняется при обновлении базы и каталога; пересчёт запускается сам."""
    if body.action == "map":
        if not body.eol_product or await db.get(EolProduct, body.eol_product) is None:
            raise HTTPException(status_code=422, detail="Укажите существующий продукт базы EOL")
    row = (await db.execute(select(EolMapping).where(EolMapping.catalog_key == body.catalog_key))).scalars().first()
    if row is None:
        row = EolMapping(catalog_key=body.catalog_key, created_by=su.display_name)
        db.add(row)
    row.action, row.eol_product, row.note, row.created_by = body.action, body.eol_product if body.action == "map" else None, body.note, su.display_name
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="eol.mapping", target_type="eol_mapping", target_id=body.catalog_key, details={"action": body.action, "eol_product": body.eol_product})
    await db.commit()
    return {"id": str(row.id)}


@router.delete("/mappings/{mid}", status_code=204)
async def del_mapping(mid: str, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    try:
        row = await db.get(EolMapping, uuid.UUID(mid))
    except ValueError:
        row = None
    if row is None:
        raise HTTPException(status_code=404, detail="Решение не найдено")
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="eol.mapping_delete", target_type="eol_mapping", target_id=row.catalog_key)
    await db.execute(delete(EolMapping).where(EolMapping.id == row.id))
    await db.commit()


@router.get("/unmatched")
async def unmatched(q: str = Query("", max_length=200), limit: int = Query(100, ge=1, le=300), su: SessionUser = Depends(require_user), srcs: list[KscSource] = Depends(source_scope),
                    db: AsyncSession = Depends(get_db)):
    """Программы каталога, для которых в базе EOL нет соответствия, а также спорные (подходит несколько продуктов) — для ручного сопоставления. Самые распространённые первыми."""
    sids = [s.id for s in srcs]
    ambiguous = (await db.execute(select(EolFinding).where(EolFinding.source_id.in_(sids), EolFinding.kind == "app", EolFinding.status == "unknown").order_by(EolFinding.hosts_active.desc()).limit(limit))).scalars().all()
    maps = {m.catalog_key: m for m in (await db.execute(select(EolMapping))).scalars()}
    idx = await C.load_index(db)
    out, seen = [], set()
    for src in srcs:
        prods = await C.light_catalog(db, src.id)
        from ..vdb import match as M  # noqa: PLC0415

        cand = C.candidates(idx, M.Matcher(prods, []), maps)
        for p in sorted(prods, key=lambda p: -p.hosts_active):
            if p.key in cand or p.key in maps or p.key in seen or p.hosts_active <= 0 or p.component:
                continue
            if q and not any_of_text(q, p.name, p.publisher):
                continue
            seen.add(p.key)
            out.append({"catalog_key": p.key, "name": p.name, "publisher": p.publisher, "hosts": p.hosts_active, "source": src.name})
            if len(out) >= limit:
                break
    return {"items": out, "ambiguous": [{"catalog_key": f.subject, "name": f.title, "publisher": f.publisher, "hosts": f.hosts_active, "reason": f.condition, "source": _names(srcs).get(f.source_id, "")} for f in ambiguous]}


def any_of_text(q: str, *values: str) -> bool:
    from ..search import any_field  # noqa: PLC0415

    m = any_field(q)
    return True if m is None else bool(m(*values))


@router.post("/recalc", status_code=202)
async def recalc(su: SessionUser = Depends(require_analyst), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    """Пересчитать сопоставление по выбранным источникам: фоновая служба подхватит в течение минуты; прежние данные остаются до завершения."""
    ids = [s.id for s in srcs]
    for sid in ids:
        if await db.get(EolState, sid) is None:
            db.add(EolState(source_id=sid))
    await db.flush()
    await db.execute(update(EolState).where(EolState.source_id.in_(ids)).values(inputs="", error_at=None))
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="eol.recalc", target_type="eol", target_id=",".join(str(i) for i in ids))
    await db.commit()
    return {"queued": len(ids)}
