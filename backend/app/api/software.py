"""Реестр ПО: исходные записи KSC, группировка по правилам, компьютеры с выбранными программами."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, current_source, get_db, require_user
from ..ksc import hosts as H
from ..ksc import queries as q
from ..ksc import software as S
from ..ksc.driver import KscError
from ..ksc.grouping import Rule
from ..models import GroupingRule, KscSource
from .schemas import ReportParams

router = APIRouter(prefix="/software", tags=["software"])


def _ksc(exc: KscError) -> HTTPException:
    return HTTPException(status_code=502 if exc.code in ("connect", "auth", "query") else 422, detail={"code": exc.code, "message": exc.message})


async def load_rule(db: AsyncSession, key: str) -> Rule:
    row = (await db.execute(select(GroupingRule).where(GroupingRule.key == key, GroupingRule.enabled.is_(True)))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Правило группировки не найдено")
    return Rule(row.key, row.name, row.name_like, row.name_regex, row.branch_regex, row.branch_parts, row.exclude_regex)


@router.get("")
async def registry(request: Request, q_: str = Query("", alias="q", max_length=200), publisher: str = Query("", max_length=200), version: str = Query("", max_length=100),
                   platform: str = Query("", pattern=r"^(windows|linux)?$"), installed_only: bool = True, sort: str = Query("name"), desc: bool = False, all_hosts: bool = False,
                   offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source),
                   db: AsyncSession = Depends(get_db)):
    """Исходный реестр программ KSC: название, версия, производитель, установок и уникальных компьютеров (активных — по глобальному фильтру). Постранично."""
    client = request.app.state.sources.client(src)
    general = await request.app.state.settings_svc.get(db, "general")
    try:
        out = await S.registry_page(client, offset=offset, limit=min(limit, request.app.state.settings.ksc_page_max), sort=sort, desc=desc, qtext=q_, publisher=publisher,
                                    version=version, platform=platform, installed_only=installed_only, active_days=None if all_hosts else general.activity_days)
        out["activity_days"] = general.activity_days
        return out
    except KscError as exc:
        raise _ksc(exc) from None


@router.get("/rules")
async def rules(db: AsyncSession = Depends(get_db), su: SessionUser = Depends(require_user)):
    rows = (await db.execute(select(GroupingRule).where(GroupingRule.enabled.is_(True)).order_by(GroupingRule.builtin.desc(), GroupingRule.name))).scalars().all()
    return {"items": [{"key": r.key, "name": r.name, "description": r.description, "builtin": r.builtin} for r in rows]}


@router.get("/grouped/{rule_key}")
async def grouped(rule_key: str, request: Request, platform: str = Query("", pattern=r"^(windows|linux)?$"), su: SessionUser = Depends(require_user),
                  src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Логическая группировка: продукт → ветки версий → пакеты. Исходные записи остаются доступны (packages)."""
    rule = await load_rule(db, rule_key)
    try:
        out = await S.grouped_view(request.app.state.sources.client(src), rule, platform=platform)
    except KscError as exc:
        raise _ksc(exc) from None
    out["fetched_at"] = datetime.now(timezone.utc)
    return out


@router.post("/hosts")
async def hosts_for_selection(request: Request, body: ReportParams, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
                              su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Компьютеры с выбранными программами и версиями (быстрый просмотр, до предела страницы). Полный список — фоновый отчёт."""
    from ..reports import builder  # noqa: PLC0415

    client = request.app.state.sources.client(src)
    rule = await load_rule(db, body.rule) if body.rule else None
    general = await request.app.state.settings_svc.get(db, "general")
    rcfg = await request.app.state.settings_svc.get(db, "reports")
    params = body.model_dump()
    if params.get("active_days") is None:
        params["active_days"] = general.activity_days
    settings = request.app.state.settings

    def work():
        from ..ksc.driver import Session  # noqa: PLC0415

        with Session(request.app.state.sources.params(src)) as conn:
            return builder.build_software(conn, params, rule, max_rows=min(settings.ksc_max_rows, 20_000), exclude_slaves=rcfg.exclude_slave_servers, progress=lambda _t: None, cancelled=lambda: False)

    async def make():
        async with client._sem:  # noqa: SLF001 — один слот источника на всё построение
            return await asyncio.to_thread(work)

    # набор строится один раз и кэшируется: порции бесконечной прокрутки берутся из кэша
    key = (str(src.id), "software_hosts", json.dumps(params, sort_keys=True, default=str), rcfg.exclude_slave_servers)
    try:
        (rows, summary), _at = await request.app.state.cache.get(key, settings.cache_ttl_seconds, make)
    except KscError as exc:
        raise _ksc(exc) from None
    page = rows[offset:offset + limit]
    return {"items": page, "total": len(rows), "offset": offset, "limit": limit, "summary": {k: v for k, v in summary.items() if k != "branches"}, "branches": summary["branches"],
            "fetched_at": summary["fetched_at"]}


@router.get("/{product_id}/hosts")
async def product_hosts(product_id: int, request: Request, su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Компьютеры, на которых установлена одна запись реестра (до 5000)."""
    client = request.app.state.sources.client(src)
    general = await request.app.state.settings_svc.get(db, "general")
    try:
        installs = await client.run(q.INSTALLS_BY_PRODUCTS.format(ids=str(int(product_id))), {"offset": 0, "limit": 5000}, max_rows=5000)
        ids = sorted({int(i["host_id"]) for i in installs})
        hosts: dict[int, dict] = {}
        for k in range(0, len(ids), 500):
            for h in await client.run(q.HOSTS_BY_IDS.format(ids=q.ids_list(ids[k:k + 500])), max_rows=1000):
                hosts[int(h["host_id"])] = h
        groups = await H.groups_map(client)
    except KscError as exc:
        raise _ksc(exc) from None
    now = datetime.now(timezone.utc)
    items = []
    for i in installs:
        h = hosts.get(int(i["host_id"]))
        if h is None:
            continue
        items.append({**H.host_row(h, groups, now), "install_date": i.get("install_date"), "install_id": int(i["install_id"])})
    items.sort(key=lambda r: r["name"].lower())
    active = sum(1 for r in items if r["days_since_connection"] is not None and r["days_since_connection"] <= general.activity_days)
    return {"items": items, "total": len(items), "active": active, "inactive": len(items) - active, "activity_days": general.activity_days, "fetched_at": now}


_ = Body
