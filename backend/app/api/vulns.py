"""Уязвимости, подтверждённые KSC: компьютеры, отсортированные по опасности, уязвимые программы и карточка компьютера.

Тяжёлая часть (агрегирование vapm_vulnerability_occurence) выполняется одним запросом на SQL Server и кэшируется в памяти процесса
(cache_ttl_seconds); фильтры по имени, группе, уровню и сортировка — по кэшированному набору; в браузер уходит только страница."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, current_source, get_db, require_user
from ..ksc import hosts as H
from ..ksc import queries as q
from ..ksc import vulns as V
from ..ksc.driver import KscError
from ..models import KscSource

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])
SEV_PARAM = {"critical": 4, "high": 2, "warning": 1}


def _ksc(exc: KscError) -> HTTPException:
    return HTTPException(status_code=502 if exc.code in ("connect", "auth", "query") else 422, detail={"code": exc.code, "message": exc.message})


def unsupported(src: KscSource, feature: str = "vulnerabilities") -> list[str] | None:
    feats = (src.last_check or {}).get("features") or {}
    f = feats.get(feature)
    return f.get("missing") if f and not f.get("ok", True) else None


async def groups_cached(request: Request, src: KscSource) -> dict[int, dict]:
    cache = request.app.state.cache
    val, _ = await cache.get((str(src.id), "groups"), request.app.state.settings.cache_ttl_seconds, lambda: H.groups_map(request.app.state.sources.client(src)))
    return val


@router.get("/hosts")
async def hosts(request: Request, q_: str = Query("", alias="q", max_length=200), group: str = Query("", max_length=200), product: str = Query("", max_length=200),
                product_id: int | None = Query(None, ge=1), product_name: str | None = Query(None, max_length=300), cve: str = Query("", max_length=100),
                severity: str = Query("", pattern=r"^(|critical|high|warning)$"), patchable: bool = False,
                sort: str = Query("risk", pattern=r"^(risk|total|critical|high|name|last_connected|patchable)$"), desc: bool = True, all_hosts: bool = False,
                offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500), refresh: bool = False,
                su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Компьютеры с действующими уязвимостями: по умолчанию сначала самые проблемные (критические, затем высокие, затем всего)."""
    miss = unsupported(src)
    if miss:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "unsupported": miss, "summary": None}
    general = await request.app.state.settings_svc.get(db, "general")
    rcfg = await request.app.state.settings_svc.get(db, "reports")
    client = request.app.state.sources.client(src)
    filters = {"cve": cve, "product": product, "product_id": product_id, "product_name": product_name}
    key = (str(src.id), "vuln_hosts", cve, product, product_id, product_name, rcfg.exclude_slave_servers)

    async def make() -> list[dict]:
        """Агрегат по компьютерам один раз на срок кэша; страницы, фильтры и сортировка — по готовому списку."""
        rows = await V.hosts_aggregate(client, **filters)
        groups = await groups_cached(request, src)
        now = datetime.now(timezone.utc)
        out = []
        for r in rows:
            if rcfg.exclude_slave_servers and r.get("is_slave"):
                continue
            h = H.host_row(r, groups, now)
            out.append({**{k: h[k] for k in ("host_id", "name", "fqdn", "ip", "os", "os_version", "group", "last_connected", "days_since_connection", "activity")},
                        **{k: int(r.get(k) or 0) for k in ("critical", "high", "warning", "total", "patchable", "products")}, "last_detected": r.get("last_detected"),
                        "_search": f"{h['name']} {h['fqdn']} {h['ip']}".lower()})
        return out

    try:
        base, at = await request.app.state.cache.get(key, request.app.state.settings.cache_ttl_seconds, make, refresh=refresh)
    except KscError as exc:
        raise _ksc(exc) from None
    items, hidden = [], 0
    needle, gneedle = q_.strip().lower(), group.strip().lower()
    for i in base:
        if not all_hosts and (i["days_since_connection"] is None or i["days_since_connection"] > general.activity_days):
            hidden += 1
            continue
        items.append(i)
    summary = {"hosts": len(items), "hidden_hosts": hidden, "total": sum(i["total"] for i in items), "critical_hosts": sum(1 for i in items if i["critical"]),
               "high_hosts": sum(1 for i in items if i["high"]), "warning_hosts": sum(1 for i in items if i["warning"]),
               "critical": sum(i["critical"] for i in items), "high": sum(i["high"] for i in items), "warning": sum(i["warning"] for i in items),
               "patchable": sum(i["patchable"] for i in items), "activity_days": general.activity_days,
               "fetched_at": datetime.fromtimestamp(at, timezone.utc)}
    if needle:
        items = [i for i in items if needle in i["_search"]]
    if gneedle:
        items = [i for i in items if gneedle in i["group"].lower()]
    if severity:
        items = [i for i in items if i[severity] > 0]
    if patchable:
        items = [i for i in items if i["patchable"] > 0]
    keyf = {"risk": lambda i: (i["critical"], i["high"], i["total"]), "total": lambda i: i["total"], "critical": lambda i: i["critical"], "high": lambda i: i["high"],
            "patchable": lambda i: i["patchable"], "name": lambda i: i["name"].lower(),
            "last_connected": lambda i: i["last_connected"] or datetime.min.replace(tzinfo=timezone.utc)}[sort]
    items.sort(key=keyf, reverse=desc if sort != "name" else not desc)
    page = [{k: v for k, v in i.items() if k != "_search"} for i in items[offset:offset + limit]]
    return {"items": page, "total": len(items), "offset": offset, "limit": limit, "summary": summary}


@router.get("/products")
async def products(request: Request, q_: str = Query("", alias="q", max_length=200), cve: str = Query("", max_length=100),
                   severity: str = Query("", pattern=r"^(|critical|high|warning)$"), sort: str = Query("risk", pattern=r"^(risk|hosts|total|name)$"), desc: bool = True,
                   all_hosts: bool = False, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500), refresh: bool = False,
                   su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Уязвимые программы: сколько компьютеров затронуто, сколько уязвимостей по уровням опасности."""
    miss = unsupported(src)
    if miss:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "unsupported": miss}
    general = await request.app.state.settings_svc.get(db, "general")
    rcfg = await request.app.state.settings_svc.get(db, "reports")
    client = request.app.state.sources.client(src)
    days = None if all_hosts else general.activity_days
    key = (str(src.id), "vuln_products", cve, days)
    try:
        rows, at = await request.app.state.cache.get(key, request.app.state.settings.cache_ttl_seconds,
                                                     lambda: V.products_aggregate(client, active_days=days, exclude_slaves=rcfg.exclude_slave_servers, cve=cve), refresh=refresh)
    except KscError as exc:
        raise _ksc(exc) from None
    items = [{"product_id": int(r["vp_id"] or 0) or None, "name": r.get("name") or "(не определена)", **{k: int(r.get(k) or 0) for k in ("hosts", "vulns", "critical", "high", "warning", "total", "patchable")},
              "last_detected": r.get("last_detected")} for r in rows]
    if q_.strip():
        items = [i for i in items if q_.strip().lower() in i["name"].lower()]
    if severity:
        items = [i for i in items if i[severity] > 0]
    keyf = {"risk": lambda i: (i["critical"] > 0, i["high"] > 0, i["hosts"], i["total"]), "hosts": lambda i: i["hosts"], "total": lambda i: i["total"],
            "name": lambda i: i["name"].lower()}[sort]
    items.sort(key=keyf, reverse=desc if sort != "name" else not desc)
    return {"items": items[offset:offset + limit], "total": len(items), "offset": offset, "limit": limit, "fetched_at": datetime.fromtimestamp(at, timezone.utc),
            "activity_days": general.activity_days}


@router.get("/hosts/{host_id}")
async def host_vulns(host_id: int, request: Request, su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source)):
    """Карточка компьютера: все действующие уязвимости с программой, версией, CVE, бюллетенями, KB и наличием исправления."""
    miss = unsupported(src)
    if miss:
        return {"items": [], "unsupported": miss}
    client = request.app.state.sources.client(src)
    try:
        rows = await client.run(q.HOST_ONE, {"id": host_id}, max_rows=1)
        if not rows:
            raise HTTPException(status_code=404, detail="Устройство не найдено")
        groups = await groups_cached(request, src)
        items = await V.on_host(client, host_id)
    except KscError as exc:
        raise _ksc(exc) from None
    now = datetime.now(timezone.utc)
    h = H.host_row(rows[0], groups, now)
    counts = {k: sum(1 for i in items if i["severity"] == k) for k in ("critical", "high", "warning")}
    return {"host": {k: h[k] for k in ("host_id", "name", "fqdn", "ip", "os", "os_version", "group", "last_connected", "days_since_connection", "activity")},
            "items": items, "counts": counts, "total": len(items), "fetched_at": now}
