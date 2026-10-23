"""Уязвимости, подтверждённые KSC (vapm_*): действующие обнаружения с CVE, опасностью и программой из реестра ПО."""
from __future__ import annotations

from . import queries as q
from .driver import SourceClient

SEVERITY = {1: "предупреждение", 2: "высокая", 4: "критическая"}
SEVERITY_KEY = {1: "warning", 2: "high", 4: "critical"}


def vuln_where(*, cve: str = "", product: str = "", product_id: int | None = None, product_name: str | None = None, severity: int | None = None) -> tuple[str, dict]:
    where, params = [q.VULNS_WHERE], {}
    if cve:
        where.append(q.VULN_CVE_EXISTS)
        params["cve"] = f"%{cve.strip()}%"
    if product:
        where.append("(vp.wstrName LIKE %(prod)s OR p.wstrDisplayName LIKE %(prod)s)")
        params["prod"] = f"%{product.strip()}%"
    if product_id:
        where.append("vp.nId = %(vpid)s")
        params["vpid"] = int(product_id)
    elif product_name is not None:
        where.append("vp.nId IS NULL AND p.wstrDisplayName = %(pname)s")
        params["pname"] = product_name
    if severity in (1, 2, 4):
        where.append("d.nKlSeverity = %(sev)s")
        params["sev"] = severity
    return " AND ".join(where), params


async def hosts_aggregate(client: SourceClient, **filters) -> list[dict]:
    """Компьютеры с действующими уязвимостями и счётчики по уровням опасности (один запрос; фильтры по программе и CVE — в SQL)."""
    where, params = vuln_where(**filters)
    join = q.VULN_JOIN_INVENTORY if (filters.get("product") or filters.get("product_name") is not None) else ""
    return await client.run(q.VULN_HOSTS_AGG.format(where=where, join_inventory=join), params, max_rows=500_000)


async def products_aggregate(client: SourceClient, *, active_days: int | None, exclude_slaves: bool = True, **filters) -> list[dict]:
    where, params = vuln_where(**filters)
    if exclude_slaves:
        where += " AND h.bIsSlaveServer = 0"
    if active_days:
        where += " AND h.tmLastNagentConnected >= DATEADD(day, -%(days)s, GETUTCDATE())"
        params["days"] = int(active_days)
    return await client.run(q.VULN_PRODUCTS_AGG.format(where=where), params, max_rows=200_000)


async def on_host(client: SourceClient, host_id: int) -> list[dict]:
    rows = await client.run(q.VULNS_ON_HOST, {"host": int(host_id)}, max_rows=5000)
    ids = sorted({int(r["descr_id"]) for r in rows})
    names: dict[int, dict[str, list[str]]] = {}
    for k in range(0, len(ids), 500):
        for n in await client.run(q.VULN_NAMES.format(ids=q.ids_list(ids[k:k + 500])), max_rows=50_000):
            d = names.setdefault(int(n["descr_id"]), {"cve": [], "mssb": [], "kb": []})
            key = {3: "cve", 5: "mssb", 6: "kb"}.get(int(n["sense"]))
            if key and n.get("name") and n["name"] not in d[key]:
                d[key].append(n["name"])
    out = []
    for r in rows:
        nm = names.get(int(r["descr_id"]), {"cve": [], "mssb": [], "kb": []})
        out.append({"occurrence_id": int(r["occurrence_id"]), "kla_id": r.get("kla_id") or "", "severity": SEVERITY_KEY.get(r.get("severity"), "warning"),
                    "severity_label": SEVERITY.get(r.get("severity"), str(r.get("severity") or "")), "url": r.get("url") or "",
                    "product": r.get("product") or r.get("app_name") or "", "product_version": r.get("product_version") or "",
                    "app_name": r.get("app_name") or "", "app_version": r.get("app_version") or "", "publisher": r.get("publisher") or "",
                    "detected": r.get("detected"), "patches_available": bool(r.get("patches_available")), "cve": sorted(nm["cve"]), "mssb": nm["mssb"],
                    "kb": [f"KB{k}" if k.isdigit() else k for k in nm["kb"]]})
    return out


async def page(client: SourceClient, *, offset: int, limit: int, host: str = "", cve: str = "", product: str = "", severity: int | None = None) -> dict:
    where, params = [q.VULNS_WHERE], {}
    if host:
        where.append("h.wstrDisplayName LIKE %(host)s")
        params["host"] = f"%{host}%"
    if cve:
        where.append("n.wstrName LIKE %(cve)s")
        params["cve"] = f"%{cve}%"
    if product:
        where.append("(p.wstrDisplayName LIKE %(prod)s OR vp.wstrName LIKE %(prod)s)")
        params["prod"] = f"%{product}%"
    if severity in (1, 2, 4):
        where.append("d.nKlSeverity = %(sev)s")
        params["sev"] = severity
    w = " AND ".join(where)
    rows = await client.run(q.VULNS_PAGE.format(where=w), {**params, "offset": offset, "limit": limit}, max_rows=limit)
    count_where = w.replace("(p.wstrDisplayName LIKE %(prod)s OR vp.wstrName LIKE %(prod)s)", "1 = 1") if product else w   # в COUNT нет соединения с продуктами
    total = int((await client.run(q.VULNS_COUNT.format(where=count_where), params, max_rows=1))[0]["n"])
    items = [{"occurrence_id": int(r["occurrence_id"]), "host_id": int(r["host_id"]), "host": r.get("host") or "", "detected": r.get("detected"), "kla_id": r.get("kla_id") or "",
              "severity": SEVERITY.get(r.get("severity"), str(r.get("severity") or "")), "cve": r.get("cve") or "", "product": r.get("product") or r.get("app_name") or "",
              "product_version": r.get("product_version") or r.get("app_version") or "", "patches_available": bool(r.get("patches_available")), "url": r.get("url") or ""} for r in rows]
    return {"items": items, "total": total, "offset": offset, "limit": limit, "approximate_total": bool(product)}
