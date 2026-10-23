"""Уязвимости, подтверждённые KSC (vapm_*): действующие обнаружения с CVE, опасностью и программой из реестра ПО."""
from __future__ import annotations

from . import queries as q
from .driver import SourceClient

SEVERITY = {1: "предупреждение", 2: "высокая", 4: "критическая"}


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
