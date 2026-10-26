"""Уязвимости, подтверждённые KSC (vapm_*): действующие обнаружения с CVE, опасностью и программой из реестра ПО."""
from __future__ import annotations

from ..search import mssql_like
from . import queries as q
from .driver import SourceClient

SEVERITY = {1: "предупреждение", 2: "высокая", 4: "критическая"}
SEVERITY_KEY = {1: "warning", 2: "high", 4: "critical"}


def vuln_where(*, cve: str = "", product: str = "", product_id: int | None = None, product_name: str | None = None, severity: int | None = None) -> tuple[str, dict]:
    where, params = [q.VULNS_WHERE], {}
    if mssql_like(cve):
        where.append(q.VULN_CVE_EXISTS)
        params["cve"] = mssql_like(cve)
    if mssql_like(product):
        where.append("(vp.wstrName LIKE %(prod)s OR p.wstrDisplayName LIKE %(prod)s)")
        params["prod"] = mssql_like(product)
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
    if mssql_like(host):
        where.append("h.wstrDisplayName LIKE %(host)s")
        params["host"] = mssql_like(host)
    if mssql_like(cve):
        where.append("n.wstrName LIKE %(cve)s")
        params["cve"] = mssql_like(cve)
    if mssql_like(product):
        where.append("(p.wstrDisplayName LIKE %(prod)s OR vp.wstrName LIKE %(prod)s)")
        params["prod"] = mssql_like(product)
    if severity in (1, 2, 4):
        where.append("d.nKlSeverity = %(sev)s")
        params["sev"] = severity
    w = " AND ".join(where)
    rows = await client.run(q.VULNS_PAGE.format(where=w), {**params, "offset": offset, "limit": limit}, max_rows=limit)
    count_where = w.replace("(p.wstrDisplayName LIKE %(prod)s OR vp.wstrName LIKE %(prod)s)", "1 = 1") if mssql_like(product) else w   # в COUNT нет соединения с продуктами
    total = int((await client.run(q.VULNS_COUNT.format(where=count_where), params, max_rows=1))[0]["n"])
    items = [{"occurrence_id": int(r["occurrence_id"]), "host_id": int(r["host_id"]), "host": r.get("host") or "", "detected": r.get("detected"), "kla_id": r.get("kla_id") or "",
              "severity": SEVERITY.get(r.get("severity"), str(r.get("severity") or "")), "cve": r.get("cve") or "", "product": r.get("product") or r.get("app_name") or "",
              "product_version": r.get("product_version") or r.get("app_version") or "", "patches_available": bool(r.get("patches_available")), "url": r.get("url") or ""} for r in rows]
    return {"items": items, "total": total, "offset": offset, "limit": limit, "approximate_total": bool(product)}


# ------------------------------------------------------------------------------------------------ быстрые отчёты и список уязвимостей
async def names_for(client: SourceClient, descr_ids: list[int]) -> dict[int, dict[str, list[str]]]:
    """CVE и KB по идентификаторам уязвимостей KSC (порциями)."""
    out: dict[int, dict[str, list[str]]] = {}
    ids = sorted({int(i) for i in descr_ids})
    for k in range(0, len(ids), 500):
        for n in await client.run(q.VULN_NAMES.format(ids=q.ids_list(ids[k:k + 500])), max_rows=100_000):
            d = out.setdefault(int(n["descr_id"]), {"cve": [], "kb": []})
            key = {3: "cve", 6: "kb"}.get(int(n["sense"]))
            if key and n.get("name") and n["name"] not in d[key]:
                d[key].append(n["name"])
    return out


async def resolve_cves(client: SourceClient, cves: list[str]) -> dict[str, int | None]:
    """Идентификаторы уязвимостей KSC по списку CVE; None — такого CVE в KSC нет."""
    found: dict[str, list[int]] = {}
    clean = [c.strip().upper() for c in cves if c and c.strip()][:200]
    for k in range(0, len(clean), 100):
        chunk = clean[k:k + 100]
        names = ", ".join(f"%(c{i})s" for i in range(len(chunk)))
        for r in await client.run(q.VULN_DESCR_BY_CVE.format(names=names), {f"c{i}": c for i, c in enumerate(chunk)}, max_rows=100_000):
            found.setdefault(str(r["name"]).upper(), []).append(int(r["descr_id"]))
    return {c: (found[c][0] if c in found else None) for c in clean}


async def detail_rows(client: SourceClient, *, descr_ids: list[int], vp_ids: list[int], product_names: list[str], host_ids: list[int], severity: int | None, patchable: bool,
                      max_rows: int, progress=lambda _t: None, cancelled=lambda: False) -> list[dict]:
    """Действующие обнаружения выбранных уязвимостей и программ (или всех уязвимостей выбранных компьютеров). Один проход по ключу o.nId, порциями по 50 000;
    активность и сеть — в приложении (по строкам), чтобы отчёт мог сказать, сколько компьютеров не вошло и почему."""
    sel, params = [], {}
    if descr_ids:
        sel.append(f"d.nId IN ({q.ids_list(descr_ids[:5000])})")
    if vp_ids:
        sel.append(f"vp.nId IN ({q.ids_list(vp_ids[:5000])})")
    names = [n for n in product_names if n][:50]
    if names:
        keys = ", ".join(f"%(n{i})s" for i in range(len(names)))
        sel.append(f"(vp.nId IS NULL AND p.wstrDisplayName IN ({keys}))")
        params.update({f"n{i}": n for i, n in enumerate(names)})
    extra = []
    if sel:
        extra.append("(" + " OR ".join(sel) + ")")
    if host_ids:
        extra.append(f"o.nHostId IN ({q.ids_list(host_ids[:5000])})")
    if not extra:
        raise ValueError("Не выбраны уязвимости, программы или компьютеры")
    if severity in (1, 2, 4):
        extra.append("d.nKlSeverity = %(sev)s")
        params["sev"] = severity
    if patchable:
        extra.append("o.bPatchesAvailable = 1")
    sql = q.VULN_DETAIL.format(top=50000, extra=" AND " + " AND ".join(extra))
    out: list[dict] = []
    after = 0
    while True:
        if cancelled():
            raise RuntimeError("cancelled")
        rows = await client.run(sql, {**params, "after": after}, max_rows=50_000)
        out += rows
        if len(out) > max_rows:
            from .driver import KscError  # noqa: PLC0415

            raise KscError("too_many_rows", f"Обнаружений больше предела отчёта ({max_rows}): сузьте выбор или период")
        progress(f"обнаружений прочитано: {len(out)}")
        if len(rows) < 50_000:
            return out
        after = int(rows[-1]["occurrence_id"])


async def descr_list(client: SourceClient, *, active_days: int | None, exclude_slaves: bool) -> list[dict]:
    """Список действующих уязвимостей KSC: опасность, CVE, затронутые программы, число компьютеров (один набор запросов, кэшируется)."""
    where = q.VULNS_WHERE
    if exclude_slaves:
        where += " AND h.bIsSlaveServer = 0"
    params: dict = {}
    if active_days:
        where += " AND h.tmLastNagentConnected >= DATEADD(day, -%(days)s, GETUTCDATE())"
        params["days"] = int(active_days)
    rows = await client.run(q.VULN_DESCR_AGG.format(where=where), params, max_rows=500_000)
    prods = await client.run(q.VULN_DESCR_PRODUCTS.format(where=where), params, max_rows=1_000_000)
    info: dict[int, dict] = {}
    for k in range(0, len(rows), 500):
        for d in await client.run(q.VULN_DESCR_INFO.format(ids=q.ids_list([int(r["descr_id"]) for r in rows[k:k + 500]])), max_rows=100_000):
            info[int(d["descr_id"])] = d
    names = await names_for(client, [int(r["descr_id"]) for r in rows])      # имена только для найденных уязвимостей, не соединение по всей таблице
    by_descr: dict[int, list[tuple[str, int]]] = {}
    for p in prods:
        by_descr.setdefault(int(p["descr_id"]), []).append((p.get("product") or "", int(p["hosts"])))
    out = []
    for r in rows:
        did = int(r["descr_id"])
        r = {**info.get(did, {}), **r}
        nm = names.get(did, {"cve": [], "kb": []})
        pr = sorted(by_descr.get(did, []), key=lambda x: -x[1])
        out.append({"descr_id": did, "kla_id": r.get("kla_id") or "", "severity": SEVERITY_KEY.get(r.get("severity"), "warning"), "severity_label": SEVERITY.get(r.get("severity"), ""),
                    "url": r.get("url") or "", "cve": sorted(nm["cve"]), "kb": nm["kb"], "products": [p for p, _ in pr if p][:6], "hosts": int(r["hosts"]), "total": int(r["total"]),
                    "patchable": int(r.get("patchable") or 0), "last_detected": r.get("last_detected")})
    return out


async def iter_detail_pages(client: SourceClient, *, host_ids: list[int] | None = None, exclude_slaves: bool = True, page: int = 20000, cancelled=lambda: False):
    """Действующие обнаружения порциями (по page строк, keyset по o.nId): весь источник или выбранные компьютеры. В памяти — одна порция, а не весь набор."""
    extra = ["h.bIsSlaveServer = 0"] if exclude_slaves else []
    if host_ids is not None:
        extra.append(f"o.nHostId IN ({q.ids_list(host_ids[:5000])})")
    sql = q.VULN_DETAIL.format(top=int(page), extra=(" AND " + " AND ".join(extra)) if extra else "")
    after = 0
    while True:
        if cancelled():
            raise RuntimeError("cancelled")
        rows = await client.run(sql, {"after": after}, max_rows=page)
        if rows:
            yield rows
        if len(rows) < page:
            return
        after = int(rows[-1]["occurrence_id"])


async def stamp(client: SourceClient) -> str:
    """Лёгкий отпечаток данных KSC (число компьютеров и действующих обнаружений, наибольшие идентификаторы): изменился — значит, после расчёта пришли новые сведения."""
    try:
        r = (await client.run(q.KSC_STAMP, max_rows=1))[0]
        return f"{r.get('hosts')}:{r.get('max_host')}:{r.get('vulns')}:{r.get('max_occ')}"
    except Exception:  # noqa: BLE001 — нет представлений уязвимостей: отпечаток по компьютерам
        r = (await client.run(q.COUNT_HOSTS, max_rows=1))[0]
        return f"{r.get('n')}:::"
