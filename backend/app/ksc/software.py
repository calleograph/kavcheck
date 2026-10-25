"""Реестр установленного ПО: исходные записи KSC (hst_inventory_products) и логическая группировка по правилам (продукт → ветки версий)."""
from __future__ import annotations

import re

from ..search import mssql_like
from . import queries as q
from . import versions
from .driver import KscError, SourceClient
from .grouping import Rule

_SORT = {"name": "p.wstrDisplayName", "version": "p.wstrDisplayVersion", "publisher": "p.wstrPublisher", "first_seen": "p.tmFirstAppear"}
PLATFORM = {1: "Windows", 2: "Linux"}
MAX_PRODUCTS_PER_RULE = 20_000


def products_where(*, qtext: str = "", publisher: str = "", version: str = "", platform: str = "", installed_only: bool = True) -> tuple[str, dict]:
    where, params = [], {}
    for text, sql, name, mode in ((qtext, "p.wstrDisplayName", "q", "contains"), (publisher, "p.wstrPublisher", "pub", "contains"), (version, "p.wstrDisplayVersion", "ver", "prefix")):
        like = mssql_like(text, mode)
        if like:
            where.append(f"{sql} LIKE %({name})s")
            params[name] = like
    if platform in ("windows", "linux"):
        where.append("(p.nPlatformTypeMask & %(pm)s) <> 0")
        params["pm"] = 1 if platform == "windows" else 2
    if installed_only:
        where.append("EXISTS (SELECT 1 FROM dbo.hst_inventory_hstprds i WHERE i.nProduct = p.nId AND i.bDeleted = 0)")
    return " AND ".join(where) or "1 = 1", params


def product_row(r: dict, counts: dict | None = None) -> dict:
    c = (counts or {}).get(int(r["product_id"]), {})
    return {"product_id": int(r["product_id"]), "name": r.get("name") or "", "version": r.get("version") or "", "publisher": r.get("publisher") or "",
            "platform": PLATFORM.get(r.get("platform_mask"), str(r.get("platform_mask") or "")), "first_seen": r.get("first_seen"),
            "upstream_version": versions.upstream(r.get("version") or ""), "installs": int(c.get("installs", 0)), "hosts": int(c.get("hosts", 0))}


async def install_counts(client: SourceClient, product_ids: list[int], active_days: int | None = None) -> dict[int, dict]:
    """Установок и компьютеров на запись реестра; active_days — только компьютеры, подключавшиеся к KSC за этот срок (глобальный фильтр)."""
    out: dict[int, dict] = {}
    for k in range(0, len(product_ids), 500):
        chunk = product_ids[k:k + 500]
        sql = (q.INSTALL_COUNTS_ACTIVE if active_days else q.INSTALL_COUNTS).format(ids=q.ids_list(chunk))
        for r in await client.run(sql, {"days": int(active_days)} if active_days else None, max_rows=len(chunk) + 1):
            out[int(r["product_id"])] = {"installs": int(r["installs"]), "hosts": int(r["hosts"])}
    return out


async def registry_page(client: SourceClient, *, offset: int, limit: int, sort: str = "name", desc: bool = False, active_days: int | None = None, **filters) -> dict:
    where, params = products_where(**filters)
    col = _SORT.get(sort, "p.wstrDisplayName")
    order = f"{col} {'DESC' if desc else 'ASC'}, p.nId"
    rows = await client.run(q.PRODUCTS_PAGE.format(where=where, order=order), {**params, "offset": offset, "limit": limit}, max_rows=limit)
    total = int((await client.run(q.PRODUCTS_COUNT.format(where=where), params, max_rows=1))[0]["n"])
    counts = await install_counts(client, [int(r["product_id"]) for r in rows], active_days) if rows else {}
    return {"items": [product_row(r, counts) for r in rows], "total": total, "offset": offset, "limit": limit}


async def products_by_ids(client: SourceClient, ids: list[int]) -> list[dict]:
    out: list[dict] = []
    for k in range(0, len(ids), 500):
        out += await client.run(q.PRODUCTS_BY_IDS.format(ids=q.ids_list(ids[k:k + 500])), max_rows=1000)
    return out


async def products_by_rule(client: SourceClient, rule: Rule, *, platform: str = "", installed_only: bool = True) -> list[dict]:
    """Все записи продуктов, подходящие под правило (LIKE в базе, затем регулярное выражение в коде). Предел — MAX_PRODUCTS_PER_RULE."""
    extra = ""
    params: dict = {"like": rule.name_like}
    if platform in ("windows", "linux"):
        extra += " AND (p.nPlatformTypeMask & %(pm)s) <> 0"
        params["pm"] = 1 if platform == "windows" else 2
    if installed_only:
        extra += " AND EXISTS (SELECT 1 FROM dbo.hst_inventory_hstprds i WHERE i.nProduct = p.nId AND i.bDeleted = 0)"
    out, offset, page = [], 0, 2000
    while True:
        rows = await client.run(q.PRODUCTS_BY_LIKE.format(extra=extra), {**params, "offset": offset, "limit": page}, max_rows=page)
        out += [r for r in rows if rule.matches(r.get("name") or "")]
        if len(rows) < page:
            break
        offset += page
        if offset >= MAX_PRODUCTS_PER_RULE:
            raise KscError("too_many_rows", f"Под правило «{rule.name}» подпадает больше {MAX_PRODUCTS_PER_RULE} записей: уточните шаблон LIKE")
    return out


async def grouped_view(client: SourceClient, rule: Rule, *, platform: str = "") -> dict:
    """Сводка по веткам продукта: установок и уникальных компьютеров на ветку, какие пакеты вошли. Пустая ветка — «не определена»."""
    products = await products_by_rule(client, rule, platform=platform)
    ids = [int(p["product_id"]) for p in products]
    # установки по продуктам (нужны идентификаторы компьютеров для подсчёта уникальных по ветке)
    installs: list[dict] = []
    for k in range(0, len(ids), 300):
        chunk = ids[k:k + 300]
        offset = 0
        while True:
            rows = await client.run(q.INSTALLS_BY_PRODUCTS.format(ids=q.ids_list(chunk)), {"offset": offset, "limit": 5000}, max_rows=5000)
            installs += rows
            if len(rows) < 5000:
                break
            offset += 5000
    by_id = {int(p["product_id"]): p for p in products}
    branches: dict[str, dict] = {}
    for i in installs:
        p = by_id[int(i["product_id"])]
        br = rule.branch(p.get("name") or "", p.get("version") or "")
        b = branches.setdefault(br, {"branch": br, "installs": 0, "hosts": set(), "packages": {}, "versions": set()})
        b["installs"] += 1
        b["hosts"].add(int(i["host_id"]))
        b["packages"][int(p["product_id"])] = p
        b["versions"].add(rule.compared_version(p.get("name") or "", p.get("version") or ""))
    out = []
    for br, b in branches.items():
        pk = sorted(b["packages"].values(), key=lambda p: ((p.get("name") or "").lower(), versions.sort_key(p.get("version") or "")))
        out.append({"branch": br or None, "installs": b["installs"], "hosts": len(b["hosts"]), "packages_count": len(pk),
                    "versions": sorted(b["versions"], key=versions.sort_key),
                    "packages": [{"product_id": int(p["product_id"]), "name": p.get("name") or "", "version": p.get("version") or "", "publisher": p.get("publisher") or "",
                                  "platform": PLATFORM.get(p.get("platform_mask"), ""), "compared_version": rule.compared_version(p.get("name") or "", p.get("version") or "")} for p in pk]})
    out.sort(key=lambda b: (b["branch"] is None, versions.sort_key(b["branch"] or "0")), reverse=False)
    out.sort(key=lambda b: (b["branch"] is None, -(0 if b["branch"] is None else 1)))
    defined = sorted([b for b in out if b["branch"]], key=lambda b: versions.sort_key(b["branch"]), reverse=True)
    undefined = [b for b in out if not b["branch"]]
    return {"rule": {"key": rule.key, "name": rule.name, "name_like": rule.name_like, "name_regex": rule.name_regex, "branch_regex": rule.branch_regex},
            "branches": defined + undefined, "products": len(products), "installs": len(installs), "hosts": len({int(i["host_id"]) for i in installs})}


def select_products(products: list[dict], rule: Rule | None, *, branches: list[str] | None, min_version: str | None, max_version: str | None,
                    below_version: str | None, name_regex: str | None) -> list[dict]:
    """Отбор записей продуктов по веткам (для правила) и диапазону версий."""
    rx = re.compile(name_regex, re.I) if name_regex else None
    out = []
    for p in products:
        name, ver = p.get("name") or "", p.get("version") or ""
        if rx and not rx.search(name):
            continue
        cv = rule.compared_version(name, ver) if rule else versions.upstream(ver)
        if branches and rule:
            br = rule.branch(name, ver)
            if (br or "") not in branches and not (br == "" and "" in branches):
                continue
        if not versions.in_range(cv, min_version, max_version, below_version):
            continue
        out.append(p)
    return out
