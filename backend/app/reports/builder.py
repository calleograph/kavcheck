"""Построение отчётов по данным KSC (в рабочем потоке, на одном соединении). Строка отчёта ПО = компьютер × пакет × версия.
Виды: software_hosts — компьютеры с выбранными программами/версиями; hosts — список компьютеров с активностью."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Callable

from ..ksc import hosts as H
from ..ksc import queries as q
from ..ksc import versions
from ..ksc.driver import KscError, Session
from ..ksc.grouping import Rule

Progress = Callable[[str], None]
CancelCheck = Callable[[], bool]

SOFTWARE_COLUMNS = [("name", "Компьютер"), ("fqdn", "FQDN"), ("ip", "IP-адрес"), ("os", "ОС"), ("linux_release", "Дистрибутив Linux"), ("platform", "Платформа пакета"),
                    ("app_name", "Программа"), ("app_version", "Версия"), ("compared_version", "Сравниваемая версия"), ("branch", "Ветка"), ("publisher", "Производитель"),
                    ("install_date", "Дата установки"), ("last_connected", "Последнее подключение (UTC)"), ("days_since_connection", "Суток без связи"),
                    ("activity", "Активность"), ("group", "Группа администрирования"), ("host_id", "HostId"), ("product_id", "ProductId"), ("install_id", "InstallId")]
HOST_COLUMNS = [("name", "Компьютер"), ("fqdn", "FQDN"), ("ip", "IP-адрес"), ("os", "ОС"), ("os_version", "Версия ОС"), ("group", "Группа администрирования"),
                ("last_connected", "Последнее подключение (UTC)"), ("last_visible", "Последняя видимость (UTC)"), ("days_since_connection", "Суток без связи"),
                ("activity", "Активность"), ("last_av_update", "Обновление баз (UTC)"), ("host_id", "HostId")]


class Cancelled(Exception):
    pass


def _check(cancelled: CancelCheck) -> None:
    if cancelled():
        raise Cancelled()


def _products(s: Session, params: dict, rule: Rule | None, progress: Progress, cancelled: CancelCheck) -> list[dict]:
    """Записи продуктов по параметрам: явные идентификаторы, правило группировки (+ ветки) или шаблон названия."""
    platform = params.get("platform") or ""
    pm = {"windows": 1, "linux": 2}.get(platform)
    out: list[dict] = []
    if params.get("product_ids"):
        ids = [int(x) for x in params["product_ids"]]
        for k in range(0, len(ids), 500):
            out += s.query(q.PRODUCTS_BY_IDS.format(ids=q.ids_list(ids[k:k + 500])), max_rows=1000)
    else:
        like = rule.name_like if rule else (params.get("name_like") or "")
        if not like:
            raise KscError("params", "Не задан ни список программ, ни правило, ни шаблон названия")
        extra = " AND EXISTS (SELECT 1 FROM dbo.hst_inventory_hstprds i WHERE i.nProduct = p.nId AND i.bDeleted = 0)"
        p: dict = {"like": like}
        if pm:
            extra += " AND (p.nPlatformTypeMask & %(pm)s) <> 0"
            p["pm"] = pm
        offset = 0
        while True:
            _check(cancelled)
            rows = s.query(q.PRODUCTS_BY_LIKE.format(extra=extra), {**p, "offset": offset, "limit": 2000}, max_rows=2000)
            out += rows
            if len(rows) < 2000:
                break
            offset += 2000
            if offset >= 50_000:
                raise KscError("too_many_rows", "Под шаблон названия подпадает больше 50 000 записей: уточните фильтр")
        if rule:
            out = [r for r in out if rule.matches(r.get("name") or "")]
    rx = re.compile(params["name_regex"], re.I) if params.get("name_regex") else None
    branches = set(params.get("branches") or [])
    minv, maxv, below = params.get("min_version") or None, params.get("max_version") or None, params.get("below_version") or None
    res = []
    for r in out:
        name, ver = r.get("name") or "", r.get("version") or ""
        if rx and not rx.search(name):
            continue
        if pm and not (int(r.get("platform_mask") or 0) & pm):
            continue
        cv = rule.compared_version(name, ver) if rule else versions.upstream(ver)
        if branches:
            br = rule.branch(name, ver) if rule else versions.branch_of(ver)
            if (br or "") not in branches:
                continue
        if not versions.in_range(cv, minv, maxv, below):
            continue
        res.append(r)
    progress(f"отобрано записей программ: {len(res)}")
    return res


def _installs(s: Session, product_ids: list[int], max_rows: int, progress: Progress, cancelled: CancelCheck) -> list[dict]:
    out: list[dict] = []
    for k in range(0, len(product_ids), 300):
        chunk = product_ids[k:k + 300]
        offset = 0
        while True:
            _check(cancelled)
            rows = s.query(q.INSTALLS_BY_PRODUCTS.format(ids=q.ids_list(chunk)), {"offset": offset, "limit": 5000}, max_rows=5000)
            out += rows
            if len(out) > max_rows:
                raise KscError("too_many_rows", f"Установок больше предела отчёта ({max_rows}): сузьте выбор")
            if len(rows) < 5000:
                break
            offset += 5000
        progress(f"установок прочитано: {len(out)}")
    return out


def _hosts(s: Session, host_ids: list[int], cancelled: CancelCheck) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for k in range(0, len(host_ids), 500):
        _check(cancelled)
        for h in s.query(q.HOSTS_BY_IDS.format(ids=q.ids_list(host_ids[k:k + 500])), max_rows=1000):
            out[int(h["host_id"])] = h
    return out


def build_software(conn: Session, params: dict, rule: Rule | None, *, max_rows: int, exclude_slaves: bool, progress: Progress, cancelled: CancelCheck) -> tuple[list[dict], dict]:
    now = datetime.now(timezone.utc)
    products = _products(conn, params, rule, progress, cancelled)
    by_id = {int(p["product_id"]): p for p in products}
    installs = _installs(conn, list(by_id), max_rows, progress, cancelled) if by_id else []
    host_ids = sorted({int(i["host_id"]) for i in installs})
    hosts = _hosts(conn, host_ids, cancelled)
    groups = {int(r["group_id"]): {"name": r["name"], "parent_id": r["parent_id"]} for r in conn.query(q.GROUPS_ALL, max_rows=100_000)}
    releases = H.releases_sync(conn, host_ids) if host_ids else {}
    active_days = params.get("active_days")
    include_inactive = bool(params.get("include_inactive"))
    group_contains = (params.get("group_contains") or "").lower()
    rows, excluded_inactive, excluded_missing = [], set(), 0
    for i in installs:
        h = hosts.get(int(i["host_id"]))
        if h is None or (exclude_slaves and h.get("is_slave")):
            excluded_missing += 1
            continue
        p = by_id[int(i["product_id"])]
        hr = H.host_row(h, groups, now, releases.get(int(h["host_id"])))
        if group_contains and group_contains not in hr["group"].lower():
            continue
        if not include_inactive and active_days is not None and (hr["days_since_connection"] is None or hr["days_since_connection"] > active_days):
            excluded_inactive.add(hr["host_id"])
            continue
        name, ver = p.get("name") or "", p.get("version") or ""
        cv = rule.compared_version(name, ver) if rule else versions.upstream(ver)
        br = (rule.branch(name, ver) if rule else versions.branch_of(ver)) or ""
        rows.append({**{k: hr[k] for k in ("name", "fqdn", "ip", "os", "linux_release", "last_connected", "days_since_connection", "activity", "group", "host_id")},
                     "platform": {1: "Windows", 2: "Linux"}.get(p.get("platform_mask"), ""), "app_name": name, "app_version": ver, "compared_version": cv, "branch": br,
                     "publisher": p.get("publisher") or "", "install_date": i.get("install_date"), "product_id": int(p["product_id"]), "install_id": int(i["install_id"])})
    rows.sort(key=lambda r: (r["name"].lower(), r["app_name"].lower(), versions.sort_key(r["app_version"])))
    by_branch: dict[str, dict] = {}
    for r in rows:
        b = by_branch.setdefault(r["branch"], {"branch": r["branch"] or "(не определена)", "installs": 0, "hosts": set(), "packages": set()})
        b["installs"] += 1
        b["hosts"].add(r["host_id"])
        b["packages"].add(r["app_name"])
    branches = [{"branch": b["branch"], "installs": b["installs"], "hosts": len(b["hosts"]), "packages": sorted(b["packages"])}
                for _, b in sorted(by_branch.items(), key=lambda kv: (kv[0] == "", versions.sort_key(kv[0] or "0")), reverse=True)]
    summary = {"products": len(products), "installs_total": len(installs), "rows": len(rows), "hosts": len({r["host_id"] for r in rows}),
               "excluded_inactive_hosts": len(excluded_inactive), "excluded_not_computers": excluded_missing, "branches": branches,
               "active_days": active_days, "include_inactive": include_inactive, "fetched_at": now.isoformat(timespec="seconds")}
    progress(f"готово: строк {len(rows)}, компьютеров {summary['hosts']}")
    return rows, summary


def build_hosts(conn: Session, params: dict, *, max_rows: int, exclude_slaves: bool, progress: Progress, cancelled: CancelCheck) -> tuple[list[dict], dict]:
    now = datetime.now(timezone.utc)
    active_days = params.get("active_days")
    where, p = H.hosts_where(qtext=params.get("q") or "", group_contains=params.get("group_contains") or "", os_contains=params.get("os_contains") or "",
                             active_days=None if params.get("include_inactive") else active_days, inactive_only=bool(params.get("inactive_only")), exclude_slaves=exclude_slaves)
    groups = {int(r["group_id"]): {"name": r["name"], "parent_id": r["parent_id"]} for r in conn.query(q.GROUPS_ALL, max_rows=100_000)}
    rows: list[dict] = []
    offset = 0
    while True:
        _check(cancelled)
        batch = conn.query(q.HOSTS_PAGE.format(where=where, order="h.nId ASC"), {**p, "offset": offset, "limit": 2000}, max_rows=2000)
        rows += [H.host_row(h, groups, now) for h in batch]
        if len(rows) > max_rows:
            raise KscError("too_many_rows", f"Компьютеров больше предела отчёта ({max_rows})")
        progress(f"компьютеров прочитано: {len(rows)}")
        if len(batch) < 2000:
            break
        offset += 2000
    rows.sort(key=lambda r: r["name"].lower())
    summary = {"rows": len(rows), "hosts": len(rows), "active_days": active_days, "include_inactive": bool(params.get("include_inactive")),
               "fetched_at": now.isoformat(timespec="seconds")}
    return rows, summary
