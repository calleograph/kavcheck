"""Компьютеры: активность по tmLastNagentConnected (пороги в сутках), IP из целого числа, путь группы, дистрибутив Linux."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..search import mssql_like
from . import queries as q

ACTIVITY = [(1, "≤1 сут"), (3, "≤3 сут"), (7, "≤7 сут"), (14, "≤14 сут"), (30, "≤30 сут")]
PLATFORM = {1: "Windows", 2: "Linux"}
_SORT = {"name": "h.wstrDisplayName", "last_connected": "h.tmLastNagentConnected", "os": "h.wstrOSName", "group": "g.wstrName", "ip": "h.nIp"}


def ip_str(n) -> str:
    # Проверено на данных: первый октет — в старшем байте (документация klakdb ошибочно называет порядок little-endian)
    return "" if not n else ".".join(str((int(n) >> s) & 255) for s in (24, 16, 8, 0))


def _utc(v) -> datetime | None:
    if v is None:
        return None
    return v.replace(tzinfo=timezone.utc) if isinstance(v, datetime) and v.tzinfo is None else v


def activity(last, now: datetime | None = None) -> tuple[float | None, str]:
    """(суток с последнего подключения, подпись). Статус отражает актуальность связи с KSC, а не доступность компьютера сейчас."""
    last = _utc(last)
    if not last:
        return None, "нет подключений Агента"
    days = ((now or datetime.now(timezone.utc)) - last).total_seconds() / 86400
    return round(days, 1), next((label for limit, label in ACTIVITY if days <= limit), ">30 сут")


def group_path(groups: dict[int, dict], gid) -> str:
    names, seen = [], set()
    while gid in groups and gid not in seen:
        seen.add(gid)
        names.append(groups[gid]["name"])
        gid = groups[gid]["parent_id"]
    return " / ".join(reversed(names))


def online(status_bits) -> bool | None:
    """В сети ли устройство сейчас — по флагу KSC «видимо» (бит 0 nStatus; KSC снимает его по тайм-ауту видимости).
    Нет значения — None («нет данных»): время последнего подключения онлайн-статус не подтверждает."""
    return None if status_bits is None else bool(int(status_bits) & 1)


def host_row(h: dict, groups: dict[int, dict] | None, now: datetime | None = None, release: str | None = None) -> dict:
    days, status = activity(h.get("last_connected"), now)
    fqdn = (h.get("dns_name") or "") + ("." + h["dns_domain"] if h.get("dns_name") and h.get("dns_domain") else "")
    return {"host_id": int(h["host_id"]), "name": h.get("name") or "", "fqdn": fqdn, "ip": ip_str(h.get("ip_int")), "os": h.get("os_name") or "",
            "os_version": ".".join(str(h[k]) for k in ("os_major", "os_minor") if h.get(k) is not None) + (f" ({h['os_build']})" if h.get("os_build") else ""),
            "platform": {2: "Windows", 6: "Linux"}.get(h.get("platform_type"), ""), "group_id": h.get("group_id"),
            "group": group_path(groups, h.get("group_id")) if groups else (h.get("group_name") or ""),
            "last_connected": _utc(h.get("last_connected")), "last_visible": _utc(h.get("last_visible")), "last_info_update": _utc(h.get("last_info_update")),
            "last_av_update": _utc(h.get("last_av_update")), "last_full_scan": _utc(h.get("last_full_scan")),
            "days_since_connection": days, "activity": status, "active": days is not None and days <= (now_days if (now_days := None) else 1e9),
            "status_bits": h.get("status_bits"), "online": online(h.get("status_bits")), "rtp_state": h.get("rtp_state"), "is_slave": bool(h.get("is_slave")), "pkg_mgr": {1: "RPM", 2: "dpkg"}.get(h.get("pkg_mgr"), ""),
            "linux_release": release or "", "created": _utc(h.get("created"))}


def hosts_where(*, qtext: str = "", group_contains: str = "", os_contains: str = "", active_days: int | None = None, inactive_only: bool = False,
                exclude_slaves: bool = True) -> tuple[str, dict]:
    where, params = [], {}
    if exclude_slaves:
        where.append("h.bIsSlaveServer = 0")
    for text, sql, name in ((qtext, "(h.wstrDisplayName LIKE %(q)s OR h.wstrDnsName LIKE %(q)s)", "q"), (group_contains, "g.wstrName LIKE %(g)s", "g"),
                            (os_contains, "h.wstrOSName LIKE %(os)s", "os")):
        like = mssql_like(text)
        if like:
            where.append(sql)
            params[name] = like
    if active_days is not None and not inactive_only:
        where.append("h.tmLastNagentConnected >= DATEADD(day, -%(days)s, GETUTCDATE())")
        params["days"] = int(active_days)
    if inactive_only and active_days is not None:
        where.append("(h.tmLastNagentConnected IS NULL OR h.tmLastNagentConnected < DATEADD(day, -%(days)s, GETUTCDATE()))")
        params["days"] = int(active_days)
    return " AND ".join(where) or "1 = 1", params


def hosts_order(sort: str, desc: bool) -> str:
    col = _SORT.get(sort, "h.wstrDisplayName")
    return f"{col} {'DESC' if desc else 'ASC'}, h.nId"


async def groups_map(client) -> dict[int, dict]:
    rows = await client.run(q.GROUPS_ALL, max_rows=100_000)
    return {int(r["group_id"]): {"name": r["name"], "parent_id": r["parent_id"]} for r in rows}


def releases_sync(session, host_ids: list[int]) -> dict[int, str]:
    out: dict[int, str] = {}
    for k in range(0, len(host_ids), 500):
        for r in session.query(q.RELEASE_PACKAGES.format(ids=q.ids_list(host_ids[k:k + 500])), max_rows=10_000):
            out[int(r["host_id"])] = f"{r['name']} {r['version']}"
    return out


def linux_release_label(package: str) -> str:
    """Понятное имя дистрибутива по версии пакета base-files / *-release (эвристика)."""
    m = re.search(r"deb(\d+)u", package)
    if m:
        return f"Debian {m.group(1)}"
    m = re.search(r"base-files (\d+)ubuntu", package)
    if m:
        return {"10": "Ubuntu 18.04", "11": "Ubuntu 20.04", "12": "Ubuntu 22.04", "13": "Ubuntu 24.04"}.get(m.group(1), "Ubuntu")
    if "astra" in package:
        return "Astra Linux"
    for name in ("centos", "almalinux", "rocky", "oraclelinux", "redhat"):
        if package.startswith(name):
            return package
    return package
