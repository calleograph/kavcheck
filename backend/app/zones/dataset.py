"""Единый набор данных «компьютер × проблемы» для зон: защита, подтверждённые KSC уязвимости, потенциальные совпадения с внешними базами и решения по ним.

Из него строятся страницы зон, карточки, фильтры «по зоне» и отчёты — отдельного генератора аналитики нет.
Разделение на два шага: `load_raw` читает KSC и внутреннюю БД (дорого, кэшируется на срок cache_ttl_seconds), `assemble` применяет зоны, решения по уязвимостям,
активность и пороги (дёшево, в памяти) — поэтому смена зоны, порога или решения не нагружает SQL Server."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..ksc import protection as P
from ..ksc import vulns as V
from ..ksc.driver import KscError, SourceClient
from ..reports import quick
from . import triage as T
from .match import ZoneIndex, annotate

SEV_RANK = {"critical": 3, "high": 2, "warning": 1, "": 0}
SEV_RU = {"critical": "Критическая", "high": "Высокая", "warning": "Предупреждение", "": ""}
CHUNK = 1500
STATE_RU = {"critical": "Критические уязвимости", "vulns": "Другие уязвимости", "protection": "Проблемы защиты", "potential": "Только потенциальные совпадения", "ok": "Без проблем"}
STATE_ORDER = ("critical", "vulns", "protection", "potential", "ok")


@dataclass
class Raw:
    base: list[dict]
    vuln_rows: list[dict]
    ext_rows: list[dict] | None = None
    agg_only: bool = False                         # деталей слишком много: известны только счётчики по компьютерам
    agg: dict[int, dict] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


async def load_raw(client: SourceClient, ctx: quick.Ctx) -> Raw:
    from ..ksc import hosts as H  # noqa: PLC0415

    groups = await H.groups_map(client)
    base = await ctx.protection_loader() if ctx.protection_loader else await P.load(client, exclude_slaves=ctx.exclude_slaves, groups=groups)
    raw = Raw(base, [], None)
    agg = await V.hosts_aggregate(client)
    raw.agg = {int(a["host_id"]): {k: int(a.get(k) or 0) for k in ("critical", "high", "warning", "total", "patchable")} for a in agg if not (ctx.exclude_slaves and a.get("is_slave"))}
    ids = sorted(raw.agg)
    total = 0
    try:
        if sum(a["total"] for a in raw.agg.values()) > ctx.max_rows:      # заведомо больше предела: деталей не читаем, только счётчики по компьютерам
            raise KscError("too_many_rows", "")
        for i in range(0, len(ids), CHUNK):
            if ctx.cancelled():
                raise RuntimeError("cancelled")
            doc = await quick.build_vulns(client, {"host_ids": ids[i:i + CHUNK], "include_inactive": True, "online_only": False, "q": "", "group_contains": ""}, ctx)
            rows = doc["tables"][0]["rows"]
            total += len(rows)
            if total > ctx.max_rows:
                raise KscError("too_many_rows", "")
            raw.vuln_rows += rows
            ctx.progress(f"уязвимости KSC: {total}")
    except KscError as exc:
        if exc.code != "too_many_rows":
            raise
        raw.vuln_rows, raw.agg_only = [], True
        raw.notes.append(f"Обнаружений уязвимостей больше предела ({ctx.max_rows}): показаны только счётчики по компьютерам, решения по отдельным уязвимостям не применяются. Увеличьте предел в настройках отчётов.")
    return raw


def _worst(rows: list[dict]) -> str:
    best = ""
    for r in rows:
        if SEV_RANK[r["severity"]] > SEV_RANK[best]:
            best = r["severity"]
    return best


def short_text(h: dict) -> str:
    """Короткая формулировка проблем компьютера для таблицы: «уязвимости: 3 критических, 8 высоких; устаревшие антивирусные базы»."""
    parts = []
    k = h["ksc"]
    sev = [f"{k[key]} {title}" for key, title in (("critical", "критических"), ("high", "высоких"), ("warning", "с низкой опасностью")) if k[key]]
    if sev:
        parts.append("уязвимости: " + ", ".join(sev))
    parts += [P.PROBLEMS[x][0].lower() for x in h["problems"]]
    e = h["ext"]
    if e["total"]:
        parts.append(f"потенциально по внешним базам: {e['total']}" + (f" (эксплуатируются: {e['kev']})" if e["kev"] else ""))
    return "; ".join(parts) or "проблем не выявлено"


def assemble(raw: Raw, zindex: ZoneIndex, tindex: T.TriageIndex, *, ext_rows: list[dict] | None = None, source_id: str, source_name: str, now: datetime, activity_days: int, include_inactive: bool, online_only: bool,
             bases_days: int = 3, scan_days: int = 30, zone_activity: dict[str, int] | None = None, min_sev: str = "", only=None) -> dict:
    """Компьютеры источника с зонами, проблемами и разобранными по решениям обнаружениями.
    Возвращает {hosts, hidden, total_all}: hosts — в области (по активности и сети), у каждого vulns.current/accepted/excluded и сводка по уровням."""
    records = annotate(raw.base, zindex, source_id)
    if only is not None:                         # отчёт или страница по выбранным зонам: остальные компьютеры источника не разбираются
        records = [r for r in records if only(r)]
    by_host: dict[int, dict[str, list[dict]]] = {}
    zones_of = {r["host_id"]: r["zones"] for r in records}
    names_of = {r["host_id"]: r["name"] for r in records}
    vr = [{**r, "zones": zones_of[r["host_id"]]} for r in raw.vuln_rows if r["host_id"] in zones_of]
    for bucket, rows in T.split(vr, tindex).items():
        for r in rows:
            by_host.setdefault(r["host_id"], {"current": [], "accepted": [], "excluded": []})[bucket].append(r)
    ext_by: dict[int, dict[str, list[dict]]] = {}
    if ext_rows is not None:
        er = [{**r, "zones": zones_of[r["host_id"]], "product": r.get("program"), "name": names_of.get(r["host_id"], ""), "ids_list": (r.get("ids") or "").split()[:20]} for r in ext_rows if r["host_id"] in zones_of]
        for bucket, rows in T.split(er, tindex, key_fields=("vuln_key", "ids_list")).items():
            for r in rows:
                ext_by.setdefault(r["host_id"], {"current": [], "accepted": [], "excluded": []})[bucket].append(r)
    floor = SEV_RANK.get(min_sev, 0)
    out, hidden, offline = [], 0, 0
    hidden_hosts: list[dict] = []
    online_data = any(r.get("online") is not None for r in records)
    for r in records:
        days_limit = (zone_activity or {}).get(r["zones"][0]) if r["zones"] else None
        limit = days_limit or activity_days
        active = r["days_since_connection"] is not None and r["days_since_connection"] <= limit
        r = {**r, "active": active}
        if not include_inactive and not active:
            hidden += 1
            hidden_hosts.append({"zones": r["zones"], "reason": "inactive"})
            continue
        if online_only and online_data and r.get("online") is not True:
            offline += 1
            hidden_hosts.append({"zones": r["zones"], "reason": "offline"})
            continue
        hv = by_host.get(r["host_id"], {"current": [], "accepted": [], "excluded": []})
        he = ext_by.get(r["host_id"], {"current": [], "accepted": [], "excluded": []})
        if raw.agg_only:
            a = raw.agg.get(r["host_id"], {})
            ksc = {"critical": a.get("critical", 0), "high": a.get("high", 0), "warning": a.get("warning", 0), "total": a.get("total", 0), "worst": "critical" if a.get("critical") else "high" if a.get("high") else "warning" if a.get("warning") else "",
                   "accepted": 0, "excluded": 0, "review": 0}
        else:
            cur = [x for x in hv["current"] if SEV_RANK[x["severity"]] >= floor]
            ksc = {k: sum(1 for x in cur if x["severity"] == k) for k in ("critical", "high", "warning")}
            ksc.update(total=len(cur), worst=_worst(cur), accepted=len(hv["accepted"]), excluded=len(hv["excluded"]), review=sum(1 for x in cur if x.get("triage") and x["triage"]["status"] == "review"))
        ec = [x for x in he["current"] if SEV_RANK[x["severity"]] >= floor]
        ext = {"total": len(ec), "critical": sum(1 for x in ec if x["severity"] == "critical"), "high": sum(1 for x in ec if x["severity"] == "high"), "warning": sum(1 for x in ec if x["severity"] == "warning"),
               "kev": sum(1 for x in ec if x.get("kev")), "confirmed": sum(1 for x in ec if x["status"] == "confirmed"), "worst": _worst(ec), "accepted": len(he["accepted"]), "excluded": len(he["excluded"])}
        problems = P.problems(r, now, bases_days=bases_days, scan_days=scan_days)
        worst = ksc["worst"] if SEV_RANK[ksc["worst"]] >= SEV_RANK[ext["worst"]] else ext["worst"]
        state = "critical" if ksc["critical"] else "vulns" if ksc["total"] else "protection" if problems else "potential" if ext["total"] else "ok"
        h = {k: r[k] for k in ("host_id", "name", "fqdn", "ip", "os", "platform", "group", "last_connected", "days_since_connection", "activity", "online", "active", "zones", "zone_conflict",
                               "zone_pinned", "zone_candidates", "zone_via", "ksc_status", "av", "mask", "agent_build", "rtp_label", "rtp_state", "last_full_scan", "uncured", "os_version")}
        hv = {**hv, "current": [x for x in hv["current"] if SEV_RANK[x["severity"]] >= floor]} if not raw.agg_only else hv
        he = {**he, "current": ec}
        h.update(source_id=source_id, source=source_name, problems=problems, ksc=ksc, ext=ext, max_sev=worst, max_sev_basis=("ksc" if SEV_RANK[ksc["worst"]] >= SEV_RANK[ext["worst"]] and ksc["worst"] else "ext" if ext["worst"] else ""),
                 state=state, rows={"ksc": hv, "ext": he})
        h["summary"] = short_text(h)
        out.append(h)
    return {"hosts": out, "hidden": hidden, "offline": offline, "hidden_hosts": hidden_hosts, "online_data": online_data, "total_all": len(records), "notes": list(raw.notes), "agg_only": raw.agg_only}


def rank_key(h: dict) -> tuple:
    """Сортировка «сначала самые проблемные»: уровень, затем число подтверждённых, затем защита."""
    return (-SEV_RANK[h["ksc"]["worst"]], -h["ksc"]["critical"], -h["ksc"]["high"], -h["ksc"]["total"], -SEV_RANK[h["ext"]["worst"]], -len(h["problems"]), -h["ext"]["total"], h["name"].lower())


def has_problem(h: dict, sections: set[str] | None = None) -> bool:
    s = sections or {"ksc", "protection", "ext"}
    return bool(("ksc" in s and h["ksc"]["total"]) or ("protection" in s and h["problems"]) or ("ext" in s and h["ext"]["total"]))


def stats(hosts: list[dict], *, total_all: int, hidden: int, sections: set[str] | None = None) -> dict:
    """Показатели зоны. Пересекающиеся категории не складываются: «состояние» — взаимоисключающее (по наиболее серьёзному), остальные счётчики — независимые."""
    s = sections or {"ksc", "protection", "ext"}
    state = Counter(h["state"] if (h["state"] != "potential" or "ext" in s) else "ok" for h in hosts)
    return {"total": total_all, "in_scope": len(hosts), "inactive": hidden, "active": sum(1 for h in hosts if h["active"]),
            "online": sum(1 for h in hosts if h["online"] is True), "offline": sum(1 for h in hosts if h["online"] is False), "online_unknown": sum(1 for h in hosts if h["online"] is None),
            "critical": sum(1 for h in hosts if h["ksc"]["critical"]), "other_vulns": sum(1 for h in hosts if h["ksc"]["total"] and not h["ksc"]["critical"]),
            "any_vulns": sum(1 for h in hosts if h["ksc"]["total"]), "protection": sum(1 for h in hosts if h["problems"]), "potential": sum(1 for h in hosts if h["ext"]["total"]),
            "ok": sum(1 for h in hosts if not has_problem(h, s)),
            "state": {k: state.get(k, 0) for k in STATE_ORDER},
            "severity": {k: sum(1 for h in hosts if h["max_sev"] == k) for k in ("critical", "high", "warning")} | {"none": sum(1 for h in hosts if not h["max_sev"])},
            "vulns": {"critical": sum(h["ksc"]["critical"] for h in hosts), "high": sum(h["ksc"]["high"] for h in hosts), "warning": sum(h["ksc"]["warning"] for h in hosts)},
            "problems": [{"key": k, "title": t, "hosts": sum(1 for h in hosts if k in h["problems"])} for k, (t, _hint) in P.PROBLEMS.items()],
            "excluded": sum(h["ksc"]["excluded"] + h["ext"]["excluded"] for h in hosts), "accepted": sum(h["ksc"]["accepted"] + h["ext"]["accepted"] for h in hosts),
            "review": sum(h["ksc"]["review"] for h in hosts)}
