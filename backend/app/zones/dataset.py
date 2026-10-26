"""Запись «компьютер × проблемы» для зон: защита, подтверждённые KSC уязвимости, потенциальные совпадения с внешними базами и решения по ним, итоги и показатели.

Расчёт данных из KSC выполняет `zones/snapshot.py` (порциями, в worker); здесь — чистые функции над одним компьютером и над списком компьютеров (`host_record`, `stats`), общие для расчёта,
чтения подготовленных данных и отчётов: итоги по сохранённым строкам совпадают с расчётом по свежим."""
from __future__ import annotations

from collections import Counter
from datetime import datetime

from ..ksc import protection as P

SEV_RANK = {"critical": 3, "high": 2, "warning": 1, "": 0}
SEV_RU = {"critical": "Критическая", "high": "Высокая", "warning": "Предупреждение", "": ""}
STATE_RU = {"critical": "Критические уязвимости", "vulns": "Другие уязвимости", "protection": "Проблемы защиты", "potential": "Только потенциальные совпадения", "ok": "Без проблем"}
STATE_ORDER = ("critical", "vulns", "protection", "potential", "ok")


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
        parts.append(f"потенциально по внешним базам: {e['total']}" + (f" (в каталоге CISA KEV: {e['kev']})" if e["kev"] else ""))
    return "; ".join(parts) or "проблем не выявлено"


def host_record(r: dict, hv: dict, he: dict, a: dict, *, agg_only: bool, floor: int, now: datetime, bases_days: int, scan_days: int, source_id: str, source_name: str) -> dict:
    """Компьютер в области: проблемы защиты, итоги по обнаружениям KSC и внешним базам, состояние и строки обнаружений. Одна функция для расчёта «на лету» и для сохранённых данных:
    итоговые числа по сохранённым строкам совпадают с расчётом по свежим."""
    if agg_only:
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
    hv = {**hv, "current": [x for x in hv["current"] if SEV_RANK[x["severity"]] >= floor]} if not agg_only else hv
    he = {**he, "current": ec}
    h.update(source_id=source_id, source=source_name, problems=problems, ksc=ksc, ext=ext, max_sev=worst, max_sev_basis=("ksc" if SEV_RANK[ksc["worst"]] >= SEV_RANK[ext["worst"]] and ksc["worst"] else "ext" if ext["worst"] else ""),
             state=state, rows={"ksc": hv, "ext": he})
    h["summary"] = short_text(h)
    return h


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
