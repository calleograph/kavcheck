"""События безопасности из журнала KSC (v_akpub_ev_event): обнаружения угроз, результат обработки и сетевые атаки за период.

Журнал — самая крупная таблица базы KSC: каждый запрос ограничен периодом по tmRiseTime и типами обнаружений (индексы KSC), сводка кэшируется,
список — постранично. События удалённых устройств сохраняются (LEFT JOIN на компьютеры). Параметры событий — docs/ksc/EVENTS.md."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from . import queries as q
from .driver import SourceClient
from .hosts import _utc, ip_str

# ключ: (тип KSC, подпись, группа для сводки)
TYPES = {
    "detected": ("GNRL_EV_VIRUS_FOUND", "Обнаружена угроза", "detections"),
    "suspicious": ("GNRL_EV_SUSPICIOUS_OBJECT_FOUND", "Подозрительный объект", "detections"),
    "notcured": ("GNRL_EV_OBJECT_NOTCURED", "Не вылечен", "notcured"),
    "deleted": ("GNRL_EV_OBJECT_DELETED", "Удалён", "resolved"),
    "cured": ("GNRL_EV_OBJECT_CURED", "Вылечен", "resolved"),
    "quarantined": ("GNRL_EV_OBJECT_QUARANTINED", "Помещён на карантин", "resolved"),
    "attack": ("GNRL_EV_ATTACK_DETECTED", "Сетевая атака", "attacks"),
}
BY_TYPE = {t: k for k, (t, _, _) in TYPES.items()}
THREAT_KIND = {"60": "вирус", "61": "троянская программа", "62": "вредоносная программа", "63": "бэкдор", "64": "червь", "65": "riskware", "0": "неизвестно"}
GROUPS = ("detections", "notcured", "resolved", "attacks")
PERIODS = {1: "hour", 7: "day", 30: "day", 90: "day"}


def _attacker(v) -> str:
    s = str(v or "").strip()
    return ip_str(int(s)) if s.isdigit() and 0 < int(s) < 2**32 else s


def event_row(r: dict) -> dict:
    """Событие с понятными полями: угроза или атака, объект, пользователь, тип опасности — по таблице параметров KSC."""
    key = BY_TYPE.get(r.get("type") or "", "")
    out = {"event_id": int(r["event_id"]), "at": _utc(r.get("at")), "type": key, "type_title": TYPES[key][1] if key else (r.get("type_name") or r.get("type") or ""),
           "severity": r.get("severity"), "host_id": r.get("host_id"), "host": r.get("host") or "", "ip": ip_str(r.get("ip_int")), "product": r.get("product") or "",
           "threat": "", "object": "", "user": "", "threat_kind": "", "attacker": "", "protocol": "", "port": ""}
    if key == "attack":
        out.update(threat=r.get("par1") or "", protocol=r.get("par2") or "", attacker=_attacker(r.get("par3")), port=r.get("par4") or "")
    else:
        out.update(threat=r.get("par5") or "", object=r.get("par2") or "", user=r.get("par7") or "", threat_kind=THREAT_KIND.get(str(r.get("par8") or "").strip(), ""))
    return out


async def summary(client: SourceClient, *, days: int) -> dict:
    """Сводка за период: по типам, динамика, компьютеры и угрозы с наибольшим числом событий."""
    p = {"hours": days * 24}
    unit = PERIODS.get(days, "day")
    by_type = await client.run(q.EVENTS_BY_TYPE, p, max_rows=100)
    hosts_n = (await client.run(q.EVENTS_HOSTS, p, max_rows=1) or [{}])[0]
    trend = await client.run(q.EVENTS_TREND.format(unit=unit), p, max_rows=20_000)
    hosts = await client.run(q.EVENTS_TOP_HOSTS, p, max_rows=15)
    threats = await client.run(q.EVENTS_TOP_THREATS, p, max_rows=15)
    types = {k: {"key": k, "title": t[1], "group": t[2], "n": 0, "hosts": 0} for k, t in TYPES.items()}
    for r in by_type:
        k = BY_TYPE.get(r["type"])
        if k:
            types[k].update(n=int(r["n"]), hosts=int(r["hosts"]))
    totals = {g: sum(t["n"] for t in types.values() if t["group"] == g) for g in GROUPS}
    now = datetime.now(timezone.utc)
    step = timedelta(hours=1) if unit == "hour" else timedelta(days=1)
    start = (now - timedelta(days=days)).replace(minute=0, second=0, microsecond=0)
    if unit == "day":
        start = start.replace(hour=0)
    buckets: dict[datetime, dict] = {}
    t = start
    while t <= now:
        buckets[t] = {"at": t, **{g: 0 for g in GROUPS}}
        t += step
    for r in trend:
        k, at = BY_TYPE.get(r["type"]), _utc(r["bucket"])
        if k and at in buckets:
            buckets[at][TYPES[k][2]] += int(r["n"])
    return {"days": days, "unit": unit, "types": list(types.values()), "totals": totals,
            "hosts": {k: int(hosts_n.get(k) or 0) for k in ("any_hosts", *GROUPS)},
            "trend": list(buckets.values()),
            "top_hosts": [{"host_id": r.get("host_id"), "name": r.get("name") or "", "ip": ip_str(r.get("ip_int")), "deleted": r.get("name") is None,
                           **{k: int(r.get(k) or 0) for k in ("n", "detections", "notcured", "attacks")}, "last": _utc(r.get("last"))} for r in hosts],
            "top_threats": [{"kind": r["kind"], "name": r.get("name") or "(без названия)", "n": int(r["n"]), "hosts": int(r["hosts"]), "last": _utc(r.get("last"))} for r in threats]}


def where(*, days: int, types: list[str], host_id: int | None, qtext: str, threat: str) -> tuple[str, dict]:
    keys = [k for k in types if k in TYPES] or list(TYPES)
    parts = [q.EV_PERIOD, "e.strEventType IN (" + ", ".join(f"'{TYPES[k][0]}'" for k in keys) + ")"]   # только константы из TYPES
    params: dict = {"hours": days * 24}
    if host_id:
        parts.append("e.nHostId = %(host)s")
        params["host"] = int(host_id)
    if qtext.strip():
        parts.append("(h.wstrDisplayName LIKE %(q)s OR e.wstrPar2 LIKE %(q)s OR e.wstrPar5 LIKE %(q)s OR e.wstrPar1 LIKE %(q)s OR e.wstrPar7 LIKE %(q)s)")
        params["q"] = f"%{qtext.strip()}%"
    if threat.strip():
        parts.append("(e.wstrPar5 = %(threat)s OR (e.strEventType = 'GNRL_EV_ATTACK_DETECTED' AND e.wstrPar1 = %(threat)s))")
        params["threat"] = threat.strip()
    return " AND ".join(parts), params


async def page(client: SourceClient, *, days: int, types: list[str], host_id: int | None = None, qtext: str = "", threat: str = "", offset: int, limit: int) -> dict:
    w, params = where(days=days, types=types, host_id=host_id, qtext=qtext, threat=threat)
    rows = await client.run(q.EVENTS_PAGE.format(where=w), {**params, "offset": offset, "limit": limit}, max_rows=limit)
    cnt = await client.run(q.EVENTS_COUNT.format(where=w), params, max_rows=1)
    return {"items": [event_row(r) for r in rows], "total": int(cnt[0]["n"]) if cnt else 0, "offset": offset, "limit": limit, "days": days}
