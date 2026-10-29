"""Состояние защиты: проблемы защиты по компьютерам, версии защитных продуктов и Агента, причины статуса KSC.

Набор по источнику читается один раз на срок кэша (cache_ttl_seconds); пороги, фильтры, сортировка и страницы — по кэшированному набору."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, current_source, get_db, require_user
from ..ksc import protection as P
from ..ksc.driver import KscError
from ..models import KscSource
from .vulns import _ksc, groups_cached, unsupported

router = APIRouter(prefix="/protection", tags=["protection"])
PROBLEM_RE = "^(|ok|hw|" + "|".join(P.PROBLEMS) + ")$"


async def protection_base(request: Request, db: AsyncSession, src: KscSource, *, refresh: bool = False) -> tuple[list[dict], float]:
    """Набор записей защиты по источнику (кэш в памяти процесса; общий для страницы «Состояние защиты» и главной): (записи, время расчёта)."""
    rcfg = await request.app.state.settings_svc.get(db, "reports")
    hw = await request.app.state.settings_svc.get(db, "hardware")
    client = request.app.state.sources.client(src)
    groups_src = src

    async def make() -> list[dict]:
        return await P.load(client, exclude_slaves=rcfg.exclude_slave_servers, groups=await groups_cached(request, groups_src), hw_cfg=hw)

    return await request.app.state.cache.get((str(src.id), "protection", rcfg.exclude_slave_servers, hw.model_dump_json()), request.app.state.settings.cache_ttl_seconds, make, refresh=refresh, swr=request.app.state.settings.cache_swr_seconds)


@router.get("")
async def protection(request: Request, problem: str = Query("", pattern=PROBLEM_RE), q_: str = Query("", alias="q", max_length=200), group: str = Query("", max_length=200),
                     hw_level: str = Query("", pattern="^(|critical|warning)$"), product: str = Query("", max_length=64), build: str = Query("", max_length=64), bases_days: int = Query(3, ge=1, le=90),
                     scan_days: int = Query(30, ge=1, le=365), sort: str = Query("risk", pattern=r"^(risk|name|last_connected|bases|scan)$"), desc: bool = True,
                     all_hosts: bool = False, online: bool = False, zone: str = Query("", max_length=40), offset: int = Query(0, ge=0), limit: int = Query(50, ge=0, le=500), refresh: bool = False,
                     su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Сводка (проблемы, статус KSC, версии) по активным компьютерам и страница компьютеров по фильтру. limit=0 — только сводка.
    online=true — только устройства, которые KSC сейчас видит в сети (флаг «видимо»); применяется до подсчёта, поэтому числа и списки совпадают.
    Если KSC не передаёт флаг ни для одного устройства, фильтр не применяется (online_data=false)."""
    miss = unsupported(src, "protection")
    if miss:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "unsupported": miss, "summary": None}
    general = await request.app.state.settings_svc.get(db, "general")
    rcfg = await request.app.state.settings_svc.get(db, "reports")
    hw = await request.app.state.settings_svc.get(db, "hardware")
    try:
        base, at = await protection_base(request, db, src, refresh=refresh)
    except KscError as exc:
        raise _ksc(exc) from None
    if zone:
        from .zones import zone_host_ids  # noqa: PLC0415

        zids = await zone_host_ids(request, db, src, zone)
        base = [h for h in base if h["host_id"] in zids]
    now = datetime.now(timezone.utc)
    hosts, sc = P.scope(base, now=now, activity_days=general.activity_days, include_inactive=all_hosts, online_only=online, bases_days=bases_days, scan_days=scan_days)
    hidden, offline, online_data = sc["hidden"], sc["offline"], sc["online_data"]
    counts = Counter(p for h in hosts for p in h["problems"])
    reasons = Counter(b for h in hosts for b in P.STATUS_MASK if h["mask"] & b)
    summary = {"hosts": len(hosts), "hidden_hosts": hidden, "offline_hosts": offline, "online_only": bool(online and online_data), "online_data": online_data,
               "activity_days": general.activity_days, "bases_days": bases_days, "scan_days": scan_days,
               "ok": sum(1 for h in hosts if not h["problems"]),
               "protected": sum(1 for h in hosts if h["av"] and not h["state_unknown"] and not {"rtp_off", "bases_old", "no_av"} & set(h["problems"])),
               "state_unknown": sum(1 for h in hosts if h["state_unknown"]),
               "problems": [{"key": k, "title": t, "hint": hint, "hosts": counts.get(k, 0)} for k, (t, hint) in P.PROBLEMS.items()],
               "hw": {"linux": sum(1 for h in hosts if h.get("platform") == "Linux"), "with_data": sum(1 for h in hosts if h.get("hw")), "critical": sum(1 for h in hosts if any(x["level"] == "critical" for x in ((h.get("hw") or {}).get("problems") or []))),
                      "warning": sum(1 for h in hosts if (h.get("hw") or {}).get("problems") and not any(x["level"] == "critical" for x in h["hw"]["problems"])), "thresholds": hw.model_dump()},
               "ksc_status": {s: sum(1 for h in hosts if h["ksc_status"] == s) for s in P.KSC_STATUS.values()},
               "reasons": [{"bit": b, "title": P.STATUS_MASK[b], "hosts": n} for b, n in reasons.most_common()],
               "versions": P.versions(hosts), "fetched_at": datetime.fromtimestamp(at, timezone.utc)}
    items = P.pick(hosts, problem=problem, product=product, build=build, q=q_, group=group, hw_level=hw_level)
    order = list(P.PROBLEMS)
    floor = datetime.min.replace(tzinfo=timezone.utc)
    keyf = {"risk": lambda h: (bool(h["problems"]), -order.index(h["problems"][0]) if h["problems"] else 0, len(h["problems"])),   # problems уже по важности
            "name": lambda h: h["name"].lower(), "last_connected": lambda h: h["last_connected"] or floor,
            "bases": lambda h: (h["av"] or {}).get("bases") or floor, "scan": lambda h: h["last_full_scan"] or floor}[sort]
    items = sorted(items, key=keyf, reverse=desc if sort != "name" else not desc)
    page = [{k: v for k, v in h.items() if k not in ("mask", "is_slave")} for h in items[offset:offset + limit]]
    from .zones import zone_labels  # noqa: PLC0415

    await zone_labels(db, src, page)
    from ..bi.read import owners_for  # noqa: PLC0415

    owners = await owners_for(db, src.id, [int(h["host_id"]) for h in page], pd=su.role in ("analyst", "admin"))         # владелец по BI: кому писать о неисправной защите
    for h in page:
        h["owner"] = owners.get(int(h["host_id"]))
    return {"items": page, "total": len(items), "offset": offset, "limit": limit, "summary": summary}
