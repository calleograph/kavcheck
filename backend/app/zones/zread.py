"""Чтение подготовленных данных зон из PostgreSQL: показатели, таблицы с серверной пагинацией, карточка компьютера, наборы для отчётов, готовые сводки.

Ни одна функция не обращается к KSC и не загружает в память весь источник: показатели считаются агрегатами SQL по индексам, таблицы — страницами (не более 500 строк),
карточка — по одному компьютеру, отчёт — порциями по компьютерам зоны. Итоги совпадают с расчётом по свежим данным (`dataset.stats`): это проверяет тест на одном наборе."""
from __future__ import annotations

import uuid
from datetime import datetime
from functools import reduce
from operator import add

from sqlalchemy import and_, case, delete, exists, func, literal, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .. import search as msearch
from ..ksc import protection as P
from ..services.resources import RES
from ..models import KscSource, Zone, ZcDashboard, ZcDetection, ZcHost, ZcHostZone, ZcSource, utcnow
from . import dataset as D
from .snapshot import UNASSIGNED, unpack_record, unpack_row

DEFAULT_BD, DEFAULT_SD = 3, 30
SEV_NAME = {3: "critical", 2: "high", 1: "warning", 0: ""}
PROBLEM_KEYS = list(P.PROBLEMS)


# ------------------------------------------------------------------------------------------------ выражения SQL
class X:
    """Выражения над колонками компьютера для заданных порогов, видимости внешних баз и границы активности (по зоне)."""

    def __init__(self, *, bd: int = DEFAULT_BD, sd: int = DEFAULT_SD, ext: bool = True, zone_col=None, zone_days: dict[str, int] | None = None, default_days: int = 30):
        H = ZcHost
        self.ext = ext
        zone_days = {z: d for z, d in (zone_days or {}).items() if d}
        limit = case(*[(zone_col == z, d) for z, d in zone_days.items()], else_=default_days) if (zone_days and zone_col is not None) else literal(default_days)
        self.active = and_(H.days_since.is_not(None), H.days_since <= limit)
        self.flags = {"no_av": H.p_no_av, "rtp_off": H.p_rtp, "infected": H.p_inf, "bases_old": and_(H.has_av, or_(H.bases_age.is_(None), H.bases_age > bd)),
                      "license": H.p_lic, "scan_old": and_(H.has_av, or_(H.scan_age.is_(None), H.scan_age > sd)), "reboot": H.p_reb, "hw_cpu": H.p_hwc, "hw_ram": H.p_hwr}
        self.prob_n = reduce(add, [case((f, 1), else_=0) for f in self.flags.values()])
        self.has_prob = self.prob_n > 0
        self.e_total = H.e_total if ext else literal(0)
        self.e_crit, self.e_high, self.e_warn = (H.e_crit, H.e_high, H.e_warn) if ext else (literal(0), literal(0), literal(0))
        self.ksc_w = case((H.k_crit > 0, 3), (H.k_high > 0, 2), (H.k_warn > 0, 1), else_=0)
        self.ext_w = case((self.e_crit > 0, 3), (self.e_high > 0, 2), (self.e_warn > 0, 1), else_=0)
        self.max_sev = case((self.ksc_w >= self.ext_w, self.ksc_w), else_=self.ext_w)
        self.state = case((H.k_crit > 0, "critical"), (H.k_total > 0, "vulns"), (self.has_prob, "protection"), (self.e_total > 0, "potential"), else_="ok")
        self.has_problem = or_(H.k_total > 0, self.has_prob, self.e_total > 0)
        self.risk_order = [self.ksc_w.desc(), H.k_crit.desc(), H.k_high.desc(), H.k_total.desc(), self.ext_w.desc(), self.prob_n.desc(), self.e_total.desc(), func.lower(H.name).asc()]


def _sum(cond):
    return func.coalesce(func.sum(case((cond, 1), else_=0)), 0)


def _joined():
    H, Z, S = ZcHost, ZcHostZone, ZcSource
    return H.__table__.join(Z.__table__, and_(Z.source_id == H.source_id, Z.host_id == H.host_id, Z.gen == H.gen)).join(S.__table__, and_(S.source_id == H.source_id, S.gen == H.gen))


def _scope(zid: str | None, sids: list[uuid.UUID] | None):
    c = [ZcSource.gen > 0]
    if zid is not None:
        c.append(ZcHostZone.zone_id == zid)
    if sids is not None:
        c.append(ZcHost.source_id.in_(sids))
    return and_(*c)


async def zone_days_map(db: AsyncSession) -> dict[str, int]:
    return {str(z.id): z.activity_days for z in (await db.execute(select(Zone))).scalars() if z.activity_days}


# ------------------------------------------------------------------------------------------------ показатели
def _stats_from(a: dict, ext: bool) -> dict:
    """Строка агрегатов → структура `dataset.stats`."""
    st = {k: int(a[f"s_{k}"]) for k in D.STATE_ORDER}
    return {"total": int(a["total"]), "in_scope": int(a["active"]), "inactive": int(a["total"]) - int(a["active"]), "active": int(a["active"]),
            "online": int(a["online"]), "offline": int(a["offline"]), "online_unknown": int(a["online_unknown"]),
            "critical": int(a["critical"]), "other_vulns": int(a["other_vulns"]), "any_vulns": int(a["any_vulns"]), "protection": int(a["protection"]), "potential": int(a["potential"]),
            "ok": int(a["ok"]), "state": st,
            "severity": {"critical": int(a["sev3"]), "high": int(a["sev2"]), "warning": int(a["sev1"]), "none": int(a["sev0"])},
            "vulns": {"critical": int(a["v_crit"]), "high": int(a["v_high"]), "warning": int(a["v_warn"])},
            "problems": [{"key": k, "title": t, "hosts": int(a[f"p_{k}"])} for k, (t, _h) in P.PROBLEMS.items()],
            "excluded": int(a["excluded"]), "accepted": int(a["accepted"]), "review": int(a["review"])}


async def group_stats(db: AsyncSession, *, sids: list[uuid.UUID] | None = None, zone_id: str | None = None, bd: int = DEFAULT_BD, sd: int = DEFAULT_SD, ext: bool = True,
                      default_days: int = 30, zone_days: dict[str, int] | None = None) -> dict[str, dict]:
    """Показатели по зонам одним запросом: {zone_id: stats}. zone_id задан — только эта зона. Считаются компьютеры, активные за период зоны (как на странице зоны)."""
    H = ZcHost
    x = X(bd=bd, sd=sd, ext=ext, zone_col=ZcHostZone.zone_id, zone_days=zone_days, default_days=default_days)
    A = x.active
    cols = [ZcHostZone.zone_id.label("zid"), func.count().label("total"), _sum(A).label("active"), _sum(A & H.online.is_(True)).label("online"), _sum(A & H.online.is_(False)).label("offline"),
            _sum(A & H.online.is_(None)).label("online_unknown"), _sum(A & (H.k_crit > 0)).label("critical"), _sum(A & (H.k_total > 0) & (H.k_crit == 0)).label("other_vulns"),
            _sum(A & (H.k_total > 0)).label("any_vulns"), _sum(A & x.has_prob).label("protection"), _sum(A & (x.e_total > 0)).label("potential"), _sum(A & ~x.has_problem).label("ok"),
            func.coalesce(func.sum(case((A, H.k_crit), else_=0)), 0).label("v_crit"), func.coalesce(func.sum(case((A, H.k_high), else_=0)), 0).label("v_high"),
            func.coalesce(func.sum(case((A, H.k_warn), else_=0)), 0).label("v_warn"),
            func.coalesce(func.sum(case((A, H.k_exc + (H.e_exc if ext else 0)), else_=0)), 0).label("excluded"), func.coalesce(func.sum(case((A, H.k_acc + (H.e_acc if ext else 0)), else_=0)), 0).label("accepted"),
            func.coalesce(func.sum(case((A, H.k_rev), else_=0)), 0).label("review")]
    cols += [_sum(A & (x.state == k)).label(f"s_{k}") for k in D.STATE_ORDER]
    cols += [_sum(A & (x.max_sev == n)).label(f"sev{n}") for n in (3, 2, 1, 0)]
    cols += [_sum(A & f).label(f"p_{k}") for k, f in x.flags.items()]
    q = select(*cols).select_from(_joined()).where(_scope(zone_id, sids)).group_by(ZcHostZone.zone_id)
    out = {r.zid: _stats_from(r._asdict(), ext) for r in (await db.execute(q)).all()}
    return out


async def conflict_counts(db: AsyncSession, sids: list[uuid.UUID] | None) -> dict[str, tuple[int, int]]:
    """{zone_id: (компьютеров, спорных)} — без учёта активности."""
    q = select(ZcHostZone.zone_id, func.count(), func.coalesce(func.sum(case((ZcHost.conflict, 1), else_=0)), 0)).select_from(_joined()).where(_scope(None, sids)).group_by(ZcHostZone.zone_id)
    return {z: (int(n), int(c)) for z, n, c in (await db.execute(q)).all()}


async def totals(db: AsyncSession, sids: list[uuid.UUID] | None) -> dict:
    q = select(func.count(), func.coalesce(func.sum(case((ZcHost.conflict, 1), else_=0)), 0)).select_from(ZcHost.__table__.join(ZcSource.__table__, and_(ZcSource.source_id == ZcHost.source_id, ZcSource.gen == ZcHost.gen))) \
        .where(and_(ZcSource.gen > 0, *( [ZcHost.source_id.in_(sids)] if sids is not None else [])))
    n, c = (await db.execute(q)).one()
    return {"unique_hosts": int(n), "conflicts": int(c)}


# ------------------------------------------------------------------------------------------------ таблица компьютеров
def _token_like(col, text: str):
    """Подстрока или маска среди элементов списка «|a|b|c|» (значения хранятся строчными): маска сопоставляется с элементом, а не со всей строкой."""
    p = msearch.local_like(text)
    if p is None:
        return literal(True)
    if not p.startswith("%"):
        p = "%|" + p
    if not p.endswith("%"):
        p += "|%"
    return col.like(p, escape="\\")


def host_out(row, x_days: int, bd: int, sd: int, ext: bool, src_names: dict, zones: list[str]) -> dict:
    """Строка таблицы зоны из колонок компьютера (без чтения обнаружений и KSC)."""
    h: ZcHost = row
    d = h.data or {}
    ksc = {"critical": h.k_crit, "high": h.k_high, "warning": h.k_warn, "total": h.k_total, "worst": SEV_NAME[3 if h.k_crit else 2 if h.k_high else 1 if h.k_warn else 0],
           "accepted": h.k_acc, "excluded": h.k_exc, "review": h.k_rev}
    et = (h.e_crit, h.e_high, h.e_warn, h.e_total, h.e_kev, h.e_conf) if ext else (0, 0, 0, 0, 0, 0)
    e = {"total": et[3], "critical": et[0], "high": et[1], "warning": et[2], "kev": et[4], "confirmed": et[5], "worst": SEV_NAME[3 if et[0] else 2 if et[1] else 1 if et[2] else 0],
         "accepted": h.e_acc if ext else 0, "excluded": h.e_exc if ext else 0}
    probs = [k for k in PROBLEM_KEYS if {"no_av": h.p_no_av, "rtp_off": h.p_rtp, "infected": h.p_inf, "license": h.p_lic, "reboot": h.p_reb,
                                         "bases_old": h.has_av and (h.bases_age is None or h.bases_age > bd), "scan_old": h.has_av and (h.scan_age is None or h.scan_age > sd), "hw_cpu": h.p_hwc, "hw_ram": h.p_hwr}[k]]
    worst = ksc["worst"] if D.SEV_RANK[ksc["worst"]] >= D.SEV_RANK[e["worst"]] else e["worst"]
    state = "critical" if ksc["critical"] else "vulns" if ksc["total"] else "protection" if probs else "potential" if e["total"] else "ok"
    out = {"source_id": str(h.source_id), "source": src_names.get(str(h.source_id), ""), "host_id": h.host_id, "name": h.name, "fqdn": d.get("fqdn", ""), "ip": d.get("ip", ""), "os": d.get("os", ""),
           "group": d.get("group", ""), "last_connected": h.last_connected, "days_since_connection": h.days_since, "active": h.days_since is not None and h.days_since <= x_days, "online": h.online,
           "max_sev": worst, "max_sev_ru": D.SEV_RU[worst], "max_sev_basis": ("ksc" if D.SEV_RANK[ksc["worst"]] >= D.SEV_RANK[e["worst"]] and ksc["worst"] else "ext" if e["worst"] else ""),
           "ksc": ksc, "ext": e, "problems": [{"key": k, "title": P.PROBLEMS[k][0], "detail": next((x["text"] for x in ((d.get("hw") or {}).get("problems") or []) if x["key"] == k), ""), "level": next((x["level"] for x in ((d.get("hw") or {}).get("problems") or []) if x["key"] == k), "")} for k in probs], "state": state, "zones": zones, "zone_conflict": h.conflict, "zone_pinned": h.pinned}
    out["summary"] = D.short_text({"ksc": ksc, "ext": e, "problems": probs})
    return out


async def hosts_page(db: AsyncSession, zid: str, sids: list[uuid.UUID] | None, *, bd: int, sd: int, ext: bool, default_days: int, zone_days: dict[str, int], state: str = "", severity: str = "",
                     problem: str = "", q: str = "", online: str = "", activity: str = "active", triage: str = "attention", cve: str = "", product: str = "", source_id: str = "", sort: str = "risk",
                     desc: bool = True, offset: int = 0, limit: int = 50) -> tuple[int, list[dict]]:
    """Страница компьютеров зоны с фильтрами и сортировкой в SQL (то же поведение, что у прежней таблицы в памяти)."""
    H = ZcHost
    x = X(bd=bd, sd=sd, ext=ext, zone_col=ZcHostZone.zone_id, zone_days=zone_days, default_days=default_days)
    cond = [_scope(zid, sids)]
    if source_id:
        cond.append(H.source_id == uuid.UUID(source_id))
    cond.append({"active": x.active, "inactive": ~x.active, "all": literal(True)}[activity])
    if state:
        cond.append(x.state == state)
    if severity:
        cond.append(x.max_sev == {"critical": 3, "high": 2, "warning": 1, "none": 0}[severity])
    if problem:
        cond.append(x.flags[problem])
    if online:
        cond.append(H.online.is_(online == "yes"))
    if msearch.clean(q):
        from ..devices.read import search_condition  # noqa: PLC0415 — единый поиск: имя, адрес (CIDR, диапазон, маска), логин; несколько значений

        c = search_condition(q, sids or [])
        if c is not None:
            cond.append(c)
    one_filter = bool(msearch.clean(cve)) != bool(msearch.clean(product))
    if triage == "attention" and one_filter:
        # обычный отбор по одной CVE/KLA или программе: по спискам компьютера (текущие обнаружения), с триграммными индексами — миллисекунды и на крупных зонах
        text, cols = (cve, (H.kk, H.ke)) if msearch.clean(cve) else (product, (H.pk, H.pe))
        cond.append(_token_like(cols[0], text) if not ext else or_(_token_like(cols[0], text), _token_like(cols[1], text)))
    elif cve or product or triage != "attention":
        # одновременно CVE и программа (в одной строке) либо иное состояние обработки: точный отбор по строкам обнаружений
        d = [ZcDetection.source_id == H.source_id, ZcDetection.gen == H.gen, ZcDetection.host_id == H.host_id]
        if not ext:
            d.append(ZcDetection.origin == "ksc")
        if triage == "attention":
            d.append(ZcDetection.bucket == "current")
        elif triage == "review":
            d.append(ZcDetection.tstatus.in_(("", "review")))
        elif triage != "all":
            d.append(ZcDetection.tstatus == triage)
        for text, col in ((cve, ZcDetection.keys), (product, ZcDetection.prod)):
            c = msearch.column_like(col, text)
            if c is not None:
                d.append(c)
        cond.append(exists().where(*d))
    if sort == "risk":
        order = x.risk_order if desc else [x.ksc_w.asc(), H.k_crit.asc(), H.k_high.asc(), H.k_total.asc(), x.ext_w.asc(), x.prob_n.asc(), x.e_total.asc(), func.lower(H.name).desc()]
    else:
        order = {"name": [func.lower(H.name).asc() if desc else func.lower(H.name).desc()], "ip": [H.ip_num.desc() if desc else H.ip_num.asc(), func.lower(H.name)],
                 "last_connected": [H.last_connected.desc() if desc else H.last_connected.asc()], "vulns": [H.k_total.desc() if desc else H.k_total.asc(), x.e_total.desc() if desc else x.e_total.asc()]}[sort]
    q = select(H, ZcHostZone.zone_id, func.count().over().label("_total")).select_from(_joined()).where(and_(*cond)).order_by(*order, H.host_id).offset(offset).limit(limit)
    rows = (await db.execute(q)).all()
    if rows:
        total = int(rows[0]._total)
    else:                                                        # страница за пределами списка: число находим отдельным запросом
        total = int((await db.execute(select(func.count()).select_from(select(H.source_id).select_from(_joined()).where(and_(*cond)).subquery()))).scalar_one()) if offset else 0
    names = {str(s.id): s.name for s in (await db.execute(select(KscSource))).scalars()}
    zmap = await zones_of(db, [(r[0].source_id, r[0].host_id, r[0].gen) for r in rows])
    items = [host_out(r[0], zone_days.get(zid) or default_days, bd, sd, ext, names, zmap.get((r[0].source_id, r[0].host_id), [])) for r in rows]
    return total, items


async def zones_of(db: AsyncSession, keys: list[tuple]) -> dict[tuple, list[str]]:
    out: dict[tuple, list[str]] = {}
    if not keys:
        return out
    by_src: dict = {}
    for s, h, g in keys:
        by_src.setdefault((s, g), []).append(h)
    for (s, g), hs in by_src.items():
        for hh, z in (await db.execute(select(ZcHostZone.host_id, ZcHostZone.zone_id).where(ZcHostZone.source_id == s, ZcHostZone.gen == g, ZcHostZone.host_id.in_(hs)))).all():
            out.setdefault((s, hh), []).append(z)
    return {k: [z for z in v if z != UNASSIGNED] for k, v in out.items()}


# ------------------------------------------------------------------------------------------------ компьютер и наборы для отчётов
async def current_gen(db: AsyncSession, sid) -> int:
    return int((await db.execute(select(ZcSource.gen).where(ZcSource.source_id == sid))).scalar_one_or_none() or 0)


async def load_host(db: AsyncSession, sid, host_id: int, *, params: dict | None = None, source_name: str = "") -> dict | None:
    """Компьютер со строками обнаружений в виде, который выдавал прежний расчёт (`dataset.host_record`): карточка и отчёт по одному компьютеру."""
    gen = await current_gen(db, sid)
    if not gen:
        return None
    row = (await db.execute(select(ZcHost).where(ZcHost.source_id == sid, ZcHost.host_id == host_id, ZcHost.gen == gen))).scalar_one_or_none()
    if row is None:
        return None
    zs = await db.get(ZcSource, sid)
    rows = (await db.execute(select(ZcDetection).where(ZcDetection.source_id == sid, ZcDetection.gen == gen, ZcDetection.host_id == host_id).order_by(ZcDetection.severity.desc(), ZcDetection.id))).scalars().all()
    return _compose(row, rows, zs, params or {}, source_name)


def _buckets(rows) -> tuple[dict, dict]:
    hv = {"current": [], "accepted": [], "excluded": []}
    he = {"current": [], "accepted": [], "excluded": []}
    for d in rows:
        (hv if d.origin == "ksc" else he)[d.bucket].append(unpack_row(d.row, d.origin))
    return hv, he


def _compose(row: ZcHost, det, zs: ZcSource, params: dict, source_name: str, *, now: datetime | None = None, zone_activity: dict | None = None, activity_days: int = 30) -> dict:
    r = unpack_record(row.data)
    days = r.get("days_since_connection")
    lim = (zone_activity or {}).get(r["zones"][0]) if r.get("zones") else None
    r["active"] = days is not None and days <= (lim or activity_days)
    hv, he = _buckets(det)
    a = {}
    if zs.agg_only:
        a = {"critical": row.k_crit, "high": row.k_high, "warning": row.k_warn, "total": row.k_total}
    return D.host_record(r, hv, he, a, agg_only=zs.agg_only, floor=D.SEV_RANK.get(params.get("severity") or "", 0), now=now or zs.built_at or utcnow(), bases_days=int(params.get("bases_days") or 3),
                         scan_days=int(params.get("scan_days") or 30), source_id=str(row.source_id), source_name=source_name)


async def parts_for_zones(db: AsyncSession, zone_ids: list[str], params: dict, sids: list[uuid.UUID] | None, *, activity_days: int, zone_activity: dict[str, int], want_ext: bool,
                          include_inactive: bool, online_only: bool, chunk: int = 600) -> list[dict]:
    """Наборы для отчёта о выбранных зонах — в форме результата `dataset.assemble`, но из сохранённых данных и порциями по компьютерам. 'ext' отключает потенциальные совпадения."""
    parts = []
    srcs = (await db.execute(select(ZcSource, KscSource).join(KscSource, KscSource.id == ZcSource.source_id).where(ZcSource.gen > 0).order_by(KscSource.position, KscSource.name))).all()
    for zs, src in srcs:
        if sids is not None and src.id not in sids:
            continue
        sel = select(ZcHost.host_id).select_from(_joined()).where(ZcHost.source_id == src.id, ZcHost.gen == zs.gen, ZcSource.gen == zs.gen, ZcHostZone.zone_id.in_(zone_ids)).distinct().order_by(ZcHost.host_id)
        ids = [i for (i,) in (await db.execute(sel)).all()]
        out, hidden, offline, hidden_hosts, online_any = [], 0, 0, [], False
        records = 0
        for i in range(0, len(ids), chunk):
            RES.check("чтение данных отчёта")              # не доводить процесс до нехватки памяти: понятная остановка вместо аварийного завершения контейнера
            part = ids[i:i + chunk]
            rows = (await db.execute(select(ZcHost).where(ZcHost.source_id == src.id, ZcHost.gen == zs.gen, ZcHost.host_id.in_(part)).order_by(ZcHost.host_id))).scalars().all()
            det: dict[int, list] = {}
            for d in (await db.execute(select(ZcDetection).where(ZcDetection.source_id == src.id, ZcDetection.gen == zs.gen, ZcDetection.host_id.in_(part)).order_by(ZcDetection.severity.desc(), ZcDetection.id))).scalars():
                if want_ext or d.origin == "ksc":
                    det.setdefault(d.host_id, []).append(d)
            for row in rows:
                records += 1
                h = _compose(row, det.get(row.host_id, []), zs, params, src.name, zone_activity=zone_activity, activity_days=activity_days)
                online_any = online_any or h["online"] is not None
                if not include_inactive and not h["active"]:
                    hidden += 1
                    hidden_hosts.append({"zones": h["zones"], "reason": "inactive"})
                    continue
                if online_only and (online_any or any(x.online is not None for x in rows)) and h["online"] is not True:
                    offline += 1
                    hidden_hosts.append({"zones": h["zones"], "reason": "offline"})
                    continue
                out.append(h)
        notes = list(zs.notes or [])
        parts.append({"hosts": out, "hidden": hidden, "offline": offline, "hidden_hosts": hidden_hosts, "online_data": online_any, "total_all": records, "notes": notes, "agg_only": zs.agg_only,
                      "source": src.name, "source_id": str(src.id), "at": zs.built_at})
    return parts


async def report_volume(db: AsyncSession, zone_ids: list[str], sids: list[uuid.UUID] | None) -> tuple[int, int]:
    """(компьютеров, строк обнаружений KSC) в выбранных зонах — для проверки, поместится ли отчёт в память: по итогам компьютеров, без чтения самих строк."""
    q = select(func.count(func.distinct(ZcHost.host_id)), func.coalesce(func.sum(ZcHost.k_total + ZcHost.k_acc + ZcHost.k_exc), 0)).select_from(_joined()).where(
        _scope(None, sids), ZcHostZone.zone_id.in_(zone_ids))
    n, rows = (await db.execute(q)).one()
    return int(n), int(rows)


async def host_ids_in_zone(db: AsyncSession, sid, zone: str) -> set[int] | None:
    """Идентификаторы компьютеров источника в зоне («none» — без ответственного); None — подготовленных данных ещё нет."""
    gen = await current_gen(db, sid)
    if not gen:
        return None
    return set((await db.execute(select(ZcHostZone.host_id).where(ZcHostZone.source_id == sid, ZcHostZone.gen == gen, ZcHostZone.zone_id == zone))).scalars().all())


async def host_zone_ids(db: AsyncSession, sid, host_id: int) -> dict | None:
    gen = await current_gen(db, sid)
    if not gen:
        return None
    row = (await db.execute(select(ZcHost.data, ZcHost.conflict, ZcHost.pinned).where(ZcHost.source_id == sid, ZcHost.host_id == host_id, ZcHost.gen == gen))).first()
    if row is None:
        return {"zones": [], "candidates": [], "conflict": False, "pinned": False, "via": "none"}
    d = row[0]
    return {"zones": d.get("zones") or [], "candidates": d.get("zone_candidates") or [], "conflict": bool(row[1]), "pinned": bool(row[2]), "via": d.get("zone_via", "none")}


async def base_records(db: AsyncSession, sid, chunk: int = 2000):
    """Записи компьютеров источника порциями (для предварительного просмотра состава зон и поиска конфликтов): без обращения к KSC."""
    gen = await current_gen(db, sid)
    last = -1
    while gen:
        rows = (await db.execute(select(ZcHost.data).where(ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.host_id > last).order_by(ZcHost.host_id).limit(chunk))).scalars().all()
        if not rows:
            return
        last = rows[-1]["host_id"]
        yield [unpack_record(d) for d in rows]


# ------------------------------------------------------------------------------------------------ готовые сводки
async def source_states(db: AsyncSession, sids: list[uuid.UUID] | None = None) -> list[dict]:
    q = select(ZcSource, KscSource).join(KscSource, KscSource.id == ZcSource.source_id).where(KscSource.is_active.is_(True)).order_by(KscSource.position, KscSource.name)
    out = []
    for zs, src in (await db.execute(q)).all():
        if sids is not None and src.id not in sids:
            continue
        out.append({"id": str(src.id), "name": src.name, "gen": zs.gen, "status": zs.status, "built_at": zs.built_at, "duration_ms": zs.duration_ms, "error": zs.error, "progress": zs.progress,
                    "hosts": zs.hosts_n, "detections": zs.detections_n, "agg_only": zs.agg_only, "stamp": zs.stamp, "newer": bool(zs.gen and ((zs.probe_stamp and zs.probe_stamp != zs.stamp) or (zs.vdb_rev_now and zs.vdb_rev_now != zs.vdb_rev))),
                    "probe_at": zs.probe_at})
    return out


async def dashboard_payload(db: AsyncSession, zone_id: str, sids: list[uuid.UUID] | None, *, default_days: int, zone_days: dict[str, int]) -> dict:
    st = (await group_stats(db, sids=sids, zone_id=zone_id, default_days=default_days, zone_days=zone_days)).get(zone_id) or _empty_stats()
    cc = (await conflict_counts(db, sids)).get(zone_id, (0, 0))
    return {"stats": st, "conflicts": cc[1], "hosts_all": cc[0]}


def _empty_stats() -> dict:
    z = {"total": 0, "in_scope": 0, "inactive": 0, "active": 0, "online": 0, "offline": 0, "online_unknown": 0, "critical": 0, "other_vulns": 0, "any_vulns": 0, "protection": 0, "potential": 0, "ok": 0,
         "state": {k: 0 for k in D.STATE_ORDER}, "severity": {"critical": 0, "high": 0, "warning": 0, "none": 0}, "vulns": {"critical": 0, "high": 0, "warning": 0},
         "problems": [{"key": k, "title": t, "hosts": 0} for k, (t, _h) in P.PROBLEMS.items()], "excluded": 0, "accepted": 0, "review": 0}
    return z


async def refresh_dashboards(sm: async_sessionmaker, zone_ids: list[str] | None, *, default_days: int, data_at: datetime | None, duration_ms: int | None = None) -> int:
    """Пересчитать и атомарно заменить готовые сводки зон (по умолчанию — все): значения читаются агрегатами SQL из подготовленных данных. Ошибка по зоне оставляет прежнюю сводку."""
    n = 0
    async with sm() as db:
        zd = await zone_days_map(db)
        ids = zone_ids if zone_ids is not None else [str(z) for z in (await db.execute(select(Zone.id))).scalars()] + [UNASSIGNED]
        states = await source_states(db)
        stamps = {s["id"]: s["stamp"] for s in states}
        all_stats = await group_stats(db, default_days=default_days, zone_days=zd)           # один запрос на все зоны
        cc = await conflict_counts(db, None)
        for zid in ids:
            payload = {"stats": all_stats.get(zid) or _empty_stats(), "conflicts": cc.get(zid, (0, 0))[1], "hosts_all": cc.get(zid, (0, 0))[0]}
            payload["stamps"] = stamps
            payload["sources"] = [{"id": s["id"], "name": s["name"]} for s in states if s["gen"]]
            cur = await db.get(ZcDashboard, (zid, "default"))
            if cur is None:
                db.add(ZcDashboard(zone_id=zid, kind="default", payload=payload, built_at=utcnow(), data_at=data_at, duration_ms=duration_ms, status="ok"))
            else:
                cur.payload, cur.built_at, cur.data_at, cur.duration_ms, cur.status, cur.error = payload, utcnow(), data_at or cur.data_at, duration_ms or cur.duration_ms, "ok", None
            n += 1
        await db.commit()
    return n


async def read_dashboard(db: AsyncSession, zone_id: str) -> ZcDashboard | None:
    return await db.get(ZcDashboard, (zone_id, "default"))


async def drop_dashboards(db: AsyncSession, keep: set[str]) -> None:
    await db.execute(delete(ZcDashboard).where(ZcDashboard.zone_id.notin_(keep | {UNASSIGNED})))
