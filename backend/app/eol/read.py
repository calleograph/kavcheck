"""Чтение готовых результатов EOL для страниц и отчётов: находки по источникам, устройства находки, EOL устройства, счётчики по зонам. Источник KSC не затрагивается."""
from __future__ import annotations

import uuid
from datetime import date

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import EolFinding, EolHost, EolHostStat, EolProduct, ZcHost, ZcHostZone, ZcSource
from ..search import any_of, column_like
from .classify import STATUS_RU

SEV_RU = {"critical": "Критическая", "high": "Высокая", "warning": "Предупреждение", "": ""}
KIND_RU = {"app": "Программа", "os": "Операционная система"}
CONF_RU = {"mapped": "по решению администратора", "high": "по идентификаторам и названию", "name": "только по названию"}
SEV_ORDER = case((EolFinding.severity == "critical", 3), (EolFinding.severity == "high", 2), (EolFinding.severity == "warning", 1), else_=0)
EMPTY = {"hosts": 0, "eol": 0, "extended": 0, "upcoming": 0, "items": 0, "os": 0}
UNDETERMINED = "undetermined"                                           # ОС, для которой выпуск или срок поддержки определить не удалось: не проблема и не «поддерживается», но в списке ОС видна с причиной
PROBLEM_STATUSES = ("eol", "extended", "upcoming")                       # что считается проблемой инфраструктуры; «unknown» — вопрос к администратору (неоднозначное соответствие)


async def zone_agg(db: AsyncSession, zone: str, sids: list[uuid.UUID]) -> dict[tuple, tuple[int, int]]:
    """(источник, тип, предмет, версия) → (устройств в зоне, из них активных) одним запросом; активность — из связей EOL, без обращения к строкам компьютеров."""
    j = (EolHost.__table__
         .join(ZcSource.__table__, and_(ZcSource.source_id == EolHost.source_id, ZcSource.gen > 0))
         .join(ZcHostZone.__table__, and_(ZcHostZone.source_id == EolHost.source_id, ZcHostZone.host_id == EolHost.host_id, ZcHostZone.gen == ZcSource.gen, ZcHostZone.zone_id == zone)))
    q = (select(EolHost.source_id, EolHost.kind, EolHost.subject, EolHost.version, func.count(), func.coalesce(func.sum(case((EolHost.active.is_(True), 1), else_=0)), 0))
         .select_from(j).where(EolHost.source_id.in_(sids)).group_by(EolHost.source_id, EolHost.kind, EolHost.subject, EolHost.version))
    return {(r[0], r[1], r[2], r[3]): (int(r[4]), int(r[5])) for r in (await db.execute(q)).all()}


def finding_out(f: EolFinding, n_all: int, n_active: int, src_names: dict, labels: dict[str, str], today: date | None = None) -> dict:
    today = today or date.today()
    return {"source_id": str(f.source_id), "source": src_names.get(f.source_id, ""), "kind": f.kind, "kind_ru": KIND_RU.get(f.kind, f.kind), "subject": f.subject, "version": f.version,
            "title": f.title, "publisher": f.publisher, "eol_product": f.eol_product, "eol_label": labels.get(f.eol_product, f.eol_product), "eol_release": f.eol_release,
            "status": f.status, "status_ru": STATUS_RU.get(f.status, f.status), "severity": f.severity, "severity_ru": SEV_RU.get(f.severity, ""), "confidence": f.confidence,
            "confidence_ru": CONF_RU.get(f.confidence, ""), "confirmed": f.confirmed, "eol_from": f.eol_from, "eoas_from": f.eoas_from, "eoes_from": f.eoes_from,
            "days_left": (f.eol_from - today).days if f.eol_from else None, "condition": f.condition, "link": f.link, "hosts": int(n_all), "hosts_active": int(n_active),
            "computed_at": f.computed_at}


async def labels_for(db: AsyncSession, names: set[str]) -> dict[str, str]:
    if not names:
        return {}
    return {n: l or n for n, l in (await db.execute(select(EolProduct.name, EolProduct.label).where(EolProduct.name.in_(names)))).all()}


def _filters(sids, *, q, kind, product, publisher, severity, status):
    c = [EolFinding.source_id.in_(sids)]
    if q:
        c.append(any_of(q, EolFinding.title, EolFinding.publisher, EolFinding.eol_product, EolFinding.subject, EolFinding.eol_release))
    if kind:
        c.append(EolFinding.kind == kind)
    if product:
        c.append(EolFinding.eol_product == product)
    if publisher:
        c.append(column_like(EolFinding.publisher, publisher))
    if severity:
        c.append(EolFinding.severity == severity)
    if status:
        c.append(EolFinding.status == status)
    else:
        c.append(or_(EolFinding.status.in_(PROBLEM_STATUSES), and_(EolFinding.kind == "os", EolFinding.status == UNDETERMINED)))
    return c


def listed(f: EolFinding) -> bool:
    """Показывается ли находка в списке по умолчанию (то же правило, что в `_filters`, для расчётов в памяти)."""
    return f.status in PROBLEM_STATUSES or (f.kind == "os" and f.status == UNDETERMINED)


SORTS = {"severity": lambda f, n: (f.severity == "critical", f.severity == "high", f.severity == "warning"), "eol_from": lambda f, n: f.eol_from or date(9999, 1, 1), "title": lambda f, n: f.title.lower(),
         "release": lambda f, n: f.eol_release, "hosts": lambda f, n: n}


async def list_findings(db: AsyncSession, sids: list[uuid.UUID], src_names: dict, *, q: str = "", kind: str = "", product: str = "", publisher: str = "", severity: str = "", status: str = "",
                        zone: str = "", all_hosts: bool = False, sort: str = "hosts", desc: bool = True, offset: int = 0, limit: int = 50) -> dict:
    """Находки для таблицы. Обычный случай — страница по индексам PostgreSQL; для зоны счётчики устройств берутся одним запросом по связям, остальное — в памяти (находок на источник — тысячи, а не миллионы)."""
    if zone:
        return await _list_zone(db, sids, src_names, zone, q=q, kind=kind, product=product, publisher=publisher, severity=severity, status=status, all_hosts=all_hosts, sort=sort, desc=desc,
                                offset=offset, limit=limit)
    shown = EolFinding.hosts_all if all_hosts else EolFinding.hosts_active
    c = _filters(sids, q=q, kind=kind, product=product, publisher=publisher, severity=severity, status=status) + [shown > 0]
    order = {"hosts": shown, "severity": SEV_ORDER, "eol_from": func.coalesce(EolFinding.eol_from, date(9999, 1, 1)), "title": func.lower(EolFinding.title), "release": EolFinding.eol_release}.get(sort, shown)
    rows = (await db.execute(select(EolFinding).where(*c).order_by(order.desc() if desc else order.asc(), SEV_ORDER.desc(), func.lower(EolFinding.title)).offset(offset).limit(limit))).scalars().all()
    total = int((await db.execute(select(func.count()).select_from(EolFinding).where(*c))).scalar_one())
    c2 = _filters(sids, q=q, kind=kind, product=product, publisher=publisher, severity=severity, status="") + [shown > 0]
    by_status = {st: int(n) for st, n in (await db.execute(select(EolFinding.status, func.count()).where(*c2).group_by(EolFinding.status))).all()}
    labels = await labels_for(db, {f.eol_product for f in rows if f.eol_product})
    return {"total": total, "by_status": by_status, "items": [finding_out(f, f.hosts_all, f.hosts_active, src_names, labels) for f in rows]}


async def zone_findings(db: AsyncSession, sids: list[uuid.UUID], zone: str, **filters) -> list[tuple[EolFinding, int, int]]:
    """Находки с устройствами выбранной зоны: (находка, устройств, из них активных)."""
    agg = await zone_agg(db, zone, sids)
    rows = (await db.execute(select(EolFinding).where(*_filters(sids, **filters)))).scalars().all()
    return [(f, *agg[k]) for f in rows if (k := (f.source_id, f.kind, f.subject, f.version)) in agg]


async def _list_zone(db, sids, src_names, zone, *, q, kind, product, publisher, severity, status, all_hosts, sort, desc, offset, limit) -> dict:
    base = dict(q=q, kind=kind, product=product, publisher=publisher, severity=severity)
    got = [(f, n, na) for f, n, na in await zone_findings(db, sids, zone, status="", **base) if (n if all_hosts else na) > 0 and listed(f)]
    by_status: dict[str, int] = {}
    for f, _n, _na in got:
        by_status[f.status] = by_status.get(f.status, 0) + 1
    sel = [x for x in got if not status or x[0].status == status]
    key = SORTS.get(sort, SORTS["hosts"])
    sel.sort(key=lambda x: (key(x[0], x[1] if all_hosts else x[2]), x[0].title.lower()), reverse=desc)
    page = sel[offset:offset + limit]
    labels = await labels_for(db, {f.eol_product for f, _n, _na in page if f.eol_product})
    return {"total": len(sel), "by_status": by_status, "items": [finding_out(f, n, na, src_names, labels) for f, n, na in page]}


async def finding_hosts(db: AsyncSession, sid: uuid.UUID, kind: str, subject: str, version: str, *, q: str = "", zone: str = "", active_only: bool = True, offset: int = 0, limit: int = 100) -> dict:
    """Устройства находки: имя, адрес, ОС, последнее подключение, зоны — из подготовленных данных зон (если расчёта зон ещё нет, возвращаются только идентификаторы).
    Отбор и страница — по связям EOL (индекс по находке); данные устройств читаются только для устройств страницы, имя в поиске — через подготовленные данные."""
    E = EolHost
    j = E.__table__
    cond = [E.source_id == sid, E.kind == kind, E.subject == subject, E.version == version]
    if active_only:
        cond.append(E.active.is_(True))
    gen = (await db.get(ZcSource, sid))
    gen = int(gen.gen) if gen is not None else 0
    if zone or q:
        if not gen:
            return {"total": 0, "items": []}
        if zone:
            j = j.join(ZcHostZone.__table__, and_(ZcHostZone.source_id == E.source_id, ZcHostZone.host_id == E.host_id, ZcHostZone.gen == gen, ZcHostZone.zone_id == zone))
        if q:
            j = j.join(ZcHost.__table__, and_(ZcHost.source_id == E.source_id, ZcHost.host_id == E.host_id, ZcHost.gen == gen))
            cond.append(any_of(q, ZcHost.name, ZcHost.search))
    total = int((await db.execute(select(func.count()).select_from(j).where(*cond))).scalar_one())
    ids = [int(h) for (h,) in (await db.execute(select(E.host_id).select_from(j).where(*cond).order_by(E.host_id).offset(offset).limit(limit))).all()]
    det = {}
    if ids and gen:
        det = {int(r.host_id): r for r in (await db.execute(select(ZcHost.host_id, ZcHost.name, ZcHost.os, ZcHost.last_connected, ZcHost.active, ZcHost.online, ZcHost.data).where(
            ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.host_id.in_(ids)))).all()}
    items = []
    for hid in ids:
        r = det.get(hid)
        d = (r.data or {}) if r is not None else {}
        items.append({"host_id": hid, "name": r.name if r is not None else f"#{hid}", "ip": d.get("ip", ""), "os": (r.os if r is not None else "") or "", "last_connected": r.last_connected if r is not None else None,
                      "active": r.active if r is not None else None, "online": r.online if r is not None else None, "group": d.get("group", ""), "zones": d.get("zones") or []})
    items.sort(key=lambda x: (x["name"].lower(), x["host_id"]))
    return {"total": total, "items": items}


async def host_items(db: AsyncSession, sid: uuid.UUID, host_id: int) -> list[dict]:
    """Программы и ОС устройства с закончившейся или заканчивающейся поддержкой (для карточки компьютера)."""
    rows = (await db.execute(select(EolFinding).join(EolHost, and_(EolHost.source_id == EolFinding.source_id, EolHost.kind == EolFinding.kind, EolHost.subject == EolFinding.subject,
                                                                  EolHost.version == EolFinding.version)).where(EolHost.source_id == sid, EolHost.host_id == host_id, EolFinding.status.in_(PROBLEM_STATUSES))
                             .order_by(SEV_ORDER.desc(), EolFinding.title))).scalars().all()
    labels = await labels_for(db, {f.eol_product for f in rows if f.eol_product})
    return [finding_out(f, f.hosts_all, f.hosts_active, {}, labels) for f in rows]


async def zone_counts(db: AsyncSession, sids: list[uuid.UUID] | None, zone: str | None = None) -> dict[str, dict]:
    """По зонам: устройства с EOL (стандартная поддержка закончена — критическая), только расширенная поддержка, скоро заканчивается; проблемные программы и ОС — без двойного подсчёта устройства.
    Читает готовые итоги по устройствам (`eol_host_stat`): миллионы связей «устройство — находка» при открытии страницы не агрегируются."""
    j = (EolHostStat.__table__
         .join(ZcSource.__table__, and_(ZcSource.source_id == EolHostStat.source_id, ZcSource.gen > 0))
         .join(ZcHostZone.__table__, and_(ZcHostZone.source_id == EolHostStat.source_id, ZcHostZone.host_id == EolHostStat.host_id, ZcHostZone.gen == ZcSource.gen)))
    w = [EolHostStat.active.is_(True)]
    if sids is not None:
        w.append(EolHostStat.source_id.in_(sids))
    if zone is not None:
        w.append(ZcHostZone.zone_id == zone)
    S = EolHostStat
    q = (select(ZcHostZone.zone_id.label("z"), func.count().label("hosts"), func.coalesce(func.sum(case((S.w == 3, 1), else_=0)), 0).label("eol"), func.coalesce(func.sum(case((S.w == 2, 1), else_=0)), 0).label("extended"),
                func.coalesce(func.sum(case((S.w == 1, 1), else_=0)), 0).label("upcoming"), func.coalesce(func.sum(S.n), 0).label("items"), func.coalesce(func.sum(S.n_os), 0).label("os"))
         .select_from(j).where(*w).group_by(ZcHostZone.zone_id))
    return {r.z: {"hosts": int(r.hosts), "eol": int(r.eol), "extended": int(r.extended), "upcoming": int(r.upcoming), "items": int(r.items), "os": int(r.os)} for r in (await db.execute(q)).all()}


async def not_ready(db: AsyncSession, sids: list[uuid.UUID] | None) -> list[str]:
    """Названия источников, по которым EOL ещё не рассчитан (нет ни одного успешного расчёта): пока они есть, нули EOL в зонах и дашбордах показывать нельзя — это «нет результата», а не «проблем нет»."""
    from ..models import EolState, KscSource  # noqa: PLC0415

    q = select(KscSource.name).outerjoin(EolState, EolState.source_id == KscSource.id).where(KscSource.is_active.is_(True), EolState.computed_at.is_(None))
    if sids is not None:
        q = q.where(KscSource.id.in_(sids))
    return list((await db.execute(q.order_by(KscSource.name))).scalars().all())


async def readiness(db: AsyncSession, sids: list[uuid.UUID] | None) -> tuple[list[uuid.UUID], list[str]]:
    """(источники с успешным расчётом, названия источников без него): итоги по нескольким источникам считаются только по первым, о вторых сообщается явно (данные неполные)."""
    from ..models import EolState, KscSource  # noqa: PLC0415

    q = select(KscSource.id, KscSource.name, EolState.computed_at).outerjoin(EolState, EolState.source_id == KscSource.id).where(KscSource.is_active.is_(True))
    if sids is not None:
        q = q.where(KscSource.id.in_(sids))
    rows = (await db.execute(q.order_by(KscSource.name))).all()
    return [r[0] for r in rows if r[2] is not None], [r[1] for r in rows if r[2] is None]
