"""Чтение готовых результатов EOL для страниц и отчётов: находки по источникам, устройства находки, EOL устройства, счётчики по зонам. Источник KSC не затрагивается."""
from __future__ import annotations

import uuid
from datetime import date

from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import EolFinding, EolHost, EolProduct, ZcHost, ZcHostZone, ZcSource
from ..search import any_of, column_like
from .classify import STATUS_RU

SEV_RU = {"critical": "Критическая", "high": "Высокая", "warning": "Предупреждение", "": ""}
KIND_RU = {"app": "Программа", "os": "Операционная система"}
CONF_RU = {"mapped": "по решению администратора", "high": "по идентификаторам и названию", "name": "только по названию"}
SEV_ORDER = case((EolFinding.severity == "critical", 3), (EolFinding.severity == "high", 2), (EolFinding.severity == "warning", 1), else_=0)
EMPTY = {"hosts": 0, "eol": 0, "extended": 0, "upcoming": 0, "items": 0, "os": 0}
PROBLEM_STATUSES = ("eol", "extended", "upcoming")                       # что считается проблемой инфраструктуры; «unknown» — вопрос к администратору (неоднозначное соответствие)


def zone_agg(zone: str, sids: list[uuid.UUID]):
    """Подзапрос: по находкам — устройства (все и активные), входящие в зону (по подготовленным данным зон)."""
    j = (EolHost.__table__
         .join(ZcSource.__table__, and_(ZcSource.source_id == EolHost.source_id, ZcSource.gen > 0))
         .join(ZcHostZone.__table__, and_(ZcHostZone.source_id == EolHost.source_id, ZcHostZone.host_id == EolHost.host_id, ZcHostZone.gen == ZcSource.gen, ZcHostZone.zone_id == zone))
         .join(ZcHost.__table__, and_(ZcHost.source_id == EolHost.source_id, ZcHost.host_id == EolHost.host_id, ZcHost.gen == ZcSource.gen)))
    return (select(EolHost.source_id.label("sid"), EolHost.kind.label("k"), EolHost.subject.label("s"), EolHost.version.label("v"), func.count().label("n"),
                   func.coalesce(func.sum(case((ZcHost.active.is_(True), 1), else_=0)), 0).label("na"))
            .select_from(j).where(EolHost.source_id.in_(sids)).group_by(EolHost.source_id, EolHost.kind, EolHost.subject, EolHost.version).subquery())


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


def _filters(sids, *, q, kind, product, publisher, severity, status, zone_sub, all_hosts):
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
        c.append(EolFinding.status.in_(PROBLEM_STATUSES))
    n_all, n_act = (zone_sub.c.n, zone_sub.c.na) if zone_sub is not None else (EolFinding.hosts_all, EolFinding.hosts_active)
    c.append((n_all if all_hosts else n_act) > 0)
    return c, n_all, n_act


async def list_findings(db: AsyncSession, sids: list[uuid.UUID], src_names: dict, *, q: str = "", kind: str = "", product: str = "", publisher: str = "", severity: str = "", status: str = "",
                        zone: str = "", all_hosts: bool = False, sort: str = "hosts", desc: bool = True, offset: int = 0, limit: int = 50) -> dict:
    zsub = zone_agg(zone, sids) if zone else None

    def sel(*cols, status_=status):
        c, n_all, n_act = _filters(sids, q=q, kind=kind, product=product, publisher=publisher, severity=severity, status=status_, zone_sub=zsub, all_hosts=all_hosts)
        s = select(*cols, n_all.label("n_all"), n_act.label("n_act")) if cols else None
        if zsub is not None and s is not None:
            s = s.select_from(EolFinding.__table__.join(zsub, and_(zsub.c.sid == EolFinding.source_id, zsub.c.k == EolFinding.kind, zsub.c.s == EolFinding.subject, zsub.c.v == EolFinding.version)))
        return s, c, n_all

    s, c, n_all = sel(EolFinding)
    shown = n_all if all_hosts else (zsub.c.na if zsub is not None else EolFinding.hosts_active)
    order = {"hosts": shown, "severity": SEV_ORDER, "eol_from": func.coalesce(EolFinding.eol_from, date(9999, 1, 1)), "title": func.lower(EolFinding.title), "release": EolFinding.eol_release}.get(sort, shown)
    s = s.where(*c).order_by(order.desc() if desc else order.asc(), SEV_ORDER.desc(), func.lower(EolFinding.title)).offset(offset).limit(limit)
    rows = (await db.execute(s)).all()
    cnt, cc, _ = sel(func.count().label("c"))
    total = int((await db.execute(cnt.where(*cc))).first().c)
    by_status = {}
    cs, cc2, _ = sel(EolFinding.status.label("st"), func.count().label("c"), status_="")
    for r in (await db.execute(cs.where(*cc2).group_by(EolFinding.status))).all():
        by_status[r.st] = int(r.c)
    labels = await labels_for(db, {r[0].eol_product for r in rows if r[0].eol_product})
    return {"total": total, "by_status": by_status,
            "items": [finding_out(r[0], r.n_all, r.n_act, src_names, labels) for r in rows]}


async def finding_hosts(db: AsyncSession, sid: uuid.UUID, kind: str, subject: str, version: str, *, q: str = "", zone: str = "", active_only: bool = True, offset: int = 0, limit: int = 100) -> dict:
    """Устройства находки: имя, адрес, ОС, последнее подключение, зоны — из подготовленных данных зон (если расчёта зон ещё нет, возвращаются только идентификаторы)."""
    E = EolHost
    base = [E.source_id == sid, E.kind == kind, E.subject == subject, E.version == version]
    j = E.__table__.outerjoin(ZcSource.__table__, ZcSource.source_id == E.source_id).outerjoin(
        ZcHost.__table__, and_(ZcHost.source_id == E.source_id, ZcHost.host_id == E.host_id, ZcHost.gen == ZcSource.gen))
    if zone:
        j = j.join(ZcHostZone.__table__, and_(ZcHostZone.source_id == E.source_id, ZcHostZone.host_id == E.host_id, ZcHostZone.gen == ZcSource.gen, ZcHostZone.zone_id == zone))
    cond = list(base)
    if active_only:
        cond.append(ZcHost.active.is_(True))
    if q:
        cond.append(any_of(q, ZcHost.name, ZcHost.search))
    total = int((await db.execute(select(func.count()).select_from(j).where(*cond))).scalar_one())
    rows = (await db.execute(select(E.host_id, ZcHost.name, ZcHost.os, ZcHost.last_connected, ZcHost.active, ZcHost.online, ZcHost.data).select_from(j).where(*cond)
                             .order_by(func.lower(func.coalesce(ZcHost.name, "")), E.host_id).offset(offset).limit(limit))).all()
    items = []
    for r in rows:
        d = r.data or {}
        items.append({"host_id": int(r.host_id), "name": r.name or f"#{r.host_id}", "ip": d.get("ip", ""), "os": r.os or "", "last_connected": r.last_connected, "active": r.active, "online": r.online,
                      "group": d.get("group", ""), "zones": d.get("zones") or []})
    return {"total": total, "items": items}


async def host_items(db: AsyncSession, sid: uuid.UUID, host_id: int) -> list[dict]:
    """Программы и ОС устройства с закончившейся или заканчивающейся поддержкой (для карточки компьютера)."""
    rows = (await db.execute(select(EolFinding).join(EolHost, and_(EolHost.source_id == EolFinding.source_id, EolHost.kind == EolFinding.kind, EolHost.subject == EolFinding.subject,
                                                                  EolHost.version == EolFinding.version)).where(EolHost.source_id == sid, EolHost.host_id == host_id, EolFinding.status.in_(PROBLEM_STATUSES))
                             .order_by(SEV_ORDER.desc(), EolFinding.title))).scalars().all()
    labels = await labels_for(db, {f.eol_product for f in rows if f.eol_product})
    return [finding_out(f, f.hosts_all, f.hosts_active, {}, labels) for f in rows]


async def zone_counts(db: AsyncSession, sids: list[uuid.UUID] | None, zone: str | None = None) -> dict[str, dict]:
    """По зонам: устройства с EOL (стандартная поддержка закончена — критическая), только расширенная поддержка, скоро заканчивается; проблемные программы и ОС — без двойного подсчёта устройства."""
    H = ZcHost
    j = (EolHost.__table__
         .join(EolFinding.__table__, and_(EolFinding.source_id == EolHost.source_id, EolFinding.kind == EolHost.kind, EolFinding.subject == EolHost.subject, EolFinding.version == EolHost.version))
         .join(ZcSource.__table__, and_(ZcSource.source_id == EolHost.source_id, ZcSource.gen > 0))
         .join(ZcHostZone.__table__, and_(ZcHostZone.source_id == EolHost.source_id, ZcHostZone.host_id == EolHost.host_id, ZcHostZone.gen == ZcSource.gen))
         .join(H.__table__, and_(H.source_id == EolHost.source_id, H.host_id == EolHost.host_id, H.gen == ZcSource.gen)))
    w = [EolFinding.status.in_(PROBLEM_STATUSES), H.active.is_(True)]
    if sids is not None:
        w.append(EolHost.source_id.in_(sids))
    if zone is not None:
        w.append(ZcHostZone.zone_id == zone)
    q = (select(ZcHostZone.zone_id.label("z"), EolHost.source_id.label("sid"), EolHost.host_id.label("h"),
                func.max(case((EolFinding.status == "eol", 3), (EolFinding.status == "extended", 2), else_=1)).label("w"),
                func.count().label("items"), func.sum(case((EolFinding.kind == "os", 1), else_=0)).label("os_items"))
         .select_from(j).where(*w).group_by(ZcHostZone.zone_id, EolHost.source_id, EolHost.host_id))
    out: dict[str, dict] = {}
    for r in (await db.execute(q)).all():
        o = out.setdefault(r.z, {"hosts": 0, "eol": 0, "extended": 0, "upcoming": 0, "items": 0, "os": 0})
        o["hosts"] += 1
        o["eol" if r.w == 3 else "extended" if r.w == 2 else "upcoming"] += 1
        o["items"] += int(r.items)
        o["os"] += int(r.os_items)
    return out


