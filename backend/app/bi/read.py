"""Чтение данных BI для страниц, карточек и отчётов. Только PostgreSQL: KSC не опрашивается.

Состояние связи «устройство × сотрудник» (одно правило для всех мест):
* current — устройство есть в последнем снимке и указано за сотрудником;
* past — устройство есть в последнем снимке, но уже за другим сотрудником (известно лишь, что смена произошла между двумя выгрузками);
* unknown — устройства нет в последнем снимке: «Историческая связь, текущий статус неизвестен».
Даты — даты выгрузок, в которых связь наблюдалась, а не даты передачи устройства. Почта — только для аналитика и администратора (`pd`)."""
from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime

import re

from sqlalchemy import String, and_, case, cast, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ksc.protection import PROBLEMS
from ..models import BiDevice, BiImport, BiMatch, BiOwner, BiPerson, BiRecord, BiSource, DeviceUser, KscSource, ZcHost, ZcSource
from ..devices.read import zone_names
from ..search import any_of, column_like, local_like
from .match import LEVEL_RU, LINKED

STATE_RU = {"current": "Текущий владелец по BI", "past": "Прежний владелец", "unknown": "Историческая связь, текущий статус неизвестен"}
CONF_RU = {"high": "высокая (устойчивый идентификатор и почта)", "medium": "средняя (имя устройства и почта)", "low": "низкая (условное имя или только ФИО)"}
KSC_PROBLEMS = (("p_no_av", "no_av"), ("p_rtp", "rtp_off"), ("p_inf", "infected"), ("p_lic", "license"))


def state(owner_present: bool, device_present: bool) -> str:
    return "unknown" if not device_present else "current" if owner_present else "past"


def state_sql():
    """Состояние связи в SQL (для фильтров и сортировки) — то же правило, что `state`."""
    return case((BiDevice.present.is_(False), "unknown"), (BiOwner.present.is_(True), "current"), else_="past")


def d(v: datetime | None) -> str:
    return v.strftime("%d.%m.%Y") if v else "—"


def person_out(p: BiPerson, pd: bool) -> dict:
    return {"id": p.id, "name": p.full_name or (p.email if pd else "") or "Без ФИО", "email": p.email if pd else "", "department": p.department, "present": p.present,
            "first_seen_at": p.first_seen_at, "last_seen_at": p.last_seen_at, "source_id": str(p.source_id)}


async def _imports(db: AsyncSession, ids) -> dict:
    ids = [i for i in set(ids) if i]
    if not ids:
        return {}
    return {i.id: {"id": str(i.id), "file": i.file_name, "at": i.snapshot_at or i.started_at} for i in (await db.execute(select(BiImport).where(BiImport.id.in_(ids)))).scalars()}


async def _src_names(db: AsyncSession) -> tuple[dict, dict]:
    bi = {s.id: s for s in (await db.execute(select(BiSource))).scalars()}
    ksc = {s.id: s.name for s in (await db.execute(select(KscSource))).scalars()}
    return bi, ksc


async def ksc_host(db: AsyncSession, sid: uuid.UUID, hid: int) -> dict | None:
    """Сводка компьютера KSC из подготовленных данных зон: защита, связь, последний замеченный пользователь KSC."""
    gen = (await db.execute(select(ZcSource.gen).where(ZcSource.source_id == sid))).scalar()
    if not gen:
        return None
    h = (await db.execute(select(ZcHost).where(ZcHost.source_id == sid, ZcHost.host_id == hid, ZcHost.gen == gen))).scalars().first()
    if h is None:
        return None
    last = (await db.execute(select(DeviceUser).where(DeviceUser.source_id == sid, DeviceUser.host_id == hid, DeviceUser.kind == "user", DeviceUser.resolved.is_(True))
                             .order_by(DeviceUser.session_now.desc(), DeviceUser.last_session_at.desc().nulls_last(), DeviceUser.last_seen_at.desc()).limit(1))).scalars().first()
    data = h.data or {}
    av = data.get("av") or {}
    problems = [PROBLEMS[k][0] for col, k in KSC_PROBLEMS if getattr(h, col)]
    zn = await zone_names(db) if data.get("zones") else {}
    return {"source_id": str(sid), "host_id": hid, "name": h.name, "os": h.os, "ip": data.get("ip", ""), "last_connected": h.last_connected, "online": h.online, "active": h.active,
            "has_av": h.has_av, "av_product": av.get("product") or "", "problems": problems, "protection_ru": ", ".join(problems) if problems else ("Kaspersky установлен, проблем нет" if h.has_av else "нет сведений о Kaspersky"),
            "ksc_user": (f"{last.domain}\\{last.login}" if last.domain else last.login) if last else "", "ksc_user_at": (last.last_session_at or last.last_seen_at) if last else None,
            "zones": [zn.get(str(z), str(z)) for z in data.get("zones") or []]}


async def device_card(db: AsyncSession, device_id: int, *, pd: bool, can_source=lambda _s: True) -> dict | None:
    """Карточка устройства BI: владельцы с датами наблюдения и снимками-основаниями, версии сведений, сопоставление с KSC, расхождения."""
    dev = await db.get(BiDevice, device_id)
    if dev is None:
        return None
    bi, ksc = await _src_names(db)
    src = bi.get(dev.source_id)
    rows = (await db.execute(select(BiOwner, BiPerson).join(BiPerson, BiPerson.id == BiOwner.person_id).where(BiOwner.device_id == device_id).order_by(BiOwner.last_seen_at.desc()))).all()
    recs = (await db.execute(select(BiRecord).where(BiRecord.device_id == device_id).order_by(BiRecord.first_seen_at.desc(), BiRecord.id.desc()).limit(60))).scalars().all()
    imps = await _imports(db, [o.first_import_id for o, _ in rows] + [o.last_import_id for o, _ in rows] + [r.first_import_id for r in recs] + [r.last_import_id for r in recs])
    firsts = sorted(o.first_seen_at for o, _ in rows)
    owners = []
    for o, p in rows:
        st = state(o.present, dev.present)
        nxt = next((f for f in firsts if f > o.last_seen_at), None)
        note = {"current": f"указан в выгрузках с {d(o.first_seen_at)} по {d(o.last_seen_at)}",
                "past": f"указан до выгрузки от {d(o.last_seen_at)}" + (f"; в выгрузке от {d(nxt)} — другой сотрудник (точная дата передачи неизвестна)" if nxt else ""),
                "unknown": f"последний раз указан в выгрузке от {d(o.last_seen_at)}; в последующих выгрузках устройства нет"}[st]
        owners.append({"person": person_out(p, pd), "state": st, "state_ru": STATE_RU[st], "note": note, "first_seen_at": o.first_seen_at, "last_seen_at": o.last_seen_at, "seen_n": o.seen_n,
                       "src_seen_at": o.src_seen_at, "owned_from": o.owned_from, "owned_to": o.owned_to, "confidence": o.confidence, "confidence_ru": CONF_RU.get(o.confidence, o.confidence),
                       "basis": o.basis, "first_import": imps.get(o.first_import_id), "last_import": imps.get(o.last_import_id)})
    owners.sort(key=lambda x: ({"current": 0, "past": 1, "unknown": 2}[x["state"]], -x["last_seen_at"].timestamp()))
    hide = () if pd else ("email", "extra")                 # без прав на персональные данные: ни почты, ни несопоставленных столбцов выгрузки
    versions = [{"first_seen_at": r.first_seen_at, "last_seen_at": r.last_seen_at, "row": r.row_n, "first_import": imps.get(r.first_import_id), "last_import": imps.get(r.last_import_id),
                 "attrs": {k: v for k, v in (r.attrs or {}).items() if k not in hide}, "flags": r.flags} for r in recs]
    matches, issues = [], []
    for m in (await db.execute(select(BiMatch).where(BiMatch.device_id == device_id).order_by(BiMatch.level))).scalars():
        if not can_source(m.ksc_source_id):
            continue
        item = {"id": m.id, "ksc_source_id": str(m.ksc_source_id), "ksc_source": ksc.get(m.ksc_source_id, ""), "host_id": m.host_id, "host_name": m.host_name, "level": m.level,
                "level_ru": LEVEL_RU.get(m.level, m.level), "signals": m.signals, "issues": m.issues, "decided_by": m.decided_by, "decided_at": m.decided_at, "note": m.note}
        if m.level in LINKED:
            item["ksc"] = await ksc_host(db, m.ksc_source_id, m.host_id)
            issues += m.issues
        matches.append(item)
    cur = [o for o in owners if o["state"] == "current"]
    if len(cur) > 1:
        issues.insert(0, {"code": "multi_owner", "text": f"В последней выгрузке устройство указано за несколькими сотрудниками ({len(cur)}): текущий владелец не выбирается"})
    linked = [m for m in matches if m["level"] in LINKED]
    return {"id": dev.id, "source_id": str(dev.source_id), "source": src.name if src else "", "name": dev.name, "names": dev.names, "generic": dev.generic, "os": dev.os, "os_family": dev.os_family,
            "personal": dev.personal, "av": dev.av, "present": dev.present, "first_seen_at": dev.first_seen_at, "last_seen_at": dev.last_seen_at,
            "snapshot_at": (await _imports(db, [src.last_import_id])).get(src.last_import_id, {}).get("at") if src and src.last_import_id else None,
            "owner": cur[0] if len(cur) == 1 else None, "owners": owners, "versions": versions, "matches": matches, "issues": issues,
            "ksc_state": "linked" if linked else "candidates" if matches else "none",
            "ksc_state_ru": "Сопоставлено с KSC" if linked else "Есть возможные соответствия в KSC — требуется решение администратора" if matches else "Не найдено соответствие в подключённых источниках KSC"}


async def host_block(db: AsyncSession, ksc_sid: uuid.UUID, host_id: int, *, pd: bool) -> dict:
    """Блок «Владелец и история принадлежности» карточки компьютера KSC."""
    ms = (await db.execute(select(BiMatch).where(BiMatch.ksc_source_id == ksc_sid, BiMatch.host_id == host_id))).scalars().all()
    linked = [m for m in ms if m.level in LINKED]
    cards = [c for m in linked if (c := await device_card(db, m.device_id, pd=pd, can_source=lambda s: s == ksc_sid))]
    bi, _ = await _src_names(db)
    cands = []
    for m in ms:
        if m.level not in LINKED and m.level != "rejected":
            dev = await db.get(BiDevice, m.device_id)
            cands.append({"device_id": m.device_id, "name": dev.name if dev else "", "source": bi[dev.source_id].name if dev and dev.source_id in bi else "", "level": m.level,
                          "level_ru": LEVEL_RU.get(m.level, m.level), "signals": m.signals})
    has_bi = bool(bi)
    note = "" if cards else ("BI-источники не подключены" if not has_bi else
                             "Есть устройство BI с тем же именем, но соответствие не подтверждено: владелец не показывается, пока администратор не подтвердит сопоставление" if cands else
                             "Сведений BI об этом компьютере нет")
    return {"devices": cards, "candidates": cands, "note": note, "bi_sources": len(bi)}


async def owners_for(db: AsyncSession, ksc_sid: uuid.UUID, host_ids: list[int], *, pd: bool) -> dict[int, dict]:
    """Владелец по BI для списка компьютеров KSC (столбец «Владелец» в списках): текущий владелец, иначе последний известный с пометкой состояния."""
    out: dict[int, dict] = {}
    if not host_ids:
        return out
    for i in range(0, len(host_ids), 1000):
        q = (select(BiMatch.host_id, BiPerson.full_name, BiPerson.email, BiPerson.department, BiOwner.present, BiDevice.present, BiOwner.last_seen_at, BiMatch.level, BiDevice.owners_now)
             .join(BiDevice, BiDevice.id == BiMatch.device_id).join(BiOwner, BiOwner.device_id == BiDevice.id).join(BiPerson, BiPerson.id == BiOwner.person_id)
             .where(BiMatch.ksc_source_id == ksc_sid, BiMatch.host_id.in_(host_ids[i:i + 1000]), BiMatch.level.in_(LINKED)))
        rank: dict[int, tuple] = {}
        for hid, name, email, dept, op, dp, last, level, n_now in (await db.execute(q)).all():
            st = state(op, dp)
            k = ({"current": 0, "past": 2, "unknown": 1}[st], -last.timestamp())
            if hid not in rank or k < rank[hid]:
                rank[hid] = k
                out[int(hid)] = {"name": name or (email if pd else ""), "email": email if pd else "", "department": dept, "state": st, "state_ru": STATE_RU[st], "level": level,
                                 "multi": st == "current" and n_now > 1, "seen_at": last}
    return out


async def attach_owners(db: AsyncSession, items: list[dict], *, pd: bool) -> list[dict]:
    """Поле owner (владелец по BI) для строк списков компьютеров KSC разных источников (source_id в строке)."""
    by: dict = defaultdict(list)
    for it in items:
        if it.get("source_id"):
            by[uuid.UUID(str(it["source_id"]))].append(int(it["host_id"]))
    found = {}
    for sid, hids in by.items():
        for hid, o in (await owners_for(db, sid, hids, pd=pd)).items():
            found[(str(sid), hid)] = o
    for it in items:
        it["owner"] = found.get((str(it.get("source_id")), int(it["host_id"])))
    return items


def _owns(st: str, p: str | None = None):
    """Есть связь сотрудника (с устройством по шаблону p) в состоянии st: current — текущая; past — прежняя или со статусом «неизвестен»."""
    c = [BiOwner.person_id == BiPerson.id]
    if p is not None:
        c.append(BiDevice.search.like(p, escape="\\"))
    if st == "current":
        c += [BiOwner.present.is_(True), BiDevice.present.is_(True)]
    elif st == "past":
        c.append(or_(BiOwner.present.is_(False), BiDevice.present.is_(False)))
    return exists(select(1).select_from(BiOwner).join(BiDevice, BiDevice.id == BiOwner.device_id).where(*c))


async def people(db: AsyncSession, *, q: str = "", source_id: uuid.UUID | None = None, dept: str = "", st: str = "", offset: int = 0, limit: int = 50, pd: bool) -> dict:
    """Сотрудники BI: поиск по ФИО, почте, подразделению, текущим и прежним именам устройств; отбор «текущие» / «прежние» владельцы (вместе с поиском по устройству — владельцы этого устройства)."""
    w = []
    if source_id:
        w.append(BiPerson.source_id == source_id)
    p = local_like(q)
    if p is not None:                            # совпадение по ФИО/почте/подразделению либо по имени устройства — тогда состояние относится именно к связи с этим устройством
        w.append(or_(and_(BiPerson.search.like(p, escape="\\"), *([_owns(st)] if st else [])), _owns(st, p)))
    elif st:
        w.append(_owns(st))
    if (c := column_like(BiPerson.department, dept)) is not None:
        w.append(c)
    total = int((await db.execute(select(func.count()).select_from(BiPerson).where(*w))).scalar_one())
    ps = (await db.execute(select(BiPerson).where(*w).order_by(func.lower(BiPerson.full_name), BiPerson.id).offset(offset).limit(limit))).scalars().all()
    devs: dict[int, dict] = defaultdict(lambda: {"current": [], "past": [], "unknown": []})
    if ps:
        q2 = select(BiOwner.person_id, BiDevice.name, BiOwner.present, BiDevice.present).join(BiDevice, BiDevice.id == BiOwner.device_id).where(BiOwner.person_id.in_([p.id for p in ps])).order_by(BiOwner.last_seen_at.desc())
        for pid, name, op, dp in (await db.execute(q2)).all():
            devs[pid][state(op, dp)].append(name)
    bi, _ = await _src_names(db)
    return {"total": total, "items": [{**person_out(p, pd), "source": bi[p.source_id].name if p.source_id in bi else "", "devices": devs[p.id]} for p in ps]}


async def person_card(db: AsyncSession, pid: int, *, pd: bool, can_source=lambda _s: True) -> dict | None:
    p = await db.get(BiPerson, pid)
    if p is None:
        return None
    bi, ksc = await _src_names(db)
    rows = (await db.execute(select(BiOwner, BiDevice).join(BiDevice, BiDevice.id == BiOwner.device_id).where(BiOwner.person_id == pid).order_by(BiOwner.last_seen_at.desc()))).all()
    ms = defaultdict(list)
    if rows:
        for m in (await db.execute(select(BiMatch).where(BiMatch.device_id.in_([dv.id for _, dv in rows]), BiMatch.level != "rejected"))).scalars():
            if can_source(m.ksc_source_id):
                ms[m.device_id].append({"ksc_source_id": str(m.ksc_source_id), "ksc_source": ksc.get(m.ksc_source_id, ""), "host_id": m.host_id, "host_name": m.host_name, "level": m.level,
                                        "level_ru": LEVEL_RU[m.level]})
    out = {"current": [], "past": [], "unknown": []}
    for o, dv in rows:
        st = state(o.present, dv.present)
        out[st].append({"device_id": dv.id, "name": dv.name, "os": dv.os, "personal": dv.personal, "generic": dv.generic, "first_seen_at": o.first_seen_at, "last_seen_at": o.last_seen_at,
                        "state": st, "state_ru": STATE_RU[st], "confidence_ru": CONF_RU.get(o.confidence, ""), "ksc": [m for m in ms.get(dv.id, []) if m["level"] in LINKED] or ms.get(dv.id, [])[:1],
                        "others_now": max(0, dv.owners_now - (1 if st == "current" else 0))})
    return {**person_out(p, pd), "source": bi[p.source_id].name if p.source_id in bi else "", "account_created": p.account_created, "devices": out,
            "note": "Дата создания учётной записи — не дата начала владения устройством. Даты связей — даты выгрузок, в которых связь наблюдалась."}


DEVICE_FILTERS = ("", "unknown_owner", "multi", "no_ksc", "candidates", "issues", "linked")


def _device_where(q: str, source_id, flt: str, os_family: str, personal: str):
    w = []
    if source_id:
        w.append(BiDevice.source_id == source_id)
    p = local_like(q)
    if p is not None:
        by_person = exists(select(1).select_from(BiOwner).join(BiPerson, BiPerson.id == BiOwner.person_id).where(BiOwner.device_id == BiDevice.id, BiPerson.search.like(p, escape="\\")))
        w.append(or_(BiDevice.search.like(p, escape="\\"), by_person))
    if os_family:
        w.append(BiDevice.os_family == ("" if os_family == "unknown" else os_family))
    if personal in ("yes", "no"):
        w.append(BiDevice.personal.is_(personal == "yes"))
    linked = exists(select(1).where(BiMatch.device_id == BiDevice.id, BiMatch.level.in_(LINKED)))
    if flt == "unknown_owner":                    # «Неопределённые владельцы»: нет ровно одного текущего владельца либо устройства нет в последнем снимке, либо связь низкой достоверности
        low = exists(select(1).where(BiOwner.device_id == BiDevice.id, BiOwner.present.is_(True), BiOwner.confidence == "low"))
        w.append(or_(BiDevice.present.is_(False), BiDevice.owners_now != 1, low))
    elif flt == "multi":
        w.append(and_(BiDevice.present.is_(True), BiDevice.owners_now > 1))
    elif flt == "no_ksc":
        w.append(~exists(select(1).where(BiMatch.device_id == BiDevice.id)))
    elif flt == "candidates":
        w.append(and_(~linked, exists(select(1).where(BiMatch.device_id == BiDevice.id, BiMatch.level.in_(("candidate", "ambiguous", "conflict"))))))
    elif flt == "linked":
        w.append(linked)
    elif flt == "issues":                        # «Расхождения BI и KSC»: противоречия сопоставленных пар, неоднозначные и противоречивые совпадения, несколько владельцев
        iss = exists(select(1).where(BiMatch.device_id == BiDevice.id, or_(BiMatch.level.in_(("ambiguous", "conflict")), and_(BiMatch.level.in_(LINKED), cast(BiMatch.issues, String) != "[]"))))
        w.append(or_(iss, and_(BiDevice.present.is_(True), BiDevice.owners_now > 1)))
    return w


async def devices(db: AsyncSession, *, q: str = "", source_id=None, flt: str = "", os_family: str = "", personal: str = "", offset: int = 0, limit: int = 50, pd: bool,
                  can_source=lambda _s: True) -> dict:
    """Устройства BI с текущим (или последним известным) владельцем и состоянием сопоставления с KSC."""
    w = _device_where(q, source_id, flt, os_family, personal)
    total = int((await db.execute(select(func.count()).select_from(BiDevice).where(*w))).scalar_one())
    ds = (await db.execute(select(BiDevice).where(*w).order_by(BiDevice.short, BiDevice.id).offset(offset).limit(limit))).scalars().all()
    return {"total": total, "items": await device_rows(db, ds, pd=pd, can_source=can_source)}


async def device_rows(db: AsyncSession, ds: list[BiDevice], *, pd: bool, can_source=lambda _s: True) -> list[dict]:
    ids = [x.id for x in ds]
    own: dict[int, list] = defaultdict(list)
    mt: dict[int, list] = defaultdict(list)
    bi, ksc = await _src_names(db)
    for i in range(0, len(ids), 1000):
        part = ids[i:i + 1000]
        for o, p in (await db.execute(select(BiOwner, BiPerson).join(BiPerson, BiPerson.id == BiOwner.person_id).where(BiOwner.device_id.in_(part)).order_by(BiOwner.last_seen_at.desc()))).all():
            own[o.device_id].append((o, p))
        for m in (await db.execute(select(BiMatch).where(BiMatch.device_id.in_(part)))).scalars():
            if can_source(m.ksc_source_id):
                mt[m.device_id].append(m)
    out = []
    for x in ds:
        ow = [(state(o.present, x.present), o, p) for o, p in own[x.id]]
        cur = [(o, p) for s, o, p in ow if s == "current"]
        prev = [(s, o, p) for s, o, p in ow if s != "current"]
        ms = mt[x.id]
        linked = [m for m in ms if m.level in LINKED]
        issues = [i["text"] for m in linked for i in m.issues] + [LEVEL_RU[m.level] for m in ms if m.level in ("ambiguous", "conflict")][:1]
        if len(cur) > 1:
            issues.insert(0, f"несколько владельцев в последней выгрузке ({len(cur)})")
        out.append({"id": x.id, "source_id": str(x.source_id), "source": bi[x.source_id].name if x.source_id in bi else "", "name": x.name, "os": x.os, "os_family": x.os_family, "personal": x.personal,
                    "generic": x.generic, "present": x.present, "last_seen_at": x.last_seen_at, "av": x.av,
                    "owners": [person_out(p, pd) | {"confidence": o.confidence} for o, p in cur], "previous": [person_out(p, pd) | {"state": s, "last_seen_at": o.last_seen_at} for s, o, p in prev[:5]],
                    "previous_n": len(prev), "ksc": [{"ksc_source_id": str(m.ksc_source_id), "ksc_source": ksc.get(m.ksc_source_id, ""), "host_id": m.host_id, "host_name": m.host_name, "level": m.level,
                                                      "level_ru": LEVEL_RU[m.level]} for m in (linked or ms)],
                    "ksc_state": "linked" if linked else "candidates" if ms else "none", "issues": issues})
    return out


async def match_list(db: AsyncSession, *, level: str = "", q: str = "", source_id=None, offset: int = 0, limit: int = 50, can_source=lambda _s: True) -> dict:
    """Сопоставления для решения администратора: кандидаты, неоднозначные, противоречивые, а также принятые автоматически (для проверки)."""
    w = [BiMatch.level == level] if level else [BiMatch.level.in_(("candidate", "ambiguous", "conflict"))]
    if source_id:
        w.append(BiMatch.bi_source_id == source_id)
    if (c := any_of(q, BiMatch.host_name, BiDevice.name)) is not None:
        w.append(c)
    base = select(BiMatch, BiDevice).join(BiDevice, BiDevice.id == BiMatch.device_id).where(*w)
    total = int((await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one())
    rows = (await db.execute(base.order_by(BiDevice.short, BiMatch.id).offset(offset).limit(limit))).all()
    bi, ksc = await _src_names(db)
    items = []
    for m, dv in rows:
        if not can_source(m.ksc_source_id):
            continue
        items.append({"id": m.id, "device_id": dv.id, "device": dv.name, "device_os": dv.os, "bi_source": bi[dv.source_id].name if dv.source_id in bi else "", "ksc_source_id": str(m.ksc_source_id),
                      "ksc_source": ksc.get(m.ksc_source_id, ""), "host_id": m.host_id, "host_name": m.host_name, "level": m.level, "level_ru": LEVEL_RU[m.level], "signals": m.signals,
                      "issues": m.issues, "decided_by": m.decided_by, "decided_at": m.decided_at, "note": m.note})
    counts = {k: n for k, n in (await db.execute(select(BiMatch.level, func.count()).where(*([BiMatch.bi_source_id == source_id] if source_id else [])).group_by(BiMatch.level))).all()}
    return {"total": total, "items": items, "counts": counts}


async def ksc_users(db: AsyncSession, sids: list[uuid.UUID], *, q: str = "", all_os: bool = False, offset: int = 0, limit: int = 50, names_max: int | None = 3) -> dict:
    """Пользователи KSC: учётные записи из списков вошедших (накопленные наблюдения), с числом компьютеров. По умолчанию — только Windows-компьютеры:
    для Linux KSC обычно не передаёт пользователей, фиктивные записи не создаются."""
    U, H = DeviceUser, ZcHost
    j = U.__table__.join(ZcSource.__table__, ZcSource.source_id == U.source_id).join(H.__table__, and_(H.source_id == U.source_id, H.host_id == U.host_id, H.gen == ZcSource.gen))
    w = [U.source_id.in_(sids), U.kind == "user", U.resolved.is_(True)]
    if not all_os:
        w.append(func.lower(H.os).like("%windows%"))
    if (c := any_of(q, U.login, U.domain, H.name)) is not None:
        w.append(c)
    key = func.lower(U.login)
    g = select(key.label("login"), func.max(U.domain).label("domain"), func.count().label("hosts"),            # запись dev_users уникальна по (источник, компьютер, логин): число строк = число компьютеров
               func.max(U.last_session_at).label("last_session_at"), func.max(case((U.session_now.is_(True), 1), else_=0)).label("now")).select_from(j).where(*w).group_by(key)
    total = int((await db.execute(select(func.count()).select_from(g.subquery()))).scalar_one())
    rows = (await db.execute(g.order_by(key).offset(offset).limit(limit))).all()
    names = defaultdict(list)
    if rows:
        logins = [r.login for r in rows]
        hq = (select(func.lower(U.login), H.name).select_from(j).where(*w, func.lower(U.login).in_(logins)).order_by(U.last_session_at.desc().nulls_last()))
        for login, hn in (await db.execute(hq)).all():
            if (names_max is None or len(names[login]) < names_max) and hn not in names[login]:          # отчёт — полный список компьютеров
                names[login].append(hn)
    bi_by = {}
    if rows:
        for p in (await db.execute(select(BiPerson).where(or_(*(func.lower(BiPerson.email).like(re.sub(r"[\\\\%_]", lambda m: "\\" + m.group(), r.login) + "@%", escape="\\") for r in rows))))).scalars():
            bi_by.setdefault(p.email.split("@", 1)[0].lower(), p)
    return {"total": total, "items": [{"login": r.login, "domain": r.domain, "hosts": int(r.hosts), "host_names": names[r.login], "last_session_at": r.last_session_at, "now": bool(r.now),
                                       "bi_person": ({"id": bi_by[r.login].id, "name": bi_by[r.login].full_name, "department": bi_by[r.login].department} if r.login in bi_by else None)} for r in rows],
            "note": "Учётные записи из списков вошедших KSC (по наблюдениям KAV Checker). " + ("Показаны все ОС." if all_os else "Только Windows-компьютеры: для Linux KSC обычно не передаёт пользователей.")}
