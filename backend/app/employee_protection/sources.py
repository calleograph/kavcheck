"""Сводка сотрудников из снимка аудита AD и связанные устройства из внутренней базы."""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from uuid import UUID

from sqlalchemy import and_, exists, or_, select, union
from sqlalchemy.orm import aliased

from ..bi.match import RULE
from ..devices.users import classify as user_kind, split_login
from ..hier.process import COMPANY, DEPT, EMAIL, TITLE
from ..hier.service import latest_ok, records_of
from ..inventory.model import CLS_RU, COMPUTERS, ST_ACTIVE
from ..models import (AdAuditAccount, AdAuditRun, BiDevice, BiMatch, BiOwner, BiPerson, BiSource, DevicesState, DeviceUser,
                      InvAsset, InvPerson, InvRef, KscSource, LdapConnection, ZcHost, ZcHostZone, ZcSource, Zone)
from ..services.resources import RES
from ..services.settings import SettingsService
from ..zones.snapshot import UNASSIGNED, unpack_record

BATCH = 500
CENSUS_AGE = timedelta(days=45)
SESSION_AGE = timedelta(days=30)
BI_AGE = timedelta(days=45)
ROSTER_NOTE = "Список основан на включённых пользовательских записях проверенного каталога AD. Полнота зависит от охвата и правил «Аудита домена»."
BI_ASSIGNMENT = "Закрепление по выгрузке BI"
SESSION = "Наблюдение сеанса KSC"
INVENTORY_USER = "Назначенный пользователь по учёту"
INVENTORY_OWNER = "Владелец по учёту"


def key(value):
    return (value or "").strip().casefold()


def qualified(login, domain):
    return f"{key(login)}@{key(domain)}" if login and domain else ""


def address(value):
    value = key(value)
    return value if re.fullmatch(r"[^@\s]+@[^@\s]+", value) else ""


def iso(value):
    return value.isoformat() if value else None


def dns_from_dn(value):
    return ".".join(re.findall(r"(?:^|,)\s*dc=([\w-]+)(?=,|$)", value, re.IGNORECASE))


async def employees(db, now):
    run = await db.scalar(select(AdAuditRun).where(AdAuditRun.status == "ok", AdAuditRun.finished_at.is_not(None))
                          .order_by(AdAuditRun.finished_at.desc(), AdAuditRun.id.desc()).limit(1))
    meta = {"ready": False, "census_at": iso(run.started_at) if run else None,
            "census_source": f"Аудит домена · {run.domain}" if run and run.domain else "Аудит домена", "warnings": [ROSTER_NOTE]}
    if run is None or not now - CENSUS_AGE <= run.started_at <= now:
        meta["warnings"].append("Нужна завершённая проверка «Аудит домена» за последние 45 суток.")
        return [], meta

    domains = defaultdict(set)
    for dns, netbios, base_dn in await db.execute(select(LdapConnection.domain_dns, LdapConnection.netbios, LdapConnection.base_dn)
                                                 .where(LdapConnection.enabled.is_(True))):
        if netbios and (dns := dns or dns_from_dn(base_dn)):
            domains[key(dns)].add(key(netbios))
    masks = [*(await SettingsService(None).get(db, "devices")).service_masks, "test", "test-*", "test_*", "тест", "тест-*", "тест_*"]
    roster = {}
    alias_owners = defaultdict(set)
    mail_owners = defaultdict(set)
    columns = (AdAuditAccount.guid, AdAuditAccount.login, AdAuditAccount.name, AdAuditAccount.upn, AdAuditAccount.mail,
               AdAuditAccount.dn, AdAuditAccount.ou, AdAuditAccount.title, AdAuditAccount.department, AdAuditAccount.created,
               AdAuditAccount.expires, AdAuditAccount.enabled, AdAuditAccount.category, AdAuditAccount.spn)
    q = select(*columns).where(AdAuditAccount.run_id == run.id).order_by(AdAuditAccount.id)
    excluded = set()
    async for part in (await db.stream(q.execution_options(yield_per=BATCH))).partitions(BATCH):
        for guid, login, name, upn, email, dn, ou, title, dept, created, expires, enabled, category, spn in part:
            if not guid:
                continue
            domain = dns_from_dn(dn)
            sam, stated_domain = split_login(login, upn)
            upn, email = address(upn), address(email)
            aliases = {upn, qualified(sam, stated_domain), qualified(sam, domain), *(qualified(sam, n) for n in domains[key(domain)])} - {""}
            for alias in aliases:
                alias_owners[alias].add(guid)
            if email:
                mail_owners[email].add(guid)
            if not enabled or category != "user" or spn or (expires and expires <= now) or user_kind(sam, domain, masks) != "user":
                excluded.add(guid)
                continue
            person = roster.setdefault(guid, {"id": guid, "name": name or sam, "login": upn or qualified(sam, domain) or sam, "email": email,
                                              "organization": "", "department": dept, "division": ou, "title": title, "account_created": iso(created),
                                              "_logins": set(), "_emails": set()})
            person["_logins"].update(aliases)
            if email:
                person["_emails"].add(email)
        await RES.breathe("список сотрудников для отчёта защиты")

    snap = await latest_ok(db)
    org = {}
    if snap and snap.source == "ldap" and snap.finished_at and now - CENSUS_AGE <= snap.finished_at <= now:
        conflict = set()
        for row in await records_of(db, snap):
            if len(row) <= COMPANY or not (mail := address(row[EMAIL])) or len(mail_owners[mail]) != 1:
                continue
            fields = row[COMPANY], row[DEPT], row[TITLE]
            if mail in org and org[mail] != fields:
                conflict.add(mail)
            org[mail] = fields
        for mail in conflict:
            org.pop(mail)
    else:
        meta["warnings"].append("Для поля «Организация» требуется свежая выгрузка LDAPS в разделе «Иерархия предприятия».")

    uncached = await db.scalar(select(KscSource.id).outerjoin(ZcSource, ZcSource.source_id == KscSource.id)
                               .where(KscSource.is_active.is_(True), or_(ZcSource.gen.is_(None), ZcSource.gen == 0, ZcSource.built_at.is_(None))).limit(1))
    if uncached:
        meta["warnings"].append("Для части подключений KSC ещё нет подготовленных данных зон. Защита связанных устройств требует проверки.")

    result = []
    for guid, p in roster.items():
        if guid in excluded:
            continue
        p["_logins"] = sorted(x for x in p["_logins"] if len(alias_owners[x]) == 1)
        p["_emails"] = sorted(x for x in p["_emails"] if len(mail_owners[x]) == 1)
        co, dept, title = org.get(p["email"], ("", "", ""))
        p.update(organization=co, department=p["department"] or dept, title=p["title"] or title)
        result.append(p)
    meta.update(ready=bool(result), excluded_accounts=len(excluded))
    if not result:
        meta["warnings"].append("В проверенной области AD нет записей, соответствующих условиям отчёта.")
    return result, meta


def inv_employees(person, by_mail, by_login):
    if person is None or not person.active:
        return None
    sam, domain = split_login(person.login, "")
    mail = by_mail.get(address(person.email))
    login = by_login.get(qualified(sam, domain))
    return None if mail and login and mail != login else mail or login


def ownership(value):
    return "personal" if value is True else "corporate" if value is False else "unknown"


def bi_binding(match):
    return and_(match.level == "confirmed", match.decided_by != RULE)


def known_binding(match):
    other = aliased(BiMatch)
    return and_(bi_binding(match), ~exists(select(1).where(other.device_id == match.device_id, other.id != match.id, bi_binding(other)).correlate(match)))


def bi_assignments(now):
    return (select(BiDevice.id, BiDevice.name, BiDevice.os, BiDevice.personal, BiDevice.last_seen_at, BiPerson.email)
            .join(BiSource, BiSource.id == BiDevice.source_id).join(BiOwner, and_(BiOwner.device_id == BiDevice.id, BiOwner.source_id == BiDevice.source_id))
            .join(BiPerson, and_(BiPerson.id == BiOwner.person_id, BiPerson.source_id == BiOwner.source_id))
            .where(BiSource.is_active.is_(True), BiDevice.present.is_(True), BiPerson.present.is_(True), BiOwner.present.is_(True),
                   BiOwner.last_seen_at >= now - BI_AGE, BiOwner.last_seen_at <= now,
                   or_(BiOwner.owned_to.is_(None), BiOwner.owned_to >= now), or_(BiOwner.owned_from.is_(None), BiOwner.owned_from <= now)))


def assets():
    user, owner = aliased(InvPerson), aliased(InvPerson)
    return (select(InvAsset, InvRef.name, user, owner).outerjoin(InvRef, InvRef.id == InvAsset.type_id)
            .outerjoin(user, user.id == InvAsset.user_id).outerjoin(owner, owner.id == InvAsset.owner_id)
            .where(InvAsset.cls.in_(COMPUTERS), InvAsset.st_cls.in_(ST_ACTIVE)))


def inv_links(user, owner, by_mail, by_login):
    links = defaultdict(list)
    for p, basis in ((user, INVENTORY_USER), (owner, INVENTORY_OWNER)):
        if pid := inv_employees(p, by_mail, by_login):
            links[pid].append(basis)
    return links


def device_row(id_, *, name, source_id=None, host_id=None, asset=None, kind=None, raw=None, personal=None, stamp=None, os="", zones=()):
    values = {p for p in personal or () if p is not None}
    if not values and asset and asset.acc_no:
        values.add(False)
    av = (raw or {}).get("av") or {}
    return {"id": id_, "source_id": str(source_id) if source_id else None, "host_id": host_id, "asset_id": asset.id if asset else None,
            "name": name, "ip": (raw or {}).get("ip", ""), "os": (raw or {}).get("os") or os, "os_version": (raw or {}).get("os_version", ""),
            "kind": kind or (CLS_RU[asset.cls] if asset else "Компьютер"), "ownership": ownership(next(iter(values), None) if len(values) == 1 else None),
            "zones": list(zones), "av_product": av.get("product", ""), "av_version": av.get("build", ""),
            "last_connected": iso((raw or {}).get("last_connected")), "snapshot_at": iso(stamp), "protection": raw}


async def devices(db, source_ids, people, now):
    by_mail = {e: p["id"] for p in people for e in p["_emails"]}
    by_login = {a: p["id"] for p in people for a in p["_logins"]}
    names = {str(zid): name for zid, name in await db.execute(select(Zone.id, Zone.name).where(Zone.enabled.is_(True)))}
    names[UNASSIGNED] = "Без зоны"
    source_ids = [UUID(str(sid)) for sid in source_ids]
    sources = (await db.execute(select(KscSource.id, ZcSource.gen, ZcSource.built_at, DevicesState.polled_at)
                                .outerjoin(ZcSource, ZcSource.source_id == KscSource.id).outerjoin(DevicesState, DevicesState.source_id == KscSource.id)
                                .where(KscSource.id.in_(source_ids), KscSource.is_active.is_(True)))).all()
    for sid, gen, stamp, poll in sources:
        sessions = (DeviceUser.source_id == sid, DeviceUser.kind == "user", DeviceUser.resolved.is_(True), DeviceUser.domain != "",
                    DeviceUser.identity_verified.is_(True), DeviceUser.last_session_at >= now - SESSION_AGE,
                    DeviceUser.last_session_at <= now, DeviceUser.last_seen_at <= poll) if poll else (False,)
        cutoff = 0
        while True:
            candidates = union(
                select(DeviceUser.host_id.label("hid")).where(DeviceUser.host_id > cutoff, *sessions),
                select(BiMatch.host_id.label("hid")).where(BiMatch.host_id > cutoff, BiMatch.ksc_source_id == sid, known_binding(BiMatch)),
                select(InvAsset.ksc_host_id.label("hid")).where(InvAsset.ksc_host_id > cutoff, InvAsset.ksc_source_id == sid, InvAsset.ksc_link == "confirmed",
                                                               InvAsset.cls.in_(COMPUTERS), InvAsset.st_cls.in_(ST_ACTIVE),
                                                               or_(InvAsset.user_id.is_not(None), InvAsset.owner_id.is_not(None))),
            ).subquery()
            ids = (await db.scalars(select(candidates.c.hid).order_by(candidates.c.hid).limit(BATCH))).all()
            if not ids:
                break
            cutoff = ids[-1]
            refs = {a.ksc_host_id: (a, typ, usr, own) for a, typ, usr, own in await db.execute(
                assets().where(InvAsset.ksc_source_id == sid, InvAsset.ksc_host_id.in_(ids), InvAsset.ksc_link == "confirmed"))}
            links = {hid: inv_links(usr, own, by_mail, by_login) for hid, (_a, _typ, usr, own) in refs.items()}
            bi = defaultdict(list)
            q = (bi_assignments(now).add_columns(BiMatch.host_id).join(BiMatch, BiMatch.device_id == BiDevice.id)
                 .where(BiMatch.ksc_source_id == sid, BiMatch.host_id.in_(ids), known_binding(BiMatch)))
            for _, name, os, personal, at, mail, hid in await db.execute(q):
                bi[hid].append((name, os, personal, at))
                if pid := by_mail.get(address(mail)):
                    links.setdefault(hid, defaultdict(list))[pid].append(BI_ASSIGNMENT)
            q = select(DeviceUser.host_id, DeviceUser.login, DeviceUser.domain).where(DeviceUser.host_id.in_(ids), *sessions)
            for hid, login, domain in await db.execute(q):
                if pid := by_login.get(qualified(login, domain)):
                    links.setdefault(hid, defaultdict(list))[pid].append(SESSION)
            active = [hid for hid, people_for_device in links.items() if people_for_device]
            if not active:
                await RES.breathe("сопоставление устройств сотрудников")
                continue
            q = select(ZcHost.host_id, ZcHost.name, ZcHost.os, ZcHost.data).where(ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.host_id.in_(active))
            hosts = {hid: (name, os, unpack_record(raw)) for hid, name, os, raw in await db.execute(q)}
            zone_ids = defaultdict(set)
            q = select(ZcHostZone.host_id, ZcHostZone.zone_id).where(ZcHostZone.source_id == sid, ZcHostZone.gen == gen, ZcHostZone.host_id.in_(active))
            for hid, zid in await db.execute(q):
                if zid in names:
                    zone_ids[hid].add(zid)
            for hid in sorted(active):
                a, typ, _, _ = refs.get(hid, (None, None, None, None))
                name, os, raw = hosts.get(hid, ("", "", None))
                infos = bi[hid]
                name = name or (a and (a.hostname or a.name)) or (infos[0][0] if infos else "") or f"Компьютер KSC {hid}"
                if a and a.zone_id and str(a.zone_id) in names:
                    zone_ids[hid].add(str(a.zone_id))
                zones = zone_ids[hid] - {UNASSIGNED} or {UNASSIGNED}
                yield device_row(f"ksc:{sid}:{hid}", name=name, source_id=sid, host_id=hid, asset=a, kind=typ, raw=raw,
                                 stamp=stamp if raw else None, os=os or (infos[0][1] if infos else ""), personal=(i[2] for i in infos),
                                 zones=({"id": z, "name": names[z]} for z in sorted(zones))), {p: sorted(set(b)) for p, b in links[hid].items()}
            await RES.breathe("сопоставление устройств сотрудников")

    q = assets().where(or_(InvAsset.ksc_source_id.is_(None), InvAsset.ksc_host_id.is_(None),
                           and_(InvAsset.ksc_source_id.in_(source_ids), InvAsset.ksc_link != "confirmed")),
                       or_(InvAsset.user_id.is_not(None), InvAsset.owner_id.is_not(None))).order_by(InvAsset.id)
    async for part in (await db.stream(q.execution_options(yield_per=BATCH))).partitions(BATCH):
        for a, typ, usr, own in part:
            if links := inv_links(usr, own, by_mail, by_login):
                zid = str(a.zone_id) if a.zone_id and str(a.zone_id) in names else UNASSIGNED
                yield device_row(f"inv:{a.id}", name=a.hostname or a.name or a.inv_no, asset=a, kind=typ, zones=[{"id": zid, "name": names[zid]}]), dict(links)
        await RES.breathe("карточки оборудования без подтверждения KSC")

    bound = exists(select(1).where(BiMatch.device_id == BiDevice.id, BiMatch.ksc_source_id.in_(source_ids), known_binding(BiMatch)).correlate(BiDevice))
    q = bi_assignments(now).where(~bound).order_by(BiDevice.id, BiPerson.id)
    current = None
    links = {}
    async for part in (await db.stream(q.execution_options(yield_per=BATCH))).partitions(BATCH):
        for did, name, os, personal, at, mail in part:
            if current is None or current[0] != did:
                if links:
                    yield unmatched_bi(*current, zones=[{"id": UNASSIGNED, "name": names[UNASSIGNED]}]), links
                current, links = (did, name, os, personal, at), {}
            if pid := by_mail.get(address(mail)):
                links[pid] = [BI_ASSIGNMENT]
        await RES.breathe("устройства BI без подтверждения KSC")
    if links:
        yield unmatched_bi(*current, zones=[{"id": UNASSIGNED, "name": names[UNASSIGNED]}]), links


def unmatched_bi(did, name, os, personal, at, zones=()):
    return device_row(f"bi:{did}", name=name or f"Устройство BI {did}", os=os, personal=[personal], stamp=at, zones=zones)
