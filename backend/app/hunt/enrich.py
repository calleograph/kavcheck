"""Связь находки с компьютером KSC: имя, адрес, ОС, источник, последнее подключение, зона, пользователь. Устройства разных источников не склеиваются по имени или адресу:
адрес, найденный у нескольких устройств, остаётся «неоднозначным» (кандидаты в доказательствах), а не присваивается наугад."""
from __future__ import annotations

import ipaddress
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import DeviceUser, KscSource, Zone, ZcHost, ZcHostZone, ZcSource

NO_ZONE = "Не назначена"
NO_USER = "Не определён"


async def _gens(db: AsyncSession, ids: list[uuid.UUID] | None = None) -> dict[uuid.UUID, int]:
    q = select(ZcSource.source_id, ZcSource.gen).where(ZcSource.gen > 0)
    if ids:
        q = q.where(ZcSource.source_id.in_(ids))
    return {sid: int(g) for sid, g in (await db.execute(q)).all()}


async def by_ip(db: AsyncSession, ips: list[str]) -> dict[str, list[dict]]:
    """Устройства KSC по IPv4-адресам (подготовленные данные зон): адрес → список устройств (несколько — неоднозначно)."""
    nums = {}
    for ip in ips:
        try:
            nums[int(ipaddress.IPv4Address(ip))] = ip
        except ValueError:
            continue
    out: dict[str, list[dict]] = {}
    if not nums:
        return out
    names = {s.id: s.name for s in (await db.execute(select(KscSource))).scalars()}
    for sid, gen in (await _gens(db)).items():
        keys = list(nums)
        for i in range(0, len(keys), 500):
            for r in (await db.execute(select(ZcHost.host_id, ZcHost.name, ZcHost.ip_num, ZcHost.os, ZcHost.last_connected, ZcHost.data).where(ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.ip_num.in_(keys[i:i + 500])))).all():
                out.setdefault(nums[int(r.ip_num)], []).append({"source_id": sid, "source": names.get(sid, ""), "host_id": int(r.host_id), "name": r.name, "os": r.os, "last_connected": r.last_connected,
                                                                 "group": str((r.data or {}).get("group", ""))})
    return out


async def details(db: AsyncSession, pairs: list[tuple[uuid.UUID, int]]) -> dict[tuple[uuid.UUID, int], dict]:
    """Зона и последний замеченный пользователь по устройствам KSC. Пользователь — последнее наблюдение KAV Checker в списках KSC, а не владелец и не интерактивный сеанс."""
    zones = {str(z.id): z.name for z in (await db.execute(select(Zone))).scalars()}
    gens = await _gens(db)
    out: dict[tuple[uuid.UUID, int], dict] = {p: {"zone": NO_ZONE, "user": NO_USER, "user_kind": ""} for p in pairs}
    by_src: dict[uuid.UUID, list[int]] = {}
    for sid, hid in pairs:
        by_src.setdefault(sid, []).append(hid)
    for sid, hids in by_src.items():
        gen = gens.get(sid)
        for i in range(0, len(hids), 500):
            chunk = hids[i:i + 500]
            if gen:
                zs: dict[int, list[str]] = {}
                for hid, z in (await db.execute(select(ZcHostZone.host_id, ZcHostZone.zone_id).where(ZcHostZone.source_id == sid, ZcHostZone.gen == gen, ZcHostZone.host_id.in_(chunk)))).all():
                    if z in zones:
                        zs.setdefault(int(hid), []).append(zones[z])
                for hid, names in zs.items():
                    out[(sid, hid)]["zone"] = ", ".join(sorted(names))[:120]
            seen: dict[int, tuple] = {}
            for u in (await db.execute(select(DeviceUser).where(DeviceUser.source_id == sid, DeviceUser.host_id.in_(chunk), DeviceUser.kind == "user").order_by(DeviceUser.last_seen_at.desc()))).scalars():
                seen.setdefault(int(u.host_id), (u.login or "", u.session_now))
            for hid, (login, now) in seen.items():
                if login:
                    out[(sid, hid)]["user"], out[(sid, hid)]["user_kind"] = login, "в сеансе сейчас" if now else "последний замеченный"
    return out
