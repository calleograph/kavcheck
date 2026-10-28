"""Область проверки CVE Hunt: активные компьютеры KSC выбранных источников, зон и групп, сети и адреса оператора, «вся инфраструктура» (сети администратора + KSC); исключения.
Все адреса проходят ту же область разрешений, что и Pentest (`pentest/targets.py`), и повторно проверяются сканером непосредственно перед сетевыми действиями."""
from __future__ import annotations

import ipaddress
import re
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import KscSource, Zone, ZcHost, ZcHostZone, ZcSource
from ..pentest import targets as T


async def ksc_hosts(db: AsyncSession, source_ids: list[uuid.UUID], *, active_days: int, zones: list[str], group: str) -> list[dict]:
    """Активные компьютеры источников (подготовленные данные зон, без чтения KSC): [{ip, name, source_id, host_id}]."""
    out: list[dict] = []
    for sid in source_ids:
        gen = (await db.execute(select(ZcSource.gen).where(ZcSource.source_id == sid))).scalar_one_or_none()
        if not gen:
            continue
        q = select(ZcHost.host_id, ZcHost.name, ZcHost.ip_num, ZcHost.days_since, ZcHost.data).where(ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.ip_num.is_not(None), ZcHost.days_since.is_not(None), ZcHost.days_since <= active_days)
        if zones:
            q = q.where(ZcHost.host_id.in_(select(ZcHostZone.host_id).where(ZcHostZone.source_id == sid, ZcHostZone.gen == gen, ZcHostZone.zone_id.in_(zones))))
        for r in (await db.execute(q)).all():
            if group and group.lower() not in str((r.data or {}).get("group", "")).lower():
                continue
            try:
                out.append({"ip": str(ipaddress.IPv4Address(int(r.ip_num))), "name": r.name, "source_id": sid, "host_id": int(r.host_id)})
            except ValueError:
                continue
    return out


def excluded(text: str):
    """Исключения (адреса, сети, диапазоны через запятую/пробел/перенос строки) → предикат «адрес исключён»."""
    nets, ips = [], set()
    for tok in re.split(r"[,\s;]+", text or ""):
        if not tok:
            continue
        try:
            if "-" in tok and "/" not in tok:
                a, _, b = tok.partition("-")
                lo = ipaddress.ip_address(a)
                hi = ipaddress.ip_address(b) if "." in b or ":" in b else ipaddress.ip_address(a.rsplit(".", 1)[0] + "." + b)
                nets.append((int(lo), int(hi), lo.version))
            elif "/" in tok:
                n = ipaddress.ip_network(tok, strict=False)
                nets.append((int(n.network_address), int(n.broadcast_address), n.version))
            else:
                ips.add(str(ipaddress.ip_address(tok)))
        except ValueError:
            raise ValueError(f"Исключение «{tok}» не распознано (адрес, сеть CIDR или диапазон)") from None

    def hit(ip: str) -> bool:
        if ip in ips:
            return True
        a = ipaddress.ip_address(ip)
        return any(lo <= int(a) <= hi and v == a.version for lo, hi, v in nets)
    return hit


async def collect(db: AsyncSession, scope: dict, settings, allowed, activity_days: int) -> dict:
    """{text, devices[], sources_n, networks_n, excluded_n}: текст целей для плана Pentest и сведения для сводки."""
    ids = [uuid.UUID(str(s)) for s in scope.get("sources", []) if allowed(uuid.UUID(str(s)))]
    kind = scope.get("kind", "custom")
    text_parts: list[str] = []
    devices: list[dict] = []
    if kind == "all":
        text_parts += list(settings.hunt_networks)
        if not ids:
            ids = [s for s in (await db.execute(select(KscSource.id).where(KscSource.is_active.is_(True)))).scalars() if allowed(s)]
    if kind in ("all", "sources", "zones", "groups"):
        devices = await ksc_hosts(db, ids, active_days=int(scope.get("active_days") or activity_days), zones=[z for z in scope.get("zones", []) if z] if kind == "zones" else [], group=(scope.get("group") or "") if kind == "groups" else "")
    if scope.get("text"):
        text_parts.append(scope["text"])
    if kind == "all" and not settings.hunt_networks and not devices and not scope.get("text"):
        raise ValueError("Область «вся инфраструктура» пуста: администратор не задал сети для CVE Hunt (Администрирование → Pentest), а в данных KSC нет активных компьютеров с адресами.")
    skip = excluded(scope.get("exclude", ""))
    keep = [d for d in devices if not skip(d["ip"])]
    return {"text": "\n".join(text_parts), "devices": keep, "skip": skip, "sources_n": len({d["source_id"] for d in keep}) if keep else len(ids), "excluded_n": len(devices) - len(keep),
            "networks_n": sum(1 for t in re.split(r"[,\s;]+", "\n".join(text_parts)) if "/" in t or "-" in t)}


async def zone_options(db: AsyncSession) -> list[dict]:
    return [{"id": str(z.id), "name": z.name} for z in (await db.execute(select(Zone).where(Zone.enabled.is_(True)).order_by(Zone.name))).scalars()]
