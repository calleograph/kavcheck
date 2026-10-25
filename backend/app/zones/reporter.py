"""Сбор данных зон из подключённых источников KSC и построение документа отчёта: общий для страниц, ручных отчётов и рассылок.
Чтение KSC выполняется один раз на источник на срок кэша; зоны, решения по уязвимостям и пороги применяются в памяти."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..config import Settings
from ..ksc.driver import KscError
from ..models import KscSource, Zone, ZoneContact
from ..reports import quick
from ..services.cache import TtlCache
from ..services.settings import SettingsService
from ..services.sources import SourceRegistry
from ..vdb import store as vdb_store
from . import dataset as D
from . import match as ZM
from . import report as R
from . import service as S
from . import triage as T

UNASSIGNED = "none"


class ZoneData:
    def __init__(self, sm: async_sessionmaker, cfg: Settings, svc: SettingsService, sources: SourceRegistry, cache: TtlCache | None = None):
        self.sm, self.cfg, self.svc, self.sources = sm, cfg, svc, sources
        self.cache = cache or TtlCache()

    async def org(self, db: AsyncSession) -> dict:
        return (await self.svc.get(db, "organization")).model_dump()

    async def active_sources(self, db: AsyncSession, ids: list[str] | None = None, allowed=None) -> list[KscSource]:
        rows = (await db.execute(select(KscSource).where(KscSource.is_active.is_(True)).order_by(KscSource.position, KscSource.name))).scalars().all()
        want = {str(i) for i in ids or []}
        return [s for s in rows if (not want or str(s.id) in want) and (allowed is None or allowed(s))]

    def ctx(self, src: KscSource, general, rcfg, org: dict):
        client = self.sources.client(src)
        return quick.Ctx(source_name=src.name, activity_days=int(general.activity_days), exclude_slaves=rcfg.exclude_slave_servers, max_rows=rcfg.max_rows, sm=self.sm, source_id=src.id, org=org,
                         protection_loader=None), client

    async def raw(self, db: AsyncSession, src: KscSource, *, with_ext: bool = False, refresh: bool = False, progress=lambda _t: None, cancelled=lambda: False) -> D.Raw:
        general, rcfg, org = await self.svc.get(db, "general"), await self.svc.get(db, "reports"), await self.org(db)
        key = (str(src.id), "zraw", rcfg.exclude_slave_servers, rcfg.max_rows)

        async def make() -> D.Raw:
            ctx, client = self.ctx(src, general, rcfg, org)
            ctx.progress, ctx.cancelled = progress, cancelled
            return await D.load_raw(client, ctx)

        try:
            raw, _ = await self.cache.get(key, self.cfg.cache_ttl_seconds, make, refresh=refresh)
        except KscError:
            raise
        return raw

    async def ext_for(self, db: AsyncSession, src: KscSource, host_ids: list[int], *, progress=lambda _t: None, cancelled=lambda: False, refresh: bool = False) -> tuple[list[dict], list[str]]:
        """Потенциальные совпадения с внешними базами для компьютеров (кэш на срок cache_ttl_seconds; меняется при обновлении баз, каталога и решений по сопоставлению)."""
        from ..reports.quick_ext import ext_rows_for_hosts  # noqa: PLC0415

        general, rcfg, org = await self.svc.get(db, "general"), await self.svc.get(db, "reports"), await self.org(db)
        rev = await vdb_store.revision(db, src.id)
        key = (str(src.id), "zext", rev, hashlib.sha1(",".join(map(str, host_ids)).encode()).hexdigest())

        async def make():
            ctx, client = self.ctx(src, general, rcfg, org)
            ctx.progress, ctx.cancelled = progress, cancelled
            return await ext_rows_for_hosts(client, ctx, host_ids)

        val, _ = await self.cache.get(key, self.cfg.cache_ttl_seconds, make, refresh=refresh)
        return val

    async def parts(self, db: AsyncSession, *, params: dict, source_ids: list[str] | None = None, allowed=None, refresh: bool = False, progress=lambda _t: None,
                    cancelled=lambda: False, zone_ids: list[str] | None = None, ext_cap: int = 30_000) -> tuple[list[dict], list[KscSource]]:
        """Наборы «компьютер × проблемы» по источникам с зонами и решениями. params: categories, include_inactive, online_only, severity, bases_days, scan_days."""
        general = await self.svc.get(db, "general")
        zdefs = await S.load_defs(db)
        zindex = await S.index(db)
        zones_days = {z.id: z.activity_days for z in (await db.execute(select(Zone))).scalars() if z.activity_days}
        cats = set(params.get("categories") or R.DEFAULT_CATEGORIES)
        with_ext = "ext_vulns" in cats or params.get("with_ext", False)
        now = datetime.now(timezone.utc)
        parts, srcs = [], await self.active_sources(db, source_ids, allowed)
        for src in srcs:
            raw = await self.raw(db, src, refresh=refresh, progress=progress, cancelled=cancelled)
            tindex = await T.load(db, src.id, now)
            ext_rows, ext_notes = None, []
            if with_ext:                         # внешние базы — только для компьютеров выбранных зон, а не для всего источника
                want = set(zone_ids or [])
                ids = sorted({r["host_id"] for r in ZM.annotate(raw.base, zindex, str(src.id))
                              if zone_ids is None or ((not r["zones"]) if UNASSIGNED in want and not r["zones"] else bool(set(r["zones"]) & want))})
                if len(ids) > ext_cap:
                    ext_notes = [f"Потенциальные совпадения с внешними базами не рассчитаны: в выбранных зонах {len(ids)} компьютеров (предел для этого вида — {ext_cap}). Сформируйте отчёт по меньшим зонам."]
                else:
                    ext_rows, ext_notes = await self.ext_for(db, src, ids, progress=progress, cancelled=cancelled, refresh=refresh)
            part = D.assemble(raw, zindex, tindex, ext_rows=ext_rows, source_id=str(src.id), source_name=src.name, now=now, activity_days=int(general.activity_days),
                              include_inactive=bool(params.get("include_inactive")) or "inactive" in cats, online_only=bool(params.get("online_only")), bases_days=int(params.get("bases_days") or 3),
                              scan_days=int(params.get("scan_days") or 30), zone_activity=zones_days, min_sev=params.get("severity") or "")
            part["notes"] += ext_notes
            part.update(source=src.name, source_id=str(src.id), at=raw.at)
            if await T.mark_stale(db, tindex):
                await db.commit()
            parts.append(part)
        _ = zdefs
        return parts, srcs

    async def host_ids(self, db: AsyncSession, src: KscSource, zone: str) -> set[int]:
        """Идентификаторы компьютеров источника, принадлежащих зоне («none» — без ответственного): общий фильтр «Зона» разделов и отчётов."""
        from . import match as ZM  # noqa: PLC0415

        raw = await self.raw(db, src, with_ext=False)
        recs = ZM.annotate(raw.base, await S.index(db), str(src.id))
        return {r["host_id"] for r in recs if (not r["zones"] if zone == UNASSIGNED else zone in r["zones"])}

    async def zone_name(self, db: AsyncSession, zone: str) -> str:
        if zone == UNASSIGNED:
            return "Без ответственного"
        z = await db.get(Zone, uuid.UUID(zone))
        return z.name if z else zone

    async def zones_info(self, db: AsyncSession, ids: list[str] | None = None) -> list[dict]:
        q = select(Zone).order_by(Zone.priority, Zone.name)
        if ids is not None:
            q = q.where(Zone.id.in_([uuid.UUID(i) for i in ids]))
        zs = (await db.execute(q)).scalars().all()
        cons: dict[uuid.UUID, list[dict]] = {}
        for c in (await db.execute(select(ZoneContact).order_by(ZoneContact.created_at))).scalars():
            cons.setdefault(c.zone_id, []).append({"id": str(c.id), "name": c.name, "position": c.position, "email": c.email, "role": c.role, "enabled": c.enabled})
        return [{"id": str(z.id), "name": z.name, "description": z.description, "purpose": z.purpose, "priority": z.priority, "activity_days": z.activity_days, "enabled": z.enabled,
                 "contacts": cons.get(z.id, [])} for z in zs]

    async def zone_doc(self, db: AsyncSession, *, zone_ids: list[str], params: dict, source_ids: list[str] | None = None, allowed=None, recipients: str = "", refresh: bool = False,
                       progress=lambda _t: None, cancelled=lambda: False, hide_other_zones: bool = False) -> dict:
        unassigned = UNASSIGNED in zone_ids
        ids = [z for z in zone_ids if z != UNASSIGNED]
        general = await self.svc.get(db, "general")
        info = await self.zones_info(db, ids)
        days = (info[0]["activity_days"] if len(info) == 1 and info[0]["activity_days"] else None) or int(general.activity_days)
        p = {**params, "_days": days, "_recipients": recipients}
        parts, _ = await self.parts(db, params=p, source_ids=source_ids, allowed=allowed, refresh=refresh, progress=progress, cancelled=cancelled, zone_ids=zone_ids)
        if params.get("hosts"):        # отчёт по выбранным компьютерам «источник:идентификатор»
            pick = set(params["hosts"])
            parts = [{**x, "hosts": [h for h in x["hosts"] if f"{h['source_id']}:{h['host_id']}" in pick]} for x in parts]
        names = None if hide_other_zones else {z["id"]: z["name"] for z in await self.zones_info(db)}
        doc = R.build_zone_doc(parts, info, params=p, org=await self.org(db), generated_at=datetime.now(timezone.utc), selection=ids, unassigned=unassigned,
                               base_url=(await self.svc.get(db, "smtp")).base_url, zone_names=names)
        return doc
