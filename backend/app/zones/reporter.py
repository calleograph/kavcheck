"""Данные зон для отчётов и рассылок: из подготовленных данных PostgreSQL; обновление из KSC — только по явному запросу или если данных ещё нет."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..config import Settings
from ..ksc.driver import KscError
from ..models import KscSource, Zone, ZoneContact
from ..services.cache import TtlCache
from ..services.settings import SettingsService
from ..services.sources import SourceRegistry
from . import report as R

UNASSIGNED = "none"
log = logging.getLogger("app.zones")


class ZoneData:
    """Доступ отчётов и рассылок к данным зон: всё берётся из подготовленных данных PostgreSQL (`zones.snapshot`/`zones.zread`); KSC опрашивается только при явном обновлении
    («Обновить данные перед формированием») или если подготовленных данных по источнику ещё нет."""

    def __init__(self, sm: async_sessionmaker, cfg: Settings, svc: SettingsService, sources: SourceRegistry, cache: TtlCache | None = None):
        self.sm, self.cfg, self.svc, self.sources = sm, cfg, svc, sources
        self.cache = cache or TtlCache()

    async def org(self, db: AsyncSession) -> dict:
        return (await self.svc.get(db, "organization")).model_dump()

    async def active_sources(self, db: AsyncSession, ids: list[str] | None = None, allowed=None) -> list[KscSource]:
        rows = (await db.execute(select(KscSource).where(KscSource.is_active.is_(True)).order_by(KscSource.position, KscSource.name))).scalars().all()
        want = {str(i) for i in ids or []}
        return [s for s in rows if (not want or str(s.id) in want) and (allowed is None or allowed(s))]

    # ------------------------------------------------------------------ обновление данных (только по явному запросу или при их отсутствии)
    async def ensure(self, db: AsyncSession, srcs: list[KscSource], zone_ids: list[str] | None, *, refresh: bool = False, max_age_h: float | None = None,
                     progress=lambda _t: None, cancelled=lambda: False) -> list[str]:
        """Гарантирует данные источников: нет данных — полный расчёт; refresh или данные старше max_age_h — обновление хостов выбранных зон. Возвращает замечания.
        Расчёт идёт под общим ограничителем ресурсов; перед формированием отчёта это единственный случай обращения к KSC."""
        from ..services.resources import RES  # noqa: PLC0415
        from . import snapshot as SN  # noqa: PLC0415
        from sqlalchemy import select as sel  # noqa: PLC0415
        from ..models import ZcHostZone  # noqa: PLC0415

        zc = await self.svc.get(db, "zonecache")
        general = await self.svc.get(db, "general")
        bc = SN.BuildCtx(self.sm, self.cfg, self.svc, self.sources, zc, progress=lambda t, _p: progress(t), cancelled=cancelled)
        notes: list[str] = []
        touched: set[str] = set()
        for src in srcs:
            zs = await SN.get_zc(db, src.id)
            await db.commit()
            stale = bool(zs.built_at) and max_age_h is not None and (datetime.now(timezone.utc) - zs.built_at).total_seconds() > max_age_h * 3600
            if zs.gen and not (refresh or stale):
                continue
            hosts = None
            if zs.gen and zone_ids is not None:
                hosts = set((await db.execute(sel(ZcHostZone.host_id).where(ZcHostZone.source_id == src.id, ZcHostZone.gen == zs.gen, ZcHostZone.zone_id.in_(zone_ids)))).scalars().all())
                if not hosts:
                    continue
            async with RES.heavy("обновление данных зоны для отчёта", 1):
                res = await SN.build_source(bc, src, hosts=hosts)
            touched |= set(res["zones"])
            notes.append(f"Данные источника «{src.name}» обновлены перед формированием отчёта ({res['hosts']} компьютеров).")
        if touched:
            from . import zread as ZR  # noqa: PLC0415

            await ZR.refresh_dashboards(self.sm, sorted(touched), default_days=int(general.activity_days), data_at=None)
        return notes

    async def parts(self, db: AsyncSession, *, params: dict, source_ids: list[str] | None = None, allowed=None, refresh: bool = False, progress=lambda _t: None,
                    cancelled=lambda: False, zone_ids: list[str] | None = None, ext_cap: int = 0, limit_hosts: int | None = None, allow_build: bool = True) -> tuple[list[dict], list[KscSource]]:
        """Наборы «компьютер × проблемы» по источникам из подготовленных данных. params: categories, include_inactive, online_only, severity, bases_days, scan_days."""
        from . import zread as ZR  # noqa: PLC0415

        general = await self.svc.get(db, "general")
        cats = set(params.get("categories") or R.DEFAULT_CATEGORIES)
        srcs = await self.active_sources(db, source_ids, allowed)
        zl = zone_ids if zone_ids is not None else [str(z) for z in (await db.execute(select(Zone.id))).scalars()] + [UNASSIGNED]
        if allow_build:
            enotes = await self.ensure(db, srcs, zl if zone_ids is not None else None, refresh=refresh, max_age_h=params.get("_max_age_h"), progress=progress, cancelled=cancelled)
        else:                                       # запрос пользователя к backend: KSC не опрашивается, нет подготовленных данных — понятный отказ
            enotes = []
            from . import zread as ZRC  # noqa: PLC0415

            if any(not await ZRC.current_gen(db, s.id) for s in srcs):
                raise KscError("no_data", "Данные зон по выбранным источникам ещё не рассчитаны: первый расчёт выполняет фоновая служба (Администрирование → Расчёт данных зон). Отчёт можно сформировать после него.")
        zdays = await ZR.zone_days_map(db)
        if limit_hosts is not None:
            n = (await ZR.conflict_counts(db, [s.id for s in srcs])).items()
            big = sum(c[0] for z, c in n if z in zl)
            if big > limit_hosts:
                raise KscError("too_many_rows", f"В выбранных зонах {big} компьютеров: слишком много для предварительного просмотра. Сформируйте отчёт (он выполняется в фоне).")
        parts = await ZR.parts_for_zones(db, zl, params, [s.id for s in srcs], activity_days=int(general.activity_days), zone_activity=zdays, want_ext="ext_vulns" in cats or bool(params.get("with_ext")),
                                         include_inactive=bool(params.get("include_inactive")) or "inactive" in cats, online_only=bool(params.get("online_only")))
        for p in parts:
            p["notes"] = list(p["notes"]) + enotes
        return parts, srcs

    async def host_ids(self, db: AsyncSession, src: KscSource, zone: str) -> set[int]:
        """Идентификаторы компьютеров источника, принадлежащих зоне («none» — без ответственного): общий фильтр «Зона» разделов и отчётов. Нет данных — расчёт источника."""
        from . import zread as ZR  # noqa: PLC0415

        ids = await ZR.host_ids_in_zone(db, src.id, zone)
        if ids is None:
            await self.ensure(db, [src], None)
            ids = await ZR.host_ids_in_zone(db, src.id, zone) or set()
        return ids

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
                       progress=lambda _t: None, cancelled=lambda: False, hide_other_zones: bool = False, limit_hosts: int | None = None, allow_build: bool = True) -> dict:
        unassigned = UNASSIGNED in zone_ids
        ids = [z for z in zone_ids if z != UNASSIGNED]
        general = await self.svc.get(db, "general")
        info = await self.zones_info(db, ids)
        days = (info[0]["activity_days"] if len(info) == 1 and info[0]["activity_days"] else None) or int(general.activity_days)
        p = {**params, "_days": days, "_recipients": recipients}
        parts, _ = await self.parts(db, params=p, source_ids=source_ids, allowed=allowed, refresh=refresh, progress=progress, cancelled=cancelled, zone_ids=zone_ids, limit_hosts=limit_hosts, allow_build=allow_build)
        if params.get("hosts"):        # отчёт по выбранным компьютерам «источник:идентификатор»
            pick = set(params["hosts"])
            parts = [{**x, "hosts": [h for h in x["hosts"] if f"{h['source_id']}:{h['host_id']}" in pick]} for x in parts]
        names = None if hide_other_zones else {z["id"]: z["name"] for z in await self.zones_info(db)}
        doc = R.build_zone_doc(parts, info, params=p, org=await self.org(db), generated_at=datetime.now(timezone.utc), selection=ids, unassigned=unassigned,
                               base_url=(await self.svc.get(db, "smtp")).base_url, zone_names=names)
        return doc
