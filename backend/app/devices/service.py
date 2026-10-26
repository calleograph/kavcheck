"""Фоновый опрос пользователей устройств: раз в `interval_minutes` по каждому источнику, где KSC отдаёт нужные объекты; ошибка источника не мешает остальным и повторяется через 10 минут."""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import DevicesState, KscSource, utcnow
from ..services.resources import RES, MemoryPressure
from ..services.settings import SettingsService
from ..services.sources import SourceRegistry
from . import users as U

log = logging.getLogger("app.devices")
RETRY_AFTER = timedelta(minutes=10)


def supported(src: KscSource) -> bool:
    f = ((src.last_check or {}).get("features") or {}).get("users")
    return True if f is None else bool(f.get("ok"))          # проверка источника ещё не выполнялась — пробуем; нет объектов — источник пропускается


class DevicesService:
    def __init__(self, sm: async_sessionmaker[AsyncSession], svc: SettingsService, sources: SourceRegistry, journal=None):
        self._sm, self._svc, self._sources, self._journal = sm, svc, sources, journal
        self._stop = asyncio.Event()
        self.current: str | None = None
        self._tasks: set[asyncio.Task] = set()

    def stop(self) -> None:
        self._stop.set()

    async def due(self) -> list[uuid.UUID]:
        out = []
        async with self._sm() as db:
            cfg = await self._svc.get(db, "devices")
            if not cfg.enabled:  # type: ignore[attr-defined]
                return []
            now = utcnow()
            for src in (await db.execute(select(KscSource).where(KscSource.is_active.is_(True)))).scalars().all():
                if not supported(src):
                    continue
                st = await db.get(DevicesState, src.id)
                if st is None or st.requested_at is not None:
                    out.append(src.id)
                elif st.error_at and now - st.error_at < RETRY_AFTER:
                    continue
                elif st.polled_at is None or now - st.polled_at >= timedelta(minutes=int(cfg.interval_minutes)):  # type: ignore[attr-defined]
                    out.append(src.id)
        return out

    async def request(self, source_ids: list[uuid.UUID]) -> None:
        async with self._sm() as db:
            for sid in source_ids:
                st = await db.get(DevicesState, sid)
                if st is None:
                    db.add(DevicesState(source_id=sid, requested_at=utcnow()))
                else:
                    st.requested_at, st.error_at = utcnow(), None
            await db.commit()

    async def run_source(self, sid: uuid.UUID) -> dict | None:
        async with self._sm() as db:
            src = await db.get(KscSource, sid)
            cfg = await self._svc.get(db, "devices")
        if src is None:
            return None
        from ..services.jobs import JOBS  # noqa: PLC0415

        async with JOBS.run("devices", str(sid)) as lease:                  # опрос источника ведёт один исполнитель; недоступный источник занимает только свою задачу
            if lease is None:
                return None
            return await self._poll(sid, src, cfg)

    async def _poll(self, sid: uuid.UUID, src, cfg) -> dict | None:
        self.current = src.name
        try:
            async with RES.heavy(f"пользователи: {src.name}", 1):
                try:
                    return await U.poll_source(self._sm, self._sources.client(src), src, list(cfg.service_masks), retention_days=int(cfg.retention_days), res=RES)  # type: ignore[attr-defined]
                except MemoryPressure:
                    raise
                except Exception as exc:  # noqa: BLE001 — KSC недоступен или нет прав: накопленное сохраняется, причина видна в интерфейсе
                    msg = f"{type(exc).__name__}: {str(exc)[:300]}"
                    log.warning("Опрос пользователей не удался", extra={"source": src.name, "error": msg})
                    async with self._sm() as db:
                        st = await db.get(DevicesState, sid)
                        if st is None:
                            db.add(DevicesState(source_id=sid, error=msg, error_at=utcnow()))
                        else:
                            st.error, st.error_at, st.requested_at = msg, utcnow(), None
                        await db.commit()
                    return None
        except MemoryPressure as exc:
            log.warning("Опрос пользователей отложен: %s", exc)
            return None
        finally:
            self.current = None

    async def tick(self) -> None:
        for sid in await self.due():
            if self._stop.is_set():
                return
            t = asyncio.get_running_loop().create_task(self.run_source(sid))     # источники опрашиваются независимо: медленный или недоступный не задерживает остальные
            self._tasks.add(t)
            t.add_done_callback(self._tasks.discard)

    async def loop(self) -> None:
        await asyncio.sleep(60)
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка цикла опроса пользователей")
            await asyncio.sleep(60)


