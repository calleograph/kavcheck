"""Ежедневные срезы показателей главной по каждому источнику (worker): график динамики не зависит от того, заходил ли кто-то на главную, а таблица «Источники данных» показывает
сводку и по источникам вне выбранной области без чтения их KSC при каждом открытии страницы. Срез — счётчики за периоды 7/30/60/90 суток (методика — overview/calc.py)."""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import date, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..ksc import hosts as H
from ..ksc import protection as P
from ..models import KscSource, OverviewDaily, utcnow
from ..services.resources import RES, MemoryPressure
from ..services.sources import SourceRegistry
from . import calc as C

log = logging.getLogger("app.overview")
INTERVAL = timedelta(hours=6)
RETRY_AFTER = timedelta(minutes=30)
KEEP_DAYS = 400


def payload(recs: list[dict], now=None) -> dict:
    """Данные среза: общее число и все счётчики по каждому периоду."""
    by = {str(d): {k: v for k, v in C.summarize(recs, d, now).items() if k in C.METRICS} for d in C.PERIODS}
    return {"total": by["30"]["total"], "by": by, **{f"a{d}": by[str(d)]["active"] for d in C.PERIODS}}


async def store(db: AsyncSession, sid: uuid.UUID, data: dict) -> None:
    """Срез текущих суток: один на источник и сутки; повторная запись заменяет данные."""
    today = date.today()
    row = await db.get(OverviewDaily, (sid, today))
    if row is None:
        db.add(OverviewDaily(source_id=sid, day=today, data=data, taken_at=utcnow()))
    else:
        row.data, row.taken_at = data, utcnow()
    await db.execute(delete(OverviewDaily).where(OverviewDaily.source_id == sid, OverviewDaily.day < today - timedelta(days=KEEP_DAYS)))
    await db.commit()


class SnapshotService:
    def __init__(self, sm: async_sessionmaker[AsyncSession], sources: SourceRegistry, svc, journal=None):
        self._sm, self._sources, self._svc = sm, sources, svc
        self._stop = asyncio.Event()
        self._tasks: set[asyncio.Task] = set()
        self._failed: dict[uuid.UUID, object] = {}
        self.current: str | None = None

    def stop(self) -> None:
        self._stop.set()

    async def due(self) -> list[uuid.UUID]:
        now, out = utcnow(), []
        async with self._sm() as db:
            for src in (await db.execute(select(KscSource).where(KscSource.is_active.is_(True)))).scalars().all():
                last = (await db.execute(select(OverviewDaily.taken_at).where(OverviewDaily.source_id == src.id).order_by(OverviewDaily.day.desc()).limit(1))).scalar_one_or_none()
                if (f := self._failed.get(src.id)) and now - f < RETRY_AFTER:
                    continue
                if last is None or now - last >= INTERVAL:
                    out.append(src.id)
        return out

    async def run_source(self, sid: uuid.UUID) -> bool:
        from ..services.jobs import JOBS  # noqa: PLC0415

        async with self._sm() as db:
            src = await db.get(KscSource, sid)
            rcfg = await self._svc.get(db, "reports")
        if src is None:
            return False
        async with JOBS.run("ov_snapshot", str(sid), "чтение записей защиты") as lease:
            if lease is None:
                return False
            self.current = src.name
            try:
                async with RES.heavy(f"срез главной: {src.name}", 1):
                    client = self._sources.client(src)
                    recs = await P.load(client, exclude_slaves=rcfg.exclude_slave_servers, groups=await H.groups_map(client), hw_cfg=None)
                    data = payload(recs)
                    del recs
                async with self._sm() as db:
                    await lease.fence(db)
                    await store(db, sid, data)
                self._failed.pop(sid, None)
                return True
            except MemoryPressure as exc:
                log.warning("Срез главной отложен: %s", exc)
            except Exception as exc:  # noqa: BLE001 — источник недоступен: прежние срезы остаются, повтор через RETRY_AFTER
                if type(exc).__name__ == "LeaseLost":
                    raise
                log.warning("Срез главной не получен", extra={"source": src.name, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
            finally:
                self.current = None
            self._failed[sid] = utcnow()
            return False

    async def tick(self) -> None:
        for sid in await self.due():
            if self._stop.is_set():
                return
            t = asyncio.get_running_loop().create_task(self.run_source(sid))
            self._tasks.add(t)
            t.add_done_callback(self._tasks.discard)

    async def loop(self) -> None:
        await asyncio.sleep(90)
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка цикла срезов главной")
            await asyncio.sleep(120)
