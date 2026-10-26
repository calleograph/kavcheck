"""Фоновый пересчёт сопоставления EOL: раз в минуту проверяет, изменились ли исходные данные источника (база EOL, каталог, решения), и при изменении пересчитывает под общим ограничителем ресурсов.
Принудительный пересчёт — сброс отпечатка (`request`). Ошибка источника не останавливает остальные; повтор не раньше чем через 15 минут."""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import CatalogState, EolProduct, EolState, KscSource, utcnow
from ..services.resources import RES, MemoryPressure
from ..services.settings import SettingsService
from ..services.sources import SourceRegistry
from . import compute as C

log = logging.getLogger("app.eol")
RETRY_AFTER = timedelta(minutes=15)


class EolService:
    def __init__(self, sm: async_sessionmaker[AsyncSession], svc: SettingsService, sources: SourceRegistry, journal=None):
        self._sm, self._svc, self._sources, self._journal = sm, svc, sources, journal
        self._stop = asyncio.Event()
        self.current: str | None = None
        self._busy: set[uuid.UUID] = set()

    def stop(self) -> None:
        self._stop.set()

    async def due(self, today=None) -> list[uuid.UUID]:
        """Источники, которым нужен пересчёт: изменились исходные данные или пересчёт запрошен вручную. Ошибки не чаще, чем раз в RETRY_AFTER."""
        out = []
        async with self._sm() as db:
            soon = int((await self._svc.get(db, "eol")).soon_days)  # type: ignore[attr-defined]
            if not (await db.execute(select(EolProduct.name).limit(1))).first():
                return []                                                       # базы EOL ещё нет: сопоставлять не с чем
            for src in (await db.execute(select(KscSource).where(KscSource.is_active.is_(True)))).scalars().all():
                cs = await db.get(CatalogState, src.id)
                if cs is None or cs.status != "ready":
                    continue                                                    # каталог источника ещё не построен
                st = await db.get(EolState, src.id)
                if st is not None and st.error_at and utcnow() - st.error_at < RETRY_AFTER:
                    continue
                if st is None or not st.inputs or st.inputs != await C.current_inputs(db, src.id, today, soon):
                    out.append(src.id)
        return out

    async def request(self, source_id: uuid.UUID | None = None) -> int:
        """Пересчёт по требованию («Пересчитать» в интерфейсе): сбрасывает отпечаток — ближайший цикл пересчитает; прежние данные остаются доступными."""
        async with self._sm() as db:
            q = update(EolState).values(inputs="", error_at=None)
            if source_id is not None:
                q = q.where(EolState.source_id == source_id)
            n = (await db.execute(q)).rowcount or 0
            await db.commit()
        return n

    async def run_source(self, source_id: uuid.UUID) -> dict | None:
        if source_id in self._busy:                                             # тот же источник уже считается в этом процессе: второй расчёт не запускается
            return None
        self._busy.add(source_id)
        try:
            return await self._run_source(source_id)
        finally:
            self._busy.discard(source_id)

    async def _run_source(self, source_id: uuid.UUID) -> dict | None:
        async with self._sm() as db:
            src = await db.get(KscSource, source_id)
            if src is None:
                return None
            general, reports, cfg = await self._svc.get(db, "general"), await self._svc.get(db, "reports"), await self._svc.get(db, "eol")
            st = await db.get(EolState, source_id)
            if st is None:
                db.add(EolState(source_id=source_id))
                await db.flush()
            await db.execute(update(EolState).where(EolState.source_id == source_id).values(started_at=utcnow(), progress="запуск"))
            await db.commit()
        self.current = src.name
        tasks: set[asyncio.Task] = set()

        def progress(text: str) -> None:                                         # этап расчёта для страницы «Выполняется: …»; ошибка записи не влияет на расчёт
            async def write() -> None:
                try:
                    async with self._sm() as db:
                        await db.execute(update(EolState).where(EolState.source_id == source_id).values(progress=text[:200]))
                        await db.commit()
                except Exception:  # noqa: BLE001
                    log.debug("EOL: не записан этап расчёта", exc_info=True)
            t = asyncio.get_running_loop().create_task(write())
            tasks.add(t)
            t.add_done_callback(tasks.discard)
        try:
            async with RES.heavy(f"EOL: {src.name}", 1):
                client = self._sources.client(src)
                try:
                    res = await C.compute_source(self._sm, client, src, activity_days=int(general.activity_days), exclude_slaves=bool(reports.exclude_slave_servers), soon_days=int(cfg.soon_days), res=RES, progress=progress)  # type: ignore[attr-defined]
                except MemoryPressure:
                    raise
                except Exception as exc:  # noqa: BLE001 — KSC недоступен: прежние данные остаются, ошибка видна администратору
                    msg = f"{type(exc).__name__}: {str(exc)[:300]}"
                    log.warning("EOL: расчёт источника не удался", extra={"source": src.name, "error": msg})
                    async with self._sm() as db:
                        await db.execute(update(EolState).where(EolState.source_id == source_id).values(error=msg, error_at=utcnow(), progress=None, started_at=None))
                        await db.commit()
                    if self._journal:
                        await self._journal.emit("system", "eol_compute_failed", level="warning", message=f"EOL «{src.name}»: {msg[:200]}", data={"source": src.name})
                    return None
            return res
        except MemoryPressure as exc:
            log.warning("EOL: расчёт отложен: %s", exc)
            return None
        finally:
            self.current = None
            for t in list(tasks):
                t.cancel()
            try:                                                                  # отложенный (память) или прерванный расчёт не остаётся «выполняющимся»
                async with self._sm() as db:
                    await db.execute(update(EolState).where(EolState.source_id == source_id).values(started_at=None, progress=None))
                    await db.commit()
            except Exception:  # noqa: BLE001
                log.warning("EOL: не снято состояние расчёта", exc_info=True)

    async def recover(self) -> int:
        """При запуске worker: расчёты, прерванные падением процесса, больше не «выполняются» — ближайший цикл запустит их заново; прежний результат не тронут."""
        async with self._sm() as db:
            n = (await db.execute(update(EolState).where(EolState.started_at.is_not(None)).values(started_at=None, progress=None))).rowcount or 0
            await db.commit()
        return n

    async def tick(self) -> None:
        for sid in await self.due():
            if self._stop.is_set():
                return
            await self.run_source(sid)

    async def loop(self) -> None:
        await asyncio.sleep(45)
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка цикла EOL")
            await asyncio.sleep(60)
