"""Фоновый пересчёт сопоставления EOL: раз в минуту проверяет, изменились ли исходные данные источника (база EOL, каталог, решения), и при изменении пересчитывает под общим ограничителем ресурсов.
Принудительный пересчёт — сброс отпечатка (`request`). Ошибка источника не останавливает остальные; повтор не раньше чем через 15 минут."""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import CatalogState, EolProduct, EolState, JobRun, KscSource, utcnow
from ..services.jobs import JOBS, LeaseLost
from .errors import describe
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
        self._tasks: set[asyncio.Task] = set()
        self.version = ""

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
                if cs is None or cs.built_at is None:
                    continue                                                    # каталога ещё ни разу не было; «строится» новая версия — считаем по последнему готовому, а после публикации нового отпечаток изменится и расчёт повторится сам
                if await JOBS.is_live("eol", str(src.id)):
                    continue                                                    # расчёт этого источника уже идёт (у этого или другого worker)
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
        """Расчёт источника под арендой: если его уже выполняет другой (этот или иной worker), второй запуск не стартует. Аренда продлевается, пока процесс жив."""
        lease = await JOBS.acquire("eol", str(source_id), "запуск")
        if lease is None:
            return None
        status, error = "success", None
        try:
            res = await self._run_source(source_id, lease)
            if res is None:
                status = "error"
                async with self._sm() as db:
                    st = await db.get(EolState, source_id)
                    error = (st.error_detail or st.error) if st is not None else None
            return res
        except LeaseLost as exc:
            status, error = "lost", str(exc)
            return None
        except asyncio.CancelledError:
            status, error = "interrupted", "выполнение отменено"
            raise
        finally:
            await lease.finish(status, error)

    async def _run_source(self, source_id: uuid.UUID, lease) -> dict | None:
        async with self._sm() as db:
            src = await db.get(KscSource, source_id)
            if src is None:
                return None
            general, reports, cfg = await self._svc.get(db, "general"), await self._svc.get(db, "reports"), await self._svc.get(db, "eol")
            st = await db.get(EolState, source_id)
            if st is None:
                db.add(EolState(source_id=source_id))
                await db.flush()
            await db.execute(update(EolState).where(EolState.source_id == source_id).values(started_at=utcnow(), attempt_at=utcnow(), app_version=(self.version or JOBS.version) or None, progress="запуск"))
            await db.commit()
        self.current = src.name
        tasks: set[asyncio.Task] = set()

        stage = {"v": "запуск"}

        def progress(text: str) -> None:                                         # этап расчёта для страницы «Выполняется: …»; ошибка записи не влияет на расчёт
            stage["v"] = text
            asyncio.get_running_loop().create_task(lease.stage(text))
            if text == "сохранение":                                             # запись состояния не должна конкурировать с транзакцией замены результатов
                return

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
                for attempt in (1, 2):
                    try:
                        res = await C.compute_source(self._sm, client, src, activity_days=int(general.activity_days), exclude_slaves=bool(reports.exclude_slave_servers), soon_days=int(cfg.soon_days), res=RES, progress=progress, lease=lease)  # type: ignore[attr-defined]
                        if res and res.get("diag"):
                            self._note(src.name, res["diag"])
                        return res
                    except LeaseLost:
                        raise
                    except Exception as exc:  # noqa: BLE001 — прежние данные остаются; причина видна: пользователю — понятно, администратору — подробно
                        d = describe(exc, stage["v"], "расчёт EOL источника")
                        if attempt == 1 and d.code == "database" and d.transient:
                            log.warning("EOL: временный сбой базы, повтор расчёта", extra={"source": src.name, "error": d.technical})
                            await asyncio.sleep(5)
                            continue
                        log.warning("EOL: расчёт источника не удался", extra={"source": src.name, "stage": stage["v"], "code": d.code, "error": d.technical})
                        async with self._sm() as db:
                            await db.execute(update(EolState).where(EolState.source_id == source_id).values(error=d.friendly, error_detail=d.technical[:2000], error_at=utcnow(), progress=None, started_at=None,
                                                                                                          diag={"stage": stage["v"], "code": d.code, "attempts": attempt}))
                            await db.commit()
                        if self._journal:
                            await self._journal.emit("system", "eol_compute_failed", level="warning", message=f"EOL «{src.name}»: {d.friendly}", data={"source": src.name, "stage": stage["v"], "code": d.code, "detail": d.technical[:600]})
                        return None
        except MemoryPressure as exc:                                          # ожидание места для тяжёлой задачи: расчёт отложен, прежний результат цел
            d = describe(exc, "ожидание ресурсов", "запуск расчёта")
            log.warning("EOL: расчёт отложен: %s", exc)
            async with self._sm() as db:
                await db.execute(update(EolState).where(EolState.source_id == source_id).values(error=d.friendly, error_detail=d.technical[:2000], error_at=utcnow(), diag={"stage": "ожидание ресурсов", "code": d.code, "attempts": 0}))
                await db.commit()
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

    def _note(self, source: str, diag: dict) -> None:
        """Объединённые дубли и конфликты записи — не ошибка расчёта, но признак проблемы в данных или параллельной записи: журнал администратора."""
        if not (diag.get("merged_keys") or diag.get("write_conflicts")):
            return
        log.warning("EOL: при расчёте разрешены повторы или конфликты ключей", extra={"source": source, **{k: diag[k] for k in ("merged_keys", "merged_rows", "write_conflicts", "examples") if k in diag}})
        if self._journal:
            asyncio.get_running_loop().create_task(self._journal.emit("system", "eol_keys_resolved", level="warning", message=f"EOL «{source}»: объединено повторных находок {diag.get('merged_keys', 0)}, конфликтов записи {diag.get('write_conflicts', 0)}",
                                                                       data={"source": source, **{k: diag.get(k) for k in ("merged_keys", "merged_rows", "write_conflicts", "examples")}}))

    async def recover(self) -> int:
        """При запуске worker: ошибки, оставшиеся от прежних версий приложения, переносятся в историю и больше не выдаются за текущую причину отказа (новая попытка ещё не выполнялась);
        признаки «выполняется» снимаются (действующих аренд у только что запущенного процесса нет). Прежние результаты не тронуты. Возвращает число перенесённых ошибок."""
        n = 0
        async with self._sm() as db:
            await db.execute(update(EolState).where(EolState.started_at.is_not(None)).values(started_at=None, progress=None))
            for st in (await db.execute(select(EolState).where(EolState.error.is_not(None)))).scalars().all():
                if st.app_version and st.app_version == (self.version or JOBS.version):
                    continue                                                  # ошибка последней попытки этой версии — она и есть текущая причина
                db.add(JobRun(kind="eol", scope=str(st.source_id), run_id=uuid.uuid4(), owner="прежняя версия", app_version=st.app_version or "до 0.9.6", started_at=st.attempt_at or st.error_at or utcnow(),
                              finished_at=st.error_at or utcnow(), status="error", stage=str((st.diag or {}).get("stage") or ""), error=" | ".join(x for x in (st.error, st.error_detail) if x)[:2000]))
                st.error, st.error_detail, st.error_at = None, None, None
                n += 1
            await db.commit()
        return n

    async def tick(self) -> None:
        """Каждый источник — отдельная задача: сбой или медленный KSC одного не задерживает остальные; тяжёлые расчёты по очереди ограничивает RES.heavy. Сначала небольшие источники."""
        due = await self.due()
        if not due:
            return
        async with self._sm() as db:
            size = {s_id: int(((cs.stats or {}).get("hosts")) or 0) for s_id in due if (cs := await db.get(CatalogState, s_id)) is not None}
        for sid in sorted(due, key=lambda i: size.get(i, 0)):
            if self._stop.is_set():
                return
            t = asyncio.get_running_loop().create_task(self.run_source(sid))
            self._tasks.add(t)
            t.add_done_callback(self._tasks.discard)

    async def loop(self) -> None:
        await asyncio.sleep(45)
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка цикла EOL")
            await asyncio.sleep(60)
