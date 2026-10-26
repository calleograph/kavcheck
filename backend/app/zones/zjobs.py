"""Фоновый расчёт данных зон (worker): ночное расписание, ручные задания, восстановление после перезапуска, лёгкие проверки свежести.

* Задания хранятся в `zc_jobs`; активное задание каждого вида одно (`dedupe_key`): повторное нажатие «Обновить данные» не создаёт копий.
* Тяжёлые расчёты идут под общим ограничителем ресурсов (`services.resources`): по одному, вместе с анализом уязвимостей и сборкой каталога; при нехватке памяти задание откладывается.
* Задание «running» без пульса дольше 10 минут (процесс перезапущен) возвращается в очередь и безопасно повторяется с начала: до подмены поколения видимые данные не менялись."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..config import Settings
from ..ksc.driver import KscError
from ..models import KscSource, ZcDashboard, ZcHostZone, ZcJob, ZcSource, utcnow
from ..services.audit import Journal
from ..services.resources import RES, MemoryPressure
from ..services.settings import SettingsService, ZonecacheSettings
from ..services.sources import SourceRegistry
from . import snapshot as SN
from . import zread as ZR

log = logging.getLogger("app.zonecache")
STALE_JOB = timedelta(minutes=10)
PROBE_EVERY = timedelta(minutes=15)
CATCHUP = timedelta(hours=6)
RETRY_AFTER_FAIL = timedelta(minutes=30)
MAX_ATTEMPTS = 5
KINDS = {"all": "Все зоны", "zone": "Одна зона", "members": "Состав зон"}


def dedupe_key(kind: str, zone_id: str | None) -> str:
    return f"{kind}:{zone_id or ''}"


async def enqueue(db: AsyncSession, kind: str, *, zone_id: str | None = None, trigger: str = "manual", by: str = "", delay_s: int = 0) -> tuple[ZcJob, bool]:
    """Поставить задание в очередь. Возвращает (задание, создано_ли_новое): если такое уже ждёт или выполняется — возвращается оно (повторных заданий нет)."""
    key = dedupe_key(kind, zone_id)
    cur = (await db.execute(select(ZcJob).where(ZcJob.dedupe_key == key, ZcJob.status.in_(("queued", "running"))))).scalars().first()
    if cur is not None:
        return cur, False
    job = ZcJob(id=uuid.uuid4(), kind=kind, zone_id=zone_id, dedupe_key=key, trigger=trigger, requested_by=by[:120], status="queued", requested_at=utcnow() + timedelta(seconds=delay_s))
    try:
        async with db.begin_nested():
            db.add(job)
            await db.flush()
    except IntegrityError:                                         # одновременный запрос успел раньше
        cur = (await db.execute(select(ZcJob).where(ZcJob.dedupe_key == key, ZcJob.status.in_(("queued", "running"))))).scalars().first()
        if cur is None:
            raise
        return cur, False
    return job, True


def job_out(j: ZcJob) -> dict:
    return {"id": str(j.id), "kind": j.kind, "kind_ru": KINDS.get(j.kind, j.kind), "zone_id": j.zone_id, "trigger": j.trigger, "status": j.status, "requested_by": j.requested_by, "requested_at": j.requested_at,
            "started_at": j.started_at, "finished_at": j.finished_at, "progress": j.progress, "pct": j.pct, "attempts": j.attempts, "error": j.error}


def tz_of(zc: ZonecacheSettings, general_tz: str) -> ZoneInfo:
    try:
        return ZoneInfo(zc.timezone or general_tz or "UTC")
    except Exception:  # noqa: BLE001
        return ZoneInfo("UTC")


def schedule_times(zc: ZonecacheSettings, general_tz: str, now: datetime) -> tuple[datetime, datetime]:
    """(последний плановый момент не позже now, ближайший будущий) в UTC."""
    tz = tz_of(zc, general_tz)
    hh, mm = (int(x) for x in zc.at.split(":"))
    loc = now.astimezone(tz)
    today = loc.replace(hour=hh, minute=mm, second=0, microsecond=0)
    last = today if today <= loc else today - timedelta(days=1)
    nxt = last + timedelta(days=1)
    return last.astimezone(timezone.utc), nxt.astimezone(timezone.utc)


class ZoneCache:
    def __init__(self, sm: async_sessionmaker, cfg: Settings, svc: SettingsService, sources: SourceRegistry, journal: Journal, res=RES):
        self.sm, self.cfg, self.svc, self.sources, self.journal, self.res = sm, cfg, svc, sources, journal, res
        self._stop = asyncio.Event()
        self._prog: tuple[str, int] = ("", 0)
        self._probe_at: dict[uuid.UUID, float] = {}
        self.current: str | None = None

    # ------------------------------------------------------------------ настройки и контекст
    async def settings(self, db: AsyncSession) -> tuple[ZonecacheSettings, str]:
        zc = await self.svc.get(db, "zonecache")
        general = await self.svc.get(db, "general")
        self.res.configure(slots=zc.parallel, pause_ms=SN.PAUSE_MS.get(zc.intensity, 60))
        return zc, general.timezone  # type: ignore[attr-defined,return-value]

    def _bc(self, zc: ZonecacheSettings) -> SN.BuildCtx:
        def progress(text: str, pct: int) -> None:
            self._prog = (text, pct if pct >= 0 else self._prog[1])

        return SN.BuildCtx(self.sm, self.cfg, self.svc, self.sources, zc, progress=progress, cancelled=self._stop.is_set, res=self.res)

    async def active_sources(self, db: AsyncSession) -> list[KscSource]:
        return list((await db.execute(select(KscSource).where(KscSource.is_active.is_(True)).order_by(KscSource.position, KscSource.name))).scalars().all())

    # ------------------------------------------------------------------ планирование
    async def tick(self) -> None:
        async with self.sm() as db:
            zc, gtz = await self.settings(db)
            await self.recover(db)
            now = utcnow()
            srcs = await self.active_sources(db)
            if zc.enabled:
                last_plan, _next = schedule_times(zc, gtz, now)
                if now - last_plan <= CATCHUP:
                    done = (await db.execute(select(func.count()).select_from(ZcJob).where(ZcJob.trigger == "nightly", ZcJob.requested_at >= last_plan))).scalar_one()
                    if not done and srcs:
                        await enqueue(db, "all", trigger="nightly", by="расписание")
            for s in srcs:                                         # источник без подготовленных данных (первый запуск после обновления): рассчитать сразу, не дожидаясь ночи
                zs = await SN.get_zc(db, s.id)
                if zs.gen == 0:
                    failed = (await db.execute(select(ZcJob).where(ZcJob.kind == "all", ZcJob.status == "failed", ZcJob.finished_at >= now - RETRY_AFTER_FAIL))).scalars().first()
                    if failed is None:
                        await enqueue(db, "all", trigger="initial", by="первый расчёт")
            await db.commit()
        await self.probes(srcs)
        await self.run_next()

    async def recover(self, db: AsyncSession) -> None:
        """Задания, которые выполнял завершившийся процесс, возвращаются в очередь; после лимита попыток — ошибка."""
        old = utcnow() - STALE_JOB
        for j in (await db.execute(select(ZcJob).where(ZcJob.status == "running", func.coalesce(ZcJob.heartbeat_at, ZcJob.started_at) < old))).scalars().all():
            if j.attempts >= MAX_ATTEMPTS:
                j.status, j.finished_at, j.error = "failed", utcnow(), "Расчёт прерван (перезапуск службы) слишком много раз подряд"
            else:
                j.status, j.progress = "queued", "возвращено в очередь после перезапуска"
            log.warning("Задание расчёта зон возвращено в очередь после перезапуска", extra={"job": str(j.id), "kind": j.kind})
        await db.flush()

    async def probes(self, srcs: list[KscSource]) -> None:
        if self.current:
            return
        for s in srcs:
            if time.monotonic() - self._probe_at.get(s.id, 0) < PROBE_EVERY.total_seconds():
                continue
            self._probe_at[s.id] = time.monotonic()
            try:
                async with self.sm() as db:
                    zc, _ = await self.settings(db)
                await SN.probe(self._bc(zc), s)
            except Exception as exc:  # noqa: BLE001
                log.debug("Проверка свежести данных KSC не удалась", extra={"source": s.name, "error": str(exc)[:200]})

    # ------------------------------------------------------------------ выполнение
    async def run_next(self) -> bool:
        async with self.sm() as db:
            job = (await db.execute(select(ZcJob).where(ZcJob.status == "queued", ZcJob.requested_at <= utcnow()).order_by(ZcJob.requested_at))).scalars().first()
            if job is None:
                return False
            jid = job.id
        await self.run_job(jid)
        return True

    async def _beat(self, jid: uuid.UUID) -> None:
        while True:
            await asyncio.sleep(3)
            try:
                async with self.sm() as db:
                    text, pct = self._prog
                    await db.execute(update(ZcJob).where(ZcJob.id == jid).values(heartbeat_at=utcnow(), progress=text[:300], pct=max(0, min(100, pct))))
                    await db.commit()
            except Exception:  # noqa: BLE001
                pass

    async def run_job(self, jid: uuid.UUID) -> None:
        async with self.sm() as db:
            job = await db.get(ZcJob, jid)
            if job is None or job.status != "queued":
                return
            job.status, job.started_at, job.heartbeat_at, job.attempts, job.error, job.progress, job.pct = "running", utcnow(), utcnow(), job.attempts + 1, None, "ожидание ресурсов", 0
            kind, zone_id, trigger, attempts = job.kind, job.zone_id, job.trigger, job.attempts
            zc, _gtz = await self.settings(db)
            await db.commit()
        self.current = str(jid)
        self._prog = ("ожидание ресурсов", 0)
        t0 = time.monotonic()
        beat = asyncio.create_task(self._beat(jid))
        status, error, delay = "done", None, 0
        try:
            weight = self.res.slots if kind in ("all", "members") else 1
            async with self.res.heavy(f"расчёт зон ({kind})", weight):
                self._prog = ("запуск", 1)
                errors = await self._execute(kind, zone_id, zc)
                if errors:
                    error = "; ".join(errors)[:1500]
        except MemoryPressure as exc:
            status, error, delay = "queued", f"Недостаточно памяти, расчёт отложен: {exc}", 600
            log.warning("Расчёт зон отложен из-за нехватки памяти", extra={"job": str(jid), "error": str(exc)})
            if attempts >= MAX_ATTEMPTS:
                status, delay = "failed", 0
        except RuntimeError as exc:
            if str(exc) == "cancelled":
                status, error = "queued", "остановлено при выключении службы"
            else:
                status, error = "failed", f"Внутренняя ошибка: {exc}"[:500]
                log.exception("Сбой расчёта зон")
        except KscError as exc:
            status, error = "failed", exc.message[:500]
        except Exception as exc:  # noqa: BLE001
            status, error = "failed", f"{type(exc).__name__}: {exc}"[:500]
            log.exception("Сбой расчёта зон", extra={"job": str(jid)})
        finally:
            beat.cancel()
            self.current = None
        async with self.sm() as db:
            job = await db.get(ZcJob, jid)
            if job is not None:
                job.status, job.error = status, error
                if status in ("done", "failed"):
                    job.finished_at, job.pct, job.progress = utcnow(), 100 if status == "done" else job.pct, None if status == "done" else job.progress
                else:
                    job.requested_at = utcnow() + timedelta(seconds=delay)
                    job.progress = "ожидает повторного запуска"
            await db.commit()
        await self.journal.emit("system", "zonecache_done" if status == "done" else "zonecache_" + status, level="info" if status == "done" else "warn",
                                message=f"Расчёт зон ({KINDS.get(kind, kind)}): {'готово' if status == 'done' else status}" + (f" — {error}" if error else ""), duration_ms=int((time.monotonic() - t0) * 1000),
                                data={"job": str(jid), "trigger": trigger})

    async def _execute(self, kind: str, zone_id: str | None, zc: ZonecacheSettings) -> list[str]:
        bc = self._bc(zc)
        errors: list[str] = []
        async with self.sm() as db:
            srcs = await self.active_sources(db)
            general = await self.svc.get(db, "general")
        days = int(general.activity_days)
        t0 = time.monotonic()
        if kind == "members":
            for s in srcs:
                await SN.recompute_membership(bc, s)
                await SN.retriage(self.sm, s.id, None)
            await ZR.refresh_dashboards(self.sm, None, default_days=days, data_at=await self._data_at())
            return errors
        touched: set[str] = set()
        for i, s in enumerate(srcs):
            if self._stop.is_set():
                raise RuntimeError("cancelled")
            self._prog = (f"источник «{s.name}»", int(100 * i / max(len(srcs), 1)))
            hosts = None
            if kind == "zone":
                async with self.sm() as db:
                    gen = await SN.db_gen(db, s.id)
                    hosts = set((await db.execute(select(ZcHostZone.host_id).where(ZcHostZone.source_id == s.id, ZcHostZone.gen == gen, ZcHostZone.zone_id == zone_id))).scalars().all()) if gen else set()
                if not hosts and gen:
                    continue
                if not gen:
                    hosts = None                                  # источника ещё нет в подготовленных данных: считаем его целиком
            try:
                res = await SN.build_source(bc, s, hosts=hosts)
                touched |= set(res["zones"])
            except (MemoryPressure, RuntimeError):
                raise
            except KscError as exc:
                errors.append(f"{s.name}: {exc.message}")
                await self._mark_failed(s.id, exc.message)
            except Exception as exc:  # noqa: BLE001
                log.exception("Сбой расчёта источника", extra={"source": s.name})
                errors.append(f"{s.name}: {type(exc).__name__}: {str(exc)[:200]}")
                await self._mark_failed(s.id, f"{type(exc).__name__}: {str(exc)[:300]}")
            else:
                zones = None if kind == "all" else sorted(touched | {zone_id or ""} - {""})
                await ZR.refresh_dashboards(self.sm, zones, default_days=days, data_at=await self._data_at(zone=kind == "zone"), duration_ms=int((time.monotonic() - t0) * 1000))
        if kind == "all" and errors and len(errors) == len(srcs):
            raise KscError("generic", "; ".join(errors)[:400])
        return errors

    async def _data_at(self, zone: bool = False) -> datetime | None:
        async with self.sm() as db:
            if zone:
                return utcnow()
            v = (await db.execute(select(func.min(ZcSource.built_at)).where(ZcSource.gen > 0))).scalar_one_or_none()
            return v

    async def _mark_failed(self, sid: uuid.UUID, msg: str) -> None:
        async with self.sm() as db:
            zs = await SN.get_zc(db, sid)
            zs.error, zs.finished_at, zs.progress = msg[:1500], utcnow(), None
            zs.status = "ready" if zs.gen else "failed"
            await db.commit()

    # ------------------------------------------------------------------ служба
    def stop(self) -> None:
        self._stop.set()

    async def loop(self) -> None:
        await asyncio.sleep(15)
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка цикла расчёта зон")
            await asyncio.sleep(20)


async def status(db: AsyncSession, svc: SettingsService) -> dict:
    """Состояние для администратора: расписание, последний успешный расчёт, длительность, ошибки, очередь."""
    zc = await svc.get(db, "zonecache")
    gtz = (await svc.get(db, "general")).timezone  # type: ignore[attr-defined]
    now = utcnow()
    last_plan, nxt = schedule_times(zc, gtz, now)
    jobs = (await db.execute(select(ZcJob).order_by(ZcJob.requested_at.desc()).limit(15))).scalars().all()
    active = [j for j in jobs if j.status in ("queued", "running")]
    srcs = await ZR.source_states(db)
    ok_at = max((s["built_at"] for s in srcs if s["built_at"]), default=None)
    return {"settings": zc.model_dump(), "timezone": str(tz_of(zc, gtz)), "next_run": nxt if zc.enabled else None, "last_success_at": ok_at, "sources": srcs,
            "jobs": [job_out(j) for j in jobs], "active": [job_out(j) for j in active], "resources": RES.snapshot(),
            "last_duration_ms": next((s["duration_ms"] for s in srcs if s["duration_ms"]), None), "last_plan": last_plan}
