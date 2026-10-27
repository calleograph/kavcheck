"""Процесс фоновой обработки отчётов (контейнер worker): тот же код и база, но без HTTP."""
from __future__ import annotations

import asyncio
import logging
import signal

from .config import get_settings
from .db import create_engine, create_session_maker
from .logging_setup import configure_logging
from .reports.runner import Runner
from .security.secretbox import SecretBox, SecretBoxError
from .services.audit import Journal
from .vdb.sync import VdbSync
from .services.catalog import CatalogScheduler
from .services.system import heartbeat_loop, install_journal_handler
from .services.settings import SettingsService
from .services.sources import SourceRegistry
from .zones.mailer import Mailer
from .zones.reporter import ZoneData
from .zones.zjobs import ZoneCache
from .eol.service import EolService
from .services.jobs import JOBS
from .devices.service import DevicesService
from .licensing.service import LicenseService
from .overview.snapshots import SnapshotService
from .services.resources import RES

log = logging.getLogger("app.worker")


async def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    engine = create_engine(settings, background=True)
    sm = create_session_maker(engine)
    try:
        box = SecretBox(settings.app_master_key) if settings.app_master_key else None
    except SecretBoxError:
        log.error("APP_MASTER_KEY некорректен — пароли источников недоступны")
        box = None
    svc, journal = SettingsService(box), Journal(sm)
    JOBS.configure(sm, ttl=settings.job_lease_seconds, version=settings.app_version)
    try:
        if n := await JOBS.recover_own():
            log.warning("Аренды заданий прежнего процесса сняты, задания будут запущены заново: %s", n)
    except Exception:  # noqa: BLE001 — например, миграция ещё не применена
        log.warning("Не удалось снять аренды прежнего процесса", exc_info=True)
    runner = Runner(sm, settings, svc, journal)
    catalog = CatalogScheduler(sm, settings, svc, journal)
    runner.catalog = catalog
    vdb = VdbSync(sm, settings, svc, journal)
    sources = SourceRegistry(settings, svc)
    mailer = Mailer(sm, settings, svc, ZoneData(sm, settings, svc, sources), journal)
    zcache = ZoneCache(sm, settings, svc, sources, journal)
    eol = EolService(sm, svc, sources, journal)
    eol.version = settings.app_version
    devices = DevicesService(sm, svc, sources, journal)
    licenses = LicenseService(sm, sources, settings.app_master_key or "", journal)
    snapshots = SnapshotService(sm, sources, svc, journal)
    try:
        if await eol.recover():
            log.warning("EOL: прерванные расчёты сброшены, будут запущены заново")
    except Exception:  # noqa: BLE001 — например, миграция ещё не применена
        log.warning("EOL: не удалось сбросить состояние расчётов", exc_info=True)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    jh = install_journal_handler("worker")

    def pulse() -> dict:
        return {"version": settings.app_version, "commit": settings.app_git_commit, "reports_running": len(runner._tasks),  # noqa: SLF001
                "catalog_building": len(catalog._tasks), "vdb_running": len(vdb._running), "zonecache_job": zcache.current, "eol_job": eol.current, "devices_job": devices.current, "resources": RES.snapshot()}  # noqa: SLF001

    tasks = [asyncio.create_task(runner.loop(), name="reports"), asyncio.create_task(catalog.loop(), name="catalog"), asyncio.create_task(vdb.loop(), name="vdb"), asyncio.create_task(mailer.loop(), name="mail"), asyncio.create_task(zcache.loop(), name="zonecache"), asyncio.create_task(eol.loop(), name="eol"), asyncio.create_task(devices.loop(), name="devices"), asyncio.create_task(licenses.loop(), name="licenses"), asyncio.create_task(snapshots.loop(), name="ov-snapshots"),
             asyncio.create_task(jh.flush_loop(sm), name="journal-flush"), asyncio.create_task(JOBS.beat_loop(), name="job-leases"), asyncio.create_task(heartbeat_loop(sm, "worker", pulse), name="heartbeat")]
    log.info("Воркер отчётов и каталога запущен", extra={"version": settings.app_version})
    await stop.wait()
    JOBS.stop()
    zcache.stop()
    eol.stop()
    devices.stop()
    licenses.stop()
    snapshots.stop()
    for task in tasks:
        task.cancel()
    for task in tasks:
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
