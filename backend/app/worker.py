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
from .services.settings import SettingsService

log = logging.getLogger("app.worker")


async def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    engine = create_engine(settings)
    sm = create_session_maker(engine)
    try:
        box = SecretBox(settings.app_master_key) if settings.app_master_key else None
    except SecretBoxError:
        log.error("APP_MASTER_KEY некорректен — пароли источников недоступны")
        box = None
    runner = Runner(sm, settings, SettingsService(box), Journal(sm))
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    task = asyncio.create_task(runner.loop())
    log.info("Воркер отчётов запущен", extra={"version": settings.app_version})
    await stop.wait()
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):  # noqa: BLE001
        pass
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
