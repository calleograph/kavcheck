"""Проверка и загрузка GeoLite2 для инвентаризации. Данные устройств остаются в контуре."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

from ..db import xact_lock
from ..models import AppSetting, JobLease, utcnow
from ..services.jobs import JOBS
from .geo_service import request_refresh

log = logging.getLogger(__name__)
KIND = "geoip_update"
STATE = "geoip_state"
REQUEST = "geoip_request"
EVERY = timedelta(hours=24)
RETRY = timedelta(hours=6)


async def snapshot(db, svc):
    cfg = await svc.get(db, "geoip")
    row = await db.get(AppSetting, "geoip")
    state, queued = await db.get(AppSetting, STATE), await db.get(AppSetting, REQUEST)
    return cfg, row.updated_at.isoformat() if row else "", dict(state.value) if state else {}, queued.value["at"] if queued else ""


def due(cfg, revision: str, state: dict, request: str, *, missing: bool = False) -> bool:
    if not cfg.account_id or not cfg.license_key:
        return False
    if request > state.get("request", ""):
        return True
    if not cfg.enabled:
        return False
    next_check = state.get("next_check_at")
    return (revision != state.get("revision") or not next_check or datetime.fromisoformat(next_check) <= utcnow()
            or (missing and not state.get("error")))


async def info(db, svc) -> dict:
    cfg, revision, state, request = await snapshot(db, svc)
    lease = await db.get(JobLease, (KIND, ""))
    running = bool(lease and lease.lease_until > utcnow())
    return {
        "enabled": cfg.enabled, "account_id": cfg.account_id, "license_key_set": bool(cfg.license_key),
        "running": running, "pending": due(cfg, revision, state, request) and not running,
        "stage": lease.stage if running and lease else "", "checked_at": state.get("checked_at"),
        "success_at": state.get("success_at"), "next_check_at": state.get("next_check_at") if cfg.enabled else None,
        "databases": state.get("databases") or {}, "error": state.get("error", ""),
    }


async def queue(db, svc) -> bool | None:
    await xact_lock(db, REQUEST)
    cfg, _, state, request = await snapshot(db, svc)
    if not (cfg.account_id and cfg.license_key):
        return None
    lease = await db.get(JobLease, (KIND, ""))
    if request > state.get("request", "") or (lease and lease.lease_until > utcnow()):
        return False
    value = {"at": utcnow().isoformat()}
    row = await db.get(AppSetting, REQUEST)
    if row is None:
        db.add(AppSetting(group=REQUEST, value=value))
    else:
        row.value = value
    return True


async def finish(sm, lease, revision: str, request: str, result: dict | None, error: str):
    now = utcnow()
    async with sm() as db:
        await lease.fence(db)
        row = await db.get(AppSetting, STATE, with_for_update=True)
        state = dict(row.value) if row else {}
        state.update(revision=revision, request=request, error=error, checked_at=now.isoformat(),
                     next_check_at=(now + (RETRY if error else EVERY)).isoformat())
        if result is not None:
            databases = result["databases"]
            if result["changed"] or databases != state.get("databases"):
                await request_refresh(db)
            state.update(success_at=now.isoformat(), databases=databases)
        if row is None:
            db.add(AppSetting(group=STATE, value=state))
        else:
            row.value = state
        await db.commit()


async def tick(sm, svc, directory: Path, journal):
    from .geo_download import EDITIONS, DownloadError, database_directory, update

    def missing():
        active = database_directory(directory, managed=True)
        return active == directory or any(not (active / f"{edition}.mmdb").is_file() for edition in EDITIONS)

    async with sm() as db:
        if not due(*(await snapshot(db, svc)), missing=missing()):
            return
    try:
        async with JOBS.run_heavy(KIND, task="базы GeoLite2") as lease:
            if lease is None:
                return
            async with sm() as db:
                cfg, revision, state, request = await snapshot(db, svc)
            if not due(cfg, revision, state, request, missing=missing()):
                return
            await lease.stage("проверка и загрузка GeoLite2")

            @asynccontextmanager
            async def publish_guard():
                async with sm() as db:
                    await xact_lock(db, "geoip")
                    row = await db.get(AppSetting, "geoip")
                    if row is None or row.updated_at.isoformat() != revision:
                        raise DownloadError("Настройки GeoLite2 изменились во время загрузки")
                    await lease.fence(db)
                    yield
                    await db.commit()

            try:
                async with asyncio.timeout(8 * 60):
                    result = await update(directory, cfg.account_id, cfg.license_key, guard=publish_guard)
            except Exception as exc:
                if isinstance(exc, DownloadError):
                    error = str(exc)
                elif isinstance(exc, TimeoutError):
                    error = "Проверка GeoLite2 заняла слишком много времени"
                else:
                    error = f"Обновление GeoLite2 недоступно ({type(exc).__name__})"
                await finish(sm, lease, revision, request, None, error)
                raise DownloadError(error) from None
            await finish(sm, lease, revision, request, result, "")
    except DownloadError as exc:
        await journal.emit("inventory", "geoip_failed", level="warn", message=str(exc))
    else:
        await journal.emit("inventory", "geoip_checked", message="Базы GeoLite2 обновлены" if result["changed"] else "Базы GeoLite2 актуальны")


async def loop(sm, svc, settings, journal):
    directory = Path(settings.data_dir) / "geoip-managed"
    while True:
        try:
            await tick(sm, svc, directory, journal)
        except Exception as exc:
            log.error("Не удалось выполнить обновление GeoLite2 (%s)", type(exc).__name__)
        await asyncio.sleep(60)
