"""Обновление локальных географических баз для инвентаризации."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

from ..db import xact_lock
from ..models import AppSetting, JobLease, utcnow
from ..services.jobs import JOBS
from .geo_service import managed_pair, managed_root, request_refresh
from .geography import GEOIP_LABELS

log = logging.getLogger(__name__)
KIND = "geoip_update"
STATE = "geoip_state"
REQUEST = "geoip_request"
RETRY = timedelta(hours=6)


async def snapshot(db, svc):
    cfg = await svc.get(db, "geoip")
    row = await db.get(AppSetting, "geoip")
    state, queued = await db.get(AppSetting, STATE), await db.get(AppSetting, REQUEST)
    return cfg, row.updated_at.isoformat() if row else "", dict(state.value) if state else {}, queued.value["at"] if queued else ""


def due(cfg, revision: str, state: dict, request: str, *, missing: bool = False) -> bool:
    if cfg.provider == "maxmind" and not (cfg.account_id and cfg.license_key):
        return False
    if request > state.get("request", ""):
        return True
    if not cfg.enabled:
        return False
    next_check = state.get("next_check_at")
    return (cfg.provider != state.get("provider", "maxmind") or revision != state.get("revision")
            or not next_check or datetime.fromisoformat(next_check) <= utcnow()
            or (missing and not state.get("error")))


def publications(state: dict) -> dict:
    if "publications" in state:
        return dict(state["publications"])
    if state.get("databases"):
        return {"maxmind": {"databases": state["databases"], "success_at": state.get("success_at")}}
    return {}


def next_check(now: datetime, provider: str, result: dict | None) -> datetime:
    if result is None or (provider == "dbip" and result.get("month") != now.strftime("%Y-%m")):
        return now + RETRY
    if provider == "maxmind":
        return now + timedelta(days=1)
    return (now.replace(day=28) + timedelta(days=4)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)


async def info(db, svc) -> dict:
    cfg, revision, state, request = await snapshot(db, svc)
    lease = await db.get(JobLease, (KIND, ""))
    running = bool(lease and lease.lease_until > utcnow())
    published = publications(state)
    active = cfg.provider if cfg.provider in published else next(iter(published), None)
    selected = published.get(active, {})
    current = state.get("provider", "maxmind") == cfg.provider
    return {
        "provider": cfg.provider, "active_provider": active, "enabled": cfg.enabled, "account_id": cfg.account_id, "license_key_set": bool(cfg.license_key),
        "running": running, "pending": due(cfg, revision, state, request) and not running,
        "stage": lease.stage if running and lease else "", "checked_at": state.get("checked_at") if current else None,
        "success_at": selected.get("success_at"), "next_check_at": state.get("next_check_at") if cfg.enabled and current else None,
        "databases": selected.get("databases", {}), "error": state.get("error", "") if current else "",
    }


async def queue(db, svc) -> bool | None:
    await xact_lock(db, REQUEST)
    cfg, _, state, request = await snapshot(db, svc)
    if cfg.provider == "maxmind" and not (cfg.account_id and cfg.license_key):
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


async def finish(sm, lease, revision: str, request: str, provider: str, result: dict | None, error: str):
    now = utcnow()
    async with sm() as db:
        await lease.fence(db)
        row = await db.get(AppSetting, STATE, with_for_update=True)
        state = dict(row.value) if row else {}
        published = publications(state)
        state = dict(provider=provider, revision=revision, request=request, error=error, checked_at=now.isoformat(),
                     next_check_at=next_check(now, provider, result).isoformat(), publications=published)
        if result is not None:
            databases = result["databases"]
            if result["changed"] or databases != published.get(provider, {}).get("databases"):
                await request_refresh(db)
            published[provider] = {"databases": databases, "success_at": now.isoformat()}
        if row is None:
            db.add(AppSetting(group=STATE, value=state))
        else:
            row.value = state
        await db.commit()


async def tick(sm, svc, directory: Path, journal):
    from .geo_download import DownloadError, update, update_dbip

    async with sm() as db:
        cfg, revision, state, request = await snapshot(db, svc)
        if not due(cfg, revision, state, request, missing=managed_pair(directory, cfg.provider) is None):
            return
    try:
        async with JOBS.run_heavy(KIND, task="географические базы") as lease:
            if lease is None:
                return
            async with sm() as db:
                cfg, revision, state, request = await snapshot(db, svc)
            provider = cfg.provider
            directory_missing = managed_pair(directory, provider) is None
            if not due(cfg, revision, state, request, missing=directory_missing):
                return
            label = GEOIP_LABELS[provider]
            await lease.stage(f"проверка и загрузка {label}")

            @asynccontextmanager
            async def publish_guard():
                async with sm() as db:
                    await xact_lock(db, "geoip")
                    row = await db.get(AppSetting, "geoip")
                    actual = row.updated_at.isoformat() if row else ""
                    if actual != revision:
                        raise DownloadError(f"Настройки {label} изменились во время загрузки")
                    await lease.fence(db)
                    yield
                    await db.commit()

            try:
                async with asyncio.timeout(8 * 60):
                    target = managed_root(directory, provider)
                    if provider == "dbip":
                        result = await update_dbip(target, guard=publish_guard, now=utcnow())
                    else:
                        result = await update(target, cfg.account_id, cfg.license_key, guard=publish_guard)
            except Exception as exc:
                if isinstance(exc, DownloadError):
                    error = str(exc)
                elif isinstance(exc, TimeoutError):
                    error = f"Проверка {label} заняла слишком много времени"
                else:
                    error = f"Обновление {label} недоступно ({type(exc).__name__})"
                await finish(sm, lease, revision, request, provider, None, error)
                raise DownloadError(error) from None
            await finish(sm, lease, revision, request, provider, result, "")
    except DownloadError as exc:
        await journal.emit("inventory", "geoip_failed", level="warn", message=str(exc))
    else:
        await journal.emit("inventory", "geoip_checked", message=f"Базы {label} {'обновлены' if result['changed'] else 'проверены'}")


async def loop(sm, svc, settings, journal):
    directory = Path(settings.data_dir) / "geoip-managed"
    while True:
        try:
            await tick(sm, svc, directory, journal)
        except Exception as exc:
            log.error("Не удалось обновить географические базы (%s)", type(exc).__name__)
        await asyncio.sleep(60)
