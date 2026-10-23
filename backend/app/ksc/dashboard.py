"""Сводка главной страницы по источнику: кэш во внутренней базе со сроком актуальности; без данных — состояние «не получено», без выдуманных чисел."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import KscCache, utcnow
from . import queries as q
from .driver import KscError, SourceClient


async def cached(db: AsyncSession, source_id, key: str, ttl_s: int) -> dict | None:
    row = await db.get(KscCache, (source_id, key))
    if row and utcnow() - row.fetched_at <= timedelta(seconds=ttl_s):
        return {**row.payload, "fetched_at": row.fetched_at}
    return None


async def store(db: AsyncSession, source_id, key: str, payload: dict) -> dict:
    row = await db.get(KscCache, (source_id, key))
    now = utcnow()
    if row is None:
        db.add(KscCache(source_id=source_id, key=key, fetched_at=now, payload=payload))
    else:
        row.fetched_at, row.payload = now, payload
    await db.commit()
    return {**payload, "fetched_at": now}


async def summary(client: SourceClient, *, activity_days: int, features: dict) -> dict:
    out: dict = {"activity_days": activity_days}
    try:
        out["hosts_total"] = int((await client.run(q.COUNT_HOSTS, max_rows=1))[0]["n"])
        out["hosts_active"] = int((await client.run(q.COUNT_HOSTS_ACTIVE, {"days": activity_days}, max_rows=1))[0]["n"])
        out["hosts_inactive"] = out["hosts_total"] - out["hosts_active"]
    except KscError as exc:
        out["hosts_error"] = exc.message
    if (features.get("software") or {}).get("ok", True):
        try:
            out["products"] = int((await client.run(q.COUNT_PRODUCTS, max_rows=1))[0]["n"])
            out["installs"] = int((await client.run(q.COUNT_INSTALLS, max_rows=1))[0]["n"])
        except KscError as exc:
            out["software_error"] = exc.message
    if (features.get("protection") or {}).get("ok", True):
        try:
            rows = await client.run(q.KSC_VERSION, max_rows=1)
            out["ksc_version"] = str(rows[0]["build"]) if rows else None
        except KscError:
            out["ksc_version"] = None
    return out
