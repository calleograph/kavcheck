"""Фоновое чтение лицензий из KSC (worker): раз в `INTERVAL`, по запросу администратора и при первом подключении источника.
Каждый источник читается независимо и под арендой; ошибка источника не мешает остальным, прежние записи остаются. Записи из KSC заменяются целиком одной транзакцией, ручные не трогаются."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..ksc import licenses as L
from ..models import KscSource, LicenseRecord, LicenseState, utcnow
from ..services.sources import SourceRegistry

log = logging.getLogger("app.licensing")
INTERVAL = timedelta(hours=6)
RETRY_AFTER = timedelta(minutes=30)


def lic_key(r: dict) -> str:
    return r["fp"][:40] if r.get("fp") else hashlib.sha1(f"{r['product']}|{r['expires_at']}|{r['limit_n']}|{r['kind']}".encode()).hexdigest()[:20]


class LicenseService:
    def __init__(self, sm: async_sessionmaker[AsyncSession], sources: SourceRegistry, secret: str, journal=None):
        self._sm, self._sources, self._secret, self._journal = sm, sources, secret, journal
        self._stop = asyncio.Event()
        self._tasks: set[asyncio.Task] = set()
        self.current: str | None = None

    def stop(self) -> None:
        self._stop.set()

    async def due(self) -> list[uuid.UUID]:
        out, now = [], utcnow()
        async with self._sm() as db:
            for src in (await db.execute(select(KscSource).where(KscSource.is_active.is_(True)))).scalars().all():
                st = await db.get(LicenseState, src.id)
                if st is None or st.requested_at is not None:
                    out.append(src.id)
                elif st.error_at and now - st.error_at < RETRY_AFTER and (st.polled_at is None or st.error_at > st.polled_at):
                    continue
                elif st.polled_at is None or now - st.polled_at >= INTERVAL:
                    out.append(src.id)
        return out

    async def run_source(self, sid: uuid.UUID) -> bool:
        from ..services.jobs import JOBS  # noqa: PLC0415

        async with self._sm() as db:
            src = await db.get(KscSource, sid)
        if src is None:
            return False
        async with JOBS.run("licenses", str(sid), "чтение лицензий") as lease:
            if lease is None:
                return False
            self.current = src.name
            try:
                got = await L.read(self._sources.client(src), self._secret)
                await self._store(sid, got, lease)
                return True
            except Exception as exc:  # noqa: BLE001 — недоступный KSC или нет прав: прежние записи остаются, причина видна администратору
                if type(exc).__name__ == "LeaseLost":
                    raise
                msg = exc.message if hasattr(exc, "message") and isinstance(exc.message, str) else f"внутренняя ошибка ({type(exc).__name__}): {str(exc)[:300]}"   # KscError — уже понятный текст
                log.warning("Чтение лицензий не удалось", extra={"source": src.name, "error": msg})
                async with self._sm() as db:
                    st = await db.get(LicenseState, sid)
                    if st is None:
                        db.add(LicenseState(source_id=sid, error=msg, error_at=utcnow()))
                    else:
                        st.error, st.error_at, st.requested_at = msg, utcnow(), None
                    await db.commit()
                return False
            finally:
                self.current = None

    async def _store(self, sid: uuid.UUID, got: dict, lease) -> None:
        now = utcnow()
        recs = []
        seen: set[str] = set()
        for r in got["records"]:
            k = lic_key(r)
            if k in seen:
                continue
            seen.add(k)
            recs.append(LicenseRecord(source_id=sid, lic_key=k, origin="ksc", product=r["product"], kind=r["kind"], expires_at=r["expires_at"], limit_n=r["limit_n"], used_n=r["used_n"],
                                      state=r["state"], fp=r["fp"], updated_at=now))
        async with self._sm() as db:
            await lease.fence(db)
            await db.execute(delete(LicenseRecord).where(LicenseRecord.source_id == sid, LicenseRecord.origin == "ksc"))
            db.add_all(recs)
            st = await db.get(LicenseState, sid)
            diag = got["diag"]
            if st is None:
                db.add(LicenseState(source_id=sid, polled_at=now, records_n=len(recs), diag=diag))
            else:
                st.polled_at, st.records_n, st.diag, st.error, st.error_at, st.requested_at = now, len(recs), diag, None, None, None
            await db.commit()

    async def tick(self) -> None:
        for sid in await self.due():
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
                log.exception("Ошибка цикла чтения лицензий")
            await asyncio.sleep(60)
