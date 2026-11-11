"""Журнал базы уязвимостей: загрузки, расчёты и их ход, решения администратора, аудит, ошибки — чтобы понимать, что случилось.

Кольцевой: общий размер записей не превышает `LIMIT_BYTES` (10 МБ); при превышении удаляются самые старые, пока не останется `KEEP` от предела. Диск не растёт и не требует чистки.
Запись — отдельной короткой транзакцией, сбой журнала не ломает работу (как `services/audit.Journal`)."""
from __future__ import annotations

import json
import logging
import uuid

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..logging_setup import scrub
from ..models import VdbJournal, utcnow

log = logging.getLogger("app.vdb.journal")
LIMIT_BYTES = 10 * 1024 * 1024
KEEP = 0.9                      # после чистки остаётся 90% предела, чтобы чистка не шла на каждой записи
OVERHEAD = 160                  # учёт служебных полей и индексов в размере записи
CHECK_EVERY = 25                # размер проверяется не на каждой записи
LEVELS = ("info", "warn", "error")
KINDS = {"analysis": "Расчёт", "sync": "Загрузка баз", "decision": "Решения", "audit": "Аудит", "system": "Служба"}
_since_check = 0


def _size(message: str, details: dict | None) -> int:
    return len(message.encode("utf-8")) + (len(json.dumps(details, ensure_ascii=False, default=str).encode("utf-8")) if details else 0) + OVERHEAD


async def total_bytes(db: AsyncSession) -> int:
    return int((await db.execute(select(func.coalesce(func.sum(VdbJournal.size), 0)))).scalar_one())


async def prune(db: AsyncSession, limit: int = LIMIT_BYTES) -> int:
    """Удалить самые старые записи, пока общий размер не станет ≤ KEEP·limit. Возвращает число удалённых."""
    total = await total_bytes(db)
    if total <= limit:
        return 0
    excess, removed, last = total - int(limit * KEEP), 0, 0
    while removed < excess:
        rows = (await db.execute(select(VdbJournal.id, VdbJournal.size).where(VdbJournal.id > last).order_by(VdbJournal.id).limit(2000))).all()
        if not rows:
            break
        cut = 0
        for rid, size in rows:
            cut, removed = rid, removed + size
            if removed >= excess:
                break
        await db.execute(delete(VdbJournal).where(VdbJournal.id <= cut))
        last = cut
    return 1


async def emit(sm: async_sessionmaker[AsyncSession], kind: str, message: str, *, level: str = "info", source_id: uuid.UUID | str | None = None, vdb_key: str = "",
               details: dict | None = None, limit: int = LIMIT_BYTES) -> None:
    """Записать событие. `kind` — analysis | sync | decision | audit | system; `details` обезличивается (пароли, ключи)."""
    global _since_check
    try:
        msg = (message or "")[:600]
        det = scrub(details) if details else None
        async with sm() as db:
            db.add(VdbJournal(at=utcnow(), level=level if level in LEVELS else "info", kind=kind[:16], source_id=uuid.UUID(str(source_id)) if source_id else None, vdb_key=vdb_key[:16],
                              message=msg, details=det, size=_size(msg, det)))
            _since_check += 1
            if _since_check >= CHECK_EVERY or level == "error":
                _since_check = 0
                await prune(db, limit)
            await db.commit()
    except Exception:  # noqa: BLE001 — журнал не должен ломать работу
        log.warning("Не удалось записать событие журнала базы уязвимостей", exc_info=True)
