"""Аренды фоновых заданий в PostgreSQL: кто выполняет задание, жив ли он, не перехвачено ли задание другим.

Зачем. Состояние «выполняется» в таблице результатов не отличает работающий расчёт от следа упавшего процесса: прежде такой след блокировал зависимые задачи на часы (например, каталог в состоянии
«строится» после перезапуска worker не давал рассчитывать EOL). Теперь «выполняется» означает «есть действующая аренда».

Как работает.
* `acquire(kind, scope)` — атомарный захват: аренды нет или она истекла (исполнитель не продлевал) → захват удался, прежний выполнявшийся заход записывается в историю как «прервано».
  Две попытки одновременно: выигрывает одна (первичный ключ), вторая получает None. Блокировки процессов и общие множества в Python не нужны — это работает между несколькими worker.
* `heartbeat` — worker раз в `ttl/4` продлевает все свои аренды. Процесс упал или завис — аренда истекает через `ttl` (по умолчанию 120 с, `JOB_LEASE_SECONDS`), задание можно запускать заново.
  Долгий расчёт не прерывается ложно: пока процесс жив, аренда продлевается сколько угодно.
* `recover_own()` — при старте worker снимаются аренды прежнего процесса этого же контейнера (имя хоста совпадает): они заведомо мертвы, ждать `ttl` не нужно.
* `fence(db)` — внутри транзакции записи результата проверяется, что аренда всё ещё принадлежит этому выполнению; иначе `LeaseLost` и запись не выполняется: запоздавший результат старого
  выполнения не перезапишет данные нового.
* История (`job_runs`): результат, этап, причина, версия приложения. Прежние ошибки остаются в истории и не выдаются за текущую причину отказа."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import uuid
from datetime import timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import JobLease, JobRun, utcnow

log = logging.getLogger("app.jobs")
KEEP_RUNS = 20


class LeaseLost(Exception):
    """Аренда задания перехвачена или истекла: результат этого выполнения записывать нельзя."""


def _insert(db: AsyncSession):
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert  # noqa: PLC0415
    else:
        from sqlalchemy.dialects.sqlite import insert  # noqa: PLC0415
    return insert


class Lease:
    def __init__(self, jobs: "Jobs", kind: str, scope: str, run_id: uuid.UUID, started):
        self.jobs, self.kind, self.scope, self.run_id, self.started = jobs, kind, scope, run_id, started
        self.lost = False
        self.stage_text = ""
        self._done = False

    async def stage(self, stage: str, progress: str | None = None) -> None:
        """Этап и ход выполнения (для интерфейса и диагностики); ошибка записи не мешает заданию."""
        self.stage_text = stage
        try:
            async with self.jobs.sm() as db:
                await db.execute(update(JobLease).where(JobLease.kind == self.kind, JobLease.scope == self.scope, JobLease.run_id == self.run_id).values(stage=stage[:160], progress=(progress or None) and progress[:300]))
                await db.commit()
        except Exception:  # noqa: BLE001
            log.debug("Не записан этап задания", exc_info=True)

    async def fence(self, db: AsyncSession) -> None:
        """В транзакции записи результата: аренда принадлежит этому выполнению. Строка блокируется до конца транзакции — перехват не успеет вклиниться между проверкой и фиксацией."""
        got = (await db.execute(select(JobLease.run_id).where(JobLease.kind == self.kind, JobLease.scope == self.scope).with_for_update())).scalar_one_or_none()
        if got != self.run_id:
            self.lost = True
            raise LeaseLost(f"аренда задания {self.kind}/{self.scope} принадлежит другому выполнению")

    async def finish(self, status: str = "success", error: str | None = None) -> None:
        """Снять аренду и записать выполнение в историю. Повторный вызов и вызов после потери аренды безопасны."""
        if self._done:
            return
        self._done = True
        self.jobs.held.pop(self.run_id, None)
        try:
            async with self.jobs.sm() as db:
                gone = (await db.execute(delete(JobLease).where(JobLease.kind == self.kind, JobLease.scope == self.scope, JobLease.run_id == self.run_id))).rowcount
                now = utcnow()
                db.add(JobRun(kind=self.kind, scope=self.scope, run_id=self.run_id, owner=self.jobs.owner, app_version=self.jobs.version, started_at=self.started, finished_at=now,
                              status=status if gone else "lost", stage=self.stage_text[:160], error=(error or None) and error[:2000], duration_ms=int((now - self.started).total_seconds() * 1000)))
                await db.flush()
                await _prune(db, self.kind, self.scope)
                await db.commit()
        except Exception:  # noqa: BLE001
            log.warning("Не записан итог задания %s/%s", self.kind, self.scope, exc_info=True)


async def _prune(db: AsyncSession, kind: str, scope: str) -> None:
    cutoff = (await db.execute(select(JobRun.id).where(JobRun.kind == kind, JobRun.scope == scope).order_by(JobRun.id.desc()).offset(KEEP_RUNS).limit(1))).scalar_one_or_none()
    if cutoff is not None:
        await db.execute(delete(JobRun).where(JobRun.kind == kind, JobRun.scope == scope, JobRun.id <= cutoff))


class Jobs:
    def __init__(self) -> None:
        self.sm: async_sessionmaker[AsyncSession] | None = None
        self.ttl = 120
        self.version = ""
        self.owner = f"{socket.gethostname()}/{os.getpid()}/{uuid.uuid4().hex[:6]}"
        self.held: dict[uuid.UUID, Lease] = {}
        self._stop = asyncio.Event()

    def configure(self, sm: async_sessionmaker[AsyncSession], *, ttl: int = 120, version: str = "") -> "Jobs":
        self.sm, self.ttl, self.version = sm, int(ttl), version
        self.owner = f"{socket.gethostname()}/{os.getpid()}/{uuid.uuid4().hex[:6]}"
        self.held.clear()
        return self

    @property
    def host(self) -> str:
        return self.owner.split("/", 1)[0] + "/"

    # ------------------------------------------------------------------------------------------ захват
    async def acquire(self, kind: str, scope: str = "", stage: str = "запуск") -> Lease | None:
        """Захватить задание или None, если его уже выполняет живой исполнитель. Истёкшая аренда перехватывается, прежний заход помечается «прервано»."""
        now = utcnow()
        run_id = uuid.uuid4()
        async with self.sm() as db:
            dead = (await db.execute(delete(JobLease).where(JobLease.kind == kind, JobLease.scope == scope, JobLease.lease_until < now)
                                     .returning(JobLease.run_id, JobLease.owner, JobLease.started_at, JobLease.stage, JobLease.app_version))).all()
            for old in dead:                                                    # исполнитель перестал продлевать аренду: прерванный заход — в историю
                db.add(JobRun(kind=kind, scope=scope, run_id=old[0], owner=old[1], app_version=old[4], started_at=old[2], finished_at=now, status="interrupted", stage=old[3],
                              error="Исполнитель завершился или завис: аренда не продлевалась", duration_ms=int((now - old[2]).total_seconds() * 1000)))
            ins = _insert(db)(JobLease.__table__).values(kind=kind, scope=scope, run_id=run_id, owner=self.owner, started_at=now, heartbeat_at=now, lease_until=now + timedelta(seconds=self.ttl),
                                                         stage=stage, progress=None, app_version=self.version).on_conflict_do_nothing(index_elements=["kind", "scope"])
            got = (await db.execute(ins)).rowcount
            if dead:
                await db.flush()
                await _prune(db, kind, scope)
            await db.commit()
        if not got:
            return None
        lease = Lease(self, kind, scope, run_id, now)
        lease.stage_text = stage
        self.held[run_id] = lease
        return lease

    @contextlib.asynccontextmanager
    async def run(self, kind: str, scope: str = "", stage: str = "запуск"):
        """Выполнение под арендой: `async with jobs.run(...) as lease:` (lease = None — задание уже выполняется). Исключение записывается в историю и пробрасывается; LeaseLost — статус «lost»."""
        lease = await self.acquire(kind, scope, stage)
        if lease is None:
            yield None
            return
        try:
            yield lease
        except LeaseLost as exc:
            await lease.finish("lost", str(exc))
            raise
        except asyncio.CancelledError:
            await lease.finish("interrupted", "выполнение отменено")
            raise
        except BaseException as exc:
            await lease.finish("error", f"{type(exc).__name__}: {exc}")
            raise
        else:
            await lease.finish("success")

    # ------------------------------------------------------------------------------------------ продление
    async def beat_once(self) -> int:
        """Продлить все аренды этого исполнителя; потерянные (перехвачены, сняты) помечаются `lost`. Возвращает число продлённых."""
        if not self.held:
            return 0
        now = utcnow()
        ids = list(self.held)
        async with self.sm() as db:
            res = (await db.execute(update(JobLease).where(JobLease.owner == self.owner, JobLease.run_id.in_(ids)).values(heartbeat_at=now, lease_until=now + timedelta(seconds=self.ttl)).returning(JobLease.run_id))).all()
            await db.commit()
        alive = {r[0] for r in res}
        for rid in ids:
            if rid not in alive and rid in self.held:
                self.held[rid].lost = True
                log.warning("Аренда задания потеряна", extra={"kind": self.held[rid].kind, "scope": self.held[rid].scope})
        return len(alive)

    async def beat_loop(self) -> None:
        every = max(3.0, self.ttl / 4)
        while not self._stop.is_set():
            try:
                await self.beat_once()
            except Exception:  # noqa: BLE001 — база недоступна: аренда может истечь, запись результата тогда не пройдёт проверку fence
                log.warning("Не удалось продлить аренды заданий", exc_info=True)
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=every)

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------------------------------ чтение и восстановление
    async def recover_own(self) -> int:
        """При старте: аренды прежнего процесса этого контейнера (то же имя хоста, другой экземпляр) заведомо мертвы — снимаются сразу, без ожидания `ttl`."""
        now = utcnow()
        async with self.sm() as db:
            dead = (await db.execute(delete(JobLease).where(JobLease.owner.like(self.host + "%"), JobLease.owner != self.owner)
                                     .returning(JobLease.kind, JobLease.scope, JobLease.run_id, JobLease.owner, JobLease.started_at, JobLease.stage, JobLease.app_version))).all()
            for k, sc, rid, ow, st, stg, ver in dead:
                db.add(JobRun(kind=k, scope=sc, run_id=rid, owner=ow, app_version=ver, started_at=st, finished_at=now, status="interrupted", stage=stg,
                              error="Процесс исполнителя перезапущен", duration_ms=int((now - st).total_seconds() * 1000)))
            await db.flush()
            for k, sc in {(d[0], d[1]) for d in dead}:
                await _prune(db, k, sc)
            await db.commit()
        return len(dead)

    async def is_live(self, kind: str, scope: str = "") -> bool:
        async with self.sm() as db:
            return (await db.execute(select(JobLease.run_id).where(JobLease.kind == kind, JobLease.scope == scope, JobLease.lease_until >= utcnow()))).first() is not None

    async def live(self, kind: str) -> dict[str, JobLease]:
        async with self.sm() as db:
            return {r.scope: r for r in (await db.execute(select(JobLease).where(JobLease.kind == kind, JobLease.lease_until >= utcnow()))).scalars().all()}

    async def runs(self, kind: str, scope: str = "", n: int = 5) -> list[JobRun]:
        async with self.sm() as db:
            return list((await db.execute(select(JobRun).where(JobRun.kind == kind, JobRun.scope == scope).order_by(JobRun.id.desc()).limit(n))).scalars().all())

    async def failures_since(self, kind: str, scope: str, since) -> int:
        """Число неудачных или прерванных заходов за период (для задержки повтора при циклических сбоях, например нехватке памяти)."""
        async with self.sm() as db:
            return int((await db.execute(select(func.count()).select_from(JobRun).where(JobRun.kind == kind, JobRun.scope == scope, JobRun.finished_at >= since,
                                                                                          JobRun.status.in_(("error", "interrupted", "lost"))))).scalar_one())

    async def all_leases(self) -> list[JobLease]:
        async with self.sm() as db:
            return list((await db.execute(select(JobLease).order_by(JobLease.kind, JobLease.scope))).scalars().all())


JOBS = Jobs()
