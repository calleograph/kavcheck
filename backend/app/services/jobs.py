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
* История (`job_runs`): результат, этап, причина, версия приложения. Прежние ошибки остаются в истории и не выдаются за текущую причину отказа.
* `run_heavy(kind, scope, …)` — тяжёлое задание: сначала место у ограничителя ресурсов (services/resources, своя полоса), затем аренда. Ожидание места — не выполнение:
  ожидающее задание видно как «ожидает исполнителя» (`waiting`), аренды у него нет и продлевать нечего. Повторная постановка того же задания в этом процессе отсекается.
* Ход выполнения: `stage()` и граница порции (`RES.breathe`) отмечают прогресс. Нет прогресса `stall_s` (по умолчанию 15 мин, `JOB_STALL_SECONDS`) — диагностическое событие
  с этапом и длительностью; нет прогресса `stall_hard_s` (6 ч) — аренда больше не продлевается: задание считается зависшим, после истечения аренды его можно запустить заново,
  а запоздавший результат не пройдёт `fence`."""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import logging
import os
import socket
import time
import uuid
from datetime import timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import JobLease, JobRun, utcnow

log = logging.getLogger("app.jobs")
KEEP_RUNS = 20
CURRENT: contextvars.ContextVar["Lease | None"] = contextvars.ContextVar("kc_lease", default=None)        # аренда выполняемого задания (для отметки прогресса из RES.breathe)


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
        self.progress_at = time.monotonic()
        self.progress_saved = self.progress_at   # последнее записанное в базу значение (job_leases.progress_at)
        self.queued_at = None                    # постановка в очередь ограничителя
        self.stalled = False                     # о зависании уже сообщено
        self.frozen = False                      # аренда больше не продлевается

    def touch(self) -> None:
        self.progress_at = time.monotonic()
        self.stalled = False

    async def stage(self, stage: str, progress: str | None = None) -> None:
        """Этап и ход выполнения (для интерфейса и диагностики); ошибка записи не мешает заданию."""
        self.touch()
        self.stage_text = stage
        try:
            async with self.jobs.sm() as db:
                await db.execute(update(JobLease).where(JobLease.kind == self.kind, JobLease.scope == self.scope, JobLease.run_id == self.run_id)
                                 .values(stage=stage[:160], progress=(progress or None) and progress[:300], progress_at=utcnow()))
                self.progress_saved = self.progress_at
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
        dur = int((utcnow() - self.started).total_seconds())
        (log.info if status == "success" else log.warning)("Задание завершено", extra={"kind": self.kind, "scope": self.scope, "status": status, "duration_s": dur, "stage": self.stage_text,
                                                                                         **({"error": error[:300]} if error else {})})
        try:
            async with self.jobs.sm() as db:
                gone = (await db.execute(delete(JobLease).where(JobLease.kind == self.kind, JobLease.scope == self.scope, JobLease.run_id == self.run_id))).rowcount
                now = utcnow()
                db.add(JobRun(kind=self.kind, scope=self.scope, run_id=self.run_id, owner=self.jobs.owner, app_version=self.jobs.version, started_at=self.started, finished_at=now,
                              status=status if gone else "lost", stage=self.stage_text[:160], error=(error or None) and error[:2000], duration_ms=int((now - self.started).total_seconds() * 1000),
                              waited_ms=int((self.started - self.queued_at).total_seconds() * 1000) if self.queued_at else None))
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
        self.waiting: dict[tuple[str, str], dict] = {}          # (вид, область) → {с какого момента, этап}: ждут места у ограничителя, аренды ещё нет
        self.queued: dict[tuple[str, str], object] = {}         # место получено, аренда ещё не захвачена: с какого момента задание ждало (для queued_at и waited_ms)
        self.stall_s, self.stall_hard_s = 900, 21600
        self.journal = None
        self._stop = asyncio.Event()

    def configure(self, sm: async_sessionmaker[AsyncSession], *, ttl: int = 120, version: str = "", stall_s: int = 900, stall_hard_s: int = 21600, journal=None) -> "Jobs":
        self.sm, self.ttl, self.version = sm, int(ttl), version
        self.stall_s, self.stall_hard_s, self.journal = int(stall_s), max(int(stall_hard_s), int(stall_s) * 2), journal
        self.owner = f"{socket.gethostname()}/{os.getpid()}/{uuid.uuid4().hex[:6]}"
        self.held.clear()
        self.waiting.clear()
        self.queued.clear()
        return self

    def busy_here(self, kind: str, scope: str = "") -> bool:
        """Задание уже ждёт места или выполняется в этом процессе: повторно не ставится (такт планировщика не плодит ожидающие копии)."""
        return (kind, scope) in self.waiting or any(le.kind == kind and le.scope == scope for le in self.held.values())

    @property
    def host(self) -> str:
        return self.owner.split("/", 1)[0] + "/"

    # ------------------------------------------------------------------------------------------ захват
    async def acquire(self, kind: str, scope: str = "", stage: str = "запуск") -> Lease | None:
        """Захватить задание или None, если его уже выполняет живой исполнитель. Истёкшая аренда перехватывается, прежний заход помечается «прервано»."""
        now = utcnow()
        run_id = uuid.uuid4()
        queued = self.queued.pop((kind, scope), None)
        async with self.sm() as db:
            dead = (await db.execute(delete(JobLease).where(JobLease.kind == kind, JobLease.scope == scope, JobLease.lease_until < now)
                                     .returning(JobLease.run_id, JobLease.owner, JobLease.started_at, JobLease.stage, JobLease.app_version))).all()
            for old in dead:                                                    # исполнитель перестал продлевать аренду: прерванный заход — в историю
                db.add(JobRun(kind=kind, scope=scope, run_id=old[0], owner=old[1], app_version=old[4], started_at=old[2], finished_at=now, status="interrupted", stage=old[3],
                              error="Исполнитель завершился или завис: аренда не продлевалась", duration_ms=int((now - old[2]).total_seconds() * 1000)))
            ins = _insert(db)(JobLease.__table__).values(kind=kind, scope=scope, run_id=run_id, owner=self.owner, started_at=now, heartbeat_at=now, lease_until=now + timedelta(seconds=self.ttl),
                                                         stage=stage, progress=None, app_version=self.version, progress_at=now, queued_at=queued).on_conflict_do_nothing(index_elements=["kind", "scope"])
            got = (await db.execute(ins)).rowcount
            if dead:
                await db.flush()
                await _prune(db, kind, scope)
            await db.commit()
        if not got:
            return None
        lease = Lease(self, kind, scope, run_id, now)
        lease.stage_text = stage
        lease.queued_at = queued
        self.held[run_id] = lease
        log.info("Задание начато", extra={"kind": kind, "scope": scope, "stage": stage})
        return lease

    @contextlib.asynccontextmanager
    async def run(self, kind: str, scope: str = "", stage: str = "запуск"):
        """Выполнение под арендой: `async with jobs.run(...) as lease:` (lease = None — задание уже выполняется). Исключение записывается в историю и пробрасывается; LeaseLost — статус «lost»."""
        lease = await self.acquire(kind, scope, stage)
        if lease is None:
            yield None
            return
        token = CURRENT.set(lease)
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
        finally:
            CURRENT.reset(token)

    @contextlib.asynccontextmanager
    async def slot(self, kind: str, scope: str = "", *, task: str = "", weight: int = 1, lane: str = "bg", stage: str = "запуск", on_wait=None):
        """Место у ограничителя ресурсов для задания (yield True) — до захвата аренды; False — задание уже ждёт или выполняется здесь, либо его выполняет другой исполнитель.
        Пока место не выдано, задание числится в `waiting` («ожидает исполнителя»): аренды нет, продлевать нечего, «выполняется» не показывается."""
        from .resources import RES  # noqa: PLC0415

        key = (kind, scope)
        if self.busy_here(kind, scope) or await self.is_live(kind, scope):
            yield False
            return
        self.waiting[key] = {"since": utcnow(), "stage": stage, "lane": lane, "task": task or f"{kind} {scope}".strip()}

        def waited() -> None:
            log.info("Задание ожидает исполнителя", extra={"kind": kind, "scope": scope, "lane": lane, "busy": sorted(RES.active)})
            if on_wait is not None:
                on_wait()
        try:
            async with RES.heavy(task or f"{kind}: {scope}", weight, lane=lane, on_wait=waited):
                self.queued[key] = self.waiting.pop(key)["since"]
                yield True
        finally:
            self.waiting.pop(key, None)
            self.queued.pop(key, None)

    @contextlib.asynccontextmanager
    async def run_heavy(self, kind: str, scope: str = "", stage: str = "запуск", *, task: str = "", weight: int = 1, lane: str = "bg", on_wait=None):
        """Тяжёлое задание: место у ограничителя (`slot`), затем аренда (`run`). lease = None — задание уже ждёт или выполняется (здесь или у другого исполнителя)."""
        async with self.slot(kind, scope, task=task, weight=weight, lane=lane, stage=stage, on_wait=on_wait) as ok:
            if not ok:
                yield None
                return
            async with self.run(kind, scope, stage) as lease:
                yield lease

    # ------------------------------------------------------------------------------------------ продление
    async def beat_once(self) -> int:
        """Продлить все аренды этого исполнителя; потерянные (перехвачены, сняты) помечаются `lost`. Возвращает число продлённых."""
        if not self.held:
            return 0
        await self._watch()
        now = utcnow()
        ids = [rid for rid, le in self.held.items() if not le.frozen]                 # зависшее (нет прогресса stall_hard_s) больше не продлеваем
        if not ids:
            return 0
        async with self.sm() as db:
            res = (await db.execute(update(JobLease).where(JobLease.owner == self.owner, JobLease.run_id.in_(ids)).values(heartbeat_at=now, lease_until=now + timedelta(seconds=self.ttl)).returning(JobLease.run_id))).all()
            mono, wall = time.monotonic(), utcnow()
            for rid in ids:                                                          # ход выполнения — отдельно от продления: живой пульс не выдаётся за работу
                le = self.held.get(rid)
                if le is not None and le.progress_at != le.progress_saved:
                    await db.execute(update(JobLease).where(JobLease.run_id == rid).values(progress_at=wall - timedelta(seconds=mono - le.progress_at)))
                    le.progress_saved = le.progress_at
            await db.commit()
        alive = {r[0] for r in res}
        for rid in ids:
            if rid not in alive and rid in self.held:
                self.held[rid].lost = True
                log.warning("Аренда задания потеряна", extra={"kind": self.held[rid].kind, "scope": self.held[rid].scope})
        return len(alive)

    async def _watch(self) -> None:
        """Сторож хода выполнения: нет прогресса stall_s — диагностическое событие (один раз до следующего прогресса); stall_hard_s — аренда больше не продлевается."""
        now = time.monotonic()
        for le in list(self.held.values()):
            idle = now - le.progress_at
            if idle >= self.stall_hard_s and not le.frozen:
                le.frozen = True
                await self._diag(le, "job_hung", f"Задание {le.kind} ({le.scope or 'общее'}) без хода выполнения {int(idle // 60)} мин на этапе «{le.stage_text}»: аренда больше не продлевается, "
                                 "задание будет считаться прерванным и запущено заново; запоздавший результат не запишется", "error")
            elif idle >= self.stall_s and not le.stalled:
                le.stalled = True
                await self._diag(le, "job_stalled", f"Задание {le.kind} ({le.scope or 'общее'}) без хода выполнения {int(idle // 60)} мин на этапе «{le.stage_text}» "
                                 f"(выполняется {int((utcnow() - le.started).total_seconds() // 60)} мин); занято: {', '.join(sorted(_res_active())) or '—'}", "warn")

    async def _diag(self, le: "Lease", event: str, text: str, level: str) -> None:
        log.warning(text, extra={"kind": le.kind, "scope": le.scope, "event": event})
        with contextlib.suppress(Exception):
            async with self.sm() as db:
                await db.execute(update(JobLease).where(JobLease.run_id == le.run_id).values(progress=text[:300]))
                await db.commit()
        if self.journal is not None:
            with contextlib.suppress(Exception):
                await self.journal.emit("system", event, level=level, message=text[:600], data={"kind": le.kind, "scope": le.scope})

    async def reap(self, grace_s: int = 600) -> int:
        """Снять аренды, просроченные дольше `grace_s`: их исполнитель исчез (контейнер пересоздан с другим именем хоста, процесс убит), а то же задание
        ещё не запускалось и не перехватило аренду. Заход записывается в историю как прерванный — «выполняется» не висит часами."""
        now = utcnow()
        async with self.sm() as db:
            dead = (await db.execute(delete(JobLease).where(JobLease.lease_until < now - timedelta(seconds=grace_s))
                                     .returning(JobLease.kind, JobLease.scope, JobLease.run_id, JobLease.owner, JobLease.started_at, JobLease.stage, JobLease.app_version))).all()
            for k, sc, rid, ow, st, stg, ver in dead:
                db.add(JobRun(kind=k, scope=sc, run_id=rid, owner=ow, app_version=ver, started_at=st, finished_at=now, status="interrupted", stage=stg,
                              error="Исполнитель исчез: аренда не продлевалась и снята", duration_ms=int((now - st).total_seconds() * 1000)))
            await db.commit()
        for k, sc, *_ in dead:
            log.warning("Снята брошенная аренда задания", extra={"kind": k, "scope": sc})
        return len(dead)

    async def beat_loop(self) -> None:
        every = max(3.0, self.ttl / 4)
        last_reap = 0.0
        while not self._stop.is_set():
            try:
                await self.beat_once()
                if time.monotonic() - last_reap > 300:
                    last_reap = time.monotonic()
                    await self.reap(max(600, self.ttl * 3))
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

    def waiting_list(self) -> list[dict]:
        """Для пульса службы: задания, ожидающие места у ограничителя (аренды у них нет)."""
        return [{"kind": k, "scope": sc, "task": w["task"], "lane": w["lane"], "since": w["since"].isoformat(), "stage": w["stage"]} for (k, sc), w in self.waiting.items()]

    async def all_leases(self) -> list[JobLease]:
        async with self.sm() as db:
            return list((await db.execute(select(JobLease).order_by(JobLease.kind, JobLease.scope))).scalars().all())


JOBS = Jobs()


def _res_active() -> list[str]:
    from .resources import RES  # noqa: PLC0415

    return list(RES.active)


def touch_current() -> None:
    """Прогресс выполняемого задания (вызывается на границе порции)."""
    le = CURRENT.get()
    if le is not None:
        le.touch()
