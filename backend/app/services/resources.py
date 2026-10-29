"""Управление ресурсами фонового процесса (worker): учёт памяти, ограничение числа одновременных тяжёлых задач, мягкий и жёсткий пределы RSS.

Пределы — страховка, а не замена алгоритма: задачи сами обрабатывают данные порциями. Если память выросла до мягкого предела, новая тяжёлая задача откладывается; до жёсткого —
текущая задача останавливается на границе порции (MemoryPressure), освобождает память и повторяется позже; все задачи продолжаются с последней сохранённой порции.

Пределы берутся из лимита контейнера (cgroup), если он задан: мягкий 50 %, жёсткий 75 %; иначе из WORKER_RSS_SOFT_MB / WORKER_RSS_HARD_MB (по умолчанию 1536 / 2304 МБ).

Очереди (полосы) мест: `bg` — тяжёлые фоновые задачи (каталог, анализ уязвимостей, расчёты по KSC), `bi` — импорт BI-выгрузок, `interactive` — отчёты пользователей.
Полосы независимы: многочасовой анализ уязвимостей не задерживает импорт BI и отчёты. Внутри полосы места выдаются строго по очереди постановки (FIFO) — задача не может
бесконечно пропускаться более лёгкими. Число мест фоновой полосы ограничено числом процессоров и памятью контейнера (`auto_cap`), сколько бы ни задал администратор.
Ожидание места — не выполнение: аренду задания (services/jobs) берут только после получения места, поэтому ожидающая задача не выглядит «выполняется»."""
from __future__ import annotations

import asyncio
import contextlib
import ctypes
import gc
import logging
import os
import time
from dataclasses import dataclass, field

log = logging.getLogger("app.resources")


class MemoryPressure(Exception):
    """Память процесса достигла жёсткого предела: задача должна сохранить сделанное, освободить память и повторить позже."""


def rss_mb() -> float:
    try:
        with open("/proc/self/status") as fh:
            for ln in fh:
                if ln.startswith("VmRSS:"):
                    return int(ln.split()[1]) / 1024
    except OSError:
        pass
    return 0.0


def container_limit_mb() -> float | None:
    """Лимит памяти контейнера (cgroup v2 или v1); None — не ограничен."""
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            raw = open(path).read().strip()
        except OSError:
            continue
        if raw.isdigit() and int(raw) < (1 << 50):
            return int(raw) / (1 << 20)
    return None


def trim() -> None:
    """Вернуть освобождённую память системе: сборка мусора и malloc_trim (без него glibc держит свободные страницы в RSS)."""
    gc.collect()
    with contextlib.suppress(Exception):
        ctypes.CDLL("libc.so.6").malloc_trim(0)


def cpu_count() -> float:
    """Доступные процессоры: квота cgroup (cpu.max) или привязка процесса; дробная квота (1.5 CPU) сохраняется."""
    try:
        quota, period = open("/sys/fs/cgroup/cpu.max").read().split()[:2]
        if quota != "max" and int(period) > 0:
            return max(0.1, int(quota) / int(period))
    except (OSError, ValueError):
        pass
    try:
        return float(len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return float(os.cpu_count() or 1)


HEAVY_MB = 600                       # оценка памяти одной тяжёлой задачи (каталог, анализ, импорт 50 тыс. строк — замеры 150–500 МБ)


@dataclass
class Limits:
    soft_mb: float
    hard_mb: float

    @classmethod
    def detect(cls) -> Limits:
        lim = container_limit_mb()
        soft = float(os.environ.get("WORKER_RSS_SOFT_MB") or (lim * 0.5 if lim else 1536))
        hard = float(os.environ.get("WORKER_RSS_HARD_MB") or (lim * 0.75 if lim else 2304))
        return cls(soft, max(hard, soft * 1.2))


@dataclass
class Resources:
    """Общие для worker ограничители. slots — сколько тяжёлых фоновых задач одновременно (каждая со своим весом), pause_ms — пауза между порциями (интенсивность)."""
    limits: Limits = field(default_factory=Limits.detect)
    slots: int = 1
    islots: int = 1                  # места для запросов пользователя (отчёты) сверх фоновых
    bislots: int = 1                 # импорт BI — своя полоса: не ждёт каталог и анализ уязвимостей
    pause_ms: int = 0
    _sem: asyncio.Condition | None = None
    used: dict[str, int] = field(default_factory=lambda: {"bg": 0, "bi": 0, "interactive": 0})
    queue: list = field(default_factory=list)         # ожидающие места: [токен, полоса, вес, название, с какого момента] — порядок постановки
    active: dict[str, float] = field(default_factory=dict)
    peak_mb: float = 0.0
    deferred: int = 0
    requested: int = 1

    def cap(self, lane: str) -> int:
        return {"bg": self.slots, "bi": self.bislots, "interactive": self.islots}.get(lane, 1)

    @staticmethod
    def auto_cap() -> int:
        """Сколько тяжёлых фоновых задач выдержит контейнер: процессоров минус один (событийный цикл, API запросов, BI) и памяти на HEAVY_MB каждая; 1–4."""
        cpu = cpu_count()
        mem = container_limit_mb()
        by_cpu = max(1, int(cpu) - 1) if cpu >= 2 else 1
        by_mem = max(1, int((mem or 4096) * 0.75 // HEAVY_MB))
        return max(1, min(4, by_cpu, by_mem))

    def _cond(self) -> asyncio.Condition:
        loop = asyncio.get_running_loop()
        if self._sem is None or getattr(self, "_sem_loop", None) is not loop:        # условие привязывается к циклу событий при первом ожидании: новый цикл (перезапуск, тесты) — новое условие
            self._sem, self._sem_loop = asyncio.Condition(), loop
        return self._sem

    def configure(self, *, slots: int | None = None, pause_ms: int | None = None) -> None:
        if slots is not None:
            self.requested = max(1, min(4, int(slots)))
            self.slots = min(self.requested, self.auto_cap())             # настройка администратора не превышает возможностей контейнера
        if pause_ms is not None:
            self.pause_ms = max(0, min(5000, int(pause_ms)))

    def check(self, label: str = "") -> float:
        """Вызывается задачей на границе порции: обновляет пик и при превышении жёсткого предела прерывает задачу."""
        cur = rss_mb()
        self.peak_mb = max(self.peak_mb, cur)
        if cur > self.limits.hard_mb:
            trim()
            cur2 = rss_mb()
            if cur2 > self.limits.hard_mb:
                self.deferred += 1
                raise MemoryPressure(f"{label or 'задача'}: память процесса {cur2:.0f} МБ выше предела {self.limits.hard_mb:.0f} МБ")
            return cur2
        return cur

    async def breathe(self, label: str = "") -> None:
        """Граница порции: проверка памяти, отметка хода выполнения задания и пауза по настройке интенсивности (отдаёт время другим задачам и SQL Server)."""
        from .jobs import touch_current  # noqa: PLC0415

        self.check(label)
        touch_current()
        await asyncio.sleep(self.pause_ms / 1000 if self.pause_ms else 0)

    @contextlib.asynccontextmanager
    async def heavy(self, name: str, weight: int = 1, wait_s: float = 0, *, interactive: bool = False, lane: str = "bg", on_wait=None):
        """Место для тяжёлой задачи в полосе `lane`: ждёт своей очереди (FIFO), свободных мест и памяти ниже мягкого предела. wait_s=0 — ждать без ограничения.
        interactive — запрос пользователя (отчёт): полоса `interactive`. on_wait — вызывается один раз, если место не выдано сразу (для показа «Ожидает исполнителя»)."""
        lane = "interactive" if interactive else lane
        cond = self._cond()
        t0 = time.monotonic()
        cap = self.cap(lane)
        weight = max(1, min(weight, cap))
        token = object()
        notified = False
        async with cond:
            self.queue.append([token, lane, weight, name, time.time()])
            try:
                while True:
                    first = next(q for q in self.queue if q[1] == lane)
                    if first[0] is token and self.used[lane] + weight <= cap and (rss_mb() <= self.limits.soft_mb or not self.active):   # первая задача идёт всегда: иначе при высоком фоне ничто не стартует
                        break
                    if wait_s and time.monotonic() - t0 > wait_s:
                        raise TimeoutError(f"нет свободных ресурсов для «{name}»")
                    if not notified and on_wait is not None:
                        notified = True
                        with contextlib.suppress(Exception):
                            on_wait()
                    with contextlib.suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(cond.wait(), timeout=5)
            finally:
                self.queue[:] = [q for q in self.queue if q[0] is not token]
                cond.notify_all()                                            # следующий в очереди проверяет своё место
            self.used[lane] += weight
            self.active[name] = time.monotonic()
        waited = time.monotonic() - t0
        if waited > 30:
            log.info("Место для задачи получено после ожидания", extra={"task": name, "lane": lane, "waited_s": round(waited)})
        try:
            yield
        finally:
            async with cond:
                self.used[lane] -= weight
                self.active.pop(name, None)
                cond.notify_all()
            trim()

    def snapshot(self) -> dict:
        now = time.time()
        return {"rss_mb": int(rss_mb()), "peak_mb": int(self.peak_mb), "soft_mb": int(self.limits.soft_mb), "hard_mb": int(self.limits.hard_mb), "slots": self.slots, "slots_requested": self.requested,
                "cpus": round(cpu_count(), 1), "used": sum(self.used.values()), "lanes": {k: {"used": v, "cap": self.cap(k)} for k, v in self.used.items()}, "interactive_slots": self.islots,
                "active": sorted(self.active), "waiting": [{"task": q[3], "lane": q[1], "wait_s": int(now - q[4])} for q in self.queue], "deferred": self.deferred}


RES = Resources()
