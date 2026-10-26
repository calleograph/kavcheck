"""Управление ресурсами фонового процесса (worker): учёт памяти, ограничение числа одновременных тяжёлых задач, мягкий и жёсткий пределы RSS.

Пределы — страховка, а не замена алгоритма: задачи сами обрабатывают данные порциями. Если память выросла до мягкого предела, новая тяжёлая задача откладывается; до жёсткого —
текущая задача останавливается на границе порции (MemoryPressure), освобождает память и повторяется позже; все задачи продолжаются с последней сохранённой порции.

Пределы берутся из лимита контейнера (cgroup), если он задан: мягкий 50 %, жёсткий 75 %; иначе из WORKER_RSS_SOFT_MB / WORKER_RSS_HARD_MB (по умолчанию 1536 / 2304 МБ)."""
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
    """Общие для worker ограничители. slots — сколько тяжёлых задач одновременно (каждая со своим весом), pause_ms — пауза между порциями (интенсивность)."""
    limits: Limits = field(default_factory=Limits.detect)
    slots: int = 1
    pause_ms: int = 0
    _sem: asyncio.Condition | None = None
    _used: int = 0
    active: dict[str, float] = field(default_factory=dict)
    peak_mb: float = 0.0
    deferred: int = 0

    def _cond(self) -> asyncio.Condition:
        if self._sem is None:
            self._sem = asyncio.Condition()
        return self._sem

    def configure(self, *, slots: int | None = None, pause_ms: int | None = None) -> None:
        if slots is not None:
            self.slots = max(1, min(4, int(slots)))
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
        """Граница порции: проверка памяти и пауза по настройке интенсивности (отдаёт время другим задачам и SQL Server)."""
        self.check(label)
        await asyncio.sleep(self.pause_ms / 1000 if self.pause_ms else 0)

    @contextlib.asynccontextmanager
    async def heavy(self, name: str, weight: int = 1, wait_s: float = 0):
        """Место для тяжёлой задачи: ждёт, пока освободятся слоты и память опустится ниже мягкого предела. wait_s=0 — ждать без ограничения."""
        weight = max(1, min(weight, self.slots))
        cond = self._cond()
        t0 = time.monotonic()
        async with cond:
            while True:
                if self._used + weight <= self.slots and (rss_mb() <= self.limits.soft_mb or not self.active):     # первая задача идёт всегда: иначе при высоком фоне ничто не стартует
                    break
                if wait_s and time.monotonic() - t0 > wait_s:
                    raise TimeoutError(f"нет свободных ресурсов для «{name}»")
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(cond.wait(), timeout=5)
            self._used += weight
            self.active[name] = time.monotonic()
        try:
            yield
        finally:
            async with cond:
                self._used -= weight
                self.active.pop(name, None)
                cond.notify_all()
            trim()

    def snapshot(self) -> dict:
        return {"rss_mb": int(rss_mb()), "peak_mb": int(self.peak_mb), "soft_mb": int(self.limits.soft_mb), "hard_mb": int(self.limits.hard_mb), "slots": self.slots, "used": self._used,
                "active": sorted(self.active), "deferred": self.deferred}


RES = Resources()
