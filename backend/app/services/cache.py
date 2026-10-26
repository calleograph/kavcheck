"""Кэш результатов тяжёлых запросов к KSC в памяти процесса (сводки по уязвимостям, состоянию защиты, событиям).
Ключ — источник и параметры запроса; срок — cache_ttl_seconds. Одновременные запросы с одним ключом ждут один расчёт."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable


class TtlCache:
    def __init__(self, max_items: int = 200):
        self._refreshing: set[tuple] = set()
        self._bg: set[asyncio.Task] = set()
        self._data: dict[tuple, tuple[float, Any]] = {}
        self._ttl: dict[tuple, float] = {}
        self._locks: dict[tuple, asyncio.Lock] = {}
        self._max = max_items

    async def get(self, key: tuple, ttl: float, make: Callable[[], Awaitable[Any]], *, refresh: bool = False, swr: float = 0) -> tuple[Any, float]:
        """(значение, время расчёта в секундах эпохи). swr — «устаревшее допустимо» (stale-while-revalidate): после ttl ещё swr секунд страница сразу получает прежний результат (с его временем расчёта),
        а обновление идёт в фоне — открытие страницы не ждёт тяжёлого запроса к KSC. `make` не должен зависеть от запроса (сессия базы, куки): он выполняется после ответа."""
        hit = self._data.get(key)
        if hit and not refresh and time.time() - hit[0] <= ttl:
            return hit[1], hit[0]
        if hit and not refresh and swr and time.time() - hit[0] <= ttl + swr:
            self._revalidate(key, ttl, swr, make)
            return hit[1], hit[0]
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            hit = self._data.get(key)
            if hit and not refresh and time.time() - hit[0] <= ttl:
                return hit[1], hit[0]
            value = await make()
            now = time.time()
            for k in [k for k, (t, _v) in self._data.items() if now - t > self._ttl.get(k, ttl + swr)]:      # истёкшие записи не лежат в памяти до вытеснения
                self._data.pop(k, None)
                self._locks.pop(k, None)
                self._ttl.pop(k, None)
            if len(self._data) >= self._max:
                for k in sorted(self._data, key=lambda k: self._data[k][0])[: self._max // 4]:
                    self._data.pop(k, None)
                    self._locks.pop(k, None)
                    self._ttl.pop(k, None)
            self._data[key] = (now, value)
            self._ttl[key] = ttl + swr
            return value, now

    def _revalidate(self, key: tuple, ttl: float, swr: float, make: Callable[[], Awaitable[Any]]) -> None:
        if key in self._refreshing:
            return
        self._refreshing.add(key)

        async def run() -> None:
            try:
                await self.get(key, ttl, make, refresh=True, swr=swr)
            except Exception:  # noqa: BLE001 — прежний результат остаётся; следующий запрос после ttl+swr получит ошибку честно
                logging.getLogger("app.cache").warning("Фоновое обновление кэша не удалось", exc_info=True)
            finally:
                self._refreshing.discard(key)

        t = asyncio.get_running_loop().create_task(run())
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)

    def drop(self, prefix: tuple) -> None:
        for k in [k for k in self._data if k[: len(prefix)] == prefix]:
            self._data.pop(k, None)
            self._ttl.pop(k, None)
