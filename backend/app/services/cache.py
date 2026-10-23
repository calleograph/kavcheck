"""Кэш результатов тяжёлых запросов к KSC в памяти процесса (сводки по уязвимостям, состоянию защиты, событиям).
Ключ — источник и параметры запроса; срок — cache_ttl_seconds. Одновременные запросы с одним ключом ждут один расчёт."""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable


class TtlCache:
    def __init__(self, max_items: int = 200):
        self._data: dict[tuple, tuple[float, Any]] = {}
        self._locks: dict[tuple, asyncio.Lock] = {}
        self._max = max_items

    async def get(self, key: tuple, ttl: float, make: Callable[[], Awaitable[Any]], *, refresh: bool = False) -> tuple[Any, float]:
        """(значение, время расчёта в секундах эпохи)."""
        hit = self._data.get(key)
        if hit and not refresh and time.time() - hit[0] <= ttl:
            return hit[1], hit[0]
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            hit = self._data.get(key)
            if hit and not refresh and time.time() - hit[0] <= ttl:
                return hit[1], hit[0]
            value = await make()
            now = time.time()
            if len(self._data) >= self._max:
                for k in sorted(self._data, key=lambda k: self._data[k][0])[: self._max // 4]:
                    self._data.pop(k, None)
                    self._locks.pop(k, None)
            self._data[key] = (now, value)
            return value, now

    def drop(self, prefix: tuple) -> None:
        for k in [k for k in self._data if k[: len(prefix)] == prefix]:
            self._data.pop(k, None)
