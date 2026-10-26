import asyncio
import time

from app.services.cache import TtlCache


async def test_stale_value_is_served_at_once_and_refreshed_in_background():
    c = TtlCache()
    calls = []

    async def make():
        calls.append(1)
        await asyncio.sleep(0.05)
        return len(calls)

    v, at = await c.get(("k",), 0.05, make, swr=5)
    assert v == 1
    await asyncio.sleep(0.08)                                      # срок истёк, но «устаревшее допустимо»
    t = time.monotonic()
    v2, at2 = await c.get(("k",), 0.05, make, swr=5)
    assert v2 == 1 and at2 == at and time.monotonic() - t < 0.04    # прежний результат — без ожидания обновления
    await asyncio.sleep(0.15)
    v3, at3 = await c.get(("k",), 5, make, swr=5)
    assert v3 == 2 and at3 > at and len(calls) == 2                 # обновлён в фоне, ровно один раз
    for _ in range(3):
        await c.get(("k",), 0.0001, make, swr=5)
    await asyncio.sleep(0.2)
    assert len(calls) <= 4


async def test_without_swr_expired_value_is_recomputed():
    c = TtlCache()
    n = {"i": 0}

    async def make():
        n["i"] += 1
        return n["i"]

    assert (await c.get(("a",), 0.01, make))[0] == 1
    await asyncio.sleep(0.02)
    assert (await c.get(("a",), 0.01, make))[0] == 2               # без swr — прежнее поведение: ждёт пересчёта


async def test_background_failure_keeps_old_value_for_the_user():
    c = TtlCache()
    n = {"i": 0}

    async def make():
        n["i"] += 1
        if n["i"] == 2:
            raise RuntimeError("KSC недоступен")
        return n["i"]

    await c.get(("b",), 0.01, make, swr=5)
    await asyncio.sleep(0.02)
    assert (await c.get(("b",), 0.01, make, swr=5))[0] == 1       # обновление в фоне упало — пользователь продолжает видеть прежние данные, а не ошибку
    await asyncio.sleep(0.05)
    assert (await c.get(("b",), 0.01, make, swr=5))[0] == 1
