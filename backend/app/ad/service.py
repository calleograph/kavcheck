"""Служба просмотра AD: выбор подключения, кэш ответов с общим выполнением одинаковых запросов и ограничением числа одновременных обращений к каталогу."""
from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Any, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.ldap import LdapConfig, LdapError
from ..services.ldap_store import LdapStore
from ..services.settings import HierSettings, SettingsService

MAX_PARALLEL = 4                 # одновременных обращений к контроллеру домена от всего приложения
CACHE_ITEMS = 300
REFRESH_MIN_AGE = 5.0            # «Обновить» чаще, чем раз в 5 секунд, отдаёт кэш: защита от нажатий подряд


class AdService:
    def __init__(self, ldap: LdapStore, svc: SettingsService):
        self.ldap, self.svc = ldap, svc
        self._cache: OrderedDict[tuple, tuple[float, float, Any]] = OrderedDict()      # ключ → (до какого времени, когда получено, значение)
        self._flight: dict[tuple, asyncio.Future] = {}
        self._sem = asyncio.Semaphore(MAX_PARALLEL)

    async def config(self, db: AsyncSession, cfg: HierSettings | None = None) -> LdapConfig:
        cfg = cfg or await self.svc.get(db, "hier")                                    # type: ignore[assignment]
        conns = [c for c in await self.ldap.connections(db) if c.enabled and c.host]
        pick = [c for c in conns if str(c.id) == cfg.ad_connection] or [c for c in conns if not cfg.ldap_connections or str(c.id) in cfg.ldap_connections] or conns
        if not pick:
            raise LdapError("not_configured", "подключение LDAPS не настроено: Администрирование → LDAPS")
        return self.ldap.config(pick[0], await self.ldap.ca_bundle(db))

    async def call(self, key: tuple, ttl: float, fn: Callable[[], Any], refresh: bool = False) -> Any:
        """Ответ из кэша или одно выполнение на все одновременные одинаковые запросы; ошибки не кэшируются."""
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit and hit[0] > now and (not refresh or now - hit[1] < REFRESH_MIN_AGE):
            return hit[2]
        fut = self._flight.get(key)
        if fut is not None:
            return await asyncio.shield(fut)
        fut = asyncio.get_running_loop().create_future()
        fut.add_done_callback(lambda f: f.cancelled() or f.exception())               # исключение без ожидающих не считается «не прочитанным»
        self._flight[key] = fut
        try:
            async with self._sem:
                val = await asyncio.to_thread(fn)
            self._cache[key] = (time.monotonic() + ttl, time.monotonic(), val)
            self._cache.move_to_end(key)
            while len(self._cache) > CACHE_ITEMS:
                self._cache.popitem(last=False)
            fut.set_result(val)
            return val
        except BaseException as exc:
            fut.set_exception(exc if isinstance(exc, Exception) else RuntimeError("cancelled"))
            raise
        finally:
            self._flight.pop(key, None)

    def forget(self) -> None:
        self._cache.clear()
