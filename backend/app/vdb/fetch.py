"""HTTP-загрузка для источников: тайм-ауты, повторы с задержкой при ограничениях (429/403/5xx), предел размера, доверенные сертификаты из общего хранилища CA."""
from __future__ import annotations

import asyncio
import logging
import ssl
import tempfile
from pathlib import Path
from typing import Callable

import httpx

log = logging.getLogger("app.vdb")
UA = "KAV-Checker/vulnerability-db (+https://github.com/calleograph/kavcheck)"
MAX_BYTES = 400 * 1024 * 1024


class FetchError(Exception):
    """Понятная пользователю ошибка загрузки (сеть, TLS, ограничение частоты, неверный ответ)."""


def make_ssl(extra_pem: list[str] | None, verify: bool) -> ssl.SSLContext | bool:
    if not verify:
        return False
    ctx = ssl.create_default_context()
    for pem in extra_pem or []:
        try:
            ctx.load_verify_locations(cadata=pem)
        except ssl.SSLError:
            log.warning("Сертификат CA из хранилища пропущен: не разобран")
    return ctx


class Http:
    """Тонкая обёртка над httpx: GET с повторами, JSON и скачивание в файл. `transport` подменяется в тестах."""

    def __init__(self, *, timeout: float = 60, verify: ssl.SSLContext | bool = True, headers: dict | None = None, transport: httpx.AsyncBaseTransport | None = None,
                 sleep: Callable[[float], "asyncio.Future"] = asyncio.sleep):
        self._c = httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=20), verify=verify, headers={"User-Agent": UA, **(headers or {})}, transport=transport, follow_redirects=True)
        self._sleep = sleep

    async def close(self) -> None:
        await self._c.aclose()

    async def get(self, url: str, params: dict | None = None, *, retries: int = 4, ok404: bool = False) -> httpx.Response | None:
        last = ""
        for n in range(retries + 1):
            try:
                r = await self._c.get(url, params=params)
            except httpx.HTTPError as exc:
                last = f"{type(exc).__name__}: {str(exc)[:160]}"
                if "CERTIFICATE_VERIFY_FAILED" in str(exc) or "certificate" in str(exc).lower():
                    raise FetchError(f"Сертификат сервера не прошёл проверку ({url.split('/')[2]}): добавьте корневой сертификат в «LDAPS → Сертификаты CA» или отключите проверку для этого источника") from None
                await self._sleep(min(30, 2 ** n * 2))
                continue
            if r.status_code == 404 and ok404:
                return None
            if r.status_code in (403, 429, 500, 502, 503, 504):
                last = f"HTTP {r.status_code}"
                ra = r.headers.get("retry-after")
                await self._sleep(float(ra) if ra and ra.isdigit() else min(60, 6 * (n + 1)))
                continue
            if r.status_code >= 400:
                raise FetchError(f"{url.split('/')[2]}: HTTP {r.status_code}")
            return r
        raise FetchError(f"{url.split('/')[2]}: источник недоступен или ограничивает запросы ({last})")

    async def json(self, url: str, params: dict | None = None, **kw):
        r = await self.get(url, params, **kw)
        if r is None:
            return None
        try:
            return r.json()
        except ValueError:
            raise FetchError(f"{url.split('/')[2]}: ответ не является JSON") from None

    async def post_json(self, url: str, body: dict, *, retries: int = 3):
        last = ""
        for n in range(retries + 1):
            try:
                r = await self._c.post(url, json=body)
            except httpx.HTTPError as exc:
                last = type(exc).__name__
                await self._sleep(2 ** n * 2)
                continue
            if r.status_code in (429, 500, 502, 503, 504):
                last = f"HTTP {r.status_code}"
                await self._sleep(min(60, 5 * (n + 1)))
                continue
            if r.status_code >= 400:
                raise FetchError(f"{url.split('/')[2]}: HTTP {r.status_code}")
            return r.json()
        raise FetchError(f"{url.split('/')[2]}: источник недоступен ({last})")

    async def download(self, url: str, dest: Path) -> int:
        """Скачивание большого файла потоком с ограничением размера."""
        total = 0
        try:
            async with self._c.stream("GET", url) as r:
                if r.status_code >= 400:
                    raise FetchError(f"{url.split('/')[2]}: HTTP {r.status_code}")
                with dest.open("wb") as f:
                    async for chunk in r.aiter_bytes(1 << 20):
                        total += len(chunk)
                        if total > MAX_BYTES:
                            raise FetchError("Файл выгрузки больше допустимого размера")
                        f.write(chunk)
        except httpx.HTTPError as exc:
            msg = str(exc)
            if "CERTIFICATE" in msg.upper():
                raise FetchError(f"Сертификат сервера не прошёл проверку ({url.split('/')[2]}): добавьте корневой сертификат в «LDAPS → Сертификаты CA» или отключите проверку для этого источника") from None
            raise FetchError(f"{url.split('/')[2]}: {type(exc).__name__}: {msg[:160]}") from None
        return total


def tempdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="vdb-"))
