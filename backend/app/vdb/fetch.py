"""HTTP-загрузка для источников: тайм-ауты, повторы с задержкой при ограничениях (429/403/5xx), предел размера, доверенные сертификаты из общего хранилища CA."""
from __future__ import annotations

import asyncio
import logging
import re
import ssl
import time
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable

import httpx

from .stream import free_bytes

log = logging.getLogger("app.vdb")
UA = "KAV-Checker/vulnerability-db (+https://github.com/calleograph/kavcheck)"
MAX_BYTES = 6 * 1024 ** 3            # предел одного файла; реальный предел — свободное место (проверяется до скачивания)
CA_DIR = Path(__file__).parent / "ca"


class FetchError(Exception):
    """Понятная пользователю ошибка загрузки (сеть, TLS, ограничение частоты, неверный ответ)."""


@dataclass
class Downloaded:
    size: int
    etag: str = ""
    last_modified: str = ""
    not_modified: bool = False


def builtin_ca(name: str) -> list[str]:
    """Сертификаты УЦ, поставляемые с приложением для конкретного источника (отдельные PEM-блоки из app/vdb/ca/<name>.pem)."""
    try:
        text = (CA_DIR / f"{name}.pem").read_text(encoding="utf-8")
    except OSError:
        return []
    return re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)


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

    async def head(self, url: str) -> httpx.Response:
        try:
            r = await self._c.head(url)
        except httpx.HTTPError as exc:
            raise FetchError(_net_error(url, exc)) from None
        if r.status_code >= 400:
            raise FetchError(f"{url.split('/')[2]}: HTTP {r.status_code}")
        return r

    async def download(self, url: str, dest: Path, *, etag: str = "", last_modified: str = "", max_bytes: int = MAX_BYTES,
                       progress: Callable[[int, int], Awaitable[None]] | None = None, headers: dict | None = None) -> Downloaded:
        """Скачивание большого файла потоком (память — один блок). Проверяется свободное место по Content-Length до начала, размер — после (оборванный файл отклоняется).
        etag/last_modified — условный запрос: 304 возвращает not_modified без скачивания."""
        total, expected, last = 0, 0, time.monotonic()
        cond = {**(headers or {}), **{k: v for k, v in (("If-None-Match", etag), ("If-Modified-Since", last_modified)) if v}}
        try:
            async with self._c.stream("GET", url, headers=cond) as r:
                if r.status_code == 304:
                    return Downloaded(0, etag, last_modified, True)
                if r.status_code >= 400:
                    raise FetchError(f"{url.split('/')[2]}: HTTP {r.status_code}")
                expected = int(r.headers.get("content-length") or 0)
                free = free_bytes(dest.parent)
                if expected and expected * 1.2 + (256 << 20) > free:
                    raise FetchError(f"Недостаточно места для загрузки: файл {expected >> 20} МБ, свободно {free >> 20} МБ в {dest.parent}")
                with dest.open("wb") as f:
                    async for chunk in r.aiter_bytes(1 << 20):
                        total += len(chunk)
                        if total > max_bytes:
                            raise FetchError("Файл выгрузки больше допустимого размера")
                        f.write(chunk)
                        if progress and time.monotonic() - last >= 3:          # показываем ход скачивания: у больших архивов он виден в интерфейсе
                            last = time.monotonic()
                            await progress(total, expected)
                if expected and total != expected:
                    raise FetchError(f"Файл получен не полностью ({total} из {expected} байт): обрыв соединения")
                return Downloaded(total, r.headers.get("etag", ""), r.headers.get("last-modified", ""))
        except httpx.HTTPError as exc:
            raise FetchError(_net_error(url, exc)) from None


def _net_error(url: str, exc: Exception) -> str:
    msg, host = str(exc), url.split("/")[2]
    if "CERTIFICATE" in msg.upper():
        return f"Сертификат сервера не прошёл проверку ({host}): добавьте корневой сертификат в «LDAPS → Сертификаты CA» или отключите проверку для этого источника"
    return f"{host}: {type(exc).__name__}: {msg[:160]}"


def tempdir(base: Path | None = None) -> Path:
    """Временный каталог загрузки: на томе данных (а не в слое контейнера); пустой при завершении загрузки."""
    if base:
        base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="vdb-", dir=base))
