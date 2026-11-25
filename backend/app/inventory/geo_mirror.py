"""Обновление комплекта GeoLite2 City, ASN и Country из зеркала."""
from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import time
from contextlib import asynccontextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from hashlib import file_digest, sha256
from ipaddress import ip_address
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from .geo_download import (
    CHUNK, COUNTRY_EDITION, CURRENT, EDITIONS, GENERATION, MANIFEST, MAX_MMDB,
    READER_GRACE, DownloadError, _epoch, _metadata, _prune, _publish, _validators, database_directory,
)
from .geography import GEOLITE_MAX_AGE

REPOSITORY = "P3TERX/GeoLite.mmdb"
RELEASE_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASE_ASSETS = "release-assets.githubusercontent.com"
MIRROR_EDITIONS = (*EDITIONS, COUNTRY_EDITION)
DIGEST = re.compile(r"[0-9a-f]{64}")
MANIFEST_LIMIT = 64 * 1024


def current_release(databases: dict, now: datetime) -> bool:
    lower, upper = (now - GEOLITE_MAX_AGE).timestamp(), (now + timedelta(days=1)).timestamp()
    for edition in MIRROR_EDITIONS:
        tag = databases.get(edition)
        epoch = tag.get("build_epoch") if isinstance(tag, dict) else None
        if type(epoch) is not int or not lower < epoch <= upper:
            return False
    return True


def fresh_directory(directory: Path, now: datetime) -> bool:
    return current_release(_metadata(directory), now)


def mirror_expiry(directory: Path) -> datetime:
    databases = _metadata(directory)
    oldest = min(databases[edition]["build_epoch"] for edition in MIRROR_EDITIONS)
    return datetime.fromtimestamp(oldest, timezone.utc) + GEOLITE_MAX_AGE


def needs_cleanup(directory: Path, now: datetime) -> bool:
    current = database_directory(directory, managed=True)
    if current != directory and not fresh_directory(current, now):
        return True
    cutoff = time.time() - READER_GRACE
    try:
        return any(path != current and GENERATION.fullmatch(path.name) and not path.is_symlink()
                   and path.is_dir() and path.stat().st_mtime < cutoff for path in directory.iterdir())
    except OSError:
        return False


def cleanup(directory: Path, now: datetime) -> bool:
    current = database_directory(directory, managed=True)
    expired = current != directory and not fresh_directory(current, now)
    if expired:
        os.utime(current, None)
        (directory / CURRENT).unlink()
        current = directory
    _prune(directory, (current,))
    return expired


def source_url(value: str) -> httpx.URL:
    try:
        url = httpx.URL(value)
    except (httpx.InvalidURL, ValueError):
        raise ValueError("Укажите действительный HTTPS-адрес каталога") from None
    if (url.scheme != "https" or not url.host or url.port not in (None, 443)
            or url.userinfo or url.query or url.fragment or "?" in value or "#" in value):
        raise ValueError("Укажите HTTPS-адрес каталога без учётных данных, параметров и фрагмента")
    return url.copy_with(raw_path=url.raw_path.rstrip(b"/") + b"/")


async def _public_endpoint(url: httpx.URL) -> tuple[httpx.URL, dict]:
    host = url.raw_host.decode("ascii")
    endpoints = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    # Подключение по проверенному IP исключает повторное разрешение имени после проверки.
    addresses = [ip_address(endpoint[4][0]) for endpoint in endpoints]
    if not addresses or any(not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_link_local
                            or getattr(ip, "is_site_local", False) for ip in addresses):
        raise DownloadError("Альтернативный источник должен иметь общедоступный HTTPS-адрес")
    address = min(addresses, key=lambda ip: ip.version)
    return url.copy_with(host=str(address)), {"headers": {"Host": host}, "extensions": {"sni_hostname": host}}


@asynccontextmanager
async def _response(client, url: httpx.URL | str, *, github_asset: bool = False, options=None):
    for _ in range(2):
        async with client.stream("GET", url, follow_redirects=False, **(options or {})) as response:
            if response.is_redirect and github_asset:
                location = response.headers.get("location", "")
                url = httpx.URL(location)
                if (url.scheme != "https" or url.host != RELEASE_ASSETS or url.port not in (None, 443)
                        or url.userinfo or url.fragment):
                    raise DownloadError("GitHub вернул недопустимый адрес загрузки")
                github_asset = False
                continue
            if response.status_code != 200:
                raise DownloadError(f"Источник GeoLite2 вернул HTTP {response.status_code}")
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise DownloadError("Источник GeoLite2 вернул сжатый ответ вместо файла")
            yield response
            return
    raise DownloadError("GitHub вернул лишнее перенаправление")


async def _manifest(client, url, options=None) -> bytes:
    data = bytearray()
    async with _response(client, url, options=options) as response:
        async for chunk in response.aiter_raw(CHUNK):
            data.extend(chunk)
            if len(data) > MANIFEST_LIMIT:
                raise DownloadError("Список GeoLite2 превышает допустимый размер")
    return data


async def _github_files(client) -> dict:
    release = json.loads(await _manifest(client, RELEASE_API))
    tag = release.get("tag_name", "")
    if not re.fullmatch(r"[0-9]{4}\.[0-9]{2}\.[0-9]{2}", tag):
        raise DownloadError("GitHub вернул неверный номер выпуска GeoLite2")
    files = {}
    for asset in release["assets"]:
        name = asset["name"].removesuffix(".mmdb")
        if name not in MIRROR_EDITIONS or asset["name"] != f"{name}.mmdb":
            continue
        digest = (asset.get("digest") or "").removeprefix("sha256:")
        size = asset.get("size")
        if name in files or not DIGEST.fullmatch(digest) or type(size) is not int or not 0 < size <= MAX_MMDB:
            raise DownloadError(f"{name}: неверная контрольная сумма или размер в выпуске GitHub")
        url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}.mmdb"
        files[name] = (url, digest, size)
    return files


async def _alternative_files(client, base, options) -> dict:
    raw = await _manifest(client, base.join("SHA256SUMS"), options)
    files = {}
    for line in raw.decode("utf-8").splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        digest, filename = parts
        filename = filename.removeprefix("*")
        name = filename.removesuffix(".mmdb")
        if name not in MIRROR_EDITIONS or filename != f"{name}.mmdb":
            continue
        if name in files or not DIGEST.fullmatch(digest.lower()):
            raise DownloadError(f"{name}: неверная контрольная сумма в SHA256SUMS")
        files[name] = (base.join(filename), digest.lower(), None)
    return files


async def _save_file(client, url, path: Path, expected: str, size: int | None, options: dict | None) -> str:
    checksum = sha256()
    total = 0
    async with _response(client, url, github_asset=options is None, options=options) as response:
        stamp = _validators(response)["last_modified"]
        with path.open("xb") as out:
            async for chunk in response.aiter_raw(CHUNK):
                total += len(chunk)
                if total > (size or MAX_MMDB):
                    raise DownloadError("полученный файл превышает допустимый размер")
                checksum.update(chunk)
                out.write(chunk)
            if (size is not None and size != total) or checksum.hexdigest() != expected:
                raise DownloadError("контрольная сумма или размер полученного файла не совпадает")
            out.flush()
            os.fsync(out.fileno())
    return stamp


def _file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


async def update_mirror(directory: Path, alternative: str = "", *, transport=None, guard=None,
                        now: datetime | None = None) -> dict:
    """Проверить файлы одного выпуска и переключить весь комплект одной операцией."""
    current = database_directory(directory, managed=True)
    manifest = _metadata(current) if current != directory else {}
    databases = {}
    changed = False
    label = "GeoLite2"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        async with asyncio.timeout(300), httpx.AsyncClient(transport=transport, timeout=30, trust_env=False,
                                                          headers={"Accept-Encoding": "identity"}) as client:
            options = None
            if alternative:
                base, options = await _public_endpoint(source_url(alternative))
                files = await _alternative_files(client, base, options)
            else:
                files = await _github_files(client)
            if files.keys() != set(MIRROR_EDITIONS):
                raise DownloadError("источник не предоставил комплект City, ASN и Country")
            with TemporaryDirectory(prefix=".geolite2-stage-", dir=directory) as temp:
                staged = Path(temp)
                for label in MIRROR_EDITIONS:
                    url, digest, size = files[label]
                    path = staged / f"{label}.mmdb"
                    prior = current / path.name
                    epoch = _epoch(prior, label) if current != directory else None
                    data = manifest.get(label, {})
                    if (epoch is not None and isinstance(data, dict) and data.get("sha256") == digest
                            and await asyncio.to_thread(_file_digest, prior) == digest):
                        os.link(prior, path)
                        databases[label] = data
                        continue
                    stamp = await _save_file(client, url, path, digest, size, options)
                    built = _epoch(path, label)
                    if built is None or (epoch is not None and built < epoch):
                        raise DownloadError("получен повреждённый или устаревший выпуск базы")
                    databases[label] = {"sha256": digest, "build_epoch": built, "last_modified": stamp}
                    changed = True
                if not current_release(databases, now or datetime.now(timezone.utc)):
                    raise DownloadError("срок использования комплекта GeoLite2 истёк")
                if changed:
                    (staged / MANIFEST).write_text(json.dumps(databases), encoding="utf-8")
                async with guard() if guard else nullcontext():
                    if changed:
                        _publish(directory, staged, current)
                    else:
                        _prune(directory, (current,))
    except DownloadError as exc:
        raise DownloadError(f"{label}: {exc}") from None
    except (httpx.HTTPError, httpx.InvalidURL, TimeoutError, socket.gaierror):
        raise DownloadError(f"{label}: не удалось получить ответ источника") from None
    except (AttributeError, KeyError, TypeError, ValueError):
        raise DownloadError(f"{label}: источник вернул неверный список файлов") from None
    except OSError:
        raise DownloadError(f"{label}: не удалось сохранить базы GeoLite2") from None
    return {"changed": changed, "databases": {name: {k: v for k, v in data.items() if k != "sha256"}
                                               for name, data in databases.items()}}
