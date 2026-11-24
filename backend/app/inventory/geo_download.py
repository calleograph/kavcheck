"""Локальная установка проверенной пары GeoLite2 City / ASN из официальных архивов."""
from __future__ import annotations

import asyncio
import gzip
import json
import logging
import os
import re
import shutil
import tarfile
import time
import zlib
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager, nullcontext
from datetime import timezone
from email.utils import parsedate_to_datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from uuid import uuid4

import httpx
import maxminddb

log = logging.getLogger(__name__)
EDITIONS = ("GeoLite2-City", "GeoLite2-ASN")
HOST = "download.maxmind.com"
STORAGE = "mm-prod-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com"
CURRENT = ".geolite2-current"
GENERATION = re.compile(r"\.geolite2-[0-9a-f]{32}")
MANIFEST = "manifest.json"
MAX_DOWNLOAD = 128 * 1024**2
MAX_UNPACKED = 192 * 1024**2
MAX_MMDB = 160 * 1024**2
CHUNK = 64 * 1024
READER_GRACE = 60


class DownloadError(Exception):
    """Безопасное сообщение для журнала и интерфейса."""


def database_directory(directory: Path, *, managed: bool) -> Path:
    if managed:
        try:
            target = (directory / CURRENT).readlink().as_posix()
            if GENERATION.fullmatch(target):
                candidate = directory / target
                if candidate.is_dir() and not candidate.is_symlink():
                    return candidate
        except OSError:
            pass
    return directory


@asynccontextmanager
async def _response(client: httpx.AsyncClient, method: str, edition: str, auth: httpx.BasicAuth):
    url = httpx.URL(f"https://{HOST}/geoip/databases/{edition}/download?suffix=tar.gz")
    for attempt in range(4):
        async with client.stream(method, url, auth=auth if attempt == 0 else None, follow_redirects=False) as response:
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location", "")
                try:
                    url = url.join(location)
                except (httpx.InvalidURL, ValueError):
                    raise DownloadError("MaxMind вернул недопустимый адрес загрузки") from None
                if (not location or url.scheme != "https" or url.host != STORAGE or url.port not in (None, 443)
                        or url.username or url.password or url.fragment):
                    raise DownloadError("MaxMind вернул недопустимый адрес загрузки")
                continue
            if response.status_code in (401, 403):
                raise DownloadError("MaxMind отклонил учётные данные или доступ к базе")
            if response.status_code == 429:
                raise DownloadError("Достигнут лимит загрузок MaxMind")
            if response.status_code != 200:
                raise DownloadError(f"MaxMind вернул HTTP {response.status_code}")
            yield response
            return
    raise DownloadError("Превышен предел перенаправлений MaxMind")


def _validators(response: httpx.Response) -> dict:
    try:
        modified = parsedate_to_datetime(response.headers.get("last-modified", ""))
        observed = modified.astimezone(timezone.utc).isoformat() if modified.tzinfo else ""
    except (OverflowError, TypeError, ValueError):
        observed = ""
    etag = response.headers.get("etag", "")
    return {"last_modified": observed, "etag": sha256(etag.encode()).hexdigest() if etag else ""}


class _BoundedReader:
    def __init__(self, stream):
        self.stream = stream
        self.left = MAX_UNPACKED

    def read(self, size: int) -> bytes:
        data = self.stream.read(min(size, self.left + 1))
        self.left -= len(data)
        if self.left < 0:
            raise DownloadError("Распакованный архив GeoLite2 превышает допустимый размер")
        return data


def _extract(archive: Path, target: Path) -> None:
    with gzip.open(archive, "rb") as gz:
        bounded = _BoundedReader(gz)
        with tarfile.open(fileobj=bounded, mode="r|") as tar:
            found = False
            for index, entry in enumerate(tar):
                if index >= 128:
                    raise DownloadError("В архиве GeoLite2 слишком много записей")
                name = PurePosixPath(entry.name)
                if name.is_absolute() or ".." in name.parts:
                    raise DownloadError("В архиве GeoLite2 обнаружен недопустимый путь")
                if name.name != target.name:
                    continue
                if found or not entry.isfile() or entry.issparse() or not 0 < entry.size <= MAX_MMDB:
                    raise DownloadError("В архиве GeoLite2 обнаружен неверный файл базы")
                with tar.extractfile(entry) as source, target.open("xb") as out:
                    shutil.copyfileobj(source, out, CHUNK)
                    out.flush()
                    os.fsync(out.fileno())
                if target.stat().st_size != entry.size:
                    raise DownloadError("Файл GeoLite2 получен не полностью")
                found = True
        # Маркер конца tar может стоять до конца gzip, где проверяется контрольная сумма.
        while bounded.read(CHUNK):
            pass
        if not found:
            raise DownloadError("В архиве GeoLite2 отсутствует файл базы")


def _epoch(path: Path, edition: str) -> int | None:
    try:
        if not 0 < path.stat().st_size <= MAX_MMDB:
            return None
        with maxminddb.open_database(str(path)) as reader:
            metadata = reader.metadata()
            if metadata.database_type == edition and metadata.build_epoch > 0:
                return metadata.build_epoch
    except (OSError, ValueError, maxminddb.InvalidDatabaseError):
        pass
    return None


async def _download(client: httpx.AsyncClient, edition: str, auth: httpx.BasicAuth, archive: Path) -> dict:
    async with _response(client, "GET", edition, auth) as response:
        header = response.headers.get("content-length", "")
        if header.isascii() and header.isdecimal() and (len(header) > 12 or int(header) > MAX_DOWNLOAD):
            raise DownloadError("Архив GeoLite2 превышает допустимый размер")
        total = 0
        with archive.open("xb") as out:
            async for chunk in response.aiter_raw(CHUNK):
                total += len(chunk)
                if total > MAX_DOWNLOAD:
                    raise DownloadError("Архив GeoLite2 превышает допустимый размер")
                out.write(chunk)
        return _validators(response)


def _metadata(directory: Path) -> dict:
    try:
        with (directory / MANIFEST).open("rb") as f:
            value = json.loads(f.read(4096))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _prune(directory: Path, keep: tuple[Path, ...]) -> None:
    try:
        cutoff = time.time() - READER_GRACE
        for path in directory.iterdir():
            if (path not in keep and GENERATION.fullmatch(path.name) and not path.is_symlink()
                    and path.is_dir() and path.stat().st_mtime < cutoff):
                shutil.rmtree(path)
    except OSError:
        log.warning("Не удалось удалить старое поколение GeoLite2")


def _publish(directory: Path, staged: Path, previous: Path) -> None:
    target = directory / f".geolite2-{uuid4().hex}"
    staged.rename(target)
    link = target / CURRENT
    try:
        if previous != directory:
            # Читатель мог выбрать прежнее поколение, ещё не открыв оба файла.
            os.utime(previous, None)
        # Относительная ссылка будет перенесена в родительский каталог одним rename.
        link.symlink_to(target.name, target_is_directory=True)
        os.replace(link, directory / CURRENT)
    except OSError:
        shutil.rmtree(target)
        raise
    _prune(directory, (target, previous))


async def update(directory: Path, account_id: str, license_key: str, *, transport: httpx.AsyncBaseTransport | None = None,
                 guard: Callable[[], AbstractAsyncContextManager] | None = None) -> dict:
    """Скачать изменившиеся базы и переключить опубликованную пару после проверки обеих."""
    current = database_directory(directory, managed=True)
    manifest = _metadata(current) if current != directory else {}
    result = {}
    changed = False
    edition = "GeoLite2"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        auth = httpx.BasicAuth(account_id, license_key)
        async with asyncio.timeout(300), httpx.AsyncClient(transport=transport, timeout=30,
                                                          headers={"Accept-Encoding": "identity"}) as client:
            with TemporaryDirectory(prefix=".geolite2-stage-", dir=directory) as temp:
                staged = Path(temp)
                for edition in EDITIONS:
                    tag = manifest.get(edition)
                    tag = tag if isinstance(tag, dict) else {}
                    filename = f"{edition}.mmdb"
                    prior = current / filename
                    epoch = _epoch(prior, edition) if current != directory else None
                    async with _response(client, "HEAD", edition, auth) as latest:
                        version = _validators(latest)
                    stamp = version["last_modified"]
                    known_stamp = tag.get("last_modified", "")
                    known_stamp = known_stamp if isinstance(known_stamp, str) else ""
                    same = epoch is not None and ((stamp and stamp <= known_stamp)
                                                 or (version["etag"] and version["etag"] == tag.get("etag")))
                    if same:
                        os.link(prior, staged / filename)
                        result[edition] = {"build_epoch": epoch, "last_modified": known_stamp, "etag": tag.get("etag", "")}
                        continue
                    archive = staged / f"{edition}.tar.gz"
                    got = await _download(client, edition, auth, archive)
                    path = staged / filename
                    await asyncio.to_thread(_extract, archive, path)
                    archive.unlink()
                    built = _epoch(path, edition)
                    if built is None or (epoch is not None and built < epoch):
                        raise DownloadError("MaxMind предоставил повреждённый или устаревший выпуск базы")
                    result[edition] = {"build_epoch": built, **{k: got[k] or version[k] for k in version}}
                    changed = True
                if changed:
                    (staged / MANIFEST).write_text(json.dumps(result), encoding="utf-8")
                async with guard() if guard else nullcontext():
                    if changed:
                        _publish(directory, staged, current)
                    else:
                        _prune(directory, (current,))
    except DownloadError as exc:
        raise DownloadError(f"{edition}: {exc}") from None
    except (httpx.HTTPError, httpx.InvalidURL, TimeoutError):
        raise DownloadError(f"{edition}: не удалось получить ответ MaxMind") from None
    except (OSError, EOFError, tarfile.TarError, zlib.error):
        raise DownloadError(f"{edition}: не удалось распаковать или сохранить базы GeoLite2") from None
    return {"changed": changed, "databases": {name: {k: v for k, v in data.items() if k != "etag"} for name, data in result.items()}}
