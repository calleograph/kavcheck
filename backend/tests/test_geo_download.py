from __future__ import annotations

import io
import os
import tarfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from app.inventory import geo_download as gd


def _archive(edition: str, data: bytes, *, name: str = "") -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        member = tarfile.TarInfo(name or f"{edition}_20261123/{edition}.mmdb")
        member.size = len(data)
        tar.addfile(member, io.BytesIO(data))
    return out.getvalue()


async def test_install_and_skip_unchanged_editions(tmp_path, monkeypatch):
    @contextmanager
    def open_fake(path):
        edition, build = Path(path).read_text().split(":")
        yield SimpleNamespace(metadata=lambda: SimpleNamespace(database_type=edition, build_epoch=int(build)))

    monkeypatch.setattr(gd.maxminddb, "open_database", open_fake)
    city, asn = gd.EDITIONS
    versions = {city: 23, asn: 23}
    wrong = False
    damaged = False
    body_requests = []

    async def handle(request):
        assert request.method in ("HEAD", "GET")
        edition = request.url.path.split("/")[-2]
        if request.url.host == gd.HOST:
            assert request.headers["Authorization"].startswith("Basic ")
            assert request.url.params["suffix"] == "tar.gz"
            return httpx.Response(302, headers={"Location": f"https://{gd.STORAGE}/local/{edition}/db?mock=signed"})
        assert request.url.host == gd.STORAGE
        assert "Authorization" not in request.headers
        stamp = f"{versions[edition]} Nov 2026 02:00:00 GMT"
        headers = {"Last-Modified": stamp} if edition == city else {"ETag": f'"test-asn-{versions[edition]}"'}
        if request.method == "HEAD":
            return httpx.Response(200, headers=headers)
        body_requests.append(edition)
        payload = f"{city if wrong and edition == asn else edition}:{versions[edition]}".encode()
        archive = _archive(edition, payload)
        if damaged and edition == asn:
            archive = archive[:-8] + bytes([archive[-8] ^ 1]) + archive[-7:]
        return httpx.Response(200, headers=headers, stream=httpx.ByteStream(archive))

    transport = httpx.MockTransport(handle)
    manual = tmp_path / f"{city}.mmdb"
    manual.write_text("manual")
    first = await gd.update(tmp_path, "10000", "sample-test-key", transport=transport)
    initial = gd.database_directory(tmp_path, managed=True)
    assert first["changed"] and first["databases"][asn]["build_epoch"] == 23
    assert body_requests == [city, asn]
    assert manual.read_text() == "manual" and gd.database_directory(tmp_path, managed=False) == tmp_path

    second = await gd.update(tmp_path, "10000", "sample-test-key", transport=transport)
    assert second == {**first, "changed": False}
    assert body_requests == [city, asn]
    assert gd.database_directory(tmp_path, managed=True) == initial

    versions[city] = versions[asn] = 24
    wrong = True
    with pytest.raises(gd.DownloadError, match="повреждённый"):
        await gd.update(tmp_path, "10000", "sample-test-key", transport=transport)
    assert gd.database_directory(tmp_path, managed=True) == initial
    assert [(initial / f"{e}.mmdb").read_text() for e in gd.EDITIONS] == [f"{city}:23", f"{asn}:23"]
    assert not list(tmp_path.glob(".geolite2-stage-*"))

    wrong = False
    damaged = True
    with pytest.raises(gd.DownloadError, match="не удалось распаковать"):
        await gd.update(tmp_path, "10000", "sample-test-key", transport=transport)
    assert gd.database_directory(tmp_path, managed=True) == initial
    assert [(initial / f"{e}.mmdb").read_text() for e in gd.EDITIONS] == [f"{city}:23", f"{asn}:23"]

    damaged = False
    body_requests.clear()

    class ExpiredLease:
        async def __aenter__(self):
            raise RuntimeError("lease expired")

        async def __aexit__(self, *exc):
            return False

    with pytest.raises(RuntimeError, match="lease expired"):
        await gd.update(tmp_path, "10000", "sample-test-key", transport=transport, guard=ExpiredLease)
    assert body_requests == [city, asn]
    assert gd.database_directory(tmp_path, managed=True) == initial
    assert {p for p in tmp_path.iterdir() if gd.GENERATION.fullmatch(p.name)} == {initial}

    versions[asn] = 23
    body_requests.clear()
    os.utime(initial, (0, 0))
    third = await gd.update(tmp_path, "10000", "sample-test-key", transport=transport)
    assert third["changed"] and body_requests == [city]
    current = gd.database_directory(tmp_path, managed=True)
    assert current != initial
    assert [(current / f"{e}.mmdb").read_text() for e in gd.EDITIONS] == [f"{city}:24", f"{asn}:23"]
    assert not (await gd.update(tmp_path, "10000", "sample-test-key", transport=transport))["changed"]
    assert initial.exists()
    os.utime(initial, (0, 0))
    with pytest.raises(RuntimeError, match="lease expired"):
        await gd.update(tmp_path, "10000", "sample-test-key", transport=transport, guard=ExpiredLease)
    assert initial.exists()
    assert not (await gd.update(tmp_path, "10000", "sample-test-key", transport=transport))["changed"]
    assert not initial.exists()


@pytest.mark.parametrize("location", [
    "https://elsewhere.example.local/db",
    f"http://{gd.STORAGE}/db",
    f"https://{gd.STORAGE}:444/db",
    f"https://unsafe@{gd.STORAGE}/db",
])
async def test_reject_untrusted_redirect(tmp_path, location):
    async def handle(request):
        assert request.url.host == gd.HOST
        return httpx.Response(302, headers={"Location": location})

    with pytest.raises(gd.DownloadError, match="недопустимый адрес"):
        await gd.update(tmp_path, "10000", "sample-test-key", transport=httpx.MockTransport(handle))
    assert not list(tmp_path.iterdir())


async def test_archive_stream_limit_without_content_length(tmp_path, monkeypatch):
    monkeypatch.setattr(gd, "MAX_DOWNLOAD", 3)

    async def handle(request):
        return httpx.Response(200, stream=httpx.ByteStream(b"test") if request.method == "GET" else None)

    with pytest.raises(gd.DownloadError, match="Архив GeoLite2 превышает"):
        await gd.update(tmp_path, "10000", "sample-test-key", transport=httpx.MockTransport(handle))
    assert not list(tmp_path.iterdir())


def test_archive_traversal_and_uncompressed_limit(tmp_path, monkeypatch):
    city = gd.EDITIONS[0]
    target, archive = tmp_path / f"{city}.mmdb", tmp_path / "fixture.tar.gz"
    archive.write_bytes(_archive(city, b"fake", name=f"../../{target.name}"))
    with pytest.raises(gd.DownloadError, match="недопустимый путь"):
        gd._extract(archive, target)
    assert not target.exists()

    monkeypatch.setattr(gd, "MAX_UNPACKED", 1024)
    archive.write_bytes(_archive(city, b"x" * 2048))
    with pytest.raises(gd.DownloadError, match="Распакованный архив"):
        gd._extract(archive, target)
