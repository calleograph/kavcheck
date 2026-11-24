import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from app.inventory import geo_download as gd, geo_mirror as gm
from app.inventory.geography import GEOLITE_LABEL, GeoIP

NOW = datetime(2026, 11, 24, tzinfo=timezone.utc)
BUILD = int(NOW.timestamp())


@pytest.fixture
def fake_mmdb(monkeypatch):
    @contextmanager
    def open_fake(path):
        edition, build = Path(path).read_text().split(":")
        yield SimpleNamespace(metadata=lambda: SimpleNamespace(database_type=edition, build_epoch=int(build)))

    monkeypatch.setattr(gd.maxminddb, "open_database", open_fake)


async def test_mirror_verifies_release_and_keeps_previous_on_failure(tmp_path, fake_mmdb):
    bodies = {edition: f"{edition}:{BUILD}".encode() for edition in gm.MIRROR_EDITIONS}
    asset_requests = []
    fail = ""
    day = 24

    async def handle(request):
        assert request.method == "GET" and "Authorization" not in request.headers
        name = request.url.path.split("/")[-1].removesuffix(".mmdb")
        if str(request.url) == gm.RELEASE_API:
            if fail == "offline":
                raise httpx.ConnectError("mirror offline", request=request)
            release = {"tag_name": f"2026.11.{day}", "assets": [
                {"name": f"{edition}.mmdb", "digest": f"sha256:{sha256(data).hexdigest()}", "size": len(data)}
                for edition, data in bodies.items()
            ]}
            return httpx.Response(200, stream=httpx.ByteStream(json.dumps(release).encode()))
        if request.url.host == "github.com":
            assert f"/releases/download/2026.11.{day}/" in request.url.path
            host = "elsewhere.example.local" if fail == "redirect" else gm.RELEASE_ASSETS
            return httpx.Response(302, headers={"Location": f"https://{host}/asset/{name}.mmdb"})
        assert request.url.host == gm.RELEASE_ASSETS
        asset_requests.append(name)
        body = bodies[name]
        if fail == "digest" and name == gd.COUNTRY_EDITION:
            body = bytes([body[0] ^ 1]) + body[1:]
        return httpx.Response(200, stream=httpx.ByteStream(body))

    transport = httpx.MockTransport(handle)
    first = await gm.update_mirror(tmp_path, transport=transport, now=NOW)
    initial = gd.database_directory(tmp_path, managed=True)
    assert first["changed"] and set(first["databases"]) == set(gm.MIRROR_EDITIONS)
    assert asset_requests == list(gm.MIRROR_EDITIONS)
    assert not (await gm.update_mirror(tmp_path, transport=transport, now=NOW))["changed"]
    assert asset_requests == list(gm.MIRROR_EDITIONS)

    day = 25
    bodies[gd.COUNTRY_EDITION] = f"{gd.COUNTRY_EDITION}:{BUILD + 1}".encode()
    for fail, error in [("offline", "не удалось получить"), ("redirect", "недопустимый адрес"), ("digest", "сумма")]:
        with pytest.raises(gd.DownloadError, match=error):
            await gm.update_mirror(tmp_path, transport=transport, now=NOW)
        assert gd.database_directory(tmp_path, managed=True) == initial
        assert (initial / f"{gd.COUNTRY_EDITION}.mmdb").read_text() == f"{gd.COUNTRY_EDITION}:{BUILD}"
        assert not list(tmp_path.glob(".geolite2-stage-*"))

    fail = ""
    bodies[gd.COUNTRY_EDITION] = f"{gd.EDITIONS[0]}:{BUILD + 1}".encode()
    with pytest.raises(gd.DownloadError, match="повреждённый"):
        await gm.update_mirror(tmp_path, transport=transport, now=NOW)
    assert gd.database_directory(tmp_path, managed=True) == initial

    bodies[gd.COUNTRY_EDITION] = f"{gd.COUNTRY_EDITION}:{BUILD + 1}".encode()
    asset_requests.clear()
    assert (await gm.update_mirror(tmp_path, transport=transport, now=NOW))["changed"]
    assert asset_requests == [gd.COUNTRY_EDITION]
    assert gd.database_directory(tmp_path, managed=True) != initial

    after_expiry = NOW + timedelta(days=30)
    assert gm.needs_cleanup(tmp_path, after_expiry)
    assert gm.cleanup(tmp_path, after_expiry)
    assert gd.database_directory(tmp_path, managed=True) == tmp_path


async def test_alternative_manifest_and_address_validation(tmp_path, fake_mmdb, monkeypatch):
    host = "geo.example.local"
    bodies = {f"{edition}.mmdb": f"{edition}:{BUILD}".encode() for edition in gm.MIRROR_EDITIONS}
    requests = []

    async def handle(request):
        assert request.headers["Host"] == host and request.extensions["sni_hostname"] == host
        assert "Authorization" not in request.headers
        assert request.url.path.startswith("/geo/")
        name = request.url.path.split("/")[-1]
        requests.append(name)
        data = "\n".join(f"{sha256(value).hexdigest()} *{key}" for key, value in bodies.items()).encode()
        return httpx.Response(200, stream=httpx.ByteStream(data if name == "SHA256SUMS" else bodies[name]))

    transport = httpx.MockTransport(handle)
    with pytest.raises(gd.DownloadError, match="общедоступный"):
        await gm.update_mirror(tmp_path, "https://192.0.2.10/geo", transport=transport, now=NOW)
    assert not requests

    async def endpoint(url):
        assert str(url) == f"https://{host}/geo/"
        return url.copy_with(host="192.0.2.10"), {"headers": {"Host": host}, "extensions": {"sni_hostname": host}}

    monkeypatch.setattr(gm, "_public_endpoint", endpoint)
    result = await gm.update_mirror(tmp_path, f"https://{host}/geo", transport=transport, now=NOW)
    assert result["changed"] and requests == ["SHA256SUMS", *bodies]

    for url in (f"http://{host}", f"https://user@{host}", f"https://{host}/?key=value", f"https://{host}:444/"):
        with pytest.raises(ValueError):
            gm.source_url(url)


def test_country_is_used_when_city_has_no_country(tmp_path, monkeypatch):
    net = "192.0.2.10"
    records = {gm.MIRROR_EDITIONS[0]: {"city": {"names": {"en": "Example City"}}},
               gm.MIRROR_EDITIONS[1]: {"autonomous_system_number": 64512},
               gd.COUNTRY_EDITION: {"country": {"iso_code": "ZZ", "names": {"en": "Example Country"}}}}

    @contextmanager
    def open_fake(path):
        edition = Path(path).stem
        yield SimpleNamespace(metadata=lambda: SimpleNamespace(database_type=edition, build_epoch=BUILD),
                              get=lambda address: records[edition] if address == net else None)

    monkeypatch.setattr(gd.maxminddb, "open_database", open_fake)
    with GeoIP(tmp_path, "mirror") as geo:
        known = geo.lookup(net)
        assert known["provider"] == GEOLITE_LABEL and known["country"] == "Example Country"
        assert known["city"] == "Example City" and known["asn"] == 64512
        assert geo.lookup("192.0.2.11") == {}
