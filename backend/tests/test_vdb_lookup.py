"""Поиск одной уязвимости во внешних базах (CVE.org, NVD, OSV) и её применимость к каталогу: разбор CVE JSON 5, подставной HTTP, маршрут /vdb/lookup. Без сети."""

import time

import httpx

from app.models import VdbVuln, utcnow
from app.vdb import lookup as L
from app.vdb import store
from app.vdb.fetch import Http
from app.vdb.normalize import Aff, Rec
from tests.conftest import login
from tests.test_vdb import _ksc_source

CVE5 = {"dataType": "CVE_RECORD", "cveMetadata": {"cveId": "CVE-2099-7001", "state": "PUBLISHED", "datePublished": "2099-01-02T10:00:00Z", "dateUpdated": "2099-01-03T10:00:00Z"},
        "containers": {"cna": {"providerMetadata": {"shortName": "google"}, "title": "Chrome V8 type confusion",
                               "descriptions": [{"lang": "en", "value": "Type confusion in V8 in Google Chrome prior to 116.0.5845.187."}],
                               "affected": [{"vendor": "Google", "product": "Chrome", "versions": [{"status": "affected", "version": "0", "lessThan": "116.0.5845.187", "versionType": "custom"}]},
                                            {"vendor": "n/a", "product": "n/a", "versions": [{"status": "affected", "version": "n/a"}]}],
                               "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 8.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}}],
                               "references": [{"url": "https://vendor.example.local/advisory", "tags": ["vendor-advisory", "patch"]}]},
                       "adp": [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [{"other": {"type": "ssvc", "content": {"options": [{"Exploitation": "active"}]}}}]}]}}


def test_parse_cve5_ranges_scores_and_exploitation():
    r = L.parse_cve5(CVE5)
    assert r.vuln_key == "CVE-2099-7001" and r.title == "Chrome V8 type confusion" and r.score == 8.8 and r.exploited and r.fix_available
    assert [(a.vendor, a.product, a.v_start, a.v_end, a.versions_all) for a in r.affected] == [("Google", "Chrome", "", "116.0.5845.187", False)]       # «n/a» — не продукт
    assert L.parse_cve5({"cveMetadata": {"cveId": "CVE-2099-1", "state": "REJECTED"}}) is None


def test_identifier_recognition():
    assert all(L.is_id(x) for x in ("CVE-2026-123633", "cve-2024-3094", "BDU:2024-01234", "GHSA-jfh8-c2jp-5v3q", "PYSEC-2021-1", "DSA-5000-1"))
    assert not any(L.is_id(x) for x in ("nginx", "open-ssl", "windows-server", "*chrome*", "CVE-2024"))


def _transport(calls: list):
    def h(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        if "cveawg" in req.url.host:
            return httpx.Response(200, json=CVE5) if req.url.path.endswith("CVE-2099-7001") else httpx.Response(404)
        if "nvd.nist.gov" in req.url.host:
            return httpx.Response(503)
        return httpx.Response(404)
    return httpx.MockTransport(h)


async def test_fetch_live_reports_each_source_separately():
    calls: list = []
    out = await L.fetch_live("cve-2099-7001", http=Http(transport=_transport(calls)))
    st = {s["source"]: s for s in out["sources"]}
    assert st["cve"]["found"] and not st["osv"]["found"] and not st["osv"]["error"] and "HTTP 503" in st["nvd"]["error"]
    assert [r.source for r in out["records"]] == ["cve"]
    calls.clear()
    out = await L.fetch_live("GHSA-jfh8-c2jp-5v3q", http=Http(transport=_transport(calls)))
    assert [s["source"] for s in out["sources"]] == ["osv"] and calls == ["https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q"]      # регистр OSV сохранён


async def test_lookup_live_record_matches_catalog_and_local_is_preferred(app, client, monkeypatch):
    await login(client, "admin", "Admin-Passw0rd-123")
    await _ksc_source(client, app)
    seen: list = []

    async def fake(ident, *, nvd_key="", http=None):
        seen.append(ident)
        return {"id": ident, "checked_at": 0, "sources": [{"source": "cve", "title": L.TITLES["cve"], "found": True, "error": "", "url": ""}], "records": [L.parse_cve5(CVE5)]}
    monkeypatch.setattr(L, "fetch_live", fake)
    r = (await client.get("/api/v1/vdb/lookup", params={"id": "CVE-2099-7001"})).json()
    assert r["local"] is None and r["live"]["title"] == "Chrome V8 type confusion" and r["live"]["cvss"]["primary"]["score"] == 8.8 and r["live"]["exploited"]
    m = r["infrastructure"]["matches"]
    assert m and {x["product_key"] for x in m} == {"google-chrome"} and {x["version"] for x in m} == {"115.0.5790.0"}       # новая версия 116.x не затронута
    assert (await client.get("/api/v1/vdb/lookup", params={"id": "chrome"})).status_code == 422
    async with app.state.session_maker() as db:            # уязвимость уже в локальной базе: внешние базы не опрашиваются без live
        await store.ensure_sources(db)
        await store.save_batch(db, 1, [Rec(source="nvd", ext_id="CVE-2099-7002", vuln_key="CVE-2099-7002", title="Local one", published=utcnow(), modified=utcnow(),
                                           affected=[Aff(vendor="google", product="chrome", v_end="116.0.5845.187")])])
        await store.refresh_vulns(db, {"CVE-2099-7002"})
        await db.commit()
        assert await db.get(VdbVuln, "CVE-2099-7002") is not None
    seen.clear()
    r = (await client.get("/api/v1/vdb/lookup", params={"id": "cve-2099-7002"})).json()
    assert r["local"]["key"] == "CVE-2099-7002" and r["live"] is None and not seen and r["infrastructure"]["matches"]
    async with app.state.session_maker() as db:            # запись без продуктов (NVD «Received»): внешние базы опрашиваются сами
        await store.save_batch(db, 1, [Rec(source="nvd", ext_id="CVE-2099-7001", vuln_key="CVE-2099-7001", title="Received", published=utcnow(), modified=utcnow())])
        await store.refresh_vulns(db, {"CVE-2099-7001"})
        await db.commit()
    r = (await client.get("/api/v1/vdb/lookup", params={"id": "CVE-2099-7001"})).json()
    assert r["local"]["key"] == "CVE-2099-7001" and seen == ["CVE-2099-7001"] and r["infrastructure"]["matches"]
    seen.clear()
    r = (await client.get("/api/v1/vdb/lookup", params={"id": "GHSA-jfh8-c2jp-5v3q"})).json()      # GHSA → CVE из внешней записи, которая есть локально
    assert r["local"]["key"] == "CVE-2099-7001"
    seen.clear()
    r = (await client.get("/api/v1/vdb/lookup", params={"id": "cve-2099-7002"})).json()
    assert r["local"]["key"] == "CVE-2099-7002" and r["live"] is None and not seen and r["infrastructure"]["matches"]
    r = (await client.get("/api/v1/vdb/lookup", params={"id": "CVE-2099-7002", "live": True})).json()
    assert seen == ["CVE-2099-7002"] and r["live"] is not None


async def test_live_cache_drops_expired_and_is_capped(monkeypatch):
    class NoNet:
        def __init__(self, **_kw):
            pass

        async def close(self):
            pass

    async def one(_http, src, ident, _key):
        return {"source": src, "found": True, "error": ""}, []

    monkeypatch.setattr(L, "Http", NoNet)
    monkeypatch.setattr(L, "_one", one)
    monkeypatch.setattr(L, "CACHE_MAX", 3)
    old = time.monotonic() - L.LIVE_TTL - 1                                                 # не 0.0: на свежей машине CI monotonic() меньше LIVE_TTL
    monkeypatch.setattr(L, "_cache", {"OLD-2000-1": (old, {}), "OLD-2000-2": (old, {})})    # истёкшие записи
    await L.fetch_live("GHSA-2222-3333-4444")
    assert list(L._cache) == ["GHSA-2222-3333-4444"]                                       # noqa: SLF001 — истёкшие удалены при вставке
    for i in range(5):
        await L.fetch_live(f"PYSEC-2099-{i}")
    assert len(L._cache) == 3 and "PYSEC-2099-4" in L._cache                                # noqa: SLF001 — размер ограничен, вытесняются старые
