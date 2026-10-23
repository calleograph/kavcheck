"""Каталог, сохранённые проверки и отчёты проверки версий через API (SQLite; данные каталога — без KSC)."""
from app.models import CatalogProduct, CatalogState, KscSource, utcnow
from tests.conftest import login


async def _source(client) -> dict:
    return (await client.post("/api/v1/admin/sources", json={"name": "KSC-A", "host": "a.example.local", "database": "KAV", "username": "u", "password": "p"})).json()


async def _seed_catalog(app, source_id: str) -> None:
    import uuid

    sid = uuid.UUID(source_id)
    async with app.state.session_maker() as db:
        db.add(CatalogState(source_id=sid, status="ready", built_at=utcnow(), activity_days=30))
        for key, name, pub, ha, hall in (("google-chrome", "Google Chrome", "Google", 10, 15), ("7-zip", "7-Zip", "Igor Pavlov", 3, 3), ("old-tool", "Old Tool", "Acme", 0, 2)):
            db.add(CatalogProduct(source_id=sid, key=key, name=name, publisher=pub, publisher_key=pub.lower(), origin="builtin", component=False, platforms=1, names=[[name, hall]],
                                  versions=[{"version": "120.0", "branch": "120", "scheme": "numeric", "platform": 1, "installs": hall, "installs_active": ha, "hosts": hall,
                                             "hosts_active": ha, "product_ids": [1, 2], "raw": ["120.0"], "names": [name]}],
                                  branches=[{"branch": "120", "installs": hall, "installs_active": ha, "hosts": hall, "hosts_active": ha, "versions": ["120.0"]}],
                                  versions_count=1, latest_version="120.0", scheme="numeric", hosts_all=hall, hosts_active=ha, installs_all=hall, installs_active=ha,
                                  search=f"{name} {pub} {key}".lower(), built_at=utcnow()))
        await db.commit()


async def test_catalog_query_and_overrides(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    src = await _source(client)
    await client.post("/api/v1/auth/source", json={"source_id": src["id"]})
    await _seed_catalog(app, src["id"])
    r = (await client.get("/api/v1/catalog")).json()
    assert [i["key"] for i in r["items"]] == ["google-chrome", "7-zip"] and r["items"][0]["hidden_hosts"] == 5 and r["state"]["status"] == "ready"
    r = (await client.get("/api/v1/catalog", params={"all_hosts": True})).json()
    assert {i["key"] for i in r["items"]} == {"google-chrome", "7-zip", "old-tool"}
    assert (await client.get("/api/v1/catalog", params={"q": "chrome"})).json()["total"] == 1
    p = (await client.get("/api/v1/catalog/products/google-chrome")).json()
    assert p["versions"][0]["version"] == "120.0" and p["builtin"]
    assert (await client.get("/api/v1/catalog/publishers")).json()["items"][0]["publisher"] == "Google"
    s = (await client.get("/api/v1/catalog/search", params={"q": "zip"})).json()["items"]
    assert s[0]["key"] == "7-zip"
    o = await client.post("/api/v1/catalog/overrides", json={"kind": "split", "from_key": "google-chrome", "match_names": ["Google Chrome Beta"], "to_name": "Chrome Beta"})
    assert o.status_code == 201 and o.json()["items"][0]["to_key"] == "manual:chrome-beta"
    assert (await client.post("/api/v1/catalog/overrides", json={"kind": "merge", "from_key": "a", "to_key": "a"})).status_code == 422
    assert len((await client.get("/api/v1/catalog/overrides")).json()["items"]) == 1
    assert (await client.post("/api/v1/catalog/rebuild")).json()["requested_at"]


async def test_saved_checks_and_audit_reports(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    src = await _source(client)
    src2 = (await client.post("/api/v1/admin/sources", json={"name": "KSC-B", "host": "b.example.local", "database": "KAV", "username": "u", "password": "p"})).json()
    await client.post("/api/v1/auth/source", json={"source_id": src["id"]})
    params = {"items": [{"product_key": "google-chrome", "product_name": "Google Chrome", "op": "lt", "value": "130", "target_version": "130.0.6723.58"},
                        {"product_key": "7-zip", "op": "lt", "value": "24.07"}]}
    bad = await client.post("/api/v1/reports", json={"kind": "version_audit", "params": {"items": [{"product_key": "x", "op": "lt"}]}})
    assert bad.status_code == 422 and "версию" in bad.text
    r = await client.post("/api/v1/reports", json={"kind": "version_audit", "params": params, "source_ids": [src["id"], src2["id"]]})
    assert r.status_code == 201, r.text
    job = r.json()
    assert job["source_ids"] == [src["id"], src2["id"]] and job["source_name"] == "KSC-A, KSC-B" and job["title"].startswith("Проверка версий: Google Chrome")
    assert job["params"]["active_days"] == 30
    assert any(j["id"] == job["id"] for j in (await client.get("/api/v1/reports")).json()["items"])
    c = await client.post("/api/v1/checks", json={"name": "Браузеры", "params": params, "source_ids": [src["id"], src2["id"]]})
    assert c.status_code == 201
    chk = c.json()
    assert chk["source_names"] == ["KSC-A", "KSC-B"] and chk["params"]["items"][0]["value"] == "130"
    run = await client.post(f"/api/v1/checks/{chk['id']}/run")
    assert run.status_code == 201 and run.json()["kind"] == "version_audit" and run.json()["title"] == "Браузеры"
    lst = (await client.get("/api/v1/checks")).json()["items"]
    assert lst[0]["last_job_id"] == run.json()["id"]
    up = await client.put(f"/api/v1/checks/{chk['id']}", json={"name": "Браузеры и архиваторы", "params": params, "source_ids": [src["id"]]})
    assert up.json()["source_ids"] == [src["id"]]
    assert (await client.delete(f"/api/v1/checks/{chk['id']}")).status_code == 204


async def test_user_source_remembered(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    await _source(client)
    s2 = (await client.post("/api/v1/admin/sources", json={"name": "KSC-B", "host": "b.example.local", "database": "KAV", "username": "u", "password": "p"})).json()
    await client.post("/api/v1/auth/source", json={"source_id": s2["id"]})
    await client.post("/api/v1/auth/logout")
    client.headers.pop("X-CSRF-Token", None)
    me = await login(client, "admin", "Admin-Passw0rd-123")
    assert me["current_source_id"] == s2["id"]           # следующий вход открывает последний выбранный источник
    _ = KscSource
