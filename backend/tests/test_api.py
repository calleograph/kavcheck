import pytest

from tests.conftest import login


async def test_login_and_roles(client):
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401
    me = await login(client, "admin", "Admin-Passw0rd-123")
    assert me["user"]["role"] == "admin" and me["csrf_token"]
    r = await client.get("/api/v1/admin/users")
    assert r.status_code == 200 and len(r.json()["items"]) == 2
    # CSRF обязателен для изменяющих запросов
    bad = await client.post("/api/v1/admin/sources", json={}, headers={"X-CSRF-Token": "wrong"})
    assert bad.status_code == 403


async def test_viewer_cannot_admin_or_create_reports(client):
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get("/api/v1/admin/users")).status_code == 403
    assert (await client.post("/api/v1/reports", json={"kind": "hosts", "params": {}})).status_code == 403
    assert (await client.get("/api/v1/dashboard")).status_code == 409      # источник не выбран


async def test_login_throttle(client):
    for _ in range(10):
        r = await client.post("/api/v1/auth/login", json={"login": "admin", "password": "wrong-password"})
        assert r.status_code == 401
    r = await client.post("/api/v1/auth/login", json={"login": "admin", "password": "wrong-password"})
    assert r.status_code == 429


async def test_sources_crud_and_secret_not_returned(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    body = {"name": "KSC-01", "host": "sql.example.local", "port": 1433, "database": "KAV", "username": "kavcheck_ro", "password": "s3cret-value"}
    r = await client.post("/api/v1/admin/sources", json=body)
    assert r.status_code == 201, r.text
    src = r.json()
    assert src["password_set"] is True and "s3cret" not in r.text
    r = await client.get("/api/v1/auth/sources")
    assert [s["name"] for s in r.json()["items"]] == ["KSC-01"]
    r = await client.post("/api/v1/auth/source", json={"source_id": src["id"]})
    assert r.status_code == 200
    # пароль хранится зашифрованным и расшифровывается только внутри приложения
    from app.models import KscSource  # noqa: PLC0415

    async with app.state.session_maker() as db:
        row = await db.get(KscSource, __import__("uuid").UUID(src["id"]))
        assert row.password_enc and "s3cret" not in row.password_enc
        assert app.state.sources.params(row).password == "s3cret-value"
    # аудит записан
    r = await client.get("/api/v1/admin/audit")
    assert any(a["action"] == "source.create" for a in r.json()["items"])


async def test_settings_and_ldap_secret(client):
    await login(client, "admin", "Admin-Passw0rd-123")
    r = await client.put("/api/v1/admin/settings/general", json={"activity_days": 14})
    assert r.status_code == 200 and r.json()["activity_days"] == 14
    r = await client.put("/api/v1/admin/settings/ldap", json={"host": "dc1.example.local", "base_dn": "DC=example,DC=local", "bind_dn": "CN=svc,DC=example,DC=local", "bind_password": "pw"})
    assert r.status_code == 200 and r.json()["bind_password_set"] is True and "bind_password" not in r.json()
    r = await client.put("/api/v1/admin/settings/general", json={"activity_days": 0})
    assert r.status_code == 422


async def test_rules_seeded_and_validated(client):
    await login(client, "admin", "Admin-Passw0rd-123")
    r = await client.get("/api/v1/software/rules")
    assert [x["key"] for x in r.json()["items"]] == ["php"]
    r = await client.post("/api/v1/admin/rules", json={"key": "bad", "name": "Bad", "name_like": "%x%", "name_regex": "("})
    assert r.status_code == 422


async def test_user_source_access(client):
    await login(client, "admin", "Admin-Passw0rd-123")
    s1 = (await client.post("/api/v1/admin/sources", json={"name": "A", "host": "a.example.local", "database": "KAV", "username": "u", "password": "p"})).json()
    s2 = (await client.post("/api/v1/admin/sources", json={"name": "B", "host": "b.example.local", "database": "KAV", "username": "u", "password": "p"})).json()
    r = await client.post("/api/v1/admin/users", json={"username": "analyst1", "role": "analyst", "password": "Analyst-Passw0rd-1", "all_sources": False, "source_ids": [s2["id"]], "must_change_password": False})
    assert r.status_code == 201, r.text
    await login(client, "analyst1", "Analyst-Passw0rd-1")
    items = (await client.get("/api/v1/auth/sources")).json()["items"]
    assert [s["name"] for s in items] == ["B"]
    assert (await client.post("/api/v1/auth/source", json={"source_id": s1["id"]})).status_code == 403


@pytest.mark.parametrize("path", ["/api/v1/health/live", "/api/v1/health/ready", "/api/v1/version"])
async def test_health(client, path):
    assert (await client.get(path)).status_code == 200


async def test_system_status_exposes_background_jobs(client):
    await login(client, "admin", "Admin-Passw0rd-123")
    r = await client.get("/api/v1/admin/system")
    assert r.status_code == 200
    j = r.json()["jobs"]
    assert set(j) >= {"worker", "sources", "reports"} and "failed_24h" in j["reports"] and j["worker"]["active"] == []
