"""Портал ответственных за зоны: доменный пользователь, назначенный зоне (учётная запись или группа AD), видит только свои зоны и строит отчёты по ним.
Изоляция — на сервере: остальные разделы, источники KSC, чужие зоны и чужие отчёты недоступны; снятие доступа действует сразу."""
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, update

from app.models import ReportJob, User, ZcSource, ZoneAccess
from tests.conftest import login
from tests.test_audit_e2e import _run
from tests.test_ksc_live import HOST
from tests.test_zones_live import dash, setup

pytestmark = pytest.mark.skipif(not HOST, reason="нет синтетической базы KSC (KSC_TEST_HOST)")
PW = "Owner-Passw0rd-777"


async def _owner(app, client, *, access=None, email="owner@example.local"):
    """Пользователь с ролью «zone» (в работе роль назначается при входе через каталог; здесь — локальная учётная запись с той же ролью) и отдельный клиент для него."""
    r = await client.post("/api/v1/admin/users", json={"username": "owner1", "display_name": "Ответственный", "email": email, "role": "viewer", "password": PW})
    assert r.status_code == 201, r.text
    async with app.state.session_maker() as db:
        u = (await db.execute(select(User).where(User.username == "owner1"))).scalar_one()
        u.role, u.email, u.must_change_password, u.ldap_groups = "zone", email, False, ["cn=srv-owners,ou=groups,dc=example,dc=local"]
        for zid, kind, value in access or []:
            db.add(ZoneAccess(zone_id=uuid.UUID(zid), kind=kind, value=value, label=value))
        await db.commit()
    oc = AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")
    await login(oc, "owner1", PW)
    return oc


async def test_owner_sees_only_own_zone_and_nothing_else(client, app):
    sid, _runner, z_srv, z_arm = await setup(client, app)
    oc = await _owner(app, client, access=[(z_srv, "group", "cn=srv-owners,ou=groups,dc=example,dc=local")])
    try:
        me = (await oc.get("/api/v1/auth/me")).json()
        assert me["user"]["role"] == "zone"
        ov = (await oc.get("/api/v1/zones")).json()
        assert [r["id"] for r in ov["items"]] == [z_srv] and ov["sources"] == [] and ov["totals"]["unassigned"] == 0          # только своя зона, без итогов инфраструктуры
        own = await dash(oc, z_srv, activity="all")
        assert own["stats"]["total"] == 4
        async with app.state.session_maker() as db:                                                                       # технические причины (тексты ошибок SQL) ответственному не показываются
            await db.execute(update(ZcSource).values(notes=["Оборудование не прочитано (Ошибка запроса к базе KSC: tech-marker-77)"]))
            await db.commit()
        assert (await dash(client, z_srv, activity="all"))["notes"] and (await dash(oc, z_srv, activity="all"))["notes"] == []
        assert (await oc.get(f"/api/v1/zones/{z_arm}")).status_code == 404                                                 # чужая зона
        assert (await oc.get("/api/v1/zones/none")).status_code == 404                                                     # «без ответственного» — тоже чужое
        # компьютер своей зоны — да; компьютер чужой зоны (даже по адресу своей) — нет
        host = own["items"][0]
        assert (await oc.get(f"/api/v1/zones/{z_srv}/hosts/{host['source_id']}/{host['host_id']}")).status_code == 200
        foreign = (await dash(client, z_arm, activity="all"))["items"][0]
        assert (await oc.get(f"/api/v1/zones/{z_srv}/hosts/{foreign['source_id']}/{foreign['host_id']}")).status_code == 404
        # остальной интерфейс и инструменты — 403, источники не открываются
        for path in ("/api/v1/hosts", "/api/v1/vulnerabilities/list", "/api/v1/vdb/findings", "/api/v1/devices", "/api/v1/eol/summary", "/api/v1/triage", "/api/v1/admin/users",
                     "/api/v1/zones/options/list", f"/api/v1/zones/of-host/{sid}/1", "/api/v1/overview", "/api/v1/pentest/jobs"):
            r = await oc.get(path, headers={"X-Source-Id": sid})
            assert r.status_code == 403, (path, r.status_code)
        assert (await oc.get("/api/v1/auth/sources")).json().get("items", []) == []
        assert (await oc.post("/api/v1/auth/source", json={"source_id": sid})).status_code == 403
    finally:
        await oc.aclose()


async def test_owner_reports_are_own_zone_only_and_private(client, app, monkeypatch):
    _sid, runner, z_srv, z_arm = await setup(client, app)
    oc = await _owner(app, client, access=[(z_srv, "user", "owner1")])
    async with app.state.session_maker() as db:
        await db.execute(update(ZcSource).values(notes=["Оборудование не прочитано (Ошибка запроса к базе KSC: tech-marker-77)"]))
        await db.commit()
    try:
        pv = await oc.post("/api/v1/quick/preview", json={"kind": "quick_zone", "params": {"zone_ids": [z_srv], "refresh_data": True}})
        assert pv.status_code == 200, pv.text
        assert "tech-marker-77" not in pv.text                                                                               # технические примечания источников — не в отчёте портала
        assert (await oc.post("/api/v1/quick/preview", json={"kind": "quick_zone", "params": {"zone_ids": [z_arm]}})).status_code == 404
        assert (await oc.post("/api/v1/quick/preview", json={"kind": "quick_hosts", "params": {"host_ids": [1]}})).status_code == 403
        r = await oc.post("/api/v1/reports", json={"kind": "quick_zone", "title": "", "params": {"zone_ids": [z_srv], "refresh_data": True}, "source_ids": []})
        assert r.status_code == 201, r.text
        jid = r.json()["id"]
        async with app.state.session_maker() as db:
            j = await db.get(ReportJob, uuid.UUID(jid))
            assert j.params["refresh_data"] is False and j.params["_portal"] is True                                        # чтение KSC из портала не запускается
        assert (await oc.post("/api/v1/reports", json={"kind": "quick_zone", "title": "", "params": {"zone_ids": [z_arm]}, "source_ids": []})).status_code == 403
        assert (await oc.post("/api/v1/reports", json={"kind": "quick_protection", "title": "", "params": {}, "source_ids": []})).status_code == 403
        await _run(app, runner, jid)
        assert (await oc.get(f"/api/v1/reports/{jid}/download/xlsx")).status_code == 200
        # отчёт администратора по той же зоне ответственному не виден, его отчёт администратор видит
        adm = (await client.post("/api/v1/reports", json={"kind": "quick_zone", "title": "", "params": {"zone_ids": [z_srv]}, "source_ids": []})).json()["id"]
        assert (await oc.get(f"/api/v1/reports/{adm}")).status_code == 404
        assert [x["id"] for x in (await oc.get("/api/v1/reports")).json()["items"]] == [jid]
        # себе на почту — только на адрес своей учётной записи
        from app.services import mail
        sent = {}

        async def fake_send(cfg, msg, rcpts):
            sent["to"], sent["subject"] = rcpts, msg["Subject"]
            return mail.SendResult(True)
        monkeypatch.setattr(mail, "check_config", lambda cfg: None)
        monkeypatch.setattr(mail, "send", fake_send)
        m = await oc.post(f"/api/v1/reports/{jid}/mail", json={"formats": ["xlsx", "pdf"]})
        assert m.status_code == 200, m.text
        assert sent["to"] == ["owner@example.local"] and m.json()["to"] == "owner@example.local" and len(m.json()["files"]) == 2
    finally:
        await oc.aclose()


async def test_removing_access_takes_effect_immediately(client, app):
    _sid, _runner, z_srv, _z_arm = await setup(client, app)
    oc = await _owner(app, client, access=[(z_srv, "user", "owner1")])
    try:
        assert (await oc.get(f"/api/v1/zones/{z_srv}")).status_code == 200
        async with app.state.session_maker() as db:
            await db.execute(delete(ZoneAccess))
            await db.commit()
        r = await oc.get(f"/api/v1/zones/{z_srv}")
        assert r.status_code == 403 and r.json()["detail"]["code"] == "zone_portal_empty"
    finally:
        await oc.aclose()


async def test_admin_assigns_portal_access_in_the_zone_editor(client, app):
    _sid, _runner, z_srv, _z_arm = await setup(client, app)
    z = (await client.get(f"/api/v1/admin/zones/{z_srv}")).json()
    body = {k: z[k] for k in ("name", "description", "purpose", "priority", "activity_days", "enabled")}
    body |= {"rules": [{"kind": r["kind"], "value": r["value"], "note": r["note"]} for r in z["rules"]],
             "contacts": [{k: c[k] for k in ("name", "position", "email", "role", "enabled")} for c in z["contacts"]],
             "access": [{"kind": "user", "value": "EXAMPLE\\Petrov", "label": "Пётр Петров"}, {"kind": "group", "value": "CN=Srv-Owners,OU=Groups,DC=example,DC=local", "label": "Srv-Owners"}]}
    r = await client.put(f"/api/v1/admin/zones/{z_srv}", json=body)
    assert r.status_code == 200, r.text
    assert sorted((a["kind"], a["value"]) for a in r.json()["access"]) == [("group", "cn=srv-owners,ou=groups,dc=example,dc=local"), ("user", "example\\petrov")]
    bad = await client.put(f"/api/v1/admin/zones/{z_srv}", json={**body, "access": [{"kind": "group", "value": "Srv-Owners"}]})
    assert bad.status_code == 422 and "DN" in bad.text
    body.pop("access")                                                                                                   # без поля — доступ не меняется (CSV, старые клиенты)
    assert len((await client.put(f"/api/v1/admin/zones/{z_srv}", json=body)).json()["access"]) == 2
    from app.zones.portal import zones_for
    async with app.state.session_maker() as db:
        assert await zones_for(db, username="petrov", email="", groups=[]) == [z_srv]                                     # «DOMAIN\\логин» совпадает с логином
        assert await zones_for(db, username="someone", groups=["CN=Srv-Owners,OU=Groups,DC=example,DC=local"]) == [z_srv]
        assert await zones_for(db, username="someone", groups=["cn=other,dc=example,dc=local"]) == []
