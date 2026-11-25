"""Автозаполнение проверяется только на обезличенных наблюдениях."""
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import select

from app.employee_protection import service
from app.inventory import autofill, model
from app.models import (AppSetting, AuditLog, EmployeeProtectionDevice, EmployeeProtectionLink, EmployeeProtectionPerson,
                        InvAsset, InvDoc, InvDocItem, InvGeo, InvGeoRule, InvHistory, InvLocation, InvPerson, InvRef, KscSource,
                        ZcHost, ZcSource, Zone, ZonePin, ZoneRule, utcnow)
from tests.conftest import login


async def test_autofill_is_opt_in_and_preserves_existing_fields_and_documents(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    url = "/api/v1/inv/auto-fill"
    assert (await client.get(url)).json()["fields"] == []
    gen, sid, now = uuid4(), uuid4(), utcnow()
    sm, svc, journal = app.state.session_maker, app.state.settings_svc, app.state.journal
    async with sm() as db:
        source = KscSource(id=sid, name="Тестовый KSC", host="ksc.example.local", database="KAV", username="ro")
        site = InvLocation(name="Кабинет", kind="room", path="Кабинет")
        old, proposed = InvRef(kind="dept", name="Ручной отдел"), InvRef(kind="dept", name="Отдел по правилу")
        person = InvPerson(name="Пользователь", email="employee@example.local")
        db.add_all([source, site, old, proposed, person])
        await db.flush()
        cards = [InvAsset(inv_no=f"TEST-{n}", cls="workstation", st_cls="use", ksc_source_id=sid, ksc_host_id=n,
                          ksc_link="auto" if n == 3 else "confirmed", dept_id=old.id if n == 1 else None)
                 for n in range(1, 6)]
        db.add_all(cards)
        await db.flush()
        doc = InvDoc(no="TEST-MOVE", kind="move", status="draft", doc_date=now.date())
        db.add(doc)
        await db.flush()
        db.add(InvDocItem(doc_id=doc.id, asset_id=cards[3].id))
        db.add(InvGeoRule(data={"name": "Локальная площадка", "networks": ["192.0.2.0/24"], "location_id": site.id, "dept_id": proposed.id}))
        for index, card in enumerate(cards):
            stamp = now - timedelta(days=20) if index == 1 else now
            addr = "198.51.100.5" if index == 4 else "192.0.2.5"
            db.add(InvGeo(asset_id=card.id, source_id=sid, host_id=card.ksc_host_id, checked_at=now, observed_at=stamp,
                          evidence={"addresses": [{"kind": "device", "ip": addr}]},
                          result={"status": "approx", "lat": 50.0, "lon": 10.0}))
        db.add(AppSetting(group=service.STATE, value={"ready": True, "generation": str(gen), "built_at": now.isoformat(),
                                                      "census_at": now.isoformat(), "inputs": {"policy": service.POLICY_VERSION}}))
        db.add(EmployeeProtectionPerson(generation=gen, id="employee", search="employee",
                                        data={"id": "employee", "name": "Пользователь", "email": person.email, "email_verified": True}))
        for card, confidence in ((cards[0], "confirmed"), (cards[-1], "likely")):
            did = f"ksc:{sid}:{card.ksc_host_id}"
            db.add(EmployeeProtectionDevice(generation=gen, id=did, search="computer", zone_keys="",
                                            data={"id": did, "name": "Тестовый компьютер", "asset_id": card.id, "source_id": str(sid),
                                                  "host_id": card.ksc_host_id, "shared_count": 1}))
            db.add(EmployeeProtectionLink(generation=gen, person_id="employee", device_id=did, evidence=[],
                                          assessment={"confidence": confidence}))
        await db.commit()
        ids, uid, manual_department, loc = [a.id for a in cards], person.id, old.id, site.id

    await autofill.tick(sm, svc, journal)
    assert (await client.get(url)).json()["pending"] is False
    enabled = await client.put("/api/v1/admin/settings/inventory", json={"auto_fill_fields": ["user_id", "location_id", "dept_id"]})
    assert enabled.status_code == 200, enabled.text
    assert (await client.get(url)).json()["pending"] is True
    await autofill.tick(sm, svc, journal)
    status = (await client.get(url)).json()
    assert not status["error"] and status["checked"] == 3 and status["changed"] == 1
    assert status["by_field"] == {"location_id": 1, "user_id": 1}
    async with sm() as db:
        rows = (await db.scalars(select(InvAsset).where(InvAsset.id.in_(ids)).order_by(InvAsset.id))).all()
        assert (rows[0].user_id, rows[0].location_id, rows[0].dept_id, rows[0].mol_id) == (uid, loc, manual_department, None)
        assert all(a.user_id is None and a.location_id is None for a in rows[1:])
        assert len((await db.scalars(select(InvHistory))).all()) == 1
        assert await db.scalar(select(AuditLog.id).where(AuditLog.action == "inv.auto_fill"))
    assert (await client.post(f"{url}/refresh")).json()["queued"] is True
    await autofill.tick(sm, svc, journal)
    assert (await client.get(url)).json()["changed"] == 0
    preview = await client.post("/api/v1/quick/preview", json={"kind": "quick_admin", "params": {"view": "inv_auto_fill"}})
    assert preview.status_code == 200 and preview.json()["total"] == len(model.AUTO_FILL_FIELDS)


async def test_assignment_zone_and_branch_flow_to_empty_cards(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    sm, svc, journal = app.state.session_maker, app.state.settings_svc, app.state.journal
    gen, sid, now = uuid4(), uuid4(), utcnow()
    async with sm() as db:
        db.add(KscSource(id=sid, name="Источник", host="ksc.example.local", database="KAV", username="ro"))
        person = InvPerson(name="Сотрудник", login=r"example.local\employee")
        branch = InvRef(kind="branch", name="Филиал")
        first, second = Zone(name="Первая зона"), Zone(name="Вторая зона")
        db.add_all([person, branch, first, second])
        await db.flush()
        db.add(ZcSource(source_id=sid, gen=1, built_at=now))
        db.add_all([ZoneRule(zone_id=first.id, kind="name", value="fixture-*"),
                    ZoneRule(zone_id=second.id, kind="name", value="fixture-conflict")])
        cards = [InvAsset(inv_no=f"AUTO-{h}", cls="workstation", st_cls="use", ksc_source_id=sid, ksc_host_id=h, ksc_link="confirmed")
                 for h in (1, 2, 3, 4)]
        db.add_all(cards)
        await db.flush()
        for n, name in enumerate(("fixture-matched", "fixture-conflict", "fixture-rule-mismatch", "fixture-manual"), 1):
            db.add(ZcHost(source_id=sid, host_id=n, gen=1, name=name))
        db.add(ZonePin(source_id=sid, host_id=4, zone_id=second.id))
        db.add(InvGeoRule(data={"name": "Филиал по сети", "networks": ["192.0.2.0/24"], "branch_id": branch.id}))
        db.add(InvGeoRule(data={"name": "Противоречащая зона", "networks": ["198.51.100.0/24"], "zone_id": str(second.id)}))
        for a, ip in ((cards[0], "192.0.2.5"), (cards[2], "198.51.100.5")):
            db.add(InvGeo(asset_id=a.id, source_id=sid, host_id=a.ksc_host_id, observed_at=now, checked_at=now,
                          evidence={"addresses": [{"kind": "device", "ip": ip}]}, result={}))
        db.add(AppSetting(group=service.STATE, value={"ready": True, "generation": str(gen), "built_at": now.isoformat(),
                                                      "census_at": now.isoformat(), "inputs": {"policy": service.POLICY_VERSION}}))
        db.add(EmployeeProtectionPerson(generation=gen, id="employee", search="employee",
                                        data={"id": "employee", "name": "Сотрудник", "login": "employee@example.local", "login_verified": True}))
        for card, stamp in ((cards[0], now), (cards[2], now - timedelta(days=4))):
            did = f"ksc:{sid}:{card.ksc_host_id}"
            db.add(EmployeeProtectionDevice(generation=gen, id=did, search="computer", zone_keys="",
                                            data={"id": did, "name": "Компьютер", "asset_id": card.id, "source_id": str(sid), "host_id": card.ksc_host_id,
                                                  "snapshot_at": now.isoformat(), "last_connected": now.isoformat(),
                                                  "shared_count": 2, "assignment": {"employee_id": "employee", "basis": "observed"}}))
            db.add(EmployeeProtectionLink(generation=gen, person_id="employee", device_id=did, evidence=[],
                                          assessment={"confidence": "likely", "assignment_basis": "observed", "last_verified_at": stamp.isoformat()}))
        await db.commit()
        ids, uid, fid, z1, z2 = [a.id for a in cards], person.id, branch.id, first.id, second.id

    response = await client.get("/api/v1/employee-protection/workplaces", params={"assignment": "observed"})
    assert response.status_code == 200, response.text
    items = {item["device"]["asset_id"]: item for item in response.json()["items"]}
    assert {key: value["id"] for key, value in items[ids[0]]["proposals"].items()} == {"user_id": uid, "branch_id": fid, "zone_id": str(z1)}
    assert items[ids[2]]["proposals"] == {}
    apply = {"generation": str(gen), "items": [{"pair": items[ids[0]]["id"], "version": items[ids[0]]["asset_version"], "values": {"zone_id": str(z2)}}]}
    assert (await client.post("/api/v1/employee-protection/workplaces/apply", json=apply)).status_code == 409
    config = await client.put("/api/v1/admin/settings/inventory", json={"auto_fill_fields": ["user_id", "zone_id", "branch_id"]})
    assert config.status_code == 200, config.text
    await autofill.tick(sm, svc, journal)
    async with sm() as db:
        cards = list(await db.scalars(select(InvAsset).where(InvAsset.id.in_(ids)).order_by(InvAsset.id)))
        assert [(a.user_id, a.branch_id, a.zone_id) for a in cards] == [(uid, fid, z1), (None, None, None), (None, None, None), (None, None, z2)]
        events = list(await db.scalars(select(InvHistory).order_by(InvHistory.asset_id)))
        assert {change["f"] for change in events[0].changes} == {"user_id", "branch_id", "zone_id"}
        assert {change["f"] for change in events[1].changes} == {"zone_id"}
