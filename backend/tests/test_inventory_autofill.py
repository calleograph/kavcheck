"""Автозаполнение проверяется только на обезличенных наблюдениях."""
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import select

from app.employee_protection import service
from app.inventory import autofill
from app.models import (AppSetting, AuditLog, EmployeeProtectionDevice, EmployeeProtectionLink, EmployeeProtectionPerson,
                        InvAsset, InvDoc, InvDocItem, InvGeo, InvGeoRule, InvHistory, InvLocation, InvPerson, InvRef, KscSource, utcnow)
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
    assert preview.status_code == 200 and preview.json()["total"] == 4
