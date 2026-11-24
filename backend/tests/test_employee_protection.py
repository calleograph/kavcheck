"""Серверный отбор, очередь и права аналитики защиты сотрудников."""
import uuid
from datetime import timedelta

from app.employee_protection import service, sources
from app.models import AuditLog, EmployeeWorkplaceDecision, InvAsset, InvHistory, InvPerson, InvRef, ReportJob, User, utcnow
from sqlalchemy import func, select
from app.services.local_admin import create_local
from tests.conftest import login

URL = "/api/v1/employee-protection"
KIND = "quick_employee_protection"


async def test_snapshot_deduplicates_devices_and_reuses_report_selection(client, app, monkeypatch):
    await login(client, "admin", "Admin-Passw0rd-123")
    assert (await client.get(f"{URL}/summary")).json()["ready"] is False
    assert (await client.post(f"{URL}/refresh")).json() == {"queued": True}
    assert (await client.get(f"{URL}/summary")).json()["running"] is True
    assert (await client.post(f"{URL}/refresh")).json() == {"queued": False}
    a, b, c, d = [uuid.uuid4().hex for _ in range(4)]
    first, second = str(uuid.uuid4()), str(uuid.uuid4())
    connected = utcnow() - timedelta(hours=1)
    async with app.state.session_maker() as db:
        asset = InvAsset(inv_no="EXAMPLE-1", cls="workstation", name="Тестовый компьютер")
        person = InvPerson(name="Delta", email="delta@example.local")
        dept = InvRef(kind="dept", name="Ops")
        db.add_all([asset, person, dept])
        await db.flush()
        aid, uid, did = asset.id, person.id, dept.id
        await db.commit()

    async def people(_db, now):
        return [{"id": pid, "name": name, "department": dep, "organization": "Example",
                 "login": f"{name.lower()}@example.local", "email": f"{name.lower()}@example.local"}
                for pid, name, dep in ((a, "Alpha", "Dev"), (b, "Bravo", "Dev"), (c, "Charlie", "Ops"), (d, "Delta", "Ops"))], {
                    "ready": True, "census_at": now, "census_source": "Аудит AD", "warnings": []}

    async def devices(_db, _ids, _people, now, *, manual):
        protected = {"last_connected": connected, "av": {"has_rtp": True, "state": 3, "bases": now}, "rtp_state": 4}
        absent = {"last_connected": connected, "mask": 32}
        shared = {"id": "first:1", "host_id": 1, "source_id": first, "name": "shared-example", "os": "Linux", "kind": "Ноутбук",
                  "ownership": "corporate", "last_connected": connected, "snapshot_at": now, "protection": protected}
        yield shared, {a: {"confidence": "confirmed", "evidence": ["Учёт", "Учёт"]},
                       b: {"confidence": "likely", "evidence": ["Наблюдение KSC"]},
                       c: {"confidence": "possible", "evidence": ["Наблюдение KSC"]}}
        yield {"id": "inventory:1", "name": "personal-example", "os": "Windows", "ownership": "personal"}, {
            a: {"confidence": "confirmed", "evidence": ["Учёт"]}}
        yield {**shared, "id": "second:1", "asset_id": aid, "source_id": second, "name": "unprotected-example", "protection": absent}, {
            d: {"confidence": "confirmed", "evidence": ["Учёт"]}}

    monkeypatch.setattr(sources, "employees", people)
    monkeypatch.setattr(sources, "devices", devices)
    await service.tick(app.state.session_maker, app.state.settings_svc, app.state.journal)
    summary = (await client.get(f"{URL}/summary")).json()
    assert summary["ready"] and not summary["running"], summary
    assert summary["totals"] == {"employees": 4, "uses_av": 2, "protected": 1, "partial": 1, "no_av": 1, "insufficient": 1,
                                 "devices": 3, "corporate": 2, "personal": 1}
    employees = (await client.get(f"{URL}/employees")).json()
    assert {p["id"]: p["status"] for p in employees["items"]} == {a: "partial", b: "protected", c: "no_devices", d: "no_av"}
    pending = next(p for p in employees["items"] if p["id"] == c)
    assert pending["reason"] == "workplace_review" and pending["pending_device_count"] == 1
    devices = (await client.get(f"{URL}/devices", params={"employee_id": a, "os": "Linux", "limit": 1})).json()
    assert devices["total"] == 1 and devices["items"][0]["shared_count"] == 3
    assert devices["items"][0]["employees"] == [{"id": a, "login": "alpha@example.local", "name": "Alpha", "evidence": ["Учёт"]}]
    assert (await client.get(f"{URL}/employees", params={"ownership": "corporate", "employee_id": a})).json()["items"][0]["status"] == "partial"
    assert (await client.get(f"{URL}/employees", params={"q": "personal-example"})).json()["total"] == 1
    header = {"X-Source-Id": str(uuid.uuid4())}
    body = {"kind": KIND, "params": {"view": "devices", "employee_id": a, "os": "Linux"}}
    preview = await client.post("/api/v1/quick/preview", json=body, headers=header)
    assert preview.status_code == 200, preview.text
    assert preview.json()["total"] == 1 and preview.json()["items"][0]["users"] == "Alpha"
    summary_report = await client.post("/api/v1/quick/preview", json={"kind": KIND, "params": {"view": "employees", "detail": "summary", "department": "Dev"}})
    assert summary_report.status_code == 200, summary_report.text
    doc = summary_report.json()
    assert [table["id"] for table in doc["doc"]["tables"]] == ["statuses", "departments", "systems", "summary"]
    assert {row["id"]: row["count"] for row in doc["items"] if row["count"]} == {"protected": 1, "partial": 1}
    job = await client.post("/api/v1/reports", json=body, headers=header)
    assert job.status_code == 201, job.text
    async with app.state.session_maker() as db:
        stored = await db.get(ReportJob, uuid.UUID(job.json()["id"]))
        assert stored.source_id is None and stored.source_name == "Защита сотрудников" and stored.params["employee_id"] == a

    workplaces = (await client.get(f"{URL}/workplaces", params={"confidence": "possible"})).json()
    assert workplaces["total"] == 1 and workplaces["items"][0]["employee"]["id"] == c
    chosen = f"{c}|first:1"
    preview = await client.post("/api/v1/quick/preview", json={"kind": KIND, "params": {"view": "workplaces", "pairs": [chosen]}})
    assert preview.status_code == 200, preview.text
    assert preview.json()["total"] == 1 and preview.json()["items"][0]["employee"] == "Charlie"
    decision = {"generation": workplaces["generation"], "items": [
        {"employee_id": c, "device_id": "first:1", "decision": "confirmed"},
        {"employee_id": b, "device_id": "first:1", "decision": "rejected"}], "comment": "Проверено"}
    assert (await client.post(f"{URL}/workplaces/decide", json=decision)).json() == {"changed": 2}
    assert (await client.get(f"{URL}/workplaces")).json()["pending"]
    await service.tick(app.state.session_maker, app.state.settings_svc, app.state.journal)
    assert (await client.post(f"{URL}/workplaces/decide", json=decision)).status_code == 409
    employees = (await client.get(f"{URL}/employees")).json()
    assert {p["id"]: p["status"] for p in employees["items"]} == {a: "partial", b: "no_devices", c: "protected", d: "no_av"}
    report = (await client.get(f"{URL}/workplaces", params={"inventory": True, "asset_id": aid})).json()
    assert report["total"] == 1
    row = report["items"][0]
    assert {k: v["id"] for k, v in row["proposals"].items()} == {"user_id": uid, "dept_id": did}
    proposal = {"generation": report["generation"], "items": [
        {"pair": row["id"], "version": row["asset_version"], "values": {"user_id": uid, "dept_id": did}}]}
    tampered = {**proposal, "items": [{**proposal["items"][0], "values": {"user_id": uid + 1}}]}
    assert (await client.post(f"{URL}/workplaces/apply", json=tampered)).status_code == 409
    assert (await client.post(f"{URL}/workplaces/apply", json=proposal)).json() == {"changed": 1}
    assert (await client.post(f"{URL}/workplaces/apply", json=proposal)).status_code == 409
    async with app.state.session_maker() as db:
        assert (await db.get(EmployeeWorkplaceDecision, (c, "first:1"))).decision == "confirmed"
        assert await db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "employee_protection.workplace")) == 2
        asset = await db.get(InvAsset, aid)
        assert (asset.user_id, asset.dept_id, asset.owner_id, asset.mol_id) == (uid, did, None, None)
        assert await db.scalar(select(func.count()).select_from(InvHistory).where(InvHistory.asset_id == aid)) == 1


async def test_dashboard_and_reports_recheck_permissions(client, app):
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get(f"{URL}/access")).json()["allowed"] is False
    assert (await client.get(f"{URL}/summary")).status_code == 403
    assert (await client.get(f"{URL}/workplaces")).status_code == 403
    assert (await client.post(f"{URL}/refresh")).status_code == 403
    assert (await client.post("/api/v1/quick/preview", json={"kind": KIND, "params": {}})).status_code == 403
    async with app.state.session_maker() as db:
        user = await create_local(db, "security", "Security-Passw0rd-123", role="security", must_change=False)
        user.all_sources = True
        report = ReportJob(kind=KIND, title="Срез защиты", params={}, source_name="", created_by_id=user.id)
        db.add(report)
        await db.commit()
        pid, rid = user.id, report.id
    await login(client, "security", "Security-Passw0rd-123")
    assert (await client.get(f"{URL}/access")).json() == {"allowed": True, "can_refresh": False}
    assert (await client.get(f"/api/v1/reports/{rid}")).status_code == 200
    async with app.state.session_maker() as db:
        (await db.get(User, pid)).all_sources = False
        await db.commit()
    assert (await client.get(f"{URL}/summary")).status_code == 403
    assert (await client.get(f"/api/v1/reports/{rid}")).status_code == 404
    assert (await client.get("/api/v1/reports")).json()["items"] == []
