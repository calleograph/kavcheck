from datetime import datetime, timedelta, timezone
from time import perf_counter
from uuid import uuid4

import pytest
from sqlalchemy import insert

from app.bi.match import RULE
from app.devices import users as ksc_users
from app.employee_protection import service
from app.employee_protection.sources import BI_ASSIGNMENT, INVENTORY_OWNER, INVENTORY_USER, devices, employees
from app.employee_protection.workplace import (CURRENT_SESSION, EXACT_ACCOUNT, HISTORY, OBSERVED_ASSIGNMENT, REGULAR, SERVER,
                                               SESSION, SHARED, SHORT_ACCOUNT, UNVERIFIED_ACCOUNT)
from app.models import (AdAuditAccount, AdAuditRun, BiDevice, BiMatch, BiOwner, BiPerson, BiSource, DevicesState, DeviceSession, DeviceUser, HierSnapshot,
                        EmployeeWorkplaceDecision, InvAsset, InvPerson, KscSource, LdapConnection, ZcHost, ZcHostZone, ZcSource, Zone, utcnow)
from tests.conftest import login
from tests.test_devices import FakeUsers, vrow

NOW = datetime(2026, 11, 24, tzinfo=timezone.utc)


def account(run, key, **data):
    values = {"run_id": run, "guid": key, "name": key.upper(), "login": key, "upn": f"{key}@example.local",
              "mail": f"{key}@example.local", "dn": f"CN={key},OU=Accounting,DC=example,DC=local", "ou": "Accounting"}
    return AdAuditAccount(**(values | data))


@pytest.mark.asyncio
async def test_employee_roster_excludes_non_staff_and_does_not_guess_people(app):
    async with app.state.session_maker() as db:
        run = AdAuditRun(id=uuid4(), started_at=NOW - timedelta(days=2), finished_at=NOW - timedelta(days=1), status="ok")
        db.add(run)
        await db.flush()
        db.add_all([LdapConnection(name="Directory", host="dc.example.local", base_dn="DC=example,DC=local", netbios="example"),
                    account(run.id, "alpha", department="Operations"), account(run.id, "alpha"), account(run.id, "bravo"),
                    account(run.id, "charlie", enabled=False, mail="bravo@example.local"), account(run.id, "delta", category="service"),
                    account(run.id, "other-bravo", login="bravo", upn="bravo@other.example.local", enabled=False,
                            dn="CN=bravo,DC=other,DC=example,DC=local"),
                    account(run.id, "echo", spn=True), account(run.id, "test-check"), account(run.id, "foxtrot", expires=NOW),
                    HierSnapshot(status="ok", source="ldap", started_at=NOW - timedelta(days=1), finished_at=NOW,
                                 records=[["ALPHA", "alpha@example.local", "Specialist", "HR", "Example company", "", "", ""],
                                          ["BRAVO", "bravo@example.local", "Specialist", "HR", "Example company", "", "", ""]])])
        await db.commit()
        people, meta = await employees(db, NOW)
        assert meta["ready"] and meta["excluded_accounts"] == 6
        assert [p["id"] for p in people] == ["alpha", "bravo"]
        assert people[0]["organization"] == "Example company" and people[0]["department"] == "Operations"
        assert people[0]["division"] == "Accounting" and people[0]["title"] == "Specialist"
        assert people[0]["_logins"] == ["alpha@example", "alpha@example.local"]
        assert people[0]["_short_logins"] == ["alpha"] and people[1]["_short_logins"] == []
        assert people[1]["_logins"] == ["bravo@example", "bravo@example.local"]
        assert people[1]["organization"] == "" and people[1]["_emails"] == []
        _, stale = await employees(db, NOW + timedelta(days=46))
        assert not stale["ready"]


@pytest.mark.asyncio
async def test_verified_session_counts_immediately_only_on_fresh_single_workstation(client, app, monkeypatch):
    await login(client, "admin", "Admin-Passw0rd-123")
    sm = app.state.session_maker
    now = utcnow() - timedelta(minutes=2)
    ids = ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel")
    async with sm() as db:
        run = AdAuditRun(id=uuid4(), started_at=now, finished_at=now, status="ok")
        source = KscSource(id=uuid4(), name="Example KSC", host="ksc.example.local", database="test", username="test")
        no_poll = KscSource(id=uuid4(), name="Waiting KSC", host="waiting.example.local", database="test", username="test")
        db.add_all([run, source, no_poll, LdapConnection(name="Directory", host="dc.example.local",
                                                       base_dn="DC=example,DC=local", netbios="example")])
        await db.flush()
        sid = source.id
        db.add_all([account(run.id, key) for key in ids[1:]] + [account(run.id, "alpha", upn="a.person@staff.example.local")])
        db.add(ZcSource(source_id=sid, gen=1, built_at=now))
        for hid in range(1, 10):
            os = "Windows Server 2025" if hid == 3 else "Microsoft Windows 11"
            last_connected = now - timedelta(days=4) if hid == 8 else now
            av = None if hid == 7 else {"product": "Kaspersky", "has_rtp": True, "state": 3, "bases": now.isoformat()}
            db.add(ZcHost(source_id=sid, gen=1, host_id=hid, name=f"WS-{hid}", os=os,
                          data={"os": os, "last_connected": last_connected.isoformat(), "av": av, "rtp_state": 4}))
        await db.commit()

    upn_only = {**vrow(1, 1, "", True, "a.person@staff.example.local"), "user_id": 1}
    windows_local = {**vrow(7, 6, "foxtrot", True, "foxtrot@example.local"), "local_host": 6}
    observed = FakeUsers([upn_only, vrow(2, 2, "EXAMPLE\\bravo", True), vrow(3, 2, "alpha", True, "a.person@staff.example.local"),
                          vrow(4, 3, "charlie", True, "charlie@example.local"), vrow(5, 4, "delta", False, "delta@example.local"),
                          vrow(6, 5, "FOREIGN\\echo", True), windows_local, vrow(8, 7, "UNCONFIGURED\\golf", True, "golf@example.local"),
                          vrow(9, 8, "hotel", True, "hotel@example.local"), vrow(10, 9, "EXAMPLE\\echo", True, "foxtrot@example.local")])
    monkeypatch.setattr(ksc_users, "utcnow", lambda: now)
    await ksc_users.poll_source(sm, observed, source, [])
    await service.tick(sm, app.state.settings_svc, app.state.journal)

    summary = (await client.get("/api/v1/employee-protection/summary")).json()
    assert summary["ready"] and summary["totals"]["devices"] == 2 and summary["totals"]["protected"] == 1
    assert summary["totals"]["uses_av"] == 1 and summary["totals"]["no_av"] == 0
    rows = (await client.get("/api/v1/employee-protection/workplaces")).json()["items"]
    by_pair = {(r["employee"]["id"], r["device"]["host_id"]): r for r in rows}
    row = by_pair["alpha", 1]
    assert row["confidence"] == "likely" and row["current_session"] and not row["regular"] and row["counted"] and not row["primary"]
    assert CURRENT_SESSION in row["evidence"]
    for pair in (("alpha", 2), ("bravo", 2), ("charlie", 3), ("delta", 4), ("hotel", 8)):
        row = by_pair[pair]
        assert row["confidence"] == "possible" and not row["counted"] and not row["primary"]
    assert SHARED in by_pair["bravo", 2]["evidence"] and SERVER in by_pair["charlie", 3]["evidence"]
    assert not {pid for pid, _ in by_pair} & {"echo", "foxtrot"}
    assert by_pair["golf", 7]["device"]["status"] == "unknown"
    async with sm() as db:
        diagnostics = {row["source_name"]: row for row in (await service.state(db))["source_diagnostics"]}
    assert diagnostics["Waiting KSC"]["status"] == "poll_missing"
    ready = diagnostics["Example KSC"]
    assert ready["status"] == "ready"
    assert {key: ready[key] for key in ("observed", "current", "matched", "eligible", "possible", "av_known")} == {
        "observed": 9, "current": 5, "matched": 6, "eligible": 2, "possible": 4, "av_known": 1}


@pytest.mark.asyncio
async def test_assignment_uses_a_recent_span_of_over_three_weeks_and_preserves_explicit_choices(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    sm = app.state.session_maker
    now = utcnow() - timedelta(minutes=1)
    async with sm() as db:
        run = AdAuditRun(id=uuid4(), started_at=now, finished_at=now, status="ok")
        source = KscSource(id=uuid4(), name="Example KSC", host="ksc.example.local", database="test", username="test")
        degraded = KscSource(id=uuid4(), name="Example delayed KSC", host="waiting.example.local", database="test", username="test")
        user = InvPerson(name="Bravo", login="bravo@example.local")
        bi = BiSource(id=uuid4(), name="Example BI")
        db.add_all([run, source, degraded, user, bi])
        await db.flush()
        sid = source.id
        db.add_all([account(run.id, "alpha"), account(run.id, "bravo"),
                    DevicesState(source_id=sid, polled_at=now),
                    DevicesState(source_id=degraded.id, polled_at=now, error="No successful latest poll"),
                    InvAsset(inv_no="EXAMPLE-ASSIGNMENT", cls="workstation", st_cls="use", user_id=user.id,
                             ksc_source_id=sid, ksc_host_id=7, ksc_link="confirmed")])
        for ksc, host_ids in ((source, [*range(1, 10), 11, 12]), (degraded, [10])):
            db.add(ZcSource(source_id=ksc.id, gen=1, built_at=now))
            for hid in host_ids:
                os = "Windows Server 2025" if hid == 5 else "Microsoft Windows 11"
                db.add(ZcHost(source_id=ksc.id, gen=1, host_id=hid, name=f"WS-{hid}", os=os,
                              data={"os": os, "last_connected": now.isoformat(), "mask": 32}))

        def observe(hid, dates, *, login="alpha", ksc=source, current=False, resolved=True):
            stamps = [now - timedelta(days=offset) for offset in dates]
            db.add(DeviceUser(source_id=ksc.id, host_id=hid, user_key=login, login=login if resolved else "",
                              domain="example.local" if resolved else "", identity_verified=resolved, resolved=resolved,
                              session_now=current, last_seen_at=stamps[-1], last_session_at=stamps[-1],
                              verified_observations={"stamps": [stamp.isoformat() for stamp in stamps]} if resolved else None))

        stable = 25, 18, 7, 1
        observe(1, stable)
        observe(1, [7], login="bravo")               # Один прошлый визит не делает станцию общей.
        observe(2, [22, 15, 8, 1])                    # Ровно три недели.
        observe(3, stable)
        observe(3, stable, login="bravo")
        observe(4, [28, 17, 8, 4])                    # Длительная, но устаревшая связь.
        for hid in range(5, 9):
            observe(hid, stable)
        observe(6, [0], login="unresolved", current=True, resolved=False)
        observe(8, stable, login="bravo")
        observe(9, [25, 0], current=True)             # Недостаточно отдельных дат.
        observe(10, stable, ksc=degraded)
        observe(11, stable)
        observe(12, stable)
        bi_pc = BiDevice(source_id=bi.id, dkey="ws-11", name="WS-11", first_seen_at=now, last_seen_at=now)
        bi_user = BiPerson(source_id=bi.id, pkey="bravo", email="bravo@example.local", first_seen_at=now, last_seen_at=now)
        db.add_all([bi_pc, bi_user])
        await db.flush()
        db.add_all([BiOwner(source_id=bi.id, device_id=bi_pc.id, person_id=bi_user.id, first_seen_at=now, last_seen_at=now),
                    BiMatch(bi_source_id=bi.id, device_id=bi_pc.id, ksc_source_id=sid, host_id=11, level="confirmed", decided_by="manual")])
        key = f"ksc:{sid}:8"
        db.add_all([EmployeeWorkplaceDecision(person_id="bravo", device_id=key, decision="assigned", decided_at=now),
                    EmployeeWorkplaceDecision(person_id="alpha", device_id=key, decision="confirmed", decided_at=now),
                    EmployeeWorkplaceDecision(person_id="alpha", device_id=f"ksc:{sid}:12", decision="rejected", decided_at=now)])
        await db.commit()

    await service.tick(sm, app.state.settings_svc, app.state.journal)
    url = "/api/v1/employee-protection"
    pairs = {(r["device"]["host_id"], r["employee"]["id"]): r for r in (await client.get(f"{url}/workplaces")).json()["items"]}
    assigned = {pair: row["assignment_basis"] for pair, row in pairs.items() if row.get("assignment_basis")}
    assert assigned == {(1, "alpha"): "observed", (7, "bravo"): "inventory", (8, "bravo"): "manual", (11, "bravo"): "bi"}
    row = pairs[1, "alpha"]
    assert row["device"]["assignment"] == {"employee_id": "alpha", "employee_name": "ALPHA", "basis": "observed",
                                           "observed_days": 4, "span_days": 24}
    assert OBSERVED_ASSIGNMENT in row["evidence"] and row["counted"] and row["primary"] and row["employee"]["login_verified"]
    assert row["last_verified_at"] == (now - timedelta(days=1)).isoformat()
    assert pairs[2, "alpha"]["span_days"] == 21 and pairs[2, "alpha"]["device"]["assignment"] is None
    assert pairs[5, "alpha"]["counted"] is False and pairs[9, "alpha"]["counted"] is True
    manual = pairs[8, "bravo"]
    assert manual["decision"] == "assigned" and manual["confidence"] == "confirmed" and manual["primary"]
    assert pairs[8, "alpha"]["counted"] and manual["device"]["shared_reason"] == SHARED


@pytest.mark.asyncio
async def test_duplicate_directory_mailbox_requires_an_exact_login_to_fill_inventory_assignee(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    sm = app.state.session_maker
    observed_at = utcnow() - timedelta(minutes=1)
    mail = "team@example.local"
    async with sm() as db:
        run = AdAuditRun(id=uuid4(), started_at=observed_at, finished_at=observed_at, status="ok")
        known_owner = InvPerson(name="Alpha", login="alpha@example.local")
        other = InvPerson(name="Bravo", email=mail)
        db.add_all([run, known_owner, other])
        await db.flush()
        db.add_all([account(run.id, "alpha", mail=mail), account(run.id, "bravo", mail=mail)])
        asset = InvAsset(inv_no="MAILBOX-EXAMPLE", cls="workstation", st_cls="use", owner_id=known_owner.id)
        db.add(asset)
        await db.flush()
        aid, owner_id, other_id = asset.id, known_owner.id, other.id
        await db.commit()

    await service.tick(sm, app.state.settings_svc, app.state.journal)
    url = "/api/v1/employee-protection/workplaces"
    result = (await client.get(url, params={"asset_id": aid})).json()
    row, = result["items"]
    assert row["employee"]["email"] == mail and row["employee"]["email_verified"] is False
    assert row["employee"]["login_verified"]
    assert row["proposals"]["user_id"]["id"] == owner_id
    payload = {"generation": result["generation"], "items": [
        {"pair": row["id"], "version": row["asset_version"], "values": {"user_id": other_id}}]}
    assert (await client.post(f"{url}/apply", json=payload)).status_code == 409


@pytest.mark.asyncio
async def test_devices_dedup_sources_and_require_strong_links(app):
    async with app.state.session_maker() as db:
        one, two = (KscSource(id=uuid4(), name=name, host=f"{name}.example.local", database="test", username="test")
                    for name in ("source-a", "source-b"))
        bi = BiSource(id=uuid4(), name="BI")
        zone = Zone(id=uuid4(), name="Accounting zone")
        db.add_all([one, two, bi, zone])
        await db.flush()
        for src in (one, two):
            db.add(ZcSource(source_id=src.id, gen=1, built_at=NOW))
            db.add(ZcHost(source_id=src.id, gen=1, host_id=1, name="pc", data={"name": "pc", "ip": "192.0.2.10", "os": "Example OS"}))
        db.add(DevicesState(source_id=two.id, polled_at=NOW))
        db.add_all([DeviceUser(source_id=two.id, host_id=1, user_key="bravo", login="bravo", domain="example.local", last_session_at=NOW,
                               last_seen_at=NOW, identity_verified=True),
                    DeviceUser(source_id=two.id, host_id=3, user_key="bravo", login="bravo", domain="example.local", last_session_at=NOW, last_seen_at=NOW)])
        db.add(ZcHostZone(source_id=one.id, gen=1, host_id=1, zone_id=str(zone.id)))
        alpha = InvPerson(name="Alpha", email="alpha@example.local")
        bravo = InvPerson(name="Bravo", login="bravo@example.local")
        db.add_all([alpha, bravo])
        await db.flush()
        db.add(InvAsset(inv_no="T-1", acc_no="AC-1", cls="workstation", st_cls="use", owner_id=alpha.id, user_id=bravo.id,
                        ksc_source_id=one.id, ksc_host_id=1, ksc_link="confirmed"))
        db.add(InvAsset(inv_no="T-2", cls="laptop", st_cls="use", user_id=alpha.id, ksc_source_id=one.id, ksc_host_id=2, ksc_link="confirmed"))
        db.add(InvAsset(inv_no="T-3", cls="laptop", st_cls="use", user_id=alpha.id))
        person = BiPerson(source_id=bi.id, pkey="alpha", full_name="Alpha", email="alpha@example.local", first_seen_at=NOW, last_seen_at=NOW)
        db.add(person)
        await db.flush()
        for j, target, level, decided in [(1, one, "confirmed", "manual"), (2, two, "confirmed", "manual"), (3, one, "confirmed", RULE),
                                           (4, two, "candidate", "manual")]:
            d = BiDevice(source_id=bi.id, dkey=f"pc-{j}", name=f"PC-{j}", os="Example OS", personal=j != 1, first_seen_at=NOW, last_seen_at=NOW)
            db.add(d)
            await db.flush()
            db.add_all([BiOwner(source_id=bi.id, device_id=d.id, person_id=person.id, first_seen_at=NOW, last_seen_at=NOW),
                        BiMatch(device_id=d.id, bi_source_id=bi.id, ksc_source_id=target.id, host_id=1, level=level, decided_by=decided)])
        await db.commit()
        roster = [{"id": key, "_emails": [f"{key}@example.local"], "_logins": [f"{key}@example.local"]} for key in ("alpha", "bravo")]
        rows = {d["id"]: (d, links) async for d, links in devices(db, [one.id, two.id], roster, NOW)}
        assert len(rows) == 7
        same_host, links = rows[f"ksc:{one.id}:1"]
        assert same_host["zones"] == [{"id": str(zone.id), "name": zone.name}]
        assert same_host["ownership"] == "corporate"
        assert links["alpha"]["confidence"] == links["bravo"]["confidence"] == "confirmed"
        assert links["alpha"]["evidence"] == sorted([INVENTORY_OWNER, BI_ASSIGNMENT, SHARED])
        assert links["bravo"]["evidence"] == sorted([INVENTORY_USER, SHARED])
        assert rows[f"ksc:{one.id}:2"][0]["protection"] is None
        assert rows[f"ksc:{two.id}:1"][0]["ownership"] == "personal"
        mixed = rows[f"ksc:{two.id}:1"][1]
        assert mixed["alpha"]["confidence"] == "confirmed" and mixed["alpha"]["evidence"] == [BI_ASSIGNMENT]
        assert mixed["bravo"]["confidence"] == "possible" and set(mixed["bravo"]["evidence"]) == {SESSION, EXACT_ACCOUNT}
        assert rows[f"ksc:{two.id}:3"][1]["bravo"]["confidence"] == "possible"
        assert UNVERIFIED_ACCOUNT in rows[f"ksc:{two.id}:3"][1]["bravo"]["evidence"]
        assert {r["name"] for r, _ in rows.values() if r["id"].startswith("bi:")} == {"PC-3", "PC-4"}


@pytest.mark.asyncio
async def test_device_source_batches_keep_2100_devices_distinct(app):
    async with app.state.session_maker() as db:
        one, two = (KscSource(id=uuid4(), name=name, host=f"{name}.example.local", database="test", username="test") for name in ("one", "two"))
        user = InvPerson(name="Alpha", email="alpha@example.local")
        db.add_all([one, two, user])
        await db.flush()
        db.add_all([ZcSource(source_id=s.id, gen=1, built_at=NOW) for s in (one, two)])
        for source in (one, two):
            await db.execute(insert(InvAsset), [{"inv_no": f"{source.name}-{i}", "cls": "workstation", "st_cls": "use", "user_id": user.id,
                                                 "ksc_source_id": source.id, "ksc_host_id": i, "ksc_link": "confirmed"} for i in range(1, 1051)])
            await db.execute(insert(ZcHost), [{"source_id": source.id, "host_id": i, "gen": 1, "name": f"WS-{i}", "data": {"os": "Example OS"}}
                                            for i in range(1, 1051)])
        await db.commit()
        start = perf_counter()
        people = [{"id": "alpha", "_emails": ["alpha@example.local"], "_logins": []}]
        rows = [d["id"] async for d, _ in devices(db, [one.id, two.id], people, NOW)]
        print(f"Сбор 2100 устройств из двух источников: {perf_counter() - start:.2f} с")
        assert len(rows) == len(set(rows)) == 2100


@pytest.mark.asyncio
async def test_usage_without_inventory_distinguishes_regular_shared_and_incomplete_evidence(app):
    async with app.state.session_maker() as db:
        source = KscSource(id=uuid4(), name="Directory devices", host="ksc.example.local", database="test", username="test")
        db.add(source)
        await db.flush()
        sid = source.id
        db.add_all([ZcSource(source_id=sid, gen=1, built_at=NOW), DevicesState(source_id=sid, polled_at=NOW - timedelta(hours=1))])
        for hid in range(1, 13):
            os = "Windows Server 2025" if hid == 3 else "Windows 11"
            name = "workgroup" if hid == 8 else f"WS-{hid}"
            db.add(ZcHost(source_id=sid, gen=1, host_id=hid, name=name, data={"os": os}))

        def observe(hid, login="alpha", domain="example.local", *, verified=True, history=False, repeat=True, future=False, legacy=False):
            last = NOW if future else NOW - timedelta(days=1)
            stamps = [(NOW - timedelta(days=offset)).isoformat() for offset in (21, 14, 7, 1)] if repeat else [last.isoformat()]
            db.add(DeviceUser(source_id=sid, host_id=hid, user_key=login, login=login, domain=domain, identity_verified=verified,
                              last_session_at=None if history else last, last_seen_at=last, first_seen_at=NOW - timedelta(days=21),
                              seen_n=500, verified_observations={"stamps": stamps} if not (legacy or history) else None))
            if repeat:
                for offset in (21, 14, 7):
                    first = NOW - timedelta(days=offset)
                    db.add(DeviceSession(source_id=sid, host_id=hid, user_key=login, started_at=first,
                                         last_active_at=first, ended_at=first + timedelta(hours=1)))

        observe(1)
        observe(2)
        observe(2, "bravo")
        observe(3)
        observe(4, domain="", verified=False)
        observe(5, domain="unrelated.example.local", verified=False)
        observe(6, history=True, repeat=False)
        observe(7, verified=False)
        observe(8, domain="workgroup", verified=False)
        observe(9, "charlie")
        observe(10, future=True)
        observe(11, "charlie", domain="", verified=False)
        observe(12, legacy=True)
        await db.commit()
        people = [{"id": key, "_emails": [], "_logins": [f"{key}@example.local", f"{key}@workgroup"],
                   "_short_logins": [key] if key != "charlie" else []} for key in ("alpha", "bravo", "charlie")]
        rows = {row["host_id"]: (row, links) async for row, links in devices(db, [sid], people, NOW)}

    assert set(rows) == {1, 2, 3, 4, 6, 7, 9, 12}
    everyday = rows[1][1]["alpha"]
    assert everyday["confidence"] == "likely" and everyday["observed_days"] == 4
    assert REGULAR in everyday["evidence"] and not everyday["shared"]
    assert everyday["first_seen_at"] == (NOW - timedelta(days=21)).isoformat()
    assert rows[2][0]["shared"] and all(SHARED in link["evidence"] for link in rows[2][1].values())
    assert rows[3][0]["shared"] and SERVER in rows[3][1]["alpha"]["evidence"]
    assert rows[4][1]["alpha"]["confidence"] == "possible" and SHORT_ACCOUNT in rows[4][1]["alpha"]["evidence"]
    assert rows[6][1]["alpha"]["confidence"] == "possible" and rows[6][1]["alpha"]["observed_days"] == 0
    assert HISTORY in rows[6][1]["alpha"]["evidence"] and rows[6][1]["alpha"]["first_seen_at"] is None
    assert rows[7][1]["alpha"]["confidence"] == "possible" and UNVERIFIED_ACCOUNT in rows[7][1]["alpha"]["evidence"]
    assert rows[9][1]["charlie"]["observed_days"] == 4
    assert rows[12][1]["alpha"]["confidence"] == "possible"
    assert rows[12][1]["alpha"]["observed_days"] == 0


@pytest.mark.asyncio
async def test_manually_linked_devices_are_returned_without_current_assignments(app):
    async with app.state.session_maker() as db:
        source = KscSource(id=uuid4(), name="Directory devices", host="ksc.example.local", database="test", username="test")
        bi = BiSource(id=uuid4(), name="BI")
        asset = InvAsset(inv_no="T-manual", hostname="ws-manual", cls="workstation", st_cls="use")
        user = InvPerson(name="Alpha", email="alpha@example.local")
        db.add_all([source, bi, asset, user])
        await db.flush()
        auto = InvAsset(inv_no="T-auto", acc_no="AC-auto", hostname="ws-auto", cls="workstation", st_cls="use", user_id=user.id,
                        ksc_source_id=source.id, ksc_host_id=2, ksc_link="auto")
        listed = BiDevice(source_id=bi.id, dkey="ws-bi", name="ws-bi", first_seen_at=NOW, last_seen_at=NOW)
        db.add_all([ZcSource(source_id=source.id, gen=1, built_at=NOW),
                    ZcHost(source_id=source.id, gen=1, host_id=1, name="ws-ksc", data={"os": "Windows 11"}), listed, auto])
        await db.commit()
        manual = {f"ksc:{source.id}:1": {"alpha"}, f"ksc:{source.id}:2": {"alpha"},
                  f"inv:{asset.id}": {"alpha"}, f"bi:{listed.id}": {"alpha"}}
        people = [{"id": "alpha", "_emails": ["alpha@example.local"], "_logins": []}]
        rows = {row["id"]: (row, links) async for row, links in devices(db, [source.id], people, NOW, manual=manual)}
        assert set(rows) == manual.keys() | {f"inv:{auto.id}"}
        assert {row["name"] for row, _ in rows.values()} == {"ws-ksc", "ws-manual", "ws-bi", "ws-auto"}
        assert all(not rows[key][1] for key in manual)
        attached = rows[f"ksc:{source.id}:2"][0]
        assert attached["asset_id"] == auto.id and attached["ownership"] == "unknown" and attached["protection"] is None
        assert rows[f"inv:{auto.id}"][1]["alpha"]["confidence"] == "confirmed"
