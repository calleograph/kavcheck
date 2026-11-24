from datetime import datetime, timedelta, timezone
from time import perf_counter
from uuid import uuid4

import pytest
from sqlalchemy import insert

from app.bi.match import RULE
from app.employee_protection.sources import BI_ASSIGNMENT, INVENTORY_OWNER, INVENTORY_USER, devices, employees
from app.employee_protection.workplace import EXACT_ACCOUNT, HISTORY, REGULAR, SERVER, SESSION, SHARED, SHORT_ACCOUNT, UNVERIFIED_ACCOUNT
from app.models import (AdAuditAccount, AdAuditRun, BiDevice, BiMatch, BiOwner, BiPerson, BiSource, DevicesState, DeviceSession, DeviceUser, HierSnapshot,
                        InvAsset, InvPerson, KscSource, LdapConnection, ZcHost, ZcHostZone, ZcSource, Zone)

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
        assert links["alpha"]["evidence"] == sorted([INVENTORY_OWNER, BI_ASSIGNMENT])
        assert links["bravo"]["evidence"] == [INVENTORY_USER]
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
        for hid in range(1, 12):
            os = "Windows Server 2025" if hid == 3 else "Windows 11"
            name = "workgroup" if hid == 8 else f"WS-{hid}"
            db.add(ZcHost(source_id=sid, gen=1, host_id=hid, name=name, data={"os": os}))

        def observe(hid, login="alpha", domain="example.local", *, verified=True, history=False, repeat=True, future=False):
            last = NOW if future else NOW - timedelta(days=1)
            db.add(DeviceUser(source_id=sid, host_id=hid, user_key=login, login=login, domain=domain, identity_verified=verified,
                              last_session_at=None if history else last, last_seen_at=last, first_seen_at=NOW - timedelta(days=21),
                              seen_n=500))
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
        observe(9, "charlie", repeat=True)
        observe(10, future=True)
        observe(11, "charlie", domain="", verified=False)
        await db.commit()
        people = [{"id": key, "_emails": [], "_logins": [f"{key}@example.local", f"{key}@workgroup"],
                   "_short_logins": [key] if key != "charlie" else []} for key in ("alpha", "bravo", "charlie")]
        rows = {row["host_id"]: (row, links) async for row, links in devices(db, [sid], people, NOW)}

    assert set(rows) == {1, 2, 3, 4, 6, 7, 9}
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
    assert rows[9][1]["charlie"]["observed_days"] == 1


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
