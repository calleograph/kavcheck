"""Сетевые наблюдения инвентаризации: правила, область доступа и сохранность учётных полей."""
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.inventory import geo_service as S, geography as G
from app.models import InvAsset, InvGeo, InvRef, KscSource, User, utcnow
from tests.conftest import login
from tests.test_inventory import API, setup

GEO = f"{API}/geography"


def _rule(id_, **fields):
    return G.Compiled(id_, G.Rule(name=f"Правило {id_}", **fields))


def _no_lookup(_ip):
    pytest.fail("Служебный или документальный адрес передан в геолокацию")


def test_rule_priority_specificity_and_conflicts():
    src = uuid4()
    evidence = {"name": "ws-test01", "domain": "example.local", "group": "Рабочие станции / Офис",
                "addresses": [{"kind": "device", "ip": "192.0.2.19"}, {"kind": "connection", "ip": "2001:db8:1::11"}]}
    broad = _rule(1, networks=["192.0.2.0/24"], site_id=1)
    narrow = _rule(2, networks=["192.0.2.16/28"], site_id=2, source_id=src, host="ws-test*", domain="example.local")
    assert G.locate(evidence, src, None, [broad, narrow], _no_lookup)["site_id"] == 2
    assert G.locate(evidence, uuid4(), None, [broad, narrow], _no_lookup)["site_id"] == 1
    prioritized = _rule(3, networks=["192.0.2.0/24"], site_id=3, priority=20)
    assert G.locate(evidence, src, None, [broad, narrow, prioritized], _no_lookup)["site_id"] == 3
    contradiction = _rule(4, networks=["192.0.2.16/28"], site_id=4, dept_id=4)
    result = G.locate(evidence, src, None, [broad, narrow, contradiction], _no_lookup)
    assert result["status"] == "conflict" and result["proposals"] == {} and {r["id"] for r in result["rules"]} == {2, 4}
    vpn = _rule(5, networks=["2001:db8:1::/64"], ip_kind="connection", vpn=True)
    result = G.locate(evidence, src, None, [broad, narrow, contradiction, vpn], _no_lookup)
    assert result["status"] == "vpn" and result["proposals"] == {} and "site_id" not in result
    additional = _rule(6, infra_source_id=4, infra_site="Площадка *", site_id=6)
    evidence["infra"] = [{"source_id": 4, "site": "Площадка 1"}]
    assert G.locate(evidence, src, None, [additional], _no_lookup)["site_id"] == 6
    device_only = _rule(7, networks=["192.0.2.0/24"], ip_kind="device", site_id=7)
    reported = {"addresses": [{"kind": "reported", "ip": "192.0.2.19"}]}
    assert G.locate(reported, src, None, [device_only], _no_lookup)["status"] == "unknown"


def test_geoip_is_only_an_approximate_egress_observation(monkeypatch):
    src = uuid4()
    evidence = {"addresses": [{"kind": "reported", "ip": "192.0.2.19"}, {"kind": "connection", "ip": "2001:db8::19"}]}
    assert G.public_connection(evidence) == ""
    assert G.locate(evidence, src, None, [], _no_lookup)["status"] == "unknown"
    monkeypatch.setattr(G, "public_connection", lambda _e: "192.0.2.19")

    def lookup(ip):
        assert ip == "192.0.2.19"
        return {"country": "Страна A", "city": "Город A", "lat": 15.4, "lon": -44.5, "radius_km": 40, "asn": 64501}

    result = G.locate(evidence, src, None, [], lookup)
    assert result["status"] == "approx" and result["confidence"] == "low" and result["radius_km"] == 40 and result["asn"] == 64501
    assert "site_id" not in result and result["proposals"] == {}


async def test_geography_from_collection_to_rule_preview_and_scoped_apply(client, app, monkeypatch):
    data = await setup(client, app)
    room, person = data["room"]["id"], data["p1"]["id"]
    site = (await client.post(f"{API}/locations", json={"kind": "building", "name": "Площадка С", "data": {"lat": 15.4, "lon": -44.5}})).json()["id"]
    sid, other_sid = uuid4(), uuid4()
    url = f"{GEO}/assets"
    async with app.state.session_maker() as db:
        old_dept, candidate_dept, candidate_branch = (InvRef(kind=k, name=n) for k, n in (
            ("dept", "Учётный отдел"), ("dept", "Предлагаемый отдел"), ("branch", "Предлагаемый филиал")))
        db.add_all([old_dept, candidate_dept, candidate_branch])
        await db.flush()
        old_dept_id, dept_id, branch_id = old_dept.id, candidate_dept.id, candidate_branch.id
        for src, name in ((sid, "Первый"), (other_sid, "Второй")):
            db.add(KscSource(id=src, name=name, host="ksc.example.local", port=1433, database="KAV", username="ro", password_enc="x"))
        common = {"type_id": data["t"]["workstation"], "cls": "workstation", "location_id": room}
        fresh = InvAsset(**common, inv_no="ТС-001", dept_id=old_dept_id, resp_id=person, ksc_source_id=sid, ksc_host_id=1, ksc_link="confirmed")
        stale = InvAsset(**common, inv_no="ТС-002", ksc_source_id=sid, ksc_host_id=2, ksc_link="confirmed")
        restricted = InvAsset(**common, inv_no="ТС-003", ksc_source_id=other_sid, ksc_host_id=1, ksc_link="confirmed")
        unobserved = InvAsset(inv_no="ТС-004", name="Устройство без наблюдения", location_id=site)
        db.add_all([fresh, stale, restricted, unobserved])
        user = await db.scalar(select(User).where(User.username == "analyst1"))
        user.all_sources, user.source_ids = False, [str(sid)]
        await db.commit()
        aid, stale_id, restricted_id, unobserved_id = fresh.id, stale.id, restricted.id, unobserved.id

    body = {"name": "Участок тестовой сети", "source_id": str(sid), "site_id": site, "networks": ["192.0.2.0/24"], "ip_kind": "device",
            "location_id": site, "dept_id": dept_id, "branch_id": branch_id, "resp_id": data["p2"]["id"]}
    saved = await client.post(f"{GEO}/rules", json=body)
    assert saved.status_code == 201, saved.text
    assert (await client.put("/api/v1/admin/settings/inventory", json={"grants": [{"login": "analyst1", "perms": [], "location_ids": [data["region"]["id"]]}]})).status_code == 200

    now = utcnow()
    evidence = {1: {"addresses": [{"kind": "device", "ip": "192.0.2.19"}], "last_info_update": now.isoformat()},
                2: {"addresses": [{"kind": "device", "ip": "192.0.2.20"}], "last_info_update": (now - timedelta(days=20)).isoformat()}}

    async def caps(_client):
        return frozenset()

    async def read(_client, ids, _caps, _groups):
        return {i: dict(evidence[i]) for i in ids}

    class Lease:
        async def stage(self, _stage, _detail=None):
            pass

        async def fence(self, db):
            assert db.in_transaction()

    class Offline:
        city = asn = None
        errors = []
        lookup = staticmethod(_no_lookup)

    monkeypatch.setattr(S.network, "capabilities", caps)
    monkeypatch.setattr(S.network, "read", read)
    assert (await S.collect(app.state.session_maker, sid, None, Offline(), Lease()))["count"] == 2
    await S.collect(app.state.session_maker, other_sid, None, Offline(), Lease())

    preview = await client.post(f"{GEO}/rules/preview", json={"id": saved.json()["id"], "rule": body})
    assert preview.status_code == 200, preview.text
    assert {k: preview.json()[k] for k in ("matched", "effective", "conflicts", "would_fill", "stale")} == {
        "matched": 2, "effective": 2, "conflicts": 0, "would_fill": 1, "stale": 1}
    response = await client.get(GEO)
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 4
    map_site = next(g for g in response.json()["groups"] if g["site_id"] == site)
    assert (map_site["n"], map_site["fresh_n"]) == (2, 1)
    assert (map_site["lat"], map_site["lon"]) == (15.4, -44.5)
    stale_map = (await client.get(GEO, params={"freshness": "stale", "site_id": site})).json()
    assert [i["id"] for i in stale_map["items"]] == [stale_id]
    unknown = (await client.get(GEO, params={"status": "unknown"})).json()
    assert {i["id"] for i in unknown["items"]} == {restricted_id, unobserved_id}

    observation = (await client.get(f"{url}/{aid}")).json()
    assert observation["status"] == "site" and observation["source"] == "Первый" and observation["fresh"]
    assert observation["connection_ip"] == {"scope": "missing"}
    assert observation["evidence"]["addresses"][0]["scope"] == "special"
    check = {"checked_at": observation["checked_at"]}
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.post(f"{url}/{aid}/apply", json=check)).status_code == 403
    assert (await client.post(f"{GEO}/rules/preview", json={"rule": body})).status_code == 403

    await login(client, "analyst1", "Analyst-Passw0rd-123")
    assert (await client.get(f"{url}/{unobserved_id}")).status_code == 404
    hidden = (await client.get(f"{url}/{restricted_id}")).json()
    assert hidden["status"] == "unknown" and "evidence" not in hidden and "connection_ip" not in hidden
    assert (await client.get(GEO, params={"observation_source": str(other_sid)})).json()["total"] == 0
    params = {"view": "geography", "geography": {"site_id": site, "freshness": "stale"}, "geo_source_ids": [str(other_sid)]}
    report = await client.post("/api/v1/quick/preview", json={"kind": "quick_inv", "params": params})
    assert report.status_code == 200, report.text
    assert [(row["inv_no"], row["source"], row["site"]) for row in report.json()["items"]] == [("ТС-002", "Первый", "Площадка С")]

    await login(client, "admin", "Admin-Passw0rd-123")
    old = (await client.get(f"{url}/{stale_id}")).json()
    assert old["fresh"] is False
    assert (await client.post(f"{url}/{stale_id}/apply", json={"checked_at": old["checked_at"]})).status_code == 409
    applied = await client.post(f"{url}/{aid}/apply", json=check)
    assert applied.status_code == 200, applied.text
    assert {f["f"] for f in applied.json()["changed"]} == {"branch_id"}
    history = (await client.get(f"{API}/assets/{aid}/history")).json()["items"]
    assert history[0]["basis"] == "Правило сетевой принадлежности"

    evidence[1]["addresses"] = [{"kind": "device", "ip": "198.51.100.19"}]
    await S.collect(app.state.session_maker, sid, None, Offline(), Lease())
    assert (await client.post(f"{url}/{aid}/apply", json=check)).status_code == 409
    async with app.state.session_maker() as db:
        a, g = await db.get(InvAsset, aid), await db.get(InvGeo, aid)
        assert a.ksc_source_id == sid and a.ksc_host_id == 1
        assert (a.location_id, a.dept_id, a.resp_id, a.branch_id) == (room, old_dept_id, person, branch_id)
        assert g.result["status"] == "unknown" and g.evidence["addresses"][0]["ip"] == "198.51.100.19"
        assert len((await db.scalars(select(InvAsset))).all()) == 4
