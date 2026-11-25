"""Сетевые наблюдения инвентаризации: правила, область доступа и сохранность учётных полей."""
from datetime import timedelta
from ipaddress import IPv4Address
from uuid import UUID, uuid4

import pytest
from openpyxl import load_workbook
from sqlalchemy import select

from app.inventory import geo_service as S, geo_updater, geography as G
from app.models import InvAsset, InvGeo, InvRef, KscSource, ReportJob, User, utcnow
from app.reports import quick, quick_export
from tests.conftest import login
from tests.test_inventory import API, setup

GEO = f"{API}/geography"


def _rule(id_, **fields):
    return G.Compiled(id_, G.Rule(name=f"Правило {id_}", **fields))


def _no_lookup(_ip):
    pytest.fail("Служебный или документальный адрес передан в геолокацию")


async def test_network_proposal_labels_are_read_in_one_batch(app, monkeypatch):
    async with app.state.session_maker() as db:
        dept = InvRef(kind="dept", name="Тестовый отдел")
        db.add(dept)
        await db.flush()
        execute = db.execute
        calls = 0

        async def count(*args, **kwargs):
            nonlocal calls
            calls += 1
            return await execute(*args, **kwargs)

        monkeypatch.setattr(db, "execute", count)
        fields = await G.proposal_fields_for(db, {i: (InvAsset(id=i), {"dept_id": dept.id}) for i in range(100)})
        assert calls == 1
        assert len(fields) == 100 and all(v["dept_id"]["value"] == dept.name for v in fields.values())


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


@pytest.mark.parametrize("provider, full_credit, link", [
    (G.DBIP_LABEL, G.DBIP_CREDIT, '<a href="https://db-ip.com/">IP Geolocation by DB-IP</a>'),
    (G.GEOLITE_LABEL, G.GEOLITE_CREDIT, '<a href="https://www.maxmind.com/">Геоданные GeoLite от MaxMind</a>'),
])
async def test_attribution_follows_geographic_results_into_reports(client, app, tmp_path, provider, full_credit, link):
    config = await setup(client, app)
    now, sid = utcnow(), uuid4()
    async with app.state.session_maker() as db:
        db.add(KscSource(id=sid, name="Тестовый источник", host="ksc.example.local", port=1433, database="KAV", username="ro", password_enc="x"))
        asset = InvAsset(inv_no="ПР-ГЕО", cls="workstation", type_id=config["t"]["workstation"], ksc_link="confirmed", ksc_source_id=sid, ksc_host_id=1)
        db.add(asset)
        await db.flush()
        aid = asset.id
        db.add(InvGeo(asset_id=aid, host_id=1, source_id=sid, checked_at=now, observed_at=now,
                      evidence={"addresses": [{"kind": "connection", "ip": "192.0.2.19"}]},
                      result={"status": "approx", "city": "Пример", "provider": provider, "database_at": now.date().isoformat()}))
        await db.commit()

    assert (await client.get(GEO)).json()["geo_attributions"] == [provider]
    assert not (await client.get(GEO, params={"q": "отсутствует"})).json()["geo_attributions"]
    report = await client.post("/api/v1/quick/preview", json={"kind": "quick_inv", "params": {"view": "geography"}})
    assert full_credit in report.json()["doc"]["notes"]
    ctx = quick.Ctx(source_name="Инвентаризация", activity_days=0, sm=app.state.session_maker)
    doc = await quick.build("quick_inv", None, {"view": "geography"}, ctx)
    assert link in quick_export.render_html(doc)
    tabbed = await quick.build("quick_inv", None, {"view": "geography_card", "asset_id": aid}, ctx)
    assert tabbed["tabs"] and link in quick_export.render_html(tabbed)
    out = tmp_path / "geography.csv"
    quick_export.write_csv_main(out, doc)
    assert full_credit in out.read_text(encoding="utf-8-sig")


async def test_expired_geoip_hidden_and_purged_without_ksc_refresh(client, app, tmp_path):
    config = await setup(client, app)
    now, sid = utcnow(), uuid4()
    old_build = (now - timedelta(days=31)).date().isoformat()
    common = {"status": "approx", "confidence": "low", "city": "Пример", "lat": 15.4, "lon": -44.5, "asn": 64501,
              "provider": G.GEOLITE_LABEL, "network": "192.0.2.0/24", "rules": [{"id": 1, "name": "Подсказка"}]}
    async with app.state.session_maker() as db:
        db.add(KscSource(id=sid, name="Синтетический источник", host="ksc.example.local", port=1433, database="KAV", username="ro"))
        assets = [InvAsset(inv_no=f"ПР-ГЕО-{i}", cls="workstation", type_id=config["t"]["workstation"], ksc_link="confirmed",
                           ksc_source_id=sid, ksc_host_id=i) for i in range(1, 5)]
        db.add_all(assets)
        await db.flush()
        ids = [asset.id for asset in assets]
        for asset, fields in zip(assets, (
                {"geoip_valid_until": (now - timedelta(seconds=1)).isoformat(timespec="seconds"), "database_at": now.date().isoformat()},
                {"database_at": old_build},
                {"geoip_valid_until": (now + timedelta(days=1)).isoformat(timespec="seconds"), "database_at": now.date().isoformat()},
                {"geoip_valid_until": "", "database_at": old_build},
        ), strict=True):
            db.add(InvGeo(asset_id=asset.id, host_id=asset.ksc_host_id, source_id=sid, checked_at=now, observed_at=now,
                          evidence={"addresses": [{"kind": "connection", "ip": "192.0.2.19"}]}, result={**common, **fields}))
        await db.commit()

    page = (await client.get(GEO)).json()
    assert [(r["status"], r.get("city")) for r in page["items"]] == [("unknown", None)] * 2 + [("approx", "Пример")] * 2
    assert sum(g["n"] for g in page["groups"] if g["city"] == "Пример") == 2
    assert (await client.get(GEO, params={"city": "Пример"})).json()["total"] == 2
    assert (await client.get(GEO, params={"status": "unknown"})).json()["total"] == 2
    card = (await client.get(f"{GEO}/assets/{ids[0]}")).json()
    assert "city" not in card and "asn" not in card and card["network"] == "192.0.2.0/24"
    assert card["connection_ip"]["ip"] == "192.0.2.19"
    ctx = quick.Ctx(source_name="Инвентаризация", activity_days=0, sm=app.state.session_maker)
    doc = await quick.build("quick_inv", None, {"view": "geography_card", "asset_id": ids[0]}, ctx)
    assert doc["tables"][0]["rows"][0]["city"] is None and G.GEOLITE_CREDIT not in doc["notes"]
    filtered = await quick.build("quick_inv", None, {"view": "geography", "geography": {"city": "Пример"}}, ctx)
    assert len(filtered["tables"][0]["rows"]) == 2

    saved = await client.put("/api/v1/admin/settings/geoip", json={"enabled": False})
    assert saved.status_code == 200
    await geo_updater.tick(app.state.session_maker, app.state.settings_svc, tmp_path, app.state.journal)
    async with app.state.session_maker() as db:
        for aid in ids[:2]:
            row = await db.get(InvGeo, aid)
            assert row.result == {"status": "unknown", "confidence": "", "network": common["network"], "rules": common["rules"],
                                  "reason": "geo_expired"}
            assert row.evidence["addresses"][0]["ip"] == "192.0.2.19"
        for aid in ids[2:]:
            assert (await db.get(InvGeo, aid)).result["city"] == "Пример"


async def test_map_explains_missing_coordinates_and_filters_reports(client, app, monkeypatch):
    config = await setup(client, app)
    now = utcnow()
    first, second = uuid4(), uuid4()
    public = {f"192.0.2.{i}" for i in (1, 2, 5, 6)}
    ip_scope = G._ip_scope
    monkeypatch.setattr(G, "_ip_scope", lambda ip: "public" if str(ip) in public else ip_scope(ip))
    values = [
        ("connection", "192.0.2.1"), ("connection", "192.0.2.2"),
        ("connection", str(IPv4Address(bytes((192, 168, 0, 19))))),
        ("connection", str(IPv4Address(bytes((100, 64, 0, 19))))),
        ("reported", "192.0.2.5"), ("connection", "192.0.2.6"),
    ]
    evidence = {i: {"addresses": [{"kind": kind, "ip": ip, "source": "v_akpub_host.nConnectionIp" if kind == "connection" else "v_akpub_host.nIp"}],
                    "last_connected": now.isoformat()} for i, (kind, ip) in enumerate(values, 1)}
    async with app.state.session_maker() as db:
        for number, sid in enumerate((first, second), 1):
            db.add(KscSource(id=sid, name=f"Тестовый источник {number}", host="ksc.example.local", port=1433, database="KAV", username="ro"))
            db.add_all([InvAsset(inv_no=f"ГЕО-{number}-{i}", cls="workstation", type_id=config["t"]["workstation"], ksc_link="confirmed",
                                 ksc_source_id=sid, ksc_host_id=i) for i in evidence])
        await db.commit()

    async def capabilities(_client):
        return frozenset()

    async def read(_client, ids, _caps, _groups):
        return {i: evidence[i].copy() for i in ids}

    class Lease:
        async def stage(self, _stage, _detail=None):
            pass

        async def fence(self, db):
            assert db.in_transaction()

    class Geo:
        city = True
        asn = None
        errors = []

        def lookup(self, ip):
            assert ip in public - {"192.0.2.5"}
            if ip == "192.0.2.1":
                return {"city": "Пример", "lat": 0.0, "lon": 0.0}
            return {"city": "Пример"} if ip == "192.0.2.2" else {}

    class NoCity(Geo):
        city = None

        def lookup(self, ip):
            assert ip in public - {"192.0.2.5"}
            return {}

    monkeypatch.setattr(S.network, "capabilities", capabilities)
    monkeypatch.setattr(S.network, "read", read)
    await S.collect(app.state.session_maker, first, None, Geo(), Lease())
    await S.collect(app.state.session_maker, second, None, NoCity(), Lease())

    def counts(page):
        return {item["code"]: item["count"] for item in page["diagnostics"] if item["count"]}

    for sid, n, expected in (
        (first, 1, {"egress_point": 1, "geo_no_point": 1, "lookup_miss": 1}),
        (second, 0, {"city_unavailable": 3}),
    ):
        page = (await client.get(GEO, params={"freshness": "fresh", "observation_source": sid})).json()
        assert page["total"] == 6 and page["with_coordinates"] == n
        assert counts(page) == {**expected, "private": 1, "shared": 1, "reported_public": 1}
        assert sum(g["n"] for g in page["groups"] if g["lat"] is not None and g["lon"] is not None) == n
    selected = (await client.get(GEO, params={"reason": "city_unavailable"})).json()
    assert selected["total"] == 3 and all(i["connection_ip"]["source"] == "v_akpub_host.nConnectionIp" for i in selected["items"])
    assert (await client.get(GEO, params={"reason": "invalid"})).status_code == 422
    ctx = quick.Ctx(source_name="Инвентаризация", activity_days=0, sm=app.state.session_maker)
    report = await quick.build("quick_inv", None, {"view": "geography", "geography": {"reason": "city_unavailable"}}, ctx)
    label = G.GEO_REASONS["city_unavailable"]
    assert [r["inv_no"] for r in report["tables"][0]["rows"]] == [r["inv_no"] for r in selected["items"]]
    assert report["tables"][1]["rows"] == [{"reason": label, "count": 3}]
    assert {"label": "Координаты и причины", "text": label} in report["conditions"]


async def test_geography_rule_report_uses_unsaved_draft_and_full_matches(client, app, tmp_path):
    config = await setup(client, app)
    now, sid = utcnow(), uuid4()
    async with app.state.session_maker() as db:
        db.add(KscSource(id=sid, name="Тестовый источник", host="ksc.example.local", port=1433, database="KAV", username="ro", password_enc="x"))
        assets = [InvAsset(inv_no=f"ПР-{i:03d}", cls="workstation", type_id=config["t"]["workstation"], ksc_link="confirmed", ksc_source_id=sid, ksc_host_id=i)
                  for i in range(1, 26)]
        db.add_all(assets)
        await db.flush()
        db.add_all([InvGeo(asset_id=a.id, host_id=a.ksc_host_id, source_id=sid, checked_at=now, observed_at=now,
                           evidence={"addresses": [{"kind": "device", "ip": "192.0.2.19"}]}, result={"status": "unknown"}) for a in assets])
        await db.commit()

    draft = {"rule": {"name": "Черновик", "networks": ["192.0.2.0/24"], "vpn": True}}
    preview = await client.post(f"{GEO}/rules/preview", json=draft)
    assert preview.status_code == 200 and preview.json()["matched"] == 25 and len(preview.json()["items"]) == 20
    params = {"view": "geography_preview", "geo_rule_preview": draft}
    form = {"kind": "quick_inv", "params": params}
    answer = await client.post("/api/v1/quick/preview", json=form)
    assert answer.status_code == 200, answer.text
    assert answer.json()["total"] == 25 and len(answer.json()["items"]) == 20
    ctx = quick.Ctx(source_name="Инвентаризация", activity_days=0, sm=app.state.session_maker)
    doc = await quick.build("quick_inv", None, params, ctx)
    path = tmp_path / "preview.xlsx"
    quick_export.write_xlsx(path, doc)
    workbook = load_workbook(path, read_only=True)
    try:
        assert [r[0] for r in workbook["Совпадения"].iter_rows(min_row=2, values_only=True)] == [f"ПР-{i:03d}" for i in range(1, 26)]
    finally:
        workbook.close()
    assert doc["tables"][1]["rows"][0]["name"] == "Черновик"
    assert (await client.get(f"{GEO}/rules")).json()["items"] == []
    template = await client.post("/api/v1/report-templates", json={**form, "name": "Тестовый шаблон", "shared": False})
    assert template.status_code == 201 and "geo_rule_preview" not in template.json()["params"]
    invalid = {**params, "geo_rule_preview": {"rule": {**draft["rule"], "site_id": 9000}}}
    assert (await client.post("/api/v1/quick/preview", json={**form, "params": invalid})).status_code == 422


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
    async def report_for(view, **params):
        return await client.post("/api/v1/quick/preview", json={"kind": "quick_inv", "params": {"view": view, **params}})

    rules_report = await report_for("geography_rules")
    assert rules_report.status_code == 200, rules_report.text
    [rule_row] = rules_report.json()["items"]
    assert (rule_row["name"], rule_row["networks"], rule_row["source_id"], rule_row["site_id"]) == (
        "Участок тестовой сети", "192.0.2.0/24", "Первый", "Площадка С")
    rules_job = await client.post("/api/v1/reports", json={"kind": "quick_inv", "params": {"view": "geography_rules"}})
    assert rules_job.status_code == 201, rules_job.text
    job_id = rules_job.json()["id"]
    async with app.state.session_maker() as db:
        analyst = await db.scalar(select(User).where(User.username == "analyst1"))
        job = await db.get(ReportJob, UUID(job_id))
        job.created_by_id = analyst.id
        await db.commit()
    check = {"checked_at": observation["checked_at"]}
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.post(f"{url}/{aid}/apply", json=check)).status_code == 403
    assert (await client.post(f"{GEO}/rules/preview", json={"rule": body})).status_code == 403

    await login(client, "analyst1", "Analyst-Passw0rd-123")
    assert (await client.get(f"{url}/{unobserved_id}")).status_code == 404
    hidden = (await client.get(f"{url}/{restricted_id}")).json()
    assert hidden["status"] == "unknown" and "evidence" not in hidden and "connection_ip" not in hidden
    assert (await client.get(GEO, params={"observation_source": str(other_sid)})).json()["total"] == 0
    proposals = (await client.get(GEO, params={"fill_available": True})).json()
    assert [(i["id"], i["proposal_fields"]) for i in proposals["items"]] == [(aid, ["Филиал"])]
    proposals_report = (await report_for("geography", geography={"fill_available": True})).json()
    assert [(i["inv_no"], i["proposal_fields"]) for i in proposals_report["items"]] == [("ТС-001", "Филиал")]
    params = {"view": "geography", "geography": {"site_id": site, "freshness": "stale"}, "geo_source_ids": [str(other_sid)]}
    report = await client.post("/api/v1/quick/preview", json={"kind": "quick_inv", "params": params})
    assert report.status_code == 200, report.text
    assert [(row["inv_no"], row["source"], row["site"]) for row in report.json()["items"]] == [("ТС-002", "Первый", "Площадка С")]
    card_report = (await report_for("geography_card", asset_id=aid)).json()
    assert [(r["inv_no"], r["source"], r["connection_scope"]) for r in card_report["items"]] == [("ТС-001", "Первый", "Адрес отсутствует")]
    assert {t["id"]: t["n"] for t in card_report["doc"]["tables"]} == {"rows": 1, "network_details": 1, "addresses": 1, "proposals": 4}
    hidden_report = (await report_for("geography_card", asset_id=restricted_id, geo_source_ids=[str(other_sid)])).json()
    assert [(r["inv_no"], r["source"]) for r in hidden_report["items"]] == [("ТС-003", "")]
    assert [t["id"] for t in hidden_report["doc"]["tables"]] == ["rows"]
    assert (await report_for("geography_card", asset_id=unobserved_id)).status_code == 409
    assert (await report_for("geography_card")).status_code == 422
    assert (await report_for("geography_rules")).status_code == 403
    assert (await client.post("/api/v1/reports", json={"kind": "quick_inv", "params": {"view": "geography_rules"}})).status_code == 403
    assert (await client.get(f"/api/v1/reports/{job_id}")).status_code == 404
    assert (await client.get(f"/api/v1/reports/{job_id}/download/xlsx")).status_code == 404
    assert (await report_for("geography_preview", geo_rule_preview={"rule": body})).status_code == 403

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
