"""Главная: методика активности (7/30/60/90 сут), серверы и станции, защита, лицензии без двойного счёта, чтение лицензий KSC по найденным столбцам, API и боковая панель."""
import uuid

import pytest
from sqlalchemy import select
from datetime import datetime, timedelta, timezone

from app.ksc import licenses as KL
from app.licensing import pools as LP
from app.models import LicenseRecord, LicenseState, OverviewDaily
from app.overview import calc as C
from tests.conftest import login

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)


def host(i, days, os_name="Windows 11 Pro", platform="Windows", av=True, mask=0, rtp=4, bases_h=5, info_days=1, name=None):
    last = None if days is None else NOW - timedelta(days=days)
    return {"host_id": i, "name": name or f"pc{i}", "fqdn": f"pc{i}.example.local", "ip": f"192.0.2.{i}", "os": os_name, "os_version": "", "platform": platform, "group": "Группа",
            "last_connected": last, "last_visible": last, "last_info_update": NOW - timedelta(days=info_days), "days_since_connection": days, "online": None, "rtp_state": rtp, "mask": mask,
            "av": {"code": "KES", "product": "KES", "build": "12.0", "state": 3, "bases": NOW - timedelta(hours=bases_h), "has_rtp": True} if av else None,
            "agent_build": "15.0" if days is not None else "", "last_full_scan": NOW, "uncured": 0}


RECS = [host(1, 1), host(2, 10, "Windows Server 2019 Standard"), host(3, 40, "Microsoft Windows Server 2012 R2", av=False), host(4, 65, "Windows 10 Pro", rtp=9),
        host(5, 100, "Windows 10 Pro"), host(6, 2, "Linux", platform="Linux"), host(7, None, "Windows 7"), host(8, 3, "Windows 11 Pro", bases_h=24 * 5), host(9, 4, "Windows 11 Pro", info_days=30),
        host(10, 5, "Windows 11 Pro", mask=512)]


def test_activity_periods_use_single_sign_and_are_nested():
    sm = C.summarize(RECS, 30, NOW)
    by = {p["days"]: p["connected"] for p in sm["periods"]}
    assert by == {7: 5, 30: 6, 60: 7, 90: 8}                            # tmLastNagentConnected, периоды вложены; без подключений ни разу (хост 7) нигде не активен
    assert sm["total"] == 10 and sm["active"] == 6 and sm["inactive"] == 4 and sm["never"] == 1
    assert sm["active"] + sm["inactive"] == sm["total"]


def test_server_workstation_other_split():
    sm = C.summarize(RECS, 30, NOW)
    assert (sm["servers"], sm["workstations"], sm["other_os"]) == (1, 4, 1)               # сервер 3 (40 сут) не активен; «Linux» без редакции — отдельно
    assert sm["servers"] + sm["workstations"] + sm["other_os"] == sm["active"]
    assert C.kind_of(host(1, 1, "Linux", platform="Linux")) == "other"               # Linux без редакции не относится ни к серверам, ни к станциям наугад
    assert C.kind_of(host(1, 1, "Ubuntu Server 22.04", platform="Linux")) == "server"
    assert C.kind_of(host(1, 1, "Сервер Windows", platform="Windows")) == "server"


def test_protection_metrics_are_among_active_and_list_matches_count():
    sm = C.summarize(RECS, 30, NOW)
    assert sm["no_av"] == 0 and sm["av_installed"] == 6                                # хост 3 без защиты — не активен за 30 сут
    assert sm["bases_old"] == 1 and sm["stale_info"] == 1 and sm["license_expired"] == 1
    assert sm["protected"] == 6 - 1                                                   # исключён хост с устаревшими базами (8); «Linux» с работающей защитой учтён
    sm60 = C.summarize(RECS, 60, NOW)
    assert sm60["no_av"] == 1 and sm60["active"] == 7
    for key in C.METRICS:                                                              # число и список — один предикат
        assert len(C.pick(RECS, key, 30, NOW)) == C.summarize(RECS, 30, NOW)[key]


def test_rtp_off_counts_only_hosts_with_protection():
    sm = C.summarize(RECS, 90, NOW)
    assert sm["rtp_off"] == 1 and C.pick(RECS, "rtp_off", 90, NOW)[0]["host_id"] == 4


# ------------------------------------------------------------------------------------------------ лицензии
def lic(source, key, limit=100, used=10, fp="", product="Kaspersky Endpoint Security", exp=None, origin="ksc", state="active"):
    return {"source_id": source, "source_name": f"S{source}", "lic_key": key, "origin": origin, "product": product, "kind": "коммерческая", "expires_at": exp or NOW + timedelta(days=200),
            "limit_n": limit, "used_n": used, "state": state, "fp": fp, "note": "", "updated_at": NOW}


def test_shared_license_is_counted_once():
    groups = LP.merge([lic(1, "a", 100, 30, fp="F1"), lic(2, "b", 100, 25, fp="F1"), lic(2, "c", 50, 5, product="Другой")])
    shared = next(g for g in groups if g["shared"])
    assert (shared["limit"], shared["used"], shared["free"], shared["basis"]) == (100, 55, 45, "fp")      # лимит общий, использование — сумма по серверам
    t = LP.totals(groups)
    assert (t["limit"], t["used"], t["free"], t["groups"], t["shared"]) == (150, 60, 90, 2, 1)            # 100 + 50, а не 250


def test_independent_licenses_are_summed_and_admin_can_merge():
    a, b = lic(1, "a", 100, 30), lic(2, "b", 100, 25)
    t = LP.totals(LP.merge([a, b]))
    assert (t["limit"], t["used"], t["groups"], t["shared"]) == (200, 55, 2, 0)
    merged = LP.merge([a, b], {("1", "a"): "Общий пул", ("2", "b"): "общий пул "})
    assert len(merged) == 1 and merged[0]["basis"] == "admin" and merged[0]["limit"] == 100 and merged[0]["used"] == 55


def test_unknown_usage_is_not_replaced_by_zero():
    groups = LP.merge([lic(1, "a", 100, None)])
    assert groups[0]["used"] is None and groups[0]["free"] is None
    t = LP.totals(groups)
    assert t["limit"] == 100 and t["used"] is None and t["free"] is None and t["share"] is None and t["complete"] is False
    assert LP.totals([])["limit"] is None


def test_differing_limits_in_a_pool_are_flagged():
    g = LP.merge([lic(1, "a", 100, 1, fp="F"), lic(2, "b", 120, 1, fp="F")])[0]
    assert g["limit"] == 120 and g["notes"]


# ------------------------------------------------------------------------------------------------ чтение лицензий KSC
def test_map_columns_skips_binary_and_secret_columns():
    cols = [("nId", "int"), ("wstrProductName", "nvarchar"), ("nLicenseCount", "int"), ("tmExpirationLimit", "datetime"), ("binKeyData", "varbinary"), ("wstrSerial", "nvarchar"),
            ("nType", "int"), ("nUsed", "int")]
    m = KL.map_columns(cols)
    assert m["expires"] == "tmExpirationLimit" and m["limit"] == "nLicenseCount" and m["used"] == "nUsed" and m["product"] == "wstrProductName" and m["serial"] == "wstrSerial"
    assert "binKeyData" not in m.values()
    assert KL.map_columns([("tmExpirationLimit", "datetime")]) == {"expires": "tmExpirationLimit"}       # «Limit» в названии срока не делает его лимитом


def test_records_hide_serial_and_mark_state():
    rows = [{"p": "KES Select", "e": NOW + timedelta(days=20), "l": 250, "u": 120, "s": "ABCD-123456-ABCDEFGH", "k": 1},
            {"p": "Старая", "e": NOW - timedelta(days=3), "l": 10, "u": None, "s": "", "k": None}, {"p": "Пустая", "e": None, "l": None, "u": 1, "s": "", "k": 0}]
    mp = {"product": "p", "expires": "e", "limit": "l", "used": "u", "serial": "s", "kind": "k"}
    recs = KL.to_records(rows, mp, "keys", "secret", NOW)
    assert len(recs) == 2 and recs[0]["state"] == "expiring" and recs[1]["state"] == "expired"
    assert recs[0]["kind"] == "коммерческая" and recs[0]["fp"] and "ABCD" not in str(recs[0]) and recs[1]["fp"] == ""
    same = KL.to_records(rows[:1], mp, "keys_installed", "secret", NOW)[0]["fp"]
    assert same == recs[0]["fp"] and KL.fingerprint("abcd123456abcdefgh", "secret") == same             # один ключ на разных KSC узнаётся
    assert KL.fingerprint("ABCD-123456-ABCDEFGH", "other-secret") != same


def test_infinite_values_are_not_limits():
    assert KL._int(10**9 - 1) is not None and KL._int(2**31 - 1) is None and KL._dt(datetime(2100, 1, 1)) is None and KL._dt(datetime(1970, 1, 1)) is None


# ------------------------------------------------------------------------------------------------ API
async def _setup(client, app, monkeypatch, names=("KSC-A",), recs=None):
    await login(client, "admin", "Admin-Passw0rd-123")
    ids = []
    for i, n in enumerate(names):
        src = (await client.post("/api/v1/admin/sources", json={"name": n, "host": f"ksc{i}.example.local", "database": "KAV", "username": "u", "password": "p"})).json()
        ids.append(src["id"])
    await client.post("/api/v1/auth/source", json={"source_id": ids[0]})

    async def base(request, db, src, refresh=False):
        return (recs or RECS), NOW.timestamp()

    monkeypatch.setattr("app.api.overview.protection_base", base)
    monkeypatch.setattr("app.api.protection.protection_base", base)
    return ids


async def test_overview_api_counts_periods_and_trend(client, app, monkeypatch):
    (sid,) = await _setup(client, app, monkeypatch)
    r = (await client.get("/api/v1/overview", params={"days": 30})).json()
    assert r["totals"]["active"] == 6 and r["totals"]["total"] == 10 and r["totals"]["servers"] == 1
    assert [p["connected"] for p in r["periods"]] == [5, 6, 7, 8]
    assert r["sources"][0]["name"] == "KSC-A" and r["sources"][0]["active"] == 6 and r["security"]["hosts_crit"] is None and r["licenses"]["totals"]["limit"] is None
    r7 = (await client.get("/api/v1/overview", params={"days": 7})).json()
    assert r7["totals"]["active"] == 5                                                # период переключается без смены источника
    async with app.state.session_maker() as db:
        rows = (await db.execute(OverviewDaily.__table__.select())).all()
    assert len(rows) == 1 and rows[0].data["a30"] == 6                                # срез дня для графика динамики записан один раз в сутки


async def test_overview_hosts_panel_matches_counts_and_paginates(client, app, monkeypatch):
    await _setup(client, app, monkeypatch)
    r = (await client.get("/api/v1/overview/hosts", params={"metric": "active", "days": 30, "limit": 3, "sort": "name"})).json()
    assert r["total"] == 6 and len(r["items"]) == 3 and r["items"][0]["name"] == "pc1" and r["items"][0]["source"] == "KSC-A"
    page2 = (await client.get("/api/v1/overview/hosts", params={"metric": "active", "days": 30, "limit": 3, "offset": 3})).json()
    assert [i["name"] for i in page2["items"]] == ["pc6", "pc8", "pc9"] and r["items"][1]["name"] == "pc10"
    srv = (await client.get("/api/v1/overview/hosts", params={"metric": "servers", "days": 30})).json()
    assert srv["total"] == 1 and srv["items"][0]["host_id"] == 2
    found = (await client.get("/api/v1/overview/hosts", params={"metric": "total", "q": "pc10"})).json()
    assert found["total"] == 1
    assert (await client.get("/api/v1/overview/hosts", params={"metric": "nope"})).status_code == 422


async def test_all_sources_exclude_duplicate_connection(client, app, monkeypatch):
    await login(client, "admin", "Admin-Passw0rd-123")
    for n in ("A", "B"):                                                              # одинаковые сервер, порт и база — повторное подключение одного KSC
        await client.post("/api/v1/admin/sources", json={"name": n, "host": "same.example.local", "database": "KAV", "username": "u", "password": "p"})
    c = await client.post("/api/v1/admin/sources", json={"name": "C", "host": "other.example.local", "database": "KAV", "username": "u", "password": "p"})
    assert c.status_code in (200, 201)

    async def base(request, db, src, refresh=False):
        return RECS, NOW.timestamp()

    monkeypatch.setattr("app.api.overview.protection_base", base)
    r = (await client.get("/api/v1/overview", params={"days": 30}, headers={"X-Source-Id": "all"})).json()
    assert r["scope"]["sources"] == 2 and r["totals"]["total"] == 20                  # A и C; B — дубль A, в итог не входит
    assert any(s.get("duplicate_of") == "A" for s in r["sources"])


async def test_license_admin_flow_manual_pool_and_permissions(client, app, monkeypatch):
    s1, s2 = await _setup(client, app, monkeypatch, names=("KSC-A", "KSC-B"))
    add = lambda sid, **kw: client.post("/api/v1/licenses/manual", json={"source_id": sid, "product": "Kaspersky Endpoint Security", "limit_n": 100, "used_n": 40, **kw})  # noqa: E731
    k1 = (await add(s1)).json()
    k2 = (await add(s2, used_n=20)).json()
    lic = (await client.get("/api/v1/licenses", headers={"X-Source-Id": "all"})).json()
    assert lic["totals"]["limit"] == 200 and lic["totals"]["used"] == 60 and lic["totals"]["groups"] == 2     # независимые лицензии каждого сервера
    assert (await client.put("/api/v1/licenses/pool", json={"source_id": s1, "lic_key": k1["lic_key"], "pool": "Общий"})).status_code == 204
    assert (await client.put("/api/v1/licenses/pool", json={"source_id": s2, "lic_key": k2["lic_key"], "pool": "общий"})).status_code == 204
    lic = (await client.get("/api/v1/licenses", headers={"X-Source-Id": "all"})).json()
    assert lic["totals"]["limit"] == 100 and lic["totals"]["used"] == 60 and lic["totals"]["groups"] == 1 and lic["groups"][0]["shared"]
    assert (await client.delete(f"/api/v1/licenses/manual/{s1}/{k1['lic_key']}")).status_code == 204
    async with app.state.session_maker() as db:
        db.add(LicenseRecord(source_id=uuid.UUID(s1), lic_key="ksc1", origin="ksc", product="KES", updated_at=datetime.now(timezone.utc)))
        await db.commit()
    assert (await client.delete(f"/api/v1/licenses/manual/{s1}/ksc1")).status_code == 404            # записи KSC вручную не удаляются
    await client.post("/api/v1/auth/logout")
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.post("/api/v1/licenses/manual", json={"source_id": s1, "product": "x"})).status_code == 403
    assert (await client.get("/api/v1/licenses/diag")).status_code == 403


async def test_overview_report_matches_page_and_respects_detail(client, app, monkeypatch):
    await _setup(client, app, monkeypatch)
    body = {"kind": "quick_overview", "params": {"days": 30, "metric": "servers"}, "source_ids": []}
    full = (await client.post("/api/v1/quick/preview", json=body)).json()
    assert full["total"] == 1 and full["items"][0]["name"] == "pc2" and full["items"][0]["kind_ru"] == "сервер"          # подробный: список выбранного показателя
    vals = {m["key"]: m["value"] for m in full["doc"]["metrics"]}
    page = (await client.get("/api/v1/overview", params={"days": 30})).json()["totals"]
    assert vals["active"] == page["active"] and vals["servers"] == page["servers"] and vals["lic_limit"] == "нет данных"      # те же числа, что на странице; нет лицензий — «нет данных»
    assert [t["id"] for t in full["doc"]["tables"]] == ["hosts", "sources", "periods", "licenses"]
    short = (await client.post("/api/v1/quick/preview", json={**body, "params": {"days": 30, "detail": "summary"}})).json()
    assert "hosts" not in [t["id"] for t in short["doc"]["tables"]] and short["doc"]["tables"][-1]["id"] == "summary"
    assert (await client.post("/api/v1/quick/preview", json={**body, "params": {"days": 30, "metric": "zzz"}})).status_code == 422
    job = await client.post("/api/v1/reports", json={**body, "title": ""})
    assert job.status_code == 201 and job.json()["kind"] == "quick_overview"


async def test_security_block_and_db_backed_panel(client, app, monkeypatch):
    from app.models import ZcDetection, ZcHost, ZcSource  # noqa: PLC0415

    (sid,) = await _setup(client, app, monkeypatch)
    u = uuid.UUID(sid)
    async with app.state.session_maker() as db:
        db.add(ZcSource(source_id=u, gen=1, status="ready"))
        for i, (days, crit) in enumerate([(2, 3), (10, 0), (50, 1), (5, 2)], 1):
            db.add(ZcHost(source_id=u, host_id=i, gen=1, name=f"zc{i}", search=f"zc{i}", os="Windows 10", days_since=days, k_crit=crit, ip_num=3221225984 + i))
        db.add(ZcDetection(source_id=u, gen=1, host_id=1, origin="ksc", vuln_key="CVE-1", severity=3, bucket="current"))
        db.add(ZcDetection(source_id=u, gen=1, host_id=4, origin="ksc", vuln_key="CVE-1", severity=3, bucket="current"))
        db.add(ZcDetection(source_id=u, gen=1, host_id=4, origin="ksc", vuln_key="CVE-2", severity=3, bucket="accepted"))
        await db.commit()
    r = (await client.get("/api/v1/overview", params={"days": 30})).json()
    assert r["security"]["hosts_crit"] == 2 and r["security"]["vulns"] == 1                  # хост 3 (50 сут) не активен; принятый риск в «критические» не входит
    page = (await client.get("/api/v1/overview/hosts", params={"metric": "crit_vuln", "days": 30, "sort": "name"})).json()
    assert page["total"] == 2 and [i["name"] for i in page["items"]] == ["zc1", "zc4"] and page["items"][0]["ip"] == "192.0.2.1"
    assert (await client.get("/api/v1/overview/hosts", params={"metric": "crit_vuln", "days": 90})).json()["total"] == 3
    rep = (await client.post("/api/v1/quick/preview", json={"kind": "quick_overview", "params": {"days": 30, "metric": "crit_vuln"}, "source_ids": []})).json()
    assert rep["total"] == 2 and rep["items"][0]["name"] == "zc1"                              # отчёт по тому, что открыто в панели


async def test_sources_outside_scope_use_daily_snapshot_and_payload_matches_summary(client, app, monkeypatch):
    from app.overview import snapshots as SN  # noqa: PLC0415

    s1, s2 = await _setup(client, app, monkeypatch, names=("KSC-A", "KSC-B"))
    data = SN.payload(RECS, NOW)
    assert data["a30"] == 6 and data["by"]["7"]["active"] == 5 and data["total"] == 10
    async with app.state.session_maker() as db:
        await SN.store(db, uuid.UUID(s2), data)
    r = (await client.get("/api/v1/overview", params={"days": 60})).json()
    other = next(x for x in r["sources"] if x["name"] == "KSC-B")
    assert other["snapshot"] and other["active"] == 7 and other["total"] == 10               # источник вне выбора — по срезу за выбранный период, без чтения его KSC
    assert r["totals"]["total"] == 10                                                          # в итоги выбранной области он не входит


async def test_pentest_results_count_is_hidden_from_viewers(client, app, monkeypatch):
    from app.models import PtJob  # noqa: PLC0415

    await _setup(client, app, monkeypatch)
    async with app.state.session_maker() as db:
        db.add(PtJob(title="t", status="done", findings_n=5, finished_at=datetime.now(timezone.utc), options={}, rejected=[], sev={}))
        await db.commit()
    assert (await client.get("/api/v1/overview")).json()["pentest"]["findings"] == 5
    await client.post("/api/v1/auth/logout")
    await login(client, "viewer", "Viewer-Passw0rd-123")
    src = (await client.get("/api/v1/auth/sources")).json()
    await client.post("/api/v1/auth/source", json={"source_id": src["items"][0]["id"]}) if src["items"] else None
    r = await client.get("/api/v1/overview")
    assert r.status_code != 200 or r.json()["pentest"] is None


async def test_unreachable_source_does_not_wipe_licenses(app):
    from app.licensing.service import LicenseService  # noqa: PLC0415
    from app.models import KscSource  # noqa: PLC0415

    sid = uuid.uuid4()
    async with app.state.session_maker() as db:
        db.add(KscSource(id=sid, name="A", host="a.example.local", port=1433, database="KAV", username="u", password_enc="x", auth_type="sql", tls_mode="request", is_active=True, position=0))
        db.add(LicenseRecord(source_id=sid, lic_key="k1", origin="ksc", product="KES", limit_n=10, updated_at=datetime.now(timezone.utc)))
        await db.commit()

    class Down:
        async def run(self, *a, **k):
            raise KL.KscError("connect", "нет соединения")

    class Reg:
        def client(self, src):
            return Down()

    svc = LicenseService(app.state.session_maker, Reg(), "s")
    assert await svc.run_source(sid) is False
    async with app.state.session_maker() as db:
        assert len((await db.execute(select(LicenseRecord).where(LicenseRecord.source_id == sid))).scalars().all()) == 1      # прежняя запись цела
        st = await db.get(LicenseState, sid)
        assert st.error and "нет соединения" in st.error
    with pytest.raises(KL.KscError):
        await KL.read(Down(), "s")
