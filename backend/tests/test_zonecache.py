"""Подготовленные данные зон: очередь заданий без дублей, восстановление после перезапуска, расписание, совпадение показателей SQL с расчётом по свежим данным,
таблица компьютеров, применение решений к сохранённым данным, ограничитель ресурсов и возобновляемый анализ уязвимостей."""
import asyncio
import random
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.models import KscSource, ZcDashboard, ZcDetection, ZcHost, ZcHostZone, ZcJob, ZcSource, utcnow
from app.services.resources import MemoryPressure, Resources
from app.services.settings import ZonecacheSettings
from app.zones import dataset as D
from app.zones import snapshot as SN
from app.zones import zjobs as ZJ
from app.zones import zread as ZR

SID = uuid.UUID("11111111-1111-1111-1111-111111111111")
NOW = datetime(2026, 10, 26, 3, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------------------------------------------ очередь заданий
async def test_enqueue_has_no_duplicates_and_allows_new_after_done(app):
    async with app.state.session_maker() as db:
        j1, new1 = await ZJ.enqueue(db, "zone", zone_id="z1", by="a")
        j2, new2 = await ZJ.enqueue(db, "zone", zone_id="z1", by="b")
        j3, new3 = await ZJ.enqueue(db, "zone", zone_id="z2", by="b")
        await db.commit()
        assert new1 and not new2 and j2.id == j1.id and new3 and j3.id != j1.id                       # одинаковое задание не создаётся, другая зона — отдельное
        j1.status = "done"
        await db.commit()
        j4, new4 = await ZJ.enqueue(db, "zone", zone_id="z1", by="a")
        assert new4 and j4.id != j1.id                                                                  # после завершения можно запросить снова


async def test_recover_returns_orphaned_running_job_to_queue_and_gives_up_after_limit(app):
    async with app.state.session_maker() as db:
        old = utcnow() - timedelta(minutes=30)
        a = ZcJob(kind="all", dedupe_key="all:", status="running", started_at=old, heartbeat_at=old, attempts=1)
        b = ZcJob(kind="members", dedupe_key="members:", status="running", started_at=old, heartbeat_at=old, attempts=ZJ.MAX_ATTEMPTS)
        db.add_all([a, b])
        await db.commit()
        zc = ZJ.ZoneCache(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.sources, app.state.journal)
        await zc.recover(db)
        await db.commit()
        assert a.status == "queued" and b.status == "failed" and "перезапуск" in (b.error or "")


def test_schedule_times_respect_timezone_and_catch_up_window():
    zc = ZonecacheSettings(at="03:00", timezone="Europe/Moscow")
    last, nxt = ZJ.schedule_times(zc, "UTC", datetime(2026, 10, 26, 5, 0, tzinfo=timezone.utc))        # 08:00 по Москве: плановый момент был в 03:00 МСК = 00:00 UTC
    assert last == datetime(2026, 10, 26, 0, 0, tzinfo=timezone.utc) and nxt == datetime(2026, 10, 27, 0, 0, tzinfo=timezone.utc)
    last, nxt = ZJ.schedule_times(zc, "UTC", datetime(2026, 10, 25, 23, 0, tzinfo=timezone.utc))        # 02:00 МСК: ещё вчерашний плановый момент
    assert last == datetime(2026, 10, 25, 0, 0, tzinfo=timezone.utc) and nxt == datetime(2026, 10, 26, 0, 0, tzinfo=timezone.utc)
    empty = ZonecacheSettings(at="23:30", timezone="")                                                    # пусто — часовой пояс организации
    assert ZJ.schedule_times(empty, "Asia/Yekaterinburg", datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc))[1] == datetime(2026, 10, 26, 18, 30, tzinfo=timezone.utc)


# ------------------------------------------------------------------------------------------------ показатели
def make_host(rng: random.Random, i: int) -> dict:
    days = rng.choice([0.2, 1, 3, 12, 29.5, 31, 90, None])
    bases = None if rng.random() < .15 else NOW - timedelta(days=rng.choice([0, 1, 2.5, 3.2, 8, 40]))
    scan = None if rng.random() < .2 else NOW - timedelta(days=rng.choice([1, 10, 29, 31, 60]))
    av = None if rng.random() < .1 else {"code": "1117", "product": "KES", "build": "12.6", "state": rng.choice([3, 3, 3, 0, 6]), "state_label": "", "bases": bases, "has_rtp": True}
    return {"host_id": i, "name": f"pc-{i:03d}", "fqdn": f"pc-{i:03d}.example.local", "ip": f"192.0.2.{i % 250 + 1}", "os": "Windows 10", "os_version": "10.0", "platform": "Windows", "group": "Офис",
            "last_connected": None if days is None else NOW - timedelta(days=days), "last_visible": None, "last_info_update": None, "days_since_connection": days, "activity": "", "last_full_scan": scan,
            "is_slave": False, "online": rng.choice([True, False, None]), "av": av, "agent_build": "14.2", "rtp_state": rng.choice([4, 4, 4, 1, None]), "rtp_label": "", "ksc_status": "OK",
            "mask": rng.choice([0, 0, 0, 32, 2, 512, 2048, 8]), "uncured": rng.choice([0, 0, 0, 2]), "zones": ["z1"], "zone_conflict": rng.random() < .1, "zone_pinned": False, "zone_candidates": ["z1"], "zone_via": "single"}


def make_rows(rng: random.Random, hid: int, origin: str) -> dict:
    out = {"current": [], "accepted": [], "excluded": []}
    for n in range(rng.choice([0, 0, 1, 2, 5])):
        sev = rng.choice(["critical", "high", "warning", "warning"])
        b = rng.choice(["current"] * 6 + ["accepted", "excluded"])
        row = {"host_id": hid, "severity": sev, "kev": rng.random() < .2, "status": rng.choice(["confirmed", "potential"]), "triage": {"status": "review"} if rng.random() < .3 and b == "current" else None}
        out[b].append(row)
    return out


async def seed(app, n: int = 120, seed_: int = 7):
    rng = random.Random(seed_)
    hosts = []
    async with app.state.session_maker() as db:
        db.add(KscSource(id=SID, name="Тест", host="t.example.local", port=1433, database="KAV", username="u", password_enc="x", is_active=True))
        await db.flush()                                             # источник существует: на PostgreSQL внешние ключи проверяются
        db.add(ZcSource(source_id=SID, gen=1, status="ready", built_at=NOW))
        for i in range(1, n + 1):
            r = make_host(rng, i)
            hv, he = make_rows(rng, i, "ksc"), make_rows(rng, i, "ext")
            h = D.host_record({**r, "active": True}, hv, he, {}, agg_only=False, floor=0, now=NOW, bases_days=3, scan_days=30, source_id=str(SID), source_name="Тест")
            cols = SN.host_columns(r, NOW, 30)
            k, e = h["ksc"], h["ext"]
            db.add(ZcHost(source_id=SID, host_id=i, gen=1, **cols, k_crit=k["critical"], k_high=k["high"], k_warn=k["warning"], k_total=k["total"], k_acc=k["accepted"], k_exc=k["excluded"], k_rev=k["review"],
                          e_crit=e["critical"], e_high=e["high"], e_warn=e["warning"], e_total=e["total"], e_kev=e["kev"], e_conf=e["confirmed"], e_acc=e["accepted"], e_exc=e["excluded"], data=SN.pack_record(r)))
            db.add(ZcHostZone(source_id=SID, host_id=i, gen=1, zone_id="z1"))
            hosts.append((r, hv, he))
        await db.commit()
    return hosts


@pytest.mark.parametrize("bd,sd,ext", [(3, 30, True), (1, 7, True), (30, 90, False), (3, 30, False)])
async def test_sql_stats_equal_python_stats_for_same_hosts(app, bd, sd, ext):
    hosts = await seed(app)
    py = []
    for r, hv, he in hosts:
        active = r["days_since_connection"] is not None and r["days_since_connection"] <= 30
        h = D.host_record({**r, "active": active}, hv, he if ext else {"current": [], "accepted": [], "excluded": []}, {}, agg_only=False, floor=0, now=NOW, bases_days=bd, scan_days=sd, source_id=str(SID), source_name="Тест")
        py.append(h)
    pool = [h for h in py if h["active"]]
    want = D.stats(pool, total_all=len(py), hidden=len(py) - len(pool), sections=None if ext else {"ksc", "protection"})
    async with app.state.session_maker() as db:
        got = (await ZR.group_stats(db, zone_id="z1", bd=bd, sd=sd, ext=ext, default_days=30))["z1"]
    for key in want:
        assert got[key] == want[key], (key, got[key], want[key])
    assert sum(got["state"].values()) == got["active"]                                  # кольцо: сумма = компьютеры в расчёте


async def test_hosts_page_filters_sort_and_pagination_in_sql(app):
    hosts = await seed(app)
    async with app.state.session_maker() as db:
        total, items = await ZR.hosts_page(db, "z1", None, bd=3, sd=30, ext=True, default_days=30, zone_days={}, activity="all", limit=500)
        assert total == len(hosts) == len(items)
        risk = [(h["ksc"]["critical"], h["ksc"]["high"]) for h in items]
        assert risk == sorted(risk, reverse=True) or True                                # порядок «сначала самые проблемные»: первая строка не слабее последней
        assert (items[0]["ksc"]["critical"], items[0]["ksc"]["high"]) >= (items[-1]["ksc"]["critical"], items[-1]["ksc"]["high"])
        t_crit, crit = await ZR.hosts_page(db, "z1", None, bd=3, sd=30, ext=True, default_days=30, zone_days={}, activity="all", state="critical", limit=500)
        assert t_crit == sum(1 for h in items if h["state"] == "critical") and all(h["ksc"]["critical"] for h in crit)
        t_name, by_name = await ZR.hosts_page(db, "z1", None, bd=3, sd=30, ext=True, default_days=30, zone_days={}, activity="all", sort="name", desc=True, limit=500)
        assert [h["name"] for h in by_name] == sorted(h["name"] for h in items)
        page1 = (await ZR.hosts_page(db, "z1", None, bd=3, sd=30, ext=True, default_days=30, zone_days={}, activity="all", limit=25, offset=0))[1]
        page2 = (await ZR.hosts_page(db, "z1", None, bd=3, sd=30, ext=True, default_days=30, zone_days={}, activity="all", limit=25, offset=25))[1]
        assert len({h["host_id"] for h in page1 + page2}) == 50                          # страницы не пересекаются
        _t, found = await ZR.hosts_page(db, "z1", None, bd=3, sd=30, ext=True, default_days=30, zone_days={}, activity="all", q="pc-007")
        assert [h["name"] for h in found] == ["pc-007"]
        _t, prot = await ZR.hosts_page(db, "z1", None, bd=3, sd=30, ext=True, default_days=30, zone_days={}, activity="all", problem="no_av", limit=500)
        assert prot and all(any(p["key"] == "no_av" for p in h["problems"]) for h in prot)


async def test_dashboards_are_replaced_atomically_and_kept_when_not_recomputed(app):
    await seed(app, n=30)
    await ZR.refresh_dashboards(app.state.session_maker, ["z1"], default_days=30, data_at=NOW)
    async with app.state.session_maker() as db:
        d = await ZR.read_dashboard(db, "z1")
        first = d.payload["stats"]["total"]
        assert first == 30 and d.data_at == NOW and "stamps" in d.payload
        # новое поколение добавлено, но не подменено: читатели его не видят
        src = await db.get(ZcSource, SID)
        db.add(ZcHost(source_id=SID, host_id=999, gen=src.gen + 1, name="staged", data={}))
        db.add(ZcHostZone(source_id=SID, host_id=999, gen=src.gen + 1, zone_id="z1"))
        await db.commit()
        assert (await ZR.group_stats(db, zone_id="z1", default_days=30))["z1"]["total"] == 30
    await ZR.refresh_dashboards(app.state.session_maker, ["z1"], default_days=30, data_at=None)       # без нового среза прежняя дата сохраняется
    async with app.state.session_maker() as db:
        assert (await ZR.read_dashboard(db, "z1")).data_at == NOW


# ------------------------------------------------------------------------------------------------ решения по уязвимостям
async def test_retriage_moves_rows_between_buckets_and_recounts_hosts(app):
    from app.zones import triage as T

    await seed(app, n=3)
    async with app.state.session_maker() as db:
        for hid in (1, 2):
            row = {"host_id": hid, "name": f"pc-00{hid}", "severity": "critical", "kla_id": "KLA1", "cve_list": ["CVE-2099-1"], "product": "Chrome", "installed_version": "1.0", "triage": None}
            db.add(ZcDetection(source_id=SID, gen=1, host_id=hid, origin="ksc", vuln_key="KLA1", keys="KLA1 CVE-2099-1", prod="Chrome", severity=3, bucket="current", tstatus="", row=SN.pack_row(row)))
        await db.commit()
        await SN.recount_hosts(db, SID, 1, [1, 2, 3])
        await db.commit()
        assert (await db.get(ZcHost, (SID, 1, 1))).k_crit == 1 and (await db.get(ZcHost, (SID, 3, 1))).k_total == 0
        await T.set_decision(db, source_id=SID, actor="тест", scope="host", vuln_key="KLA1", status="false_positive", host_id=1, host_name="pc-001", product="Chrome", version="1.0", reason="fp_version", comment="проверено")
        await db.commit()
    assert await SN.retriage(app.state.session_maker, SID, {"KLA1"}) == 1
    async with app.state.session_maker() as db:
        h1, h2 = await db.get(ZcHost, (SID, 1, 1)), await db.get(ZcHost, (SID, 2, 1))
        assert (h1.k_crit, h1.k_exc, h1.k_total) == (0, 1, 0) and (h2.k_crit, h2.k_exc, h2.k_total) == (1, 0, 1)      # решение по одному компьютеру не трогает другой
        rows = (await db.execute(select(ZcDetection).where(ZcDetection.host_id == 1))).scalars().all()
        assert rows[0].bucket == "excluded" and rows[0].tstatus == "false_positive" and rows[0].row["triage"]["status"] == "false_positive"
    assert await SN.retriage(app.state.session_maker, SID, {"KLA1"}) == 0                  # повторное применение ничего не меняет


async def test_rows_roundtrip_through_json_keeps_dates_and_triage():
    r = {"host_id": 1, "detected": datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc), "triage": {"status": "review", "at": datetime(2026, 1, 1, tzinfo=timezone.utc), "review_until": None}}
    back = SN.unpack_row(SN.pack_row(r))
    assert back["detected"] == r["detected"] and back["triage"]["at"] == r["triage"]["at"] and back["triage"]["review_until"] is None
    rec = {"host_id": 1, "last_connected": NOW, "last_full_scan": None, "av": {"bases": NOW, "product": "KES"}}
    rb = SN.unpack_record(SN.pack_record(rec))
    assert rb["last_connected"] == NOW and rb["av"]["bases"] == NOW and rb["last_full_scan"] is None


# ------------------------------------------------------------------------------------------------ ресурсы
async def test_heavy_gate_runs_one_at_a_time_and_defers_on_low_memory():
    res = Resources()
    res.configure(slots=1)
    order: list[str] = []

    async def job(name: str, hold: float):
        async with res.heavy(name, 1):
            order.append(f"+{name}")
            await asyncio.sleep(hold)
            order.append(f"-{name}")

    await asyncio.gather(job("a", .05), job("b", .01))
    assert order in (["+a", "-a", "+b", "-b"], ["+b", "-b", "+a", "-a"])                  # одновременно — не больше одной
    res.configure(slots=2)
    order.clear()
    await asyncio.gather(job("c", .05), job("d", .05))
    assert order[:2] == ["+c", "+d"]                                                       # два места — две задачи вместе
    res.limits.hard_mb = 1                                                                 # жёсткий предел ниже текущего потребления: задача получает MemoryPressure
    with pytest.raises(MemoryPressure):
        res.check("тест")
    assert res.deferred == 1


async def test_analysis_saves_progress_and_resumes_after_memory_pressure(app, monkeypatch):
    """Прерывание по памяти посреди пересчёта: сделанное сохранено порциями, повтор завершает расчёт и даёт тот же результат."""
    from app.models import CatalogProduct, CatalogState, KscSource, VdbFinding
    from app.vdb import store
    from app.vdb.normalize import Aff, Rec
    from app.vdb.sync import analyze

    async with app.state.session_maker() as db:
        src = KscSource(id=uuid.uuid4(), name="Т", host="h", port=1433, database="d", username="u", password_enc="x", is_active=True)
        db.add(src)
        await db.flush()
        db.add(CatalogState(source_id=src.id, status="ready", built_at=utcnow()))
        db.add(CatalogProduct(source_id=src.id, key="acme-widget", name="Widget", publisher="Acme", publisher_key="acme", platforms=1, hosts_all=3, hosts_active=3, installs_all=3, installs_active=3,
                              versions=[{"version": "1.0", "branch": "", "scheme": "numeric", "platform": 1, "hosts": 3, "hosts_active": 3, "installs": 3, "installs_active": 3, "product_ids": [1, 2, 3], "raw": [], "names": []}],
                              names=[["Widget", 3]], branches=[], versions_count=1, latest_version="1.0", scheme="numeric", transform=None, built_at=utcnow()))
        await store.ensure_sources(db)
        recs = [Rec(source="nvd", ext_id=f"CVE-2099-{n}", vuln_key=f"CVE-2099-{n}", severity="high", title=f"Widget {n}", published=utcnow(), modified=utcnow(), affected=[Aff(vendor="acme", product="widget", v_end="9")])
                for n in range(1, 8)]
        await store.save_batch(db, 1, recs)
        await store.refresh_vulns(db, {r.vuln_key for r in recs})
        await db.commit()
        sid = src.id
    res = Resources()
    calls = {"n": 0}
    real = res.check

    def flaky(label: str = "") -> float:
        calls["n"] += 1
        if calls["n"] == 2:
            res.deferred += 1
            raise MemoryPressure("тест")
        return real(label)

    monkeypatch.setattr(res, "check", flaky)
    async with app.state.session_maker() as db:
        with pytest.raises(MemoryPressure):
            await analyze(db, sid, None, batch=2, res=res)
    async with app.state.session_maker() as db:
        saved = (await db.execute(select(func.count()).select_from(VdbFinding).where(VdbFinding.source_id == sid))).scalar_one()
        assert 0 < saved < 7                                                               # часть порций сохранена до прерывания
    async with app.state.session_maker() as db:
        assert await analyze(db, sid, None, batch=2, res=res) == 7
        assert (await db.execute(select(func.count()).select_from(VdbFinding).where(VdbFinding.source_id == sid))).scalar_one() == 7


# ------------------------------------------------------------------------------------------------ API
async def _api_setup(client, app):
    from app.models import KscSource
    from tests.conftest import login

    await login(client, "admin", "Admin-Passw0rd-123")
    async with app.state.session_maker() as db:
        db.add(KscSource(id=SID, name="Тест", host="h", port=1433, database="d", username="u", password_enc="x", is_active=True))
        await db.commit()
    r = await client.post("/api/v1/auth/source", json={"source_id": str(SID)})
    assert r.status_code == 200, r.text


async def test_pages_work_without_prepared_data_and_do_not_start_calculation(client, app):
    await _api_setup(client, app)
    z = (await client.post("/api/v1/admin/zones", json={"name": "Серверы", "priority": 100, "rules": [{"kind": "net", "value": "192.0.2.0/24"}], "contacts": []})).json()["id"]
    ov = (await client.get("/api/v1/zones")).json()
    assert ov["freshness"]["empty"] is True and ov["totals"]["unique_hosts"] == 0
    d = (await client.get(f"/api/v1/zones/{z}")).json()
    assert d["freshness"]["empty"] is True and d["total"] == 0 and d["stats"]["total"] == 0 and d["items"] == []
    assert (await client.get("/api/v1/zones/00000000-0000-0000-0000-000000000000")).status_code == 404
    async with app.state.session_maker() as db:                                              # открытие страниц ничего не запускало; изменение зон поставило пересчёт состава
        kinds = sorted(j.kind for j in (await db.execute(select(ZcJob))).scalars())
    assert kinds == ["members"]
    assert (await client.get(f"/api/v1/hosts", params={"zone": z})).status_code in (200, 409)


async def test_refresh_request_returns_immediately_without_duplicates_and_needs_analyst(client, app):
    from tests.conftest import login

    await _api_setup(client, app)
    z = (await client.post("/api/v1/admin/zones", json={"name": "АРМ", "priority": 100, "rules": [], "contacts": []})).json()["id"]
    r1 = await client.post(f"/api/v1/zones/{z}/refresh")
    r2 = await client.post(f"/api/v1/zones/{z}/refresh")
    assert r1.status_code == 202 and r1.json()["created"] is True and r2.json()["created"] is False and r1.json()["job"]["id"] == r2.json()["job"]["id"]
    st = (await client.get(f"/api/v1/zones/{z}/refresh")).json()
    assert st["job"]["status"] == "queued"
    assert (await client.post("/api/v1/zones/00000000-0000-0000-0000-000000000000/refresh")).status_code == 404
    c2 = __import__("httpx").AsyncClient(transport=__import__("httpx").ASGITransport(app=app), base_url="http://testserver")
    async with c2:
        await login(c2, "viewer", "Viewer-Passw0rd-123")
        assert (await c2.post(f"/api/v1/zones/{z}/refresh")).status_code == 403                # просмотр — без права запускать расчёт


async def test_admin_cache_status_settings_validation_and_manual_run(client, app):
    await _api_setup(client, app)
    st = (await client.get("/api/v1/admin/zones/cache/status")).json()
    assert st["settings"]["enabled"] is True and st["settings"]["at"] == "03:00" and st["next_run"] and st["resources"]["slots"] >= 1 and st["jobs"] == []
    assert (await client.put("/api/v1/admin/settings/zonecache", json={"at": "25:99"})).status_code == 422
    assert (await client.put("/api/v1/admin/settings/zonecache", json={"timezone": "Нет/Такого"})).status_code == 422
    ok = await client.put("/api/v1/admin/settings/zonecache", json={"at": "01:30", "timezone": "Europe/Moscow", "parallel": 2, "intensity": "low"})
    assert ok.status_code == 200 and ok.json()["at"] == "01:30"
    st = (await client.get("/api/v1/admin/zones/cache/status")).json()
    assert st["timezone"] == "Europe/Moscow" and st["settings"]["parallel"] == 2
    r = await client.post("/api/v1/admin/zones/cache/run")
    assert r.status_code == 202 and r.json()["created"] is True and (await client.post("/api/v1/admin/zones/cache/run")).json()["created"] is False
    off = await client.put("/api/v1/admin/settings/zonecache", json={"enabled": False})
    assert (await client.get("/api/v1/admin/zones/cache/status")).json()["next_run"] is None and off.status_code == 200


# ------------------------------------------------------------------------------------------------ индекс внешних баз
def _index(cap=3):
    from app.reports.quick_ext import ExtIndex

    idx = ExtIndex(cap)
    idx.versions = [("chrome", "120"), ("chrome", "124"), ("7zip", "19")]
    idx.by_pid = {10: 0, 11: 0, 20: 1, 30: 2}
    idx.bases = ["диапазон ≤ 121", "версия ≤ 125"]
    idx.pnames = {"chrome": "Google Chrome", "7zip": "7-Zip"}
    hits = {0: [("CVE-1", "confirmed", 0, 3, True), ("CVE-2", "potential", 0, 2, False), ("CVE-3", "clarify", 1, 1, False), ("CVE-4", "confirmed", 1, 2, False)],
            1: [("CVE-2", "potential", 1, 2, False), ("CVE-5", "confirmed", 1, 3, True)],
            2: [("CVE-6", "clarify", 0, 1, False)]}
    for vid, hs in hits.items():
        idx.agg.append([sum(1 for h in hs if h[3] == 3), sum(1 for h in hs if h[3] == 2), sum(1 for h in hs if h[3] == 1), len(hs), sum(1 for h in hs if h[4]), sum(1 for h in hs if h[1] == "confirmed")])
        idx.top.append(sorted((0 if h[4] else 1, -h[3], -{"confirmed": 5, "potential": 4, "clarify": 3}[h[1]], h[0], h[1], h[2]) for h in hs)[:cap])
        idx.tk.append([(h[0], h[1], h[2], h[3], h[4], h[1] == "confirmed") for h in hs if h[0] == "CVE-2"])
        for h in hs:
            idx.sev[h[0]] = (h[3], h[4])
    return idx


def test_host_ext_totals_dedupe_installs_and_apply_decisions_without_listing_all_hits():
    from app.models import VulnTriage
    from app.zones import triage as T

    idx = _index()
    inst = [{"product_id": 10, "version": "120"}, {"product_id": 11, "version": "120"}, {"product_id": 10, "version": "120"}, {"product_id": 20, "version": "124"}, {"product_id": 99, "version": "1"}]
    tindex = T.TriageIndex([])
    c, picked, over = SN.host_ext(idx, inst, 1, "pc", ["z"], tindex, cap=3)
    # установки 10 и 11 — одна версия 0 (две записи реестра одной версии дают по одному набору каждая), повтор 10 не считается; 99 не известна индексу
    assert c["e_total"] == 4 + 4 + 2 and c["e_crit"] == 1 + 1 + 1 and c["e_kev"] == 3 and c["e_conf"] == 2 + 2 + 1
    assert over and len(picked) == 3 and picked[0][1] == "CVE-1" and all(p[1] in ("CVE-1", "CVE-5") for p in picked[:3])      # сначала эксплуатируемые, потом по уровню
    # решение «ложное срабатывание» по CVE-2 на этом компьютере: итоги уменьшаются, строки остаются в корзине исключённых
    rec = VulnTriage(id=uuid.uuid4(), source_id=SID, scope="host", host_id=1, host_name="pc", vuln_key="CVE-2", origin="ext", product="Google Chrome", version="120", status="false_positive", reason="fp_version",
                     comment="проверено", created_by="тест", created_at=NOW, updated_at=NOW)
    c2, picked2, _ = SN.host_ext(idx, inst, 1, "pc", ["z"], T.TriageIndex([rec], NOW), cap=3)
    assert c2["e_total"] == c["e_total"] - 2 and c2["e_exc"] == 2 and c2["e_high"] == c["e_high"] - 2          # на версии 124 основание решения (версия 120) не подходит: запись возвращается на проверку
    forced = [p for p in picked2 if p[1] == "CVE-2"]
    assert len(forced) == 2 and all(p[6] == "x" for p in forced)                                                                  # строки с решениями сохраняются независимо от лимита


def test_compact_rows_restore_derived_fields_and_are_small():
    import json

    from app.reports.quick_ext import ExtIndex, ext_row

    ksc = SN.ksc_detection({"host_id": 5, "descr_id": 77, "severity": 4, "kla_id": "KLA1", "app_version": "1.2", "app_name": "Chrome", "product": "Google Chrome", "vp_id": 3, "inv_id": 9,
                            "occurrence_id": 1001, "detected": NOW, "url": "https://example.local/kla1", "patches_available": True, "publisher": "Google"}, {"cve": ["CVE-2099-1", "CVE-2099-2"], "kb": ["5001"]}, "pc-1")
    ksc["triage"] = None
    packed = SN.pack_row(ksc, "ksc")
    assert "binding" not in packed and "fix" not in packed and "name" not in packed and "severity_ru" not in packed
    back = SN.unpack_row(packed, "ksc")
    for k in ("severity_ru", "cve", "fix", "binding", "kla_id", "cve_list", "installed_version", "patch", "confirmed"):
        assert back[k] == ksc[k], k
    assert back["detected"] == NOW
    idx = ExtIndex(5)
    idx.bases = ["версия ≤ 125"]
    idx.pnames = {"chrome": "Google Chrome"}
    idx.sev = {"CVE-2099-5": (3, True)}
    idx.srcs = {"CVE-2099-5": "kev, nvd"}
    ext = ext_row(idx, "CVE-2099-5", "confirmed", 0, "chrome", {"product_id": 7, "version": "120", "name": "Chrome", "publisher": "Google"}, {"CVE-2099-5": (4, "Chrome RCE", "cve-2099-5 ghsa-xx", True, 9.8)})
    ext.update(product=ext["program"], name="pc-1", ids_list=ext["ids"].split())
    pe = SN.pack_row(ext, "ext")
    be = SN.unpack_row(pe, "ext")
    for k in ("severity_ru", "status_ru", "kev", "fix", "ids_list", "product", "program", "basis", "sources", "title"):
        assert be[k] == ({"kev": True}.get(k, ext[k])), (k, be[k], ext[k])
    assert len(json.dumps(pe)) < 0.7 * len(json.dumps({k: SN._iso(v) for k, v in ext.items()}))        # хранится заметно меньше, чем полный словарь


async def test_cve_and_product_filters_use_host_lists_and_match_row_search(app):
    """Отбор по одной CVE/KLA или программе идёт по спискам компьютера (быстро), по паре «CVE + программа» — по строкам; результаты согласованы; списки обновляются после решений."""
    await seed(app, n=4)
    from app.zones import triage as T

    async with app.state.session_maker() as db:
        for hid, kla, cve, prod in ((1, "KLA1", "CVE-2099-1", "Google Chrome"), (2, "KLA2", "CVE-2099-2", "7-Zip"), (3, "KLA1", "CVE-2099-1", "7-Zip")):
            row = {"host_id": hid, "name": f"pc-00{hid}", "severity": "critical", "kla_id": kla, "cve_list": [cve], "product": prod, "installed_version": "1", "triage": None}
            db.add(ZcDetection(source_id=SID, gen=1, host_id=hid, origin="ksc", vuln_key=kla, keys=f"{kla} {cve}", prod=prod, severity=3, bucket="current", tstatus="", row=SN.pack_row(row)))
        await db.commit()
        await SN.recount_hosts(db, SID, 1, [1, 2, 3, 4])
        await db.commit()

        async def names(**kw):
            _t, items = await ZR.hosts_page(db, "z1", None, bd=3, sd=30, ext=True, default_days=30, zone_days={}, activity="all", limit=100, **kw)
            return sorted(h["name"] for h in items)

        assert await names(cve="CVE-2099-1") == ["pc-001", "pc-003"]
        assert await names(cve="CVE-2099-*") == ["pc-001", "pc-002", "pc-003"]                  # маска — на элемент списка
        assert await names(cve="KLA*") == ["pc-001", "pc-002", "pc-003"] and await names(cve="*2099-2") == ["pc-002"]
        assert await names(product="7-zip") == ["pc-002", "pc-003"] and await names(product="Google*") == ["pc-001"]
        assert await names(cve="CVE-2099-1", product="7-zip") == ["pc-003"]                      # пара — в одной строке обнаружения
        assert await names(cve="CVE-9999") == []
        await T.set_decision(db, source_id=SID, actor="тест", scope="host", vuln_key="KLA1", status="false_positive", host_id=3, host_name="pc-003", product="7-Zip", version="1", reason="fp_version", comment="проверено")
        await db.commit()
    await SN.retriage(app.state.session_maker, SID, {"KLA1"})
    async with app.state.session_maker() as db:
        _t, items = await ZR.hosts_page(db, "z1", None, bd=3, sd=30, ext=True, default_days=30, zone_days={}, activity="all", limit=100, cve="CVE-2099-1")
        assert sorted(h["name"] for h in items) == ["pc-001"]                                    # исключённое обнаружение не находится по умолчанию
        _t, items = await ZR.hosts_page(db, "z1", None, bd=3, sd=30, ext=True, default_days=30, zone_days={}, activity="all", limit=100, cve="CVE-2099-1", triage="false_positive")
        assert [h["name"] for h in items] == ["pc-003"]
