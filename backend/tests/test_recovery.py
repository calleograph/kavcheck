"""Восстановление фоновых задач после перезапуска, сбоя и обновления; независимость источников; координация между исполнителями.
Источники и данные синтетические и общие (не повторяют чью-либо установку). Параллельные сценарии — на PostgreSQL (TEST_PG_URL)."""
import asyncio
import os
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select, update

import app.services.catalog as CS
from app.eol import compute as C
from app.eol.service import EolService
from app.ksc import catalog_build as CB
from app.models import CatalogProduct, CatalogState, EolState, JobLease, JobRun, KscSource, ReportJob, VdbSource, ZcJob, utcnow
from app.reports.runner import Runner
from app.services.jobs import JOBS, Jobs
from app.vdb.sync import VdbSync
from app.zones.zjobs import ZoneCache
from tests.test_eol_compute import FakeKsc, TODAY, hosts
from tests.test_eol_multisource import rows, seed_many

PG = bool(os.environ.get("TEST_PG_URL"))
needs_pg = pytest.mark.skipif(not PG, reason="нужен PostgreSQL: настоящие параллельные транзакции")


def family(key="php", version="7.4.16"):
    return {"key": key, "name": key.upper(), "publisher": "Vendor", "publisher_key": "vendor", "origin": "auto", "component": False, "family_key": key, "family_size": 1, "platforms": 1, "note": None,
            "names": [[key, 1]], "versions": [{"version": version, "branch": "7.4", "scheme": "numeric", "platform": 1, "installs": 1, "installs_active": 1, "hosts": 1, "hosts_active": 1, "product_ids": [1], "raw": [version], "names": [key]}],
            "branches": [], "versions_count": 1, "latest_version": version, "scheme": "numeric", "transform": None, "hosts_all": 1, "hosts_active": 1, "installs_all": 1, "installs_active": 1, "first_seen": None}


class FakeSession:
    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def sched(app):
    return CS.CatalogScheduler(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal)


def patch_ksc(monkeypatch, *, version="9.9.9", gate=None, calls=None):
    """Подставной KSC для сборки каталога; gate — threading.Event: сборка ждёт его (имитация долгой работы)."""
    monkeypatch.setattr(CS, "Session", FakeSession)
    monkeypatch.setattr(CS.CB, "signature", lambda s: "sig")

    def build(s, activity_days, overrides, progress):
        if calls is not None:
            calls.append(1)
        if gate is not None:
            gate.wait(20)
        return [family(version=version)], {"products": 1, "installs": 1, "hosts": 1}

    monkeypatch.setattr(CS.CB, "build", build)
    monkeypatch.setattr(CS.CatalogScheduler, "_params", lambda self, src: None)


async def state(app, sid):
    async with app.state.session_maker() as db:
        return await db.get(CatalogState, sid)


async def make_stale_build(app, sid, *, other_host="old-container"):
    """След убитого worker: состояние «строится» и аренда, которую никто не продлевает."""
    old = Jobs().configure(app.state.session_maker, ttl=120)
    old.owner = f"{other_host}/1/dead"
    await old.acquire("catalog", str(sid), "чтение данных KSC")
    async with app.state.session_maker() as db:
        st = await db.get(CatalogState, sid)
        st.status, st.started_at, st.progress = "building", utcnow(), "запуск"
        await db.commit()
    return old


# ---- 1, 5, 13. перезапуск в момент построения при наличии прежнего каталога; EOL по прежнему каталогу
async def test_restart_during_build_with_previous_catalog_recovers_without_waiting(app, monkeypatch):
    (sid,) = await seed_many(app, 1)
    await make_stale_build(app, sid, other_host="host-a")
    new = Jobs().configure(app.state.session_maker, ttl=120)
    new.owner = "host-a/9/new"                                                       # тот же контейнер после перезапуска
    assert await new.recover_own() == 1
    s = sched(app)
    async with app.state.session_maker() as db:
        src = await db.get(KscSource, sid)
        assert await CS.effective_status(await db.get(CatalogState, sid)) == "interrupted"                      # «строится» без процесса не показывается как работа
        svc = EolService(app.state.session_maker, app.state.settings_svc, None)
        assert sid in await svc.due(TODAY)                                                                       # EOL не ждёт пересборки: считает по последнему готовому каталогу
        reason = await s.due(db, src, 30, (await CS.load_overrides(db))[1])
    assert reason == "прервано предыдущее построение"
    async with app.state.session_maker() as db:
        assert (await db.execute(select(CatalogProduct).where(CatalogProduct.source_id == sid))).scalars().first() is not None      # прежние данные на месте
    patch_ksc(monkeypatch, version="8.8.8")
    await s.tick()
    await asyncio.gather(*list(s._tasks))
    st = await state(app, sid)
    assert st.status == "ready" and st.error is None
    async with app.state.session_maker() as db:
        assert (await db.execute(select(CatalogProduct.latest_version).where(CatalogProduct.source_id == sid))).scalar_one() == "8.8.8"


# ---- 6. зависшее «строится» без прежнего результата
async def test_stuck_building_without_previous_result_is_rebuilt(app, monkeypatch):
    (sid,) = await seed_many(app, 1)
    async with app.state.session_maker() as db:
        await db.execute(CatalogProduct.__table__.delete().where(CatalogProduct.source_id == sid))
        st = await db.get(CatalogState, sid)
        st.status, st.built_at = "building", None
        await db.commit()
    await make_stale_build(app, sid)
    async with app.state.session_maker() as db:
        await db.execute(update(JobLease).values(lease_until=utcnow() - timedelta(seconds=1)))                    # аренда истекла (процесс чужого контейнера не продлевает)
        await db.commit()
    s = sched(app)
    patch_ksc(monkeypatch)
    await s.tick()
    await asyncio.gather(*list(s._tasks))
    st = await state(app, sid)
    assert st.status == "ready" and st.built_at is not None
    assert [r.status for r in await JOBS.runs("catalog", str(sid), 5)][-1] == "interrupted"                      # прерванный заход сохранён в истории


async def test_live_build_is_not_touched_and_crash_loop_is_backed_off(app, monkeypatch):
    (sid,) = await seed_many(app, 1)
    old = await make_stale_build(app, sid)
    s = sched(app)
    async with app.state.session_maker() as db:
        src = await db.get(KscSource, sid)
        rev = (await CS.load_overrides(db))[1]
        assert await s.due(db, src, 30, rev) is None                                                               # исполнитель жив (аренда действует): ничего не трогаем
        assert (await db.get(CatalogState, sid)).status == "building"
        await db.execute(update(JobLease).values(lease_until=utcnow() - timedelta(seconds=1)))
        await db.commit()
    for _ in range(3):                                                                                              # три прерывания подряд: не гоняем источник по кругу
        lease = await old.acquire("catalog", str(sid))
        async with app.state.session_maker() as db:
            await db.execute(update(JobLease).values(lease_until=utcnow() - timedelta(seconds=1)))
            await db.commit()
        await Jobs().configure(app.state.session_maker).acquire("catalog", str(sid))
        async with app.state.session_maker() as db:
            await db.execute(update(JobLease).values(lease_until=utcnow() - timedelta(seconds=1)))
            await db.commit()
    async with app.state.session_maker() as db:
        st = await db.get(CatalogState, sid)
        st.status = "building"
        await db.commit()
        assert await s.due(db, src, 30, rev) is None


# ---- 7, 8. два исполнителя; запоздавший результат
async def test_two_workers_build_one_catalog_once(app, monkeypatch):
    import threading

    (sid,) = await seed_many(app, 1)
    calls, gate = [], threading.Event()
    patch_ksc(monkeypatch, gate=gate, calls=calls)
    a, b = sched(app), sched(app)
    ta = asyncio.create_task(a.build(sid, "тест"))
    await asyncio.sleep(0.5)
    tb = asyncio.create_task(b.build(sid, "тест"))                                                                  # второй исполнитель той же задачи
    await asyncio.sleep(0.5)
    gate.set()
    await asyncio.gather(ta, tb)
    assert len(calls) == 1


async def test_late_result_of_a_taken_over_build_is_not_published(app, monkeypatch):
    import threading

    (sid,) = await seed_many(app, 1)
    gate = threading.Event()
    patch_ksc(monkeypatch, version="1.1.1", gate=gate)
    s = sched(app)
    t = asyncio.create_task(s.build(sid, "тест"))
    await asyncio.sleep(0.5)
    async with app.state.session_maker() as db:
        await db.execute(update(JobLease).where(JobLease.kind == "catalog").values(lease_until=utcnow() - timedelta(seconds=1)))
        await db.commit()
    thief = Jobs().configure(app.state.session_maker, ttl=120)
    thief.owner = "other-host/2/x"
    assert await thief.acquire("catalog", str(sid)) is not None                                                     # другой исполнитель перехватил задание (аренда не продлевалась)
    gate.set()
    await t
    async with app.state.session_maker() as db:
        assert (await db.execute(select(CatalogProduct.latest_version).where(CatalogProduct.source_id == sid))).scalar_one() == "7.4.16"      # запоздавший результат не опубликован
    assert (await JOBS.runs("catalog", str(sid), 1))[0].status == "lost"


# ---- 2, 3, 4, 12. перезапуск всего стека во время нескольких заданий
async def test_full_stack_restart_leaves_no_running_state(app):
    (sid,) = await seed_many(app, 1)
    sm = app.state.session_maker
    old = Jobs().configure(sm, ttl=120)
    old.owner = "stack-1/1/dead"
    job_id, zjob_id = uuid.uuid4(), uuid.uuid4()
    async with sm() as db:
        db.add(ReportJob(id=job_id, source_id=sid, source_ids=[str(sid)], source_name="KSC-1", kind="version_audit", title="t", params={}, created_by="x", status="running", started_at=utcnow()))
        db.add(ZcJob(id=zjob_id, kind="all", dedupe_key="all:", status="running", started_at=utcnow(), heartbeat_at=utcnow(), attempts=1))
        vs = await db.get(VdbSource, "nvd")
        if vs is None:
            db.add(VdbSource(key="nvd", enabled=True, interval_hours=24))
            await db.flush()
            vs = await db.get(VdbSource, "nvd")
        vs.status, vs.last_started_at = "running", utcnow()
        st = await db.get(CatalogState, sid)
        st.status = "building"
        db.add(EolState(source_id=sid, started_at=utcnow(), progress="устройства: программы", app_version="0.0.1", error="Не удалось рассчитать EOL", error_at=utcnow()))
        await db.commit()
    for kind, scope in (("catalog", str(sid)), ("eol", str(sid)), ("report", str(job_id)), ("zjob", str(zjob_id)), ("vdb_sync", "nvd")):
        await old.acquire(kind, scope)
    new = Jobs().configure(sm, ttl=120)
    new.owner = "stack-1/5/new"                                                                                       # все контейнеры стека перезапущены
    assert await new.recover_own() == 5
    JOBS.configure(sm, ttl=120)
    JOBS.owner = "stack-1/5/new"
    assert await Runner(sm, app.state.settings, app.state.settings_svc, app.state.journal).recover_orphans() == 1
    await ZoneCache(sm, app.state.settings, app.state.settings_svc, app.state.sources, app.state.journal).recover_on_start()
    await VdbSync(sm, app.state.settings, app.state.settings_svc, app.state.journal).recover_interrupted()
    eol = EolService(sm, app.state.settings_svc, None)
    eol.version = "9.9.9"
    assert await eol.recover() == 1
    async with sm() as db:
        assert (await db.get(ReportJob, job_id)).status == "queued"                                                   # отчёт вернулся в очередь, а не завис на три часа
        assert (await db.get(ZcJob, zjob_id)).status == "queued"
        assert (await db.get(VdbSource, "nvd")).status == "error" and (await db.get(EolState, sid)).started_at is None and (await db.get(EolState, sid)).error is None
        assert (await db.execute(select(JobLease))).scalars().all() == []
    reasons = [r.status for r in await JOBS.runs("eol", str(sid), 5)]
    assert "interrupted" in reasons and "error" in reasons                                                            # прерванный заход и прежняя ошибка — в истории


async def test_a_job_led_by_another_worker_is_not_hijacked_on_restart(app):
    (sid,) = await seed_many(app, 1)
    sm = app.state.session_maker
    other = Jobs().configure(sm, ttl=120)
    other.owner = "worker-2/1/live"
    zjob_id = uuid.uuid4()
    async with sm() as db:
        db.add(ZcJob(id=zjob_id, kind="all", dedupe_key="all:", status="running", started_at=utcnow(), heartbeat_at=utcnow(), attempts=1))
        await db.commit()
    await other.acquire("zjob", str(zjob_id))
    JOBS.configure(sm, ttl=120)
    await ZoneCache(sm, app.state.settings, app.state.settings_svc, app.state.sources, app.state.journal).recover_on_start()
    async with sm() as db:
        assert (await db.get(ZcJob, zjob_id)).status == "running"                                                      # задание ведёт живой второй worker


# ---- 9, 10. сбой процесса посреди расчёта EOL и повторный запуск
async def test_killed_eol_calculation_resumes_and_keeps_previous_result(app):
    a, b = await seed_many(app, 2)
    sm = app.state.session_maker
    from tests.test_eol_multisource import run
    await run(app, a)
    before = await rows(app, a)
    dead = Jobs().configure(sm, ttl=120)
    dead.owner = "host-z/1/dead"
    await dead.acquire("eol", str(a), "устройства: операционные системы")                                             # процесс убит (OOM) посреди расчёта
    async with sm() as db:
        await db.execute(update(EolState).where(EolState.source_id == a).values(started_at=utcnow(), progress="устройства: операционные системы", inputs=""))
        await db.commit()
    new = Jobs().configure(sm, ttl=120)
    new.owner = "host-z/9/new"
    await new.recover_own()
    JOBS.configure(sm, ttl=120)
    svc = EolService(sm, app.state.settings_svc, type("S", (), {"client": lambda self, s: FakeKsc({11: [(1, 1), (2, 0)], 12: [(5, 1)], 13: [(1, 1)]}, hosts())})(), app.state.journal)
    assert await svc.recover() == 0
    assert await rows(app, a) == before                                                                                 # прежний результат цел
    assert a in await svc.due(TODAY)
    assert await svc.run_source(a) is not None
    async with sm() as db:
        st = await db.get(EolState, a)
    assert st.computed_at and st.error is None and st.started_at is None and await rows(app, a) == before


# ---- 11. один недоступный источник не останавливает остальные
async def test_unreachable_source_does_not_stop_others(app):
    ids = await seed_many(app, 3)
    sm = app.state.session_maker
    order = []

    class Registry:
        def client(self, src):
            idx = ids.index(src.id)

            class K(FakeKsc):
                async def run(self, sql, params=None, *, max_rows=0):
                    order.append(idx)
                    if idx == 0:
                        await asyncio.sleep(0.2)
                        raise ConnectionError("KSC недоступен")
                    return await super().run(sql, params, max_rows=max_rows)
            return K({11: [(1, 1)], 12: [(5, 1)], 13: []}, hosts())

    svc = EolService(sm, app.state.settings_svc, Registry(), app.state.journal)
    await svc.tick()
    await asyncio.gather(*list(svc._tasks))
    async with sm() as db:
        states = {i: await db.get(EolState, i) for i in ids}
    assert states[ids[0]].error and "Предыдущие результаты сохранены" in states[ids[0]].error and states[ids[0]].computed_at is None
    assert all(states[i].computed_at and states[i].error is None for i in ids[1:])                                    # остальные рассчитаны
    assert (await rows(app, ids[1]))[0] and not (await rows(app, ids[0]))[0]


@needs_pg
async def test_sources_are_processed_concurrently_not_one_after_another(app):
    ids = await seed_many(app, 3)
    sm = app.state.session_maker
    started, finished = [], []

    class Registry:
        def client(self, src):
            class K(FakeKsc):
                async def run(self, sql, params=None, *, max_rows=0):
                    started.append(src.id)
                    await asyncio.sleep(0.4)
                    return await super().run(sql, params, max_rows=max_rows)
            return K({11: [(1, 1)], 12: [], 13: []}, hosts())

    from app.services.resources import RES
    old = RES.slots
    RES.slots = 3
    try:
        svc = EolService(sm, app.state.settings_svc, Registry(), app.state.journal)
        await svc.tick()
        await asyncio.sleep(0.5)
        assert len(set(started)) == 3                                                                                  # медленный источник не держит остальные в очереди
        await asyncio.gather(*list(svc._tasks))
    finally:
        RES.slots = old


@needs_pg
async def test_concurrent_eol_runs_of_one_source_on_two_executors_do_not_conflict(app):
    (sid,) = await seed_many(app, 1)
    sm = app.state.session_maker
    reg = type("S", (), {"client": lambda self, s: FakeKsc({11: [(1, 1)], 12: [(5, 1)], 13: []}, hosts())})()
    a, b = EolService(sm, app.state.settings_svc, reg, app.state.journal), EolService(sm, app.state.settings_svc, reg, app.state.journal)
    res = await asyncio.gather(a.run_source(sid), b.run_source(sid), a.run_source(sid), b.run_source(sid), return_exceptions=True)
    assert not [r for r in res if isinstance(r, Exception)] and sum(1 for r in res if r) >= 1
    assert (await rows(app, sid))[0]
