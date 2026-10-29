"""Фоновые задания и ресурсы worker: ожидание места — не выполнение (аренды нет, «ожидает исполнителя»), BI не ждёт тяжёлый анализ, очередь по порядку постановки,
предел по CPU и памяти, сторож хода выполнения, журнал импорта с момента постановки в очередь, восстановление после перезапуска."""
import asyncio
import uuid

from sqlalchemy import select

from app.bi import service as SV
from app.models import BiImport, BiSource, JobLease
from app.services import resources as RS
from app.services.jobs import JOBS
from app.services.resources import RES
from tests.test_bi_api import SRC, setup
from tests.test_bi_import import BASE, row, xlsx
from tests.conftest import login


async def leases(app, kind):
    async with app.state.session_maker() as db:
        return (await db.execute(select(JobLease).where(JobLease.kind == kind))).scalars().all()


async def test_waiting_job_holds_no_lease_and_queue_is_fifo(app):
    """Так зависал BI-импорт: аренды заданий брались до места у ограничителя — четыре задания «выполнялись» (аренда продлевалась), а на деле ждали одного анализа уязвимостей."""
    order, gate = [], asyncio.Event()

    async def long_analysis():
        async with JOBS.run_heavy("vdb_analyze", "s1", task="анализ уязвимостей s1"):
            await gate.wait()

    async def job(kind, scope):
        async with JOBS.run_heavy(kind, scope, task=f"{kind} {scope}") as lease:
            order.append((kind, lease is not None))

    holder = asyncio.create_task(long_analysis())
    await asyncio.sleep(0.05)
    waiters = []
    for k, sc in (("catalog", "s1"), ("devices", "s1"), ("devices", "s2")):                          # по одному: порядок постановки в очередь определён
        waiters.append(asyncio.create_task(job(k, sc)))
        await asyncio.sleep(0.05)
    assert [x.kind for x in await leases(app, "vdb_analyze")] == ["vdb_analyze"]
    assert not await leases(app, "catalog") and not await leases(app, "devices")                       # ждут места — аренды нет, «выполняется» не показывается
    assert {k for k, _ in JOBS.waiting} == {"catalog", "devices"} and [w["task"] for w in RES.snapshot()["waiting"]] == ["catalog s1", "devices s1", "devices s2"]
    again = asyncio.create_task(job("catalog", "s1"))                                                    # такт планировщика: та же задача уже ждёт — копия не ставится
    await asyncio.sleep(0.05)
    assert again.done() and order == [("catalog", False)]
    gate.set()
    await asyncio.gather(holder, *waiters)
    assert order[1:] == [("catalog", True), ("devices", True), ("devices", True)]                        # по порядку постановки
    assert not JOBS.waiting and RES.used["bg"] == 0


async def test_bi_import_is_not_blocked_by_heavy_background_jobs(client, app, tmp_path):
    """Полоса BI отдельна: пока анализ уязвимостей занимает все фоновые места, импорт BI начинается и завершается; строка журнала — с постановки в очередь."""
    gate = asyncio.Event()

    async def hog():
        async with RES.heavy("анализ уязвимостей", RES.slots):
            await gate.wait()

    t = asyncio.create_task(hog())
    await asyncio.sleep(0.05)
    try:
        sid, _ = await asyncio.wait_for(setup(client, app, tmp_path), 60)                                # setup: загрузка файла и run_source — завершается, а не ждёт анализ
    finally:
        gate.set()
        await t
    async with app.state.session_maker() as db:
        rows = (await db.execute(select(BiImport).where(BiImport.source_id == uuid.UUID(sid)))).scalars().all()
    assert [r.status for r in rows] == ["ok"]                                                           # одна строка: «в очереди» → … → итог (без второй строки)


async def test_import_row_exists_from_enqueue_and_shows_waiting(client, app, tmp_path):
    await login(client, "admin", "Admin-Passw0rd-123")
    sid, _ = await setup(client, app, tmp_path)
    f = xlsx(tmp_path / "b.xlsx", [*BASE, row("Новиков Ян", "y.novikov@example.local", "Отдел", "WS-077")])
    up = await client.post(f"/api/v1/bi/sources/{sid}/upload", content=f.read_bytes(), headers={"Content-Type": "application/octet-stream", "X-File-Name": "b.xlsx"})
    imp_id = up.json()["import_id"]
    last = (await client.get(f"/api/v1/bi/sources/{sid}/imports")).json()["items"][0]
    assert last["id"] == imp_id and last["status"] == "queued" and last["status_ru"] == "в очереди"   # журнал заполнен сразу после постановки
    gate = asyncio.Event()

    async def hog():
        async with RES.heavy("BI: другой импорт", 1, lane="bi"):
            await gate.wait()

    h = asyncio.create_task(hog())
    await asyncio.sleep(0.05)
    svc = SV.BiService(app.state.session_maker, app.state.settings, app.state.settings_svc)
    run = asyncio.create_task(svc.run_source(uuid.UUID(sid)))
    for _ in range(50):
        await asyncio.sleep(0.05)
        st = (await client.get(f"/api/v1/bi/sources/{sid}/imports")).json()["items"][0]
        if st["status"] == "waiting":
            break
    assert st["status_ru"] == "ожидает исполнителя" and "занято" in st["message"]
    assert not await leases(app, "bi")
    gate.set()
    await h
    imp = await run
    assert imp.status == "ok" and str(imp.id) == imp_id


async def test_restart_during_import_leaves_clear_status(app):
    """Обновление приложения во время импорта: строка не остаётся «импорт» навсегда, опубликованные данные не тронуты; запрос в очереди сохраняется."""
    async with app.state.session_maker() as db:
        s = BiSource(**{k: v for k, v in SRC.items() if k != "password"})
        db.add(s)
        await db.flush()
        mid = BiImport(source_id=s.id, trigger="manual", status="importing")
        queued = BiImport(source_id=s.id, trigger="manual", status="queued")
        db.add_all([mid, queued])
        await db.flush()
        s.request = {"by": "admin", "imp_id": str(queued.id)}
        await db.commit()
        ids = (mid.id, queued.id)
    n = await SV.BiService(app.state.session_maker, app.state.settings, app.state.settings_svc).recover()
    async with app.state.session_maker() as db:
        a, b = await db.get(BiImport, ids[0]), await db.get(BiImport, ids[1])
    assert n == 1 and a.status == "failed" and "перезапуском" in a.message and b.status == "queued"


async def test_parallelism_follows_cpu_and_memory(monkeypatch):
    monkeypatch.setattr(RS, "cpu_count", lambda: 2.0)
    monkeypatch.setattr(RS, "container_limit_mb", lambda: 3072.0)
    r = RS.Resources()
    r.configure(slots=4)
    assert r.slots == 1 and r.requested == 4                                                               # 2 CPU: одно место фоновым (второе — циклу, API и BI)
    monkeypatch.setattr(RS, "cpu_count", lambda: 8.0)
    monkeypatch.setattr(RS, "container_limit_mb", lambda: 1024.0)
    r.configure(slots=4)
    assert r.slots == 1                                                                                    # 1 ГБ памяти: одна тяжёлая задача
    monkeypatch.setattr(RS, "container_limit_mb", lambda: 8192.0)
    r.configure(slots=3)
    assert r.slots == 3


async def test_stall_watchdog_reports_and_stops_renewing_hung_job(app):
    events = []

    class J:
        async def emit(self, category, event, **kw):
            events.append((event, kw.get("message", "")))
    old = JOBS.journal, JOBS.stall_s, JOBS.stall_hard_s
    JOBS.journal, JOBS.stall_s, JOBS.stall_hard_s = J(), 60, 120
    try:
        lease = await JOBS.acquire("catalog", "stuck", "чтение данных KSC")
        lease.progress_at -= 90
        await JOBS.beat_once()
        assert [e for e, _ in events] == ["job_stalled"] and "без хода выполнения" in events[0][1] and "чтение данных KSC" in events[0][1]
        await JOBS.beat_once()
        assert len(events) == 1                                                                            # о том же зависании — один раз
        lease.progress_at -= 60
        before = (await leases(app, "catalog"))[0].lease_until
        await JOBS.beat_once()
        assert events[-1][0] == "job_hung" and lease.frozen
        assert (await leases(app, "catalog"))[0].lease_until == before                                   # зависшее больше не продлевается
        lease.touch()
        await lease.finish("success")
    finally:
        JOBS.journal, JOBS.stall_s, JOBS.stall_hard_s = old
