"""«Техническое состояние»: показатели из /proc и cgroup, задания (живой пульс без хода выполнения, просроченная аренда, ожидание с причиной от планировщика),
PostgreSQL без значений в текстах запросов, диагностический отчёт без секретов, доступ только администратору, «Обновить данные» без лавины расчётов."""
import asyncio
import json
import time
import uuid
from datetime import timedelta

from app.models import JobLease, JobRun, KscSource, ServiceHeartbeat, utcnow
from app.services.jobs import JOBS
from app.services.resources import RES
from app.tech import collect as TC
from app.tech import pg as PG
from app.tech import report as TR
from app.tech.probe import Sampler, cgroup
from tests.conftest import login


def fake_host(tmp_path, busy=1000, total=10000, usec=1_000_000):
    proc, cg = tmp_path / "proc", tmp_path / "cg"
    (proc / "pressure").mkdir(parents=True, exist_ok=True)
    cg.mkdir(exist_ok=True)
    (proc / "stat").write_text(f"cpu  {busy} 0 0 {total - busy} 0 0 0 0 0 0\n")
    (proc / "loadavg").write_text("1.50 1.20 0.90 2/300 12345\n")
    (proc / "meminfo").write_text("MemTotal:       8000000 kB\nMemAvailable:   2000000 kB\nSwapTotal:      0 kB\nSwapFree:       0 kB\n")
    (proc / "pressure" / "io").write_text("some avg10=42.50 avg60=10.00 avg300=1.00 total=1\nfull avg10=1.00 avg60=0 avg300=0 total=1\n")
    (cg / "cpu.stat").write_text(f"usage_usec {usec}\nthrottled_usec 0\n")
    (cg / "cpu.max").write_text("200000 100000\n")
    (cg / "memory.current").write_text("471859200\n")
    (cg / "memory.max").write_text("3221225472\n")
    (cg / "memory.peak").write_text("500000000\n")
    (cg / "memory.events").write_text("low 0\nhigh 0\nmax 2\noom 1\noom_kill 1\n")
    (cg / "pids.current").write_text("7\n")
    return str(proc), str(cg)


def test_probe_reads_cgroup_and_counts_one_core(tmp_path):
    proc, cg = fake_host(tmp_path)
    s = Sampler(proc_root=proc, cg_root=cg, high_pct=85)
    s.sample()
    c = cgroup(cg)
    assert c["cpu_limit"] == 2.0 and c["mem"] == 471859200 and c["mem_limit"] == 3221225472 and c["oom_kill"] == 1 and c["pids"] == 7
    s._cg = (time.time() - 1.0, 0)                                                     # прошла секунда, процесс потратил 1 с процессора — одно ядро целиком
    fake_host(tmp_path, busy=1500, total=11000, usec=1_000_000)
    x = s.sample()
    assert 95 <= x["cpu_pct"] <= 105 and x["high_since"] is not None                   # 100 % = одно ядро, а не «весь сервер»
    assert x["host_cpu_pct"] == 50.0 and x["load"] == [1.5, 1.2, 0.9] and x["host_io_pressure"] == 42.5 and x["mem"]["available"] == 2048000000
    assert len(s.snapshot()["hist"]) == 2


def test_sql_text_is_masked():
    q = "SELECT * FROM bi_persons WHERE email = 'ivan@example.local' AND id IN (1, 2, 3) AND ip = '192.0.2.10' AND t2.x > 5"
    m = PG.mask_sql(q)
    assert "ivan" not in m and "192.0.2.10" not in m and "(…)" in m and "t2.x" in m and PG.kind_of(q) == "SELECT" and PG.table_of(q) == "bi_persons"


def test_report_masks_secrets_and_external_identifiers():
    state = {"version": "0.18.0", "commit": "abc", "built_at": "", "level": "warn", "thresholds": {}, "host": None, "disk": None, "dirs": None, "helper": {},
             "problems": [{"level": "warn", "area": "KSC «Головной офис»", "text": "ошибка подключения к ksc01.corp.example.local (192.0.2.10): password=Secret123", "tab": "sources"}],
             "services": [], "jobs": {"items": [], "history": [], "by_kind": [], "counts": {"total": 0, "waiting": 0, "running": 0, "stalled": 0, "done_24h": 0, "failed_24h": 0}},
             "pg": {"ok": True, "long": [], "locks": [], "tables": {"items": [], "indexes": []}, "dsn": "postgresql://kc:pw@db/kc"},
             "sources": {"ksc": [{"name": "Головной офис", "check_ok": True, "check_at": None, "sync": {"at": None, "status": None}, "catalog": {"at": None}}],
                         "bi": [{"name": "BI кадры", "last_ok_at": None, "last_try_at": None, "last_error": "\\\\fs01.corp.example.local\\share нет доступа для ivan.petrov@corp.example.local"}],
                         "pentest": {"alive": True, "nmap": "7.95", "nse_scripts": 600, "nuclei": {"version": "", "templates": ""}, "queued": 0, "running": 0}},
             "journal": {"errors_24h": 0, "warn_24h": 0, "recent": []}, "components": {"items": []}}
    inner = TR.build(state, external=False)
    txt = json.dumps(inner, ensure_ascii=False)
    assert "Secret123" not in txt and ":pw@" not in txt and "Головной офис" in txt         # секреты — всегда, названия — только во внешнем режиме
    ext = TR.build(state, external=True)
    t2 = json.dumps(ext, ensure_ascii=False) + TR.to_text(ext) + TR.to_html(ext)
    for leak in ("Secret123", "192.0.2.10", "Головной офис", "BI кадры", "ivan.petrov", "fs01", "ksc01"):
        assert leak not in t2, leak
    assert "ip-1" in t2 and "источник-1" in t2


async def test_state_shows_stalled_expired_and_waiting_reason(client, app):
    async with app.state.session_maker() as db:
        src = KscSource(name="KSC A", host="192.0.2.5", port=1433, database="KAV", username="u")
        db.add(src)
        await db.flush()
        now = utcnow()
        db.add(JobLease(kind="vdb_analyze", scope="nvd", run_id=uuid.uuid4(), owner="wk1/7/aa", started_at=now - timedelta(minutes=40), heartbeat_at=now - timedelta(seconds=5),
                        lease_until=now + timedelta(minutes=2), stage="сопоставление", progress_at=now - timedelta(minutes=25), queued_at=now - timedelta(minutes=41)))
        db.add(JobLease(kind="catalog", scope=str(src.id), run_id=uuid.uuid4(), owner="wk1/7/aa", started_at=now - timedelta(minutes=9), heartbeat_at=now - timedelta(minutes=8),
                        lease_until=now - timedelta(minutes=6), stage="чтение", progress_at=now - timedelta(minutes=8)))
        db.add(ServiceHeartbeat(name="worker", at=now, started_at=now - timedelta(hours=1), data={"version": "t", "waiting": [{"kind": "bi", "scope": "b1", "task": "импорт BI b1", "lane": "bi", "since": (now - timedelta(minutes=17)).isoformat(), "stage": "запуск"}],
                                                                                                 "resources": {"waiting": [{"task": "импорт BI b1", "lane": "bi", "wait_s": 1020, "reason": "все места очереди заняты (1 из 1): «анализ уязвимостей»"}]},
                                                                                                 "probe": {"at": time.time(), "host": "wk1", "cpus": 8, "cpu_pct": 99.0, "high_since": time.time() - 1500, "cgroup": {"mem": 450 * 2**20, "mem_limit": 3 * 2**30}, "hist": []}}))
        db.add(JobRun(kind="vdb_sync", scope="kev", run_id=uuid.uuid4(), started_at=now - timedelta(hours=2), finished_at=now - timedelta(hours=1), status="success", duration_ms=60000, waited_ms=30000))
        await db.commit()
    assert (await client.get("/api/v1/admin/tech")).status_code == 401
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get("/api/v1/admin/tech")).status_code == 403                                         # только администратору
    await login(client, "admin", "Admin-Passw0rd-123")
    r = await client.get("/api/v1/admin/tech")
    assert r.status_code == 200, r.text
    d = r.json()
    items = {i["kind"]: i for i in d["jobs"]["items"]}
    assert items["vdb_analyze"]["state"] == "running" and items["vdb_analyze"]["stalled"] and "пульс аренды живой" in items["vdb_analyze"]["reason"]   # пульс ≠ работа
    assert items["vdb_analyze"]["wait_s"] == 60 and items["vdb_analyze"]["executor"] == "worker"
    assert items["catalog"]["state"] == "expired" and items["catalog"]["scope"] == "KSC A"
    assert items["bi"]["state"] == "waiting" and "все места очереди заняты" in items["bi"]["reason"] and items["bi"]["wait_s"] >= 1019
    texts = " | ".join(p["text"] for p in d["problems"])
    assert "ожидает исполнителя 17 мин: все места очереди заняты" in texts and "одного ядра" in texts and "8 ядер" in texts
    assert d["jobs"]["counts"]["waiting"] == 1 and d["jobs"]["counts"]["stalled"] == 1 and d["jobs"]["counts"]["wait_max_s"] == 30.0
    assert d["level"] == "bad" and any(s["key"] == "worker" and s["res"]["mem_limit"] == 3 * 2**30 for s in d["services"])
    rep = await client.get("/api/v1/admin/tech/report", params={"format": "txt", "external": True})
    assert rep.status_code == 200 and "attachment" in rep.headers["content-disposition"] and "192.0.2.5" not in rep.text and "KSC A" not in rep.text


async def test_refresh_is_rate_limited_and_single_flight(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    TC.CACHE.drop(("tech",))
    calls = 0
    real = TC.collect

    async def counting(a, db):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.05)
        return await real(a, db)
    TC.collect = counting
    try:
        rs = await asyncio.gather(*[client.post("/api/v1/admin/tech/refresh") for _ in range(5)])
        assert all(r.status_code == 200 for r in rs) and calls == 1                   # пять нажатий — один расчёт
        await client.post("/api/v1/admin/tech/refresh")
        assert calls == 1                                                             # повтор раньше 10 с — прежний результат
    finally:
        TC.collect = real


async def test_lease_records_queue_wait_and_progress_apart_from_heartbeat(app):
    async with JOBS.run_heavy("eol", "s9", task="EOL s9") as lease:
        assert lease is not None and lease.queued_at is not None
        lease.progress_at -= 600                                                      # последний ход — 10 минут назад
        await JOBS.beat_once()
        async with app.state.session_maker() as db:
            row = await db.get(JobLease, ("eol", "s9"))
            assert (row.heartbeat_at - row.progress_at).total_seconds() >= 590          # пульс свежий, ход выполнения — старый
    async with app.state.session_maker() as db:
        from sqlalchemy import select  # noqa: PLC0415

        run = (await db.execute(select(JobRun).where(JobRun.kind == "eol"))).scalars().one()
        assert run.waited_ms is not None and run.status == "success"
    assert not RES.queue


async def test_postgres_lock_shows_waiter_and_holder(app):
    """Только PostgreSQL: одна транзакция держит блокировку таблицы, вторая ждёт — в сводке видно, кто ждёт и кто мешает; текст запроса без значений."""
    import pytest  # noqa: PLC0415
    from sqlalchemy import text  # noqa: PLC0415

    async with app.state.session_maker() as probe:
        if probe.bind.dialect.name != "postgresql":
            pytest.skip("нужен PostgreSQL (TEST_PG_URL)")
    async with app.state.session_maker() as a, app.state.session_maker() as b:
        await a.execute(text("LOCK TABLE event_log IN ACCESS EXCLUSIVE MODE"))
        waiter = asyncio.create_task(b.execute(text("SELECT count(*) FROM event_log WHERE message = 'секрет-123'")))
        await asyncio.sleep(0.5)
        async with app.state.session_maker() as db:
            act = await PG.activity(db, long_s=0)
        await a.rollback()
        await waiter
    assert act["ok"] and act["waiting"] >= 1 and act["locks"]
    lk = act["locks"][0]
    assert lk["waiting"]["kind"] == "SELECT" and lk["waiting"]["table"] == "event_log" and lk["holder"]["state"] == "idle in transaction"
    assert "секрет-123" not in json.dumps(act, ensure_ascii=False)


async def test_abandoned_lease_is_reaped_into_history(app):
    """Контейнер worker пересоздан (другое имя хоста): его аренда просрочена и никем не перехвачена — снимается и записывается как прерванная."""
    from sqlalchemy import select  # noqa: PLC0415

    now = utcnow()
    async with app.state.session_maker() as db:
        db.add(JobLease(kind="zonecache", scope="s1", run_id=uuid.uuid4(), owner="oldhost/1/aa", started_at=now - timedelta(hours=2), heartbeat_at=now - timedelta(hours=1),
                        lease_until=now - timedelta(minutes=58), stage="чтение"))
        db.add(JobLease(kind="eol", scope="s1", run_id=uuid.uuid4(), owner="oldhost/1/aa", started_at=now, heartbeat_at=now, lease_until=now - timedelta(seconds=30), stage="x"))
        await db.commit()
    assert await JOBS.reap(600) == 1                                                  # только давно просроченная; свежая ждёт обычного перехвата
    async with app.state.session_maker() as db:
        assert [r.kind for r in (await db.execute(select(JobLease))).scalars()] == ["eol"]
        run = (await db.execute(select(JobRun).where(JobRun.kind == "zonecache"))).scalars().one()
        assert run.status == "interrupted" and "Исполнитель исчез" in run.error
