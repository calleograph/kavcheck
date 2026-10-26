"""Аренды фоновых заданий: единственный исполнитель, перехват после истечения, запоздавший результат, восстановление после перезапуска, история."""
import asyncio
import os
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select, update

from app.models import JobLease, JobRun, utcnow
from app.services.jobs import Jobs, LeaseLost

PG = bool(os.environ.get("TEST_PG_URL"))


def worker(app, name="w1", ttl=120):
    j = Jobs().configure(app.state.session_maker, ttl=ttl, version="9.9.9")
    j.owner = f"{name}/1/{uuid.uuid4().hex[:4]}"
    return j


async def expire(app, kind, scope=""):
    async with app.state.session_maker() as db:
        await db.execute(update(JobLease).where(JobLease.kind == kind, JobLease.scope == scope).values(lease_until=utcnow() - timedelta(seconds=1)))
        await db.commit()


async def test_only_one_executor_and_release_writes_history(app):
    a, b = worker(app, "a"), worker(app, "b")
    la = await a.acquire("catalog", "s1")
    assert la is not None and await b.acquire("catalog", "s1") is None and await b.acquire("catalog", "s2") is not None     # другая область — свой исполнитель
    assert await a.is_live("catalog", "s1")
    await la.finish("success")
    assert not await a.is_live("catalog", "s1") and [r.status for r in await a.runs("catalog", "s1")] == ["success"]
    assert await b.acquire("catalog", "s1") is not None                                                                       # после завершения задание свободно


async def test_expired_lease_is_taken_over_and_late_result_is_fenced(app):
    a, b = worker(app, "a"), worker(app, "b")
    la = await a.acquire("eol", "s1", "устройства")
    await expire(app, "eol", "s1")                                                                                           # исполнитель a перестал продлевать аренду
    lb = await b.acquire("eol", "s1")
    assert lb is not None and lb.run_id != la.run_id
    assert [r.status for r in await b.runs("eol", "s1")] == ["interrupted"]                                                  # прерванный заход записан в историю
    async with app.state.session_maker() as db:
        with pytest.raises(LeaseLost):                                                                                       # запоздавший результат a записать нельзя
            await la.fence(db)
        await lb.fence(db)                                                                                                   # новому выполнению можно
    await la.finish("success")                                                                                               # a «закончил»: в истории «lost», аренда b цела
    assert await b.is_live("eol", "s1") and (await b.runs("eol", "s1", 1))[0].status == "lost"


async def test_heartbeat_keeps_a_long_running_job_alive_and_marks_lost_leases(app):
    a, b = worker(app, "a", ttl=30), worker(app, "b", ttl=30)
    la = await a.acquire("catalog", "s1")
    for _ in range(3):
        await expire(app, "catalog", "s1")                                                                                    # аренда «почти истекла»
        await a.beat_once()                                                                                                   # …но исполнитель жив и продлевает
        assert await b.acquire("catalog", "s1") is None and not la.lost
    await expire(app, "catalog", "s1")
    assert await b.acquire("catalog", "s1") is not None                                                                      # продления не было — перехват
    await a.beat_once()
    assert la.lost                                                                                                            # a узнаёт о потере аренды


async def test_restarted_worker_releases_its_own_stale_leases_at_once(app):
    old = worker(app, "host-a")
    other = worker(app, "host-b")
    await old.acquire("catalog", "s1")
    await other.acquire("catalog", "s2")
    new = Jobs().configure(app.state.session_maker, ttl=120)
    new.owner = old.owner.split("/")[0] + "/77/new"                                                                          # тот же контейнер, новый процесс
    assert await new.recover_own() == 1
    assert not await new.is_live("catalog", "s1") and await new.is_live("catalog", "s2")                                      # чужие аренды не тронуты
    assert (await new.runs("catalog", "s1"))[0].status == "interrupted"
    assert await new.acquire("catalog", "s1") is not None                                                                    # перезапуск не ждёт истечения аренды


async def test_run_context_records_success_error_and_lost(app):
    a = worker(app)
    async with a.run("devices", "s1") as lease:
        assert lease is not None
        async with a.run("devices", "s1") as again:
            assert again is None                                                                                              # повторный вход в то же задание
    with pytest.raises(ValueError):
        async with a.run("devices", "s1"):
            raise ValueError("сбой расчёта")
    runs = await a.runs("devices", "s1")
    assert [r.status for r in runs] == ["error", "success"] and "сбой расчёта" in runs[0].error and runs[0].app_version == "9.9.9"
    assert not await a.is_live("devices", "s1")                                                                              # после ошибки аренда снята: повтор не ждёт


async def test_history_is_bounded(app):
    a = worker(app)
    for _ in range(25):
        async with a.run("report", "x"):
            pass
    assert len(await a.runs("report", "x", 100)) == 20


@pytest.mark.skipif(not PG, reason="нужен PostgreSQL: настоящая гонка транзакций")
async def test_many_workers_racing_for_one_job_get_exactly_one_lease(app):
    ws = [worker(app, f"w{i}") for i in range(8)]
    got = await asyncio.gather(*(w.acquire("eol", "race") for w in ws for _ in range(3)))
    assert sum(1 for g in got if g is not None) == 1
    async with app.state.session_maker() as db:
        assert len((await db.execute(select(JobLease).where(JobLease.kind == "eol", JobLease.scope == "race"))).scalars().all()) == 1
    await expire(app, "eol", "race")
    got = await asyncio.gather(*(w.acquire("eol", "race") for w in ws))                                                       # истекшую аренду перехватывает ровно один
    assert sum(1 for g in got if g is not None) == 1
    async with app.state.session_maker() as db:
        assert len((await db.execute(select(JobRun).where(JobRun.kind == "eol", JobRun.scope == "race", JobRun.status == "interrupted"))).scalars().all()) == 1   # прерванный заход записан один раз
