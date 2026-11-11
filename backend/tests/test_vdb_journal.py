"""Журнал базы уязвимостей (кольцевой), ход расчёта и его зависание, аудит применения, независимость расчёта от загрузок, ревизия по версии данных."""
import uuid
from datetime import timedelta

from sqlalchemy import delete, func, select

from app.models import VdbAnalysis, VdbJournal, VdbSource, VdbVersionHit, VdbMapping, utcnow
from app.vdb import hostext as HX
from app.vdb import journal as J
from app.vdb import store
from app.vdb.normalize import Aff, Rec
from tests.conftest import login
from tests.test_vdb import _ksc_source, make_sync


async def _seed(app, client):
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await _ksc_source(client, app)
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        a = Rec(source="nvd", ext_id="CVE-2099-1", vuln_key="CVE-2099-1", severity="critical", score=9.8, title="Chrome RCE", published=utcnow(), modified=utcnow(),
                affected=[Aff(vendor="google", product="chrome", v_end="116.0.5845.187")])
        await store.save_batch(db, 1, [a])
        await store.refresh_vulns(db, {"CVE-2099-1"})
        await db.commit()
    return sid


async def test_journal_is_a_ring_buffer_with_a_size_limit(app):
    sm = app.state.session_maker
    for i in range(300):
        await J.emit(sm, "sync", f"запись {i}", vdb_key="nvd", details={"x": "я" * 1000}, limit=60_000)
    async with sm() as db:
        total = await J.total_bytes(db)
        ids = (await db.execute(select(VdbJournal.message).order_by(VdbJournal.id))).scalars().all()
    assert total <= 60_000 + 25 * 2200                                  # проверка размера — раз в несколько записей: превышение ограничено
    assert ids[-1] == "запись 299" and "запись 0" not in ids and len(ids) < 300     # новые на месте, старые перезаписаны
    await J.emit(sm, "analysis", "ошибка", level="error", limit=60_000)    # запись уровня error чистит сразу
    async with sm() as db:
        assert await J.total_bytes(db) <= 60_000


async def test_analysis_writes_journal_and_progress(app, client):
    sid = await _seed(app, client)
    assert await make_sync(app).analyze_full(uuid.UUID(sid)) == 1
    j = (await client.get("/api/v1/vdb/journal", params={"kind": "analysis"})).json()
    msgs = [e["message"] for e in j["items"]]
    assert any(m.startswith("Расчёт начат") for m in msgs) and any(m.startswith("Расчёт завершён") for m in msgs) and any(m.startswith("Подобрано уязвимостей") for m in msgs)
    assert j["bytes"] > 0 and j["limit_bytes"] == 10 * 1024 * 1024
    st = (await client.get("/api/v1/vdb/analysis")).json()["items"][0]
    assert st["state"] == "fresh" and st["progress"] is None and st["hits"] > 0
    only_err = (await client.get("/api/v1/vdb/journal", params={"level": "error"})).json()
    assert only_err["items"] == []                                       # ошибок не было


async def test_stalled_and_interrupted_analysis_are_visible_and_reset(app, client):
    sid = await _seed(app, client)
    old = utcnow() - timedelta(minutes=30)
    async with app.state.session_maker() as db:
        db.add(VdbAnalysis(source_id=uuid.UUID(sid), status="running", started_at=old, progress_at=old, stage="сопоставление", done=10, total=100))
        await db.commit()
        info = await HX.state(db, uuid.UUID(sid))
    assert info["state"] == "stalled" and info["progress"]["done"] == 10
    assert "давно не обновлял ход" in HX.state_note(info)
    row = (await client.get("/api/v1/vdb/analysis")).json()["items"][0]
    assert row["state"] == "stalled" and row["progress"]["total"] == 100 and row["lease"] is False
    await make_sync(app)._recover_analysis()                              # перезапуск службы: аренды нет — «идёт расчёт» снимается с записью в журнал
    row = (await client.get("/api/v1/vdb/analysis")).json()["items"][0]
    assert row["status"] == "error" and "прерван" in row["error"] and row["progress"] is None
    msgs = [e for e in (await client.get("/api/v1/vdb/journal", params={"level": "warn"})).json()["items"]]
    assert any("Расчёт прерван" in e["message"] for e in msgs)


async def test_analysis_does_not_block_source_loading(app, monkeypatch):
    sync = make_sync(app)

    async def boom():
        raise AssertionError("расчёт не должен выполняться внутри цикла загрузок")
    monkeypatch.setattr(sync, "analysis_tick", boom)
    await sync.tick()                                                     # загрузки идут своим циклом, расчёт — своим (analysis_loop)


async def test_revision_depends_on_data_changes_not_on_every_successful_load(app, client):
    sid = await _seed(app, client)
    sm = app.state.session_maker
    async with sm() as db:
        r0 = await store.revision(db, uuid.UUID(sid))
        (await db.get(VdbSource, "nvd")).last_ok_at = utcnow()           # загрузка «без изменений»: время обновилось, данные те же
        await db.commit()
        assert await store.revision(db, uuid.UUID(sid)) == r0            # повторный полный расчёт не нужен
        (await db.get(VdbSource, "nvd")).data_ver = 5
        await db.commit()
        assert await store.revision(db, uuid.UUID(sid)) != r0


async def test_decision_recalculates_its_vulnerabilities_and_keeps_results_fresh(app, client):
    sid = await _seed(app, client)
    assert await make_sync(app).analyze_full(uuid.UUID(sid)) == 1
    r = await client.post("/api/v1/vdb/mappings", json={"vendor_key": "google", "product": "chrome", "catalog_key": "google-chrome", "action": "exclude"})
    assert r.status_code == 201
    st = (await client.get("/api/v1/vdb/analysis")).json()["items"][0]
    assert st["state"] == "fresh"                                         # решение разобрано сразу, полный пересчёт всей базы не требуется
    async with app.state.session_maker() as db:
        n = (await db.execute(select(func.count()).select_from(VdbVersionHit).where(VdbVersionHit.source_id == uuid.UUID(sid)))).scalar_one()
    assert n == 0                                                         # исключённое совпадение убрано из подготовленных результатов
    dec = (await client.get("/api/v1/vdb/journal", params={"kind": "decision"})).json()["items"]
    assert len(dec) == 1 and "исключено совпадение" in dec[0]["message"]


async def test_audit_confirms_consistent_data_and_catches_a_broken_one(app, client):
    sid = await _seed(app, client)
    assert await make_sync(app).analyze_full(uuid.UUID(sid)) == 1
    a = (await client.post("/api/v1/vdb/audit/run", params={"source_id": sid})).json()
    by = {c["key"]: c for c in a["checks"]}
    assert by["state"]["status"] == "ok" and by["sample"]["status"] == "ok" and "совпало" in by["sample"]["detail"]
    assert by["findings_without_hits"]["status"] == "ok" and by["coverage"]["data"]["hits"] > 0 and a["counts"]["error"] == 0
    async with app.state.session_maker() as db:                           # результаты испорчены: находки остались, строк по версиям нет
        await db.execute(delete(VdbVersionHit).where(VdbVersionHit.source_id == uuid.UUID(sid)))
        await db.commit()
    b = {c["key"]: c for c in (await client.post("/api/v1/vdb/audit/run", params={"source_id": sid})).json()["checks"]}
    assert b["findings_without_hits"]["status"] == "error" and b["findings_without_hits"]["data"]["count"] == 1
    j = (await client.get("/api/v1/vdb/journal", params={"kind": "audit"})).json()["items"]
    assert len(j) == 2 and j[0]["level"] == "error" and j[1]["level"] == "info"                  # итоги обоих аудитов в журнале


async def test_journal_and_audit_require_proper_roles(app, client):
    sid = await _seed(app, client)
    assert (await client.get("/api/v1/vdb/journal")).status_code == 200
    await client.post("/api/v1/auth/logout")
    assert (await client.get("/api/v1/vdb/journal")).status_code in (401, 403)
    assert (await client.post("/api/v1/vdb/audit/run", params={"source_id": sid})).status_code in (401, 403)


async def _stale_state(app, sid, *, started_ago_h, status="ok", rev=f"{store.MATCH_REV}.устарело"):
    async with app.state.session_maker() as db:
        await db.execute(delete(VdbAnalysis))
        db.add(VdbAnalysis(source_id=uuid.UUID(sid), status=status, rev=rev, built_at=utcnow() - timedelta(hours=started_ago_h), started_at=utcnow() - timedelta(hours=started_ago_h)))
        await db.commit()


async def test_automatic_full_recalculation_is_not_more_often_than_every_six_hours(app, client, monkeypatch):
    """Расчёт на большой базе идёт десятки минут; новый сразу за ним (данные успели измениться) не даёт посчитать ничего до конца: автоматически — не чаще раза в 6 часов от начала прошлого."""
    sid = await _seed(app, client)
    sync = make_sync(app)
    calls = []

    async def fake_full(source_id):
        calls.append(source_id)
        return 1
    monkeypatch.setattr(sync, "analyze_full", fake_full)
    await _stale_state(app, sid, started_ago_h=1)
    await sync.analysis_tick()
    assert calls == []                                                                                     # прошёл час: рано, показан последний результат
    msgs = [e["message"] for e in (await client.get("/api/v1/vdb/journal", params={"kind": "analysis"})).json()["items"]]
    assert any("не раньше" in m and "не чаще раза в 6 ч" in m for m in msgs)                              # причина ожидания записана
    st = (await client.get("/api/v1/vdb/analysis")).json()["items"][0]
    assert st["state"] == "stale" and st["next_auto_at"] and st["min_hours"] == 6
    await _stale_state(app, sid, started_ago_h=7)
    await sync.analysis_tick()
    assert len(calls) == 1                                                                                 # прошло больше 6 часов — пора
    await _stale_state(app, sid, started_ago_h=1, rev="")                                                  # «Пересчитать» вручную обходит интервал
    await sync.analysis_tick()
    assert len(calls) == 2
    await _stale_state(app, sid, started_ago_h=1, status="error")                                          # ошибка — повтор не ждёт 6 часов (пауза 5 минут)
    await sync.analysis_tick()
    assert len(calls) == 3
    await _stale_state(app, sid, started_ago_h=1, rev="3.прежняя-логика")                                  # сменилась версия логики сопоставления — пересчёт сразу
    await sync.analysis_tick()
    assert len(calls) == 4


async def test_catalog_rebuild_without_composition_change_does_not_change_the_revision(app, client):
    from app.models import CatalogProduct, CatalogState

    sid = uuid.UUID(await _seed(app, client))
    sm = app.state.session_maker
    async with sm() as db:
        r0 = await store.revision(db, sid)
        (await db.get(CatalogState, sid)).built_at = utcnow() + timedelta(hours=1)                         # каталог перестроен, состав тот же
        await db.commit()
        assert await store.revision(db, sid) == r0                                                         # полный пересчёт не нужен
        row = await db.get(CatalogProduct, (sid, "google-chrome"))
        row.versions_count += 1
        await db.commit()
        assert await store.revision(db, sid) != r0                                                         # новая версия программы — нужен


def test_durations_are_readable():
    from app.vdb.sync import _dur

    assert [_dur(5), _dur(125), _dur(2862), _dur(7500)] == ["5 с", "2 мин 5 с", "47 мин 42 с", "2 ч 5 мин"]


async def test_service_stop_during_calculation_is_recorded_not_silent(app, client, monkeypatch):
    import asyncio

    from app.vdb import sync as sync_mod

    sid = await _seed(app, client)

    async def cancelled(*_a, **_k):
        raise asyncio.CancelledError()
    monkeypatch.setattr(sync_mod, "analyze", cancelled)
    try:
        await make_sync(app).analyze_full(uuid.UUID(sid))
    except asyncio.CancelledError:
        pass
    row = (await client.get("/api/v1/vdb/analysis")).json()["items"][0]
    assert row["status"] == "error" and "остановкой службы" in row["error"]
    warn = (await client.get("/api/v1/vdb/journal", params={"level": "warn"})).json()["items"]
    assert any("служба остановлена" in e["message"] for e in warn)
