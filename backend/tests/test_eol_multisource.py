"""EOL на нескольких источниках: идемпотентность, независимость источников, объединение повторов, сохранность прежнего результата при сбоях, диагностика.
Данные синтетические и общие (не повторяют чью-либо установку). Сценарии с реальными параллельными транзакциями выполняются на PostgreSQL (TEST_PG_URL)."""
import asyncio
import os
import tracemalloc
import uuid

import pytest
from sqlalchemy import exc as sa_exc, func, select, update

from app.eol import compute as C
from app.eol.errors import describe
from app.eol.service import EolService
from app.eol.sync import apply_products
from app.models import CatalogProduct, CatalogState, EolFinding, EolHost, EolMapping, EolState, KscSource, utcnow
from tests.conftest import login
from tests.test_eol_compute import DOC, TODAY, FakeKsc, cat, hosts

PG = bool(os.environ.get("TEST_PG_URL"))
needs_pg = pytest.mark.skipif(not PG, reason="нужен PostgreSQL (TEST_PG_URL): реальные параллельные транзакции")


async def seed_many(app, n=2, versions=(("7.4.16", [11, 12]), ("8.3.2", [13]))):
    """n источников с одинаковыми названиями программ и версиями (каталоги одинаковы по содержанию, ключи источника разные)."""
    sm = app.state.session_maker
    await apply_products(sm, DOC["result"])
    ids = []
    async with sm() as db:
        for i in range(n):
            sid = uuid.uuid4()
            ids.append(sid)
            db.add(KscSource(id=sid, name=f"KSC-{i + 1}", host=f"h{i}.example.local", port=1433, database="KAV", username="u", password_enc="x", is_active=True, position=i))
        await db.flush()
        for sid in ids:
            db.add(CatalogState(source_id=sid, status="ready", built_at=utcnow(), activity_days=30))
            db.add(cat(sid, "php", "PHP", "The PHP Group", list(versions)))
        await db.commit()
    return ids


async def run(app, sid, ksc=None):
    sm = app.state.session_maker
    async with sm() as db:
        src = await db.get(KscSource, sid)
    return await C.compute_source(sm, ksc or FakeKsc({11: [(1, 1), (2, 0)], 12: [(5, 1)], 13: [(1, 1)]}, hosts()), src, activity_days=30, today=TODAY)


async def rows(app, sid):
    async with app.state.session_maker() as db:
        f = sorted((x.kind, x.subject, x.version, x.status, x.hosts_all) for x in (await db.execute(select(EolFinding).where(EolFinding.source_id == sid))).scalars())
        h = (await db.execute(select(func.count()).select_from(EolHost).where(EolHost.source_id == sid))).scalar_one()
    return f, h


# ---- 1. повторяющиеся установки
async def test_many_repeated_installs_count_each_device_once(app):
    (sid,) = await seed_many(app, 1, versions=(("7.4.16", list(range(100, 140))),))
    apps = {pid: [(h, 1) for h in range(1, 31)] * 3 for pid in range(100, 140)}               # 40 записей реестра, на каждой те же 30 устройств, строки повторяются трижды
    res = await run(app, sid, FakeKsc(apps, hosts()))
    f, h = await rows(app, sid)
    php = next(x for x in f if x[1] == "php")
    assert php[4] == 30 and res["links"] >= 30 and not res["diag"]["merged_keys"]             # устройств 30, а не 3600


# ---- 2. два источника с одинаковыми названиями и версиями; 5. повтор; независимость
async def test_two_sources_same_products_are_independent_and_idempotent(app):
    a, b = await seed_many(app, 2)
    r1 = await run(app, a)
    r2 = await run(app, b, FakeKsc({11: [(1, 1)], 12: [], 13: []}, hosts()))
    fa, ha = await rows(app, a)
    fb, hb = await rows(app, b)
    assert {x[:3] for x in fa} == {x[:3] for x in fb} and fa != fb                           # те же ключи, разные счётчики устройств
    for _ in range(3):                                                                         # повторные расчёты одного источника не меняют результата и не трогают соседа
        again = await run(app, a)
        assert again["signature"] == r1["signature"]
        assert await rows(app, a) == (fa, ha) and await rows(app, b) == (fb, hb)
    assert r2["signature"] != r1["signature"] or fa != fb


# ---- 3. несколько правил EOL на один продукт
async def test_ambiguous_rules_make_one_finding_per_version_and_manual_mapping_resolves(app, monkeypatch):
    (sid,) = await seed_many(app, 1)
    real = C.candidates
    monkeypatch.setattr(C, "candidates", lambda idx, m, maps: {**real(idx, m, maps), "php": [("php", "high"), ("nginx", "high")]})
    res = await run(app, sid)
    f, _h = await rows(app, sid)
    assert [x for x in f if x[1] == "php" and x[3] == "unknown"] and len({x[:3] for x in f}) == len(f) and res["diag"]["merged_keys"] == 0
    monkeypatch.undo()
    async with app.state.session_maker() as db:
        db.add(EolMapping(catalog_key="php", eol_product="php", action="map", note="", created_by="t"))
        await db.commit()
    await run(app, sid)
    f2, _ = await rows(app, sid)
    assert any(x[1] == "php" and x[3] == "eol" for x in f2) and not any(x[3] == "unknown" and x[1] == "php" for x in f2)


# ---- объединение одинаковых и сохранение разных
def test_merge_findings_merges_equal_keys_and_keeps_distinct_ones():
    sid = uuid.uuid4()
    mk = lambda subject, version, status="eol", sev="critical", pids=(), hosts_all=1: EolFinding(source_id=sid, kind="app", subject=subject, version=version, status=status, severity=sev, product_ids=list(pids), hosts_all=hosts_all, hosts_active=hosts_all, installs_active=hosts_all)  # noqa: E731
    out, info = C.merge_findings([mk("php", "7.4", pids=[1]), mk("php", "7.4", "extended", "high", [2], 5), mk("php", "8.0"), mk("PHP", "7.4"), mk("php", "7.4 ")])
    assert len(out) == 4 and info["merged_keys"] == 1 and info["merged_rows"] == 1                                # PHP и «7.4 » — другие факты и не объединяются
    m = next(x for x in out if x.subject == "php" and x.version == "7.4")
    assert m.status == "eol" and m.product_ids == [1, 2] and m.hosts_all == 5                                      # серьёзнее по состоянию, записи реестра объединены, счётчики — наибольшие


# ---- запись: конфликт ключа не теряет данные и не роняет расчёт
async def test_write_findings_resolves_a_foreign_row_without_losing_ours(app):
    (sid,) = await seed_many(app, 1)
    sm = app.state.session_maker
    mk = lambda v, st: EolFinding(source_id=sid, kind="app", subject="php", version=v, title="PHP", publisher="", eol_product="php", eol_release="7.4", status=st, severity="critical", confidence="high", confirmed=True,  # noqa: E731
                                 condition="", link="", product_ids=[], hosts_all=1, hosts_active=1, installs_active=1, computed_at=utcnow())
    async with sm() as db:
        await C.write_findings(db, [mk("1", "upcoming")])
        await db.commit()
    async with sm() as db:
        n = await C.write_findings(db, [mk("1", "eol"), mk("2", "eol")])                                         # ключ «1» уже есть (чужая запись)
        await db.commit()
    async with sm() as db:
        got = {x.version: x.status for x in (await db.execute(select(EolFinding).where(EolFinding.source_id == sid))).scalars()}
    assert got == {"1": "eol", "2": "eol"} and (n == 1 if PG else n == 0)


# ---- 7, 8. сбой и прерывание: прежний результат цел, соседний источник не затронут
async def test_failed_or_interrupted_calculation_keeps_previous_results(app, monkeypatch):
    a, b = await seed_many(app, 2)
    await run(app, a)
    await run(app, b)
    before_a, before_b = await rows(app, a), await rows(app, b)
    real = C.write_findings

    async def boom(db, rs, batch=500):
        await real(db, rs[:1], batch)                                                                              # часть строк уже записана в транзакции
        raise sa_exc.IntegrityError("INSERT", {}, Exception('duplicate key value violates unique constraint "eol_findings_pkey"\nDETAIL:  Key (source_id, kind, subject, version)=(x, app, php, 7.4) already exists.'))

    monkeypatch.setattr(C, "write_findings", boom)
    svc = EolService(app.state.session_maker, app.state.settings_svc, type("S", (), {"client": lambda self, s: FakeKsc({11: [(1, 1)]}, hosts())})(), app.state.journal)
    await svc.request(a)
    assert await svc.run_source(a) is None
    assert await rows(app, a) == before_a and await rows(app, b) == before_b                                    # частичной записи нет, сосед не тронут
    async with app.state.session_maker() as db:
        st = await db.get(EolState, a)
    assert "конфликт данных" in st.error and "Предыдущие результаты сохранены" in st.error and "eol_findings_pkey" not in st.error and "INSERT" not in st.error     # пользователь видит понятный текст
    assert "eol_findings_pkey" in st.error_detail and "php" in st.error_detail and st.diag["stage"] == "сохранение" and st.attempt_at     # администратору — ключ и этап
    monkeypatch.setattr(C, "write_findings", real)

    started = asyncio.Event()

    async def hang(db, rs, batch=500):
        await real(db, rs[:1], batch)
        started.set()
        await asyncio.sleep(60)

    monkeypatch.setattr(C, "write_findings", hang)
    task = asyncio.create_task(run(app, a))
    await asyncio.wait_for(started.wait(), 20)
    task.cancel()                                                                                               # процесс прерван посреди транзакции
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await rows(app, a) == before_a
    monkeypatch.setattr(C, "write_findings", real)
    assert await svc.recover() >= 0
    await run(app, a)                                                                                           # следующий запуск проходит без конфликтов
    assert await rows(app, a) == before_a


# ---- 4, 6. параллельность
@needs_pg
async def test_parallel_calculation_of_different_sources_and_manual_vs_auto(app):
    ids = await seed_many(app, 3)
    res = await asyncio.gather(*(run(app, s) for s in ids), *(run(app, ids[0]) for _ in range(3)), return_exceptions=True)        # три источника + три «ручных» расчёта первого
    assert not [r for r in res if isinstance(r, Exception)], res
    base = await rows(app, ids[0])
    for s in ids:
        assert (await rows(app, s))[0] == base[0]                                                              # все источники получили полный результат
    svc = EolService(app.state.session_maker, app.state.settings_svc, type("S", (), {"client": lambda self, s: FakeKsc({11: [(1, 1)]}, hosts())})(), app.state.journal)
    out = await asyncio.gather(svc.run_source(ids[1]), svc.run_source(ids[1]))                                 # автоматический и ручной запуск одного источника: второй не стартует
    assert sum(1 for o in out if o is not None) == 1


# ---- 9. «Все источники»: неполнота
async def test_all_sources_summary_marks_incomplete_data(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    a, b = await seed_many(app, 2)
    await run(app, a)
    async with app.state.session_maker() as db:
        await db.execute(update(EolState).where(EolState.source_id == a).values(started_at=None))
        db.add(EolState(source_id=b, error="Не удалось рассчитать EOL", error_detail="этап «сохранение»: тест", error_at=utcnow(), attempt_at=utcnow(), app_version=app.state.settings.app_version))
        await db.commit()
    s = (await client.get("/api/v1/eol/summary", headers={"X-Source-Id": "all"})).json()
    assert s["complete"] is False and s["incomplete"] == ["KSC-2"] and s["findings"]["eol"] >= 1                 # итоги — по рассчитанному источнику, неполнота названа
    assert s["sources"][str(b)]["state"] == "error" and s["sources"][str(b)]["error_detail"].startswith("этап")  # администратору — техническая причина
    await client.post("/api/v1/auth/logout")
    await login(client, "viewer", "Viewer-Passw0rd-123")
    v = (await client.get("/api/v1/eol/summary", headers={"X-Source-Id": "all"})).json()
    assert "error_detail" not in v["sources"][str(b)] and "diag" not in v["sources"][str(b)]                  # пользователю — только понятный текст


# ---- 10. память
async def test_memory_does_not_grow_over_repeated_calculations(app):
    (sid,) = await seed_many(app, 1, versions=tuple((f"7.4.{i}", [1000 + i, 2000 + i]) for i in range(300)))
    apps = {1000 + i: [(h, 1) for h in range(1, 200)] for i in range(300)}
    ksc = FakeKsc(apps, hosts())
    await run(app, sid, ksc)
    tracemalloc.start()
    await run(app, sid, ksc)
    first = tracemalloc.get_traced_memory()[0]
    for _ in range(4):
        await run(app, sid, ksc)
    grown = tracemalloc.get_traced_memory()[0] - first
    tracemalloc.stop()
    assert grown < 8 * 1024 * 1024, f"после повторных расчётов память выросла на {grown / 1048576:.1f} МБ"


# ---- диагностика
def test_describe_hides_sql_from_user_and_keeps_key_for_admin():
    e = sa_exc.IntegrityError("INSERT INTO eol_findings (...) VALUES (...)", {"x": 1}, Exception('duplicate key value violates unique constraint "eol_findings_pkey"\nDETAIL:  Key (source_id, kind, subject, version)=(1, app, php, 7.4) already exists.'))
    d = describe(e, "сохранение", "запись находок")
    assert d.code == "conflict" and "INSERT" not in d.friendly and "eol_findings" not in d.friendly and "Предыдущие результаты сохранены" in d.friendly
    assert "eol_findings_pkey" in d.technical and "(source_id, kind, subject, version)" in d.technical and "php" in d.technical and "сохранение" in d.technical
    assert describe(RuntimeError("boom"), "x").code == "internal" and describe(sa_exc.OperationalError("s", {}, Exception("conn")), "x").transient


async def test_read_only_diagnostics_report_state_and_do_not_change_data(app):
    from app.tools.eol_diag import diagnose, render

    a, b = await seed_many(app, 2)
    await run(app, a)
    async with app.state.session_maker() as db:
        db.add(EolState(source_id=b, error="Ошибка", error_detail="этап «сохранение»", error_at=utcnow(), attempt_at=None))
        await db.commit()
    before = await rows(app, a)
    d = await diagnose(app.state.session_maker)
    text = render(d)
    assert {s["source"] for s in d["sources"]} == {"KSC-1", "KSC-2"} and "KSC-2" in text and "новая попытка расчёта ещё не выполнялась" in text
    assert next(s for s in d["sources"] if s["source"] == "KSC-1")["duplicate_keys_in_db"] == 0 and await rows(app, a) == before
