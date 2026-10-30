"""Сопоставление BI и KSC с учётом активности (0.19.0): одинаковое имя в нескольких KSC разрешается по последнему подключению Агента (tmLastNagentConnected), записи разных источников
не объединяются, устаревшие не мешают, спорное остаётся на ручное решение с причиной, подтверждённые связи не переключаются без явной причины, история сохраняется."""
from datetime import timedelta

from sqlalchemy import select, update

from app.bi import match as M
from app.models import BiMatch, BiSource, KscSource, ZcHost, ZcSource, utcnow
from tests.conftest import login
from tests.test_bi_import import row, source, xlsx
from tests.test_bi_import import run as import_file
from tests.test_bi_match import ksc

WIN = "Windows 11"


async def setup(app, tmp_path, hosts_a, hosts_b=(), bi_names=("PC-1",), a_built=0.0, b_built=0.0, **opt):
    """Два источника KSC («KSC-01», «KSC-02») и BI с устройствами `bi_names` (одна Windows-станция на имя)."""
    a = await ksc(app, "KSC-01", hosts_a, built_days_ago=a_built)
    b = await ksc(app, "KSC-02", hosts_b, built_days_ago=b_built)
    sid = await source(app, drift_pct=1000, **opt)
    rows = [row(f"Сотрудник {i}", f"u{i}@example.local", "Отдел", n, os=WIN) for i, n in enumerate(bi_names, 1)]
    await import_file(app, sid, xlsx(tmp_path / "bi.xlsx", rows))
    await M.run(app.state.session_maker, sid, force=True)
    return sid, a, b


async def rows_of(app, sid, name=None) -> dict:
    """(источник KSC, имя компьютера) → строка сопоставления."""
    async with app.state.session_maker() as db:
        names = {k.id: k.name for k in (await db.execute(select(KscSource))).scalars()}
        return {(names[m.ksc_source_id], m.host_name): m for m in (await db.execute(select(BiMatch).where(BiMatch.bi_source_id == sid))).scalars()
                if name is None or m.host_name.lower() == name.lower()}


async def set_age(app, ksc_id, host_id, days):
    async with app.state.session_maker() as db:
        await db.execute(update(ZcHost).where(ZcHost.source_id == ksc_id, ZcHost.host_id == host_id).values(last_connected=None if days is None else utcnow() - timedelta(days=days)))
        await db.commit()


def lv(rows) -> dict:
    return {k: m.level for k, m in rows.items()}


def host(name, ago, hid=1):
    return (hid, name, WIN, True, False, "", ago)


# ---------------------------------------------------------------------------------------------------------------- выбор актуальной записи (чистая функция)
def H(sid, last, act=""):
    return {"sid": sid, "hid": 1, "name": "PC", "last": last, "act": act}


def test_pick_current_rules():
    now = utcnow()
    names = {"a": "KSC-01", "b": "KSC-02"}
    built = {"a": now, "b": now}
    d = lambda n: now - timedelta(days=n)                                     # noqa: E731
    p = M.pick_current([H("a", d(1)), H("b", d(78))], now, 30, 3, built, names)
    assert p["verdict"] == "single" and p["winner"]["sid"] == "a" and "единственный активный источник KSC за 30 дней" in p["short"]       # пример из постановки
    assert M.pick_current([H("a", d(40)), H("b", d(78))], now, 30, 3, built, names)["verdict"] == "none_active"                         # актуального нет
    assert M.pick_current([H("a", None), H("b", None)], now, 30, 3, built, names)["verdict"] == "no_data"
    assert M.pick_current([H("a", d(5)), H("b", d(5) - timedelta(hours=2))], now, 30, 3, built, names)["verdict"] == "tie"              # «на несколько часов» — не причина
    p = M.pick_current([H("a", d(1)), H("b", d(10))], now, 30, 3, built, names)
    assert p["verdict"] == "latest" and p["winner"]["sid"] == "a"
    assert M.pick_current([H("a", d(1)), H("b", d(10))], now, 30, 3, {"a": now, "b": d(20)}, names)["verdict"] == "old_data"            # срез b старше последнего подключения на a
    assert M.pick_current([H("a", now + timedelta(days=40)), H("b", d(2))], now, 30, 3, built, names)["verdict"] == "dubious"          # дата в будущем
    assert M.pick_current([H("a", d(2)), H("b", None)], now, 30, 3, built, names)["winner"]["sid"] == "a"                               # «нет сведений» не мешает активной


def test_stamp_changes_with_day_and_settings():
    src = BiSource(name="x", last_import_id=None, options={"activity_days": 30})
    now = utcnow()
    one = M.make_stamp(src, {}, now)
    assert one == M.make_stamp(src, {}, now) and one != M.make_stamp(src, {}, now + timedelta(days=1))                                  # активность зависит от даты
    src.options = {"activity_days": 60}
    assert one != M.make_stamp(src, {}, now)


# ---------------------------------------------------------------------------------------------------------------- сценарии
async def test_only_one_active_source_wins_and_old_record_is_stale(app, tmp_path):
    sid, a, b = await setup(app, tmp_path, [host("pc-1", 1)], [host("pc-1", 78)])
    r = await rows_of(app, sid)
    assert lv(r) == {("KSC-01", "pc-1"): "auto", ("KSC-02", "pc-1"): "stale"}
    win, old = r[("KSC-01", "pc-1")], r[("KSC-02", "pc-1")]
    assert win.name_match == "exact" and win.activity == "active" and "единственный активный источник KSC за 30 дней" in win.signals[0] and win.signals[0].startswith("Точное совпадение имени")
    assert old.activity == "stale" and "не подключалась более 30 дней" in old.signals[0] and old.host_last_connected is not None                           # запись KSC-02 остаётся в своём источнике, не удаляется
    async with app.state.session_maker() as db:
        assert (await db.execute(select(ZcHost).where(ZcHost.source_id == b))).scalars().one().name == "pc-1"


async def test_migration_between_ksc_keeps_history_and_does_not_flap(app, tmp_path):
    sid, a, b = await setup(app, tmp_path, [host("pc-1", 50)], [host("pc-1", 3)], auto_exact=True)
    r = await rows_of(app, sid)
    assert r[("KSC-02", "pc-1")].level == "confirmed" and r[("KSC-02", "pc-1")].decided_by == M.RULE and r[("KSC-01", "pc-1")].level == "stale"
    await M.run(app.state.session_maker, sid, force=True)                                               # повторный расчёт без изменений — то же самое
    assert lv(await rows_of(app, sid)) == lv(r)
    await set_age(app, a, 1, 1)                                                                         # компьютер перешёл на KSC-01
    await set_age(app, b, 1, 40)
    await M.run(app.state.session_maker, sid, force=True)
    r = await rows_of(app, sid)
    assert r[("KSC-01", "pc-1")].level == "confirmed" and r[("KSC-01", "pc-1")].decided_by == M.RULE
    assert r[("KSC-02", "pc-1")].level == "history" and "Прежнее соответствие" in r[("KSC-02", "pc-1")].note and "KSC-01" in r[("KSC-02", "pc-1")].note
    await M.run(app.state.session_maker, sid, force=True)                                               # история переживает пересчёт
    assert lv(await rows_of(app, sid))[("KSC-02", "pc-1")] == "history"
    await set_age(app, b, 1, 1)                                                                         # теперь активны оба с разницей меньше порога — связь не переключается
    await M.run(app.state.session_maker, sid, force=True)
    r = await rows_of(app, sid)
    assert r[("KSC-01", "pc-1")].level == "confirmed" and r[("KSC-02", "pc-1")].level == "history"                  # связь не переключилась обратно, прежняя запись осталась историей


async def test_simultaneous_activity_needs_margin_and_fresh_data(app, tmp_path):
    sid, a, b = await setup(app, tmp_path, [host("pc-1", 1)], [host("pc-1", 1.1)])                       # почти одновременно — спорно
    r = await rows_of(app, sid)
    assert set(lv(r).values()) == {"ambiguous"} and "менее чем на 3 дня" in r[("KSC-01", "pc-1")].signals[0] and all(m.name_match == "exact_dup" for m in r.values())
    await set_age(app, b, 1, 12)                                                                        # разница 11 суток, срезы свежие — выбирается поздняя
    await M.run(app.state.session_maker, sid, force=True)
    r = await rows_of(app, sid)
    assert r[("KSC-01", "pc-1")].level == "auto" and r[("KSC-02", "pc-1")].level == "stale" and "уступает по дате" in r[("KSC-02", "pc-1")].signals[0]
    async with app.state.session_maker() as db:                                                         # срез KSC-02 получен раньше последнего подключения на KSC-01: актуальность не подтверждена
        await db.execute(update(ZcSource).where(ZcSource.source_id == b).values(built_at=utcnow() - timedelta(days=20)))
        await db.commit()
    await M.run(app.state.session_maker, sid, force=True)
    r = await rows_of(app, sid)
    assert r[("KSC-01", "pc-1")].level == "ambiguous" and "актуальность не подтверждена" in r[("KSC-01", "pc-1")].signals[0]


async def test_no_activity_data_future_dates_and_all_stale(app, tmp_path):
    a = await ksc(app, "KSC-01", [host("pc-1", 45, 1), host("pc-2", None, 2), host("pc-3", -40, 3)])           # PC-1: давно; PC-2: Агент не подключался; PC-3: дата в будущем
    b = await ksc(app, "KSC-02", [host("pc-1", 78, 1)])
    sid = await source(app, drift_pct=1000)
    await import_file(app, sid, xlsx(tmp_path / "bi.xlsx", [row(f"С {n}", f"{n}@example.local", "Отдел", n, os=WIN) for n in ("PC-1", "PC-2", "PC-3")]))
    await M.run(app.state.session_maker, sid, force=True)
    r1, r2, r3 = await rows_of(app, sid, "pc-1"), await rows_of(app, sid, "pc-2"), await rows_of(app, sid, "pc-3")
    assert set(lv(r1).values()) == {"inactive"} and "актуальный компьютер KSC не найден" in r1[("KSC-01", "pc-1")].signals[0]
    assert lv(r2) == {("KSC-01", "pc-2"): "inactive"} and "нет сведений о подключении Агента" in r2[("KSC-01", "pc-2")].signals[0]
    assert lv(r3) == {("KSC-01", "pc-3"): "ambiguous"} and "недостоверная дата" in r3[("KSC-01", "pc-3")].signals[0]       # дата в будущем — не подтверждается автоматически
    assert not [m for m in (await rows_of(app, sid)).values() if m.level in ("auto", "candidate", "confirmed")]
    _ = (a, b)


async def test_unknown_date_does_not_block_active_record(app, tmp_path):
    sid, *_ = await setup(app, tmp_path, [host("pc-1", None)], [host("pc-1", 2)])
    r = await rows_of(app, sid)
    assert r[("KSC-02", "pc-1")].level == "auto" and r[("KSC-01", "pc-1")].level == "stale" and "нет сведений о подключении" in r[("KSC-01", "pc-1")].signals[0]


async def test_admin_confirmed_link_never_switches_silently(client, app, tmp_path):
    sid, a, b = await setup(app, tmp_path, [host("pc-1", 2)], [host("pc-1", 60)])
    await login(client, "admin", "Admin-Passw0rd-123")
    r = await rows_of(app, sid)
    old = r[("KSC-02", "pc-1")]
    assert old.level == "stale"
    d = await client.post("/api/v1/bi/matches/decide", json={"device_id": old.device_id, "ksc_source_id": str(old.ksc_source_id), "host_id": old.host_id, "decision": "confirm"})   # администратор выбрал устаревшую запись
    assert d.status_code == 200, d.text
    await M.run(app.state.session_maker, sid, force=True)
    r = await rows_of(app, sid)
    assert r[("KSC-02", "pc-1")].level == "confirmed" and r[("KSC-02", "pc-1")].decided_by != M.RULE                       # решение не пересчитывается
    prop = r[("KSC-01", "pc-1")]
    assert prop.level == "candidate" and prop.name_match == "moved" and "переход между источниками KSC" in prop.signals[0]  # только предложение
    plan = (await client.post("/api/v1/bi/matches/bulk", json={"action": "confirm", "scope": "exact", "source_id": str(sid)})).json()
    assert plan["n"] == 0                                                                                    # массовое «точное» подтверждение предложение не затрагивает
    d = await client.post("/api/v1/bi/matches/decide", json={"device_id": prop.device_id, "ksc_source_id": str(prop.ksc_source_id), "host_id": prop.host_id, "decision": "confirm"})
    assert d.status_code == 200
    r = await rows_of(app, sid)
    assert r[("KSC-01", "pc-1")].level == "confirmed" and r[("KSC-02", "pc-1")].level == "history"                          # прежняя связь — в историю, не удалена
    await M.run(app.state.session_maker, sid, force=True)
    assert lv(await rows_of(app, sid)) == {("KSC-01", "pc-1"): "confirmed", ("KSC-02", "pc-1"): "history"}


async def test_rule_link_is_kept_when_data_is_not_enough_to_switch(app, tmp_path):
    sid, a, b = await setup(app, tmp_path, [host("pc-1", 40)], [host("pc-1", 3)], auto_exact=True)
    assert (await rows_of(app, sid))[("KSC-02", "pc-1")].level == "confirmed"
    await set_age(app, a, 1, 2.9)                                                                        # второй источник тоже активен почти одновременно — переключения нет
    await M.run(app.state.session_maker, sid, force=True)
    r = await rows_of(app, sid)
    assert r[("KSC-02", "pc-1")].level == "confirmed" and r[("KSC-01", "pc-1")].level != "confirmed"
    await set_age(app, b, 1, 90)                                                                         # прежняя запись давно не подключалась, а новая активна — переход
    await M.run(app.state.session_maker, sid, force=True)
    r = await rows_of(app, sid)
    assert r[("KSC-01", "pc-1")].level == "confirmed" and r[("KSC-02", "pc-1")].level == "history"


async def test_bulk_preview_counts_stale_disputed_and_inactive(client, app, tmp_path):
    a = await ksc(app, "KSC-01", [host("ok-1", 1, 1), host("ok-2", 2, 2), host("dup", 1, 3), host("old", 60, 4)])
    b = await ksc(app, "KSC-02", [host("ok-1", 90, 1), host("dup", 1.2, 3)])
    sid = await source(app, drift_pct=1000)
    await import_file(app, sid, xlsx(tmp_path / "bi.xlsx", [row(f"С {n}", f"{n}@example.local", "Отдел", n, os=WIN) for n in ("ok-1", "ok-2", "dup", "old")]))
    await M.run(app.state.session_maker, sid, force=True)
    await login(client, "admin", "Admin-Passw0rd-123")
    plan = (await client.post("/api/v1/bi/matches/bulk", json={"action": "confirm", "scope": "exact", "source_id": str(sid)})).json()
    assert plan["n"] == 2 and plan["stale_n"] == 1 and plan["disputed_n"] == 1 and plan["inactive_n"] == 1                # ok-1, ok-2 | устаревшая запись ok-1 | dup | old
    assert {x["device"] for x in plan["sample"]} == {"ok-1", "ok-2"} and all(x["last_connected"] for x in plan["sample"])
    lst = (await client.get("/api/v1/bi/matches", params={"level": "needs_manual", "source_id": str(sid)})).json()
    assert lst["counts"]["stale"] >= 2 and {i["host_name"] for i in lst["items"]} == {"dup"}
    assert all(i["activity"] == "active" and i["last_connected"] for i in lst["items"])
    stale = (await client.get("/api/v1/bi/matches", params={"level": "stale", "source_id": str(sid)})).json()
    assert {i["level"] for i in stale["items"]} == {"stale", "inactive"}
    dev = (await client.get("/api/v1/bi/matches", params={"level": "exact", "source_id": str(sid)})).json()
    ok1 = next(i for i in dev["items"] if i["device"] == "ok-1")
    assert ok1["others"] and ok1["others"][0]["level"] == "stale" and ok1["others"][0]["ksc_source"] == "KSC-02" and ok1["others"][0]["last_connected"]        # устаревшая запись видна у устройства
    _ = (a, b)


async def test_activity_period_setting_is_applied_and_triggers_recalc(app, tmp_path):
    sid, a, b = await setup(app, tmp_path, [host("pc-1", 20)], [host("pc-1", 40)])
    assert lv(await rows_of(app, sid)) == {("KSC-01", "pc-1"): "auto", ("KSC-02", "pc-1"): "stale"}
    async with app.state.session_maker() as db:
        src = await db.get(BiSource, sid)
        src.options = {**src.options, "activity_days": 60}                                               # шире окно: обе активны, разница 20 суток — выбирается поздняя
        await db.commit()
    assert await M.stale(app.state.session_maker, sid)                                                   # настройка меняет отпечаток: пересчёт без force
    await M.run(app.state.session_maker, sid)
    r = await rows_of(app, sid)
    assert r[("KSC-01", "pc-1")].level == "auto" and "уступает по дате" in r[("KSC-02", "pc-1")].signals[0]


async def test_bulk_confirmed_links_survive_resync_without_switching(client, app, tmp_path):
    """Массовое подтверждение, затем данные KSC меняются так, что актуальной выглядит запись другого источника: подтверждённые связи остаются, появляются только предложения «переход между KSC»."""
    names = [f"wk-{i:02d}" for i in range(1, 11)]
    a = await ksc(app, "KSC-01", [host(n, 1, i) for i, n in enumerate(names, 1)])
    b = await ksc(app, "KSC-02", [host(n, 70, i) for i, n in enumerate(names, 1)])
    sid = await source(app, drift_pct=1000)
    await import_file(app, sid, xlsx(tmp_path / "bi.xlsx", [row(f"С {n}", f"{n}@example.local", "Отдел", n, os=WIN) for n in names]))
    await M.run(app.state.session_maker, sid, force=True)
    await login(client, "admin", "Admin-Passw0rd-123")
    go = (await client.post("/api/v1/bi/matches/bulk", json={"action": "confirm", "scope": "exact", "source_id": str(sid), "preview": False})).json()
    for _ in range(100):
        st = (await client.get(f"/api/v1/bi/matches/bulk/{go['op']}")).json()
        if st["status"] != "running":
            break
    assert st["status"] == "done" and st["changed"] == 10
    before = {k: m.level for k, m in (await rows_of(app, sid)).items()}
    assert [k for k, v in before.items() if v == "confirmed"] == [("KSC-01", n) for n in names]
    for i in range(1, 11):                                                                               # «перенос парка»: теперь на KSC-02 свежее, на KSC-01 давно
        await set_age(app, b, i, 1)
        await set_age(app, a, i, 60)
    await M.run(app.state.session_maker, sid, force=True)
    await M.run(app.state.session_maker, sid, force=True)                                                # повторная синхронизация
    after = await rows_of(app, sid)
    assert all(after[("KSC-01", n)].level == "confirmed" for n in names)                                 # ничто не переключилось само
    assert all(after[("KSC-02", n)].level == "candidate" and after[("KSC-02", n)].name_match == "moved" for n in names)
    plan = (await client.post("/api/v1/bi/matches/bulk", json={"action": "confirm", "scope": "exact", "source_id": str(sid)})).json()
    assert plan["n"] == 0                                                                                # массовая операция предложений не подтверждает
    _ = (a, b)
