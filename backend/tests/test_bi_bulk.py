"""Массовое сопоставление BI и KSC: точное совпадение имени (регистр и пробелы не учитываются, короткое имя ↔ FQDN — отдельно), предварительная сводка,
выполнение на сервере порциями, идемпотентность, отмена, правило автоподтверждения и его отмена, неоднозначные случаи остаются ручными."""
import asyncio
import uuid

from sqlalchemy import select

from app.bi import match as M
from app.models import BiMatch, BiOwner, BiSource
from tests.conftest import login
from tests.test_bi_import import run, row, source, xlsx
from tests.test_bi_match import ksc


async def world(app, tmp_path, n=300, **opt):
    """n однозначных имён (часть — в другом регистре), повтор имени в двух KSC, «Личный ПК» у двух сотрудников, короткое имя ↔ FQDN, ручное решение."""
    hosts = [(i, f"WS-{i:04d}" if i % 3 else f"ws-{i:04d}", "Windows 11", True, False, "") for i in range(1, n + 1)]
    hosts += [(9001, "DUP-01", "Windows 11", True, False, ""), (9002, "srv-fqdn", "Windows 11", True, False, "srv-fqdn.example.local"), (9003, "OS-DIFF", "Astra Linux 1.7", True, False, ""),
              (9004, "srv-short.example.local", "Windows 11", True, False, "srv-short.example.local")]
    k1 = await ksc(app, "KSC A", hosts)
    k2 = await ksc(app, "KSC B", [(1, "DUP-01", "Windows 11", True, False, "")])
    sid = await source(app, drift_pct=1000, **opt)
    rows = [row(f"Сотрудник {i:04d}", f"u{i:04d}@example.local", "Отдел", f"WS-{i:04d}", os="Windows 11") for i in range(1, n + 1)]
    rows += [row("Дубль Имени", "d@example.local", "Отдел", "DUP-01", os="Windows 11"), row("Полное Имя", "f@example.local", "Отдел", "srv-fqdn.example.local", os="Windows 11"),
             row("Короткое Имя", "s@example.local", "Отдел", "SRV-SHORT", os="Windows 11"),
             row("Другая ОС", "o@example.local", "Отдел", "OS-DIFF", os="Windows 11"), row("Личный 1", "p1@example.local", "Отдел", "Личный ПК"), row("Личный 2", "p2@example.local", "Отдел", "Личный ПК")]
    await run(app, sid, xlsx(tmp_path / "bi.xlsx", rows))
    await M.run(app.state.session_maker, sid, force=True)
    return sid, k1, k2


async def by_name(app, sid) -> dict:
    async with app.state.session_maker() as db:
        return {m.host_name: m for m in (await db.execute(select(BiMatch).where(BiMatch.bi_source_id == sid))).scalars()}


async def wait_op(client, op):
    for _ in range(200):
        st = (await client.get(f"/api/v1/bi/matches/bulk/{op}")).json()
        if st["status"] != "running":
            return st
        await asyncio.sleep(0.05)
    raise AssertionError("операция не завершилась")


async def test_exact_name_categories_and_bulk_confirm_with_preview(client, app, tmp_path):
    sid, _k1, _k2 = await world(app, tmp_path)
    m = await by_name(app, sid)
    assert m["ws-0003"].name_match == "exact" and m["WS-0001"].name_match == "exact"                     # BI «WS-0003», KSC «ws-0003»: регистр не важен, исходное имя KSC сохранено
    assert m["DUP-01"].level == "ambiguous" and m["DUP-01"].name_match == "exact_dup"                     # одно имя в двух KSC — только вручную
    async with app.state.session_maker() as db:
        from app.models import BiDevice
        fq = {d: x.name_match for x, d in (await db.execute(select(BiMatch, BiDevice.name).join(BiDevice, BiDevice.id == BiMatch.device_id).where(BiMatch.bi_source_id == sid))).all()}
    assert fq["srv-fqdn.example.local"] == "exact"                                                          # полное имя BI = FQDN компьютера KSC
    assert fq["SRV-SHORT"] == "short"                                                                       # короткое имя ↔ FQDN — отдельный тип, не «точное»
    assert m["OS-DIFF"].name_match == "exact_dup"                                                           # имя совпадает, ОС противоречит — вручную
    assert not any(k == "Личный ПК" for k in m)
    await login(client, "admin", "Admin-Passw0rd-123")
    lst = (await client.get("/api/v1/bi/matches", params={"level": "exact", "source_id": str(sid), "limit": 50})).json()
    assert lst["counts"]["exact"] == lst["total"] >= 300 and all(i["name_ru"] == "Точное совпадение имени" for i in lst["items"])
    prev = (await client.post("/api/v1/bi/matches/bulk", json={"action": "confirm", "scope": "exact", "source_id": str(sid)})).json()
    assert prev["n"] == lst["total"] and "op" not in prev and len(prev["sample"]) == 30 and prev["by_ksc_source"] == {"KSC A": prev["n"]}
    async with app.state.session_maker() as db:                                                             # предпросмотр ничего не меняет
        assert not (await db.execute(select(BiMatch).where(BiMatch.bi_source_id == sid, BiMatch.level == "confirmed"))).scalars().all()
    go = (await client.post("/api/v1/bi/matches/bulk", json={"action": "confirm", "scope": "exact", "source_id": str(sid), "preview": False})).json()
    st = await wait_op(client, go["op"])
    assert st["status"] == "done" and st["changed"] == prev["n"]
    again = (await client.post("/api/v1/bi/matches/bulk", json={"action": "confirm", "scope": "exact", "source_id": str(sid)})).json()
    assert again["n"] == 0                                                                                   # повторное нажатие — ничего не дублирует
    left = (await client.get("/api/v1/bi/matches", params={"level": "needs_manual", "source_id": str(sid)})).json()
    assert {i["host_name"] for i in left["items"]} >= {"DUP-01", "OS-DIFF"} and left["counts"]["exact"] == 0
    async with app.state.session_maker() as db:
        confirmed = (await db.execute(select(BiMatch).where(BiMatch.bi_source_id == sid, BiMatch.level == "confirmed"))).scalars().all()
        assert len(confirmed) == prev["n"] and len({(c.ksc_source_id, c.host_id) for c in confirmed}) == len(confirmed)
        audit = (await db.execute(select(__import__("app.models", fromlist=["AuditLog"]).AuditLog).where(__import__("app.models", fromlist=["AuditLog"]).AuditLog.action == "bi.match.bulk_confirm"))).scalars().all()
        assert len(audit) == 1 and audit[0].details["changed"] == prev["n"]


async def test_bulk_undo_reimport_keeps_decisions_and_owner_history(client, app, tmp_path):
    sid, _k1, _k2 = await world(app, tmp_path, n=40)
    await login(client, "admin", "Admin-Passw0rd-123")
    go = (await client.post("/api/v1/bi/matches/bulk", json={"action": "confirm", "scope": "exact", "source_id": str(sid), "preview": False})).json()
    await wait_op(client, go["op"])
    m = await by_name(app, sid)
    undo_ids = [m["WS-0001"].id, m["WS-0002"].id]
    undo = (await client.post("/api/v1/bi/matches/bulk", json={"action": "reset", "scope": "ids", "ids": undo_ids, "preview": False})).json()
    assert (await wait_op(client, undo["op"]))["changed"] == 2
    async with app.state.session_maker() as db:
        owners_before = len((await db.execute(select(BiOwner).where(BiOwner.source_id == sid))).scalars().all())
    await M.run(app.state.session_maker, sid, force=True)                                                   # пересчёт (как после повторного импорта)
    m = await by_name(app, sid)
    assert m["WS-0001"].level in ("auto", "candidate") and m["ws-0003"].level == "confirmed"               # отменённое — снова кандидат, подтверждённые сохранены
    rej = (await client.post("/api/v1/bi/matches/bulk", json={"action": "reject", "scope": "ids", "ids": [m["WS-0001"].id], "preview": False})).json()
    await wait_op(client, rej["op"])
    await M.run(app.state.session_maker, sid, force=True)
    assert (await by_name(app, sid))["WS-0001"].level == "rejected"
    async with app.state.session_maker() as db:
        assert len((await db.execute(select(BiOwner).where(BiOwner.source_id == sid))).scalars().all()) == owners_before      # история владельцев не тронута


async def test_selected_rows_skip_conflicts_and_two_admins_do_not_duplicate(client, app, tmp_path):
    sid, _k1, _k2 = await world(app, tmp_path, n=30)
    await login(client, "admin", "Admin-Passw0rd-123")
    m = await by_name(app, sid)
    dup = [x.id for x in (await by_name(app, sid)).values() if x.host_name == "DUP-01"]
    async with app.state.session_maker() as db:
        dup = [x.id for x in (await db.execute(select(BiMatch).where(BiMatch.bi_source_id == sid, BiMatch.host_name == "DUP-01"))).scalars()]
    prev = (await client.post("/api/v1/bi/matches/bulk", json={"action": "confirm", "scope": "ids", "ids": dup + [m["WS-0005"].id]})).json()
    assert prev["n"] == 1 and {s["reason"] for s in prev["skipped"]} == {"several"}                           # два компьютера для одного устройства — пропуск с причиной
    body = {"action": "confirm", "scope": "exact", "source_id": str(sid), "preview": False}
    a = await client.post("/api/v1/bi/matches/bulk", json=body)
    b = await client.post("/api/v1/bi/matches/bulk", json=body)
    assert a.status_code == 200 and b.status_code in (200, 409)
    await wait_op(client, a.json()["op"])
    if b.status_code == 200 and "op" in b.json():
        await wait_op(client, b.json()["op"])
    async with app.state.session_maker() as db:
        c = (await db.execute(select(BiMatch).where(BiMatch.bi_source_id == sid, BiMatch.level == "confirmed"))).scalars().all()
    assert len(c) == len({x.device_id for x in c})                                                            # одно подтверждённое соответствие на устройство


async def test_auto_exact_rule_and_its_undo(client, app, tmp_path):
    sid, _k1, _k2 = await world(app, tmp_path, n=20, auto_exact=True)
    m = await by_name(app, sid)
    assert m["WS-0001"].level == "confirmed" and m["WS-0001"].decided_by == M.RULE and "автоматически" in m["WS-0001"].note
    assert m["DUP-01"].level == "ambiguous" and m["OS-DIFF"].level != "confirmed"                            # неоднозначное и противоречивое — не подтверждаются
    await login(client, "admin", "Admin-Passw0rd-123")
    r = await client.post("/api/v1/bi/matches/decide", json={"device_id": m["WS-0001"].device_id, "ksc_source_id": str(m["WS-0001"].ksc_source_id), "host_id": m["WS-0001"].host_id, "decision": "reset"})
    assert r.status_code == 200, r.text
    await M.run(app.state.session_maker, sid, force=True)
    m = await by_name(app, sid)
    assert m["WS-0001"].level == "manual"                                                                     # правило больше не подтверждает отменённую пару
    left = (await client.get("/api/v1/bi/matches", params={"level": "needs_manual", "source_id": str(sid)})).json()
    assert "WS-0001" in {i["host_name"] for i in left["items"]}
    async with app.state.session_maker() as db:
        s = await db.get(BiSource, sid)
        assert s.options.get("auto_exact") is True
    _ = uuid
