"""BI через API: настройка источника и секреты, проверка структуры без записи в базу, загрузка файла администратором, поиск текущих и прежних владельцев,
карточки, решения по сопоставлению с журналом, права и персональные данные, отчёты всех видов, чтение во время импорта."""
import asyncio
import uuid

from sqlalchemy import select

from app.bi import importer as IM
from app.bi import match as M
from app.bi import service as SV
from app.models import AuditLog, BiImport, BiPerson, BiSource, User
from app.services import local_admin as la
from tests.conftest import login
from tests.test_bi_import import BASE, HDR, row, xlsx
from tests.test_bi_match import ksc

SRC = {"name": "BI выгрузка", "smb_host": "files.example.local", "smb_share": "bi", "smb_path": "exports", "username": "EXAMPLE\\svc-bi-ro", "password": "S3cret-pass",
       "file_mode": "fixed", "file_name": "computers.xlsx", "schedule_time": "06:30", "timezone": "Europe/Moscow"}


async def setup(client, app, tmp_path, rows=BASE):
    await login(client, "admin", "Admin-Passw0rd-123")
    r = await client.post("/api/v1/bi/sources", json=SRC)
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    f = xlsx(tmp_path / "computers.xlsx", rows)
    pv = await client.post(f"/api/v1/bi/sources/{sid}/preview", content=f.read_bytes(), headers={"Content-Type": "application/octet-stream", "X-File-Name": "computers.xlsx"})
    assert pv.status_code == 200, pv.text
    prof = pv.json()["suggested"]
    r = await client.put(f"/api/v1/bi/sources/{sid}", json={**SRC, "password": None, "profile": prof})
    assert r.status_code == 200, r.text
    up = await client.post(f"/api/v1/bi/sources/{sid}/upload", content=f.read_bytes(), headers={"Content-Type": "application/octet-stream", "X-File-Name": "computers.xlsx"})
    assert up.status_code == 202, up.text
    imp = await SV.BiService(app.state.session_maker, app.state.settings, app.state.settings_svc).run_source(uuid.UUID(sid))
    assert imp.status == "ok" and imp.trigger == "upload", imp.message
    return sid, pv.json()


async def test_source_secrets_preview_and_upload(client, app, tmp_path):
    sid, pv = await setup(client, app, tmp_path)
    assert pv["headers"] == HDR and pv["check"]["ok"] == 6 and pv["sheet"] == "Table 1" and pv["origin"]["kind"] == "upload"
    assert pv["suggested"]["columns"]["device_name"] == "Имя рабочей станции"
    r = (await client.get("/api/v1/bi/sources")).json()["items"][0]
    assert r["password_set"] and "password" not in r and "password_enc" not in r and "S3cret" not in str(r)
    assert r["published"]["rows_valid"] == 6 and r["next_run_at"]
    async with app.state.session_maker() as db:
        s = await db.get(BiSource, uuid.UUID(sid))
        assert s.password_enc and "S3cret" not in s.password_enc
        audit = " ".join(str(a.details) for a in (await db.execute(select(AuditLog).where(AuditLog.action.like("bi.%")))).scalars())
        assert "S3cret" not in audit
    imps = (await client.get(f"/api/v1/bi/sources/{sid}/imports")).json()["items"]
    one = (await client.get(f"/api/v1/bi/imports/{imps[0]['id']}")).json()
    assert one["status"] == "ok" and any(w["code"] == "future_date" for w in one["warnings"])
    bad = await client.post(f"/api/v1/bi/sources/{sid}/preview", content=b"not an xlsx", headers={"Content-Type": "application/octet-stream"})
    assert bad.status_code == 422 and "XLSX" in bad.json()["detail"]
    r = await client.put(f"/api/v1/bi/sources/{sid}", json={**SRC, "profile": {"columns": {"person_name": "ФИО сотрудника"}}})
    assert r.status_code == 422 and "Имя компьютера" in r.json()["detail"]
    assert (await client.post(f"/api/v1/bi/sources/{sid}/run", json={"force": True})).status_code == 202


async def test_people_search_cards_and_roles(client, app, tmp_path):
    sid, _ = await setup(client, app, tmp_path)
    k = await ksc(app, "KSC A", [(1, "WS-001", "Windows 10", True, True, ""), (2, "Личный ПК", "Windows 11", True, False, "")])
    async with app.state.session_maker() as db:
        await IM.import_file(app.state.session_maker, uuid.UUID(sid), xlsx(tmp_path / "2.xlsx", [row("Смирнов Олег", "o.smirnov@example.local", "ИТ", "WS-001"), *BASE[1:]]),
                             file_name="2.xlsx", file_size=1, file_mtime=(await db.get(BiImport, (await db.get(BiSource, uuid.UUID(sid))).last_import_id)).snapshot_at.replace(year=2027), trigger="manual", by="t")
    await M.run(app.state.session_maker, uuid.UUID(sid))
    cur = (await client.get("/api/v1/bi/people", params={"q": "WS-001", "state": "current"})).json()
    assert [p["name"] for p in cur["items"]] == ["Смирнов Олег"]
    allp = (await client.get("/api/v1/bi/people", params={"q": "ws-001"})).json()
    assert {p["name"] for p in allp["items"]} == {"Иванов Иван Иванович", "Смирнов Олег"}       # поиск по устройству находит и прежнего владельца
    iv = next(p for p in allp["items"] if p["name"].startswith("Иванов"))
    assert iv["devices"]["past"] == ["WS-001"] and "Личный ПК" in iv["devices"]["current"]
    card = (await client.get(f"/api/v1/bi/people/{iv['id']}")).json()
    assert [d_["name"] for d_ in card["devices"]["past"]] == ["WS-001"] and card["email"] == "i.ivanov@example.local"
    dev = (await client.get("/api/v1/bi/devices", params={"q": "ws-001"})).json()["items"][0]
    dc = (await client.get(f"/api/v1/bi/devices/{dev['id']}")).json()
    assert dc["owner"]["person"]["name"] == "Смирнов Олег" and [o["state"] for o in dc["owners"]] == ["current", "past"]
    assert "точная дата передачи неизвестна" in dc["owners"][1]["note"] and dc["owners"][1]["first_import"]["file"] == "computers.xlsx"
    assert dc["ksc_state"] == "linked" and dc["matches"][0]["ksc"]["problems"] == ["Защита не работает"]
    assert any(i["code"] == "av_broken" for i in dc["issues"])
    hb = (await client.get(f"/api/v1/bi/host/{k}/1")).json()
    assert hb["devices"][0]["owner"]["person"]["email"] == "o.smirnov@example.local" and hb["can_decide"]
    nobi = (await client.get(f"/api/v1/bi/host/{k}/2")).json()
    assert nobi["devices"] == [] and nobi["candidates"] == []                  # «Личный ПК» в KSC не связывается с «Личным ПК» сотрудника
    # просмотр: блок владельца в карточке — без почты; списки сотрудников — нет
    await login(client, "viewer", "Viewer-Passw0rd-123")
    hb = (await client.get(f"/api/v1/bi/host/{k}/1")).json()
    assert hb["devices"][0]["owner"]["person"]["name"] == "Смирнов Олег" and hb["devices"][0]["owner"]["person"]["email"] == ""
    assert all("email" not in v["attrs"] and "extra" not in v["attrs"] for v in hb["devices"][0]["versions"])
    assert (await client.get("/api/v1/bi/people")).status_code == 403
    assert (await client.get("/api/v1/bi/sources")).status_code == 403
    assert (await client.post("/api/v1/quick/preview", json={"kind": "quick_bi", "params": {"view": "owners"}})).status_code in (403, 409)
    # аналитик без доступа ко всем источникам KSC списков BI не видит
    async with app.state.session_maker() as db:
        await la.create_local(db, "analyst1", "Analyst-Passw0rd-123", role="analyst", must_change=False)
        u = (await db.execute(select(User).where(User.username == "analyst1"))).scalar_one()
        u.all_sources, u.source_ids = False, [str(k)]
        await db.commit()
    await login(client, "analyst1", "Analyst-Passw0rd-123")
    assert (await client.get("/api/v1/bi/people")).status_code == 403
    assert (await client.get(f"/api/v1/bi/host/{k}/1")).json()["devices"][0]["owner"]["person"]["email"] == "o.smirnov@example.local"


async def test_match_decisions_are_audited(client, app, tmp_path):
    sid, _ = await setup(client, app, tmp_path)
    k = await ksc(app, "KSC A", [(4, "MAC-007", "", False, False, "")])
    await M.run(app.state.session_maker, uuid.UUID(sid))
    lst = (await client.get("/api/v1/bi/matches")).json()
    m = lst["items"][0]
    assert m["level"] == "candidate" and lst["counts"][""] == 1 and lst["counts"]["unmatched"] >= 1   # «не сопоставлены» — устройства BI без единой пары в KSC
    r = await client.post("/api/v1/bi/matches/decide", json={"device_id": m["device_id"], "ksc_source_id": str(k), "host_id": 4, "decision": "confirm", "note": "проверено по инвентарному номеру"})
    assert r.status_code == 200 and r.json()["level"] == "confirmed"
    await M.run(app.state.session_maker, uuid.UUID(sid))
    hb = (await client.get(f"/api/v1/bi/host/{k}/4")).json()
    assert hb["devices"][0]["matches"][0]["level"] == "confirmed" and hb["devices"][0]["owner"]["person"]["name"] == "Кузнецова Мария"
    assert (await client.post("/api/v1/bi/matches/decide", json={"device_id": m["device_id"], "ksc_source_id": str(k), "host_id": 4, "decision": "reset"})).status_code == 200
    async with app.state.session_maker() as db:
        acts = [a.action for a in (await db.execute(select(AuditLog).where(AuditLog.action.like("bi.match.%")))).scalars()]
        assert acts == ["bi.match.confirm", "bi.match.reset"]


async def test_reports_all_views(client, app, tmp_path):
    sid, _ = await setup(client, app, tmp_path)
    k = await ksc(app, "KSC A", [(1, "WS-001", "Windows 10", True, True, ""), (9, "orphan", "Windows 10", False, False, "")], users=[(1, "i.ivanov")])
    await M.run(app.state.session_maker, uuid.UUID(sid))
    for view, check in (("owners", lambda t: any(r["host"] == "WS-001" and r["user"] == "Иванов Иван Иванович" and r["protection"] == "Защита не работает" for r in t["rows"])),
                        ("history", lambda t: len(t["rows"]) == 6),
                        ("unknown", lambda t: {r["host"] for r in t["rows"]} == {"Личный ПК"}),
                        ("discrepancies", lambda t: [r["host"] for r in t["rows"]] == ["WS-001"]),
                        ("problems", lambda t: {(r["host"], r["owner"]) for r in t["rows"]} == {("WS-001", "Иванов Иван Иванович"), ("orphan", "не определён")})):
        r = await client.post("/api/v1/quick/preview", json={"kind": "quick_bi", "params": {"view": view}})
        assert r.status_code == 200, (view, r.text)
        doc = r.json()["doc"]
        t = {"rows": r.json()["items"]}
        assert check(t), (view, t["rows"])
        assert any("персональные данные" in n for n in doc["notes"]) and any(c["label"] == "Сведения BI" for c in doc["conditions"])
    flt = (await client.post("/api/v1/quick/preview", json={"kind": "quick_bi", "params": {"view": "owners", "q": "mac"}})).json()
    assert [r["host"] for r in flt["items"]] == ["MAC-007"]                # фильтры страницы попадают в отчёт
    from app.models import ReportJob  # noqa: PLC0415
    from app.reports.runner import Runner  # noqa: PLC0415

    job = await client.post("/api/v1/reports", json={"kind": "quick_bi", "title": "Владельцы", "params": {"view": "problems"}, "source_ids": []})
    assert job.status_code == 201, job.text
    rid = job.json()["id"]
    async with app.state.session_maker() as db:
        await Runner(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal)._execute_quick(await db.get(ReportJob, uuid.UUID(rid)))
    assert (await client.get(f"/api/v1/reports/{rid}")).json()["status"] == "done"
    html = (await client.get(f"/api/v1/reports/{rid}/download/html")).text
    assert "Проблемы защиты и контактные лица" in html and "Иванов Иван Иванович" in html and "i.ivanov@example.local" in html
    assert (await client.get(f"/api/v1/reports/{rid}/download/pdf")).content[:5] == b"%PDF-"
    assert (await client.get(f"/api/v1/reports/{rid}/download/xlsx")).content[:2] == b"PK"
    assert "Контактная почта".encode() in (await client.get(f"/api/v1/reports/{rid}/download/csv")).content
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get(f"/api/v1/reports/{rid}")).status_code == 404          # отчёт с персональными данными недоступен роли «Просмотр»
    _ = k


async def test_reading_during_import_sees_previous_snapshot(client, app, tmp_path, monkeypatch):
    sid, _ = await setup(client, app, tmp_path)
    gate, entered = asyncio.Event(), asyncio.Event()
    orig = IM.publish

    async def slow(db, *a, **kw):
        await orig(db, *a, **kw)
        entered.set()
        await gate.wait()                                                    # снимок записан, транзакция ещё не зафиксирована

    monkeypatch.setattr(IM, "publish", slow)
    new = xlsx(tmp_path / "n.xlsx", [row("Смирнов Олег", "o.smirnov@example.local", "ИТ", "WS-001"), *BASE[1:]])
    async with app.state.session_maker() as db:
        snap = (await db.get(BiImport, (await db.get(BiSource, uuid.UUID(sid))).last_import_id)).snapshot_at
    task = asyncio.create_task(IM.import_file(app.state.session_maker, uuid.UUID(sid), new, file_name="n.xlsx", file_size=1, file_mtime=snap.replace(year=2027), trigger="manual", by="t"))
    await asyncio.wait_for(entered.wait(), 10)
    try:
        async with app.state.session_maker() as db:
            names = {p.full_name for p in (await db.execute(select(BiPerson).where(BiPerson.source_id == uuid.UUID(sid)))).scalars()}
        assert "Смирнов Олег" not in names                                   # читатель видит последний опубликованный снимок
    finally:
        gate.set()
    assert (await task).status == "ok"
    async with app.state.session_maker() as db:
        assert "Смирнов Олег" in {p.full_name for p in (await db.execute(select(BiPerson))).scalars()}
