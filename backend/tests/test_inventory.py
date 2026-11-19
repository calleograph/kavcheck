"""Раздел «Инвентаризация»: карточки и история (с состоянием на дату), права и область учёта, документы с применением на своём этапе, связь с KSC без дублей,
лицензии с зашифрованным ключом, печатные формы и этикетки. Все данные — вымышленные (example.local)."""
from __future__ import annotations

import io
import uuid
import zipfile
from datetime import date, datetime, timedelta, timezone

import pytest

from app.models import InvAsset, KscSource, ZcHost, ZcSource
from app.services import local_admin as la
from tests.conftest import login

API = "/api/v1/inv"


async def setup(client, app):
    async with app.state.session_maker() as db:
        await la.create_local(db, "analyst1", "Analyst-Passw0rd-123", role="analyst", must_change=False)
        await db.commit()
    await login(client, "admin", "Admin-Passw0rd-123")
    meta = (await client.get(f"{API}/meta")).json()
    t = {r["data"].get("cls"): r["id"] for r in meta["refs"] if r["kind"] == "type"}
    st = {r["data"].get("cls"): r["id"] for r in meta["refs"] if r["kind"] == "status"}
    region = (await client.post(f"{API}/locations", json={"kind": "region", "name": "Центральный регион"})).json()
    office = (await client.post(f"{API}/locations", json={"kind": "building", "name": "Офис 1", "parent_id": region["id"]})).json()
    room = (await client.post(f"{API}/locations", json={"kind": "room", "name": "Кабинет 101", "parent_id": office["id"]})).json()
    store = (await client.post(f"{API}/locations", json={"kind": "storage", "name": "Склад ИТ", "parent_id": office["id"]})).json()
    p1 = (await client.post(f"{API}/people", json={"name": "Сотрудник Первый", "email": "user1@example.local", "dept": "Отдел учёта"})).json()
    p2 = (await client.post(f"{API}/people", json={"name": "Сотрудник Второй", "email": "user2@example.local"})).json()
    return {"t": t, "st": st, "region": region, "room": room, "store": store, "p1": p1, "p2": p2}


async def test_card_lifecycle_history_as_of_and_props(client, app):
    s = await setup(client, app)
    assert s["room"]["path"] == "Центральный регион / Офис 1 / Кабинет 101"
    prop = (await client.post(f"{API}/props", json={"name": "Класс энергопотребления", "type": "select", "options": ["A", "B"], "required": True, "type_ids": [s["t"]["laptop"]]})).json()
    r = await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["laptop"], "name": "Ноутбук бухгалтера", "serial": "SN-001", "location_id": s["store"]["id"], "cost": "85 400,50"}})
    assert r.status_code == 422 and f"props.{prop['code']}" in r.json()["detail"]["errors"]       # обязательное свойство
    r = await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["laptop"], "name": "Ноутбук бухгалтера", "serial": "SN-001", "location_id": s["store"]["id"], "cost": "85 400,50",
                                                          "props": {prop["code"]: "A"}}})
    assert r.status_code == 201, r.text
    a = r.json()
    assert a["inv_no"] == "ИТ-000001" and a["cls"] == "laptop" and a["st_cls"] == "stock" and a["cost"] == 8540050 and a["props_text"][prop["code"]] == "A"
    dup = await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["monitor"], "serial": "sn-001"}})
    assert dup.status_code == 409 and dup.json()["detail"]["duplicate"] == a["id"]                 # тот же серийный номер — нужно подтверждение
    upd = await client.put(f"{API}/assets/{a['id']}", json={"data": {"user_id": s["p1"]["id"], "location_id": s["room"]["id"]}, "version": a["version"], "comment": "рабочее место"})
    assert upd.status_code == 200 and upd.json()["user"] == "Сотрудник Первый"
    stale = await client.put(f"{API}/assets/{a['id']}", json={"data": {"name": "x"}, "version": a["version"]})
    assert stale.status_code == 409                                                                  # одновременная правка не перетирает чужие изменения
    h = (await client.get(f"{API}/assets/{a['id']}/history")).json()["items"]
    assert [x["kind"] for x in h] == ["update", "create"] and h[0]["state"]["user"] == "Сотрудник Первый"
    assert {c["f"] for c in h[0]["changes"]} == {"user_id", "location_id"}
    today = date.today().isoformat()
    asof = (await client.get(f"{API}/assets/{a['id']}/asof", params={"on": today})).json()
    assert asof["state"]["location"].endswith("Кабинет 101")
    assert (await client.get(f"{API}/assets/{a['id']}/asof", params={"on": "2000-01-01"})).json()["exists"] is False
    found = (await client.get(f"{API}/assets", params={"q": "бухгалтер первый"})).json()
    assert found["total"] == 1                                                                       # поиск по словам: наименование и пользователь
    assert (await client.get(f"{API}/assets", params={f"p.{prop['code']}": "A"})).json()["total"] == 1
    grp = (await client.get(f"{API}/assets/groups", params={"by": "location"})).json()["items"]
    assert grp[0]["name"].endswith("Кабинет 101") and grp[0]["cost"] == 8540050
    assert (await client.get(f"{API}/lookup", params={"code": f"http://testserver/inventory/a/{a['uid']}"})).json()["id"] == a["id"]
    assert (await client.get(f"{API}/lookup", params={"code": "ИТ-000001"})).json()["id"] == a["id"]
    locs = {x["id"]: x for x in (await client.get(f"{API}/locations")).json()["items"]}
    assert locs[s["region"]["id"]]["total"] == 1 and locs[s["room"]["id"]]["n"] == 1


async def test_permissions_and_location_scope(client, app):
    s = await setup(client, app)
    other = (await client.post(f"{API}/locations", json={"kind": "region", "name": "Северный регион"})).json()
    a1 = (await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["monitor"], "location_id": s["room"]["id"]}})).json()
    a2 = (await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["monitor"], "location_id": other["id"]}})).json()
    await client.put("/api/v1/admin/settings/inventory", json={"grants": [{"login": "analyst1", "perms": [], "location_ids": [s["region"]["id"]]}]})
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get(f"{API}/assets")).json()["total"] == 2
    assert (await client.put(f"{API}/assets/{a1['id']}", json={"data": {"name": "x"}})).status_code == 403          # просмотр без изменения
    await login(client, "analyst1", "Analyst-Passw0rd-123")
    lst = (await client.get(f"{API}/assets")).json()
    assert [x["id"] for x in lst["items"]] == [a1["id"]]                                                          # чужой регион не виден
    assert (await client.get(f"{API}/assets/{a2['id']}")).status_code == 404
    r = await client.put(f"{API}/assets/{a1['id']}", json={"data": {"location_id": other["id"]}})
    assert r.status_code == 422 and "области учёта" in str(r.json())                                               # вынести за пределы области нельзя
    assert (await client.post(f"{API}/locations", json={"kind": "room", "name": "Новый", "parent_id": s["room"]["id"]})).status_code == 403   # справочники — администратору


async def test_documents_apply_on_their_stage_and_print(client, app):
    s = await setup(client, app)
    ids = [(await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["workstation"], "name": f"ПК {i}", "serial": f"WS-{i}", "location_id": s["store"]["id"]}})).json()["id"] for i in range(2)]
    doc = (await client.post(f"{API}/docs", json={"kind": "issue", "to_person_id": s["p1"]["id"], "to_location_id": s["room"]["id"], "basis": "Приказ № 1",
                                                   "items": [{"asset_id": i, "condition": "исправно"} for i in ids]})).json()
    assert doc["no"] == f"ВД-{date.today().year}-00001" and doc["status"] == "draft" and len(doc["items"]) == 2
    assert (await client.get(f"{API}/assets/{ids[0]}")).json()["user_id"] is None                            # черновик карточки не меняет
    r = await client.post(f"{API}/docs/{doc['id']}/status", json={"to": "done"})
    assert r.status_code == 200 and r.json()["changed"] == 2
    a = (await client.get(f"{API}/assets/{ids[0]}")).json()
    assert a["user"] == "Сотрудник Первый" and a["st_cls"] == "use" and a["location"].endswith("Кабинет 101")
    hist = (await client.get(f"{API}/assets/{ids[0]}/history")).json()["items"][0]
    assert hist["doc_no"] == doc["no"] and hist["basis"] == "Приказ № 1"
    assert (await client.post(f"{API}/docs/{doc['id']}/status", json={"to": "draft"})).status_code == 409      # проведённый не возвращается в черновик
    form = (await client.get(f"{API}/docs/{doc['id']}/print")).json()
    assert form["title"] == "Акт выдачи оборудования сотруднику" and [r["serial"] for r in form["rows"]] == ["WS-0", "WS-1"] and form["signatures"][1][1] == "Сотрудник Первый"
    html = (await client.get(f"{API}/docs/{doc['id']}/print", params={"fmt": "html"})).text
    assert "Акт выдачи оборудования сотруднику" in html and "WS-0" in html and "Сотрудник Первый" in html and "ksc" not in html.lower()
    pdf = await client.get(f"{API}/docs/{doc['id']}/print", params={"fmt": "pdf"})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    docx = await client.get(f"{API}/docs/{doc['id']}/print", params={"fmt": "docx"})
    z = zipfile.ZipFile(io.BytesIO(docx.content))
    assert "Сотрудник Первый" in z.read("word/document.xml").decode()
    xlsx = await client.get(f"{API}/docs/{doc['id']}/print", params={"fmt": "xlsx"})
    from openpyxl import load_workbook

    ws = load_workbook(io.BytesIO(xlsx.content)).active
    assert xlsx.status_code == 200 and any("Сотрудник Первый" in str(c.value or "") for row in ws.iter_rows() for c in row)
    # перемещение: «в пути» после отправки, новое место — только после приёма
    mv = (await client.post(f"{API}/docs", json={"kind": "move", "to_location_id": s["store"]["id"], "role": "", "items": [{"asset_id": ids[1]}]})).json()
    for st in ("prepared", "sent"):
        assert (await client.post(f"{API}/docs/{mv['id']}/status", json={"to": st})).status_code == 200
    a = (await client.get(f"{API}/assets/{ids[1]}")).json()
    assert a["in_transit"] and a["location"].endswith("Кабинет 101")
    busy = await client.post(f"{API}/docs", json={"kind": "return", "items": [{"asset_id": ids[1]}]})
    assert busy.status_code == 409                                                                              # единица «в пути» не попадает в другой документ
    await client.post(f"{API}/docs/{mv['id']}/status", json={"to": "accepted"})
    a = (await client.get(f"{API}/assets/{ids[1]}")).json()
    assert not a["in_transit"] and a["location"].endswith("Склад ИТ")
    # ремонт: «В ремонте» при отправке, прежний статус — при возврате
    rp = (await client.post(f"{API}/docs", json={"kind": "repair", "data": {"fault": "не включается", "vendor": "Сервис (пример)"}, "items": [{"asset_id": ids[0]}]})).json()
    await client.post(f"{API}/docs/{rp['id']}/status", json={"to": "sent"})
    assert (await client.get(f"{API}/assets/{ids[0]}")).json()["st_cls"] == "repair"
    await client.post(f"{API}/docs/{rp['id']}/status", json={"to": "done", "data": {"result": "заменён блок питания", "cost": "1500"}})
    assert (await client.get(f"{API}/assets/{ids[0]}")).json()["st_cls"] == "use"
    # возврат снимает пользователя
    rt = (await client.post(f"{API}/docs", json={"kind": "return", "from_person_id": s["p1"]["id"], "to_location_id": s["store"]["id"], "items": [{"asset_id": ids[0]}]})).json()
    await client.post(f"{API}/docs/{rt['id']}/status", json={"to": "done"})
    a = (await client.get(f"{API}/assets/{ids[0]}")).json()
    assert a["user_id"] is None and a["st_cls"] == "stock"
    person = (await client.get(f"{API}/people/{s['p1']['id']}")).json()
    assert {h["action"] for h in person["history"]} >= {"закреплено"}
    lab = await client.get(f"{API}/labels", params={"ids": ",".join(map(str, ids))})
    assert lab.status_code == 200 and lab.content[:4] == b"%PDF"
    zpl = await client.get(f"{API}/labels", params={"ids": str(ids[0]), "fmt": "zpl"})
    assert "^XA" in zpl.text and "/inventory/a/" in zpl.text


async def test_ksc_import_without_duplicates_and_link_sync(client, app):
    s = await setup(client, app)
    sid = uuid.uuid4()
    now = datetime.now(timezone.utc)
    async with app.state.session_maker() as db:
        db.add(KscSource(id=sid, name="KSC-тест", host="ksc.example.local", port=1433, database="KAV", username="ro", password_enc="x"))
        db.add(ZcSource(source_id=sid, gen=1, status="ready", built_at=now))
        for hid, name, os_ in ((1, "pc-001", "Windows 11 Pro"), (2, "srv-app01.example.local", "Windows Server 2022"), (3, "pc-legacy", "Windows 10")):
            db.add(ZcHost(source_id=sid, host_id=hid, gen=1, name=name, search=name, os=os_, last_connected=now, active=True, data={"ip": "192.0.2.10"}))
        await db.commit()
    lst = (await client.get(f"{API}/ksc/hosts", params={"source": str(sid)})).json()
    assert lst["total"] == 3
    r = (await client.post(f"{API}/ksc/import", json={"source_id": str(sid), "host_ids": [1, 2]})).json()
    assert r["created"] == 2
    again = (await client.post(f"{API}/ksc/import", json={"source_id": str(sid), "host_ids": [1, 2]})).json()
    assert again["created"] == 0 and again["skipped"] == 2                                                   # повторный импорт не создаёт дублей
    srv = (await client.get(f"{API}/assets", params={"cls": "server"})).json()["items"]
    assert len(srv) == 1 and srv[0]["hostname"] == "srv-app01" and srv[0]["ksc_link"] == "confirmed"
    bh = (await client.get(f"{API}/by-host", params={"source": str(sid), "host": 1})).json()
    assert bh["asset"]["hostname"] == "pc-001"
    manual = (await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["workstation"], "hostname": "PC-LEGACY"}})).json()
    assert (await client.get(f"{API}/by-host", params={"source": str(sid), "host": 3})).json()["candidates"][0]["id"] == manual["id"]
    from app.inventory.service import sync_links

    async with app.state.session_maker() as db:
        st = await sync_links(db)
        await db.commit()
    assert st["auto"] == 1                                                                                   # единственное совпадение имени — предполагаемая связь
    async with app.state.session_maker() as db:
        await db.execute(ZcHost.__table__.delete().where(ZcHost.host_id == 1))
        await db.commit()
        st = await sync_links(db)
        await db.commit()
        lost = (await db.execute(InvAsset.__table__.select().where(InvAsset.ksc_host_id == 1))).first()
    assert st["lost"] == 1 and lost.ksc_link == "lost"                                                       # карточка остаётся, связь — утрачена
    conflict = await client.put(f"{API}/assets/{manual['id']}/ksc", json={"source_id": str(sid), "host_id": 2})
    assert conflict.status_code == 409
    sid2 = uuid.uuid4()                                                    # второй источник: выбор нескольких источников и фильтр «на связи за N суток»
    async with app.state.session_maker() as db:
        db.add(KscSource(id=sid2, name="KSC-второй", host="ksc2.example.local", port=1433, database="KAV", username="ro", password_enc="x"))
        db.add(ZcSource(source_id=sid2, gen=1, status="ready", built_at=now))
        db.add(ZcHost(source_id=sid2, host_id=1, gen=1, name="pc-b01", search="pc-b01", os="Windows 11 Pro", last_connected=now, active=True, data={}))
        db.add(ZcHost(source_id=sid2, host_id=2, gen=1, name="pc-b-old", search="pc-b-old", os="Windows 10", last_connected=now - timedelta(days=90), active=False, data={}))
        await db.commit()
    both = (await client.get(f"{API}/ksc/hosts", params={"source": f"{sid},{sid2}", "days": 30})).json()
    assert {h["name"] for h in both["items"]} == {"pc-b01"} and both["hidden_old"] == 1 and both["items"][0]["source"] == "KSC-второй"
    r = (await client.post(f"{API}/ksc/import", json={"hosts": [{"source_id": h["source_id"], "host_id": h["host_id"]} for h in both["items"]]})).json()
    assert r["created"] == 1 and (await client.get(f"{API}/ksc/hosts", params={"source": f"{sid},{sid2}", "days": 30})).json()["total"] == 0


async def test_licenses_keep_key_reference_not_key(client, app):
    s = await setup(client, app)
    a = (await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["workstation"]}})).json()
    ref = "https://vault.example.local/records/office-2026"
    assert (await client.post(f"{API}/licenses", json={"name": "Офисный пакет (пример)", "key": "AAAAA-BBBBB-CCCCC"})).status_code == 422     # ключи здесь не хранятся
    r = await client.post(f"{API}/licenses", json={"name": "Офисный пакет (пример)", "qty": 1, "valid_until": "2000-01-01", "key_ref": ref, "match": ["Офисный пакет*"]})
    lid = r.json()["id"]
    await client.post(f"{API}/licenses/{lid}/assign", json={"asset_ids": [a["id"]], "person_ids": [s["p1"]["id"]]})
    card = (await client.get(f"{API}/licenses/{lid}")).json()
    assert card["assigned"] == 2 and "срок действия истёк" in card["issues"] and any("назначено больше" in i for i in card["issues"])
    assert card["key_ref"] == ref and not card["key_set"]
    async with app.state.session_maker() as db:                       # ключ прежней версии: виден по праву keys с записью в журнал, удаляется пустым значением
        from app.models import InvLicense

        lc = await db.get(InvLicense, lid)
        lc.key_enc = app.state.settings_svc.encrypt("OLD-KEY", f"inv.lic.{lid}")
        await db.commit()
    assert (await client.get(f"{API}/licenses/{lid}/key")).json()["key"] == "OLD-KEY"
    await login(client, "analyst1", "Analyst-Passw0rd-123")
    assert (await client.get(f"{API}/licenses/{lid}/key")).status_code == 403
    await login(client, "admin", "Admin-Passw0rd-123")
    log = (await client.get("/api/v1/admin/audit", params={"q": "inv.license.key_view"})).json()
    assert any(i["action"] == "inv.license.key_view" for i in log.get("items", log if isinstance(log, list) else []))
    body = {k: card[k] for k in ("name", "qty", "match")} | {"key_ref": ref, "key": ""}
    assert (await client.put(f"{API}/licenses/{lid}", json=body)).status_code == 200
    assert not (await client.get(f"{API}/licenses/{lid}")).json()["key_set"]


async def test_reports_build_with_tabs_and_respect_scope(client, app):
    s = await setup(client, app)
    other = (await client.post(f"{API}/locations", json={"kind": "region", "name": "Северный регион"})).json()
    a1 = (await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["laptop"], "name": "Ноутбук А", "serial": "DUP-1", "location_id": s["room"]["id"], "cost": "1000", "user_id": s["p1"]["id"]}})).json()
    await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["laptop"], "name": "Ноутбук Б", "serial": "DUP-1", "location_id": other["id"]}, "force": True})
    for view in ("registry", "computers", "card", "by_person", "by_resp", "by_location", "stock", "repair", "warranty", "writtenoff", "cost", "owner_history", "moves", "licenses",
                 "license_usage", "components", "docs", "duplicates", "hardware", "software"):
        r = await client.post("/api/v1/quick/preview", json={"kind": "quick_inv", "params": {"view": view, "asset_id": a1["id"]}})
        assert r.status_code == 200, (view, r.text)
    reg = (await client.post("/api/v1/quick/preview", json={"kind": "quick_inv", "params": {"view": "registry"}})).json()
    assert reg["doc"]["title"] == "Реестр ИТ-оборудования" and reg["total"] == 2
    dup = (await client.post("/api/v1/quick/preview", json={"kind": "quick_inv", "params": {"view": "duplicates"}})).json()
    assert dup["total"] == 2
    from app.reports.quick import Ctx, build

    doc = await build("quick_inv", None, {"view": "registry"}, Ctx(source_name="", activity_days=30, sm=app.state.session_maker))
    assert [t["id"] for t in doc["tabs"]] == ["rows", "by_type", "by_loc", "by_st"] and len(doc["tables"][0]["rows"]) == 2
    await client.put("/api/v1/admin/settings/inventory", json={"grants": [{"login": "analyst1", "perms": [], "location_ids": [s["region"]["id"]]}]})
    await login(client, "analyst1", "Analyst-Passw0rd-123")
    r = await client.post("/api/v1/quick/preview", json={"kind": "quick_inv", "params": {"view": "registry", "scope_ids": []}})
    assert r.json()["total"] == 1                                                              # область учёта не обходится параметром клиента
    job = await client.post("/api/v1/reports", json={"kind": "quick_inv", "title": "Реестр", "params": {"view": "registry"}})
    assert job.status_code == 201 and job.json()["params"]["scope_ids"] == [s["region"]["id"]]



async def test_rerun_of_inventory_report_applies_current_scope(client, app):
    s = await setup(client, app)
    await login(client, "analyst1", "Analyst-Passw0rd-123")
    job = (await client.post("/api/v1/reports", json={"kind": "quick_inv", "title": "Реестр", "params": {"view": "registry"}})).json()
    assert job["params"]["scope_ids"] == []                                                   # пока ограничений нет — весь учёт
    await login(client, "admin", "Admin-Passw0rd-123")
    await client.put("/api/v1/admin/settings/inventory", json={"grants": [{"login": "analyst1", "perms": [], "location_ids": [s["region"]["id"]]}]})
    await login(client, "analyst1", "Analyst-Passw0rd-123")
    again = await client.post(f"/api/v1/reports/{job['id']}/rerun")
    assert again.status_code == 201 and again.json()["params"]["scope_ids"] == [s["region"]["id"]]      # повтор не расширяет область прежними параметрами

async def test_import_csv_preview_check_and_upsert(client, app):
    s = await setup(client, app)
    csv_text = ("Инв. номер;Наименование;Серийный номер;Тип;Производитель;Модель;Местоположение;Пользователь;Стоимость;Гарантия до\n"
                "ИТ-100001;Ноутбук отдела;SN-A1;Ноутбук;Вендор (пример);Модель X1;Центральный регион / Офис 1 / Кабинет 202;user1@example.local;54 000,00;31.12.2027\n"
                "ИТ-100002;Монитор;SN-A2;Монитор;Вендор (пример);Модель M2;Центральный регион / Офис 1 / Кабинет 202;Новый Сотрудник;12000;\n"
                "ИТ-100001;Повтор;SN-A3;Монитор;;;;;;\n"
                "ИТ-100003;Неизвестный тип;SN-A4;Холодильник;;;;;;\n").encode("utf-8")
    pv = (await client.post(f"{API}/import/preview", content=csv_text, headers={"X-File-Name": "import.csv", "Content-Type": "application/octet-stream"})).json()
    assert pv["total"] == 4 and pv["mapping"]["Инв. номер"] == "inv_no" and pv["mapping"]["Местоположение"] == "location" and pv["mapping"]["Гарантия до"] == "warranty_until"
    from urllib.parse import quote
    import json as _j

    hdrs = {"X-File-Name": "import.csv", "X-Mapping": quote(_j.dumps(pv["mapping"])), "Content-Type": "application/octet-stream"}
    chk = (await client.post(f"{API}/import/run", params={"dry_run": True}, content=csv_text, headers=hdrs)).json()
    assert chk["created"] == 2 and chk["skipped"] == 2 and {e["row"] for e in chk["errors"]} == {4, 5}
    assert (await client.get(f"{API}/assets")).json()["total"] == 0                                            # проверка ничего не записывает
    run = (await client.post(f"{API}/import/run", params={"dry_run": False}, content=csv_text, headers=hdrs)).json()
    assert run["created"] == 2 and run["created_refs"]["locations"] == 1 and run["created_refs"]["people"] == 1
    a = (await client.get(f"{API}/assets", params={"q": "SN-A1"})).json()["items"][0]
    assert a["user"] == "Сотрудник Первый" and a["location"].endswith("Кабинет 202") and a["cost"] == 5400000 and a["warranty_until"] == "2027-12-31" and a["model"] == "Модель X1"
    again = (await client.post(f"{API}/import/run", params={"dry_run": False}, content=csv_text, headers=hdrs)).json()
    assert again["created"] == 0 and again["unchanged"] == 2                                                   # повторный импорт не создаёт дублей


async def test_import_template_example_imports_cleanly(client, app):
    await setup(client, app)
    from urllib.parse import quote
    import json as _j

    empty = await client.get(f"{API}/import/template", params={"fmt": "xlsx"})
    assert empty.status_code == 200 and empty.content[:2] == b"PK"
    csv_text = (await client.get(f"{API}/import/template", params={"fmt": "csv", "example": True})).content
    assert csv_text.startswith("\ufeff".encode())
    pv = (await client.post(f"{API}/import/preview", content=csv_text, headers={"X-File-Name": "t.csv", "Content-Type": "application/octet-stream"})).json()
    assert pv["total"] == 3 and set(pv["mapping"].values()) >= {"serial", "type", "location", "user", "cost", "warranty_until"}
    hdrs = {"X-File-Name": "t.csv", "X-Mapping": quote(_j.dumps(pv["mapping"])), "Content-Type": "application/octet-stream"}
    chk = (await client.post(f"{API}/import/run", params={"dry_run": True}, content=csv_text, headers=hdrs)).json()
    assert chk["created"] == 3 and not chk["errors"], chk


def test_inventory_enum_values_fit_postgres_column_lengths():
    """SQLite длину строк не проверяет: значения словарей раздела должны помещаться в столбцы PostgreSQL."""
    from app import models as m
    from app.inventory import model as M

    cases = [(m.InvAsset.cls, M.CLS_RU), (m.InvAsset.st_cls, M.ST_RU), (m.InvAsset.rel, M.REL_RU), (m.InvAsset.ksc_link, ("confirmed", "auto", "lost")), (m.InvLocation.kind, M.LOC_RU),
             (m.InvRef.kind, M.REF_RU), (m.InvDoc.kind, M.DOC_RU), (m.InvDoc.status, M.DOC_STATUS_RU), (m.InvHistory.kind, M.HIST_RU), (m.InvLicense.metric, M.METRIC_RU),
             (m.InvPerson.source, ("manual", "bi", "hier", "ad")), (m.InvFile.owner, ("asset", "doc", "license")), (m.InvProp.type, M.PROP_TYPES)]
    for col, values in cases:
        assert col.type.length >= max(len(v) for v in values), (col, values)


async def test_count_scan_offline_close_and_decisions(client, app):
    s = await setup(client, app)
    room2 = (await client.post(f"{API}/locations", json={"kind": "room", "name": "Кабинет 102", "parent_id": s["region"]["id"]})).json()
    mk = lambda i, loc, **kw: client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["monitor"], "serial": f"CNT-{i}", "location_id": loc, **kw}})
    a = [(await mk(i, s["room"]["id"])).json() for i in range(3)]
    other = (await mk(9, room2["id"])).json()
    skip = (await mk(8, s["room"]["id"], no_count=True)).json()
    c = (await client.post(f"{API}/counts", json={"location_id": s["room"]["id"]})).json()
    assert c["status"] == "active" and c["stats"]["expected"] == 3                       # «не подлежит инвентаризации» не ожидается
    scan = lambda code, loc=s["room"]["id"], **kw: client.post(f"{API}/counts/{c['id']}/scan", json={"code": code, "location_id": loc, **kw})
    assert (await scan(a[0]["inv_no"])).json()["result"] == "found"
    assert (await scan("CNT-1", loc=room2["id"])).json()["result"] == "moved"           # по серийному номеру, но в другом помещении
    assert (await scan(f"http://testserver/inventory/a/{other['uid']}")).json()["result"] == "extra"
    assert (await scan("НЕТ-ТАКОГО")).json()["result"] == "unknown"
    assert (await scan(a[0]["inv_no"])).json()["result"] == "again"
    sync = (await client.post(f"{API}/counts/{c['id']}/sync", json={"scans": [{"code": skip["inv_no"], "location_id": s["room"]["id"], "user_id": s["p2"]["id"]}]})).json()
    assert sync["results"][0]["result"] == "extra"                                          # отметка из автономного режима
    assert (await client.get(f"{API}/assets/{a[1]['id']}")).json()["location"].endswith("Кабинет 101")    # сканирование учёт не меняет
    st = (await client.get(f"{API}/counts/{c['id']}")).json()["stats"]
    assert st["by_state"]["pending"] == 1 and st["user_diff"] == 1
    closed = (await client.post(f"{API}/counts/{c['id']}/close")).json()
    assert closed["status"] == "closed" and closed["stats"]["by_state"]["missing"] == 1
    diff = (await client.get(f"{API}/counts/{c['id']}/items", params={"diff": True})).json()["items"]
    by = {d["state"]: d for d in diff}
    assert set(by) == {"moved", "extra", "unknown", "missing"}
    r = await client.post(f"{API}/counts/{c['id']}/decide", json={"item_ids": [by["moved"]["id"]], "decision": "apply"})
    assert r.json()["changed"] == 1
    moved = (await client.get(f"{API}/assets/{a[1]['id']}")).json()
    assert moved["location"].endswith("Кабинет 102")
    h = (await client.get(f"{API}/assets/{a[1]['id']}/history")).json()["items"][0]
    assert h["kind"] == "count" and c["no"] in h["basis"]
    assert (await client.post(f"{API}/counts/{c['id']}/decide", json={"item_ids": [by["unknown"]["id"]], "decision": "apply"})).status_code == 422
    assert (await client.post(f"{API}/counts/{c['id']}/decide", json={"item_ids": [by["missing"]["id"]], "decision": "lost"})).json()["changed"] == 1
    assert (await client.get(f"{API}/assets/{by['missing']['asset_id']}")).json()["st_cls"] == "lost"
    rep = (await client.post("/api/v1/quick/preview", json={"kind": "quick_inv", "params": {"view": "count_diff", "count_id": c["id"]}})).json()
    assert rep["total"] == 5
    off = (await client.get(f"{API}/counts/{c['id']}/offline")).json()
    assert len(off["items"]) == 5 and any(l["id"] == s["room"]["id"] for l in off["locations"]) is True


async def test_receipt_creates_cards_stock_and_digest(client, app):
    s = await setup(client, app)
    lines = [{"type_id": s["t"]["laptop"], "name": "Ноутбук (поставка)", "qty": 3, "cost": "50 000", "warranty_until": "2030-01-31", "serials": ["RC-1", "RC-2"]},
             {"type_id": s["t"]["monitor"], "qty": 2}]
    d = (await client.post(f"{API}/docs", json={"kind": "receipt", "to_location_id": s["store"]["id"], "basis": "Счёт № 7 (пример)", "data": {"lines": lines}})).json()
    assert d["no"].startswith("ПС-") and d["items_n"] == 0
    form = (await client.get(f"{API}/docs/{d['id']}/print")).json()
    assert len(form["rows"]) == 2                                                              # до приёмки — строки заказа
    assert (await client.post(f"{API}/docs/{d['id']}/status", json={"to": "sent"})).status_code == 200
    r = (await client.post(f"{API}/docs/{d['id']}/status", json={"to": "done"})).json()
    assert r["status"] == "done"
    got = (await client.get(f"{API}/assets", params={"location": s["store"]["id"]})).json()["items"]
    assert len(got) == 5 and {a["serial"] for a in got} >= {"RC-1", "RC-2"} and all(a["st_cls"] == "stock" for a in got)
    lap = next(a for a in got if a["serial"] == "RC-1")
    assert lap["cost"] == 5000000 and lap["warranty_until"] == "2030-01-31" and lap["purchase_doc"].startswith("Счёт")
    doc = (await client.get(f"{API}/docs/{d['id']}")).json()
    assert len(doc["items"]) == 5
    stock = (await client.get(f"{API}/stock")).json()
    assert stock["by_st"]["stock"] == 5 and stock["receipts"][0]["created"] == 5
    big = await client.post(f"{API}/docs", json={"kind": "receipt", "to_location_id": s["store"]["id"], "data": {"lines": [{"type_id": s["t"]["monitor"], "qty": 501}]}})
    assert big.status_code == 422
    # комплектующее: установка и снятие — событие «Состав»
    comp = (await client.post(f"{API}/assets", json={"data": {"type_id": next(r["id"] for r in (await client.get(f"{API}/meta")).json()["refs"] if r["kind"] == "type" and r["data"]["cls"] == "component"), "name": "Модуль памяти"}})).json()
    up = await client.put(f"{API}/assets/{comp['id']}", json={"data": {"parent_id": lap["id"]}, "version": comp["version"]})
    assert up.json()["rel"] == "part"
    assert (await client.get(f"{API}/assets/{comp['id']}/history")).json()["items"][0]["kind"] == "part"
    from app.inventory.service import digest
    from app.services.settings import InventorySettings

    async with app.state.session_maker() as db:
        secs = await digest(db, InventorySettings(warranty_days=730))
    assert not secs or all(sec["rows"] for sec in secs)
    pv = (await client.get(f"{API}/notify/preview")).json()
    assert isinstance(pv["sections"], list)


def _count_sql(app):
    """Счётчик SQL-операторов движка приложения (для проверки отсутствия N+1)."""
    from sqlalchemy import event

    n = [0]

    def hook(*_a, **_kw):
        n[0] += 1

    event.listen(app.state.engine.sync_engine, "before_cursor_execute", hook)
    return n, lambda: event.remove(app.state.engine.sync_engine, "before_cursor_execute", hook)


async def test_bulk_edit_is_batched_and_rolls_back_invalid_card(client, app):
    s = await setup(client, app)
    ids = [(await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["monitor"], "location_id": s["room"]["id"], "user_id": s["p1"]["id"]}})).json()["id"] for _ in range(50)]
    n, stop = _count_sql(app)
    r = await client.post(f"{API}/assets/bulk", json={"ids": ids, "data": {"status_id": s["st"]["use"], "location_id": s["store"]["id"], "resp_id": s["p2"]["id"]}})
    stop()
    assert r.json()["changed"] == 50 and n[0] < 200, n[0]                     # пакет — не десятки запросов на карточку
    print(f"bulk 50 cards: {n[0]} SQL statements")
    lap = (await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["laptop"], "location_id": s["room"]["id"]}})).json()
    await client.post(f"{API}/props", json={"name": "Класс (пример)", "type": "text", "required": True, "type_ids": [s["t"]["laptop"]]})
    r = (await client.post(f"{API}/assets/bulk", json={"ids": [ids[0], lap["id"]], "data": {"status_id": s["st"]["repair"], "props": {}}})).json()
    assert r["changed"] == 1 and [e["id"] for e in r["errors"]] == [lap["id"]]
    after = (await client.get(f"{API}/assets/{lap['id']}")).json()
    assert after["st_cls"] == "stock" and after["version"] == lap["version"]                               # карточка с ошибкой не изменена частично
    assert [h["kind"] for h in (await client.get(f"{API}/assets/{lap['id']}/history")).json()["items"]] == ["create"]
    assert (await client.get(f"{API}/assets/{ids[0]}")).json()["st_cls"] == "repair"


async def test_document_stage_rechecks_transit_and_writeoff(client, app):
    s = await setup(client, app)
    x = (await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["monitor"], "location_id": s["room"]["id"]}})).json()["id"]
    mv = [(await client.post(f"{API}/docs", json={"kind": "move", "to_location_id": s["store"]["id"], "items": [{"asset_id": x}]})).json()["id"] for _ in range(2)]
    for d in mv:
        assert (await client.post(f"{API}/docs/{d}/status", json={"to": "prepared"})).status_code == 200
    assert (await client.post(f"{API}/docs/{mv[0]}/status", json={"to": "sent"})).status_code == 200
    assert (await client.post(f"{API}/docs/{mv[1]}/status", json={"to": "sent"})).status_code == 409      # уже «в пути» по первому перемещению
    assert (await client.post(f"{API}/docs/{mv[0]}/status", json={"to": "accepted"})).status_code == 200
    a = (await client.get(f"{API}/assets/{x}")).json()
    assert not a["in_transit"] and a["location"].endswith("Склад ИТ")
    iss = (await client.post(f"{API}/docs", json={"kind": "issue", "to_person_id": s["p1"]["id"], "items": [{"asset_id": x}]})).json()["id"]
    wo = (await client.post(f"{API}/docs", json={"kind": "writeoff", "items": [{"asset_id": x}]})).json()["id"]
    assert (await client.post(f"{API}/docs/{wo}/status", json={"to": "done"})).status_code == 200
    assert (await client.post(f"{API}/docs/{iss}/status", json={"to": "done"})).status_code == 409         # списанное не выдаётся по старому черновику
    assert (await client.get(f"{API}/assets/{x}")).json()["st_cls"] == "writeoff"


async def test_import_failed_row_does_not_poison_created_refs(client, app):
    await setup(client, app)
    from urllib.parse import quote
    import json as _j

    csv_text = ("Инв. номер;Наименование;Производитель;Гарантия до\n"
                "ИТ-200001;Первый;Новый вендор (пример);не дата\n"
                "ИТ-200002;Второй;Новый вендор (пример);31.12.2030\n").encode("utf-8")
    mapping = {"Инв. номер": "inv_no", "Наименование": "name", "Производитель": "manufacturer", "Гарантия до": "warranty_until"}
    hdrs = {"X-File-Name": "i.csv", "X-Mapping": quote(_j.dumps(mapping)), "Content-Type": "application/octet-stream"}
    run = (await client.post(f"{API}/import/run", params={"dry_run": False}, content=csv_text, headers=hdrs)).json()
    assert run["created"] == 1 and [e["row"] for e in run["errors"]] == [2] and run["created_refs"]["refs"] == 1, run
    assert (await client.get(f"{API}/assets", params={"q": "ИТ-200002"})).json()["items"][0]["manufacturer"] == "Новый вендор (пример)"


async def test_location_scope_covers_docs_files_counts_and_licenses(client, app):
    s = await setup(client, app)
    other = (await client.post(f"{API}/locations", json={"kind": "region", "name": "Северный регион"})).json()
    a1 = (await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["monitor"], "name": "Монитор свой", "location_id": s["room"]["id"]}})).json()
    a2 = (await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["monitor"], "name": "Монитор чужой", "location_id": other["id"]}})).json()
    d_in = (await client.post(f"{API}/docs", json={"kind": "work", "items": [{"asset_id": a1["id"]}]})).json()["id"]
    d_out = (await client.post(f"{API}/docs", json={"kind": "work", "items": [{"asset_id": a2["id"]}]})).json()["id"]
    d_mix = (await client.post(f"{API}/docs", json={"kind": "work", "items": [{"asset_id": a1["id"]}, {"asset_id": a2["id"]}]})).json()["id"]
    fid = (await client.post(f"{API}/files", params={"owner": "doc", "oid": d_out}, content=b"x", headers={"X-File-Name": "a.txt"})).json()["id"]
    c_out = (await client.post(f"{API}/counts", json={"location_id": other["id"], "start": False})).json()["id"]
    c_in = (await client.post(f"{API}/counts", json={"location_id": s["room"]["id"], "start": False})).json()["id"]
    lid = (await client.post(f"{API}/licenses", json={"name": "Программа (пример)"})).json()["id"]
    await client.post(f"{API}/licenses/{lid}/assign", json={"asset_ids": [a2["id"]]})
    from sqlalchemy import select
    from app.models import InvLicAssign

    async with app.state.session_maker() as db:
        asg = (await db.execute(select(InvLicAssign.id).where(InvLicAssign.asset_id == a2["id"]))).scalar_one()
    await client.put("/api/v1/admin/settings/inventory", json={"grants": [{"login": "analyst1", "perms": [], "location_ids": [s["region"]["id"]]}]})
    await login(client, "analyst1", "Analyst-Passw0rd-123")
    assert [d["id"] for d in (await client.get(f"{API}/docs")).json()["items"]] == [d_in]
    assert (await client.get(f"{API}/docs", params={"q": "чужой"})).json()["total"] == 0
    for path in (f"/docs/{d_out}", f"/docs/{d_mix}", f"/docs/{d_out}/print", f"/files/{fid}", f"/counts/{c_out}"):
        assert (await client.get(API + path)).status_code == 404, path
    assert (await client.get(f"{API}/docs/{d_in}")).status_code == 200
    assert [c["id"] for c in (await client.get(f"{API}/counts")).json()["items"]] == [c_in]
    assert (await client.post(f"{API}/licenses/{lid}/assign", json={"asset_ids": [a1["id"], a2["id"]]})).json()["added"] == 1
    assert (await client.delete(f"{API}/licenses/{lid}/assign/{asg}")).status_code == 404


async def test_print_xlsx_escapes_formulas(client, app):
    s = await setup(client, app)
    a = (await client.post(f"{API}/assets", json={"data": {"type_id": s["t"]["monitor"], "name": "=HYPERLINK(\"http://example.local\")"}})).json()
    d = (await client.post(f"{API}/docs", json={"kind": "work", "items": [{"asset_id": a["id"]}]})).json()["id"]
    from openpyxl import load_workbook

    ws = load_workbook(io.BytesIO((await client.get(f"{API}/docs/{d}/print", params={"fmt": "xlsx"})).content)).active
    vals = [str(c.value) for row in ws.iter_rows() for c in row if c.value]
    assert any(v.startswith("'=HYPERLINK") for v in vals) and not any(v.startswith("=HYPERLINK") for v in vals)   # имя карточки не становится формулой


async def test_infra_sync_error_of_one_source_does_not_stop_others(client, app, monkeypatch):
    await login(client, "admin", "Admin-Passw0rd-123")
    ids = [(await client.post(f"{API}/infra/sources", json={"kind": "proxmox", "name": nm, "url": f"https://{h}.example.local", "username": "reader@pve!kav", "secret": "y"})).json()["id"]
           for nm, h in (("Сбойный (пример)", "pve1"), ("Рабочий (пример)", "pve2"))]
    from app.infra import connectors as K
    from app.infra import sync as IS
    from app.inventory.service import InvService

    async def fetch(src, secret, transport=None):
        return []
    real = IS.sync_source

    async def sync_source(db, row, objects):
        if row.name.startswith("Сбойный"):
            raise RuntimeError("сбой сопоставления")
        return await real(db, row, objects)
    monkeypatch.setattr(K, "fetch", fetch)
    monkeypatch.setattr(IS, "sync_source", sync_source)
    await InvService(app.state.session_maker, app.state.settings_svc, None, None).infra_tick(force=True)
    srcs = {x["id"]: x for x in (await client.get(f"{API}/infra/sources")).json()["items"]}
    assert "RuntimeError" in srcs[ids[0]]["last_error"] and srcs[ids[0]]["last_try_at"]
    assert srcs[ids[1]]["last_error"] == "" and srcs[ids[1]]["last_ok_at"]


def test_read_table_rejects_non_csv_with_message():
    from app.inventory import importer as IM
    with pytest.raises(IM.ImportError_, match="не похож на таблицу"):
        IM.read_table(b"\0" * 200_000, "x.csv")              # «поле» больше предела csv — понятная ошибка вместо 500
