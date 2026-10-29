"""Отчёты по таблицам администрирования: те же условия, что у таблиц страниц (журнал событий — уровень, компонент, текст), все представления строятся, доступ — только администратору."""
from app.models import EventLog, utcnow
from tests.conftest import login


def prev(client, **p):
    return client.post("/api/v1/quick/preview", json={"kind": "quick_admin", "params": p, "source_ids": []})


async def test_admin_reports_follow_page_filters_and_are_admin_only(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    async with app.state.session_maker() as db:
        now = utcnow()
        db.add_all([EventLog(at=now, level="error", category="catalog", event="catalog_failed", source="KSC-A", message="Каталог не построен: SQL Server недоступен"),
                    EventLog(at=now, level="info", category="catalog", event="catalog_built", source="KSC-A", message="Каталог построен"),
                    EventLog(at=now, level="warn", category="system", event="log_warn", message="Чтение лицензий не удалось")])
        await db.commit()
    page = (await client.get("/api/v1/admin/journal", params={"level": "error", "category": "catalog"})).json()
    r = await prev(client, view="journal", level="error", category="catalog", range="24h")
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["total"] == page["total"] == 1 and doc["items"][0]["event"] == "catalog_failed"       # отчёт = выборка страницы, не весь журнал
    assert any(c["label"] == "Уровень" for c in doc["doc"]["conditions"])
    warn = (await prev(client, view="journal", level="warn")).json()
    assert {i["event"] for i in warn["items"]} == {"catalog_failed", "log_warn"}
    csv = (await client.get("/api/v1/admin/journal/export.csv", params={"level": "error", "category": "catalog"})).text
    assert "catalog_failed" in csv and "catalog_built" not in csv                                     # и выгрузка CSV на странице — с теми же условиями
    for view in ("licenses", "audit", "users", "components"):
        got = await prev(client, view=view)
        assert got.status_code == 200, (view, got.text)
        assert got.json()["doc"]["tables"], view
    users = (await prev(client, view="users", q="viewer")).json()
    assert [i["login"] for i in users["items"]] == ["viewer"] and "password" not in str(users).lower()
    assert (await prev(client, view="bi_imports")).status_code == 422                                 # без источника — понятная ошибка
    job = await client.post("/api/v1/reports", json={"kind": "quick_admin", "title": "Журнал событий", "params": {"view": "journal", "level": "error"}, "source_ids": []})
    assert job.status_code == 201, job.text
    await client.post("/api/v1/auth/logout")
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await prev(client, view="journal")).status_code == 403
    assert (await client.get(f"/api/v1/reports/{job.json()['id']}")).status_code in (403, 404)


async def test_ksc_users_report_has_full_host_lists_and_hides_bi_for_viewer(client, app):
    import uuid

    from app.models import DeviceUser, KscSource, ZcHost, ZcSource
    from app.reports import quick
    from app.reports.quick_devices import build_devices

    async with app.state.session_maker() as db:
        src = KscSource(name="KSC-U", host="ksc.example.local", database="KAV", username="u", password_enc="x")
        db.add(src)
        await db.flush()
        db.add(ZcSource(source_id=src.id, gen=1, status="ready"))
        for i in range(5):
            db.add(ZcHost(source_id=src.id, gen=1, host_id=i, name=f"ws-{i}", os="Windows 11"))
            db.add(DeviceUser(source_id=src.id, host_id=i, user_key="i.ivanov", login="i.ivanov", domain="EXAMPLE", kind="user", resolved=True, first_seen_at=utcnow(), last_seen_at=utcnow()))
        await db.commit()
        sid = src.id
    ctx = quick.Ctx(source_name="KSC-U", activity_days=30, sm=app.state.session_maker, source_id=sid, source_ids=[sid])
    doc = await build_devices(None, {"view": "users", "pd": False}, ctx)
    (row,) = doc["tables"][0]["rows"]
    assert row["hosts"] == 5 and len(row["host_names"].split("; ")) == 5                         # на странице — три и «+N», в отчёте — все
    assert "bi" not in {c["key"] for c in doc["tables"][0]["columns"]}
    _ = uuid


async def test_job_lists_of_pentest_and_hunt_report_with_page_filters(client, app):
    from app.models import PtJob

    await login(client, "admin", "Admin-Passw0rd-123")
    async with app.state.session_maker() as db:
        db.add_all([PtJob(title="Сеть офиса", status="done", findings_n=3, options={}, rejected=[], sev={}),
                    PtJob(title="Склад", status="partial", error="2 хоста не ответили до тайм-аута", options={}, rejected=[], sev={}),
                    PtJob(title="CVE-2024-6387", status="done", profile="hunt", options={}, rejected=[], sev={})])
        await db.commit()
    pt = (await client.post("/api/v1/quick/preview", json={"kind": "quick_pentest", "params": {"view": "jobs", "status": "partial"}, "source_ids": []})).json()
    assert [i["title"] for i in pt["items"]] == ["Склад"] and "тайм-аута" in pt["items"][0]["error"]           # причина частичного завершения — в отчёте
    hunt = (await client.post("/api/v1/quick/preview", json={"kind": "quick_hunt", "params": {"view": "jobs"}, "source_ids": []})).json()
    assert [i["title"] for i in hunt["items"]] == ["CVE-2024-6387"]                                          # история CVE Hunt — только задания целевого поиска


async def test_source_card_shows_failed_background_read(client, app):
    """«Проверен» в карточке источника — только ручная проверка; ошибка ночного чтения данных видна там же, вместе со временем последних данных."""
    from app.models import KscSource, ZcSource

    await login(client, "admin", "Admin-Passw0rd-123")
    async with app.state.session_maker() as db:
        src = KscSource(name="KSC-S", host="ksc.example.local", database="KAV", username="u", password_enc="x", last_check_ok=True)
        db.add(src)
        await db.flush()
        db.add(ZcSource(source_id=src.id, gen=2, status="ready", built_at=utcnow(), finished_at=utcnow(), error="Вход на SQL Server отклонён: проверьте имя пользователя и пароль"))
        await db.commit()
    (item,) = [i for i in (await client.get("/api/v1/admin/sources")).json()["items"] if i["name"] == "KSC-S"]
    assert item["last_check_ok"] is True and item["sync"]["status"] == "ready" and "отклонён" in item["sync"]["error"]
