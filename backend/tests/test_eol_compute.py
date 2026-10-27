"""Сопоставление каталога и ОС источника с жизненным циклом: находки, устройства, неоднозначность, решения администратора (SQLite, подставной KSC; данные endoflife.date — срез из fixtures)."""
import json
import uuid
from datetime import date
from pathlib import Path

from sqlalchemy import select

from app.eol import compute as C
from app.ksc import guard
from app.eol.service import EolService
from app.eol.sync import apply_products
from app.models import CatalogProduct, CatalogState, EolFinding, EolHost, EolMapping, EolState, KscSource, utcnow
from tests.conftest import login

DOC = json.loads((Path(__file__).parent / "fixtures" / "eol_sample.json").read_text(encoding="utf-8"))
TODAY = date(2026, 10, 26)


class FakeKsc:
    """Отвечает на два запроса EOL: записи реестра → устройства и страницы компьютеров."""
    def __init__(self, apps: dict[int, list[tuple[int, int]]], hosts: list[dict], pkgs: dict[int, list[tuple[str, str]]] | None = None):
        self.apps, self.hosts, self.pkgs, self.queries = apps, hosts, pkgs or {}, []

    async def run(self, sql, params=None, *, max_rows=0):
        self.queries.append(sql)
        if "base-files" in sql:                                          # пакеты дистрибутива Linux
            ids = {int(x) for x in sql.split("i.nHostId IN (")[1].split(")")[0].split(",")}
            return [{"host_id": h, "name": n, "version": v} for h, lst in self.pkgs.items() if h in ids for n, v in lst]
        if "hst_inventory_hstprds" in sql:
            ids = {int(x) for x in sql.split("IN (")[1].split(")")[0].split(",")}
            return [{"host_id": h, "product_id": p, "active": a} for p, lst in self.apps.items() if p in ids for h, a in lst]
        after = int(params["after"])
        return [h for h in self.hosts if h["host_id"] > after][: int(params["n"])]


def cat(sid, key, name, pub, versions):
    return CatalogProduct(source_id=sid, key=key, name=name, publisher=pub, publisher_key=pub.lower(), origin="auto", component=False, platforms=1, names=[[name, 5]],
                          versions=[{"version": v, "branch": v.split(".")[0], "scheme": "numeric", "platform": 1, "installs": 5, "installs_active": 4, "hosts": 5, "hosts_active": 4, "product_ids": pids, "raw": [v], "names": [name]}
                                    for v, pids in versions],
                          branches=[], versions_count=len(versions), latest_version=versions[0][0], scheme="numeric", hosts_all=5, hosts_active=4, installs_all=5, installs_active=4,
                          search=f"{name} {pub} {key}".lower(), built_at=utcnow())


async def seed(app):
    sm = app.state.session_maker
    await apply_products(sm, DOC["result"])
    sid = uuid.uuid4()
    async with sm() as db:
        db.add(KscSource(id=sid, name="KSC-A", host="a.example.local", port=1433, database="KAV", username="u", password_enc="x", is_active=True))
        await db.flush()
        db.add(CatalogState(source_id=sid, status="ready", built_at=utcnow(), activity_days=30))
        db.add(cat(sid, "php", "PHP", "The PHP Group", [("7.4.16", [11, 12]), ("8.3.2", [13])]))
        db.add(cat(sid, "mystery", "Mystery Tool", "Nobody", [("9.9", [21])]))
        await db.commit()
    return sid


def hosts():
    return [{"host_id": 1, "os_name": "Microsoft Windows Server 2012 R2 Standard", "os_major": 6, "os_minor": 3, "os_build": 9600, "active": 1},
            {"host_id": 2, "os_name": "Microsoft Windows Server 2012 R2 Standard", "os_major": 6, "os_minor": 3, "os_build": 9600, "active": 0},
            {"host_id": 3, "os_name": "Ubuntu 22.04.3 LTS", "os_major": 5, "os_minor": 15, "os_build": 0, "active": 1},
            {"host_id": 4, "os_name": "Linux", "os_major": 5, "os_minor": 10, "os_build": 0, "active": 1}]


async def test_findings_hosts_and_unknowns(app):
    sid = await seed(app)
    sm = app.state.session_maker
    ksc = FakeKsc({11: [(1, 1), (2, 0)], 12: [(2, 0), (5, 1)], 13: [(1, 1)]}, hosts())
    async with sm() as db:
        src = await db.get(KscSource, sid)
    res = await C.compute_source(sm, ksc, src, activity_days=30, today=TODAY)
    async with sm() as db:
        f = {(x.kind, x.subject, x.version): x for x in (await db.execute(select(EolFinding))).scalars()}
        links = {(h.kind, h.subject, h.version): h.host_id for h in (await db.execute(select(EolHost))).scalars()}
        st = await db.get(EolState, sid)
    php = f[("app", "php", "7.4.16")]
    assert php.status == "eol" and php.severity == "critical" and php.eol_release == "7.4" and php.confirmed
    assert (php.hosts_all, php.hosts_active) == (3, 2)                                  # устройства 1, 2 и 5 (запись 12 — тоже php 7.4.16), активные 1 и 5
    assert ("app", "php", "8.3.2") not in f and ("app", "mystery", "9.9") not in f      # поддерживаемое и неизвестное EOL не присваивается
    ws = f[("os", "Microsoft Windows Server 2012 R2 Standard", "6.3.9600")]
    assert ws.status == "eol" and ws.eol_product == "windows-server" and (ws.hosts_all, ws.hosts_active) == (2, 1)
    lx = f[("os", "Linux", "—")]                                                                        # «Linux» без сведений о дистрибутиве: не скрыто, но и не «поддерживается», и не EOL
    assert lx.status == "undetermined" and lx.severity == "" and not lx.confirmed and "Не удалось определить EOL" in lx.condition and lx.os_key["code"] == "linux_no_info" and lx.hosts_all == 1
    assert not any("Ubuntu" in k[1] for k in f)                                                         # Ubuntu 22.04 поддерживается: в список проблем не попадает
    assert st.items == len(f) and st.inputs and res["links"] == 6 and links and res["diag"]["os_undetermined"] == {"hosts": 1, "reasons": {"linux_no_info": 1}}
    for sql in ksc.queries:                                                             # запросы к KSC проходят защиту «только чтение»
        guard.check(sql)


async def test_mapping_exclude_and_manual_choice_are_kept_on_recompute(app):
    sid = await seed(app)
    sm = app.state.session_maker
    async with sm() as db:
        db.add(EolMapping(catalog_key="php", action="exclude", eol_product=None, note="внутренняя сборка", created_by="admin"))
        db.add(EolMapping(catalog_key="mystery", action="map", eol_product="nginx", note="", created_by="admin"))
        await db.commit()
        src = await db.get(KscSource, sid)
    ksc = FakeKsc({11: [(1, 1)], 21: [(7, 1)]}, [])
    await C.compute_source(sm, ksc, src, activity_days=30, today=TODAY)
    async with sm() as db:
        f = {(x.kind, x.subject): x for x in (await db.execute(select(EolFinding))).scalars()}
    assert ("app", "php") not in f                                                      # исключено решением
    # решение «это nginx» применяется к продукту, но версия 9.9 не соответствует ни одной ветке nginx — EOL не присваивается
    assert ("app", "mystery") not in f


async def test_due_follows_inputs_and_manual_request(app):
    sid = await seed(app)
    sm = app.state.session_maker
    svc = EolService(sm, app.state.settings_svc, app.state.sources)
    assert await svc.due(TODAY) == [sid]
    async with sm() as db:
        src = await db.get(KscSource, sid)
    await C.compute_source(sm, FakeKsc({11: [(1, 1)]}, []), src, activity_days=30, today=TODAY)
    assert await svc.due(TODAY) == []                                                        # данные не менялись
    async with sm() as db:
        p = await db.get(CatalogProduct, (sid, "php"))
        p.built_at = utcnow().replace(year=2030)
        await db.commit()
    assert await svc.due(TODAY) == [sid]                                                     # каталог пересобран
    await C.compute_source(sm, FakeKsc({}, []), src, activity_days=30, today=TODAY)
    assert await svc.due(TODAY) == [] and await svc.request(sid) == 1 and await svc.due(TODAY) == [sid]
    await C.compute_source(sm, FakeKsc({}, []), src, activity_days=30, today=TODAY)
    assert await svc.due(date(2026, 11, 20)) == [sid]                                   # у какой-то ветки (PostgreSQL 14: 12.11.2026) за это время сменился этап


_ = login


async def test_api_summary_infra_hosts_mappings(client, app):
    """Страницы EOL читают готовое: сводка, список, устройства находки, режим «Все источники», права на запись решений."""
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await seed(app)
    sm = app.state.session_maker
    async with sm() as db:
        src = await db.get(KscSource, sid)
    await C.compute_source(sm, FakeKsc({11: [(1, 1), (2, 0)], 12: [(5, 1)]}, hosts()), src, activity_days=30, today=TODAY)
    h = {"X-Source-Id": str(sid)}
    s = (await client.get("/api/v1/eol/summary", headers=h)).json()
    assert s["findings"]["eol"] == 2 and s["devices"]["eol"] == 2 and s["kinds"] == {"app": 1, "os": 1}      # PHP: устройства 1, 2, 5; Windows Server 2012 R2: 1, 2; активны (связь за период) 1 и 5 — два, без двойного подсчёта
    items = (await client.get("/api/v1/eol/infra", headers=h)).json()
    assert items["total"] == 3 and {i["kind"] for i in items["items"]} == {"app", "os"} and items["by_status"]["eol"] == 2 and items["by_status"]["undetermined"] == 1      # «Linux» без сведений о дистрибутиве — в списке ОС с причиной
    php = next(i for i in items["items"] if i["kind"] == "app")
    assert php["severity_ru"] == "Критическая" and php["source"] == "KSC-A" and php["hosts_active"] == 2 and php["eol_label"]
    assert (await client.get("/api/v1/eol/infra", headers={"X-Source-Id": "all"})).json()["total"] == 3           # «Все источники»: те же данные, у записи указан источник
    assert (await client.get("/api/v1/eol/infra", params={"q": "ph*", "status": "eol"}, headers=h)).json()["total"] == 1
    assert (await client.get("/api/v1/eol/infra", params={"kind": "os", "severity": "high"}, headers=h)).json()["total"] == 0
    hs = (await client.get("/api/v1/eol/infra/hosts", params={"source_id": str(sid), "kind": "app", "subject": "php", "version": "7.4.16", "all_hosts": True}, headers=h)).json()
    assert hs["total"] == 3 and hs["items"][0]["name"] == "#1"                                                # данных зон ещё нет: показываются идентификаторы устройств
    p = (await client.get("/api/v1/eol/products/php", headers=h)).json()
    assert {r["name"]: r["status"] for r in p["releases"]}["7.4"] == "eol" and next(r for r in p["releases"] if r["name"] == "7.4")["installed_hosts"] == 2
    allp = (await client.get("/api/v1/eol/products", params={"state": "installed"}, headers=h)).json()
    assert {i["name"] for i in allp["items"]} == {"php", "windows-server"}
    m = await client.post("/api/v1/eol/mappings", json={"catalog_key": "mystery", "eol_product": "nginx", "action": "map"})
    assert m.status_code == 201 and len((await client.get("/api/v1/eol/mappings")).json()["items"]) == 1
    assert (await client.post("/api/v1/eol/mappings", json={"catalog_key": "x", "eol_product": "no-such", "action": "map"})).status_code == 422
    assert (await client.post("/api/v1/eol/recalc", headers=h)).status_code == 202
    await client.post("/api/v1/auth/logout")
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.post("/api/v1/eol/mappings", json={"catalog_key": "mystery", "action": "exclude"})).status_code == 403


async def test_zone_counters_and_zone_filter_have_no_double_counting(client, app):
    from app.models import ZcHost, ZcHostZone, ZcSource

    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await seed(app)
    sm = app.state.session_maker
    async with sm() as db:
        src = await db.get(KscSource, sid)
        db.add(ZcSource(source_id=sid, gen=1, status="ready"))
        for hid, active, zone in ((1, True, "z1"), (2, True, "z1"), (3, True, "z2"), (5, False, "z1")):
            db.add(ZcHost(source_id=sid, host_id=hid, gen=1, name=f"srv-{hid}", active=active, os="Windows", data={"ip": f"192.0.2.{hid}", "zones": [zone]}))
            db.add(ZcHostZone(source_id=sid, host_id=hid, gen=1, zone_id=zone))
        await db.commit()
    await C.compute_source(sm, FakeKsc({11: [(1, 1), (2, 1)], 12: [(5, 0)]}, hosts()), src, activity_days=30, today=TODAY)
    async with sm() as db:
        from app.eol import read as R

        z = await R.zone_counts(db, [sid])
    assert z["z1"]["hosts"] == 2 and z["z1"]["eol"] == 2 and z["z1"]["items"] == 4 and z["z1"]["os"] == 2          # устройства 1 и 2: у каждого PHP и Windows Server — устройство считается один раз; неактивное 5 не считается
    assert "z2" not in z
    h = {"X-Source-Id": str(sid)}
    r = (await client.get("/api/v1/eol/infra", params={"zone": "z1"}, headers=h)).json()
    assert {i["kind"]: i["hosts_active"] for i in r["items"]} == {"app": 2, "os": 2}
    assert (await client.get("/api/v1/eol/infra", params={"zone": "z2"}, headers=h)).json()["total"] == 0
    hs = (await client.get("/api/v1/eol/infra/hosts", params={"source_id": str(sid), "kind": "app", "subject": "php", "version": "7.4.16", "zone": "z1"}, headers=h)).json()
    assert [i["name"] for i in hs["items"]] == ["srv-1", "srv-2"] and hs["items"][0]["ip"] == "192.0.2.1"
    assert (await client.get("/api/v1/eol/summary", params={"zone": "z1"}, headers=h)).json()["devices"]["eol"] >= 1


async def test_quick_eol_report_previews_and_exports_full_device_list(client, app):
    from app.models import ZcHost, ZcSource

    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await seed(app)
    sm = app.state.session_maker
    async with sm() as db:
        src = await db.get(KscSource, sid)
        db.add(ZcSource(source_id=sid, gen=1, status="ready"))
        for hid in (1, 2, 5):
            db.add(ZcHost(source_id=sid, host_id=hid, gen=1, name=f"srv-{hid}", active=True, os="Windows", data={"ip": f"192.0.2.{hid}", "zones": ["z1"], "group": "Серверы"}))
        await db.commit()
    await C.compute_source(sm, FakeKsc({11: [(1, 1), (2, 1)], 12: [(5, 1)]}, hosts()), src, activity_days=30, today=TODAY)
    r = (await client.post("/api/v1/quick/preview", json={"kind": "quick_eol", "params": {"statuses": ["eol"]}, "source_ids": [str(sid)]}, headers={"X-Source-Id": str(sid)})).json()
    r0 = r
    assert r["total"] == 2 and {m["key"]: m["value"] for m in r["doc"]["metrics"]}["hosts"] == 3
    assert {t["id"]: t["n"] for t in r["doc"]["tables"]} == {"rows": 2, "devices": 5}                     # PHP: 1, 2, 5; Windows Server: 1, 2 — устройство × проблема, без сокращений
    r = (await client.post("/api/v1/quick/preview", json={"kind": "quick_eol", "params": {"kinds": ["os"], "devices": False}}, headers={"X-Source-Id": str(sid)})).json()
    assert r["total"] == 1 and r["items"][0]["title"].startswith("Microsoft Windows Server 2012") and r["items"][0]["eol_from"]
    lv = {x["key"]: x["value"] for x in r0["doc"]["severity"]["levels"]}
    assert sum(lv.values()) == 3 and lv["critical"] == 3                                                       # у устройства — наивысшая критичность: сумма уровней равна числу устройств
    bad = await client.post("/api/v1/quick/preview", json={"kind": "quick_eol", "params": {"statuses": ["bogus"]}}, headers={"X-Source-Id": str(sid)})
    assert bad.status_code == 422


async def test_failed_recalculation_keeps_previous_results_and_reports_the_error(app):
    from app.models import EolState

    sid = await seed(app)
    sm = app.state.session_maker
    async with sm() as db:
        src = await db.get(KscSource, sid)
    await C.compute_source(sm, FakeKsc({11: [(1, 1)]}, hosts()), src, activity_days=30, today=TODAY)

    class Down:
        def client(self, _src):
            class Dead:
                async def run(self, *a, **k):
                    raise ConnectionError("KSC недоступен")
            return Dead()

    svc = EolService(sm, app.state.settings_svc, Down())
    await svc.request(sid)
    assert await svc.run_source(sid) is None
    async with sm() as db:
        st = await db.get(EolState, sid)
        n = len((await db.execute(select(EolFinding).where(EolFinding.source_id == sid))).scalars().all())
    assert st.error and "Предыдущие результаты сохранены" in st.error and "KSC недоступен" not in st.error and "KSC недоступен" in (st.error_detail or "") and st.error_at and st.attempt_at and n == 3                  # прежние результаты на месте, причина записана
    assert await svc.due(TODAY) == []                                                              # повтор не сразу: пауза после ошибки не даёт долбить недоступный KSC


async def test_quick_eol_refuses_oversized_device_table_with_guidance(app):
    import pytest

    from app.ksc.driver import KscError
    from app.reports import quick

    sid = await seed(app)
    sm = app.state.session_maker
    async with sm() as db:
        src = await db.get(KscSource, sid)
    await C.compute_source(sm, FakeKsc({11: [(1, 1), (2, 1)], 12: [(5, 1)]}, hosts()), src, activity_days=30, today=TODAY)
    ctx = quick.Ctx(source_name="KSC-A", activity_days=30, sm=sm, source_id=sid, source_ids=[sid], max_rows=2)
    with pytest.raises(KscError) as e:
        await quick.build("quick_eol", None, {"statuses": ["eol"]}, ctx)       # type: ignore[arg-type]
    assert e.value.code == "too_many_rows" and "таблицу устройств" in e.value.message
    doc = await quick.build("quick_eol", None, {"statuses": ["eol"], "devices": False}, ctx)         # type: ignore[arg-type]
    assert doc["tables"][1]["rows"] == [] and len(doc["tables"][0]["rows"]) == 2                      # без таблицы устройств отчёт строится


async def test_same_version_under_two_schemes_does_not_duplicate_findings(app):
    """Регрессия UniqueViolation в eol_findings: каталог хранит версию отдельно по схемам (Windows — numeric, Linux — dpkg), и одна и та же версия приходит дважды;
    находка одна на (источник, продукт, версия), записи реестра и устройства объединяются; повторные расчёты дают тот же результат."""
    sid = await seed(app)
    sm = app.state.session_maker
    async with sm() as db:
        p = await db.get(CatalogProduct, (sid, "php"))
        dup = dict(p.versions[0], scheme="dpkg", platform=2, product_ids=[14], installs=2, installs_active=1, hosts=2, hosts_active=1)
        long_a, long_b = "7.4." + "1" * 130 + "a", "7.4." + "1" * 130 + "b"             # различаются только после 120 символов: обрезка не должна создавать дубль
        p.versions = [*p.versions, dup, dict(p.versions[0], version=long_a, product_ids=[15]), dict(p.versions[0], version=long_b, product_ids=[16])]
        await db.commit()
        src = await db.get(KscSource, sid)
    ksc = FakeKsc({11: [(1, 1)], 14: [(3, 1)], 15: [(4, 1)], 16: [(1, 0)]}, hosts())
    for _ in range(2):
        res = await C.compute_source(sm, ksc, src, activity_days=30, today=TODAY)
        async with sm() as db:
            rows = [x for x in (await db.execute(select(EolFinding).where(EolFinding.kind == "app", EolFinding.subject == "php"))).scalars()]
        by = {x.version: x for x in rows}
        assert len(rows) == len(by) == 2 and by["7.4.16"].hosts_all == 2             # записи 11 и 14 — одна находка (устройства 1 и 3); длинные версии с общим началом — тоже одна
        assert set(by["7.4.16"].product_ids) >= {11, 12, 14}
    assert res["items"] >= 2


async def test_calculation_states_waiting_running_error_stale_ready(client, app):
    """Состояния расчёта: «Ожидает запуска» не выдаётся за ноль находок; «Выполняется» — только при живой аренде (след упавшего процесса не в счёт); ошибка прежней версии — в истории, а не текущая причина."""
    from datetime import timedelta

    from sqlalchemy import update

    from app.models import JobLease
    from app.services.jobs import JOBS

    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await seed(app)
    sm = app.state.session_maker
    h = {"X-Source-Id": str(sid)}
    ver = app.state.settings.app_version

    async def state():
        return (await client.get("/api/v1/eol/summary", headers=h)).json()["sources"][str(sid)]

    assert (await state())["state"] == "waiting"
    async with sm() as db:
        src = await db.get(KscSource, sid)
    await C.compute_source(sm, FakeKsc({11: [(1, 1)]}, hosts()), src, activity_days=30)       # сегодняшняя дата: API сверяет отпечаток тоже на сегодня
    assert (await state())["state"] == "ready"
    lease = await JOBS.acquire("eol", str(sid), "устройства: программы")
    assert lease is not None and (await state())["state"] == "running"                                  # аренда живая — расчёт идёт
    async with sm() as db:
        await db.execute(update(JobLease).values(lease_until=utcnow() - timedelta(seconds=5)))
        await db.commit()
    assert (await state())["state"] == "ready"                                                           # исполнитель не продлевает аренду — «выполняется» не показывается
    async with sm() as db:
        await db.execute(update(EolState).where(EolState.source_id == sid).values(error="Не удалось рассчитать EOL", error_at=utcnow(), app_version="0.0.0-old"))
        await db.commit()
    s = await state()
    assert s["state"] == "ready" and s["error"] is None                                                  # ошибка прежней версии не показывается как текущая
    async with sm() as db:
        await db.execute(update(EolState).where(EolState.source_id == sid).values(app_version=ver))
        await db.commit()
    s = await state()
    assert s["state"] == "error" and s["error"] and s["retry_at"]                                         # ошибка последней попытки этой версии — текущая
    svc = EolService(sm, app.state.settings_svc, None)
    svc.version = "9.9.9"
    assert await svc.recover() == 1                                                                       # после обновления старая ошибка переносится в историю
    async with sm() as db:
        st = await db.get(EolState, sid)
    assert st.error is None and any(r.status == "error" and "Не удалось рассчитать EOL" in (r.error or "") for r in await JOBS.runs("eol", str(sid), 5))
    async with sm() as db:
        await db.execute(update(EolState).where(EolState.source_id == sid).values(error=None, error_at=None, inputs="old"))
        await db.commit()
    assert (await state())["state"] == "stale"


async def test_not_ready_lists_sources_without_a_successful_calculation(app):
    """Нули EOL в зонах не показываются, пока нет расчёта: источник без успешного расчёта числится в not_ready, после расчёта — нет."""
    from app.eol import read as R

    sid = await seed(app)
    sm = app.state.session_maker
    async with sm() as db:
        assert await R.not_ready(db, [sid]) == ["KSC-A"]
        src = await db.get(KscSource, sid)
    await C.compute_source(sm, FakeKsc({11: [(1, 1)]}, hosts()), src, activity_days=30, today=TODAY)
    async with sm() as db:
        assert await R.not_ready(db, [sid]) == []


async def test_two_concurrent_calculations_of_one_source_do_not_conflict(app):
    """На PostgreSQL два процесса (старый и новый worker при обновлении) могли одновременно заменять результаты одного источника и падали на eol_findings_pkey; замена идёт под блокировкой источника."""
    import asyncio
    import os

    import pytest

    if not os.environ.get("TEST_PG_URL"):
        pytest.skip("нужен PostgreSQL (TEST_PG_URL): в SQLite параллельной записи нет")
    sid = await seed(app)
    sm = app.state.session_maker
    async with sm() as db:
        src = await db.get(KscSource, sid)
    ksc = FakeKsc({11: [(1, 1), (2, 0)], 12: [(5, 1)]}, hosts())
    results = await asyncio.gather(*(C.compute_source(sm, ksc, src, activity_days=30, today=TODAY) for _ in range(4)), return_exceptions=True)
    assert not [r for r in results if isinstance(r, Exception)], results
    async with sm() as db:
        n = len((await db.execute(select(EolFinding).where(EolFinding.source_id == sid))).scalars().all())
    assert n == results[0]["items"] == 3
