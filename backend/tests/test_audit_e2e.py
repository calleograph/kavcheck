"""Сквозная проверка: пользователь выбирает программу и условие → просмотр → отчёт → содержимое отчёта, оператор и число компьютеров.
Синтетическая база KAVTEST (Contoso Agent: версии и компьютеры известны заранее, tests/ksc_synthetic/schema.sql). Без KSC_TEST_HOST пропускается."""
import csv
import io
import uuid

import pytest
from openpyxl import load_workbook

from app.models import ReportJob
from app.reports.runner import Runner, job_dir
from app.services.catalog import CatalogScheduler
from tests.conftest import login
from tests.test_ksc_live import HOST, params

pytestmark = pytest.mark.skipif(not HOST, reason="нет синтетической базы KSC (KSC_TEST_HOST)")

CASES = [  # оператор, значение, мин, макс → ожидаемые компьютеры среди активных за 30 суток
    ("lt", "8.4.15", None, None, {1}), ("le", "8.4.15", None, None, {1, 2, 3}), ("eq", "8.4.15", None, None, {2, 3}), ("ge", "8.4.15", None, None, {2, 3, 4, 6, 7}),
    ("gt", "8.4.15", None, None, {4, 6, 7}), ("range", None, "8.4.15", "8.9", {2, 3, 4, 6, 7}), ("lt", "8.10", None, None, {1, 2, 3, 4, 6, 7}), ("gt", "9", None, None, set()),
]
H = {"Origin": "http://testserver"}


async def _setup(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    p = params()
    r = await client.post("/api/v1/admin/sources", json={"name": "KAVTEST", "host": p.host, "port": p.port, "database": p.database, "username": p.username, "password": p.password,
                                                       "tls_mode": "request", "trust_server_cert": True})
    sid = r.json()["id"]
    await client.post("/api/v1/auth/source", json={"source_id": sid})
    cat = CatalogScheduler(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal)
    await cat.build(uuid.UUID(sid), "тест")
    runner = Runner(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal)
    runner.catalog = cat
    return sid, runner


async def _run(app, runner, job_id: str) -> dict:
    async with app.state.session_maker() as db:
        job = await db.get(ReportJob, uuid.UUID(job_id))
        await runner.run_job(job)


def _item(op, value, vmin, vmax):
    return {"kind": "product", "product_key": "contoso-agent", "product_name": "Contoso Agent", "op": op, "value": value, "min": vmin, "max": vmax}


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c[0]} {c[1] or ''}{c[2] or ''}..{c[3] or ''}")
async def test_preview_report_and_exports_agree(client, app, case):
    op, value, vmin, vmax, hosts = case
    sid, runner = await _setup(client, app)
    items = {"items": [_item(op, value, vmin, vmax)], "include_inactive": False}
    pv = (await client.post("/api/v1/audit/preview", json={"params": items, "source_ids": [sid]})).json()
    created = await client.post("/api/v1/reports", json={"kind": "version_audit", "title": "", "params": items, "source_ids": [sid]})
    assert created.status_code == 201, created.text
    job = created.json()
    assert job["params"]["items"][0]["op"] == op and job["params"]["items"][0]["value"] == value                 # условие сохранено без изменений
    await _run(app, runner, job["id"])
    done = (await client.get(f"/api/v1/reports/{job['id']}")).json()
    assert done["status"] == "done", done
    s = done["summary"]
    expected_condition = {"lt": "ниже", "le": "ниже или равна", "eq": "равна", "ge": "выше или равна", "gt": "выше"}.get(op)
    cond = f"Установленная версия {expected_condition} {value}" if expected_condition else f"Установленная версия от {vmin} до {vmax} включительно"
    assert s["programs"][0]["condition"] == cond and done["params"]["_expect"] == [cond]
    # просмотр и отчёт: одно и то же
    assert pv["summary"]["hosts"] == s["hosts"] == len(hosts) and pv["total"] == s["rows"] and pv["summary"]["programs"][0]["condition"] == cond
    rows = (await client.get(f"/api/v1/reports/{job['id']}/rows", params={"limit": 1000})).json()
    assert {r["host_id"] for r in rows["items"]} == hosts and rows["total"] == s["rows"]
    assert all(r["condition"] == cond for r in rows["items"])
    if not hosts:
        assert "не соответствует ни одна установка" in s["programs"][0]["explain"] and "8.4.14" in s["programs"][0]["explain"]
    # экспорт: CSV и XLSX содержат то же условие и то же число уникальных компьютеров
    csv_text = (await client.get(f"/api/v1/reports/{job['id']}/download/csv")).content.decode("utf-8-sig")
    data = list(csv.reader(io.StringIO(csv_text), delimiter=";"))
    head = data[0]
    assert len(data) - 1 == s["rows"] and ({int(r[head.index("HostId")]) for r in data[1:]} == hosts)
    assert all(r[head.index("Условие проверки")] == cond for r in data[1:])
    wb = load_workbook(job_dir(app.state.settings, uuid.UUID(job["id"])) / "report.xlsx", read_only=True)
    summary = list(wb["Итог"].iter_rows(values_only=True))
    h = next(i for i, r in enumerate(summary) if r[0] == "Программа")                                 # над таблицей может быть шапка организации
    assert summary[h][:3] == ("Программа", "Условие проверки", "Целевая версия") and summary[h + 1][1] == cond and summary[h + 1][3] == len(hosts)
    sheet = list(wb["Компьютеры"].iter_rows(values_only=True))
    assert len(sheet) - 1 == s["rows"] and {r[sheet[0].index("HostId")] for r in sheet[1:]} == hosts


async def test_saved_check_and_rerun_keep_condition(client, app):
    sid, runner = await _setup(client, app)
    body = {"name": "Contoso ниже 8.4.15", "params": {"items": [_item("lt", "8.4.15", None, None)], "include_inactive": False}, "source_ids": [sid]}
    chk = (await client.post("/api/v1/checks", json=body)).json()
    j1 = (await client.post(f"/api/v1/checks/{chk['id']}/run")).json()
    await _run(app, runner, j1["id"])
    j2 = (await client.post(f"/api/v1/reports/{j1['id']}/rerun")).json()
    await _run(app, runner, j2["id"])
    for j in (j1, j2):
        d = (await client.get(f"/api/v1/reports/{j['id']}")).json()
        assert d["status"] == "done" and d["params"]["items"][0]["op"] == "lt" and d["summary"]["hosts"] == 1
        assert d["summary"]["programs"][0]["condition"] == "Установленная версия ниже 8.4.15"


async def test_changed_condition_fails_instead_of_empty_report(client, app):
    """Если условие в задании не совпадает с заданным при создании, отчёт не формируется (а не выдаётся пустым по другому условию)."""
    sid, runner = await _setup(client, app)
    job = (await client.post("/api/v1/reports", json={"kind": "version_audit", "title": "", "params": {"items": [_item("lt", "8.4.15", None, None)]}, "source_ids": [sid]})).json()
    async with app.state.session_maker() as db:
        row = await db.get(ReportJob, uuid.UUID(job["id"]))
        p = dict(row.params)
        p["items"] = [{**p["items"][0], "op": "ge"}]            # подмена оператора между постановкой и выполнением
        row.params = p
        await db.commit()
    await _run(app, runner, job["id"])
    d = (await client.get(f"/api/v1/reports/{job['id']}")).json()
    assert d["status"] == "failed" and "Расхождение условий" in d["error"] and "ниже 8.4.15" in d["error"]


async def test_range_with_swapped_bounds_is_rejected(client, app):
    sid, _runner = await _setup(client, app)
    r = await client.post("/api/v1/audit/preview", json={"params": {"items": [_item("range", None, "8.10", "8.9")]}, "source_ids": [sid]})
    assert r.status_code == 422 and "нижняя граница" in r.text


async def test_filters_activity_online_groups_and_multi_program_dedup(client, app):
    """Активность (30 суток) и «онлайн сейчас» — разные фильтры; несколько программ не удваивают компьютеры; группы и источники."""
    sid, runner = await _setup(client, app)

    async def preview(extra=None, items=None):
        body = {"params": {"items": items or [_item("lt", "8.10", None, None)], "include_inactive": False, **(extra or {})}, "source_ids": [sid]}
        return (await client.post("/api/v1/audit/preview", json=body)).json()

    base = await preview()
    assert base["summary"]["hosts"] == 6 and base["summary"]["hidden_inactive_hosts"] == 1                       # 1, 2, 3, 4, 6, 7 активны; 5 — нет связи 45 сут
    online = await preview({"online_only": True})
    assert online["summary"]["hosts"] == 5 and online["summary"]["hidden_offline_hosts"] == 1 and 7 not in {r["host_id"] for r in online["items"]}   # 7 — подключался 20 суток назад, в сети нет
    assert all(r["online"] is True for r in online["items"]) and {r["host_id"] for r in base["items"] if r["host_id"] == 7 and r["online"] is False}
    both = await preview({"include_inactive": True})
    assert both["summary"]["hosts"] == 7 and both["summary"]["hidden_inactive_hosts"] == 0                         # + компьютер 5 (кластер 9 — не компьютер)
    grp = await preview({"group_contains": "Рабочие"})
    assert {r["host_id"] for r in grp["items"]} <= {6, 7} and grp["summary"]["hosts"] == len({r["host_id"] for r in grp["items"]})
    # две программы: компьютер с обеими считается один раз, а установки — каждая
    two = await preview(items=[_item("lt", "8.10", None, None), {"kind": "pattern", "name_like": "Java%", "product_name": "Java", "op": "any"}])
    contoso, java = {r["host_id"] for r in two["items"] if r["program"] == "Contoso Agent"}, {r["host_id"] for r in two["items"] if r["program"] == "Java"}
    assert contoso & java and two["summary"]["hosts"] == len(contoso | java) < len(contoso) + len(java)
    assert two["summary"]["rows"] == len(two["items"]) == two["total"] and sum(p["installs"] for p in two["summary"]["programs"]) == two["summary"]["rows"]
    assert [p["hosts"] for p in two["summary"]["programs"]] == [len(contoso), len(java)]
