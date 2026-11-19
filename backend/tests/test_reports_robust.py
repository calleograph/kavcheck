"""Конструктор отчётов: null в необязательных параметрах, двойная отправка, очередь и повтор при временном сбое источника."""
import uuid

from app.models import ReportJob
from app.reports.runner import Runner
from tests.conftest import login

ITEMS = [{"kind": "pattern", "name_like": "Telegram*", "op": "lt", "value": "7.3.3"}]


async def _src(client):
    r = await client.post("/api/v1/admin/sources", json={"name": "kav02", "host": "b.example.local", "database": "KAV", "username": "u", "password": "p"})
    sid = r.json()["id"]
    await client.post("/api/v1/auth/source", json={"source_id": sid})
    return sid


async def test_version_check_without_zone_is_accepted_with_null_zone(client):
    """Регрессия: params.zone = null (зона не выбрана) приводил к «Input should be a valid string»; проверка идёт без ограничения по зоне."""
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await _src(client)
    r = await client.post("/api/v1/reports", json={"kind": "version_audit", "title": "", "source_ids": [sid], "params": {"items": ITEMS, "zone": None, "group_contains": None, "active_days": None, "online_only": None}})
    assert r.status_code == 201, r.text
    assert (r.json()["params"].get("zone") or "") == ""
    pv = await client.post("/api/v1/audit/preview", json={"params": {"items": ITEMS, "zone": None}, "source_ids": [sid]})
    assert pv.status_code != 422, pv.text


async def test_readable_error_for_wrong_parameters(client):
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await _src(client)
    r = await client.post("/api/v1/reports", json={"kind": "version_audit", "title": "", "source_ids": [sid], "params": {"items": [{"kind": "pattern", "op": "lt", "value": "1"}]}})
    assert r.status_code == 422 and "Укажите шаблон названия" in r.text and "Input should" not in r.text


async def test_double_submit_does_not_create_a_second_job(client):
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await _src(client)
    body = {"kind": "version_audit", "title": "", "source_ids": [sid], "params": {"items": ITEMS}}
    a, b = await client.post("/api/v1/reports", json=body), await client.post("/api/v1/reports", json=body)
    assert a.json()["id"] == b.json()["id"]
    other = await client.post("/api/v1/reports", json={**body, "params": {"items": [{**ITEMS[0], "value": "8"}]}})
    assert other.json()["id"] != a.json()["id"]                                          # другие условия — другой отчёт


async def test_transient_source_failure_is_retried_then_succeeds(client, app, monkeypatch):
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await _src(client)
    job = (await client.post("/api/v1/reports", json={"kind": "version_audit", "title": "", "source_ids": [sid], "params": {"items": ITEMS}})).json()
    runner = Runner(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal)
    monkeypatch.setattr(Runner, "RETRY_DELAYS", (0, 0))
    calls = []

    async def fake(self, j):
        calls.append(1)
        status, err = ("failed", "Не удалось подключиться: недоступен") if len(calls) < 3 else ("done", None)
        await self._set(j.id, status=status, error=err)

    monkeypatch.setattr(Runner, "_execute", fake)
    async with app.state.session_maker() as db:
        await runner.run_job(await db.get(ReportJob, uuid.UUID(job["id"])))
    assert len(calls) == 3
    assert (await client.get(f"/api/v1/reports/{job['id']}")).json()["status"] == "done"


async def test_permanent_error_is_not_retried(client, app, monkeypatch):
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await _src(client)
    job = (await client.post("/api/v1/reports", json={"kind": "version_audit", "title": "", "source_ids": [sid], "params": {"items": ITEMS}})).json()
    runner = Runner(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal)
    monkeypatch.setattr(Runner, "RETRY_DELAYS", (0, 0))
    calls = []

    async def fake(self, j):
        calls.append(1)
        await self._set(j.id, status="failed", error="Условие проверки неверно")

    monkeypatch.setattr(Runner, "_execute", fake)
    async with app.state.session_maker() as db:
        await runner.run_job(await db.get(ReportJob, uuid.UUID(job["id"])))
    assert len(calls) == 1


async def test_report_waiting_for_a_slot_is_not_requeued_and_cancel_wins(client, app, monkeypatch):
    """Задание ждёт места у ограничителя (status=running, аренды нет): сторож не возвращает его в очередь; отменённое до запуска не выполняется и не получает «готово»."""
    from app.services.jobs import JOBS  # noqa: PLC0415

    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await _src(client)
    job = (await client.post("/api/v1/reports", json={"kind": "version_audit", "title": "", "source_ids": [sid], "params": {"items": ITEMS}})).json()
    runner = Runner(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal)
    async with app.state.session_maker() as db:
        (await db.get(ReportJob, uuid.UUID(job["id"]))).status = "running"
        await db.commit()
    JOBS.waiting[("report", job["id"])] = {"since": None, "stage": "запуск", "lane": "interactive", "task": "t"}
    try:
        assert await runner.recover_orphans() == 0
    finally:
        JOBS.waiting.pop(("report", job["id"]), None)
    async with app.state.session_maker() as db:
        (await db.get(ReportJob, uuid.UUID(job["id"]))).status = "cancelled"
        await db.commit()
    calls = []

    async def fake(self, j):
        calls.append(1)
        await self._set(j.id, status="done")

    monkeypatch.setattr(Runner, "_execute", fake)
    async with app.state.session_maker() as db:
        await runner.run_job(await db.get(ReportJob, uuid.UUID(job["id"])))
    assert calls == [] and (await client.get(f"/api/v1/reports/{job['id']}")).json()["status"] == "cancelled"
    await runner._set(uuid.UUID(job["id"]), status="done")                                   # итог выполнения не затирает отмену
    assert (await client.get(f"/api/v1/reports/{job['id']}")).json()["status"] == "cancelled"
