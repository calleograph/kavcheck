"""Обмен с помощником обновлений: прерванное действие не показывается как «Выполняется», устаревший помощник, скачивание журнала для диагностики, запрос локальной сборки."""
import json
import time

import pytest
from pathlib import Path

from app.services.updates import Channel
from tests.conftest import login


def put(d: Path, name: str, data) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")


def status(**kw) -> dict:
    return {"ts": time.time(), "pid": 1, "updater_api": 3, "state": "idle", "action": "", "step_no": 0, "step_total": 11, "step_name": "", "started_at": 0, "finished_at": 0, "last_output_at": 0, **kw}


def test_stale_busy_status_is_interrupted_not_running(tmp_path):
    put(tmp_path, "status.json", status(ts=time.time() - 600, state="updating", action="update", step_no=7))
    st = Channel(str(tmp_path)).status()
    assert st["available"] is False and st["interrupted"] is True and st["state"] == "interrupted" and st["result"] == "failed"


def test_live_helper_is_available_and_old_helper_is_flagged(tmp_path):
    put(tmp_path, "status.json", status(updater_api=1))
    st = Channel(str(tmp_path)).status()
    assert st["available"] and st["api_outdated"] and not st["interrupted"]


def test_no_progress_warning_after_silence(tmp_path):
    put(tmp_path, "status.json", status(state="updating", action="update", last_output_at=time.time() - 400))
    assert 380 <= Channel(str(tmp_path)).status()["stalled_s"] <= 500
    put(tmp_path, "status.json", status(state="updating", action="update", last_output_at=time.time() - 10))
    assert Channel(str(tmp_path)).status()["stalled_s"] is None


def test_log_download_has_diagnostics_and_masks_secrets(tmp_path):
    put(tmp_path, "status.json", status(action="update", step_no=5, step_name="Образы релиза"))
    put(tmp_path, "report.json", {"result": "failed", "stage": "Образы релиза", "from_version": "0.4.0", "to_version": "0.5.0", "reason_code": "registry", "advice": "Недоступен реестр", "actions": ["образы не получены"]})
    put(tmp_path, "update.log", "\x1b[36m•\x1b[0m запуск\nNPM_REGISTRY=https://user:s3cret@mirror.example.net/npm\npassword=hunter2\nError: i/o timeout\n")
    text = Channel(str(tmp_path)).download_text()
    assert "причина: registry" in text and "Недоступен реестр" in text and "Error: i/o timeout" in text and "образы не получены" in text
    assert "s3cret" not in text and "hunter2" not in text and "\x1b[" not in text and "mirror.example.net" in text


async def test_download_endpoint_audit_and_permissions(app, client):
    d = Path(app.state.settings.data_dir) / "updater"
    put(d, "status.json", status())
    put(d, "update.log", "строка журнала\n")
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get("/api/v1/admin/updates/log/download")).status_code == 403
    await login(client, "admin", "Admin-Passw0rd-123")
    r = await client.get("/api/v1/admin/updates/log/download")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"] and "строка журнала" in r.text and r.headers["content-type"].startswith("text/plain")
    audit = (await client.get("/api/v1/admin/audit", params={"q": "update_log"})).json()
    assert audit["total"] == 1


async def test_local_build_needs_separate_confirmation_and_is_passed_to_helper(app, client):
    d = Path(app.state.settings.data_dir) / "updater"
    put(d, "status.json", status())
    await login(client, "admin", "Admin-Passw0rd-123")
    assert (await client.post("/api/v1/admin/updates/run", json={"confirm": True, "mode": "build"})).status_code == 422
    assert (await client.post("/api/v1/admin/updates/run", json={"confirm": True, "mode": "weird"})).status_code == 422
    r = await client.post("/api/v1/admin/updates/run", json={"confirm": True, "mode": "build", "confirm_build": True, "target": "v0.5.0"})
    assert r.status_code == 200
    req = (d / "request.txt").read_text()
    assert "action=update" in req and "mode=build" in req and "target=v0.5.0" in req
    ov = (await client.get("/api/v1/admin/updates")).json()
    assert ov["updater"]["api_expected"] == 3 and ov["can_act"] is False          # запрос уже ожидает выполнения


async def test_overview_shows_interrupted_helper_state(app, client):
    d = Path(app.state.settings.data_dir) / "updater"
    put(d, "status.json", status(ts=time.time() - 900, state="updating", action="update"))
    await login(client, "admin", "Admin-Passw0rd-123")
    ov = (await client.get("/api/v1/admin/updates")).json()
    assert ov["updater"]["state"] == "interrupted" and ov["updater"]["available"] is False and ov["can_act"] is False and len(ov["reasons"]) == 1 and "Пульс помощника" in ov["reasons"][0]


def hb(**kw) -> dict:
    return {"ts": time.time(), "pid": 7, "updater_api": 3, "boot_id": "", "started_at": time.time() - 100, "script_sha": "x", "op_alive": False, "stopped": False, "unit": "kavcheck-updater-demo", **kw}


def test_heartbeat_is_independent_of_operation_progress(tmp_path):
    """Долгая сборка без вывода: операция «выполняется», помощник «доступен» — без противоречий и без предупреждения «не запущен»."""
    put(tmp_path, "heartbeat.json", hb(op_alive=True))
    put(tmp_path, "operation.json", status(ts=time.time() - 900, state="updating", action="update", started_at=time.time() - 600, last_output_at=time.time() - 500))
    st = Channel(str(tmp_path)).status()
    assert st["available"] and not st["interrupted"] and st["state"] == "updating" and st["down_reason"] == "" and st["stalled_s"] >= 400


def test_dead_operation_process_is_interrupted_even_if_helper_is_alive(tmp_path):
    put(tmp_path, "heartbeat.json", hb(op_alive=False))
    put(tmp_path, "operation.json", status(state="updating", action="update", started_at=time.time() - 300))
    st = Channel(str(tmp_path)).status()
    assert st["available"] and st["interrupted"] and st["state"] == "interrupted"


def test_fresh_operation_start_is_not_flagged_before_pid_is_published(tmp_path):
    put(tmp_path, "heartbeat.json", hb(op_alive=False))
    put(tmp_path, "operation.json", status(state="updating", action="update", started_at=time.time() - 3))
    assert not Channel(str(tmp_path)).status()["interrupted"]


@pytest.mark.parametrize("age,extra,expect", [(600, {}, "не обновлялся"), (60, {"stopped": True}, "остановлена"), (90, {"boot_id": "другая-загрузка"}, "перезагружался")])
def test_down_reason_is_specific(tmp_path, age, extra, expect):
    put(tmp_path, "heartbeat.json", hb(ts=time.time() - age, **extra))
    st = Channel(str(tmp_path)).status()
    assert not st["available"] and expect in st["down_reason"]


def test_stopped_flag_makes_helper_unavailable_immediately(tmp_path):
    put(tmp_path, "heartbeat.json", hb(stopped=True))
    assert not Channel(str(tmp_path)).status()["available"]


async def test_overview_gives_one_reason_not_contradictions(app, client):
    d = Path(app.state.settings.data_dir) / "updater"
    put(d, "heartbeat.json", hb(op_alive=True))
    put(d, "operation.json", status(state="updating", action="update", started_at=time.time() - 60, last_output_at=time.time() - 5))
    await login(client, "admin", "Admin-Passw0rd-123")
    ov = (await client.get("/api/v1/admin/updates")).json()
    assert ov["updater"]["available"] and ov["updater"]["state"] == "updating" and ov["can_act"] is False and len(ov["reasons"]) == 1 and "выполняется" in ov["reasons"][0]
