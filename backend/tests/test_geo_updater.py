"""Управление GeoLite2 из приложения. Сетевые запросы провайдера подменяются."""
from sqlalchemy import select

from app.inventory import geo_download, geo_updater
from app.inventory.geo_service import REQUEST
from app.models import AppSetting
from tests.conftest import login


PATH = "/api/v1/inv/geography/geoip"
CONFIG = "/api/v1/admin/settings/geoip"
KEY = "Synthetic_Not_A_Real_Key"


async def test_geoip_configuration_initial_update_and_failed_refresh_keep_previous(client, app, tmp_path, monkeypatch):
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get(PATH)).status_code == 403
    assert (await client.post(f"{PATH}/refresh")).status_code == 403
    assert (await client.put(CONFIG, json={"license_key": KEY})).status_code == 403

    await login(client, "admin", "Admin-Passw0rd-123")
    assert (await client.post(f"{PATH}/refresh")).status_code == 422
    assert (await client.put(CONFIG, json={"enabled": True, "account_id": "12345"})).status_code == 422
    invalid = await client.put(CONFIG, json={"license_key": f"{KEY} invalid"})
    assert invalid.status_code == 422 and KEY not in invalid.text
    saved = await client.put(CONFIG, json={"enabled": True, "account_id": "12345", "license_key": KEY})
    assert saved.status_code == 200 and saved.json() == {"enabled": True, "account_id": "12345", "license_key_set": True}
    assert KEY not in (await client.get(CONFIG)).text
    assert (await client.get(PATH)).json()["pending"] is True

    async with app.state.session_maker() as db:
        row = await db.scalar(select(AppSetting).where(AppSetting.group == "geoip"))
        assert "license_key" not in row.value and KEY not in str(row.value)
        assert (await app.state.settings_svc.get(db, "geoip")).license_key == KEY

    calls = []
    databases = {"GeoLite2-City": {"build_epoch": 1760000000}, "GeoLite2-ASN": {"build_epoch": 1760000000}}

    async def update(directory, account_id, license_key, *, guard):
        assert directory == tmp_path and (account_id, license_key) == ("12345", KEY)
        calls.append(None)
        if len(calls) > 1:
            raise geo_download.DownloadError("MaxMind недоступен")
        async with guard():
            return {"changed": True, "databases": databases}

    monkeypatch.setattr(geo_download, "update", update)
    # Подменяем опубликованное поколение, так как здесь проверяется расписание и связь с БД.
    active = tmp_path / ".fixture"
    active.mkdir()
    for edition in databases:
        (active / f"{edition}.mmdb").touch()
    monkeypatch.setattr(geo_download, "database_directory", lambda d, managed: active)
    worker = app.state
    await geo_updater.tick(worker.session_maker, worker.settings_svc, tmp_path, worker.journal)
    status = (await client.get(PATH)).json()
    assert status["databases"] == databases and status["success_at"] and not status["pending"]
    async with worker.session_maker() as db:
        marker = (await db.get(AppSetting, REQUEST)).value
    await geo_updater.tick(worker.session_maker, worker.settings_svc, tmp_path, worker.journal)
    assert len(calls) == 1

    queued = await client.post(f"{PATH}/refresh")
    assert queued.status_code == 202 and queued.json()["pending"]
    assert (await client.post(f"{PATH}/refresh")).json()["pending"]
    await geo_updater.tick(worker.session_maker, worker.settings_svc, tmp_path, worker.journal)
    failed = (await client.get(PATH)).json()
    assert failed["error"] == "MaxMind недоступен" and failed["databases"] == databases
    assert failed["success_at"] == status["success_at"] and not failed["pending"] and KEY not in str(failed)
    async with worker.session_maker() as db:
        assert (await db.get(AppSetting, REQUEST)).value == marker

    assert (await client.put(CONFIG, json={"enabled": False})).json()["license_key_set"]
    await geo_updater.tick(worker.session_maker, worker.settings_svc, tmp_path, worker.journal)
    assert len(calls) == 2

    async def superseded(_directory, _account_id, _key, *, guard):
        assert (await client.put(CONFIG, json={"account_id": "54321"})).status_code == 200
        async with guard():
            raise AssertionError("Изменённая конфигурация разрешила переключить файлы")

    monkeypatch.setattr(geo_download, "update", superseded)
    assert (await client.post(f"{PATH}/refresh")).json()["pending"]
    await geo_updater.tick(worker.session_maker, worker.settings_svc, tmp_path, worker.journal)
    stopped = (await client.get(PATH)).json()
    assert "Настройки GeoLite2 изменились" in stopped["error"] and stopped["databases"] == databases

    cleared = await client.put(CONFIG, json={"license_key": ""})
    assert not cleared.json()["license_key_set"]
