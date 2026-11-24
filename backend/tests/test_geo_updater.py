"""Управление географическими базами из приложения. Сетевые запросы подменяются."""
from datetime import datetime, timezone

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
    assert (await client.put(CONFIG, json={"provider": "maxmind", "enabled": False})).status_code == 200
    assert (await client.post(f"{PATH}/refresh")).status_code == 422
    assert (await client.put(CONFIG, json={"enabled": True, "account_id": "12345"})).status_code == 422
    invalid = await client.put(CONFIG, json={"license_key": f"{KEY} invalid"})
    assert invalid.status_code == 422 and KEY not in invalid.text
    saved = await client.put(CONFIG, json={"enabled": True, "account_id": "12345", "license_key": KEY})
    assert saved.status_code == 200 and saved.json() == {"provider": "maxmind", "enabled": True, "account_id": "12345", "license_key_set": True}
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


async def test_default_dbip_starts_without_settings_row_and_keeps_last_pair(client, app, tmp_path, monkeypatch):
    await login(client, "admin", "Admin-Passw0rd-123")
    assert (await client.get(CONFIG)).json() == {"provider": "dbip", "enabled": True, "account_id": "", "license_key_set": False}
    assert (await client.get(PATH)).json()["pending"]
    worker = app.state
    async with worker.session_maker() as db:
        assert await db.get(AppSetting, "geoip") is None

    now = datetime(2026, 11, 24, 10, tzinfo=timezone.utc)
    monkeypatch.setattr(geo_updater, "utcnow", lambda: now)
    root = tmp_path / "dbip"
    active = root / (".geolite2-" + "0" * 32)
    editions = geo_download.DBIP_EDITIONS
    databases = {edition: {"build_epoch": 1793501546} for edition in editions}
    attempts = []

    async def update_dbip(directory, *, guard, now):
        assert directory == root
        attempts.append(now)
        if len(attempts) > 1:
            raise geo_download.DownloadError("DB-IP Lite недоступен")
        async with guard():
            active.mkdir(parents=True)
            for edition in editions:
                (active / f"{edition}.mmdb").touch()
            (root / geo_download.CURRENT).symlink_to(active.name)
        return {"changed": True, "month": "2026-11", "databases": databases}

    monkeypatch.setattr(geo_download, "update_dbip", update_dbip)
    await geo_updater.tick(worker.session_maker, worker.settings_svc, tmp_path, worker.journal)
    status = (await client.get(PATH)).json()
    assert status["active_provider"] == "dbip" and status["databases"] == databases
    assert status["next_check_at"] == "2026-12-01T00:00:00+00:00"
    await geo_updater.tick(worker.session_maker, worker.settings_svc, tmp_path, worker.journal)
    assert len(attempts) == 1

    now = datetime(2026, 12, 1, tzinfo=timezone.utc)
    await geo_updater.tick(worker.session_maker, worker.settings_svc, tmp_path, worker.journal)
    status = (await client.get(PATH)).json()
    assert status["active_provider"] == "dbip" and status["databases"] == databases
    assert status["error"] and status["next_check_at"] == "2026-12-01T06:00:00+00:00"


async def test_legacy_maxmind_selection_and_secret_are_preserved(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    svc = app.state.settings_svc
    async with app.state.session_maker() as db:
        encrypted = svc.encrypt(KEY, "geoip.license_key")
        db.add(AppSetting(group="geoip", value={"enabled": True, "account_id": "12345", "license_key_enc": encrypted}))
        await db.commit()
    assert (await client.get(CONFIG)).json() == {"provider": "maxmind", "enabled": True, "account_id": "12345", "license_key_set": True}
    switched = await client.put(CONFIG, json={"provider": "dbip"})
    assert switched.status_code == 200 and switched.json()["provider"] == "dbip" and switched.json()["license_key_set"]
    async with app.state.session_maker() as db:
        assert (await db.get(AppSetting, "geoip")).value["license_key_enc"] == encrypted
