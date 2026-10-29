"""Темы оформления: по умолчанию «Тёмный профессиональный» для всех (и до входа), личный выбор хранится в профиле и важнее темы системы, смена темы системы не перезаписывает выбор."""
from tests.conftest import login


async def test_theme_default_personal_choice_and_system_default(client, app):
    opts = (await client.get("/api/v1/auth/login-options")).json()
    assert opts["default_theme"] == "night"                                                 # страница входа — тёмная тема по умолчанию
    await login(client, "admin", "Admin-Passw0rd-123")
    me = (await client.get("/api/v1/auth/me")).json()
    assert me["theme"] is None and me["default_theme"] == "night"                            # существующий пользователь без выбора — тема по умолчанию
    assert (await client.put("/api/v1/auth/me/theme", json={"theme": "glass"})).status_code == 200
    assert (await client.put("/api/v1/auth/me/theme", json={"theme": "pink"})).status_code == 422
    r = await client.put("/api/v1/admin/settings/appearance", json={"default_theme": "grove"})
    assert r.status_code == 200, r.text
    me = (await client.get("/api/v1/auth/me")).json()
    assert me["theme"] == "glass" and me["default_theme"] == "grove"                         # личный выбор важнее и не перезаписан
    await client.post("/api/v1/auth/logout")
    assert (await client.get("/api/v1/auth/login-options")).json()["default_theme"] == "grove"
    await login(client, "admin", "Admin-Passw0rd-123")
    assert (await client.get("/api/v1/auth/me")).json()["theme"] == "glass"                 # выбор сохраняется после выхода и входа (и на других устройствах — он в профиле)
    await client.put("/api/v1/auth/me/theme", json={"theme": None})
    assert (await client.get("/api/v1/auth/me")).json()["theme"] is None
    await client.post("/api/v1/auth/logout")
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.put("/api/v1/auth/me/theme", json={"theme": "aurora"})).status_code == 200          # тему выбирает любой пользователь
    assert (await client.put("/api/v1/admin/settings/appearance", json={"default_theme": "night"})).status_code == 403
