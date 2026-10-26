"""Главная: просроченная сводка показывается сразу, свежая считается в фоне; первая загрузка и «Обновить» считают сразу."""
import asyncio
import uuid
from datetime import timedelta

from app.ksc import dashboard as D
from app.models import KscCache, utcnow
from tests.conftest import login


async def test_stale_summary_is_returned_at_once_and_refreshed_in_background(client, app, monkeypatch):
    await login(client, "admin", "Admin-Passw0rd-123")
    src = (await client.post("/api/v1/admin/sources", json={"name": "KSC-A", "host": "a.example.local", "database": "KAV", "username": "u", "password": "p"})).json()
    await client.post("/api/v1/auth/source", json={"source_id": src["id"]})
    sid = uuid.UUID(src["id"])
    calls = []

    async def summary(client_, *, activity_days, features):
        calls.append(1)
        return {"hosts": 100 + len(calls)}

    monkeypatch.setattr(D, "summary", summary)
    async with app.state.session_maker() as db:
        db.add(KscCache(source_id=sid, key="summary:30", fetched_at=utcnow() - timedelta(hours=3), payload={"hosts": 7}))
        await db.commit()
    r = (await client.get("/api/v1/dashboard")).json()
    assert r["summary"]["hosts"] == 7 and r["error"] is None                      # просроченная сводка — сразу, с временем получения
    for _ in range(50):
        if calls:
            break
        await asyncio.sleep(0.05)
    await asyncio.sleep(0.2)
    assert len(calls) == 1
    r2 = (await client.get("/api/v1/dashboard")).json()
    assert r2["summary"]["hosts"] == 101                                          # фоновое обновление сохранено
    assert (await client.get("/api/v1/dashboard", params={"refresh": True})).json()["summary"]["hosts"] == 102        # «Обновить» считает сразу
