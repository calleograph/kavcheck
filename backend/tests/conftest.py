"""Тестовое приложение на SQLite (aiosqlite): схема создаётся из моделей, секреты — тестовый ключ. Базы KSC подменяются."""
from __future__ import annotations

import base64
import os
import tempfile

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.main import create_app
from app.models import Base
from app.services import local_admin as la

MASTER_KEY = base64.b64encode(b"0" * 32).decode()


@pytest_asyncio.fixture
async def app():
    tmp = tempfile.mkdtemp()
    settings = Settings(database_url=f"sqlite+aiosqlite:///{tmp}/test.db", app_master_key=MASTER_KEY, cookie_secure="false", app_public_url="http://testserver", data_dir=tmp)
    application = create_app(settings, start_workers=False)
    from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415

    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()
    async with application.router.lifespan_context(application):
        async with application.state.session_maker() as db:
            await la.create_local(db, "admin", "Admin-Passw0rd-123", role="admin", must_change=False)
            await la.create_local(db, "viewer", "Viewer-Passw0rd-123", role="viewer", must_change=False)
            await db.commit()
        yield application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


async def login(client: AsyncClient, username: str, password: str) -> dict:
    r = await client.post("/api/v1/auth/login", json={"login": username, "password": password}, headers={"Origin": "http://testserver"})
    assert r.status_code == 200, r.text
    data = r.json()
    client.headers["X-CSRF-Token"] = data["csrf_token"]
    client.headers["Origin"] = "http://testserver"
    return data


_ = os
