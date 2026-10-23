"""Alembic: асинхронное окружение. URL внутренней базы — из настроек приложения (POSTGRES_* / DATABASE_URL)
либо из sqlalchemy.url, заданного программно (тесты). Миграции относятся ТОЛЬКО к внутренней базе KAV Checker: базы KSC не затрагиваются."""
from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from app.config import Settings
from app.models import Base

config = context.config
target_metadata = Base.metadata


def _url():
    explicit = config.get_main_option("sqlalchemy.url")
    url = explicit if explicit else Settings().sqlalchemy_url
    # str(URL) маскирует пароль («***»): для подключения нужна полная строка
    return url if isinstance(url, str) else url.render_as_string(hide_password=False)


def run_migrations_offline() -> None:
    context.configure(url=str(_url()), target_metadata=target_metadata, literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def _do_run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True, render_as_batch=connection.dialect.name == "sqlite")
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_async_engine(_url())
    async with engine.connect() as connection:
        await connection.run_sync(_do_run)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
