from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from .config import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    url = settings.sqlalchemy_url
    if str(url).startswith("sqlite"):
        return create_async_engine(url)
    return create_async_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=10, pool_timeout=15, pool_recycle=1800,
                               connect_args={"server_settings": {"application_name": "kavcheck", "statement_timeout": "120000"}})


def create_session_maker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)
