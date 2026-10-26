from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from .config import Settings


def create_engine(settings: Settings, *, background: bool = False) -> AsyncEngine:
    """Подключение к внутренней базе. Страницы: запрос не дольше 2 минут — дольше значит ошибку в запросе, а не «медленную страницу». Фоновая служба (worker): расчёты зон, EOL и баз уязвимостей —
    законные длинные запросы (до 30 минут), но блокировки ждут не дольше минуты, а транзакция, зависшая «в простое», закрывается (страницы — через 5 минут, worker — через 15) и не держит блокировки и память."""
    url = settings.sqlalchemy_url
    if str(url).startswith("sqlite"):
        return create_async_engine(url)
    server = {"application_name": "kavcheck-worker" if background else "kavcheck", "statement_timeout": "1800000" if background else "120000", "lock_timeout": "60000",
              "idle_in_transaction_session_timeout": "900000" if background else "300000"}
    return create_async_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=10, pool_timeout=15, pool_recycle=1800, connect_args={"server_settings": server})


def create_session_maker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def xact_lock(db: AsyncSession, name: str) -> None:
    """Блокировка до конца транзакции по имени (PostgreSQL): два процесса не заменяют результаты одного источника одновременно — второй ждёт первого и пишет поверх готового. В SQLite (тесты) не нужна."""
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        from sqlalchemy import text  # noqa: PLC0415

        await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:n, 0))"), {"n": name})
