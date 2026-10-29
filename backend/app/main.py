"""Фабрика приложения FastAPI."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.datastructures import MutableHeaders

from .api import admin, admin_ldap, bi as bi_api, admin_updates, auth, auth_totp, catalog, dashboard, devices as devices_api, eol as eol_api, events, health, hosts, logs as logs_api, hunt as hunt_api, components as components_api, overview, pentest as pentest_api, protection, quick, reports, software, vdb as vdb_api, vulns, zones as zones_api
from .auth.deps import client_ip
from .search import MaskError
from .auth.service import AuthService
from .auth.sessions import SessionStore
from .config import Settings, get_settings
from .db import create_engine, create_session_maker
from .ksc.grouping import BUILTIN_RULES
from .logging_setup import configure_logging, request_id_var
from .models import GroupingRule
from .reports.runner import Runner
from .security.secretbox import SecretBox, SecretBoxError
from .services.audit import Journal, audit_ctx
from .services.cache import TtlCache
from .services.ldap_store import LdapStore
from .security import totp
from .services.settings import SettingsService
from .services.sources import SourceRegistry

log = logging.getLogger("app")
_RID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class RequestContext:
    """Идентификатор запроса, контекст аудита, заголовки безопасности, строка журнала на каждый запрос API."""

    def __init__(self, app, settings: Settings):
        self.app, self.settings = app, settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        path = scope["path"]
        incoming = request.headers.get("x-request-id", "")
        rid = incoming if _RID_RE.match(incoming) else uuid.uuid4().hex[:16]
        token = request_id_var.set(rid)
        ctx_token = audit_ctx.set({"ip": client_ip(request)})
        started = time.perf_counter()
        status = 0

        async def send_with_headers(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                h = MutableHeaders(scope=message)
                h["X-Request-ID"] = rid
                h.setdefault("X-Content-Type-Options", "nosniff")
                h.setdefault("Referrer-Policy", "same-origin")
                if path.startswith("/api/"):
                    h.setdefault("Cache-Control", "no-store")
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception:
            log.exception("Необработанная ошибка", extra={"path": path, "method": scope["method"]})
            raise
        finally:
            request_id_var.reset(token)
            audit_ctx.reset(ctx_token)
        if path.startswith("/api/") and not path.startswith("/api/v1/health"):
            log.info("http", extra={"method": scope["method"], "path": path, "status": status, "ms": int((time.perf_counter() - started) * 1000)})


async def seed_builtin_rules(session_maker) -> None:
    async with session_maker() as db:
        for b in BUILTIN_RULES:
            if (await db.execute(select(GroupingRule).where(GroupingRule.key == b["key"]))).scalar_one_or_none() is None:
                db.add(GroupingRule(**b, builtin=True, enabled=True))
        await db.commit()


def create_app(settings: Settings | None = None, *, start_workers: bool = True, run_reports: bool = False) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine = create_engine(settings)
        session_maker = create_session_maker(engine)
        from .services.jobs import JOBS  # noqa: PLC0415

        JOBS.configure(session_maker, ttl=settings.job_lease_seconds, version=settings.app_version)       # backend только читает аренды (состояния в интерфейсе); продлевает и захватывает worker
        try:
            box = SecretBox(settings.app_master_key) if settings.app_master_key else None
        except SecretBoxError:
            log.error("APP_MASTER_KEY некорректен — пароли источников и LDAP недоступны")
            box = None
        settings_svc = SettingsService(box)
        app.state.settings, app.state.engine, app.state.session_maker = settings, engine, session_maker
        app.state.settings_svc = settings_svc
        app.state.sessions = SessionStore(settings)
        totp.set_pepper(settings.app_master_key)
        app.state.ldap = LdapStore(settings_svc)
        app.state.auth = AuthService(settings, settings_svc, app.state.ldap)
        app.state.journal = Journal(session_maker)
        app.state.sources = SourceRegistry(settings, settings_svc)
        app.state.runner = Runner(session_maker, settings, settings_svc, app.state.journal)
        app.state.cache = TtlCache()
        tasks: list[asyncio.Task] = []
        from .services.system import install_journal_handler  # noqa: PLC0415

        jh = install_journal_handler("backend")
        try:
            await seed_builtin_rules(session_maker)
            async with session_maker() as db:
                await app.state.ldap.migrate_legacy(db)
            async with session_maker() as db:
                from .vdb.store import ensure_sources  # noqa: PLC0415

                await ensure_sources(db)
                await db.commit()
        except Exception as exc:  # noqa: BLE001 — до миграций таблиц нет
            log.warning("Начальные данные не загружены (%s): при первом запуске до миграций это нормально", type(exc).__name__)

        async def housekeeping():
            while True:
                try:
                    async with session_maker() as db:
                        await app.state.sessions.purge_expired(db)
                except Exception:  # noqa: BLE001
                    log.warning("Очистка сессий не выполнена", exc_info=True)
                await asyncio.sleep(600)

        if start_workers:
            tasks.append(asyncio.create_task(housekeeping(), name="housekeeping"))
            tasks.append(asyncio.create_task(jh.flush_loop(session_maker), name="journal-flush"))
        if run_reports:
            tasks.append(asyncio.create_task(app.state.runner.loop(), name="reports"))
        log.info("Приложение запущено", extra={"version": settings.app_version, "commit": settings.app_git_commit})
        await app.state.journal.emit("system", "app_started", message=f"Версия {settings.app_version}, commit {settings.app_git_commit}")
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()
            for t in tasks:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t
            logging.getLogger().removeHandler(jh)
            await engine.dispose()

    app = FastAPI(title="KAV Checker API", version=settings.app_version, lifespan=lifespan, docs_url="/api/v1/docs" if settings.docs_enabled else None, redoc_url=None,
                  openapi_url="/api/v1/openapi.json" if settings.docs_enabled else None)
    app.add_middleware(RequestContext, settings=settings)

    from sqlalchemy import exc as sa_exc

    @app.exception_handler(sa_exc.DBAPIError)
    async def db_unavailable(request: Request, exc: sa_exc.DBAPIError):
        if not (exc.connection_invalidated or isinstance(exc, (sa_exc.OperationalError, sa_exc.InterfaceError))):
            raise exc
        log.error("Внутренняя база недоступна", extra={"path": request.url.path, "error": type(exc.orig).__name__ if exc.orig else type(exc).__name__})
        return JSONResponse({"detail": "Внутренняя база данных временно недоступна. Повторите через несколько секунд."}, status_code=503, headers={"Retry-After": "5"})

    from fastapi.exceptions import RequestValidationError

    from .validation_text import explain

    @app.exception_handler(RequestValidationError)
    async def bad_request(request: Request, exc: RequestValidationError):
        errors = [{k: v for k, v in e.items() if k != "ctx" and k != "input"} | {"ctx": {a: b for a, b in (e.get("ctx") or {}).items() if isinstance(b, (int, str, float))}} for e in exc.errors()]
        return JSONResponse({"detail": "Проверьте параметры: " + explain(exc.errors()), "errors": errors}, status_code=422)

    @app.exception_handler(MaskError)
    async def bad_mask(request: Request, exc: MaskError):
        return JSONResponse({"detail": str(exc)}, status_code=422)

    prefix = "/api/v1"
    for r in (auth.router, auth_totp.router, admin_ldap.router, software.router, catalog.router, hosts.router, vulns.router, protection.router, events.router, quick.router, reports.router, reports.templates, reports.checks, dashboard.router, overview.router, overview.lic_router, pentest_api.router, admin.router, logs_api.router, components_api.router, hunt_api.router, bi_api.router,
              admin_updates.router, vdb_api.router, eol_api.router, devices_api.router, zones_api.router, zones_api.admin_router, zones_api.mail_router, zones_api.triage_router, health.router):
        app.include_router(r, prefix=prefix)
    return app


def app_factory() -> FastAPI:
    return create_app()
