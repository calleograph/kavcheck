from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, client_ip, current_session, get_db, require_user
from ..auth.service import AuthError
from ..config import origin_allowed
from ..models import KscSource, User
from ..security.passwords import verify_password
from ..services import local_admin as la
from ..services.audit import audit_now, write_audit
from ..services.sources import source_out, visible_sources
from .schemas import LoginIn, MeOut, TotpLoginIn, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])
log = logging.getLogger("app.auth")


async def _me(request: Request, db: AsyncSession, su: SessionUser) -> MeOut:
    general = await request.app.state.settings_svc.get(db, "general")
    look = await request.app.state.settings_svc.get(db, "appearance")
    u = await db.get(User, su.user_id)
    return MeOut(user=UserOut(id=su.user_id, username=su.username, display_name=su.display_name, role=su.role, is_admin=su.is_admin, local=su.local),
                 csrf_token=su.csrf, must_change_password=su.must_change, current_source_id=str(su.current_source_id) if su.current_source_id else None, site_name=general.site_name,
                 activity_days=general.activity_days, must_enroll_totp=su.must_totp, totp_enabled=bool(u and u.totp_enabled), second_factor=su.second_factor,
                 secure_cookie=request.app.state.settings.secure_cookie(request.headers.get("x-forwarded-proto")), theme=u.theme if u else None, default_theme=look.default_theme)


def _check_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin is not None and not origin_allowed(origin, request.app.state.settings):
        raise HTTPException(status_code=403, detail="Недопустимый Origin")


def _fail(exc: AuthError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message}, headers={"Retry-After": str(exc.retry_after)} if exc.retry_after else None)


@router.get("/login-options")
async def login_options(request: Request, db: AsyncSession = Depends(get_db)):
    """Для страницы входа: список доменов (названия подключений LDAPS) — только если их несколько, чтобы пользователь мог выбрать домен."""
    conns = [c for c in await request.app.state.ldap.connections(db) if c.enabled and c.host]
    look = await request.app.state.settings_svc.get(db, "appearance")          # страница входа до авторизации — в теме системы (если в браузере нет личного выбора)
    return {"domains": [{"id": str(c.id), "name": c.name} for c in conns] if len(conns) > 1 else [], "default_theme": look.default_theme}


@router.put("/me/theme")
async def set_theme(request: Request, body: dict = Body(...), su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Личная тема оформления (хранится в профиле — действует на всех устройствах); null — вернуться к теме по умолчанию системы."""
    from ..services.settings import THEMES  # noqa: PLC0415

    _check_origin(request)
    theme = body.get("theme")
    if theme is not None and theme not in THEMES:
        raise HTTPException(status_code=422, detail="Неизвестная тема оформления")
    u = await db.get(User, su.user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    u.theme = theme
    await db.commit()
    return {"theme": theme}


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    """Первый шаг входа. Ответ — сведения о пользователе и cookie сессии либо {totp_required, challenge}, если нужен код второго фактора."""
    _check_origin(request)
    ip = client_ip(request)
    journal = request.app.state.journal
    try:
        result = await request.app.state.auth.login(db, body.login, body.password, body.domain)
    except AuthError as exc:
        # пользователю — общее сообщение; администратору в журналах — точная причина (пользователь не найден, ошибка поиска, пароль отклонён, нет группы…)
        why = {"code": exc.code, "reason": exc.reason, **({"detail": exc.detail[:500]} if exc.detail else {})}
        await audit_now(request.app.state.session_maker, actor_user_id=None, actor=body.login[:80], action="auth.login_failed", target_type="user", target_id=body.login[:80],
                        result="denied" if exc.code in ("throttled", "no_role", "account_disabled", "account_locked") else "failure", details=why)
        await journal.emit("auth", "login_failed", level="warn", user=body.login[:80], ip=ip, message=f"{exc.message} Причина: {exc.detail or exc.reason}", data=why)
        raise _fail(exc) from None
    if result.challenge:
        await journal.emit("auth", "login_password_ok", user=result.user.username, ip=ip, message="Пароль принят, ожидается код второго фактора")
        return JSONResponse({"totp_required": True, "challenge": result.challenge}, headers={"Cache-Control": "no-store"})
    return await _open_session(request, response, db, result, ip=ip)


@router.post("/login/totp", response_model=MeOut)
async def login_totp(body: TotpLoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    """Второй шаг входа: код из приложения-аутентификатора или резервный код."""
    _check_origin(request)
    ip = client_ip(request)
    try:
        result = await request.app.state.auth.complete_totp(db, body.challenge, body.code)
    except AuthError as exc:
        await audit_now(request.app.state.session_maker, actor_user_id=None, actor="(2FA)", action="auth.totp_failed", target_type="user", target_id="-",
                        result="denied" if exc.code in ("throttled", "totp_expired") else "failure", details={"code": exc.code})
        await request.app.state.journal.emit("auth", "totp_failed", level="warn", ip=ip, message=exc.message, data={"code": exc.code})
        raise _fail(exc) from None
    return await _open_session(request, response, db, result, ip=ip)


async def _open_session(request: Request, response: Response, db: AsyncSession, result, *, ip: str) -> MeOut:
    settings = request.app.state.settings
    user = result.user
    sid = await request.app.state.sessions.create(db, user, ip=ip, ua=request.headers.get("user-agent") or "", must_totp=result.must_totp, second_factor=result.second_factor)
    # источник: последний выбранный этим пользователем (если ещё доступен), иначе первый доступный
    got = await request.app.state.sessions.get(db, sid)
    su = SessionUser.build(sid, got[0], got[1])
    srcs = await visible_sources(db, su)
    if srcs:
        pick = next((s for s in srcs if s.id == user.current_source_id), srcs[0])
        await request.app.state.sessions.set_source(db, sid, pick.id)
        su = SessionUser.build(sid, *(await request.app.state.sessions.get(db, sid)))
    write_audit(db, actor_user_id=user.id, actor=user.display_name, action="auth.login", target_type="user", target_id=str(user.id),
                details={"login": user.username, "role": user.role, "local": user.auth_source == "local", "second_factor": result.second_factor, "must_totp": result.must_totp})
    await db.commit()
    await request.app.state.journal.emit("auth", "login_ok", user=user.username, ip=ip, data={"role": user.role, "second_factor": result.second_factor})
    response.set_cookie(settings.cookie_name, sid, httponly=True, secure=settings.secure_cookie(request.headers.get("x-forwarded-proto")), samesite="lax", path="/")
    response.headers["Cache-Control"] = "no-store"
    return await _me(request, db, su)


@router.post("/logout", status_code=204)
async def logout(request: Request, response: Response, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    await request.app.state.sessions.destroy(db, su.session_id)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="auth.logout", target_type="user", target_id=str(su.user_id))
    await db.commit()
    response.delete_cookie(request.app.state.settings.cookie_name, path="/")
    response.status_code = 204


@router.get("/me", response_model=MeOut)
async def me(request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    return await _me(request, db, su)


@router.get("/sources")
async def my_sources(su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Источники KSC, доступные пользователю (для переключателя в верхней панели)."""
    return {"items": [source_out(s) for s in await visible_sources(db, su)], "current": str(su.current_source_id) if su.current_source_id else None}


@router.post("/source")
async def select_source(request: Request, body: dict = Body(...), su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    try:
        sid = uuid.UUID(str(body.get("source_id")))
    except ValueError:
        raise HTTPException(status_code=422, detail="source_id") from None
    src = await db.get(KscSource, sid)
    if src is None or not src.is_active or not su.can_use_source(sid):
        raise HTTPException(status_code=403, detail="Нет доступа к этому источнику")
    await request.app.state.sessions.set_source(db, su.session_id, sid)
    user = await db.get(User, su.user_id)
    if user is not None:                       # запоминается для пользователя: следующий вход откроет этот же источник; другие пользователи не затрагиваются
        user.current_source_id = sid
        await db.commit()
    return {"current": str(sid)}


@router.post("/change-password", status_code=204)
async def change_password(request: Request, body: dict = Body(...), su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    if not su.local:
        raise HTTPException(status_code=403, detail="Пароль доменной учётной записи меняется в каталоге.")
    user = await db.get(User, su.user_id)
    cur, new = str(body.get("current_password") or ""), str(body.get("new_password") or "")
    if user is None or not user.password_hash or not verify_password(user.password_hash, cur):
        raise HTTPException(status_code=403, detail="Текущий пароль указан неверно.")
    try:
        la.validate_new_password(new, user.username, old=cur)
    except la.LocalAdminError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    await la.set_password(db, user, new, must_change=False)
    write_audit(db, actor_user_id=user.id, actor=user.display_name, action="user.password_changed", target_type="user", target_id=str(user.id))
    await db.commit()
    await request.app.state.sessions.destroy_user(db, user.id, keep=su.session_id)
    _ = current_session
