"""Двухфакторная аутентификация (TOTP): настройка пользователем, резервные коды, сброс администратором.

Включение: пароль → секрет и QR-код (секрет ждёт подтверждения 10 минут, зашифрован) → код из приложения → резервные коды (показываются один раз).
Секрет хранится зашифрованным (APP_MASTER_KEY, AAD — пользователь), резервные коды — только в виде HMAC. Выключить 2FA нельзя, если её требует политика.
Каждое действие записывается в журнал действий."""
from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_admin, require_user
from ..auth.service import AuthError, totp_required
from ..models import AuthChallenge, User, UserBackupCode, utcnow
from ..security import totp
from ..services.audit import write_audit

router = APIRouter(tags=["auth"])
PENDING = timedelta(minutes=10)


class PasswordIn(BaseModel):
    password: str = Field(min_length=1, max_length=512)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class PasswordCodeIn(PasswordIn, CodeIn):
    pass


def _setup_key(user_id) -> str:
    return hashlib.sha256(f"setup:{user_id}".encode()).hexdigest()


def _box(request: Request):
    box = request.app.state.settings_svc.box
    if box is None:
        raise HTTPException(status_code=503, detail="APP_MASTER_KEY не задан: секрет второго фактора сохранить нельзя.")
    return box


async def _user(db: AsyncSession, su: SessionUser) -> User:
    u = await db.get(User, su.user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return u


async def _reauth(request: Request, db: AsyncSession, user: User, password: str) -> None:
    try:
        ok = await request.app.state.auth.verify_current(db, user, password)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from None
    if not ok:
        raise HTTPException(status_code=403, detail="Неверный пароль.")


async def _new_codes(db: AsyncSession, user: User) -> list[str]:
    await db.execute(delete(UserBackupCode).where(UserBackupCode.user_id == user.id))
    codes = totp.new_backup_codes()
    for c in codes:
        db.add(UserBackupCode(user_id=user.id, code_hash=totp.hash_backup(str(user.id), c)))
    return [totp.format_backup(c) for c in codes]


@router.get("/auth/totp/status")
async def status(request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    cfg, user = await request.app.state.auth.totp_cfg(db), await _user(db, su)
    left = (await db.execute(select(func.count()).select_from(UserBackupCode).where(UserBackupCode.user_id == user.id, UserBackupCode.used_at.is_(None)))).scalar_one()
    return {"available": cfg.totp_policy != "off" and request.app.state.settings_svc.box is not None, "policy": cfg.totp_policy, "enabled": user.totp_enabled,
            "required": cfg.totp_policy != "off" and totp_required(cfg, role=user.role, groups=user.ldap_groups or []), "backup_left": left if user.totp_enabled else 0,
            "enabled_at": user.totp_enabled_at}


@router.post("/auth/totp/setup")
async def setup(body: PasswordIn, request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    cfg, user = await request.app.state.auth.totp_cfg(db), await _user(db, su)
    if cfg.totp_policy == "off":
        raise HTTPException(status_code=403, detail="Двухфакторная аутентификация отключена администратором.")
    box = _box(request)
    if user.totp_enabled:
        raise HTTPException(status_code=409, detail="Двухфакторная аутентификация уже включена.")
    await _reauth(request, db, user, body.password)
    secret = totp.new_secret()
    key = _setup_key(user.id)
    old = await db.get(AuthChallenge, key)
    if old is not None:
        await db.delete(old)
        await db.flush()
    db.add(AuthChallenge(key=key, kind="totp_setup", user_id=user.id, data={"secret": box.encrypt(secret, aad=f"totp_setup.{user.id}".encode())}, expires_at=utcnow() + PENDING))
    await db.commit()
    uri = totp.otpauth_uri(cfg.totp_issuer, user.username, secret)
    return {"secret": " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)), "uri": uri, "qr_svg": totp.qr_svg(uri), "expires_in": int(PENDING.total_seconds())}


@router.post("/auth/totp/enable")
async def enable(body: CodeIn, request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    user = await _user(db, su)
    box = _box(request)
    ch = await db.get(AuthChallenge, _setup_key(user.id))
    if ch is None or ch.expires_at < utcnow():
        raise HTTPException(status_code=409, detail="Время настройки истекло. Начните заново.")
    ch.attempts += 1
    if ch.attempts > 10:
        await db.delete(ch)
        await db.commit()
        raise HTTPException(status_code=429, detail="Слишком много неверных кодов. Начните настройку заново.")
    secret = box.decrypt(ch.data["secret"], aad=f"totp_setup.{user.id}".encode())
    step = totp.verify(secret, body.code)
    if step is None:
        await db.commit()
        raise HTTPException(status_code=422, detail="Код не подошёл. Проверьте время на телефоне и введите текущий код.")
    user.totp_secret_enc = box.encrypt(secret, aad=f"user_totp.{user.id}".encode())
    user.totp_enabled, user.totp_enabled_at, user.totp_last_step = True, utcnow(), step
    codes = await _new_codes(db, user)
    await db.delete(ch)
    write_audit(db, actor_user_id=user.id, actor=user.display_name, action="auth.totp_enable", target_type="user", target_id=str(user.id))
    await db.commit()
    await request.app.state.sessions.set_must_totp(db, su.session_id, False)
    return {"backup_codes": codes}


async def _code_ok(request: Request, db: AsyncSession, user: User, code: str) -> tuple[bool, bool]:
    ok, backup = await request.app.state.auth.check_code(db, user, code)
    if not ok:
        write_audit(db, actor_user_id=user.id, actor=user.display_name, action="auth.totp_failed", target_type="user", target_id=str(user.id), result="failure", details={"where": "self_service"})
        await db.commit()
    return ok, backup


@router.post("/auth/totp/disable", status_code=204)
async def disable(body: PasswordCodeIn, request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    cfg, user = await request.app.state.auth.totp_cfg(db), await _user(db, su)
    if not user.totp_enabled:
        return
    if cfg.totp_policy != "off" and totp_required(cfg, role=user.role, groups=user.ldap_groups or []):
        raise HTTPException(status_code=403, detail="Политика безопасности требует двухфакторную аутентификацию: отключить её нельзя.")
    await _reauth(request, db, user, body.password)
    ok, _ = await _code_ok(request, db, user, body.code)
    if not ok:
        raise HTTPException(status_code=403, detail="Неверный код.")
    await clear(db, user)
    write_audit(db, actor_user_id=user.id, actor=user.display_name, action="auth.totp_disable", target_type="user", target_id=str(user.id))
    await db.commit()


@router.post("/auth/totp/backup-codes")
async def regenerate(body: PasswordCodeIn, request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Новые резервные коды (старые перестают действовать): пароль и текущий код из приложения."""
    user = await _user(db, su)
    if not user.totp_enabled:
        raise HTTPException(status_code=409, detail="Двухфакторная аутентификация не включена.")
    await _reauth(request, db, user, body.password)
    ok, backup = await _code_ok(request, db, user, body.code)
    if not ok or backup:
        raise HTTPException(status_code=403, detail="Нужен текущий код из приложения.")
    codes = await _new_codes(db, user)
    write_audit(db, actor_user_id=user.id, actor=user.display_name, action="auth.totp_backup_regenerate", target_type="user", target_id=str(user.id))
    await db.commit()
    return {"backup_codes": codes}


async def clear(db: AsyncSession, user: User) -> None:
    user.totp_enabled, user.totp_secret_enc, user.totp_last_step, user.totp_enabled_at = False, None, None, None
    await db.execute(delete(UserBackupCode).where(UserBackupCode.user_id == user.id))


@router.post("/admin/users/{user_id}/totp/reset", status_code=204)
async def admin_reset(user_id: uuid.UUID, body: PasswordIn, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Потеря телефона: администратор сбрасывает 2FA пользователя (подтверждая своим паролем); пользователь настроит её заново."""
    await _reauth(request, db, await _user(db, su), body.password)
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    await clear(db, user)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="auth.totp_reset", target_type="user", target_id=str(user.id), details={"user": user.username})
    await db.commit()
    await request.app.state.sessions.destroy_user(db, user.id)
