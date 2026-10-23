"""Сценарий входа: защита от перебора → локальная учётная запись → каталог (несколько подключений) → правила доступа по группам → второй фактор → сессия.

Локальные учётные записи остаются резервным способом входа (каталог недоступен — администратор входит локально).
Доменному пользователю роль и доступ к источникам назначаются правилами групп при каждом входе: нет подходящего правила — нет входа.
Второй фактор: если у пользователя включён TOTP, пароль даёт только одноразовое подтверждение (challenge), сессию открывает код из приложения
или резервный код. Если политика требует 2FA, а она не настроена — открывается сессия «только для настройки 2FA»."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings
from ..models import AuthChallenge, LoginFailure, User, UserBackupCode, utcnow
from ..security import totp
from ..security.passwords import verify_password
from . import ldap as ldapmod

log = logging.getLogger("app.auth")
_LOGIN = re.compile(r"^[\w][\w.@\\-]{0,255}$")
CHALLENGE_TTL = timedelta(minutes=5)
CHALLENGE_ATTEMPTS = 5

MESSAGES = {
    "invalid_credentials": ("Неверный логин или пароль.", 401),
    "account_disabled": ("Учётная запись отключена.", 403),
    "account_locked": ("Учётная запись заблокирована в каталоге.", 403),
    "password_expired": ("Срок действия пароля истёк — смените пароль в домене.", 403),
    "password_must_change": ("Требуется сменить пароль в домене.", 403),
    "account_restriction": ("Вход ограничен политикой учётной записи в каталоге.", 403),
    "throttled": ("Слишком много неудачных попыток. Повторите позже.", 429),
    "not_configured": ("Вход доменной учётной записью не настроен. Войдите локальной учётной записью.", 503),
    "directory_unavailable": ("Каталог недоступен. Повторите позже или войдите локальной учётной записью.", 503),
    "no_role": ("Нет доступа: вашей учётной записи не назначена роль в KAV Checker. Обратитесь к администратору.", 403),
    "totp_expired": ("Время подтверждения истекло. Войдите заново.", 401),
    "invalid_code": ("Неверный код. Проверьте время на телефоне или введите резервный код.", 401),
}


class AuthError(Exception):
    def __init__(self, code: str, retry_after: int | None = None):
        super().__init__(code)
        self.code = code
        self.message, self.status = MESSAGES.get(code, MESSAGES["invalid_credentials"])
        self.retry_after = retry_after


@dataclass
class LoginResult:
    user: User
    challenge: str | None = None       # пароль принят, нужен код 2FA (сессии ещё нет)
    must_totp: bool = False            # политика требует 2FA, а она не настроена
    second_factor: str | None = None   # totp | backup_code


def _h(login: str) -> str:
    return hashlib.sha256(login.strip().lower().encode()).hexdigest()


def _th(token: str) -> str:
    return hashlib.sha256(("chal:" + token).encode()).hexdigest()


def totp_required(cfg, *, role: str, groups) -> bool:
    p = cfg.totp_policy
    return p == "all" or (p == "admins" and role == "admin") or (p == "groups" and bool(cfg.group_set() & {str(g).lower() for g in (groups or [])}))


class AuthService:
    def __init__(self, settings: Settings, settings_svc, ldap_store):
        self._s = settings
        self._svc = settings_svc
        self._ldap = ldap_store

    # ------------------------------------------------------------------------------ перебор
    async def _check_throttle(self, db: AsyncSession, key: str) -> None:
        row = await db.get(LoginFailure, _h(key))
        if row and row.locked_until and row.locked_until > utcnow():
            raise AuthError("throttled", retry_after=int((row.locked_until - utcnow()).total_seconds()))

    async def _record_failure(self, db: AsyncSession, key: str) -> None:
        k, now = _h(key), utcnow()
        row = await db.get(LoginFailure, k)
        if row is None or now - row.first_at > timedelta(seconds=self._s.login_lockout_seconds * 3):
            row = row or LoginFailure(key=k)
            row.count, row.first_at, row.locked_until = 0, now, None
            db.add(row)
        row.count += 1
        if row.count >= self._s.login_max_failures:
            row.locked_until = now + timedelta(seconds=self._s.login_lockout_seconds)
            row.count = 0
        await db.commit()

    async def _record_success(self, db: AsyncSession, key: str) -> None:
        row = await db.get(LoginFailure, _h(key))
        if row:
            await db.delete(row)
            await db.commit()

    # ------------------------------------------------------------------------------ вход
    async def login(self, db: AsyncSession, login: str, password: str) -> LoginResult:
        login = (login or "").strip()
        if not _LOGIN.match(login) or not password or len(password) > 512:
            raise AuthError("invalid_credentials")
        await self._check_throttle(db, login)
        norm = login.split("\\")[-1].split("@")[0].lower()
        local = (await db.execute(select(User).where(User.auth_source == "local", func.lower(User.username) == norm))).scalar_one_or_none()
        if local is not None and local.password_hash and "\\" not in login and "@" not in login:
            if verify_password(local.password_hash, password):
                if not local.is_active:
                    raise AuthError("account_disabled")
                await self._record_success(db, login)
                return await self.second_factor(db, local, groups=[])
            await self._record_failure(db, login)
            raise AuthError("invalid_credentials")
        directory = await self._ldap.directory(db)
        if not directory.configs:
            await self._record_failure(db, login)
            raise AuthError("invalid_credentials" if local is None else "not_configured")
        try:
            ident = await asyncio.to_thread(directory.authenticate, login, password)
        except ldapmod.LdapError as exc:
            if exc.code in ("invalid_credentials", "user_not_found", "ambiguous_user"):
                await self._record_failure(db, login)
                raise AuthError("invalid_credentials") from None
            if exc.code in ("account_disabled", "account_locked", "password_expired", "password_must_change", "account_restriction", "not_configured"):
                raise AuthError(exc.code) from None
            log.error("Ошибка каталога при входе", extra={"ldap_code": exc.code})
            raise AuthError("directory_unavailable") from None
        decision = self._ldap.decide(await self._ldap.rules(db), ident)
        await self._record_success(db, login)          # пароль верен — это не перебор, даже если доступа нет
        if decision.role is None:
            raise AuthError("no_role")
        user = (await db.execute(select(User).where(User.ldap_guid == ident.guid))).scalar_one_or_none()
        if user is None:
            user = (await db.execute(select(User).where(User.auth_source == "ldap", func.lower(User.username) == ident.username.lower()))).scalar_one_or_none()
        if user is None:
            user = User(username=ident.username.lower(), display_name=ident.display_name, auth_source="ldap", ldap_guid=ident.guid, role=decision.role, is_active=True)
            db.add(user)
        if user.is_active is False:                         # отключён администратором в KAV Checker (независимо от каталога)
            await db.commit()
            raise AuthError("account_disabled")
        user.username, user.display_name, user.email, user.ldap_guid, user.role = ident.username.lower(), ident.display_name, ident.email, ident.guid, decision.role
        user.all_sources, user.source_ids = decision.all_sources, sorted(decision.source_ids)
        user.ldap_connection_id = uuid.UUID(ident.connection_id) if ident.connection_id else None
        user.ldap_groups = sorted(ident.groups)[:1000]
        await db.commit()
        await db.refresh(user)
        return await self.second_factor(db, user, groups=list(ident.groups))

    async def totp_cfg(self, db: AsyncSession):
        return await self._svc.get(db, "auth_security")

    async def second_factor(self, db: AsyncSession, user: User, *, groups) -> LoginResult:
        cfg = await self.totp_cfg(db)
        on = cfg.totp_policy != "off" and self._svc.box is not None
        if on and user.totp_enabled and user.totp_secret_enc:
            token = secrets.token_urlsafe(24)
            db.add(AuthChallenge(key=_th(token), kind="totp", user_id=user.id, attempts=0, expires_at=utcnow() + CHALLENGE_TTL))
            await db.execute(delete(AuthChallenge).where(AuthChallenge.expires_at < utcnow()))
            await db.commit()
            return LoginResult(user, challenge=token)
        user.last_login_at = utcnow()
        await db.commit()
        must = bool(on and totp_required(cfg, role=user.role, groups=groups) and not user.totp_enabled)
        return LoginResult(user, must_totp=must)

    async def complete_totp(self, db: AsyncSession, token: str, code: str) -> LoginResult:
        """Второй шаг входа: код из приложения или резервный код; не больше пяти попыток на одно подтверждение."""
        ch = await db.get(AuthChallenge, _th(token or ""))
        if ch is None or ch.kind != "totp" or ch.expires_at < utcnow():
            raise AuthError("totp_expired")
        user = await db.get(User, ch.user_id)
        if user is None or not user.is_active or not user.totp_enabled:
            await db.delete(ch)
            await db.commit()
            raise AuthError("totp_expired")
        await self._check_throttle(db, user.username)
        ch.attempts += 1
        await db.commit()
        if ch.attempts > CHALLENGE_ATTEMPTS:
            await db.delete(ch)
            await db.commit()
            raise AuthError("totp_expired")
        ok, backup = await self.check_code(db, user, code)
        if not ok:
            await self._record_failure(db, user.username)
            raise AuthError("invalid_code")
        await db.delete(ch)
        user.last_login_at = utcnow()
        await db.commit()
        await self._record_success(db, user.username)
        return LoginResult(user, second_factor="backup_code" if backup else "totp")

    def decrypt_totp(self, user: User) -> str:
        if self._svc.box is None or not user.totp_secret_enc:
            return ""
        try:
            return self._svc.box.decrypt(user.totp_secret_enc, aad=f"user_totp.{user.id}".encode())
        except Exception:  # noqa: BLE001 — повреждённый секрет = «кода нет», а не падение входа
            return ""

    async def check_code(self, db: AsyncSession, user: User, code: str) -> tuple[bool, bool]:
        """(принят, это резервный код). Код приложения — с защитой от повтора; резервный код гасится одним условным UPDATE."""
        if totp.looks_like_backup(code):
            res = await db.execute(update(UserBackupCode).where(UserBackupCode.user_id == user.id, UserBackupCode.code_hash == totp.hash_backup(str(user.id), code),
                                                                UserBackupCode.used_at.is_(None)).values(used_at=utcnow()))
            await db.commit()
            return res.rowcount == 1, res.rowcount == 1
        secret = self.decrypt_totp(user)
        step = totp.verify(secret, code, user.totp_last_step) if secret else None
        if step is None:
            return False, False
        res = await db.execute(update(User).where(User.id == user.id, (User.totp_last_step.is_(None)) | (User.totp_last_step < step)).values(totp_last_step=step))
        await db.commit()
        return res.rowcount == 1, False

    async def verify_current(self, db: AsyncSession, user: User, password: str) -> bool:
        """Повторное подтверждение пароля вошедшего пользователя (включение и отключение 2FA, сброс администратором)."""
        if not password or len(password) > 512:
            return False
        await self._check_throttle(db, user.username)
        ok = False
        if user.auth_source == "local":
            ok = bool(user.password_hash and verify_password(user.password_hash, password))
        else:
            try:
                ident = await asyncio.to_thread((await self._ldap.directory(db)).authenticate, user.username, password)
                ok = ident.guid == user.ldap_guid
            except ldapmod.LdapError:
                ok = False
        if not ok:
            await self._record_failure(db, user.username)
        return ok
