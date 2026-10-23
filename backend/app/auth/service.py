"""Сценарий входа: защита от перебора → локальный пользователь → LDAP → сессия."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings
from ..models import LoginFailure, User, utcnow
from ..security.passwords import verify_password
from . import ldap as ldapmod

log = logging.getLogger("app.auth")
_LOGIN = re.compile(r"^[\w][\w.@\\-]{0,255}$")

MESSAGES = {
    "invalid_credentials": ("Неверный логин или пароль.", 401),
    "account_disabled": ("Учётная запись отключена.", 403),
    "throttled": ("Слишком много неудачных попыток. Повторите позже.", 429),
    "not_configured": ("Вход доменной учётной записью не настроен. Войдите локальным администратором и настройте LDAP.", 503),
    "directory_unavailable": ("Каталог LDAP недоступен. Повторите позже или войдите локальной учётной записью.", 503),
    "no_role": ("Нет разрешения на вход: пользователь не входит ни в одну группу с ролью KAV Checker.", 403),
}


class AuthError(Exception):
    def __init__(self, code: str, retry_after: int | None = None):
        super().__init__(code)
        self.code = code
        self.message, self.status = MESSAGES.get(code, MESSAGES["invalid_credentials"])
        self.retry_after = retry_after


def _h(login: str) -> str:
    return hashlib.sha256(login.strip().lower().encode()).hexdigest()


class AuthService:
    def __init__(self, settings: Settings, settings_svc):
        self._s = settings
        self._svc = settings_svc          # services.settings.SettingsService: конфигурация LDAP

    async def _check_throttle(self, db: AsyncSession, login: str) -> None:
        row = await db.get(LoginFailure, _h(login))
        if row and row.locked_until and row.locked_until > utcnow():
            raise AuthError("throttled", retry_after=int((row.locked_until - utcnow()).total_seconds()))

    async def _record_failure(self, db: AsyncSession, login: str) -> None:
        key, now = _h(login), utcnow()
        row = await db.get(LoginFailure, key)
        if row is None or now - row.first_at > timedelta(seconds=self._s.login_lockout_seconds * 3):
            row = row or LoginFailure(key=key)
            row.count, row.first_at, row.locked_until = 0, now, None
            db.add(row)
        row.count += 1
        if row.count >= self._s.login_max_failures:
            row.locked_until = now + timedelta(seconds=self._s.login_lockout_seconds)
            row.count = 0
        await db.commit()

    async def _record_success(self, db: AsyncSession, login: str) -> None:
        row = await db.get(LoginFailure, _h(login))
        if row:
            await db.delete(row)
            await db.commit()

    async def login(self, db: AsyncSession, login: str, password: str) -> User:
        login = (login or "").strip()
        if not _LOGIN.match(login) or not password or len(password) > 512:
            raise AuthError("invalid_credentials")
        await self._check_throttle(db, login)
        norm = login.split("\\")[-1].split("@")[0].lower()
        local = (await db.execute(select(User).where(User.auth_source == "local", func.lower(User.username) == norm))).scalar_one_or_none()
        if local is not None and local.password_hash:
            if verify_password(local.password_hash, password):
                if not local.is_active:
                    raise AuthError("account_disabled")
                await self._record_success(db, login)
                local.last_login_at = utcnow()
                await db.commit()
                return local
            await self._record_failure(db, login)
            raise AuthError("invalid_credentials")
        cfg = await self._svc.ldap_config(db)
        if not cfg.enabled:
            await self._record_failure(db, login)
            raise AuthError("invalid_credentials" if local is None else "not_configured")
        try:
            ident = await asyncio.to_thread(ldapmod.authenticate, cfg, norm, password)
        except ldapmod.LdapError as exc:
            if exc.code in ("invalid_credentials", "user_not_found"):
                await self._record_failure(db, login)
                raise AuthError("invalid_credentials") from None
            if exc.code == "account_disabled":
                raise AuthError("account_disabled") from None
            if exc.code == "not_configured":
                raise AuthError("not_configured") from None
            log.error("Ошибка каталога при входе", extra={"ldap_code": exc.code})
            raise AuthError("directory_unavailable") from None
        role = role_from_groups(cfg, ident.groups)
        if role is None:
            await self._record_success(db, login)
            raise AuthError("no_role")
        await self._record_success(db, login)
        user = (await db.execute(select(User).where(User.ldap_guid == ident.guid))).scalar_one_or_none()
        if user is None:
            user = (await db.execute(select(User).where(User.auth_source == "ldap", func.lower(User.username) == ident.username.lower()))).scalar_one_or_none()
        if user is None:
            user = User(username=ident.username.lower(), display_name=ident.display_name, auth_source="ldap", ldap_guid=ident.guid, role=role)
            db.add(user)
        user.username, user.display_name, user.email, user.ldap_guid, user.role = ident.username.lower(), ident.display_name, ident.email, ident.guid, role
        if not user.is_active:
            await db.commit()
            raise AuthError("account_disabled")
        user.last_login_at = utcnow()
        await db.commit()
        await db.refresh(user)
        return user


def role_from_groups(cfg: ldapmod.LdapConfig, groups: frozenset[str]) -> str | None:
    """Роль по группам каталога: старшая из подходящих. Пустые настройки групп аналитика и просмотра — вход всем с ролью «просмотр»,
    если задана хотя бы группа администраторов; без единой группы — вход невозможен."""
    g = {x.lower() for x in groups}
    if cfg.admin_group_dn and cfg.admin_group_dn.lower() in g:
        return "admin"
    if cfg.analyst_group_dn and cfg.analyst_group_dn.lower() in g:
        return "analyst"
    if cfg.viewer_group_dn:
        return "viewer" if cfg.viewer_group_dn.lower() in g else None
    return "viewer" if (cfg.admin_group_dn or cfg.analyst_group_dn) else None
