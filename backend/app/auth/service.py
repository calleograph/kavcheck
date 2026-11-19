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
from ..services.jobs import _insert
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
    "choose_domain": ("Учётная запись с таким именем есть в нескольких доменах. Выберите домен и войдите снова.", 409),
    "totp_expired": ("Время подтверждения истекло. Войдите заново.", 401),
    "totp_unavailable": ("Второй фактор недоступен: не задан ключ шифрования. Обратитесь к администратору.", 503),
    "invalid_code": ("Неверный код. Проверьте время на телефоне или введите резервный код.", 401),
}


class AuthError(Exception):
    """code и message — для пользователя (общие формулировки); reason и detail — точная причина для журнала администратора."""

    def __init__(self, code: str, retry_after: int | None = None, reason: str = "", detail: str = ""):
        super().__init__(code)
        self.code = code
        self.message, self.status = MESSAGES.get(code, MESSAGES["invalid_credentials"])
        self.retry_after = retry_after
        self.reason, self.detail = reason or code, detail

    @classmethod
    def from_ldap(cls, code: str, exc: ldapmod.LdapError) -> "AuthError":
        where = f" (подключение «{exc.connection}»)" if exc.connection else ""
        return cls(code, reason=exc.code, detail=exc.message + where)


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
            raise AuthError("throttled", retry_after=int((row.locked_until - utcnow()).total_seconds()), reason="lockout", detail=f"неудачных попыток: {row.count}, блокировка до {row.locked_until:%H:%M:%S} UTC")

    async def _record_failure(self, db: AsyncSession, key: str) -> int | None:
        """+1 неудача атомарно в SQL (параллельные запросы не видят один и тот же счётчик); возвращает номер попытки, None — ключ уже заблокирован."""
        k, now = _h(key), utcnow()
        free = LoginFailure.locked_until.is_(None) | (LoginFailure.locked_until <= now)
        sync = {"synchronize_session": False}
        await db.execute(update(LoginFailure).where(LoginFailure.key == k, free, LoginFailure.first_at < now - timedelta(seconds=self._s.login_lockout_seconds * 3))
                         .values(count=0, first_at=now, locked_until=None).execution_options(**sync))
        await db.execute(_insert(db)(LoginFailure).values(key=k, count=0, first_at=now).on_conflict_do_nothing(index_elements=["key"]))
        n = (await db.execute(update(LoginFailure).where(LoginFailure.key == k, free).values(count=LoginFailure.count + 1).returning(LoginFailure.count).execution_options(**sync))).scalar_one_or_none()
        if n is not None and n >= self._s.login_max_failures:
            await db.execute(update(LoginFailure).where(LoginFailure.key == k).values(locked_until=now + timedelta(seconds=self._s.login_lockout_seconds), count=0).execution_options(**sync))
        await db.commit()
        return n

    async def _record_success(self, db: AsyncSession, key: str) -> None:
        row = await db.get(LoginFailure, _h(key))
        if row:
            await db.delete(row)
            await db.commit()

    # ------------------------------------------------------------------------------ вход
    async def login(self, db: AsyncSession, login: str, password: str, domain: str = "") -> LoginResult:
        """Пользователь вводит короткое имя: сначала локальная учётная запись KAV Checker (если домен не выбран явно), затем каталог LDAPS."""
        login, domain = (login or "").strip(), (domain or "").strip()
        if not _LOGIN.match(login) or not password or len(password) > 512:
            raise AuthError("invalid_credentials", reason="bad_login_format")
        norm = login.split("\\")[-1].split("@")[0].lower()
        key = norm                                      # счётчик неудач — по логину без домена: «a\\jsmith», «b\\jsmith» не обходят блокировку для jsmith
        await self._check_throttle(db, key)
        local = (await db.execute(select(User).where(User.auth_source == "local", func.lower(User.username) == norm))).scalar_one_or_none()
        if local is not None and local.password_hash and "\\" not in login and "@" not in login and not domain:
            if verify_password(local.password_hash, password):
                if not local.is_active:
                    raise AuthError("account_disabled", reason="local_disabled", detail="локальная учётная запись отключена в KAV Checker")
                await self._record_success(db, key)
                return await self.second_factor(db, local, groups=[])
            await self._record_failure(db, key)
            raise AuthError("invalid_credentials", reason="local_bad_password", detail="локальная учётная запись: пароль не подошёл")
        directory = await self._ldap.directory(db)
        if not directory.configs:
            await self._record_failure(db, key)
            raise AuthError("invalid_credentials" if local is None else "not_configured", reason="ldap_not_configured")
        try:
            ident = await asyncio.to_thread(directory.authenticate, login, password, domain)
        except ldapmod.LdapError as exc:
            if exc.code in ("invalid_credentials", "user_not_found", "ambiguous_user", "bad_login"):
                await self._record_failure(db, key)
                raise AuthError.from_ldap("invalid_credentials", exc) from None
            if exc.code in ("choose_domain", "unknown_domain"):
                raise AuthError.from_ldap("choose_domain", exc) from None
            if exc.code in ("account_disabled", "account_locked", "password_expired", "password_must_change", "account_restriction", "not_configured"):
                raise AuthError.from_ldap(exc.code, exc) from None
            log.error("Ошибка каталога при входе", extra={"ldap_code": exc.code})
            raise AuthError.from_ldap("directory_unavailable", exc) from None
        from ..zones.portal import ROLE as ZONE_ROLE, netbios_of, zones_for  # noqa: PLC0415

        netbios = await netbios_of(db, ident.connection_id)
        decision = self._ldap.decide(await self._ldap.rules(db), ident, netbios)
        await self._record_success(db, key)          # пароль верен — это не перебор, даже если доступа нет
        role, all_sources, source_ids = decision.role, decision.all_sources, sorted(decision.source_ids)
        if role is None:                                   # правил нет — может быть, это ответственный за зону: вход только в портал своих зон, без источников KSC
            if await zones_for(db, username=ident.username, email=ident.email or "", upn=ident.upn or "", groups=ident.groups, netbios=netbios):
                role, all_sources, source_ids = ZONE_ROLE, False, []
        if role is None:
            raise AuthError("no_role", reason="no_access_rule", detail=f"ни учётная запись, ни её группы не разрешены правилами доступа и не назначены ответственными за зону (подключение «{ident.connection}»)")
        conn_id = uuid.UUID(ident.connection_id) if ident.connection_id else None
        user = (await db.execute(select(User).where(User.ldap_guid == ident.guid))).scalar_one_or_none()
        if user is None:   # запись без GUID (созданная до 0.2.0) — только из того же подключения: одинаковое имя в другом домене — другой человек
            user = (await db.execute(select(User).where(User.auth_source == "ldap", func.lower(User.username) == ident.username.lower(),
                                                        User.ldap_connection_id.is_(None) | (User.ldap_connection_id == conn_id)))).scalar_one_or_none()
        username = await self._username(db, ident, user)
        if user is None:
            user = User(username=username, display_name=ident.display_name, auth_source="ldap", ldap_guid=ident.guid, role=role, is_active=True)
            db.add(user)
        if user.is_active is False:                         # отключён администратором в KAV Checker (независимо от каталога)
            await db.commit()
            raise AuthError("account_disabled", reason="disabled_in_kavchecker")
        user.username, user.display_name, user.email, user.ldap_guid, user.role = username, ident.display_name, ident.email, ident.guid, role
        user.all_sources, user.source_ids = all_sources, source_ids
        user.upn = (ident.upn or "")[:300] or None
        user.ldap_connection_id = conn_id
        user.ldap_groups = sorted(ident.groups)[:1000]
        await db.commit()
        await db.refresh(user)
        return await self.second_factor(db, user, groups=list(ident.groups))

    @staticmethod
    async def _username(db: AsyncSession, ident: "ldapmod.LdapIdentity", current: User | None) -> str:
        """Имя записи пользователя: имя учётной записи; если оно занято (локальный пользователь или тот же логин в другом домене) — имя@домен."""
        plain = ident.username.lower()
        qualified = f"{plain}@{ident.domain}" if ident.domain else f"{plain}@{(ident.connection_id or 'ldap')[:8]}"
        if current is not None and current.username in (plain, qualified):
            return current.username
        for cand in (plain, qualified):
            taken = (await db.execute(select(User.id).where(func.lower(User.username) == cand))).scalar_one_or_none()
            if taken is None or (current is not None and taken == current.id):
                return cand
        return f"{plain}@{(ident.connection_id or 'ldap')[:8]}"

    async def totp_cfg(self, db: AsyncSession):
        return await self._svc.get(db, "auth_security")

    async def second_factor(self, db: AsyncSession, user: User, *, groups) -> LoginResult:
        cfg = await self.totp_cfg(db)
        on = cfg.totp_policy != "off" and self._svc.box is not None
        if cfg.totp_policy != "off" and self._svc.box is None and user.totp_enabled and user.totp_secret_enc:
            raise AuthError("totp_unavailable", reason="totp_no_master_key", detail=f"{user.username}: второй фактор недоступен: не задан ключ шифрования (APP_MASTER_KEY)")
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
            raise AuthError("totp_expired", reason="challenge_missing_or_expired", detail="подтверждение не найдено или истекло")
        user = await db.get(User, ch.user_id)
        if user is None or not user.is_active or not user.totp_enabled:
            await db.delete(ch)
            await db.commit()
            raise AuthError("totp_expired", reason="user_unavailable", detail="пользователь отключён или второй фактор выключен")
        tkey = f"totp:{user.id}"                         # свой счётчик: верный пароль его не сбрасывает, иначе цикл «пароль → 5 кодов» перебирал бы код без блокировки
        try:
            await self._check_throttle(db, tkey)
        except AuthError as exc:
            exc.detail = f"{user.username}: {exc.detail}"
            raise
        # попытка засчитывается до проверки кода и одним UPDATE: параллельные запросы не обходят пределы
        n = (await db.execute(update(AuthChallenge).where(AuthChallenge.key == ch.key).values(attempts=AuthChallenge.attempts + 1)
                              .returning(AuthChallenge.attempts).execution_options(synchronize_session=False))).scalar_one_or_none()
        await db.commit()
        if n is None or n > CHALLENGE_ATTEMPTS:
            await db.execute(delete(AuthChallenge).where(AuthChallenge.key == ch.key))
            await db.commit()
            raise AuthError("totp_expired", reason="too_many_attempts", detail=f"{user.username}: больше {CHALLENGE_ATTEMPTS} попыток на одно подтверждение")
        tn = await self._record_failure(db, tkey)        # неудача по пользователю тоже засчитывается заранее; верный код сбрасывает счётчик
        if tn is None:
            raise AuthError("throttled", retry_after=self._s.login_lockout_seconds, reason="lockout", detail=f"{user.username}: блокировка после неверных кодов")
        ok, backup = await self.check_code(db, user, code)
        if not ok:
            raise AuthError("invalid_code", reason="bad_code", detail=f"{user.username}: {'резервный код' if totp.looks_like_backup(code) else 'код приложения'} не принят (попытка {n} из {CHALLENGE_ATTEMPTS})")
        await db.execute(delete(AuthChallenge).where(AuthChallenge.key == ch.key))
        user.last_login_at = utcnow()
        await db.commit()
        await self._record_success(db, tkey)
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
                d = await self._ldap.directory(db)
                dom = str(user.ldap_connection_id) if user.ldap_connection_id and any(c.id == str(user.ldap_connection_id) for c in d.configs) else ""
                ident = await asyncio.to_thread(d.authenticate, user.username.split("@")[0], password, dom)
                ok = ident.guid == user.ldap_guid
            except ldapmod.LdapError:
                ok = False
        if not ok:
            await self._record_failure(db, user.username)
        return ok
