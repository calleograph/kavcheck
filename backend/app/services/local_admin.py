"""Локальные учётные записи: администратор создаётся при установке (пароль показывается один раз), пароли — только хэш argon2id."""
from __future__ import annotations

import re
import secrets

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import User, utcnow
from ..security.passwords import hash_password

_USERNAME = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")
_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
MIN_PASSWORD = 12


class LocalAdminError(Exception):
    """Сообщение безопасно для показа."""


def generate_password(groups: int = 4, size: int = 6) -> str:
    return "-".join("".join(secrets.choice(_ALPHABET) for _ in range(size)) for _ in range(groups))


def validate_username(name: str) -> str:
    name = (name or "").strip().lower()
    if not _USERNAME.match(name):
        raise LocalAdminError("Логин: 3–64 символа, строчные латинские буквы, цифры, «.», «_», «-», начинается с буквы.")
    return name


def validate_new_password(password: str, username: str, old: str | None = None) -> None:
    if len(password or "") < MIN_PASSWORD or len(password) > 256:
        raise LocalAdminError(f"Пароль должен быть не короче {MIN_PASSWORD} символов.")
    if username.lower() in password.lower():
        raise LocalAdminError("Пароль не должен содержать имя пользователя.")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-zа-я]", r"[A-ZА-Я]", r"\d", r"[^\w\s]|_"))
    if classes < 2:
        raise LocalAdminError("Используйте не менее двух видов символов: строчные и заглавные буквы, цифры, знаки.")
    if old is not None and password == old:
        raise LocalAdminError("Новый пароль должен отличаться от прежнего.")


async def find_local(db: AsyncSession, username: str) -> User | None:
    return (await db.execute(select(User).where(User.auth_source == "local", func.lower(User.username) == username.lower()))).scalar_one_or_none()


async def create_local(db: AsyncSession, username: str, password: str, *, role: str = "admin", display_name: str = "", must_change: bool = True) -> User:
    username = validate_username(username)
    if (await db.execute(select(User).where(func.lower(User.username) == username))).scalar_one_or_none() is not None:
        raise LocalAdminError("Пользователь с таким логином уже существует.")
    user = User(username=username, display_name=display_name or ("Локальный администратор" if role == "admin" else username), auth_source="local",
                password_hash=hash_password(password), must_change_password=must_change, role=role, is_active=True)
    db.add(user)
    await db.flush()
    return user


async def set_password(db: AsyncSession, user: User, password: str, *, must_change: bool) -> None:
    user.password_hash = hash_password(password)
    user.must_change_password = must_change
    user.is_active = True
    user.last_login_at = user.last_login_at or None
    await db.flush()
    _ = utcnow()
