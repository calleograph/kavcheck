"""Служебные команды (внутри контейнера backend):
    python -m app.cli create-admin [--username admin] [--password …]   — локальный администратор (пароль печатается один раз)
    python -m app.cli reset-password --username admin [--password …]  — сброс пароля локального пользователя
    python -m app.cli status                                           — краткая проверка базы и миграций"""
from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy import select, text

from .config import get_settings
from .db import create_engine, create_session_maker
from .models import User
from .services import local_admin as la


async def _create_admin(username: str, password: str | None) -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_session_maker(engine)
    pw = password or la.generate_password()
    async with sm() as db:
        try:
            la.validate_new_password(pw, username)
            user = await la.create_local(db, username, pw, role="admin", must_change=True)
        except la.LocalAdminError as exc:
            print(f"Ошибка: {exc}", file=sys.stderr)
            return 1
        la_audit = __import__("app.services.audit", fromlist=["write_audit"]).write_audit
        la_audit(db, actor_user_id=None, actor="install", action="user.create", target_type="user", target_id=str(user.id), details={"username": username, "role": "admin"})
        await db.commit()
    await engine.dispose()
    print(f"Создан локальный администратор: {username}")
    print(f"Пароль (показывается один раз, при первом входе потребуется сменить): {pw}")
    return 0


async def _reset(username: str, password: str | None) -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_session_maker(engine)
    pw = password or la.generate_password()
    async with sm() as db:
        user = await la.find_local(db, username)
        if user is None:
            print("Локальный пользователь не найден", file=sys.stderr)
            return 1
        try:
            la.validate_new_password(pw, username)
        except la.LocalAdminError as exc:
            print(f"Ошибка: {exc}", file=sys.stderr)
            return 1
        await la.set_password(db, user, pw, must_change=True)
        user.is_active = True
        from .models import Session  # noqa: PLC0415
        from sqlalchemy import delete  # noqa: PLC0415

        await db.execute(delete(Session).where(Session.user_id == user.id))
        __import__("app.services.audit", fromlist=["write_audit"]).write_audit(db, actor_user_id=None, actor="cli", action="user.password_reset", target_type="user", target_id=str(user.id), details={"username": username})
        await db.commit()
    await engine.dispose()
    print(f"Пароль пользователя {username} сброшен. Новый пароль (сменить при входе): {pw}")
    return 0


async def _status() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sm = create_session_maker(engine)
    async with sm() as db:
        rev = (await db.execute(text("SELECT version_num FROM alembic_version"))).scalar_one_or_none()
        users = len((await db.execute(select(User.id))).all())
    await engine.dispose()
    print(f"База доступна. Ревизия схемы: {rev}. Пользователей: {users}.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="app.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("create-admin")
    a.add_argument("--username", default="admin")
    a.add_argument("--password")
    r = sub.add_parser("reset-password")
    r.add_argument("--username", required=True)
    r.add_argument("--password")
    sub.add_parser("status")
    args = ap.parse_args(argv)
    if args.cmd == "create-admin":
        return asyncio.run(_create_admin(args.username, args.password))
    if args.cmd == "reset-password":
        return asyncio.run(_reset(args.username, args.password))
    return asyncio.run(_status())


if __name__ == "__main__":
    sys.exit(main())
