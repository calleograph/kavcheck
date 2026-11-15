"""Портал ответственных за зоны: доменные пользователи, назначенные зоне (учётная запись или группа AD), входят с ролью «zone» и видят только свои зоны.

Права проверяются на сервере: роль «zone» допускается только к маршрутам входа, своих зон (панель, карточки компьютеров своей зоны) и отчётов по своим зонам
(`ALLOWED`); остальные разделы и инструменты KAV Checker, источники KSC и чужие зоны — 403/404. Состав зон пересчитывается на каждом запросе по учётной записи
и группам, сохранённым при входе: снятие доступа администратором действует сразу, без повторного входа."""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Zone, ZoneAccess

ROLE = "zone"
API = "/api/v1"
ALLOWED = ("/auth/", "/zones", "/quick/preview", "/reports")          # префиксы маршрутов (после /api/v1), доступные роли «zone»; внутри — проверка зоны
DENIED = ("/zones/options", "/zones/of-host")                           # служебные маршруты списка зон и «зоны компьютера» — не для портала


def idents(username: str, email: str = "", upn: str = "") -> set[str]:
    """Полные записи учётной записи в нижнем регистре: логин, UPN, почта. Часть адреса до «@» не используется — у разных людей она совпадает."""
    return {v for v in ((x or "").strip().lower() for x in (username, email, upn)) if v}


async def zones_for(db: AsyncSession, *, username: str, email: str = "", upn: str = "", groups=(), netbios: str = "") -> list[str]:
    """Включённые зоны, к которым допущен пользователь: группа каталога (включая вложенные — они уже в списке групп при входе) или учётная запись.
    Учётная запись сравнивается полностью (логин, UPN, почта); «DOMAIN\\логин» — логин и NetBIOS-имя подключения, через которое вошёл пользователь
    (`netbios`; неизвестно — такая запись не подходит, чтобы однофамилец из другого каталога не получил чужую зону)."""
    names = idents(username, email, upn)
    login, nb = (username or "").strip().lower().split("\\")[-1], (netbios or "").strip().lower()
    grp = {str(g).strip().lower() for g in groups or [] if g}

    def user_ok(value: str) -> bool:
        if "\\" in value:
            dom, _sep, who = value.partition("\\")
            return bool(nb) and dom == nb and who == login
        return value in names

    rows = (await db.execute(select(ZoneAccess.zone_id, ZoneAccess.kind, ZoneAccess.value).join(Zone, Zone.id == ZoneAccess.zone_id).where(Zone.enabled.is_(True)))).all()
    return sorted({str(z) for z, kind, value in rows if (kind == "group" and value in grp) or (kind == "user" and user_ok(value))})


async def netbios_of(db: AsyncSession, connection_id) -> str:
    """NetBIOS-имя подключения каталога, через которое вошёл пользователь (для записей «DOMAIN\\логин»)."""
    from ..models import LdapConnection  # noqa: PLC0415

    if not connection_id:
        return ""
    c = await db.get(LdapConnection, connection_id if isinstance(connection_id, uuid.UUID) else uuid.UUID(str(connection_id)))
    return (c.netbios or "") if c is not None else ""


def path_allowed(path: str) -> bool:
    p = path[len(API):] if path.startswith(API) else path
    return any(p == a.rstrip("/") or p.startswith(a.rstrip("/") + "/") for a in ALLOWED) and not any(p.startswith(d) for d in DENIED)
