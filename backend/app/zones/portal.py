"""Портал ответственных за зоны: доменные пользователи, назначенные зоне (учётная запись или группа AD), входят с ролью «zone» и видят только свои зоны.

Права проверяются на сервере: роль «zone» допускается только к маршрутам входа, своих зон (панель, карточки компьютеров своей зоны) и отчётов по своим зонам
(`ALLOWED`); остальные разделы и инструменты KAV Checker, источники KSC и чужие зоны — 403/404. Состав зон пересчитывается на каждом запросе по учётной записи
и группам, сохранённым при входе: снятие доступа администратором действует сразу, без повторного входа."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Zone, ZoneAccess

ROLE = "zone"
API = "/api/v1"
ALLOWED = ("/auth/", "/zones", "/quick/preview", "/reports")          # префиксы маршрутов (после /api/v1), доступные роли «zone»; внутри — проверка зоны
DENIED = ("/zones/options", "/zones/of-host")                           # служебные маршруты списка зон и «зоны компьютера» — не для портала


def idents(username: str, email: str = "", upn: str = "") -> set[str]:
    """Как администратор мог записать учётную запись: «логин», «DOMAIN\\логин», «логин@домен» (UPN или почта) — всё в нижнем регистре."""
    out = set()
    for v in (username, email, upn):
        v = (v or "").strip().lower()
        if v:
            out |= {v, v.split("\\")[-1]}
            if "@" in v:
                out.add(v.split("@")[0])
    return {x for x in out if x}


def _short(v: str) -> str:
    return v.split("\\")[-1].split("@")[0]


async def zones_for(db: AsyncSession, *, username: str, email: str = "", upn: str = "", groups=()) -> list[str]:
    """Включённые зоны, к которым допущен пользователь (по учётной записи или группе AD, включая вложенные — они уже в списке групп при входе).
    Учётная запись в доступе сравнивается полностью («DOMAIN\\логин», UPN, почта) либо по логину без домена — так, как её записал администратор."""
    names = idents(username, email, upn)
    shorts = {_short(n) for n in names}
    grp = {str(g).strip().lower() for g in groups or [] if g}
    rows = (await db.execute(select(ZoneAccess.zone_id, ZoneAccess.kind, ZoneAccess.value).join(Zone, Zone.id == ZoneAccess.zone_id).where(Zone.enabled.is_(True)))).all()
    out = {str(z) for z, kind, value in rows if (kind == "group" and value in grp) or (kind == "user" and (value in names or ("\\" in value and _short(value) in shorts)))}
    return sorted(out)


def path_allowed(path: str) -> bool:
    p = path[len(API):] if path.startswith(API) else path
    return any(p == a.rstrip("/") or p.startswith(a.rstrip("/") + "/") for a in ALLOWED) and not any(p.startswith(d) for d in DENIED)
