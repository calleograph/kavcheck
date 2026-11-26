"""Аудит домена: состав привилегированных групп и изменения учётных записей между проверками.

Читаются только сохранённые проверки (каталог не опрашивается); общие для API раздела и отчётов `quick_adaudit` (виды groups, changes).
Изменения считаются в SQL (новые, удалённые, изменившиеся — соединением по objectGUID), в память попадают только изменившиеся записи (не больше LIMIT)."""
from __future__ import annotations

from sqlalchemy import String, and_, cast, exists, func, or_, select
from sqlalchemy.orm import aliased

from ..models import AdAuditAccount as A
from ..models import AdAuditRun
from . import checks as K
from . import query as Q

LIMIT = 2000
GROUP_ORDER = ["Enterprise Admins", "Domain Admins", "Schema Admins", "Administrators", "Account Operators", "Server Operators", "Backup Operators", "Print Operators"]
KIND_RU = {"new": "Новая учётная запись", "removed": "Удалена из каталога", "disabled": "Отключена", "enabled": "Включена снова", "category": "Сменилась категория",
           "moved": "Перемещена в другое подразделение (OU)", "priv_add": "Добавлена в привилегированные группы", "priv_del": "Исключена из привилегированных групп"}


async def prev_run(db, run: AdAuditRun) -> AdAuditRun | None:
    return (await db.execute(select(AdAuditRun).where(AdAuditRun.status == "ok", AdAuditRun.started_at < run.started_at).order_by(AdAuditRun.started_at.desc()).limit(1))).scalar_one_or_none()


def _iso(d) -> str | None:
    return d.isoformat() if d else None


def mini(a: A, at) -> dict:
    return {"guid": a.guid, "login": a.login, "name": a.name, "ou": a.ou, "enabled": a.enabled, "locked": a.locked, "state": Q.account_state(a.enabled, a.locked, a.expires, at),
            "category": a.category, "category_ru": K.CATEGORY_RU.get(a.category, a.category), "last_logon": _iso(a.last_logon), "idle_days": a.idle_days, "pwd_age": a.pwd_age, "pne": a.pne,
            "protected": a.protected, "created": _iso(a.created)}


def _priv(t):
    return cast(t.privileged, String) != "[]"


async def groups(db, run: AdAuditRun, *, include_inactive=False) -> dict:
    """Привилегированные группы проверки: участники (с учётом вложенности и первичной группы), добавленные и исключённые с предыдущей проверки."""
    prev = await prev_run(db, run)
    cur = (await db.execute(Q.accounts(run, include_inactive=include_inactive).where(_priv(A)).order_by(A.login))).scalars().all()
    old_q = Q.accounts(prev, include_inactive=True).where(_priv(A)) if prev else None
    if old_q is not None and not include_inactive:
        current = aliased(A)
        old_q = old_q.where(Q.active(A, prev.started_at),
                            select(1).where(current.run_id == run.id, current.guid == A.guid, Q.active(current, run.started_at)).exists())
    old = (await db.execute(old_q.order_by(A.login))).scalars().all() if old_q is not None else []
    was = {(g, a.guid) for a in old for g in a.privileged}
    now = {(g, a.guid) for a in cur for g in a.privileged}
    out: dict[str, dict] = {}
    for a in cur:
        for g in a.privileged:
            out.setdefault(g, {"group": g, "members": [], "removed": []})["members"].append({**mini(a, run.started_at), "added": prev is not None and (g, a.guid) not in was})
    for a in old:
        for g in a.privileged:
            if (g, a.guid) not in now:
                out.setdefault(g, {"group": g, "members": [], "removed": []})["removed"].append(mini(a, prev.started_at))
    rank = {g: i for i, g in enumerate(GROUP_ORDER)}
    items = sorted(out.values(), key=lambda x: (rank.get(x["group"], len(rank)), x["group"].casefold()))
    return {"prev": _iso(prev.started_at) if prev else None, "items": items}


async def changes(db, run: AdAuditRun, *, include_inactive=False, limit=LIMIT) -> dict:
    """Изменения с предыдущей проверки: новые и удалённые учётные записи, отключение и включение, категория, подразделение, привилегированные группы."""
    prev = await prev_run(db, run)
    if prev is None:
        return {"prev": None, "counts": {}, "items": [], "truncated": False}
    P = aliased(A)
    counts: dict[str, int] = {}
    items: list[dict] = []
    scope = Q.account_scope(A, run.started_at, include_inactive)
    new_w = (A.run_id == run.id, scope, ~exists().where(P.run_id == prev.id, P.guid == A.guid))
    counts["new"] = (await db.execute(select(func.count()).select_from(A).where(*new_w))).scalar_one()
    for a in (await db.execute(select(A).where(*new_w).order_by(A.created.desc().nulls_last(), A.login).limit(limit))).scalars():
        items.append({**mini(a, run.started_at), "kind": "new", "before": "", "after": f"категория «{K.CATEGORY_RU.get(a.category, a.category)}»"})
    if include_inactive:
        gone_w = (P.run_id == prev.id, ~exists().where(A.run_id == run.id, A.guid == P.guid))
        counts["removed"] = (await db.execute(select(func.count()).select_from(P).where(*gone_w))).scalar_one()
        for a in (await db.execute(select(P).where(*gone_w).order_by(P.login).limit(limit))).scalars():
            m = mini(a, prev.started_at)
            items.append({**m, "kind": "removed", "before": m["state"], "after": ""})
    chg = (await db.execute(select(A, P).join(P, and_(P.run_id == prev.id, P.guid == A.guid)).where(A.run_id == run.id, scope, or_(A.enabled != P.enabled, A.category != P.category, A.ou != P.ou,
                                                                                                                               cast(A.privileged, String) != cast(P.privileged, String)))
                            .order_by(A.login).limit(limit))).all()
    truncated = len(chg) >= limit or counts["new"] > limit or counts.get("removed", 0) > limit
    for a, b in chg:
        m = mini(a, run.started_at)
        if a.enabled != b.enabled:
            items.append({**m, "kind": "enabled" if a.enabled else "disabled", "before": "активна" if b.enabled else "отключена", "after": "активна" if a.enabled else "отключена"})
        if a.category != b.category:
            items.append({**m, "kind": "category", "before": K.CATEGORY_RU.get(b.category, b.category), "after": K.CATEGORY_RU.get(a.category, a.category)})
        if a.ou != b.ou:
            items.append({**m, "kind": "moved", "before": b.ou or "корень домена", "after": a.ou or "корень домена"})
        added, dropped = sorted(set(a.privileged) - set(b.privileged)), sorted(set(b.privileged) - set(a.privileged))
        if added:
            items.append({**m, "kind": "priv_add", "before": ", ".join(b.privileged) or "нет", "after": ", ".join(added)})
        if dropped:
            items.append({**m, "kind": "priv_del", "before": ", ".join(dropped), "after": ", ".join(a.privileged) or "нет"})
    for x in items:
        x["kind_ru"] = KIND_RU[x["kind"]]
        if x["kind"] not in ("new", "removed"):
            counts[x["kind"]] = counts.get(x["kind"], 0) + 1
    return {"prev": _iso(prev.started_at), "counts": counts, "items": items, "truncated": truncated}
