"""Общий отбор снимка аудита для раздела и отчётов."""
from datetime import date, timedelta

from sqlalchemy import String, and_, case, cast, func, or_, select
from sqlalchemy.orm import aliased

from ..models import AdAuditAccount as A
from ..models import AdAuditDecision as D
from ..models import AdAuditFinding as F
from ..models import AdAuditRun as R
from ..models import AdPwdEvent as E
from ..search import column_like

ACCOUNT_VIEWS = ("enabled", "disabled", "locked", "must_change", "expired", "new", "pne", "privileged", "inactive", "never", "with_findings", "reset", "no_logs_op")


def active(table, at):
    return and_(table.enabled.is_(True), table.locked.is_(False), or_(table.expires.is_(None), table.expires > at))


def account_state(enabled, locked, expires, at):
    if enabled is None:
        return ""
    if not enabled:
        return "отключена"
    if locked:
        return "заблокирована"
    return "истёк срок действия" if expires and expires <= at else "активна"


def account_scope(table, at, include_inactive=False, state=""):
    if state == "disabled":
        return table.enabled.is_(False)
    return True if include_inactive and state != "enabled" else active(table, at)


def accounts(run, *, include_inactive=False, q="", category="", view="", bucket="", ou=""):
    pol = run.policy or {}
    at = run.started_at
    stmt = select(A).where(A.run_id == run.id)
    if q.strip():
        stmt = stmt.where(or_(*(column_like(col, q.strip()) for col in (A.login, A.name, A.upn, A.description, A.department, A.ou))))
    if ou.strip():
        stmt = stmt.where(column_like(A.ou, ou.strip()))
    if category:
        stmt = stmt.where(A.category == category)
    if view == "disabled":
        return stmt.where(A.enabled.is_(False))
    if view == "locked":
        return stmt.where(A.locked.is_(True))
    if view == "expired":
        return stmt.where(A.expires <= at)
    stmt = stmt.where(account_scope(A, at, include_inactive, view))
    if bucket:
        stmt = stmt.where(A.pwd_bucket == bucket)
    condition = {
        "must_change": A.must_change.is_(True),
        "new": A.created >= at - timedelta(days=int(pol.get("new_days") or 30)),
        "pne": A.pne.is_(True),
        "privileged": A.category.in_(("admin", "service")),
        "inactive": A.idle_days > int(pol.get("inactive_days") or 90),
        "never": A.last_logon.is_(None),
        "with_findings": A.findings_n > 0,
        "reset": A.guid.in_(select(F.guid).where(F.run_id == run.id, F.code == "reset")),
    }.get(view)
    return stmt.where(condition) if condition is not None else stmt


def unresolved():
    return or_(D.key.is_(None), D.state.in_(("open", "in_progress", "fixed")), and_(D.state == "exception", D.due.is_not(None), D.due < date.today()))


def findings(run, *, include_inactive=False, q="", ou="", code="", severity="", status="", category="", decision="", carried=False, state=""):
    stmt = (select(F, D, A.ou, A.enabled, A.locked, A.expires)
            .outerjoin(D, D.key == F.key).outerjoin(A, and_(A.run_id == F.run_id, A.guid == F.guid))
            .where(F.run_id == run.id, account_scope(A, run.started_at, include_inactive, state)))
    if q.strip():
        stmt = stmt.where(or_(*(column_like(col, q.strip()) for col in (F.login, F.name, A.ou))))
    if ou.strip():
        stmt = stmt.where(column_like(A.ou, ou.strip()))
    for col, val in ((F.code, code), (F.status, status), (F.category, category)):
        if val:
            stmt = stmt.where(col == val)
    if severity:
        stmt = stmt.where(F.severity.in_(("critical", "high")) if severity == "high_or_critical" else F.severity == severity)
    if carried:
        stmt = stmt.where(F.runs_n > 1)
    if decision == "unresolved":
        stmt = stmt.where(unresolved())
    elif decision == "open":
        stmt = stmt.where(or_(D.key.is_(None), D.state == "open"))
    elif decision:
        stmt = stmt.where(D.state == decision)
    return stmt


def resolved(stmt, current, *, include_inactive=False, state=""):
    prior = aliased(F)
    stmt = stmt.where(~select(1).where(prior.run_id == current.id, prior.key == F.key).exists())
    if not include_inactive and state != "disabled":
        target = aliased(A)
        stmt = stmt.where(select(1).where(target.run_id == current.id, target.guid == F.guid, active(target, current.started_at)).exists())
    return stmt


def event_query(run, *, include_inactive=False, kind="", success=None, q=""):
    stmt = select(E)
    if not include_inactive:
        if run is None:
            return stmt.where(False)
        scope = (A.run_id == run.id, active(A, run.started_at))
        sids = select(A.sid).where(*scope, A.sid != "")
        logins = select(func.lower(A.login)).where(*scope, A.login != "")
        stmt = stmt.where(or_(E.target_sid.in_(sids), and_(E.target_sid == "", func.lower(E.target).in_(logins))))
    if kind:
        stmt = stmt.where(E.kind == kind)
    if success is not None:
        stmt = stmt.where(E.success.is_(success))
    if q.strip():
        stmt = stmt.where(or_(column_like(E.target, q.strip()), column_like(E.by, q.strip())))
    return stmt


async def totals(db, runs):
    out = {run.id: run.stats["active_scope"] for run in runs if "active_scope" in (run.stats or {})}
    ids = [run.id for run in runs if run.id not in out]
    if not ids:
        return out
    scope = A.run_id.in_(ids)
    acc = (await db.execute(select(A.run_id, func.count()).join(R, R.id == A.run_id)
                            .where(scope, active(A, R.started_at)).group_by(A.run_id))).all()
    found = (await db.execute(select(F.run_id, F.status, func.count()).join(A, and_(A.run_id == F.run_id, A.guid == F.guid))
                              .join(R, R.id == A.run_id).where(scope, active(A, R.started_at)).group_by(F.run_id, F.status))).all()
    out.update({rid: {"accounts": 0, "enabled": 0, "findings": 0, "f_violation": 0} for rid in ids})
    for run_id, n in acc:
        out[run_id].update(accounts=n, enabled=n)
    for run_id, status, n in found:
        out[run_id]["findings"] += n
        out[run_id][f"f_{status}"] = n
    return out


async def stats(db, run, *, include_inactive=False):
    saved = run.stats or {}
    if include_inactive:
        return {k: v for k, v in saved.items() if k != "active_scope"}
    if "active_scope" in saved:
        return saved["active_scope"]
    scope = (A.run_id == run.id, active(A, run.started_at))
    pol = run.policy or {}
    inactive = int(pol.get("inactive_days") or 90)
    inactive_since = run.started_at - timedelta(days=inactive)
    aggregate = {
        "pne": A.pne.is_(True), "must_change": A.must_change.is_(True),
        "inactive": or_(A.idle_days > inactive, and_(A.last_logon.is_(None), A.created < inactive_since)),
        "privileged": cast(A.privileged, String) != "[]",
        "new": A.created >= run.started_at - timedelta(days=int(pol.get("new_days") or 30)),
    }
    counts = (await db.execute(select(func.count(), *(func.coalesce(func.sum(case((cond, 1), else_=0)), 0)
                                                    for cond in aggregate.values())).where(*scope))).one()
    result = dict(zip(aggregate, counts[1:]))
    result.update(accounts=counts[0], enabled=counts[0], findings=0, f_violation=0, have_logs=saved.get("have_logs", 0))
    for col, prefix in ((A.category, "cat_"), (A.pwd_bucket, "pwd_"), (A.pwd_op["state"].as_string(), "op_")):
        pairs = (await db.execute(select(col, func.count()).where(*scope).group_by(col))).all()
        result.update((f"{prefix}{key}", n) for key, n in pairs if key)
    joined = and_(A.run_id == F.run_id, A.guid == F.guid)
    found = (await db.execute(select(F.status, F.code, func.count()).join(A, joined).where(*scope).group_by(F.status, F.code))).all()
    for status, code, count in found:
        result["findings"] = result.get("findings", 0) + count
        result[f"f_{status}"] = result.get(f"f_{status}", 0) + count
        if code == "reset":
            result["reset_pending"] = count
    previous = (await db.execute(select(R).where(R.status == "ok", R.started_at < run.started_at)
                                 .order_by(R.started_at.desc()).limit(1))).scalar_one_or_none()
    if previous is not None:
        result["prev_run"] = str(previous.id)
        previous_keys = select(F.key).where(F.run_id == previous.id)
        result["new_since_prev"] = (await db.execute(select(func.count()).select_from(F).join(A, joined)
                                                    .where(*scope, F.key.not_in(previous_keys)))).scalar_one()
        fixed = resolved(findings(previous), run).subquery()
        result["fixed_since_prev"] = (await db.execute(select(func.count()).select_from(fixed))).scalar_one()
    return result
