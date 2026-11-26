"""Раздел «Аудит домена»: сводка, проверки (снимки) и их история, учётные записи с карточкой, замечания с решениями администратора, события смены и сброса пароля.

Данные читаются из сохранённых проверок (каталог страницами раздела не опрашивается); сбор — в worker. Доступ — специалист по ИБ и администратор.
Раздел только читает домен: ни одна операция не меняет учётные записи AD. Решения, категории и загрузки журналов пишутся в журнал действий."""
from __future__ import annotations

from datetime import date, datetime
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import Integer, and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..adaudit import checks as K
from ..adaudit import diff as DF
from ..adaudit import events as EV
from ..adaudit import query as Q
from ..adaudit import service as AS
from ..auth.deps import SessionUser, get_db, require_admin, require_security
from ..models import AdAuditAccount as A
from ..models import AdAuditDecision as D
from ..models import AdAuditFinding as Fd
from ..models import AdAuditRun, AdClassOverride, AdEventImport, AdPwdEvent, utcnow
from ..services.audit import write_audit
from ..services.settings import SettingsError

router = APIRouter(prefix="/adaudit", tags=["adaudit"])
DECISION_RU = {"open": "Открыто", "in_progress": "В работе", "fixed": "Отмечено устранённым", "exception": "Согласованное исключение"}


def _iso(d) -> str | None:
    return d.isoformat() if d else None


async def _run(db: AsyncSession, run_id: str | None) -> AdAuditRun | None:
    if run_id:
        try:
            import uuid  # noqa: PLC0415

            r = await db.get(AdAuditRun, uuid.UUID(run_id))
        except ValueError:
            r = None
        if r is None or r.status != "ok":
            raise HTTPException(status_code=404, detail="Проверка не найдена")
        return r
    return (await db.execute(select(AdAuditRun).where(AdAuditRun.status == "ok").order_by(AdAuditRun.started_at.desc()).limit(1))).scalar_one_or_none()


def _run_out(r: AdAuditRun | None, stats: dict | None = None) -> dict | None:
    if r is None:
        return None
    st = {k: v for k, v in (r.stats or {}).items() if k != "active_scope"} if stats is None else stats
    return {"id": str(r.id), "started_at": _iso(r.started_at), "finished_at": _iso(r.finished_at), "status": r.status, "kind": r.kind, "kind_ru": AS.KIND_RU.get(r.kind, r.kind), "by": r.by,
            "period": r.period, "domain": r.domain, "message": r.message, "stats": st, "coverage": r.coverage, "notes": r.notes, "policy": r.policy}


def _active_exception():
    return and_(D.state == "exception", or_(D.due.is_(None), D.due >= date.today()))


@router.get("/state")
async def state(request: Request, run: str | None = None, include_inactive: bool = False, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Сводка раздела: последняя успешная проверка и предыдущая (для динамики), идущая или запрошенная проверка, расписание, журналы событий, открытые замечания."""
    latest = await _run(db, None)
    current = await _run(db, run) if run else latest
    prev = await DF.prev_run(db, current) if current else None
    last_any = (await db.execute(select(AdAuditRun).order_by(AdAuditRun.started_at.desc()).limit(1))).scalar_one_or_none()
    st = await AS.get_state(request.app.state.session_maker)
    cfg = await request.app.state.settings_svc.get(db, "adaudit")
    imp = (await db.execute(select(AdEventImport).order_by(AdEventImport.at.desc()).limit(1))).scalar_one_or_none()
    open_n = exc_n = None
    by_code: list[dict] = []
    if current is not None:
        scoped = Q.findings(current, include_inactive=include_inactive)
        q = scoped.with_only_columns(Fd.code, Fd.severity, Fd.status, D.state, func.count()).group_by(Fd.code, Fd.severity, Fd.status, D.state)
        agg: dict[str, dict] = {}
        open_n = exc_n = 0
        for code, sev, status, dst, n in (await db.execute(q)).all():
            a = agg.setdefault(code, {"code": code, "title": K.CHECK_RU.get(code, code), "severity": sev, "status": status, "total": 0, "open": 0, "exception": 0, "in_progress": 0})
            if K.SEV_RANK[sev] > K.SEV_RANK[a["severity"]]:
                a["severity"] = sev
            if status == "violation":                  # вид замечания с нарушениями и случаями «проверить» — показывается как нарушение
                a["status"] = "violation"
            a["total"] += n
            key = "exception" if dst == "exception" else "in_progress" if dst == "in_progress" else "open"
            a[key] += n
        exc_rows = (await db.execute(select(func.count()).select_from(scoped.where(_active_exception()).subquery()))).scalar_one()
        for a in agg.values():
            open_n += a["open"] + a["in_progress"]
        exc_n = exc_rows
        by_code = sorted(agg.values(), key=lambda a: (-K.SEV_RANK[a["severity"]], -a["total"]))
    carried = 0
    if current is not None:
        carried = (await db.execute(select(func.count()).select_from(scoped.where(Fd.runs_n > 1).subquery()))).scalar_one()
    viewed = _run_out(current, await Q.stats(db, current, include_inactive=include_inactive)) if current else None
    totals = await Q.totals(db, [r for r in (latest, prev) if r and r != current]) if not include_inactive else {}
    return {"latest": viewed if current == latest else _run_out(latest, totals.get(latest.id) if latest else None),
            "viewed": viewed, "previous": _run_out(prev, totals.get(prev.id) if prev else None), "last": _run_out(last_any) if last_any is not None and (latest is None or last_any.id != latest.id) else None,
            "requested": bool(st.get("requested")), "next_run": st.get("next_run") if cfg.enabled else None, "schedule": {"enabled": cfg.enabled, "day": cfg.day_of_month, "time": cfg.schedule_time, "timezone": cfg.timezone},
            "import": {"at": _iso(imp.at), "by": imp.by, "file_name": imp.file_name, "events": imp.events, "added": imp.added, "dcs": imp.dcs} if imp else None,
            "open": open_n, "exceptions": exc_n, "carried": carried, "by_code": by_code, "policy": cfg.model_dump(include=AS.POLICY_FIELDS), "can_admin": su.is_admin}


class PolicyBody(BaseModel):
    pwd_days: dict[str, int] = Field(default_factory=dict)
    inactive_days: int = Field(ge=14, le=3650)
    new_days: int = Field(ge=1, le=365)
    grace_days: int = Field(ge=1, le=365)
    protected_users: bool = True
    policy_note: str = Field(default="", max_length=1000)


@router.put("/policy")
async def put_policy(body: PolicyBody, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Политика проверки из раздела: сроки паролей по категориям, пороги и основание (приказ, требования предприятия). Применяется со следующей проверки;
    у каждой проверки хранится политика, по которой она выполнена. Остальные настройки раздела (подключение, правила) не затрагиваются."""
    if set(body.pwd_days) - set(K.CATEGORY_RU) or any(not 1 <= v <= 3650 for v in body.pwd_days.values()):
        raise HTTPException(status_code=422, detail="Срок пароля — от 1 до 3650 суток для категорий: пользователь, административная, сервисная, временная, подрядчик")
    svc = request.app.state.settings_svc
    cur = await svc.get(db, "adaudit")
    patch = body.model_dump() | {"pwd_days": {**cur.pwd_days, **body.pwd_days}}
    try:
        changed = await svc.update(db, "adaudit", patch, actor=su.display_name)
    except SettingsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="adaudit.policy", target_type="settings", target_id="adaudit", details={"changed": changed, **{k: patch[k] for k in changed if k in patch}})
    await db.commit()
    return {"changed": changed, "policy": (await svc.get(db, "adaudit")).model_dump(include=AS.POLICY_FIELDS)}


@router.get("/groups")
async def priv_groups(run: str | None = None, include_inactive: bool = False, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Состав привилегированных групп в проверке и изменения с предыдущей (добавленные, исключённые)."""
    r = await _run(db, run)
    return {"prev": None, "items": []} if r is None else await DF.groups(db, r, include_inactive=include_inactive)


@router.get("/changes")
async def changes(run: str | None = None, include_inactive: bool = False, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Изменения учётных записей с предыдущей проверки."""
    r = await _run(db, run)
    return {"prev": None, "counts": {}, "items": [], "truncated": False} if r is None else await DF.changes(db, r, include_inactive=include_inactive)


@router.get("/policies")
async def policies(su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Политика, по которой выполнена каждая успешная проверка (история изменений сроков и порогов)."""
    rows = (await db.execute(select(AdAuditRun).where(AdAuditRun.status == "ok").order_by(AdAuditRun.started_at.desc()).limit(120))).scalars().all()
    return {"items": [{"id": str(r.id), "started_at": _iso(r.started_at), "kind_ru": AS.KIND_RU.get(r.kind, r.kind), "by": r.by, "policy": r.policy} for r in rows]}


class RunBody(BaseModel):
    kind: str = Field(default="manual", pattern=r"^(manual|quarterly)$")


@router.post("/run", status_code=202)
async def run_now(body: RunBody, request: Request, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    await AS.set_state(request.app.state.session_maker, requested={"kind": body.kind, "by": su.display_name})
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="adaudit.run", target_type="adaudit", target_id=body.kind, details={})
    await db.commit()
    return {"queued": True}


@router.get("/runs")
async def runs(include_inactive: bool = False, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(AdAuditRun).order_by(AdAuditRun.started_at.desc()).limit(120))).scalars().all()
    counts = await Q.totals(db, [r for r in rows if r.status == "ok"]) if not include_inactive else {}
    return {"items": [{k: v for k, v in _run_out(r, counts.get(r.id)).items() if k not in ("notes", "coverage")} for r in rows]}


ACC_SORT = {"name": A.name, "login": A.login, "pwd_age": A.pwd_age, "idle": A.idle_days, "created": A.created, "risk": A.max_sev, "findings": A.findings_n}


def _acc_out(a: A, at: datetime) -> dict:
    return {"guid": a.guid, "login": a.login, "name": a.name, "upn": a.upn, "mail": a.mail, "dn": a.dn, "ou": a.ou, "description": a.description, "title": a.title, "department": a.department, "manager": a.manager,
            "category": a.category, "category_ru": K.CATEGORY_RU.get(a.category, a.category), "category_basis": a.category_basis, "enabled": a.enabled, "locked": a.locked, "state": Q.account_state(a.enabled, a.locked, a.expires, at), "pne": a.pne,
            "must_change": a.must_change, "pwd_expired": a.pwd_expired, "pwd_last_set": _iso(a.pwd_last_set), "pwd_age": a.pwd_age, "pwd_bucket": a.pwd_bucket, "pwd_bucket_ru": K.BUCKET_RU.get(a.pwd_bucket, ""),
            "expires": _iso(a.expires), "last_logon": _iso(a.last_logon), "last_logon_src": a.last_logon_src, "idle_days": a.idle_days, "created": _iso(a.created), "privileged": a.privileged,
            "protected": a.protected, "spn": a.spn, "workstations": a.workstations, "groups": a.groups, "pwd_op": a.pwd_op, "findings_n": a.findings_n, "max_sev": a.max_sev}


@router.get("/accounts")
async def accounts(run: str | None = None, q: str = Query("", max_length=200), category: str = Query("", pattern=r"^(|user|admin|service|temp|contractor|undefined)$"),
                   view: str = Query("", pattern=r"^(|" + "|".join(Q.ACCOUNT_VIEWS) + ")$"), include_inactive: bool = False, bucket: str = Query("", pattern=r"^(|le30|le90|le180|gt180|unknown)$"), ou: str = Query("", max_length=200),
                   sort: str = Query("risk", pattern=r"^(name|login|pwd_age|idle|created|risk|findings)$"), desc: bool = True, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500),
                   su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    r = await _run(db, run)
    if r is None:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "run": None}
    stmt = Q.accounts(r, include_inactive=include_inactive, q=q, category=category, view=view, bucket=bucket, ou=ou)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    col = ACC_SORT[sort]
    order = [col.desc().nulls_last() if desc else col.asc().nulls_last(), A.login]
    rows = (await db.execute(stmt.order_by(*order).offset(offset).limit(limit))).scalars().all()
    stats = (await Q.totals(db, [r]))[r.id] if not include_inactive and view not in ("disabled", "locked", "expired") else None
    return {"items": [_acc_out(a, r.started_at) for a in rows], "total": total, "offset": offset, "limit": limit, "run": _run_out(r, stats) | {"notes": None}}


def _dec_out(d: D | None) -> dict | None:
    if d is None:
        return None
    return {"state": d.state, "state_ru": DECISION_RU.get(d.state, d.state), "comment": d.comment, "owner": d.owner, "due": _iso(d.due), "by": d.by, "at": _iso(d.at), "history": d.history[-20:],
            "expired": d.state == "exception" and d.due is not None and d.due < date.today()}


@router.get("/accounts/{guid}")
async def account_card(guid: str, run: str | None = None, include_inactive: bool = False, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Карточка учётной записи: состояние в проверке, категория и основания, замечания с решениями, события паролей, история по проверкам."""
    r = await _run(db, run)
    if r is None:
        raise HTTPException(status_code=404, detail="Проверок ещё не было")
    a = (await db.execute(Q.accounts(r, include_inactive=include_inactive).where(A.guid == guid))).scalar_one_or_none()
    if a is None:
        raise HTTPException(status_code=404, detail="Учётная запись не найдена в проверке")
    fs = (await db.execute(select(Fd, D).outerjoin(D, D.key == Fd.key).where(Fd.run_id == r.id, Fd.guid == guid).order_by(Fd.sev_rank.desc()))).all()
    evq = select(AdPwdEvent).where(or_(AdPwdEvent.target_sid == (a.sid or "-"), and_(AdPwdEvent.target_sid == "", func.lower(AdPwdEvent.target) == a.login.lower())))
    evs = (await db.execute(evq.order_by(AdPwdEvent.at.desc()).limit(100))).scalars().all()
    hist_q = select(AdAuditRun.started_at, AdAuditRun.kind, A.category, A.enabled, A.pwd_last_set, A.last_logon, A.findings_n).join(AdAuditRun, AdAuditRun.id == A.run_id).where(A.guid == guid, AdAuditRun.status == "ok").order_by(AdAuditRun.started_at.desc()).limit(24)
    hist = [{"at": _iso(at), "kind_ru": AS.KIND_RU.get(k, k), "category_ru": K.CATEGORY_RU.get(c, c), "enabled": en, "pwd_last_set": _iso(p), "last_logon": _iso(ll), "findings": n} for at, k, c, en, p, ll, n in (await db.execute(hist_q)).all()]
    ov = await db.get(AdClassOverride, guid)
    return {**_acc_out(a, r.started_at), "run": {"id": str(r.id), "started_at": _iso(r.started_at)}, "findings": [{**_find_out(f, a.ou, a.enabled, Q.account_state(a.enabled, a.locked, a.expires, r.started_at)), "decision": _dec_out(d)} for f, d in fs],
            "events": [{"at": _iso(e.at), "kind": e.kind, "kind_ru": "Сброс пароля (4724)" if e.kind == "reset" else "Смена пароля (4723)", "success": e.success, "by": f"{e.by_domain}\\{e.by}" if e.by_domain else e.by, "dc": e.dc} for e in evs],
            "history": hist, "override": {"category": ov.category, "note": ov.note, "by": ov.by, "at": _iso(ov.at)} if ov else None}


def _find_out(f: Fd, ou: str | None, enabled: bool | None, acc_state: str) -> dict:
    return {"ou": ou or "", "enabled": enabled, "acc_state": acc_state, "key": f.key, "guid": f.guid, "login": f.login, "name": f.name, "category": f.category, "category_ru": K.CATEGORY_RU.get(f.category, f.category), "code": f.code, "title": f.title,
            "severity": f.severity, "severity_ru": K.SEV_RU.get(f.severity, f.severity), "status": f.status, "status_ru": K.STATUS_RU.get(f.status, f.status), "basis": f.basis,
            "first_seen": _iso(f.first_seen), "runs_n": f.runs_n}


@router.get("/findings")
async def findings(run: str | None = None, q: str = Query("", max_length=200), code: str = Query("", max_length=24), severity: str = Query("", pattern=r"^(|critical|high|medium|low|high_or_critical)$"),
                   status: str = Query("", pattern=r"^(|violation|review)$"), category: str = Query("", pattern=r"^(|user|admin|service|temp|contractor|undefined)$"),
                   decision: str = Query("", pattern=r"^(|open|in_progress|fixed|exception|unresolved)$"), carried: bool = False, gone: bool = False,
                   ou: str = Query("", max_length=200), state: str = Query("", pattern=r"^(|enabled|disabled)$"), include_inactive: bool = False,
                   offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500), su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Замечания проверки. decision=unresolved — без решения, «в работе» и «отмечено устранённым», но обнаруженные снова (исключения не входят); carried — остались с прошлых проверок;
    gone — были в предыдущей проверке и в этой не обнаружены (устранены). ou — подразделение (часть пути или маска), state — состояние учётной записи."""
    r = await _run(db, run)
    if r is None:
        return {"items": [], "total": 0, "offset": offset, "limit": limit}
    snapshot = await DF.prev_run(db, r) if gone else r
    if snapshot is None:
        return {"items": [], "total": 0, "offset": offset, "limit": limit}
    stmt = Q.findings(snapshot, include_inactive=include_inactive, q=q, ou=ou, code=code, severity=severity, status=status,
                      category=category, decision=decision, carried=carried, state=state)
    if gone:
        stmt = Q.resolved(stmt, r, include_inactive=include_inactive, state=state)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(Fd.sev_rank.desc(), Fd.runs_n.desc(), Fd.login).offset(offset).limit(limit))).all()
    return {"items": [{**_find_out(f, o, en, Q.account_state(en, lk, exp, snapshot.started_at)), "decision": _dec_out(d)} for f, d, o, en, lk, exp in rows],
            "total": total, "offset": offset, "limit": limit}


@router.get("/ous")
async def ous(run: str | None = None, include_inactive: bool = False, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Подразделения (OU) проверки: учётных записей, активных, замечаний, требующих внимания (в т. ч. критических и высоких) — для отбора и обзора «где больше всего проблем»."""
    r = await _run(db, run)
    if r is None:
        return {"items": []}
    scope = Q.account_scope(A, r.started_at, include_inactive)
    acc = {o: (n, en) for o, n, en in (await db.execute(select(A.ou, func.count(), func.sum(func.cast(Q.active(A, r.started_at), Integer))).where(A.run_id == r.id, scope).group_by(A.ou))).all()}
    fq = (select(A.ou, func.count(), func.sum(func.cast(Fd.sev_rank >= 3, Integer)), func.count(func.distinct(Fd.guid)))
          .select_from(Fd).join(A, and_(A.run_id == Fd.run_id, A.guid == Fd.guid)).outerjoin(D, D.key == Fd.key).where(Fd.run_id == r.id, scope, Q.unresolved()).group_by(A.ou))
    fnd = {o: (n, hi or 0, g) for o, n, hi, g in (await db.execute(fq)).all()}
    items = [{"ou": o, "accounts": n, "enabled": int(en or 0), "open": fnd.get(o, (0, 0, 0))[0], "high": fnd.get(o, (0, 0, 0))[1], "with_findings": fnd.get(o, (0, 0, 0))[2]} for o, (n, en) in acc.items()]
    items.sort(key=lambda x: (-x["high"], -x["open"], -x["accounts"], x["ou"]))
    return {"items": items}


class DecisionBody(BaseModel):
    keys: list[str] = Field(min_length=1, max_length=2000)
    state: str = Field(pattern=r"^(open|in_progress|fixed|exception)$")
    comment: str = Field(default="", max_length=4000)
    owner: str = Field(default="", max_length=200)
    due: date | None = None


@router.put("/decisions")
async def decide(body: DecisionBody, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Решение по замечаниям (сразу по нескольким): статус, комментарий, ответственный, срок. Прежние значения сохраняются в истории решения."""
    if body.state == "exception" and not body.comment.strip():
        raise HTTPException(status_code=422, detail="Для согласованного исключения укажите основание в комментарии (кем и когда согласовано)")
    keys = list(dict.fromkeys(k for k in body.keys if ":" in k and len(k) <= 80))
    now = utcnow()
    have = {d.key: d for d in (await db.execute(select(D).where(D.key.in_(keys)))).scalars().all()}
    logins = dict((await db.execute(select(Fd.key, Fd.login).where(Fd.key.in_(keys)).distinct())).all())
    for k in keys:
        d = have.get(k)
        entry = {"at": now.isoformat(), "by": su.display_name, "state": body.state, "comment": body.comment, "owner": body.owner, "due": _iso(body.due)}
        if d is None:
            guid, code = k.rsplit(":", 1)
            db.add(D(key=k, guid=guid, code=code, login=logins.get(k, "")[:256], state=body.state, comment=body.comment, owner=body.owner, due=body.due, by=su.display_name, at=now, history=[entry]))
        else:
            d.state, d.comment, d.owner, d.due, d.by, d.at = body.state, body.comment, body.owner, body.due, su.display_name, now
            d.history = [*(d.history or []), entry][-100:]
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="adaudit.decision", target_type="adaudit", target_id=body.state, details={"keys": keys[:50], "n": len(keys), "owner": body.owner, "due": _iso(body.due)})
    await db.commit()
    return {"updated": len(keys)}


class CategoryBody(BaseModel):
    category: str | None = Field(default=None, pattern=r"^(user|admin|service|temp|contractor)$")
    note: str = Field(default="", max_length=300)


@router.put("/accounts/{guid}/category")
async def set_category(guid: str, body: CategoryBody, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Категория вручную (важнее правил); null — вернуть определение по правилам. Применяется со следующей проверки."""
    login = (await db.execute(select(A.login).where(A.guid == guid).limit(1))).scalar_one_or_none()
    if login is None:
        raise HTTPException(status_code=404, detail="Учётная запись не найдена в проверках")
    ov = await db.get(AdClassOverride, guid)
    if body.category is None:
        if ov is not None:
            await db.delete(ov)
    elif ov is None:
        db.add(AdClassOverride(guid=guid, login=login, category=body.category, note=body.note, by=su.display_name, at=utcnow()))
    else:
        ov.category, ov.note, ov.by, ov.at = body.category, body.note, su.display_name, utcnow()
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="adaudit.category", target_type="adaudit", target_id=login, details={"category": body.category, "note": body.note})
    await db.commit()
    return {"ok": True}


@router.get("/events")
async def events(run: str | None = None, include_inactive: bool = False, kind: str = Query("", pattern=r"^(|change|reset)$"), success: bool | None = None, q: str = Query("", max_length=200), offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500),
                 su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    latest = await _run(db, run)
    stmt = Q.event_query(latest, include_inactive=include_inactive, kind=kind, success=success, q=q)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(AdPwdEvent.at.desc()).offset(offset).limit(limit))).scalars().all()
    names: dict[str, tuple[str, str]] = {}
    if latest is not None and rows:
        sids = {e.target_sid for e in rows if e.target_sid}
        for sid, guid, name in (await db.execute(select(A.sid, A.guid, A.name).where(A.run_id == latest.id, A.sid.in_(sids)))).all():
            names[sid] = (guid, name)
    return {"items": [{"at": _iso(e.at), "kind": e.kind, "kind_ru": "Сброс пароля" if e.kind == "reset" else "Смена пароля пользователем", "event_id": 4724 if e.kind == "reset" else 4723,
                       "success": e.success, "target": f"{e.target_domain}\\{e.target}" if e.target_domain else e.target, "target_guid": names.get(e.target_sid, ("", ""))[0],
                       "target_name": names.get(e.target_sid, ("", ""))[1], "by": f"{e.by_domain}\\{e.by}" if e.by_domain else e.by, "dc": e.dc} for e in rows],
            "total": total, "offset": offset, "limit": limit}


@router.get("/imports")
async def imports(su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(AdEventImport).order_by(AdEventImport.at.desc()).limit(50))).scalars().all()
    cov = await AS.coverage(db)
    return {"items": [{"at": _iso(i.at), "by": i.by, "file_name": i.file_name, "events": i.events, "added": i.added, "skipped": i.skipped, "dcs": i.dcs} for i in rows],
            "coverage": {k: [_iso(a), _iso(b)] for k, (a, b) in cov.dcs.items()}}


@router.post("/events/import")
async def import_events(request: Request, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Загрузка выгрузки скрипта Export-KavPasswordEvents.ps1 (тело запроса — файл JSON, имя — заголовок X-File-Name)."""
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > EV.MAX_BYTES:
            raise HTTPException(status_code=413, detail="Файл слишком большой: выгрузите период короче")
    try:
        parsed = EV.parse(bytes(buf))
    except EV.EventsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    name = unquote(request.headers.get("x-file-name", "") or "events.json")[:300]
    imp = await AS.import_events(request.app.state.session_maker, parsed, file_name=name, by=su.display_name)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="adaudit.import", target_type="adaudit", target_id=name[:120], details={"events": imp.events, "added": imp.added, "dcs": len(imp.dcs)})
    await db.commit()
    return {"events": imp.events, "added": imp.added, "skipped": imp.skipped, "dcs": imp.dcs,
            "note": "События учитываются при следующей проверке: запустите её, чтобы обновить способ последней операции с паролем." if imp.added else "Новых событий нет: все уже загружены ранее."}
