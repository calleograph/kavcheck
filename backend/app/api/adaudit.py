"""Раздел «Аудит домена»: сводка, проверки (снимки) и их история, учётные записи с карточкой, замечания с решениями администратора, события смены и сброса пароля.

Данные читаются из сохранённых проверок (каталог страницами раздела не опрашивается); сбор — в worker. Доступ — специалист по ИБ и администратор.
Раздел только читает домен: ни одна операция не меняет учётные записи AD. Решения, категории и загрузки журналов пишутся в журнал действий."""
from __future__ import annotations

from datetime import date, datetime, timezone
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..adaudit import checks as K
from ..adaudit import events as EV
from ..adaudit import service as AS
from ..auth.deps import SessionUser, get_db, require_security
from ..models import AdAuditAccount as A
from ..models import AdAuditDecision as D
from ..models import AdAuditFinding as Fd
from ..models import AdAuditRun, AdClassOverride, AdEventImport, AdPwdEvent, utcnow
from ..search import column_like
from ..services.audit import write_audit

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


def _run_out(r: AdAuditRun | None) -> dict | None:
    if r is None:
        return None
    return {"id": str(r.id), "started_at": _iso(r.started_at), "finished_at": _iso(r.finished_at), "status": r.status, "kind": r.kind, "kind_ru": AS.KIND_RU.get(r.kind, r.kind), "by": r.by,
            "period": r.period, "domain": r.domain, "message": r.message, "stats": r.stats, "coverage": r.coverage, "notes": r.notes, "policy": r.policy}


def _active_exception():
    return and_(D.state == "exception", or_(D.due.is_(None), D.due >= date.today()))


@router.get("/state")
async def state(request: Request, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Сводка раздела: последняя успешная проверка и предыдущая (для динамики), идущая или запрошенная проверка, расписание, журналы событий, открытые замечания."""
    latest = await _run(db, None)
    prev = None
    if latest is not None:
        prev = (await db.execute(select(AdAuditRun).where(AdAuditRun.status == "ok", AdAuditRun.started_at < latest.started_at).order_by(AdAuditRun.started_at.desc()).limit(1))).scalar_one_or_none()
    last_any = (await db.execute(select(AdAuditRun).order_by(AdAuditRun.started_at.desc()).limit(1))).scalar_one_or_none()
    st = await AS.get_state(request.app.state.session_maker)
    cfg = await request.app.state.settings_svc.get(db, "adaudit")
    imp = (await db.execute(select(AdEventImport).order_by(AdEventImport.at.desc()).limit(1))).scalar_one_or_none()
    open_n = exc_n = None
    by_code: list[dict] = []
    if latest is not None:
        q = select(Fd.code, Fd.severity, Fd.status, D.state, func.count()).outerjoin(D, D.key == Fd.key).where(Fd.run_id == latest.id).group_by(Fd.code, Fd.severity, Fd.status, D.state)
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
        exc_rows = (await db.execute(select(func.count()).select_from(Fd).join(D, D.key == Fd.key).where(Fd.run_id == latest.id, _active_exception()))).scalar_one()
        for a in agg.values():
            open_n += a["open"] + a["in_progress"]
        exc_n = exc_rows
        by_code = sorted(agg.values(), key=lambda a: (-K.SEV_RANK[a["severity"]], -a["total"]))
    carried = 0
    if latest is not None:
        carried = (await db.execute(select(func.count()).select_from(Fd).where(Fd.run_id == latest.id, Fd.runs_n > 1))).scalar_one()
    return {"latest": _run_out(latest), "previous": _run_out(prev), "last": _run_out(last_any) if last_any is not None and (latest is None or last_any.id != latest.id) else None,
            "requested": bool(st.get("requested")), "next_run": st.get("next_run") if cfg.enabled else None, "schedule": {"enabled": cfg.enabled, "day": cfg.day_of_month, "time": cfg.schedule_time, "timezone": cfg.timezone},
            "import": {"at": _iso(imp.at), "by": imp.by, "file_name": imp.file_name, "events": imp.events, "added": imp.added, "dcs": imp.dcs} if imp else None,
            "open": open_n, "exceptions": exc_n, "carried": carried, "by_code": by_code, "policy": cfg.model_dump(include={"pwd_days", "inactive_days", "new_days", "grace_days"}), "can_admin": su.is_admin}


class RunBody(BaseModel):
    kind: str = Field(default="manual", pattern=r"^(manual|quarterly)$")


@router.post("/run", status_code=202)
async def run_now(body: RunBody, request: Request, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    await AS.set_state(request.app.state.session_maker, requested={"kind": body.kind, "by": su.display_name})
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="adaudit.run", target_type="adaudit", target_id=body.kind, details={})
    await db.commit()
    return {"queued": True}


@router.get("/runs")
async def runs(su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(AdAuditRun).order_by(AdAuditRun.started_at.desc()).limit(120))).scalars().all()
    return {"items": [{k: v for k, v in _run_out(r).items() if k not in ("notes", "coverage")} for r in rows]}


ACC_SORT = {"name": A.name, "login": A.login, "pwd_age": A.pwd_age, "idle": A.idle_days, "created": A.created, "risk": A.max_sev, "findings": A.findings_n}
VIEWS = ("enabled", "disabled", "locked", "must_change", "expired", "new", "pne", "privileged", "inactive", "never", "with_findings", "reset", "no_logs_op")


def _acc_filter(stmt, run: AdAuditRun, *, q: str, category: str, view: str, bucket: str, now: datetime):
    pol = run.policy or {}
    if q:
        stmt = stmt.where(or_(column_like(A.login, q), column_like(A.name, q), column_like(A.upn, q), column_like(A.description, q), column_like(A.department, q)))
    if category:
        stmt = stmt.where(A.category == category)
    if bucket:
        stmt = stmt.where(A.pwd_bucket == bucket, A.enabled.is_(True))
    inactive = int(pol.get("inactive_days") or 90)
    if view == "enabled":
        stmt = stmt.where(A.enabled.is_(True))
    elif view == "disabled":
        stmt = stmt.where(A.enabled.is_(False))
    elif view == "locked":
        stmt = stmt.where(A.locked.is_(True))
    elif view == "must_change":
        stmt = stmt.where(A.must_change.is_(True), A.enabled.is_(True))
    elif view == "expired":
        stmt = stmt.where(A.expires.is_not(None), A.expires < run.started_at)
    elif view == "new":
        from datetime import timedelta  # noqa: PLC0415

        stmt = stmt.where(A.created >= run.started_at - timedelta(days=int(pol.get("new_days") or 30)))
    elif view == "pne":
        stmt = stmt.where(A.pne.is_(True))
    elif view == "privileged":
        stmt = stmt.where(A.category.in_(("admin", "service")))
    elif view == "inactive":
        stmt = stmt.where(A.enabled.is_(True), A.idle_days > inactive)
    elif view == "never":
        stmt = stmt.where(A.enabled.is_(True), A.last_logon.is_(None))
    elif view == "with_findings":
        stmt = stmt.where(A.findings_n > 0)
    elif view == "reset":
        stmt = stmt.where(A.guid.in_(select(Fd.guid).where(Fd.run_id == run.id, Fd.code == "reset")))
    return stmt


def _acc_out(a: A) -> dict:
    return {"guid": a.guid, "login": a.login, "name": a.name, "upn": a.upn, "mail": a.mail, "dn": a.dn, "description": a.description, "title": a.title, "department": a.department, "manager": a.manager,
            "category": a.category, "category_ru": K.CATEGORY_RU.get(a.category, a.category), "category_basis": a.category_basis, "enabled": a.enabled, "locked": a.locked, "pne": a.pne,
            "must_change": a.must_change, "pwd_expired": a.pwd_expired, "pwd_last_set": _iso(a.pwd_last_set), "pwd_age": a.pwd_age, "pwd_bucket": a.pwd_bucket, "pwd_bucket_ru": K.BUCKET_RU.get(a.pwd_bucket, ""),
            "expires": _iso(a.expires), "last_logon": _iso(a.last_logon), "last_logon_src": a.last_logon_src, "idle_days": a.idle_days, "created": _iso(a.created), "privileged": a.privileged,
            "protected": a.protected, "spn": a.spn, "workstations": a.workstations, "groups": a.groups, "pwd_op": a.pwd_op, "findings_n": a.findings_n, "max_sev": a.max_sev}


@router.get("/accounts")
async def accounts(run: str | None = None, q: str = Query("", max_length=200), category: str = Query("", pattern=r"^(|user|admin|service|temp|contractor|undefined)$"),
                   view: str = Query("", pattern=r"^(|" + "|".join(VIEWS) + ")$"), bucket: str = Query("", pattern=r"^(|le30|le90|le180|gt180|unknown)$"),
                   sort: str = Query("risk", pattern=r"^(name|login|pwd_age|idle|created|risk|findings)$"), desc: bool = True, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500),
                   su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    r = await _run(db, run)
    if r is None:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "run": None}
    stmt = _acc_filter(select(A).where(A.run_id == r.id), r, q=q.strip(), category=category, view=view, bucket=bucket, now=utcnow())
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    col = ACC_SORT[sort]
    order = [col.desc().nulls_last() if desc else col.asc().nulls_last(), A.login]
    rows = (await db.execute(stmt.order_by(*order).offset(offset).limit(limit))).scalars().all()
    return {"items": [_acc_out(a) for a in rows], "total": total, "offset": offset, "limit": limit, "run": _run_out(r) | {"notes": None}}


def _dec_out(d: D | None) -> dict | None:
    if d is None:
        return None
    return {"state": d.state, "state_ru": DECISION_RU.get(d.state, d.state), "comment": d.comment, "owner": d.owner, "due": _iso(d.due), "by": d.by, "at": _iso(d.at), "history": d.history[-20:],
            "expired": d.state == "exception" and d.due is not None and d.due < date.today()}


@router.get("/accounts/{guid}")
async def account_card(guid: str, run: str | None = None, su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Карточка учётной записи: состояние в проверке, категория и основания, замечания с решениями, события паролей, история по проверкам."""
    r = await _run(db, run)
    if r is None:
        raise HTTPException(status_code=404, detail="Проверок ещё не было")
    a = (await db.execute(select(A).where(A.run_id == r.id, A.guid == guid))).scalar_one_or_none()
    if a is None:
        raise HTTPException(status_code=404, detail="Учётная запись не найдена в проверке")
    fs = (await db.execute(select(Fd, D).outerjoin(D, D.key == Fd.key).where(Fd.run_id == r.id, Fd.guid == guid).order_by(Fd.sev_rank.desc()))).all()
    evq = select(AdPwdEvent).where(or_(AdPwdEvent.target_sid == (a.sid or "-"), and_(AdPwdEvent.target_sid == "", func.lower(AdPwdEvent.target) == a.login.lower())))
    evs = (await db.execute(evq.order_by(AdPwdEvent.at.desc()).limit(100))).scalars().all()
    hist_q = select(AdAuditRun.started_at, AdAuditRun.kind, A.category, A.enabled, A.pwd_last_set, A.last_logon, A.findings_n).join(AdAuditRun, AdAuditRun.id == A.run_id).where(A.guid == guid, AdAuditRun.status == "ok").order_by(AdAuditRun.started_at.desc()).limit(24)
    hist = [{"at": _iso(at), "kind_ru": AS.KIND_RU.get(k, k), "category_ru": K.CATEGORY_RU.get(c, c), "enabled": en, "pwd_last_set": _iso(p), "last_logon": _iso(ll), "findings": n} for at, k, c, en, p, ll, n in (await db.execute(hist_q)).all()]
    ov = await db.get(AdClassOverride, guid)
    return {**_acc_out(a), "run": {"id": str(r.id), "started_at": _iso(r.started_at)}, "findings": [{**_find_out(f), "decision": _dec_out(d)} for f, d in fs],
            "events": [{"at": _iso(e.at), "kind": e.kind, "kind_ru": "Сброс пароля (4724)" if e.kind == "reset" else "Смена пароля (4723)", "success": e.success, "by": f"{e.by_domain}\\{e.by}" if e.by_domain else e.by, "dc": e.dc} for e in evs],
            "history": hist, "override": {"category": ov.category, "note": ov.note, "by": ov.by, "at": _iso(ov.at)} if ov else None}


def _find_out(f: Fd) -> dict:
    return {"key": f.key, "guid": f.guid, "login": f.login, "name": f.name, "category": f.category, "category_ru": K.CATEGORY_RU.get(f.category, f.category), "code": f.code, "title": f.title,
            "severity": f.severity, "severity_ru": K.SEV_RU.get(f.severity, f.severity), "status": f.status, "status_ru": K.STATUS_RU.get(f.status, f.status), "basis": f.basis,
            "first_seen": _iso(f.first_seen), "runs_n": f.runs_n}


@router.get("/findings")
async def findings(run: str | None = None, q: str = Query("", max_length=200), code: str = Query("", max_length=24), severity: str = Query("", pattern=r"^(|critical|high|medium|low)$"),
                   status: str = Query("", pattern=r"^(|violation|review)$"), category: str = Query("", pattern=r"^(|user|admin|service|temp|contractor|undefined)$"),
                   decision: str = Query("", pattern=r"^(|open|in_progress|fixed|exception|unresolved)$"), carried: bool = False, gone: bool = False,
                   offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500), su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    """Замечания проверки. decision=unresolved — без решения, «в работе» и «отмечено устранённым», но обнаруженные снова (исключения не входят); carried — остались с прошлых проверок;
    gone — были в предыдущей проверке и в этой не обнаружены (устранены)."""
    r = await _run(db, run)
    if r is None:
        return {"items": [], "total": 0, "offset": offset, "limit": limit}
    rid = r.id
    if gone:
        prev = (await db.execute(select(AdAuditRun.id).where(AdAuditRun.status == "ok", AdAuditRun.started_at < r.started_at).order_by(AdAuditRun.started_at.desc()).limit(1))).scalar_one_or_none()
        if prev is None:
            return {"items": [], "total": 0, "offset": offset, "limit": limit}
        rid = prev
    stmt = select(Fd, D).outerjoin(D, D.key == Fd.key).where(Fd.run_id == rid)
    if gone:
        stmt = stmt.where(Fd.key.not_in(select(Fd.key).where(Fd.run_id == r.id)))
    if q.strip():
        stmt = stmt.where(or_(column_like(Fd.login, q.strip()), column_like(Fd.name, q.strip())))
    for colm, val in ((Fd.code, code), (Fd.severity, severity), (Fd.status, status), (Fd.category, category)):
        if val:
            stmt = stmt.where(colm == val)
    if carried:
        stmt = stmt.where(Fd.runs_n > 1)
    if decision == "unresolved":
        stmt = stmt.where(or_(D.key.is_(None), D.state.in_(("open", "in_progress", "fixed")), and_(D.state == "exception", D.due.is_not(None), D.due < date.today())))
    elif decision == "open":
        stmt = stmt.where(or_(D.key.is_(None), D.state == "open"))
    elif decision:
        stmt = stmt.where(D.state == decision)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(Fd.sev_rank.desc(), Fd.runs_n.desc(), Fd.login).offset(offset).limit(limit))).all()
    return {"items": [{**_find_out(f), "decision": _dec_out(d)} for f, d in rows], "total": total, "offset": offset, "limit": limit}


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
async def events(kind: str = Query("", pattern=r"^(|change|reset)$"), success: bool | None = None, q: str = Query("", max_length=200), offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500),
                 su: SessionUser = Depends(require_security), db: AsyncSession = Depends(get_db)):
    stmt = select(AdPwdEvent)
    if kind:
        stmt = stmt.where(AdPwdEvent.kind == kind)
    if success is not None:
        stmt = stmt.where(AdPwdEvent.success.is_(success))
    if q.strip():
        stmt = stmt.where(or_(column_like(AdPwdEvent.target, q.strip()), column_like(AdPwdEvent.by, q.strip())))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(AdPwdEvent.at.desc()).offset(offset).limit(limit))).scalars().all()
    latest = await _run(db, None)
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
