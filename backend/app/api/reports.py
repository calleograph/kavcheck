"""Отчёты: постановка в очередь (в том числе проверка версий по нескольким источникам), состояние, просмотр с фильтрами и сортировкой,
экспорт CSV/XLSX, отмена, повтор, шаблоны, сохранённые проверки версий."""
from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_analyst, require_user
from ..ksc import versions
from ..search import any_field
from ..models import AuditCheck, KscSource, ReportJob, ReportTemplate, utcnow
from ..reports import audit, quick
from ..reports.export import read_all_jsonl
from ..reports.runner import job_dir
from ..services.audit import write_audit
from .schemas import QUICK_PARAMS, AuditParams, ReportIn, ReportParams, SavedCheckIn, TemplateIn

router = APIRouter(prefix="/reports", tags=["reports"])
KIND_TITLE = {"software_hosts": "Компьютеры с программами", "hosts": "Компьютеры и активность", "version_audit": "Проверка версий", **quick.KIND_TITLE}


def job_sources(j: ReportJob) -> list[str]:
    return [str(x) for x in (j.source_ids or ([str(j.source_id)] if j.source_id else []))]


def job_out(j: ReportJob) -> dict:
    return {"id": str(j.id), "source_id": str(j.source_id) if j.source_id else None, "source_ids": job_sources(j), "source_name": j.source_name, "kind": j.kind,
            "title": j.title, "params": j.params, "status": j.status, "progress": j.progress, "created_by": j.created_by, "created_at": j.created_at,
            "started_at": j.started_at, "finished_at": j.finished_at, "data_fetched_at": j.data_fetched_at, "rows": j.rows, "summary": j.summary, "error": j.error}


def can_see(su: SessionUser, j: ReportJob) -> bool:
    if j.kind == "quick_bi":                              # сведения о сотрудниках BI: аналитик и администратор с доступом ко всем источникам
        return su.role in ("analyst", "admin") and (su.is_admin or su.all_sources)
    if j.kind in ("quick_pentest", "quick_hunt"):          # результаты сканирования не принадлежат источнику KSC: права — аналитик и администратор
        return su.role in ("analyst", "admin")
    ids = job_sources(j)
    return bool(ids) and all(su.can_use_source(uuid.UUID(i)) for i in ids)


async def _job(db: AsyncSession, job_id: uuid.UUID, su: SessionUser) -> ReportJob:
    j = await db.get(ReportJob, job_id)
    if j is None or not can_see(su, j):
        raise HTTPException(status_code=404, detail="Отчёт не найден")
    return j


async def _sources(db: AsyncSession, su: SessionUser, ids: list[uuid.UUID], fallback: uuid.UUID | None) -> list[KscSource]:
    ids = ids or ([fallback] if fallback else [])
    if not ids:
        raise HTTPException(status_code=409, detail={"code": "no_source", "message": "Источник KSC не выбран."})
    out = []
    for i in dict.fromkeys(ids):
        s = await db.get(KscSource, i)
        if s is None or not s.is_active:
            raise HTTPException(status_code=409, detail="Источник не найден или выключен")
        if not su.can_use_source(s.id):
            raise HTTPException(status_code=403, detail=f"Нет доступа к источнику «{s.name}»")
        out.append(s)
    return out


def validate_params(kind: str, params: dict) -> dict:
    try:
        model = QUICK_PARAMS.get(kind) or (AuditParams if kind == "version_audit" else ReportParams)
        return model.model_validate(params).model_dump()
    except ValidationError as exc:
        msg = "; ".join(str(e.get("msg", "")).removeprefix("Value error, ") for e in exc.errors())
        raise HTTPException(status_code=422, detail=msg or "Некорректные параметры") from None


async def enqueue(request: Request, db: AsyncSession, su: SessionUser, *, kind: str, title: str, params: dict, sources: list[KscSource], audit_action: str = "report.create",
                  extra: dict | None = None) -> ReportJob:
    general = await request.app.state.settings_svc.get(db, "general")
    if params.get("active_days") is None:
        params["active_days"] = general.activity_days
    if kind == "version_audit":
        params["_expect"] = [audit.item_condition(i) for i in params.get("items") or []]   # условия в виде, заданном пользователем: сверяются при выполнении
    title = title.strip() or default_title(kind, params)
    ids = [str(s.id) for s in sources]
    live = (await db.execute(select(ReportJob).where(ReportJob.status.in_(("queued", "running")), ReportJob.kind == kind, ReportJob.created_by_id == su.user_id)
                             .order_by(ReportJob.created_at.desc()).limit(20))).scalars().all()
    same = next((j for j in live if list(j.source_ids or [str(j.source_id)]) == ids and (j.params or {}) == params and j.title == title[:300]), None)
    if same is not None:                                   # двойной щелчок или повторная отправка: тот же отчёт уже формируется — второе задание не создаётся
        return same
    job = ReportJob(id=uuid.uuid4(), source_id=sources[0].id if sources else None, source_ids=[str(s.id) for s in sources], source_name=(", ".join(s.name for s in sources) or "Pentest")[:600], kind=kind,
                    title=title[:300], params=params, created_by=su.display_name, created_by_id=su.user_id)
    db.add(job)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action=audit_action, target_type="report", target_id=str(job.id), source_id=sources[0].id if sources else None,
                details={"kind": kind, "title": title, "sources": [s.name for s in sources], **(extra or {})})
    await db.commit()
    await request.app.state.journal.emit("report", "report_queued", user=su.username, source=job.source_name[:120], message=title, data={"job_id": str(job.id), "kind": kind})
    return job


def default_title(kind: str, params: dict) -> str:
    if kind == "version_audit":
        items = params.get("items") or []
        names = [i.get("product_name") or i.get("product_key") or i.get("name_like") or "?" for i in items]
        cond = versions.condition_text(items[0].get("op") or "lt", items[0].get("value"), items[0].get("min"), items[0].get("max"), full=False) if len(items) == 1 else ""
        return (f"{names[0]}: версия {cond}" if len(items) == 1 else f"Проверка версий: {', '.join(names[:4])}{'…' if len(names) > 4 else ''}")[:300]
    return KIND_TITLE.get(kind, kind)


@router.get("")
async def list_jobs(source_only: bool = True, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), su: SessionUser = Depends(require_user),
                    db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(ReportJob).order_by(ReportJob.created_at.desc()).offset(offset).limit(limit * 3))).scalars().all()
    cur = str(su.current_source_id) if su.current_source_id else None
    out = [j for j in rows if can_see(su, j) and (not source_only or not cur or cur in job_sources(j) or j.kind in ("quick_pentest", "quick_hunt", "quick_bi"))]
    return {"items": [job_out(j) for j in out[:limit]]}


@router.post("", status_code=201)
async def create_job(body: ReportIn, request: Request, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    params = validate_params(body.kind, body.params)
    if body.kind == "quick_bi" and not (su.is_admin or su.all_sources):
        raise HTTPException(status_code=403, detail="Отчёты BI доступны аналитику и администратору с доступом ко всем источникам KSC")
    if body.kind in ("quick_pentest", "quick_hunt", "quick_bi"):
        sources = []
    elif body.kind in ("quick_zone", "quick_eol", "quick_devices", "quick_overview"):      # зона и EOL могут охватывать несколько источников: без явного выбора — все доступные пользователю
        from ..services.sources import visible_sources  # noqa: PLC0415

        ids = body.source_ids or [s.id for s in await visible_sources(db, su)]
        sources = await _sources(db, su, ids, su.current_source_id)
    else:
        sources = await _sources(db, su, body.source_ids if body.kind == "version_audit" else body.source_ids[:1], su.current_source_id)
    job = await enqueue(request, db, su, kind=body.kind, title=body.title, params=params, sources=sources)
    return job_out(job)


@router.get("/{job_id}")
async def get_job(job_id: uuid.UUID, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    return job_out(await _job(db, job_id, su))


_SEARCH_KEYS = {"name", "fqdn", "ip", "os", "app_name", "app_version", "group", "program", "host", "threat", "cve", "kla_id", "product", "installed_version", "problems", "av", "type_ru", "target", "user", "object"}
_ROWS_CACHE: dict[str, tuple[int, list[dict]]] = {}


def _job_rows(p: Path) -> list[dict]:
    """Строки отчёта из файла; последний прочитанный отчёт держится в памяти (порции прокрутки не перечитывают файл)."""
    key, stamp = str(p), p.stat().st_mtime_ns
    got = _ROWS_CACHE.get(key)
    if got and got[0] == stamp:
        return got[1]
    rows = read_all_jsonl(p)
    if len(_ROWS_CACHE) >= 3:
        _ROWS_CACHE.pop(next(iter(_ROWS_CACHE)))
    _ROWS_CACHE[key] = (stamp, rows)
    return rows


SORTABLE = {"name", "program", "app_version", "compared_version", "source", "ip", "os", "last_connected", "days_since_connection", "group", "app_name", "activity", "target_version"}


@router.get("/{job_id}/rows")
async def job_rows(job_id: uuid.UUID, request: Request, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000), q: str = Query("", max_length=200),
                   source: str = Query("", max_length=200), program: str = Query("", max_length=300), sort: str = Query("", max_length=40), desc: bool = False,
                   su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Строки отчёта: фильтры по тексту, источнику и программе, сортировка по столбцу — на сервере."""
    j = await _job(db, job_id, su)
    if j.status != "done":
        raise HTTPException(status_code=409, detail="Отчёт ещё не сформирован")
    p: Path = job_dir(request.app.state.settings, j.id) / "rows.jsonl"
    if not p.exists():
        raise HTTPException(status_code=410, detail="Файлы отчёта удалены по сроку хранения")
    rows = list(_job_rows(p))
    if source:
        rows = [r for r in rows if r.get("source") == source]
    if program:
        rows = [r for r in rows if r.get("program") == program]
    if (hit := any_field(q)):
        rows = [r for r in rows if hit(*(v for k, v in r.items() if isinstance(v, (str, int)) and k in _SEARCH_KEYS))]
    if sort in SORTABLE or (sort and rows and sort in rows[0]):
        if sort in ("app_version", "compared_version"):
            rows.sort(key=lambda r: versions.sort_key(str(r.get(sort) or "0")), reverse=desc)
        elif sort == "days_since_connection" or all(isinstance(r.get(sort), (int, float)) or r.get(sort) is None for r in rows):
            rows.sort(key=lambda r: (r.get(sort) is None, r.get(sort) or 0), reverse=desc)
        else:
            rows.sort(key=lambda r: str(r.get(sort) or "").lower(), reverse=desc)
    return {"items": rows[offset:offset + limit], "total": len(rows), "offset": offset, "limit": limit}


@router.get("/{job_id}/download/{fmt}")
async def download(job_id: uuid.UUID, fmt: str, request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    if fmt not in ("csv", "xlsx", "html", "pdf"):
        raise HTTPException(status_code=404, detail="Формат: csv | xlsx | html | pdf")
    j = await _job(db, job_id, su)
    p: Path = job_dir(request.app.state.settings, j.id) / f"report.{fmt}"
    if j.status != "done" or not p.exists():
        raise HTTPException(status_code=409, detail="Файл отчёта недоступен")
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="report.download", target_type="report", target_id=str(j.id), source_id=j.source_id, details={"format": fmt})
    await db.commit()
    name = f"kavcheck_{j.kind}_{j.created_at:%Y%m%d_%H%M}.{fmt}"
    media = {"csv": "text/csv; charset=utf-8", "html": "text/html; charset=utf-8", "pdf": "application/pdf"}.get(fmt, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    return FileResponse(p, media_type=media, filename=name, content_disposition_type="attachment", headers={"X-Content-Type-Options": "nosniff"})


@router.post("/{job_id}/cancel")
async def cancel(job_id: uuid.UUID, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    j = await _job(db, job_id, su)
    if j.status == "queued":
        j.status, j.progress = "cancelled", "отменён до запуска"
    elif j.status == "running":
        j.cancel_requested = True
    else:
        raise HTTPException(status_code=409, detail="Отчёт уже завершён")
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="report.cancel", target_type="report", target_id=str(j.id), source_id=j.source_id)
    await db.commit()
    return job_out(j)


@router.post("/{job_id}/rerun", status_code=201)
async def rerun(job_id: uuid.UUID, request: Request, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Повторить отчёт с теми же условиями и источниками."""
    old = await _job(db, job_id, su)
    sources = await _sources(db, su, [uuid.UUID(i) for i in job_sources(old)], None)
    job = await enqueue(request, db, su, kind=old.kind, title=old.title, params=dict(old.params or {}), sources=sources, audit_action="report.rerun", extra={"from": str(old.id)})
    return job_out(job)


@router.delete("/{job_id}", status_code=204)
async def delete_job(job_id: uuid.UUID, request: Request, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    import shutil  # noqa: PLC0415

    j = await _job(db, job_id, su)
    if j.status == "running":
        raise HTTPException(status_code=409, detail="Сначала отмените формирование")
    shutil.rmtree(job_dir(request.app.state.settings, j.id), ignore_errors=True)
    await db.delete(j)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="report.delete", target_type="report", target_id=str(job_id), source_id=j.source_id)
    await db.commit()


# ------------------------------------------------------------------------------------------------- шаблоны
templates = APIRouter(prefix="/report-templates", tags=["reports"])


def tpl_out(t: ReportTemplate) -> dict:
    return {"id": str(t.id), "name": t.name, "kind": t.kind, "params": t.params, "shared": t.shared, "owner_id": str(t.owner_id) if t.owner_id else None, "created_at": t.created_at}


@templates.get("")
async def list_templates(su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(ReportTemplate).order_by(ReportTemplate.name))).scalars().all()
    return {"items": [tpl_out(t) for t in rows if t.shared or t.owner_id == su.user_id]}


# Выбор строк и фильтры страницы шаблон не хранит: они берутся с той страницы, откуда открыт конструктор. В шаблоне — настройки отчёта (подробность, столбцы, состояния, критичность…).
CONTEXT_KEYS = {"host_ids", "descr_ids", "cves", "vp_ids", "product_names", "vuln_keys", "product_keys", "event_ids", "host_id", "finding", "q", "zone", "group_contains", "threat", "product", "build", "problem"}


def template_settings(params: dict) -> dict:
    """Настройки быстрого отчёта для шаблона: без контекста страницы, только простые значения (строки, числа, флаги и списки строк/чисел) — проверка полей выполняется при запуске отчёта."""
    out: dict = {}
    for k, v in params.items():
        if k in CONTEXT_KEYS or not isinstance(k, str) or len(k) > 40 or len(out) >= 40:
            continue
        if isinstance(v, (bool, int, float)) or v is None or (isinstance(v, str) and len(v) <= 200) or (isinstance(v, list) and len(v) <= 60 and all(isinstance(x, (str, int)) and len(str(x)) <= 120 for x in v)):
            out[k] = v
    return out


@templates.post("", status_code=201)
async def create_template(body: TemplateIn, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    params = template_settings(body.params) if body.kind in QUICK_PARAMS else validate_params(body.kind, body.params)
    t = ReportTemplate(name=body.name, kind=body.kind, params=params, shared=body.shared, owner_id=su.user_id)
    db.add(t)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="template.create", target_type="template", target_id=str(t.id), details={"name": body.name})
    await db.commit()
    return tpl_out(t)


@templates.delete("/{template_id}", status_code=204)
async def delete_template(template_id: uuid.UUID, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    t = await db.get(ReportTemplate, template_id)
    if t is None:
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    if t.owner_id != su.user_id and not su.is_admin:
        raise HTTPException(status_code=403, detail="Чужой шаблон может удалить только администратор")
    await db.delete(t)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="template.delete", target_type="template", target_id=str(template_id))
    await db.commit()


# ------------------------------------------------------------------------------------------------- сохранённые проверки версий
checks = APIRouter(prefix="/checks", tags=["checks"])


def check_out(c: AuditCheck, names: dict[str, str]) -> dict:
    ids = [str(x) for x in (c.source_ids or ([str(c.source_id)] if c.source_id else []))]
    return {"id": str(c.id), "kind": c.kind, "name": c.name, "description": c.description, "params": c.params if c.kind == "version_audit" else None,
            "selection": c.selection if c.kind == "legacy" else None, "source_ids": ids, "source_names": [names.get(i, "удалён") for i in ids],
            "shared": c.shared, "owner_id": str(c.owner_id) if c.owner_id else None, "created_by": c.created_by, "created_at": c.created_at, "updated_at": c.updated_at,
            "last_run_at": c.last_run_at, "last_job_id": str(c.last_job_id) if c.last_job_id else None, "cve": c.cve, "severity": c.severity}


async def _names(db: AsyncSession) -> dict[str, str]:
    return {str(s.id): s.name for s in (await db.execute(select(KscSource))).scalars().all()}


def _visible(su: SessionUser, c: AuditCheck) -> bool:
    ids = [str(x) for x in (c.source_ids or ([str(c.source_id)] if c.source_id else []))]
    return (c.shared or c.owner_id == su.user_id or su.is_admin) and all(su.can_use_source(uuid.UUID(i)) for i in ids)


@checks.get("")
async def list_checks(su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(AuditCheck).order_by(AuditCheck.created_at.desc()))).scalars().all()
    names = await _names(db)
    return {"items": [check_out(c, names) for c in rows if _visible(su, c)]}


@checks.post("", status_code=201)
async def create_check(body: SavedCheckIn, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    sources = await _sources(db, su, body.source_ids, su.current_source_id)
    c = AuditCheck(id=uuid.uuid4(), kind="version_audit", name=body.name.strip(), description=body.description, params=body.params.model_dump(),
                   source_ids=[str(s.id) for s in sources], source_id=None, shared=body.shared, owner_id=su.user_id, created_by=su.display_name, updated_at=utcnow())
    db.add(c)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="check.create", target_type="check", target_id=str(c.id), details={"name": c.name})
    await db.commit()
    return check_out(c, await _names(db))


async def _check(db: AsyncSession, su: SessionUser, check_id: uuid.UUID, *, write: bool = False) -> AuditCheck:
    c = await db.get(AuditCheck, check_id)
    if c is None or not _visible(su, c):
        raise HTTPException(status_code=404, detail="Проверка не найдена")
    if write and c.owner_id not in (None, su.user_id) and not su.is_admin:
        raise HTTPException(status_code=403, detail="Изменить чужую проверку может только её автор или администратор")
    return c


@checks.put("/{check_id}")
async def update_check(check_id: uuid.UUID, body: SavedCheckIn, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    c = await _check(db, su, check_id, write=True)
    sources = await _sources(db, su, body.source_ids, su.current_source_id)
    c.kind, c.name, c.description, c.params, c.source_ids, c.shared, c.updated_at = "version_audit", body.name.strip(), body.description, body.params.model_dump(), \
        [str(s.id) for s in sources], body.shared, utcnow()
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="check.update", target_type="check", target_id=str(c.id), details={"name": c.name})
    await db.commit()
    return check_out(c, await _names(db))


@checks.delete("/{check_id}", status_code=204)
async def delete_check(check_id: uuid.UUID, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    c = await _check(db, su, check_id, write=True)
    await db.delete(c)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="check.delete", target_type="check", target_id=str(check_id), source_id=c.source_id)
    await db.commit()


@checks.post("/{check_id}/run", status_code=201)
async def run_check(check_id: uuid.UUID, request: Request, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Повторный запуск сохранённой проверки без заполнения параметров: создаётся фоновый отчёт по тем же источникам."""
    c = await _check(db, su, check_id)
    ids = [uuid.UUID(str(x)) for x in (c.source_ids or ([str(c.source_id)] if c.source_id else []))]
    actives = [s for s in [await db.get(KscSource, i) for i in ids] if s is not None and s.is_active and su.can_use_source(s.id)]
    if not actives:
        raise HTTPException(status_code=409, detail="Источники проверки удалены или выключены")
    if c.kind == "legacy":
        params, kind = validate_params("software_hosts", dict(c.selection or {})), "software_hosts"
        actives = actives[:1]
    else:
        params, kind = dict(c.params or {}), "version_audit"
        params["active_days"] = None              # текущий порог из общих настроек
    job = await enqueue(request, db, su, kind=kind, title=c.name, params=params, sources=actives, audit_action="check.run", extra={"check": str(c.id)})
    c.last_run_at, c.last_job_id = utcnow(), job.id
    await db.commit()
    return job_out(job)



