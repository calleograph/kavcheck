"""Отчёты: постановка в очередь, состояние, постраничный просмотр, экспорт CSV/XLSX, отмена, шаблоны, сохранённые сценарии аудита."""
from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, current_source, get_db, require_analyst, require_user
from ..models import AuditCheck, KscSource, ReportJob, ReportTemplate
from ..reports.export import read_jsonl
from ..reports.runner import job_dir
from ..services.audit import write_audit
from .schemas import CheckIn, ReportIn, TemplateIn

router = APIRouter(prefix="/reports", tags=["reports"])
KIND_TITLE = {"software_hosts": "Компьютеры с программами", "hosts": "Компьютеры и активность"}


def job_out(j: ReportJob) -> dict:
    return {"id": str(j.id), "source_id": str(j.source_id), "source_name": j.source_name, "kind": j.kind, "title": j.title, "params": j.params, "status": j.status,
            "progress": j.progress, "created_by": j.created_by, "created_at": j.created_at, "started_at": j.started_at, "finished_at": j.finished_at,
            "data_fetched_at": j.data_fetched_at, "rows": j.rows, "summary": j.summary, "error": j.error}


async def _job(db: AsyncSession, job_id: uuid.UUID, su: SessionUser) -> ReportJob:
    j = await db.get(ReportJob, job_id)
    if j is None or not su.can_use_source(j.source_id):
        raise HTTPException(status_code=404, detail="Отчёт не найден")
    return j


@router.get("")
async def list_jobs(source_only: bool = True, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), su: SessionUser = Depends(require_user),
                    db: AsyncSession = Depends(get_db)):
    stmt = select(ReportJob).order_by(ReportJob.created_at.desc()).offset(offset).limit(limit)
    if source_only and su.current_source_id:
        stmt = stmt.where(ReportJob.source_id == su.current_source_id)
    rows = [j for j in (await db.execute(stmt)).scalars().all() if su.can_use_source(j.source_id)]
    return {"items": [job_out(j) for j in rows]}


@router.post("", status_code=201)
async def create_job(body: ReportIn, request: Request, su: SessionUser = Depends(require_analyst), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    general = await request.app.state.settings_svc.get(db, "general")
    params = body.params.model_dump()
    if params.get("active_days") is None:
        params["active_days"] = general.activity_days
    title = body.title.strip() or KIND_TITLE[body.kind]
    job = ReportJob(source_id=src.id, source_name=src.name, kind=body.kind, title=title[:300], params=params, created_by=su.display_name, created_by_id=su.user_id)
    db.add(job)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="report.create", target_type="report", target_id=str(job.id), source_id=src.id, details={"kind": body.kind, "title": title})
    await db.commit()
    await request.app.state.journal.emit("report", "report_queued", user=su.username, source=src.name, message=title, data={"job_id": str(job.id), "kind": body.kind})
    return job_out(job)


@router.get("/{job_id}")
async def get_job(job_id: uuid.UUID, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    return job_out(await _job(db, job_id, su))


@router.get("/{job_id}/rows")
async def job_rows(job_id: uuid.UUID, request: Request, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000), su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    j = await _job(db, job_id, su)
    if j.status != "done":
        raise HTTPException(status_code=409, detail="Отчёт ещё не сформирован")
    p = job_dir(request.app.state.settings, j.id) / "rows.jsonl"
    if not p.exists():
        raise HTTPException(status_code=410, detail="Файлы отчёта удалены по сроку хранения")
    return {"items": read_jsonl(p, offset, limit), "total": j.rows, "offset": offset, "limit": limit}


@router.get("/{job_id}/download/{fmt}")
async def download(job_id: uuid.UUID, fmt: str, request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    if fmt not in ("csv", "xlsx"):
        raise HTTPException(status_code=404, detail="Формат: csv | xlsx")
    j = await _job(db, job_id, su)
    p: Path = job_dir(request.app.state.settings, j.id) / f"report.{fmt}"
    if j.status != "done" or not p.exists():
        raise HTTPException(status_code=409, detail="Файл отчёта недоступен")
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="report.download", target_type="report", target_id=str(j.id), source_id=j.source_id, details={"format": fmt})
    await db.commit()
    name = f"kavcheck_{j.kind}_{j.created_at:%Y%m%d_%H%M}.{fmt}"
    media = "text/csv; charset=utf-8" if fmt == "csv" else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return FileResponse(p, media_type=media, filename=name)


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
    """Повторить ранее сформированный отчёт с теми же условиями (на том же источнике)."""
    old = await _job(db, job_id, su)
    src = await db.get(KscSource, old.source_id)
    if src is None or not src.is_active:
        raise HTTPException(status_code=409, detail="Источник отчёта недоступен")
    job = ReportJob(source_id=src.id, source_name=src.name, kind=old.kind, title=old.title, params=old.params, created_by=su.display_name, created_by_id=su.user_id)
    db.add(job)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="report.rerun", target_type="report", target_id=str(job.id), source_id=src.id, details={"from": str(old.id)})
    await db.commit()
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


@templates.post("", status_code=201)
async def create_template(body: TemplateIn, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    t = ReportTemplate(name=body.name, kind=body.kind, params=body.params.model_dump(), shared=body.shared, owner_id=su.user_id)
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


# ------------------------------------------------------------------------------------------------- сценарии аудита (пользовательские критерии)
checks = APIRouter(prefix="/checks", tags=["checks"])


def check_out(c: AuditCheck) -> dict:
    return {"id": str(c.id), "source_id": str(c.source_id), "name": c.name, "selection": c.selection, "cve": c.cve, "severity": c.severity, "description": c.description,
            "comment": c.comment, "created_by": c.created_by, "created_at": c.created_at, "user_defined": True}


@checks.get("")
async def list_checks(su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(AuditCheck).where(AuditCheck.source_id == src.id).order_by(AuditCheck.created_at.desc()))).scalars().all()
    return {"items": [check_out(c) for c in rows]}


@checks.post("", status_code=201)
async def create_check(body: CheckIn, su: SessionUser = Depends(require_analyst), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    c = AuditCheck(source_id=src.id, name=body.name, selection=body.selection.model_dump(), cve=body.cve, severity=body.severity, description=body.description, comment=body.comment, created_by=su.display_name)
    db.add(c)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="check.create", target_type="check", target_id=str(c.id), source_id=src.id, details={"name": body.name, "cve": body.cve})
    await db.commit()
    return check_out(c)


@checks.delete("/{check_id}", status_code=204)
async def delete_check(check_id: uuid.UUID, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    c = await db.get(AuditCheck, check_id)
    if c is None or not su.can_use_source(c.source_id):
        raise HTTPException(status_code=404, detail="Сценарий не найден")
    await db.delete(c)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="check.delete", target_type="check", target_id=str(check_id), source_id=c.source_id)
    await db.commit()
