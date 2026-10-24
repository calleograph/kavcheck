"""Быстрые контекстные отчёты: предварительный просмотр (счётчики и первые строки) по текущему выбору, фильтрам и области активности.

Просмотр строит тот же документ, что и фоновый отчёт (reports/quick.py), поэтому число компьютеров в просмотре и в готовых XLSX/HTML совпадает.
Результат кэшируется на срок cache_ttl_seconds по (источник, вид, параметры): повторное открытие или изменение формата не читает KSC заново."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, current_source, get_db, require_user
from ..ksc import protection as P
from ..ksc.driver import KscError
from ..models import KscSource
from ..reports import quick, quick_export
from .catalog import audit_preview
from .schemas import QUICK_PARAMS, AuditParams
from .vulns import _ksc, groups_cached, unsupported

router = APIRouter(prefix="/quick", tags=["quick"])
PREVIEW_ROWS = 1000          # строк в просмотре; полный список — в отчёте


class QuickPreviewIn(BaseModel):
    kind: str = Field(pattern=r"^(version_audit|quick_vulns|quick_hosts|quick_protection|quick_events)$")
    params: dict
    source_ids: list[str] = Field(default_factory=list, max_length=50)
    refresh: bool = False


FEATURE = {"quick_vulns": "vulnerabilities", "quick_protection": "protection", "quick_events": "events", "quick_hosts": "hosts"}


@router.post("/preview")
async def preview(body: QuickPreviewIn, request: Request, su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    if body.kind == "version_audit":
        try:
            params = AuditParams.model_validate(body.params).model_dump()
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="; ".join(str(e.get("msg", "")).removeprefix("Value error, ") for e in exc.errors())) from None
        import uuid  # noqa: PLC0415

        from ..reports.runner import job_dir  # noqa: PLC0415,F401

        merged, rows = await audit_preview(request, db, su, params, [uuid.UUID(s) for s in body.source_ids])
        doc = quick.doc_from_audit(rows, merged, {"source": ", ".join(s["source"] for s in merged.get("sources", [])) or src.name})
        doc.update(kind="version_audit", generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"), source=src.name)
        return _answer(doc, merged.get("fetched_at"))
    miss = unsupported(src, FEATURE[body.kind])
    if miss:
        return {"unsupported": miss, "doc": None, "items": [], "total": 0}
    try:
        params = QUICK_PARAMS[body.kind].model_validate(body.params).model_dump()
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="; ".join(str(e.get("msg", "")).removeprefix("Value error, ") for e in exc.errors())) from None
    general = await request.app.state.settings_svc.get(db, "general")
    rcfg = await request.app.state.settings_svc.get(db, "reports")
    client = request.app.state.sources.client(src)
    ttl = request.app.state.settings.cache_ttl_seconds
    cache = request.app.state.cache
    key = (str(src.id), "quick", body.kind, hashlib.sha1(json.dumps(params, sort_keys=True, default=str).encode()).hexdigest(), general.activity_days, rcfg.exclude_slave_servers)

    async def make() -> dict:
        ctx = quick.Ctx(source_name=src.name, activity_days=int(general.activity_days), exclude_slaves=rcfg.exclude_slave_servers, max_rows=rcfg.max_rows,
                        protection_loader=lambda: _cached_protection(request, src, rcfg.exclude_slave_servers))
        doc = await quick.build(body.kind, client, params, ctx)
        main = doc["tables"][0]
        # в кэше и ответе — только документ без строк и первые строки основной таблицы
        return {"doc": quick.brief(doc), "items": main["rows"][:PREVIEW_ROWS], "total": len(main["rows"]), "columns": main["columns"], "at": ctx.now}

    try:
        data, _at = await cache.get(key, ttl, make, refresh=body.refresh)
    except KscError as exc:
        raise _ksc(exc) from None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return {**data, "fetched_at": data["at"], "preview_rows": PREVIEW_ROWS, "html_row_limit": quick_export.HTML_ROW_LIMIT}


async def _load_protection(request: Request, src: KscSource, exclude_slaves: bool) -> list[dict]:
    return await P.load(request.app.state.sources.client(src), exclude_slaves=exclude_slaves, groups=await groups_cached(request, src))


async def _cached_protection(request: Request, src: KscSource, exclude_slaves: bool) -> list[dict]:
    """Набор «Состояния защиты» из того же кэша, что у страницы: просмотр отчёта по защите не перечитывает KSC."""
    val, _ = await request.app.state.cache.get((str(src.id), "protection", exclude_slaves), request.app.state.settings.cache_ttl_seconds, lambda: _load_protection(request, src, exclude_slaves))
    return val


def _answer(doc: dict, fetched_at) -> dict:
    main = doc["tables"][0]
    return {"doc": quick.brief(doc), "items": main["rows"][:PREVIEW_ROWS], "total": len(main["rows"]), "columns": main["columns"], "fetched_at": fetched_at, "preview_rows": PREVIEW_ROWS,
            "html_row_limit": quick_export.HTML_ROW_LIMIT}
