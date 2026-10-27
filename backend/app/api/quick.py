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
from ..vdb import store as vdb_store
from .catalog import audit_preview
from .schemas import QUICK_PARAMS, AuditParams, QuickZone as AuditParamsZone
from .vulns import _ksc, groups_cached, unsupported

router = APIRouter(prefix="/quick", tags=["quick"])
PREVIEW_ROWS = 1000          # строк в просмотре; полный список — в отчёте


class QuickPreviewIn(BaseModel):
    kind: str = Field(pattern=r"^(version_audit|quick_zone|quick_vulns|quick_hosts|quick_protection|quick_events|quick_extvulns|quick_eol|quick_devices)$")
    params: dict
    source_ids: list[str] = Field(default_factory=list, max_length=50)
    refresh: bool = False


FEATURE = {"quick_vulns": "vulnerabilities", "quick_protection": "protection", "quick_events": "events", "quick_hosts": "hosts", "quick_extvulns": "software"}


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
    if body.kind == "quick_zone":
        try:
            params = AuditParamsZone.model_validate(body.params).model_dump()
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="; ".join(str(e.get("msg", "")).removeprefix("Value error, ") for e in exc.errors())) from None
        from .zones import zd  # noqa: PLC0415

        try:
            doc = await zd(request).zone_doc(db, zone_ids=params["zone_ids"], params=params, source_ids=body.source_ids or None, allowed=lambda s: su.can_use_source(s.id), allow_build=False, limit_hosts=3000)
        except KscError as exc:
            if exc.code == "no_data":
                raise HTTPException(status_code=409, detail=exc.message) from None
            raise _ksc(exc) from None
        return _answer(doc, doc.get("data_at") or doc.get("generated_at"))
    if body.kind in ("quick_eol", "quick_devices"):      # данные из PostgreSQL: KSC не нужен; источников может быть несколько («Все источники»)
        import uuid  # noqa: PLC0415

        try:
            params = QUICK_PARAMS[body.kind].model_validate(body.params).model_dump()
            ids = [uuid.UUID(x) for x in body.source_ids] or [src.id]
        except (ValidationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:300]) from None
        for sid in ids:
            if not su.can_use_source(sid):
                raise HTTPException(status_code=403, detail="Нет доступа к этому источнику KSC")
        general = await request.app.state.settings_svc.get(db, "general")
        ctx = quick.Ctx(source_name=src.name, activity_days=int(general.activity_days), sm=request.app.state.session_maker, source_id=src.id, source_ids=ids)
        doc = await quick.build(body.kind, None, params, ctx)  # type: ignore[arg-type]
        return _answer(doc, ctx.now)
    miss = unsupported(src, FEATURE[body.kind])
    if miss:
        return {"unsupported": miss, "doc": None, "items": [], "total": 0}
    try:
        params = QUICK_PARAMS[body.kind].model_validate(body.params).model_dump()
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="; ".join(str(e.get("msg", "")).removeprefix("Value error, ") for e in exc.errors())) from None
    general = await request.app.state.settings_svc.get(db, "general")
    rcfg = await request.app.state.settings_svc.get(db, "reports")
    hw = await request.app.state.settings_svc.get(db, "hardware")
    client = request.app.state.sources.client(src)
    ttl = request.app.state.settings.cache_ttl_seconds
    cache = request.app.state.cache
    zset, zname = None, ""
    if params.get("zone"):
        from .zones import zd, zone_host_ids  # noqa: PLC0415

        zset, zname = await zone_host_ids(request, db, src, params["zone"]), await zd(request).zone_name(db, params["zone"])
    rev = await vdb_store.revision(db, src.id) if body.kind == "quick_extvulns" else ""
    if zset is not None:
        rev += f"|zone:{hashlib.sha1(','.join(map(str, sorted(zset))).encode()).hexdigest()}"      # состав зоны меняет результат      # данные внешних баз, сопоставления и каталог меняют результат
    key = (str(src.id), "quick", body.kind, hashlib.sha1(json.dumps(params, sort_keys=True, default=str).encode()).hexdigest(), general.activity_days, rcfg.exclude_slave_servers, rev)

    async def make() -> dict:
        ctx = quick.Ctx(source_name=src.name, activity_days=int(general.activity_days), exclude_slaves=rcfg.exclude_slave_servers, max_rows=rcfg.max_rows,
                        protection_loader=lambda: _cached_protection(request, src, rcfg.exclude_slave_servers, hw), hw_cfg=hw, sm=request.app.state.session_maker, source_id=src.id,
                        zone_hosts=zset, zone_name=zname)
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


async def _load_protection(request: Request, src: KscSource, exclude_slaves: bool, hw=None) -> list[dict]:
    return await P.load(request.app.state.sources.client(src), exclude_slaves=exclude_slaves, groups=await groups_cached(request, src), hw_cfg=hw)


async def _cached_protection(request: Request, src: KscSource, exclude_slaves: bool, hw=None) -> list[dict]:
    """Набор «Состояния защиты» из того же кэша, что у страницы: просмотр отчёта по защите не перечитывает KSC."""
    val, _ = await request.app.state.cache.get((str(src.id), "protection", exclude_slaves, hw.model_dump_json() if hw else ""), request.app.state.settings.cache_ttl_seconds, lambda: _load_protection(request, src, exclude_slaves, hw))
    return val


def _answer(doc: dict, fetched_at) -> dict:
    main = doc["tables"][0]
    return {"doc": quick.brief(doc), "items": main["rows"][:PREVIEW_ROWS], "total": len(main["rows"]), "columns": main["columns"], "fetched_at": fetched_at, "preview_rows": PREVIEW_ROWS,
            "html_row_limit": quick_export.HTML_ROW_LIMIT}
