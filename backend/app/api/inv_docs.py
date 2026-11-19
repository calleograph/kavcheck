"""Документы раздела «Инвентаризация» (выдача, возврат, перемещение, приём-передача, передача МЦ, приём неисправного, ремонт, списание, работы), их печатные формы
(HTML, PDF, DOCX) и этикетки (PDF, ZPL). Логика этапов — inventory/docs.py."""
from __future__ import annotations

from datetime import date
from datetime import date as Date
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_db
from ..inventory import core as C
from ..inventory import docs as D
from ..inventory import labels as L
from ..inventory import model as M
from ..inventory import printing as P
from ..models import InvAsset, InvDoc, InvDocItem, InvFile, InvLocation, InvPerson
from ..search import column_like
from .inv import Ix, audit, inv_ctx

router = APIRouter(prefix="/inv", tags=["inventory"])


async def _names(db: AsyncSession, docs: list[InvDoc]) -> tuple[dict, dict]:
    pids = {getattr(d, f) for d in docs for f in ("from_person_id", "to_person_id", "resp_id")} - {None}
    lids = {getattr(d, f) for d in docs for f in ("from_location_id", "to_location_id")} - {None}
    people = dict((await db.execute(select(InvPerson.id, InvPerson.name).where(InvPerson.id.in_(pids)))).all()) if pids else {}
    locs = dict((await db.execute(select(InvLocation.id, InvLocation.path).where(InvLocation.id.in_(lids)))).all()) if lids else {}
    return people, locs


def doc_out(d: InvDoc, people: dict, locs: dict, n_items: int | None = None) -> dict:
    return {"id": d.id, "no": d.no, "kind": d.kind, "kind_ru": M.DOC_SHORT.get(d.kind, d.kind), "title": M.DOC_RU.get(d.kind, d.kind), "status": d.status,
            "status_ru": M.DOC_STATUS_RU.get(d.status, d.status), "date": d.doc_date.isoformat(), "from_location_id": d.from_location_id, "from_location": locs.get(d.from_location_id, ""),
            "to_location_id": d.to_location_id, "to_location": locs.get(d.to_location_id, ""), "from_person_id": d.from_person_id, "from_person": people.get(d.from_person_id, ""),
            "to_person_id": d.to_person_id, "to_person": people.get(d.to_person_id, ""), "resp_id": d.resp_id, "resp": people.get(d.resp_id, ""), "basis": d.basis, "comment": d.comment,
            "data": d.data or {}, "history": d.history or [], "created_at": C._iso(d.created_at), "created_by": d.created_by, "done_at": C._iso(d.done_at), "items_n": n_items,
            "next": list(D.flow_of(d.kind).get(d.status, ()))}


@router.get("/docs")
async def docs(kind: str = Query("", max_length=60), status: str = Query("", max_length=60), q: str = Query("", max_length=200), asset: int | None = None, person: int | None = None,
               open_only: bool = False, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    w = []
    if kind:
        w.append(InvDoc.kind.in_(kind.split(",")))
    if status:
        w.append(InvDoc.status.in_(status.split(",")))
    if open_only:
        w.append(InvDoc.status.not_in(("done", "cancelled")))
    if q.strip():
        conds = [c for c in (column_like(InvDoc.no, q.strip()), column_like(InvDoc.basis, q.strip()), column_like(InvDoc.comment, q.strip())) if c is not None]
        conds.append(InvDoc.id.in_(select(InvDocItem.doc_id).join(InvAsset, InvAsset.id == InvDocItem.asset_id).where(column_like(InvAsset.search, q.strip()))))
        w.append(or_(*conds))
    if asset:
        w.append(InvDoc.id.in_(select(InvDocItem.doc_id).where(InvDocItem.asset_id == asset)))
    if person:
        w.append(or_(InvDoc.from_person_id == person, InvDoc.to_person_id == person, InvDoc.resp_id == person))
    total = (await db.execute(select(func.count()).select_from(InvDoc).where(*w))).scalar_one()
    rows = (await db.execute(select(InvDoc).where(*w).order_by(InvDoc.doc_date.desc(), InvDoc.id.desc()).offset(offset).limit(limit))).scalars().all()
    counts = dict((await db.execute(select(InvDocItem.doc_id, func.count()).where(InvDocItem.doc_id.in_([d.id for d in rows])).group_by(InvDocItem.doc_id))).all()) if rows else {}
    people, locs = await _names(db, list(rows))
    return {"items": [doc_out(d, people, locs, counts.get(d.id, 0)) for d in rows], "total": total, "offset": offset, "limit": limit}


class DocBody(BaseModel):
    kind: str = Field(default="", pattern=r"^(|" + "|".join(M.DOC_RU) + ")$")
    date: Date | None = None
    from_location_id: int | None = None
    to_location_id: int | None = None
    from_person_id: int | None = None
    to_person_id: int | None = None
    resp_id: int | None = None
    basis: str = Field(default="", max_length=500)
    comment: str = Field(default="", max_length=4000)
    data: dict = Field(default_factory=dict)
    items: list[dict] | None = None


def _clean_data(kind: str, data: dict) -> dict:
    keep = {"role", "also_roles", "clear_roles", "status_id", "fault", "found_at", "vendor", "vendor_id", "warranty", "result", "parts", "cost", "returned_at", "work_kind", "executor",
            "due", "description", "lines", "supplier_id", "invoice", "checklist"}
    out = {k: v for k, v in data.items() if k in keep and v not in (None, "")}
    for k in ("role",):
        if k in out and out[k] not in ("", *D.ROLE_FIELD):
            raise HTTPException(status_code=422, detail="Неизвестная роль")
    for k in ("also_roles", "clear_roles"):
        if k in out:
            out[k] = [r for r in out[k] if r in D.ROLE_FIELD][:5]
    if "cost" in out:
        try:
            out["cost"] = C.parse_money(out["cost"])
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Стоимость ремонта: {exc}") from None
    for k in ("fault", "result", "parts", "description", "vendor", "executor", "invoice"):
        if k in out:
            out[k] = str(out[k])[:2000]
    if "checklist" in out:
        out["checklist"] = {k: bool(v) for k, v in (out["checklist"] or {}).items() if k in ("monitoring", "backup", "ips", "links")}
    if "lines" in out:
        if kind != "receipt" or not isinstance(out["lines"], list):
            raise HTTPException(status_code=422, detail="Строки поступления — только у документа «Поступление»")
        lines, total = [], 0
        for ln in out["lines"][:200]:
            qty = int(ln.get("qty") or 1)
            if qty < 1:
                raise HTTPException(status_code=422, detail="Количество — от 1")
            total += qty
            if not (ln.get("type_id") or ln.get("model_id")):
                raise HTTPException(status_code=422, detail="В каждой строке поступления укажите тип или модель")
            try:
                cost = C.parse_money(ln.get("cost")) if ln.get("cost") not in (None, "") else None
                wu = C.parse_date(ln.get("warranty_until")).isoformat() if ln.get("warranty_until") else None
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=f"Строка поступления: {exc}") from None
            lines.append({"type_id": ln.get("type_id"), "manufacturer_id": ln.get("manufacturer_id"), "model_id": ln.get("model_id"), "name": str(ln.get("name") or "")[:300], "qty": qty,
                          "cost": round(cost / 100, 2) if cost is not None else None, "warranty_until": wu, "serials": [str(x).strip()[:120] for x in (ln.get("serials") or []) if str(x).strip()][:qty]})
        if total > M.RECEIPT_MAX_QTY:
            raise HTTPException(status_code=422, detail=f"В одном поступлении не больше {M.RECEIPT_MAX_QTY} единиц: разделите его")
        out["lines"] = lines
    return out


async def _check_refs(db: AsyncSession, ix: Ix, body: DocBody) -> None:
    for f in ("from_person_id", "to_person_id", "resp_id"):
        v = getattr(body, f)
        if v and await db.get(InvPerson, v) is None:
            raise HTTPException(status_code=422, detail="Сотрудник не найден")
    for f in ("from_location_id", "to_location_id"):
        v = getattr(body, f)
        if v:
            loc = await db.get(InvLocation, v)
            if loc is None:
                raise HTTPException(status_code=422, detail="Местоположение не найдено")
            if f == "to_location_id" and not ix.acc.loc_ok(loc):
                raise HTTPException(status_code=403, detail="Местоположение вне вашей области учёта")


@router.post("/docs", status_code=201)
async def create_doc(body: DocBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Черновик документа с оборудованием. Номер присваивается сразу (вид-год-порядковый), чтобы его можно было назвать до проведения."""
    if not body.kind:
        raise HTTPException(status_code=422, detail="Укажите вид документа")
    ix.acc.need(D.perm_of(body.kind))
    await _check_refs(db, ix, body)
    d0 = body.date or date.today()
    doc = InvDoc(no=await D.new_number(db, ix.cfg, body.kind, d0), kind=body.kind, status="draft", doc_date=d0, from_location_id=body.from_location_id, to_location_id=body.to_location_id,
                 from_person_id=body.from_person_id, to_person_id=body.to_person_id, resp_id=body.resp_id, basis=body.basis, comment=body.comment, data=_clean_data(body.kind, body.data),
                 created_by=ix.su.display_name, history=[{"at": C.utcnow().isoformat(), "by": ix.su.display_name, "from": "", "to": "draft", "comment": "создан"}])
    db.add(doc)
    await db.flush()
    if body.items:
        await D.set_items(db, doc, body.items, ix.acc)
    audit(db, ix, "doc.create", doc.no, {"id": doc.id, "kind": doc.kind, "items": len(body.items or [])})
    await db.commit()
    return await get_doc(doc.id, ix, db)


@router.get("/docs/{did}")
async def get_doc(did: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    d = await db.get(InvDoc, did)
    if d is None:
        raise HTTPException(status_code=404, detail="Документ не найден")
    items = list((await db.execute(select(InvDocItem).where(InvDocItem.doc_id == did).order_by(InvDocItem.id))).scalars())
    assets = {a.id: a for a in (await db.execute(select(InvAsset).where(InvAsset.id.in_([i.asset_id for i in items])))).scalars()} if items else {}
    n = await C.names_for(db, list(assets.values()), props=False)
    people, locs = await _names(db, [d])
    files = (await db.execute(select(InvFile.id, InvFile.name, InvFile.size, InvFile.at, InvFile.by).where(InvFile.owner == "doc", InvFile.owner_id == did))).all()
    return {**doc_out(d, people, locs, len(items)),
            "items": [{"id": i.id, "asset_id": i.asset_id, "snap": i.snap, "condition": i.condition, "note": i.note, "current": C.asset_row(assets[i.asset_id], n) if i.asset_id in assets else None}
                      for i in items],
            "files": [{"id": i, "name": nm, "size": sz, "at": C._iso(at), "by": by} for i, nm, sz, at, by in files],
            "can": {"edit": ix.acc.can(D.perm_of(d.kind)) and (d.status in ("draft", "prepared") or (d.kind == "receipt" and d.status == "sent")), "move": ix.acc.can(D.perm_of(d.kind))}}


@router.put("/docs/{did}")
async def edit_doc(did: int, body: DocBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Изменение черновика или подготовленного документа (реквизиты и состав). Проведённый документ не меняется — его можно только отменить, если этап это допускает."""
    d = await db.get(InvDoc, did, with_for_update=True)
    if d is None:
        raise HTTPException(status_code=404, detail="Документ не найден")
    ix.acc.need(D.perm_of(d.kind))
    if d.status not in ("draft", "prepared") and not (d.kind == "receipt" and d.status == "sent"):
        raise HTTPException(status_code=409, detail="Документ уже отправлен или проведён: изменять его нельзя")
    await _check_refs(db, ix, body)
    if body.date:
        d.doc_date = body.date
    d.from_location_id, d.to_location_id, d.from_person_id, d.to_person_id, d.resp_id = body.from_location_id, body.to_location_id, body.from_person_id, body.to_person_id, body.resp_id
    d.basis, d.comment, d.data, d.updated_at = body.basis, body.comment, _clean_data(d.kind, body.data), C.utcnow()
    if body.items is not None:
        await D.set_items(db, d, body.items, ix.acc)
    audit(db, ix, "doc.edit", d.no, {"id": d.id, "items": len(body.items) if body.items is not None else None})
    await db.commit()
    return await get_doc(did, ix, db)


class StatusBody(BaseModel):
    to: str = Field(pattern=r"^(" + "|".join(M.DOC_STATUS_RU) + ")$")
    comment: str = Field(default="", max_length=1000)
    data: dict | None = None                                     # уточнения на этапе: результат ремонта, стоимость, дата возврата


@router.post("/docs/{did}/status")
async def move_doc(did: int, body: StatusBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    d = await db.get(InvDoc, did, with_for_update=True)
    if d is None:
        raise HTTPException(status_code=404, detail="Документ не найден")
    ix.acc.need(D.perm_of(d.kind))
    if body.data:
        d.data = {**(d.data or {}), **_clean_data(d.kind, body.data)}
    try:
        touched = await D.transition(db, d, body.to, ix.acc, ix.su.display_name, body.comment)
    except C.Invalid as exc:
        raise HTTPException(status_code=422, detail=f"Изменения не применены: {exc}") from None
    audit(db, ix, "doc.status", d.no, {"id": d.id, "to": body.to, "assets": len(touched)})
    await db.commit()
    return {"status": d.status, "changed": len(touched)}


@router.get("/docs/{did}/print")
async def print_doc(did: int, request: Request, fmt: str = Query("json", pattern=r"^(json|html|pdf|docx|xlsx)$"), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Печатная форма документа: json — структура для страницы печати в приложении, html — файл для сохранения, PDF, DOCX (для правки). Черновик помечается «не проведён»."""
    d = await db.get(InvDoc, did)
    if d is None:
        raise HTTPException(status_code=404, detail="Документ не найден")
    org = (await request.app.state.settings_svc.get(db, "organization")).model_dump()
    p = await P.build(db, d, ix.cfg, org)
    name = f"{d.no}"
    if fmt == "json":
        return p
    if fmt == "html":                                              # файлом: открывается локально (политика безопасности приложения не допускает встроенных стилей)
        return HTMLResponse(P.render_html(p), headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}.html"})
    if fmt == "pdf":
        return Response(P.render_pdf(p), media_type="application/pdf", headers={"Content-Disposition": f"inline; filename*=UTF-8''{quote(name)}.pdf"})
    if fmt == "xlsx":
        return Response(P.render_xlsx(p), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}.xlsx"})
    return Response(P.render_docx(p), media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}.docx"})


@router.get("/labels")
async def labels(request: Request, ids: str = Query("", max_length=40000), locations: str = Query("", max_length=8000), fmt: str = Query("pdf", pattern=r"^(pdf|zpl)$"),
                 ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Этикетки выбранных карточек (ids) или местоположений (locations) по шаблону из настроек: PDF или ZPL. QR ведёт на карточку по адресу KAV Checker."""
    aids = [int(x) for x in ids.split(",") if x.strip().isdigit()][:3000]
    lids = [int(x) for x in locations.split(",") if x.strip().isdigit()][:1000]
    if not aids and not lids:
        raise HTTPException(status_code=422, detail="Выберите карточки или местоположения")
    org = (await request.app.state.settings_svc.get(db, "organization")).model_dump()
    org_name = (org.get("short_name") or org.get("full_name") or "").strip()
    base = request.app.state.settings.app_public_url
    out: list[L.Label] = []
    if aids:
        stmt = select(InvAsset).where(InvAsset.id.in_(aids))
        if (af := ix.acc.asset_filter()) is not None:
            stmt = stmt.where(af)
        rows = (await db.execute(stmt.order_by(InvAsset.inv_no))).scalars().all()
        n = await C.names_for(db, list(rows), props=False)
        for a in rows:
            r = C.asset_row(a, n)
            r["name"] = r["name"] or r["label"].rsplit(" (", 1)[0]
            out.append(L.asset_label(r, ix.cfg, base, org_name))
    if lids:
        for x in (await db.execute(select(InvLocation).where(InvLocation.id.in_(lids)).order_by(InvLocation.path))).scalars():
            out.append(L.location_label({"id": x.id, "path": x.path}, ix.cfg, org_name))
    audit(db, ix, "labels", f"{len(out)} этикеток", {"assets": len(aids), "locations": len(lids), "fmt": fmt})
    await db.commit()
    if fmt == "zpl":
        return Response(L.render_zpl(out, ix.cfg), media_type="text/plain; charset=utf-8", headers={"Content-Disposition": "attachment; filename=labels.zpl"})
    return Response(L.render_pdf(out, ix.cfg), media_type="application/pdf", headers={"Content-Disposition": "inline; filename=labels.pdf"})
