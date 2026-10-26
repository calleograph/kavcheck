"""Зоны ответственности: страницы анализа (все пользователи) и администрирование (зоны, CSV, закрепления, SMTP, расписания, история рассылок)."""
from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete as sa_delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_admin, require_analyst, require_user
from ..ksc import protection as P
from ..ksc.driver import KscError
from ..models import KscSource, MailOutbox, ReportSchedule, VulnTriage, ZcDashboard, ZcHostZone, ZcJob, ZcSource, Zone, ZoneContact, ZonePin, ZoneRule
from ..search import any_field, matcher
from ..services import mail as M
from ..services.audit import write_audit
from ..eol import read as EOLR
from ..zones import csv_io, mailer
from ..zones import dataset as D
from ..zones import match as ZM
from ..zones import report as R
from ..zones import schedule as SC
from ..zones import service as S
from ..zones import snapshot as SN
from ..zones import triage as T
from ..zones import zjobs as ZJ
from ..zones import zread as ZR
from ..zones.reporter import UNASSIGNED, ZoneData

router = APIRouter(prefix="/zones", tags=["zones"])
admin_router = APIRouter(prefix="/admin/zones", tags=["admin-zones"])
mail_router = APIRouter(prefix="/admin/mail", tags=["admin-mail"])
triage_router = APIRouter(prefix="/triage", tags=["triage"])
MAX_CSV = csv_io.MAX_BYTES


def zd(request: Request) -> ZoneData:
    z = getattr(request.app.state, "zones", None)
    if z is None:
        st = request.app.state
        z = st.zones = ZoneData(st.session_maker, st.settings, st.settings_svc, st.sources, st.cache)
    return z


def _ksc(exc: KscError) -> HTTPException:
    return HTTPException(status_code=503 if exc.code in ("connect", "timeout", "unavailable") else 502, detail=exc.message)


def _uid(v: str) -> uuid.UUID:
    try:
        return uuid.UUID(v)
    except ValueError:
        raise HTTPException(status_code=404, detail="Зона не найдена") from None


async def _members_changed(db: AsyncSession, su: SessionUser) -> None:
    """Состав зон изменился (правила, закрепления, CSV): пересчёт принадлежности по сохранённым данным ставится в очередь worker (без обращения к KSC), сводки обновятся после него."""
    await ZJ.enqueue(db, "members", trigger="auto", by=su.display_name)


# ------------------------------------------------------------------------------------------------ схемы
class RuleIn(BaseModel):
    kind: Literal["net", "exclude", "group", "name"] = "net"
    value: str = Field(min_length=1, max_length=300)
    note: str = Field(default="", max_length=200)


class ContactIn(BaseModel):
    name: str = Field(default="", max_length=200)
    position: str = Field(default="", max_length=200)
    email: str = Field(min_length=3, max_length=254)
    role: Literal["responsible", "cc", "group"] = "responsible"
    enabled: bool = True


class ZoneIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=4000)
    purpose: str = Field(default="", max_length=300)
    priority: int = Field(default=100, ge=1, le=1000)
    activity_days: int | None = Field(default=None, ge=1, le=3650)
    enabled: bool = True
    rules: list[RuleIn] = Field(default_factory=list, max_length=5000)
    contacts: list[ContactIn] = Field(default_factory=list, max_length=200)


def _clean_zone(body: ZoneIn) -> tuple[list[tuple[str, str, str]], list[dict]]:
    try:
        rules = S.check_rules([r.model_dump() for r in body.rules])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    seen, contacts = set(), []
    for i, c in enumerate(body.contacts, 1):
        em = c.email.strip().lower()
        if not csv_io.valid_email(em):
            raise HTTPException(status_code=422, detail=f"Получатель {i}: адрес «{c.email}» записан неверно")
        if em in seen:
            raise HTTPException(status_code=422, detail=f"Получатель {em} указан дважды")
        seen.add(em)
        contacts.append({**c.model_dump(), "email": em})
    return rules, contacts


def _zone_out(z: Zone, rules: list[ZoneRule], contacts: list[ZoneContact]) -> dict:
    return {"id": str(z.id), "name": z.name, "description": z.description, "purpose": z.purpose, "priority": z.priority, "activity_days": z.activity_days, "enabled": z.enabled,
            "updated_at": z.updated_at, "updated_by": z.updated_by,
            "rules": [{"id": str(r.id), "kind": r.kind, "kind_ru": ZM.KIND_TITLE[r.kind], "value": r.value, "note": r.note} for r in sorted(rules, key=lambda r: r.position)],
            "contacts": [{"id": str(c.id), "name": c.name, "position": c.position, "email": c.email, "role": c.role, "enabled": c.enabled} for c in sorted(contacts, key=lambda c: c.created_at)]}


async def _load_zone(db: AsyncSession, zid: uuid.UUID) -> dict:
    z = await db.get(Zone, zid)
    if z is None:
        raise HTTPException(status_code=404, detail="Зона не найдена")
    rules = (await db.execute(select(ZoneRule).where(ZoneRule.zone_id == zid))).scalars().all()
    cons = (await db.execute(select(ZoneContact).where(ZoneContact.zone_id == zid))).scalars().all()
    return _zone_out(z, list(rules), list(cons))


# ------------------------------------------------------------------------------------------------ администрирование зон
@admin_router.get("")
async def list_admin(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    zs = (await db.execute(select(Zone).order_by(Zone.priority, Zone.name))).scalars().all()
    nr = dict((await db.execute(select(ZoneRule.zone_id, func.count()).group_by(ZoneRule.zone_id))).all())
    nc = dict((await db.execute(select(ZoneContact.zone_id, func.count()).group_by(ZoneContact.zone_id))).all())
    return {"items": [{"id": str(z.id), "name": z.name, "description": z.description, "purpose": z.purpose, "priority": z.priority, "enabled": z.enabled, "rules": nr.get(z.id, 0),
                       "contacts": nc.get(z.id, 0), "updated_at": z.updated_at} for z in zs]}


@admin_router.get("/{zid}")
async def get_admin(zid: str, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    return await _load_zone(db, _uid(zid))


async def _name_taken(db: AsyncSession, name: str, own: uuid.UUID | None) -> bool:
    want = name.strip().lower()
    return any(i != own and n.lower() == want for i, n in (await db.execute(select(Zone.id, Zone.name))).all())      # сравнение в Python: lower() SQLite не знает кириллицу


async def _write_zone(db: AsyncSession, z: Zone, body: ZoneIn, rules, contacts, actor: str) -> None:
    z.name, z.description, z.purpose, z.priority, z.activity_days, z.enabled = body.name.strip(), body.description.strip(), body.purpose.strip(), body.priority, body.activity_days, body.enabled
    z.updated_at, z.updated_by = datetime.now(timezone.utc), actor
    await db.flush()
    for r in (await db.execute(select(ZoneRule).where(ZoneRule.zone_id == z.id))).scalars():
        await db.delete(r)
    old = {c.email.lower(): c for c in (await db.execute(select(ZoneContact).where(ZoneContact.zone_id == z.id))).scalars()}
    await db.flush()
    for i, (k, v, n) in enumerate(rules):
        db.add(ZoneRule(zone_id=z.id, kind=k, value=v, note=n, position=i))
    keep = set()
    for c in contacts:
        keep.add(c["email"])
        cur = old.get(c["email"])
        if cur:
            cur.name, cur.position, cur.role, cur.enabled = c["name"], c["position"], c["role"], c["enabled"]
        else:
            db.add(ZoneContact(zone_id=z.id, name=c["name"], position=c["position"], email=c["email"], role=c["role"], enabled=c["enabled"]))
    for em, cur in old.items():
        if em not in keep:
            await db.delete(cur)


@admin_router.post("", status_code=201)
async def create(body: ZoneIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    rules, contacts = _clean_zone(body)
    if await _name_taken(db, body.name, None):
        raise HTTPException(status_code=409, detail="Зона с таким названием уже есть")
    z = Zone(id=uuid.uuid4())
    db.add(z)
    await _write_zone(db, z, body, rules, contacts, su.display_name)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="zone.create", target_type="zone", target_id=str(z.id), details={"name": z.name, "rules": len(rules), "contacts": len(contacts)})
    await _members_changed(db, su)
    await db.commit()
    return await _load_zone(db, z.id)


@admin_router.put("/{zid}")
async def update(zid: str, body: ZoneIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    z = await db.get(Zone, _uid(zid))
    if z is None:
        raise HTTPException(status_code=404, detail="Зона не найдена")
    rules, contacts = _clean_zone(body)
    if await _name_taken(db, body.name, z.id):
        raise HTTPException(status_code=409, detail="Зона с таким названием уже есть")
    await _write_zone(db, z, body, rules, contacts, su.display_name)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="zone.update", target_type="zone", target_id=str(z.id), details={"name": z.name, "rules": len(rules), "contacts": len(contacts)})
    await _members_changed(db, su)
    await db.commit()
    return await _load_zone(db, z.id)


@admin_router.delete("/{zid}", status_code=204)
async def delete(zid: str, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    z = await db.get(Zone, _uid(zid))
    if z is None:
        raise HTTPException(status_code=404, detail="Зона не найдена")
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="zone.delete", target_type="zone", target_id=str(z.id), details={"name": z.name})
    await S.delete_zone(db, z.id)
    await db.execute(sa_delete(ZcHostZone).where(ZcHostZone.zone_id == str(z.id)))
    await db.execute(sa_delete(ZcDashboard).where(ZcDashboard.zone_id == str(z.id)))
    await _members_changed(db, su)
    await db.commit()
    return Response(status_code=204)


class PreviewIn(BaseModel):
    zone_id: str | None = None
    name: str = Field(default="Новая зона", max_length=120)
    priority: int = Field(default=100, ge=1, le=1000)
    rules: list[RuleIn] = Field(default_factory=list, max_length=5000)
    limit: int = Field(default=100, ge=1, le=500)


@admin_router.post("/preview/composition")
async def preview_composition(body: PreviewIn, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Какие компьютеры попадут в зону при указанных признаках — до сохранения. Показаны найденные, пересечения с другими зонами и число активных и онлайн."""
    try:
        rules = S.check_rules([r.model_dump() for r in body.rules])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    defs = await S.load_defs(db)
    me = body.zone_id or "preview"
    defs = [d for d in defs if d.id != me] + [ZM.ZoneDef(me, body.name, body.priority, [(k, v) for k, v, _ in rules])]
    idx = ZM.ZoneIndex(defs, await S.load_pins(db))
    names = {d.id: d.name for d in defs}
    general = await request.app.state.settings_svc.get(db, "general")
    found, active, online, shared, total_hosts, matched = [], 0, 0, 0, 0, 0
    sids, _all, srcs = await _scope(db, su)
    prepared = False
    for src in srcs:                                         # по сохранённым данным компьютеров, порциями: KSC не опрашивается
        async for chunk in ZR.base_records(db, src.id):
            prepared = True
            for r in ZM.annotate(chunk, idx, str(src.id)):
                total_hosts += 1
                if me not in r["zone_candidates"]:
                    continue
                matched += 1
                act = r["days_since_connection"] is not None and r["days_since_connection"] <= general.activity_days
                active += act
                online += r.get("online") is True
                other = [names[z] for z in r["zone_candidates"] if z != me]
                shared += bool(other)
                if len(found) < 5000:
                    found.append({"source": src.name, "host_id": r["host_id"], "name": r["name"], "ip": r["ip"], "os": r["os"], "group": r["group"], "active": act, "online": r.get("online"),
                                  "also_in": other, "assigned_here": me in r["zones"], "via": r["zone_via"]})
    found.sort(key=lambda h: (not h["active"], h["name"].lower()))
    return {"total": matched, "active": active, "online": online, "shared": shared, "all_hosts": total_hosts, "items": found[:body.limit], "rules": [{"kind": k, "value": v} for k, v, _ in rules],
            "prepared": prepared, "note": "" if prepared else "Подготовленных данных о компьютерах ещё нет: первый расчёт выполняет фоновая служба."}


@admin_router.get("/overview/conflicts")
async def conflicts(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Компьютеры, подходящие нескольким зонам: спорные (равные приоритеты — видны во всех зонах) и решённые приоритетом или закреплением."""
    zdata = zd(request)
    names = {z["id"]: z["name"] for z in await zdata.zones_info(db)}
    idx = await S.index(db)
    out, counts = [], Counter()
    _sids, _all, srcs = await _scope(db, su)
    for src in srcs:
        async for chunk in ZR.base_records(db, src.id):
            for r in ZM.annotate(chunk, idx, str(src.id)):
                if len(r["zone_candidates"]) > 1:
                    counts[r["zone_via"]] += 1
                    if len(out) < 5000:
                        out.append({"source_id": str(src.id), "source": src.name, "host_id": r["host_id"], "name": r["name"], "ip": r["ip"], "via": r["zone_via"], "conflict": r["zone_conflict"],
                                    "zones": [{"id": z, "name": names.get(z, z), "chosen": z in r["zones"]} for z in r["zone_candidates"]]})
    out.sort(key=lambda x: (not x["conflict"], x["name"].lower()))
    return {"items": out[:1000], "total": sum(counts.values()), "by_via": dict(counts)}


@admin_router.get("/cache/status")
async def cache_status(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Подготовленные данные зон: расписание ночного расчёта, последний успешный расчёт и его длительность, ошибки, очередь заданий, ресурсы worker."""
    return await ZJ.status(db, request.app.state.settings_svc)


@admin_router.post("/cache/run", status_code=202)
async def cache_run(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Пересчитать данные всех зон сейчас (в очередь worker; одинаковое задание не дублируется)."""
    job, created = await ZJ.enqueue(db, "all", trigger="manual", by=su.display_name)
    if created:
        write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="zone.cache.run", target_type="zone", target_id="*", details={"job": str(job.id)})
    await db.commit()
    return {"created": created, "job": ZJ.job_out(job)}


class PinIn(BaseModel):
    source_id: uuid.UUID
    host_id: int
    host_name: str = Field(default="", max_length=300)
    zone_id: uuid.UUID


@admin_router.post("/pins", status_code=201)
async def pin(body: PinIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Явное решение по спорному компьютеру: он относится к указанной зоне, даже если подходит под несколько."""
    if await db.get(Zone, body.zone_id) is None or await db.get(KscSource, body.source_id) is None:
        raise HTTPException(status_code=404, detail="Зона или источник не найдены")
    cur = (await db.execute(select(ZonePin).where(ZonePin.source_id == body.source_id, ZonePin.host_id == body.host_id))).scalar_one_or_none()
    if cur:
        cur.zone_id, cur.created_by = body.zone_id, su.display_name
    else:
        db.add(ZonePin(source_id=body.source_id, host_id=body.host_id, host_name=body.host_name, zone_id=body.zone_id, created_by=su.display_name))
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="zone.pin", target_type="zone", target_id=str(body.zone_id), details={"host": body.host_name or body.host_id})
    await _members_changed(db, su)
    await db.commit()
    return {"ok": True}


@admin_router.delete("/pins/{source_id}/{host_id}", status_code=204)
async def unpin(source_id: uuid.UUID, host_id: int, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    cur = (await db.execute(select(ZonePin).where(ZonePin.source_id == source_id, ZonePin.host_id == host_id))).scalar_one_or_none()
    if cur:
        write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="zone.unpin", target_type="zone", target_id=str(cur.zone_id), details={"host": cur.host_name or host_id})
        await db.delete(cur)
        await _members_changed(db, su)
        await db.commit()
    return Response(status_code=204)


# ------------------------------------------------------------------------------------------------ CSV
async def _read_body(request: Request) -> bytes:
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > MAX_CSV:
            raise HTTPException(status_code=413, detail=f"Файл больше {MAX_CSV // (1024 * 1024)} МБ")
    return bytes(data)


@admin_router.get("/csv/sample")
async def csv_sample(su: SessionUser = Depends(require_admin)):
    return Response(csv_io.sample_csv(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="zones-sample.csv"'})


@admin_router.get("/csv/export")
async def csv_export(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    ex = await S.existing(db)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="zone.csv.export", target_type="zone", target_id="*", details={"zones": len(ex)})
    await db.commit()
    return Response(csv_io.to_csv(csv_io.export_rows(ex)), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="zones-{datetime.now(timezone.utc):%Y%m%d}.csv"'})


@admin_router.post("/csv/preview")
async def csv_preview(request: Request, mode: str = Query("add_update", pattern="^(add_update|add_only|replace)$"), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Разбор файла и план изменений без записи: сколько зон создано/обновлено, какие строки с ошибками, пересечения сетей."""
    data = await _read_body(request)
    plan = csv_io.plan(csv_io.parse(data), await S.existing(db), mode)
    return plan.public()


@admin_router.post("/csv/apply")
async def csv_apply(request: Request, mode: str = Query("add_update", pattern="^(add_update|add_only|replace)$"), expect: str = Query("", max_length=40), confirm: bool = False,
                    su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Применение одной транзакцией. expect — отпечаток плана из просмотра: если данные изменились после просмотра, применение отклоняется. replace требует confirm=true."""
    data = await _read_body(request)
    plan = csv_io.plan(csv_io.parse(data), await S.existing(db), mode, confirm=confirm)
    if mode == "replace" and not confirm:
        raise HTTPException(status_code=422, detail="Полная замена удаляет всё, чего нет в файле. Подтвердите её явно.")
    if not plan.ok:
        raise HTTPException(status_code=422, detail={"message": "Файл содержит ошибки: изменения не применены.", "errors": plan.errors[:50]})
    if expect and expect != plan.fingerprint():
        raise HTTPException(status_code=409, detail="Данные изменились после просмотра. Откройте просмотр заново.")
    try:
        done = await S.apply_plan(db, plan, su.display_name)
    except Exception:
        await db.rollback()
        raise
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="zone.csv.import", target_type="zone", target_id="*", details={"mode": mode, **done, "rows": plan.summary["rows"]})
    await _members_changed(db, su)
    await db.commit()
    return {"done": done, "summary": plan.summary}


# ------------------------------------------------------------------------------------------------ страницы анализа
def _host_out(h: dict) -> dict:
    """Строка таблицы компьютеров зоны (без строк обнаружений: они — в карточке компьютера)."""
    return {"source_id": h["source_id"], "source": h["source"], "host_id": h["host_id"], "name": h["name"], "fqdn": h["fqdn"], "ip": h["ip"], "os": h["os"], "group": h["group"],
            "last_connected": h["last_connected"], "days_since_connection": h["days_since_connection"], "active": h["active"], "online": h["online"], "max_sev": h["max_sev"],
            "max_sev_ru": D.SEV_RU[h["max_sev"]], "max_sev_basis": h["max_sev_basis"], "ksc": h["ksc"], "ext": h["ext"], "problems": [{"key": k, "title": P.PROBLEMS[k][0]} for k in h["problems"]],
            "state": h["state"], "summary": h["summary"], "zones": h["zones"], "zone_conflict": h["zone_conflict"], "zone_pinned": h["zone_pinned"]}


async def _scope(db: AsyncSession, su: SessionUser) -> tuple[list[uuid.UUID], bool, list[KscSource]]:
    """Источники, доступные пользователю: (идентификаторы, доступны ли все активные, сами источники)."""
    allv = (await db.execute(select(KscSource).where(KscSource.is_active.is_(True)).order_by(KscSource.position, KscSource.name))).scalars().all()
    mine = [s for s in allv if su.can_use_source(s.id)]
    return [s.id for s in mine], len(mine) == len(allv), mine


def _freshness(states: list[dict], dash, job, sids: list[str]) -> dict:
    """Сведения об актуальности для страницы: когда данные получены из KSC, есть ли более свежие, идёт ли пересчёт."""
    mine = [s for s in states if s["id"] in sids]
    built = [s["built_at"] for s in mine if s["built_at"]]
    return {"empty": not any(s["gen"] for s in mine), "data_at": dash.data_at if dash is not None and dash.data_at else (min(built) if built else None),
            "calculated_at": dash.built_at if dash is not None else None, "newer": any(s["newer"] for s in mine), "errors": [{"source": s["name"], "error": s["error"]} for s in mine if s["error"]],
            "building": [s["name"] for s in mine if s["progress"]], "job": ZJ.job_out(job) if job is not None else None,
            "sources": [{"id": s["id"], "name": s["name"], "built_at": s["built_at"], "status": s["status"], "agg_only": s["agg_only"]} for s in mine]}


async def _active_job(db: AsyncSession, zid: str | None):
    """Выполняющееся или ожидающее задание, относящееся к зоне (её собственное или общий расчёт)."""
    q = select(ZcJob).where(ZcJob.status.in_(("queued", "running")))
    rows = (await db.execute(q.order_by(ZcJob.requested_at))).scalars().all()
    return next((j for j in rows if j.kind in ("all", "members") or (zid is not None and j.kind == "zone" and j.zone_id == zid)), None)


@router.get("")
async def overview(request: Request, q_: str = Query("", alias="q", max_length=200), state: str = Query("", pattern="^(|critical|vulns|protection|ok)$"),
                   sort: str = Query("risk", pattern="^(risk|name|hosts|problems|critical|protection)$"), desc: bool = True,
                   su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Все зоны с показателями из подготовленных данных (без обращения к KSC): компьютеры, активные, онлайн, проблемные, критические, проблемы защиты; ответственные."""
    zdata = zd(request)
    infos = await zdata.zones_info(db)
    sids, all_ok, srcs = await _scope(db, su)
    general = await request.app.state.settings_svc.get(db, "general")
    zdays = await ZR.zone_days_map(db)
    dashes = {d.zone_id: d for d in (await db.execute(select(ZcDashboard).where(ZcDashboard.kind == "default"))).scalars()}
    if all_ok and dashes:
        stats = {z: d.payload.get("stats") for z, d in dashes.items()}
        confl = {z: d.payload.get("conflicts", 0) for z, d in dashes.items()}
    else:                                           # ограниченный доступ к источникам или сводки ещё нет: агрегаты SQL по доступным источникам
        stats = await ZR.group_stats(db, sids=sids, default_days=int(general.activity_days), zone_days=zdays)
        confl = {z: c for z, (_n, c) in (await ZR.conflict_counts(db, sids)).items()}
    eol_on = bool((await request.app.state.settings_svc.get(db, "eol")).include_in_analytics)       # type: ignore[attr-defined]
    eol_ready, eol_missing = await EOLR.readiness(db, sids) if eol_on else ([], [])
    if eol_missing:
        eol_sids = eol_ready                            # итоги — только по рассчитанным источникам; по остальным сообщается `eol_missing` (данные неполные, нули не показываем как результат)
        if not eol_ready:
            eol_on = False                              # не рассчитан ни один источник: колонка скрыта
    else:
        eol_sids = sids
    eol = (await request.app.state.cache.get(("eol-zones", tuple(sorted(map(str, eol_sids or [])))), 60, lambda: EOLR.zone_counts(db, eol_sids)))[0] if eol_on else {}       # раз в минуту: не агрегировать итоги EOL при каждом открытии
    rows = []
    unassigned = {"id": UNASSIGNED, "name": "Без ответственного", "description": "Компьютеры, не подошедшие ни одной зоне", "purpose": "", "priority": 0, "contacts": [], "enabled": True, "activity_days": None}
    for z in infos + [unassigned]:
        st = stats.get(z["id"]) or ZR._empty_stats()  # noqa: SLF001
        rows.append({"id": z["id"], "name": z["name"], "description": z["description"], "purpose": z["purpose"], "enabled": z["enabled"],
                     "stats": {k: st[k] for k in ("total", "active", "online", "critical", "other_vulns", "protection", "ok", "state", "inactive")},
                     "problem_hosts": st["in_scope"] - st["ok"], "conflicts": confl.get(z["id"], 0), "eol": (eol.get(z["id"]) or EOLR.EMPTY) if eol_on else None,
                     "responsible": [(c["name"] or c["email"]) + (f" ({c['position']})" if c["position"] else "") for c in z["contacts"] if c["role"] == "responsible"][:3],
                     "contacts_n": len([c for c in z["contacts"] if c["enabled"]]), "activity_days": z["activity_days"] or general.activity_days})
    needle = matcher(q_)
    if needle:
        rows = [r for r in rows if needle(r["name"]) or needle(r["description"]) or any(needle(x) for x in r["responsible"])]
    if state:
        rows = [r for r in rows if r["stats"]["state"].get(state, 0) > 0]
    key = {"risk": lambda r: (r["stats"]["critical"], r["problem_hosts"], r["stats"]["protection"]), "name": lambda r: r["name"].lower(), "hosts": lambda r: r["stats"]["total"],
           "problems": lambda r: r["problem_hosts"], "critical": lambda r: r["stats"]["critical"], "protection": lambda r: r["stats"]["protection"]}[sort]
    rows.sort(key=key, reverse=desc if sort != "name" else not desc)
    rows.sort(key=lambda r: r["id"] == UNASSIGNED)             # «Без ответственного» — всегда последней
    tot = await ZR.totals(db, sids)
    states = await ZR.source_states(db, sids)
    job = await _active_job(db, None)
    dsample = next(iter(dashes.values()), None)
    fr = _freshness(states, dsample, job, [str(i) for i in sids])
    return {"items": rows, "totals": {"zones": len(infos), "hosts": tot["unique_hosts"], "unique_hosts": tot["unique_hosts"], "unassigned": (stats.get(UNASSIGNED) or {}).get("total", 0), "conflicts": tot["conflicts"]},
            "sources": [s.name for s in srcs], "activity_days": general.activity_days, "notes": list(dict.fromkeys(n for ns in await _notes(db, sids) for n in ns)), "fetched_at": fr["data_at"], "freshness": fr, "eol_missing": eol_missing}


@router.get("/{zid}")
async def dashboard(zid: str, request: Request, state: str = Query("", pattern="^(|critical|vulns|protection|potential|ok)$"), severity: str = Query("", pattern="^(|critical|high|warning|none)$"),
                    problem: str = Query("", pattern="^(|" + "|".join(P.PROBLEMS) + ")$"), q_: str = Query("", alias="q", max_length=200), online: str = Query("", pattern="^(|yes|no)$"),
                    activity: str = Query("active", pattern="^(active|all|inactive)$"), triage: str = Query("attention", pattern="^(attention|all|review|confirmed|false_positive|obsolete|risk_accepted)$"),
                    cve: str = Query("", max_length=100), product: str = Query("", max_length=200), ext: bool = True, source_id: str = Query("", max_length=40),
                    sort: str = Query("risk", pattern="^(risk|name|ip|last_connected|vulns)$"), desc: bool = True, offset: int = Query(0, ge=0), limit: int = Query(50, ge=0, le=500),
                    bases_days: int = Query(3, ge=1, le=90), scan_days: int = Query(30, ge=1, le=365),
                    su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Дашборд зоны из подготовленных данных: показатели и данные диаграмм читаются готовыми (или считаются агрегатом SQL при нестандартных порогах), таблица компьютеров — страница с фильтрами
    и сортировкой в SQL. KSC не опрашивается, расчёт не запускается."""
    if zid != UNASSIGNED:
        _uid(zid)
    zdata = zd(request)
    info = next((z for z in await zdata.zones_info(db) if z["id"] == zid), None) if zid != UNASSIGNED else \
        {"id": UNASSIGNED, "name": "Без ответственного", "description": "Компьютеры, не подошедшие ни одной зоне. Добавьте для них сети или группы в нужной зоне либо закрепите вручную.", "purpose": "", "priority": 0, "contacts": [], "enabled": True, "activity_days": None}
    if info is None:
        raise HTTPException(status_code=404, detail="Зона не найдена")
    general = await request.app.state.settings_svc.get(db, "general")
    sids, all_ok, srcs = await _scope(db, su)
    if source_id:
        try:
            one = uuid.UUID(source_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="Некорректный источник") from None
        sids = [one] if one in sids else []
    zdays = await ZR.zone_days_map(db)
    days = info["activity_days"] or general.activity_days
    dash = await ZR.read_dashboard(db, zid)
    default = bases_days == ZR.DEFAULT_BD and scan_days == ZR.DEFAULT_SD and ext and all_ok and not source_id
    if default and dash is not None:
        stat = dash.payload["stats"]
        conflicts = dash.payload.get("conflicts", 0)
    else:                                           # нестандартные пороги, ограниченный доступ или сводки ещё нет: тот же агрегат SQL «на лету» (быстро, без KSC)
        stat = (await ZR.group_stats(db, sids=sids, zone_id=zid, bd=bases_days, sd=scan_days, ext=ext, default_days=int(general.activity_days), zone_days=zdays)).get(zid) or ZR._empty_stats()  # noqa: SLF001
        conflicts = (await ZR.conflict_counts(db, sids)).get(zid, (0, 0))[1]
    stat = {**stat, "bars": {"severity": stat["severity"], "problems": stat["problems"], "vulns": stat["vulns"]}, "eol": ((await EOLR.zone_counts(db, sids, zid)).get(zid) or EOLR.EMPTY) if (await request.app.state.settings_svc.get(db, "eol")).include_in_analytics else None}  # type: ignore[attr-defined]
    stat["eol_missing"] = (await EOLR.readiness(db, sids))[1] if stat.get("eol") is not None else []          # EOL по этим источникам не рассчитан: числа выше неполные
    total, items = await ZR.hosts_page(db, zid, sids, bd=bases_days, sd=scan_days, ext=ext, default_days=int(general.activity_days), zone_days=zdays, state=state, severity=severity, problem=problem,
                                       q=q_, online=online, activity=activity, triage=triage, cve=cve, product=product, source_id=source_id, sort=sort, desc=desc, offset=offset, limit=limit)
    states = await ZR.source_states(db, sids)
    fr = _freshness(states, dash, await _active_job(db, zid), [str(i) for i in sids])
    notes = list(dict.fromkeys(n for ns in await _notes(db, sids) for n in ns))
    return {"zone": info, "stats": stat, "activity_days": days, "total": total, "offset": offset, "limit": limit, "items": items,
            "sources": [{"id": str(s.id), "name": s.name} for s in srcs], "notes": notes, "fetched_at": fr["data_at"], "conflicts": conflicts, "ext_included": ext, "freshness": fr,
            "ext_cap": (await request.app.state.settings_svc.get(db, "zonecache")).ext_per_host}


async def _notes(db: AsyncSession, sids: list[uuid.UUID]) -> list[list[str]]:
    return [list(n or []) for (n,) in (await db.execute(select(ZcSource.notes).where(ZcSource.source_id.in_(sids), ZcSource.gen > 0))).all()]


@router.post("/{zid}/refresh", status_code=202)
async def refresh(zid: str, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Поставить в очередь пересчёт данных одной зоны («Обновить данные»): запрос возвращается сразу, расчёт выполняет worker; одинаковые задания не дублируются."""
    if zid != UNASSIGNED:
        if await db.get(Zone, _uid(zid)) is None:
            raise HTTPException(status_code=404, detail="Зона не найдена")
    job, created = await ZJ.enqueue(db, "zone", zone_id=zid, trigger="manual", by=su.display_name)
    if created:
        write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="zone.refresh", target_type="zone", target_id=zid, details={"job": str(job.id)})
    await db.commit()
    return {"created": created, "job": ZJ.job_out(job)}


@router.get("/{zid}/refresh")
async def refresh_state(zid: str, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Ход пересчёта зоны: активное задание (своё или общий расчёт) или последнее завершённое."""
    job = await _active_job(db, zid)
    last = None
    if job is None:
        last = (await db.execute(select(ZcJob).where(ZcJob.kind == "zone", ZcJob.zone_id == zid).order_by(ZcJob.requested_at.desc()).limit(1))).scalars().first()
    dash = await ZR.read_dashboard(db, zid)
    return {"job": ZJ.job_out(job) if job else None, "last": ZJ.job_out(last) if last else None, "data_at": dash.data_at if dash else None, "calculated_at": dash.built_at if dash else None}


@router.get("/{zid}/hosts/{source_id}/{host_id}")
async def host_card(zid: str, source_id: str, host_id: int, request: Request, ext: bool = True, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Карточка компьютера: уязвимости KSC и потенциальные совпадения (с решениями), принятые и исключённые обнаружения, проблемы защиты, зона и ответственные."""
    try:
        sid = uuid.UUID(source_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Компьютер не найден") from None
    if not su.can_use_source(sid):
        raise HTTPException(status_code=403, detail="Нет доступа к источнику")
    src = await db.get(KscSource, sid)
    h = await ZR.load_host(db, sid, host_id, source_name=src.name if src else "")
    if h is None:
        raise HTTPException(status_code=404, detail="Компьютер не найден среди доступных источников")
    if not ext:
        h["rows"]["ext"] = {"current": [], "accepted": [], "excluded": []}
    infos = {z["id"]: z for z in await zd(request).zones_info(db)}
    zs = [{"id": z, "name": infos[z]["name"], "contacts": [c for c in infos[z]["contacts"] if c["role"] != "cc"]} for z in h["zones"] if z in infos]
    av = h["av"] or {}
    prot = [{"key": k, "title": P.PROBLEMS[k][0], "detail": R._detail(h, k, 3, 30)} for k in h["problems"]]  # noqa: SLF001
    rows = {o: {b: [{k: v for k, v in r.items() if k not in ("zones",)} for r in rs] for b, rs in h["rows"][o].items()} for o in ("ksc", "ext")}
    return {**_host_out(h), "zones_info": zs, "candidates": [{"id": z, "name": infos[z]["name"] if z in infos else z} for z in h["zone_candidates"]], "zone_via": h["zone_via"], "protection": prot,
            "av": {"product": av.get("product"), "build": av.get("build"), "state": av.get("state_label"), "bases": av.get("bases"), "rtp": h["rtp_label"], "last_full_scan": h["last_full_scan"], "agent": h["agent_build"],
                   "ksc_status": h["ksc_status"]}, "rows": rows}


@router.get("/of-host/{source_id}/{host_id}")
async def of_host(source_id: uuid.UUID, host_id: int, request: Request, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Зона компьютера и её ответственные — для карточек компьютеров и уязвимостей в других разделах (из подготовленных данных, без обращения к KSC)."""
    if not su.can_use_source(source_id):
        raise HTTPException(status_code=403, detail="Нет доступа к источнику")
    if await db.get(KscSource, source_id) is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    rec = await ZR.host_zone_ids(db, source_id, host_id)
    if rec is None:
        return {"zones": [], "candidates": [], "conflict": False, "prepared": False}
    infos = {z["id"]: z for z in await zd(request).zones_info(db)}
    f = lambda ids: [{"id": z, "name": infos[z]["name"], "responsible": [(c["name"] or c["email"]) for c in infos[z]["contacts"] if c["role"] == "responsible" and c["enabled"]][:3]} for z in ids if z in infos]  # noqa: E731
    return {"zones": f(rec["zones"]), "candidates": f(rec["candidates"]), "conflict": rec["conflict"], "pinned": rec["pinned"], "via": rec["via"], "prepared": True}


async def zone_host_ids(request: Request, db: AsyncSession, src: KscSource, zone: str) -> set[int]:
    """Идентификаторы компьютеров источника, принадлежащих зоне (или «none» — без ответственного): общий фильтр «Зона» разделов приложения (из подготовленных данных)."""
    if zone != UNASSIGNED:
        _uid(zone)
    ids = await ZR.host_ids_in_zone(db, src.id, zone)
    if ids is None:
        raise HTTPException(status_code=409, detail="Данные зон ещё не рассчитаны: первый расчёт выполняется фоновой службой, повторите позже или запустите его в разделе «Администрирование → Зоны → Расчёт»")
    return ids


async def zone_labels(db: AsyncSession, src: KscSource, rows: list[dict]) -> None:
    """Добавляет строкам компьютеров поле zone — подпись зоны для столбца «Зона» в разделах (одна выборка зон на страницу, без обращения к KSC)."""
    defs = await S.load_defs(db)
    if not defs:
        return
    names = {d.id: d.name for d in defs}
    idx = ZM.ZoneIndex(defs, await S.load_pins(db))
    for r in rows:
        a = idx.assign(r.get("host_id"), str(src.id), name=r.get("name") or "", fqdn=r.get("fqdn") or "", group=r.get("group") or "", ips=[r["ip"]] if r.get("ip") else [])
        r["zone"] = " / ".join(names[z] for z in a.zone_ids if z in names) + (" (спорный)" if a.conflict else "") if a.zone_ids else "Без ответственного"


@router.get("/options/list")
async def zone_options(su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Короткий список зон для фильтров «Зона ответственности»."""
    zs = (await db.execute(select(Zone.id, Zone.name).where(Zone.enabled.is_(True)).order_by(Zone.name))).all()
    return {"items": [{"id": str(i), "name": n} for i, n in zs] + [{"id": UNASSIGNED, "name": "Без ответственного"}]}


# ------------------------------------------------------------------------------------------------ обработка уязвимостей
class TriageIn(BaseModel):
    source_id: uuid.UUID
    vuln_key: str = Field(min_length=3, max_length=80)
    origin: Literal["ksc", "ext"] = "ksc"
    scope: Literal["host", "product", "zone"] = "host"
    host_id: int | None = None
    host_name: str = Field(default="", max_length=300)
    zone_id: uuid.UUID | None = None
    product: str = Field(default="", max_length=300)
    version: str = Field(default="", max_length=120)
    status: Literal["review", "confirmed", "false_positive", "obsolete", "risk_accepted"]
    reason: str = Field(default="", max_length=40)
    comment: str = Field(default="", max_length=T.MAX_COMMENT)
    review_until: datetime | None = None


class TriageBulk(BaseModel):
    items: list[TriageIn] = Field(min_length=1, max_length=200)


def _check_rights(su: SessionUser, b: TriageIn) -> None:
    if not su.can_use_source(b.source_id):
        raise HTTPException(status_code=403, detail="Нет доступа к источнику")
    if (b.scope != "host" or b.status == "risk_accepted") and not su.is_admin:
        raise HTTPException(status_code=403, detail="Решение шире одного компьютера и принятие риска доступны только администратору")
    if su.role == "viewer":
        raise HTTPException(status_code=403, detail="Нужны права аналитика")


async def _apply_triage(db: AsyncSession, su: SessionUser, b: TriageIn) -> VulnTriage:
    _check_rights(su, b)
    try:
        t = await T.set_decision(db, source_id=b.source_id, actor=su.display_name, scope=b.scope, vuln_key=b.vuln_key, status=b.status, origin=b.origin, host_id=b.host_id, host_name=b.host_name, zone_id=b.zone_id,
                                 product=b.product, version=b.version, reason=b.reason, comment=b.comment, review_until=b.review_until)
    except T.TriageError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="triage.set", target_type="vuln_triage", target_id=str(t.id), source_id=b.source_id,
                details={"vuln": t.vuln_key, "scope": t.scope, "host": t.host_name or t.host_id, "status": t.status, "product": t.product, "reason": t.reason})
    return t


async def _retriage(request: Request, keys: dict[uuid.UUID, set[str]]) -> None:
    """Решения применяются к сохранённым строкам сразу (только затронутые обнаружения), итоги компьютеров и сводки зон обновляются без обращения к KSC."""
    st = request.app.state
    for sid, ks in keys.items():
        await SN.retriage(st.session_maker, sid, ks)
    async with st.session_maker() as db:
        days = int((await st.settings_svc.get(db, "general")).activity_days)
    await ZR.refresh_dashboards(st.session_maker, None, default_days=days, data_at=None)


def _triage_out(t: VulnTriage) -> dict:
    until = t.review_until.replace(tzinfo=timezone.utc) if t.review_until is not None and t.review_until.tzinfo is None else t.review_until
    expired = t.status == "risk_accepted" and until is not None and until < datetime.now(timezone.utc)
    return {"id": str(t.id), "source_id": str(t.source_id), "scope": t.scope, "scope_ru": T.SCOPE_RU[t.scope], "host_id": t.host_id, "host_name": t.host_name, "zone_id": str(t.zone_id) if t.zone_id else None,
            "vuln_key": t.vuln_key, "origin": t.origin, "product": t.product, "version": t.version, "status": "review" if (t.recheck or expired) else t.status, "stored_status": t.status,
            "status_ru": T.STATUS_RU["review" if (t.recheck or expired) else t.status], "stored_status_ru": T.STATUS_RU[t.status], "reason": t.reason, "reason_ru": T.REASONS.get(t.reason, ""), "comment": t.comment,
            "review_until": t.review_until, "recheck": t.recheck, "recheck_reason": t.recheck_reason or ("срок пересмотра принятого риска истёк" if expired else ""), "created_by": t.created_by,
            "created_at": t.created_at, "updated_at": t.updated_at}


@triage_router.get("/meta")
async def triage_meta(su: SessionUser = Depends(require_user)):
    return {"statuses": [{"key": k, "title": v} for k, v in T.STATUS_RU.items()], "reasons": [{"key": k, "title": v} for k, v in T.REASONS.items()], "scopes": [{"key": k, "title": v} for k, v in T.SCOPE_RU.items()],
            "default_review_days": T.DEFAULT_REVIEW_DAYS, "can_wide": su.is_admin, "can_set": su.role in ("analyst", "admin")}


@triage_router.post("")
async def triage_set(body: TriageIn, request: Request, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    t = await _apply_triage(db, su, body)
    await db.commit()
    await _retriage(request, {t.source_id: {t.vuln_key}})
    return _triage_out(t)


@triage_router.post("/bulk")
async def triage_bulk(body: TriageBulk, request: Request, su: SessionUser = Depends(require_analyst), db: AsyncSession = Depends(get_db)):
    """Одно решение для нескольких обнаружений (одной транзакцией): либо все, либо ни одного."""
    ts = [await _apply_triage(db, su, b) for b in body.items]
    out = [_triage_out(t) for t in ts]
    await db.commit()
    keys: dict[uuid.UUID, set[str]] = {}
    for t in ts:
        keys.setdefault(t.source_id, set()).add(t.vuln_key)
    await _retriage(request, keys)
    return {"items": out, "count": len(out)}


@triage_router.get("")
async def triage_list(source_id: uuid.UUID, status: str = Query("", pattern="^(|review|confirmed|false_positive|obsolete|risk_accepted|recheck|expiring)$"), q_: str = Query("", alias="q", max_length=200),
                      scope: str = Query("", pattern="^(|host|product|zone)$"), offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                      su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Журнал решений по уязвимостям источника: что и кем признано ложным, неактуальным, принято по риску; что вернулось на проверку и что скоро истекает."""
    if not su.can_use_source(source_id):
        raise HTTPException(status_code=403, detail="Нет доступа к источнику")
    await T.sweep_expired(db, source_id)
    await db.commit()
    stmt = select(VulnTriage).where(VulnTriage.source_id == source_id)
    if scope:
        stmt = stmt.where(VulnTriage.scope == scope)
    if status == "recheck":
        stmt = stmt.where(VulnTriage.recheck.is_(True))
    elif status == "expiring":
        stmt = stmt.where(VulnTriage.status == "risk_accepted", VulnTriage.review_until < datetime.now(timezone.utc) + timedelta(days=14))
    elif status:
        stmt = stmt.where(VulnTriage.status == status)
    rows = (await db.execute(stmt.order_by(VulnTriage.updated_at.desc()))).scalars().all()
    m = any_field(q_)
    if m:
        rows = [r for r in rows if m(r.vuln_key, r.host_name, r.product, r.comment, r.created_by)]
    counts = Counter(r.status for r in (await db.execute(select(VulnTriage).where(VulnTriage.source_id == source_id))).scalars())
    return {"items": [_triage_out(r) for r in rows[offset:offset + limit]], "total": len(rows), "counts": dict(counts), "offset": offset, "limit": limit}


@triage_router.get("/{tid}/history")
async def triage_history(tid: uuid.UUID, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    t = await db.get(VulnTriage, tid)
    if t is None or not su.can_use_source(t.source_id):
        raise HTTPException(status_code=404, detail="Решение не найдено")
    return {"decision": _triage_out(t), "events": await T.history(db, tid)}


# ------------------------------------------------------------------------------------------------ почта и расписания
@mail_router.post("/check")
async def mail_check(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    cfg = await request.app.state.settings_svc.get(db, "smtp")
    res = await M.test_connection(cfg)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="mail.check", target_type="smtp", target_id=cfg.host, result="success" if res.ok else "failure")
    await db.commit()
    return {"ok": res.ok, "error": res.error, "transient": res.transient}


class TestMail(BaseModel):
    to: str = Field(min_length=3, max_length=254)


@mail_router.post("/test")
async def mail_test(body: TestMail, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Тестовое письмо на указанный адрес. «Принято сервером» — не доставка."""
    to = body.to.strip().lower()
    if not csv_io.valid_email(to):
        raise HTTPException(status_code=422, detail="Адрес электронной почты записан неверно")
    cfg = await request.app.state.settings_svc.get(db, "smtp")
    org = await request.app.state.settings_svc.get(db, "organization")
    who = org.short_name or org.full_name or "KAV Checker"
    msg = M.compose(cfg, to=[to], cc=[], subject="KAV Checker: тестовое письмо",
                    text=f"Это тестовое письмо KAV Checker ({who}). Если вы его получили, отправка отчётов настроена верно.", html=f"<p>Это тестовое письмо KAV Checker ({who}).</p><p>Если вы его получили, отправка отчётов настроена верно.</p>")
    res = await M.send(cfg, msg, [to])
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="mail.test", target_type="smtp", target_id=to, result="success" if res.ok else "failure")
    await db.commit()
    return {"ok": res.ok, "error": res.error, "refused": res.refused, "note": "Сервер принял письмо; это не означает доставку и прочтение." if res.ok else ""}


class ScheduleIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    enabled: bool = True
    zone_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    include_unassigned: bool = False
    sections: list[str] = Field(default_factory=lambda: list(R.DEFAULT_CATEGORIES), min_length=1, max_length=20)
    filters: dict = Field(default_factory=dict)
    level: Literal["management", "technical"] = "management"
    frequency: Literal["daily", "weekly", "monthly"] = "weekly"
    weekday: int = Field(default=0, ge=0, le=6)
    monthday: int = Field(default=1, ge=1, le=31)
    at_time: str = Field(default="08:00", pattern=r"^\d{2}:\d{2}$")
    tz: str = Field(default="UTC", max_length=64)
    attach_html: bool = True
    attach_xlsx: bool = False
    skip_empty: bool = False


def _clean_filters(f: dict) -> dict:
    out = {}
    if f.get("severity") in ("critical", "high"):
        out["severity"] = f["severity"]
    for k in ("online_only", "include_inactive", "show_excluded"):
        if f.get(k):
            out[k] = True
    for k, lo, hi in (("bases_days", 1, 90), ("scan_days", 1, 365)):
        if f.get(k) is not None:
            try:
                out[k] = max(lo, min(hi, int(f[k])))
            except (TypeError, ValueError):
                pass
    if f.get("source_ids"):
        out["source_ids"] = [str(uuid.UUID(str(s))) for s in f["source_ids"]][:50]
    return out


def _sched_out(s: ReportSchedule, zones: dict[str, str], recipients_n: dict[str, int] | None = None) -> dict:
    return {"id": str(s.id), "name": s.name, "enabled": s.enabled, "zone_ids": [str(z) for z in s.zone_ids or []], "zone_names": [zones.get(str(z), "?") for z in s.zone_ids or []], "all_zones": not s.zone_ids,
            "include_unassigned": s.include_unassigned, "sections": s.sections, "sections_ru": [R.CATEGORIES.get(c, c) for c in s.sections or []], "filters": s.filters, "level": s.level, "level_ru": R.LEVELS.get(s.level, s.level),
            "frequency": s.frequency, "weekday": s.weekday, "monthday": s.monthday, "at_time": s.at_time, "tz": s.tz, "when": SC.describe(s.frequency, s.weekday, s.monthday, s.at_time, s.tz),
            "attach_html": s.attach_html, "attach_xlsx": s.attach_xlsx, "skip_empty": s.skip_empty, "next_run_at": s.next_run_at if s.enabled else None, "last_run_at": s.last_run_at,
            "last_period": s.last_period, "created_by": s.created_by, "created_at": s.created_at}


async def _sched_apply(s: ReportSchedule, b: ScheduleIn, db: AsyncSession) -> None:
    try:
        SC.parse_time(b.at_time)
        SC.tz_of(b.tz)
        flt = _clean_filters(b.filters)
    except (SC.ScheduleError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    bad = [c for c in b.sections if c not in R.CATEGORIES]
    if bad:
        raise HTTPException(status_code=422, detail=f"Неизвестные категории отчёта: {', '.join(bad)}")
    if b.zone_ids:
        n = (await db.execute(select(func.count()).select_from(Zone).where(Zone.id.in_(b.zone_ids)))).scalar_one()
        if n != len(set(b.zone_ids)):
            raise HTTPException(status_code=422, detail="Одна из выбранных зон не найдена")
    s.name, s.enabled, s.zone_ids, s.include_unassigned, s.sections, s.filters = b.name.strip(), b.enabled, [str(z) for z in dict.fromkeys(b.zone_ids)], b.include_unassigned, b.sections, flt
    s.level, s.frequency, s.weekday, s.monthday, s.at_time, s.tz, s.attach_html, s.attach_xlsx, s.skip_empty = b.level, b.frequency, b.weekday, b.monthday, b.at_time, b.tz, b.attach_html, b.attach_xlsx, b.skip_empty
    s.updated_at = datetime.now(timezone.utc)
    s.next_run_at = SC.next_after(b.frequency, b.weekday, b.monthday, b.at_time, b.tz, datetime.now(timezone.utc)) if b.enabled else None


async def _zone_names(db: AsyncSession) -> dict[str, str]:
    return {str(i): n for i, n in (await db.execute(select(Zone.id, Zone.name))).all()}


@mail_router.get("/schedules")
async def schedules(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    names = await _zone_names(db)
    rows = (await db.execute(select(ReportSchedule).order_by(ReportSchedule.name))).scalars().all()
    return {"items": [_sched_out(s, names) for s in rows], "categories": [{"key": k, "title": v} for k, v in R.CATEGORIES.items()]}


@mail_router.post("/schedules", status_code=201)
async def schedule_create(body: ScheduleIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    s = ReportSchedule(id=uuid.uuid4(), created_by=su.display_name)
    await _sched_apply(s, body, db)
    db.add(s)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="mail.schedule.create", target_type="schedule", target_id=str(s.id), details={"name": s.name, "when": SC.describe(s.frequency, s.weekday, s.monthday, s.at_time, s.tz)})
    await db.commit()
    return _sched_out(s, await _zone_names(db))


@mail_router.put("/schedules/{sid}")
async def schedule_update(sid: uuid.UUID, body: ScheduleIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    s = await db.get(ReportSchedule, sid)
    if s is None:
        raise HTTPException(status_code=404, detail="Расписание не найдено")
    await _sched_apply(s, body, db)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="mail.schedule.update", target_type="schedule", target_id=str(s.id), details={"name": s.name, "enabled": s.enabled})
    await db.commit()
    return _sched_out(s, await _zone_names(db))


@mail_router.post("/schedules/{sid}/toggle")
async def schedule_toggle(sid: uuid.UUID, enabled: bool, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Временно отключить или включить расписание. При включении следующий запуск считается от текущего момента: пропущенные за время отключения запуски не нагоняются."""
    s = await db.get(ReportSchedule, sid)
    if s is None:
        raise HTTPException(status_code=404, detail="Расписание не найдено")
    s.enabled = enabled
    s.next_run_at = SC.next_after(s.frequency, s.weekday, s.monthday, s.at_time, s.tz, datetime.now(timezone.utc)) if enabled else None
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="mail.schedule.toggle", target_type="schedule", target_id=str(s.id), details={"enabled": enabled})
    await db.commit()
    return _sched_out(s, await _zone_names(db))


@mail_router.delete("/schedules/{sid}", status_code=204)
async def schedule_delete(sid: uuid.UUID, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    s = await db.get(ReportSchedule, sid)
    if s is None:
        raise HTTPException(status_code=404, detail="Расписание не найдено")
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="mail.schedule.delete", target_type="schedule", target_id=str(s.id), details={"name": s.name})
    await db.delete(s)
    await db.commit()
    return Response(status_code=204)


class RunIn(BaseModel):
    zone_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)


@mail_router.post("/schedules/{sid}/run")
async def schedule_run(sid: uuid.UUID, request: Request, body: RunIn | None = None, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Отправить отчёт вручную сейчас (всем зонам правила или выбранным). Письмо ставится в очередь; период у такой отправки собственный, расписание не сдвигается."""
    s = await db.get(ReportSchedule, sid)
    if s is None:
        raise HTTPException(status_code=404, detail="Расписание не найдено")
    mlr = mailer.Mailer(request.app.state.session_maker, request.app.state.settings, request.app.state.settings_svc, zd(request), request.app.state.journal)
    period = f"manual-{datetime.now(timezone.utc):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}"
    res = await mlr.enqueue(db, s, period=period, kind="manual", zone_ids=[str(z) for z in body.zone_ids] if body and body.zone_ids else None)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="mail.schedule.run", target_type="schedule", target_id=str(s.id), details=res)
    await db.commit()
    return res


def _outbox_out(r: MailOutbox) -> dict:
    return {"id": str(r.id), "schedule_id": str(r.schedule_id) if r.schedule_id else None, "zone_id": str(r.zone_id) if r.zone_id else None, "zone_name": r.zone_name, "period_key": r.period_key,
            "kind": r.kind, "status": r.status, "subject": r.subject, "to": r.to_addrs, "cc": r.cc_addrs, "stats": r.stats, "attempts": r.attempts, "last_error": r.last_error, "refused": r.refused,
            "created_at": r.created_at, "next_attempt_at": r.next_attempt_at if r.status == "queued" else None, "sent_at": r.sent_at}


@mail_router.get("/outbox")
async def outbox(status: str = Query("", pattern="^(|queued|sending|accepted|failed|skipped)$"), schedule_id: uuid.UUID | None = None, q_: str = Query("", alias="q", max_length=200),
                 offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """История и очередь рассылок: когда сформирован отчёт, кому направлен, принят ли сервером SMTP, когда следующая попытка."""
    stmt = select(MailOutbox)
    if status:
        stmt = stmt.where(MailOutbox.status == status)
    if schedule_id:
        stmt = stmt.where(MailOutbox.schedule_id == schedule_id)
    rows = (await db.execute(stmt.order_by(MailOutbox.created_at.desc()).limit(2000))).scalars().all()
    m = any_field(q_)
    if m:
        rows = [r for r in rows if m(r.zone_name, r.subject, " ".join(r.to_addrs or []), r.last_error)]
    counts = dict((await db.execute(select(MailOutbox.status, func.count()).group_by(MailOutbox.status))).all())
    return {"items": [_outbox_out(r) for r in rows[offset:offset + limit]], "total": len(rows), "counts": counts}


@mail_router.post("/outbox/{oid}/retry")
async def outbox_retry(oid: uuid.UUID, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Повторить неудачную (или пропущенную) отправку. Отчёт собирается заново по свежим данным."""
    r = await db.get(MailOutbox, oid)
    if r is None:
        raise HTTPException(status_code=404, detail="Запись не найдена")
    if r.status not in ("failed", "skipped"):
        raise HTTPException(status_code=409, detail="Повторить можно только неудачную или пропущенную отправку")
    if r.body_path:
        from pathlib import Path  # noqa: PLC0415

        Path(r.body_path).unlink(missing_ok=True)
    r.status, r.attempts, r.last_error, r.body_path, r.next_attempt_at = "queued", 0, None, None, datetime.now(timezone.utc)
    if r.zone_id:
        z = (await zd_info(db, r.zone_id))
        if z:
            r.to_addrs, r.cc_addrs = mailer.recipients(z["contacts"])
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="mail.retry", target_type="mail_outbox", target_id=str(r.id), details={"zone": r.zone_name})
    await db.commit()
    return _outbox_out(r)


async def zd_info(db: AsyncSession, zone_id: uuid.UUID) -> dict | None:
    z = await db.get(Zone, zone_id)
    if z is None:
        return None
    cons = (await db.execute(select(ZoneContact).where(ZoneContact.zone_id == zone_id))).scalars().all()
    return {"contacts": [{"email": c.email, "role": c.role, "enabled": c.enabled} for c in cons]}


@mail_router.get("/summary")
async def mail_summary(request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    cfg = await request.app.state.settings_svc.get(db, "smtp")
    since = datetime.now(timezone.utc) - timedelta(days=30)
    counts = dict((await db.execute(select(MailOutbox.status, func.count()).where(MailOutbox.created_at >= since).group_by(MailOutbox.status))).all())
    nxt = (await db.execute(select(func.min(ReportSchedule.next_run_at)).where(ReportSchedule.enabled.is_(True)))).scalar_one()
    return {"smtp_ready": bool(cfg.enabled and cfg.host and cfg.from_addr), "smtp_enabled": cfg.enabled, "counts_30d": counts, "next_run_at": nxt}
