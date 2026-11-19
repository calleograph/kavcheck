"""Серверная и сетевая инфраструктура: обзор, источники (только чтение, секреты зашифрованы — только администратор), объекты источников и их сопоставление с учётом,
расхождения сверки с решениями, IP-адреса, стойки, сведения для карточки (приоритет источников по полям). Логика — app/infra/."""
from __future__ import annotations

import json
from datetime import date, timedelta
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import get_db
from ..infra import connectors as K
from ..infra import sync as S
from ..inventory import core as C
from ..models import InfraChange, InfraFinding, InfraObject, InfraSource, InvAsset, InvLocation, utcnow
from ..search import column_like
from .inv import Ix, audit, get_asset, inv_ctx

router = APIRouter(prefix="/inv", tags=["infra"])
INFRA_CLS = ("server", "vm", "network", "storage")


def src_out(s: InfraSource) -> dict:
    return {"id": s.id, "kind": s.kind, "kind_ru": K.KINDS_RU.get(s.kind, s.kind), "name": s.name, "url": s.url, "username": s.username, "secret_set": bool(s.secret_enc), "verify_tls": s.verify_tls,
            "enabled": s.enabled, "every_min": s.every_min, "options": s.options or {}, "requested": s.requested, "last_try_at": C._iso(s.last_try_at), "last_ok_at": C._iso(s.last_ok_at),
            "last_error": s.last_error, "last_stats": s.last_stats or {}, "upload": s.kind in K.UPLOAD, "network": s.kind in K.FETCH}


def obj_out(o: InfraObject, s: InfraSource | None, asset: InvAsset | None = None) -> dict:
    return {"id": o.id, "source_id": o.source_id, "source": s.name if s else "", "source_kind": s.kind if s else "", "ext_id": o.ext_id, "kind": o.kind, "kind_ru": K.OBJ_RU.get(o.kind, o.kind),
            "name": o.name, "fqdn": o.fqdn, "ips": o.ips or [], "macs": o.macs or [], "bios_uuid": o.bios_uuid, "serial": o.serial, "parent_ext": o.parent_ext, "attrs": o.attrs or {},
            "present": o.present, "first_seen": C._iso(o.first_seen), "last_seen": C._iso(o.last_seen), "asset_id": o.asset_id, "match": o.match, "match_basis": o.match_basis,
            "asset": {"id": asset.id, "inv_no": asset.inv_no, "name": asset.name or asset.hostname} if asset else None}


def find_out(f: InfraFinding, assets: dict | None = None) -> dict:
    a = (assets or {}).get(f.asset_id)
    return {"id": f.id, "code": f.code, "title": f.title, "severity": f.severity, "status": f.status, "status_ru": S.STATUS_RU.get(f.status, f.status), "asset_id": f.asset_id,
            "asset": {"inv_no": a.inv_no, "name": a.name or a.hostname} if a else None, "object_id": f.object_id, "found": f.found, "expected": f.expected, "source": f.source,
            "action": f.action, "first_seen": C._iso(f.first_seen), "last_seen": C._iso(f.last_seen), "closed_at": C._iso(f.closed_at), "comment": f.comment, "owner": f.owner,
            "due": C._d(f.due), "decided_by": f.decided_by, "history": (f.history or [])[-10:]}


def need_admin(ix: Ix) -> None:
    if not ix.su.is_admin:
        raise HTTPException(status_code=403, detail="Источники инфраструктуры настраивает администратор")


# ------------------------------------------------------------------------------------------------ обзор
@router.get("/infra/overview")
async def overview(site: int | None = None, resp: int | None = None, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Единая панель: состав, активные и выведенные, без мониторинга/резервного копирования/ответственных, расхождения, устаревшие сведения, состояние источников.
    Каждый показатель открывает список (ссылка на страницу с отбором)."""
    w = [InvAsset.cls.in_(INFRA_CLS)]
    if (af := ix.acc.asset_filter()) is not None:
        w.append(af)
    if site:
        loc = await db.get(InvLocation, site)
        w.append(InvAsset.location_id.in_(select(InvLocation.id).where(InvLocation.ids_path.like((loc.ids_path if loc else "/-/") + "%"))))
    if resp:
        w.append(or_(InvAsset.it_id == resp, InvAsset.resp_id == resp))
    rows = (await db.execute(select(InvAsset.cls, InvAsset.st_cls, func.count()).where(*w).group_by(InvAsset.cls, InvAsset.st_cls))).all()
    cnt = lambda cls=None, st=None: sum(n for c, s, n in rows if (cls is None or c in cls) and (st is None or s in st))   # noqa: E731
    obj_n = dict((await db.execute(select(InfraObject.kind, func.count()).where(InfraObject.present.is_(True)).group_by(InfraObject.kind))).all())
    hyper = (await db.execute(select(func.count(func.distinct(InfraObject.parent_ext))).where(InfraObject.kind == "vm", InfraObject.present.is_(True), InfraObject.parent_ext != ""))).scalar_one()
    asset_ids = select(InvAsset.id).where(*w)
    fq = select(InfraFinding.code, func.count()).where(InfraFinding.status.in_(("attention", "review", "fixing")), or_(InfraFinding.asset_id.is_(None), InfraFinding.asset_id.in_(asset_ids))).group_by(InfraFinding.code)
    by_code = dict((await db.execute(fq)).all())
    sites = (await db.execute(select(func.count()).select_from(InvLocation).where(InvLocation.kind.in_(("site", "server_room")), InvLocation.active.is_(True)))).scalar_one()
    srcs = list((await db.execute(select(InfraSource).order_by(InfraSource.name))).scalars())
    return {"counts": {"server": cnt(("server",), ("stock", "use", "reserve", "repair")), "vm": cnt(("vm",), ("stock", "use", "reserve", "repair")), "network": cnt(("network",), ("stock", "use", "reserve", "repair")),
                       "storage": cnt(("storage",), ("stock", "use", "reserve", "repair")), "active": cnt(None, ("use",)), "decom": cnt(None, ("decom", "writeoff")), "hypervisors": hyper,
                       "clusters": obj_n.get("cluster", 0), "sites": sites + obj_n.get("site", 0), "resources": obj_n.get("resource", 0), "objects": sum(obj_n.values())},
            "findings": {k: by_code.get(k, 0) for k in S.CODES}, "findings_total": sum(by_code.values()),
            "codes": {k: {"title": v[0], "severity": v[1]} for k, v in S.CODES.items()}, "sources": [src_out(s) for s in srcs],
            "source_errors": sum(1 for s in srcs if s.last_error and s.enabled)}


# ------------------------------------------------------------------------------------------------ источники
@router.get("/infra/sources")
async def sources(ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(InfraSource).order_by(InfraSource.name))).scalars().all()
    n = dict((await db.execute(select(InfraObject.source_id, func.count()).where(InfraObject.present.is_(True)).group_by(InfraObject.source_id))).all())
    return {"items": [{**src_out(s), "objects": n.get(s.id, 0)} for s in rows], "kinds": K.KINDS_RU}


class SourceBody(BaseModel):
    kind: str = Field(pattern=r"^(" + "|".join(K.KINDS_RU) + ")$")
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(default="", max_length=500)
    username: str = Field(default="", max_length=200)
    secret: str | None = Field(default=None, max_length=4000)               # None — не менять
    verify_tls: bool = True
    enabled: bool = True
    every_min: int = Field(default=60, ge=5, le=10080)
    options: dict = Field(default_factory=dict)


def _apply_src(s: InfraSource, b: SourceBody, request: Request) -> None:
    if b.url and not b.url.lower().startswith(("https://", "http://")):
        raise HTTPException(status_code=422, detail="Адрес — https://… или http://…")
    if b.kind in K.FETCH and b.kind not in ("backup",) and not b.url:
        raise HTTPException(status_code=422, detail="Укажите адрес API источника")
    opts = {k: v for k, v in b.options.items() if k in ("create_assets", "items", "id", "name", "ip", "mac", "uuid", "serial", "cpu", "ram_mb", "disk_gb", "status", "last_backup", "fqdn", "kind",
                                                       "auth_header", "auth_prefix") and isinstance(v, (str, bool, int))}
    s.kind, s.name, s.url, s.username, s.verify_tls, s.enabled, s.every_min, s.options = b.kind, b.name.strip(), b.url.strip(), b.username.strip(), b.verify_tls, b.enabled, b.every_min, opts
    if b.secret is not None:
        svc = request.app.state.settings_svc
        if b.secret and svc.box is None:
            raise HTTPException(status_code=409, detail="Секреты не сохраняются: не задан APP_MASTER_KEY")
        s.secret_enc = svc.encrypt(b.secret, f"infra.{s.id}") if b.secret else ""


@router.post("/infra/sources", status_code=201)
async def add_source(body: SourceBody, request: Request, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    need_admin(ix)
    s = InfraSource(kind=body.kind, name=body.name)
    db.add(s)
    await db.flush()
    _apply_src(s, body, request)
    s.requested = s.kind in K.FETCH
    audit(db, ix, "infra.source.add", s.name, {"id": s.id, "kind": s.kind})
    await db.commit()
    return src_out(s)


@router.put("/infra/sources/{sid}")
async def edit_source(sid: int, body: SourceBody, request: Request, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    need_admin(ix)
    s = await db.get(InfraSource, sid)
    if s is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    _apply_src(s, body, request)
    audit(db, ix, "infra.source.edit", s.name, {"id": sid, "secret_changed": body.secret is not None})
    await db.commit()
    return src_out(s)


@router.delete("/infra/sources/{sid}")
async def del_source(sid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Удаление источника удаляет его объекты и их историю; учётные карточки остаются (в истории карточек события сохраняются)."""
    need_admin(ix)
    s = await db.get(InfraSource, sid)
    if s is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    audit(db, ix, "infra.source.delete", s.name, {"id": sid})
    await db.delete(s)
    await db.commit()
    return {"ok": True}


@router.post("/infra/sources/{sid}/test")
async def test_source(sid: int, request: Request, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Проверка соединения: запрос к источнику без записи; ответ — число объектов по видам и первые объекты."""
    need_admin(ix)
    s = await db.get(InfraSource, sid)
    if s is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    secret = request.app.state.settings_svc.decrypt(s.secret_enc, f"infra.{s.id}") if s.secret_enc else ""
    try:
        objs = await K.fetch(s, secret)
    except K.SourceError as exc:
        return {"ok": False, "error": str(exc)}
    by: dict[str, int] = {}
    for o in objs:
        by[o["kind"]] = by.get(o["kind"], 0) + 1
    return {"ok": True, "total": len(objs), "by_kind": {K.OBJ_RU.get(k, k): v for k, v in by.items()},
            "sample": [{"kind": K.OBJ_RU.get(o["kind"], o["kind"]), "name": o["name"], "ips": o["ips"][:3], "attrs": {k: v for k, v in o["attrs"].items() if k in ("cpu", "ram_mb", "power", "available", "os")}} for o in objs[:20]]}


@router.post("/infra/sources/{sid}/sync")
async def sync_now(sid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Запустить синхронизацию (worker, в течение минуты). Источник-выгрузку обновляют загрузкой файла."""
    if not (ix.su.is_admin or ix.acc.can("edit")):
        ix.acc.need("edit")
    s = await db.get(InfraSource, sid)
    if s is None:
        raise HTTPException(status_code=404, detail="Источник не найден")
    if s.kind not in K.FETCH:
        raise HTTPException(status_code=409, detail="Этот источник обновляется загрузкой выгрузки")
    s.requested = True
    await db.commit()
    return {"queued": True}


@router.post("/infra/sources/{sid}/upload")
async def upload(sid: int, request: Request, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Загрузка выгрузки (Hyper-V — скрипт Export-KavHyperV.ps1; резервное копирование — JSON по путям полей из настроек источника): запись, сопоставление и сверка сразу."""
    need_admin(ix)
    s = await db.get(InfraSource, sid)
    if s is None or s.kind not in K.UPLOAD:
        raise HTTPException(status_code=404, detail="Источник не принимает файлы")
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Файл больше 50 МБ")
    try:
        data = json.loads(bytes(buf).decode("utf-8-sig"))
        objs = K.parse_hyperv(data) if s.kind == "hyperv" else K.parse_generic(data, s.options or {}, "backup")
    except (ValueError, K.SourceError) as exc:
        raise HTTPException(status_code=422, detail=f"Файл не разобран: {exc}") from None
    st = await S.sync_source(db, s, objs)
    s.last_try_at = s.last_ok_at = utcnow()
    s.last_error, s.last_stats = "", {**st, "file": unquote(request.headers.get("x-file-name", ""))[:200]}
    cfg = ix.cfg
    rc = await S.reconcile(db, cfg.infra_stale_days, by=ix.su.display_name)
    audit(db, ix, "infra.upload", s.name, {"objects": len(objs)})
    await db.commit()
    return {**st, "reconcile": rc}


@router.post("/infra/reconcile")
async def reconcile_now(ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    ix.acc.need("edit")
    st = await S.reconcile(db, ix.cfg.infra_stale_days, by=ix.su.display_name)
    await db.commit()
    return st


# ------------------------------------------------------------------------------------------------ объекты источников
@router.get("/infra/objects")
async def objects(source: int | None = None, kind: str = Query("", max_length=80), match: str = Query("", max_length=60), present: bool | None = None, q: str = Query("", max_length=200),
                  asset: int | None = None, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    w = []
    if source:
        w.append(InfraObject.source_id == source)
    if kind:
        w.append(InfraObject.kind.in_(kind.split(",")))
    if match:
        w.append(InfraObject.match.in_(match.split(",")))
    if present is not None:
        w.append(InfraObject.present.is_(present))
    if asset:
        w.append(InfraObject.asset_id == asset)
    for word in q.split()[:5]:
        if (c := column_like(InfraObject.search, word)) is not None:
            w.append(c)
    total = (await db.execute(select(func.count()).select_from(InfraObject).where(*w))).scalar_one()
    rows = list((await db.execute(select(InfraObject).where(*w).order_by(InfraObject.present.desc(), InfraObject.name).offset(offset).limit(limit))).scalars())
    srcs = {s.id: s for s in (await db.execute(select(InfraSource))).scalars()}
    assets = {a.id: a for a in (await db.execute(select(InvAsset).where(InvAsset.id.in_({o.asset_id for o in rows} - {None})))).scalars()} if rows else {}
    return {"items": [obj_out(o, srcs.get(o.source_id), assets.get(o.asset_id)) for o in rows], "total": total, "offset": offset, "limit": limit, "kinds": K.OBJ_RU}


@router.get("/infra/objects/{oid}")
async def object_card(oid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    o = await db.get(InfraObject, oid)
    if o is None:
        raise HTTPException(status_code=404, detail="Объект не найден")
    s = await db.get(InfraSource, o.source_id)
    a = await db.get(InvAsset, o.asset_id) if o.asset_id else None
    ch = (await db.execute(select(InfraChange).where(InfraChange.object_id == oid).order_by(InfraChange.at.desc()).limit(300))).scalars().all()
    return {**obj_out(o, s, a), "changes": [{"at": C._iso(c.at), "field": c.field, "label": S.FIELD_RU.get(c.field, c.field), "old": c.old, "new": c.new} for c in ch]}


class MatchBody(BaseModel):
    action: str = Field(pattern=r"^(link|reject|create|reset)$")
    asset_id: int | None = None


@router.put("/infra/objects/{oid}/match")
async def set_match(oid: int, body: MatchBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Решение по сопоставлению: link — связать с карточкой (подтверждено), create — создать карточку по объекту, reject — не связывать, reset — вернуть автоматике."""
    ix.acc.need("edit")
    o = await db.get(InfraObject, oid)
    if o is None:
        raise HTTPException(status_code=404, detail="Объект не найден")
    s = await db.get(InfraSource, o.source_id)
    if body.action == "link":
        if not body.asset_id:
            raise HTTPException(status_code=422, detail="Выберите карточку")
        a = await get_asset(db, ix, body.asset_id)
        o.asset_id, o.match, o.match_basis = a.id, "confirmed", f"решение: {ix.su.display_name}"
        e = dict(a.ext_ids or {})
        e[f"src:{s.id}"] = o.ext_id
        if o.bios_uuid and not e.get("bios_uuid"):
            e["bios_uuid"] = o.bios_uuid
        a.ext_ids = e
        await C.record(db, a, "link", [{"f": "infra", "label": "Объект источника", "old": "", "new": f"{s.name}: {o.name}"}], ix.su.display_name, title=f"Сопоставлено с объектом «{o.name}» ({s.name})")
    elif body.action == "create":
        ix.acc.need("create")
        if o.kind not in S.ASSET_KINDS:
            raise HTTPException(status_code=422, detail="Карточка создаётся для сервера, ВМ или сетевого устройства")
        a = await S.create_asset(db, o, s, ix.su.display_name)
        o.asset_id, o.match, o.match_basis = a.id, "confirmed", f"карточка создана: {ix.su.display_name}"
    elif body.action == "reject":
        o.asset_id, o.match, o.match_basis = None, "rejected", f"не связывать: {ix.su.display_name}"
    else:
        o.match, o.match_basis = "none", ""
    audit(db, ix, "infra.match", o.name[:120], {"object": oid, "action": body.action, "asset": o.asset_id})
    await S.reconcile(db, ix.cfg.infra_stale_days, by=ix.su.display_name)
    await db.commit()
    return {"ok": True, "asset_id": o.asset_id}


# ------------------------------------------------------------------------------------------------ расхождения
@router.get("/infra/findings")
async def findings(status: str = Query("", max_length=80), code: str = Query("", max_length=200), q: str = Query("", max_length=200), asset: int | None = None,
                   offset: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=2000), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """status: open (требует внимания, проверки, исправляется) | конкретные через запятую | пусто — все."""
    w = []
    if status == "open":
        w.append(InfraFinding.status.in_(("attention", "review", "fixing")))
    elif status:
        w.append(InfraFinding.status.in_(status.split(",")))
    if code:
        w.append(InfraFinding.code.in_(code.split(",")))
    if asset:
        w.append(InfraFinding.asset_id == asset)
    if q.strip():
        w.append(or_(*[c for c in (column_like(InfraFinding.found, q.strip()), column_like(InfraFinding.title, q.strip())) if c is not None],
                     InfraFinding.asset_id.in_(select(InvAsset.id).where(column_like(InvAsset.search, q.strip())))))
    if (af := ix.acc.asset_filter()) is not None:
        w.append(or_(InfraFinding.asset_id.is_(None), InfraFinding.asset_id.in_(select(InvAsset.id).where(af))))
    total = (await db.execute(select(func.count()).select_from(InfraFinding).where(*w))).scalar_one()
    rows = list((await db.execute(select(InfraFinding).where(*w).order_by(InfraFinding.status, InfraFinding.last_seen.desc()).offset(offset).limit(limit))).scalars())
    rows.sort(key=lambda f: (f.status not in ("attention",), -S.SEV_RANK.get(f.severity, 0)))
    assets = {a.id: a for a in (await db.execute(select(InvAsset).where(InvAsset.id.in_({f.asset_id for f in rows} - {None})))).scalars()} if rows else {}
    return {"items": [find_out(f, assets) for f in rows], "total": total, "codes": {k: v[0] for k, v in S.CODES.items()}, "statuses": S.STATUS_RU}


class DecideBody(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=5000)
    status: str = Field(pattern=r"^(attention|review|confirmed|fixing|fixed|exception)$")
    comment: str = Field(default="", max_length=2000)
    owner: str = Field(default="", max_length=200)
    due: date | None = None


@router.put("/infra/findings")
async def decide(body: DecideBody, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Решение по расхождениям: проверено, исправляется (ответственный, срок), устранено, принято как исключение (основание обязательно). История решений сохраняется."""
    ix.acc.need("edit")
    if body.status == "exception" and not body.comment.strip():
        raise HTTPException(status_code=422, detail="Для исключения укажите основание (кем и почему принято)")
    now = utcnow()
    rows = (await db.execute(select(InfraFinding).where(InfraFinding.id.in_(body.ids)))).scalars().all()
    for f in rows:
        f.status, f.comment, f.owner, f.due, f.decided_by, f.decided_at = body.status, body.comment, body.owner, body.due, ix.su.display_name, now
        f.closed_at = now if body.status in ("fixed",) else None
        f.history = [*(f.history or []), {"at": now.isoformat(), "by": ix.su.display_name, "status": body.status, "comment": body.comment}][-50:]
    audit(db, ix, "infra.decide", body.status, {"n": len(rows), "ids": body.ids[:50]})
    await db.commit()
    return {"updated": len(rows)}


# ------------------------------------------------------------------------------------------------ IP-адреса, стойки, карточка
@router.get("/infra/ips")
async def ips(q: str = Query("", max_length=100), dup: bool = False, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Реестр IP-адресов по данным всех источников: кто владеет адресом, в каких источниках, повторы; подсети и VLAN — из реестра инфраструктуры."""
    rows = list((await db.execute(select(InfraObject).where(InfraObject.present.is_(True), InfraObject.kind.in_(("server", "vm", "network", "monitor", "ip", "resource"))))).scalars())
    srcs = {s.id: s.name for s in (await db.execute(select(InfraSource))).scalars()}
    assets = {a.id: a for a in (await db.execute(select(InvAsset).where(InvAsset.id.in_({o.asset_id for o in rows} - {None})))).scalars()}
    by: dict[str, dict] = {}
    for o in rows:
        for ip in o.ips or []:
            r = by.setdefault(ip, {"ip": ip, "objects": [], "assets": {}, "sources": set()})
            if o.kind != "ip":
                r["objects"].append(f"{o.name} ({srcs.get(o.source_id, '')})")
            r["sources"].add(srcs.get(o.source_id, ""))
            if o.asset_id in assets:
                a = assets[o.asset_id]
                r["assets"][a.id] = {"id": a.id, "inv_no": a.inv_no, "name": a.name or a.hostname}
    out = []
    for r in by.values():
        item = {"ip": r["ip"], "objects": sorted(set(r["objects"]))[:10], "assets": list(r["assets"].values()), "sources": sorted(r["sources"]), "dup": len(r["assets"]) > 1}
        if (not q or q in r["ip"] or any(q.casefold() in x.casefold() for x in r["objects"])) and (not dup or item["dup"]):
            out.append(item)
    out.sort(key=lambda x: tuple(int(p) if p.isdigit() else 0 for p in x["ip"].split(".")) if "." in x["ip"] else (999,))
    nets = list((await db.execute(select(InfraObject).where(InfraObject.present.is_(True), InfraObject.kind.in_(("prefix", "vlan"))).order_by(InfraObject.kind, InfraObject.name))).scalars())
    return {"items": out[:5000], "total": len(out), "prefixes": [obj_out(o, None) for o in nets if o.kind == "prefix"], "vlans": [obj_out(o, None) for o in nets if o.kind == "vlan"]}


@router.get("/infra/racks")
async def racks(ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Стойки (местоположения вида «стойка») с размещённым оборудованием по юнитам: что где стоит и где свободно."""
    rows = list((await db.execute(select(InvLocation).where(InvLocation.kind == "rack", InvLocation.active.is_(True)).order_by(InvLocation.path))).scalars())
    assets = list((await db.execute(select(InvAsset).where(InvAsset.location_id.in_([r.id for r in rows]), InvAsset.st_cls.in_(("use", "stock", "reserve", "repair"))))).scalars()) if rows else []
    n = await C.names_for(db, assets, props=False)
    by: dict[int, list] = {}
    for a in assets:
        by.setdefault(a.location_id, []).append({"id": a.id, "inv_no": a.inv_no, "name": C.label(a, n).rsplit(" (", 1)[0], "cls": a.cls, "unit": a.rack_unit, "units": a.rack_units or 1,
                                                 "status": n.ref(a.status_id), "loc_detail": a.loc_detail})
    out = []
    for r in rows:
        units = int((r.data or {}).get("units") or 42)
        items = sorted(by.get(r.id, []), key=lambda x: -(x["unit"] or 0))
        used = sum(x["units"] for x in items if x["unit"])
        out.append({"id": r.id, "name": r.name, "path": r.path, "units": units, "used": used, "free": max(0, units - used), "items": items,
                    "unplaced": [x for x in items if not x["unit"]]})
    return {"items": out}


@router.get("/assets/{aid}/infra")
async def asset_infra(aid: int, ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    """Сведения источников для карточки: объекты, значения полей по приоритету источников (с расхождениями), история конфигурации, открытые расхождения."""
    a = await get_asset(db, ix, aid)
    pairs = (await db.execute(select(InfraObject, InfraSource).join(InfraSource, InfraSource.id == InfraObject.source_id).where(InfraObject.asset_id == a.id))).all()
    ch = (await db.execute(select(InfraChange, InfraObject.name).join(InfraObject, InfraObject.id == InfraChange.object_id).where(InfraObject.asset_id == a.id)
                           .order_by(InfraChange.at.desc()).limit(200))).all()
    fs = (await db.execute(select(InfraFinding).where(InfraFinding.asset_id == a.id).order_by(InfraFinding.last_seen.desc()).limit(100))).scalars().all()
    return {"objects": [obj_out(o, s) for o, s in pairs], "resolved": S.resolve([(o, s) for o, s in pairs], ix.cfg.infra_priority),
            "changes": [{"at": C._iso(c.at), "object": nm, "field": c.field, "label": S.FIELD_RU.get(c.field, c.field), "old": c.old, "new": c.new} for c, nm in ch],
            "findings": [find_out(f) for f in fs]}


@router.get("/infra/changes")
async def changes(days: int = Query(30, ge=1, le=3650), ix: Ix = Depends(inv_ctx), db: AsyncSession = Depends(get_db)):
    since = utcnow() - timedelta(days=days)
    rows = (await db.execute(select(InfraChange, InfraObject, InfraSource.name).join(InfraObject, InfraObject.id == InfraChange.object_id).join(InfraSource, InfraSource.id == InfraObject.source_id)
                             .where(InfraChange.at >= since).order_by(InfraChange.at.desc()).limit(2000))).all()
    return {"items": [{"at": C._iso(c.at), "object_id": o.id, "object": o.name, "kind_ru": K.OBJ_RU.get(o.kind, o.kind), "source": sn, "asset_id": o.asset_id, "field": c.field,
                       "label": S.FIELD_RU.get(c.field, c.field), "old": c.old, "new": c.new} for c, o, sn in rows]}
