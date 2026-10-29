"""BI-выгрузки: источники (администратор), сотрудники и устройства BI, история принадлежности, сопоставление с KSC, пользователи KSC.

Права (сведения о сотрудниках — персональные данные):
* настройка источников, загрузка файла, решения по сопоставлению — администратор;
* списки сотрудников и устройств BI, почта — аналитик и администратор с доступом ко всем источникам KSC (выгрузка BI не делится по источникам KSC);
* блок «Владелец» в карточке компьютера — любой пользователь с доступом к источнику KSC; почта — только аналитику и администратору.
Тяжёлая обработка (импорт, сопоставление) — только в worker; здесь — постановка в очередь и чтение готового."""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Literal
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, get_db, require_admin, require_user, source_scope
from ..bi import importer as IM
from ..bi import profile as PR
from ..bi import read as R
from ..bi import smb as S
from ..bi import xlsx as X
from ..bi import match as M
from ..bi.match import LEVEL_RU
from ..bi.service import conn_of, enqueue, next_run, src_dir
from ..models import BiDevice, BiImport, BiMatch, BiSource, KscSource, utcnow
from ..services.audit import write_audit

log = logging.getLogger("app.bi")
router = APIRouter(prefix="/bi", tags=["bi"])
SAMPLE_ROWS = 5
CHECK_ROWS = 2000
STATUS_RU = IM.STATUS_RU


def pd(su: SessionUser) -> bool:
    return su.role in ("analyst", "admin")


async def require_people(su: SessionUser = Depends(require_user)) -> SessionUser:
    if su.role not in ("analyst", "admin") or not (su.is_admin or su.all_sources):
        raise HTTPException(status_code=403, detail="Сведения о сотрудниках BI доступны аналитику и администратору с доступом ко всем источникам KSC")
    return su


class OptionsIn(BaseModel):
    partial: bool = True
    max_reject_pct: int = Field(5, ge=0, le=100)
    drift_pct: int = Field(20, ge=1, le=1000)
    max_mb: int = Field(50, ge=1, le=500)
    max_rows: int = Field(200_000, ge=100, le=2_000_000)
    keep_files: int = Field(10, ge=0, le=1000)
    keep_days: int = Field(90, ge=1, le=3650)
    retry_minutes: int = Field(60, ge=5, le=1440)
    retries: int = Field(3, ge=0, le=20)
    stable_s: int = Field(10, ge=0, le=300)
    full_snapshot: bool = True
    owner_drift_pct: int = Field(25, ge=1, le=100)
    auto_exact: bool = False                                              # автоматически подтверждать однозначные точные совпадения имён (по умолчанию — нет)


class SourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    is_active: bool = True
    smb_host: str = Field(min_length=1, max_length=253)
    smb_port: int = Field(445, ge=1, le=65535)
    smb_share: str = Field(min_length=1, max_length=120)
    smb_path: str = Field("", max_length=500)
    username: str = Field("", max_length=256)
    password: str | None = Field(None, max_length=512)
    smb_encrypt: bool = True
    file_mode: str = Field("fixed", pattern=r"^(fixed|auto)$")
    file_name: str = Field("", max_length=255)
    schedule_time: str = Field("06:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    timezone: str = Field("UTC", max_length=64)
    profile: dict = Field(default_factory=dict)
    options: OptionsIn = Field(default_factory=OptionsIn)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        from zoneinfo import ZoneInfo  # noqa: PLC0415

        try:
            ZoneInfo(v)
        except Exception:  # noqa: BLE001
            raise ValueError("Неизвестный часовой пояс") from None
        return v


def src_out(s: BiSource, last: BiImport | None, ok: BiImport | None) -> dict:
    return {"id": str(s.id), "name": s.name, "kind": s.kind, "is_active": s.is_active, "smb_host": s.smb_host, "smb_port": s.smb_port, "smb_share": s.smb_share, "smb_path": s.smb_path,
            "username": s.username, "password_set": bool(s.password_enc), "smb_encrypt": s.smb_encrypt, "file_mode": s.file_mode, "file_name": s.file_name, "schedule_time": s.schedule_time,
            "timezone": s.timezone, "profile": s.profile or {}, "options": IM.options(s), "next_run_at": s.next_run_at, "queued": bool(s.request), "last_try_at": s.last_try_at,
            "last_ok_at": s.last_ok_at, "last_error": s.last_error, "fail_n": s.fail_n, "matched_at": s.matched_at,
            "last": imp_out(last) if last else None, "published": imp_out(ok) if ok else None}


def imp_out(i: BiImport, full: bool = False) -> dict:
    out = {"id": str(i.id), "started_at": i.started_at, "finished_at": i.finished_at, "trigger": i.trigger, "by": i.by, "file_name": i.file_name, "file_size": i.file_size, "file_mtime": i.file_mtime,
           "snapshot_at": i.snapshot_at, "sha256": i.sha256, "status": i.status, "status_ru": STATUS_RU.get(i.status, i.status), "message": i.message, "rows_read": i.rows_read, "rows_valid": i.rows_valid,
           "rows_new": i.rows_new, "rows_changed": i.rows_changed, "rows_same": i.rows_same, "rows_rejected": i.rows_rejected, "rows_gone": i.rows_gone, "rows_empty": i.rows_empty,
           "devices_n": i.devices_n, "persons_n": i.persons_n, "ms": i.ms, "stored": bool(i.stored), "warnings_n": len(i.warnings or []), "errors_n": i.rows_rejected}
    if full:
        out.update(warnings=i.warnings, errors=i.errors, headers=i.headers)
    return out


async def _get(db: AsyncSession, sid: uuid.UUID) -> BiSource:
    s = await db.get(BiSource, sid)
    if s is None:
        raise HTTPException(status_code=404, detail="BI-источник не найден")
    return s


def _apply(s: BiSource, body: SourceIn, svc) -> None:
    if body.profile:
        try:
            s.profile = PR.validate_profile(body.profile)
        except PR.ProfileError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
    if body.file_mode == "fixed" and not body.file_name.strip():
        raise HTTPException(status_code=422, detail="Укажите имя файла выгрузки")
    if any(c in body.file_name for c in "\\/"):
        raise HTTPException(status_code=422, detail="Имя файла или маска — без пути: папка задаётся отдельно")
    for k in ("name", "is_active", "smb_host", "smb_port", "smb_share", "smb_path", "username", "smb_encrypt", "file_mode", "schedule_time", "timezone"):
        v = getattr(body, k)
        setattr(s, k, v.strip() if isinstance(v, str) else v)
    s.file_name = body.file_name.strip() or "*.xlsx"
    s.options = body.options.model_dump()
    if body.password is not None:
        s.password_enc = svc.encrypt(body.password, f"bi.{s.id}") if body.password else None
    s.next_run_at = next_run(s.schedule_time, IM.tz_of(s), utcnow())


# ------------------------------------------------------------------------------------------------ источники (администратор)
@router.get("/sources")
async def sources(su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    out = []
    for s in (await db.execute(select(BiSource).order_by(BiSource.name))).scalars():
        last = (await db.execute(select(BiImport).where(BiImport.source_id == s.id).order_by(BiImport.started_at.desc()).limit(1))).scalars().first()
        out.append(src_out(s, last, await db.get(BiImport, s.last_import_id) if s.last_import_id else None))
    return {"items": out, "fields": {k: v[0] for k, v in PR.FIELDS.items()}, "defaults": IM.DEFAULT_OPTIONS, "generic_names": list(PR.GENERIC_NAMES)}


@router.post("/sources", status_code=201)
async def create(body: SourceIn, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if (await db.execute(select(BiSource).where(BiSource.name == body.name.strip()))).scalar():
        raise HTTPException(status_code=409, detail="Источник с таким названием уже есть")
    s = BiSource(id=uuid.uuid4())
    _apply(s, body, request.app.state.settings_svc)
    db.add(s)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="bi.source.create", target_type="bi_source", target_id=str(s.id), details={"name": s.name, "host": s.smb_host})
    await db.commit()
    return src_out(s, None, None)


@router.put("/sources/{sid}")
async def update_source(sid: uuid.UUID, body: SourceIn, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    s = await _get(db, sid)
    _apply(s, body, request.app.state.settings_svc)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="bi.source.update", target_type="bi_source", target_id=str(s.id), details={"name": s.name, "host": s.smb_host})
    await db.commit()
    return src_out(s, None, await db.get(BiImport, s.last_import_id) if s.last_import_id else None)


@router.delete("/sources/{sid}", status_code=204)
async def delete_source(sid: uuid.UUID, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    s = await _get(db, sid)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="bi.source.delete", target_type="bi_source", target_id=str(s.id), details={"name": s.name})
    await db.delete(s)
    await db.commit()
    import shutil  # noqa: PLC0415

    shutil.rmtree(Path(request.app.state.settings.data_dir) / "bi" / str(sid), ignore_errors=True)
    return Response(status_code=204)


async def _conn(request: Request, db: AsyncSession, s: BiSource) -> tuple[S.Conn, list[str]]:
    svc = request.app.state.settings_svc
    cfg = await svc.get(db, "bi")
    return conn_of(s, svc.decrypt(s.password_enc, f"bi.{s.id}")), list(cfg.allowed_hosts)  # type: ignore[attr-defined]


@router.post("/sources/{sid}/test")
async def test_source(sid: uuid.UUID, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """«Проверить подключение»: доступность SMB, вход и диалект, права чтения, обнаруженные файлы и выбор актуального."""
    s = await _get(db, sid)
    conn, allowed = await _conn(request, db, s)
    res = await asyncio.to_thread(S.diagnose, conn, s.file_mode, s.file_name, allowed)
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="bi.source.test", target_type="bi_source", target_id=str(s.id), result="success" if res["ok"] else "failure",
                details={"stages": [f"{x['stage']}:{'ok' if x['ok'] else 'fail'}" for x in res["stages"]]})
    await db.commit()
    return res


async def _save_body(request: Request, dst: Path, max_bytes: int) -> int:
    n = 0
    with dst.open("wb") as f:
        async for chunk in request.stream():
            n += len(chunk)
            if n > max_bytes:
                f.close()
                dst.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail=f"Файл больше {max_bytes // (1024 * 1024)} МБ")
            f.write(chunk)
    if not n:
        dst.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail="Пустой файл")
    return n


def _preview(path: Path, prof: dict | None, tz, now: datetime) -> dict:
    """Листы, заголовки, примеры значений, подсказка сопоставления и проверка первых строк — без записи в базу."""
    warns = X.check_archive(path)
    wb = X.open_book(path)
    try:
        sheets = list(wb.sheetnames)
        ws = X.pick_sheet(wb, (prof or {}).get("sheet", "") if (prof or {}).get("sheet") in sheets else "")
        hn, hdr = X.headers(ws, (prof or {}).get("header_row", 0))
        samples, check = [], {"rows": 0, "ok": 0, "empty": 0, "rejected": [], "warnings": {}}
        p = None
        try:
            p = PR.validate_profile(prof) if prof and prof.get("columns") else PR.validate_profile(PR.suggest(hdr))
        except PR.ProfileError as exc:
            check["profile_error"] = str(exc)
        missing = [h for h in (PR.required_headers(p) if p else []) if h not in hdr]
        for n, vals in X.rows(ws, hn, hdr):
            if len(samples) < SAMPLE_ROWS and any(PR.text(v) for v in vals.values()):
                samples.append({h: PR.text(v)[:80] for h, v in vals.items()})
            if p is None or missing:
                if len(samples) >= SAMPLE_ROWS:
                    break
                continue
            check["rows"] += 1
            if check["rows"] > CHECK_ROWS:
                check["rows"] -= 1
                check["truncated"] = True
                break
            recs, why, ws_ = PR.parse_row(vals, p, tz, now)
            for w in ws_:
                k = f"{w['code']}:{p['columns'].get(w['field'], w['field'])}"
                check["warnings"][k] = check["warnings"].get(k, 0) + 1
            if recs:
                check["ok"] += 1
            elif why:
                if len(check["rejected"]) < 20:
                    check["rejected"].append({"row": n, "reason": why})
            else:
                check["empty"] += 1
    finally:
        wb.close()
    return {"sheets": sheets, "sheet": ws.title, "header_row": hn, "headers": hdr, "samples": samples, "suggested": PR.suggest(hdr), "missing": missing, "check": check, "archive_warnings": warns,
            "fields": {k: v[0] for k, v in PR.FIELDS.items()}}


@router.post("/sources/{sid}/preview")
async def preview(sid: uuid.UUID, request: Request, profile: str = Query("", max_length=20000), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """«Проверить структуру файла». Тело запроса — образец XLSX (application/octet-stream); без тела — пробное чтение актуального файла с SMB. В базу ничего не записывается."""
    s = await _get(db, sid)
    opt = IM.options(s)
    base = src_dir(request.app.state.settings.data_dir, sid)
    tmp = base / f"preview-{uuid.uuid4().hex}.xlsx"
    try:
        prof = json.loads(profile) if profile else (s.profile or None)
    except ValueError:
        raise HTTPException(status_code=422, detail="profile: неверный JSON") from None
    try:
        if int(request.headers.get("content-length") or 0) > 0:
            await _save_body(request, tmp, int(opt["max_mb"]) * 1024 * 1024)
            origin = {"kind": "upload", "name": unquote(request.headers.get("x-file-name", ""))[:255]}
        else:
            conn, allowed = await _conn(request, db, s)

            def fetch():
                why = S.host_allowed(conn.host, allowed)
                if why:
                    raise S.SmbError("allowed", why)
                with S.Smb(conn) as c:
                    hit, _cand, why = S.choose(c.listing(), s.file_mode, s.file_name)
                    if hit is None:
                        raise S.SmbError("choose", why)
                    c.copy(hit.name, tmp, int(opt["max_mb"]) * 1024 * 1024)
                    return hit

            try:
                hit = await asyncio.to_thread(fetch)
            except S.SmbError as exc:
                raise HTTPException(status_code=422, detail=exc.message) from None
            origin = {"kind": "smb", "name": hit.name, "mtime": hit.mtime, "size": hit.size}
        try:
            out = await asyncio.to_thread(_preview, tmp, prof, IM.tz_of(s), utcnow())
        except X.XlsxError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
    finally:
        tmp.unlink(missing_ok=True)
    return {**out, "origin": origin}


class RunIn(BaseModel):
    force: bool = False


@router.post("/sources/{sid}/run", status_code=202)
async def run(sid: uuid.UUID, body: RunIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """«Запустить импорт»: worker получит файл в течение минуты. force — принять файл, даже если число записей резко изменилось или он не отличается от прошлого."""
    s = await _get(db, sid)
    if not s.profile:
        raise HTTPException(status_code=422, detail="Сначала проверьте структуру файла и сохраните сопоставление столбцов")
    imp_id = await enqueue(db, s.id, trigger="manual", by=su.display_name)          # строка журнала «в очереди» — сразу, до начала обработки
    s.request = {"at": utcnow().isoformat(), "by": su.display_name, "force": body.force, "imp_id": str(imp_id)}
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="bi.import.request", target_type="bi_source", target_id=str(s.id), details={"force": body.force})
    await db.commit()
    return {"queued": True, "import_id": str(imp_id)}


@router.post("/sources/{sid}/upload", status_code=202)
async def upload(sid: uuid.UUID, request: Request, force: bool = False, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Импорт файла, загруженного администратором (например, первой выгрузки до настройки SMB). Выполняет worker; без явного действия администратора данные не загружаются."""
    s = await _get(db, sid)
    if not s.profile:
        raise HTTPException(status_code=422, detail="Сначала проверьте структуру файла и сохраните сопоставление столбцов")
    base = src_dir(request.app.state.settings.data_dir, sid)
    name = f"upload-{uuid.uuid4().hex}.xlsx"
    size = await _save_body(request, base / name, int(IM.options(s)["max_mb"]) * 1024 * 1024)
    orig = Path(unquote(request.headers.get("x-file-name", "")) or "upload.xlsx").name[:200]
    imp_id = await enqueue(db, s.id, trigger="upload", by=su.display_name)
    s.request = {"at": utcnow().isoformat(), "by": su.display_name, "force": force, "upload": name, "name": orig, "imp_id": str(imp_id)}
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action="bi.import.upload", target_type="bi_source", target_id=str(s.id), details={"file": orig, "size": size, "force": force})
    await db.commit()
    return {"queued": True, "import_id": str(imp_id)}


@router.get("/sources/{sid}/imports")
async def imports(sid: uuid.UUID, limit: int = Query(50, ge=1, le=500), su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    await _get(db, sid)
    rows = (await db.execute(select(BiImport).where(BiImport.source_id == sid).order_by(BiImport.started_at.desc()).limit(limit))).scalars().all()
    return {"items": [imp_out(i) for i in rows]}


@router.get("/imports/{iid}")
async def import_one(iid: uuid.UUID, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    i = await db.get(BiImport, iid)
    if i is None:
        raise HTTPException(status_code=404, detail="Импорт не найден")
    return imp_out(i, full=True)


# ------------------------------------------------------------------------------------------------ сопоставление с KSC
class DecideIn(BaseModel):
    device_id: int
    ksc_source_id: uuid.UUID
    host_id: int
    decision: str = Field(pattern=r"^(confirm|reject|reset)$")
    note: str = Field("", max_length=500)


@router.post("/matches/decide")
async def decide(body: DecideIn, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Решение администратора: подтвердить (надёжное соответствие), отклонить (больше не предлагается) или сбросить (снова решает автоматическое сопоставление)."""
    from ..models import BiDevice  # noqa: PLC0415

    dev = await db.get(BiDevice, body.device_id)
    if dev is None or await db.get(KscSource, body.ksc_source_id) is None:
        raise HTTPException(status_code=404, detail="Устройство BI или источник KSC не найден")
    m = (await db.execute(select(BiMatch).where(BiMatch.device_id == body.device_id, BiMatch.ksc_source_id == body.ksc_source_id, BiMatch.host_id == body.host_id))).scalars().first()
    before = m.level if m else ""
    if body.decision == "reset":
        if m is not None and m.level == "confirmed" and m.decided_by == M.RULE:
            m.level, m.decided_by, m.decided_at, m.note, m.updated_at = "manual", su.display_name[:300], utcnow(), "автоподтверждение отменено администратором", utcnow()   # правило больше не подтвердит эту пару
        elif m is not None and m.level in M.MANUAL:
            await db.delete(m)
    else:
        if body.decision == "confirm":                      # подтверждено одно соответствие: прочие подтверждения этого устройства снимаются
            await db.execute(delete(BiMatch).where(BiMatch.device_id == body.device_id, BiMatch.level == "confirmed"))
        from ..bi.read import ksc_host  # noqa: PLC0415

        h = await ksc_host(db, body.ksc_source_id, body.host_id)
        if h is None:
            raise HTTPException(status_code=404, detail="Компьютер не найден в подготовленных данных KSC")
        if m is None:
            m = BiMatch(device_id=body.device_id, bi_source_id=dev.source_id, ksc_source_id=body.ksc_source_id, host_id=body.host_id, signals=[], issues=[])
            db.add(m)
        m.level, m.host_name, m.decided_by, m.decided_at, m.note, m.updated_at = ("confirmed" if body.decision == "confirm" else "rejected"), h["name"][:300], su.display_name[:300], utcnow(), body.note, utcnow()
    src = await db.get(BiSource, dev.source_id)
    if src is not None:
        src.match_stamp = ""                                # пересчитать сопоставление источника на ближайшем такте worker
    write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action=f"bi.match.{body.decision}", target_type="bi_device", target_id=str(body.device_id),
                details={"device": dev.name, "ksc_source": str(body.ksc_source_id), "host_id": body.host_id, "before": before, "note": body.note})
    await db.commit()
    return {"ok": True, "level": "" if body.decision == "reset" else m.level, "level_ru": LEVEL_RU.get(m.level, "") if body.decision != "reset" and m else ""}


@router.get("/matches")
async def matches(level: str = Query("", pattern="^(" + "|".join(R.MATCH_FILTERS) + ")$"), q: str = Query("", max_length=200), source_id: uuid.UUID | None = None,
                  offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), su: SessionUser = Depends(require_people), db: AsyncSession = Depends(get_db)):
    return await R.match_list(db, level=level, q=q, source_id=source_id, offset=offset, limit=limit, can_source=su.can_use_source)


class BulkIn(BaseModel):
    action: Literal["confirm", "reject", "reset"]
    scope: Literal["exact", "ids"]                                        # exact — все однозначные точные совпадения (по фильтру, на сервере); ids — отмеченные строки
    ids: list[int] = Field(default_factory=list, max_length=5000)
    source_id: uuid.UUID | None = None
    note: str = Field(default="", max_length=300)
    preview: bool = True


BULK_SKIP_RU = {"already": "уже в этом состоянии", "taken": "компьютер уже сопоставлен с другим устройством", "several": "для устройства отмечено несколько компьютеров",
                "not_manual": "нет решения, которое можно отменить", "not_exact": "уже не однозначное точное совпадение"}


async def _bulk_plan(db: AsyncSession, body: BulkIn, su: SessionUser) -> tuple[list[BiMatch], dict]:
    """Какие строки изменит массовая операция и какие пропустит (с причиной). Только на сервере — браузер не загружает все записи."""
    w = R.match_where("exact", body.source_id) if body.scope == "exact" else [BiMatch.id.in_(body.ids or [-1])]
    rows = [m for m in (await db.execute(select(BiMatch).where(*w).order_by(BiMatch.id))).scalars() if su.can_use_source(m.ksc_source_id)]
    skipped: dict = {}
    keep: list[BiMatch] = []
    per_dev: dict = {}
    for m in rows:
        per_dev.setdefault(m.device_id, []).append(m)
    taken = {(k, h): d for k, h, d in (await db.execute(select(BiMatch.ksc_source_id, BiMatch.host_id, BiMatch.device_id).where(BiMatch.level == "confirmed"))).all()}
    for m in rows:
        why = ""
        if body.action == "confirm":
            if m.level == "confirmed":
                why = "already"
            elif len(per_dev[m.device_id]) > 1:
                why = "several"
            elif taken.get((m.ksc_source_id, m.host_id), m.device_id) != m.device_id:
                why = "taken"
        elif body.action == "reject" and m.level == "rejected":
            why = "already"
        elif body.action == "reset" and m.level not in M.MANUAL:
            why = "not_manual"
        if why:
            skipped[why] = skipped.get(why, 0) + 1
        else:
            keep.append(m)
    return keep, skipped


@router.post("/matches/bulk")
async def bulk(body: BulkIn, request: Request, su: SessionUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Массовое решение по сопоставлениям: preview=true — что именно изменится (точное число, примеры, пропуски с причиной); preview=false — выполнение в фоне
    (порциями, под блокировкой сопоставления источника; повторный запуск не создаёт дублей). Ход и итог — GET /bi/matches/bulk/{op}."""
    keep, skipped = await _bulk_plan(db, body, su)
    bi, ksc = await R._src_names(db)                                    # noqa: SLF001
    devs = {d.id: d for d in (await db.execute(select(BiDevice).where(BiDevice.id.in_([m.device_id for m in keep[:30]] or [-1])))).scalars()} if keep else {}
    by_bi, by_ksc = {}, {}
    for m in keep:
        b = bi[m.bi_source_id].name if m.bi_source_id in bi else ""
        by_bi[b] = by_bi.get(b, 0) + 1
        by_ksc[ksc.get(m.ksc_source_id, "")] = by_ksc.get(ksc.get(m.ksc_source_id, ""), 0) + 1
    plan = {"action": body.action, "n": len(keep), "skipped": [{"reason": k, "text": BULK_SKIP_RU[k], "n": v} for k, v in skipped.items()], "by_bi_source": by_bi, "by_ksc_source": by_ksc,
            "sample": [{"device": devs[m.device_id].name if m.device_id in devs else "", "host_name": m.host_name, "bi_source": bi[m.bi_source_id].name if m.bi_source_id in bi else "",
                        "ksc_source": ksc.get(m.ksc_source_id, ""), "level_ru": M.LEVEL_RU.get(m.level, m.level), "name_ru": M.NAME_RU.get(m.name_match, "")} for m in keep[:30]]}
    if body.preview or not keep:
        return plan
    ops = request.app.state.__dict__.setdefault("bi_ops", {})
    if any(o["status"] == "running" for o in ops.values()):
        raise HTTPException(status_code=409, detail="Уже выполняется другая массовая операция с сопоставлениями — дождитесь её завершения")
    op = uuid.uuid4().hex[:12]
    ops[op] = {"id": op, "status": "running", "action": body.action, "total": len(keep), "done": 0, "changed": 0, "skipped": plan["skipped"], "by": su.display_name, "started_at": utcnow(), "error": None}
    for k in [k for k, o in ops.items() if o["status"] != "running"][:-20]:
        ops.pop(k, None)
    t = asyncio.get_running_loop().create_task(_bulk_run(request.app, ops[op], [m.id for m in keep], body, su))
    request.app.state.__dict__.setdefault("bi_op_tasks", set()).add(t)
    t.add_done_callback(request.app.state.bi_op_tasks.discard)
    return {**plan, "op": op}


async def _bulk_run(app, op: dict, ids: list[int], body: BulkIn, su: SessionUser) -> None:
    from ..db import xact_lock  # noqa: PLC0415

    sm, now = app.state.session_maker, utcnow()
    level = {"confirm": "confirmed", "reject": "rejected"}.get(body.action)
    note = body.note or {"confirm": "массовое подтверждение", "reject": "массовое отклонение", "reset": ""}[body.action]
    try:
        srcs: set = set()
        for i in range(0, len(ids), 200):
            async with sm() as db:
                part = (await db.execute(select(BiMatch).where(BiMatch.id.in_(ids[i:i + 200])))).scalars().all()
                for b in sorted({m.bi_source_id for m in part}, key=str):
                    await xact_lock(db, f"bi-match:{b}")                 # одновременная операция второго администратора или пересчёт сопоставления — по очереди
                taken = {(k, h): d for k, h, d in (await db.execute(select(BiMatch.ksc_source_id, BiMatch.host_id, BiMatch.device_id).where(BiMatch.level == "confirmed"))).all()}
                for m in (await db.execute(select(BiMatch).where(BiMatch.id.in_(ids[i:i + 200])))).scalars():     # перечитано под блокировкой: идемпотентно
                    if body.action == "reset":
                        if m.level == "confirmed" and m.decided_by == M.RULE:
                            m.level, m.decided_by, m.decided_at, m.note, m.updated_at = "manual", su.display_name[:300], now, "автоподтверждение отменено администратором", now
                        elif m.level in M.MANUAL:
                            await db.delete(m)
                        else:
                            continue
                    elif m.level == level or (level == "confirmed" and taken.get((m.ksc_source_id, m.host_id), m.device_id) != m.device_id):
                        continue
                    else:
                        if level == "confirmed":
                            await db.execute(delete(BiMatch).where(BiMatch.device_id == m.device_id, BiMatch.level == "confirmed", BiMatch.id != m.id))
                            taken[(m.ksc_source_id, m.host_id)] = m.device_id
                        m.level, m.decided_by, m.decided_at, m.note, m.updated_at = level, su.display_name[:300], now, note[:500], now
                    op["changed"] += 1
                    srcs.add(m.bi_source_id)
                for s_ in srcs:
                    src = await db.get(BiSource, s_)
                    if src is not None:
                        src.match_stamp = ""                             # пересчёт сопоставления на ближайшем такте: прочие кандидаты подтверждённых устройств уходят
                await db.commit()
            op["done"] = min(len(ids), i + 200)
        async with sm() as db:
            write_audit(db, actor_user_id=su.user_id, actor=su.display_name, action=f"bi.match.bulk_{body.action}", target_type="bi_match", target_id=body.scope,
                        details={"selected": len(ids), "changed": op["changed"], "scope": body.scope, "source": str(body.source_id) if body.source_id else None})
            await db.commit()
        op["status"] = "done"
    except Exception as exc:  # noqa: BLE001 — сделанное порциями сохранено; повтор безопасен
        log.exception("Массовая операция с сопоставлениями BI не удалась")
        op["status"], op["error"] = "failed", f"{type(exc).__name__}: {str(exc)[:200]}"
    op["finished_at"] = utcnow()


@router.get("/matches/bulk/{op}")
async def bulk_status(op: str, request: Request, su: SessionUser = Depends(require_admin)):
    got = getattr(request.app.state, "bi_ops", {}).get(op)
    if got is None:
        raise HTTPException(status_code=404, detail="Операция не найдена")
    return got


# ------------------------------------------------------------------------------------------------ сотрудники и устройства BI
@router.get("/summary")
async def summary(su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Есть ли BI-источники и когда опубликован последний снимок (для подписей «сведения на дату» и подсказок)."""
    out = []
    for s in (await db.execute(select(BiSource).order_by(BiSource.name))).scalars():
        ok = await db.get(BiImport, s.last_import_id) if s.last_import_id else None
        out.append({"id": str(s.id), "name": s.name, "snapshot_at": ok.snapshot_at if ok else None, "last_ok_at": s.last_ok_at, "error": bool(s.last_error)})
    return {"items": out, "can_people": su.role in ("analyst", "admin") and (su.is_admin or su.all_sources), "can_pd": pd(su)}


@router.get("/people")
async def people(q: str = Query("", max_length=200), source_id: uuid.UUID | None = None, dept: str = Query("", max_length=200), state: str = Query("", pattern=r"^(|current|past)$"),
                 offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), su: SessionUser = Depends(require_people), db: AsyncSession = Depends(get_db)):
    """Сотрудники BI. Поиск — ФИО, почта, подразделение, текущее и прежнее имя устройства."""
    return await R.people(db, q=q, source_id=source_id, dept=dept, st=state, offset=offset, limit=limit, pd=True)


@router.get("/people/{pid}")
async def person(pid: int, su: SessionUser = Depends(require_people), db: AsyncSession = Depends(get_db)):
    out = await R.person_card(db, pid, pd=True, can_source=su.can_use_source)
    if out is None:
        raise HTTPException(status_code=404, detail="Сотрудник не найден")
    return out


@router.get("/devices")
async def devices(q: str = Query("", max_length=200), source_id: uuid.UUID | None = None, filter: str = Query("", pattern="^(" + "|".join(R.DEVICE_FILTERS) + ")$"),
                  os: str = Query("", pattern=r"^(|windows|linux|mac|unknown)$"), personal: str = Query("", pattern=r"^(|yes|no)$"), offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                  su: SessionUser = Depends(require_people), db: AsyncSession = Depends(get_db)):
    return await R.devices(db, q=q, source_id=source_id, flt=filter, os_family=os, personal=personal, offset=offset, limit=limit, pd=True, can_source=su.can_use_source)


@router.get("/devices/{did}")
async def device(did: int, su: SessionUser = Depends(require_people), db: AsyncSession = Depends(get_db)):
    out = await R.device_card(db, did, pd=True, can_source=su.can_use_source)
    if out is None:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    return out


@router.get("/host/{source_id}/{host_id}")
async def host(source_id: uuid.UUID, host_id: int, su: SessionUser = Depends(require_user), db: AsyncSession = Depends(get_db)):
    """Блок «Владелец и история принадлежности» карточки компьютера KSC."""
    if not su.can_use_source(source_id):
        raise HTTPException(status_code=403, detail="Нет доступа к этому источнику KSC")
    return {**await R.host_block(db, source_id, host_id, pd=pd(su)), "can_people": su.role in ("analyst", "admin") and (su.is_admin or su.all_sources), "can_decide": su.is_admin}


@router.get("/ksc-users")
async def ksc_users(q: str = Query("", max_length=200), all_os: bool = False, source_id: uuid.UUID | None = None, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                    su: SessionUser = Depends(require_user), srcs: list[KscSource] = Depends(source_scope), db: AsyncSession = Depends(get_db)):
    """Пользователи KSC по накопленным наблюдениям (только источники, доступные пользователю)."""
    sids = [s.id for s in srcs if source_id is None or s.id == source_id]
    out = await R.ksc_users(db, sids, q=q, all_os=all_os, offset=offset, limit=limit)
    if not pd(su):
        for it in out["items"]:
            it["bi_person"] = None
    return out


@router.get("/stats")
async def stats(su: SessionUser = Depends(require_people), db: AsyncSession = Depends(get_db)):
    from ..models import BiDevice, BiPerson  # noqa: PLC0415

    n = lambda q: db.execute(q)  # noqa: E731
    persons = int((await n(select(func.count()).select_from(BiPerson).where(BiPerson.present.is_(True)))).scalar_one())
    devices_ = int((await n(select(func.count()).select_from(BiDevice).where(BiDevice.present.is_(True)))).scalar_one())
    levels = {k: v for k, v in (await n(select(BiMatch.level, func.count(func.distinct(BiMatch.device_id))).group_by(BiMatch.level))).all()}
    return {"persons": persons, "devices": devices_, "levels": levels, "at": datetime.now(timezone.utc)}
