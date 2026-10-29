"""Импорт снимка BI: получение файла → проверка контейнера и структуры → разбор строк → сравнение с прошлым снимком → публикация одной транзакцией.

Гарантии:
* Ошибка на любом этапе не меняет опубликованные данные: страницы продолжают показывать последний успешный снимок.
* Тот же файл (SHA-256) повторно не обрабатывается; то же содержание с другим оформлением или порядком строк — «Изменений нет», даты наблюдения продлеваются.
* Записи без изменений не копируются: продлевается версия; изменилась — новая версия, прежняя остаётся.
* Старый владелец не удаляется: связь становится «прежней», если устройство есть в снимке с другим сотрудником, и «текущий статус неизвестен», если устройство из снимка исчезло.
* Частичный импорт (часть строк отклонена) не делает выводов об исчезновении устройств."""
from __future__ import annotations

import hashlib
import logging
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import xact_lock
from ..models import BiDevice, BiImport, BiOwner, BiPerson, BiRecord, BiSource, utcnow
from . import profile as PR
from . import xlsx as X

log = logging.getLogger("app.bi")
DEFAULT_OPTIONS = {"partial": True, "max_reject_pct": 5, "drift_pct": 50, "max_mb": 50, "max_rows": 200_000, "keep_files": 10, "keep_days": 90, "retry_minutes": 60, "retries": 3,
                   "stable_s": 10, "full_snapshot": True}
MAX_ERRORS = 500
CHUNK = 1000
WARN_TEXT = {"bad_email": "Некорректная рабочая почта (значение не сохранено)", "bad_date": "Нераспознанная дата", "future_date": "Дата из будущего: сохранена как есть, как дата наблюдения не используется",
             "old_date": "Дата раньше 1990 года: сохранена как есть, как дата наблюдения не используется"}


def options(src: BiSource) -> dict:
    return {**DEFAULT_OPTIONS, **(src.options or {})}


def tz_of(src: BiSource) -> ZoneInfo:
    try:
        return ZoneInfo(src.timezone or "UTC")
    except Exception:  # noqa: BLE001
        return ZoneInfo("UTC")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while b := f.read(1024 * 1024):
            h.update(b)
    return h.hexdigest()


@dataclass
class Parsed:
    headers: list[str]
    recs: dict[str, dict] = field(default_factory=dict)
    read: int = 0
    empty: int = 0
    rejected: int = 0
    errors: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    content_hash: str = ""


def parse_file(path: Path, prof: dict, tz: ZoneInfo, snapshot_at: datetime, max_rows: int) -> Parsed:
    """Синхронный разбор (вызывается в отдельном потоке). Нарушение обязательной структуры — X.XlsxError (импорт отклоняется целиком)."""
    arch = X.check_archive(path)
    wb = X.open_book(path)
    try:
        ws = X.pick_sheet(wb, prof.get("sheet", ""))
        hn, hdr = X.headers(ws, prof.get("header_row", 0))
        miss = [h for h in set(prof["columns"].values()) | set(prof.get("origin", [])) if h not in hdr]
        req = [h for h in PR.required_headers(prof) if h in miss]
        if req:
            raise X.XlsxError(f"Нет обязательных столбцов: {', '.join('«' + h + '»' for h in req)}. Структура файла изменилась — исправьте выгрузку или профиль сопоставления")
        p = Parsed(headers=hdr)
        wc: Counter = Counter()
        wex: dict = {}
        dup_same = dup_diff = 0
        owners: dict[str, set] = defaultdict(set)
        for n, vals in X.rows(ws, hn, hdr):
            p.read += 1
            if p.read > max_rows:
                raise X.XlsxError(f"В файле больше {max_rows} строк: увеличьте предел в настройках источника или проверьте выгрузку")
            for h in miss:
                vals.setdefault(h, None)
            rec, why, warns = PR.parse_row(vals, prof, tz, snapshot_at)
            for w in warns:
                key = (w["code"], w["field"])
                wc[key] += 1
                wex.setdefault(key, w.get("value"))
            if rec is None:
                if why:
                    p.rejected += 1
                    if len(p.errors) < MAX_ERRORS:
                        p.errors.append({"row": n, "reason": why})
                else:
                    p.empty += 1
                continue
            rec["row"] = n
            have = p.recs.get(rec["rkey"])
            if have is not None:
                dup_same += have["rhash"] == rec["rhash"]
                dup_diff += have["rhash"] != rec["rhash"]
                continue
            p.recs[rec["rkey"]] = rec
            if rec["pkey"] and not rec["generic"]:
                owners[rec["dkey"]].add(rec["pkey"])
    finally:
        wb.close()
    col = {f: prof["columns"].get(f, f) for f in PR.FIELDS}
    for (code, f), n in sorted(wc.items()):
        ex = f" (например, {wex[(code, f)]})" if wex.get((code, f)) else ""
        p.warnings.append({"code": code, "n": n, "text": f"{WARN_TEXT[code]} — столбец «{col.get(f, f)}»: {n} строк{ex}"})
    if dup_same:
        p.warnings.append({"code": "dup", "n": dup_same, "text": f"Повторяющиеся строки (учтены один раз): {dup_same}"})
    if dup_diff:
        p.warnings.append({"code": "dup_diff", "n": dup_diff, "text": f"Противоречивые повторы «устройство × сотрудник» (учтена первая строка): {dup_diff}"})
    multi = sum(1 for s in owners.values() if len(s) > 1)
    if multi:
        p.warnings.append({"code": "multi_owner", "n": multi, "text": f"Устройств с несколькими сотрудниками в одном снимке: {multi} (показываются как противоречие, текущий владелец не выбирается)"})
    gen = sum(1 for r in p.recs.values() if r["generic"])
    if gen:
        p.warnings.append({"code": "generic", "n": gen, "text": f"Записей с условным именем устройства («Личный ПК» и т. п.): {gen} — хранятся по сотруднику, с KSC по имени не сопоставляются"})
    p.warnings += [{"code": "archive", "n": 1, "text": t} for t in arch]
    p.content_hash = hashlib.sha256("\n".join(sorted(r["rhash"] for r in p.recs.values())).encode()).hexdigest()
    return p


def verdict(p: Parsed, opt: dict, prev: BiImport | None, force: bool) -> str:
    """Причина отказа или "" (можно публиковать)."""
    total = len(p.recs) + p.rejected
    if not p.recs:
        return "В файле нет ни одной пригодной записи"
    if p.rejected and not opt["partial"]:
        return f"Отклонено строк: {p.rejected}; частичный импорт выключен — снимок не опубликован"
    if p.rejected and p.rejected * 100 > opt["max_reject_pct"] * total:
        return f"Отклонено строк: {p.rejected} из {total} — больше допустимых {opt['max_reject_pct']}%; снимок не опубликован"
    if prev is not None and prev.rows_valid >= 20 and not force:
        d = abs(len(p.recs) - prev.rows_valid) * 100 / prev.rows_valid
        if d > opt["drift_pct"]:
            return (f"Число записей изменилось слишком сильно: {prev.rows_valid} → {len(p.recs)} ({d:.0f}%, порог {opt['drift_pct']}%). Если изменение ожидаемо, запустите импорт "
                    "с подтверждением «Принять изменение объёма»")
    return ""


def structure_diff(prev: list[str], cur: list[str]) -> str:
    if not prev:
        return ""
    add, rem = [h for h in cur if h not in prev], [h for h in prev if h not in cur]
    if not add and not rem:
        return ""
    return "Структура файла изменилась: " + "; ".join(x for x in [f"добавлены {', '.join(add[:8])}" if add else "", f"удалены {', '.join(rem[:8])}" if rem else ""] if x)


async def _load(db: AsyncSession, cols, where) -> list:
    return (await db.execute(select(*cols).where(*where))).all()


async def _insert(db: AsyncSession, model, rows: list[dict], key: str) -> dict:
    out = {}
    for i in range(0, len(rows), CHUNK):
        for rid, k in (await db.execute(insert(model).returning(model.id, getattr(model, key)), rows[i:i + CHUNK])).all():
            out[k] = rid
    return out


async def _update(db: AsyncSession, model, rows: list[dict]) -> None:
    for i in range(0, len(rows), CHUNK):
        await db.execute(update(model), rows[i:i + CHUNK])


async def _save(db: AsyncSession, model, rows: list[dict], have: dict[int, dict], snap: datetime, iid) -> None:
    """Существующие записи: изменившиеся — построчно, без изменений — только даты наблюдения, одним запросом на порцию (снимок в десятки тысяч строк не переписывается целиком)."""
    changed, same = [], []
    for r in rows:
        old = have.get(r["id"])
        (same if old is not None and all(old[k] == r[k] for k in old) else changed).append(r)
    await _update(db, model, changed)
    ids = [r["id"] for r in same]
    for i in range(0, len(ids), CHUNK):
        await db.execute(update(model).where(model.id.in_(ids[i:i + CHUNK])).values(last_seen_at=snap, last_import_id=iid))


async def publish(db: AsyncSession, src: BiSource, imp: BiImport, p: Parsed, snap: datetime, *, full: bool) -> None:
    """Опубликовать снимок (вызывается внутри транзакции, под блокировкой источника). Пишет сотрудников, устройства, связи, версии записей и счётчики импорта."""
    sid, iid = src.id, imp.id
    recs = list(p.recs.values())
    # сотрудники: последняя строка снимка задаёт ФИО, почту и подразделение
    people: dict[str, dict] = {}
    for r in recs:
        if r["pkey"]:
            people[r["pkey"]] = {"full_name": r["person_name"][:300], "email": r["email"][:320], "department": r["department"][:300],
                                 "account_created": datetime.fromisoformat(r["account_created"]) if r.get("account_created") else None}
    P_CMP = ("full_name", "email", "department", "account_created", "present", "search")
    loaded = await _load(db, (BiPerson.id, BiPerson.pkey, *(getattr(BiPerson, c) for c in P_CMP)), (BiPerson.source_id == sid,))
    have_p = {x[1]: x[0] for x in loaded}
    old_p = {x[0]: dict(zip(P_CMP, x[2:])) for x in loaded}
    upd, new = [], []
    for k, v in people.items():
        s = " ".join(x for x in (v["full_name"], v["email"], v["department"]) if x).lower()[:1000]
        if k in have_p:
            upd.append({"id": have_p[k], **v, "last_seen_at": snap, "last_import_id": iid, "present": True, "search": s})
        else:
            new.append({"source_id": sid, "pkey": k, **v, "first_seen_at": snap, "last_seen_at": snap, "last_import_id": iid, "present": True, "search": s})
    await _save(db, BiPerson, upd, old_p, snap, iid)
    pid = {**have_p, **await _insert(db, BiPerson, new, "pkey")}
    # устройства
    devs: dict[str, dict] = {}
    owners_now: dict[str, set] = defaultdict(set)
    for r in recs:
        devs[r["dkey"]] = r
        if r["pkey"]:
            owners_now[r["dkey"]].add(r["pkey"])
    D_CMP = ("name", "short", "generic", "os", "os_family", "personal", "av", "owners_now", "present", "names", "search")
    loaded = await _load(db, (BiDevice.id, BiDevice.dkey, *(getattr(BiDevice, c) for c in D_CMP)), (BiDevice.source_id == sid,))
    have_d = {x[1]: (x[0], x[2], x[11]) for x in loaded}
    old_d = {x[0]: dict(zip(D_CMP, x[2:])) for x in loaded}
    upd, new = [], []
    for k, r in devs.items():
        av = {"uses": r["av_uses"], "other": r["av_other"], "origin": r["origin"]}
        v = {"name": r["device_name"][:300], "short": r["short"][:300], "generic": r["generic"], "os": r["os"][:200], "os_family": PR.os_family(r["os"]), "personal": r["personal"], "av": av,
             "owners_now": len(owners_now[k]), "last_seen_at": snap, "last_import_id": iid, "present": True}
        if k in have_d:
            i, old, names = have_d[k]
            names = list(names or [])
            if old and old != v["name"]:                                 # переименование (только при устойчивом идентификаторе): прежнее имя остаётся в истории и поиске
                names.append({"name": old, "until": snap.isoformat(timespec="seconds")})
            v["names"] = names[-20:]
            v["search"] = " ".join([v["name"], *(n["name"] for n in v["names"])]).lower()[:1500]
            upd.append({"id": i, **v})
        else:
            new.append({"source_id": sid, "dkey": k[:700], **v, "names": [], "search": v["name"].lower(), "first_seen_at": snap})
    await _save(db, BiDevice, upd, old_d, snap, iid)
    did = {k: i for k, (i, _n, _ns) in have_d.items()} | await _insert(db, BiDevice, new, "dkey")
    # связи «устройство × сотрудник»
    O_CMP = ("present", "src_seen_at", "owned_from", "owned_to", "confidence")
    loaded = await _load(db, (BiOwner.id, BiOwner.device_id, BiOwner.person_id, *(getattr(BiOwner, c) for c in O_CMP)), (BiOwner.source_id == sid,))
    have_o = {(x[1], x[2]): (x[0], x[3]) for x in loaded}
    old_o = {x[0]: dict(zip(O_CMP, x[3:])) for x in loaded}
    seen_pairs, seen_devs = set(), {did[k] for k in devs}
    upd, new = [], []
    for r in recs:
        if not r["pkey"]:
            continue
        pair = (did[r["dkey"]], pid[r["pkey"]])
        seen_pairs.add(pair)
        v = {"last_seen_at": snap, "last_import_id": iid, "present": True, "src_seen_at": PR.trusted(r, "observed_at"), "owned_from": PR.trusted(r, "owned_from"), "owned_to": PR.trusted(r, "owned_to"),
             "confidence": PR.confidence(r)}
        if pair in have_o:
            upd.append({"id": have_o[pair][0], **v})
        else:
            new.append({"source_id": sid, "device_id": pair[0], "person_id": pair[1], **v, "first_seen_at": snap, "first_import_id": iid, "seen_n": 1,
                        "basis": "устройство указано за сотрудником в выгрузке BI"})
    await _save(db, BiOwner, upd, old_o, snap, iid)
    for i in range(0, len(new), CHUNK):
        await db.execute(insert(BiOwner), new[i:i + CHUNK])
    if upd:
        ids = [u["id"] for u in upd]
        for i in range(0, len(ids), CHUNK):
            await db.execute(update(BiOwner).where(BiOwner.id.in_(ids[i:i + CHUNK])).values(seen_n=BiOwner.seen_n + 1))
    gone = [i for (d, pp), (i, present) in have_o.items() if present and d in seen_devs and (d, pp) not in seen_pairs]       # устройство есть в снимке, но уже за другим сотрудником
    for i in range(0, len(gone), CHUNK):
        await db.execute(update(BiOwner).where(BiOwner.id.in_(gone[i:i + CHUNK])).values(present=False))
    if full and not p.rejected:                                         # полный снимок без отклонённых строк: чего нет — отсутствует в источнике
        for m in (BiPerson, BiDevice):
            await db.execute(update(m).where(m.source_id == sid, m.present.is_(True), (m.last_import_id.is_(None)) | (m.last_import_id != iid)).values(present=False))
    # версии записей
    prev = {k: (i, h) for i, k, h in await _load(db, (BiRecord.id, BiRecord.rkey, BiRecord.rhash), (BiRecord.source_id == sid, BiRecord.last_import_id == src.last_import_id))} if src.last_import_id else {}
    same, new = [], []
    for r in recs:
        old = prev.get(r["rkey"])
        if old and old[1] == r["rhash"]:
            same.append(old[0])
            continue
        imp.rows_changed += bool(old)
        imp.rows_new += not old
        attrs = {k: r[k] for k in ("person_name", "email", "department", "account_created", "device_name", "device_uid", "os", "personal", "av_uses", "av_other", "observed_at", "manual_at",
                                   "owned_from", "owned_to", "origin", "extra") if r.get(k) not in (None, "", [], {})}
        attrs.update({k: r[k] for k in r if k.endswith("_raw")})
        new.append({"source_id": sid, "rkey": r["rkey"], "rhash": r["rhash"], "device_id": did[r["dkey"]], "person_id": pid.get(r["pkey"]) if r["pkey"] else None, "first_import_id": iid,
                    "last_import_id": iid, "first_seen_at": snap, "last_seen_at": snap, "row_n": r["row"], "attrs": attrs, "flags": r["flags"]})
    for i in range(0, len(same), CHUNK):
        await db.execute(update(BiRecord).where(BiRecord.id.in_(same[i:i + CHUNK])).values(last_import_id=iid, last_seen_at=snap))
    for i in range(0, len(new), CHUNK):
        await db.execute(insert(BiRecord), new[i:i + CHUNK])
    imp.rows_same = len(same)
    imp.rows_gone = len(set(prev) - set(p.recs))
    imp.rows_valid, imp.devices_n, imp.persons_n = len(recs), len(devs), len(people)
    src.last_import_id = iid


async def extend(db: AsyncSession, src: BiSource, imp: BiImport, snap: datetime) -> None:
    """То же содержание в новом файле: снимок подтверждает прежние данные на новую дату — продлеваются даты наблюдения, новые версии не создаются."""
    prev, iid = src.last_import_id, imp.id
    for m in (BiRecord, BiPerson, BiDevice, BiOwner):
        await db.execute(update(m).where(m.source_id == src.id, m.last_import_id == prev).values(last_import_id=iid, last_seen_at=snap))
    last = await db.get(BiImport, prev)
    if last is not None:
        imp.rows_valid, imp.rows_same, imp.devices_n, imp.persons_n = last.rows_valid, last.rows_valid, last.devices_n, last.persons_n
    src.last_import_id = iid


async def import_file(sm, src_id: uuid.UUID, path: Path, *, file_name: str, file_size: int | None, file_mtime: datetime | None, trigger: str, by: str, force: bool = False,
                      lease=None, imp_id: uuid.UUID | None = None, store_dir: Path | None = None) -> BiImport:
    """Импорт уже полученного файла. Возвращает запись BiImport с итогом; опубликованные данные меняются только при статусе ok/partial/unchanged-с-продлением."""
    import asyncio  # noqa: PLC0415

    t0 = time.monotonic()
    now = utcnow()
    async with sm() as db:
        src = await db.get(BiSource, src_id)
        opt, tz, prof = options(src), tz_of(src), PR.validate_profile(src.profile or {})
        prev = await db.get(BiImport, src.last_import_id) if src.last_import_id else None
        imp = await db.get(BiImport, imp_id) if imp_id else None
        if imp is None:
            imp = BiImport(id=imp_id or uuid.uuid4(), source_id=src_id, started_at=now, trigger=trigger, by=by[:300])
            db.add(imp)
        imp.file_name, imp.file_size, imp.file_mtime = file_name[:255], file_size, file_mtime
        warns: list[dict] = []
        snap = file_mtime or now
        if snap > now + PR.FUTURE_SLACK:
            warns.append({"code": "mtime", "n": 1, "text": f"Время изменения файла в будущем ({snap:%d.%m.%Y}): датой снимка принято время получения"})
            snap = now
        imp.snapshot_at = snap
        imp.sha256 = await asyncio.to_thread(sha256_file, path)
        await db.commit()

        async def finish(status: str, message: str = "") -> BiImport:
            imp.status, imp.message, imp.finished_at, imp.ms = status, message[:2000], utcnow(), int((time.monotonic() - t0) * 1000)
            imp.warnings = (warns + list(imp.warnings or []))[:100]
            await db.commit()
            return imp

        if prev is not None and prev.sha256 == imp.sha256 and not force:
            imp.rows_valid, imp.devices_n, imp.persons_n = prev.rows_valid, prev.devices_n, prev.persons_n
            src.last_ok_at, src.last_error, src.fail_n = utcnow(), None, 0                 # файл получен успешно, просто не изменился
            return await finish("unchanged", "Изменений нет: файл совпадает с уже импортированным")
        if prev is not None and prev.snapshot_at and snap < prev.snapshot_at and not force:
            return await finish("rejected", f"Файл старше уже импортированного снимка ({prev.snapshot_at:%d.%m.%Y %H:%M} UTC): история не перезаписывается старыми данными")
        try:
            p = await asyncio.to_thread(parse_file, path, prof, tz, snap, int(opt["max_rows"]))
        except X.XlsxError as exc:
            return await finish("rejected", str(exc))
        imp.headers, imp.rows_read, imp.rows_empty, imp.rows_rejected, imp.errors, imp.content_hash = p.headers[:200], p.read, p.empty, p.rejected, p.errors, p.content_hash
        sd = structure_diff(prev.headers if prev else [], p.headers)
        imp.warnings = ([{"code": "structure", "n": 1, "text": sd}] if sd else []) + p.warnings
        why = verdict(p, opt, prev, force)
        if why:
            return await finish("rejected", why)
        if prev is not None and prev.content_hash == p.content_hash and not force:
            await xact_lock(db, f"bi:{src_id}")
            if lease is not None:
                await lease.fence(db)
            await extend(db, src, imp, snap)
            src.last_ok_at, src.last_error, src.fail_n = utcnow(), None, 0
            return await finish("unchanged", "Изменений нет: содержание совпадает с прошлым снимком (отличается только оформление или порядок строк); даты наблюдения продлены")
        try:
            await xact_lock(db, f"bi:{src_id}")
            if lease is not None:
                await lease.fence(db)
            await publish(db, src, imp, p, snap, full=bool(opt["full_snapshot"]))
            src.last_ok_at, src.last_error, src.fail_n = utcnow(), None, 0
            if store_dir is not None:
                imp.stored = str(Path(store_dir.name) / f"{imp.id}.xlsx")
            status = "partial" if p.rejected else "ok"
            msg = f"Опубликовано записей: {len(p.recs)}" + (f"; отклонено строк: {p.rejected} (исчезновение устройств в этом снимке не учитывается)" if p.rejected else "")
            return await finish(status, msg)
        except Exception:
            await db.rollback()                                            # ничего из снимка не записано: прежняя версия данных цела
            raise
