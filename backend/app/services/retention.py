"""Хранение журналов: ротация по сроку, объёму и общей квоте, сжатые архивы, контроль свободного места.

Физически журналы не объединяются: у каждого типа свой владелец и место (таблица базы, файл Docker), здесь они только управляются из одного места. Три разные политики:
* **операционные** (журнал событий, журналы выполнения Pentest) — чистятся по сроку и объёму, при желании сначала архивируются;
* **аудит** (журнал действий) — по умолчанию не удаляется; при заданном сроке запись удаляется только после успешной записи в архив; предел объёма только предупреждает;
* **результаты сканирований** (задания, находки) здесь не затрагиваются — их срок задаёт Pentest.
Тяжёлая очистка не выполняется при активном сканировании и идёт порциями (без загрузки таблицы в память). Нехватка места не должна останавливать приложение: сбой записи журнала не влияет на работу,
а невозможность освободить место без нарушения правил хранения показывается предупреждением."""
from __future__ import annotations

import asyncio
import gzip
import json
import logging
import re
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import AppSetting, AuditLog, EventLog, PtEvent, utcnow

log = logging.getLogger("app.retention")
CHUNK = 2000
STATE_KEY = "logs_state"
ARCHIVE_RE = re.compile(r"^(journal|audit|pt_events)-\d{8}-\d{6}-\d{2}\.ndjson(\.gz)?$")

# тип → описание (владелец, место, формат, назначение), модель, имя поля срока в настройках
TYPES: dict[str, dict] = {
    "journal": {"title": "Журнал событий приложения", "owner": "backend, worker", "location": "PostgreSQL, таблица event_log", "format": "строки таблицы (JSON в поле data)", "kind": "operational",
                "purpose": "ошибки и предупреждения служб, входы, подключения к источникам KSC, каталог программ, EOL, базы уязвимостей, формирование отчётов, системные события", "model": EventLog,
                "days": "journal_days", "max": "journal_max_mb", "archive": "journal_archive", "tab": "journal"},
    "audit": {"title": "Журнал действий", "owner": "backend", "location": "PostgreSQL, таблица audit_log", "format": "строки таблицы (JSON в поле details)", "kind": "audit",
              "purpose": "кто, что и когда сделал в KAV Checker (действия администраторов и пользователей); обязательные события не теряются", "model": AuditLog,
              "days": "audit_days", "max": "audit_max_mb", "archive": None, "tab": "audit"},
    "pt_events": {"title": "Журналы выполнения заданий Pentest", "owner": "сканер Pentest", "location": "PostgreSQL, таблица pt_events", "format": "нормализованные события задания (Nmap, NSE, Nuclei, сопоставление)", "kind": "operational",
                  "purpose": "ход и диагностика заданий сканирования; находки, порты и хосты — в результатах и этими настройками не затрагиваются", "model": PtEvent,
                  "days": "pt_events_days", "max": "pt_events_max_mb", "archive": "pt_events_archive", "tab": "pentest"},
}
EXTERNAL = [{"key": "docker", "title": "Журналы контейнеров (stdout)", "owner": "Docker", "location": "драйвер json-file на сервере", "format": "JSON-строки", "kind": "operational",
             "purpose": "вывод backend, worker, сканера и web; ротацию (max-size, max-file) задаёт deployment/compose.yml — из интерфейса не меняется"}]


def archive_dir(reports_dir: str) -> Path:
    return Path(reports_dir) / "_logs" / "archive"


def _dialect(db: AsyncSession) -> str:
    return db.bind.dialect.name if db.bind is not None else "sqlite"


async def table_stats(db: AsyncSession, key: str) -> dict:
    m = TYPES[key]["model"]
    tbl = m.__tablename__
    if _dialect(db) == "postgresql":
        size = int((await db.execute(text("SELECT pg_total_relation_size(CAST(:t AS regclass))"), {"t": tbl})).scalar_one())
        rows = int((await db.execute(text("SELECT GREATEST(reltuples, 0)::bigint FROM pg_class WHERE oid = CAST(:t AS regclass)"), {"t": tbl})).scalar_one())
        if rows < 10_000:                                           # оценка PostgreSQL неточна на малых таблицах — считаем точно
            rows = int((await db.execute(select(func.count()).select_from(m))).scalar_one())
    else:
        rows = int((await db.execute(select(func.count()).select_from(m))).scalar_one())
        size = rows * 450
    oldest = (await db.execute(select(func.min(m.at)))).scalar_one()
    return {"rows": rows, "bytes": size, "oldest": oldest}


def list_archives(directory: Path) -> list[dict]:
    out = []
    try:
        for f in sorted(directory.iterdir()):
            if ARCHIVE_RE.match(f.name) and f.is_file():
                st = f.stat()
                out.append({"name": f.name, "type": f.name.split("-", 1)[0], "bytes": st.st_size, "at": datetime.fromtimestamp(st.st_mtime, timezone.utc), "gz": f.suffix == ".gz"})
    except OSError:
        pass
    return out


def disk_info(path: str, warn_free_mb: int) -> dict:
    try:
        u = shutil.disk_usage(path)
    except OSError:
        return {"free": None, "total": None, "warn": False}
    return {"free": u.free, "total": u.total, "warn": u.free < warn_free_mb * 1024 * 1024}


def _row_dict(r) -> dict:
    out = {}
    for c in r.__table__.columns:
        v = getattr(r, c.key)
        out[c.key] = v.isoformat() if isinstance(v, datetime) else str(v) if isinstance(v, uuid.UUID) else v
    return out


class _Writer:
    """Файлы архива одного прогона: ротация по размеру (archive_file_mb), сжатие gzip; закрытые файлы остаются на месте."""

    def __init__(self, directory: Path, key: str, file_mb: int, compress: bool):
        self.dir, self.key, self.limit, self.compress = directory, key, file_mb * 1024 * 1024, compress
        self.stamp = utcnow().strftime("%Y%m%d-%H%M%S")
        self.part, self.f, self.size, self.files = 0, None, 0, []

    def _open(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.part += 1
        name = f"{self.key}-{self.stamp}-{self.part:02d}.ndjson" + (".gz" if self.compress else "")
        path = self.dir / name
        self.f = gzip.open(path, "wb", compresslevel=6) if self.compress else open(path, "wb")      # noqa: SIM115
        self.size, _ = 0, self.files.append(path)

    def write(self, lines: list[bytes]) -> None:
        blob = b"".join(lines)
        if self.f is None or (self.size and self.size + len(blob) > self.limit):
            self.close()
            self._open()
        self.f.write(blob)
        self.f.flush()
        self.size += len(blob)

    def close(self) -> None:
        if self.f is not None:
            self.f.close()
            self.f = None


async def _move(sm: async_sessionmaker[AsyncSession], key: str, where: list, cfg, directory: Path, archive: bool, max_rows: int | None = None) -> dict:
    """Строки по условию — порциями в архив (если включён) и затем удаление; запись в архив подтверждена до удаления порции."""
    m = TYPES[key]["model"]
    w = _Writer(directory, key, cfg.archive_file_mb, cfg.compress) if archive else None
    done = 0
    try:
        while max_rows is None or done < max_rows:
            async with sm() as db:
                rows = (await db.execute(select(m).where(*where).order_by(m.id).limit(CHUNK if max_rows is None else min(CHUNK, max_rows - done)))).scalars().all()
                if not rows:
                    break
                if w is not None:
                    lines = [(json.dumps(_row_dict(r), ensure_ascii=False, default=str) + "\n").encode() for r in rows]
                    await asyncio.to_thread(w.write, lines)
                await db.execute(delete(m).where(m.id.in_([r.id for r in rows])))
                await db.commit()
                done += len(rows)
            await asyncio.sleep(0.05)                               # не занимать диск и процессор подряд
    finally:
        if w is not None:
            await asyncio.to_thread(w.close)
    return {"rows": done, "files": [p.name for p in (w.files if w else [])]}


async def run(sm: async_sessionmaker[AsyncSession], cfg, reports_dir: str, *, busy: bool = False, force: bool = False) -> dict:
    """Один прогон: срок → объём → квота → срок архивов → проверка диска. Возвращает отчёт (сохраняется в состоянии и показывается администратору)."""
    rep: dict = {"at": utcnow().isoformat(), "moved": {}, "warnings": [], "deleted_archives": [], "deferred": False}
    directory = archive_dir(reports_dir)
    if busy and not force:
        rep["deferred"] = True
        rep["warnings"].append("Очистка отложена: выполняется сканирование Pentest (тяжёлая очистка не конкурирует с ним за диск и процессор).")
        return rep
    now = utcnow()
    for key, t in TYPES.items():
        days = getattr(cfg, t["days"])
        arch = True if key == "audit" else bool(getattr(cfg, t["archive"]))
        m = t["model"]
        moved = {"rows": 0, "files": []}
        if cfg.auto_clean or force:
            if days:                                               # 1) срок хранения
                if key == "journal" and cfg.journal_by_category:
                    for cat, d in cfg.journal_by_category.items():
                        r = await _move(sm, key, [m.category == cat, m.at < now - timedelta(days=d)], cfg, directory, arch)
                        moved["rows"] += r["rows"]
                        moved["files"] += r["files"]
                    rest = [m.category.notin_(list(cfg.journal_by_category))]
                else:
                    rest = []
                r = await _move(sm, key, [*rest, m.at < now - timedelta(days=days)], cfg, directory, arch)
                moved["rows"] += r["rows"]
                moved["files"] += r["files"]
            cap = getattr(cfg, t["max"])
            if cap:                                                # 2) объём
                async with sm() as db:
                    st = await table_stats(db, key)
                if st["bytes"] > cap * 1024 * 1024:
                    if key == "audit":
                        rep["warnings"].append(f"Журнал действий занимает больше заданного предела ({cap} МБ), но записи аудита по объёму не удаляются.")
                    elif st["rows"]:
                        drop = int(st["rows"] * (1 - 0.9 * cap * 1024 * 1024 / st["bytes"])) + 1
                        r = await _move(sm, key, [], cfg, directory, arch, max_rows=drop)
                        moved["rows"] += r["rows"]
                        moved["files"] += r["files"]
                        rep["warnings"].append(f"{t['title']}: объём превышал {cap} МБ — удалено самых старых записей: {r['rows']}.")
        rep["moved"][key] = moved
    # 3) срок и число архивов
    arcs = list_archives(directory)
    cut = now - timedelta(days=cfg.archive_days)
    for a in list(arcs):
        expired = (bool(cfg.audit_days) and a["at"] < now - timedelta(days=max(cfg.archive_days, cfg.audit_days))) if a["type"] == "audit" else a["at"] < cut
        if expired:
            if _rm(directory / a["name"]):
                rep["deleted_archives"].append(a["name"])
                arcs.remove(a)
    arcs.sort(key=lambda a: a["at"])
    over = [a for a in arcs if a["type"] != "audit"][:max(0, len([a for a in arcs if a["type"] != "audit"]) - cfg.archive_max_files)]
    for a in over:
        if _rm(directory / a["name"]):
            rep["deleted_archives"].append(a["name"])
            arcs.remove(a)
    # 4) общая квота
    if cfg.quota_mb:
        total = await usage(sm, directory)
        if total > cfg.quota_mb * 1024 * 1024 and (cfg.auto_clean or force):
            for key in ("journal", "pt_events"):                   # сжатие: записи старше половины срока — в архив (данные сохраняются, места занимают меньше)
                t = TYPES[key]
                days = getattr(cfg, t["days"])
                r = await _move(sm, key, [t["model"].at < now - timedelta(days=max(1, days // 2))], cfg, directory, True)
                rep["moved"][key]["rows"] += r["rows"]
                rep["moved"][key]["files"] += r["files"]
            total = await usage(sm, directory)
            for a in sorted([x for x in list_archives(directory) if x["type"] != "audit"], key=lambda x: x["at"]):      # старейшие архивы операционных журналов — пока не уложимся
                if total <= cfg.quota_mb * 1024 * 1024:
                    break
                if a["at"] < now - timedelta(days=getattr(cfg, TYPES[a["type"]]["days"])) and _rm(directory / a["name"]):
                    rep["deleted_archives"].append(a["name"])
                    total -= a["bytes"]
            if total > cfg.quota_mb * 1024 * 1024:
                rep["warnings"].append(f"Квота {cfg.quota_mb} МБ превышена: освободить место без нарушения правил хранения нельзя (занято {total // 1048576} МБ). Увеличьте квоту или сократите сроки.")
    di = disk_info(str(Path(reports_dir)), cfg.disk_warn_free_mb)
    if di["warn"]:
        rep["warnings"].append(f"На диске данных свободно меньше {cfg.disk_warn_free_mb} МБ — освободите место до того, как это затронет базу данных.")
    return rep


def _rm(p: Path) -> bool:
    try:
        p.unlink()
        return True
    except OSError:
        log.warning("Архив журнала не удалён", extra={"file": p.name}, exc_info=True)
        return False


async def usage(sm: async_sessionmaker[AsyncSession], directory: Path) -> int:
    async with sm() as db:
        db_bytes = sum([(await table_stats(db, k))["bytes"] for k in TYPES])
    return db_bytes + sum(a["bytes"] for a in list_archives(directory))


async def get_state(sm: async_sessionmaker[AsyncSession]) -> dict:
    async with sm() as db:
        row = await db.get(AppSetting, STATE_KEY)
        return dict(row.value or {}) if row else {}


async def set_state(sm: async_sessionmaker[AsyncSession], **kv) -> None:
    async with sm() as db:
        row = await db.get(AppSetting, STATE_KEY)
        if row is None:
            db.add(AppSetting(group=STATE_KEY, value=kv))
        else:
            row.value = {**(row.value or {}), **kv}
        await db.commit()


class Retention:
    """Фоновая служба (worker): ротация раз в rotate_hours или по запросу администратора."""

    def __init__(self, sm: async_sessionmaker[AsyncSession], settings, svc):
        self._sm, self._settings, self._svc = sm, settings, svc
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    async def tick(self) -> bool:
        from .jobs import JOBS  # noqa: PLC0415

        async with self._sm() as db:
            cfg = await self._svc.get(db, "logs")
        st = await get_state(self._sm)
        last = datetime.fromisoformat(st["last_run"]) if st.get("last_run") else None
        due = st.get("requested") or last is None or utcnow() - last >= timedelta(hours=cfg.rotate_hours)
        if not due:
            return False
        busy = bool(await JOBS.live("pentest"))
        rep = await run(self._sm, cfg, self._settings.reports_dir, busy=busy, force=bool(st.get("requested")))
        if rep["deferred"]:
            await set_state(self._sm, last_report=rep, next_run=(utcnow() + timedelta(minutes=30)).isoformat())
            return False
        await set_state(self._sm, last_run=utcnow().isoformat(), requested=False, last_report=rep, next_run=(utcnow() + timedelta(hours=cfg.rotate_hours)).isoformat())
        if rep["warnings"]:
            log.warning("Хранение журналов: " + "; ".join(rep["warnings"])[:500])
        return True

    async def loop(self) -> None:
        await asyncio.sleep(120)
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка ротации журналов")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass
