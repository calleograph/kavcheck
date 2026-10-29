"""Фоновое получение BI-выгрузок (worker): раз в сутки в заданное время источника, по требованию администратора и с ограниченными повторами после сбоя.

Каждый источник — отдельное задание под арендой ("bi", источник): недоступный SMB не задерживает остальные. Исходные копии файлов хранятся отдельно от структурированной истории
и удаляются по сроку и числу; история принадлежности при этом сохраняется."""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import BiImport, BiSource, utcnow
from ..services.resources import RES, MemoryPressure
from . import importer as IM
from . import match as M
from . import smb as S

log = logging.getLogger("app.bi")
TICK_S = 15                                   # ручной запуск импорта начинается не позже чем через такт; проверка запросов дешёвая


def next_run(hhmm: str, tz, after: datetime) -> datetime:
    """Ближайшее время запуска строго после `after` (время — в часовом поясе источника)."""
    try:
        h, m = (int(x) for x in (hhmm or "06:00").split(":"))
    except ValueError:
        h, m = 6, 0
    local = after.astimezone(tz)
    cand = local.replace(hour=h % 24, minute=m % 60, second=0, microsecond=0)
    if cand <= local:
        cand += timedelta(days=1)
    return cand.astimezone(timezone.utc)


def src_dir(data_dir: str, sid: uuid.UUID) -> Path:
    d = Path(data_dir) / "bi" / str(sid)
    d.mkdir(parents=True, exist_ok=True)
    return d


def due(src: BiSource, now: datetime) -> bool:
    if src.request:
        return True
    if not src.is_active:
        return False
    opt = IM.options(src)
    if src.fail_n and src.fail_n <= int(opt["retries"]) and src.last_try_at and now - src.last_try_at >= timedelta(minutes=int(opt["retry_minutes"])):
        return True
    return src.next_run_at is not None and now >= src.next_run_at


def conn_of(src: BiSource, password: str) -> S.Conn:
    return S.Conn(host=src.smb_host, share=src.smb_share, path=src.smb_path, username=src.username, password=password, port=src.smb_port, encrypt=src.smb_encrypt)


def rotate(stored: list[BiImport], keep_files: int, keep_days: int, now: datetime, base: Path) -> list[BiImport]:
    """Копии исходных файлов сверх числа и срока хранения удаляются; запись об импорте и история остаются. Возвращает импорты, у которых копия удалена."""
    out = []
    for i, imp in enumerate(sorted(stored, key=lambda x: x.started_at, reverse=True)):
        if i >= keep_files or now - imp.started_at > timedelta(days=keep_days):
            (base / imp.stored).unlink(missing_ok=True)
            imp.stored = ""
            out.append(imp)
    return out


async def enqueue(db: AsyncSession, sid: uuid.UUID, *, trigger: str, by: str = "") -> uuid.UUID:
    """Строка журнала импорта «в очереди» — с момента постановки (запуск вручную, загрузка файла, расписание), а не только после начала обработки.
    Уже есть незавершённая — она и используется: повторный запрос не плодит строк."""
    cur = (await db.execute(select(BiImport).where(BiImport.source_id == sid, BiImport.status.in_(IM.ACTIVE)).order_by(BiImport.started_at.desc()).limit(1))).scalars().first()
    if cur is not None:
        return cur.id
    imp = BiImport(source_id=sid, started_at=utcnow(), trigger=trigger, by=by[:300], status="queued", message="Задание поставлено в очередь")
    db.add(imp)
    await db.flush()
    return imp.id


class BiService:
    def __init__(self, sm: async_sessionmaker[AsyncSession], settings, svc, journal=None):
        self._sm, self._settings, self._svc, self._journal = sm, settings, svc, journal
        self._stop = asyncio.Event()
        self._tasks: set[asyncio.Task] = set()
        self.current: str | None = None

    def stop(self) -> None:
        self._stop.set()

    async def tick(self) -> None:
        now = utcnow()
        async with self._sm() as db:
            srcs = (await db.execute(select(BiSource))).scalars().all()
            for s in srcs:
                if s.next_run_at is None and s.is_active:
                    s.next_run_at = next_run(s.schedule_time, IM.tz_of(s), now)
            await db.commit()
        for s in srcs:
            if self._stop.is_set():
                return
            if due(s, now):
                self._spawn(self.run_source(s.id))
            elif s.last_import_id:
                self._spawn(self.rematch(s.id))                   # данные KSC пересчитаны (новое поколение зон) — пересопоставить; без изменений — пропуск

    def _spawn(self, coro) -> None:
        t = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def rematch(self, sid: uuid.UUID, force: bool = False) -> None:
        from ..services.jobs import JOBS  # noqa: PLC0415

        if JOBS.busy_here("bi", str(sid)):                       # импорт этого источника ждёт места или идёт: сопоставление выполнит он
            return
        if not force and not await M.stale(self._sm, sid):        # ничего не изменилось: аренду не берём, журнал и история заданий не засоряются каждым тактом
            return
        async with JOBS.run("bi", str(sid), "сопоставление") as lease:
            if lease is None:
                return
            try:
                await M.run(self._sm, sid, force=force, lease=lease)
            except Exception:  # noqa: BLE001 — сопоставление повторится на следующем такте; опубликованный снимок не затрагивается
                log.exception("Сопоставление BI с KSC не удалось", extra={"source": str(sid)})

    async def _state(self, imp_id: uuid.UUID, status: str, message: str | None = None, lease=None) -> None:
        """Видимое состояние импорта: строка журнала и этап аренды (для «Состояния системы»)."""
        async with self._sm() as db:
            row = await db.get(BiImport, imp_id)
            if row is not None and (row.status in IM.ACTIVE or status in IM.ACTIVE):
                row.status = status
                if message is not None:
                    row.message = message[:2000]
                await db.commit()
        if lease is not None:
            await lease.stage(IM.STATUS_RU.get(status, status))

    async def run_source(self, sid: uuid.UUID) -> BiImport | None:
        """Импорт источника. Своя полоса ограничителя (`bi`): анализ уязвимостей, каталог и расчёты по KSC не задерживают импорт. Строка журнала — с постановки в очередь:
        «в очереди» → «ожидает исполнителя» (если место занято) → «подключение к SMB» → «получение Excel» → «проверка структуры» → «импорт» → «сопоставление с KSC» → итог."""
        from ..services.jobs import JOBS  # noqa: PLC0415

        if JOBS.busy_here("bi", str(sid)):                       # уже ждёт места или выполняется в этом процессе
            return None
        async with self._sm() as db:
            src = await db.get(BiSource, sid)
            if src is None:
                return None
            req = dict(src.request or {})
            imp_id = uuid.UUID(req["imp_id"]) if req.get("imp_id") else await enqueue(db, sid, trigger="upload" if req.get("upload") else "manual" if req else "schedule", by=str(req.get("by") or ""))
            await db.commit()
            name = src.name

        def waiting() -> None:
            busy = ", ".join(sorted(RES.active)) or "—"
            self._spawn(self._state(imp_id, "waiting", f"Ожидает исполнителя: место для импорта занято ({busy})"))

        async with JOBS.run_heavy("bi", str(sid), "в очереди", task=f"BI: импорт «{name}»", lane="bi", on_wait=waiting) as lease:
            if lease is None:                                    # выполняет другой исполнитель: строка останется в очереди и будет взята им или следующим тактом
                return None
            try:
                imp = await self._run(sid, lease, imp_id)
            except MemoryPressure as exc:
                log.warning("Импорт BI отложен: %s", exc)
                await self._state(imp_id, "queued", f"Отложено: не хватает памяти фоновой службы ({exc}); повтор на следующем такте")
                return None
            if imp is not None and imp.status in ("ok", "partial", "unchanged"):
                final, msg = imp.status, imp.message
                await self._state(imp.id, "matching", None, lease)
                try:
                    await M.run(self._sm, sid, force=imp.status != "unchanged", lease=lease)
                except Exception as exc:  # noqa: BLE001
                    log.exception("Сопоставление BI с KSC не удалось", extra={"source": str(sid)})
                    msg = f"{msg}; сопоставление с KSC не удалось ({type(exc).__name__}), повторится автоматически"
                async with self._sm() as db:
                    row = await db.get(BiImport, imp.id)
                    if row is not None:
                        row.status, row.message = final, msg[:2000]
                        await db.commit()
                imp.status = final
            return imp

    async def recover(self) -> int:
        """При старте worker: импорты, прерванные перезапуском (обновление приложения, сбой), не остаются «в работе» навсегда — им ставится понятный итог;
        опубликованные данные при этом не менялись (публикация — одна транзакция). Строки «в очереди» с ещё не взятым запросом остаются и будут выполнены."""
        n = 0
        async with self._sm() as db:
            rows = (await db.execute(select(BiImport).where(BiImport.status.in_(IM.ACTIVE)))).scalars().all()
            for r in rows:
                src = await db.get(BiSource, r.source_id)
                if r.status == "queued" and src is not None and (src.request or {}).get("imp_id") == str(r.id):
                    continue
                r.status, r.finished_at = "failed", utcnow()
                r.message = "Прервано перезапуском фоновой службы (например, обновлением приложения): опубликованные данные не изменены. " + \
                    ("Импорт по расписанию повторится автоматически." if r.trigger == "schedule" else "Запустите импорт снова.")
                if src is not None and r.trigger == "schedule":
                    src.fail_n = (src.fail_n or 0) + 1
                n += 1
            await db.commit()
        return n

    async def _run(self, sid: uuid.UUID, lease, imp_id: uuid.UUID) -> BiImport | None:
        now = utcnow()
        async with self._sm() as db:
            src = await db.get(BiSource, sid)
            imp = await db.get(BiImport, imp_id)
            if src is None or imp is None:
                return None
            req = dict(src.request or {})
            scheduled = not req
            src.request, src.last_try_at = None, now
            if scheduled or (src.next_run_at and src.next_run_at <= now):
                src.next_run_at = next_run(src.schedule_time, IM.tz_of(src), now)
            imp.started_at, imp.status, imp.message = now, "fetching" if req.get("upload") else "connecting", ""        # время начала — начало обработки (поставлено в очередь — раньше)
            await db.commit()
            name, mode, rule, opt = src.name, src.file_mode, src.file_name, IM.options(src)
            password = self._svc.decrypt(src.password_enc, f"bi.{sid}") if not req.get("upload") else ""
            conn = conn_of(src, password)
            cfg = await self._svc.get(db, "bi")
        self.current = name
        base = src_dir(self._settings.data_dir, sid)
        incoming = base / f"incoming-{imp.id}.xlsx"
        try:
            if req.get("upload"):
                up = base / Path(str(req["upload"])).name
                up.rename(incoming)
                fname, fsize, fmtime = str(req.get("name") or up.name), incoming.stat().st_size, None
            else:
                await lease.stage(IM.STATUS_RU["connecting"])
                loop = asyncio.get_running_loop()

                def fetching() -> None:                         # из потока получения: соединение установлено, файл выбран — идёт копирование
                    loop.call_soon_threadsafe(lambda: self._spawn(self._state(imp.id, "fetching", None, lease)))
                fi = await asyncio.to_thread(self._fetch, conn, mode, rule, list(cfg.allowed_hosts), incoming, int(opt["max_mb"]) * 1024 * 1024, float(opt["stable_s"]), fetching)  # type: ignore[attr-defined]
                fname, fsize, fmtime = fi.name, fi.size, fi.mtime
            imp = await IM.import_file(self._sm, sid, incoming, file_name=fname, file_size=fsize, file_mtime=fmtime, trigger=imp.trigger, by=imp.by, force=bool(req.get("force")),
                                       lease=lease, imp_id=imp.id, store_dir=base)
        except Exception as exc:  # noqa: BLE001 — любой сбой: прежний снимок цел, причина видна в интерфейсе, повтор по настройкам источника
            msg = exc.message if isinstance(exc, S.SmbError) else f"{type(exc).__name__}: {str(exc)[:300]}"
            if not isinstance(exc, S.SmbError):
                log.exception("Импорт BI не удался", extra={"source": name})
            async with self._sm() as db:
                row = await db.get(BiImport, imp.id)
                src = await db.get(BiSource, sid)
                if row is not None:
                    row.status, row.message, row.finished_at = "failed", msg[:2000], utcnow()
                if src is not None:
                    src.last_error, src.fail_n = msg[:2000], (src.fail_n or 0) + 1
                await db.commit()
                imp = row
            await self._emit("import_failed", name, f"Получение выгрузки не удалось: {msg}", "error")
            return imp
        finally:
            self.current = None
            if not (imp is not None and imp.status in ("ok", "partial") and imp.stored):
                incoming.unlink(missing_ok=True)
        async with self._sm() as db:
            src = await db.get(BiSource, sid)
            if imp.status in ("ok", "partial") and imp.stored:
                incoming.rename(base.parent / imp.stored)
            elif imp.status in ("rejected",) and src is not None:
                src.last_error = imp.message
            stored = (await db.execute(select(BiImport).where(BiImport.source_id == sid, BiImport.stored != ""))).scalars().all()
            rotate(stored, int(opt["keep_files"]), int(opt["keep_days"]), utcnow(), base.parent)
            await db.commit()
        level = {"ok": "info", "partial": "warn", "unchanged": "info"}.get(imp.status, "warn")
        await self._emit(f"import_{imp.status}", name, f"{fname}: {imp.message}" + (f" (новых {imp.rows_new}, изменено {imp.rows_changed}, без изменений {imp.rows_same}, отклонено {imp.rows_rejected})"
                                                                                  if imp.status in ("ok", "partial") else ""), level)
        return imp

    @staticmethod
    def _fetch(conn: S.Conn, mode: str, rule: str, allowed: list[str], dst: Path, max_bytes: int, stable_s: float, on_fetch=None) -> S.FileInfo:
        why = S.host_allowed(conn.host, allowed)
        if why:
            raise S.SmbError("allowed", why)
        S.tcp_check(conn.host, conn.port, conn.timeout)
        with S.Smb(conn) as s:
            hit, _cand, why = S.choose(s.listing(), mode, rule)
            if hit is None:
                raise S.SmbError("choose", why)
            if on_fetch is not None:
                on_fetch()
            return S.fetch_stable(s, hit.name, dst, max_bytes, stable_s)

    async def _emit(self, event: str, source: str, message: str, level: str = "info") -> None:
        if self._journal is not None:
            await self._journal.emit("bi", event, level=level, source=source, message=message[:600])

    async def loop(self) -> None:
        await asyncio.sleep(30)
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка цикла BI-выгрузок")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=TICK_S)
            except asyncio.TimeoutError:
                pass
