"""Синхронизация базы уязвимостей: расписание, ручной запуск, состояние источников, история, безопасная замена данных, анализ по каталогу (находки для специалиста ИБ).
Работает в воркере; API только ставит запрос на запуск (`requested_at`) и читает состояние."""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..config import Settings
from ..models import CaCertificate, CatalogState, KscSource, VdbAffected, VdbAnalysis, VdbFinding, VdbFindingProduct, VdbRecord, VdbRun, VdbSource, VdbVersionHit, VdbVuln, utcnow
from ..services.settings import SettingsService
from ..services.audit import Journal
from ..services.resources import RES, MemoryPressure, Resources
from . import journal as J
from . import match as M
from . import sources as S
from . import store
from .classmap import class_map
from ..services.jobs import JOBS
from .fetch import FetchError, Http, builtin_ca, make_ssl

log = logging.getLogger("app.vdb")
STALE = timedelta(hours=3)
BACKLOG_DAYS = 90
MIN_FREE_MB = int(os.environ.get("VDB_MIN_FREE_MB", "1024"))
MIN_ANALYSIS_H = float(os.environ.get("VDB_ANALYSIS_MIN_HOURS", "6"))      # автоматический полный расчёт одного источника — не чаще; ручной «Пересчитать» и первый расчёт ограничению не подчиняются
UPLOAD_DIR = "vdb"


def upload_path(settings: Settings, key: str) -> Path:
    d = Path(settings.data_dir) / UPLOAD_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{key}-upload.bin"


class VdbSync:
    def __init__(self, sm: async_sessionmaker[AsyncSession], settings: Settings, svc: SettingsService, journal: Journal, *, http_factory=None, sleep=asyncio.sleep):
        self._sm, self._settings, self._svc, self._journal = sm, settings, svc, journal
        self._http_factory, self._sleep = http_factory, sleep
        self._running: set[str] = set()
        self._retry_at: dict[uuid.UUID, float] = {}
        self._pending: set[str] = set()                    # изменённые уязвимости, пока полный расчёт не позволял разобрать их частично: разбираются сразу после него
        self._said: dict[tuple, float] = {}                # когда в журнал последний раз писали повторяющееся сообщение (чтобы не засорять его)

    # ------------------------------------------------------------------------------------------ запуск источника
    async def _http(self, db: AsyncSession, key: str, row: VdbSource) -> Http:
        if self._http_factory:
            return self._http_factory(key)
        pems = [c.pem for c in (await db.execute(select(CaCertificate))).scalars().all()] if key == "bdu" else []
        if key == "bdu" and (row.settings or {}).get("builtin_ca", True):
            pems = builtin_ca("russian_trusted_chain") + pems         # сертификаты Минцифры — только для соединений с БДУ
        return Http(verify=make_ssl(pems, bool((row.settings or {}).get("verify_tls", True))), timeout=90)

    async def run_source(self, key: str, trigger: str = "schedule", file: Path | None = None) -> bool:
        """Загрузить источник. Возвращает True при успехе. Ошибка не затрагивает действующие данные: последняя корректная база остаётся в работе."""
        if key in self._running or key not in S.SOURCES:
            return False
        free_mb = shutil.disk_usage(self._settings.data_dir).free >> 20
        if free_mb < MIN_FREE_MB:               # плановая загрузка не должна добивать диск: останавливаемся заранее и говорим об этом
            msg = f"Недостаточно места на диске: свободно {free_mb} МБ, для загрузки нужно не менее {MIN_FREE_MB} МБ. Освободите место (старые резервные копии, образы Docker) и нажмите «Обновить сейчас»"
            async with self._sm() as db:
                row = await db.get(VdbSource, key)
                if row is not None:
                    row.status, row.last_error, row.progress, row.requested_at, row.last_started_at = "error", msg, None, None, utcnow()
                    await db.commit()
            await self._journal.emit("system", "vdb_sync_failed", level="error", message=f"{S.INFO[key]['title']}: {msg}", data={"source": key, "trigger": trigger})
            await J.emit(self._sm, "sync", f"{S.INFO[key]['title']}: загрузка не начата: {msg}", level="error", vdb_key=key, details={"free_mb": free_mb, "need_mb": MIN_FREE_MB})
            return False
        lease = await JOBS.acquire("vdb_sync", key)                 # загрузку источника выполняет один исполнитель (между несколькими worker тоже)
        if lease is None:
            return False
        self._running.add(key)
        started = time.perf_counter()
        run_id = 0
        outcome = ["success", None]
        try:
            async with self._sm() as db:
                row = await db.get(VdbSource, key)
                if row is None:
                    return False
                settings, cursor = dict(row.settings or {}), dict(row.cursor or {})
                secret = self._svc.decrypt(row.secret_enc, f"vdb.{key}") if row.secret_enc else ""
                row.status, row.last_started_at, row.progress, row.requested_at = "running", utcnow(), "запуск", None
                has_data = row.records > 0 and row.last_ok_at is not None
                generation = row.active_generation
                run = VdbRun(source=key, trigger=trigger, mode=S.INFO[key]["mode"])
                db.add(run)
                await db.flush()
                run_id = run.id
                http = await self._http(db, key, row)
                await db.commit()
            await J.emit(self._sm, "sync", f"{S.INFO[key]['title']}: загрузка начата ({'вручную' if trigger != 'schedule' else 'по расписанию'})", vdb_key=key, details={"trigger": trigger, "run_id": run_id, "mode": S.INFO[key]["mode"]})

            async def progress(text: str) -> None:
                async with self._sm() as db2:
                    await db2.execute(update(VdbSource).where(VdbSource.key == key).values(progress=text[:300]))
                    await db2.commit()

            ctx = S.RunCtx(self._sm, key, settings, secret, cursor, http, progress, file=file, sleep=self._sleep, data_dir=Path(self._settings.data_dir), has_data=has_data, generation=generation, force=trigger == "manual")
            error = ""
            try:
                await S.SOURCES[key](ctx)
            except (FetchError, store.IntegrityError) as exc:
                error = str(exc)
            except Exception as exc:  # noqa: BLE001
                log.exception("Сбой загрузки источника %s", key)
                error = f"Внутренняя ошибка: {type(exc).__name__}"
                await ctx.discard()
            finally:
                ctx.cleanup()
                await http.close()
            ms = int((time.perf_counter() - started) * 1000)
            async with self._sm() as db:
                row = await db.get(VdbSource, key)
                if ctx.new_cursor is not None:
                    row.cursor = {**(row.cursor or {}), **ctx.new_cursor} if not error or "pub_loaded_until" in ctx.new_cursor else row.cursor
                row.diag = ctx.attempts or None
                if error:
                    row.status, row.last_error, row.progress = "error", error[:1500], None
                else:
                    row.status, row.last_ok_at, row.last_error, row.progress, row.channel = "ok", utcnow(), None, None, ctx.channel
                    if key == "oval":                                    # свои таблицы: число определений
                        from ..models import OvalDef  # noqa: PLC0415

                        row.records = int((await db.execute(select(func.count()).select_from(OvalDef))).scalar_one())
                    elif S.INFO[key].get("own_store"):                  # источник со своими таблицами (endoflife.date): число продуктов
                        from ..eol.sync import count as eol_count  # noqa: PLC0415

                        row.records = await eol_count(self._sm)
                    else:
                        row.records = int((await db.execute(select(func.count()).select_from(VdbRecord).where(VdbRecord.source == key, VdbRecord.generation == row.active_generation))).scalar_one())
                row.last_duration_ms = ms
                if not error and (ctx.changed or ctx.keys):
                    row.data_ver = (row.data_ver or 0) + 1                  # данные изменились: от этого зависит ревизия расчёта; загрузка «без изменений» повторного расчёта не вызывает
                await store.finish_run(db, run_id, finished_at=utcnow(), status="error" if error else "ok", fetched=ctx.fetched, changed=ctx.changed, duration_ms=ms, error=error[:1500] or None, channel=ctx.channel, attempts=ctx.attempts or None)
                await store.prune_runs(db, key)
                await db.commit()
            await self._journal.emit("system", "vdb_sync_done" if not error else "vdb_sync_failed", level="info" if not error else "error", message=f"{S.INFO[key]['title']}: "
                                     + (f"записей получено {ctx.fetched}, изменено {ctx.changed}" if not error else error[:300]), duration_ms=ms, data={"source": key, "trigger": trigger})
            await J.emit(self._sm, "sync", f"{S.INFO[key]['title']}: " + (f"загружено, получено {ctx.fetched}, изменено {ctx.changed}, {ms / 1000:.0f} с" + (f"; не получено: {len(ctx.warnings)} (см. подробности)" if ctx.warnings else "") if not error else f"ошибка загрузки: {error[:300]}"),
                         level="error" if error else ("warn" if ctx.warnings else "info"), vdb_key=key, details={"run_id": run_id, "fetched": ctx.fetched, "changed": ctx.changed, "seconds": round(ms / 1000), "channel": ctx.channel,
                                                                                    "attempts": (ctx.attempts or [])[:6], "warnings": ctx.warnings[:20]})
            if error:
                outcome[:] = ["error", error[:500]]
            if not error and ctx.keys and len(ctx.keys) <= 3000:
                await self.analyze_keys(ctx.keys)               # больше — полный пересчёт по изменению ревизии данных (analysis_tick)
            return not error
        except asyncio.CancelledError:
            outcome[:] = ["interrupted", "выполнение отменено"]
            raise
        except BaseException as exc:
            outcome[:] = ["error", f"{type(exc).__name__}: {exc}"[:500]]
            raise
        finally:
            self._running.discard(key)
            await lease.finish(outcome[0], outcome[1])

    # ------------------------------------------------------------------------------------------ расписание
    async def tick(self) -> None:
        now = datetime.now(timezone.utc)
        async with self._sm() as db:
            rows = (await db.execute(select(VdbSource))).scalars().all()
            todo = []
            for r in rows:
                if r.status == "running" and r.key not in self._running and not await JOBS.is_live("vdb_sync", r.key):
                    # «выполняется» без действующей аренды — след остановившегося процесса: снимаем сразу и повторяем (при частых прерываниях — через 30 минут)
                    r.status, r.last_error, r.progress = "error", "Загрузка прервана (перезапуск или сбой службы); будет повторена автоматически", None
                    if await JOBS.failures_since("vdb_sync", r.key, now - timedelta(minutes=30)) < 3:
                        r.last_started_at = None
                    continue
                if r.key in self._running or r.status == "running" or await JOBS.is_live("vdb_sync", r.key):
                    continue
                if r.key == "oval" and r.requested_at is None and not any(isinstance(f, dict) and f.get("url") for f in (r.settings or {}).get("feeds") or []):
                    continue                                        # плановая загрузка OVAL без заданных фидов бессмысленна: ошибка каждые 30 минут не нужна, ручной запуск объяснит причину
                wait = timedelta(minutes=30) if r.status == "error" else timedelta(hours=max(1, r.interval_hours))       # после ошибки — повтор через 30 минут, а не через сутки
                due = r.requested_at is not None or (r.enabled and (r.last_started_at is None or now - _utc(r.last_started_at) >= wait))
                if due and (r.enabled or r.requested_at is not None):
                    todo.append((r.key, "manual" if r.requested_at else "schedule"))
            await db.commit()
        for key, trig in todo:
            up = upload_path(self._settings, key)
            file = up if trig == "manual" and up.exists() else None
            await self.run_source(key, "file" if file else trig, file=file)
            if file is not None:
                file.unlink(missing_ok=True)

    async def upgrade_scores(self) -> int:
        async with self._sm() as db:
            n = await store.upgrade_scores(db)
            await db.commit()
        if n:
            log.info("Оценки CVSS преобразованы для %s записей", n)
        return n

    def purge_tmp(self) -> int:
        """Остатки прерванных загрузок (перезапуск, сбой питания) во временном каталоге на томе данных; запущенных загрузок при старте нет."""
        n = 0
        d = Path(self._settings.data_dir) / UPLOAD_DIR / "tmp"
        if d.is_dir():
            for x in d.iterdir():
                shutil.rmtree(x, ignore_errors=True) if x.is_dir() else x.unlink(missing_ok=True)
                n += 1
        return n

    async def recover_interrupted(self) -> int:
        """После перезапуска службы загрузок не идёт ни одна: «выполняется» — след прерванной загрузки. Статус снимается сразу (а не через часы), недозагруженные поколения
        удаляются, действующие данные не затрагиваются (они меняются только при успешной проверке)."""
        n = 0
        async with self._sm() as db:
            for r in (await db.execute(select(VdbSource))).scalars().all():
                if r.status == "running" and not await JOBS.is_live("vdb_sync", r.key):          # загрузку, которую ведёт другой worker, не трогаем
                    r.status, r.last_error, r.progress, n = "error", "Загрузка прервана (перезапуск службы); будет повторена автоматически", None, n + 1
                keep = [g for g in (r.active_generation, r.prev_generation) if g is not None]
                for model in (VdbAffected, VdbRecord):
                    await db.execute(delete(model).where(model.source == r.key, model.generation.notin_(keep)))
            await db.commit()
        return n

    async def loop(self) -> None:
        await asyncio.sleep(10)
        try:
            if await self.recover_interrupted():
                log.warning("Прерванные загрузки базы уязвимостей помечены как ошибка")
        except Exception:  # noqa: BLE001
            log.exception("Не удалось обработать прерванные загрузки")
        try:
            if self.purge_tmp():
                log.info("Удалены остатки прерванных загрузок")
        except OSError:
            log.exception("Не удалось очистить временные файлы загрузок")
        try:
            await self.upgrade_scores()
        except Exception:  # noqa: BLE001
            log.exception("Не удалось преобразовать прежние оценки CVSS")
        try:
            await self._recover_analysis()
        except Exception:  # noqa: BLE001
            log.exception("Не удалось обработать прерванные расчёты")
        # расчёт (часы на большой базе) идёт в своём цикле: он не должен задерживать загрузки источников и очередь «Обновить сейчас»
        self._analysis_task = asyncio.create_task(self.analysis_loop())
        while True:
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка цикла базы уязвимостей")
            await asyncio.sleep(60)

    async def analysis_loop(self) -> None:
        await asyncio.sleep(20)
        while True:
            try:
                await self.analysis_tick()
            except Exception as exc:  # noqa: BLE001
                log.exception("Ошибка цикла расчёта базы уязвимостей")
                await J.emit(self._sm, "analysis", f"Ошибка цикла расчёта: {type(exc).__name__}: {exc}"[:500], level="error", details={"trace": traceback.format_exc()[-1500:]})
            await asyncio.sleep(30)

    async def _recover_analysis(self) -> None:
        """После перезапуска «идёт расчёт» без действующей аренды — след прерванного расчёта: статус снимается сразу (с записью в журнал), расчёт начнётся заново."""
        async with self._sm() as db:
            stuck = [(a.source_id, a.started_at) for a in (await db.execute(select(VdbAnalysis).where(VdbAnalysis.status == "running"))).scalars().all()]
        for sid, started in stuck:
            if await JOBS.is_live("vdb_analyze", str(sid)):
                continue
            async with self._sm() as db:
                await _set_state(db, sid, status="error", error="Расчёт прерван (перезапуск или сбой службы); будет начат заново", stage="")
                await db.commit()
            await J.emit(self._sm, "analysis", "Расчёт прерван: служба перезапущена или остановлена во время расчёта; будет начат заново", level="warn", source_id=sid,
                         details={"started_at": started.isoformat() if started else None})
    # ------------------------------------------------------------------------------------------ анализ по каталогу
    async def analysis_tick(self) -> None:
        """Полный пересчёт находок источника KSC, когда изменились данные, от которых зависит сопоставление: загрузка баз, решения администратора, перестроение каталога."""
        async with self._sm() as db:
            states = (await db.execute(select(CatalogState).where(CatalogState.built_at.is_not(None)))).scalars().all()
            has = (await db.execute(select(func.count()).select_from(VdbVuln))).scalar_one()
            todo = []
            if has:
                for st in states:
                    rev = await store.revision(db, st.source_id)
                    done = await db.get(VdbAnalysis, st.source_id)
                    if done is not None and done.status == "ok" and done.rev == store.rev_hash(rev) and done.built_at is not None:
                        continue                                    # результаты построены для этой ревизии данных (в том числе до перезапуска службы)
                    if done is not None and done.status == "ok" and done.built_at is not None and done.rev.startswith(f"{store.MATCH_REV}.") and done.started_at is not None:
                        # данные изменились, но прошлый полный расчёт начат недавно: на большой базе он идёт десятки минут, и следующий сразу за ним не даёт ничего посчитать до конца — ждём интервала
                        st_at = done.started_at if done.started_at.tzinfo else done.started_at.replace(tzinfo=timezone.utc)
                        due_at = st_at + timedelta(hours=MIN_ANALYSIS_H)
                        if datetime.now(timezone.utc) < due_at:
                            if self._once(("throttle", st.source_id), 3600):
                                await J.emit(self._sm, "analysis", f"Данные изменились; следующий автоматический расчёт не раньше {due_at:%d.%m.%Y %H:%M} UTC (не чаще раза в {MIN_ANALYSIS_H:g} ч). Показан последний готовый результат; изменения небольших уязвимостей разбираются сразу, «Пересчитать» — вручную",
                                             source_id=st.source_id, details={"min_hours": MIN_ANALYSIS_H})
                            continue
                    why = "расчёта ещё не было" if done is None or done.built_at is None else "прошлый расчёт завершился ошибкой" if done.status == "error" else \
                          "прошлый расчёт не закончен" if done.status == "running" else "данные баз, каталога или решения изменились"
                    todo.append((st.source_id, rev, why))
        for sid, rev, why in todo:
            if time.monotonic() < self._retry_at.get(sid, 0):
                continue
            try:
                await J.emit(self._sm, "analysis", f"Полный расчёт поставлен: {why}", source_id=sid)
                if await self.analyze_full(sid) is None:          # None — расчёт этого источника ведёт другой исполнитель: состояние запишет он
                    if self._once(("busy", sid), 1800):
                        await J.emit(self._sm, "analysis", "Расчёт не начат: источник уже обрабатывает другой исполнитель (аренда действует)", level="warn", source_id=sid)
                else:
                    await self._drain_pending()
            except MemoryPressure as exc:               # память на пределе: сделанное сохранено порциями, повторим позже
                self._retry_at[sid] = time.monotonic() + 600
                log.warning("Анализ уязвимостей отложен: %s", exc)
                await J.emit(self._sm, "analysis", f"Расчёт отложен на 10 минут: не хватает памяти ({exc})", level="warn", source_id=sid)
            except Exception as exc:                    # ошибка записана в состояние расчёта (видна в интерфейсе); повтор через 5 минут, а не каждую минуту
                self._retry_at[sid] = time.monotonic() + 300
                log.exception("Анализ уязвимостей не выполнен", extra={"source_id": str(sid)})
                await J.emit(self._sm, "analysis", f"Расчёт не выполнен: {type(exc).__name__}: {exc}"[:500], level="error", source_id=sid, details={"trace": traceback.format_exc()[-1500:], "retry_in_s": 300})

    def _once(self, key: tuple, every_s: float) -> bool:
        """Истина, если это сообщение давно не писали: повторяющиеся события не заполняют журнал."""
        now = time.monotonic()
        if now - self._said.get(key, -1e9) < every_s:
            return False
        self._said[key] = now
        return True

    async def _drain_pending(self) -> None:
        """Уязвимости, изменившиеся во время полного расчёта, разбираются частично сразу после него (иначе полный расчёт пришлось бы повторять)."""
        if self._pending:
            keys, self._pending = self._pending, set()
            await J.emit(self._sm, "analysis", f"Разбор изменений, накопленных за время расчёта: {len(keys)} уязвимостей")
            await self.analyze_keys(keys)

    async def analyze_keys(self, keys: set[str]) -> None:
        async with self._sm() as db:
            sids = [s for s in (await db.execute(select(KscSource.id).where(KscSource.is_active.is_(True)))).scalars().all()]
        for sid in sids:
            async with self._sm() as db:
                ok = await db.get(VdbAnalysis, sid)
            if ok is None or ok.status != "ok":            # полного расчёта ещё нет (или он идёт): изменения разберутся сразу после него
                self._pending |= set(keys)
                continue
            # место, затем аренда; один анализ источника за раз (между worker тоже); идёт чужой — пропускаем: полный анализ по ревизии догонит
            async with JOBS.run_heavy("vdb_analyze", str(sid), "анализ изменённых уязвимостей", task=f"анализ уязвимостей {sid}") as lease:
                if lease is None:
                    self._pending |= set(keys)
                    continue
                async with self._sm() as db:
                    await analyze(db, sid, keys=sorted(keys), res=RES, lease=lease)
                    rev = await store.revision(db, sid)
                    await db.execute(update(VdbAnalysis).where(VdbAnalysis.source_id == sid).values(rev=store.rev_hash(rev), built_at=utcnow()))
                    await db.commit()

    async def analyze_full(self, source_id: uuid.UUID) -> int | None:
        # одно место (не все): анализ не задерживает каталог, расчёты по KSC и импорт BI; ожидание места не держит аренду
        async with JOBS.run_heavy("vdb_analyze", str(source_id), "анализ уязвимостей", task=f"анализ уязвимостей {source_id}") as lease:
            if lease is None:
                return None
            try:
                async with self._sm() as db:
                    n = await analyze(db, source_id, keys=None, res=RES, lease=lease)
                    await db.commit()
            except BaseException as exc:
                stopped = isinstance(exc, asyncio.CancelledError)
                msg = "Расчёт прерван остановкой службы (обновление или перезапуск); будет начат заново" if stopped else f"{type(exc).__name__}: {exc}"[:400]
                async with self._sm() as db:
                    await _set_state(db, source_id, status="error", error=msg, stage="", eta_s=None)
                    await db.commit()
                if stopped:
                    await J.emit(self._sm, "analysis", "Расчёт прерван: служба остановлена (обновление или перезапуск); будет начат заново", level="warn", source_id=source_id)
                raise
        return n


async def _set_state(db: AsyncSession, source_id: uuid.UUID, **fields) -> None:
    st = await db.get(VdbAnalysis, source_id)
    if st is None:
        db.add(VdbAnalysis(source_id=source_id, **fields))
    else:
        for k, v in fields.items():
            setattr(st, k, v)


def _dur(sec: float) -> str:
    sec = int(sec)
    return f"{sec // 3600} ч {sec % 3600 // 60} мин" if sec >= 3600 else f"{sec // 60} мин {sec % 60} с" if sec >= 60 else f"{sec} с"


def _utc(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


async def analyze(db: AsyncSession, source_id: uuid.UUID, keys: list[str] | None, *, batch: int = 300, res: Resources | None = None, lease=None) -> int:
    """Сопоставить уязвимости с каталогом источника и обновить находки (без обращения к KSC). keys=None — полный пересчёт по продуктам каталога.
    Данные обрабатываются порциями по `batch` уязвимостей: записи источников читаются как строки без ORM, результат порции сразу сохраняется и фиксируется, память не растёт
    с числом уязвимостей (в памяти — каталог, множество уже обработанных ключей и одна порция). Прерванный пересчёт безопасно повторяется: находки меняются по ключу."""
    prods, maps = await M.load_context(db, source_id)
    if not prods:
        return 0
    full = keys is None
    jsm = async_sessionmaker(db.bind, expire_on_commit=False) if full else None            # журнал пишется отдельными короткими транзакциями

    async def emit(msg: str, **kw) -> None:
        await J.emit(jsm, "analysis", msg, source_id=source_id, **kw)
    if full:
        rev0 = store.rev_hash(await store.revision(db, source_id))            # ревизия данных на начало расчёта: изменились во время расчёта — следующий проход пересчитает
        await _set_state(db, source_id, status="running", started_at=utcnow(), error="", stage="подбор уязвимостей по каталогу", done=0, total=0, progress_at=utcnow())
        await db.commit()
        n_versions = sum(len(p.versions) for p in prods)
        await emit(f"Расчёт начат: продуктов {len(prods)}, версий {n_versions}", details={"products": len(prods), "versions": n_versions, "rev": rev0})
    matcher = M.Matcher(prods, maps)
    classes = await class_map(db, prods)
    t_keys = time.monotonic()
    all_keys = await M.reverse_keys(db, prods, maps) if keys is None else sorted(set(keys))
    if full:
        await _set_state(db, source_id, stage="сопоставление", total=len(all_keys), done=0, progress_at=utcnow())
        await db.commit()
        await emit(f"Подобрано уязвимостей для сопоставления: {len(all_keys)} (поиск {_dur(time.monotonic() - t_keys)})")
    scope = None if keys is None else set(keys)
    matched: set[str] = set()
    now = utcnow()
    total, done, t0 = len(all_keys), 0, time.monotonic()
    next_mark, last_say = max(1, total // 10), time.monotonic()
    hist: list[tuple[float, int]] = [(time.monotonic(), 0)]        # (время, обработано): оценка по скорости последних минут — расчёт замедляется к концу, средняя скорость обманывает в 3–4 раза
    log.info("Анализ уязвимостей начат", extra={"source_id": str(source_id), "keys": total, "products": len(prods)})
    async for part, rows in M.iter_affected(db, all_keys, batch):
        # сопоставление — чистые вычисления Python: в отдельном потоке, иначе событийный цикл стоит и продление аренд, этапы и другие задания ждут
        # версии без активных компьютеров тоже сохраняются (компьютер вне периода активности всё равно показывает свои уязвимости), находки и план — только по активным
        every = [m for m in await asyncio.to_thread(lambda rows=rows: list(M.matches_from(matcher, rows, only_active=False))) if m.status in M.AFFECTED]
        matches = [m for m in every if m.hosts_active]
        done += len(part)
        if lease is not None:
            await lease.stage("анализ уязвимостей", f"обработано {min(done, total)} из {total} уязвимостей, найдено {len(matched)}")
        if full:
            nowm = time.monotonic()
            hist.append((nowm, done))
            while len(hist) > 2 and nowm - hist[0][0] > 420:
                hist.pop(0)
            span = nowm - hist[0][0]
            eta = int((total - done) * span / max(done - hist[0][1], 1)) if span > 0 and done > hist[0][1] else None
            await _set_state(db, source_id, done=min(done, total), progress_at=utcnow(), eta_s=eta)
            if done >= next_mark or nowm - last_say >= 180:             # ход в журнал: каждые 10% или раз в 3 минуты
                next_mark, last_say = done + max(1, total // 10), nowm
                el = nowm - t0
                await emit(f"Ход расчёта: {min(done, total)} из {total} ({100 * min(done, total) // max(total, 1)}%), прошло {_dur(el)}" + (f", осталось ≈{_dur(eta)} (по скорости последних минут)" if eta is not None else ""),
                           details={"done": done, "total": total, "matched": len(matched), "eta_s": eta})
        by: dict[str, list[M.Match]] = {}
        for m in matches:
            by.setdefault(m.vuln_key, []).append(m)
        del rows, matches
        fp_rows: list[VdbFindingProduct] = []
        if by:
            ks = list(by)
            meta = {v.vuln_key: v for v in (await db.execute(select(VdbVuln).where(VdbVuln.vuln_key.in_(ks)))).scalars().all()}
            existing = {f.vuln_key: f for f in (await db.execute(select(VdbFinding).where(VdbFinding.source_id == source_id, VdbFinding.vuln_key.in_(ks)))).scalars().all()}
            for k, ms in by.items():
                v = meta.get(k)
                best = max(ms, key=lambda m: M.STATUS_RANK[m.status]).status
                prod_rows: dict[str, dict] = {}
                for m in ms:
                    p = prod_rows.setdefault(m.product_key, {"key": m.product_key, "name": m.product_name, "versions": [], "installs": 0, "hosts": 0})
                    p["versions"].append(m.version)
                    p["installs"] += m.installs_active
                    p["hosts"] += m.hosts_active
                for pr in prod_rows.values():
                    pm = [m for m in ms if m.product_key == pr["key"]]
                    fp_rows.append(VdbFindingProduct(source_id=source_id, vuln_key=k, product_key=pr["key"], name=pr["name"][:300], category=classes.get(pr["key"], ("unclassified", ""))[0],
                                                     status=max(pm, key=lambda m: M.STATUS_RANK[m.status]).status, sev_rank=v.sev_rank if v else 0, exploited=bool(v.exploited) if v else False,
                                                     installs=pr["installs"], hosts=pr["hosts"], versions=sorted({m.version for m in pm if m.version})[:40]))
                fields = dict(status=best, sev_rank=v.sev_rank if v else 0, exploited=bool(v.exploited) if v else False, products=sorted(prod_rows.values(), key=lambda p: -p["installs"])[:30],
                              installs=sum(p["installs"] for p in prod_rows.values()), hosts_max=sum(p["hosts"] for p in prod_rows.values()), updated_at=now)
                f = existing.get(k)
                if f is None:
                    # первичный просмотр базы: давние уязвимости (изменены раньше 90 суток назад) — исходное состояние, а не новость для специалиста
                    old = bool(v and v.modified and _utc(v.modified) < now - timedelta(days=BACKLOG_DAYS))
                    db.add(VdbFinding(source_id=source_id, vuln_key=k, first_seen_at=now, seen_at=now if old else None, seen_by="исходное состояние базы" if old else None, **fields))
                else:
                    for a, b in fields.items():
                        setattr(f, a, b)
            matched |= set(by)
            await db.execute(delete(VdbFindingProduct).where(VdbFindingProduct.source_id == source_id, VdbFindingProduct.vuln_key.in_(ks)))
            db.add_all(fp_rows)
        await db.execute(delete(VdbVersionHit).where(VdbVersionHit.source_id == source_id, VdbVersionHit.vuln_key.in_(part)))
        if every:
            await db.execute(insert(VdbVersionHit), [dict(source_id=source_id, product_key=m.product_key, version=m.version[:200], vuln_key=m.vuln_key, status=m.status, basis=m.basis[:400]) for m in every])
        await db.commit()                       # порция сохранена: транзакция не остаётся открытой на время вычислений следующей
        db.expunge_all()
        if res is not None:
            await res.breathe("анализ уязвимостей")
    existing_keys = (await db.execute(select(VdbFinding.vuln_key).where(VdbFinding.source_id == source_id))).scalars().all()
    stale = [k for k in existing_keys if k not in matched and (scope is None or k in scope)]
    for i in range(0, len(stale), 400):
        await db.execute(delete(VdbFinding).where(VdbFinding.source_id == source_id, VdbFinding.vuln_key.in_(stale[i:i + 400])))
        await db.execute(delete(VdbFindingProduct).where(VdbFindingProduct.source_id == source_id, VdbFindingProduct.vuln_key.in_(stale[i:i + 400])))
    if scope is None:                         # полный расчёт: результаты уязвимостей, которых больше нет среди кандидатов каталога
        seen = set(all_keys)
        gone = [k for k in (await db.execute(select(VdbVersionHit.vuln_key).where(VdbVersionHit.source_id == source_id).distinct())).scalars().all() if k not in seen]
        for i in range(0, len(gone), 400):
            await db.execute(delete(VdbVersionHit).where(VdbVersionHit.source_id == source_id, VdbVersionHit.vuln_key.in_(gone[i:i + 400])))
    await db.commit()
    if full:
        hits = (await db.execute(select(func.count()).select_from(VdbVersionHit).where(VdbVersionHit.source_id == source_id))).scalar_one()
        await _set_state(db, source_id, status="ok", error="", rev=rev0, built_at=utcnow(), hits=int(hits), duration_ms=int((time.monotonic() - t0) * 1000), stage="", done=total, total=total, progress_at=utcnow(), eta_s=None)
        await db.commit()
        await emit(f"Расчёт завершён: уязвимостей {total}, с совпадениями {len(matched)}, строк результата {int(hits)}, {_dur(time.monotonic() - t0)}",
                   details={"keys": total, "matched": len(matched), "hits": int(hits), "seconds": round(time.monotonic() - t0)})
    log.info("Анализ уязвимостей завершён", extra={"source_id": str(source_id), "keys": total, "matched": len(matched), "duration_s": round(time.monotonic() - t0)})
    return len(matched)
