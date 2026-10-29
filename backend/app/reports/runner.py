"""Фоновый воркер отчётов: берёт задания из таблицы report_jobs, строит отчёт в рабочем потоке, пишет файлы в DATA_DIR/reports/<id>/.
Отмена — флаг cancel_requested, проверяется между пачками запросов. Одновременно не больше report_concurrency тяжёлых заданий."""
from __future__ import annotations

import asyncio
import logging
import shutil
import socket
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..config import Settings
from ..ksc.driver import ConnParams, KscError, Session, SourceClient
from ..ksc.grouping import Rule
from ..models import GroupingRule, KscSource, ReportJob, utcnow
from ..services import catalog as catalog_svc
from ..services.audit import Journal
from ..services.resources import RES, MemoryPressure
from ..services.settings import ReportsSettings, SettingsService
from . import quick_pdf, audit, builder, export, quick, quick_export

log = logging.getLogger("app.reports")
WORKER = f"{socket.gethostname()}-{uuid.uuid4().hex[:6]}"


def conn_params(src: KscSource, password: str) -> ConnParams:
    return ConnParams(host=src.host, port=src.port, database=src.database, username=src.username, password=password, tls_mode=src.tls_mode,
                      trust_server_cert=src.trust_server_cert, connect_timeout_s=src.connect_timeout_s, query_timeout_s=src.query_timeout_s)


def job_dir(settings: Settings, job_id) -> Path:
    return Path(settings.reports_dir) / str(job_id)


class Runner:
    def __init__(self, session_maker: async_sessionmaker[AsyncSession], settings: Settings, settings_svc: SettingsService, journal: Journal):
        self._sm, self._cfg, self._svc, self._journal = session_maker, settings, settings_svc, journal
        self._sem = asyncio.Semaphore(settings.report_concurrency)
        self._tasks: set[asyncio.Task] = set()
        self.catalog = None          # services.catalog.CatalogScheduler: сборка каталога источника, если его ещё нет (задаётся в worker)

    async def _claim(self) -> ReportJob | None:
        async with self._sm() as db:
            job = (await db.execute(select(ReportJob).where(ReportJob.status == "queued").order_by(ReportJob.created_at).limit(1))).scalar_one_or_none()
            if job is None:
                return None
            res = await db.execute(update(ReportJob).where(ReportJob.id == job.id, ReportJob.status == "queued").values(status="running", started_at=utcnow(), worker=WORKER, progress="запуск"))
            await db.commit()
            if res.rowcount != 1:
                return None
            await db.refresh(job)
            return job

    async def _set(self, job_id, **values) -> None:
        async with self._sm() as db:
            await db.execute(update(ReportJob).where(ReportJob.id == job_id).values(**values))
            await db.commit()

    async def _cancelled(self, job_id) -> bool:
        async with self._sm() as db:
            return bool((await db.execute(select(ReportJob.cancel_requested).where(ReportJob.id == job_id))).scalar_one_or_none())

    TRANSIENT = ("Не удалось подключиться", "тайм-аут", "Время ожидания", "недоступен", "Connection", "timed out")      # временные сбои источника: повтор имеет смысл
    RETRY_DELAYS = (30, 120)

    async def run_job(self, job: ReportJob) -> None:
        from ..services.jobs import JOBS  # noqa: PLC0415

        lease = await JOBS.acquire("report", str(job.id), "запуск")
        if lease is None:                                       # задание уже ведёт другой исполнитель
            return
        status, error = "success", None
        try:
            await self._run_job(job)
            async with self._sm() as db:
                cur = await db.get(ReportJob, job.id)
            if cur is not None and cur.status == "failed":
                status, error = "error", cur.error
        except asyncio.CancelledError:
            status, error = "interrupted", "выполнение отменено"
            raise
        except BaseException as exc:
            status, error = "error", f"{type(exc).__name__}: {exc}"
            raise
        finally:
            await lease.finish(status, error)

    async def _run_job(self, job: ReportJob) -> None:
        async with self._sem:
            async with RES.heavy(f"отчёт {job.kind}", 1, interactive=True):          # отчёты идут под общим ограничителем: при занятых слотах или нехватке памяти ждут, а не копят память
                for attempt in range(len(self.RETRY_DELAYS) + 1):
                    await self._execute(job)
                    if attempt == len(self.RETRY_DELAYS):
                        break
                    async with self._sm() as db:
                        cur = await db.get(ReportJob, job.id)
                    if cur is None or cur.status != "failed" or not any(t in (cur.error or "") for t in self.TRANSIENT):
                        break
                    delay = self.RETRY_DELAYS[attempt]
                    await self._set(job.id, status="running", error=None, finished_at=None, progress=f"Источник недоступен: {cur.error[:120]}. Повтор через {delay} с (попытка {attempt + 2} из {len(self.RETRY_DELAYS) + 1})")
                    await asyncio.sleep(delay)

    async def _execute(self, job: ReportJob) -> None:
        if job.kind == "version_audit":
            await self._execute_audit(job)
            return
        if job.kind == "quick_zone":
            await self._execute_zone(job)
            return
        if job.kind in quick.QUICK_KINDS:
            await self._execute_quick(job)
            return
        started = utcnow()
        async with self._sm() as db:
            src = await db.get(KscSource, job.source_id)
            rcfg: ReportsSettings = await self._svc.get(db, "reports")  # type: ignore[assignment]
            rule_row = (await db.execute(select(GroupingRule).where(GroupingRule.key == job.params.get("rule")))).scalar_one_or_none() if job.params.get("rule") else None
            org = (await self._svc.get(db, "organization")).model_dump()
        if src is None:
            await self._set(job.id, status="failed", finished_at=utcnow(), error="Источник удалён")
            return
        password = self._svc.decrypt(src.password_enc, f"source.{src.id}")
        rule = Rule(rule_row.key, rule_row.name, rule_row.name_like, rule_row.name_regex, rule_row.branch_regex, rule_row.branch_parts, rule_row.exclude_regex) if rule_row else None
        loop = asyncio.get_running_loop()
        flag = {"cancel": False}

        async def watch():
            while True:
                await asyncio.sleep(2)
                if await self._cancelled(job.id):
                    flag["cancel"] = True
                    return

        watcher = asyncio.create_task(watch())

        def progress(text: str) -> None:
            loop.call_soon_threadsafe(lambda: asyncio.ensure_future(self._set(job.id, progress=text[:300])))

        def work():
            with Session(conn_params(src, password)) as conn:
                if job.kind == "software_hosts":
                    return builder.build_software(conn, job.params, rule, max_rows=rcfg.max_rows, exclude_slaves=rcfg.exclude_slave_servers, progress=progress, cancelled=lambda: flag["cancel"])
                if job.kind == "hosts":
                    return builder.build_hosts(conn, job.params, max_rows=rcfg.max_rows, exclude_slaves=rcfg.exclude_slave_servers, progress=progress, cancelled=lambda: flag["cancel"])
                raise KscError("kind", f"Неизвестный вид отчёта: {job.kind}")

        try:
            rows, summary = await asyncio.to_thread(work)
            d = job_dir(self._cfg, job.id)
            d.mkdir(parents=True, exist_ok=True)
            meta = {"Отчёт": job.title, "Вид": job.kind, "Источник KSC": job.source_name, "Данные получены (UTC)": summary.get("fetched_at"), "Сформировал": job.created_by,
                    "Параметры": job.params, "Строк": summary.get("rows"), "Уникальных компьютеров": summary.get("hosts"),
                    "Исключено компьютеров без связи": summary.get("excluded_inactive_hosts"), "Порог активности, сут": summary.get("active_days"),
                    "_org": org, "Время": "все даты в UTC", "Версии": "Версия — версия пакета/программы из инвентаризации KSC; сравниваемая версия — без эпохи и ревизии; ветка — major.minor. "
                                                       "Версия пакета не обязательно равна версии работающей программы."}
            await asyncio.to_thread(self._write, d, job.kind, rows, summary, meta)
            await self._set(job.id, status="done", finished_at=utcnow(), rows=len(rows), summary=summary, progress="готово",
                            data_fetched_at=datetime.fromisoformat(summary["fetched_at"]).replace(tzinfo=timezone.utc))
            await self._journal.emit("report", "report_done", user=job.created_by, source=job.source_name, message=f"{job.title}: строк {len(rows)}",
                                     duration_ms=int((utcnow() - started).total_seconds() * 1000), data={"job_id": str(job.id), "kind": job.kind})
        except builder.Cancelled:
            await self._set(job.id, status="cancelled", finished_at=utcnow(), progress="отменён")
            await self._journal.emit("report", "report_cancelled", level="warn", user=job.created_by, source=job.source_name, message=job.title, data={"job_id": str(job.id)})
        except KscError as exc:
            await self._set(job.id, status="failed", finished_at=utcnow(), error=exc.message, progress="ошибка")
            await self._journal.emit("report", "report_failed", level="error", user=job.created_by, source=job.source_name, message=f"{job.title}: {exc.message}", data={"job_id": str(job.id), "code": exc.code})
        except Exception as exc:  # noqa: BLE001
            log.exception("Сбой формирования отчёта", extra={"job_id": str(job.id)})
            await self._set(job.id, status="failed", finished_at=utcnow(), error=f"Внутренняя ошибка: {type(exc).__name__}", progress="ошибка")
            await self._journal.emit("report", "report_failed", level="error", user=job.created_by, source=job.source_name, message=f"{job.title}: {type(exc).__name__}", data={"job_id": str(job.id)})
        finally:
            watcher.cancel()

    async def _execute_quick(self, job: ReportJob) -> None:
        """Быстрый контекстный отчёт (уязвимости, компьютеры, защита, события): тот же построитель, что у предпросмотра; выгрузки XLSX, HTML, CSV."""
        started = utcnow()
        async with self._sm() as db:
            src = await db.get(KscSource, job.source_id) if job.source_id else None
            rcfg: ReportsSettings = await self._svc.get(db, "reports")  # type: ignore[assignment]
            general = await self._svc.get(db, "general")
            org = (await self._svc.get(db, "organization")).model_dump()
            hw = await self._svc.get(db, "hardware")
        if src is None and job.kind not in quick.NO_KSC:                    # результаты Pentest, BI и администрирования не принадлежат источнику KSC
            await self._set(job.id, status="failed", finished_at=utcnow(), error="Источник удалён")
            return
        if src is None:
            src = KscSource(id=uuid.uuid4(), name={"quick_bi": "BI", "quick_admin": "KAV Checker"}.get(job.kind, "Pentest"))                  # только имя для шапки отчёта; в базу не записывается
            client = None
        else:
            client = SourceClient(conn_params(src, self._svc.decrypt(src.password_enc, f"source.{src.id}")), concurrency=self._cfg.ksc_concurrency, name=src.name)
        flag = {"cancel": False}
        loop = asyncio.get_running_loop()

        async def watch():
            while True:
                await asyncio.sleep(2)
                if await self._cancelled(job.id):
                    flag["cancel"] = True
                    return

        watcher = asyncio.create_task(watch())
        ctx = quick.Ctx(source_name=src.name, activity_days=int(general.activity_days), exclude_slaves=rcfg.exclude_slave_servers, max_rows=rcfg.max_rows,
                        progress=lambda t: loop.call_soon_threadsafe(lambda: asyncio.ensure_future(self._set(job.id, progress=t[:300]))), cancelled=lambda: flag["cancel"], sm=self._sm, source_id=src.id, org=org, hw_cfg=hw, settings=self._cfg)
        if job.kind in ("quick_eol", "quick_devices", "quick_overview"):
            ctx.source_ids = [uuid.UUID(str(x)) for x in (job.source_ids or [str(job.source_id)])]
        if job.kind == "quick_overview":
            async def records_for(s: KscSource):                                    # у каждого источника свой клиент и своё чтение; ошибка источника попадает в отчёт отдельной строкой
                from ..ksc import hosts as H  # noqa: PLC0415
                from ..ksc import protection as P  # noqa: PLC0415

                c = SourceClient(conn_params(s, self._svc.decrypt(s.password_enc, f"source.{s.id}")), concurrency=self._cfg.ksc_concurrency, name=s.name)
                recs = await P.load(c, exclude_slaves=rcfg.exclude_slave_servers, groups=await H.groups_map(c), hw_cfg=None)
                return recs, datetime.now(timezone.utc)

            ctx.records_for = records_for
        try:
            zone = (job.params or {}).get("zone") or ""
            if zone and job.kind not in ("quick_eol", "quick_devices", "quick_overview"):
                from ..services.sources import SourceRegistry  # noqa: PLC0415
                from ..zones.reporter import ZoneData  # noqa: PLC0415

                if getattr(self, "_zones", None) is None:
                    self._zones = ZoneData(self._sm, self._cfg, self._svc, SourceRegistry(self._cfg, self._svc))
                async with self._sm() as db:
                    ctx.zone_hosts, ctx.zone_name = await self._zones.host_ids(db, src, zone), await self._zones.zone_name(db, zone)
            doc = await quick.build(job.kind, client, {k: v for k, v in (job.params or {}).items() if not k.startswith("_")}, ctx)
            if job.title:
                doc["title"] = job.title if job.title != quick.KIND_TITLE.get(job.kind) else doc["title"]
            d = job_dir(self._cfg, job.id)
            d.mkdir(parents=True, exist_ok=True)
            main = doc["tables"][0]["rows"]
            await asyncio.to_thread(self._write_quick, d, doc)
            summary = {**quick.brief(doc), "rows": len(main), "hosts": next((m["value"] for m in doc["metrics"] if m["key"] == "hosts"), None),
                       "fetched_at": ctx.now.isoformat(timespec="seconds")}
            await self._set(job.id, status="done", finished_at=utcnow(), rows=len(main), summary=summary, progress="готово", data_fetched_at=ctx.now)
            await self._journal.emit("report", "report_done", user=job.created_by, source=job.source_name[:120], message=f"{job.title}: строк {len(main)}",
                                     duration_ms=int((utcnow() - started).total_seconds() * 1000), data={"job_id": str(job.id), "kind": job.kind})
        except RuntimeError as exc:
            if str(exc) != "cancelled":
                raise
            await self._set(job.id, status="cancelled", finished_at=utcnow(), progress="отменён")
        except KscError as exc:
            await self._set(job.id, status="failed", finished_at=utcnow(), error=exc.message, progress="ошибка")
            await self._journal.emit("report", "report_failed", level="error", user=job.created_by, source=job.source_name[:120], message=f"{job.title}: {exc.message}",
                                     data={"job_id": str(job.id), "code": exc.code})
        except Exception as exc:  # noqa: BLE001
            log.exception("Сбой формирования отчёта", extra={"job_id": str(job.id)})
            await self._set(job.id, status="failed", finished_at=utcnow(), error=f"Внутренняя ошибка: {type(exc).__name__}", progress="ошибка")
        finally:
            watcher.cancel()

    async def _execute_zone(self, job: ReportJob) -> None:
        """Отчёт по зонам ответственности: один документ по всем выбранным источникам, те же выгрузки XLSX, HTML, CSV."""
        from ..services.sources import SourceRegistry  # noqa: PLC0415
        from ..zones.reporter import ZoneData  # noqa: PLC0415

        started = utcnow()
        if getattr(self, "_zones", None) is None:
            self._zones = ZoneData(self._sm, self._cfg, self._svc, SourceRegistry(self._cfg, self._svc))
        loop = asyncio.get_running_loop()
        flag = {"cancel": False}

        async def watch():
            while True:
                await asyncio.sleep(2)
                if await self._cancelled(job.id):
                    flag["cancel"] = True
                    return

        watcher = asyncio.create_task(watch())
        params = {k: v for k, v in (job.params or {}).items() if not k.startswith("_") and k != "active_days"}
        try:
            async with self._sm() as db:
                doc = await self._zones.zone_doc(db, zone_ids=params["zone_ids"], params=params, source_ids=job.source_ids or None, refresh=bool(params.get("refresh_data")),
                                                 progress=lambda t: loop.call_soon_threadsafe(lambda: asyncio.ensure_future(self._set(job.id, progress=t[:300]))), cancelled=lambda: flag["cancel"])
            if job.title and job.title != quick.KIND_TITLE.get(job.kind):
                doc["title"] = job.title
            d = job_dir(self._cfg, job.id)
            d.mkdir(parents=True, exist_ok=True)
            main = doc["tables"][0]["rows"]
            await asyncio.to_thread(self._write_quick, d, doc)
            summary = {**quick.brief(doc), "rows": len(main), "hosts": doc["stats"]["total"], "fetched_at": doc["generated_at"]}
            await self._set(job.id, status="done", finished_at=utcnow(), rows=len(main), summary=summary, progress="готово", data_fetched_at=datetime.fromisoformat(doc["generated_at"]))
            await self._journal.emit("report", "report_done", user=job.created_by, source=job.source_name[:120], message=f"{job.title}: проблемных компьютеров {len(main)}",
                                     duration_ms=int((utcnow() - started).total_seconds() * 1000), data={"job_id": str(job.id), "kind": job.kind})
        except RuntimeError as exc:
            if str(exc) != "cancelled":
                raise
            await self._set(job.id, status="cancelled", finished_at=utcnow(), progress="отменён")
        except KscError as exc:
            await self._set(job.id, status="failed", finished_at=utcnow(), error=exc.message, progress="ошибка")
            await self._journal.emit("report", "report_failed", level="error", user=job.created_by, source=job.source_name[:120], message=f"{job.title}: {exc.message}", data={"job_id": str(job.id), "code": exc.code})
        except MemoryPressure as exc:
            await self._set(job.id, status="failed", finished_at=utcnow(), progress="ошибка",
                            error="Не хватило памяти для отчёта: слишком много данных в выбранных зонах. Сформируйте отчёт по меньшим зонам или выбранным компьютерам, в управленческом варианте либо увеличьте память службы (WORKER_MEM_LIMIT). " + str(exc)[-120:])
        except Exception as exc:  # noqa: BLE001
            log.exception("Сбой формирования отчёта по зоне", extra={"job_id": str(job.id)})
            await self._set(job.id, status="failed", finished_at=utcnow(), error=f"Внутренняя ошибка: {type(exc).__name__}", progress="ошибка")
        finally:
            watcher.cancel()

    @staticmethod
    def _write_quick(d: Path, doc: dict) -> None:
        export.write_jsonl(d / "rows.jsonl", doc["tables"][0]["rows"])
        quick_export.write_csv_main(d / "report.csv", doc)
        quick_export.write_xlsx(d / "report.xlsx", doc)
        quick_export.write_html(d / "report.html", doc)
        try:
            quick_pdf.write_pdf(d / "report.pdf", doc)
        except Exception:  # noqa: BLE001 — PDF вспомогательный: сбой его построения не должен лишать отчёт XLSX, CSV и HTML
            log.warning("PDF отчёта не построен", exc_info=True)

    async def _execute_audit(self, job: ReportJob) -> None:
        """Проверка версий по одному или нескольким источникам: источники обрабатываются по очереди, каждый на своём соединении."""
        started = utcnow()
        params = job.params or {}
        items = params.get("items") or []
        ids = [uuid.UUID(str(x)) for x in (job.source_ids or ([str(job.source_id)] if job.source_id else []))]
        async with self._sm() as db:
            rcfg: ReportsSettings = await self._svc.get(db, "reports")  # type: ignore[assignment]
            rules = {r.key: Rule(r.key, r.name, r.name_like, r.name_regex, r.branch_regex, r.branch_parts, r.exclude_regex)
                     for r in (await db.execute(select(GroupingRule).where(GroupingRule.enabled.is_(True)))).scalars().all()}
            srcs = [s for s in [await db.get(KscSource, i) for i in ids] if s is not None]
            org = (await self._svc.get(db, "organization")).model_dump()
        if not srcs:
            await self._set(job.id, status="failed", finished_at=utcnow(), error="Источники отчёта удалены")
            return
        plan = []
        notes: list[str] = []
        for src in srcs:
            async with self._sm() as db:
                if not await catalog_svc.catalog_ready(db, src.id) and any((it.get("kind") or "product") == "product" for it in items):
                    if self.catalog is None:
                        notes.append(f"{src.name}: каталог программ ещё не построен")
                    else:
                        await self._set(job.id, progress=f"{src.name}: построение каталога программ")
                        await self.catalog.build(src.id, "нужен для отчёта")        # если каталог уже строит другой исполнитель, build вернётся сразу — ждём его завершения
                        for _ in range(180):
                            async with self._sm() as db3:
                                if await catalog_svc.catalog_ready(db3, src.id):
                                    break
                            from ..services.jobs import JOBS  # noqa: PLC0415

                            if not await JOBS.is_live("catalog", str(src.id)):
                                break
                            await asyncio.sleep(5)
                async with self._sm() as db2:
                    resolved, missing = await catalog_svc.resolve_items(db2, src.id, items)
            try:
                audit.check_conditions(items, resolved)      # условие должно дойти до выполнения без изменений
            except KscError as exc:
                await self._set(job.id, status="failed", finished_at=utcnow(), error=exc.message, progress="ошибка")
                return
            if missing:
                notes.append(f"{src.name}: нет в каталоге — {', '.join(missing)}")
            zset = None
            if params.get("zone"):
                from ..services.sources import SourceRegistry  # noqa: PLC0415
                from ..zones.reporter import ZoneData  # noqa: PLC0415

                if getattr(self, "_zones", None) is None:
                    self._zones = ZoneData(self._sm, self._cfg, self._svc, SourceRegistry(self._cfg, self._svc))
                async with self._sm() as db3:
                    zset = await self._zones.host_ids(db3, src, params["zone"])
            plan.append((src.name, conn_params(src, self._svc.decrypt(src.password_enc, f"source.{src.id}")), resolved, zset))
        loop = asyncio.get_running_loop()
        flag = {"cancel": False}

        async def watch():
            while True:
                await asyncio.sleep(2)
                if await self._cancelled(job.id):
                    flag["cancel"] = True
                    return

        watcher = asyncio.create_task(watch())

        def progress(text: str) -> None:
            loop.call_soon_threadsafe(lambda: asyncio.ensure_future(self._set(job.id, progress=text[:300])))

        def work():
            all_rows, per_source = [], []
            for name, cp, resolved, zset in plan:
                progress(f"{name}: подключение")
                with Session(cp) as conn:
                    rows, summ = audit.build_source(conn, source_name=name, items=resolved, rules=rules, active_days=params.get("active_days"),
                                                    include_inactive=bool(params.get("include_inactive")), group_contains=params.get("group_contains") or "",
                                                    exclude_slaves=rcfg.exclude_slave_servers, max_rows=rcfg.max_rows - len(all_rows), progress=progress,
                                                    cancelled=lambda: flag["cancel"], online_only=bool(params.get("online_only")), host_filter=zset)
                all_rows += rows
                per_source.append(summ)
            return all_rows, audit.merge_summaries(per_source, items, active_days=params.get("active_days"), include_inactive=bool(params.get("include_inactive")), rows=all_rows, online_only=bool(params.get("online_only")))

        expect = params.get("_expect")
        try:
            rows, summary = await asyncio.to_thread(work)
            done = [p["condition"] for p in summary["programs"]]
            if expect is not None and done != expect:
                raise KscError("params", f"Расхождение условий проверки: задано «{'; '.join(expect)}», выполнено «{'; '.join(done)}». Отчёт не сформирован.")
            summary["notes"] = notes
            d = job_dir(self._cfg, job.id)
            d.mkdir(parents=True, exist_ok=True)
            meta = {"Отчёт": job.title, "Вид": "Проверка версий программ", "Источники KSC": ", ".join(s.name for s in srcs), "Данные получены (UTC)": summary.get("fetched_at"),
                    "_org": org, "Сформировал": job.created_by, "Программы и условия": "; ".join(f"{p['program']}: {p['condition']}" + (f" → {p['target_version']}" if p["target_version"] else "")
                                                                        for p in summary["programs"]),
                    "Строк": summary.get("rows"), "Компьютеров (по источникам)": summary.get("hosts"),
                    "Скрыто давно не подключавшихся компьютеров": summary.get("hidden_inactive_hosts"),
                    "Показаны компьютеры, активные за, сут": "все" if summary.get("include_inactive") else summary.get("active_days"),
                    "Примечания": "; ".join(notes) or "—", "Время": "все даты в UTC",
                    "Смысл результата": "Соответствие заданному условию версии, а не подтверждённая уязвимость. Подтверждённые KSC уязвимости — раздел «Уязвимости».",
                    "Сравнение версий": "Пакеты Linux — по версии без эпохи и ревизии (граница с ревизией сравнивается с полной версией), программы Windows — по числовым частям "
                                        "(130 = 130.0.0.0); нестандартная нумерация Java и Python для Windows приводится к обычной."}
            await asyncio.to_thread(self._write, d, job.kind, rows, summary, meta)
            doc = quick.doc_from_audit(rows, summary, {"title": job.title, "source": job.source_name, "org": org})
            await asyncio.to_thread(self._write_audit_html, d, doc)
            await self._set(job.id, status="done", finished_at=utcnow(), rows=len(rows), summary=summary, progress="готово",
                            data_fetched_at=datetime.fromisoformat(summary["fetched_at"]).replace(tzinfo=timezone.utc) if summary.get("fetched_at") else utcnow())
            await self._journal.emit("report", "report_done", user=job.created_by, source=job.source_name[:120], message=f"{job.title}: строк {len(rows)}",
                                     duration_ms=int((utcnow() - started).total_seconds() * 1000), data={"job_id": str(job.id), "kind": job.kind})
        except builder.Cancelled:
            await self._set(job.id, status="cancelled", finished_at=utcnow(), progress="отменён")
        except KscError as exc:
            await self._set(job.id, status="failed", finished_at=utcnow(), error=exc.message, progress="ошибка")
            await self._journal.emit("report", "report_failed", level="error", user=job.created_by, source=job.source_name[:120], message=f"{job.title}: {exc.message}",
                                     data={"job_id": str(job.id), "code": exc.code})
        except Exception as exc:  # noqa: BLE001
            log.exception("Сбой формирования отчёта", extra={"job_id": str(job.id)})
            await self._set(job.id, status="failed", finished_at=utcnow(), error=f"Внутренняя ошибка: {type(exc).__name__}", progress="ошибка")
        finally:
            watcher.cancel()

    @staticmethod
    def _write_audit_html(d: Path, doc: dict) -> None:
        doc.update(kind="version_audit", generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        quick_export.write_html(d / "report.html", doc)

    @staticmethod
    def _write(d: Path, kind: str, rows: list[dict], summary: dict, meta: dict) -> None:
        export.write_jsonl(d / "rows.jsonl", rows)
        cols = audit.AUDIT_COLUMNS if kind == "version_audit" else builder.SOFTWARE_COLUMNS if kind == "software_hosts" else builder.HOST_COLUMNS
        export.write_csv(d / "report.csv", rows, cols)
        export.write_xlsx(d / "report.xlsx", kind, rows, summary, meta)

    async def recover_orphans(self) -> int:
        """Задания «в работе» без действующей аренды (исполнитель завершился или завис) возвращаются в очередь сразу, а не через часы; при повторяющихся прерываниях — ошибка.
        Задание, которое ведёт другой worker, не трогается."""
        from ..services.jobs import JOBS  # noqa: PLC0415

        n = 0
        async with self._sm() as db:
            for j in (await db.execute(select(ReportJob).where(ReportJob.status == "running"))).scalars().all():
                if await JOBS.is_live("report", str(j.id)):
                    continue
                if await JOBS.failures_since("report", str(j.id), utcnow() - timedelta(days=1)) >= 3:
                    j.status, j.finished_at, j.error, j.progress = "failed", utcnow(), "Формирование прерывалось несколько раз подряд (перезапуск или нехватка памяти)", "ошибка"
                else:
                    j.status, j.started_at, j.progress = "queued", None, "возвращено в очередь после прерывания"
                n += 1
            await db.commit()
        return n

    async def cleanup(self, keep_days: int) -> int:
        """Удаление отчётов старше срока хранения (файлы и записи)."""
        n = 0
        async with self._sm() as db:
            old = (await db.execute(select(ReportJob).where(ReportJob.created_at < utcnow() - timedelta(days=keep_days)))).scalars().all()
            for j in old:
                shutil.rmtree(job_dir(self._cfg, j.id), ignore_errors=True)
                await db.delete(j)
                n += 1
            await db.commit()
        return n

    async def loop(self) -> None:
        await self.recover_orphans()
        last_cleanup = utcnow() - timedelta(hours=2)
        last_orphan = utcnow()
        while True:
            try:
                job = await self._claim() if len(self._tasks) < self._cfg.report_concurrency else None        # лишние задания ждут в очереди (видны как «в очереди»), а не занимают «в работе»
                if job is not None:
                    t = asyncio.create_task(self.run_job(job))
                    self._tasks.add(t)
                    t.add_done_callback(self._tasks.discard)
                    continue
                if utcnow() - last_orphan > timedelta(seconds=60):
                    last_orphan = utcnow()
                    await self.recover_orphans()
                if utcnow() - last_cleanup > timedelta(hours=1):
                    async with self._sm() as db:
                        keep = (await self._svc.get(db, "general")).report_keep_days  # type: ignore[attr-defined]
                    await self.cleanup(keep)
                    last_cleanup = utcnow()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка цикла воркера отчётов")
            await asyncio.sleep(2)
