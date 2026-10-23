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
from ..ksc.driver import ConnParams, KscError, Session
from ..ksc.grouping import Rule
from ..models import GroupingRule, KscSource, ReportJob, utcnow
from ..services.audit import Journal
from ..services.settings import ReportsSettings, SettingsService
from . import builder, export

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

    async def run_job(self, job: ReportJob) -> None:
        async with self._sem:
            await self._execute(job)

    async def _execute(self, job: ReportJob) -> None:
        started = utcnow()
        async with self._sm() as db:
            src = await db.get(KscSource, job.source_id)
            rcfg: ReportsSettings = await self._svc.get(db, "reports")  # type: ignore[assignment]
            rule_row = (await db.execute(select(GroupingRule).where(GroupingRule.key == job.params.get("rule")))).scalar_one_or_none() if job.params.get("rule") else None
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
                    "Время": "все даты в UTC", "Версии": "Версия — версия пакета/программы из инвентаризации KSC; сравниваемая версия — без эпохи и ревизии; ветка — major.minor. "
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

    @staticmethod
    def _write(d: Path, kind: str, rows: list[dict], summary: dict, meta: dict) -> None:
        export.write_jsonl(d / "rows.jsonl", rows)
        export.write_csv(d / "report.csv", rows, builder.SOFTWARE_COLUMNS if kind == "software_hosts" else builder.HOST_COLUMNS)
        export.write_xlsx(d / "report.xlsx", kind, rows, summary, meta)

    async def recover_orphans(self) -> int:
        """Задания, оставшиеся «в работе» после перезапуска воркера, закрываются как прерванные."""
        async with self._sm() as db:
            res = await db.execute(update(ReportJob).where(ReportJob.status == "running", ReportJob.started_at < utcnow() - timedelta(hours=3))
                                   .values(status="failed", finished_at=utcnow(), error="Формирование прервано перезапуском сервиса"))
            await db.commit()
            return res.rowcount

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
        while True:
            try:
                job = await self._claim()
                if job is not None:
                    t = asyncio.create_task(self.run_job(job))
                    self._tasks.add(t)
                    t.add_done_callback(self._tasks.discard)
                    continue
                if utcnow() - last_cleanup > timedelta(hours=1):
                    async with self._sm() as db:
                        keep = (await self._svc.get(db, "general")).report_keep_days  # type: ignore[attr-defined]
                    await self.cleanup(keep)
                    last_cleanup = utcnow()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка цикла воркера отчётов")
            await asyncio.sleep(2)
