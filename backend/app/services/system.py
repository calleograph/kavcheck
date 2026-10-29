"""Состояние системы: пульс служб, предупреждения и ошибки приложения в журнале событий, ресурсы сервера, размеры данных.

* Предупреждения и ошибки логгеров app.* (в том числе фоновых задач) копируются в журнал событий (event_log) с маскированием секретов —
  их видно в «Администрирование → Журнал событий» с фильтром по компоненту.
* Worker раз в 30 секунд обновляет пульс (service_heartbeats): версия, время запуска, выполняемые задачи.
* Ресурсы процессора, памяти и диска читаются из /proc и файловой системы данных; размеры образов Docker и резервных копий сообщает
  помощник обновлений на хосте (DATA_DIR/updater/system.json)."""
from __future__ import annotations

import asyncio
import collections
import logging
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..logging_setup import scrub
from ..models import EventLog, ServiceHeartbeat, utcnow

COMPONENTS = {"app.ksc": "ksc", "app.reports": "report", "app.catalog": "catalog", "app.auth": "auth", "app.ldap": "auth", "app.worker": "worker", "app.updates": "system"}


def component_of(logger: str) -> str:
    for prefix, comp in COMPONENTS.items():
        if logger.startswith(prefix):
            return comp
    return "system"


class JournalHandler(logging.Handler):
    """Буфер предупреждений и ошибок: запись в базу выполняет flush_loop (из логгера в базу напрямую писать нельзя — он синхронный)."""

    def __init__(self, service: str):
        super().__init__(level=logging.WARNING)
        self.service = service
        self.buf: collections.deque = collections.deque(maxlen=500)

    def emit(self, record: logging.LogRecord) -> None:
        if not record.name.startswith("app.") or record.name in ("app.audit", "app.system") or getattr(record, "_journal", False):
            return
        try:
            msg = record.getMessage()
            if record.exc_info and record.exc_info[1] is not None:
                msg += f": {type(record.exc_info[1]).__name__}: {str(record.exc_info[1])[:200]}"
            extra = {k: v for k, v in record.__dict__.items() if k not in logging.LogRecord("x", 0, "x", 0, "", (), None).__dict__ and not k.startswith("_")
                     and k not in ("message", "asctime", "taskName")}
            self.buf.append((datetime.fromtimestamp(record.created, timezone.utc), "error" if record.levelno >= logging.ERROR else "warn", component_of(record.name),
                             record.name, scrub(msg)[:600], scrub(extra) if extra else None))
        except Exception:  # noqa: BLE001
            pass

    async def flush_loop(self, sm: async_sessionmaker[AsyncSession]) -> None:
        log = logging.getLogger("app.system")
        while True:
            await asyncio.sleep(5)
            if not self.buf:
                continue
            items = []
            while self.buf:
                items.append(self.buf.popleft())
            try:
                async with sm() as db:
                    for at, level, comp, name, msg, data in items:
                        db.add(EventLog(at=at, level=level, category=comp, event=f"log_{level}", user=None, source=self.service, message=msg,
                                        data={"logger": name, **(data or {})}))
                    await db.commit()
            except Exception:  # noqa: BLE001
                log.debug("Журнал событий недоступен для записи ошибок приложения", extra={"_journal": True})


def install_journal_handler(service: str) -> JournalHandler:
    h = JournalHandler(service)
    logging.getLogger().addHandler(h)
    return h


HEARTBEAT_S = 15


async def heartbeat_loop(sm: async_sessionmaker[AsyncSession], name: str, data_fn) -> None:
    """Пульс службы раз в 15 с: её сведения (`data_fn`) и показатели её контейнера (`probe`: CPU, память, лимиты, процессы, история около часа) — чтение /proc и cgroup, без внешних программ."""
    from ..tech.probe import Sampler  # noqa: PLC0415

    started = utcnow()
    sampler = Sampler()
    while True:
        try:
            sampler.sample()
            async with sm() as db:
                row = await db.get(ServiceHeartbeat, name)
                if row is None:
                    row = ServiceHeartbeat(name=name)
                    db.add(row)
                row.at, row.started_at, row.data = utcnow(), started, {**data_fn(), "probe": sampler.snapshot()}
                await db.commit()
            Path(f"/tmp/{name}.alive").touch()                       # для healthcheck контейнера: пульс записан в базу, значит цикл событий жив
        except Exception:  # noqa: BLE001
            logging.getLogger("app.system").debug("Пульс службы не записан", extra={"_journal": True})
        await asyncio.sleep(HEARTBEAT_S)


def resources(data_dir: str) -> dict:
    out: dict = {"cpu_count": os.cpu_count()}
    try:
        out["load"] = [round(x, 2) for x in os.getloadavg()]
    except OSError:
        out["load"] = None
    try:
        mem = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            mem[k] = int(v.strip().split()[0]) * 1024
        out["memory_total"], out["memory_available"] = mem.get("MemTotal"), mem.get("MemAvailable")
    except (OSError, ValueError):
        pass
    for key, path in (("disk_data", f"{data_dir}/reports"), ("disk_root", "/")):
        try:
            u = shutil.disk_usage(path)
            out[key] = {"total": u.total, "used": u.used, "free": u.free}
        except OSError:
            out[key] = None
    return out


def dir_size(path: str, limit_files: int = 200_000) -> int | None:
    total, n = 0, 0
    try:
        for root, _dirs, files in os.walk(path):
            for f in files:
                n += 1
                if n > limit_files:
                    return total
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    except OSError:
        return None
    return total


_uptime_started = time.time()


def uptime_s() -> int:
    return int(time.time() - _uptime_started)
