"""«Техническое состояние»: сводка исправности KAV Checker из уже собранных замеров — без внешних программ и без обращений к KSC и SMB.

Источники и частота:
  * пульс служб (`service_heartbeats`, раз в 15 с): сведения службы и показатели её контейнера (app/tech/probe.py);
  * помощник обновлений на сервере (`containers.json` раз в минуту, `dirs.json` раз в 15 минут): состояние Docker, проверки здоровья, перезапуски, OOM, лимиты;
    контейнеры приложения доступа к Docker не имеют;
  * аренды и история заданий (`job_leases`, `job_runs`), очередь ограничителя (пульс worker), таблицы отчётов, Pentest и BI;
  * PostgreSQL (app/tech/pg.py): активность — кэш 30 с, размеры таблиц — 10 минут;
  * результаты фоновых проверок источников KSC и BI (последняя проверка, последний расчёт), реестр компонентов.
Каждый блок несёт время измерения: устаревший замер показывается как устаревший, а не как текущее состояние.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (BiImport, BiSource, CatalogState, DevicesState, EolState, EventLog, JobLease, JobRun, KscSource, PtEngine, PtJob, ReportJob, ServiceHeartbeat, ZcSource,
                      utcnow)
from ..services.cache import TtlCache
from . import pg as PG

CACHE = TtlCache(max_items=20)
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

KIND_RU = {"catalog": "Каталог программ", "eol": "Расчёт EOL", "vdb_sync": "Загрузка базы уязвимостей", "vdb_analyze": "Анализ уязвимостей", "zonecache": "Данные зон (чтение KSC)",
           "zjob": "Расчёт зон", "report": "Отчёт", "bi": "Импорт BI", "devices": "Опрос пользователей устройств", "licenses": "Чтение лицензий", "ov_snapshot": "Срез главной",
           "pentest": "Сканирование Pentest", "hunt": "CVE Hunt", "mail": "Рассылка", "retention": "Ротация журналов", "components": "Проверка версий компонентов"}
GROUP = {"zonecache": "ksc", "zjob": "ksc", "devices": "ksc", "licenses": "ksc", "ov_snapshot": "ksc", "catalog": "catalog", "vdb_sync": "vdb", "vdb_analyze": "vdb", "eol": "eol",
         "bi": "bi", "report": "reports", "mail": "reports", "pentest": "pentest", "hunt": "hunt"}
GROUP_RU = {"ksc": "KSC", "catalog": "Каталог", "vdb": "Уязвимости", "eol": "EOL", "bi": "BI", "reports": "Отчёты", "pentest": "Pentest", "hunt": "CVE Hunt", "other": "Другие"}
LANE_RU = {"bg": "тяжёлые расчёты", "bi": "импорт BI", "interactive": "отчёты"}
SERVICES = {"backend": ("Backend", "API и страницы"), "worker": ("Worker", "фоновые задания: KSC, каталог, уязвимости, EOL, BI, отчёты"),
            "pentest": ("Pentest", "сканер: Nmap, NSE, Nuclei, CVE Hunt"), "postgres": ("PostgreSQL", "внутренняя база"), "web": ("Web", "интерфейс и прокси")}
HB_EXPECTED = ("backend", "worker", "pentest")
STATE_RU = {"running": "работает", "exited": "остановлен", "restarting": "перезапускается", "paused": "приостановлен", "dead": "не работает", "created": "создан, не запущен", "removing": "удаляется"}


def _json(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _age(t) -> int | None:
    return None if t is None else int((utcnow() - t).total_seconds())


def _pct(a, b) -> float | None:
    return round(100.0 * a / b, 1) if a is not None and b else None


async def thresholds(app, db: AsyncSession):
    return await app.state.settings_svc.get(db, "tech")


async def _pg(app) -> dict:
    sm = app.state.session_maker

    async def act():
        async with sm() as db:
            if db.bind.dialect.name != "postgresql":
                return {"ok": True, "version": "SQLite (тесты)", "unsupported": True, "at": time.time()}
            try:
                return await PG.activity(db)
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}", "at": time.time()}

    async def tbl():
        async with sm() as db:
            if db.bind.dialect.name != "postgresql":
                return {"items": [], "indexes": [], "at": time.time()}
            return await PG.tables(db, n=200)
    a, _ = await CACHE.get(("pg",), 30, act)
    t, _ = await CACHE.get(("pg-tables",), 600, tbl, swr=600)
    return {**a, "tables": t}


async def _web(app) -> dict:
    async def check():
        import httpx  # noqa: PLC0415

        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.5) as cl:
                r = await cl.get(os.environ.get("WEB_HEALTH_URL", "http://web:8080/healthz"))
            return {"ok": r.status_code == 200, "text": "отвечает" if r.status_code == 200 else f"ответ {r.status_code}", "ms": round((time.perf_counter() - t0) * 1000), "at": time.time()}
        except Exception as exc:  # noqa: BLE001
            return {"ok": None, "text": f"не проверен изнутри ({type(exc).__name__})", "at": time.time()}
    v, _ = await CACHE.get(("web",), 30, check)
    return v


async def _components(app) -> dict:
    from ..services import components as C  # noqa: PLC0415

    async def make():
        async with app.state.session_maker() as db:
            return await C.table(db, app.state.settings)
    v, _ = await CACHE.get(("components",), 300, make, swr=600)
    return v


def _svc_status(key: str, hb_age: int | None, cont: dict | None, th) -> tuple[str, str]:
    """Состояние контейнера (по Docker) — отдельно от работы его функций: здесь только «запущен ли и отвечает ли пульс»."""
    if cont is not None and cont.get("state") not in (None, "running"):
        return "bad", (f"контейнер {STATE_RU.get(cont.get('state'), cont.get('state'))}" + (f", код выхода {cont.get('exit_code')}" if cont.get("exit_code") else "")
                       + (" — завершён по нехватке памяти" if cont.get("oom_killed") and cont.get("exit_code") == 137 else ""))
    if key in HB_EXPECTED:
        if hb_age is None:
            return ("unknown", "пульса нет: служба не запускалась") if cont is None else ("bad", "пульса нет")
        if hb_age > th.heartbeat_seconds:
            return "bad", f"нет пульса {hb_age // 60} мин {hb_age % 60} с — служба не отвечает" + (" (Docker при этом считает контейнер исправным)" if cont and cont.get("health") == "healthy" else "")
    if cont is not None and cont.get("health") == "unhealthy":
        return "warn", "проверка здоровья Docker не проходит" + (f": {cont['health_out'][:120]}" if cont.get("health_out") else "")
    return "ok", "работает"


async def collect(app, db: AsyncSession) -> dict[str, Any]:
    s = app.state.settings
    th = await thresholds(app, db)
    now = utcnow()
    problems: list[dict] = []

    def problem(level: str, area: str, text: str, tab: str = "overview") -> None:
        problems.append({"level": level, "area": area, "text": text, "tab": tab})

    # ------------------------------------------------------------------ службы и контейнеры
    hbs = {h.name: h for h in (await db.execute(select(ServiceHeartbeat))).scalars()}
    helper = _json(f"{s.data_dir}/updater/containers.json")
    helper_age = int(time.time() - helper["checked_at"]) if helper and helper.get("checked_at") else None
    conts = {c.get("service") or c.get("name"): c for c in (helper or {}).get("items", [])} if helper_age is not None and helper_age < 300 else {}
    host = None
    for k in ("backend", "worker", "pentest"):                                  # хост: из самого свежего пульса (в контейнере /proc показывает сервер)
        p = ((hbs.get(k).data or {}).get("probe") if hbs.get(k) else None) or {}
        if p.get("at") and (host is None or p["at"] > host["at"]):
            host = p
    keys = list(dict.fromkeys([*SERVICES, *conts, *[k for k in hbs if k in SERVICES]]))
    pgs = await _pg(app)
    web = await _web(app)
    services = []
    for key in keys:
        if key not in SERVICES and key not in conts:
            continue
        hb = hbs.get(key)
        hb_age = _age(hb.at) if hb else None
        cont = conts.get(key)
        if key not in hbs and key not in conts and key in ("pentest",) and helper is not None:
            continue                                                            # сканер не установлен
        probe = ((hb.data or {}).get("probe") if hb else None) or None
        level, text = _svc_status(key, hb_age, cont, th)
        func_ = {"level": "ok", "text": ""}
        if key == "postgres":
            func_ = {"level": "ok" if pgs.get("ok") else "bad", "text": f"отвечает за {pgs.get('ping_ms')} мс" if pgs.get("ok") else f"не отвечает: {pgs.get('error', '')}"}
        elif key == "web":
            func_ = {"level": "ok" if web["ok"] else "warn" if web["ok"] is None else "bad", "text": web["text"]}
        elif key == "backend":
            func_ = {"level": "ok", "text": "отвечает на запросы"}
        cg = (probe or {}).get("cgroup") or {}
        res = {"cpu_pct": (probe or {}).get("cpu_pct") if probe else (cont or {}).get("cpu_pct"), "mem": cg.get("mem") if cg.get("mem") is not None else (cont or {}).get("mem"),
               "mem_limit": cg.get("mem_limit") or (cont or {}).get("mem_limit"), "mem_peak": cg.get("mem_peak"), "cpu_limit": cg.get("cpu_limit") or (cont or {}).get("cpu_limit"),
               "pids": cg.get("pids") if cg.get("pids") is not None else (cont or {}).get("pids"), "threads": (probe or {}).get("threads"), "oom_kill": cg.get("oom_kill"),
               "high_since": (probe or {}).get("high_since"), "io_pressure": cg.get("io_pressure"), "top": (probe or {}).get("top") or [], "hist": (probe or {}).get("hist") or [],
               "at": (probe or {}).get("at") or ((helper or {}).get("checked_at") if cont else None), "source": "пульс службы" if probe else "помощник на сервере" if cont else ""}
        if key == "postgres" and res["mem"] is None and cont is None:
            res["source"] = ""
        title, purpose = SERVICES.get(key, (key, ""))
        services.append({"key": key, "title": title, "purpose": purpose, "level": level, "text": text, "func": func_, "heartbeat_age_s": hb_age, "started_at": hb.started_at if hb else None,
                         "version": ((hb.data or {}).get("version") if hb else None) or (s.app_version if key == "backend" else None), "host": (probe or {}).get("host"),
                         "container": cont, "res": res, "data": {k: v for k, v in (hb.data or {}).items() if k not in ("probe", "resources", "waiting")} if hb else {}})
        if level == "bad":
            problem("bad", title, text, "services")
        elif level == "warn":
            problem("warn", title, text, "services")
        if func_["level"] == "bad":
            problem("bad", title, func_["text"], "services")
        if cont and cont.get("restarts"):
            problem("warn", title, f"контейнер перезапускался {cont['restarts']} раз(а) с момента создания", "services")
        if (cg.get("oom_kill") or 0) > 0 or (not cg and cont and cont.get("oom_killed") and cont.get("state") == "running"):     # счётчик cgroup точнее флага Docker: флаг не сбрасывается
            problem("bad", title, f"с момента запуска контейнера процессы завершались из-за нехватки памяти (OOM: {cg.get('oom_kill') or 1})", "resources")
        if res["mem"] and res["mem_limit"] and _pct(res["mem"], res["mem_limit"]) >= th.container_mem_pct:
            problem("warn", title, f"память {_pct(res['mem'], res['mem_limit'])} % лимита контейнера"
                    + (" — включая файловый кеш базы: ядро освобождает его первым, опасно только вместе с OOM или ростом ожидания диска" if key == "postgres" else ""), "resources")
        if res["cpu_pct"] is not None and res["high_since"] and res["cpu_pct"] >= th.core_pct and time.time() - res["high_since"] >= th.cpu_minutes * 60:
            mins = int((time.time() - res["high_since"]) // 60)
            cores = res["cpu_pct"] / 100
            problem("warn", title, f"загружает {res['cpu_pct']:.0f} % одного ядра ({cores:.1f} ядра) уже {mins} мин"
                    + (f"; на сервере {host['cpus']} ядер — это {res['cpu_pct'] / host['cpus']:.0f} % всего процессора" if host and host.get("cpus") else ""), "resources")

    # ------------------------------------------------------------------ ресурсы сервера
    hostres = None
    if host:
        m = host.get("mem") or {}
        hostres = {"at": host.get("at"), "cpus": host.get("cpus"), "cpu_pct": host.get("host_cpu_pct"), "load": host.get("load"), "mem_total": m.get("total"), "mem_available": m.get("available"),
                   "swap_total": m.get("swap_total"), "swap_free": m.get("swap_free"), "io_pressure": host.get("host_io_pressure"), "mem_pressure": host.get("host_mem_pressure"),
                   "hist": [[p[0], p[1]] for p in host.get("hist") or []]}
        if hostres["cpu_pct"] is not None and hostres["cpu_pct"] >= th.cpu_pct:
            problem("warn", "Сервер", f"загрузка процессора {hostres['cpu_pct']:.0f} % (порог {th.cpu_pct} %)", "resources")
        if m.get("total") and m.get("available") is not None and _pct(m["available"], m["total"]) < th.mem_free_pct:
            problem("bad", "Сервер", f"доступно памяти {_pct(m['available'], m['total'])} % (порог {th.mem_free_pct} %)", "resources")
        if (hostres["io_pressure"] or 0) >= 30:
            problem("warn", "Сервер", f"задачи ждут диск {hostres['io_pressure']:.0f} % времени (давление ввода-вывода за 10 с)", "resources")
    dirs = _json(f"{s.data_dir}/updater/dirs.json")
    disk = None
    try:
        u = shutil.disk_usage(s.reports_dir)
        disk = {"total": u.total, "used": u.used, "free": u.free, "path": "каталог данных (отчёты, BI)"}
    except OSError:
        pass
    if disk and (disk["free"] < th.disk_free_gb * 1024**3 or _pct(disk["free"], disk["total"]) < th.disk_free_pct):
        problem("bad", "Диск", f"на диске данных свободно {disk['free'] / 1024**3:.1f} ГБ ({_pct(disk['free'], disk['total'])} %)", "resources")

    # ------------------------------------------------------------------ задания
    jobs = await _jobs(db, hbs, services, th, problem)

    # ------------------------------------------------------------------ PostgreSQL
    if pgs.get("ok") and not pgs.get("unsupported"):
        for q in pgs.get("long", []):
            if q["query_s"] >= th.sql_long_seconds:
                problem("warn", "PostgreSQL", f"запрос {q['kind']}{' к ' + q['table'] if q['table'] else ''} ({q['app']}) выполняется {int(q['query_s'])} с", "pg")
        for lk in pgs.get("locks", []):
            h = lk["holder"]
            problem("warn", "PostgreSQL", f"{lk['waiting']['app']} ждёт блокировку {int(lk['waiting']['query_s'] or 0)} с: держит {h['app']} ({h.get('state') or '—'}"
                    + (f", транзакция {int(h['xact_s'])} с" if h.get("xact_s") else "") + ")", "pg")
        for x in pgs.get("long_xact", [])[:3]:
            if x["state"] == "idle in transaction":
                problem("warn", "PostgreSQL", f"транзакция {x['app']} простаивает открытой {int(x['xact_s'])} с — держит блокировки", "pg")

    # ------------------------------------------------------------------ источники
    sources = await _sources(app, db, th, jobs["items"], hbs, problem)

    # ------------------------------------------------------------------ журнал, компоненты
    err24 = int((await db.execute(select(func.count()).select_from(EventLog).where(EventLog.level == "error", EventLog.at >= now - timedelta(hours=24)))).scalar_one())
    warn24 = int((await db.execute(select(func.count()).select_from(EventLog).where(EventLog.level == "warn", EventLog.at >= now - timedelta(hours=24)))).scalar_one())
    last_err = (await db.execute(select(EventLog).where(EventLog.level == "error").order_by(EventLog.id.desc()).limit(1))).scalar_one_or_none()
    recent = (await db.execute(select(EventLog).where(EventLog.level.in_(("error", "warn"))).order_by(EventLog.id.desc()).limit(15))).scalars().all()
    if err24 > th.errors_24h:
        problem("warn", "Журнал", f"ошибок за сутки: {err24} (порог {th.errors_24h})", "diag")
    comps = await _components(app)
    for c in comps["items"]:
        if c["status"] == "incompatible":
            problem("warn", "Компоненты", f"{c['title']}: несовместимая версия — {c['why']}", "components")

    if app.state.settings_svc.box is None:
        problem("bad", "Безопасность", "APP_MASTER_KEY не задан или некорректен: пароли источников KSC, BI и LDAPS и второй фактор недоступны — задайте ключ в .env и перезапустите службы", "diag")
    if not s.app_public_url.lower().startswith("https://"):
        problem("warn", "Безопасность", f"приложение открывается по HTTP ({s.app_public_url}): cookie сессии без флага Secure — после перехода на HTTPS укажите https:// в APP_PUBLIC_URL", "diag")
    order = {"bad": 0, "warn": 1}
    problems.sort(key=lambda p: order.get(p["level"], 2))
    level = "bad" if any(p["level"] == "bad" for p in problems) else "warn" if problems else "ok"
    return {"at": time.time(), "version": s.app_version, "commit": s.app_git_commit, "built_at": s.app_built_at, "level": level, "problems": problems, "thresholds": th.model_dump(),
            "host": hostres, "disk": disk, "dirs": dirs, "helper": {"available": helper is not None, "age_s": helper_age}, "services": services, "jobs": jobs, "pg": pgs, "sources": sources,
            "journal": {"errors_24h": err24, "warn_24h": warn24, "last_error": {"at": last_err.at, "category": last_err.category, "message": last_err.message, "source": last_err.source} if last_err else None,
                        "recent": [{"at": e.at, "level": e.level, "category": e.category, "event": e.event, "source": e.source, "message": e.message} for e in recent]},
            "components": {"counts": comps["counts"], "checked_at": comps["checked_at"], "reviewed_for": comps["reviewed_for"], "items": comps["items"]}}


async def _jobs(db: AsyncSession, hbs: dict, services: list, th, problem) -> dict:
    """Все фоновые задания одним списком: ожидают места (пульс worker), захвачены и выполняются (аренды), стоят в очереди своих таблиц (отчёты, Pentest, BI), завершены за сутки (история)."""
    now = utcnow()
    names = {str(x.id): x.name for x in (await db.execute(select(KscSource))).scalars()}
    names.update({str(x.id): x.name for x in (await db.execute(select(BiSource))).scalars()})
    by_host = {sv["host"]: sv for sv in services if sv.get("host")}
    items: list[dict] = []
    wpulse = (hbs["worker"].data or {}) if hbs.get("worker") else {}
    wage = _age(hbs["worker"].at) if hbs.get("worker") else None
    def named(t: str) -> str:                                                  # «анализ уязвимостей <uuid>» → «анализ уязвимостей Kaspersky 02»
        return _UUID.sub(lambda m: names.get(m.group(0), m.group(0)), t or "")
    reasons = {w["task"]: named(w.get("reason", "")) for w in (wpulse.get("resources") or {}).get("waiting", [])}
    running_res = [{**r, "task": named(r["task"])} for r in (wpulse.get("resources") or {}).get("running", [])]
    stale_pulse = wage is None or wage > th.heartbeat_seconds
    for w in wpulse.get("waiting", []) if not stale_pulse else []:
        since = w.get("since")
        try:
            from datetime import datetime  # noqa: PLC0415

            wait_s = int((now - datetime.fromisoformat(since)).total_seconds())
        except (TypeError, ValueError):
            wait_s = None
        reason = reasons.get(w["task"], "")
        items.append({"id": f"wait:{w['kind']}:{w['scope']}", "kind": w["kind"], "kind_ru": KIND_RU.get(w["kind"], w["kind"]), "group": GROUP.get(w["kind"], "other"), "scope": names.get(w["scope"], w["scope"]),
                      "state": "waiting", "state_ru": "Ожидает исполнителя", "stage": w.get("stage") or "", "queued_at": since, "started_at": None, "wait_s": wait_s, "executor": "worker",
                      "lane": LANE_RU.get(w["lane"], w["lane"]), "reason": reason, "progress": None, "progress_age_s": None, "heartbeat_age_s": None})
        if wait_s is not None and wait_s >= th.job_wait_minutes * 60:
            problem("warn", "Задания", f"{KIND_RU.get(w['kind'], w['kind'])}{' · ' + names.get(w['scope'], w['scope']) if w['scope'] else ''} ожидает исполнителя {wait_s // 60} мин"
                    + (f": {reason}" if reason else ""), "jobs")
    for le in (await db.execute(select(JobLease).order_by(JobLease.started_at))).scalars():
        host = le.owner.split("/", 1)[0]
        sv = by_host.get(host)
        prog_age = _age(le.progress_at) if le.progress_at else None
        hb_age = _age(le.heartbeat_at)
        expired = le.lease_until < now
        captured = le.progress_at is not None and abs((le.progress_at - le.started_at).total_seconds()) < 1 and (le.stage or "") in ("", "запуск")
        state, state_ru = ("expired", "Аренда просрочена") if expired else ("captured", "Захвачено исполнителем") if captured else ("running", "Выполняется")
        item = {"id": str(le.run_id), "kind": le.kind, "kind_ru": KIND_RU.get(le.kind, le.kind), "group": GROUP.get(le.kind, "other"), "scope": names.get(le.scope, le.scope), "state": state, "state_ru": state_ru,
                "stage": le.stage, "progress": le.progress, "queued_at": le.queued_at, "started_at": le.started_at, "duration_s": _age(le.started_at),
                "wait_s": int((le.started_at - le.queued_at).total_seconds()) if le.queued_at else None, "progress_age_s": prog_age, "heartbeat_age_s": hb_age,
                "executor": sv["key"] if sv else host, "owner": le.owner, "app_version": le.app_version, "lane": "", "reason": "",
                "res": {"cpu_pct": sv["res"]["cpu_pct"], "mem": sv["res"]["mem"], "note": "весь контейнер службы: задания одного процесса не разделяются"} if sv else None}
        title = f"{item['kind_ru']}{' · ' + item['scope'] if item['scope'] else ''}"
        if expired:
            gone = sv is None and bool(by_host)
            item["reason"] = (f"исполнитель не продлевает аренду {secs_ru(hb_age)}: его контейнера больше нет (прежний запуск) — аренда будет снята, задание запустится заново" if gone else
                              f"исполнитель не продлевает аренду {secs_ru(hb_age)}: завершился или завис — задание будет перехвачено и запущено заново")
            problem("bad", "Задания", f"{title}: {item['reason']}", "jobs")
        elif prog_age is not None and prog_age >= th.no_progress_minutes * 60:
            item["reason"] = (f"нет хода выполнения {prog_age // 60} мин на этапе «{le.stage}», хотя пульс аренды живой ({hb_age} с назад)" if hb_age <= 60 else
                              f"нет хода выполнения {prog_age // 60} мин на этапе «{le.stage}»; пульс аренды тоже не обновляется {hb_age} с — исполнитель не отвечает")
            item["stalled"] = True
            problem("warn", "Задания", f"{title}: {item['reason']}", "jobs")
        items.append(item)
    for r in (await db.execute(select(ReportJob).where(ReportJob.status == "queued").order_by(ReportJob.created_at).limit(50))).scalars():
        items.append({"id": f"report:{r.id}", "kind": "report", "kind_ru": "Отчёт", "group": "reports", "scope": r.title or r.kind, "state": "waiting", "state_ru": "В очереди", "stage": "",
                      "queued_at": r.created_at, "started_at": None, "wait_s": _age(r.created_at), "executor": "worker", "lane": LANE_RU["interactive"], "reason": "", "progress": None})
    for p in (await db.execute(select(PtJob).where(PtJob.status.in_(("queued", "running"))).order_by(PtJob.created_at).limit(50))).scalars():
        kind = "hunt" if p.profile == "hunt" else "pentest"
        if p.status == "running" and any(i["kind"] == "pentest" and i["scope"] == str(p.id) for i in items):
            continue
        items.append({"id": f"pt:{p.id}", "kind": kind, "kind_ru": KIND_RU[kind], "group": kind, "scope": p.title, "state": "waiting" if p.status == "queued" else "running",
                      "state_ru": "В очереди" if p.status == "queued" else "Выполняется", "stage": p.stage_ru or p.stage or "", "queued_at": p.created_at, "started_at": p.started_at,
                      "wait_s": _age(p.created_at) if p.status == "queued" else None, "duration_s": _age(p.started_at) if p.started_at else None, "executor": "pentest", "lane": "", "reason": "",
                      "progress": f"{p.pct} %" if p.pct else None})
    from ..bi.importer import STATUS_RU  # noqa: PLC0415

    for b in (await db.execute(select(BiImport).where(BiImport.status.in_(("queued", "waiting"))).order_by(BiImport.started_at).limit(20))).scalars():
        if any(i["kind"] == "bi" and i["state"] == "waiting" and i["scope"] == names.get(str(b.source_id)) for i in items):
            continue
        items.append({"id": f"bi:{b.id}", "kind": "bi", "kind_ru": "Импорт BI", "group": "bi", "scope": names.get(str(b.source_id), ""), "state": "waiting", "state_ru": STATUS_RU.get(b.status, b.status).capitalize(),
                      "stage": STATUS_RU.get(b.status, b.status), "queued_at": b.started_at, "started_at": None, "wait_s": _age(b.started_at), "executor": "worker", "lane": LANE_RU["bi"], "reason": "", "progress": None})
    day = now - timedelta(hours=24)
    runs = (await db.execute(select(JobRun).where(JobRun.finished_at >= day).order_by(JobRun.id.desc()).limit(2000))).scalars().all()
    by_kind: dict[str, dict] = {}
    for r in runs:
        k = by_kind.setdefault(r.kind, {"kind": r.kind, "kind_ru": KIND_RU.get(r.kind, r.kind), "group": GROUP.get(r.kind, "other"), "n": 0, "failed": 0, "dur": [], "wait": []})
        k["n"] += 1
        k["failed"] += r.status in ("error", "interrupted", "lost")
        if r.duration_ms is not None and r.status == "success":
            k["dur"].append(r.duration_ms / 1000)
        if r.waited_ms is not None:
            k["wait"].append(r.waited_ms / 1000)
    kinds = []
    for k in sorted(by_kind.values(), key=lambda x: -x["n"]):
        d, w = k.pop("dur"), k.pop("wait")
        kinds.append({**k, "avg_s": round(sum(d) / len(d), 1) if d else None, "max_s": round(max(d), 1) if d else None, "wait_avg_s": round(sum(w) / len(w), 1) if w else None,
                      "wait_max_s": round(max(w), 1) if w else None})
    waits_all = [r.waited_ms / 1000 for r in runs if r.waited_ms is not None]
    waiting = [i for i in items if i["state"] == "waiting"]
    st_ru = {"success": "Завершено", "error": "Ошибка", "interrupted": "Прервано", "lost": "Аренда потеряна", "deferred": "Отложено"}
    history = [{"id": r.id, "kind": r.kind, "kind_ru": KIND_RU.get(r.kind, r.kind), "group": GROUP.get(r.kind, "other"), "scope": names.get(r.scope, r.scope), "status": r.status, "status_ru": st_ru.get(r.status, r.status),
                "started_at": r.started_at, "finished_at": r.finished_at, "duration_s": round(r.duration_ms / 1000, 1) if r.duration_ms is not None else None,
                "wait_s": round(r.waited_ms / 1000, 1) if r.waited_ms is not None else None, "stage": r.stage, "error": (r.error or "")[:400]} for r in runs[:60]]
    return {"items": items, "history": history, "by_kind": kinds, "groups": GROUP_RU, "worker_pulse_age_s": wage, "running_slots": running_res,
            "slots": {k: (wpulse.get("resources") or {}).get(k) for k in ("slots", "slots_requested", "cpus", "lanes", "rss_mb", "peak_mb", "soft_mb", "hard_mb")},
            "counts": {"total": len(items), "waiting": len(waiting), "running": sum(1 for i in items if i["state"] in ("running", "captured")), "stalled": sum(1 for i in items if i.get("stalled")),
                       "expired": sum(1 for i in items if i["state"] == "expired"), "done_24h": sum(1 for r in runs if r.status == "success"),
                       "failed_24h": sum(1 for r in runs if r.status in ("error", "interrupted", "lost")), "oldest_wait_s": max((i["wait_s"] or 0 for i in waiting), default=None) if waiting else None,
                       "wait_avg_s": round(sum(waits_all) / len(waits_all), 1) if waits_all else None, "wait_max_s": round(max(waits_all), 1) if waits_all else None}}


async def _sources(app, db: AsyncSession, th, items: list, hbs: dict, problem) -> dict:
    now = utcnow()
    ksc = []
    for x in (await db.execute(select(KscSource).order_by(KscSource.position))).scalars():
        zc, cs, ev, dv = await db.get(ZcSource, x.id), await db.get(CatalogState, x.id), await db.get(EolState, x.id), await db.get(DevicesState, x.id)
        sync_at = zc.built_at if zc else None
        stale = x.is_active and (sync_at is None or now - sync_at > timedelta(hours=th.ksc_stale_hours))
        cur = [f"{i['kind_ru']}: {i.get('stage') or i['state_ru']}" for i in items if i["scope"] == x.name]
        row = {"id": str(x.id), "name": x.name, "active": x.is_active, "check_at": x.last_check_at, "check_ok": x.last_check_ok, "check_error": next((f"{st.get('stage')}: {st.get('message')}" for st in (x.last_check or {}).get("stages", []) if st.get("ok") is False or st.get("status") in ("error", "fail", "failed")), None)
               if x.last_check_ok is False else None,
               "ksc_version": (x.last_check or {}).get("ksc_version"),
               "sync": {"at": sync_at, "status": zc.status if zc else None, "error": zc.error if zc else None, "duration_ms": zc.duration_ms if zc else None, "hosts": zc.hosts_n if zc else None, "progress": zc.progress if zc else None},
               "catalog": {"at": cs.built_at if cs else None, "status": cs.status if cs else None, "error": cs.error if cs else None, "duration_ms": cs.duration_ms if cs else None},
               "eol": {"at": ev.computed_at if ev else None, "error": ev.error if ev else None}, "devices": {"at": dv.polled_at if dv else None, "error": dv.error if dv else None},
               "stale": stale, "current": cur}
        ksc.append(row)
        if x.is_active and x.last_check_ok is False:
            problem("bad", f"KSC «{x.name}»", f"последняя проверка соединения не прошла ({fmt_at(x.last_check_at)})", "sources")
        if x.is_active and zc and zc.status == "failed":
            problem("bad", f"KSC «{x.name}»", f"чтение данных KSC завершилось ошибкой: {(zc.error or '')[:160]}", "sources")
        if x.is_active and cs and cs.status == "failed":
            problem("warn", f"KSC «{x.name}»", f"каталог программ не построен: {(cs.error or '')[:160]}", "sources")
        if x.is_active and zc and zc.status == "failed":
            pass
        elif stale:
            problem("warn", f"KSC «{x.name}»", "данные не обновлялись" + (f" с {fmt_at(sync_at)}" if sync_at else " ни разу") + f" (порог {th.ksc_stale_hours} ч)", "sources")
    bi = []
    from ..bi.importer import STATUS_RU  # noqa: PLC0415

    for b in (await db.execute(select(BiSource).order_by(BiSource.created_at))).scalars():
        last = await db.get(BiImport, b.last_import_id) if b.last_import_id else None
        active = (await db.execute(select(BiImport).where(BiImport.source_id == b.id, BiImport.status.in_(("queued", "waiting", "connecting", "fetching", "checking", "importing", "matching"))).limit(1))).scalar_one_or_none()
        row = {"id": str(b.id), "name": b.name, "kind": b.kind, "active": b.is_active, "smb": f"\\\\{b.smb_host}\\{b.smb_share}" if b.kind == "smb" and b.smb_host else None,
               "last_try_at": b.last_try_at, "last_ok_at": b.last_ok_at, "last_error": b.last_error, "fail_n": b.fail_n, "next_run_at": b.next_run_at,
               "last": {"status": last.status, "status_ru": STATUS_RU.get(last.status, last.status), "message": last.message, "finished_at": last.finished_at, "rows": last.rows_valid,
                        "devices": last.devices_n, "persons": last.persons_n, "ms": last.ms} if last else None,
               "now": STATUS_RU.get(active.status, active.status) if active else None}
        bi.append(row)
        if b.is_active and b.last_error and (not b.last_ok_at or (b.last_try_at and b.last_try_at > b.last_ok_at)):
            problem("bad" if (b.fail_n or 0) >= 3 else "warn", f"BI «{b.name}»", f"последний импорт не удался: {b.last_error[:180]}", "sources")
        elif b.is_active and b.kind == "smb" and b.last_ok_at and now - b.last_ok_at > timedelta(hours=th.bi_stale_hours):
            problem("warn", f"BI «{b.name}»", f"нет успешного импорта с {fmt_at(b.last_ok_at)} (порог {th.bi_stale_hours} ч)", "sources")
    pt_hb = hbs.get("pentest")
    pdata = (pt_hb.data or {}) if pt_hb else {}
    eng = await db.get(PtEngine, "nuclei")
    q = dict((await db.execute(select(PtJob.status, func.count()).where(PtJob.status.in_(("queued", "running"))).group_by(PtJob.status))).all())
    failed = int((await db.execute(select(func.count()).select_from(PtJob).where(PtJob.status == "failed", PtJob.finished_at >= now - timedelta(hours=24)))).scalar_one())
    alive = pt_hb is not None and _age(pt_hb.at) <= th.heartbeat_seconds
    pentest = {"installed": pt_hb is not None, "alive": alive, "heartbeat_age_s": _age(pt_hb.at) if pt_hb else None, "nmap": pdata.get("nmap"), "net_raw": pdata.get("net_raw"),
               "nse_scripts": pdata.get("nse_scripts"), "nuclei": {"version": eng.version if eng else "", "templates": eng.templates_ver if eng else "", "templates_n": eng.templates_n if eng else 0,
                                                                  "templates_at": eng.templates_at if eng else None, "status": (eng.status if eng else "") or "idle", "message": eng.message if eng else ""},
               "queued": int(q.get("queued", 0)), "running": int(q.get("running", 0)), "failed_24h": failed}
    if (pentest["queued"] or pentest["running"]) and not alive:
        problem("bad", "Pentest", "сканер не отвечает, а задания ждут в очереди", "sources")
    elif alive and not pentest["nmap"]:
        problem("bad", "Pentest", "Nmap не найден в контейнере сканера: сканирование невозможно", "sources")
    if eng and eng.status == "error":
        problem("warn", "Pentest", f"Nuclei: {eng.message[:160]}", "sources")
    return {"ksc": ksc, "bi": bi, "pentest": pentest}


def secs_ru(s: int | None) -> str:
    return "—" if s is None else f"{s} с" if s < 120 else f"{s // 60} мин" if s < 7200 else f"{s // 3600} ч {s % 3600 // 60} мин"


def fmt_at(t) -> str:
    return t.astimezone().strftime("%d.%m.%Y %H:%M") if t else "—"


async def cached(app, db: AsyncSession, *, refresh: bool = False) -> tuple[dict, float]:
    """Сводка с кэшем 5 с: несколько открытых страниц и опрос раз в 10 с не умножают запросы; «Обновить данные» — не чаще раза в 10 с, параллельные нажатия ждут один расчёт."""
    sm = app.state.session_maker

    async def make():
        async with sm() as db2:
            return await collect(app, db2)
    if not refresh:
        return await CACHE.get(("tech",), 5, make)
    global _REFRESH
    loop = asyncio.get_running_loop()
    if _REFRESH is None or _REFRESH[0] is not loop:
        _REFRESH = (loop, asyncio.Lock())
    async with _REFRESH[1]:
        hit = CACHE._data.get(("tech",))  # noqa: SLF001
        if hit and time.time() - hit[0] < 10:
            return hit[1], hit[0]
        CACHE.drop(("pg",))
        CACHE.drop(("web",))
        return await CACHE.get(("tech",), 5, make, refresh=True)


_REFRESH: tuple | None = None
