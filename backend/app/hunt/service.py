"""Создание задания CVE Hunt: критерии → порты, цели, проверки → задание Pentest (`pt_jobs`, профиль «hunt») + данные KSC. Своей очереди и своего исполнителя нет: задание выполняет сканер Pentest."""
from __future__ import annotations

import asyncio
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import HuntHit, PtEngine, PtJob, utcnow
from ..pentest import diag as D
from ..pentest import nmap as N
from ..pentest import service as S
from ..pentest import targets as T
from . import criteria as C
from . import ksc as K
from . import kb as KB
from . import results as RS
from . import scope as SC

MODES = ("ksc", "network", "combined")
MAX_CRITERIA = 20
WEB_SCRIPTS = ["http-headers"]


class HuntError(Exception):
    pass


async def resolve(db: AsyncSession, cves: list[str], products: list[dict]) -> list[dict]:
    out: list[dict] = []
    for c in cves[:MAX_CRITERIA]:
        if not C.CVE_RE.match(c.strip()):
            raise HuntError(f"«{c}» не похоже на идентификатор CVE (пример: CVE-2024-6387)")
        out.append(await C.resolve_cve(db, c))
    for p in products[:MAX_CRITERIA]:
        try:
            out.append(await C.resolve_product(db, p))
        except ValueError as exc:
            raise HuntError(str(exc)) from None
    if not out:
        raise HuntError("Выберите CVE или продукт для поиска")
    if len(out) > MAX_CRITERIA:
        raise HuntError(f"Критериев не больше {MAX_CRITERIA}")
    seen = set()
    for c in out:
        if c["key"] in seen:
            raise HuntError(f"Критерий «{c['title']}» указан дважды")
        seen.add(c["key"])
    return out


def ports_for(crits: list[dict], extra: str) -> tuple[str, list[int]]:
    ports = list(dict.fromkeys(p for c in crits for p in c.get("ports", [])))
    if extra.strip():
        for tok in extra.replace(";", ",").split(","):
            tok = tok.strip()
            if tok:
                ports += [int(x) for x in N.ports_spec(tok).split(",") if "-" not in x]
    spec = ",".join(str(p) for p in dict.fromkeys(ports))
    return (N.ports_spec(spec) if spec else ""), ports


async def preview(db: AsyncSession, crits: list[dict], scope: dict, extra_ports: str, settings, allowed, activity_days: int) -> dict:
    sc = await SC.collect(db, scope, settings, allowed, activity_days)
    plan = T.build(sc["text"], T.Policy.from_settings(settings), T.resolve_name, [(d["ip"], d["name"]) for d in sc["devices"]]) if (sc["text"] or sc["devices"]) else T.Plan()
    plan.addresses = [a for a in plan.addresses if not sc["skip"](a)]
    spec, ports = ports_for(crits, extra_ports)
    text = (f"Выбрано {plan.total} адресов" + (f" ({len(sc['devices'])} компьютеров KSC из {sc['sources_n']} источников)" if sc["devices"] else "") + f", {sc['networks_n']} сетей и диапазонов, {len(crits)} критериев поиска, {len(ports)} TCP-портов")
    return {"targets": plan.total, "ksc_hosts": len(sc["devices"]), "sources": sc["sources_n"], "networks": sc["networks_n"], "excluded": sc["excluded_n"], "criteria": len(crits), "ports": ports, "ports_spec": spec,
            "rejected": plan.rejected[:20], "text": text}


def _nse_for(crits: list[dict]) -> list[str]:
    return list(WEB_SCRIPTS) if any((c.get("kb") in ("php", "apache", "nginx", "bitrix", "tomcat")) for c in crits) else []


async def create(db: AsyncSession, app, *, title: str, crits: list[dict], logic: str, mode: str, scope: dict, extra_ports: str, force: bool, confirm_scope: bool, confirm_large: bool,
                 user, base_job_id: uuid.UUID | None, settings, allowed, activity_days: int) -> PtJob:
    if mode not in MODES:
        raise HuntError("Неизвестный режим поиска")
    if logic not in ("any", "all"):
        raise HuntError("Неизвестная логика критериев")
    spec, ports = ports_for(crits, extra_ports)
    net = mode in ("network", "combined")
    if net and not spec:
        raise HuntError("Для сетевой проверки нужен хотя бы один TCP-порт")
    sc = await SC.collect(db, scope, settings, allowed, activity_days)
    policy = T.Policy.from_settings(settings)
    try:
        plan = await asyncio.to_thread(T.build, sc["text"], policy, T.resolve_name, [(d["ip"], d["name"]) for d in sc["devices"]]) if (sc["text"] or sc["devices"]) else T.Plan()
    except T.TargetError as exc:
        raise HuntError(str(exc)) from None
    plan.addresses = [a for a in plan.addresses if not sc["skip"](a)]
    eng = await db.get(PtEngine, "nuclei")
    ready = bool(eng and eng.version and eng.templates_ver)
    checks = [x["id"] for c in crits for x in c.get("checks", [])] if (net and ready and settings.nuclei_enabled) else []
    nse = _nse_for(crits) if net else []
    try:
        opts = S.check_options(settings, "custom", spec or "80", "off", 2, False, plan if (net or plan.total) else _ksc_plan(plan), confirm_scope or not net, confirm_large or not net,     # без сети адреса не сканируются — подтверждение не нужно
                                 scan=None, engine_ready=ready)
    except S.JobError as exc:
        raise HuntError(str(exc)) from None
    opts["scan"] = {"preset": "hunt", "nse": bool(nse), "nse_groups": [], "nse_only": nse, "nuclei": bool(checks), "cats": [], "active": False, "only_checks": sorted(set(checks))}
    opts["hunt"] = {"criteria": crits, "logic": logic, "mode": mode, "scope": {k: v for k, v in scope.items() if k != "exclude"} | {"exclude": scope.get("exclude", "")}, "ports": ports, "force": bool(force),
                    "activity_days": int(scope.get("active_days") or activity_days), "source_ids": sorted({str(d["source_id"]) for d in sc["devices"]}) or [str(s) for s in scope.get("sources", [])]}
    text = "; ".join(c["title"] for c in crits)[:2000]
    job = await S.create_job(db, title=title.strip() or f"Целевой поиск {utcnow():%d.%m.%Y %H:%M}", text=text, plan=plan if net else T.Plan(), profile="custom", options=opts, user_name=user.display_name, user_id=user.user_id, base_job_id=base_job_id)
    job.profile = "hunt"
    job.targets_n = plan.total
    sink = D.Sink(None, job.id, 0)                         # события создания пишутся в той же транзакции, что и задание
    await db.flush()
    if mode in ("ksc", "combined"):
        await _ksc_stage(db, app, job, crits, opts["hunt"], sink)
    if mode == "ksc":
        job.status, job.finished_at, job.started_at, job.pct, job.stage, job.stage_ru = "done", utcnow(), utcnow(), 100, "report", "Готово"
        n = len([1 for _ in (await db.execute(select(HuntHit.id).where(HuntHit.job_id == job.id))).all()])
        job.findings_n = n
        sink.add("info", "results", "", f"Режим «По данным KSC»: сетевая проверка не выполнялась; найдено компьютеров: {n}", engine="scanner", kind="step")
        job.stages = {"results": {"ru": "Результаты", "state": "done", "note": f"найдено: {n}"}}
        job.diag = {"reasons": [], "skipped": {"сетевая проверка": "режим «По данным KSC»"}, "completeness": "ok", "no_version": 0}
    db.add_all(sink._buf)  # noqa: SLF001
    await db.flush()
    return job


def _ksc_plan(plan: T.Plan) -> T.Plan:
    """Только для проверки параметров: в режиме «По данным KSC» сетевой план не нужен, задание создаётся без адресов (без PtHost)."""
    p = T.Plan()
    p.addresses = [plan.addresses[0]] if plan.addresses else ["192.0.2.1"]
    return p


async def _ksc_stage(db: AsyncSession, app, job: PtJob, crits: list[dict], hunt: dict, sink: D.Sink) -> None:
    """Чтение реестра программ KSC: совпавшие компьютеры сохраняются сразу, с возрастом данных."""
    from ..models import KscSource  # noqa: PLC0415

    ids = [uuid.UUID(s) for s in hunt.get("source_ids", [])]
    if not ids:
        ids = list((await db.execute(select(KscSource.id).where(KscSource.is_active.is_(True)))).scalars())
    srcs = [s for s in (await db.execute(select(KscSource).where(KscSource.id.in_(ids)))).scalars()]
    total = 0
    for src in srcs:
        for c in crits:
            if not c.get("catalog"):
                continue
            try:
                rows, info = await asyncio.wait_for(K.inventory(app, src, c, active_days=hunt["activity_days"]), 180)
            except Exception as exc:  # noqa: BLE001 — недоступный источник не отменяет остальные
                sink.add("warn", "targets", "", f"KSC «{src.name}»: данные о программах не получены ({c['title'][:60]}) — {type(exc).__name__}: {str(exc)[:160]}", engine="scanner", incomplete=True, kind="problem", retry="safe")
                job.errors_n += 1
                continue
            for r in rows:
                st, note = K.status_of(c, r)
                at = info.get("fetched_at") or utcnow()
                db.add(HuntHit(job_id=job.id, crit_key=c["key"], vuln_key=c.get("cve", ""), ip=r["ip"] or "", source_id=src.id, host_id=int(r["host_id"]), host_name=(r["name"] or "")[:300], os=(r["os"] or "")[:200], group_name=(r["group"] or "")[:300],
                               last_connected=r["last_connected"], product=r["app_name"][:200], version=(r["app_version"] or "")[:120], status=st, basis="ksc", data_at=at,
                               evidence=[RS.ev("ksc", f"KSC «{src.name}»: установленный продукт {r['app_name']}, версия {r['app_version'] or 'не указана'}, сведения получены {at:%d.%m.%Y}" + (f". {note}" if note else ""), at)]))
            total += len(rows)
            sink.add("info", "targets", "", f"KSC «{src.name}»: «{c['title'][:60]}» — компьютеров с продуктом: {len(rows)}", engine="scanner", kind="step")
    await db.flush()
    if total:
        await RS.finalize(db, job.id)
