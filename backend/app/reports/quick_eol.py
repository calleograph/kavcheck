"""Быстрый отчёт «EOL в инфраструктуре»: программы и операционные системы, у которых закончилась или заканчивается поддержка производителя (по базе endoflife.date), и устройства, на которых они найдены.
Данные берутся из готовых результатов KAV Checker (PostgreSQL), к KSC отчёт не обращается. Несколько источников — в одном отчёте, у каждой строки указан источник; в таблице устройств список полный (без сокращений «+N»)."""
from __future__ import annotations

from sqlalchemy import and_, select

from ..eol import read as R
from ..ksc.driver import KscError, SourceClient
from ..models import EolFinding, EolHost, KscSource, ZcHost, ZcSource
from ..search import any_of
from ..zones import zread as ZR
from .quick import Ctx, col, metric

SEV_LABEL = {"critical": "Критическая", "high": "Высокая", "warning": "Предупреждение"}
FINDING_COLS = [col("severity_ru", "Критичность", "sev"), col("source", "Источник"), col("kind_ru", "Тип"), col("title", "Программа или ОС"), col("publisher", "Производитель"), col("version", "Версия", "mono"),
                col("eol_label", "Продукт endoflife.date"), col("eol_release", "Ветка", "mono"), col("status_ru", "Состояние поддержки"), col("eol_from", "Стандартная поддержка до", "date"),
                col("eoes_from", "Расширенная поддержка до", "date"), col("confirmed_ru", "Подтверждено"), col("condition", "Пояснение"), col("hosts", "Устройств", "num"), col("hosts_active", "Из них активных", "num"),
                col("link", "Ссылка на политику поддержки")]
DEVICE_COLS = [col("severity_ru", "Критичность", "sev"), col("source", "Источник"), col("name", "Устройство"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("group", "Группа администрирования"),
               col("zones", "Зоны ответственности"), col("last_connected", "Последнее подключение к KSC (UTC)", "date"), col("active", "Связь за период"), col("kind_ru", "Тип"), col("title", "Программа или ОС"),
               col("version", "Версия", "mono"), col("status_ru", "Состояние поддержки"), col("eol_from", "Стандартная поддержка до", "date")]


async def build_eol(client: SourceClient, p: dict, ctx: Ctx) -> dict:
    if ctx.sm is None or not (ctx.source_ids or ctx.source_id):
        raise KscError("params", "Отчёт EOL недоступен: нет доступа к локальной базе")
    sids = list(ctx.source_ids or [ctx.source_id])
    statuses = [s for s in (p.get("statuses") or ["eol", "extended", "upcoming"]) if s in R.PROBLEM_STATUSES]
    kinds = p.get("kinds") or ["app", "os"]
    async with ctx.sm() as db:
        names = {s.id: s.name for s in (await db.execute(select(KscSource).where(KscSource.id.in_(sids)))).scalars()}
        cond = [EolFinding.source_id.in_(sids), EolFinding.status.in_(statuses), EolFinding.kind.in_(kinds)]
        if p.get("publisher"):
            cond.append(any_of(p["publisher"], EolFinding.publisher))
        if p.get("q"):
            cond.append(any_of(p["q"], EolFinding.title, EolFinding.publisher, EolFinding.eol_product, EolFinding.subject))
        if p.get("severity"):
            cond.append(EolFinding.severity == p["severity"])
        zone = p.get("zone") or ""
        counts: dict[tuple, tuple[int, int]] = {}
        if zone:                                        # отчёт по зоне: считаются только устройства зоны (по подготовленным данным зон)
            zsub = R.zone_agg(zone, sids)
            q = select(EolFinding, zsub.c.n, zsub.c.na).join(zsub, and_(zsub.c.sid == EolFinding.source_id, zsub.c.k == EolFinding.kind, zsub.c.s == EolFinding.subject, zsub.c.v == EolFinding.version))
            res = (await db.execute(q.where(*cond).order_by(R.SEV_ORDER.desc(), EolFinding.title))).all()
            findings = [r[0] for r in res]
            counts = {(r[0].source_id, r[0].kind, r[0].subject, r[0].version): (int(r.n), int(r.na)) for r in res}
        else:
            findings = (await db.execute(select(EolFinding).where(*cond).order_by(R.SEV_ORDER.desc(), EolFinding.title))).scalars().all()
        n_of = lambda f: counts.get((f.source_id, f.kind, f.subject, f.version), (f.hosts_all, f.hosts_active))  # noqa: E731
        if not p.get("include_inactive"):
            findings = [f for f in findings if n_of(f)[1] > 0]
        labels = await R.labels_for(db, {f.eol_product for f in findings if f.eol_product})
        rows = []
        for f in findings:
            o = R.finding_out(f, *n_of(f), names, labels)
            o["confirmed_ru"] = "да" if f.confirmed else "нет: зависит от подписки или договора, либо соответствие по названию"
            rows.append(o)
        devices: list[dict] = []
        if p.get("devices", True):
            by_key = {(f.source_id, f.kind, f.subject, f.version): f for f in findings}
            for sid in sids:
                keys = {k[1:]: f for k, f in by_key.items() if k[0] == sid}
                if not keys:
                    continue
                in_zone = await ZR.host_ids_in_zone(db, sid, zone) if zone else None
                ids = (await db.execute(select(EolHost.kind, EolHost.subject, EolHost.version, EolHost.host_id).where(EolHost.source_id == sid))).all()
                gen = (await db.get(ZcSource, sid))
                hosts = {}
                if gen is not None and gen.gen:
                    for h in (await db.execute(select(ZcHost.host_id, ZcHost.name, ZcHost.os, ZcHost.last_connected, ZcHost.active, ZcHost.data).where(ZcHost.source_id == sid, ZcHost.gen == gen.gen))).all():
                        hosts[int(h.host_id)] = h
                for kind, subject, version, hid in ids:
                    f = keys.get((kind, subject, version))
                    h = hosts.get(int(hid))
                    if f is None or (in_zone is not None and int(hid) not in in_zone) or (h is not None and not h.active and not p.get("include_inactive")):
                        continue
                    d = (h.data or {}) if h is not None else {}
                    devices.append({"severity": f.severity, "severity_ru": R.SEV_RU.get(f.severity, ""), "source": names.get(sid, ""), "name": (h.name if h is not None else f"#{hid}"), "ip": d.get("ip", ""),
                                    "os": (h.os if h is not None else ""), "group": d.get("group", ""), "zones": ", ".join(str(z) for z in d.get("zones") or []), "last_connected": h.last_connected if h is not None else None,
                                    "active": ("да" if h.active else "нет") if h is not None else "нет данных", "kind_ru": R.KIND_RU.get(f.kind, f.kind), "title": f.title, "version": f.version,
                                    "status_ru": R.STATUS_RU.get(f.status, f.status), "eol_from": f.eol_from, "host_key": (str(sid), int(hid))})
            devices.sort(key=lambda r: (-{"critical": 3, "high": 2, "warning": 1}.get(r["severity"], 0), r["name"].lower(), r["title"].lower()))
    level = {k: len({r["host_key"] for r in devices if r["severity"] == k}) for k in ("critical", "high", "warning")}
    uniq = {r.pop("host_key") for r in devices}
    metrics = [metric("hosts", "Устройств с проблемой поддержки", len(uniq), "устройство с несколькими проблемами считается один раз", "danger" if uniq else "ok"),
               metric("items", "Программ и ОС (версий)", len(rows)), metric("eol", "Стандартная поддержка закончилась", sum(1 for r in rows if r["status"] == "eol"), "", "danger" if any(r["status"] == "eol" for r in rows) else "ok"),
               metric("extended", "Только расширенная (платная) поддержка", sum(1 for r in rows if r["status"] == "extended"), "не подтверждено: зависит от подписки или договора"),
               metric("upcoming", "Скоро заканчивается", sum(1 for r in rows if r["status"] == "upcoming"))]
    notes = ["Сроки поддержки взяты из базы endoflife.date (https://endoflife.date). «EOL» присваивается, только когда закончилась стандартная поддержка безопасности; расширенная поддержка "
             "(платная или по договору) показывается отдельно и не считается подтверждённой. Продукты без дат в базе в отчёт не попадают."]
    if p.get("devices", True) and not devices and rows:
        notes.append("Список устройств пуст: подготовленные данные источника ещё не рассчитаны или устройства неактивны за период.")
    return {"title": "EOL в инфраструктуре", "subtitle": "Программы и операционные системы с закончившейся или приближающейся датой окончания поддержки", "conditions": [
        {"label": "Источники", "text": ", ".join(names.get(s, "?") for s in sids)}, {"label": "Состояние", "text": ", ".join(R.STATUS_RU.get(s, s) for s in statuses)}],
        "metrics": metrics, "severity": {"title": "Устройства по наивысшей критичности", "levels": [{"key": k, "label": SEV_LABEL[k], "value": level[k], "hint": ""} for k in ("critical", "high", "warning")]},
        "notes": notes, "tables": [{"id": "rows", "title": "Программы и ОС с EOL", "columns": FINDING_COLS, "rows": rows,
                                    "note": "Одна строка — программа (версия каталога) или ОС источника. «Устройств» — все, «Из них активных» — со связью за период."},
                                   {"id": "devices", "title": "Устройства", "columns": DEVICE_COLS, "rows": devices, "note": "Одна строка — устройство × программа или ОС. Список полный."}]}
