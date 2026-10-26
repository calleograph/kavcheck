"""Быстрый отчёт «EOL в инфраструктуре»: программы и операционные системы, у которых закончилась или заканчивается поддержка производителя (по базе endoflife.date), и устройства, на которых они найдены.
Данные берутся из готовых результатов KAV Checker (PostgreSQL), к KSC отчёт не обращается. Несколько источников — в одном отчёте, у каждой строки указан источник; в таблице устройств список полный (без сокращений «+N»)."""
from __future__ import annotations

from sqlalchemy import and_, func, or_, select

from ..eol import read as R
from ..ksc.driver import KscError, SourceClient
from ..models import EolFinding, EolHost, KscSource, ZcHost, ZcHostZone, ZcSource
from ..search import any_of
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
            agg = await R.zone_agg(db, zone, sids)
            findings = [f for f in (await db.execute(select(EolFinding).where(*cond).order_by(R.SEV_ORDER.desc(), EolFinding.title))).scalars() if (f.source_id, f.kind, f.subject, f.version) in agg]
            counts = {(f.source_id, f.kind, f.subject, f.version): agg[(f.source_id, f.kind, f.subject, f.version)] for f in findings}
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
        est = sum(r["hosts"] if p.get("include_inactive") else r["hosts_active"] for r in rows)         # строк в таблице устройств (устройство × проблема)
        if p.get("devices", True) and est > ctx.max_rows:
            raise KscError("too_many_rows", f"Строк в таблице устройств около {est}, предел отчёта — {ctx.max_rows}: отключите таблицу устройств, выберите зону, состояние или критичность либо повысьте предел в «Администрирование → Общие настройки»")
        if p.get("devices", True):
            # одним потоковым запросом: устройства находок + данные подготовленных зон (только нужные поля, без загрузки всех компьютеров источника)
            J = (EolHost.__table__.join(EolFinding.__table__, and_(EolFinding.source_id == EolHost.source_id, EolFinding.kind == EolHost.kind, EolFinding.subject == EolHost.subject, EolFinding.version == EolHost.version))
                 .outerjoin(ZcSource.__table__, and_(ZcSource.source_id == EolHost.source_id, ZcSource.gen > 0))
                 .outerjoin(ZcHost.__table__, and_(ZcHost.source_id == EolHost.source_id, ZcHost.host_id == EolHost.host_id, ZcHost.gen == ZcSource.gen)))
            dcond = list(cond)
            if zone:
                J = J.join(ZcHostZone.__table__, and_(ZcHostZone.source_id == EolHost.source_id, ZcHostZone.host_id == EolHost.host_id, ZcHostZone.gen == ZcSource.gen, ZcHostZone.zone_id == zone))
            if not p.get("include_inactive"):
                dcond.append(or_(ZcHost.active.is_(True), ZcHost.host_id.is_(None)))
            q = (select(EolHost.source_id, EolHost.host_id, EolFinding.severity, EolFinding.kind, EolFinding.title, EolFinding.version, EolFinding.status, EolFinding.eol_from, ZcHost.host_id.label("zh"), ZcHost.name,
                        ZcHost.os, ZcHost.last_connected, ZcHost.active, ZcHost.data["ip"].as_string().label("ip"), ZcHost.data["group"].as_string().label("grp"), ZcHost.data["zones"].as_json().label("zones"))
                 .select_from(J).where(*dcond).order_by(R.SEV_ORDER.desc(), func.lower(ZcHost.name), EolFinding.title, EolHost.host_id))
            async for r in await db.stream(q.execution_options(yield_per=5000)):
                hid, known = int(r.host_id), r.zh is not None
                devices.append({"severity": r.severity, "severity_ru": R.SEV_RU.get(r.severity, ""), "source": names.get(r.source_id, ""), "name": (r.name if known else f"#{hid}"), "ip": r.ip or "",
                                "os": (r.os if known else "") or "", "group": r.grp or "", "zones": ", ".join(str(z) for z in (r.zones or [])), "last_connected": r.last_connected if known else None,
                                "active": ("да" if r.active else "нет") if known else "нет данных", "kind_ru": R.KIND_RU.get(r.kind, r.kind), "title": r.title, "version": r.version,
                                "status_ru": R.STATUS_RU.get(r.status, r.status), "eol_from": r.eol_from, "host_key": (str(r.source_id), hid)})
    rank = {"critical": 3, "high": 2, "warning": 1}
    worst: dict[tuple, int] = {}                                              # у устройства учитывается наивысшая критичность: сумма по уровням равна числу устройств
    for r in devices:
        worst[r["host_key"]] = max(worst.get(r["host_key"], 0), rank.get(r["severity"], 0))
    level = {k: sum(1 for v in worst.values() if v == rank[k]) for k in rank}
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
