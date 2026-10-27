"""Быстрый отчёт «Сводка инфраструктуры» — то, что показывает главная страница: активные компьютеры за выбранный период, серверы и станции, защита, лицензии, источники данных.
Условия те же, что на странице (источники, период, показатель); при выбранном показателе подробный отчёт содержит полный список его устройств. Числа считаются теми же
предикатами (`overview.calc`), что и страница и боковая панель, поэтому совпадают с ними."""
from __future__ import annotations

from sqlalchemy import select

from ..ksc.driver import KscError, SourceClient
from ..models import KscSource
from ..overview import calc as C
from ..overview.service import DB_METRICS, _db_hosts, _scope, licenses_block
from .quick import Ctx, col, metric

HOST_COLS = [col("source", "Источник"), col("name", "Компьютер"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("kind_ru", "Тип ОС"), col("group", "Группа администрирования"),
             col("last_connected", "Последнее подключение к KSC (UTC)", "date"), col("days", "Суток с подключения", "num"), col("av_ru", "Защитный продукт"), col("rtp_ru", "Постоянная защита"),
             col("bases", "Базы (UTC)", "date"), col("info", "Сведения об устройстве обновлены (UTC)", "date")]
KIND_RU = {"server": "сервер", "workstation": "рабочая станция", "other": "не определён"}
SRC_COLS = [col("name", "Источник"), col("total", "Всего в KSC", "num"), col("active", "Активные", "num"), col("servers", "Серверы", "num"), col("workstations", "Рабочие станции", "num"),
            col("other_os", "Тип не определён", "num"), col("protected", "Защищены", "num"), col("no_av", "Без защиты", "num"), col("license", "Лицензии: использовано / лимит"), col("synced", "Данные получены (UTC)", "date")]
PERIOD_COLS = [col("days", "Период, сут", "num"), col("connected", "Подключались к KSC", "num"), col("visible", "Видны в сети", "num"), col("servers", "Серверы", "num"), col("workstations", "Станции", "num"),
               col("av_installed", "Защита установлена", "num"), col("av_running", "Защита работает", "num")]
LIC_COLS = [col("product", "Продукт"), col("kind", "Тип"), col("limit", "Лимит", "num"), col("used", "Использовано", "num"), col("free", "Свободно", "num"), col("expires", "Срок действия (UTC)", "date"),
            col("state_ru", "Состояние"), col("scope", "Принадлежность"), col("sources", "Источники"), col("basis", "Данные")]
STATE_RU = {"active": "действует", "expiring": "скоро истекает", "expired": "истекла", "unknown": "срок не указан"}


def _lic_rows(groups: list[dict]) -> list[dict]:
    out = []
    for g in groups:
        out.append({"product": g["product"], "kind": g["kind"], "limit": g["limit"], "used": g["used"], "free": g["free"], "expires": g["expires_at"], "state_ru": STATE_RU.get(g["state"], g["state"]),
                    "scope": "общий пул" if g["shared"] else "отдельный источник", "sources": "; ".join(s["name"] for s in g["sources"]),
                    "basis": "внесено вручную" if g["origin"] == ["manual"] else "из KSC" if g["origin"] == ["ksc"] else "из KSC и вручную"})
    return out


async def build_overview(client: SourceClient | None, p: dict, ctx: Ctx) -> dict:
    if ctx.sm is None or ctx.records_for is None:
        raise KscError("params", "Сводка недоступна: нет доступа к данным источников")
    days = int(p.get("days") or 30)
    only = p.get("metric") or ""
    if only and only not in C.METRICS and only not in DB_METRICS:
        raise KscError("params", "Неизвестный показатель главной")
    async with ctx.sm() as db:
        srcs = list((await db.execute(select(KscSource).where(KscSource.id.in_(list(ctx.source_ids or [ctx.source_id])), KscSource.is_active.is_(True)).order_by(KscSource.position, KscSource.name))).scalars())
        scope, skipped = _scope(srcs)
        lic = await licenses_block(db, scope)
    tot = {k: 0 for k in C.METRICS}
    rows, hosts, errors = [], [], []
    periods = {d: {"days": d, "connected": 0, "visible": 0, "servers": 0, "workstations": 0, "av_installed": 0, "av_running": 0} for d in C.PERIODS}
    for i, s in enumerate(scope):
        ctx.progress(f"источник {i + 1} из {len(scope)}: {s.name}")
        try:
            recs, at = await ctx.records_for(s)
        except KscError as exc:
            errors.append(f"{s.name}: {exc.message}")
            rows.append({"name": s.name, "synced": None})
            continue
        sm = C.summarize(recs, days, ctx.now)
        for k in C.METRICS:
            tot[k] += sm[k]
        for pr in sm["periods"]:
            for k in pr:
                if k != "days":
                    periods[pr["days"]][k] += pr[k]
        lb = lic["by_source"].get(str(s.id)) or {}
        rows.append({"name": s.name, **{k: sm[k] for k in ("total", "active", "servers", "workstations", "other_os", "protected", "no_av")},
                     "license": (f"{lb['used'] if lb.get('used') is not None else '—'} / {lb['limit']}" + (f" (свободно {lb['free']})" if lb.get("free") is not None else "") if lb.get("limit") is not None else "нет данных"), "synced": at})
        if p.get("detail") != "summary":
            for r in ([] if only in DB_METRICS else C.pick(recs, only or "active", days, ctx.now)):
                av = r.get("av") or {}
                hosts.append({"source": s.name, "name": r["name"], "ip": r["ip"], "os": r["os"], "kind_ru": KIND_RU[C.kind_of(r)], "group": r["group"], "last_connected": r["last_connected"],
                              "days": r["days_since_connection"], "av_ru": av.get("product") or "нет", "rtp_ru": r.get("rtp_label") or "", "bases": av.get("bases"), "info": r.get("last_info_update")})
        if len(hosts) > ctx.max_rows:
            raise KscError("too_many_rows", f"Устройств больше предела отчёта ({ctx.max_rows}): сузьте условия или повысьте предел в «Администрирование → Общие настройки»")
    list_n = tot[only] if only in C.METRICS else tot["active"]
    if only in DB_METRICS:                                              # устройства из подготовленных данных зон и результатов EOL (не из записей защиты)
        async with ctx.sm() as db:
            list_n = int((await _db_hosts(db, scope, only, days, "", "name", False, 0, 1))["total"])
            offset = 0
            while p.get("detail") != "summary":
                page = await _db_hosts(db, scope, only, days, "", "name", False, offset, 500)
                for h in page["items"]:
                    hosts.append({"source": h["source"], "name": h["name"], "ip": h["ip"], "os": h["os"], "kind_ru": "", "group": h["group"], "last_connected": h["last_connected"], "days": h["days_since_connection"],
                                  "av_ru": "", "rtp_ru": "", "bases": None, "info": None})
                offset += 500
                if offset >= page["total"] or len(hosts) > ctx.max_rows:
                    break
    lt = lic["totals"]
    metrics = [metric("hosts", (C.METRICS.get(only) or (DB_METRICS.get(only, ""),))[0] if only else f"Активные компьютеры за {days} сут", list_n, "в списке отчёта" if only else "Агент подключался к Серверу администрирования; основной показатель", "ok" if not only else ""),
               metric("active", f"Активные компьютеры за {days} сут", tot["active"], "Агент подключался к Серверу администрирования; основной показатель", "ok"),
               metric("servers", "Активные серверы", tot["servers"]), metric("workstations", "Активные рабочие станции", tot["workstations"]),
               metric("other_os", "Тип ОС не определён", tot["other_os"], "например, Linux без указания редакции в KSC"),
               metric("inactive", "Неактивные компьютеры", tot["inactive"], f"без связи с KSC дольше {days} сут", "warn" if tot["inactive"] else ""), metric("total", "Всего объектов в KSC", tot["total"]),
               metric("protected", "Защищены", tot["protected"], "защита работает, базы не старше 3 сут"), metric("no_av", "Без защиты", tot["no_av"], "", "danger" if tot["no_av"] else "ok"),
               metric("rtp_off", "Защита не работает", tot["rtp_off"], "", "danger" if tot["rtp_off"] else "ok"), metric("bases_old", "Устаревшие базы", tot["bases_old"]),
               metric("stale_info", "Сведения давно не поступали", tot["stale_info"], f"активные, сведения об устройстве не обновлялись дольше {C.STALE_DAYS} сут"),
               metric("lic_limit", "Лицензий всего", lt["limit"] if lt["limit"] is not None else "нет данных", "общие пулы считаются один раз"),
               metric("lic_used", "Лицензий использовано", lt["used"] if lt["used"] is not None else "нет данных", "по данным KSC или внесённым вручную"),
               metric("lic_free", "Лицензий свободно", lt["free"] if lt["free"] is not None else "нет данных")]
    cond = [{"label": "Источники", "text": ", ".join(s.name for s in scope) or "—"}, {"label": "Период активности", "text": f"{days} сут (Агент подключался к KSC)"}]
    if only:
        cond.append({"label": "Показатель", "text": (C.METRICS.get(only) or (DB_METRICS[only],))[0]})
    notes = ["Активный компьютер — Агент подключался к Серверу администрирования за выбранный период (tmLastNagentConnected). «Виден в сети», «Агент установлен», «защита работает» и «лицензия» считаются отдельно и активность не заменяют.",
             "Linux в KSC приходит как «Linux» без редакции, поэтому такие компьютеры показаны отдельно («тип не определён»), а не причислены к серверам или станциям."]
    notes += [f"Источник «{n}» — повторное подключение «{o}», в итоги не входит." for n, o in [(s.name, skipped[str(s.id)]) for s in srcs if str(s.id) in skipped]]
    notes += [f"Нет данных по источнику — {e}" for e in errors]
    if lt["limit"] is None:
        notes.append("Сведений о лицензиях нет: KSC их не передал или они не прочитаны; администратор может внести их вручную («Администрирование → Лицензии»).")
    return {"title": "Сводка инфраструктуры", "subtitle": f"Активные компьютеры за {days} сут, защита и лицензии", "conditions": cond, "metrics": metrics, "severity": None, "notes": notes,
            "tables": [
                       {"id": "hosts", "title": (C.METRICS.get(only or "active") or (DB_METRICS.get(only, ""),))[0] + " (список)", "columns": HOST_COLS, "rows": hosts, "note": "Одна строка — компьютер."},
                       {"id": "sources", "title": "Источники данных", "columns": SRC_COLS, "rows": rows, "note": "Одна строка — источник KSC."},
                       {"id": "periods", "title": "Активность по периодам", "columns": PERIOD_COLS, "rows": list(periods.values()), "note": "Периоды вложены: подключавшиеся за 7 сут входят в 30 и т. д."},
                       {"id": "licenses", "title": "Лицензии Kaspersky", "columns": LIC_COLS, "rows": _lic_rows(lic["groups"]), "note": "Общий пул считается один раз: лимит общий, использование — сумма по серверам."}]}
