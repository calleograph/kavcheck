"""Отчёт «Результаты целевого поиска уязвимостей» (CVE Hunt): компактный перечень затронутых компьютеров по выбранным критериям.

Главная таблица — компьютер (первый столбец), пользователь, зона ответственности, IP, продукт, версия, результат, основание. Длинные описания CVE, CVSS-векторы и ссылки не включаются.
Статусы выбираются при формировании (по умолчанию «Подтверждено» и «Вероятно»); не затронутые компьютеры в основной отчёт не входят — они в отдельной таблице охвата. Отсутствие совпадения при сетевом
сканировании не доказывает отсутствия программного обеспечения."""
from __future__ import annotations

import uuid
from collections import Counter

from sqlalchemy import func, select

from ..hunt import criteria as C
from ..hunt import results as RS
from ..ksc.driver import KscError, SourceClient
from ..models import HuntHit, PtHost, PtJob
from .quick import Ctx, col, metric

LIMIT = 20000
MAIN_COLS = [col("host", "Имя компьютера"), col("user", "Пользователь / владелец"), col("zone", "Зона ответственности"), col("ip", "IP-адрес", "mono"), col("product", "Продукт"), col("version", "Обнаруженная версия", "mono"),
             col("status_ru", "Результат"), col("evidence", "Основание обнаружения"), col("criterion", "Критерий (CVE / продукт)", "mono"), col("port", "Порт", "num"), col("os", "ОС"), col("basis_ru", "Источник данных"),
             col("source", "Источник KSC"), col("last_connected", "Последняя связь с KSC (UTC)", "date"), col("data_at", "Данные получены (UTC)", "date"), col("note", "Примечание")]
COV_COLS = [col("ip", "IP-адрес", "mono"), col("state_ru", "Итог проверки"), col("ports", "Открытых портов", "num"), col("error", "Причина")]
STATE_RU = {"done": "проверен", "down": "не отвечает", "error": "не удалось проверить", "pending": "не проверялся", "up": "не завершён", "ports": "не завершён", "svc": "не завершён", "chk": "не завершён"}
MODE_RU = {"ksc": "по данным KSC", "network": "сетевая проверка", "combined": "комбинированный (KSC и сеть)"}
DEFAULT_COLS = ["host", "user", "zone", "ip", "product", "version", "status_ru", "evidence"]       # обязательный состав отчёта; остальное — по выбору столбцов (при нескольких критериях добавляется «Критерий»)
DISCLAIMER = "Отсутствие совпадения при сетевом сканировании не доказывает отсутствие уязвимого программного обеспечения: продукт может не раскрывать версию, работать без открытого порта или за другим сервисом."


async def build_hunt(client: SourceClient | None, p: dict, ctx: Ctx) -> dict:
    if ctx.sm is None:
        raise KscError("params", "Отчёт недоступен: нет доступа к локальной базе")
    try:
        job_id = uuid.UUID(str(p.get("job_id")))
    except ValueError:
        raise KscError("params", "Выберите задание целевого поиска") from None
    statuses = [s for s in dict.fromkeys(p.get("statuses") or ["confirmed", "probable"]) if s in ("confirmed", "probable", "needs_check")] or ["confirmed", "probable"]
    async with ctx.sm() as db:
        job = await db.get(PtJob, job_id)
        if job is None or job.profile != "hunt":
            raise KscError("params", "Задание целевого поиска не найдено")
        h = (job.options or {}).get("hunt", {})
        w = [HuntHit.job_id == job_id, HuntHit.status.in_(statuses)]
        if p.get("zone"):
            w.append(HuntHit.zone == p["zone"])
        if p.get("q"):
            from ..search import any_of  # noqa: PLC0415

            cond = any_of(p["q"], HuntHit.host_name, HuntHit.ip, HuntHit.user_name, HuntHit.zone, HuntHit.product, HuntHit.version)
            if cond is not None:
                w.append(cond)
        rank = {k: v for k, v in RS.RANK.items()}
        rows = (await db.execute(select(HuntHit).where(*w).order_by(func.lower(HuntHit.host_name), HuntHit.ip).limit(LIMIT))).scalars().all()
        rows.sort(key=lambda r: (rank.get(r.status, 9), (r.host_name or r.ip).lower(), r.ip))
        allc = {k: n for k, n in (await db.execute(select(HuntHit.status, func.count()).where(HuntHit.job_id == job_id).group_by(HuntHit.status))).all()}
        hosts = (await db.execute(select(PtHost.ip, PtHost.state, PtHost.ports_n, PtHost.error).where(PtHost.job_id == job_id).order_by(PtHost.ip).limit(LIMIT))).all() if p.get("coverage") else []
        checked = int((await db.execute(select(func.count()).select_from(PtHost).where(PtHost.job_id == job_id, PtHost.state.in_(("done", "down"))))).scalar_one())
        from ..models import KscSource  # noqa: PLC0415

        names = {s.id: s.name for s in (await db.execute(select(KscSource))).scalars()}
    crit_title = {c["key"]: c["title"] for c in h.get("criteria", [])}
    out = []
    for r in rows:
        ev = r.evidence[0]["text"] if r.evidence else ""
        out.append({"host": r.host_name or (f"{r.ip} (нет в KSC)" if r.ip else "—"), "user": r.user_name or "Не определён", "zone": r.zone or "Не назначена", "ip": r.ip, "product": r.product, "version": r.version or "не определена",
                    "status": r.status, "status_ru": RS.STATUS_RU[r.status], "evidence": ev, "criterion": r.vuln_key or crit_title.get(r.crit_key, r.crit_key), "port": r.port, "os": r.os, "basis_ru": RS.BASIS_RU.get(r.basis, r.basis),
                    "source": names.get(r.source_id, "") if r.source_id else "", "last_connected": r.last_connected, "data_at": r.data_at,
                    "note": "; ".join(x for x in ["адрес совпал с несколькими устройствами KSC" if r.ambiguous else "", "версии в KSC и по сети различаются" if r.diff else ""] if x)})
    uniq = len({(r["ip"] or r["host"]) for r in out})
    cnt = Counter(r.status for r in rows)
    crit_lines = [f"{c['title']} — {C.describe_condition(c)}" for c in h.get("criteria", [])]
    unconfirmed = allc.get("needs_check", 0)
    incomplete = job.incomplete_n + job.errors_n
    cond = [{"label": "Задание", "text": job.title}, {"label": "Дата и время", "text": f"{(job.finished_at or job.created_at):%d.%m.%Y %H:%M} UTC"}, {"label": "Режим", "text": MODE_RU.get(h.get("mode"), "")},
            {"label": "Логика критериев", "text": "все выбранные критерии" if h.get("logic") == "all" else "любой из выбранных критериев"}, {"label": "Критерии и версии", "text": "; ".join(crit_lines) or "—"},
            {"label": "Область проверки", "text": f"адресов в задании: {job.targets_n}; TCP-порты: {', '.join(str(x) for x in h.get('ports', [])) or '—'}"},
            {"label": "Статусы в отчёте", "text": ", ".join(RS.STATUS_RU[s] for s in statuses)}]
    metrics = [metric("checked", "Проверено компьютеров", checked, "адресов, которые сканер просмотрел"), metric("matches", "Совпадений", len(out), f"уникальных компьютеров: {uniq}", "danger" if out else "ok"),
               metric("confirmed", "Подтверждено", cnt.get("confirmed", 0)), metric("probable", "Вероятно уязвимы", cnt.get("probable", 0)),
               metric("needs_check", "Требуют проверки (в задании)", unconfirmed, "не входят в отчёт, если статус не выбран", "warn" if unconfirmed else ""),
               metric("incomplete", "Не удалось проверить / неполные проверки", incomplete, "", "warn" if incomplete else "ok")]
    multi = len(h.get("criteria", [])) > 1
    keys = [k for k in (p.get("columns") or []) if any(c["key"] == k for c in MAIN_COLS)] or [*DEFAULT_COLS, *(["criterion"] if multi else [])]
    shown = [next(c for c in MAIN_COLS if c["key"] == k) for k in keys]
    tables = [{"id": "hits", "title": "Затронутые компьютеры", "columns": shown, "rows": out, "note": "Одна строка — компьютер и критерий. Сначала подтверждённые, затем вероятные; внутри — по имени компьютера."}]
    if p.get("coverage"):
        tables.append({"id": "coverage", "title": "Журнал охвата проверки", "columns": COV_COLS, "rows": [{"ip": ip, "state_ru": STATE_RU.get(st, st), "ports": n, "error": e or ""} for ip, st, n, e in hosts],
                       "note": "Все адреса задания, включая не затронутые: «проверен» означает, что сканер просмотрел выбранные порты."})
    notes = [DISCLAIMER, "Статус «Вероятно» — продукт и версия соответствуют условию, но дополнительные условия уязвимости не подтверждены. «Подтверждено» — только если безопасная проверка подтвердила проблему."]
    if len(rows) >= LIMIT:
        notes.append(f"В отчёт включены первые {LIMIT} записей.")
    return {"title": "Результаты целевого поиска уязвимостей", "subtitle": job.title, "conditions": cond, "metrics": metrics, "severity": None, "notes": notes, "tables": tables, "hunt": True, "columns_all": [{"key": c["key"], "title": c["title"]} for c in MAIN_COLS],
            "hunt_statuses": statuses, "hunt_filters": [{"key": k, "label": RS.STATUS_RU[k], "n": cnt.get(k, 0)} for k in statuses]}
