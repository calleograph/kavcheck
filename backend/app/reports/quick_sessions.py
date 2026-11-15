"""Быстрый отчёт «Сейчас в системе»: пользователи в текущем списке вошедших KSC по одному или нескольким источникам (живой запрос, как на вкладке).
Каждый источник читается своим клиентом параллельно; ошибка одного источника попадает в примечания, остальные данные не теряются."""
from __future__ import annotations

from sqlalchemy import select

from ..devices import sessions as SN
from ..models import KscSource
from .quick import Ctx, col, metric

NOTE = ("Список вошедших — из KSC в момент формирования: пользователи в ТЕКУЩЕМ списке вошедших (обновляется при синхронизации Агента администрирования). "
        "Время входа KSC не хранит. «В сети» — компьютер виден KSC в момент формирования.")


async def build_sessions(_client, p: dict, ctx: Ctx) -> dict:
    async with ctx.sm() as db:
        srcs = [s for s in (await db.execute(select(KscSource).where(KscSource.id.in_(ctx.source_ids or [ctx.source_id]), KscSource.is_active.is_(True)))).scalars().all()]
        masks = list((await ctx.settings.get(db, "devices")).service_masks) if ctx.settings is not None else []  # type: ignore[attr-defined]
    ctx.progress(f"запрос к KSC: источников {len(srcs)}")
    rows, states = await SN.fetch_many(srcs, ctx.client_for, user_q=p.get("q") or "", host_q=p.get("host") or "", online_only=bool(p.get("online_only", True)),
                                       show_service=bool(p.get("show_service")), masks=masks, top=min(int(ctx.max_rows), 20000))
    for r in rows:
        r["online_ru"] = "в сети" if r["online"] else ("не в сети" if r["online"] is False else "нет данных")
        r["account"] = f"{r['domain']}\\{r['login']}" if r["domain"] and r["domain"] != "локальная" else r["login"]
    notes = [NOTE] + [f"{s['source']}: не прочитан ({s['error']})." for s in states if s["error"]] + \
            [f"{s['source']}: показаны первые {s['rows']} записей — уточните условия." for s in states if s["more"]]
    conds = [{"label": "Пользователь", "text": p.get("q") or "любой"}, {"label": "Компьютер", "text": p.get("host") or "любой"},
             {"label": "Компьютеры", "text": "только в сети" if p.get("online_only", True) else "все из списка вошедших"},
             {"label": "Служебные учётные записи", "text": "показаны" if p.get("show_service") else "скрыты"}, {"label": "Источники KSC", "text": ", ".join(s.name for s in srcs)}]
    cols = [col("account", "Учётная запись"), col("user_name", "Пользователь"), col("host", "Компьютер"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("group", "Группа администрирования"),
            col("online_ru", "В сети сейчас"), col("last_connected", "Последнее подключение к KSC (UTC)", "date"), col("source", "Источник KSC")]
    metrics = [metric("users", "Пользователей", len({(r["login"] or "").lower() for r in rows}), "уникальных учётных записей"), metric("hosts", "Компьютеров", len({(r["source_id"], r["host_id"]) for r in rows})),
               metric("rows", "Сеансов (пользователь × компьютер)", len(rows)), metric("sources", "Источников прочитано", sum(1 for s in states if not s["error"]), f"из {len(states)}")]
    return {"title": "Сейчас в системе" + (f": {p['q']}" if p.get("q") else ""), "subtitle": "Пользователи в текущем списке вошедших KSC", "conditions": conds, "metrics": metrics,
            "notes": notes, "tables": [{"id": "sessions", "title": "Вошли сейчас", "columns": cols, "rows": rows}]}
