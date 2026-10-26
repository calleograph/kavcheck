"""Диагностика EOL только для чтения (внутренняя база KAV Checker; к KSC не обращается, ничего не записывает и не удаляет).
    python -m app.tools.eol_diag [--source ИМЯ] [--json]

По каждому источнику показывает: состояние расчёта (последняя попытка, ошибка и её давность — свежая она или осталась с прошлых попыток), будет ли расчёт запущен и если нет — почему
(каталог не построен, пауза после ошибки, нет сигнала worker), повторы версий в каталоге, находки, которые расчёт построил бы по каталогу сейчас и сколько ключей пришлось бы объединить,
превышения длин столбцов, число сохранённых находок. Для проверки на рабочем сервере: ничего не меняет, безопасно запускать в рабочее время."""
from __future__ import annotations

import argparse
import asyncio
import json
from collections import Counter
from datetime import date, datetime, timezone

from sqlalchemy import func, select

from ..config import get_settings
from ..db import create_engine, create_session_maker
from ..eol import compute as C
from ..eol.service import RETRY_AFTER
from ..models import CatalogProduct, CatalogState, EolFinding, EolState, KscSource, ServiceHeartbeat, utcnow


def _age(d: datetime | None) -> str:
    if d is None:
        return "—"
    s = int((utcnow() - d).total_seconds())
    return f"{d:%Y-%m-%d %H:%M:%S} UTC ({s // 3600} ч {s % 3600 // 60} мин назад)"


async def diagnose(sm, only: str = "") -> dict:
    out: dict = {"at": utcnow().isoformat(), "sources": []}
    async with sm() as db:
        hb = await db.get(ServiceHeartbeat, "worker")
        out["worker"] = {"heartbeat_age_s": int((utcnow() - hb.at).total_seconds()) if hb else None, "started_at": hb.started_at.isoformat() if hb and hb.started_at else None,
                         "eol_job": ((hb.data or {}).get("eol_job") if hb else None), "memory": ((hb.data or {}).get("resources") if hb else None)}
        srcs = (await db.execute(select(KscSource).order_by(KscSource.position))).scalars().all()
    for src in srcs:
        if only and only.lower() not in src.name.lower():
            continue
        async with sm() as db:
            st, cs = await db.get(EolState, src.id), await db.get(CatalogState, src.id)
            n_find = (await db.execute(select(func.count()).select_from(EolFinding).where(EolFinding.source_id == src.id))).scalar_one()
            dup = (await db.execute(select(func.count()).select_from(select(EolFinding.kind, EolFinding.subject, EolFinding.version).where(EolFinding.source_id == src.id)
                                                              .group_by(EolFinding.kind, EolFinding.subject, EolFinding.version).having(func.count() > 1).subquery()))).scalar_one()
            cat_n = (await db.execute(select(func.count()).select_from(CatalogProduct).where(CatalogProduct.source_id == src.id))).scalar_one()
            soon = 180
            cur = await C.current_inputs(db, src.id, date.today(), soon)
            stats = Counter()
            examples: list[str] = []
            async for row in await db.stream_scalars(select(CatalogProduct).where(CatalogProduct.source_id == src.id).execution_options(yield_per=200)):
                vs = row.versions or []
                merged = C.merge_versions(vs)
                if len(merged) < len(vs):
                    stats["products_with_repeated_versions"] += 1
                    stats["repeated_version_rows"] += len(vs) - len(merged)
                    if len(examples) < 3:
                        examples.append(f"{row.key[:50]}: {len(vs)} записей → {len(merged)}")
                if any(len(str(v.get("version") or "")) > 120 for v in vs):
                    stats["versions_over_120_chars"] += 1
                if len(row.key) > 160:
                    stats["keys_over_160_chars"] += 1
        planned = merged_keys = None
        try:
            _inputs, _idx, _win, found = await C.catalog_findings(sm, src, date.today(), soon)
            rows, info = C.merge_findings(found)
            planned, merged_keys = len(rows), info["merged_keys"]
        except Exception as exc:  # noqa: BLE001
            planned = f"не удалось построить: {type(exc).__name__}"
        why = []
        if cs is None or cs.status != "ready":
            why.append(f"каталог источника не построен (состояние: {cs.status if cs else 'нет'}) — расчёт не запускается, пока он не будет готов")
        if st is not None and st.error_at and utcnow() - st.error_at < RETRY_AFTER:
            why.append(f"пауза после ошибки ещё {int((RETRY_AFTER - (utcnow() - st.error_at)).total_seconds() // 60) + 1} мин")
        if st is not None and st.inputs and st.inputs == cur:
            why.append("исходные данные не менялись с последнего успешного расчёта")
        if out["worker"]["heartbeat_age_s"] is None or out["worker"]["heartbeat_age_s"] > 120:
            why.append("нет сигнала worker: расчёт некому запускать")
        item = {"source": src.name, "active": src.is_active, "catalog": {"status": cs.status if cs else None, "built_at": cs.built_at.isoformat() if cs and cs.built_at else None, "products": cat_n},
                "state": ({"computed_at": _age(st.computed_at), "attempt_at": _age(st.attempt_at), "error": st.error, "error_at": _age(st.error_at), "error_detail": st.error_detail, "running": bool(st.started_at),
                           "progress": st.progress, "diag": st.diag} if st else None),
                "will_run": not why, "why_not": why, "saved_findings": n_find, "duplicate_keys_in_db": dup,
                "catalog_checks": dict(stats), "examples": examples, "would_build": planned, "keys_to_merge": merged_keys}
        # «старая ошибка»: после неё была более поздняя попытка, но ни успеха, ни новой ошибки (процесс прерван), либо попыток не было вообще
        if st and st.error and st.app_version != get_settings().app_version:
            item["error_is_stale"] = f"ошибка записана версией {st.app_version or 'до 0.9.6'}, сейчас {get_settings().app_version}: после обновления новая попытка расчёта ещё не выполнялась (при запуске worker такая ошибка переносится в историю)"
        elif st and st.error and (not st.attempt_at or (st.error_at and st.attempt_at <= st.error_at)):
            item["error_is_stale"] = "последняя попытка расчёта не новее ошибки: расчёт после этой ошибки не запускался" if st.attempt_at else "попыток расчёта этой версией не было — ошибка осталась от прошлой версии"
        out["sources"].append(item)
    return out


def render(d: dict) -> str:
    L = [f"Диагностика EOL (только чтение), {d['at']}", f"Worker: сигнал {d['worker']['heartbeat_age_s']} с назад, запущен {d['worker']['started_at']}, EOL сейчас: {d['worker']['eol_job'] or 'не считается'}"]
    for s in d["sources"]:
        L += ["", f"== {s['source']}" + ("" if s["active"] else " (выключен)"), f"Каталог: {s['catalog']}"]
        st = s["state"]
        if st:
            L += [f"Последний успех: {st['computed_at']}", f"Последняя попытка: {st['attempt_at']}", f"Ошибка: {st['error'] or 'нет'}" + (f" от {st['error_at']}" if st["error"] else ""),
                  f"Техническая причина: {st['error_detail'] or '—'}", f"Идёт расчёт: {'да, ' + str(st['progress']) if st['running'] else 'нет'}", f"Сведения расчёта: {st['diag']}"]
        if s.get("error_is_stale"):
            L.append(f"!! {s['error_is_stale']}")
        L += [f"Запустится ли расчёт: {'да' if s['will_run'] else 'нет — ' + '; '.join(s['why_not'])}", f"Сохранено находок: {s['saved_findings']}; повторов ключа в базе: {s['duplicate_keys_in_db']}",
              f"Каталог: {s['catalog_checks'] or 'повторов версий и превышений длин нет'}" + (f" ({'; '.join(s['examples'])})" if s["examples"] else ""),
              f"Построил бы сейчас по каталогу: {s['would_build']} находок, ключей к объединению: {s['keys_to_merge']}"]
    return "\n".join(L)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    eng = create_engine(get_settings())
    try:
        d = await diagnose(create_session_maker(eng), a.source)
    finally:
        await eng.dispose()
    print(json.dumps(d, ensure_ascii=False, indent=1, default=str) if a.json else render(d))


if __name__ == "__main__":
    asyncio.run(main())
