"""Аудит применения баз уязвимостей к источнику KSC: охват, согласованность и контрольная сверка подготовленных результатов с пересчётом «с нуля» на выборке.

Только чтение. Тяжёлое не запускается: агрегаты SQL по таблицам результатов и пересчёт небольшой выборки уязвимостей (по умолчанию 30). Результат — список проверок
со статусом ok | warn | error | info и пояснением, что делать; ничего не подменяется нулями."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import and_, exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import CatalogProduct, CatalogState, KscSource, VdbAnalysis, VdbFinding, VdbJournal, VdbVersionHit as H, VdbVuln, ZcHost, ZcSource
from . import hostext as HX
from . import match as M
from .journal import LIMIT_BYTES, total_bytes

SAMPLE = 30


def _chk(key: str, title: str, status: str, detail: str, data: dict | None = None) -> dict:
    return {"key": key, "title": title, "status": status, "detail": detail, "data": data or {}}


def _age(at: datetime | None) -> str:
    if at is None:
        return "—"
    sec = int((datetime.now(timezone.utc) - (at if at.tzinfo else at.replace(tzinfo=timezone.utc))).total_seconds())
    return f"{sec // 3600} ч {sec % 3600 // 60} мин назад" if sec >= 3600 else f"{sec // 60} мин назад"


async def run(db: AsyncSession, source_id: uuid.UUID, *, sample: int = SAMPLE) -> dict:
    src = await db.get(KscSource, source_id)
    checks: list[dict] = []
    info = await HX.state(db, source_id)
    st = await db.get(VdbAnalysis, source_id)

    # 1. состояние расчёта
    label = {"fresh": "актуально", "stale": "устарело, ждёт пересчёта", "updating": "идёт расчёт", "stalled": "расчёт не обновлял ход дольше 10 минут", "none": "не подготовлено"}[info["state"]]
    level = {"fresh": "ok", "stale": "warn", "updating": "info", "stalled": "error", "none": "error"}[info["state"]]
    detail = f"Состояние: {label}. Последний успешный расчёт: {info['built_at']:%d.%m.%Y %H:%M} UTC ({_age(info['built_at'])})." if info["built_at"] else f"Состояние: {label}. Успешных расчётов не было."
    if info.get("error"):
        detail += f" Ошибка: {info['error']}"
    if info["state"] in ("none", "stalled"):
        detail += " Карточки компьютеров и отчёты не получают внешних уязвимостей, пока расчёт не завершится: смотрите журнал и ход расчёта."
    checks.append(_chk("state", "Состояние расчёта", level, detail, {"state": info["state"], "hits": st.hits if st else 0, "duration_s": (st.duration_ms // 1000) if st else 0}))

    # 2. каталог
    cs = await db.get(CatalogState, source_id)
    prods = (await db.execute(select(CatalogProduct.key, CatalogProduct.versions).where(CatalogProduct.source_id == source_id))).all()
    pairs_all: set[tuple[str, str]] = set()
    active_pairs: set[tuple[str, str]] = set()
    pids = 0
    for key, versions in prods:
        for v in versions or []:
            pr = (key, v.get("version") or "")
            pairs_all.add(pr)
            pids += len(v.get("product_ids") or [])
            if v.get("hosts_active"):
                active_pairs.add(pr)
    if not prods:
        checks.append(_chk("catalog", "Каталог программ", "error", "Каталог программ источника не построен: сопоставлять нечего (Администрирование → Каталог программ)."))
    else:
        checks.append(_chk("catalog", "Каталог программ", "ok", f"Продуктов {len(prods)}, версий {len(pairs_all)} (с активными компьютерами {len(active_pairs)}), записей реестра ПО {pids}. "
                           f"Построен {cs.built_at:%d.%m.%Y %H:%M} UTC." if cs and cs.built_at else f"Продуктов {len(prods)}, версий {len(pairs_all)}.", {"products": len(prods), "versions": len(pairs_all), "active": len(active_pairs)}))

    # 3. охват результатами
    hit_pairs = {(pk, v) for pk, v in (await db.execute(select(H.product_key, H.version).where(H.source_id == source_id).distinct())).all()}
    by_status = dict((await db.execute(select(H.status, func.count()).where(H.source_id == source_id).group_by(H.status))).all())
    hits_n = sum(by_status.values())
    vulns_n = int((await db.execute(select(func.count(func.distinct(H.vuln_key))).where(H.source_id == source_id))).scalar_one())
    with_hits = len(active_pairs & hit_pairs)
    cover = f"Строк результата {hits_n}, различных уязвимостей {vulns_n}; версий каталога с уязвимостями {with_hits} из {len(active_pairs)} активных"
    cover += " (остальные версии — без найденных уязвимостей)." if active_pairs else "."
    st_ru = ", ".join(f"{M.STATUS_RU.get(k, k)}: {v}" for k, v in sorted(by_status.items()))
    checks.append(_chk("coverage", "Охват результатами", "ok" if hits_n else ("info" if info["state"] != "fresh" else "warn"), cover + (f" По статусам — {st_ru}." if st_ru else " Результатов нет."),
                       {"hits": hits_n, "vulns": vulns_n, "versions_with_hits": with_hits, "versions_active": len(active_pairs), "by_status": by_status}))

    # 4. согласованность
    gone = sorted(hit_pairs - pairs_all)
    checks.append(_chk("orphan_versions", "Результаты по версиям, которых нет в каталоге", "ok" if not gone else "warn",
                       "Нет." if not gone else f"{len(gone)} версий (например {', '.join(f'{p} {v}' for p, v in gone[:3])}): каталог перестроен после расчёта, пересчёт уберёт их.", {"count": len(gone)}))
    miss_vuln = int((await db.execute(select(func.count(func.distinct(H.vuln_key))).select_from(H).outerjoin(VdbVuln, VdbVuln.vuln_key == H.vuln_key)
                                      .where(H.source_id == source_id, VdbVuln.vuln_key.is_(None)))).scalar_one())
    checks.append(_chk("orphan_vulns", "Результаты по уязвимостям, которых нет в базе", "ok" if not miss_vuln else "warn",
                       "Нет." if not miss_vuln else f"{miss_vuln} уязвимостей удалены из баз после расчёта: пересчёт уберёт их.", {"count": miss_vuln}))
    nofind = int((await db.execute(select(func.count()).select_from(VdbFinding).where(VdbFinding.source_id == source_id, ~exists().where(and_(H.source_id == VdbFinding.source_id, H.vuln_key == VdbFinding.vuln_key))))).scalar_one())
    checks.append(_chk("findings_without_hits", "Находки без подготовленных результатов", "ok" if not nofind else "error",
                       "Нет: каждая находка (список «Уязвимости», план) опирается на результаты по версиям." if not nofind else f"{nofind} находок не имеют строк результата: данные расходятся, запустите «Пересчитать сейчас».", {"count": nofind}))

    # 5. контрольная сверка: пересчёт выборки «с нуля» и сравнение с сохранённым
    keys = [k for (k,) in (await db.execute(select(H.vuln_key).where(H.source_id == source_id).group_by(H.vuln_key).order_by(func.random()).limit(sample))).all()]
    if not keys or not prods:
        checks.append(_chk("sample", "Контрольная сверка выборки", "info", "Нет результатов для сверки."))
    else:
        mp = (await M.load_context(db, source_id))
        matcher = M.Matcher(*mp)
        fresh = {(m.vuln_key, m.product_key, m.version, m.status) for m in M.matches_from(matcher, await M.affected_for(db, keys), only_active=False) if m.status in M.AFFECTED}
        stored = {(vk, pk, v, s) for vk, pk, v, s in (await db.execute(select(H.vuln_key, H.product_key, H.version, H.status).where(H.source_id == source_id, H.vuln_key.in_(keys)))).all()}
        miss, extra = sorted(fresh - stored), sorted(stored - fresh)
        ok = not miss and not extra
        explain = "" if ok else (" Расхождения ожидаемы, пока данные устарели (идёт пересчёт)." if info["state"] != "fresh" else " Данные актуальны, а результаты расходятся с пересчётом: это ошибка — сообщите, приложите журнал.")
        checks.append(_chk("sample", "Контрольная сверка выборки", "ok" if ok else ("warn" if info["state"] != "fresh" else "error"),
                           f"Пересчитано с нуля {len(keys)} уязвимостей ({len(fresh)} совпадений): совпало с сохранённым полностью." if ok else
                           f"Пересчитано {len(keys)} уязвимостей: нет в сохранённом {len(miss)}, лишних в сохранённом {len(extra)}." + explain,
                           {"checked": len(keys), "missing": [list(x) for x in miss[:5]], "extra": [list(x) for x in extra[:5]]}))

    # 6. компьютеры: подготовленные данные зон
    zs = await db.get(ZcSource, source_id)
    if zs is None or not zs.gen:
        checks.append(_chk("hosts", "Компьютеры: подготовленные данные зон", "info", "Данные зон ещё не рассчитаны: покрытие по компьютерам определить нельзя. Карточка компьютера читает результаты напрямую и от них не зависит."))
    else:
        hosts = int((await db.execute(select(func.count()).select_from(ZcHost).where(ZcHost.source_id == source_id, ZcHost.gen == zs.gen))).scalar_one())
        with_ext = int((await db.execute(select(func.count()).select_from(ZcHost).where(ZcHost.source_id == source_id, ZcHost.gen == zs.gen, ZcHost.e_total > 0))).scalar_one())
        older = bool(zs.finished_at and info["built_at"] and (zs.finished_at if zs.finished_at.tzinfo else zs.finished_at.replace(tzinfo=timezone.utc)) < (info["built_at"] if info["built_at"].tzinfo else info["built_at"].replace(tzinfo=timezone.utc)))
        lvl = "warn" if (older or info["state"] in ("none", "stalled")) else "ok"
        txt = f"В расчёте зон {hosts} компьютеров, из них с результатами внешних баз {with_ext}. Зоны рассчитаны {_age(zs.finished_at)}."
        if older:
            txt += " Расчёт зон выполнен раньше последнего расчёта внешних баз: итоги по компьютерам в зонах устарели — выполните «Пересчитать данные зон»."
        checks.append(_chk("hosts", "Компьютеры: подготовленные данные зон", lvl, txt, {"hosts": hosts, "with_ext": with_ext, "zones_stale": older}))

    # 7. журнал
    day = datetime.now(timezone.utc).timestamp() - 86400
    errs = int((await db.execute(select(func.count()).select_from(VdbJournal).where(VdbJournal.level == "error", VdbJournal.at >= datetime.fromtimestamp(day, timezone.utc)))).scalar_one())
    size = await total_bytes(db)
    checks.append(_chk("journal", "Журнал и ошибки", "ok" if not errs else "warn", f"Ошибок за сутки: {errs}. Журнал занимает {size / 1048576:.1f} из {LIMIT_BYTES // 1048576} МБ (старые записи перезаписываются)."
                       + (" Смотрите раздел «Журнал» ниже." if errs else ""), {"errors_24h": errs, "bytes": size}))

    counts = {k: sum(1 for c in checks if c["status"] == k) for k in ("ok", "info", "warn", "error")}
    return {"source_id": str(source_id), "source": src.name if src else "", "at": datetime.now(timezone.utc).isoformat(), "checks": checks, "counts": counts}
