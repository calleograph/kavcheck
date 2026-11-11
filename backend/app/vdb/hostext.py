"""Результаты проверки по внешним базам для компьютера — из подготовленных данных (`vdb_version_hits`), без пересчёта.

Сопоставление уязвимостей с каталогом считает фоновый анализ (`vdb/sync.analyze`) и сохраняет по паре «продукт — версия каталога»; результат не зависит от компьютера.
Здесь по установленным у компьютера продуктам берутся готовые строки одним запросом. Состояние расчёта (`vdb_analysis`) говорит, насколько данные свежи: пользователь видит
последний успешный результат с отметкой, а не пересчёт в момент обращения."""
from __future__ import annotations

import uuid
from typing import Iterable

from sqlalchemy import select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import CatalogProduct, CatalogState, VdbAnalysis, VdbVersionHit as H, VdbVuln as V
from . import store
from .match import STATUS_RANK, STATUS_RU
from .normalize import SEV_RANK, SEV_RU

LIMIT = 200_000                     # предел строк одного компьютера (защита памяти); превышение — явная отметка, а не тихое усечение
_PIDS: dict[uuid.UUID, tuple[str, dict[int, tuple[str, str, str]]]] = {}      # источник → (отпечаток каталога, идентификатор записи реестра → (ключ продукта, название, версия))


async def pid_map(db: AsyncSession, source_id: uuid.UUID) -> dict[int, tuple[str, str, str]]:
    """Какая версия каталога соответствует записи реестра ПО KSC. Строится по каталогу и держится в памяти до его перестроения."""
    built = (await db.execute(select(CatalogState.built_at).where(CatalogState.source_id == source_id))).scalar_one_or_none()
    stamp = str(built)
    cur = _PIDS.get(source_id)
    if cur and cur[0] == stamp and built is not None:
        return cur[1]
    out: dict[int, tuple[str, str, str]] = {}
    for key, name, versions in (await db.execute(select(CatalogProduct.key, CatalogProduct.name, CatalogProduct.versions).where(CatalogProduct.source_id == source_id))).all():
        for v in versions or []:
            for pid in v.get("product_ids") or []:
                out[int(pid)] = (key, name, v.get("version") or "")
    _PIDS[source_id] = (stamp, out)
    return out


async def state(db: AsyncSession, source_id: uuid.UUID) -> dict:
    """Актуальность подготовленных данных: none (ещё не рассчитаны) | updating | stale (данные баз или каталога изменились, идёт ожидание пересчёта) | fresh."""
    st = await db.get(VdbAnalysis, source_id)
    if st is None or st.built_at is None:
        return {"state": "updating" if st is not None and st.status == "running" else "none", "built_at": None, "error": st.error if st else ""}
    if st.status == "running":
        kind = "updating"
    else:
        kind = "fresh" if st.rev == await store.analysis_rev(db, source_id) else "stale"
    return {"state": kind, "built_at": st.built_at, "error": st.error if st.status == "error" else ""}


def state_note(info: dict) -> str:
    """Подпись для интерфейса и отчёта: что за данные и насколько они актуальны."""
    at = info.get("built_at")
    when = f"{at:%d.%m.%Y %H:%M} UTC" if at else ""
    return {"none": "Проверка по внешним базам ещё не подготовлена: фоновый расчёт не завершался для этого источника. Раздел не включён, а не равен нулю.",
            "updating": f"Результаты проверки по внешним базам пересчитываются; показан последний готовый расчёт от {when}." if when else "Результаты проверки по внешним базам готовятся; расчёт ещё не завершён.",
            "stale": f"Базы уязвимостей или каталог программ изменились; показан последний готовый расчёт от {when}, пересчёт выполняется в фоне.",
            "fresh": ""}[info.get("state") or "none"] + (f" Последний расчёт завершился ошибкой: {info['error']}." if info.get("error") else "")


async def items_for(db: AsyncSession, source_id: uuid.UUID, pids: Iterable[int]) -> tuple[list[dict], bool]:
    """Строки внешних баз по установленным записям реестра (идентификаторам ПО KSC). Возвращает (элементы по убыванию важности, усечён ли список пределом)."""
    pm = await pid_map(db, source_id)
    pairs = sorted({(pm[p][0], pm[p][2]) for p in {int(x) for x in pids} if p in pm})
    names = {k: n for k, n, _v in pm.values()}
    items: list[dict] = []
    cut = False
    for i in range(0, len(pairs), 400):
        q = (select(H.vuln_key, H.product_key, H.version, H.status, H.basis, V.title, V.sev_rank, V.exploited, V.sources, V.ids_text)
             .select_from(H).outerjoin(V, V.vuln_key == H.vuln_key).where(H.source_id == source_id, tuple_(H.product_key, H.version).in_(pairs[i:i + 400])).limit(LIMIT + 1 - len(items)))
        for vk, pk, ver, status, basis, title, rank, exploited, srcs, ids_text in (await db.execute(q)).all():
            rank = rank or 0
            items.append({"key": vk, "title": title or "", "severity_ru": SEV_RU[next((k for k, r in SEV_RANK.items() if r == rank), "")], "sev_rank": rank, "exploited": bool(exploited),
                          "product": names.get(pk, pk), "version": ver, "status": status, "status_ru": STATUS_RU.get(status, status), "basis": basis,
                          "sources": [x for x in (srcs or "").split(",") if x], "ids": [x.upper() for x in (ids_text or "").split()][:20]})
        if len(items) > LIMIT:
            cut = True
            del items[LIMIT:]
            break
    items.sort(key=lambda x: (not x["exploited"], -x["sev_rank"], -STATUS_RANK[x["status"]]))
    return items, cut
