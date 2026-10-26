"""Категории продуктов каталога источника (решения администратора, endoflife.date, правила по названию) — для плана устранения."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import EolMapping, ProductClass
from . import match as M
from .classify import classify


async def class_map(db: AsyncSession, prods: list[M.CatProd]) -> dict[str, tuple[str, str]]:
    """key каталога → (категория, основание). Недоступность базы EOL не мешает: остаются решения администратора и правила по названию."""
    overrides = {r.catalog_key: r.category for r in (await db.execute(select(ProductClass))).scalars().all()}
    eol_cat: dict[str, str] = {}
    try:
        from ..eol import compute as EC  # noqa: PLC0415

        idx = await EC.load_index(db)
        if idx.products:
            maps = {m.catalog_key: m for m in (await db.execute(select(EolMapping))).scalars().all()}
            for key, found in EC.candidates(idx, M.Matcher(prods, []), maps).items():
                if len(found) == 1 and found[0][0] in idx.products and found[0][1] in ("mapped", "high"):         # только надёжное соответствие: «по названию» категорию не определяет
                    eol_cat[key] = idx.products[found[0][0]].category
    except Exception:  # noqa: BLE001
        eol_cat = {}
    return {p.key: classify(p.name, p.publisher, p.key, p.platforms, p.component, eol_cat.get(p.key), overrides.get(p.key)) for p in prods}
