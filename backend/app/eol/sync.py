"""Загрузка базы жизненного цикла ПО из API v1 endoflife.date (`/products/full`: все продукты и ветки одним документом) в локальные таблицы PostgreSQL.

Обновление инкрементальное: документ запрашивается условным запросом (ETag; без изменений — 304, ничего не читается), а при изменении каждый продукт сравнивается по хэшу содержимого —
переписываются только изменившиеся, исчезнувшие удаляются. Порциями по продуктам, каждая в своей транзакции. Разбор терпим к пропускам: нет дат, неизвестные поля, значения `true/false`."""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import date, datetime, timezone
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import EolProduct, EolRelease, utcnow

log = logging.getLogger("app.eol")
API = "https://endoflife.date/api/v1"
BATCH = 40


class EolFormatError(ValueError):
    """Ответ не похож на документ API endoflife.date."""


def _date(v) -> date | None:
    """Дата из строки ISO; всё остальное (null, true/false, пустое) — нет даты."""
    if isinstance(v, str) and len(v) >= 10:
        try:
            return date.fromisoformat(v[:10])
        except ValueError:
            return None
    return None


def _flag(v) -> bool | None:
    return v if isinstance(v, bool) else None


def digest(p: dict) -> str:
    return hashlib.md5(json.dumps(p, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def search_text(p: dict) -> str:
    ids = " ".join(str(i.get("id", "")) for i in p.get("identifiers") or [] if isinstance(i, dict))
    return " ".join(x for x in [p.get("name", ""), p.get("label", ""), *(p.get("aliases") or []), p.get("category", ""), *(p.get("tags") or []), ids] if x).lower()[:4000]


def parse_product(p: dict) -> tuple[dict, list[dict]]:
    """Строка продукта и строки веток (в порядке API)."""
    name = str(p.get("name") or "").strip()
    if not name:
        raise EolFormatError("у продукта нет названия")
    rels = []
    for i, r in enumerate(p.get("releases") or []):
        rn = str(r.get("name") or "").strip()
        if not rn:
            continue
        latest = r.get("latest") if isinstance(r.get("latest"), dict) else {}
        rels.append({"name": rn[:80], "position": i, "label": str(r.get("label") or rn)[:200], "codename": (r.get("codename") or None), "release_date": _date(r.get("releaseDate")),
                     "is_lts": bool(r.get("isLts")), "lts_from": _date(r.get("ltsFrom")), "eoas_from": _date(r.get("eoasFrom")), "eol_from": _date(r.get("eolFrom")), "eoes_from": _date(r.get("eoesFrom")),
                     "eol_flag": _flag(r.get("isEol")), "eoes_flag": _flag(r.get("isEoes")), "discontinued_from": _date(r.get("discontinuedFrom")),
                     "latest_name": (str(latest.get("name"))[:80] if latest.get("name") else None), "latest_date": _date(latest.get("date")), "latest_link": (str(latest.get("link"))[:400] if latest.get("link") else None),
                     "custom": r.get("custom") if isinstance(r.get("custom"), dict) else None})
    row = {"name": name[:120], "label": str(p.get("label") or name)[:200], "category": str(p.get("category") or "")[:40], "tags": list(p.get("tags") or []), "aliases": list(p.get("aliases") or []),
           "identifiers": [i for i in (p.get("identifiers") or []) if isinstance(i, dict)], "labels": p.get("labels") if isinstance(p.get("labels"), dict) else {},
           "links": p.get("links") if isinstance(p.get("links"), dict) else {}, "search": search_text(p), "releases_n": len(rels), "digest": digest(p)}
    return row, rels


def load_document(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        raise EolFormatError("Ответ не является JSON") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("result"), list):
        raise EolFormatError("Ответ не похож на документ endoflife.date (нет списка result)")
    return doc


async def apply_products(sm: async_sessionmaker[AsyncSession], products: list[dict], *, progress=None) -> dict:
    """Записывает изменившиеся продукты и удаляет исчезнувшие. Возвращает {total, changed, added, removed}."""
    parsed = []
    for p in products:
        try:
            parsed.append(parse_product(p))
        except EolFormatError:
            continue
    if len(parsed) < 20:
        raise EolFormatError(f"В документе слишком мало продуктов ({len(parsed)}): файл неполный, прежняя база сохранена")
    async with sm() as db:
        have = dict((await db.execute(select(EolProduct.name, EolProduct.digest))).all())
    changed = added = 0
    now = utcnow()
    for i in range(0, len(parsed), BATCH):
        part = [(r, rels) for r, rels in parsed[i:i + BATCH] if have.get(r["name"]) != r["digest"]]
        if part:
            async with sm() as db:
                for row, rels in part:
                    cur = await db.get(EolProduct, row["name"])
                    if cur is None:
                        db.add(EolProduct(**row, updated_at=now))
                        added += 1
                    else:
                        for k, v in row.items():
                            setattr(cur, k, v)
                        cur.updated_at = now
                        await db.execute(delete(EolRelease).where(EolRelease.product == row["name"]))
                    await db.flush()
                    db.add_all([EolRelease(product=row["name"], **r) for r in rels])
                    changed += 1
                await db.commit()
        if progress:
            await progress(f"продукты: {min(i + BATCH, len(parsed))} из {len(parsed)}, изменено {changed}")
    gone = sorted(set(have) - {r["name"] for r, _ in parsed})
    if gone:
        async with sm() as db:
            await db.execute(delete(EolProduct).where(EolProduct.name.in_(gone)))
            await db.commit()
    return {"total": len(parsed), "changed": changed, "added": added, "removed": len(gone)}


async def count(sm: async_sessionmaker[AsyncSession]) -> int:
    async with sm() as db:
        return int((await db.execute(select(func.count()).select_from(EolProduct))).scalar_one())


def parse_time(v: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(v).astimezone(timezone.utc) if v else None
    except ValueError:
        return None
