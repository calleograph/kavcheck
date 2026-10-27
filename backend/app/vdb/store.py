"""Запись в локальную базу уязвимостей: поколения (полные выгрузки подменяют данные только после проверки), построчное обновление, сводка по уязвимостям, откат."""
from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime, timezone

from sqlalchemy import String, and_, cast, delete, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import VdbAffected, VdbRecord, VdbRun, VdbSource, VdbVuln, utcnow
from .normalize import SEV_RANK, Rec, legacy_score, norm, pick_primary

log = logging.getLogger("app.vdb")
SOURCE_PRIORITY = ("nvd", "bdu", "osv", "kev")
CHUNK = 400


def _chunks(seq: list, n: int = CHUNK):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def active(model):
    """Условие соединения: строки активного поколения своего источника."""
    return and_(VdbSource.key == model.source, VdbSource.active_generation == model.generation)


def _rec_row(r: Rec, gen: int, now: datetime) -> dict:
    return dict(source=r.source, generation=gen, ext_id=r.ext_id[:80], vuln_key=r.vuln_key[:80], aliases=r.aliases[:30], title=r.title[:500], description=r.description[:20000],
                severity=r.severity, score=r.score, vector=r.vector[:200], scores=r.scores[:12], scores_at=now, published=r.published, modified=r.modified, exploited=r.exploited, fix_available=r.fix_available,
                fix_text=r.fix_text[:4000], status=r.status[:80], refs=r.refs[:40], extra=r.extra, fetched_at=now)


def _aff_row(a, r: Rec, gen: int) -> dict:
    d = asdict(a)
    d.update(source=r.source, generation=gen, ext_id=r.ext_id[:80], vuln_key=r.vuln_key[:80], vendor_key=norm(a.vendor)[:200], product_key=norm(a.product)[:300])
    for k, n in (("vendor", 200), ("product", 300), ("cpe", 400), ("purl", 400), ("pkg_name", 300), ("exact", 120), ("v_start", 120), ("v_end", 120), ("fixed", 120), ("version_text", 300)):
        d[k] = (d[k] or "")[:n]
    return d


async def save_batch(db: AsyncSession, gen: int, recs: list[Rec], *, force: bool = False) -> tuple[int, set[str]]:
    """Записать пачку записей одного источника в поколение. Неизменившиеся (та же дата изменения) пропускаются, если не задано force (повторное получение: запись заменяется,
    дублей нет — ключ записи ext_id). Возвращает (изменено, затронутые ключи уязвимостей)."""
    if not recs:
        return 0, set()
    now = utcnow()
    src = recs[0].source
    by_id = {r.ext_id[:80]: r for r in recs}          # дубликаты в пачке: побеждает последний
    existing: dict[str, tuple[datetime | None, str]] = {}
    for ch in _chunks(list(by_id)):
        for ext, mod, key in (await db.execute(select(VdbRecord.ext_id, VdbRecord.modified, VdbRecord.vuln_key).where(VdbRecord.source == src, VdbRecord.generation == gen,
                                                                                                                    VdbRecord.ext_id.in_(ch)))).all():
            existing[ext] = (mod, key)
    todo, keys = [], set()
    for ext, r in by_id.items():
        old = existing.get(ext)
        if not force and old is not None and r.modified is not None and old[0] is not None and _utc(old[0]) == _utc(r.modified) and old[1] == r.vuln_key:
            continue
        todo.append(r)
        keys.add(r.vuln_key)
        if old is not None:
            keys.add(old[1])
    if not todo:
        return 0, set()
    ids = [r.ext_id[:80] for r in todo if r.ext_id[:80] in existing]
    for ch in _chunks(ids):
        await db.execute(delete(VdbAffected).where(VdbAffected.source == src, VdbAffected.generation == gen, VdbAffected.ext_id.in_(ch)))
        await db.execute(delete(VdbRecord).where(VdbRecord.source == src, VdbRecord.generation == gen, VdbRecord.ext_id.in_(ch)))
    for ch in _chunks(todo, 200):
        await db.execute(insert(VdbRecord), [_rec_row(r, gen, now) for r in ch])
        rows = [_aff_row(a, r, gen) for r in ch for a in r.affected]
        for ach in _chunks(rows, 500):
            await db.execute(insert(VdbAffected), ach)
    return len(todo), keys


def _utc(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


async def next_generation(db: AsyncSession, source: str) -> int:
    """Номер нового поколения — всегда больше действующего и предыдущего, поэтому загрузка (в том числе первая) не видна, пока не проверена и не подменила действующее."""
    row = await db.get(VdbSource, source)
    top = int((await db.execute(select(func.coalesce(func.max(VdbRecord.generation), 0)).where(VdbRecord.source == source))).scalar_one())
    return max(top, row.active_generation if row else 0, (row.prev_generation or 0) if row else 0) + 1


async def discard_generation(db: AsyncSession, source: str, gen: int) -> None:
    await db.execute(delete(VdbAffected).where(VdbAffected.source == source, VdbAffected.generation == gen))
    await db.execute(delete(VdbRecord).where(VdbRecord.source == source, VdbRecord.generation == gen))


class IntegrityError(Exception):
    """Загруженная выгрузка не прошла проверку целостности: активные данные не заменены."""


async def swap_generation(db: AsyncSession, row: VdbSource, new_gen: int, keep_prev: bool = True) -> tuple[int, set[str]]:
    """Подменить активное поколение источника новым после проверки (непустое и не меньше половины прежнего); прежнее остаётся для отката, более старые удаляются."""
    n_new = int((await db.execute(select(func.count()).select_from(VdbRecord).where(VdbRecord.source == row.key, VdbRecord.generation == new_gen))).scalar_one())
    n_old = int((await db.execute(select(func.count()).select_from(VdbRecord).where(VdbRecord.source == row.key, VdbRecord.generation == row.active_generation))).scalar_one()) \
        if row.active_generation != new_gen else 0
    if n_new == 0:
        raise IntegrityError("Выгрузка не содержит ни одной записи")
    if n_old >= 100 and n_new < n_old * 0.5:
        raise IntegrityError(f"В новой выгрузке {n_new} записей против {n_old} в действующей: возможно, файл неполный; данные не заменены")
    old_gen = row.active_generation
    keys = set((await db.execute(select(VdbRecord.vuln_key).where(VdbRecord.source == row.key, VdbRecord.generation.in_([new_gen, old_gen])))).scalars().all())
    row.prev_generation, row.active_generation, row.records = (old_gen if keep_prev else None), new_gen, n_new
    await db.flush()
    keep = [new_gen, old_gen] if keep_prev else [new_gen]       # предыдущая копия — только если она нужна для отката (у крупных источников удаляется: проверка при замене уже пройдена)
    for model in (VdbAffected, VdbRecord):
        await db.execute(delete(model).where(model.source == row.key, model.generation.notin_(keep)))
    return n_new, keys


async def delete_records(db: AsyncSession, source: str, gen: int, ext_ids: list[str]) -> set[str]:
    """Удалить записи, которые источник отозвал (NVD: Rejected, OSV: withdrawn): иначе они остаются в базе навсегда. Возвращает затронутые ключи для пересчёта сводки."""
    keys: set[str] = set()
    for ch in _chunks(list(dict.fromkeys(ext_ids))):
        keys |= set((await db.execute(select(VdbRecord.vuln_key).where(VdbRecord.source == source, VdbRecord.generation == gen, VdbRecord.ext_id.in_(ch)))).scalars().all())
        await db.execute(delete(VdbAffected).where(VdbAffected.source == source, VdbAffected.generation == gen, VdbAffected.ext_id.in_(ch)))
        await db.execute(delete(VdbRecord).where(VdbRecord.source == source, VdbRecord.generation == gen, VdbRecord.ext_id.in_(ch)))
    return keys


async def restore_previous(db: AsyncSession, row: VdbSource) -> set[str]:
    """Откат к предыдущей полной копии источника (после неудачной или ошибочной загрузки)."""
    if row.prev_generation is None:
        raise IntegrityError("Предыдущей копии нет")
    keys = set((await db.execute(select(VdbRecord.vuln_key).where(VdbRecord.source == row.key, VdbRecord.generation.in_([row.active_generation, row.prev_generation])))).scalars().all())
    row.active_generation, row.prev_generation = row.prev_generation, row.active_generation
    row.records = int((await db.execute(select(func.count()).select_from(VdbRecord).where(VdbRecord.source == row.key, VdbRecord.generation == row.active_generation))).scalar_one())
    await db.flush()
    return keys


def record_scores(r: VdbRecord) -> list[dict]:
    """Оценки записи; у записи из прежней версии (без списка) — единственная оценка по сохранённым баллу и вектору, если версию методики можно определить."""
    if r.scores:
        return r.scores
    s = legacy_score(r.source, r.score, r.vector, r.modified) if r.score is not None else None
    return [s] if s else []


async def upgrade_scores(db: AsyncSession) -> int:
    """Однократно после обновления: превратить балл и вектор прежних записей в список оценок (версия по вектору) и пересчитать сводку. Безопасно повторять: запись с готовым списком не меняется.
    scores_at не ставится — отсутствующие оценки NVD дозагрузит следующая загрузка источника. Возвращает число обновлённых записей."""
    n, last = 0, 0
    while True:
        # только записи, которым это нужно (есть балл, нет списка оценок): остальные не читаются, а прочитанные не копятся в памяти сессии
        rows = (await db.execute(select(VdbRecord).where(VdbRecord.id > last, VdbRecord.score.is_not(None), cast(VdbRecord.scores, String) == "[]").order_by(VdbRecord.id).limit(500))).scalars().all()
        if not rows:
            break
        last = rows[-1].id
        keys = set()
        for r in rows:
            s = legacy_score(r.source, r.score, r.vector, r.modified)
            r.scores, r.score = ([s] if s else []), (r.score if s else None)      # версию методики определить нельзя — оценка недостоверна и не показывается
            keys.add(r.vuln_key)
            n += 1
        await db.flush()
        await refresh_vulns(db, keys)
        await db.commit()
        db.expunge_all()
    return n


async def refresh_vulns(db: AsyncSession, keys: set[str] | list[str]) -> None:
    """Пересчитать сводку по уязвимостям: объединяет записи активных поколений всех источников (опасность — максимальная, подтверждённая эксплуатация — если есть в любом источнике)."""
    keys = list(keys)
    for ch in _chunks(keys, 300):
        recs = (await db.execute(select(VdbRecord).join(VdbSource, active(VdbRecord)).where(VdbRecord.vuln_key.in_(ch)))).scalars().all()
        affs = (await db.execute(select(VdbAffected.vuln_key, VdbAffected.vendor, VdbAffected.product, VdbAffected.pkg_name).join(VdbSource, active(VdbAffected))
                                 .where(VdbAffected.vuln_key.in_(ch)))).all()
        prods: dict[str, list[str]] = {}
        for k, v, p, pk in affs:
            s = " ".join(x for x in (v, p or pk) if x)
            if s and s not in prods.setdefault(k, []) and len(prods[k]) < 40:
                prods[k].append(s)
        by: dict[str, list[VdbRecord]] = {}
        for r in recs:
            by.setdefault(r.vuln_key, []).append(r)
        await db.execute(delete(VdbVuln).where(VdbVuln.vuln_key.in_(ch)))
        rows = []
        for k, rs in by.items():
            rs.sort(key=lambda r: SOURCE_PRIORITY.index(r.source) if r.source in SOURCE_PRIORITY else 9)
            main = next((r for r in rs if r.title), rs[0])
            best = pick_primary([s for r in rs for s in record_scores(r)])
            rank = SEV_RANK.get(best["severity"], 0) if best else max((SEV_RANK.get(r.severity, 0) for r in rs), default=0)   # нет числовой оценки — уровень, названный источником
            fixes = [r.fix_available for r in rs if r.fix_available is not None]
            pubs = [_utc(r.published) for r in rs if r.published]
            mods = [_utc(r.modified) for r in rs if r.modified]
            ids = {k, *(r.ext_id for r in rs), *(a for r in rs for a in r.aliases)}
            rows.append(dict(vuln_key=k, title=main.title[:500], sev_rank=rank, score=best["score"] if best else None,
                             score_version=best["version"] if best else "", score_source=best["source"] if best else "", exploited=any(r.exploited for r in rs), has_fix=any(fixes) if fixes else None, published=min(pubs) if pubs else None, modified=max(mods) if mods else None,
                             sources=",".join(sorted({r.source for r in rs})), ids_text=" ".join(sorted(ids)).lower(), products_text="; ".join(prods.get(k, [])).lower()[:4000],
                             description=(next((r.description for r in rs if r.description), ""))[:3000]))
        if rows:
            await db.execute(insert(VdbVuln), rows)


async def finish_run(db: AsyncSession, run_id: int, **fields) -> None:
    await db.execute(update(VdbRun).where(VdbRun.id == run_id).values(**fields))


async def prune_runs(db: AsyncSession, source: str, keep: int = 60) -> None:
    ids = (await db.execute(select(VdbRun.id).where(VdbRun.source == source).order_by(VdbRun.id.desc()).offset(keep))).scalars().all()
    if ids:
        await db.execute(delete(VdbRun).where(VdbRun.id.in_(ids)))


async def revision(db: AsyncSession, source_id) -> str:
    """Отпечаток состояния данных, от которых зависит сопоставление: время загрузки источников, число решений администратора, построение каталога источника KSC."""
    from ..models import CatalogState, VdbMapping  # noqa: PLC0415

    srcs = (await db.execute(select(VdbSource.key, VdbSource.last_ok_at, VdbSource.active_generation, VdbSource.enabled).where(VdbSource.key.notin_(("eol", "oval"))).order_by(VdbSource.key))).all()
    maps = (await db.execute(select(func.count(), func.max(VdbMapping.created_at)).select_from(VdbMapping))).one()
    built = (await db.execute(select(CatalogState.built_at).where(CatalogState.source_id == source_id))).scalar_one_or_none()
    return "|".join([",".join(f"{k}:{t.isoformat() if t else ''}:{g}:{int(e)}" for k, t, g, e in srcs), f"{maps[0]}:{maps[1]}", str(built)])


DEFAULTS = {"kev": (True, 12, {}), "nvd": (False, 6, {"years_back": 3}), "osv": (False, 24, {"ecosystems": ["Debian", "Alpine", "Red Hat", "AlmaLinux", "Rocky Linux"]}),
            "bdu": (False, 24, {"url": "https://bdu.fstec.ru/files/documents/vulxml.zip", "verify_tls": True, "builtin_ca": True}), "eol": (True, 24, {"url": "https://endoflife.date/api/v1"}), "oval": (False, 24, {"feeds": []})}


async def ensure_sources(db: AsyncSession) -> None:
    """Строки источников по умолчанию (если миграция их не создала, например в тестах на SQLite)."""
    have = set((await db.execute(select(VdbSource.key))).scalars().all())
    for k, (en, hrs, st) in DEFAULTS.items():
        if k not in have:
            db.add(VdbSource(key=k, enabled=en, interval_hours=hrs, settings=st))
    await db.flush()
