"""Каталог продуктов во внутренней базе: хранение результата сборки, ручные корректировки, планировщик пересборки, выборки для интерфейса.

Каталог пересобирается фоновой задачей (контейнер worker), когда:
* его ещё нет, администратор или аналитик запросил обновление, изменились порог активности или ручные корректировки;
* изменились данные KSC — отпечаток (число действующих установок, наибольшие идентификаторы) проверяется раз в CHECK_EVERY;
* прошло больше MAX_AGE с последней сборки (активность компьютеров меняется со временем)."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from datetime import datetime, timedelta

from sqlalchemy import Integer, cast, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..config import Settings
from ..ksc import catalog_build as CB
from ..ksc.driver import KscError, Session
from ..models import CatalogOverride, CatalogProduct, CatalogState, KscSource, utcnow
from .audit import Journal
from .settings import SettingsService

log = logging.getLogger("app.catalog")
CHECK_EVERY = timedelta(minutes=15)
MAX_AGE = timedelta(hours=12)
STALE_BUILD = timedelta(hours=2)
RETRY_FAILED = timedelta(minutes=30)


# ------------------------------------------------------------------------------------------------ ручные корректировки
async def load_overrides(db: AsyncSession) -> tuple[CB.Overrides, str]:
    rows = (await db.execute(select(CatalogOverride).order_by(CatalogOverride.created_at))).scalars().all()
    ov = CB.Overrides()
    h = hashlib.sha256()
    for r in rows:
        h.update(f"{r.id}|{r.kind}|{r.from_key}|{r.match_name}|{r.to_key}|{r.to_name}|{r.to_publisher}\n".encode())
        if r.kind == "merge" and r.from_key:
            ov.merge[r.from_key] = r.to_key
        elif r.kind == "split" and r.match_name:
            ov.split[r.match_name.lower()] = (r.to_key, r.to_name or r.to_key)
        elif r.kind == "rename":
            ov.rename[r.to_key] = (r.to_name, r.to_publisher)
    return ov, h.hexdigest()[:32]


def override_out(r: CatalogOverride) -> dict:
    return {"id": str(r.id), "kind": r.kind, "from_key": r.from_key, "match_name": r.match_name, "to_key": r.to_key, "to_name": r.to_name,
            "to_publisher": r.to_publisher, "note": r.note, "created_by": r.created_by, "created_at": r.created_at}


# ------------------------------------------------------------------------------------------------ хранение
async def get_state(db: AsyncSession, source_id: uuid.UUID) -> CatalogState:
    st = await db.get(CatalogState, source_id)
    if st is None:
        st = CatalogState(source_id=source_id, status="empty")
        db.add(st)
        await db.flush()
    return st


def state_out(st: CatalogState | None) -> dict:
    if st is None:
        return {"status": "empty"}
    return {"status": st.status, "built_at": st.built_at, "started_at": st.started_at, "requested_at": st.requested_at, "activity_days": st.activity_days,
            "progress": st.progress, "error": st.error, "stats": st.stats, "duration_ms": st.duration_ms}


async def store(db: AsyncSession, source_id: uuid.UUID, families: list[dict], built_at: datetime) -> None:
    await db.execute(delete(CatalogProduct).where(CatalogProduct.source_id == source_id))
    batch = []
    for f in families:
        search = " ".join([f["name"], f["publisher"], f["key"], *[n for n, _ in f["names"][:15]]]).lower()[:4000]
        batch.append(CatalogProduct(source_id=source_id, key=f["key"][:160], name=f["name"], publisher=f["publisher"], publisher_key=f["publisher_key"][:160], origin=f["origin"],
                                    component=f["component"], platforms=f["platforms"], note=f["note"] or None, names=f["names"], versions=f["versions"], branches=f["branches"],
                                    versions_count=f["versions_count"], latest_version=(f["latest_version"] or "")[:200], scheme=f["scheme"], transform=f["transform"],
                                    hosts_all=f["hosts_all"], hosts_active=f["hosts_active"], installs_all=f["installs_all"], installs_active=f["installs_active"],
                                    first_seen=f["first_seen"], search=search, built_at=built_at))
        if len(batch) >= 500:
            db.add_all(batch)
            await db.flush()
            batch = []
    db.add_all(batch)
    await db.flush()


async def request_rebuild(db: AsyncSession, source_id: uuid.UUID) -> CatalogState:
    st = await get_state(db, source_id)
    st.requested_at = utcnow()
    return st


# ------------------------------------------------------------------------------------------------ планировщик (worker)
class CatalogScheduler:
    def __init__(self, sm: async_sessionmaker[AsyncSession], settings: Settings, svc: SettingsService, journal: Journal):
        self._sm, self._cfg, self._svc, self._journal = sm, settings, svc, journal
        self._running: set[uuid.UUID] = set()

    async def _activity_days(self, db: AsyncSession) -> int:
        return int((await self._svc.get(db, "general")).activity_days)  # type: ignore[attr-defined]

    def _params(self, src: KscSource):
        from ..reports.runner import conn_params  # noqa: PLC0415

        return conn_params(src, self._svc.decrypt(src.password_enc, f"source.{src.id}"))

    async def due(self, db: AsyncSession, src: KscSource, activity_days: int, rev: str) -> str | None:
        """Причина пересборки или None."""
        st = await get_state(db, src.id)
        now = utcnow()
        if st.status == "building" and st.started_at and now - st.started_at < STALE_BUILD:
            return None
        if st.status in ("empty",) or st.built_at is None:
            return "первая сборка" if not (st.status == "failed" and st.started_at and now - st.started_at < RETRY_FAILED) else None
        if st.status == "failed" and st.started_at and now - st.started_at < RETRY_FAILED:
            return None
        if st.requested_at and st.requested_at > (st.started_at or st.built_at):
            return "запрошено пользователем"
        if st.activity_days != activity_days:
            return "изменён порог активности"
        if st.overrides_rev != rev:
            return "изменены ручные корректировки"
        if now - st.built_at > MAX_AGE:
            return "плановое обновление"
        if st.checked_at is None or now - st.checked_at > CHECK_EVERY:
            st.checked_at = now
            await db.commit()
            try:
                sig = await asyncio.to_thread(self._signature, src)
            except KscError as exc:
                log.warning("Отпечаток данных KSC не получен", extra={"source": src.name, "error": exc.message})
                return None
            if sig != st.signature:
                return "изменились данные KSC"
        return None

    def _signature(self, src: KscSource) -> str:
        with Session(self._params(src)) as s:
            return CB.signature(s)

    async def build(self, source_id: uuid.UUID, reason: str = "") -> None:
        if source_id in self._running:
            return
        self._running.add(source_id)
        started = time.perf_counter()
        try:
            async with self._sm() as db:
                src = await db.get(KscSource, source_id)
                if src is None:
                    return
                activity_days = await self._activity_days(db)
                ov, rev = await load_overrides(db)
                st = await get_state(db, source_id)
                st.status, st.started_at, st.progress, st.error = "building", utcnow(), "запуск", None
                await db.commit()
                params = self._params(src)
                name = src.name
            loop = asyncio.get_running_loop()

            def progress(text: str) -> None:
                loop.call_soon_threadsafe(lambda: asyncio.ensure_future(self._progress(source_id, text)))

            def work():
                with Session(params) as s:
                    sig = CB.signature(s)
                    fams, stats = CB.build(s, activity_days=activity_days, overrides=ov, progress=progress)
                    return sig, fams, stats

            sig, fams, stats = await asyncio.to_thread(work)
            ms = int((time.perf_counter() - started) * 1000)
            async with self._sm() as db:
                now = utcnow()
                await store(db, source_id, fams, now)
                st = await get_state(db, source_id)
                st.status, st.built_at, st.signature, st.activity_days, st.overrides_rev = "ready", now, sig, activity_days, rev
                st.checked_at, st.progress, st.error, st.stats, st.duration_ms = now, "готово", None, stats, ms
                await db.commit()
            await self._journal.emit("catalog", "catalog_built", source=name, duration_ms=ms,
                                     message=f"Каталог построен ({reason or 'обновление'}): продуктов {stats['products']}, установок {stats['installs']}")
        except (KscError, CB.Cancelled, Exception) as exc:  # noqa: BLE001
            msg = exc.message if isinstance(exc, KscError) else f"{type(exc).__name__}: {exc}"[:300]
            if not isinstance(exc, KscError):
                log.exception("Сбой сборки каталога", extra={"source_id": str(source_id)})
            async with self._sm() as db:
                st = await get_state(db, source_id)
                st.status, st.error, st.progress = ("failed" if st.built_at is None else "ready"), msg, "ошибка"
                if st.built_at is not None:
                    st.started_at = utcnow()          # не повторять сразу: следующая попытка — по расписанию
                    st.error = f"Последнее обновление не удалось: {msg}"
                await db.commit()
            await self._journal.emit("catalog", "catalog_failed", level="error", message=f"Каталог не построен: {msg}", data={"source_id": str(source_id)})
        finally:
            self._running.discard(source_id)

    async def _progress(self, source_id: uuid.UUID, text: str) -> None:
        try:
            async with self._sm() as db:
                st = await db.get(CatalogState, source_id)
                if st is not None and st.status == "building":       # запоздавшее сообщение не затирает итог сборки
                    st.progress = text[:300]
                    await db.commit()
        except Exception:  # noqa: BLE001
            pass

    async def tick(self) -> None:
        async with self._sm() as db:
            sources = (await db.execute(select(KscSource).where(KscSource.is_active.is_(True)).order_by(KscSource.position))).scalars().all()
            activity_days = await self._activity_days(db)
            _ov, rev = await load_overrides(db)
            todo = []
            for src in sources:
                if (src.last_check or {}).get("features", {}).get("software", {}).get("ok") is False:
                    continue
                reason = await self.due(db, src, activity_days, rev)
                if reason:
                    todo.append((src.id, reason))
            await db.commit()
        for sid, reason in todo:
            await self.build(sid, reason)

    async def loop(self) -> None:
        await asyncio.sleep(5)
        while True:
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка цикла каталога")
            await asyncio.sleep(30)


# ------------------------------------------------------------------------------------------------ выборки
SORTS = {"hosts": None, "name": CatalogProduct.name, "publisher": CatalogProduct.publisher, "versions": CatalogProduct.versions_count, "first_seen": CatalogProduct.first_seen}


def product_out(p: CatalogProduct, *, all_hosts: bool, full: bool = False) -> dict:
    hosts = p.hosts_all if all_hosts else p.hosts_active
    vs = [v for v in p.versions if all_hosts or v.get("hosts_active")]
    defined = [v for v in vs if v.get("branch")]
    out = {"key": p.key, "name": p.name, "publisher": p.publisher, "publisher_key": p.publisher_key, "origin": p.origin, "component": p.component,
           "platforms": [x for b, x in ((1, "Windows"), (2, "Linux")) if p.platforms & b], "hosts": hosts, "hosts_all": p.hosts_all, "hosts_active": p.hosts_active,
           "hidden_hosts": p.hosts_all - p.hosts_active, "installs": p.installs_all if all_hosts else p.installs_active, "versions_count": len(vs),
           "latest_version": defined[0]["version"] if defined else (vs[0]["version"] if vs else p.latest_version),
           "oldest_version": defined[-1]["version"] if defined else (vs[-1]["version"] if vs else ""),
           "branches": [{"branch": b["branch"], "hosts": b["hosts"] if all_hosts else b["hosts_active"]} for b in p.branches if all_hosts or b.get("hosts_active")][:12],
           "first_seen": p.first_seen, "built_at": p.built_at, "scheme": p.scheme}
    if full:
        out.update({"note": p.note, "names": p.names, "transform": p.transform,
                    "versions": [{**{k: v[k] for k in ("version", "branch", "scheme", "raw", "names")}, "platform": [x for b, x in ((1, "Windows"), (2, "Linux")) if v["platform"] & b],
                                  "hosts": v["hosts"] if all_hosts else v["hosts_active"], "hosts_all": v["hosts"], "installs": v["installs"] if all_hosts else v["installs_active"],
                                  "records": len(v["product_ids"])} for v in vs],
                    "branches": [{**b, "hosts_shown": b["hosts"] if all_hosts else b["hosts_active"]} for b in p.branches if all_hosts or b.get("hosts_active")]})
    return out


async def query(db: AsyncSession, source_id: uuid.UUID, *, q: str = "", publisher_key: str = "", platform: str = "", sort: str = "hosts", desc: bool = True,
                all_hosts: bool = False, components: bool = False, offset: int = 0, limit: int = 50) -> dict:
    hosts_col = CatalogProduct.hosts_all if all_hosts else CatalogProduct.hosts_active
    conds = [CatalogProduct.source_id == source_id, hosts_col > 0]
    if q.strip():
        for word in q.strip().lower().split()[:5]:
            conds.append(CatalogProduct.search.like(f"%{word}%"))
    if publisher_key:
        conds.append(CatalogProduct.publisher_key == publisher_key)
    if platform in ("windows", "linux"):
        conds.append(CatalogProduct.platforms.op("&")(1 if platform == "windows" else 2) != 0)
    if not components:
        conds.append(CatalogProduct.component.is_(False))
    col = SORTS.get(sort) or hosts_col
    order = [col.desc() if desc else col.asc(), CatalogProduct.name]
    total = (await db.execute(select(func.count()).select_from(CatalogProduct).where(*conds))).scalar_one()
    rows = (await db.execute(select(CatalogProduct).where(*conds).order_by(*order).offset(offset).limit(limit))).scalars().all()
    return {"items": [product_out(p, all_hosts=all_hosts) for p in rows], "total": total, "offset": offset, "limit": limit}


async def publishers(db: AsyncSession, source_id: uuid.UUID, *, q: str = "", all_hosts: bool = False, offset: int = 0, limit: int = 50) -> dict:
    hosts_col = CatalogProduct.hosts_all if all_hosts else CatalogProduct.hosts_active
    conds = [CatalogProduct.source_id == source_id, hosts_col > 0, CatalogProduct.component.is_(False), CatalogProduct.publisher_key != ""]
    if q.strip():
        conds.append(or_(func.lower(CatalogProduct.publisher).like(f"%{q.strip().lower()}%"), CatalogProduct.search.like(f"%{q.strip().lower()}%")))
    grp = (select(CatalogProduct.publisher_key, func.max(CatalogProduct.publisher).label("publisher"), func.count().label("products"),
                  func.max(hosts_col).label("max_hosts"), func.sum(hosts_col).label("sum_hosts"))
           .where(*conds).group_by(CatalogProduct.publisher_key))
    total = (await db.execute(select(func.count()).select_from(grp.subquery()))).scalar_one()
    rows = (await db.execute(grp.order_by(func.max(hosts_col).desc()).offset(offset).limit(limit))).all()
    out = []
    for r in rows:
        top = (await db.execute(select(CatalogProduct.name).where(*conds, CatalogProduct.publisher_key == r.publisher_key).order_by(hosts_col.desc()).limit(4))).scalars().all()
        out.append({"publisher_key": r.publisher_key, "publisher": r.publisher, "products": r.products, "max_hosts": int(r.max_hosts or 0), "top": list(top)})
    return {"items": out, "total": total, "offset": offset, "limit": limit}


async def product(db: AsyncSession, source_id: uuid.UUID, key: str) -> CatalogProduct | None:
    return await db.get(CatalogProduct, (source_id, key))


async def search_keys(db: AsyncSession, source_ids: list[uuid.UUID], q: str, limit: int = 20) -> list[dict]:
    """Поиск продукта для конструктора отчётов: по всем выбранным источникам, ключ одинаков во всех источниках."""
    conds = [CatalogProduct.source_id.in_(source_ids), CatalogProduct.hosts_all > 0]
    for word in q.strip().lower().split()[:5]:
        conds.append(CatalogProduct.search.like(f"%{word}%"))
    rows = (await db.execute(select(CatalogProduct.key, func.max(CatalogProduct.name), func.max(CatalogProduct.publisher), func.sum(CatalogProduct.hosts_active),
                                    func.sum(CatalogProduct.hosts_all), func.max(CatalogProduct.latest_version), func.max(cast(CatalogProduct.component, Integer)))
                             .where(*conds).group_by(CatalogProduct.key).order_by(func.sum(CatalogProduct.hosts_active).desc()).limit(limit))).all()
    return [{"key": k, "name": n, "publisher": p, "hosts": int(ha or 0), "hosts_all": int(hall or 0), "latest_version": lv, "component": bool(c)} for k, n, p, ha, hall, lv, c in rows]


async def resolve_items(db: AsyncSession, source_id: uuid.UUID, items: list[dict]) -> tuple[list[dict], list[str]]:
    """Пункты проверки для источника: ключ каталога → идентификаторы записей реестра этого источника. Возвращает также программы, которых в источнике нет."""
    out, missing = [], []
    for it in items:
        it = dict(it)
        if (it.get("kind") or "product") == "product":
            row = await db.get(CatalogProduct, (source_id, it.get("product_key") or ""))
            it["product_ids"] = sorted({int(pid) for v in (row.versions if row else []) for pid in v.get("product_ids", [])})
            if row is None:
                missing.append(it.get("product_name") or it.get("product_key") or "?")
            elif not it.get("product_name"):
                it["product_name"] = row.name
        out.append(it)
    return out, missing


async def catalog_ready(db: AsyncSession, source_id: uuid.UUID) -> bool:
    st = await db.get(CatalogState, source_id)
    return st is not None and st.built_at is not None


def time_ago(dt: datetime | None) -> float | None:
    return None if dt is None else (utcnow() - dt).total_seconds()
