"""Загрузчики источников: NVD (API 2.0, инкрементально по дате изменения), CISA KEV (полный каталог), OSV (по CVE и по пакетам каталога), БДУ ФСТЭК (XML-выгрузка).
Каждый загрузчик — `async def run(ctx)`; общие операции записи (поколения, сводка) — в `RunCtx`. Новый источник: функция здесь, запись в `SOURCES`, строка `vdb_sources`."""
from __future__ import annotations

import asyncio
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Awaitable, Callable

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import VdbRecord, VdbSource, utcnow
from . import parsers, store
from .fetch import FetchError, Http
from .normalize import Rec

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_URL = "https://api.osv.dev/v1"
BDU_URL = "https://bdu.fstec.ru/files/documents/vulxml.zip"
NVD_WINDOW = timedelta(days=119)           # предел NVD — 120 суток на запрос по датам
INFO = {
    "nvd": {"title": "NVD (NIST)", "url": "https://nvd.nist.gov/", "mode": "incremental", "terms": "Открытые данные правительства США; API 2.0: до 5 запросов за 30 с без ключа, до 50 — с ключом"},
    "kev": {"title": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "mode": "full", "terms": "Каталог CISA публикуется открыто, свободное использование"},
    "osv": {"title": "OSV", "url": "https://osv.dev/", "mode": "incremental", "terms": "Открытый API; данные распространяются на условиях CC-BY 4.0 и лицензий исходных баз"},
    "bdu": {"title": "БДУ ФСТЭК России", "url": "https://bdu.fstec.ru/", "mode": "full", "terms": "XML-выгрузка с сайта; условия использования — по тексту на bdu.fstec.ru (приложение хранит ссылку на первоисточник); сертификат сайта выдан российским УЦ — добавьте его в «LDAPS → Сертификаты CA»"},
}


@dataclass
class RunCtx:
    sm: async_sessionmaker[AsyncSession]
    key: str
    settings: dict
    secret: str
    cursor: dict
    http: Http
    progress: Callable[[str], Awaitable[None]]
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    file: Path | None = None
    linux_packages: Callable[[], Awaitable[list[tuple[str, str]]]] | None = None
    sleep: Callable[[float], Awaitable] = asyncio.sleep
    fetched: int = 0
    changed: int = 0
    keys: set[str] = field(default_factory=set)
    mode: str = "incremental"
    new_cursor: dict | None = None
    generation: int = 1

    async def save(self, recs: list[Rec], *, refresh: bool = True, force: bool = False) -> None:
        """Записать пачку: в активное поколение (инкрементальные источники — с пересчётом сводки) либо в подготавливаемое (refresh=False)."""
        self.fetched += len(recs)
        async with self.sm() as db:
            n, keys = await store.save_batch(db, self.generation, recs, force=force)
            if refresh and keys:
                await store.refresh_vulns(db, keys)
            await db.commit()
        self.changed += n
        self.keys |= keys

    async def begin_full(self) -> None:
        async with self.sm() as db:
            self.generation = await store.next_generation(db, self.key)
        self.mode = "full"

    async def finish_full(self) -> None:
        async with self.sm() as db:
            row = await db.get(VdbSource, self.key)
            try:
                n, keys = await store.swap_generation(db, row, self.generation)
                await store.refresh_vulns(db, keys)
            except store.IntegrityError:
                await db.rollback()
                async with self.sm() as db2:
                    await store.discard_generation(db2, self.key, self.generation)
                    await db2.commit()
                raise
            await db.commit()
        self.changed, self.keys = n, keys


# ------------------------------------------------------------------------------------------------ CISA KEV
async def run_kev(ctx: RunCtx) -> None:
    await ctx.begin_full()
    await ctx.progress("загрузка каталога CISA KEV")
    doc = await ctx.http.json(ctx.settings.get("url") or KEV_URL)
    if not isinstance(doc, dict) or "vulnerabilities" not in doc:
        raise FetchError("Ответ CISA KEV не похож на каталог (нет списка vulnerabilities)")
    recs = list(parsers.parse_kev(doc))
    for i in range(0, len(recs), 500):
        await ctx.save(recs[i:i + 500], refresh=False)
    await ctx.finish_full()
    ctx.new_cursor = {"catalog_version": doc.get("catalogVersion"), "released": doc.get("dateReleased")}


# ------------------------------------------------------------------------------------------------ БДУ ФСТЭК
async def run_bdu(ctx: RunCtx) -> None:
    await ctx.begin_full()
    tmp = ctx.file
    if tmp is None:
        from .fetch import tempdir  # noqa: PLC0415

        tmp = tempdir() / "bdu.bin"
        await ctx.progress("скачивание выгрузки БДУ")
        size = await ctx.http.download(ctx.settings.get("url") or BDU_URL, tmp)
        await ctx.progress(f"выгрузка получена: {size // 1024} КБ")
    try:
        stream = _open_xml(tmp)
        batch: list[Rec] = []
        for rec in parsers.parse_bdu(stream):
            batch.append(rec)
            if len(batch) >= 400:
                await ctx.save(batch, refresh=False)
                await ctx.progress(f"разобрано записей БДУ: {ctx.fetched}")
                batch = []
        if batch:
            await ctx.save(batch, refresh=False)
    except (zipfile.BadZipFile, ValueError) as exc:
        raise FetchError(f"Файл выгрузки БДУ повреждён или имеет неверный формат ({type(exc).__name__})") from None
    except Exception as exc:  # noqa: BLE001 — xml.etree.ParseError
        if type(exc).__name__ == "ParseError":
            raise FetchError("Файл выгрузки БДУ не является корректным XML") from None
        raise
    await ctx.progress("проверка целостности и замена данных")
    await ctx.finish_full()


def _open_xml(path: Path):
    head = path.read_bytes()[:4]
    if head[:2] == b"PK":
        z = zipfile.ZipFile(path)
        names = [n for n in z.namelist() if n.lower().endswith(".xml")]
        if not names:
            raise ValueError("в архиве нет XML")
        return z.open(names[0])
    return path.open("rb")


# ------------------------------------------------------------------------------------------------ NVD
def _nvd_dt(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


async def _nvd_pages(ctx: RunCtx, params: dict, delay: float):
    start = 0
    while True:
        doc = await ctx.http.json(NVD_URL, {**params, "resultsPerPage": 2000, "startIndex": start})
        items = doc.get("vulnerabilities") or []
        yield doc.get("totalResults", 0), items
        start += len(items)
        if not items or start >= int(doc.get("totalResults", 0)):
            return
        await ctx.sleep(delay)


async def run_nvd(ctx: RunCtx) -> None:
    delay = 0.8 if ctx.secret else 6.5
    if ctx.secret:
        ctx.http._c.headers["apiKey"] = ctx.secret  # noqa: SLF001
    cur = ctx.cursor or {}
    now = ctx.now
    if cur.get("last_mod"):
        since, field_ = datetime.fromisoformat(cur["last_mod"]), "lastMod"
    elif cur.get("pub_loaded_until"):          # прерванная первоначальная загрузка продолжается с последнего загруженного окна
        since, field_ = datetime.fromisoformat(cur["pub_loaded_until"]), "pub"
    else:
        since, field_ = now - timedelta(days=int(ctx.settings.get("history_days") or 365)), "pub"
    t = since
    while t < now:
        end = min(t + NVD_WINDOW, now)
        total = 0
        async for tot, items in _nvd_pages(ctx, {f"{field_}StartDate": _nvd_dt(t), f"{field_}EndDate": _nvd_dt(end)}, delay):
            recs = [r for r in (parsers.parse_nvd(i) for i in items) if r is not None]
            total = tot
            await ctx.save(recs)
            await ctx.progress(f"NVD: {ctx.fetched} из ~{total} записей окна {t:%Y-%m-%d}…{end:%Y-%m-%d}")
            await ctx.sleep(delay)
        t = end
        ctx.new_cursor = {"last_mod": end.isoformat()} if field_ == "lastMod" else {"pub_loaded_until": end.isoformat()}
    # после первой (по датам публикации) загрузки дальше идём по дате изменения от момента её начала
    ctx.new_cursor = {"last_mod": now.isoformat()}
    # дополнение: эксплуатируемые уязвимости (KEV), которых ещё нет в NVD-данных, — по одной (ограниченным числом за запуск)
    limit = 400 if ctx.secret else 20
    async with ctx.sm() as db:
        have = set((await db.execute(select(VdbRecord.vuln_key).join(VdbSource, store.active(VdbRecord)).where(VdbRecord.source == "nvd"))).scalars().all())
        kev = [k for k in (await db.execute(select(VdbRecord.vuln_key).join(VdbSource, store.active(VdbRecord)).where(VdbRecord.source == "kev"))).scalars().all() if k not in have]
    for k in kev[:limit]:
        doc = await ctx.http.json(NVD_URL, {"cveId": k})
        recs = [r for r in (parsers.parse_nvd(i) for i in (doc or {}).get("vulnerabilities") or []) if r is not None]
        if recs:
            await ctx.save(recs)
        await ctx.sleep(delay)
    if kev[limit:]:
        await ctx.progress(f"NVD: сведения по {len(kev) - limit} эксплуатируемым CVE будут догружены следующими запусками")
    await _nvd_rescore(ctx, delay)


async def _nvd_rescore(ctx: RunCtx, delay: float, max_pages: int = 40) -> None:
    """Повторное получение оценок CVSS: записи NVD, сохранённые прежней версией без списка оценок (scores_at пуст), заменяются целиком (ключ ext_id — дублей нет).
    Окно по дате публикации читается страницами (до 2000 записей на запрос), но сохраняются только записи, которые уже есть в локальной базе: чужие CVE из окна не загружаются.
    Если в окне ждут обновления лишь несколько записей, они запрашиваются по одной. За запуск не больше `max_pages` запросов, остальное — в следующий раз.
    Записи, которых NVD уже не отдаёт (отозваны), помечаются проверенными, чтобы их не запрашивать снова."""
    pub = VdbRecord.published
    cond = (VdbRecord.source == "nvd", VdbRecord.scores_at.is_(None), pub.is_not(None))
    pages = 0
    while pages < max_pages:
        async with ctx.sm() as db:
            lo = (await db.execute(select(func.min(pub)).join(VdbSource, store.active(VdbRecord)).where(*cond))).scalar_one()
            if lo is None:
                return
            lo = (lo if lo.tzinfo else lo.replace(tzinfo=timezone.utc)).replace(hour=0, minute=0, second=0, microsecond=0)
            end = min(lo + NVD_WINDOW, ctx.now)
            ids = select(VdbRecord.id).join(VdbSource, store.active(VdbRecord)).where(*cond, pub >= lo, pub < end + timedelta(days=1))
            pending = set((await db.execute(select(VdbRecord.ext_id).where(VdbRecord.id.in_(ids)))).scalars().all())
        if len(pending) <= 8:
            for cid in sorted(pending):
                doc = await ctx.http.json(NVD_URL, {"cveId": cid})
                recs = [r for r in (parsers.parse_nvd(i) for i in (doc or {}).get("vulnerabilities") or []) if r is not None and r.ext_id in pending]
                if recs:
                    await ctx.save(recs, force=True)
                pages += 1
                await ctx.sleep(delay)
        else:
            async for _tot, items in _nvd_pages(ctx, {"pubStartDate": _nvd_dt(lo), "pubEndDate": _nvd_dt(end)}, delay):
                pages += 1
                recs = [r for r in (parsers.parse_nvd(i) for i in items) if r is not None and r.ext_id in pending]
                if recs:
                    await ctx.save(recs, force=True)
                await ctx.progress(f"NVD: повторное получение оценок CVSS, окно {lo:%Y-%m-%d}…{end:%Y-%m-%d}")
                await ctx.sleep(delay)
        async with ctx.sm() as db:      # окно прочитано целиком: оставшиеся без оценок записи NVD больше не отдаёт
            await db.execute(update(VdbRecord).where(VdbRecord.id.in_(ids)).values(scores_at=utcnow()))
            await db.commit()


# ------------------------------------------------------------------------------------------------ OSV
async def run_osv(ctx: RunCtx) -> None:
    """OSV: (1) уточнение по CVE, уже известным локальной базе (эксплуатируемые и серьёзные), (2) уязвимости пакетов Linux из каталога для выбранных экосистем (исправления дистрибутива)."""
    cap = int(ctx.settings.get("max_per_run") or 300)
    got: set[str] = set()
    async with ctx.sm() as db:
        have = set((await db.execute(select(VdbRecord.ext_id).join(VdbSource, store.active(VdbRecord)).where(VdbRecord.source == "osv"))).scalars().all())
    ecos = [e for e in ctx.settings.get("ecosystems") or [] if e]
    if ctx.linux_packages and ecos:
        pkgs = sorted(set(await ctx.linux_packages()))[:5000]
        await ctx.progress(f"OSV: проверка {len(pkgs)} пакетов Linux, экосистемы: {', '.join(ecos)}")
        queries = [(p, v, e) for e in ecos for p, v in pkgs]
        ids: dict[str, str] = {}
        for i in range(0, len(queries), 500):
            part = queries[i:i + 500]
            doc = await ctx.http.post_json(f"{OSV_URL}/querybatch", {"queries": [{"package": {"name": p, "ecosystem": e}, "version": v} for p, v, e in part]})
            for res in doc.get("results") or []:
                for v in res.get("vulns") or []:
                    ids[v["id"]] = v.get("modified", "")
            await ctx.sleep(0.2)
        todo = [i for i in ids if i not in have][:cap]
        for n, vid in enumerate(todo):
            d = await ctx.http.json(f"{OSV_URL}/vulns/{vid}", ok404=True)
            rec = parsers.parse_osv(d) if d else None
            if rec:
                got.add(vid)
                await ctx.save([rec])
            if n % 20 == 0:
                await ctx.progress(f"OSV: загружено {n + 1} из {len(todo)} описаний пакетов")
    if ctx.settings.get("enrich", True):
        async with ctx.sm() as db:      # эксплуатируемые и критические CVE без записи OSV
            q = select(VdbRecord.vuln_key).join(VdbSource, store.active(VdbRecord)).where(VdbRecord.source.in_(("kev", "nvd")), VdbRecord.vuln_key.like("CVE-%")).distinct()
            keys = [k for k in (await db.execute(q)).scalars().all() if k not in have and k not in got]
        for k in keys[: max(0, cap - len(got))]:
            d = await ctx.http.json(f"{OSV_URL}/vulns/{k}", ok404=True)
            rec = parsers.parse_osv(d) if d else None
            if rec:
                await ctx.save([rec])
            await ctx.sleep(0.1)


SOURCES: dict[str, Callable[[RunCtx], Awaitable[None]]] = {"kev": run_kev, "bdu": run_bdu, "nvd": run_nvd, "osv": run_osv}
