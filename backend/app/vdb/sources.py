"""Загрузчики источников: NVD (официальные ленты JSON 2.0 по годам и «изменённые», запасной канал — API 2.0), CISA KEV (cisa.gov, запасной — GitHub cisagov/kev-data),
OSV (официальные архивы по экосистемам и modified_id.csv), БДУ ФСТЭК (XML-выгрузка с сайта по проверенному TLS либо файл, загруженный вручную).

Каждый источник — список каналов; при ошибке канала пробуется следующий, все попытки (канал, результат, время, причина) сохраняются для диагностики.
Первоначальная загрузка и пересборка пишутся в новое «поколение» и становятся действующими только после проверки (`finish_full`): непустая и не меньше половины прежней.
Последующие обновления — по изменившимся записям в действующее поколение (каждая запись целиком, в своей транзакции). Скачанные файлы — потоково во временный
каталог на томе данных, свободное место проверяется до скачивания, файлы удаляются сразу после разбора. Новый источник: каналы здесь, запись в `SOURCES`/`INFO`, строка `vdb_sources`."""
from __future__ import annotations

import asyncio
import gzip
import json
import shutil
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Awaitable, Callable
from urllib.parse import quote

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import VdbRecord, VdbSource, utcnow
from . import parsers, store
from .fetch import FetchError, Http, tempdir
from .normalize import Rec
from .stream import iter_array, sha256_stream

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_FEEDS = "https://nvd.nist.gov/feeds/json/cve/2.0"
KEV_URLS = (("cisa", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
            ("github", "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"))
OSV_BUCKET = "https://storage.googleapis.com/osv-vulnerabilities"
OSV_API = "https://api.osv.dev/v1"
BDU_URL = "https://bdu.fstec.ru/files/documents/vulxml.zip"
NVD_WINDOW = timedelta(days=119)           # предел NVD — 120 суток на запрос по датам
FEED_HORIZON = timedelta(days=7)            # лента «изменённые» хранит последние 8 суток
OSV_INCR_MAX = 4000                          # изменённых записей одной экосистемы за запуск; больше — перезагрузка архивом
BATCH = 400
PARSER_REV = 2            # растёт при улучшении разбора БДУ: следующая загрузка перечитывает выгрузку, даже если файл на сайте не менялся
OSV_ECOSYSTEMS = ("AlmaLinux", "Alpaquita", "Alpine", "Android", "Azure Linux", "BellSoft Hardened Containers", "Bitnami", "CRAN", "Chainguard", "CleanStart", "Debian", "Echo", "GHC",
                  "GIT", "GSD", "GitHub Actions", "Go", "Hackage", "Hex", "Julia", "Linux", "Mageia", "Maven", "MinimOS", "NuGet", "OSS-Fuzz", "Packagist", "Pub", "PyPI", "Red Hat",
                  "Rocky Linux", "Root", "RubyGems", "SUSE", "SwiftURL", "TuxCare", "Ubuntu", "VSCode", "Wolfi", "crates.io", "npm", "opam", "openEuler", "openSUSE")
OSV_DEFAULT = ["Debian", "Alpine", "Red Hat", "AlmaLinux", "Rocky Linux"]       # ≈120 МБ архивов; Ubuntu (≈750 МБ) включается отдельно
INFO = {
    "nvd": {"title": "NVD (NIST)", "url": "https://nvd.nist.gov/", "mode": "incremental", "channels": ["Ленты JSON 2.0 (nvd.nist.gov/feeds)", "API 2.0 (services.nvd.nist.gov)"],
            "terms": "Открытые данные правительства США. Первая загрузка — официальные ленты по годам (сотни мегабайт, потоком), дальше — лента «изменённые» (суточные изменения); запасной канал — API 2.0 (без ключа 5 запросов за 30 с)"},
    "kev": {"title": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "mode": "full", "keep_previous": True, "channels": ["cisa.gov (JSON)", "GitHub cisagov/kev-data (JSON)"],
            "terms": "Каталог CISA публикуется открыто, свободное использование; запасной канал — официальный репозиторий CISA на GitHub"},
    "osv": {"title": "OSV", "url": "https://osv.dev/", "mode": "incremental", "channels": ["Архивы экосистем и modified_id.csv (storage.googleapis.com/osv-vulnerabilities)"],
            "terms": "Открытая выгрузка; данные распространяются на условиях CC-BY 4.0 и лицензий исходных баз. Первая загрузка — архивы выбранных экосистем, дальше — только изменённые записи"},
    "eol": {"title": "endoflife.date (жизненный цикл ПО)", "url": "https://endoflife.date/docs/api/v1/", "mode": "incremental", "own_store": True, "channels": ["API v1 endoflife.date (products/full)"],
            "terms": "Открытый API endoflife.date (лицензия MIT на данные). Это не база уязвимостей: сведения о датах окончания поддержки продуктов и их веток. Документ загружается условным запросом (ETag); изменившиеся продукты обновляются, остальные не переписываются. Окончание поддержки показывается как отдельная проблема EOL, а не как CVE"},
    "oval": {"title": "OVAL (определения проверок)", "url": "https://oval.mitre.org/", "mode": "full", "own_store": True, "channels": ["Фиды OVAL по адресам из настроек (XML, .bz2, .gz)"],
             "terms": "Фиды задаёт администратор (Ubuntu, Debian, Red Hat и др.): определения vulnerability/patch с CVE хранятся отдельно от записей баз уязвимостей. OVAL описывает проверки состояния системы: по сети можно "
                      "проверить лишь версию сервиса, поэтому тесты пакетов оцениваются только по перечню пакетов устройства, явно связанного с KSC; остальные — «недостаточно данных»"},
    "bdu": {"title": "БДУ ФСТЭК России", "url": "https://bdu.fstec.ru/", "mode": "full", "channels": ["Выгрузка vulxml.zip с сайта bdu.fstec.ru", "Файл, загруженный вручную"],
            "terms": "XML-выгрузка с сайта (≈34 МБ в архиве); условия использования — по тексту на bdu.fstec.ru, приложение хранит ссылку на первоисточник. Сертификат сайта выдан УЦ Минцифры России: его корневой и промежуточный сертификаты поставляются с приложением и применяются только к этому источнику"},
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
    sleep: Callable[[float], Awaitable] = asyncio.sleep
    data_dir: Path | None = None
    has_data: bool = False                  # в действующем поколении уже есть записи источника
    force: bool = False                     # ручной запуск («Обновить сейчас»): условные запросы не используются
    fetched: int = 0
    changed: int = 0
    keys: set[str] = field(default_factory=set)
    mode: str = "incremental"
    new_cursor: dict | None = None
    generation: int = 1                     # поколение, в которое пишутся записи (у инкрементальной загрузки — действующее)
    channel: str = ""
    attempts: list[dict] = field(default_factory=list)
    _tmp: Path | None = None
    _swapped: bool = False

    def dl_progress(self, what: str):
        async def cb(done: int, total: int) -> None:
            await self.progress(f"{what}: скачано {done >> 20} из {total >> 20} МБ" if total else f"{what}: скачано {done >> 20} МБ")
        return cb

    def tmp(self) -> Path:
        if self._tmp is None:
            self._tmp = tempdir((self.data_dir / "vdb" / "tmp") if self.data_dir else None)
        return self._tmp

    def cleanup(self) -> None:
        if self._tmp is not None:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None

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

    async def drop(self, ext_ids: list[str]) -> None:
        """Записи, отозванные источником (в инкрементальной загрузке): удаляются из действующего поколения, сводка пересчитывается."""
        if not ext_ids:
            return
        async with self.sm() as db:
            keys = await store.delete_records(db, self.key, self.generation, ext_ids)
            if keys:
                await store.refresh_vulns(db, keys)
            await db.commit()
        self.changed += len(ext_ids)
        self.keys |= keys

    async def begin_full(self) -> None:
        async with self.sm() as db:
            self.generation = await store.next_generation(db, self.key)
        self.mode, self._swapped = "full", False

    async def finish_full(self) -> None:
        async with self.sm() as db:
            row = await db.get(VdbSource, self.key)
            try:
                n, keys = await store.swap_generation(db, row, self.generation, keep_prev=INFO[self.key].get("keep_previous", False))
                await store.refresh_vulns(db, keys)
            except store.IntegrityError:
                await db.rollback()
                await self.discard()
                raise
            await db.commit()
        self.changed, self.keys, self._swapped, self.has_data = n, keys, True, True

    async def discard(self) -> None:
        """Отбросить недозагруженное поколение: действующие данные не затрагиваются."""
        if self.mode == "full" and not self._swapped:
            async with self.sm() as db:
                await store.discard_generation(db, self.key, self.generation)
                await db.commit()
            self._swapped = True


# ------------------------------------------------------------------------------------------------ каналы
Channel = tuple[str, str, Callable[[RunCtx], Awaitable[None]]]


async def run_channels(ctx: RunCtx, channels: list[Channel]) -> None:
    """Пробует каналы по очереди; результат каждой попытки сохраняется в ctx.attempts. Недозагруженное поколение отбрасывается, действующие данные остаются."""
    errors: list[str] = []
    for key, title, fn in channels:
        t0, start = time.perf_counter(), ctx.fetched
        ctx.channel = key
        await ctx.progress(f"канал «{title}»")
        try:
            await fn(ctx)
        except (FetchError, store.IntegrityError, zipfile.BadZipFile, ValueError, OSError) as exc:
            await ctx.discard()
            ctx.cleanup()
            msg = str(exc) if isinstance(exc, (FetchError, store.IntegrityError)) else f"{type(exc).__name__}: {str(exc)[:200]}"
            ctx.attempts.append({"channel": key, "title": title, "ok": False, "error": msg[:600], "ms": int((time.perf_counter() - t0) * 1000), "records": ctx.fetched - start})
            errors.append(f"{title}: {msg}")
            ctx.fetched = start
            continue
        ctx.cleanup()
        ctx.attempts.append({"channel": key, "title": title, "ok": True, "error": "", "ms": int((time.perf_counter() - t0) * 1000), "records": ctx.fetched - start})
        return
    raise FetchError("Данные не получены ни одним каналом. " + " | ".join(errors))


# ------------------------------------------------------------------------------------------------ CISA KEV
def _kev_channel(name: str, default_url: str) -> Callable[[RunCtx], Awaitable[None]]:
    async def run(ctx: RunCtx) -> None:
        url = (ctx.settings.get("url") if name == "cisa" else "") or default_url
        await ctx.begin_full()
        await ctx.progress("загрузка каталога CISA KEV")
        doc = await ctx.http.json(url)
        if not isinstance(doc, dict) or "vulnerabilities" not in doc:
            raise FetchError("Ответ не похож на каталог CISA KEV (нет списка vulnerabilities)")
        recs = list(parsers.parse_kev(doc))
        if not recs:
            raise FetchError("В каталоге нет ни одной записи: файл неполный")
        for i in range(0, len(recs), 500):
            await ctx.save(recs[i:i + 500], refresh=False)
        await ctx.progress("проверка целостности и замена данных")
        await ctx.finish_full()
        ctx.new_cursor = {"catalog_version": doc.get("catalogVersion"), "released": doc.get("dateReleased")}
    return run


async def run_kev(ctx: RunCtx) -> None:
    await run_channels(ctx, [(n, t, _kev_channel(n, u)) for (n, u), t in zip(KEV_URLS, INFO["kev"]["channels"])])


# ------------------------------------------------------------------------------------------------ БДУ ФСТЭК
def _open_xml(path: Path):
    if path.read_bytes()[:2] == b"PK":
        z = zipfile.ZipFile(path)
        names = [n for n in z.namelist() if n.lower().endswith(".xml")]
        if not names:
            raise ValueError("в архиве нет XML")
        return z.open(names[0])
    return path.open("rb")


async def _bdu_parse(ctx: RunCtx, path: Path) -> None:
    if path.read_bytes()[:2] == b"PK":
        try:
            bad = zipfile.ZipFile(path).testzip()
        except zipfile.BadZipFile as exc:
            raise FetchError(f"Файл выгрузки БДУ повреждён ({exc})") from None
        if bad:
            raise FetchError(f"Файл выгрузки БДУ повреждён (запись {bad})")
    await ctx.begin_full()
    batch: list[Rec] = []
    try:
        with _open_xml(path) as stream:
            for rec in parsers.parse_bdu(stream):
                batch.append(rec)
                if len(batch) >= BATCH:
                    await ctx.save(batch, refresh=False)
                    await ctx.progress(f"разбор выгрузки БДУ: записей {ctx.fetched}")
                    batch = []
    except Exception as exc:  # noqa: BLE001 — xml.etree.ParseError
        if type(exc).__name__ == "ParseError":
            raise FetchError("Файл выгрузки БДУ не является корректным XML (обрыв или повреждение)") from None
        raise
    if batch:
        await ctx.save(batch, refresh=False)
    await ctx.progress("проверка целостности и замена данных")
    await ctx.finish_full()


async def _bdu_site(ctx: RunCtx) -> None:
    url = ctx.settings.get("url") or BDU_URL
    cur = ctx.cursor or {}
    dest = ctx.tmp() / "bdu.zip"
    await ctx.progress("скачивание выгрузки БДУ")
    cond = ctx.has_data and not ctx.force and cur.get("rev") == PARSER_REV          # ручной запуск и новая версия разбора — выгрузка читается заново
    got = await ctx.http.download(url, dest, etag=cur.get("etag", "") if cond else "", last_modified=cur.get("last_modified", "") if cond else "", progress=ctx.dl_progress("выгрузка БДУ"))
    if got.not_modified:                # на сайте нет новой выгрузки: действующая копия актуальна
        await ctx.progress("выгрузка на сайте не изменилась")
        return
    await ctx.progress(f"выгрузка получена: {got.size // 1024} КБ")
    await _bdu_parse(ctx, dest)
    ctx.new_cursor = {"etag": got.etag, "last_modified": got.last_modified, "size": got.size, "rev": PARSER_REV}


async def _bdu_file(ctx: RunCtx) -> None:
    if ctx.file is None:
        raise FetchError("Файл выгрузки не загружен: загрузите XML или ZIP из БДУ")
    await _bdu_parse(ctx, ctx.file)


async def run_bdu(ctx: RunCtx) -> None:
    if ctx.file is not None:            # администратор загрузил файл сам: сайт не опрашивается
        await run_channels(ctx, [("file", INFO["bdu"]["channels"][1], _bdu_file)])
    else:
        await run_channels(ctx, [("site", INFO["bdu"]["channels"][0], _bdu_site)])


# ------------------------------------------------------------------------------------------------ NVD
def _nvd_dt(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _parse_meta(text: str) -> dict:
    return {k.strip(): v.strip() for k, _, v in (ln.partition(":") for ln in text.splitlines() if ":" in ln)}


async def _feed_apply(ctx: RunCtx, name: str, *, refresh: bool) -> None:
    """Лента NVD: скачивание, проверка размера и SHA-256 распакованного потока по файлу .meta (до разбора — повреждённые данные не применяются), потоковый разбор."""
    meta_r = await ctx.http.get(f"{NVD_FEEDS}/{name}.meta")
    meta = _parse_meta(meta_r.text) if meta_r is not None else {}
    gz = ctx.tmp() / f"{name}.json.gz"
    await ctx.progress(f"{name}: скачивание")
    await ctx.http.download(f"{NVD_FEEDS}/{name}.json.gz", gz, progress=ctx.dl_progress(name))
    try:
        with gzip.open(gz, "rb") as f:
            digest, size = sha256_stream(f)
        if meta.get("sha256") and digest != meta["sha256"].upper():
            raise FetchError(f"Лента {name}: контрольная сумма не совпала с {name}.meta (файл повреждён или обновился во время скачивания)")
        if meta.get("size") and size != int(meta["size"]):
            raise FetchError(f"Лента {name}: размер {size} байт не совпадает с {name}.meta")
        start, batch, rejected = ctx.fetched, [], []
        with gzip.open(gz, "rb") as f:
            for item in iter_array(f, "vulnerabilities"):
                rec = parsers.parse_nvd(item)
                if rec is None:
                    if refresh and str((item.get("cve") or {}).get("vulnStatus") or "").lower() == "rejected":
                        rejected.append(str((item.get("cve") or {}).get("id") or "").upper())       # в обновлениях: ранее загруженная запись отозвана
                    continue
                batch.append(rec)
                if len(batch) >= BATCH:
                    await ctx.save(batch, refresh=refresh)
                    batch = []
                    await ctx.progress(f"{name}: записей {ctx.fetched}")
        if batch:
            await ctx.save(batch, refresh=refresh)
        await ctx.drop(rejected)
        if ctx.fetched == start and not name.endswith("modified"):
            raise FetchError(f"Лента {name} не содержит записей")
    finally:
        gz.unlink(missing_ok=True)


async def _nvd_feeds(ctx: RunCtx) -> None:
    """Ленты JSON 2.0: первая загрузка — годы за `years_back` (по умолчанию 3) в новое поколение; обновления — лента «изменённые» (если с прошлой загрузки ≤ 7 суток),
    иначе ленты текущего года и года прошлой загрузки; увеличенная глубина истории догружает более ранние годы."""
    years_back = max(1, min(30, int(ctx.settings.get("years_back") or 3)))
    now = ctx.now
    first = now.year - years_back + 1
    cur = ctx.cursor or {}
    last_mod = datetime.fromisoformat(cur["last_mod"]) if cur.get("last_mod") and cur.get("feed") == "feeds" else None
    have_from = int(cur.get("years_from") or 0)
    if not ctx.has_data or last_mod is None:
        await ctx.begin_full()
        for y in range(first, now.year + 1):
            await _feed_apply(ctx, f"nvdcve-2.0-{y}", refresh=False)
        await ctx.progress("проверка целостности и построение сводки")
        await ctx.finish_full()
        years_from = first
        await _feed_apply(ctx, "nvdcve-2.0-modified", refresh=True)         # изменения после сборки годовых лент
    else:
        years_from = min(have_from or first, first)
        for y in range(first, have_from or first):
            await _feed_apply(ctx, f"nvdcve-2.0-{y}", refresh=True)
        if now - last_mod <= FEED_HORIZON:
            await _feed_apply(ctx, "nvdcve-2.0-modified", refresh=True)
        else:
            for y in range(max(first, last_mod.year), now.year + 1):
                await _feed_apply(ctx, f"nvdcve-2.0-{y}", refresh=True)
    ctx.new_cursor = {"last_mod": now.isoformat(), "years_from": years_from, "feed": "feeds"}


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


async def _nvd_api(ctx: RunCtx) -> None:
    """Запасной канал: API 2.0 — окна по дате изменения (после первой загрузки) или публикации (первая загрузка за history_days). Скорость ограничена правилами NVD."""
    delay = 0.8 if ctx.secret else 6.5
    if ctx.secret:
        ctx.http._c.headers["apiKey"] = ctx.secret  # noqa: SLF001
    cur = ctx.cursor or {}
    now = ctx.now
    if cur.get("last_mod") and ctx.has_data:
        since, field_ = datetime.fromisoformat(cur["last_mod"]), "lastMod"
    elif cur.get("pub_loaded_until"):          # прерванная первоначальная загрузка продолжается с последнего загруженного окна
        since, field_ = datetime.fromisoformat(cur["pub_loaded_until"]), "pub"
    else:
        since, field_ = now - timedelta(days=int(ctx.settings.get("history_days") or 365)), "pub"
    t = since
    while t < now:
        end = min(t + NVD_WINDOW, now)
        async for tot, items in _nvd_pages(ctx, {f"{field_}StartDate": _nvd_dt(t), f"{field_}EndDate": _nvd_dt(end)}, delay):
            recs = [r for r in (parsers.parse_nvd(i) for i in items) if r is not None]
            await ctx.save(recs)
            await ctx.progress(f"NVD API: {ctx.fetched} из ~{tot} записей окна {t:%Y-%m-%d}…{end:%Y-%m-%d}")
            await ctx.sleep(delay)
        t = end
        ctx.new_cursor = {"last_mod": end.isoformat(), "feed": "api"} if field_ == "lastMod" else {"pub_loaded_until": end.isoformat()}
    ctx.new_cursor = {"last_mod": now.isoformat(), "feed": "api"}


async def _nvd_kev_supplement(ctx: RunCtx) -> None:
    """Эксплуатируемые уязвимости (KEV), которых нет в данных NVD (старше глубины истории), — по одной через API (ограниченным числом за запуск)."""
    delay = 0.8 if ctx.secret else 6.5
    if ctx.secret:
        ctx.http._c.headers["apiKey"] = ctx.secret  # noqa: SLF001
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


async def run_nvd(ctx: RunCtx) -> None:
    await run_channels(ctx, [("feeds", INFO["nvd"]["channels"][0], _nvd_feeds), ("api", INFO["nvd"]["channels"][1], _nvd_api)])
    try:      # дополнения не должны отменять уже успешную загрузку
        await _nvd_kev_supplement(ctx)
        await _nvd_rescore(ctx, 0.8 if ctx.secret else 6.5)
    except FetchError as exc:
        ctx.attempts.append({"channel": "supplement", "title": "Дополнение: эксплуатируемые CVE и оценки CVSS", "ok": False, "error": str(exc)[:300], "ms": 0, "records": 0})


# ------------------------------------------------------------------------------------------------ OSV
def _eco_url(eco: str, tail: str) -> str:
    return f"{OSV_BUCKET}/{quote(eco)}/{tail}" if eco else f"{OSV_BUCKET}/{tail}"


async def _osv_zip(ctx: RunCtx, eco: str) -> str:
    """Архив экосистемы (или всей базы) → записи нового поколения; архив удаляется после разбора. Возвращает самую позднюю дату изменения записей."""
    name = eco or "вся база"
    dest = ctx.tmp() / "osv.zip"
    await ctx.progress(f"OSV {name}: скачивание архива")
    got = await ctx.http.download(_eco_url(eco, "all.zip"), dest, progress=ctx.dl_progress(f"OSV {name}"))
    await ctx.progress(f"OSV {name}: архив получен ({got.size >> 20} МБ), разбор")
    newest, batch = "", []
    with zipfile.ZipFile(dest) as z:
        bad = z.testzip()
        if bad is not None:
            raise FetchError(f"Архив OSV {name} повреждён (запись {bad})")
        for info in z.infolist():
            if not info.filename.endswith(".json"):
                continue
            with z.open(info) as f:
                doc = json.load(f)
            newest = max(newest, str(doc.get("modified") or ""))
            rec = parsers.parse_osv(doc)
            if rec is None:
                continue
            batch.append(rec)
            if len(batch) >= BATCH:
                await ctx.save(batch, refresh=False)
                batch = []
                await ctx.progress(f"OSV {name}: разобрано записей {ctx.fetched}")
    if batch:
        await ctx.save(batch, refresh=False)
    dest.unlink(missing_ok=True)
    return newest


async def _osv_modified(ctx: RunCtx, eco: str, since: str) -> list[str]:
    """Идентификаторы записей экосистемы, изменённых после `since`: modified_id.csv идёт от новых к старым и читается потоком до первой старой строки."""
    ids: list[str] = []
    url = _eco_url(eco, "modified_id.csv")
    try:
        async with ctx.http._c.stream("GET", url) as r:  # noqa: SLF001
            if r.status_code >= 400:
                raise FetchError(f"{url.split('/')[2]}: HTTP {r.status_code}")
            async for line in r.aiter_lines():
                ts, _, rid = line.partition(",")
                if not rid:
                    continue
                if ts <= since:
                    break
                ids.append(rid.strip())
                if len(ids) > OSV_INCR_MAX:
                    break
    except FetchError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise FetchError(f"{url.split('/')[2]}: {type(exc).__name__}: {str(exc)[:160]}") from None
    return ids


async def _osv_archives(ctx: RunCtx) -> None:
    ecos = [e for e in (ctx.settings.get("ecosystems") or OSV_DEFAULT) if e in OSV_ECOSYSTEMS]
    targets = [""] if ctx.settings.get("all_ecosystems") else ecos
    if not targets:
        raise FetchError("Не выбрана ни одна экосистема OSV")
    cur = dict(ctx.cursor or {})
    marks: dict[str, str] = dict(cur.get("modified") or {})
    pending: dict[str, list[str]] | None = None
    if ctx.has_data and sorted(cur.get("targets") or []) == sorted(targets) and all(marks.get(e) for e in targets):
        pending = {}
        for eco in targets:
            ids = await _osv_modified(ctx, eco, marks[eco])
            if len(ids) > OSV_INCR_MAX:             # слишком много изменений (долгий перерыв): проще и надёжнее перезагрузить архив
                pending = None
                break
            pending[eco] = ids
    if pending is None:
        await ctx.begin_full()
        marks = {}
        for eco in targets:
            marks[eco] = await _osv_zip(ctx, eco)
        await ctx.progress("проверка целостности и построение сводки")
        await ctx.finish_full()
    else:
        for eco, ids in pending.items():
            newest = marks.get(eco, "")
            for n, rid in enumerate(ids):
                doc = await ctx.http.json(_eco_url(eco, f"{quote(rid)}.json"), ok404=True)
                if doc is None and eco:
                    doc = await ctx.http.json(f"{OSV_API}/vulns/{quote(rid)}", ok404=True)       # запасной путь для одной записи
                rec = parsers.parse_osv(doc) if doc else None
                if doc and doc.get("withdrawn"):
                    await ctx.drop([str(doc.get("id") or rid)])           # запись отозвана источником
                if rec:
                    newest = max(newest, str(doc.get("modified") or ""))
                    await ctx.save([rec])
                if n % 50 == 0:
                    await ctx.progress(f"OSV {eco or 'вся база'}: обновлено {n + 1} из {len(ids)}")
            marks[eco] = newest
    ctx.new_cursor = {"modified": marks, "targets": targets}


async def run_osv(ctx: RunCtx) -> None:
    await run_channels(ctx, [("archives", INFO["osv"]["channels"][0], _osv_archives)])


# ------------------------------------------------------------------------------------------------ endoflife.date
async def _eol_api(ctx: RunCtx) -> None:
    from ..eol import sync as eol_sync  # noqa: PLC0415

    url = (ctx.settings.get("url") or eol_sync.API).rstrip("/") + "/products/full"
    cur = ctx.cursor or {}
    dest = ctx.tmp() / "eol.json"
    await ctx.progress("запрос базы жизненного цикла")
    cond = ctx.has_data and not ctx.force
    got = await ctx.http.download(url, dest, etag=cur.get("etag", "") if cond else "", progress=ctx.dl_progress("endoflife.date"), headers={"Accept-Encoding": "identity", "Accept": "application/json"})
    if got.not_modified:
        await ctx.progress("база на сайте не изменилась")
        return
    try:
        doc = eol_sync.load_document(dest)
        res = await eol_sync.apply_products(ctx.sm, doc["result"], progress=ctx.progress)
    except eol_sync.EolFormatError as exc:
        raise FetchError(str(exc)) from None
    ctx.fetched, ctx.changed = res["total"], res["changed"] + res["removed"]
    ctx.new_cursor = {"etag": got.etag, "generated_at": doc.get("generated_at"), "schema_version": doc.get("schema_version"), "products": res["total"], "added": res["added"], "removed": res["removed"]}


async def run_eol(ctx: RunCtx) -> None:
    await run_channels(ctx, [("api", INFO["eol"]["channels"][0], _eol_api)])


async def _oval_feeds(ctx: RunCtx) -> None:
    from ..pentest import oval  # noqa: PLC0415

    feeds = [f for f in (ctx.settings.get("feeds") or []) if isinstance(f, dict) and f.get("url") and f.get("name")]
    if not feeds:
        await ctx.progress("фиды OVAL не заданы в настройках источника")
        return
    cur = dict(ctx.cursor or {})
    done: dict = dict(cur.get("feeds") or {})
    for i, f in enumerate(feeds):
        name, url = str(f["name"])[:60], str(f["url"])
        dest = ctx.tmp() / f"oval-{i}.xml"
        await ctx.progress(f"фид «{name}»: загрузка")
        cond = ctx.has_data and not ctx.force
        got = await ctx.http.download(url, dest, etag=(done.get(name) or {}).get("etag", "") if cond else "", progress=ctx.dl_progress(name))
        if got.not_modified:
            continue
        await ctx.progress(f"фид «{name}»: разбор и запись")
        try:
            n = await oval.store_feed(ctx.sm, name, oval.batches(oval.parse(dest)))
        except Exception as exc:  # noqa: BLE001 — повреждённый фид не должен ломать остальные; прежние определения этого фида сохраняются (транзакция откатывается)
            raise FetchError(f"Фид «{name}»: файл не разобран ({type(exc).__name__}: {str(exc)[:120]})") from None
        dest.unlink(missing_ok=True)
        ctx.fetched += n
        ctx.changed += n
        done[name] = {"etag": got.etag, "definitions": n, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    ctx.new_cursor = {"feeds": done}


async def run_oval(ctx: RunCtx) -> None:
    await run_channels(ctx, [("feeds", INFO["oval"]["channels"][0], _oval_feeds)])


SOURCES: dict[str, Callable[[RunCtx], Awaitable[None]]] = {"kev": run_kev, "bdu": run_bdu, "nvd": run_nvd, "osv": run_osv, "eol": run_eol, "oval": run_oval}
