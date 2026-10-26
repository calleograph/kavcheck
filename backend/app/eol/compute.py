"""Сопоставление установленного ПО и ОС источника KSC с жизненным циклом endoflife.date (в фоне, порциями; страницы читают готовые `eol_findings`).

Программы: каталог → (производитель, продукт) из CPE/PURL/названия продукта EOL → тот же сопоставитель, что у базы уязвимостей (`vdb.match.Matcher`: встроенные соответствия, производитель, название),
затем ветка по установленной версии (`classify.pick_release`). ОС: названия и сборки из `v_akpub_host` (`osmatch`). Уверенность сопоставления хранится: «только по названию» не даёт критической оценки.
Устройства: по записям реестра ПО (программы) и по полям ОС компьютера — порциями из KSC, без загрузки всех установок в память.
Результат записывается заменой всех строк источника в одной транзакции: пока считается новое, видно прежнее; при ошибке прежнее остаётся."""
from __future__ import annotations

import hashlib
import logging
import re
import time
import uuid
from datetime import date

from sqlalchemy import case, delete, func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..ksc import queries as q
from ..ksc.driver import SourceClient
from ..models import CatalogProduct, EolFinding, EolHost, EolHostStat, EolMapping, EolProduct, EolRelease, EolState, KscSource, utcnow
from ..vdb import match as M
from .classify import classify, pick_release
from .osmatch import os_release

log = logging.getLogger("app.eol")
CONF_RANK = {"mapped": 0, "high": 1, "name": 2}
MAX_IDS = 60000                    # записей реестра ПО у одного совпадения (для списков устройств); больше не хранится — список строится по продукту
# Соответствия, которые нельзя вывести из названий (данные, как vdb/aliases.py): продукт endoflife.date → ключи каталога
EOL_ALIASES: dict[str, list[str]] = {
    "chrome": ["google-chrome"], "firefox": ["mozilla-firefox"], "edge": ["microsoft-edge"], "office": ["microsoft-office"], "nodejs": ["nodejs"], "python": ["python"], "php": ["php"],
    "postgresql": ["postgresql"], "mysql": ["mysql"], "mariadb": ["mariadb"], "nginx": ["nginx"], "tomcat": ["apache-tomcat"], "apache-http-server": ["apache-httpd"], "openssl": ["openssl"],
    "redis": ["redis"], "mongodb": ["mongodb"], "git": ["git"], "docker-engine": ["docker-engine"], "dotnet": ["dotnet-runtime"], "dotnetfx": ["dotnet-framework"],
    "libreoffice": ["libreoffice"], "thunderbird": ["mozilla-thunderbird"], "wireshark": ["wireshark"], "vlc": ["vlc"], "zoom": ["zoom"], "putty": ["putty"], "7-zip": ["7-zip"],
}
_CPE23 = re.compile(r"^cpe:2\.3:[aoh]:([^:]+):([^:]+)")
_CPE22 = re.compile(r"^cpe:/[aoh]:([^:]+):([^:]+)")
_PURL = re.compile(r"^pkg:[a-z]+/(?:[^/]+/)?([^@?#/]+)$")


def pairs_of(p: dict) -> list[tuple[str, str]]:
    """(производитель, продукт) для сопоставления с каталогом: из CPE, имён пакетов PURL и названий продукта EOL (без производителя — это «по названию»)."""
    out: list[tuple[str, str]] = []
    for i in p.get("identifiers") or []:
        v = str(i.get("id") or "")
        m = _CPE23.match(v) or _CPE22.match(v)
        if m:
            out.append((m.group(1), m.group(2)))
        elif i.get("type") == "purl":
            m = _PURL.match(v)
            if m:
                out.append(("", m.group(1)))
    for n in [p.get("name"), p.get("label"), *(p.get("aliases") or [])]:
        if n:
            out.append(("", str(n)))
    return list(dict.fromkeys(out))


class Index:
    """База EOL в памяти в компактном виде: продукты (~500) и их ветки (~10 тыс.) — маленькая; каталог и устройства в память не загружаются."""

    def __init__(self, products: list[EolProduct], releases: list[EolRelease]):
        self.products = {p.name: p for p in products}
        self.releases: dict[str, dict[str, EolRelease]] = {}
        for r in releases:
            self.releases.setdefault(r.product, {})[r.name] = r
        self.names = {k: list(v) for k, v in self.releases.items()}

    def release(self, product: str, name: str) -> EolRelease | None:
        return self.releases.get(product, {}).get(name)


async def load_index(db: AsyncSession) -> Index:
    return Index(list((await db.execute(select(EolProduct))).scalars().all()), list((await db.execute(select(EolRelease))).scalars().all()))


def _finding(source_id, kind: str, subject: str, version: str, title: str, publisher: str, ep: EolProduct, rel: EolRelease, conf: str, today: date, soon: int = 180, **extra) -> EolFinding | None:
    lc = classify(rel, ep.labels, today, soon_days=soon)
    if lc.status in ("supported", "unknown"):
        return None                                       # поддерживаемое и без дат не сохраняем: EOL автоматически не присваивается, список проблем остаётся компактным
    weak = conf == "name"
    sev, confirmed, cond = lc.severity, lc.confirmed and not weak, lc.condition
    if weak:                                              # продукт сопоставлен только по названию: критичность не утверждается
        sev = "high" if sev == "critical" else sev
        cond += " Продукт сопоставлен только по названию — подтвердите соответствие."
    return EolFinding(source_id=source_id, kind=kind, subject=subject[:200], version=version[:120], title=title[:300], publisher=publisher[:300], eol_product=ep.name, eol_release=rel.name,
                      status=lc.status, severity=sev, confidence=conf, confirmed=confirmed, eol_from=lc.eol_from, eoas_from=lc.eoas_from, eoes_from=lc.eoes_from, condition=cond[:600],
                      link=((ep.links or {}).get("releasePolicy") or (ep.links or {}).get("html") or "")[:400], computed_at=utcnow(), **extra)


def signature(rows: list[EolFinding]) -> str:
    h = hashlib.sha1()
    for r in sorted(rows, key=lambda r: (r.kind, r.subject, r.version)):
        h.update(f"{r.kind}|{r.subject}|{r.version}|{r.eol_product}|{r.eol_release}|{r.status}|{r.severity}|{r.confirmed}\n".encode())
    return h.hexdigest()[:40]


async def light_catalog(db: AsyncSession, source_id: uuid.UUID) -> list[M.CatProd]:
    """Продукты каталога без списков версий (они читаются только у совпавших): память — по числу продуктов, а не установок."""
    cols = (CatalogProduct.key, CatalogProduct.name, CatalogProduct.publisher, CatalogProduct.publisher_key, CatalogProduct.platforms, CatalogProduct.scheme, CatalogProduct.family_key,
            CatalogProduct.component, CatalogProduct.names, CatalogProduct.hosts_active, CatalogProduct.installs_active)
    rows = (await db.execute(select(*cols).where(CatalogProduct.source_id == source_id))).all()
    shim = [type("R", (), {"key": r[0], "name": r[1], "publisher": r[2], "publisher_key": r[3], "platforms": r[4], "scheme": r[5], "family_key": r[6], "component": r[7], "names": r[8],
                           "hosts_active": r[9], "installs_active": r[10], "versions": []})() for r in rows]
    return M.load_catalog(shim)  # type: ignore[arg-type]


def candidates(idx: Index, matcher: M.Matcher, maps: dict[str, EolMapping]) -> dict[str, list[tuple[str, str]]]:
    """Ключ каталога → [(продукт EOL, уверенность)] по решениям администратора, таблице EOL_ALIASES и общим правилам названий. Исключённые решением пропускаются."""
    found: dict[str, dict[str, str]] = {}

    def add(key: str, eol: str, conf: str) -> None:
        cur = found.setdefault(key, {})
        if eol not in cur or CONF_RANK[conf] < CONF_RANK[cur[eol]]:
            cur[eol] = conf

    for name, ep in idx.products.items():
        for key in EOL_ALIASES.get(name, []):
            if key in matcher.by_key:
                add(key, name, "high")
        for vendor, product in pairs_of({"identifiers": ep.identifiers, "name": ep.name, "label": ep.label, "aliases": ep.aliases}):
            for link in matcher.links(vendor, product):
                add(link.prod.key, name, {"mapped": "mapped", "high": "high", "medium": "name"}[link.confidence])
    for key, m in maps.items():
        if m.action == "exclude":
            found.pop(key, None)
        elif m.eol_product in idx.products:
            found[key] = {m.eol_product: "mapped"}
    out: dict[str, list[tuple[str, str]]] = {}
    for key, c in found.items():
        best = min(CONF_RANK[v] for v in c.values())
        out[key] = sorted((e, v) for e, v in c.items() if CONF_RANK[v] == best)       # остаются самые уверенные; несколько равных — неоднозначность
    return out


ID_CHUNK = 1500              # записей реестра в одном запросе к KSC
ROWS_PER_QUERY = 150_000     # и ожидаемых строк (устройство × запись) в одной порции: память — одна порция, а не вся инфраструктура
HOST_PAGE = 20000


def inputs_hash(idx_sig: str, catalog_sig: str, maps_sig: str, day_sig: str) -> str:
    return hashlib.sha1(f"{idx_sig}|{catalog_sig}|{maps_sig}|{day_sig}".encode()).hexdigest()[:40]


_DAY: dict = {}


async def day_signature(db: AsyncSession, today: date, soon_days: int) -> str:
    """Состояние всех веток на сегодня: пересчёт нужен, только когда у какой-либо ветки сегодня сменился этап (а не каждые сутки). Кэшируется на сутки и версию базы EOL."""
    from sqlalchemy import func  # noqa: PLC0415

    n, last = (await db.execute(select(func.count(), func.max(EolProduct.updated_at)))).one()
    key = (today, soon_days, n, last)
    if _DAY.get("key") != key:
        idx = await load_index(db)
        h = hashlib.sha1()
        for pname, rels in sorted(idx.releases.items()):
            labels = idx.products[pname].labels
            for rname, r in sorted(rels.items()):
                h.update(f"{pname}|{rname}|{classify(r, labels, today, soon_days=soon_days).status}\n".encode())
        _DAY.clear()
        _DAY.update(key=key, sig=h.hexdigest()[:20])
    return _DAY["sig"]


async def current_inputs(db: AsyncSession, source_id: uuid.UUID, today: date | None = None, soon_days: int = 180) -> str:
    """Отпечаток исходных данных расчёта: база EOL (число и время продуктов), этапы веток на сегодня, каталог источника (время сборки), решения администратора, порог «приближается»."""
    from sqlalchemy import func  # noqa: PLC0415

    n, last = (await db.execute(select(func.count(), func.max(EolProduct.updated_at)))).one()
    cat = (await db.execute(select(func.count(), func.max(CatalogProduct.built_at)).where(CatalogProduct.source_id == source_id))).one()
    ms = (await db.execute(select(EolMapping.catalog_key, EolMapping.eol_product, EolMapping.action).order_by(EolMapping.catalog_key))).all()
    return inputs_hash(f"{n}|{last}", f"{cat[0]}|{cat[1]}", "|".join(map(str, ms)), await day_signature(db, today or date.today(), soon_days))


async def _app_links(client, findings: list[EolFinding], where: str, days: int, act: set[int], res=None) -> tuple[dict[tuple, set[int]], dict[tuple, int]]:
    """finding.key → устройства (все / активные). Находки группируются так, чтобы все записи реестра одной находки читались одним запросом (дубликатов нет)."""
    links: dict[tuple, set[int]] = {}
    active: dict[tuple, int] = {}
    batch: list[EolFinding] = []
    pending = est = 0

    async def flush() -> None:
        nonlocal batch, pending, est
        if not batch:
            return
        pids: dict[int, list[tuple]] = {}
        for f in batch:
            for p in f.product_ids:
                pids.setdefault(int(p), []).append((f.kind, f.subject, f.version))
        ids = sorted(pids)
        seen_active: dict[tuple, set[int]] = {}
        for i in range(0, len(ids), ID_CHUNK):
            part = ids[i:i + ID_CHUNK]
            for r in await client.run(q.EOL_APP_HOSTS.format(where=where, ids=q.ids_list(part)), {"days": days}, max_rows=3_000_000):
                for key in pids.get(int(r["product_id"]), ()):
                    links.setdefault(key, set()).add(int(r["host_id"]))
                    if r["active"]:
                        seen_active.setdefault(key, set()).add(int(r["host_id"]))
                        act.add(int(r["host_id"]))
        for k, v in seen_active.items():
            active[k] = len(v)
        batch, pending, est = [], 0, 0
        if res is not None:
            await res.breathe("EOL: устройства программ")

    for f in findings:
        n = len(f.product_ids)
        if pending and (pending + n > ID_CHUNK or est + f.hosts_all > ROWS_PER_QUERY):
            await flush()
        batch.append(f)
        pending += n
        est += f.hosts_all
    await flush()
    return links, active


async def _os_links(client, rules: dict, where: str, days: int, act: set[int], res=None) -> tuple[dict[tuple, set[int]], dict[tuple, int], dict[tuple, int]]:
    """Страницами по компьютерам: по каждой отличающейся комбинации (название, версия, сборка) ОС определяется ветка один раз. Возвращает (ключ находки → устройства, активные, счётчик по комбинации)."""
    links: dict[tuple, set[int]] = {}
    active: dict[tuple, int] = {}
    after = 0
    while True:
        rows = await client.run(q.EOL_OS_HOSTS.format(where=where), {"n": HOST_PAGE, "after": after, "days": days}, max_rows=HOST_PAGE + 10)
        if not rows:
            break
        for r in rows:
            if r["active"]:
                act.add(int(r["host_id"]))
            key = rules["resolve"](r)
            if key is None:
                continue
            hid = int(r["host_id"])
            links.setdefault(key, set()).add(hid)
            if r["active"]:
                active[key] = active.get(key, 0) + 1
        after = int(rows[-1]["host_id"])
        if len(rows) < HOST_PAGE:
            break
        if res is not None:
            await res.breathe("EOL: операционные системы")
    return links, active, {}


async def compute_source(sm: async_sessionmaker[AsyncSession], client: SourceClient | None, src: KscSource, *, activity_days: int, exclude_slaves: bool = True, today: date | None = None,
                         soon_days: int = 180, res=None, progress=None) -> dict:
    """Пересчитывает `eol_findings` и `eol_hosts` источника. client нужен для устройств и ОС; без него считаются только находки по программам каталога (без списков устройств)."""
    t0 = time.monotonic()
    today = today or date.today()
    where = "h.bIsSlaveServer = 0" if exclude_slaves else "1 = 1"
    out: list[EolFinding] = []

    def step(text: str) -> None:
        if progress:
            progress(text)

    async with sm() as db:
        inputs = await current_inputs(db, src.id, today, soon_days)
        idx = await load_index(db)
        maps = {m.catalog_key: m for m in (await db.execute(select(EolMapping))).scalars().all()}
        prods = await light_catalog(db, src.id)
        matcher = M.Matcher(prods, [])
        cand = candidates(idx, matcher, maps)
        keys = sorted(cand)
        step("программы каталога")
        for i in range(0, len(keys), 100):
            part = keys[i:i + 100]
            rows = {r.key: r for r in (await db.execute(select(CatalogProduct).where(CatalogProduct.source_id == src.id, CatalogProduct.key.in_(part)))).scalars().all()}
            for key in part:
                row = rows.get(key)
                if row is None:
                    continue
                cs = cand[key]
                for v in row.versions or []:
                    ver = str(v.get("version") or "")
                    if not (v.get("hosts_active") or v.get("hosts")):
                        continue
                    pids = [int(x) for x in (v.get("product_ids") or [])][:MAX_IDS]
                    if len(cs) > 1:                                             # равноценные кандидаты: не угадываем
                        out.append(EolFinding(source_id=src.id, kind="app", subject=key, version=ver[:120], title=row.name[:300], publisher=row.publisher[:300], eol_product="", eol_release="", status="unknown",
                                              severity="", confidence="name", confirmed=False, condition=("Подходит несколько продуктов endoflife.date: " + ", ".join(e for e, _ in cs) + ". Выберите нужный вручную.")[:600], link="",
                                              product_ids=[], hosts_all=int(v.get("hosts") or 0), hosts_active=int(v.get("hosts_active") or 0), installs_active=int(v.get("installs_active") or 0), computed_at=utcnow()))
                        continue
                    eol, conf = cs[0]
                    ep = idx.products[eol]
                    rname = pick_release(idx.names.get(eol, []), ver) or (pick_release(idx.names.get(eol, []), str(v.get("branch") or "")) if v.get("branch") else None)
                    rel = idx.release(eol, rname) if rname else None
                    if rel is None:
                        continue
                    f = _finding(src.id, "app", key, ver, row.name, row.publisher, ep, rel, conf, today, soon_days, product_ids=pids,
                                 hosts_all=int(v.get("hosts") or 0), hosts_active=int(v.get("hosts_active") or 0), installs_active=int(v.get("installs_active") or 0))
                    if f is not None:
                        out.append(f)
            if res is not None:
                await res.breathe("EOL: программы")
        win = [{"name": r.name, "latest_name": r.latest_name} for r in idx.releases.get("windows", {}).values()]

    links: dict[tuple, set[int]] = {}
    act: set[int] = set()                                    # устройства со связью за период активности (по ответам KSC)
    if client is not None:
        step("устройства: программы")
        app_links, app_active = await _app_links(client, [f for f in out if f.kind == "app" and f.product_ids and f.status != "unknown"], where, activity_days, act, res)
        links.update(app_links)
        for f in out:
            k = (f.kind, f.subject, f.version)
            if k in app_links:
                f.hosts_all, f.hosts_active = len(app_links[k]), app_active.get(k, 0)         # по данным реестра на момент расчёта, а не по каталогу
        step("устройства: операционные системы")
        cache: dict[tuple, tuple | None] = {}
        made: dict[tuple, EolFinding] = {}

        def resolve(r: dict):
            ck = (r.get("os_name"), r.get("os_major"), r.get("os_minor"), r.get("os_build"))
            if ck not in cache:
                hit = os_release(r.get("os_name") or "", r.get("os_major"), r.get("os_minor"), r.get("os_build"), windows_releases=win)
                rel = idx.release(hit.product, hit.release) if hit and hit.product in idx.products else None
                f = _finding(src.id, "os", str(r.get("os_name") or "")[:200], f"{r.get('os_major') or 0}.{r.get('os_minor') or 0}.{r.get('os_build') or 0}", str(r.get("os_name") or ""), "",
                             idx.products[hit.product], rel, hit.confidence, today, soon_days, os_key={"name": r.get("os_name"), "major": r.get("os_major"), "minor": r.get("os_minor"), "build": r.get("os_build")}) if rel else None
                if f is not None and hit.note:
                    f.condition = (f.condition + " " + hit.note)[:600]
                cache[ck] = (f.kind, f.subject, f.version) if f else None
                if f:
                    made[cache[ck]] = f
            return cache[ck]

        os_l, os_active, _ = await _os_links(client, {"resolve": resolve}, where, activity_days, act, res)
        for k, f in made.items():
            f.hosts_all, f.hosts_active, f.installs_active = len(os_l.get(k, ())), os_active.get(k, 0), os_active.get(k, 0)
            out.append(f)
        links.update(os_l)
    out = [f for f in out if f.kind == "app" or f.hosts_all]
    sig = signature(out)
    step("сохранение")
    async with sm() as db:
        await db.execute(delete(EolHostStat).where(EolHostStat.source_id == src.id))
        await db.execute(delete(EolHost).where(EolHost.source_id == src.id))
        await db.execute(delete(EolFinding).where(EolFinding.source_id == src.id))
        db.add_all(out)
        await db.flush()
        batch: list[dict] = []                                  # строки устройств пишутся порциями: общий список связей в памяти не строится
        for k, hs in links.items():
            for h in hs:
                batch.append({"source_id": src.id, "kind": k[0], "subject": k[1], "version": k[2], "host_id": h, "active": h in act})
                if len(batch) >= 5000:
                    await db.execute(insert(EolHost), batch)
                    batch = []
        if batch:
            await db.execute(insert(EolHost), batch)
        await db.flush()
        problem = ("eol", "extended", "upcoming")                  # итоги по устройствам: одним запросом в самой базе, без выгрузки связей в Python
        agg = (select(EolHost.source_id, EolHost.host_id, func.count(), func.sum(case((EolFinding.kind == "os", 1), else_=0)),
                      func.max(case((EolFinding.status == "eol", 3), (EolFinding.status == "extended", 2), else_=1)), func.max(case((EolHost.active.is_(True), 1), else_=0)) > 0)
               .select_from(EolHost.__table__.join(EolFinding.__table__, (EolFinding.source_id == EolHost.source_id) & (EolFinding.kind == EolHost.kind) & (EolFinding.subject == EolHost.subject)
                                                   & (EolFinding.version == EolHost.version)))
               .where(EolHost.source_id == src.id, EolFinding.status.in_(problem)).group_by(EolHost.source_id, EolHost.host_id))
        await db.execute(insert(EolHostStat).from_select(["source_id", "host_id", "n", "n_os", "w", "active"], agg))
        st = await db.get(EolState, src.id)
        if st is None:
            st = EolState(source_id=src.id)
            db.add(st)
        st.computed_at, st.duration_ms, st.items, st.error, st.error_at, st.progress = utcnow(), int((time.monotonic() - t0) * 1000), len(out), None, None, None
        changed = st.rev != sig
        st.rev, st.inputs = sig, inputs
        await db.commit()
    return {"items": len(out), "links": sum(len(v) for v in links.values()), "changed": changed, "signature": sig, "seconds": round(time.monotonic() - t0, 1)}
