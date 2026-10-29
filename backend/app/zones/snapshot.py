"""Расчёт подготовленных данных зон по источнику KSC (выполняет worker; страницы и отчёты читают готовое из PostgreSQL).

Принципы:
* **Порциями.** Компьютеры читаются порциями по ID, обнаружения KSC — потоком по `o.nId` (по 20 000 строк), потенциальные совпадения с внешними базами — по порциям компьютеров.
  В памяти одновременно — одна порция, компактные счётчики по компьютерам и таблица «компьютер → зоны, имя» (десятки байт на компьютер). Весь каталог, все обнаружения или все компьютеры в память не загружаются.
* **Атомарно.** Новое поколение данных записывается рядом с действующим (колонка `gen`); читатели видят его только после одной транзакции, которая подменяет `zc_sources.gen`.
  Ошибка или остановка — поколение удаляется, действующие данные не меняются. Обновление одной зоны заменяет строки её компьютеров одной транзакцией.
* **Решения по уязвимостям** применяются при записи строки (бакет current/accepted/excluded), поэтому показатели и отчёты не обращаются к KSC.
Расчёт безопасно повторяется с начала: до подмены поколения ничего видимого не меняется."""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import and_, bindparam, delete, distinct, func, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..config import Settings
from ..ksc import hosts as H
from ..ksc import hardware as HW
from ..ksc import protection as P
from ..ksc import queries as q
from ..ksc import vulns as V
from ..ksc.driver import KscError
from ..models import KscSource, Zone, ZcDashboard, ZcDetection, ZcHost, ZcHostZone, ZcSource, utcnow
from ..reports import quick
from ..reports.quick_ext import ext_meta, ext_row
from ..reports.quick import SEV_RU
from ..vdb.match import STATUS_RU as M_STATUS_RU
from ..vdb.normalize import SEV_RANK as SEV_RANK_RU
from ..vdb.normalize import SEV_RU as EXT_SEV_RU
from ..services.resources import RES
from ..services.settings import SettingsService
from ..services.sources import SourceRegistry
from ..vdb import store as vdb_store
from . import match as ZM
from . import service as S
from . import triage as T

log = logging.getLogger("app.zonecache")
UNASSIGNED = "none"
SEV_INT = {"critical": 3, "high": 2, "warning": 1, "": 0}
CHUNK = {"low": 200, "normal": 400, "high": 800}                     # компьютеров в порции по настройке интенсивности
PAUSE_MS = {"low": 250, "normal": 60, "high": 0}
COUNTERS = ("k_crit", "k_high", "k_warn", "k_total", "k_acc", "k_exc", "k_rev", "e_crit", "e_high", "e_warn", "e_total", "e_kev", "e_conf", "e_acc", "e_exc")
DT_KEYS = ("last_connected", "last_visible", "last_info_update", "last_av_update", "last_full_scan", "created")
INSERT_BATCH = 2000
HUGE = 10 ** 6


# ------------------------------------------------------------------------------------------------ упаковка в JSON
def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


def _dt(v):
    if isinstance(v, str):
        try:
            d = datetime.fromisoformat(v)
        except ValueError:
            return None
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    return v


def pack_record(r: dict) -> dict:
    """Запись компьютера (с зонами) → словарь, пригодный для JSON (даты — строки ISO)."""
    out = {k: _iso(v) for k, v in r.items()}
    if isinstance(r.get("av"), dict):
        out["av"] = {k: _iso(v) for k, v in r["av"].items()}
    return out


def unpack_record(d: dict) -> dict:
    out = dict(d)
    for k in DT_KEYS:
        if k in out:
            out[k] = _dt(out[k])
    if isinstance(out.get("av"), dict):
        out["av"] = {**out["av"], "bases": _dt(out["av"].get("bases"))}
    return out


# поля строки обнаружения, которые восстанавливаются при чтении (длинные константы и повторы не хранятся: размер строки — треть исходного)
_KSC_DROP = ("severity_ru", "cve", "host_id", "name", "fix", "binding", "install_key", "descr_id_dup")
_EXT_DROP = ("severity_ru", "status_ru", "host_id", "name", "product", "ids_list")


def pack_row(r: dict, origin: str = "") -> dict:
    """Строка обнаружения → компактный словарь для JSON (даты — строки ISO; восстанавливаемые поля не сохраняются)."""
    out = {k: _iso(v) for k, v in r.items()}
    t = r.get("triage")
    if t:
        out["triage"] = {k: _iso(v) for k, v in t.items()}
    if origin == "ksc":
        for k in _KSC_DROP:
            out.pop(k, None)
    elif origin == "ext":
        for k in _EXT_DROP:
            out.pop(k, None)
        out["kev"] = bool(r.get("kev"))
        out["fix"] = r.get("fix") == "есть сведения об исправлении"
    return out


def unpack_row(d: dict, origin: str = "") -> dict:
    out = dict(d)
    if "detected" in out:
        out["detected"] = _dt(out["detected"])
    t = out.get("triage")
    if t:
        out["triage"] = {**t, "at": _dt(t.get("at")), "review_until": _dt(t.get("review_until"))}
    if origin == "ksc" and "severity" in out:
        out.setdefault("severity_ru", SEV_RU[out["severity"]])
        out.setdefault("cve", ", ".join(out.get("cve_list") or []))
        out.setdefault("fix", ("Исправление доступно" + (f" ({', '.join(out.get('kb') or [])})" if out.get("kb") else "")) if out.get("patch") else "Сведений об исправлении в KSC нет")
        out.setdefault("binding", "подтверждено KSC: найдена программа в реестре" if out.get("confirmed") else "KSC не определил установленную версию: указана версия из справочника уязвимости")
    elif origin == "ext" and "severity" in out:
        out.setdefault("severity_ru", EXT_SEV_RU[next((k2 for k2, r2 in SEV_RANK_RU.items() if r2 == out.get("rank", 0)), "")])
        out["status_ru"] = M_STATUS_RU.get(out.get("status", ""), "")
        out["product"] = out.get("program", "")
        out["ids_list"] = (out.get("ids") or "").split()[:20]
        out["fix"] = "есть сведения об исправлении" if out.get("fix") is True else "нет сведений" if out.get("fix") is False else out.get("fix", "")
    return out


# ------------------------------------------------------------------------------------------------ колонки компьютера
def host_columns(r: dict, now: datetime, activity_days: int) -> dict:
    """Колонки для фильтров и итогов; проблемы, зависящие от порогов (старые базы и проверка), хранятся возрастом — порог применяется при чтении."""
    pr = set(P.problems(r, now, bases_days=HUGE, scan_days=HUGE))                    # без порогов остаются только независимые признаки
    av = r.get("av")
    bases = av.get("bases") if av else None
    scan = r.get("last_full_scan")
    ip = r.get("ip") or ""
    ipn = ZM.ip_int(ip) if ip else None
    days = r.get("days_since_connection")
    return {"name": (r.get("name") or "")[:300], "search": " ".join(x for x in (r.get("name"), r.get("fqdn"), ip) if x).lower()[:800], "ip_num": ipn if ipn is not None and ipn < (1 << 62) else None,
            "os": (r.get("os") or "")[:200], "last_connected": r.get("last_connected"), "days_since": None if days is None else float(days), "active": days is not None and days <= activity_days,
            "online": r.get("online"), "has_av": av is not None, "bases_age": None if not bases else (now - bases).total_seconds() / 86400, "scan_age": None if not scan else (now - scan).total_seconds() / 86400,
            "p_no_av": "no_av" in pr, "p_rtp": "rtp_off" in pr, "p_inf": "infected" in pr, "p_lic": "license" in pr, "p_reb": "reboot" in pr,
            "p_hwc": "hw_cpu" in pr, "p_hwr": "hw_ram" in pr, "hw_crit": any(x["level"] == "critical" for x in ((r.get("hw") or {}).get("problems") or [])),
            "conflict": bool(r.get("zone_conflict")), "pinned": bool(r.get("zone_pinned"))}


def ksc_detection(r: dict, nm: dict, host_name: str) -> dict:
    """Строка обнаружения KSC для хранения (как в быстром отчёте по уязвимостям, без полей компьютера)."""
    did = int(r["descr_id"])
    sk = V.SEVERITY_KEY.get(r.get("severity"), "warning")
    kb = [f"KB{k}" if str(k).isdigit() else str(k) for k in nm["kb"]]
    installed = r.get("app_version") or r.get("product_version") or ""
    confirmed = bool(r.get("app_name"))
    return {"host_id": int(r["host_id"]), "name": host_name, "severity": sk, "severity_ru": SEV_RU[sk], "kla_id": r.get("kla_id") or "", "descr_id": did, "cve": ", ".join(sorted(nm["cve"])), "cve_list": sorted(nm["cve"]),
            "product": r.get("product") or r.get("app_name") or "(программа не определена)", "installed_version": installed, "app_name": r.get("app_name") or "", "publisher": r.get("publisher") or "",
            "vp_id": r.get("vp_id"), "detected": _iso(r.get("detected")), "url": r.get("url") or "", "occurrence_id": int(r["occurrence_id"]),
            "fix": ("Исправление доступно" + (f" ({', '.join(kb)})" if kb else "")) if r.get("patches_available") else "Сведений об исправлении в KSC нет", "patch": bool(r.get("patches_available")),
            "binding": "подтверждено KSC: найдена программа в реестре" if confirmed else "KSC не определил установленную версию: указана версия из справочника уязвимости",
            "confirmed": confirmed, "kb": kb, "inv_id": r.get("inv_id")}


class RetryClient:
    """Клиент KSC для фонового расчёта: свой, с длинным тайм-аутом запроса и без конкуренции с интерактивными запросами, повтор при временных сбоях (обрыв, тайм-аут сервера)."""

    TRANSIENT = ("connect", "timeout", "unavailable")

    def __init__(self, params, name: str, tries: int = 3):
        from dataclasses import replace  # noqa: PLC0415

        from ..ksc.driver import SourceClient  # noqa: PLC0415

        self.params = replace(params, query_timeout_s=max(params.query_timeout_s, 600), connect_timeout_s=max(params.connect_timeout_s, 20))
        self._c = SourceClient(self.params, concurrency=1, name=name)
        self.tries = tries

    async def run(self, sql: str, params=None, *, max_rows: int = 100_000):
        import asyncio  # noqa: PLC0415

        for i in range(self.tries):
            try:
                return await self._c.run(sql, params, max_rows=max_rows)
            except KscError as exc:
                transient = exc.code in self.TRANSIENT or "timed out" in exc.message or "connection failed" in exc.message
                if not transient or i == self.tries - 1:
                    raise
                log.warning("Временный сбой чтения KSC при расчёте зон, повтор", extra={"attempt": i + 1, "error": exc.message[:200]})
                await asyncio.sleep(15 * (i + 1))


# ------------------------------------------------------------------------------------------------ контекст расчёта
@dataclass
class BuildCtx:
    sm: async_sessionmaker
    cfg: Settings
    svc: SettingsService
    sources: SourceRegistry
    zc: object                                        # настройки группы zonecache
    progress: Callable[[str, int], None] = lambda _t, _p: None
    cancelled: Callable[[], bool] = lambda: False
    res: object = field(default_factory=lambda: RES)
    ext_index: dict = field(default_factory=dict)     # (source_id, vdb_rev) → ExtIndex на время задания

    @property
    def chunk(self) -> int:
        return CHUNK.get(getattr(self.zc, "intensity", "normal"), 400)


async def get_zc(db: AsyncSession, source_id) -> ZcSource:
    zs = await db.get(ZcSource, source_id)
    if zs is None:
        zs = ZcSource(source_id=source_id)
        db.add(zs)
        await db.flush()
    return zs


def vdb_rev_hash(rev: str) -> str:
    import hashlib  # noqa: PLC0415

    return hashlib.sha1(rev.encode()).hexdigest()[:16]


async def probe(bc: BuildCtx, src: KscSource) -> None:
    """Лёгкая проверка KSC (несколько агрегатов): отпечаток данных и состояние баз уязвимостей — для отметки «доступны более свежие сведения»."""
    client = RetryClient(bc.sources.params(src), src.name, tries=1)
    st = await V.stamp(client)
    async with bc.sm() as db:
        zs = await get_zc(db, src.id)
        zs.probe_stamp, zs.probe_at = st, utcnow()
        zs.vdb_rev_now = vdb_rev_hash(await vdb_store.revision(db, src.id))
        await db.commit()


# ------------------------------------------------------------------------------------------------ расчёт источника
async def build_source(bc: BuildCtx, src: KscSource, *, hosts: set[int] | None = None) -> dict:
    """Рассчитать подготовленные данные источника. hosts=None — полный расчёт (новое поколение), иначе — обновление указанных компьютеров (строки заменяются одной транзакцией).
    Возвращает сводку расчёта. Исключения: MemoryPressure (отложить), RuntimeError('cancelled'), KscError."""
    t0 = time.monotonic()
    started = utcnow()
    sid = src.id
    partial = hosts is not None
    async with bc.sm() as db:
        zs = await get_zc(db, sid)
        cur = zs.gen
        stage = -int(time.time()) if partial else cur + 1                       # поколение обновления зоны — минус время начала (по нему находятся хвосты прерванных заданий)
        zs.status = "building" if cur == 0 else zs.status
        zs.started_at, zs.progress = started, "подготовка"
        general, rcfg, hwcfg = await bc.svc.get(db, "general"), await bc.svc.get(db, "reports"), await bc.svc.get(db, "hardware")
        zindex = await S.index(db)
        zones_days = {str(z.id): z.activity_days for z in (await db.execute(select(Zone))).scalars() if z.activity_days}
        tindex = await T.load(db, sid, started)
        vrev = vdb_rev_hash(await vdb_store.revision(db, sid))
        old_gens = (await db.execute(select(ZcHost.gen).where(ZcHost.source_id == sid, ZcHost.gen != cur).distinct())).scalars().all()
        await db.commit()
    now_s = int(time.time())
    # хвосты прерванных расчётов, которые читатели не видят: неподменённые полные поколения и обновления зон старше 3 часов (свежие могут принадлежать идущему сейчас заданию)
    leftovers = [g for g in old_gens if (g > cur and not partial) or (g < 0 and -g < now_s - 3 * 3600)]
    for g in set(leftovers) | {stage}:
        await purge_gen(bc.sm, sid, g)
    activity_days = int(general.activity_days)
    excl = rcfg.exclude_slave_servers
    max_det = int(getattr(bc.zc, "max_detections", 3_000_000))
    client = RetryClient(bc.sources.params(src), src.name)
    ctx = quick.Ctx(source_name=src.name, activity_days=activity_days, exclude_slaves=excl, max_rows=rcfg.max_rows, sm=bc.sm, source_id=sid, org={}, protection_loader=None)
    ctx.progress, ctx.cancelled = lambda t: bc.progress(t, -1), bc.cancelled
    notes: list[str] = []

    def tick(text: str, pct: int) -> None:
        bc.progress(text, pct)
        if bc.cancelled():
            raise RuntimeError("cancelled")

    try:
        stamp_now = await V.stamp(client)
        groups = await H.groups_map(client)
        where = "h.bIsSlaveServer = 0" if excl else "1 = 1"
        ids = sorted(int(r["host_id"]) for r in await client.run(q.HOST_IDS.format(where=where), max_rows=2_000_000))
        if partial:
            ids = [i for i in ids if i in hosts]
        n_hosts = len(ids)
        # --- A. компьютеры: запись, зоны
        hmeta: dict[int, tuple[str, list[str]]] = {}
        cnt: dict[int, dict[str, int]] = defaultdict(lambda: dict.fromkeys(COUNTERS, 0))
        cz = bc.chunk
        for i in range(0, n_hosts, cz):
            part = ids[i:i + cz]
            idl = q.ids_list(part)
            hrows = await client.run(q.PROTECTION_HOSTS.format(where=f"{where} AND h.nId IN ({idl})"), max_rows=cz * 2)
            by_host: dict[int, list[dict]] = {}
            for p in await client.run(q.PROTECTION_PRODUCTS_FOR.format(ids=idl), max_rows=cz * 200):
                by_host.setdefault(int(p["host_id"]), []).append(p)
            recs = ZM.annotate([P.record(h, by_host.get(int(h["host_id"]), []), groups, started) for h in hrows], zindex, str(sid))
            if hwcfg.enabled:                                    # оборудование Linux-серверов порции (ядра и ОЗУ): нет данных или объектов — оценки ресурсов нет
                linux = [int(h["host_id"]) for h in hrows if h.get("platform_type") == 6]
                try:
                    HW.attach(recs, await HW.load_for(client, linux) if linux else {}, hwcfg)
                except Exception as exc:  # noqa: BLE001
                    why = exc.message if isinstance(exc, KscError) else "ошибка чтения данных KSC"
                    notes_hw = f"Оборудование Linux-серверов не прочитано ({why}): проверки ядер CPU и ОЗУ для этого расчёта не выполнены"
                    if notes_hw not in notes:
                        notes.append(notes_hw)
            rows_h, rows_z = [], []
            for r in recs:
                zl = r["zones"] or [UNASSIGNED]
                lim = zones_days.get(r["zones"][0]) if r["zones"] else None
                cols = host_columns(r, started, lim or activity_days)
                rows_h.append({"source_id": sid, "host_id": r["host_id"], "gen": stage, **cols, "data": pack_record(r)})
                rows_z += [{"source_id": sid, "host_id": r["host_id"], "gen": stage, "zone_id": z} for z in zl]
                hmeta[r["host_id"]] = (r["name"], r["zones"])
            async with bc.sm() as db:
                if rows_h:
                    await db.execute(insert(ZcHost), rows_h)
                    await db.execute(insert(ZcHostZone), rows_z)
                await db.commit()
            tick(f"компьютеры: {min(i + cz, n_hosts)} из {n_hosts}", 5 + 25 * min(i + cz, n_hosts) // max(n_hosts, 1))
            await bc.res.breathe("расчёт зон: компьютеры")
        # --- B. обнаружения KSC потоком
        agg_only = False
        total_det = 0
        agg = {int(a["host_id"]): a for a in await V.hosts_aggregate(client) if int(a["host_id"]) in hmeta}
        if sum(int(a.get("total") or 0) for a in agg.values()) > max_det:
            agg_only = True
            notes.append(f"Обнаружений уязвимостей KSC больше предела расчёта ({max_det}): сохранены только счётчики по компьютерам, решения по отдельным уязвимостям не применяются. Предел задаётся в настройках расчёта.")
            for hid, a in agg.items():
                c = cnt[hid]
                c["k_crit"], c["k_high"], c["k_warn"], c["k_total"] = (int(a.get(k) or 0) for k in ("critical", "high", "warning", "total"))
        else:
            names_cache: dict[int, dict] = {}
            pages = [V.iter_detail_pages(client, exclude_slaves=excl, cancelled=bc.cancelled)] if not partial else \
                [V.iter_detail_pages(client, host_ids=ids[i:i + 2000], exclude_slaves=excl, cancelled=bc.cancelled) for i in range(0, n_hosts, 2000)]
            for gen_pages in pages:
                async for page in gen_pages:
                    page = [r for r in page if int(r["host_id"]) in hmeta]
                    need = sorted({int(r["descr_id"]) for r in page} - set(names_cache))
                    if need:
                        names_cache.update(await V.names_for(client, need))
                    out_rows = []
                    for r in page:
                        hid = int(r["host_id"])
                        name, zones = hmeta[hid]
                        row = ksc_detection(r, names_cache.get(int(r["descr_id"]), {"cve": [], "kb": []}), name)
                        d = tindex.lookup(host_id=hid, host_name=name, keys=[row["kla_id"], *row["cve_list"]], product=row["product"], version=row["installed_version"], zone_ids=zones)
                        bucket = "excluded" if d and d.status in T.EXCLUDED else "accepted" if d and d.status == "risk_accepted" else "current"
                        row["triage"] = d.public() if d else None
                        c = cnt[hid]
                        if bucket == "current":
                            c["k_total"] += 1
                            c[{"critical": "k_crit", "high": "k_high"}.get(row["severity"], "k_warn")] += 1
                            if d and d.status == "review":
                                c["k_rev"] += 1
                        else:
                            c["k_acc" if bucket == "accepted" else "k_exc"] += 1
                        out_rows.append({"source_id": sid, "gen": stage, "host_id": hid, "origin": "ksc", "vuln_key": (row["kla_id"] or "")[:80], "keys": " ".join([row["kla_id"], *row["cve_list"]]).upper()[:600],
                                         "prod": row["product"][:300], "severity": SEV_INT[row["severity"]], "bucket": bucket, "tstatus": d.status if d else "", "flags": 0, "row": pack_row(row, "ksc")})
                    total_det += len(out_rows)
                    await _insert_rows(bc, out_rows)
                    tick(f"обнаружения KSC: {total_det}", 30 + 35 * min(total_det, max_det) // max(max_det, 1))
                    await bc.res.breathe("расчёт зон: обнаружения")
        # --- C. потенциальные совпадения с внешними базами: итоги — по версиям каталога, строки — только самые приоритетные на компьютер
        ext_total = 0
        index = await _ext_index(bc, src, ctx, vrev, tindex)
        if index.notes:
            notes += index.notes
        else:
            ez = max(25, cz // 8)                                # компьютеров в порции: установки читаются порцией, строки собираются по одному компьютеру
            cap = int(getattr(bc.zc, "ext_per_host", 60))
            capped = 0
            for i in range(0, n_hosts, ez):
                part = ids[i:i + ez]
                installs: dict[int, list[dict]] = {}
                for r in await client.run(q.INSTALLS_FOR_HOSTS.format(ids=q.ids_list(part)), max_rows=2_000_000):
                    installs.setdefault(int(r["host_id"]), []).append(r)
                picked: list[tuple[int, int, str, str, int, str, dict, str]] = []          # (компьютер, версия, уязвимость, статус, основание, продукт, установка, корзина)
                for hid, inst in installs.items():
                    if hid not in hmeta:
                        continue
                    name, zones = hmeta[hid]
                    c, cands, over = host_ext(index, inst, hid, name, zones, tindex, cap)
                    capped += 1 if over else 0
                    for k, v in c.items():
                        cnt[hid][k] += v
                    picked += [(hid, *x) for x in cands]
                meta = await ext_meta(ctx, sorted({x[2] for x in picked}))
                out_rows = []
                for hid, vid, vk, status, bid, pkey, inst, forced_bucket in picked:
                    name, zones = hmeta[hid]
                    row = ext_row(index, vk, status, bid, pkey, inst, meta)
                    row.update(product=row["program"], name=name, ids_list=(row["ids"] or "").split()[:20])
                    d = tindex.lookup(host_id=hid, host_name=name, keys=[vk, *row["ids_list"]], product=row["program"], version=row["installed_version"], zone_ids=zones)
                    bucket = "excluded" if d and d.status in T.EXCLUDED else "accepted" if d and d.status == "risk_accepted" else "current"
                    row["triage"] = d.public() if d else None
                    out_rows.append({"source_id": sid, "gen": stage, "host_id": hid, "origin": "ext", "vuln_key": vk[:80], "keys": " ".join([vk, *row["ids_list"]]).upper()[:600], "prod": row["program"][:300],
                                     "severity": SEV_INT[row["severity"]], "bucket": bucket, "tstatus": d.status if d else "", "flags": (1 if row["kev"] else 0) | (2 if status == "confirmed" else 0), "row": pack_row(row, "ext")})
                ext_total += len(out_rows)
                await _insert_rows(bc, out_rows)
                tick(f"внешние базы: компьютеров {min(i + ez, n_hosts)} из {n_hosts}, строк {ext_total}", 65 + 25 * min(i + ez, n_hosts) // max(n_hosts, 1))
                await bc.res.breathe("расчёт зон: внешние базы")
            log.info("Расчёт зон: потенциальные совпадения", extra={"source": src.name, "hosts_over_cap": capped, "cap": cap, "rows": ext_total})
        # --- D. итоги по компьютерам, подмена поколения
        tick("сохранение итогов", 92)
        async with bc.sm() as db:
            upd = update(ZcHost.__table__).where(ZcHost.source_id == bindparam("b_s"), ZcHost.host_id == bindparam("b_h"), ZcHost.gen == bindparam("b_g")).values({k: bindparam(k) for k in COUNTERS}).execution_options(synchronize_session=False)
            items = [{"b_s": sid, "b_h": hid, "b_g": stage, **c} for hid, c in cnt.items()]
            for i in range(0, len(items), 2000):
                await db.execute(upd, items[i:i + 2000])
            await refresh_texts(db, sid, stage, sorted(hmeta))
            await T.mark_stale(db, tindex)
            if partial:
                await _swap_partial(db, sid, cur, stage, set(ids))
                zs = await get_zc(db, sid)
                zs.error, zs.progress = None, None
            else:
                zs = await get_zc(db, sid)
                zs.gen, zs.status, zs.built_at, zs.finished_at = stage, "ready", started, utcnow()
                zs.duration_ms, zs.progress, zs.error = int((time.monotonic() - t0) * 1000), None, None
                zs.hosts_n, zs.detections_n, zs.agg_only, zs.notes = n_hosts, total_det + ext_total, agg_only, notes
                zs.stamp, zs.probe_stamp, zs.probe_at, zs.vdb_rev, zs.vdb_rev_now = stamp_now, stamp_now, utcnow(), vrev, vrev
            await db.commit()
        if not partial and cur:
            await purge_gen(bc.sm, sid, cur)
        return {"hosts": n_hosts, "detections": total_det, "ext": ext_total, "agg_only": agg_only, "seconds": round(time.monotonic() - t0, 1), "stamp": stamp_now, "started": started,
                "zones": sorted({z for _n, zs_ in hmeta.values() for z in (zs_ or [UNASSIGNED])})}
    except BaseException:
        await purge_gen(bc.sm, sid, stage)
        raise


async def _insert_rows(bc: BuildCtx, rows: list[dict]) -> None:
    for i in range(0, len(rows), INSERT_BATCH):
        async with bc.sm() as db:
            await db.execute(insert(ZcDetection), rows[i:i + INSERT_BATCH])
            await db.commit()


async def _ext_index(bc: BuildCtx, src: KscSource, ctx, vrev: str, tindex: T.TriageIndex):
    from ..reports.quick_ext import build_ext_index  # noqa: PLC0415

    tkeys = frozenset({r.vuln_key.upper() for rs in (*tindex.by_host.values(), *tindex.by_product.values(), *tindex.by_zone.values(), *tindex.by_host_name.values()) for r in rs if r.origin == "ext"})
    key = (str(src.id), vrev, tuple(sorted(tkeys)))
    idx = bc.ext_index.get(key)
    if idx is None:
        bc.ext_index.clear()
        bc.progress("индекс внешних баз", -1)
        idx = bc.ext_index[key] = await build_ext_index(ctx, res=bc.res, tkeys=tkeys, cap=int(getattr(bc.zc, "ext_per_host", 60)))
    return idx


def host_ext(index, inst: list[dict], hid: int, name: str, zones: list[str], tindex: T.TriageIndex, cap: int) -> tuple[dict[str, int], list[tuple], bool]:
    """Потенциальные совпадения одного компьютера из индекса версий: (итоги, строки для сохранения, были ли отброшены менее опасные). Не перебирает совпадения: итоги — сумма по установкам."""
    import heapq  # noqa: PLC0415
    from itertools import islice  # noqa: PLC0415

    c = dict.fromkeys(("e_crit", "e_high", "e_warn", "e_total", "e_kev", "e_conf", "e_acc", "e_exc"), 0)
    seen: set[int] = set()
    lists = []
    forced: list[tuple] = []
    total_hits = 0
    for r in inst:
        pid = int(r["product_id"])
        if pid in seen:
            continue
        seen.add(pid)
        vid = index.by_pid.get(pid)
        if vid is None:
            continue
        a = index.agg[vid]
        c["e_crit"] += a[0]
        c["e_high"] += a[1]
        c["e_warn"] += a[2]
        c["e_total"] += a[3]
        c["e_kev"] += a[4]
        c["e_conf"] += a[5]
        total_hits += a[3]
        pkey = index.versions[vid][0]
        for vk, status, bid, sev, kev, conf in index.tk[vid]:                      # совпадения с уязвимостями, по которым есть решения: корзина — по решению для этого компьютера
            d = tindex.lookup(host_id=hid, host_name=name, keys=[vk], product=index.pnames.get(pkey, pkey), version=r.get("version") or "", zone_ids=zones)
            if d and (d.status in T.EXCLUDED or d.status == "risk_accepted"):
                c["e_crit" if sev == 3 else "e_high" if sev == 2 else "e_warn"] -= 1
                c["e_total"] -= 1
                c["e_kev"] -= 1 if kev else 0
                c["e_conf"] -= 1 if conf else 0
                c["e_exc" if d.status in T.EXCLUDED else "e_acc"] += 1
                forced.append((vid, vk, status, bid, pkey, r, "x"))
        lists.append(((t, vid, pkey, r) for t in index.top[vid]))
    picked: list[tuple] = []
    for (t, vid, pkey, r) in islice(heapq.merge(*lists, key=lambda x: x[0][:4]), cap):
        picked.append((vid, t[3], t[4], t[5], pkey, r, "c"))
    have = {(x[0], x[1], int(x[5]["product_id"])) for x in picked}
    picked += [x for x in forced if (x[0], x[1], int(x[5]["product_id"])) not in have]
    return c, picked, total_hits > cap


async def _swap_partial(db: AsyncSession, sid, cur: int, stage: int, hosts: set[int]) -> None:
    """Заменить строки указанных компьютеров строками подготовленного поколения — в одной транзакции вызывающего."""
    lst = sorted(hosts)
    for i in range(0, len(lst), 2000):
        part = lst[i:i + 2000]
        for model in (ZcDetection, ZcHostZone, ZcHost):
            await db.execute(delete(model).where(model.source_id == sid, model.gen == cur, model.host_id.in_(part)))
    for model in (ZcHost, ZcHostZone, ZcDetection):
        await db.execute(update(model).where(model.source_id == sid, model.gen == stage).values(gen=cur).execution_options(synchronize_session=False))


async def purge_gen(sm: async_sessionmaker, sid, gen: int) -> None:
    """Удалить поколение порциями (чтобы не держать длинных транзакций и не упираться в тайм-аут запроса)."""
    while True:
        async with sm() as db:
            ids = (await db.execute(select(ZcDetection.id).where(ZcDetection.source_id == sid, ZcDetection.gen == gen).limit(20000))).scalars().all()
            if not ids:
                break
            await db.execute(delete(ZcDetection).where(ZcDetection.id.in_(ids)))
            await db.commit()
    async with sm() as db:
        await db.execute(delete(ZcHostZone).where(ZcHostZone.source_id == sid, ZcHostZone.gen == gen))
        await db.execute(delete(ZcHost).where(ZcHost.source_id == sid, ZcHost.gen == gen))
        await db.commit()


async def drop_zone(sm: async_sessionmaker, zone_id: str) -> None:
    """Удалённая зона: принадлежность и сводка убираются сразу; строки компьютеров остаются (они принадлежат источнику)."""
    async with sm() as db:
        await db.execute(delete(ZcHostZone).where(ZcHostZone.zone_id == zone_id))
        await db.execute(delete(ZcDashboard).where(ZcDashboard.zone_id == zone_id))
        await db.commit()


async def recompute_membership(bc: BuildCtx, src: KscSource) -> int:
    """Пересчитать принадлежность компьютеров зонам по сохранённым данным (без обращения к KSC): после изменения правил зон или закреплений."""
    sid = src.id
    n = 0
    async with bc.sm() as db:
        gen = (await get_zc(db, sid)).gen
        if not gen:
            return 0
        zindex = await S.index(db)
    last = -1
    while True:
        async with bc.sm() as db:
            rows = (await db.execute(select(ZcHost.host_id, ZcHost.data).where(ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.host_id > last).order_by(ZcHost.host_id).limit(2000))).all()
            if not rows:
                break
            last = rows[-1][0]
            recs = ZM.annotate([unpack_record(d) for _h, d in rows], zindex, str(sid))
            ids = [r["host_id"] for r in recs]
            await db.execute(delete(ZcHostZone).where(ZcHostZone.source_id == sid, ZcHostZone.gen == gen, ZcHostZone.host_id.in_(ids)))
            await db.execute(insert(ZcHostZone), [{"source_id": sid, "host_id": r["host_id"], "gen": gen, "zone_id": z} for r in recs for z in (r["zones"] or [UNASSIGNED])])
            old = {h: d for h, d in rows}
            upd = []
            for r in recs:                                    # актуальные зоны и признаки спорности внутри данных компьютера (карточка, отчёты)
                d = dict(old[r["host_id"]])
                d.update(zones=r["zones"], zone_conflict=r["zone_conflict"], zone_pinned=r["zone_pinned"], zone_candidates=r["zone_candidates"], zone_via=r["zone_via"])
                upd.append({"b_h": r["host_id"], "b_d": d, "b_c": bool(r["zone_conflict"]), "b_p": bool(r["zone_pinned"])})
            await db.execute(update(ZcHost.__table__).where(ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.host_id == bindparam("b_h")).values(data=bindparam("b_d"), conflict=bindparam("b_c"), pinned=bindparam("b_p")).execution_options(synchronize_session=False), upd)
            await db.commit()
            n += len(recs)
        await bc.res.breathe("пересчёт состава зон")
    return n


async def total_rows(db: AsyncSession, sid, gen: int) -> tuple[int, int]:
    h = (await db.execute(select(func.count()).select_from(ZcHost).where(ZcHost.source_id == sid, ZcHost.gen == gen))).scalar_one()
    d = (await db.execute(select(func.count()).select_from(ZcDetection).where(ZcDetection.source_id == sid, ZcDetection.gen == gen))).scalar_one()
    return int(h), int(d)


# ------------------------------------------------------------------------------------------------ решения по уязвимостям и итоги
async def refresh_texts(db: AsyncSession, sid, gen: int, host_ids: list[int]) -> None:
    """Списки идентификаторов и программ текущих обнаружений компьютеров (для поиска по CVE/KLA и программе в таблице зоны): пересобираются агрегатами SQL по группам компьютеров."""
    D = ZcDetection
    pg = db.get_bind().dialect.name == "postgresql"
    agg = (lambda x: func.string_agg(distinct(x), "|")) if pg else (lambda x: func.group_concat(distinct(x)))
    for i in range(0, len(host_ids), 1000):
        part = host_ids[i:i + 1000]
        rows = (await db.execute(select(D.host_id, D.origin, agg(func.replace(func.lower(D.keys), " ", "|")), agg(func.lower(D.prod)))
                                 .where(D.source_id == sid, D.gen == gen, D.host_id.in_(part), D.bucket == "current").group_by(D.host_id, D.origin))).all()
        got = {h: {"kk": "", "ke": "", "pk": "", "pe": ""} for h in part}
        for h, o, keys, prods in rows:
            sep = "|" if pg else ","
            wrap = lambda t: ("|" + (t or "").replace(sep, "|")[:60000] + "|") if t else ""  # noqa: E731
            got[h]["kk" if o == "ksc" else "ke"], got[h]["pk" if o == "ksc" else "pe"] = wrap(keys), wrap(prods)
        await db.execute(update(ZcHost.__table__).where(ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.host_id == bindparam("b_h")).values(kk=bindparam("kk"), ke=bindparam("ke"), pk=bindparam("pk"), pe=bindparam("pe"))
                         .execution_options(synchronize_session=False), [{"b_h": h, **v} for h, v in got.items()])


async def recount_hosts(db: AsyncSession, sid, gen: int, host_ids: list[int]) -> None:
    """Пересчитать итоги компьютеров по сохранённым обнаружениям (после изменения решений): агрегатами SQL, без чтения строк в память."""
    from sqlalchemy import case  # noqa: PLC0415

    D = ZcDetection

    def c(origin: str, *conds):
        return func.coalesce(func.sum(case((and_(D.origin == origin, *conds), 1), else_=0)), 0)

    for i in range(0, len(host_ids), 1000):
        part = host_ids[i:i + 1000]
        rows = (await db.execute(select(D.host_id,
                                        c("ksc", D.bucket == "current", D.severity == 3), c("ksc", D.bucket == "current", D.severity == 2), c("ksc", D.bucket == "current", D.severity < 2), c("ksc", D.bucket == "current"),
                                        c("ksc", D.bucket == "accepted"), c("ksc", D.bucket == "excluded"), c("ksc", D.bucket == "current", D.tstatus == "review"),
                                        c("ext", D.bucket == "current", D.severity == 3), c("ext", D.bucket == "current", D.severity == 2), c("ext", D.bucket == "current", D.severity < 2), c("ext", D.bucket == "current"),
                                        func.coalesce(func.sum(case((and_(D.origin == "ext", D.bucket == "current", D.flags.op("&")(1) > 0), 1), else_=0)), 0),
                                        func.coalesce(func.sum(case((and_(D.origin == "ext", D.bucket == "current", D.flags.op("&")(2) > 0), 1), else_=0)), 0),
                                        c("ext", D.bucket == "accepted"), c("ext", D.bucket == "excluded"))
                                 .where(D.source_id == sid, D.gen == gen, D.host_id.in_(part)).group_by(D.host_id))).all()
        got = {r[0]: r[1:] for r in rows}
        upd = [{"b_h": h, **{k: int(v) for k, v in zip(COUNTERS, got.get(h, (0,) * len(COUNTERS)))}} for h in part]
        await db.execute(update(ZcHost.__table__).where(ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.host_id == bindparam("b_h")).values({k: bindparam(k) for k in COUNTERS}).execution_options(synchronize_session=False), upd)
    await refresh_texts(db, sid, gen, host_ids)


async def retriage(sm: async_sessionmaker, sid, keys: set[str] | None = None) -> int:
    """Применить текущие решения к сохранённым обнаружениям (корзины current/accepted/excluded, решение в строке) и пересчитать итоги затронутых компьютеров.
    keys — идентификаторы уязвимостей изменённых решений (ускоряет: читаются только подходящие строки); None — все строки источника. Возвращает число изменённых строк."""
    changed = 0
    touched: set[int] = set()
    async with sm() as db:
        gen = await db_gen(db, sid)
        if not gen:
            return 0
        tindex = await T.load(db, sid, utcnow())
    last = 0
    klist = sorted({k.upper() for k in keys}) if keys else None
    while True:
        async with sm() as db:
            q = select(ZcDetection).where(ZcDetection.source_id == sid, ZcDetection.gen == gen, ZcDetection.id > last)
            if klist:
                q = q.where(or_(*[ZcDetection.keys.like(f"%{k}%") for k in klist[:50]]))
            rows = (await db.execute(q.order_by(ZcDetection.id).limit(2000))).scalars().all()
            if not rows:
                break
            last = rows[-1].id
            hosts = {h: (d.get("name", ""), d.get("zones") or []) for h, d in (await db.execute(select(ZcHost.host_id, ZcHost.data).where(ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.host_id.in_({r.host_id for r in rows})))).all()}
            for r in rows:
                name, zones = hosts.get(r.host_id, ("", []))
                row = unpack_row(r.row, r.origin)
                keys_ = ([row.get("kla_id") or "", *row.get("cve_list", [])] if r.origin == "ksc" else [row.get("vuln_key") or "", *row.get("ids_list", [])])
                prod = row.get("product") or row.get("program") or ""
                dcs = tindex.lookup(host_id=r.host_id, host_name=name, keys=keys_, product=prod, version=row.get("installed_version") or "", zone_ids=zones)
                bucket = "excluded" if dcs and dcs.status in T.EXCLUDED else "accepted" if dcs and dcs.status == "risk_accepted" else "current"
                ts = dcs.status if dcs else ""
                if bucket != r.bucket or ts != r.tstatus or bool(row.get("triage")) != bool(dcs) or (dcs and row.get("triage", {}).get("id") != dcs.id):
                    row["triage"] = dcs.public() if dcs else None
                    r.bucket, r.tstatus, r.row = bucket, ts, pack_row(row, r.origin)
                    touched.add(r.host_id)
                    changed += 1
            await db.commit()
    if touched:
        async with sm() as db:
            await recount_hosts(db, sid, gen, sorted(touched))
            await db.commit()
    return changed


async def db_gen(db: AsyncSession, sid) -> int:
    return int((await db.execute(select(ZcSource.gen).where(ZcSource.source_id == sid))).scalar_one_or_none() or 0)
