"""Построение каталога продуктов одного источника KSC (в рабочем потоке, на одном соединении, только чтение).

Читаются три набора постранично по первичному ключу (keyset — без OFFSET по большим таблицам):
устройства (nId, последнее подключение Агента, признак кластера), записи реестра ПО и действующие установки (bDeleted = 0).
Счёт компьютеров ведётся по множествам идентификаторов, поэтому компьютер с несколькими версиями продукта считается один раз.
«Активные» — подключавшиеся к KSC за activity_days суток; остальные учитываются отдельно (показ всех устройств)."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from . import catalog as C
from . import versions
from .driver import Session

Progress = Callable[[str], None]
CancelCheck = Callable[[], bool]

HOSTS_KEYSET = ("SELECT TOP (20000) h.nId AS host_id, h.tmLastNagentConnected AS last_connected, h.bIsSlaveServer AS is_slave "
                "FROM dbo.v_akpub_host h WHERE h.nId > %(last)s ORDER BY h.nId")
PRODUCTS_KEYSET = ("SELECT TOP (5000) p.nId AS product_id, p.wstrDisplayName AS name, p.wstrDisplayVersion AS version, p.wstrPublisher AS publisher, "
                   "p.nPlatformTypeMask AS platform_mask, p.tmFirstAppear AS first_seen FROM dbo.hst_inventory_products p WHERE p.nId > %(last)s ORDER BY p.nId")
INSTALLS_KEYSET = ("SELECT TOP (50000) i.nId AS install_id, i.nHostId AS host_id, i.nProduct AS product_id FROM dbo.hst_inventory_hstprds i "
                   "WHERE i.bDeleted = 0 AND i.nId > %(last)s ORDER BY i.nId")
SIGNATURE = ("SELECT (SELECT COUNT_BIG(*) FROM dbo.hst_inventory_hstprds i WHERE i.bDeleted = 0) AS installs, (SELECT MAX(i.nId) FROM dbo.hst_inventory_hstprds i) AS max_install, "
             "(SELECT COUNT_BIG(*) FROM dbo.hst_inventory_products p) AS products, (SELECT MAX(p.nId) FROM dbo.hst_inventory_products p) AS max_product")


class Cancelled(Exception):
    pass


@dataclass
class Overrides:
    """Ручные корректировки каталога: разделение по точному названию записи, объединение продуктов, переименование."""
    split: dict[str, tuple[str, str]] = field(default_factory=dict)      # название записи (нижний регистр) → (ключ, название)
    merge: dict[str, str] = field(default_factory=dict)                  # ключ → ключ
    rename: dict[str, tuple[str | None, str | None]] = field(default_factory=dict)   # ключ → (название, производитель)

    def resolve(self, key: str) -> str:
        seen = set()
        while key in self.merge and key not in seen and len(seen) < 20:
            seen.add(key)
            key = self.merge[key]
        return key


def _utc(v):
    if v is None:
        return None
    return v.replace(tzinfo=timezone.utc) if isinstance(v, datetime) and v.tzinfo is None else v


def signature(s: Session) -> str:
    r = s.query(SIGNATURE, max_rows=1)[0]
    return f"{r.get('installs')}:{r.get('max_install')}:{r.get('products')}:{r.get('max_product')}"


def _keyset(s: Session, sql: str, key: str, page: int, cancelled: CancelCheck):
    last = -1
    while True:
        if cancelled():
            raise Cancelled()
        rows = s.query(sql, {"last": last}, max_rows=page)
        if not rows:
            return
        yield rows
        if len(rows) < page:
            return
        last = int(rows[-1][key])


def build(s: Session, *, activity_days: int, overrides: Overrides | None = None, exclude_slaves: bool = True,
          progress: Progress = lambda _t: None, cancelled: CancelCheck = lambda: False, now: datetime | None = None) -> tuple[list[dict], dict]:
    ov = overrides or Overrides()
    now = now or datetime.now(timezone.utc)
    border = now - timedelta(days=activity_days)
    hosts: dict[int, bool] = {}               # host_id → активен
    slaves: set[int] = set()
    for rows in _keyset(s, HOSTS_KEYSET, "host_id", 20000, cancelled):
        for h in rows:
            hid = int(h["host_id"])
            if exclude_slaves and h.get("is_slave"):
                slaves.add(hid)
                continue
            last = _utc(h.get("last_connected"))
            hosts[hid] = last is not None and last >= border
    progress(f"устройств: {len(hosts)}")

    # записи реестра → продукт, схема и версия
    recs: dict[int, tuple] = {}               # product_id → (family_key, version_key, name, raw_version, publisher, mask, first_seen)
    fam_meta: dict[str, dict] = {}
    for rows in _keyset(s, PRODUCTS_KEYSET, "product_id", 5000, cancelled):
        for p in rows:
            name, raw = (p.get("name") or "").strip(), (p.get("version") or "").strip()
            mask = int(p.get("platform_mask") or 0)
            cl = C.classify(name, mask)
            d = cl.builtin
            key, fam_name, origin = cl.key, cl.name, ("builtin" if d else "auto")
            sp = ov.split.get(name.lower())
            if sp:
                key, fam_name, origin, d = sp[0], sp[1], "manual", None
            key = ov.resolve(key)
            if key != cl.key and origin != "manual":
                origin, d = "manual", (C.BUILTIN_BY_KEY.get(key) or d)
            scheme = (d.scheme if d and d.scheme else None) or versions.scheme_for(mask)
            cv = C.compared_version(d, name, raw, scheme)
            br = C.branch(d, name, raw, scheme)
            recs[int(p["product_id"])] = (key, f"{cv}|{scheme}", name, raw, p.get("publisher") or "", mask, _utc(p.get("first_seen")), cv, br, scheme)
            m = fam_meta.setdefault(key, {"origin": origin, "def": d, "names": Counter(), "fam_names": Counter(), "publishers": Counter()})
            if origin == "manual":
                m["origin"] = "manual"
            if d and not m["def"]:
                m["def"] = d
            m["fam_names"][fam_name] += 1
    progress(f"записей реестра: {len(recs)}")

    # установки
    fam = defaultdict(lambda: {"hosts": set(), "hosts_active": set(), "installs": 0, "installs_active": 0, "platforms": 0, "first_seen": None})
    ver = defaultdict(lambda: {"hosts": set(), "hosts_active": set(), "installs": 0, "installs_active": 0, "product_ids": set(), "raw": Counter(), "names": Counter()})
    brs = defaultdict(lambda: {"hosts": set(), "hosts_active": set(), "installs": 0, "installs_active": 0, "versions": set()})
    n_inst = skipped = 0
    for rows in _keyset(s, INSTALLS_KEYSET, "install_id", 50000, cancelled):
        for i in rows:
            hid, pid = int(i["host_id"]), int(i["product_id"])
            rec = recs.get(pid)
            if rec is None or hid not in hosts:
                skipped += 1                   # кластеры, подчинённые серверы, удалённые устройства
                continue
            n_inst += 1
            key, vkey, name, raw, pub, mask, first_seen, cv, br, scheme = rec
            active = hosts[hid]
            f = fam[key]
            f["hosts"].add(hid)
            f["installs"] += 1
            f["platforms"] |= mask
            if first_seen and (f["first_seen"] is None or first_seen < f["first_seen"]):
                f["first_seen"] = first_seen
            v = ver[(key, vkey)]
            v["hosts"].add(hid)
            v["installs"] += 1
            v["product_ids"].add(pid)
            v["raw"][raw] += 1
            v["names"][name] += 1
            v["meta"] = (cv, br, scheme, mask)
            b = brs[(key, br)]
            b["hosts"].add(hid)
            b["installs"] += 1
            b["versions"].add(cv)
            if active:
                f["hosts_active"].add(hid)
                f["installs_active"] += 1
                v["hosts_active"].add(hid)
                v["installs_active"] += 1
                b["hosts_active"].add(hid)
                b["installs_active"] += 1
            meta = fam_meta[key]
            meta["names"][name] += 1
            if pub:
                meta["publishers"][C.clean_publisher(pub)] += 1
        progress(f"установок обработано: {n_inst}")

    by_key_versions: dict[str, list] = defaultdict(list)
    for (key, _vkey), v in ver.items():
        cv, br, scheme, mask = v["meta"]
        by_key_versions[key].append({"version": cv, "branch": br, "scheme": scheme, "platform": mask, "installs": v["installs"], "installs_active": v["installs_active"],
                                     "hosts": len(v["hosts"]), "hosts_active": len(v["hosts_active"]), "product_ids": sorted(v["product_ids"]),
                                     "raw": [x for x, _ in v["raw"].most_common(5)], "names": [x for x, _ in v["names"].most_common(5)]})
    by_key_branches: dict[str, list] = defaultdict(list)
    for (key, br), b in brs.items():
        by_key_branches[key].append({"branch": br, "installs": b["installs"], "installs_active": b["installs_active"], "hosts": len(b["hosts"]),
                                     "hosts_active": len(b["hosts_active"]), "versions": sorted(b["versions"], key=versions.sort_key, reverse=True)[:30]})

    out: list[dict] = []
    for key, f in fam.items():
        meta = fam_meta[key]
        d: C.ProductDef | None = meta["def"]
        name = d.name if d and meta["origin"] == "builtin" else (meta["fam_names"].most_common(1)[0][0] if meta["fam_names"] else key)
        publisher = (d.publisher if d and d.publisher else "") or (meta["publishers"].most_common(1)[0][0] if meta["publishers"] else "")
        rn = ov.rename.get(key)
        if rn:
            name, publisher = rn[0] or name, rn[1] if rn[1] is not None else publisher
        # сначала версии с определённой веткой (новые сверху), затем без ветки — метапакеты с эпохой и нечисловые версии не считаются «новейшими»
        allv = by_key_versions[key]
        vs = sorted([v for v in allv if v["branch"]], key=lambda x: versions.sort_key(x["version"] or "0"), reverse=True) + \
            sorted([v for v in allv if not v["branch"]], key=lambda x: versions.sort_key(x["version"] or "0"), reverse=True)
        bs = sorted(by_key_branches[key], key=lambda x: (x["branch"] == "", versions.sort_key(x["branch"] or "0")), reverse=False)
        bs = sorted([b for b in bs if b["branch"]], key=lambda x: versions.sort_key(x["branch"]), reverse=True) + [b for b in bs if not b["branch"]]
        out.append({"key": key, "name": name[:300], "publisher": publisher[:300], "publisher_key": C.publisher_key(publisher), "origin": meta["origin"],
                    "component": bool(d.component) if d else False, "platforms": f["platforms"], "note": d.note if d else "",
                    "names": [[n, c] for n, c in meta["names"].most_common(30)], "versions": vs, "branches": bs, "versions_count": len(vs),
                    "latest_version": vs[0]["version"] if vs else "", "hosts_all": len(f["hosts"]), "hosts_active": len(f["hosts_active"]),
                    "installs_all": f["installs"], "installs_active": f["installs_active"], "first_seen": f["first_seen"],
                    "scheme": Counter(v["scheme"] for v in vs).most_common(1)[0][0] if vs else "numeric",
                    "transform": d.transform if d else None})
    stats = {"hosts": len(hosts), "hosts_active": sum(1 for a in hosts.values() if a), "slaves": len(slaves), "records": len(recs), "installs": n_inst,
             "installs_skipped": skipped, "products": len(out), "activity_days": activity_days, "built_at": now.isoformat(timespec="seconds")}
    progress(f"готово: продуктов {len(out)}")
    return out, stats
