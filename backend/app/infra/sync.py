"""Синхронизация объектов источника, сопоставление с учётными единицами, приоритет источников по полям и сверка инфраструктуры.

* store — обновление объектов источника по устойчивому идентификатору (повторная синхронизация не создаёт дублей); изменения атрибутов — история (InfraChange);
  исчезнувший объект — present = False (не удаляется).
* match — лестница признаков: прежняя связь → SMBIOS UUID (оба порядка байт) → серийный номер → MAC → имя (только если однозначно; совпадение IP — подтверждение).
  Неоднозначное — «ambiguous», решает человек. Новый сервер или ВМ из системы виртуализации может создать учётную карточку (настройка источника).
* reconcile — расхождения со статусами и решениями; не обнаруженное при очередной сверке закрывается «устранено», исключения не трогаются.
Источники только читаются: никакие изменения во внешние системы не отправляются."""
from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..inventory import core as C
from ..models import InfraChange, InfraFinding, InfraObject, InfraSource, InvAsset, InvRef, KscSource, utcnow
from . import connectors as K

TRACKED = ("name", "fqdn", "ips", "macs", "bios_uuid", "serial", "parent_ext")
TRACKED_ATTRS = ("cpu", "ram_mb", "disk_gb", "power", "os", "available", "monitored", "status", "host", "cluster")
EVENT_CODES = ("ip_changed", "host_changed", "config_changed")          # события изменения: закрываются решением, а не сверкой
ASSET_KINDS = ("server", "vm", "network")
FIELD_RU = {"name": "Имя", "fqdn": "FQDN", "ips": "IP-адреса", "macs": "MAC-адреса", "bios_uuid": "SMBIOS UUID", "serial": "Серийный номер", "parent_ext": "Хост",
            "cpu": "CPU", "ram_mb": "ОЗУ, МБ", "disk_gb": "Диски, ГБ", "power": "Питание", "os": "ОС", "available": "Доступность", "monitored": "На мониторинге", "status": "Состояние",
            "host": "Хост", "cluster": "Кластер", "present": "Есть в источнике"}
CODES = {  # code: (заголовок, важность, рекомендация)
    "not_registered": ("Объект есть в источнике, но нет в учёте", "high", "Создайте учётную карточку или сопоставьте с существующей"),
    "ambiguous": ("Неоднозначное сопоставление", "medium", "Выберите учётную карточку вручную"),
    "monitor_only": ("В мониторинге, но нет в учёте", "medium", "Сопоставьте узел мониторинга с карточкой или создайте её"),
    "no_monitoring": ("Сервер не поставлен на мониторинг", "high", "Поставьте на мониторинг или оформите исключение"),
    "monitoring_off": ("Мониторинг узла отключён", "medium", "Включите мониторинг или оформите исключение"),
    "unavailable": ("Узел недоступен по данным мониторинга", "high", "Проверьте состояние сервера"),
    "no_backup": ("Сервер не включён в резервное копирование", "high", "Включите в резервное копирование или оформите обоснованное исключение"),
    "no_admin": ("Нет ответственного администратора", "high", "Назначьте ответственного ИТ-специалиста"),
    "no_purpose": ("Не указано назначение", "medium", "Заполните назначение и сервис в карточке"),
    "no_protection": ("Нет агента Kaspersky (нет связи с KSC)", "medium", "Установите агент или свяжите карточку с компьютером KSC"),
    "gone": ("Исчез из источников", "medium", "Проверьте: выведен из эксплуатации, переименован или перенесён"),
    "stale": ("Сведения давно не обновлялись", "low", "Проверьте источник и связь объекта"),
    "ip_dup": ("Один IP-адрес у нескольких объектов", "high", "Проверьте адресацию"),
    "decom_monitored": ("Выведенный из эксплуатации остаётся в мониторинге", "medium", "Снимите с мониторинга"),
    "decom_backup": ("Выведенный из эксплуатации остаётся в резервном копировании", "low", "Исключите из резервного копирования, если копии больше не нужны"),
    "ip_changed": ("Изменился IP-адрес", "low", "Подтвердите изменение"),
    "host_changed": ("ВМ перенесена на другой хост", "low", "Подтвердите изменение"),
    "config_changed": ("Изменилась конфигурация", "low", "Подтвердите изменение (CPU, память, диски)"),
}
STATUS_RU = {"attention": "Требует внимания", "review": "Требует проверки", "confirmed": "Подтверждено", "fixing": "Исправляется", "fixed": "Устранено", "exception": "Принято как исключение"}
SEV_RANK = {"high": 3, "medium": 2, "low": 1}
DEFAULT_PRIORITY = {"cpu": ["vsphere", "proxmox", "ovirt", "hyperv", "netbox", "generic"], "ram_mb": ["vsphere", "proxmox", "ovirt", "hyperv", "netbox", "generic"],
                    "disk_gb": ["vsphere", "proxmox", "ovirt", "hyperv", "netbox", "generic"], "power": ["vsphere", "proxmox", "ovirt", "hyperv", "zabbix"],
                    "os": ["vsphere", "ovirt", "proxmox", "zabbix", "netbox"], "ips": ["netbox", "vsphere", "proxmox", "ovirt", "hyperv", "zabbix", "generic"],
                    "available": ["zabbix"], "monitored": ["zabbix"], "host": ["vsphere", "proxmox", "ovirt", "hyperv"], "cluster": ["vsphere", "ovirt", "proxmox", "hyperv", "netbox"],
                    "site": ["netbox"], "rack": ["netbox"], "last_backup": ["backup"]}


def short(n: str) -> str:
    return (n or "").split(".")[0].strip().casefold()


def search_of(o: dict) -> str:
    return " ".join([o["name"], o["fqdn"], *o["ips"], *o["macs"], o["serial"], o["bios_uuid"], o["ext_id"]]).casefold()[:1500]


def _txt(v) -> str:
    if isinstance(v, list):
        return ", ".join(map(str, v))
    if isinstance(v, bool):
        return "да" if v else "нет"
    return "" if v is None else str(v)


async def store(db: AsyncSession, src: InfraSource, objects: list[dict]) -> dict:
    """Обновить объекты источника. Возвращает {received, new, changed, gone}; изменения — InfraChange и события расхождений (IP, хост, конфигурация)."""
    now = utcnow()
    have = {o.ext_id: o for o in (await db.execute(select(InfraObject).where(InfraObject.source_id == src.id))).scalars()}
    seen: set[str] = set()
    st = {"received": len(objects), "new": 0, "changed": 0, "gone": 0}
    for d in objects:
        if d["ext_id"] in seen:
            continue
        seen.add(d["ext_id"])
        o = have.get(d["ext_id"])
        if o is None:
            o = InfraObject(source_id=src.id, ext_id=d["ext_id"], kind=d["kind"], first_seen=now)
            db.add(o)
            for f in TRACKED:
                setattr(o, f, d[f])
            o.attrs, o.present, o.last_seen, o.search = d["attrs"], True, now, search_of(d)
            st["new"] += 1
            continue
        changes = []
        for f in TRACKED:
            if getattr(o, f) != d[f]:
                changes.append((f, _txt(getattr(o, f)), _txt(d[f])))
                setattr(o, f, d[f])
        old = o.attrs or {}
        for f in TRACKED_ATTRS:
            if old.get(f) != d["attrs"].get(f) and not (old.get(f) in (None, "") and d["attrs"].get(f) in (None, "")):
                changes.append((f, _txt(old.get(f)), _txt(d["attrs"].get(f))))
        if not o.present:
            changes.append(("present", "нет", "да"))
        o.kind, o.attrs, o.present, o.last_seen, o.search = d["kind"], d["attrs"], True, now, search_of(d)
        if changes:
            st["changed"] += 1
            await db.flush()
            for f, a, b in changes:
                db.add(InfraChange(object_id=o.id, at=now, field=f, old=a[:1000], new=b[:1000]))
            if o.asset_id and o.kind in ASSET_KINDS:
                fs = {f for f, _a, _b in changes}
                if "ips" in fs and any(f == "ips" and a for f, a, _b in changes):
                    await event(db, "ip_changed", o, src, next(f"{a} → {b}" for f, a, b in changes if f == "ips"))
                if "parent_ext" in fs and any(f == "parent_ext" and a for f, a, _b in changes):
                    await event(db, "host_changed", o, src, next(f"{a} → {b}" for f, a, b in changes if f == "parent_ext"))
                cfg = [f"{FIELD_RU[f]}: {a} → {b}" for f, a, b in changes if f in ("cpu", "ram_mb", "disk_gb") and a]
                if cfg:
                    await event(db, "config_changed", o, src, "; ".join(cfg))
    for ext, o in have.items():
        if ext not in seen and o.present:
            o.present = False
            st["gone"] += 1
            await db.flush()
            db.add(InfraChange(object_id=o.id, at=now, field="present", old="да", new="нет"))
    await db.flush()
    return st


async def event(db: AsyncSession, code: str, o: InfraObject, src: InfraSource, found: str) -> None:
    import hashlib  # noqa: PLC0415

    key = f"{code}:o{o.id}:{hashlib.sha1(found.encode()).hexdigest()[:12]}"
    if (await db.execute(select(InfraFinding.id).where(InfraFinding.key == key))).first():
        return
    t, sev, act = CODES[code]
    db.add(InfraFinding(key=key[:200], code=code, severity=sev, status="review", asset_id=o.asset_id, object_id=o.id, title=t, found=found[:1000], source=src.name[:200], action=act,
                        history=[{"at": utcnow().isoformat(), "by": "сверка", "status": "review"}]))


# ------------------------------------------------------------------------------------------------ сопоставление
async def match(db: AsyncSession, src: InfraSource, by: str = "") -> dict:
    """Сопоставить объекты источника с учётными единицами. Подтверждённые и отклонённые решения не меняются."""
    by = by or f"KAV Checker (источник «{src.name}»)"
    assets = list((await db.execute(select(InvAsset))).scalars())
    by_uuid, by_serial, by_mac, by_name, by_key = defaultdict(set), defaultdict(set), defaultdict(set), defaultdict(set), {}
    ip_of: dict[int, set[str]] = defaultdict(set)
    for a in assets:
        e = a.ext_ids or {}
        for u in K.uuid_variants(e.get("bios_uuid", "")):
            by_uuid[u].add(a.id)
        if a.serial:
            by_serial[a.serial.casefold()].add(a.id)
        for m in e.get("macs") or []:
            by_mac[m].add(a.id)
        for n in {short(a.hostname), short(a.name) if a.cls in ("server", "vm", "network") else ""} - {""}:
            by_name[n].add(a.id)
        for k, v in e.items():
            if k.startswith("src:"):
                by_key[(k, str(v))] = a.id
    for o in (await db.execute(select(InfraObject).where(InfraObject.asset_id.is_not(None), InfraObject.present.is_(True)))).scalars():
        ip_of[o.asset_id].update(o.ips or [])
        for u in K.uuid_variants(o.bios_uuid):
            by_uuid[u].add(o.asset_id)
        for m in o.macs or []:
            by_mac[m].add(o.asset_id)
    objs = list((await db.execute(select(InfraObject).where(InfraObject.source_id == src.id, InfraObject.present.is_(True),
                                                            InfraObject.kind.in_(("server", "vm", "network", "monitor", "backup", "resource"))))).scalars())
    st = {"matched": 0, "created": 0, "ambiguous": 0}
    create = (src.options or {}).get("create_assets", src.kind in ("vsphere", "proxmox", "ovirt", "hyperv", "netbox"))
    key = f"src:{src.id}"
    for o in objs:
        if o.match in ("confirmed", "rejected"):
            continue
        cand, basis = set(), ""
        if (key, o.ext_id) in by_key:
            cand, basis = {by_key[(key, o.ext_id)]}, "прежняя связь"
        if not cand and o.bios_uuid:
            cand = set().union(*[by_uuid.get(u, set()) for u in K.uuid_variants(o.bios_uuid)])
            basis = "SMBIOS UUID" if cand else ""
        if not cand and o.serial and o.kind in ("server", "network", "monitor"):
            cand, basis = set(by_serial.get(o.serial.casefold(), set())), "серийный номер"
        if not cand and o.macs:
            cand = set().union(*[by_mac.get(m, set()) for m in o.macs])
            basis = "MAC-адрес" if cand else ""
        if not cand:
            names = {short(o.name), short(o.fqdn)} - {""}
            cand = set().union(*[by_name.get(n, set()) for n in names]) if names else set()
            if cand:
                basis = "имя" + (" и IP-адрес" if len(cand) == 1 and set(o.ips or []) & ip_of.get(next(iter(cand)), set()) else "")
        if len(cand) == 1:
            aid = next(iter(cand))
            if o.asset_id != aid:
                o.asset_id = aid
            o.match, o.match_basis = "auto", basis
            st["matched"] += 1
        elif len(cand) > 1:
            o.asset_id, o.match, o.match_basis = None, "ambiguous", f"{basis}: {len(cand)} карточки"
            st["ambiguous"] += 1
        elif create and o.kind in ("server", "vm", "network"):
            a = await create_asset(db, o, src, by)
            o.asset_id, o.match, o.match_basis = a.id, "auto", "карточка создана по данным источника"
            by_name[short(o.name)].add(a.id)
            st["created"] += 1
        else:
            o.asset_id, o.match, o.match_basis = None, "none", ""
    await db.flush()
    # идентификаторы оборудования и связь «ВМ на хосте» — технические сведения источника в карточке
    linked = [o for o in objs if o.asset_id]
    amap = {a.id: a for a in (await db.execute(select(InvAsset).where(InvAsset.id.in_({o.asset_id for o in linked})))).scalars()} if linked else {}
    by_ext = {o.ext_id: o for o in objs}
    for o in linked:
        a = amap.get(o.asset_id)
        if a is None:
            continue
        e = dict(a.ext_ids or {})
        e[key] = o.ext_id
        if o.bios_uuid and not e.get("bios_uuid"):
            e["bios_uuid"] = o.bios_uuid
        if o.macs:
            e["macs"] = sorted(set(e.get("macs") or []) | set(o.macs))[:32]
        if e != (a.ext_ids or {}):
            a.ext_ids = e
        host = by_ext.get(o.parent_ext) if o.parent_ext else None
        if o.kind == "vm" and host is not None and host.asset_id and a.parent_id != host.asset_id:
            hn = amap.get(host.asset_id) or await db.get(InvAsset, host.asset_id)
            ch = await C.apply_changes(db, a, {"parent_id": host.asset_id, "rel": "vm"}, C.Access(frozenset({"edit"})))
            if ch:
                await C.record(db, a, "part", ch, by, title=f"ВМ размещена на хосте {hn.hostname or hn.name or hn.inv_no} (по данным «{src.name}»)")
    return st


async def create_asset(db: AsyncSession, o: InfraObject, src: InfraSource, by: str) -> InvAsset:
    from ..services.settings import InventorySettings  # noqa: PLC0415
    from ..models import AppSetting  # noqa: PLC0415

    row = await db.get(AppSetting, "inventory")
    cfg = InventorySettings(**{k: v for k, v in ((row.value if row else {}) or {}).items() if k in InventorySettings.model_fields})
    cls = {"vm": "vm", "server": "server", "network": "network"}[o.kind]
    t = await C.type_for_cls(db, cls)
    st = await C.default_status(db, "use" if (o.attrs or {}).get("power", "on") == "on" else "stock")
    a = InvAsset(uid=uuid.uuid4(), inv_no=await C.next_inv_no(db, cfg), created_by=by, updated_by=by, version=1,
                 ext_ids={f"src:{src.id}": o.ext_id, **({"bios_uuid": o.bios_uuid} if o.bios_uuid else {}), **({"macs": o.macs} if o.macs else {})})
    db.add(a)
    data = {"type_id": t.id if t else None, "status_id": st.id if st else None, "name": o.name[:300], "hostname": short(o.fqdn or o.name)[:255], "serial": o.serial}
    ch = await C.apply_changes(db, a, {k: v for k, v in data.items() if v}, C.Access(frozenset({"edit"})), creating=True)
    await db.flush()
    await C.record(db, a, "import", ch, by, title=f"Карточка создана по данным источника «{src.name}»: {K.OBJ_RU.get(o.kind, o.kind).lower()} {o.name}")
    return a


# ------------------------------------------------------------------------------------------------ приоритет источников по полям
def resolve(objs: list[tuple[InfraObject, InfraSource]], priority: dict[str, list[str]]) -> list[dict]:
    """Значение каждого атрибута по правилам приоритета источников: значение, источник, время; другие значения — как расхождение."""
    rows = []
    for attr, order in {**DEFAULT_PRIORITY, **(priority or {})}.items():
        vals = []
        for o, s in objs:
            v = o.ips if attr == "ips" else (o.attrs or {}).get(attr)
            if attr == "host" and not v and o.parent_ext:
                v = o.parent_ext.split(":", 1)[-1]
            if v in (None, "", []):
                continue
            rank = order.index(s.kind) if s.kind in order else 99
            vals.append({"value": _txt(v), "source": s.name, "kind": s.kind, "at": C._iso(o.last_seen), "present": o.present, "rank": rank})
        if not vals:
            continue
        vals.sort(key=lambda x: (not x["present"], x["rank"]))
        best = vals[0]
        others = [v for v in vals[1:] if v["value"] != best["value"] and v["present"]]
        rows.append({"attr": attr, "label": FIELD_RU.get(attr, {"site": "Площадка", "rack": "Стойка", "last_backup": "Последняя резервная копия"}.get(attr, attr)), "value": best["value"],
                     "source": best["source"], "at": best["at"], "conflicts": [{"value": v["value"], "source": v["source"]} for v in others]})
    return rows


# ------------------------------------------------------------------------------------------------ сверка
async def reconcile(db: AsyncSession, stale_days: int = 7, by: str = "сверка") -> dict:
    now = utcnow()
    srcs = {s.id: s for s in (await db.execute(select(InfraSource).where(InfraSource.enabled.is_(True)))).scalars()}
    has_mon = any(s.kind == "zabbix" for s in srcs.values())
    has_bak = any(s.kind == "backup" for s in srcs.values())
    has_ksc = bool((await db.execute(select(KscSource.id).limit(1))).first())
    objs = list((await db.execute(select(InfraObject).where(InfraObject.source_id.in_(list(srcs))))).scalars()) if srcs else []
    by_asset: dict[int, list[InfraObject]] = defaultdict(list)
    for o in objs:
        if o.asset_id:
            by_asset[o.asset_id].append(o)
    found: dict[str, dict] = {}

    def add(code: str, *, asset: InvAsset | None = None, o: InfraObject | None = None, found_: str = "", expected: str = "", source: str = "", suffix: str = "") -> None:
        k = f"{code}:" + (f"a{asset.id}" if asset is not None else f"o{o.id}") + (f":{suffix}" if suffix else "")
        t, sev, act = CODES[code]
        found[k] = {"code": code, "severity": sev, "title": t, "action": act, "asset_id": asset.id if asset is not None else (o.asset_id if o else None), "object_id": o.id if o else None,
                    "found": found_[:1000], "expected": expected[:1000], "source": source[:200]}

    for o in objs:
        if not o.present:
            continue
        s = srcs[o.source_id]
        if o.kind in ASSET_KINDS and o.match == "none":
            add("not_registered", o=o, found_=f"{K.OBJ_RU.get(o.kind, o.kind)} «{o.name}»", expected="учётная карточка", source=s.name)
        elif o.match == "ambiguous":
            add("ambiguous", o=o, found_=f"«{o.name}»: {o.match_basis}", expected="одна учётная карточка", source=s.name)
        elif o.kind == "monitor" and not o.asset_id:
            add("monitor_only", o=o, found_=f"узел «{o.name}»", expected="учётная карточка", source=s.name)
    infra_assets = list((await db.execute(select(InvAsset).where(InvAsset.cls.in_(("server", "vm", "network", "storage"))))).scalars())
    for a in infra_assets:
        mine = by_asset.get(a.id, [])
        mon = [o for o in mine if srcs[o.source_id].kind == "zabbix" and o.present]
        bak = [o for o in mine if srcs[o.source_id].kind == "backup" and o.present]
        if a.st_cls == "use":
            if a.cls in ("server", "vm"):
                if has_mon and not mon:
                    add("no_monitoring", asset=a, found_="узел мониторинга не найден", expected="на мониторинге")
                for o in mon:
                    if (o.attrs or {}).get("monitored") is False:
                        add("monitoring_off", asset=a, o=o, found_=f"узел «{o.name}» отключён", expected="мониторинг включён", source=srcs[o.source_id].name)
                    elif (o.attrs or {}).get("available") is False:
                        add("unavailable", asset=a, o=o, found_=f"узел «{o.name}» недоступен", expected="доступен", source=srcs[o.source_id].name)
                if has_bak and not bak:
                    add("no_backup", asset=a, found_="нет в системе резервного копирования", expected="есть резервная копия")
                if has_ksc and not a.ksc_host_id:
                    add("no_protection", asset=a, found_="карточка не связана с компьютером KSC", expected="агент Kaspersky")
                if not a.purpose:
                    add("no_purpose", asset=a, found_="назначение не заполнено", expected="назначение и сервис")
            if not a.it_id and not a.resp_id:
                add("no_admin", asset=a, found_="ответственный не назначен", expected="ответственный ИТ-специалист")
            tech = [o for o in mine if o.kind in ASSET_KINDS]
            if tech and not any(o.present for o in tech):
                add("gone", asset=a, found_="; ".join(f"{srcs[o.source_id].name}: нет с {o.last_seen:%d.%m.%Y}" for o in tech[:5]), expected="есть в источнике")
            elif tech and max(o.last_seen for o in tech) < now - timedelta(days=stale_days):
                add("stale", asset=a, found_=f"последнее обновление {max(o.last_seen for o in tech):%d.%m.%Y}", expected=f"не старше {stale_days} дн.")
        elif a.st_cls in ("decom", "writeoff"):
            for o in mon:
                if (o.attrs or {}).get("monitored") is not False:
                    add("decom_monitored", asset=a, o=o, found_=f"узел «{o.name}» на мониторинге", expected="снят с мониторинга", source=srcs[o.source_id].name)
            for o in bak:
                add("decom_backup", asset=a, o=o, found_=f"«{o.name}» в резервном копировании", expected="исключён", source=srcs[o.source_id].name)
    ip_assets: dict[str, set] = defaultdict(set)
    ip_obj: dict[str, InfraObject] = {}
    for o in objs:
        if o.present and o.kind in ("server", "vm", "network", "monitor"):
            for ip in o.ips or []:
                ip_assets[ip].add(o.asset_id or f"o{o.id}")
                ip_obj.setdefault(ip, o)
    for ip, owners in ip_assets.items():
        if len(owners) > 1:
            add("ip_dup", o=ip_obj[ip], found_=f"{ip}: {len(owners)} объекта", expected="один объект", suffix=ip)
    # запись: новые и повторные — открыть или обновить; не обнаруженные — «устранено» (кроме исключений и событий изменения)
    have = {f.key: f for f in (await db.execute(select(InfraFinding).where(InfraFinding.code.not_in(EVENT_CODES)))).scalars()}
    st = {"open": 0, "new": 0, "fixed": 0, "reopened": 0}
    for k, d in found.items():
        f = have.get(k)
        if f is None:
            db.add(InfraFinding(key=k[:200], status="attention" if d["severity"] == "high" or d["code"] in ("not_registered", "no_admin", "no_monitoring", "no_backup") else "review",
                                history=[{"at": now.isoformat(), "by": by, "status": "attention"}], first_seen=now, last_seen=now, **d))
            st["new"] += 1
        else:
            for f2 in ("asset_id", "object_id", "found", "expected", "source", "title", "severity", "action"):
                setattr(f, f2, d[f2])
            f.last_seen = now
            if f.status == "fixed":
                f.status, f.closed_at = "attention", None
                f.history = [*(f.history or []), {"at": now.isoformat(), "by": by, "status": "attention", "comment": "обнаружено снова"}][-50:]
                st["reopened"] += 1
        st["open"] += 1
    for k, f in have.items():
        if k not in found and f.status not in ("fixed", "exception"):
            f.status, f.closed_at = "fixed", now
            f.history = [*(f.history or []), {"at": now.isoformat(), "by": by, "status": "fixed", "comment": "не обнаружено при сверке"}][-50:]
            st["fixed"] += 1
    await db.flush()
    return st


async def sync_source(db: AsyncSession, src: InfraSource, objects: list[dict]) -> dict:
    """Записать полученные объекты, сопоставить с учётом; сверку запускает вызывающий (после всех источников)."""
    st = await store(db, src, objects)
    st.update(await match(db, src))
    return st


async def type_name(db: AsyncSession, tid: int | None) -> str:
    r = await db.get(InvRef, tid) if tid else None
    return r.name if r else ""
