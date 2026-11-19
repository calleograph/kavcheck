"""Инфраструктурные виды отчёта «Инвентаризация» (`quick_inv`, view = infra_*): реестр серверов, ВМ и сетевого оборудования с полями по приоритету источников,
гипервизоры и кластеры, IP-адреса и подсети, стойки, расхождения, изменения, новые и исчезнувшие объекты, синхронизация, вывод из эксплуатации, состояние на дату,
периодическая (полугодовая) проверка. Только внутренняя база: источники не опрашиваются."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select

from ..infra import connectors as K
from ..infra import sync as S
from ..inventory import core as C
from ..inventory import model as M
from ..models import InfraChange, InfraFinding, InfraObject, InfraSource, InvAsset, InvDoc, InvDocItem, InvHistory, InvLocation, utcnow
from .quick import col, metric

INFRA = ("server", "vm", "network", "storage")


def _period(p: dict) -> tuple[datetime, datetime]:
    try:
        d1 = C.parse_date(p.get("date_from")) or (date.today() - timedelta(days=30))
        d2 = C.parse_date(p.get("date_to")) or date.today()
    except ValueError:
        d1, d2 = date.today() - timedelta(days=30), date.today()
    return datetime(d1.year, d1.month, d1.day, tzinfo=timezone.utc), datetime(d2.year, d2.month, d2.day, tzinfo=timezone.utc) + timedelta(days=1)


async def build_infra_view(db, view: str, p: dict, acc: C.Access, cfg, ctx):
    tables, metrics, tabs, sub, notes = [], [], None, "", ["Сведения источников — по последней синхронизации (только чтение внешних систем). Время — UTC."]
    srcs = {s.id: s for s in (await db.execute(select(InfraSource))).scalars()}
    aw = [InvAsset.cls.in_(INFRA)]
    if (af := acc.asset_filter()) is not None:
        aw.append(af)
    if view in ("infra_registry", "infra_review", "infra_asof"):
        assets = list((await db.execute(select(InvAsset).where(*aw).order_by(InvAsset.cls, InvAsset.hostname, InvAsset.inv_no).limit(ctx.max_rows))).scalars())
        n = await C.names_for(db, assets, props=False)
        objs = defaultdict(list)
        for o in (await db.execute(select(InfraObject).where(InfraObject.asset_id.in_([a.id for a in assets])))).scalars() if assets else []:
            objs[o.asset_id].append((o, srcs[o.source_id]))
        open_f = defaultdict(list)
        for f in (await db.execute(select(InfraFinding).where(InfraFinding.status.in_(("attention", "review", "fixing"))))).scalars():
            if f.asset_id:
                open_f[f.asset_id].append(f)
    if view == "infra_registry":
        rows = []
        for a in assets:
            res = {r["attr"]: r["value"] for r in S.resolve(objs.get(a.id, []), cfg.infra_priority)}
            rows.append({"inv_no": a.inv_no, "name": a.hostname or a.name, "cls": M.CLS_RU.get(a.cls, a.cls), "status": n.ref(a.status_id), "purpose": a.purpose, "service": a.service,
                         "admin": n.person(a.it_id) or n.person(a.resp_id), "location": n.loc(a.location_id), "host": res.get("host", ""), "cluster": res.get("cluster", ""), "cpu": res.get("cpu", ""),
                         "ram": res.get("ram_mb", ""), "disk": res.get("disk_gb", ""), "os": res.get("os", ""), "ips": res.get("ips", ""), "monitoring": "да" if any(s.kind == "zabbix" and o.present for o, s in objs.get(a.id, [])) else "нет",
                         "backup": "да" if any(s.kind == "backup" and o.present for o, s in objs.get(a.id, [])) else "нет", "ksc": "да" if a.ksc_host_id else "нет",
                         "sources": ", ".join(sorted({s.name for o, s in objs.get(a.id, []) if o.present})), "issues": "; ".join(f.title for f in open_f.get(a.id, []))[:500], "_cls": a.cls})
        cols = [col("inv_no", "Инв. номер"), col("name", "Имя"), col("status", "Статус"), col("purpose", "Назначение"), col("service", "Сервис"), col("admin", "Ответственный"), col("location", "Размещение"),
                col("host", "Хост"), col("cluster", "Кластер"), col("cpu", "CPU", "num"), col("ram", "ОЗУ, МБ", "num"), col("disk", "Диски, ГБ", "num"), col("os", "ОС"), col("ips", "IP-адреса"),
                col("monitoring", "Мониторинг"), col("backup", "Резервное копирование"), col("ksc", "KSC"), col("sources", "Источники"), col("issues", "Открытые расхождения")]
        for cls, title in (("server", "Физические серверы"), ("vm", "Виртуальные машины"), ("network", "Сетевое оборудование"), ("storage", "Системы хранения")):
            part = [r for r in rows if r["_cls"] == cls]
            if part or cls in ("server", "vm"):
                tables.append({"id": cls, "title": title, "columns": cols, "rows": part})
        tabs = [{"id": t["id"], "title": t["title"]} for t in tables]
        metrics = [metric("all", "Объектов учёта", len(rows)), *[metric(t["id"], t["title"], len(t["rows"])) for t in tables],
                   metric("nomon", "Без мониторинга", sum(1 for r in rows if r["monitoring"] == "нет" and r["_cls"] in ("server", "vm")), "", "warn")]
        notes.append("Поля CPU, ОЗУ, диски, ОС, адреса, хост и кластер — по правилам приоритета источников (настройки раздела); при расхождении источников в карточке видны все значения.")
    elif view == "infra_hypervisors":
        objs_all = list((await db.execute(select(InfraObject).where(InfraObject.kind.in_(("server", "cluster", "vm"))))).scalars())
        vm_by_host = Counter((o.source_id, o.parent_ext) for o in objs_all if o.kind == "vm" and o.present)
        rows = [{"name": o.name, "source": srcs[o.source_id].name, "kind": K.OBJ_RU.get(o.kind, o.kind), "hypervisor": (o.attrs or {}).get("hypervisor", ""), "cpu": (o.attrs or {}).get("cpu"),
                 "ram": (o.attrs or {}).get("ram_mb"), "vms": vm_by_host.get((o.source_id, o.ext_id), 0), "power": (o.attrs or {}).get("power", ""), "present": "да" if o.present else "нет",
                 "last_seen": C._iso(o.last_seen)} for o in objs_all if o.kind in ("server", "cluster") and srcs[o.source_id].kind in ("vsphere", "proxmox", "ovirt", "hyperv")]
        tables.append({"id": "rows", "title": "Хосты виртуализации и кластеры", "columns": [col("name", "Имя"), col("kind", "Вид"), col("source", "Источник"), col("hypervisor", "Гипервизор"), col("cpu", "CPU", "num"),
                       col("ram", "ОЗУ, МБ", "num"), col("vms", "ВМ", "num"), col("power", "Питание"), col("present", "Есть в источнике"), col("last_seen", "Обновлено (UTC)", "date")], "rows": rows})
        metrics = [metric("hosts", "Хостов", sum(1 for r in rows if r["kind"] != "Кластер")), metric("clusters", "Кластеров", sum(1 for r in rows if r["kind"] == "Кластер")), metric("vms", "ВМ", sum(vm_by_host.values()))]
    elif view == "infra_ips":
        objs_all = list((await db.execute(select(InfraObject).where(InfraObject.present.is_(True)))).scalars())
        by = defaultdict(lambda: {"objects": set(), "assets": set(), "sources": set()})
        for o in objs_all:
            for ip in o.ips or []:
                r = by[ip]
                if o.kind != "ip":
                    r["objects"].add(o.name)
                if o.asset_id:
                    r["assets"].add(o.asset_id)
                r["sources"].add(srcs[o.source_id].name)
        rows = [{"ip": ip, "objects": ", ".join(sorted(r["objects"]))[:500], "assets": len(r["assets"]), "sources": ", ".join(sorted(r["sources"])), "dup": "да" if len(r["assets"]) > 1 else ""} for ip, r in sorted(by.items())]
        tables += [{"id": "ips", "title": "IP-адреса", "columns": [col("ip", "IP-адрес"), col("objects", "Объекты"), col("assets", "Учётных единиц", "num"), col("sources", "Источники"), col("dup", "Повтор")], "rows": rows},
                   {"id": "prefixes", "title": "Подсети", "columns": [col("name", "Подсеть"), col("vlan", "VLAN"), col("site", "Площадка"), col("status", "Статус")],
                    "rows": [{"name": o.name, "vlan": (o.attrs or {}).get("vlan", ""), "site": (o.attrs or {}).get("site", ""), "status": (o.attrs or {}).get("status", "")} for o in objs_all if o.kind == "prefix"]},
                   {"id": "vlans", "title": "VLAN", "columns": [col("name", "VLAN"), col("site", "Площадка")], "rows": [{"name": o.name, "site": (o.attrs or {}).get("site", "")} for o in objs_all if o.kind == "vlan"]}]
        tabs = [{"id": t["id"], "title": t["title"]} for t in tables]
        metrics = [metric("ips", "IP-адресов", len(rows)), metric("dup", "С повтором", sum(1 for r in rows if r["dup"]), "", "warn")]
    elif view == "infra_racks":
        racks = list((await db.execute(select(InvLocation).where(InvLocation.kind == "rack").order_by(InvLocation.path))).scalars())
        assets = list((await db.execute(select(InvAsset).where(InvAsset.location_id.in_([r.id for r in racks]))).scalars())) if racks else []
        n = await C.names_for(db, assets, props=False)
        by = defaultdict(list)
        for a in assets:
            by[a.location_id].append(a)
        rows, summ = [], []
        for r in racks:
            units = int((r.data or {}).get("units") or 42)
            items = sorted(by.get(r.id, []), key=lambda a: -(a.rack_unit or 0))
            used = sum((a.rack_units or 1) for a in items if a.rack_unit)
            summ.append({"rack": r.path, "units": units, "used": used, "free": max(0, units - used), "items": len(items)})
            rows += [{"rack": r.path, "unit": a.rack_unit, "units": a.rack_units or 1, "inv_no": a.inv_no, "name": C.label(a, n).rsplit(" (", 1)[0], "cls": M.CLS_RU.get(a.cls, a.cls), "status": n.ref(a.status_id)} for a in items]
        tables += [{"id": "racks", "title": "Стойки", "columns": [col("rack", "Стойка"), col("units", "Юнитов", "num"), col("used", "Занято", "num"), col("free", "Свободно", "num"), col("items", "Единиц", "num")], "rows": summ},
                   {"id": "items", "title": "Оборудование в стойках", "columns": [col("rack", "Стойка"), col("unit", "Юнит", "num"), col("units", "Высота", "num"), col("inv_no", "Инв. номер"), col("name", "Наименование"),
                                                                                    col("cls", "Класс"), col("status", "Статус")], "rows": rows}]
        tabs = [{"id": "racks", "title": "Стойки"}, {"id": "items", "title": "Оборудование"}]
        metrics = [metric("racks", "Стоек", len(racks)), metric("free", "Свободных юнитов", sum(s["free"] for s in summ))]
    elif view == "infra_findings":
        w = []
        if p.get("status") == "open" or not p.get("status"):
            w.append(InfraFinding.status.in_(("attention", "review", "fixing")))
        elif p.get("status") != "all":
            w.append(InfraFinding.status.in_(str(p["status"]).split(",")))
        if p.get("code"):
            w.append(InfraFinding.code.in_(str(p["code"]).split(",")))
        fs = list((await db.execute(select(InfraFinding).where(*w).order_by(InfraFinding.code, InfraFinding.last_seen.desc()).limit(ctx.max_rows))).scalars())
        assets = {a.id: a for a in (await db.execute(select(InvAsset).where(InvAsset.id.in_({f.asset_id for f in fs} - {None})))).scalars()} if fs else {}
        rows = [{"title": f.title, "status": S.STATUS_RU.get(f.status, f.status), "severity": {"high": "Высокая", "medium": "Средняя", "low": "Низкая"}.get(f.severity, f.severity),
                 "asset": f"{assets[f.asset_id].inv_no} {assets[f.asset_id].hostname or assets[f.asset_id].name}" if f.asset_id in assets else "", "found": f.found, "expected": f.expected,
                 "source": f.source, "first_seen": C._iso(f.first_seen), "action": f.action, "owner": f.owner, "due": C._d(f.due), "comment": f.comment, "_code": f.code} for f in fs]
        cols = [col("title", "Расхождение"), col("severity", "Важность"), col("status", "Статус"), col("asset", "Объект учёта"), col("found", "Обнаружено"), col("expected", "Ожидалось"), col("source", "Источник"),
                col("first_seen", "Обнаружено впервые (UTC)", "date"), col("action", "Рекомендуемое действие"), col("owner", "Ответственный"), col("due", "Срок", "date"), col("comment", "Комментарий")]
        tables.append({"id": "rows", "title": "Все расхождения", "columns": cols, "rows": rows})
        groups = [("monitor", "Мониторинг", ("no_monitoring", "monitoring_off", "unavailable", "monitor_only", "decom_monitored")), ("backup", "Резервное копирование", ("no_backup", "decom_backup")),
                  ("registry", "Учёт и ответственные", ("not_registered", "ambiguous", "no_admin", "no_purpose", "gone", "stale", "no_protection")), ("net", "Сеть и конфигурация", ("ip_dup", "ip_changed", "host_changed", "config_changed"))]
        for gid, gt, codes in groups:
            tables.append({"id": gid, "title": gt, "columns": cols, "rows": [r for r in rows if r["_code"] in codes]})
        tabs = [{"id": t["id"], "title": t["title"]} for t in tables]
        cnt = Counter(r["title"] for r in rows)
        metrics = [metric("all", "Расхождений", len(rows)), *[metric(f"c{i}", k, v) for i, (k, v) in enumerate(cnt.most_common(4))]]
    elif view in ("infra_changes", "infra_new_gone"):
        d1, d2 = _period(p)
        sub = f"{d1:%d.%m.%Y} — {(d2 - timedelta(days=1)):%d.%m.%Y}"
        if view == "infra_changes":
            q = (select(InfraChange, InfraObject).join(InfraObject, InfraObject.id == InfraChange.object_id).where(InfraChange.at >= d1, InfraChange.at < d2, InfraChange.field != "present")
                 .order_by(InfraChange.at.desc()).limit(ctx.max_rows))
            rows = [{"at": C._iso(c.at), "object": o.name, "kind": K.OBJ_RU.get(o.kind, o.kind), "source": srcs[o.source_id].name, "field": S.FIELD_RU.get(c.field, c.field), "old": c.old, "new": c.new}
                    for c, o in (await db.execute(q)).all()]
            tables.append({"id": "rows", "title": TITLE_CH, "columns": [col("at", "Когда (UTC)", "date"), col("object", "Объект"), col("kind", "Вид"), col("source", "Источник"), col("field", "Поле"),
                                                                   col("old", "Было"), col("new", "Стало")], "rows": rows})
            metrics = [metric("rows", "Изменений", len(rows)), metric("objects", "Объектов", len({r["object"] for r in rows}))]
        else:
            new = list((await db.execute(select(InfraObject).where(InfraObject.first_seen >= d1, InfraObject.first_seen < d2).order_by(InfraObject.first_seen.desc()))).scalars())
            gone_ids = {c.object_id: c.at for c in (await db.execute(select(InfraChange).where(InfraChange.field == "present", InfraChange.new == "нет", InfraChange.at >= d1, InfraChange.at < d2))).scalars()}
            gone = list((await db.execute(select(InfraObject).where(InfraObject.id.in_(list(gone_ids))))).scalars()) if gone_ids else []
            cc = [col("name", "Объект"), col("kind", "Вид"), col("source", "Источник"), col("at", "Когда (UTC)", "date"), col("asset", "Учёт")]
            tables += [{"id": "new", "title": "Новые объекты", "columns": cc, "rows": [{"name": o.name, "kind": K.OBJ_RU.get(o.kind, o.kind), "source": srcs[o.source_id].name, "at": C._iso(o.first_seen),
                                                                                         "asset": "сопоставлен" if o.asset_id else "нет в учёте"} for o in new]},
                       {"id": "gone", "title": "Исчезнувшие объекты", "columns": cc, "rows": [{"name": o.name, "kind": K.OBJ_RU.get(o.kind, o.kind), "source": srcs[o.source_id].name, "at": C._iso(gone_ids[o.id]),
                                                                                                "asset": "сопоставлен" if o.asset_id else ""} for o in gone]}]
            tabs = [{"id": "new", "title": "Новые"}, {"id": "gone", "title": "Исчезнувшие"}]
            metrics = [metric("new", "Новых", len(new)), metric("gone", "Исчезнувших", len(gone), "", "warn")]
    elif view == "infra_sync":
        rows = [{"name": s.name, "kind": K.KINDS_RU.get(s.kind, s.kind), "enabled": "да" if s.enabled else "нет", "last_ok": C._iso(s.last_ok_at), "last_try": C._iso(s.last_try_at), "error": s.last_error,
                 "received": (s.last_stats or {}).get("received"), "new": (s.last_stats or {}).get("new"), "changed": (s.last_stats or {}).get("changed"), "gone": (s.last_stats or {}).get("gone")} for s in srcs.values()]
        tables.append({"id": "rows", "title": "Источники", "columns": [col("name", "Источник"), col("kind", "Тип"), col("enabled", "Включён"), col("last_ok", "Последняя успешная (UTC)", "date"),
                       col("last_try", "Последняя попытка (UTC)", "date"), col("received", "Получено", "num"), col("new", "Новых", "num"), col("changed", "Изменено", "num"), col("gone", "Исчезло", "num"),
                       col("error", "Ошибка")], "rows": rows})
        metrics = [metric("src", "Источников", len(rows)), metric("err", "С ошибкой", sum(1 for r in rows if r["error"]), "", "bad")]
    elif view == "infra_decom":
        docs = list((await db.execute(select(InvDoc).where(InvDoc.kind == "decom").order_by(InvDoc.doc_date.desc()))).scalars())
        items = defaultdict(list)
        for di, no in (await db.execute(select(InvDocItem, InvAsset.inv_no).join(InvAsset, InvAsset.id == InvDocItem.asset_id).where(InvDocItem.doc_id.in_([d.id for d in docs])))).all() if docs else []:
            items[di.doc_id].append(no)
        rows = [{"no": d.no, "date": d.doc_date.isoformat(), "status": M.DOC_STATUS_RU.get(d.status, d.status), "items": ", ".join(items.get(d.id, [])), "basis": d.basis,
                 "checklist": ", ".join(k for k, v in ((d.data or {}).get("checklist") or {}).items() if v), "by": d.created_by} for d in docs]
        tables.append({"id": "rows", "title": "Документы вывода из эксплуатации", "columns": [col("no", "Номер"), col("date", "Дата", "date"), col("status", "Этап"), col("items", "Оборудование"),
                       col("basis", "Основание"), col("checklist", "Выполнено"), col("by", "Оформил")], "rows": rows})
        left = list((await db.execute(select(InfraFinding).where(InfraFinding.code.in_(("decom_monitored", "decom_backup")), InfraFinding.status.in_(("attention", "review", "fixing"))))).scalars())
        tables.append({"id": "left", "title": "Остались в мониторинге или резервном копировании", "columns": [col("title", "Расхождение"), col("found", "Обнаружено"), col("source", "Источник")],
                       "rows": [{"title": f.title, "found": f.found, "source": f.source} for f in left]})
        tabs = [{"id": "rows", "title": "Документы"}, {"id": "left", "title": "Незавершённое"}]
        metrics = [metric("docs", "Документов", len(rows)), metric("left", "Незавершённых действий", len(left), "", "warn")]
    elif view == "infra_asof":
        on = C.parse_date(p.get("on")) if p.get("on") else date.today()
        end = datetime(on.year, on.month, on.day, tzinfo=timezone.utc) + timedelta(days=1)
        sub = f"на {on:%d.%m.%Y}"
        hist = {}
        for h in (await db.execute(select(InvHistory).where(InvHistory.asset_id.in_([a.id for a in assets]), InvHistory.at < end).order_by(InvHistory.asset_id, InvHistory.at, InvHistory.id))).scalars() if assets else []:
            hist[h.asset_id] = h.state
        rows = [{"inv_no": a.inv_no, "name": a.hostname or a.name, "cls": M.CLS_RU.get(a.cls, a.cls), "status": st.get("status", ""), "location": st.get("location", ""), "admin": st.get("it", "") or st.get("resp", "")}
                for a in assets for st in [hist.get(a.id)] if st]
        tables.append({"id": "rows", "title": f"Состояние на {on:%d.%m.%Y}", "columns": [col("inv_no", "Инв. номер"), col("name", "Имя"), col("cls", "Класс"), col("status", "Статус"), col("location", "Размещение"),
                       col("admin", "Ответственный")], "rows": rows})
        metrics = [metric("rows", "Объектов на дату", len(rows))]
        notes.append("Учётное состояние — по истории карточек: последнее событие не позже конца выбранного дня.")
    elif view == "infra_review":
        act = [a for a in assets if a.st_cls == "use"]
        fl = lambda a, *codes: any(f.code in codes for f in open_f.get(a.id, []))                      # noqa: E731
        stats = [("Объектов в эксплуатации (серверы, ВМ, сеть, СХД)", len(act)), ("Без ответственного", sum(1 for a in act if not a.it_id and not a.resp_id)),
                 ("Без назначения", sum(1 for a in act if a.cls in ("server", "vm") and not a.purpose)), ("Без мониторинга", sum(1 for a in act if fl(a, "no_monitoring", "monitoring_off"))),
                 ("Без резервного копирования", sum(1 for a in act if fl(a, "no_backup"))), ("Без агента Kaspersky", sum(1 for a in act if fl(a, "no_protection"))),
                 ("Исчезли из источников или устарели", sum(1 for a in act if fl(a, "gone", "stale"))), ("Открытых расхождений", sum(len(v) for v in open_f.values())),
                 ("Источников с ошибкой", sum(1 for s in srcs.values() if s.enabled and s.last_error))]
        tables.append({"id": "summary", "title": "Итоги проверки", "columns": [col("k", "Показатель"), col("v", "Значение", "num")], "rows": [{"k": k, "v": v} for k, v in stats]})
        n_ = await C.names_for(db, act, props=False)
        probs = [{"inv_no": a.inv_no, "name": a.hostname or a.name, "admin": n_.person(a.it_id) or n_.person(a.resp_id), "issues": "; ".join(f.title for f in open_f.get(a.id, []))} for a in act if open_f.get(a.id)]
        tables.append({"id": "issues", "title": "Объекты с замечаниями", "columns": [col("inv_no", "Инв. номер"), col("name", "Имя"), col("admin", "Ответственный"), col("issues", "Замечания")], "rows": probs})
        exc = list((await db.execute(select(InfraFinding).where(InfraFinding.status == "exception"))).scalars())
        tables.append({"id": "exceptions", "title": "Принятые исключения", "columns": [col("title", "Расхождение"), col("found", "Обнаружено"), col("comment", "Основание"), col("by", "Кто принял"), col("due", "Срок", "date")],
                       "rows": [{"title": f.title, "found": f.found, "comment": f.comment, "by": f.decided_by, "due": C._d(f.due)} for f in exc]})
        tabs = [{"id": t["id"], "title": t["title"]} for t in tables]
        complete = round(100 * (1 - (stats[1][1] + stats[3][1] + stats[4][1]) / max(1, 3 * len(act))))
        metrics = [metric("act", "В эксплуатации", len(act)), metric("complete", "Полнота сведений, %", complete), metric("issues", "Объектов с замечаниями", len(probs), "", "warn")]
        notes.append("Периодическая проверка (рекомендуется дважды в год): полнота реестра, ответственные, мониторинг, резервное копирование, защита и расхождения — вместо ручной проверки таблиц.")
    return tables, metrics, tabs, sub, notes


TITLE_CH = "Изменения конфигурации"
