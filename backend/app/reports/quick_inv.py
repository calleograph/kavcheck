"""Отчёты раздела «Инвентаризация» (вид `quick_inv`, вид отчёта — параметр `view`). Строятся по внутренней базе с отбором страницы (те же параметры, что у списка) и областью
учёта пользователя (scope_ids — проставляет сервер при создании задания); технические разделы (конфигурация, установленное ПО) читают KSC по связанным компьютерам группами.

В HTML логические части — вкладками, в XLSX — листами. В каждом отчёте только относящиеся к нему поля: учётные отчёты не содержат технических столбцов KSC."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import func, or_, select

from ..inventory import core as C
from ..inventory import geography as G
from ..inventory import model as M
from ..inventory.query import Filters, where_of
from ..ksc.driver import KscError
from ..models import InvAsset, InvDoc, InvDocItem, InvGeo, InvHistory, InvLicAssign, InvLicense, InvLocation, InvPerson, InvProp, InvRef, KscSource
from .quick import Ctx, col, metric

TITLE = {"registry": "Реестр ИТ-оборудования", "computers": "Реестр компьютеров и серверов", "card": "Карточка учётной единицы", "by_person": "Оборудование по сотрудникам",
         "by_resp": "Оборудование по ответственным", "by_location": "Оборудование по местоположениям", "stock": "Оборудование на складе", "repair": "Оборудование в ремонте",
         "warranty": "Оборудование с истекающей гарантией", "writtenoff": "Списанное и выведенное из эксплуатации оборудование", "cost": "Стоимость оборудования",
         "owner_history": "История принадлежности оборудования", "moves": "История перемещений", "hardware": "Аппаратная конфигурация компьютеров", "software": "Реестр установленного ПО",
         "licenses": "Реестр лицензий", "license_usage": "Использование лицензий", "components": "Комплектующие и состав оборудования", "docs": "Журнал документов",
         "duplicates": "Возможные дубли карточек", "count": "Результаты инвентаризации", "count_diff": "Расхождения инвентаризации",
         "infra_registry": "Реестр серверной инфраструктуры", "infra_hypervisors": "Гипервизоры и кластеры", "infra_ips": "IP-адреса, подсети и VLAN", "infra_racks": "Состав оборудования по стойкам",
         "infra_findings": "Расхождения между источниками", "infra_changes": "Изменения конфигурации", "infra_new_gone": "Новые и исчезнувшие объекты", "infra_sync": "Синхронизация источников",
         "infra_decom": "Вывод серверов из эксплуатации", "infra_asof": "Состояние инфраструктуры на дату", "infra_review": "Периодическая проверка инфраструктуры",
         "infra_netscan": "Сетевое обнаружение", "geography": "Сетевые местоположения оборудования"}
BASE_COLS = [col("inv_no", "Инв. номер"), col("name", "Наименование"), col("type", "Тип"), col("model", "Производитель и модель"), col("serial", "Серийный номер"), col("status", "Статус"),
             col("location", "Местоположение"), col("user", "Пользователь"), col("resp", "Ответственный"), col("zone", "Зона ответственности"), col("tags", "Теги")]
MONEY = "num"


def _row(a: InvAsset, n: C.Names) -> dict:
    r = C.asset_row(a, n)
    return {"inv_no": a.inv_no, "acc_no": a.acc_no, "name": r["label"].rsplit(" (", 1)[0], "type": r["type"] or r["cls_ru"], "cls": r["cls_ru"], "model": " ".join(x for x in (r["manufacturer"], r["model"]) if x),
            "serial": a.serial, "hostname": a.hostname, "status": r["status"], "st": r["st_ru"], "location": " · ".join(x for x in (r["location"], r["loc_detail"]) if x),
            "user": r["user"], "owner": r["owner"], "resp": r["resp"], "mol": r["mol"], "it": r["it"], "dept": r["dept"], "branch": r["branch"], "zone": r["zone"],
            "tags": ", ".join(r["tags"]), "purchase_date": r["purchase_date"],
            "commissioned_date": r["commissioned_date"], "warranty_until": r["warranty_until"], "cost": round(a.cost / 100, 2) if a.cost is not None else None, "supplier": r["supplier"],
            "purchase_doc": a.purchase_doc, "parent": r["parent"], "rel": r["rel_ru"], "ksc": f"{a.ksc_name} ({'подтверждено' if a.ksc_link == 'confirmed' else 'предполагается' if a.ksc_link == 'auto' else 'нет в KSC'})" if a.ksc_host_id else "",
            "note": (a.note or "")[:500], "updated_at": C._iso(a.updated_at), **{f"p.{k}": v for k, v in r["props_text"].items()}}


async def _assets(db, p: dict, ctx: Ctx, acc: C.Access, cfg, extra: list | None = None, order=None) -> list[InvAsset]:
    f = Filters(**{k: v for k, v in p.items() if k in Filters.model_fields and v not in (None, "", [])})
    w = await where_of(db, f, acc, cfg) + (extra or [])
    rows = (await db.execute(select(InvAsset).where(*w).order_by(*(order or [InvAsset.inv_no])).limit(ctx.max_rows))).scalars().all()
    return list(rows)


def _cond(p: dict) -> list[dict]:
    out = []
    labels = {"q": "Поиск", "cls": "Классы", "st": "Состояние", "warranty": "Гарантия", "ksc": "Связь с KSC", "role": "Роль сотрудника"}
    for k, lb in labels.items():
        if p.get(k):
            v = p[k]
            if k == "cls":
                v = ", ".join(M.CLS_RU.get(x, x) for x in str(v).split(","))
            elif k == "st":
                v = "действующее" if v == "active" else ", ".join(M.ST_RU.get(x, x) for x in str(v).split(","))
            out.append({"label": lb, "text": str(v)})
    if p.get("ids"):
        out.append({"label": "Выбрано вручную", "text": f"{len(p['ids'])} карточек"})
    if p.get("scope_ids"):
        out.append({"label": "Область учёта", "text": "ограничена местоположениями пользователя"})
    return out


async def build_inv(_client, p: dict, ctx: Ctx) -> dict:
    if ctx.sm is None:
        raise KscError("params", "Отчёт недоступен")
    view = p.get("view") or "registry"
    if view not in TITLE:
        raise KscError("params", "Неизвестный вид отчёта инвентаризации")
    async with ctx.sm() as db:
        cfg = await _cfg(db)
        scopes = tuple(x for (x,) in (await db.execute(select(InvLocation.ids_path).where(InvLocation.id.in_(p.get("scope_ids") or [])))).all()) if p.get("scope_ids") else ()
        acc = C.Access(frozenset({"view"}), scopes or (("/-/",) if p.get("scope_ids") else ()))
        notes = ["Данные — учётные сведения раздела «Инвентаризация» на момент формирования. Время — UTC. Отчёт может содержать персональные данные (ФИО сотрудников)."]
        tables, metrics, tabs = [], [], None
        sub = ""
        today = date.today()
        props = list((await db.execute(select(InvProp).where(InvProp.active.is_(True), InvProp.in_list.is_(True)).order_by(InvProp.sort))).scalars())
        pcols = [col(f"p.{x.code}", x.name) for x in props]

        if view in ("registry", "computers", "stock", "repair", "warranty", "writtenoff", "components"):
            extra, order = [], [InvAsset.inv_no]
            q = dict(p)
            if view == "computers":
                q["cls"] = q.get("cls") or ",".join(M.COMPUTERS)
            elif view == "stock":
                q["st"] = "stock,reserve"
            elif view == "repair":
                q["st"] = "repair"
            elif view == "warranty":
                q["warranty"] = q.get("warranty") or "soon"
                q["st"] = q.get("st") or "active"
                order = [InvAsset.warranty_until]
            elif view == "writtenoff":
                q["st"] = "writeoff,decom,lost"
            elif view == "components":
                extra = [or_(InvAsset.cls == "component", InvAsset.parent_id.is_not(None))]
            rows = await _assets(db, q, ctx, acc, cfg, extra, order)
            n = await C.names_for(db, rows)
            data = [_row(a, n) for a in rows]
            if view == "computers":
                cols = [col("inv_no", "Инв. номер"), col("hostname", "Имя компьютера"), col("name", "Наименование"), col("cls", "Класс"), col("model", "Производитель и модель"), col("serial", "Серийный номер"),
                        col("status", "Статус"), col("location", "Местоположение"), col("user", "Пользователь"), col("resp", "Ответственный"), col("it", "ИТ-специалист"), col("ksc", "Компьютер KSC"),
                        col("warranty_until", "Гарантия до", "date")]
            elif view == "warranty":
                cols = [col("warranty_until", "Гарантия до", "date"), *BASE_COLS, col("supplier", "Поставщик")]
                for r, a in zip(data, rows):
                    r["days"] = (a.warranty_until - today).days if a.warranty_until else None
                cols.insert(1, col("days", "Осталось дней", "num"))
                notes.append(f"Истекающей считается гарантия, заканчивающаяся в ближайшие {cfg.warranty_days} дней (настройка раздела).")
            elif view == "components":
                cols = [col("parent", "Входит в"), col("rel", "Вид связи"), *BASE_COLS[:6], col("location", "Местоположение")]
                data.sort(key=lambda r: (r["parent"] or "яяя", r["inv_no"]))
            elif view == "writtenoff":
                cols = [*BASE_COLS[:6], col("acc_no", "Бух. номер"), col("cost", "Стоимость, ₽", MONEY), col("updated_at", "Изменено (UTC)", "date")]
            else:
                cols = [*BASE_COLS, col("owner", "Владелец"), col("mol", "МОЛ"), col("dept", "Подразделение"), col("acc_no", "Бух. номер"), col("purchase_date", "Приобретено", "date"),
                        col("warranty_until", "Гарантия до", "date"), col("cost", "Стоимость, ₽", MONEY), *pcols, col("note", "Примечание")]
            tables.append({"id": "rows", "title": TITLE[view], "columns": cols, "rows": data, "note": "Одна строка — учётная единица."})
            by_type = Counter(r["type"] for r in data)
            by_loc = Counter(r["location"].split(" · ")[0] or "Не указано" for r in data)
            by_st = Counter(r["status"] or "—" for r in data)
            cost = sum(r["cost"] or 0 for r in data)
            if view in ("registry", "computers"):
                tables += [{"id": "by_type", "title": "По типам", "columns": [col("k", "Тип"), col("v", "Единиц", "num")], "rows": [{"k": k, "v": v} for k, v in by_type.most_common()]},
                           {"id": "by_loc", "title": "По местоположениям", "columns": [col("k", "Местоположение"), col("v", "Единиц", "num")], "rows": [{"k": k, "v": v} for k, v in by_loc.most_common()]},
                           {"id": "by_st", "title": "По статусам", "columns": [col("k", "Статус"), col("v", "Единиц", "num")], "rows": [{"k": k, "v": v} for k, v in by_st.most_common()]}]
                tabs = [{"id": t["id"], "title": t["title"]} for t in tables]
            if view == "repair":
                rep = (await db.execute(select(InvDoc).where(InvDoc.kind == "repair", InvDoc.status == "sent").order_by(InvDoc.doc_date))).scalars().all()
                its = defaultdict(list)
                for d0, inv_no in (await db.execute(select(InvDocItem.doc_id, InvAsset.inv_no).join(InvAsset, InvAsset.id == InvDocItem.asset_id).where(InvDocItem.doc_id.in_([d.id for d in rep])))).all() if rep else []:
                    its[d0].append(inv_no)
                tables.append({"id": "repairs", "title": "Открытые ремонты", "columns": [col("no", "Документ"), col("date", "Передано", "date"), col("days", "Дней в ремонте", "num"), col("vendor", "Исполнитель"),
                                                                                  col("fault", "Неисправность"), col("items", "Оборудование")],
                               "rows": [{"no": d.no, "date": d.doc_date.isoformat(), "days": (today - d.doc_date).days, "vendor": (d.data or {}).get("vendor", ""), "fault": (d.data or {}).get("fault", ""),
                                         "items": ", ".join(its.get(d.id, []))} for d in rep]})
                tabs = [{"id": "rows", "title": "В ремонте"}, {"id": "repairs", "title": "Открытые ремонты"}]
            metrics = [metric("rows", "Единиц", len(data)), metric("cost", "Стоимость, ₽", C.money_str(int(cost * 100))), *[metric(f"t{i}", k, v) for i, (k, v) in enumerate(by_type.most_common(3))]]

        elif view in ("by_person", "by_resp"):
            fld = "user_id" if view == "by_person" else "resp_id"
            role = p.get("role") or ("user" if view == "by_person" else "resp")
            fld = f"{role}_id" if role in M.ROLES_RU else fld
            rows = await _assets(db, p, ctx, acc, cfg, [getattr(InvAsset, fld).is_not(None)])
            n = await C.names_for(db, rows)
            data = []
            for a in rows:
                r = _row(a, n)
                person = n.people.get(getattr(a, fld))
                r["person"] = person.name if person else ""
                r["person_dept"] = person.dept if person else ""
                r["person_email"] = person.email if person else ""
                data.append(r)
            data.sort(key=lambda r: (r["person"].casefold(), r["inv_no"]))
            tables.append({"id": "rows", "title": f"{TITLE[view]} ({M.ROLES_RU.get(role, '')})", "columns": [col("person", M.ROLES_RU.get(role, "Сотрудник")), col("person_dept", "Подразделение"),
                                                                                                               col("person_email", "Почта"), *[c for c in BASE_COLS if c["key"] not in ("user", "resp")]], "rows": data})
            cnt = Counter(r["person"] for r in data)
            tables.append({"id": "sum", "title": "Итого по сотрудникам", "columns": [col("k", "Сотрудник"), col("v", "Единиц", "num")], "rows": [{"k": k, "v": v} for k, v in cnt.most_common()]})
            tabs = [{"id": "rows", "title": "Оборудование"}, {"id": "sum", "title": "Итого по сотрудникам"}]
            metrics = [metric("people", "Сотрудников", len(cnt)), metric("rows", "Единиц", len(data))]

        elif view == "geography":
            f = Filters(**{k: v for k, v in p.items() if k in Filters.model_fields and v not in (None, "", [])})
            source_ids = [UUID(s) for s in p["geo_source_ids"]] if p.get("geo_source_ids") is not None else None
            w = await where_of(db, f, acc, cfg) + G.geo_where(G.GeoFilters.model_validate(p.get("geography") or {}), ctx.now)
            pairs = (await db.execute(select(InvAsset, InvGeo).outerjoin(InvGeo, G.selection(source_ids)).where(*w)
                                      .order_by(InvAsset.inv_no, InvAsset.id).limit(ctx.max_rows))).all()
            names = await C.names_for(db, [a for a, _ in pairs], props=False)
            locations = {i: value for i, value in (await db.execute(select(InvLocation.id, InvLocation.path).where(
                InvLocation.id.in_({g.result["site_id"] for _, g in pairs if g and g.result.get("site_id")})))).all()}
            sources = {i: value for i, value in (await db.execute(select(KscSource.id, KscSource.name).where(
                KscSource.id.in_({g.source_id for _, g in pairs if g})))).all()}
            rows = []
            for a, g in pairs:
                r = g.result if g else {}
                rows.append({"inv_no": a.inv_no, "name": a.name or a.hostname, "account_location": names.loc(a.location_id),
                             "site": locations.get(r.get("site_id"), ""), "country": r.get("country"), "region": r.get("region"), "city": r.get("city"),
                             "status": G.LABELS[r.get("status", "unknown")], "network": r.get("network"), "source": sources.get(g.source_id, "") if g else "",
                             "observed_at": g.observed_at if g else None, "fresh": "да" if g and G.fresh(g.observed_at, ctx.now) else "нет",
                             "lat": r.get("lat"), "lon": r.get("lon"), "radius_km": r.get("radius_km"), "operator": r.get("operator"), "asn": r.get("asn")})
            columns = [col(k, label) for k, label in (("inv_no", "Инв. номер"), ("name", "Наименование"), ("account_location", "Учётное местоположение"),
                       ("site", "Сетевая площадка"), ("country", "Страна"), ("region", "Регион"), ("city", "Город"), ("status", "Оценка"), ("network", "Сеть"),
                       ("source", "Источник"), ("fresh", "Актуально"), ("lat", "Широта"), ("lon", "Долгота"), ("radius_km", "Погрешность, км"), ("operator", "Организация ASN"), ("asn", "ASN"))]
            columns.append(col("observed_at", "Наблюдение (UTC)", "date"))
            tables.append({"id": "rows", "title": TITLE[view], "columns": columns, "rows": rows})
            metrics = [metric("rows", "Устройств", len(rows)), metric("known", "С координатами", sum(r["lat"] is not None for r in rows))]
            notes.append("География публичного адреса описывает выход в сеть. Известные площадки привязаны вручную через правила и справочник.")

        elif view in ("by_location", "cost"):
            rows = await _assets(db, {**p, "st": p.get("st") or "active"}, ctx, acc, cfg, order=[InvAsset.location_id, InvAsset.inv_no])
            n = await C.names_for(db, rows)
            data = [_row(a, n) for a in rows]
            data.sort(key=lambda r: (r["location"] or "яяя", r["inv_no"]))
            if view == "by_location":
                tables.append({"id": "rows", "title": TITLE[view], "columns": [col("location", "Местоположение"), *[c for c in BASE_COLS if c["key"] != "location"]], "rows": data})
                agg = defaultdict(lambda: Counter())
                for r in data:
                    agg[r["location"].split(" · ")[0] or "Не указано"][r["type"]] += 1
                types = [t for t, _ in Counter(r["type"] for r in data).most_common(8)]
                tables.append({"id": "sum", "title": "Состав по местоположениям", "columns": [col("k", "Местоположение"), col("total", "Всего", "num"), *[col(f"t{i}", t, "num") for i, t in enumerate(types)]],
                               "rows": [{"k": k, "total": sum(c.values()), **{f"t{i}": c.get(t, 0) for i, t in enumerate(types)}} for k, c in sorted(agg.items())]})
                tabs = [{"id": "sum", "title": "Сводка"}, {"id": "rows", "title": "Оборудование"}]
                metrics = [metric("locs", "Местоположений", len(agg)), metric("rows", "Единиц", len(data))]
            else:
                def by(key: str) -> list[dict]:
                    s, c = defaultdict(float), Counter()
                    for r in data:
                        s[r[key] or "Не указано"] += r["cost"] or 0
                        c[r[key] or "Не указано"] += 1
                    return [{"k": k, "n": c[k], "sum": round(v, 2)} for k, v in sorted(s.items(), key=lambda x: -x[1])]
                cc = [col("k", ""), col("n", "Единиц", "num"), col("sum", "Стоимость, ₽", MONEY)]
                tables += [{"id": "by_type", "title": "По типам", "columns": [{**cc[0], "title": "Тип"}, *cc[1:]], "rows": by("type")},
                           {"id": "by_loc", "title": "По местоположениям", "columns": [{**cc[0], "title": "Местоположение"}, *cc[1:]], "rows": by("location")},
                           {"id": "by_dept", "title": "По подразделениям", "columns": [{**cc[0], "title": "Подразделение"}, *cc[1:]], "rows": by("dept")},
                           {"id": "rows", "title": "Оборудование", "columns": [*BASE_COLS[:6], col("purchase_date", "Приобретено", "date"), col("cost", "Стоимость, ₽", MONEY), col("supplier", "Поставщик")], "rows": data}]
                tabs = [{"id": t["id"], "title": t["title"]} for t in tables]
                total = sum(r["cost"] or 0 for r in data)
                metrics = [metric("cost", "Общая стоимость, ₽", C.money_str(int(total * 100))), metric("rows", "Единиц", len(data)), metric("nocost", "Без стоимости", sum(1 for r in data if r["cost"] is None), "", "warn")]
                notes.append("Учитывается действующее оборудование (кроме списанного, выведенного и утраченного). Стоимость — из учётных карточек.")

        elif view == "card":
            aid = int(p.get("asset_id") or (p.get("ids") or [0])[0])
            rows = await _assets(db, {"ids": [aid]}, ctx, acc, cfg)
            if not rows:
                raise KscError("no_data", "Карточка не найдена или вне вашей области учёта")
            a = rows[0]
            n = await C.names_for(db, [a])
            r = C.asset_row(a, n)
            sub = r["label"]
            kv = [("Инвентарный номер", a.inv_no), ("Бухгалтерский номер", a.acc_no), ("Наименование", r["name"]), ("Тип", r["type"]), ("Производитель", r["manufacturer"]), ("Модель", r["model"]),
                  ("Серийный номер", a.serial), ("Имя компьютера", a.hostname), ("Статус", r["status"]), ("Местоположение", r["location"]), ("Уточнение местоположения", a.loc_detail),
                  *[(M.ROLES_RU[k], r[k]) for k in ("user", "owner", "resp", "mol", "it")], ("Подразделение", r["dept"]), ("Филиал", r["branch"]), ("Дата приобретения", r["purchase_date"]),
                  ("Дата поступления", r["received_date"]), ("Ввод в эксплуатацию", r["commissioned_date"]), ("Гарантия до", r["warranty_until"]), ("Стоимость, ₽", r["cost_text"]),
                  ("Поставщик", r["supplier"]), ("Документ приобретения", a.purchase_doc), ("Входит в", r["parent"]), ("Компьютер KSC", a.ksc_name), ("Примечание", a.note)]
            tables.append({"id": "card", "title": "Учётные сведения", "columns": [col("k", "Поле"), col("v", "Значение")], "rows": [{"k": k, "v": v} for k, v in kv if v]})
            tables.append({"id": "props", "title": "Дополнительные свойства", "columns": [col("k", "Свойство"), col("v", "Значение")],
                           "rows": [{"k": x.name, "v": r["props_text"].get(x.code, "")} for x in n.props if x.code in r["props_text"]]})
            kids = (await db.execute(select(InvAsset).where(InvAsset.parent_id == a.id).order_by(InvAsset.inv_no))).scalars().all()
            kn = await C.names_for(db, list(kids))
            tables.append({"id": "parts", "title": "Состав и связанные единицы", "columns": BASE_COLS[:6], "rows": [_row(k, kn) for k in kids]})
            docs = (await db.execute(select(InvDoc).join(InvDocItem, InvDocItem.doc_id == InvDoc.id).where(InvDocItem.asset_id == a.id).order_by(InvDoc.doc_date.desc()))).scalars().all()
            tables.append({"id": "docs", "title": "Документы", "columns": [col("no", "Номер"), col("kind", "Вид"), col("date", "Дата", "date"), col("status", "Этап"), col("basis", "Основание")],
                           "rows": [{"no": d.no, "kind": M.DOC_SHORT.get(d.kind, d.kind), "date": d.doc_date.isoformat(), "status": M.DOC_STATUS_RU.get(d.status, d.status), "basis": d.basis} for d in docs]})
            hist = (await db.execute(select(InvHistory).where(InvHistory.asset_id == a.id).order_by(InvHistory.at.desc()).limit(ctx.max_rows))).scalars().all()
            tables.append({"id": "history", "title": "История", "columns": [col("at", "Когда (UTC)", "date"), col("title", "Событие"), col("changes", "Изменения"), col("by", "Кто"), col("basis", "Основание")],
                           "rows": [{"at": C._iso(h.at), "title": h.title, "changes": "; ".join(f"{c['label']}: {c.get('old') or '—'} → {c.get('new') or '—'}" for c in (h.changes or [])), "by": h.by,
                                     "basis": h.basis} for h in hist]})
            lics = (await db.execute(select(InvLicense.name, InvLicAssign.at).join(InvLicAssign, InvLicAssign.license_id == InvLicense.id).where(InvLicAssign.asset_id == a.id))).all()
            tables.append({"id": "licenses", "title": "Лицензии", "columns": [col("name", "Лицензия"), col("at", "Назначена (UTC)", "date")], "rows": [{"name": nm, "at": C._iso(at)} for nm, at in lics]})
            tabs = [{"id": t["id"], "title": t["title"]} for t in tables]
            metrics = [metric("docs", "Документов", len(docs)), metric("hist", "Событий истории", len(hist)), metric("parts", "Связанных единиц", len(kids))]

        elif view in ("owner_history", "moves"):
            d_from = _date(p.get("date_from")) or (today - timedelta(days=365))
            d_to = _date(p.get("date_to")) or today
            w = [InvHistory.at >= datetime(d_from.year, d_from.month, d_from.day, tzinfo=timezone.utc), InvHistory.at < datetime(d_to.year, d_to.month, d_to.day, tzinfo=timezone.utc) + timedelta(days=1)]
            if (af := acc.asset_filter()) is not None:
                w.append(InvHistory.asset_id.in_(select(InvAsset.id).where(af)))
            if p.get("ids"):
                w.append(InvHistory.asset_id.in_(p["ids"]))
            fields = set(M.PEOPLE_FIELDS) if view == "owner_history" else {"location_id", "loc_detail"}
            hq = select(InvHistory, InvAsset.inv_no, InvAsset.name, InvAsset.serial).join(InvAsset, InvAsset.id == InvHistory.asset_id).where(*w).order_by(InvHistory.at.desc()).limit(ctx.max_rows * 2)
            data = []
            for h, no, nm, sn in (await db.execute(hq)).all():
                for c in h.changes or []:
                    if c.get("f") in fields:
                        data.append({"at": C._iso(h.at), "inv_no": no, "name": nm, "serial": sn, "what": c["label"], "old": c.get("old") or "", "new": c.get("new") or "", "event": h.title, "by": h.by, "basis": h.basis})
            if view == "moves":
                for h, no, nm, sn in (await db.execute(hq.where(InvHistory.kind == "doc", InvHistory.title.like("%отправлено%")))).all():
                    data.append({"at": C._iso(h.at), "inv_no": no, "name": nm, "serial": sn, "what": "Отправлено", "old": "", "new": h.title, "event": h.title, "by": h.by, "basis": h.basis})
                data.sort(key=lambda r: r["at"], reverse=True)
            cols = [col("at", "Когда (UTC)", "date"), col("inv_no", "Инв. номер"), col("name", "Наименование"), col("serial", "Серийный номер"), col("what", "Что" if view == "moves" else "Роль"),
                    col("old", "Было"), col("new", "Стало"), col("event", "Событие"), col("by", "Кто"), col("basis", "Основание")]
            tables.append({"id": "rows", "title": TITLE[view], "columns": cols, "rows": data[:ctx.max_rows]})
            sub = f"{d_from:%d.%m.%Y} — {d_to:%d.%m.%Y}"
            metrics = [metric("rows", "Изменений", len(data)), metric("assets", "Единиц", len({r["inv_no"] for r in data}))]

        elif view in ("hardware", "software"):
            rows = await _assets(db, {**p, "cls": p.get("cls") or ",".join(M.COMPUTERS)}, ctx, acc, cfg, [InvAsset.ksc_host_id.is_not(None)])
            n = await C.names_for(db, rows)
            by_src = defaultdict(list)
            for a in rows:
                by_src[a.ksc_source_id].append(a)
            data, errors = [], []
            from ..ksc import hardware as HW  # noqa: PLC0415
            from ..ksc import queries as kq  # noqa: PLC0415

            for sid, assets in by_src.items():
                src = await db.get(KscSource, sid)
                if src is None or ctx.client_for is None:
                    errors.append("Источник KSC удалён или недоступен")
                    continue
                client = ctx.client_for(src)
                for i in range(0, len(assets), 300):
                    part = assets[i:i + 300]
                    ids = kq.ids_list([a.ksc_host_id for a in part])
                    try:
                        if view == "hardware":
                            agg = {int(r["host_id"]): r for r in await client.run(kq.HW_AGG_FOR.format(ids=ids), max_rows=20000)}
                        else:
                            sw = await client.run(kq.SOFTWARE_ON_HOSTS.format(ids=ids), max_rows=ctx.max_rows)
                    except KscError as exc:
                        errors.append(f"{src.name}: {exc.message}")
                        break
                    for a in part:
                        base = {"inv_no": a.inv_no, "hostname": a.hostname or a.ksc_name, "name": C.label(a, n).rsplit(" (", 1)[0], "user": n.person(a.user_id), "location": n.loc(a.location_id), "source": src.name}
                        if view == "hardware":
                            g = agg.get(a.ksc_host_id) or {}
                            data.append({**base, "cpus": g.get("cpus"), "cores": g.get("cores") if g.get("cpus_known") else None, "threads": g.get("threads") or None,
                                         "ram_gb": round(int(g["ram_bytes"]) / 1073741824, 1) if g.get("ram_bytes") else None, "ram_modules": g.get("ram_modules")})
                    if view == "software":
                        amap = {a.ksc_host_id: a for a in part}
                        for s0 in sw:
                            a = amap.get(int(s0["host_id"]))
                            if a is not None:
                                data.append({"inv_no": a.inv_no, "hostname": a.hostname or a.ksc_name, "user": n.person(a.user_id), "product": s0.get("name") or "", "version": s0.get("version") or "",
                                             "publisher": s0.get("publisher") or "", "install_date": C._iso(s0.get("install_date")), "source": src.name})
                    if ctx.cancelled():
                        raise RuntimeError("cancelled")
            if view == "hardware":
                cols = [col("inv_no", "Инв. номер"), col("hostname", "Имя компьютера"), col("name", "Наименование"), col("user", "Пользователь"), col("location", "Местоположение"),
                        col("cpus", "Процессоров", "num"), col("cores", "Ядер", "num"), col("threads", "Потоков", "num"), col("ram_gb", "ОЗУ, ГБ", "num"), col("ram_modules", "Модулей ОЗУ", "num"), col("source", "Источник KSC")]
                tables.append({"id": "rows", "title": TITLE[view], "columns": cols, "rows": data})
                metrics = [metric("rows", "Компьютеров", len(data)), metric("nodata", "Без сведений об оборудовании", sum(1 for r in data if not r["cpus"]), "", "warn")]
            else:
                cols = [col("inv_no", "Инв. номер"), col("hostname", "Имя компьютера"), col("user", "Пользователь"), col("product", "Программа"), col("version", "Версия"), col("publisher", "Производитель"),
                        col("install_date", "Установлена", "date"), col("source", "Источник KSC")]
                tables.append({"id": "rows", "title": TITLE[view], "columns": cols, "rows": data[:ctx.max_rows]})
                prod = Counter(r["product"] for r in data)
                tables.append({"id": "products", "title": "Программы", "columns": [col("k", "Программа"), col("v", "Компьютеров", "num")], "rows": [{"k": k, "v": v} for k, v in prod.most_common()]})
                tabs = [{"id": "products", "title": "Программы"}, {"id": "rows", "title": "Установки по компьютерам"}]
                metrics = [metric("hosts", "Компьютеров", len({r["inv_no"] for r in data})), metric("rows", "Установок", len(data)), metric("products", "Программ", len(prod))]
            notes.append("Технические сведения — из KSC по связанным с карточками компьютерам (только чтение). Карточки без связи с KSC в отчёт не входят.")
            notes += [f"Не получено: {e}" for e in errors[:10]]

        elif view in ("licenses", "license_usage"):
            lics = (await db.execute(select(InvLicense).where(InvLicense.active.is_(True)).order_by(InvLicense.name))).scalars().all()
            rid = {x for lc in lics for x in (lc.type_id, lc.supplier_id)} - {None}
            refs = dict((await db.execute(select(InvRef.id, InvRef.name).where(InvRef.id.in_(rid)))).all()) if rid else {}
            resp = dict((await db.execute(select(InvPerson.id, InvPerson.name).where(InvPerson.id.in_({lc.resp_id for lc in lics} - {None})))).all()) if lics else {}
            asg = dict((await db.execute(select(InvLicAssign.license_id, func.count()).group_by(InvLicAssign.license_id))).all())
            data = []
            for lc in lics:
                u = lc.usage or {}
                a = asg.get(lc.id, 0)
                issues = []
                if lc.valid_until and lc.valid_until < today:
                    issues.append("срок истёк")
                elif lc.valid_until and lc.valid_until <= today + timedelta(days=cfg.license_days):
                    issues.append("срок истекает")
                if lc.qty is not None and u.get("installs") is not None and u["installs"] > lc.qty and lc.metric == "device":
                    issues.append("установок больше, чем лицензий")
                if lc.qty is not None and a > lc.qty:
                    issues.append("назначений больше, чем лицензий")
                data.append({"name": lc.name, "vendor": lc.vendor, "version": " ".join(x for x in (lc.version, lc.edition) if x), "type": refs.get(lc.type_id, ""), "metric": M.METRIC_RU.get(lc.metric, ""),
                             "qty": lc.qty, "assigned": a, "installs": u.get("installs"), "free": (lc.qty - a) if lc.qty is not None else None, "valid_until": C._d(lc.valid_until),
                             "supplier": refs.get(lc.supplier_id, ""), "cost": round(lc.cost / 100, 2) if lc.cost is not None else None, "resp": resp.get(lc.resp_id, ""), "issues": "; ".join(issues),
                             "usage_at": u.get("at")})
            if view == "licenses":
                cols = [col("name", "Продукт"), col("vendor", "Производитель"), col("version", "Версия, редакция"), col("type", "Тип лицензии"), col("metric", "Учёт"), col("qty", "Куплено", "num"),
                        col("valid_until", "Действует до", "date"), col("supplier", "Поставщик"), col("cost", "Стоимость, ₽", MONEY), col("resp", "Ответственный")]
            else:
                cols = [col("name", "Продукт"), col("qty", "Куплено", "num"), col("assigned", "Назначено", "num"), col("free", "Свободно", "num"), col("installs", "Установлено (KSC)", "num"),
                        col("issues", "Расхождения"), col("valid_until", "Действует до", "date"), col("usage_at", "Подсчёт установок (UTC)", "date")]
                notes.append("«Установлено» — число активных компьютеров, где найдена программа по маскам лицензии (подсчёт выполняется фоново). Ключи активации в отчёт не выводятся.")
            tables.append({"id": "rows", "title": TITLE[view], "columns": cols, "rows": data})
            metrics = [metric("rows", "Лицензий", len(data)), metric("issues", "С расхождениями", sum(1 for r in data if r["issues"]), "", "warn")]

        elif view == "docs":
            w = []
            if p.get("doc_kind"):
                w.append(InvDoc.kind.in_(str(p["doc_kind"]).split(",")))
            if p.get("date_from"):
                w.append(InvDoc.doc_date >= _date(p["date_from"]))
            if p.get("date_to"):
                w.append(InvDoc.doc_date <= _date(p["date_to"]))
            docs = (await db.execute(select(InvDoc).where(*w).order_by(InvDoc.doc_date.desc(), InvDoc.id.desc()).limit(ctx.max_rows))).scalars().all()
            cnt = dict((await db.execute(select(InvDocItem.doc_id, func.count()).where(InvDocItem.doc_id.in_([d.id for d in docs])).group_by(InvDocItem.doc_id))).all()) if docs else {}
            pids = {x for d in docs for x in (d.from_person_id, d.to_person_id)} - {None}
            ppl = dict((await db.execute(select(InvPerson.id, InvPerson.name).where(InvPerson.id.in_(pids)))).all()) if pids else {}
            data = [{"no": d.no, "kind": M.DOC_SHORT.get(d.kind, d.kind), "date": d.doc_date.isoformat(), "status": M.DOC_STATUS_RU.get(d.status, d.status), "from": ppl.get(d.from_person_id, ""),
                     "to": ppl.get(d.to_person_id, ""), "items": cnt.get(d.id, 0), "basis": d.basis, "by": d.created_by} for d in docs]
            tables.append({"id": "rows", "title": TITLE[view], "columns": [col("no", "Номер"), col("kind", "Вид"), col("date", "Дата", "date"), col("status", "Этап"), col("from", "От кого"), col("to", "Кому"),
                                                                          col("items", "Единиц", "num"), col("basis", "Основание"), col("by", "Оформил")], "rows": data})
            metrics = [metric("rows", "Документов", len(data)), *[metric(f"k{i}", k, v) for i, (k, v) in enumerate(Counter(r["kind"] for r in data).most_common(4))]]

        elif view in ("count", "count_diff"):
            from ..inventory import counting as K  # noqa: PLC0415
            from ..models import InvCount, InvCountItem  # noqa: PLC0415

            cnt = await db.get(InvCount, int(p.get("count_id") or 0)) if p.get("count_id") else (await db.execute(select(InvCount).where(InvCount.status != "cancelled").order_by(InvCount.created_at.desc()).limit(1))).scalar_one_or_none()
            if cnt is None:
                raise KscError("no_data", "Инвентаризаций ещё не было")
            sub = f"{cnt.no} · {cnt.title}"
            items = list((await db.execute(select(InvCountItem).where(InvCountItem.count_id == cnt.id).order_by(InvCountItem.id))).scalars())
            locs, people = await K.names(db, items)
            data = [K.item_out(it, locs, people) for it in items]
            if scopes:
                allowed = {i for (i,) in (await db.execute(select(InvAsset.id).where(acc.asset_filter())))}
                data = [r for r in data if r["asset_id"] is None or r["asset_id"] in allowed]
            for r in data:
                r["found_at"] = r["found_at"] or None
            cols = [col("state_ru", "Результат"), col("inv_no", "Инв. номер"), col("name", "Наименование"), col("serial", "Серийный номер"), col("exp_location", "По учёту"),
                    col("found_location", "Найдено в"), col("user", "Пользователь по учёту"), col("found_user", "Фактический пользователь"), col("found_at", "Отмечено (UTC)", "date"),
                    col("found_by", "Кто отметил"), col("decision_ru", "Решение"), col("note", "Примечание")]
            diff = [r for r in data if r["discrepancy"]]
            if view == "count":
                tables.append({"id": "rows", "title": "Все строки", "columns": cols, "rows": data})
            tables.append({"id": "diff", "title": "Расхождения", "columns": cols, "rows": diff, "note": "Найдено в другом месте, не ожидалось, код не найден в учёте, не найдено, другой пользователь."})
            st = await K.stats(db, cnt) if cnt.status in ("active", "closed") else {"locations": [], "by_state": {}, "expected": 0, "checked": 0}
            tables.append({"id": "locs", "title": "По местоположениям", "columns": [col("location", "Местоположение"), col("expected", "Ожидалось", "num"), col("found", "Найдено на месте", "num"),
                                                                                   col("moved_out", "Найдено в другом месте", "num"), col("left", "Не найдено / осталось", "num")], "rows": st["locations"]})
            tabs = [{"id": t["id"], "title": t["title"]} for t in tables]
            bs = st.get("by_state", {})
            metrics = [metric("expected", "Ожидалось", st.get("expected", 0)), metric("checked", "Проверено", st.get("checked", 0)), metric("missing", "Не найдено", bs.get("missing", 0) + bs.get("pending", 0), "", "warn"),
                       metric("moved", "В другом месте", bs.get("moved", 0)), metric("extra", "Не ожидалось", bs.get("extra", 0) + bs.get("unknown", 0))]
            notes.append(f"Статус инвентаризации: {M.COUNT_STATUS_RU.get(cnt.status, cnt.status)}. Обнаружение само по себе учёт не меняет: изменения вносятся решениями по расхождениям.")
        elif view.startswith("infra_"):
            from .quick_infra import build_infra_view  # noqa: PLC0415

            tables, metrics, tabs, sub, more = await build_infra_view(db, view, p, acc, cfg, ctx)
            notes += more
        else:                                                           # duplicates
            rows = await _assets(db, p, ctx, acc, cfg)
            n = await C.names_for(db, rows)
            groups = defaultdict(list)
            for a in rows:
                if a.serial:
                    groups[("Серийный номер", a.serial.casefold())].append(a)
                if a.hostname:
                    groups[("Имя компьютера", a.hostname.split(".")[0].casefold())].append(a)
            data = []
            for (kind, val), items in sorted(groups.items()):
                if len(items) > 1:
                    for a in items:
                        data.append({"match": kind, "value": val, **_row(a, n)})
            tables.append({"id": "rows", "title": TITLE[view], "columns": [col("match", "Совпадение"), col("value", "Значение"), *BASE_COLS[:7], col("ksc", "Компьютер KSC")], "rows": data})
            metrics = [metric("groups", "Групп совпадений", len({(r["match"], r["value"]) for r in data}), "", "warn"), metric("rows", "Карточек", len(data))]
            notes.append("Совпадение серийного номера или имени — повод проверить карточки; автоматически они не объединяются.")
    return {"title": TITLE[view], "subtitle": sub, "conditions": _cond(p), "severity": None, "notes": notes, "metrics": metrics, "tables": tables, **({"tabs": tabs} if tabs and len(tabs) > 1 else {})}


def _date(v) -> date | None:
    try:
        return C.parse_date(v)
    except ValueError:
        return None


async def _cfg(db):
    from ..models import AppSetting  # noqa: PLC0415
    from ..services.settings import InventorySettings  # noqa: PLC0415

    row = await db.get(AppSetting, "inventory")
    try:
        return InventorySettings(**{k: v for k, v in (row.value if row else {}).items() if k in InventorySettings.model_fields})
    except ValueError:
        return InventorySettings()
