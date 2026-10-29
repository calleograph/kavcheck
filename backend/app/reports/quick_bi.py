"""Отчёты по данным BI (одна точка входа, вид — параметр `view`):

* owners — «Устройства и владельцы»: компьютер, владелец, подразделение, источник, тип устройства, ОС, состояние защиты KSC;
* history — «История принадлежности устройств»: каждая связь «устройство × сотрудник» с датами наблюдения и выгрузкой-основанием;
* unknown — «Неопределённые владельцы»: нет ровно одного текущего владельца, устройства нет в последнем снимке или связь низкой достоверности;
* discrepancies — «Расхождения BI и KSC»: противоречия, неоднозначные сопоставления, несколько владельцев;
* problems — «Проблемы защиты и контактные лица»: компьютеры KSC с проблемами Kaspersky, пользователь KSC, владелец и почта по BI.

Фильтры — те же, что на странице (поиск, источник BI, отбор, ОС, личные устройства, сотрудник, устройство). Даты связей — даты выгрузок, а не даты передачи устройства."""
from __future__ import annotations

import uuid
from collections import Counter

from sqlalchemy import or_, select

from ..bi import read as R
from ..bi.match import LINKED
from ..ksc.driver import KscError, SourceClient
from ..ksc.protection import PROBLEMS
from ..models import BiDevice, BiImport, BiMatch, BiOwner, BiPerson, BiSource, DeviceUser, KscSource, ZcHost, ZcSource
from .quick import Ctx, col, metric

LIMIT = 50_000
TITLE = {"owners": "Устройства и владельцы", "history": "История принадлежности устройств", "unknown": "Неопределённые владельцы", "discrepancies": "Расхождения BI и KSC",
         "problems": "Проблемы защиты и контактные лица"}
FLT = {"unknown": "unknown_owner", "discrepancies": "issues"}
TYPE_RU = {True: "личное", False: "корпоративное", None: "не указано"}
OS_RU = {"windows": "Windows", "linux": "Linux", "mac": "macOS", "": "не указана"}


def _owner(it: dict) -> tuple[str, str, str]:
    if len(it["owners"]) == 1:
        p = it["owners"][0]
        return p["name"], p["email"], p["department"]
    if len(it["owners"]) > 1:
        return "несколько: " + ", ".join(p["name"] for p in it["owners"][:3]), ", ".join(p["email"] for p in it["owners"][:3] if p["email"]), it["owners"][0]["department"]
    if it["previous"]:
        p = it["previous"][0]
        return f"{p['name']} ({R.STATE_RU[p['state']].lower()})", p["email"], p["department"]
    return "не определён", "", ""


async def _protection(db, pairs: set) -> dict:
    """(источник KSC, компьютер) → состояние защиты по подготовленным данным зон."""
    out = {}
    by: dict = {}
    for s, h in pairs:
        by.setdefault(s, []).append(h)
    for s, hids in by.items():
        gen = (await db.execute(select(ZcSource.gen).where(ZcSource.source_id == s))).scalar()
        for i in range(0, len(hids), 1000):
            for hz in (await db.execute(select(ZcHost).where(ZcHost.source_id == s, ZcHost.gen == gen, ZcHost.host_id.in_(hids[i:i + 1000])))).scalars():
                probs = [PROBLEMS[k][0] for c, k in R.KSC_PROBLEMS if getattr(hz, c)]
                out[(s, hz.host_id)] = ", ".join(probs) if probs else ("работает" if hz.has_av else "нет сведений о Kaspersky")
    return out


async def build_bi(client: SourceClient | None, p: dict, ctx: Ctx) -> dict:
    if ctx.sm is None:
        raise KscError("params", "Отчёт недоступен: нет доступа к локальной базе")
    view = p.get("view") or "owners"
    if view not in TITLE:
        raise KscError("params", "Неизвестный вид отчёта BI")
    bsid = uuid.UUID(p["source_id"]) if p.get("source_id") else None
    async with ctx.sm() as db:
        srcs = (await db.execute(select(BiSource).order_by(BiSource.name))).scalars().all()
        snaps = {i.source_id: i.snapshot_at for i in (await db.execute(select(BiImport).where(BiImport.id.in_([s.last_import_id for s in srcs if s.last_import_id])))).scalars()}
        prov = "; ".join(f"«{s.name}» — выгрузка от {R.d(snaps.get(s.id))}" for s in srcs if (bsid is None or s.id == bsid)) or "BI-источники не подключены"
        cond = [{"label": "Вид отчёта", "text": TITLE[view]}, {"label": "Сведения BI", "text": prov}]
        for k, label in (("q", "Поиск"), ("dept", "Подразделение"), ("os", "ОС"), ("filter", "Отбор")):
            if p.get(k):
                cond.append({"label": label, "text": str(p[k])})
        if view == "problems":
            doc = await _problems(db, p, ctx)
        elif view == "history":
            doc = await _history(db, p, bsid)
        else:
            doc = await _devices(db, p, bsid, view)
    notes = ["Сведения о сотрудниках и устройствах — из BI-выгрузок; состояние защиты — по KSC (подготовленные данные зон). Сведения BI об антивирусе не заменяют фактическое состояние Kaspersky.",
             "Даты связей — даты выгрузок, в которых связь наблюдалась, а не даты передачи устройства. «Предполагаемое» сопоставление с KSC основано на имени и подтверждающих признаках; «Надёжное» — подтверждено администратором.",
             "Отчёт содержит персональные данные: передавайте его только тем, кому они необходимы."]
    if doc.pop("truncated", False):
        notes.append(f"В отчёт включены первые {LIMIT} записей.")
    return {"title": TITLE[view], "subtitle": prov, "conditions": cond + doc.pop("cond", []), "severity": None, "notes": notes, **doc}


async def _device_list(db, p: dict, bsid, view: str) -> tuple[list[dict], bool]:
    w = R._device_where(p.get("q", ""), bsid, FLT.get(view, p.get("filter", "")), p.get("os", ""), p.get("personal", ""))  # noqa: SLF001
    if p.get("device_id"):
        w.append(BiDevice.id == int(p["device_id"]))
    if p.get("person_id"):
        w.append(BiDevice.id.in_(select(BiOwner.device_id).where(BiOwner.person_id == int(p["person_id"]))))
    ds = (await db.execute(select(BiDevice).where(*w).order_by(BiDevice.short, BiDevice.id).limit(LIMIT + 1))).scalars().all()
    items = []
    for i in range(0, min(len(ds), LIMIT), 1000):
        items += await R.device_rows(db, ds[i:i + 1000], pd=True)
    return items, len(ds) > LIMIT


async def _devices(db, p: dict, bsid, view: str) -> dict:
    items, trunc = await _device_list(db, p, bsid, view)
    prot = await _protection(db, {(uuid.UUID(k["ksc_source_id"]), k["host_id"]) for it in items for k in it["ksc"] if k["level"] in LINKED})
    rows = []
    for it in items:
        name, email, dept = _owner(it)
        link = [k for k in it["ksc"] if k["level"] in LINKED]
        ksc = "; ".join(f"{k['host_name']} ({k['ksc_source']})" for k in link) or ("требует решения: " + it["ksc"][0]["level_ru"].split(": ", 1)[-1] if it["ksc"] else "не найдено в KSC")
        why = []
        if view == "unknown":
            if not it["present"]:
                why.append("нет в последней выгрузке")
            if len(it["owners"]) > 1:
                why.append("несколько владельцев")
            if not it["owners"] and it["present"]:
                why.append("в выгрузке без сотрудника" if not it["previous"] else "текущий владелец не указан")
            if any(o.get("confidence") == "low" for o in it["owners"]):
                why.append("низкая достоверность связи (условное имя или только ФИО)")
        rows.append({"host": it["name"], "user": name, "email": email, "department": dept, "source": it["source"], "type": TYPE_RU[it["personal"]], "os": it["os"] or OS_RU[it["os_family"]],
                     "protection": "; ".join(prot.get((uuid.UUID(k["ksc_source_id"]), k["host_id"]), "") for k in link) or "—", "ksc": ksc, "match": (link or it["ksc"] or [{"level_ru": "Не сопоставлено"}])[0]["level_ru"],
                     "previous": ", ".join(x["name"] for x in it["previous"][:3]) + (f" и ещё {it['previous_n'] - 3}" if it["previous_n"] > 3 else ""), "issues": "; ".join(it["issues"]),
                     "reason": "; ".join(why), "seen": it["last_seen_at"]})
    if view == "discrepancies":
        cols = [col("host", "Компьютер"), col("ksc", "Компьютер KSC"), col("issues", "Расхождение"), col("match", "Сопоставление"), col("user", "Владелец по BI"), col("protection", "Защита по KSC"), col("source", "Источник BI")]
    elif view == "unknown":
        cols = [col("host", "Компьютер"), col("reason", "Почему владелец не определён"), col("user", "Последний известный владелец"), col("department", "Подразделение"), col("os", "ОС"), col("ksc", "Компьютер KSC"),
                col("seen", "Последняя выгрузка с устройством", "date"), col("source", "Источник BI")]
    else:
        cols = [col("host", "Компьютер"), col("user", "Владелец"), col("department", "Подразделение"), col("email", "Рабочая почта"), col("source", "Источник сведений"), col("type", "Тип устройства"),
                col("os", "ОС"), col("protection", "Состояние защиты (KSC)"), col("ksc", "Компьютер KSC"), col("match", "Сопоставление"), col("previous", "Прежние владельцы"), col("seen", "Последняя выгрузка", "date")]
    n_link = sum(1 for it in items if any(k["level"] in LINKED for k in it["ksc"]))
    n_owner = sum(1 for it in items if len(it["owners"]) == 1)
    metrics = [metric("devices", "Устройств", len(rows)), metric("owner", "С текущим владельцем", n_owner, "ровно один сотрудник в последней выгрузке"),
               metric("linked", "Сопоставлено с KSC", n_link, "надёжно или предположительно"), metric("not_linked", "Без соответствия в KSC", len(rows) - n_link, "отсутствие в KSC не означает отсутствия Kaspersky", "warn" if len(rows) - n_link else "")]
    return {"metrics": metrics, "tables": [{"id": "rows", "title": TITLE[view], "columns": cols, "rows": rows, "note": "Одна строка — устройство BI."}], "truncated": trunc}


async def _history(db, p: dict, bsid) -> dict:
    items, trunc = await _device_list(db, p, bsid, "history")
    ids = [it["id"] for it in items]
    rows, imps = [], {}
    q = select(BiOwner, BiPerson, BiDevice).join(BiPerson, BiPerson.id == BiOwner.person_id).join(BiDevice, BiDevice.id == BiOwner.device_id)
    got = []
    for i in range(0, len(ids), 1000):
        got += (await db.execute(q.where(BiOwner.device_id.in_(ids[i:i + 1000])))).all()
    imp_ids = {x for o, _p, _d in got for x in (o.first_import_id, o.last_import_id) if x}
    for i in (await db.execute(select(BiImport).where(BiImport.id.in_(list(imp_ids))))).scalars() if imp_ids else []:
        imps[i.id] = f"{i.file_name} от {R.d(i.snapshot_at)}"
    src = {s.id: s.name for s in (await db.execute(select(BiSource))).scalars()}
    got.sort(key=lambda x: (x[2].short, {"current": 0, "past": 1, "unknown": 2}[R.state(x[0].present, x[2].present)], -x[0].last_seen_at.timestamp()))
    for o, pr, dv in got:
        st = R.state(o.present, dv.present)
        rows.append({"host": dv.name, "user": pr.full_name, "email": pr.email, "department": pr.department, "state": R.STATE_RU[st], "first": o.first_seen_at, "last": o.last_seen_at,
                     "first_file": imps.get(o.first_import_id, ""), "confidence": R.CONF_RU.get(o.confidence, o.confidence), "source": src.get(dv.source_id, ""),
                     "period": f"{R.d(o.owned_from)} — {R.d(o.owned_to)}" if o.owned_from or o.owned_to else "не передаётся источником"})
    cnt = Counter(r["state"] for r in rows)
    cols = [col("host", "Компьютер"), col("user", "Сотрудник"), col("department", "Подразделение"), col("state", "Состояние связи"), col("first", "Впервые в выгрузке", "date"), col("last", "Последний раз в выгрузке", "date"),
            col("first_file", "Выгрузка-основание"), col("period", "Период владения по источнику"), col("confidence", "Достоверность"), col("email", "Рабочая почта"), col("source", "Источник BI")]
    metrics = [metric("links", "Связей «устройство × сотрудник»", len(rows)), metric("devices", "Устройств", len(items)), metric("cur", "Текущих", cnt.get(R.STATE_RU["current"], 0)),
               metric("past", "Прежних", cnt.get(R.STATE_RU["past"], 0)), metric("unk", "Текущий статус неизвестен", cnt.get(R.STATE_RU["unknown"], 0), "устройства нет в последней выгрузке")]
    return {"metrics": metrics, "tables": [{"id": "rows", "title": "История принадлежности", "columns": cols, "rows": rows, "note": "Одна строка — связь устройства с сотрудником; сначала текущие, затем прежние."}],
            "truncated": trunc}


async def _problems(db, p: dict, ctx: Ctx) -> dict:
    """Компьютеры KSC с проблемами Kaspersky (нет антивируса, защита не работает, невылеченные объекты, лицензия) и контактные лица: пользователь KSC и владелец по BI."""
    sids = list(ctx.source_ids or [])
    if not sids:
        sids = [s.id for s in (await db.execute(select(KscSource).where(KscSource.is_active.is_(True)))).scalars()]
    names = {s.id: s.name for s in (await db.execute(select(KscSource).where(KscSource.id.in_(sids)))).scalars()}
    zn = await R.zone_names(db)
    rows, trunc = [], False
    for sid in sids:
        gen = (await db.execute(select(ZcSource.gen).where(ZcSource.source_id == sid))).scalar()
        if not gen:
            continue
        H = ZcHost
        hs = (await db.execute(select(H.host_id, H.name, H.last_connected, H.p_no_av, H.p_rtp, H.p_inf, H.p_lic, H.data["zones"])               # только нужные столбцы: без полной записи компьютера
                               .where(H.source_id == sid, H.gen == gen, H.active.is_(True), or_(H.p_no_av, H.p_rtp, H.p_inf, H.p_lic)).order_by(H.name).limit(LIMIT + 1))).all()
        trunc |= len(hs) > LIMIT
        hs = hs[:LIMIT]
        linked = {int(h) for (h,) in (await db.execute(select(BiMatch.host_id).where(BiMatch.ksc_source_id == sid, BiMatch.level.in_(LINKED)))).all()}
        own = await R.owners_for(db, sid, [h.host_id for h in hs if h.host_id in linked], pd=True)                                     # владельцы — только у сопоставленных с BI
        users: dict = {}
        ids = [h.host_id for h in hs]
        for i in range(0, len(ids), 1000):
            for hid, login, dom in (await db.execute(select(DeviceUser.host_id, DeviceUser.login, DeviceUser.domain).where(DeviceUser.source_id == sid, DeviceUser.host_id.in_(ids[i:i + 1000]), DeviceUser.kind == "user",
                                                                                                                     DeviceUser.resolved.is_(True)).order_by(DeviceUser.session_now.desc(), DeviceUser.last_session_at.desc().nulls_last()))).all():
                users.setdefault(hid, f"{dom}\\{login}" if dom else login)
        for h in hs:
            o = own.get(h.host_id)
            probs = [PROBLEMS[k][0] for c, k in R.KSC_PROBLEMS if getattr(h, c)]
            rows.append({"host": h.name, "problem": ", ".join(probs), "ksc_user": users.get(h.host_id, "нет данных KSC"), "owner": (o["name"] + ("" if o["state"] == "current" else f" ({o['state_ru'].lower()})")) if o else "не определён",
                         "email": o["email"] if o else "", "department": o["department"] if o else "", "zone": ", ".join(zn.get(str(z), str(z)) for z in h[7] or []) or "не назначена",
                         "basis": ("BI: " + ("подтверждённое сопоставление" if o["level"] == "confirmed" else "предполагаемое сопоставление") + f", выгрузка от {R.d(o['seen_at'])}") if o else "",
                         "last": h.last_connected, "source": names.get(sid, "")})
    with_owner = sum(1 for r in rows if r["owner"] != "не определён")
    cols = [col("host", "Компьютер"), col("problem", "Проблема Kaspersky"), col("ksc_user", "Пользователь KSC"), col("owner", "Владелец по BI"), col("email", "Контактная почта"), col("department", "Подразделение"),
            col("zone", "Зона ответственности"), col("basis", "Источник сведений о владельце"), col("last", "Последняя связь с KSC (UTC)", "date"), col("source", "Источник KSC")]
    metrics = [metric("hosts", "Компьютеров с проблемами", len(rows), "", "danger" if rows else "ok"), metric("owner", "Владелец определён по BI", with_owner),
               metric("no_owner", "Владелец не определён", len(rows) - with_owner, "", "warn" if len(rows) - with_owner else "")]
    return {"metrics": metrics, "tables": [{"id": "rows", "title": TITLE["problems"], "columns": cols, "rows": rows, "note": "Активные компьютеры KSC с проблемами Kaspersky; владелец — по сопоставленным устройствам BI."}],
            "truncated": trunc, "cond": [{"label": "Источники KSC", "text": ", ".join(names.values()) or "—"}]}
