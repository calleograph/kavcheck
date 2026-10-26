"""Быстрые контекстные отчёты: уязвимости (по CVE и программам), компьютеры, состояние защиты, события безопасности — и проверка версий в том же виде.

Каждый построитель возвращает документ (`doc`): заголовок, условия, показатели, распределение по опасности, замечания о достоверности и таблицы
(первая — основная). Один документ рисуют все выгрузки (XLSX, HTML, CSV) и предварительный просмотр в интерфейсе, поэтому числа везде одинаковы.

Правила подсчёта (подписаны в показателях):
* компьютеры — уникальные: компьютер с несколькими уязвимыми программами считается один раз;
* установки — уникальные пары «компьютер × установленная программа»;
* обнаружения — записи KSC «компьютер × уязвимость × программа»;
* «связывался с KSC за N суток» и «в сети сейчас» — разные состояния (второе — флаг KSC «видимо», нет значения — «нет данных»).
Подтверждённые KSC уязвимости (vapm) и результат проверки версий по условию пользователя — разные вещи и подписаны по-разному."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from ..ksc import events as EV
from ..ksc import hosts as H
from ..ksc import protection as P
from ..ksc import queries as q
from ..ksc import vulns as V
from ..ksc.driver import KscError, SourceClient
from ..search import any_field, matcher

QUICK_KINDS = ("quick_vulns", "quick_hosts", "quick_protection", "quick_events", "quick_extvulns", "quick_eol")
KIND_TITLE = {"quick_zone": "Состояние безопасности зоны", "quick_vulns": "Уязвимости", "quick_hosts": "Компьютеры", "quick_protection": "Состояние защиты", "quick_events": "События безопасности", "quick_extvulns": "Уязвимости по внешним базам", "quick_eol": "EOL в инфраструктуре"}
SEV_RU = {"critical": "Критическая", "high": "Высокая", "warning": "Предупреждение"}
SEV_RANK = {"critical": 3, "high": 2, "warning": 1}
ONLINE_RU = {True: "в сети", False: "не в сети", None: "нет данных"}


@dataclass
class Ctx:
    source_name: str
    activity_days: int
    exclude_slaves: bool = True
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    max_rows: int = 100_000
    progress: Callable[[str], None] = lambda _t: None
    cancelled: Callable[[], bool] = lambda: False
    protection_loader: Callable | None = None         # асинхронный источник набора «Состояния защиты» (кэш страницы); без него набор читается из KSC
    sm: object | None = None                          # фабрика сессий внутренней базы (отчёты по внешним базам уязвимостей)
    source_id: object | None = None
    zone_name: str = ""
    zone_hosts: set | None = None                      # компьютеры выбранной зоны (фильтр «Зона ответственности»); None — без отбора
    source_ids: list | None = None                     # источники отчёта, не привязанного к одному (EOL); None — только source_id
    org: dict = field(default_factory=dict)            # данные организации для шапки и подвала (настройки «Организация и оформление отчётов»)


def col(key: str, title: str, kind: str = "text") -> dict:
    return {"key": key, "title": title, "type": kind}


def _days(p: dict, ctx: Ctx) -> int:
    return int(p.get("active_days") or ctx.activity_days)


def scope_conditions(p: dict, ctx: Ctx) -> list[dict]:
    n = _days(p, ctx)
    out = [{"label": "Источник KSC", "text": ctx.source_name},
           {"label": "Давность связи", "text": "все устройства, включая давно не подключавшиеся к KSC" if p.get("include_inactive") else f"только устройства, связывавшиеся с KSC за последние {n} сут"},
           {"label": "Состояние «в сети»", "text": "только устройства, которые KSC видит в сети сейчас" if p.get("online_only") else "не используется как фильтр (колонка «В сети сейчас» показывает текущее состояние)"}]
    if p.get("group_contains"):
        out.append({"label": "Группа администрирования", "text": f"содержит «{p['group_contains']}»"})
    if p.get("q"):
        out.append({"label": "Поиск по компьютеру", "text": f"«{p['q']}»"})
    if p.get("zone"):
        out.append({"label": "Зона ответственности", "text": "Без ответственного" if p["zone"] == "none" else (ctx.zone_name or p["zone"])})
    return out


def host_part(hr: dict, p: dict, ctx: Ctx) -> dict:
    """Общие поля компьютера: имя, адрес, ОС, группа, связь с KSC (за N суток) и состояние «в сети»."""
    days = hr.get("days_since_connection")
    return {"host_id": hr["host_id"], "name": hr["name"], "fqdn": hr["fqdn"], "ip": hr["ip"], "os": (hr["os"] + (" " + hr["os_version"] if hr.get("os_version") else "")).strip(),
            "group": hr["group"], "last_connected": hr["last_connected"], "active": "да" if days is not None and days <= _days(p, ctx) else "нет",
            "online": ONLINE_RU[hr.get("online")], "online_raw": hr.get("online")}


def apply_scope(hosts: dict[int, dict], p: dict, ctx: Ctx) -> tuple[set[int], dict]:
    """Какие компьютеры входят в отчёт по давности связи и сети; сколько не вошло и почему."""
    n = _days(p, ctx)
    online_known = any(h.get("online") is not None for h in hosts.values())
    keep, hidden, offline = set(), 0, 0
    if ctx.zone_hosts is not None:
        hosts = {k: v for k, v in hosts.items() if k in ctx.zone_hosts}
    for hid, h in hosts.items():
        d = h.get("days_since_connection")
        if not p.get("include_inactive") and (d is None or d > n):
            hidden += 1
            continue
        if p.get("online_only") and online_known and h.get("online") is not True:
            offline += 1
            continue
        keep.add(hid)
    return keep, {"hidden_inactive": hidden, "hidden_offline": offline, "online_known": online_known, "online_unavailable": bool(p.get("online_only") and not online_known and hosts)}


def scope_notes(info: dict, p: dict, ctx: Ctx) -> list[str]:
    out = []
    if info["hidden_inactive"]:
        out.append(f"Не вошло компьютеров без связи с KSC дольше {_days(p, ctx)} сут: {info['hidden_inactive']}. Чтобы увидеть их, включите «Все устройства».")
    if info["hidden_offline"]:
        out.append(f"Не вошло компьютеров, которых KSC сейчас не видит в сети: {info['hidden_offline']}.")
    if info["online_unavailable"]:
        out.append("KSC не передаёт статус «в сети» для этих устройств: фильтр «только онлайн» не применён.")
    return out


def metric(key: str, label: str, value, hint: str = "", tone: str = "") -> dict:
    return {"key": key, "label": label, "value": value, "hint": hint, "tone": tone}


def _unique_online(rows: list[dict]) -> tuple[int, int, int]:
    seen: dict[int, bool | None] = {}
    for r in rows:
        seen.setdefault(r["host_id"], r.get("online_raw"))
    return (sum(1 for v in seen.values() if v is True), sum(1 for v in seen.values() if v is False), sum(1 for v in seen.values() if v is None))


# ------------------------------------------------------------------------------------------------ уязвимости
VULN_COLS = [col("severity_ru", "Опасность", "sev"), col("kla_id", "Уязвимость (KLA)", "mono"), col("cve", "CVE", "mono"), col("product", "Программа"),
             col("installed_version", "Установленная версия", "mono"), col("name", "Компьютер"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("group", "Группа администрирования"),
             col("last_connected", "Последнее подключение к KSC (UTC)", "date"), col("active", "Связь за период"), col("online", "В сети сейчас"), col("detected", "Обнаружена (UTC)", "date"),
             col("fix", "Исправление"), col("binding", "Привязка к версии (KSC)")]


async def build_vulns(client: SourceClient, p: dict, ctx: Ctx) -> dict:
    descr_ids = [int(i) for i in p.get("descr_ids") or []]
    notes: list[str] = []
    cves = [c for c in (p.get("cves") or []) if c]
    if cves:
        res = await V.resolve_cves(client, cves)
        missing = [c for c, i in res.items() if i is None]
        descr_ids += [i for i in res.values() if i]
        if missing:
            notes.append(f"В KSC нет уязвимости с идентификатором: {', '.join(missing)}. По ним в отчёте данных нет.")
    sev = {"critical": 4, "high": 2, "warning": 1}.get(p.get("severity") or "")
    vp_ids, host_ids, names = [int(i) for i in p.get("vp_ids") or []], [int(i) for i in p.get("host_ids") or []], list(p.get("product_names") or [])
    if cves and not (descr_ids or vp_ids or host_ids or names):
        raw = []                                                                    # выбраны только CVE, которых в KSC нет: пустой результат с пояснением, не ошибка
    else:
        raw = await V.detail_rows(client, descr_ids=descr_ids, vp_ids=vp_ids, product_names=names, host_ids=host_ids, severity=sev, patchable=bool(p.get("patchable")),
                                  max_rows=ctx.max_rows, progress=ctx.progress, cancelled=ctx.cancelled)
    groups = await H.groups_map(client)
    hosts: dict[int, dict] = {}
    not_computers = 0
    for r in raw:
        hid = int(r["host_id"])
        if hid in hosts:
            continue
        hosts[hid] = H.host_row(r, groups, ctx.now)
        hosts[hid]["is_slave"] = bool(r.get("is_slave"))
    keep, info = apply_scope({h: v for h, v in hosts.items() if not (ctx.exclude_slaves and v["is_slave"])}, p, ctx)
    not_computers = len({h for h, v in hosts.items() if ctx.exclude_slaves and v["is_slave"]})
    needle, gneedle = any_field(p.get("q")), matcher(p.get("group_contains"))
    used = [r for r in raw if int(r["host_id"]) in keep]
    if needle:
        used = [r for r in used if needle(*(hosts[int(r["host_id"])][k] for k in ("name", "fqdn", "ip")))]
    if gneedle:
        used = [r for r in used if gneedle(hosts[int(r["host_id"])]["group"])]
    names = await V.names_for(client, sorted({int(r["descr_id"]) for r in used}))
    rows: list[dict] = []
    for r in used:
        hr = hosts[int(r["host_id"])]
        did = int(r["descr_id"])
        nm = names.get(did, {"cve": [], "kb": []})
        sk = V.SEVERITY_KEY.get(r.get("severity"), "warning")
        kb = [f"KB{k}" if str(k).isdigit() else str(k) for k in nm["kb"]]
        installed = r.get("app_version") or r.get("product_version") or ""
        confirmed = bool(r.get("app_name"))
        rows.append({**host_part(hr, p, ctx), "severity": sk, "severity_ru": SEV_RU[sk], "kla_id": r.get("kla_id") or "", "descr_id": did, "cve": ", ".join(sorted(nm["cve"])), "cve_list": sorted(nm["cve"]),
                     "product": r.get("product") or r.get("app_name") or "(программа не определена)", "installed_version": installed, "app_name": r.get("app_name") or "", "publisher": r.get("publisher") or "",
                     "vp_id": r.get("vp_id"), "detected": r.get("detected"), "url": r.get("url") or "", "occurrence_id": int(r["occurrence_id"]),
                     "fix": ("Исправление доступно" + (f" ({', '.join(kb)})" if kb else "")) if r.get("patches_available") else "Сведений об исправлении в KSC нет",
                     "patch": bool(r.get("patches_available")),
                     "binding": "подтверждено KSC: найдена программа в реестре" if confirmed else "KSC не определил установленную версию: указана версия из справочника уязвимости",
                     "confirmed": confirmed, "install_key": f"{hr['host_id']}:{r.get('inv_id') or ''}:{r.get('vp_id') or ''}:{r.get('app_name') or r.get('product') or ''}:{installed}"})
    rows.sort(key=lambda r: (-SEV_RANK[r["severity"]], r["kla_id"], r["name"].lower()))
    # показатели: уникальные компьютеры, установки и обнаружения считаются раздельно
    hosts_u = {r["host_id"] for r in rows}
    installs = {r["install_key"] for r in rows}
    descrs = {r["descr_id"] for r in rows}
    cve_set = {c for r in rows for c in r["cve_list"]}
    worst: dict[int, str] = {}
    for r in rows:
        if SEV_RANK[r["severity"]] > SEV_RANK.get(worst.get(r["host_id"], ""), 0):
            worst[r["host_id"]] = r["severity"]
    on, off, nodata = _unique_online(rows)
    sev_stat = {k: {"hosts_worst": sum(1 for v in worst.values() if v == k), "rows": sum(1 for r in rows if r["severity"] == k),
                    "vulns": len({r["descr_id"] for r in rows if r["severity"] == k})} for k in SEV_RANK}
    metrics = [metric("hosts", "Затронуто компьютеров (уникальных)", len(hosts_u), "компьютер с несколькими уязвимостями или программами считается один раз", "danger" if hosts_u else "ok"),
               metric("installs", "Уязвимых установок (компьютер × программа)", len(installs), "одна и та же программа на одном компьютере — одна установка"),
               metric("rows", "Обнаружений (запись KSC: компьютер × уязвимость × программа)", len(rows)),
               metric("descr", "Различных уязвимостей (KLA)", len(descrs), f"различных CVE: {len(cve_set)}"),
               metric("online", "Из затронутых компьютеров в сети сейчас", on, f"не в сети: {off}; нет данных: {nodata}")]
    # название отчёта
    sel = sorted({r["kla_id"] for r in rows}) if p.get("descr_ids") or cves else []
    label = ", ".join(cves[:3]) + (f" и ещё {len(cves) - 3}" if len(cves) > 3 else "") if cves else ", ".join(sel[:3]) + (f" и ещё {len(sel) - 3}" if len(sel) > 3 else "") if sel \
        else ", ".join(sorted({r["product"] for r in rows})[:3]) if p.get("vp_ids") or p.get("product_names") else f"компьютеров: {len(p.get('host_ids') or [])}"
    conds = [{"label": "Что проверено", "text": ("уязвимости: " + (", ".join(cves) if cves else ", ".join(sel[:10]) or "выбранные") if descr_ids else
                                             "уязвимые программы: " + (", ".join(sorted({r['product'] for r in rows})[:10]) or "выбранные") if p.get("vp_ids") or p.get("product_names") else
                                             f"все действующие уязвимости на выбранных компьютерах ({len(p.get('host_ids') or [])})")}]
    if p.get("severity"):
        conds.append({"label": "Опасность", "text": SEV_RU[p["severity"]]})
    if p.get("patchable"):
        conds.append({"label": "Исправление", "text": "только уязвимости, для которых KSC сообщает о доступном исправлении"})
    conds += scope_conditions(p, ctx)
    notes += scope_notes(info, p, ctx)
    if not_computers:
        notes.append(f"Не вошли записи кластеров и подчинённых серверов (не компьютеры): {not_computers}.")
    unconfirmed = sum(1 for r in rows if not r["confirmed"])
    notes.append("Источник данных — действующие уязвимости, найденные Kaspersky Security Center (не проверка версий по условию пользователя). Безопасная версия в KSC не хранится: "
                 "для каждой уязвимости показано только наличие исправления.")
    if unconfirmed:
        notes.append(f"У {unconfirmed} обнаружений KSC не связал уязвимость с установленной программой реестра: версия взята из справочника уязвимости и может не совпадать с фактической.")
    if not rows:
        notes.append("По выбранным условиям затронутых компьютеров не найдено.")
    # таблицы: основная, по компьютерам, по программам, по уязвимостям
    by_host: dict[int, dict] = {}
    for r in rows:
        h = by_host.setdefault(r["host_id"], {**{k: r[k] for k in ("host_id", "name", "ip", "os", "group", "last_connected", "active", "online")}, "critical": 0, "high": 0, "warning": 0, "total": 0,
                                              "patchable": 0, "programs": set(), "worst": "", "_w": 0})
        h[r["severity"]] += 1
        h["total"] += 1
        h["patchable"] += 1 if r["patch"] else 0
        h["programs"].add(f"{r['product']} {r['installed_version']}".strip())
        if SEV_RANK[r["severity"]] > h["_w"]:
            h["_w"], h["worst"] = SEV_RANK[r["severity"]], SEV_RU[r["severity"]]
    host_rows = sorted(({**h, "programs": "; ".join(sorted(h["programs"]))[:500]} for h in by_host.values()), key=lambda h: (-h["_w"], -h["total"], h["name"].lower()))
    by_prog: dict[tuple[str, str], dict] = {}
    for r in rows:
        k = (r["product"], r["installed_version"])
        g = by_prog.setdefault(k, {"product": k[0], "installed_version": k[1], "hosts": set(), "descr": set(), "rows": 0, "_w": 0, "worst": ""})
        g["hosts"].add(r["host_id"])
        g["descr"].add(r["kla_id"])
        g["rows"] += 1
        if SEV_RANK[r["severity"]] > g["_w"]:
            g["_w"], g["worst"] = SEV_RANK[r["severity"]], SEV_RU[r["severity"]]
    prog_rows = sorted(({**g, "hosts": len(g["hosts"]), "vulns": len(g["descr"])} for g in by_prog.values()), key=lambda g: (-g["_w"], -g["hosts"], g["product"].lower()))
    by_vuln: dict[int, dict] = {}
    for r in rows:
        g = by_vuln.setdefault(r["descr_id"], {"kla_id": r["kla_id"], "cve": r["cve"], "severity_ru": r["severity_ru"], "_w": SEV_RANK[r["severity"]], "hosts": set(), "products": set(), "patch": 0, "rows": 0,
                                                "url": r["url"]})
        g["hosts"].add(r["host_id"])
        g["products"].add(r["product"])
        g["rows"] += 1
        g["patch"] += 1 if r["patch"] else 0
    vuln_rows = sorted(({**g, "hosts": len(g["hosts"]), "products": "; ".join(sorted(g["products"]))[:300], "fix": "доступно" if g["patch"] else "нет сведений"} for g in by_vuln.values()),
                       key=lambda g: (-g["_w"], -g["hosts"], g["kla_id"]))
    return {"title": f"Уязвимости: {label}" if rows or label else "Уязвимости", "subtitle": "Действующие уязвимости, найденные Kaspersky Security Center", "conditions": conds, "metrics": metrics,
            "severity": {"title": "Компьютеры по наивысшему уровню опасности (сумма = затронуто компьютеров)", "levels": [{"key": k, "label": SEV_RU[k], "value": sev_stat[k]["hosts_worst"],
                                                                                                                             "hint": f"обнаружений {sev_stat[k]['rows']}, уязвимостей {sev_stat[k]['vulns']}"} for k in ("critical", "high", "warning")]},
            "notes": notes, "tables": [
                {"id": "rows", "title": "Обнаружения", "columns": VULN_COLS, "rows": rows, "note": "Одна строка — одно обнаружение KSC: компьютер × уязвимость × программа."},
                {"id": "hosts", "title": "Компьютеры", "columns": [col("name", "Компьютер"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("group", "Группа администрирования"), col("worst", "Наивысшая опасность", "sev"),
                                                                  col("critical", "Критических", "num"), col("high", "Высоких", "num"), col("warning", "Предупреждений", "num"), col("total", "Всего обнаружений", "num"),
                                                                  col("patchable", "С исправлением", "num"), col("programs", "Программы и версии"), col("last_connected", "Последнее подключение к KSC (UTC)", "date"),
                                                                  col("active", "Связь за период"), col("online", "В сети сейчас")], "rows": host_rows},
                {"id": "programs", "title": "Программы", "columns": [col("product", "Программа"), col("installed_version", "Установленная версия", "mono"), col("hosts", "Компьютеров", "num"),
                                                                    col("vulns", "Уязвимостей", "num"), col("rows", "Обнаружений", "num"), col("worst", "Наивысшая опасность", "sev")], "rows": prog_rows},
                {"id": "vulns", "title": "Уязвимости", "columns": [col("kla_id", "Уязвимость (KLA)", "mono"), col("cve", "CVE", "mono"), col("severity_ru", "Опасность", "sev"), col("hosts", "Компьютеров", "num"),
                                                                    col("rows", "Обнаружений", "num"), col("products", "Программы"), col("fix", "Исправление"), col("url", "Описание")], "rows": vuln_rows}]}


# ------------------------------------------------------------------------------------------------ компьютеры
async def _host_protection(client: SourceClient, ids: list[int], groups: dict, ctx: Ctx) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for k in range(0, len(ids), 500):
        chunk = ids[k:k + 500]
        hosts = await client.run(q.PROTECTION_HOSTS.format(where=f"h.nId IN ({q.ids_list(chunk)})"), max_rows=1000)
        prods: dict[int, list[dict]] = defaultdict(list)
        for pr in await client.run(q.PROTECTION_PRODUCTS_FOR.format(ids=q.ids_list(chunk)), max_rows=10_000):
            prods[int(pr["host_id"])].append(pr)
        for h in hosts:
            out[int(h["host_id"])] = P.record(h, prods.get(int(h["host_id"]), []), groups, ctx.now)
    return out


async def build_hosts(client: SourceClient, p: dict, ctx: Ctx) -> dict:
    ids = [int(i) for i in p.get("host_ids") or []][:500]
    if not ids:
        raise KscError("params", "Не выбраны компьютеры")
    groups = await H.groups_map(client)
    recs = await _host_protection(client, ids, groups, ctx)
    secs = set(p.get("sections") or ["software", "vulns", "protection"])
    bases_days, scan_days = int(p.get("bases_days") or 3), int(p.get("scan_days") or 30)
    soft_rows: list[dict] = []
    if "software" in secs:
        for hid in ids:
            if ctx.cancelled():
                raise RuntimeError("cancelled")
            for s in await client.run(q.SOFTWARE_ON_HOST, {"id": hid}, max_rows=20_000):
                soft_rows.append({"host_id": hid, "name": recs[hid]["name"] if hid in recs else str(hid), "program": s.get("name") or "", "version": s.get("version") or "",
                                  "publisher": s.get("publisher") or "", "install_date": s.get("install_date")})
            ctx.progress(f"программы: {len(soft_rows)}")
    vul = await build_vulns(client, {**p, "host_ids": ids, "descr_ids": [], "cves": [], "vp_ids": [], "product_names": [], "include_inactive": True, "online_only": False, "q": "", "group_contains": ""},
                            ctx) if "vulns" in secs else None
    vrows = vul["tables"][0]["rows"] if vul else []
    by_vuln: dict[int, Counter] = defaultdict(Counter)
    for r in vrows:
        by_vuln[r["host_id"]][r["severity"]] += 1
    soft_n = Counter(r["host_id"] for r in soft_rows)
    rows, missing = [], [i for i in ids if i not in recs]
    for hid in ids:
        r = recs.get(hid)
        if r is None:
            continue
        pr = P.problems(r, ctx.now, bases_days=bases_days, scan_days=scan_days)
        av = r["av"] or {}
        c = by_vuln.get(hid, Counter())
        rows.append({**host_part(r, p, ctx), "ksc_status": r["ksc_status"] or "—", "reasons": "; ".join(P.STATUS_MASK[b] for b in P.STATUS_MASK if r["mask"] & b),
                     "problems": "; ".join(P.PROBLEMS[x][0] for x in pr) or "защита в порядке", "problems_n": len(pr), "av": av.get("product") or "нет", "av_build": av.get("build") or "",
                     "rtp": r["rtp_label"] or av.get("state_label") or "—", "bases": av.get("bases"), "last_full_scan": r["last_full_scan"], "agent": r["agent_build"],
                     "software": soft_n.get(hid, 0) if "software" in secs else None, "v_critical": c["critical"], "v_high": c["high"], "v_warning": c["warning"], "v_total": sum(c.values()),
                     "is_slave": r["is_slave"]})
    on = sum(1 for r in rows if r["online_raw"] is True)
    notes = ["Состояние защиты — по последним отчётам Агентов администрирования в KSC; время — UTC.",
             "Уязвимости — подтверждённые KSC (vapm); проверка версий по условию пользователя — отдельный отчёт."]
    if missing:
        notes.append(f"Не найдены в KSC: {len(missing)} из выбранных компьютеров.")
    conds = [{"label": "Компьютеры", "text": ", ".join(r["name"] for r in rows[:10]) + (f" и ещё {len(rows) - 10}" if len(rows) > 10 else "")},
             {"label": "Разделы", "text": ", ".join({"software": "установленное ПО", "vulns": "уязвимости", "protection": "состояние защиты"}[s] for s in ("software", "vulns", "protection") if s in secs)},
             {"label": "Источник KSC", "text": ctx.source_name}, {"label": "Порог баз / полной проверки", "text": f"{bases_days} / {scan_days} сут"}]
    metrics = [metric("hosts", "Компьютеров в отчёте", len(rows)), metric("online", "В сети сейчас", on, f"не в сети: {sum(1 for r in rows if r['online_raw'] is False)}; нет данных: {sum(1 for r in rows if r['online_raw'] is None)}"),
               metric("problems", "С проблемами защиты", sum(1 for r in rows if r["problems_n"]), "", "danger" if any(r["problems_n"] for r in rows) else "ok")]
    if "software" in secs:
        metrics.append(metric("software", "Установленных программ (записей)", len(soft_rows)))
    if vul is not None:
        metrics += [metric("vhosts", "Компьютеров с уязвимостями", len({r["host_id"] for r in vrows}), "уникальных"), metric("vrows", "Обнаружений уязвимостей", len(vrows), "компьютер × уязвимость × программа")]
    tables = [{"id": "hosts", "title": "Компьютеры", "columns": [col("name", "Компьютер"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("group", "Группа администрирования"),
                                                                  col("last_connected", "Последнее подключение к KSC (UTC)", "date"), col("active", "Связь за период"), col("online", "В сети сейчас"),
                                                                  col("ksc_status", "Статус KSC"), col("problems", "Проблемы защиты"), col("av", "Защитный продукт"), col("av_build", "Версия", "mono"),
                                                                  col("rtp", "Постоянная защита"), col("bases", "Базы (UTC)", "date"), col("last_full_scan", "Полная проверка (UTC)", "date"),
                                                                  col("agent", "Агент", "mono"), col("software", "Программ", "num"), col("v_critical", "Критических", "num"), col("v_high", "Высоких", "num"),
                                                                  col("v_warning", "Предупреждений", "num"), col("v_total", "Уязвимостей", "num"), col("reasons", "Причины статуса KSC")], "rows": rows}]
    if "software" in secs:
        tables.append({"id": "software", "title": "Установленное ПО", "columns": [col("name", "Компьютер"), col("program", "Программа"), col("version", "Версия", "mono"), col("publisher", "Производитель"),
                                                                                  col("install_date", "Установлена", "date")], "rows": soft_rows})
    if vul is not None:
        tables.append({**vul["tables"][0], "id": "vulns", "title": "Уязвимости"})
    return {"title": f"Компьютеры: {rows[0]['name']}" if len(rows) == 1 else f"Компьютеры: {len(rows)}", "subtitle": "Состояние, защита, установленное ПО и уязвимости", "conditions": conds,
            "metrics": metrics, "severity": vul["severity"] if vul else None, "notes": notes, "tables": tables}


# ------------------------------------------------------------------------------------------------ состояние защиты
async def build_protection(client: SourceClient, p: dict, ctx: Ctx) -> dict:
    groups = await H.groups_map(client)
    base = await ctx.protection_loader() if ctx.protection_loader else await P.load(client, exclude_slaves=ctx.exclude_slaves, groups=groups)
    bases_days, scan_days = int(p.get("bases_days") or 3), int(p.get("scan_days") or 30)
    if ctx.zone_hosts is not None:
        base = [h for h in base if h["host_id"] in ctx.zone_hosts]
    hosts, sc = P.scope(base, now=ctx.now, activity_days=_days(p, ctx), include_inactive=bool(p.get("include_inactive")), online_only=bool(p.get("online_only")), bases_days=bases_days, scan_days=scan_days)
    problem = p.get("problem") or ""
    items = P.pick(hosts, problem=problem, product=p.get("product") or "", build=p.get("build") or "", q=p.get("q") or "", group=p.get("group_contains") or "", host_ids=[int(i) for i in p.get("host_ids") or []])
    counts = Counter(x for h in hosts for x in h["problems"])
    rows = []
    for h in sorted(items, key=lambda h: (not h["problems"], [list(P.PROBLEMS).index(x) for x in h["problems"]][:1] or [99], h["name"].lower())):
        av = h["av"] or {}
        rows.append({**host_part(h, p, ctx), "problems": "; ".join(P.PROBLEMS[x][0] for x in h["problems"]) or "защита в порядке", "problems_n": len(h["problems"]), "av": av.get("product") or "нет",
                     "av_build": av.get("build") or "", "rtp": h["rtp_label"] or av.get("state_label") or "—", "bases": av.get("bases"), "last_full_scan": h["last_full_scan"], "agent": h["agent_build"],
                     "ksc_status": h["ksc_status"] or "—", "reasons": "; ".join(P.STATUS_MASK[b] for b in P.STATUS_MASK if h["mask"] & b)})
    title = P.PROBLEMS[problem][0] if problem in P.PROBLEMS else "Без проблем" if problem == "ok" else "Состояние защиты"
    conds = [{"label": "Категория", "text": title if problem else "все компьютеры области"}]
    if p.get("product"):
        conds.append({"label": "Версия продукта", "text": f"{p['product']} {p.get('build') or ''}".strip()})
    if p.get("host_ids"):
        conds.append({"label": "Выбрано компьютеров", "text": str(len(p["host_ids"]))})
    conds += scope_conditions(p, ctx) + [{"label": "Порог баз / полной проверки", "text": f"{bases_days} / {scan_days} сут"}]
    on, off, nodata = _unique_online(rows)
    protected = sum(1 for h in hosts if h["av"] and not {"rtp_off", "bases_old", "no_av"} & set(h["problems"]))
    metrics = [metric("hosts", "Компьютеров в отчёте", len(rows), f"в области отчёта всего: {len(hosts)}", "danger" if problem not in ("", "ok") and rows else ""),
               metric("online", "Из них в сети сейчас", on, f"не в сети: {off}; нет данных: {nodata}"),
               metric("protected", "Защищены (область отчёта)", f"{round(protected / len(hosts) * 100) if hosts else 0}%", f"{protected} из {len(hosts)}: антивирус работает, базы свежее {bases_days} сут")]
    notes = scope_notes({"hidden_inactive": sc["hidden"], "hidden_offline": sc["offline"], "online_known": sc["online_data"], "online_unavailable": bool(p.get("online_only") and not sc["online_data"])}, p, ctx)
    notes.append("Состояние защиты — по последним отчётам Агентов администрирования в KSC; у устройств, которых нет в сети, оно может быть устаревшим (см. «Подключение к KSC»).")
    prob_rows = [{"problem": P.PROBLEMS[k][0], "hosts": counts.get(k, 0), "share": f"{round(counts.get(k, 0) / len(hosts) * 100) if hosts else 0}%"} for k in P.PROBLEMS]
    return {"title": f"Состояние защиты: {title}" if problem else "Состояние защиты", "subtitle": "Компьютеры по проблемам защиты Kaspersky", "conditions": conds, "metrics": metrics, "severity": None,
            "notes": notes, "tables": [
                {"id": "hosts", "title": "Компьютеры", "columns": [col("name", "Компьютер"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("group", "Группа администрирования"), col("online", "В сети сейчас"),
                                                                  col("last_connected", "Последнее подключение к KSC (UTC)", "date"), col("active", "Связь за период"), col("problems", "Проблемы защиты"),
                                                                  col("av", "Защитный продукт"), col("av_build", "Версия", "mono"), col("rtp", "Постоянная защита"), col("bases", "Базы (UTC)", "date"),
                                                                  col("last_full_scan", "Полная проверка (UTC)", "date"), col("agent", "Агент", "mono"), col("ksc_status", "Статус KSC"),
                                                                  col("reasons", "Причины статуса KSC")], "rows": rows},
                {"id": "problems", "title": "Проблемы в области отчёта", "columns": [col("problem", "Проблема"), col("hosts", "Компьютеров", "num"), col("share", "Доля")], "rows": prob_rows}]}


# ------------------------------------------------------------------------------------------------ события безопасности
async def build_events(client: SourceClient, p: dict, ctx: Ctx) -> dict:
    days = int(p.get("days") or 7)
    types = [t for t in EV.GROUP_TYPES.get(p.get("group") or "", []) + list(p.get("types") or [])]
    event_ids = [int(i) for i in p.get("event_ids") or []]
    ctx.progress("чтение событий")
    try:
        rows_raw = await EV.all_rows(client, days=days, types=types, host_id=p.get("host_id") or None, qtext=p.get("q") or "", threat=p.get("threat") or "", event_ids=event_ids, max_rows=ctx.max_rows)
    except KscError as exc:
        if exc.code != "too_many_rows":
            raise
        raise KscError("too_many_rows", f"Событий больше предела отчёта ({ctx.max_rows}): сузьте период или фильтр") from None
    ctx.progress(f"событий прочитано: {len(rows_raw)}")
    rows = [{**r, "at": r["at"], "type_ru": r["type_title"], "ip": r["ip"] or "нет данных", "target": (f"{r['attacker'] or '?'} → порт {r['port']} ({r['protocol']})" if r["type"] == "attack" else r["object"])} for r in rows_raw]
    hosts_u = {r["host_id"] or r["host"] for r in rows}
    n_deleted = len({r["host_id"] or r["host"] for r in rows if not r["host_known"]})
    ev_deleted = sum(1 for r in rows if not r["host_known"])
    threats = Counter(r["threat"] for r in rows if r["threat"])
    by_type = Counter(r["type_title"] for r in rows)
    notcured = sum(1 for r in rows if r["type"] == "notcured")
    metrics = [metric("rows", "Событий в отчёте", len(rows)), metric("hosts", "Затронуто компьютеров (уникальных)", len(hosts_u), f"из них устройств, которых уже нет в KSC: {n_deleted}" if n_deleted else ""),
               metric("threats", "Различных угроз и атак", len(threats)), metric("notcured", "Событий «не вылечен»", notcured, "", "danger" if notcured else "ok")]
    conds = [{"label": "Период", "text": "последние сутки" if days == 1 else f"последние {days} сут"}, {"label": "Источник KSC", "text": ctx.source_name}]
    if p.get("group"):
        conds.append({"label": "Результат", "text": {"detections": "обнаружения", "notcured": "не вылечено", "resolved": "обработано", "attacks": "сетевые атаки"}.get(p["group"], p["group"])})
    if p.get("threat"):
        conds.append({"label": "Угроза", "text": p["threat"]})
    if p.get("q"):
        conds.append({"label": "Поиск", "text": f"«{p['q']}»"})
    if event_ids:
        conds.append({"label": "Выбрано событий", "text": str(len(event_ids))})
    top_h: dict = {}
    for r in rows:
        k = r["host_id"] or r["host"]
        g = top_h.setdefault(k, {"name": r["host"], "ip": r["ip"], "n": 0, "notcured": 0, "last": r["at"]})
        g["n"] += 1
        g["notcured"] += 1 if r["type"] == "notcured" else 0
    return {"title": "События безопасности" + (f": {p['threat']}" if p.get("threat") else ""), "subtitle": "Обнаружения угроз и сетевые атаки из журнала событий KSC", "conditions": conds, "metrics": metrics,
            "severity": None, "notes": ["Время события задаёт устройство; в отчёте — UTC.", "События — из журнала KSC за указанный период."]
            + ([f"События устройств, которых уже нет в KSC: {ev_deleted} (устройств: {n_deleted}). Имя и IP-адрес на момент события в публичном представлении KSC недоступны — указан идентификатор устройства, в столбце IP-адрес — «нет данных»."] if ev_deleted else [])
            + ([] if rows else ["По выбранным условиям событий не найдено."]), "tables": [
                {"id": "rows", "title": "События", "columns": [col("at", "Время (UTC)", "date"), col("host", "Компьютер"), col("ip", "IP-адрес", "mono"), col("type_ru", "Событие"), col("threat", "Угроза или атака", "mono"),
                                                              col("threat_kind", "Вид"), col("target", "Объект / источник атаки"), col("user", "Пользователь")], "rows": rows},
                {"id": "hosts", "title": "Компьютеры", "columns": [col("name", "Компьютер"), col("ip", "IP-адрес", "mono"), col("n", "Событий", "num"), col("notcured", "Не вылечено", "num"), col("last", "Последнее (UTC)", "date")],
                 "rows": sorted(top_h.values(), key=lambda g: -g["n"])},
                {"id": "threats", "title": "Угрозы", "columns": [col("threat", "Угроза или атака", "mono"), col("n", "Событий", "num"), col("type", "Типы событий")],
                 "rows": [{"threat": t, "n": n, "type": ", ".join(sorted({r["type_title"] for r in rows if r["threat"] == t}))} for t, n in threats.most_common()]},
                {"id": "types", "title": "Типы событий", "columns": [col("type", "Событие"), col("n", "Событий", "num")], "rows": [{"type": t, "n": n} for t, n in by_type.most_common()]}]}


# ------------------------------------------------------------------------------------------------ проверка версий в том же виде
AUDIT_VIEW_COLS = [col("program", "Программа"), col("product", "Продукт каталога"), col("app_version", "Установленная версия", "mono"), col("condition", "Условие проверки"), col("target_version", "Целевая версия", "mono"),
                   col("name", "Компьютер"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("group", "Группа администрирования"), col("last_connected", "Последнее подключение к KSC (UTC)", "date"),
                   col("active", "Связь за период"), col("online", "В сети сейчас"), col("app_name", "Запись реестра KSC"), col("publisher", "Производитель")]


def doc_from_audit(rows: list[dict], summary: dict, ctx_info: dict) -> dict:
    """Документ для проверки версий (version_audit): те же показатели и таблицы, что в быстрых отчётах; условие — дословно заданное пользователем."""
    days = summary.get("active_days")
    view = []
    for r in rows:
        d = r.get("days_since_connection")
        view.append({**r, "active": "да" if d is not None and (summary.get("include_inactive") or (days is not None and d <= days)) else "нет", "online": ONLINE_RU[r.get("online")], "online_raw": r.get("online"),
                     "product": r.get("product") or ""})
    progs = summary.get("programs", [])
    on, off, nodata = _unique_online(view)
    metrics = [metric("hosts", "Компьютеров, соответствующих условию (уникальных)", summary.get("hosts", 0), "компьютер с несколькими подходящими установками считается один раз", "danger" if summary.get("hosts") else "ok"),
               metric("rows", "Установок, соответствующих условию (компьютер × запись реестра)", summary.get("rows", 0)),
               metric("programs", "Программ проверено", len(progs), f"с находками: {sum(1 for x in progs if x['hosts'])}"),
               metric("online", "Из подходящих компьютеров в сети сейчас", on, f"не в сети: {off}; нет данных: {nodata}")]
    conds = [{"label": f"Условие: {x['program']}", "text": x["condition"] + (f" → целевая версия {x['target_version']}" if x.get("target_version") else "")} for x in progs]
    conds += [{"label": "Источники KSC", "text": ", ".join(s["source"] for s in summary.get("sources", [])) or ctx_info.get("source", "")},
              {"label": "Давность связи", "text": "все устройства" if summary.get("include_inactive") else f"только устройства, связывавшиеся с KSC за последние {days} сут"},
              {"label": "Состояние «в сети»", "text": "только устройства, которые KSC видит в сети сейчас" if summary.get("online_only") else "не используется как фильтр"}]
    notes = ["Результат проверки версий — соответствие установленной версии заданному условию, а не подтверждённая уязвимость. Подтверждённые KSC уязвимости — в разделе «Уязвимости» и в отчётах по CVE."]
    notes += list(summary.get("notes") or [])
    if summary.get("hidden_inactive_hosts") and not summary.get("include_inactive"):
        notes.append(f"Не вошло компьютеров без связи с KSC дольше {days} сут: {summary['hidden_inactive_hosts']}.")
    if summary.get("hidden_offline_hosts"):
        notes.append(f"Не вошло компьютеров, которых KSC сейчас не видит в сети: {summary['hidden_offline_hosts']}.")
    notes += [f"{x['program']}: {x['explain']}" for x in progs if x.get("explain")]
    prog_rows = [{"program": x["program"], "condition": x["condition"], "target": x.get("target_version") or "", "hosts": x["hosts"], "installs": x["installs"], "found": len(x.get("found", [])),
                  "matched": sum(1 for f in x.get("found", []) if f["matched"]), "explain": x.get("explain") or ""} for x in progs]
    found_rows = [{"program": x["program"], "name": f["name"], "version": f["version"], "compared": f.get("compared_version") or "", "publisher": f.get("publisher") or "", "product": f.get("product") or "",
                   "matched": "да" if f["matched"] else "нет"} for x in progs for f in x.get("found", [])]
    by_host: dict = {}
    for r in view:
        g = by_host.setdefault((r.get("source"), r["host_id"]), {**{k: r.get(k) for k in ("source", "name", "ip", "os", "group", "last_connected", "active", "online")}, "programs": set(), "n": 0})
        g["programs"].add(f"{r['program']} {r['app_version']}")
        g["n"] += 1
    host_rows = [{**g, "programs": "; ".join(sorted(g["programs"]))[:500]} for g in sorted(by_host.values(), key=lambda g: g["name"].lower())]
    return {"kind": "version_audit", "org": ctx_info.get("org") or {}, "title": ctx_info.get("title") or "Проверка версий", "subtitle": "Компьютеры, версия программы на которых соответствует условию проверки", "conditions": conds, "metrics": metrics, "severity": None,
            "notes": notes, "tables": [
                {"id": "rows", "title": "Компьютеры и установки", "columns": AUDIT_VIEW_COLS, "rows": view, "note": "Одна строка — одна установка, подходящая под условие."},
                {"id": "programs", "title": "Итог по программам", "columns": [col("program", "Программа"), col("condition", "Условие проверки"), col("target", "Целевая версия", "mono"), col("hosts", "Компьютеров", "num"),
                                                                              col("installs", "Установок", "num"), col("found", "Найдено записей реестра", "num"), col("matched", "Подходят под условие", "num"),
                                                                              col("explain", "Пояснение")], "rows": prog_rows},
                {"id": "hosts", "title": "Компьютеры", "columns": [col("name", "Компьютер"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("group", "Группа администрирования"),
                                                                  col("last_connected", "Последнее подключение к KSC (UTC)", "date"), col("active", "Связь за период"), col("online", "В сети сейчас"),
                                                                  col("n", "Установок", "num"), col("programs", "Программы и версии")], "rows": host_rows},
                {"id": "found", "title": "Найденные пакеты и версии", "columns": [col("program", "Программа"), col("name", "Запись реестра KSC"), col("version", "Версия", "mono"),
                                                                                    col("compared", "Сравниваемая версия", "mono"), col("publisher", "Производитель"), col("product", "Продукт каталога"),
                                                                                    col("matched", "Подходит под условие")], "rows": found_rows}]}


BUILDERS = {"quick_vulns": build_vulns, "quick_hosts": build_hosts, "quick_protection": build_protection, "quick_events": build_events}


async def build(kind: str, client: SourceClient, params: dict, ctx: Ctx) -> dict:
    if kind == "quick_extvulns" and kind not in BUILDERS:
        from .quick_ext import build_extvulns  # noqa: PLC0415 — отложенный импорт: модуль использует помощники этого файла

        BUILDERS[kind] = build_extvulns
    if kind == "quick_eol" and kind not in BUILDERS:
        from .quick_eol import build_eol  # noqa: PLC0415

        BUILDERS[kind] = build_eol
    if kind not in BUILDERS:
        raise KscError("kind", f"Неизвестный вид быстрого отчёта: {kind}")
    doc = await BUILDERS[kind](client, params, ctx)
    doc.update(kind=kind, generated_at=ctx.now.isoformat(timespec="seconds"), source=ctx.source_name, org=ctx.org)
    return doc


def brief(doc: dict) -> dict:
    """Документ без строк таблиц (для хранения в сводке отчёта и ответа предпросмотра): строки основной таблицы — отдельно, остальные — числом."""
    out = {k: v for k, v in doc.items() if k not in ("tables", "host_details")}
    if out.get("org"):
        out["org"] = {k: v for k, v in out["org"].items() if k != "logo"}          # логотип в сводке отчёта не хранится
    return {**out, "tables": [{"id": t["id"], "title": t["title"], "columns": t["columns"], "n": len(t["rows"]), "note": t.get("note", "")} for t in doc["tables"]]}
