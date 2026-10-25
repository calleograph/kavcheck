"""Отчёт «Состояние безопасности зоны ответственности» (вид quick_zone): тот же документ `doc`, те же выгрузки XLSX/HTML/CSV, что у остальных отчётов.

Порядок подачи: показатели → компактная таблица проблемных компьютеров (одна строка — компьютер) → подробности по каждому компьютеру → методика, источники, исключения.
Подтверждённые KSC уязвимости, потенциальные совпадения с внешними базами, проблемы защиты, принятые риски и исключённые (ложные) обнаружения подаются отдельно и не суммируются."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from ..ksc import protection as P
from ..reports.quick import ONLINE_RU, col, metric
from . import dataset as D
from . import triage as T

CATEGORIES = {"ksc_vulns": "Уязвимости, подтверждённые KSC", "ksc_critical": "Только критические уязвимости KSC", "ext_vulns": "Потенциальные уязвимости ПО по внешним базам",
              "no_av": P.PROBLEMS["no_av"][0], "rtp_off": P.PROBLEMS["rtp_off"][0], "bases_old": P.PROBLEMS["bases_old"][0], "infected": P.PROBLEMS["infected"][0],
              "license": P.PROBLEMS["license"][0], "scan_old": P.PROBLEMS["scan_old"][0], "reboot": P.PROBLEMS["reboot"][0], "inactive": "Давно не подключавшиеся к KSC компьютеры"}
DEFAULT_CATEGORIES = ["ksc_vulns", "ext_vulns", "no_av", "rtp_off", "bases_old", "infected", "inactive"]
PROTECTION_KEYS = tuple(P.PROBLEMS)
SEV_BADGE = {"critical": "Критическая", "high": "Высокая", "warning": "Предупреждение", "": ""}
LEVELS = {"management": "для руководства", "technical": "для администраторов"}
TOP_N = 15


def _fmt_dt(v) -> str:
    return v.strftime("%d.%m.%Y %H:%M") if isinstance(v, datetime) else ""


def matches(h: dict, cats: set[str]) -> bool:
    """Входит ли компьютер в список проблемных по выбранным категориям."""
    if "ksc_vulns" in cats and h["ksc"]["total"]:
        return True
    if "ksc_critical" in cats and h["ksc"]["critical"]:
        return True
    if "ext_vulns" in cats and h["ext"]["total"]:
        return True
    if any(k in cats and k in h["problems"] for k in PROTECTION_KEYS):
        return True
    return "inactive" in cats and not h["active"]


def _detail(h: dict, key: str, bases_days: int, scan_days: int) -> str:
    av = h["av"] or {}
    return {"no_av": "защитный продукт Kaspersky не найден или KSC не получал сведений о нём",
            "rtp_off": f"постоянная защита: {h['rtp_label'] or av.get('state_label') or 'не работает'}",
            "bases_old": f"базы от {_fmt_dt(av.get('bases')) or 'неизвестно'} (порог {bases_days} сут)",
            "infected": f"невылеченных объектов: {h.get('uncured') or 'есть'}", "license": "лицензия истекла (по статусу KSC)",
            "scan_old": f"полная проверка: {_fmt_dt(h['last_full_scan']) or 'не выполнялась'} (порог {scan_days} сут)", "reboot": "требуется перезагрузка (по статусу KSC)"}.get(key, "")


def anchor(h: dict) -> str:
    return f"h-{str(h['source_id'])[:8]}-{h['host_id']}"


def responsible_text(contacts: list[dict], limit: int = 3) -> str:
    """Компактно: «Иван Петров (начальник отдела), Мария Сидорова и ещё 2; рассылка: it@example.local»."""
    people = [c for c in contacts if c["role"] != "group" and c.get("enabled", True)]
    groups = [c["email"] for c in contacts if c["role"] == "group" and c.get("enabled", True)]
    names = [(c["name"] or c["email"]) + (f" ({c['position']})" if c.get("position") else "") for c in people if c["role"] == "responsible"]
    out = ", ".join(names[:limit]) + (f" и ещё {len(names) - limit}" if len(names) > limit else "")
    if groups:
        out += ("; " if out else "") + "рассылка: " + ", ".join(groups[:2]) + (f" и ещё {len(groups) - 2}" if len(groups) > 2 else "")
    return out


def build_zone_doc(parts: list[dict], zones: list[dict], *, params: dict, org: dict, generated_at: datetime, selection: list[str], unassigned: bool, base_url: str = "", zone_names: dict[str, str] | None = None) -> dict:
    """parts — результаты D.assemble по источникам (с ключом `source`), zones — сведения о выбранных зонах [{id,name,description,purpose,contacts}],
    selection — идентификаторы зон отчёта, unassigned — отчёт по компьютерам «Без ответственного»."""
    cats = set(params.get("categories") or DEFAULT_CATEGORIES)
    level = params.get("level") or "management"
    bases_days, scan_days = int(params.get("bases_days") or 3), int(params.get("scan_days") or 30)
    sel = set(selection)
    hosts_all, notes_src = [], []
    for part in parts:
        for h in part["hosts"]:
            if (unassigned and not h["zones"]) or (sel & set(h["zones"])):
                hosts_all.append(h)
        notes_src += part["notes"]
    # «Без связи» и «не в сети» считаются только по компьютерам выбранных зон (счётчики источника относятся ко всему источнику)
    mine = [x for part in parts for x in part.get("hidden_hosts", []) if (unassigned and not x["zones"]) or (sel & set(x["zones"]))]
    inactive = sum(1 for x in mine if x["reason"] == "inactive")
    total_zone = len(hosts_all) + len(mine)
    stat = D.stats(hosts_all, total_all=total_zone, hidden=inactive, sections=_sections(cats))
    multi_src = len({h["source_id"] for h in hosts_all} | {p["source_id"] for p in parts if p.get("source_id")}) > 1
    multi_zone = len(sel) + (1 if unassigned else 0) > 1
    zname = {z["id"]: z["name"] for z in zones} if zone_names is None else dict(zone_names)    # для рассылки — только свои зоны: чужие названия получателю не раскрываются
    other = lambda z: zname.get(z, "другая зона")  # noqa: E731
    probs = sorted((h for h in hosts_all if matches(h, cats)), key=D.rank_key)
    title_zone = "Без ответственного" if unassigned and not sel else zones[0]["name"] if len(zones) == 1 and not unassigned else f"{len(zones) + (1 if unassigned else 0)} зон"
    # ---- таблицы
    rows = []
    for h in probs:
        zl = [zname.get(z, "") for z in h["zones"] if z in zname]
        conflict = f"; спорный: подходит также зонам {', '.join(other(z) for z in h['zone_candidates'] if z not in sel)}" if h["zone_conflict"] and any(z not in sel for z in h["zone_candidates"]) else ""
        sev = SEV_BADGE[h["max_sev"]] + (" (потенциально)" if h["max_sev"] and h["max_sev_basis"] == "ext" else "")
        rows.append({"host_id": h["host_id"], "name": h["name"], "ip": h["ip"], "os": (h["os"] + (" " + h["os_version"] if h.get("os_version") else "")).strip(), "summary": h["summary"] + conflict,
                     "max_sev": sev, "last_connected": h["last_connected"], "online": ONLINE_RU[h.get("online")], "online_raw": h.get("online"), "active": "да" if h["active"] else "нет",
                     "zone": ", ".join(z for z in zl if z) or "Без ответственного", "source": h["source"], "anchor": anchor(h), "_sev": D.SEV_RANK[h["max_sev"]],
                     "ksc_total": h["ksc"]["total"], "ksc_critical": h["ksc"]["critical"], "prot": len(h["problems"]), "ext_total": h["ext"]["total"]})
    cols_hosts = [col("name", "Компьютер", "host"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("summary", "Проблемы"), col("max_sev", "Критичность", "sev"),
                  col("last_connected", "Последнее подключение к KSC (UTC)", "date"), col("online", "В сети сейчас")]
    if multi_zone or unassigned:
        cols_hosts.insert(1, col("zone", "Зона"))
    if multi_src:
        cols_hosts.insert(1, col("source", "Источник KSC"))
    v_rows, ext_rows, prot_rows, acc_rows, exc_rows = [], [], [], [], []
    for h in probs:
        for bucket, dest in (("current", v_rows), ("accepted", acc_rows), ("excluded", exc_rows)):
            for r in h["rows"]["ksc"][bucket]:
                dest.append(_vrow(h, r, "ksc"))
        for bucket, dest in (("current", ext_rows), ("accepted", acc_rows), ("excluded", exc_rows)):
            for r in h["rows"]["ext"][bucket]:
                dest.append(_vrow(h, r, "ext"))
        for k in h["problems"]:
            if "protection" in _sections(cats) and (k in cats or not (cats & set(PROTECTION_KEYS))):
                av = h["av"] or {}
                prot_rows.append({"name": h["name"], "ip": h["ip"], "problem": P.PROBLEMS[k][0], "detail": _detail(h, k, bases_days, scan_days), "av": av.get("product") or "нет", "av_build": av.get("build") or "",
                                  "rtp": h["rtp_label"] or av.get("state_label") or "—", "bases": av.get("bases"), "last_full_scan": h["last_full_scan"], "agent": h["agent_build"],
                                  "ksc_status": h["ksc_status"] or "—", "anchor": anchor(h), "source": h["source"]})
    if "inactive" in cats:
        for h in probs:
            if not h["active"]:
                prot_rows.append({"name": h["name"], "ip": h["ip"], "problem": "Давно не подключался к KSC", "detail": f"последнее подключение: {_fmt_dt(h['last_connected']) or 'никогда'}", "av": "", "av_build": "", "rtp": "",
                                  "bases": None, "last_full_scan": None, "agent": h["agent_build"], "ksc_status": h["ksc_status"] or "—", "anchor": anchor(h), "source": h["source"]})
    sev_order = {"Критическая": 3, "Высокая": 2, "Предупреждение": 1}
    v_rows.sort(key=lambda r: (-sev_order.get(r["severity_ru"], 0), r["vuln"], r["name"].lower()))
    ext_rows.sort(key=lambda r: (-int(bool(r["kev"])), -sev_order.get(r["severity_ru"], 0), r["vuln"], r["name"].lower()))
    exc_rows.sort(key=lambda r: (r["name"].lower(), r["vuln"]))
    acc_rows.sort(key=lambda r: (r["name"].lower(), r["vuln"]))
    # ---- показатели
    scope_word = "активных" if not params.get("include_inactive") else "всех"
    metrics = [metric("hosts", "Всего компьютеров в зоне", stat["total"], "включая давно не подключавшиеся"),
               metric("active", f"Активных за последние {params.get('_days')} сут" if params.get("_days") else "Активных за период", stat["active"], f"в сети сейчас: {stat['online']}; не в сети: {stat['offline']}; нет данных: {stat['online_unknown']}"),
               metric("critical", "С критическими уязвимостями (KSC)", stat["critical"], "подтверждены Kaspersky Security Center", "danger" if stat["critical"] else "ok"),
               metric("other", "С другими уязвимостями (KSC)", stat["other_vulns"], "высокие и предупреждения, без критических"),
               metric("protection", "С проблемами антивирусной защиты", stat["protection"], "", "danger" if stat["protection"] else "ok"),
               metric("ok", "Без выявленных проблем", stat["ok"], f"среди {scope_word} компьютеров"),
               metric("potential", "С потенциальными уязвимостями ПО", stat["potential"], "по внешним базам; не подтверждены KSC")]
    if stat["inactive"] and not params.get("include_inactive"):
        metrics.append(metric("inactive", "Без связи с KSC за период", stat["inactive"], "не входят в расчёт проблем; включите «Все устройства», чтобы увидеть"))
    if stat["accepted"] or stat["excluded"]:
        metrics.append(metric("triage", "Обработано специалистом", stat["excluded"] + stat["accepted"], f"ложных и неактуальных (исключены): {stat['excluded']}; принятых рисков: {stat['accepted']}"))
    severity = {"title": "Компьютеры по наиболее серьёзной проблеме (сумма = компьютеры в расчёте; категории не пересекаются)",
                "levels": [{"key": "critical", "label": "Критические уязвимости", "value": stat["state"]["critical"], "hint": ""}, {"key": "high", "label": "Другие уязвимости", "value": stat["state"]["vulns"], "hint": ""},
                           {"key": "warning", "label": "Только проблемы защиты", "value": stat["state"]["protection"], "hint": ""}, {"key": "potential", "label": "Только потенциальные", "value": stat["state"]["potential"], "hint": ""},
                           {"key": "ok", "label": "Без проблем", "value": stat["state"]["ok"], "hint": ""}]}
    conds = _conditions(params, zones, unassigned, cats, level, parts, hosts_all)
    meta = _meta(zones, unassigned, generated_at, parts, params, stat)
    top_v: dict[str, dict] = {}
    for r in v_rows:
        g = top_v.setdefault(r["vuln"], {"vuln": r["vuln"], "cve": r["cve"], "severity_ru": r["severity_ru"], "product": r["product"], "hosts": set(), "fix": r["fix"]})
        g["hosts"].add((r["source"], r["host_id"]))
    top_rows = sorted(({**g, "hosts": len(g["hosts"])} for g in top_v.values()), key=lambda g: (-sev_order.get(g["severity_ru"], 0), -g["hosts"], g["vuln"]))
    prot_sum = [{"problem": x["title"], "hosts": x["hosts"], "share": f"{round(x['hosts'] / max(stat['in_scope'], 1) * 100)}%"} for x in stat["problems"] if x["hosts"]]
    VC = [col("severity_ru", "Опасность", "sev"), col("vuln", "Уязвимость", "mono"), col("cve", "CVE / идентификаторы", "mono"), col("name", "Компьютер", "host"), col("ip", "IP-адрес", "mono"), col("product", "Программа"),
          col("installed_version", "Установленная версия", "mono"), col("fix", "Исправление"), col("detected", "Обнаружена (UTC)", "date"), col("triage", "Обработка"), col("source", "Источник")]
    EC = [col("severity_ru", "Опасность", "sev"), col("vuln", "Уязвимость", "mono"), col("title", "Название"), col("kev", "Эксплуатация (KEV)"), col("name", "Компьютер", "host"), col("ip", "IP-адрес", "mono"),
          col("product", "Программа"), col("installed_version", "Установленная версия", "mono"), col("status_ru", "Результат сопоставления"), col("basis", "Основание"), col("fix", "Исправление"),
          col("sources", "Источники сведений"), col("triage", "Обработка")]
    XC = [col("name", "Компьютер", "host"), col("ip", "IP-адрес", "mono"), col("severity_ru", "Опасность", "sev"), col("vuln", "Уязвимость", "mono"), col("product", "Программа"), col("installed_version", "Версия", "mono"),
          col("origin_ru", "Откуда сведения"), col("triage_status", "Решение"), col("triage_reason", "Основание"), col("triage_comment", "Комментарий"), col("triage_by", "Кто принял"), col("triage_at", "Когда (UTC)", "date"),
          col("triage_until", "Пересмотр до", "date"), col("triage_scope", "Область действия")]
    tables = [{"id": "problem_hosts", "title": "Проблемные компьютеры", "columns": cols_hosts, "rows": rows,
               "note": "Одна строка — один компьютер; сначала самые серьёзные проблемы. Критичность «потенциально» — по внешним базам, не подтверждена KSC."},
              {"id": "top_vulns", "title": "Самые распространённые уязвимости", "columns": [col("severity_ru", "Опасность", "sev"), col("vuln", "Уязвимость", "mono"), col("cve", "CVE", "mono"), col("product", "Программа"),
                                                                                     col("hosts", "Компьютеров", "num"), col("fix", "Исправление")], "rows": top_rows[:TOP_N], "note": f"Первые {TOP_N} из {len(top_rows)} по опасности и числу компьютеров."},
              {"id": "protection_summary", "title": "Проблемы защиты (сводка)", "columns": [col("problem", "Проблема"), col("hosts", "Компьютеров", "num"), col("share", "Доля")], "rows": prot_sum},
              {"id": "vulns", "title": "Уязвимости, подтверждённые KSC", "columns": VC, "rows": v_rows, "note": "Подтверждены Kaspersky Security Center; не включают ложные срабатывания и принятые риски (они ниже)."},
              {"id": "ext", "title": "Потенциальные уязвимости ПО (внешние базы)", "columns": EC, "rows": ext_rows,
               "note": "Предположения о применимости по NVD, CISA KEV, OSV и БДУ ФСТЭК и каталогу ПО — не подтверждены KSC. Статус и основание указаны в строке."},
              {"id": "protection", "title": "Проблемы защиты и связи", "columns": [col("name", "Компьютер", "host"), col("ip", "IP-адрес", "mono"), col("problem", "Проблема"), col("detail", "Подробности"), col("av", "Защитный продукт"),
                                                                              col("av_build", "Версия", "mono"), col("rtp", "Постоянная защита"), col("bases", "Базы (UTC)", "date"), col("last_full_scan", "Полная проверка (UTC)", "date"),
                                                                              col("agent", "Агент", "mono"), col("ksc_status", "Статус KSC"), col("source", "Источник")], "rows": prot_rows},
              {"id": "accepted", "title": "Принятые риски", "columns": XC, "rows": acc_rows, "note": "Подтверждённые проблемы, которые сознательно не устраняются до срока пересмотра. Не равны устранённым и не входят в показатели."},
              {"id": "excluded", "title": "Исключённые обнаружения (ложные срабатывания и неактуальные)", "columns": XC, "rows": exc_rows,
               "note": "Исходные сведения об этих обнаружениях сохранены; они не включены в показатели."}]
    layout = [{"id": "problem_hosts", "section": "summary"}, {"id": "top_vulns", "section": "summary", "inline": True}, {"id": "protection_summary", "section": "summary", "inline": True},
              {"id": "vulns", "section": "detail", "html": "technical"}, {"id": "ext", "section": "detail", "html": "technical", "optional": True}, {"id": "protection", "section": "detail", "html": "technical"},
              {"id": "accepted", "section": "detail", "html": "technical", "optional": True}, {"id": "excluded", "section": "detail", "html": "technical" if params.get("show_excluded") else "never", "optional": True}]
    notes = ["Подтверждённые KSC уязвимости, проблемы защиты и потенциальные совпадения по внешним базам считаются раздельно; один компьютер может входить в несколько категорий, поэтому категории не суммируются.",
             "Все показатели рассчитаны по реальным данным подключённых источников KSC на указанный момент; время — UTC. «Активен» — связывался с KSC за период; «в сети сейчас» — флаг KSC «видимо»: это разные состояния."]
    if stat["excluded"] or stat["accepted"]:
        notes.append(f"Исключено из показателей как ложные или неактуальные обнаружения: {stat['excluded']}; принятых рисков: {stat['accepted']} (учтены отдельно). Исходные сведения сохранены в базе KAV Checker.")
    notes += notes_src
    if unassigned:
        notes.append("Отчёт по компьютерам «Без ответственного»: они не подходят ни под одну зону. Добавьте сети или группы в нужную зону либо закрепите компьютер вручную.")
    if any(h["zone_conflict"] for h in hosts_all):
        notes.append(f"Есть компьютеры, подходящие сразу нескольким зонам (пересечение сетей): {sum(1 for h in hosts_all if h['zone_conflict'])}. Они показаны в каждой подходящей зоне с пометкой и в итогах организации считаются один раз.")
    det: list[dict] = []
    if level == "technical":
        for h, r in zip(probs, rows):
            det.append({"anchor": r["anchor"], "name": h["name"], "ip": h["ip"], "os": r["os"], "summary": h["summary"], "max_sev": r["max_sev"], "source": h["source"], "zone": r["zone"],
                        "last_connected": h["last_connected"], "online": r["online"], "ksc": [_vrow(h, x, "ksc") for x in h["rows"]["ksc"]["current"]], "ext": [_vrow(h, x, "ext") for x in h["rows"]["ext"]["current"]],
                        "protection": [{"problem": P.PROBLEMS[k][0], "detail": _detail(h, k, bases_days, scan_days)} for k in h["problems"]],
                        "accepted": [_vrow(h, x, o) for o in ("ksc", "ext") for x in h["rows"][o]["accepted"]], "excluded": [_vrow(h, x, o) for o in ("ksc", "ext") for x in h["rows"][o]["excluded"]] if params.get("show_excluded") else []})
    return {"title": f"Состояние безопасности: {title_zone}", "subtitle": f"Отчёт {LEVELS.get(level, '')}", "kind": "quick_zone", "level": level, "conditions": conds, "meta": meta, "metrics": metrics, "severity": severity,
            "notes": notes, "tables": tables, "layout": layout, "host_details": det, "org": org, "stats": {k: v for k, v in stat.items() if k != "problems"}, "base_url": base_url,
            "zone_names": [z["name"] for z in zones] + (["Без ответственного"] if unassigned else [])}


def _sections(cats: set[str]) -> set[str]:
    s = set()
    if cats & {"ksc_vulns", "ksc_critical"}:
        s.add("ksc")
    if "ext_vulns" in cats:
        s.add("ext")
    if cats & set(PROTECTION_KEYS):
        s.add("protection")
    return s or {"ksc", "protection", "ext"}


def _vrow(h: dict, r: dict, origin: str) -> dict:
    t = r.get("triage")
    out = {"host_id": h["host_id"], "source": h["source"], "name": h["name"], "ip": h["ip"], "severity_ru": r.get("severity_ru") or D.SEV_RU.get(r.get("severity", ""), ""), "origin": origin,
           "origin_ru": "подтверждено KSC" if origin == "ksc" else "внешние базы (потенциально)", "product": r.get("product") or r.get("program") or "", "installed_version": r.get("installed_version") or "",
           "anchor": anchor(h)}
    if origin == "ksc":
        out.update(vuln=r.get("kla_id") or "", cve=r.get("cve") or "", fix=r.get("fix") or "", detected=r.get("detected"))
    else:
        out.update(vuln=r.get("vuln_key") or "", cve=r.get("ids") or "", title=r.get("title") or "", kev="да" if r.get("kev") else "", status_ru=r.get("status_ru") or "", basis=r.get("basis") or "",
                   fix=r.get("fix") or "", sources=r.get("sources") or "", detected=None)
    if t:
        out.update(triage=t["status_ru"] + (f" — {t['recheck_reason']}" if t["recheck_reason"] else ""), triage_status=t["stored_status_ru"], triage_reason=t["reason_ru"], triage_comment=t["comment"], triage_by=t["by"],
                   triage_at=t["at"], triage_until=t["review_until"], triage_scope=t["scope_ru"])
    else:
        out.update(triage="Требует проверки", triage_status="", triage_reason="", triage_comment="", triage_by="", triage_at=None, triage_until=None, triage_scope="")
    return out


def _conditions(params: dict, zones: list[dict], unassigned: bool, cats: set[str], level: str, parts: list[dict], hosts: list[dict]) -> list[dict]:
    out = [{"label": "Зоны ответственности", "text": ", ".join([z["name"] for z in zones] + (["Без ответственного"] if unassigned else [])) or "все"},
           {"label": "Источники KSC", "text": ", ".join(p["source"] for p in parts if p.get("source")) or "—"},
           {"label": "Включены категории", "text": ", ".join(CATEGORIES[c] for c in CATEGORIES if c in cats)},
           {"label": "Давность связи", "text": "все устройства, включая давно не подключавшиеся" if params.get("include_inactive") else f"только устройства, связывавшиеся с KSC за последние {params.get('_days') or 30} сут"},
           {"label": "Состояние «в сети»", "text": "только устройства, которые KSC видит в сети сейчас" if params.get("online_only") else "не используется как фильтр"}]
    if params.get("severity"):
        out.append({"label": "Критичность уязвимостей", "text": {"critical": "только критические", "high": "высокие и критические"}.get(params["severity"], params["severity"])})
    out.append({"label": "Пороги защиты", "text": f"базы старше {params.get('bases_days') or 3} сут; полная проверка старше {params.get('scan_days') or 30} сут"})
    out.append({"label": "Исключённые обнаружения", "text": "перечислены в отчёте с обоснованиями" if params.get("show_excluded") else "не показываются; их число указано в показателях"})
    out.append({"label": "Подробность", "text": LEVELS.get(level, level)})
    return out


def _meta(zones: list[dict], unassigned: bool, generated_at: datetime, parts: list[dict], params: dict, stat: dict) -> list[dict]:
    out = []
    if len(zones) == 1 and not unassigned:
        z = zones[0]
        if z.get("description") or z.get("purpose"):
            out.append({"label": "Назначение", "text": z.get("purpose") or z.get("description")})
        r = responsible_text(z.get("contacts") or [])
        if r:
            out.append({"label": "Ответственные", "text": r})
    at = max((p.get("at") for p in parts if p.get("at")), default=generated_at)
    out.append({"label": "Актуальность сведений", "text": f"{_fmt_dt(at)} UTC"})
    out.append({"label": "Период проверки", "text": f"состояние на момент формирования; активность — {params.get('_days') or 30} сут"})
    if params.get("_recipients"):
        out.append({"label": "Адресаты", "text": params["_recipients"]})
    return out


def counts_for_mail(doc: dict) -> dict[str, Any]:
    s = doc["stats"]
    return {"total": s["total"], "active": s["active"], "critical": s["critical"], "other": s["other_vulns"], "protection": s["protection"], "ok": s["ok"], "potential": s["potential"],
            "problem_hosts": len(doc["tables"][0]["rows"]), "excluded": s["excluded"], "accepted": s["accepted"]}
