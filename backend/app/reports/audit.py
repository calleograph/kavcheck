"""Проверка версий программ (вид отчёта version_audit): одна или несколько программ × условие версии × один или несколько источников KSC.

Программа задаётся ключом каталога (обычный режим), шаблоном названия SQL LIKE / регулярным выражением или правилом группировки (дополнительные настройки).
Каждая запись реестра сравнивается по схеме своего продукта (пакеты Linux — dpkg, программы Windows — numeric, нестандартная нумерация приводится),
поэтому «ниже 130» для Google Chrome и «ниже 7.4.33-1+deb11u5» для пакета PHP означают ровно то, что написано.
Результат — соответствие заданному условию, а не подтверждённая уязвимость: подтверждённые KSC уязвимости — отдельный раздел."""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Callable

from ..ksc import catalog as C
from ..ksc import hosts as H
from ..ksc import queries as q
from ..ksc import versions
from ..ksc.driver import KscError, Session
from ..ksc.grouping import Rule
from ..search import matcher
from .builder import Cancelled, _hosts, _installs

Progress = Callable[[str], None]
CancelCheck = Callable[[], bool]

AUDIT_COLUMNS = [("source", "Источник KSC"), ("program", "Программа"), ("product", "Продукт каталога"), ("app_version", "Установленная версия"), ("target_version", "Целевая версия"),
                 ("name", "Компьютер"), ("ip", "IP-адрес"), ("os", "ОС"), ("last_connected", "Последнее подключение (UTC)"), ("days_since_connection", "Суток без связи"),
                 ("condition", "Условие проверки"), ("app_name", "Запись реестра KSC"), ("compared_version", "Сравниваемая версия"), ("branch", "Ветка"),
                 ("publisher", "Производитель"), ("fqdn", "FQDN"), ("group", "Группа администрирования"), ("linux_release", "Дистрибутив Linux"), ("activity", "Активность"),
                 ("install_date", "Дата установки"), ("host_id", "HostId"), ("product_id", "ProductId")]


def target_text(item: dict) -> str:
    """Требуемая версия: указанная пользователем либо выведенная из условия («ниже 130» → «130 или выше»)."""
    t = (item.get("target_version") or "").strip()
    if t:
        return t
    op, v = item.get("op") or "lt", (item.get("value") or "").strip()
    if op == "lt" and v:
        return f"{v} или выше"
    if op == "le" and v:
        return f"выше {v}"
    return ""


def item_title(item: dict) -> str:
    if item.get("kind") == "pattern":
        return item.get("product_name") or item.get("name_like") or item.get("name_regex") or "шаблон"
    if item.get("kind") == "rule":
        return item.get("product_name") or item.get("rule") or "правило"
    d = C.BUILTIN_BY_KEY.get(item.get("product_key") or "")
    return item.get("product_name") or (d.name if d else None) or item.get("product_key") or "программа"


_COND_FIELDS = ("op", "value", "min", "max", "exclude", "branches", "platform", "name_like", "name_regex", "publisher_like", "rule", "product_key", "product_keys", "kind")


def check_conditions(original: list[dict], executed: list[dict]) -> None:
    """Условие, которое выполняется, должно совпадать с заданным пользователем: оператор, границы, исключения, ветки. Иначе отчёт не формируется
    (пустой отчёт по изменённому условию был бы ошибочным решением об обновлении)."""
    if len(original) != len(executed):
        raise KscError("params", "Расхождение условий проверки: число пунктов изменилось. Отчёт не сформирован.")
    for n, (a, b) in enumerate(zip(original, executed), 1):
        for f in _COND_FIELDS:
            va, vb = a.get(f) or ([] if f in ("exclude", "branches", "product_keys") else None), b.get(f) or ([] if f in ("exclude", "branches", "product_keys") else None)
            if va != vb:
                raise KscError("params", f"Расхождение условий проверки в пункте {n}: «{item_condition(a)}» задано, а выполнялось бы «{item_condition(b)}» (поле {f}). Отчёт не сформирован.")


def item_condition(item: dict) -> str:
    text = versions.condition_text(item.get("op") or "lt", item.get("value"), item.get("min"), item.get("max"))
    if item.get("branches"):
        text += f"; ветки {', '.join(b or 'не определена' for b in item['branches'])}"
    if item.get("exclude"):
        text += f"; кроме {', '.join(item['exclude'])}"
    return text


def _record_def(item: dict, name: str, mask: int, rule: Rule | None) -> C.ProductDef | None:
    # пункт из нескольких продуктов (семейство, компоненты): каждая запись — по своему описанию и схеме версий
    if item.get("kind") == "product" and not item.get("product_keys"):
        d = C.BUILTIN_BY_KEY.get(item.get("product_key") or "")
        if d:
            return d
    return C.classify(name, mask).builtin


def record_matches(item: dict, rec: dict, rule: Rule | None) -> tuple[bool, str, str]:
    """(подходит, сравниваемая версия, ветка) для записи реестра по условию пункта проверки."""
    name, raw, mask = rec.get("name") or "", rec.get("version") or "", int(rec.get("platform_mask") or 0)
    plat = item.get("platform")
    if plat in ("windows", "linux") and not mask & (1 if plat == "windows" else 2):
        return False, "", ""
    if rule is not None:
        scheme = versions.scheme_for(mask)
        cv = rule.compared_version(name, raw)
        br = rule.branch(name, raw)
        kind = None
        ver_for = cv
    else:
        d = _record_def(item, name, mask, rule)
        scheme = (d.scheme if d and d.scheme else None) or versions.scheme_for(mask)
        kind = d.transform if d else None
        cv = C.compared_version(d, name, raw, scheme)
        br = C.branch(d, name, raw, scheme)
        ver_for = cv if d and d.branch == "phpname" else C.record_version(d, name, raw)
    if item.get("branches") and (br or "") not in item["branches"]:
        return False, cv, br
    if versions.excluded(ver_for, item.get("exclude"), scheme=scheme, kind=kind):
        return False, cv, br
    ok = versions.matches(ver_for, item.get("op") or "lt", item.get("value"), item.get("min"), item.get("max"), scheme=scheme, kind=kind)
    return ok, cv, br


def _candidates(s: Session, item: dict, rule: Rule | None, cancelled: CancelCheck) -> list[dict]:
    if item.get("kind") == "product":
        ids = [int(x) for x in item.get("product_ids") or []]
        out: list[dict] = []
        for k in range(0, len(ids), 500):
            if cancelled():
                raise Cancelled()
            out += s.query(q.PRODUCTS_BY_IDS.format(ids=q.ids_list(ids[k:k + 500])), max_rows=1000)
        return out
    like = rule.name_like if rule else (item.get("name_like") or "")
    if not like and item.get("name_regex"):
        like = "%"
    if not like:
        raise KscError("params", f"«{item_title(item)}»: не задан шаблон названия")
    extra, p = " AND EXISTS (SELECT 1 FROM dbo.hst_inventory_hstprds i WHERE i.nProduct = p.nId AND i.bDeleted = 0)", {"like": like}
    if item.get("publisher_like"):
        extra += " AND p.wstrPublisher LIKE %(pub)s"
        p["pub"] = item["publisher_like"]
    out, offset = [], 0
    while True:
        if cancelled():
            raise Cancelled()
        rows = s.query(q.PRODUCTS_BY_LIKE.format(extra=extra), {**p, "offset": offset, "limit": 2000}, max_rows=2000)
        out += rows
        if len(rows) < 2000:
            break
        offset += 2000
        if offset >= 50_000:
            raise KscError("too_many_rows", f"«{item_title(item)}»: под шаблон подпадает больше 50 000 записей — уточните шаблон")
    rx = re.compile(item["name_regex"], re.I) if item.get("name_regex") else None
    if rule:
        out = [r for r in out if rule.matches(r.get("name") or "")]
    if rx:
        out = [r for r in out if rx.search(r.get("name") or "")]
    return out


def build_source(s: Session, *, source_name: str, items: list[dict], rules: dict[str, Rule], active_days: int | None, include_inactive: bool,
                 group_contains: str = "", exclude_slaves: bool = True, max_rows: int, progress: Progress, cancelled: CancelCheck,
                 now: datetime | None = None, online_only: bool = False) -> tuple[list[dict], dict]:
    """Строки и сводка по одному источнику."""
    now = now or datetime.now(timezone.utc)
    matched: dict[int, list[tuple[int, str, str]]] = {}       # product_id → [(номер пункта, сравниваемая версия, ветка)]
    records: dict[int, dict] = {}
    per_item: list[dict] = []
    for n, item in enumerate(items):
        rule = rules.get(item.get("rule") or "") if item.get("kind") == "rule" else None
        if item.get("kind") == "rule" and rule is None:
            raise KscError("params", f"Правило группировки «{item.get('rule')}» не найдено или выключено")
        cands = _candidates(s, item, rule, cancelled)
        hit = 0
        found: dict[tuple[str, str], dict] = {}      # какие пакеты и версии найдены и подходят ли под условие
        for r in cands:
            ok, cv, br = record_matches(item, r, rule)
            f = found.setdefault((r.get("name") or "", r.get("version") or ""), {"name": r.get("name") or "", "version": r.get("version") or "", "compared_version": cv,
                                                                                "publisher": C.clean_publisher(r.get("publisher") or ""), "matched": False,
                                                                                "product": (item.get("pid_product") or {}).get(int(r["product_id"]), "")})
            if ok:
                f["matched"] = True
                pid = int(r["product_id"])
                records[pid] = r
                matched.setdefault(pid, []).append((n, cv, br))
                hit += 1
        per_item.append({"records_checked": len(cands), "records_matched": hit,
                         "found": sorted(found.values(), key=lambda x: (not x["matched"], x["name"].lower(), versions.sort_key(x["compared_version"] or "0")))[:300]})
        progress(f"{source_name}: «{item_title(item)}» — подходящих записей реестра {hit} из {len(cands)}")
    installs = _installs(s, list(matched), max_rows, progress, cancelled) if matched else []
    host_ids = sorted({int(i["host_id"]) for i in installs})
    hosts = _hosts(s, host_ids, cancelled)
    groups = {int(r["group_id"]): {"name": r["name"], "parent_id": r["parent_id"]} for r in s.query(q.GROUPS_ALL, max_rows=100_000)} if host_ids else {}
    releases = H.releases_sync(s, host_ids) if host_ids else {}
    gc = matcher(group_contains)
    rows: list[dict] = []
    hidden: set[int] = set()
    not_computers = 0
    for i in installs:
        h = hosts.get(int(i["host_id"]))
        if h is None or (exclude_slaves and h.get("is_slave")):
            not_computers += 1
            continue
        hr = H.host_row(h, groups, now, releases.get(int(h["host_id"])))
        if gc and not gc(hr["group"]):
            continue
        if not include_inactive and active_days is not None and (hr["days_since_connection"] is None or hr["days_since_connection"] > active_days):
            hidden.add(hr["host_id"])
            continue
        rec = records[int(i["product_id"])]
        for n, cv, br in matched[int(i["product_id"])]:
            item = items[n]
            rows.append({"source": source_name, "program": item_title(item), "product": (item.get("pid_product") or {}).get(int(rec["product_id"]), ""), "item": n,
                         "app_name": rec.get("name") or "", "app_version": rec.get("version") or "",
                         "compared_version": cv, "branch": br, "condition": item_condition(item), "target_version": target_text(item),
                         "publisher": C.clean_publisher(rec.get("publisher") or ""), "install_date": i.get("install_date"),
                         **{k: hr[k] for k in ("name", "fqdn", "ip", "os", "linux_release", "group", "last_connected", "days_since_connection", "activity", "host_id", "online")},
                         "product_id": int(rec["product_id"])})
    rows.sort(key=lambda r: (r["program"].lower(), r["name"].lower(), versions.sort_key(r["compared_version"] or "0")))
    offline_hidden = 0
    unavailable = False
    if online_only:
        # «в сети» — флаг KSC «видимо», не давность подключения; если KSC не передаёт флаг ни для одного компьютера, фильтр не применяется и это отмечено
        if any(r.get("online") is not None for r in rows):
            keep = [r for r in rows if r.get("online") is True]
            offline_hidden = len({r["host_id"] for r in rows}) - len({r["host_id"] for r in keep})
            rows = keep
        else:
            unavailable = bool(rows)
    for n, item in enumerate(items):
        rs = [r for r in rows if r["item"] == n]
        per_item[n].update({"program": item_title(item), "condition": item_condition(item), "target_version": target_text(item), "hosts": len({r["host_id"] for r in rs}),
                            "installs": len(rs), "versions": [[v, c] for v, c in Counter(r["compared_version"] for r in rs).most_common(50)]})
    summary = {"source": source_name, "rows": len(rows), "hosts": len({r["host_id"] for r in rows}), "hidden_inactive_hosts": len(hidden),
               "excluded_not_computers": not_computers, "items": per_item, "fetched_at": now.isoformat(timespec="seconds"), "hidden_offline_hosts": offline_hidden,
               "online_unavailable": unavailable}
    return rows, summary


def explain_empty(found: list[dict], condition: str) -> str:
    """Почему результат пуст: что нашлось в KSC и почему не подходит (чтобы пустой отчёт не выглядел как ошибка условия)."""
    if not found:
        return "В KSC не найдено ни одной записи реестра этой программы на учтённых компьютерах (проверьте источник, платформу и каталог)."
    vs = sorted({f["compared_version"] for f in found if f.get("compared_version")}, key=versions.sort_key)
    span = f"от {vs[0]} до {vs[-1]}" if len(vs) > 1 else (vs[0] if vs else "—")
    return f"Условию «{condition}» не соответствует ни одна установка. Найдено записей реестра: {len(found)}, версии {span}; подходящих нет."


def merge_summaries(per_source: list[dict], items: list[dict], *, active_days: int | None, include_inactive: bool, rows: list[dict], online_only: bool = False) -> dict:
    """Общий итог: уникальные компьютеры считаются в пределах источника (источник — часть идентификации записи)."""
    progs = []
    for n, item in enumerate(items):
        rs = [r for r in rows if r["item"] == n]
        found: dict[tuple[str, str], dict] = {}
        for s in per_source:
            for f in s["items"][n].get("found", []):
                cur = found.setdefault((f["name"], f["version"]), dict(f))
                cur["matched"] = cur["matched"] or f["matched"]
        progs.append({"program": item_title(item), "condition": item_condition(item), "target_version": target_text(item), "hosts": len({(r["source"], r["host_id"]) for r in rs}),
                      "installs": len(rs), "by_source": [{"source": s["source"], "hosts": s["items"][n]["hosts"]} for s in per_source],
                      "found": sorted(found.values(), key=lambda x: (not x["matched"], x["name"].lower()))[:300]})
        if not progs[-1]["hosts"]:
            progs[-1]["explain"] = explain_empty(list(found.values()), item_condition(item))
    return {"rows": len(rows), "hosts": len({(r["source"], r["host_id"]) for r in rows}), "sources": per_source, "programs": progs,
            "hidden_inactive_hosts": sum(s["hidden_inactive_hosts"] for s in per_source), "active_days": active_days, "include_inactive": include_inactive,
            "hidden_offline_hosts": sum(s.get("hidden_offline_hosts", 0) for s in per_source), "online_unavailable": any(s.get("online_unavailable") for s in per_source),
            "online_only": online_only,
            "fetched_at": max((s["fetched_at"] for s in per_source), default=datetime.now(timezone.utc).isoformat(timespec="seconds"))}
