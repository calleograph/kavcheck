"""Порядок подачи таблиц во всех отчётах: сначала краткая сводка, затем компактный список компьютеров (программ, уязвимостей), затем подробности; методика и условия — отдельно.

Документ (`doc`, см. quick.py) хранит таблицы как есть, ничего не теряя; `doc["layout"]` лишь определяет, в каком порядке и в каком виде их показывают HTML и Excel.
Запись: {"id": имя блока, "table": id таблицы (по умолчанию id), "section": "summary" | "detail", "title": заголовок, "cols": [ключи столбцов] — краткий вид,
"where": ключ, значение которого должно быть истинным — только такие строки, "inline": True — в Excel на листе «Сводка», "html": "technical"/"never" — условие показа в HTML}.
Таблицы, не названные в layout, добавляются в конец раздела «Подробности», поэтому данные не пропадают."""
from __future__ import annotations

LAYOUTS: dict[str, list[dict]] = {
    "quick_vulns": [{"id": "hosts", "section": "summary", "title": "Затронутые компьютеры"}, {"id": "vulns", "section": "detail", "title": "Уязвимости"},
                    {"id": "programs", "section": "detail", "title": "Уязвимые программы и версии"}, {"id": "rows", "section": "detail", "title": "Обнаружения (подробно)"}],
    "quick_extvulns": [{"id": "hosts", "section": "summary", "title": "Потенциально затронутые компьютеры"}, {"id": "vulns", "section": "detail", "title": "Уязвимости"},
                       {"id": "programs", "section": "detail", "title": "Программы и версии"}, {"id": "rows", "section": "detail", "title": "Обнаружения (подробно)"}],
    "quick_eol": [{"id": "rows", "section": "summary", "title": "Программы и ОС с EOL"}, {"id": "devices", "section": "detail", "title": "Устройства"}],
    "quick_hosts": [{"id": "hosts_short", "table": "hosts", "section": "summary", "title": "Состояние компьютеров", "where": "",
                     "cols": ["name", "ip", "os", "online", "last_connected", "problems", "v_critical", "v_high", "v_warning", "software"]},
                    {"id": "hosts", "section": "detail", "title": "Компьютеры: все показатели"}, {"id": "vulns", "section": "detail"}, {"id": "software", "section": "detail"}],
    "quick_protection": [{"id": "problems", "section": "summary", "title": "Сколько компьютеров с какой проблемой"},
                         {"id": "hosts_short", "table": "hosts", "section": "summary", "title": "Проблемные компьютеры", "where": "problems_n",
                          "cols": ["name", "ip", "os", "problems", "online", "last_connected", "bases"]},
                         {"id": "hosts", "section": "detail", "title": "Компьютеры: компоненты защиты (подробно)"}],
    "quick_events": [{"id": "hosts", "section": "summary", "title": "Компьютеры с событиями"}, {"id": "threats", "section": "summary", "title": "Угрозы"}, {"id": "types", "section": "summary"},
                     {"id": "rows", "section": "detail", "title": "События (подробно)"}],
    "version_audit": [{"id": "programs", "section": "summary", "title": "Итог по программам"}, {"id": "hosts", "section": "summary", "title": "Компьютеры, требующие внимания"},
                      {"id": "rows", "section": "detail", "title": "Установки (подробно)"}, {"id": "found", "section": "detail"}],
}


def resolve(doc: dict) -> list[dict]:
    """Упорядоченные блоки документа: {entry, table, columns, rows, section, title}. Таблицы вне layout дописываются в «Подробности»."""
    layout = doc.get("layout") or LAYOUTS.get(doc.get("kind") or "", [])
    by_id = {t["id"]: t for t in doc["tables"]}
    out = []
    for e in layout:
        t = by_id.get(e.get("table") or e["id"])
        if t is None:
            continue
        cols = [c for k in e["cols"] for c in t["columns"] if c["key"] == k] if e.get("cols") else t["columns"]
        rows = [r for r in t["rows"] if r.get(e["where"])] if e.get("where") else t["rows"]
        out.append({"entry": e, "id": e["id"], "table": t, "columns": cols, "rows": rows, "section": e.get("section", "detail"), "title": e.get("title") or t["title"], "note": t.get("note", "")})
    named = {(e.get("table") or e["id"]) for e in layout}
    for t in doc["tables"]:
        if t["id"] not in named:
            out.append({"entry": {}, "id": t["id"], "table": t, "columns": t["columns"], "rows": t["rows"], "section": "detail", "title": t["title"], "note": t.get("note", "")})
    return out
