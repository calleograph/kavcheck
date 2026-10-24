"""Выгрузка документа быстрого отчёта (reports/quick.py): XLSX, самостоятельный HTML и CSV.

HTML — один файл без внешних ресурсов (стили внутри, шрифты системные), открывается без подключения к KAV Checker и печатается/сохраняется в PDF браузером.
XLSX — сводка, основная таблица и дополнительные листы; у таблиц фильтры, сортировка, закреплённый заголовок и ширина столбцов по содержимому."""
from __future__ import annotations

import html
from datetime import date, datetime
from pathlib import Path

from .export import _cell, _text, write_csv

HTML_ROW_LIMIT = 3000        # строк основной таблицы в HTML; полный список — в Excel
TONE_COLOR = {"danger": "#b3261e", "ok": "#1b6e46", "": "#14181d"}


def _fmt(v, kind: str) -> str:
    if v is None or v == "":
        return "—" if kind in ("date",) else ""
    if isinstance(v, datetime):
        return v.strftime("%d.%m.%Y %H:%M")
    if isinstance(v, date):
        return v.strftime("%d.%m.%Y")
    if isinstance(v, str) and kind == "date" and len(v) >= 16 and v[4:5] == "-":
        try:
            return datetime.fromisoformat(v).strftime("%d.%m.%Y %H:%M")
        except ValueError:
            return v
    return str(v)


def write_csv_main(path: Path, doc: dict) -> None:
    t = doc["tables"][0]
    write_csv(path, t["rows"], [(c["key"], c["title"]) for c in t["columns"]])


# ------------------------------------------------------------------------------------------------ XLSX
def _sheet_name(title: str, used: set[str]) -> str:
    base = "".join("_" if ch in '[]:*?/\\' else ch for ch in title)[:28] or "Лист"
    name, n = base, 2
    while name in used:
        name = f"{base[:25]} {n}"
        n += 1
    used.add(name)
    return name


def write_xlsx(path: Path, doc: dict) -> None:
    from openpyxl import Workbook  # noqa: PLC0415
    from openpyxl.styles import Alignment, Font, PatternFill  # noqa: PLC0415
    from openpyxl.utils import get_column_letter  # noqa: PLC0415

    wb = Workbook()
    bold, head_fill = Font(bold=True), PatternFill("solid", fgColor="E5E9ED")
    used: set[str] = set()
    s = wb.active
    s.title = _sheet_name("Сводка", used)
    s.append([doc["title"]])
    s["A1"].font = Font(bold=True, size=14)
    s.append([doc.get("subtitle") or ""])
    s.append(["Сформирован (UTC)", doc.get("generated_at") or ""])
    s.append(["Источник KSC", doc.get("source") or ""])
    s.append([])
    s.append(["Условия отчёта"])
    s[f"A{s.max_row}"].font = bold
    for c in doc["conditions"]:
        s.append([c["label"], c["text"]])
    s.append([])
    s.append(["Показатели"])
    s[f"A{s.max_row}"].font = bold
    for m in doc["metrics"]:
        s.append([m["label"], m["value"], m.get("hint") or ""])
    if doc.get("severity"):
        s.append([])
        s.append([doc["severity"]["title"]])
        s[f"A{s.max_row}"].font = bold
        for lv in doc["severity"]["levels"]:
            s.append([lv["label"], lv["value"], lv.get("hint") or ""])
    s.append([])
    s.append(["Достоверность и ограничения"])
    s[f"A{s.max_row}"].font = bold
    for n in doc["notes"]:
        s.append([n])
        s[f"A{s.max_row}"].alignment = Alignment(wrap_text=False)
    s.column_dimensions["A"].width, s.column_dimensions["B"].width, s.column_dimensions["C"].width = 62, 40, 70
    for t in doc["tables"]:
        ws = wb.create_sheet(_sheet_name(t["title"], used))
        cols = t["columns"]
        ws.append([c["title"] for c in cols])
        for c in ws[1]:
            c.font, c.fill = bold, head_fill
            c.alignment = Alignment(vertical="center", wrap_text=True)
        for r in t["rows"]:
            ws.append([_cell(r.get(c["key"])) for c in cols])
        for i, c in enumerate(cols, 1):
            letter = get_column_letter(i)
            width = max([len(c["title"])] + [len(_fmt(r.get(c["key"]), c["type"])) for r in t["rows"][:2000]]) + 2
            ws.column_dimensions[letter].width = min(60, max(10, width))
            if c["type"] == "date":
                for cell in ws[letter][1:]:
                    cell.number_format = "dd.mm.yyyy hh:mm"
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions if t["rows"] else f"A1:{get_column_letter(len(cols))}1"
    m = wb.create_sheet(_sheet_name("Параметры", used))
    m.append(["Параметр", "Значение"])
    for c in m[1]:
        c.font, c.fill = bold, head_fill
    for c in doc["conditions"]:
        m.append([c["label"], c["text"]])
    m.append(["Сформирован (UTC)", doc.get("generated_at") or ""])
    m.append(["Вид отчёта", doc.get("kind") or ""])
    m.column_dimensions["A"].width, m.column_dimensions["B"].width = 40, 110
    wb.save(path)


# ------------------------------------------------------------------------------------------------ HTML
CSS = """
:root { --ink:#14181d; --ink2:#39424c; --muted:#59636e; --line:#dee2e7; --bg:#f3f5f7; --card:#fff; --accent:#0f6a8b; --crit:#b3261e; --high:#b45309; --warn:#6b5f1a; --ok:#1b6e46; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.wrap { max-width: 1240px; margin: 0 auto; padding: 28px 24px 60px; }
header.doc { background: #121820; color: #e4e9ee; border-radius: 12px; padding: 22px 26px; }
header.doc h1 { margin: 0 0 4px; font-size: 24px; line-height: 1.25; color: #fff; letter-spacing: -.01em; }
header.doc p { margin: 0; color: #aab4be; }
header.doc .meta { margin-top: 12px; display: flex; flex-wrap: wrap; gap: 6px 22px; font-size: 13px; color: #c9d1d9; }
h2 { font-size: 17px; margin: 28px 0 10px; letter-spacing: -.005em; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; margin-top: 18px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; break-inside: avoid; }
.card .l { font-size: 12.5px; color: var(--muted); line-height: 1.35; }
.card .v { font-size: 30px; font-weight: 650; letter-spacing: -.02em; line-height: 1.15; margin-top: 4px; font-variant-numeric: tabular-nums; }
.card .h { font-size: 12px; color: var(--muted); margin-top: 4px; line-height: 1.35; }
.card.danger .v { color: var(--crit); } .card.ok .v { color: var(--ok); }
.panel { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 14px 18px; break-inside: avoid; }
dl.cond { display: grid; grid-template-columns: minmax(150px, 26%) 1fr; margin: 0; }
dl.cond dt, dl.cond dd { margin: 0; padding: 6px 0; border-top: 1px solid var(--line); }
dl.cond dt:first-of-type, dl.cond dt:first-of-type + dd { border-top: 0; }
dl.cond dt { color: var(--muted); padding-right: 14px; }
.bar { display: flex; height: 22px; border-radius: 5px; overflow: hidden; background: #e5e9ed; margin: 10px 0 8px; }
.bar > i { display: block; height: 100%; }
.legend { display: flex; flex-wrap: wrap; gap: 4px 20px; font-size: 13px; }
.legend b { font-variant-numeric: tabular-nums; }
.sw { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: -1px; }
ul.notes { margin: 0; padding-left: 20px; } ul.notes li { margin: 3px 0; color: var(--ink2); }
.tablewrap { background: var(--card); border: 1px solid var(--line); border-radius: 10px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: #eef1f4; color: var(--ink2); font-weight: 600; white-space: nowrap; position: sticky; top: 0; }
tbody tr:nth-child(even) td { background: #fafbfc; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
td.mono { font-family: ui-monospace, "Cascadia Mono", Menlo, Consolas, monospace; font-size: 12px; }
.nw { white-space: nowrap; }
.sev { display: inline-block; padding: 0 7px; border-radius: 4px; font-size: 12px; line-height: 19px; white-space: nowrap; }
.sev.s-crit { background: #fbe6e4; color: var(--crit); } .sev.s-high { background: #fdeccf; color: var(--high); } .sev.s-warn { background: #f1eed7; color: var(--warn); }
.tnote { color: var(--muted); font-size: 12.5px; margin: 0 0 6px; }
footer { margin-top: 30px; color: var(--muted); font-size: 12px; }
@page { size: A4 landscape; margin: 12mm; }
@media print {
  body { background: #fff; } .wrap { max-width: none; padding: 0; }
  header.doc { border: 1px solid #999; background: #fff; color: #000; } header.doc h1 { color: #000; } header.doc p, header.doc .meta { color: #333; }
  .tablewrap { overflow: visible; border-radius: 0; } th { position: static; } thead { display: table-header-group; } tr { break-inside: avoid; }
  h2 { break-after: avoid; } table { font-size: 10.5px; } th, td { padding: 3px 6px; }
}
@media (max-width: 700px) { .wrap { padding: 14px 10px 40px; } dl.cond { grid-template-columns: 1fr; } dl.cond dd { border-top: 0; padding-top: 0; } }
"""
SEV_CLASS = {"Критическая": "s-crit", "Высокая": "s-high", "Предупреждение": "s-warn"}
LEVEL_COLOR = {"critical": "#b3261e", "high": "#d97706", "warning": "#a39a3c"}


def _td(v, c: dict) -> str:
    kind = c["type"]
    text = html.escape(_fmt(v, kind))
    if kind == "sev" and text:
        return f'<td><span class="sev {SEV_CLASS.get(str(v), "")}">{text}</span></td>'
    if c["key"] == "url" and str(v).startswith("http"):
        return f'<td><a href="{html.escape(str(v), quote=True)}" rel="noopener noreferrer">{html.escape(str(v).rsplit("/", 1)[-1])}</a></td>'
    if kind == "mono" and ", " in text:        # CVE и версии списком: переносить между значениями, не внутри
        text = ", ".join(f'<span class="nw">{t}</span>' for t in text.split(", "))
    return f'<td class="{"num" if kind == "num" else "mono" if kind == "mono" else ""}">{text}</td>'


def render_html(doc: dict) -> str:
    esc = html.escape
    out = [f'<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{esc(doc["title"])}</title><style>{CSS}</style></head><body><div class="wrap">']
    out.append(f'<header class="doc"><h1>{esc(doc["title"])}</h1><p>{esc(doc.get("subtitle") or "")}</p><div class="meta"><span>Сформирован: {esc(_fmt(doc.get("generated_at"), "date").replace("T", " "))} UTC</span>'
               f'<span>Источник KSC: {esc(doc.get("source") or "")}</span><span>KAV Checker</span></div></header>')
    out.append('<div class="cards">' + "".join(f'<div class="card {esc(m.get("tone") or "")}"><div class="l">{esc(m["label"])}</div><div class="v">{esc(str(m["value"]))}</div>'
                                              + (f'<div class="h">{esc(m["hint"])}</div>' if m.get("hint") else "") + "</div>" for m in doc["metrics"]) + "</div>")
    if doc.get("severity"):
        lv = doc["severity"]["levels"]
        tot = sum(x["value"] for x in lv) or 1
        out.append(f'<h2>{esc(doc["severity"]["title"])}</h2><div class="panel"><div class="bar" role="img" aria-label="распределение по опасности">'
                   + "".join(f'<i style="width:{x["value"] / tot * 100:.2f}%;background:{LEVEL_COLOR[x["key"]]}"></i>' for x in lv if x["value"]) + '</div><div class="legend">'
                   + "".join(f'<span><i class="sw" style="background:{LEVEL_COLOR[x["key"]]}"></i>{esc(x["label"])}: <b>{x["value"]}</b> <span style="color:#59636e">({esc(x.get("hint") or "")})</span></span>' for x in lv) + "</div></div>")
    out.append('<h2>Условия отчёта</h2><div class="panel"><dl class="cond">' + "".join(f'<dt>{esc(c["label"])}</dt><dd>{esc(c["text"])}</dd>' for c in doc["conditions"]) + "</dl></div>")
    if doc["notes"]:
        out.append('<h2>Достоверность и ограничения</h2><div class="panel"><ul class="notes">' + "".join(f"<li>{esc(n)}</li>" for n in doc["notes"]) + "</ul></div>")
    for i, t in enumerate(doc["tables"]):
        rows = t["rows"]
        cut = i == 0 and len(rows) > HTML_ROW_LIMIT
        shown = rows[:HTML_ROW_LIMIT] if cut else rows
        out.append(f'<h2>{esc(t["title"])} <span style="color:#59636e;font-weight:400">· {len(rows)}</span></h2>')
        if t.get("note"):
            out.append(f'<p class="tnote">{esc(t["note"])}</p>')
        if cut:
            out.append(f'<p class="tnote">Показаны первые {HTML_ROW_LIMIT} строк из {len(rows)}; полный список — в файле Excel.</p>')
        if not rows:
            out.append('<div class="panel">Нет данных.</div>')
            continue
        out.append('<div class="tablewrap"><table><thead><tr>' + "".join(f'<th class="{"num" if c["type"] == "num" else ""}">{esc(c["title"])}</th>' for c in t["columns"]) + "</tr></thead><tbody>")
        out.append("".join("<tr>" + "".join(_td(r.get(c["key"]), c) for c in t["columns"]) + "</tr>" for r in shown))
        out.append("</tbody></table></div>")
    out.append(f'<footer>KAV Checker · отчёт сформирован {esc(_fmt(doc.get("generated_at"), "date").replace("T", " "))} UTC · данные Kaspersky Security Center «{esc(doc.get("source") or "")}». Файл самодостаточен: открывается без подключения к приложению, для PDF используйте печать браузера.</footer>')
    out.append("</div></body></html>")
    return "".join(out)


def write_html(path: Path, doc: dict) -> None:
    path.write_text(render_html(doc), encoding="utf-8")


_ = _text
