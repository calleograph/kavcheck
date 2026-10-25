"""Выгрузка документа отчёта (reports/quick.py, zones/report.py): XLSX, самостоятельный HTML и CSV.

Порядок подачи везде один (reports/layout.py): шапка организации и условия → показатели → компактная таблица (компьютеры, программы, уязвимости) → подробности → методика и ограничения.
HTML — один файл без внешних ресурсов (стили внутри, шрифты системные), открывается без подключения к KAV Checker, печатается и сохраняется в PDF браузером (шапки таблиц повторяются, строки не рвутся).
XLSX — «Сводка» первым листом, затем компактные таблицы, подробности и в конце «Параметры отчёта»; у таблиц фильтры, закреплённый заголовок и ширина столбцов по содержимому."""
from __future__ import annotations

import html
from datetime import date, datetime
from pathlib import Path

from . import layout as L
from .export import _cell, _text, write_csv

HTML_ROW_LIMIT = 3000        # строк одной таблицы в HTML; полный список — в Excel
HOST_DETAIL_LIMIT = 300      # компьютеров с подробной карточкой в HTML (остальные — в Excel)
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


def org_lines(doc: dict) -> dict:
    """Сведения организации для шапки и подвала; пустые поля не попадают (без пустых заголовков)."""
    o = doc.get("org") or {}
    name = (o.get("short_name") or o.get("full_name") or "").strip()
    return {"name": name, "full": (o.get("full_name") or "").strip() if o.get("short_name") else "", "unit": (o.get("unit") or "").strip(), "classification": (o.get("classification") or "").strip(),
            "email": (o.get("contact_email") or "").strip(), "contacts": (o.get("contacts") or "").strip(), "footnote": (o.get("footnote") or "").strip(), "signature": (o.get("signature") or "").strip(),
            "logo": o.get("logo") if o.get("show_logo", True) else ""}


# ------------------------------------------------------------------------------------------------ XLSX
XLSX_NAMES = {"problem_hosts": "Проблемные компьютеры", "vulns": "Уязвимости", "protection": "Проблемы защиты", "ext": "Потенциальные (внешние)", "accepted": "Принятые риски", "excluded": "Исключённые"}


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
    org = org_lines(doc)
    blocks = L.resolve(doc)
    s = wb.active
    s.title = _sheet_name("Сводка", used)

    def put(row: list, *, font=None) -> None:
        s.append([_cell(x) for x in row])
        if font:
            for c in s[s.max_row]:
                c.font = font

    if org["name"]:
        put([org["name"]], font=Font(bold=True, size=12))
        for x in (org["full"], org["unit"], org["classification"]):
            if x:
                put([x])
    put([doc["title"]], font=Font(bold=True, size=14))
    if doc.get("subtitle"):
        put([doc["subtitle"]])
    put(["Сформирован (UTC)", doc.get("generated_at") or ""])
    put(["Источник KSC", doc.get("source") or ""])
    for m in doc.get("meta") or []:
        put([m["label"], m["text"]])
    s.append([])
    put(["Показатели"], font=bold)
    for m in doc["metrics"]:
        put([m["label"], m["value"], m.get("hint") or ""])
    if doc.get("severity"):
        s.append([])
        put([doc["severity"]["title"]], font=bold)
        for lv in doc["severity"]["levels"]:
            put([lv["label"], lv["value"], lv.get("hint") or ""])
    for b in blocks:
        if b["entry"].get("inline") and b["rows"]:
            s.append([])
            put([b["title"]], font=bold)
            put([c["title"] for c in b["columns"]], font=bold)
            for r in b["rows"]:
                put([r.get(c["key"]) for c in b["columns"]])
    s.column_dimensions["A"].width, s.column_dimensions["B"].width, s.column_dimensions["C"].width = 62, 40, 70
    for b in blocks:
        if b["entry"].get("inline") or (b["entry"].get("optional") and not b["rows"]):
            continue
        derived = bool(b["entry"].get("cols") or b["entry"].get("where"))       # краткий вид таблицы получает название блока, полный — прежнее название таблицы
        ws = wb.create_sheet(_sheet_name(XLSX_NAMES.get(b["id"], b["title"]) if doc.get("kind") == "quick_zone" else b["title"] if derived else b["table"]["title"], used))
        cols, rows = b["columns"], b["rows"]
        ws.append([c["title"] for c in cols])
        for c in ws[1]:
            c.font, c.fill = bold, head_fill
            c.alignment = Alignment(vertical="center", wrap_text=True)
        for r in rows:
            ws.append([_cell(r.get(c["key"])) for c in cols])
        for i, c in enumerate(cols, 1):
            letter = get_column_letter(i)
            width = max([len(c["title"])] + [len(_fmt(r.get(c["key"]), c["type"])) for r in rows[:2000]]) + 2
            ws.column_dimensions[letter].width = min(60, max(10, width))
            if c["type"] == "date":
                for cell in ws[letter][1:]:
                    cell.number_format = "dd.mm.yyyy hh:mm"
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions if rows else f"A1:{get_column_letter(len(cols))}1"
        ws.page_setup.orientation = "landscape"                      # печать: ширина листа по ширине страницы, заголовок на каждой странице
        ws.page_setup.fitToWidth, ws.page_setup.fitToHeight = 1, 0
        ws.sheet_properties.pageSetUpPr.fitToPage = True
        ws.print_title_rows = "1:1"
    m = wb.create_sheet(_sheet_name("Параметры отчёта", used))
    m.append(["Параметр", "Значение"])
    for c in m[1]:
        c.font, c.fill = bold, head_fill
    for c in doc["conditions"]:
        m.append([_cell(c["label"]), _cell(c["text"])])
    m.append(["Сформирован (UTC)", doc.get("generated_at") or ""])
    m.append(["Вид отчёта", doc.get("kind") or ""])
    if doc.get("notes"):
        m.append([])
        m.append(["Методика, источники и ограничения"])
        m[f"A{m.max_row}"].font = bold
        for n in doc["notes"]:
            m.append([_cell(n)])
    for x in (org["footnote"], org["signature"]):
        if x:
            m.append([])
            m.append([_cell(x)])
    m.column_dimensions["A"].width, m.column_dimensions["B"].width = 40, 110
    wb.save(path)


# ------------------------------------------------------------------------------------------------ HTML
CSS = """
:root { --ink:#14181d; --ink2:#39424c; --muted:#59636e; --line:#dce1e6; --bg:#f3f5f7; --card:#fff; --accent:#0f6a8b; --crit:#b3261e; --high:#b45309; --warn:#6b5f1a; --ok:#1b6e46; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 13.5px/1.42 system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.wrap { max-width: 1240px; margin: 0 auto; padding: 18px 20px 40px; }
header.doc { background: #fff; border: 1px solid var(--line); border-top: 4px solid var(--accent); border-radius: 8px; padding: 12px 18px 14px; }
.org { display: flex; align-items: center; gap: 12px; padding-bottom: 8px; margin-bottom: 8px; border-bottom: 1px solid var(--line); }
.org img { max-height: 38px; max-width: 150px; display: block; }
.org .on { font-weight: 650; font-size: 14px; } .org .ou { color: var(--muted); font-size: 12.5px; }
.org .cls { margin-left: auto; font-size: 12px; font-weight: 600; letter-spacing: .02em; color: var(--ink2); border: 1px solid var(--ink2); padding: 1px 8px; border-radius: 3px; white-space: nowrap; }
header.doc h1 { margin: 0; font-size: 21px; line-height: 1.25; letter-spacing: -.01em; }
header.doc p.sub { margin: 1px 0 0; color: var(--muted); }
dl.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2px 24px; margin: 8px 0 0; font-size: 12.5px; }
dl.meta div { display: flex; gap: 8px; } dl.meta dt { color: var(--muted); flex: none; } dl.meta dd { margin: 0; font-weight: 500; }
nav.toc { margin: 8px 0 0; font-size: 12.5px; display: flex; gap: 14px; flex-wrap: wrap; } nav.toc a { color: var(--accent); text-decoration: none; } nav.toc a:hover { text-decoration: underline; }
h2 { font-size: 15px; margin: 18px 0 7px; letter-spacing: -.005em; break-after: avoid; } h2 .cnt { color: var(--muted); font-weight: 400; }
h3 { font-size: 13.5px; margin: 0; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 8px; margin-top: 12px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 8px 12px; break-inside: avoid; }
.card .l { font-size: 12px; color: var(--muted); line-height: 1.3; }
.card .v { font-size: 24px; font-weight: 650; letter-spacing: -.02em; line-height: 1.15; margin-top: 2px; font-variant-numeric: tabular-nums; }
.card .h { font-size: 11.5px; color: var(--muted); margin-top: 2px; line-height: 1.3; }
.card.danger .v { color: var(--crit); } .card.ok .v { color: var(--ok); }
.panel { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 8px 14px; break-inside: avoid; }
dl.cond { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); gap: 0 28px; margin: 0; }
dl.cond div { display: grid; grid-template-columns: minmax(120px, 36%) 1fr; padding: 3px 0; border-top: 1px solid var(--line); }
dl.cond dt { color: var(--muted); padding-right: 10px; } dl.cond dd { margin: 0; }
.bar { display: flex; height: 16px; border-radius: 4px; overflow: hidden; background: #e5e9ed; margin: 6px 0 6px; }
.bar > i { display: block; height: 100%; }
.legend { display: flex; flex-wrap: wrap; gap: 2px 18px; font-size: 12.5px; }
.legend b { font-variant-numeric: tabular-nums; }
.sw { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 5px; vertical-align: -1px; }
ul.notes { margin: 0; padding-left: 18px; } ul.notes li { margin: 2px 0; color: var(--ink2); }
.tablewrap { background: var(--card); border: 1px solid var(--line); border-radius: 8px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: #eef1f4; color: var(--ink2); font-weight: 600; white-space: nowrap; position: sticky; top: 0; }
tbody tr:nth-child(even) td { background: #fafbfc; }
tbody tr:last-child td { border-bottom: 0; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
td.mono { font-family: ui-monospace, "Cascadia Mono", Menlo, Consolas, monospace; font-size: 12px; }
td a { color: var(--accent); text-decoration: none; font-weight: 550; } td a:hover { text-decoration: underline; }
.nw { white-space: nowrap; }
.sev { display: inline-block; padding: 0 7px; border-radius: 4px; font-size: 12px; line-height: 18px; white-space: nowrap; }
.sev.s-crit { background: #fbe6e4; color: var(--crit); } .sev.s-high { background: #fdeccf; color: var(--high); } .sev.s-warn { background: #f1eed7; color: var(--warn); } .sev.s-pot { background: #e4ebf3; color: #2f4b6e; }
.tnote { color: var(--muted); font-size: 12px; margin: 0 0 4px; }
.cutwarn { margin: 10px 0 0; padding: 8px 12px; border: 1px solid #e3c36b; background: #fbf3d9; color: #5c4300; border-radius: 8px; }
section.host { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 8px 12px 10px; margin: 0 0 8px; }
section.host header { display: flex; flex-wrap: wrap; gap: 2px 14px; align-items: baseline; margin-bottom: 4px; } section.host header .m { color: var(--muted); font-size: 12px; }
section.host h4 { margin: 8px 0 3px; font-size: 12px; color: var(--ink2); text-transform: none; }
section.host .back { font-size: 12px; float: right; } section.host .back a { color: var(--accent); text-decoration: none; }
section.host .tablewrap { border-radius: 6px; }
footer { margin-top: 20px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); padding-top: 8px; }
footer p { margin: 2px 0; }
@page { size: A4 landscape; margin: 10mm 10mm 12mm; }
@media print {
  body { background: #fff; font-size: 11px; } .wrap { max-width: none; padding: 0; } nav.toc, .back { display: none; }
  header.doc, .card, .panel, .tablewrap, section.host { border-color: #b5bcc4; } header.doc { border-top-width: 3px; }
  .tablewrap { overflow: visible; border-radius: 0; } th { position: static; } thead { display: table-header-group; } tr { break-inside: avoid; }
  h2 { margin-top: 12px; } table { font-size: 10px; } th, td { padding: 2px 5px; } .cards { grid-template-columns: repeat(5, 1fr); gap: 6px; margin-top: 8px; } .card .v { font-size: 18px; }
  td a { color: inherit; font-weight: 500; } section.host { margin-bottom: 6px; padding: 5px 8px 6px; }
}
@media (max-width: 700px) { .wrap { padding: 10px 8px 30px; } dl.cond div { grid-template-columns: 1fr; } .org { flex-wrap: wrap; } .org .cls { margin-left: 0; } }
"""
NW_KEYS = {"online", "active", "last_connected", "installed_version", "detected"}
SEV_CLASS = {"Критическая": "s-crit", "Высокая": "s-high", "Предупреждение": "s-warn"}
LEVEL_COLOR = {"critical": "#b3261e", "high": "#d97706", "warning": "#a39a3c", "potential": "#5b7fa6", "ok": "#1b6e46"}


def _sev_class(v: str) -> str:
    v = str(v)
    if v.endswith("(потенциально)"):
        return "s-pot"
    return SEV_CLASS.get(v, "")


def _td(v, c: dict, anchors: set[str] | None = None, row: dict | None = None) -> str:
    kind = c["type"]
    text = html.escape(_fmt(v, kind))
    if kind == "sev" and text:
        return f'<td><span class="sev {_sev_class(v)}">{text}</span></td>'
    if kind == "host" and row is not None and anchors and row.get("anchor") in anchors:
        return f'<td><a href="#{html.escape(row["anchor"], quote=True)}">{text}</a></td>'
    if c["key"] == "url" and str(v).startswith("http"):
        return f'<td><a href="{html.escape(str(v), quote=True)}" rel="noopener noreferrer">{html.escape(str(v).rsplit("/", 1)[-1])}</a></td>'
    if kind == "mono" and ", " in text:        # CVE и версии списком: переносить между значениями, не внутри
        text = ", ".join(f'<span class="nw">{t}</span>' for t in text.split(", "))
    cls = "num" if kind == "num" else "mono" if kind == "mono" else "nw" if kind == "date" or c["key"] in NW_KEYS else ""
    return f'<td class="{cls}">{text}</td>'


def _table(cols: list[dict], rows: list[dict], *, anchors: set[str] | None = None, limit: int = HTML_ROW_LIMIT) -> str:
    shown = rows[:limit]
    head = "".join(f'<th class="{"num" if c["type"] == "num" else ""}">{html.escape(c["title"])}</th>' for c in cols)
    body = "".join("<tr>" + "".join(_td(r.get(c["key"]), c, anchors, r) for c in cols) + "</tr>" for r in shown)
    return f'<div class="tablewrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _host_card(d: dict, esc=html.escape) -> str:
    v_cols = [{"key": "severity_ru", "title": "Опасность", "type": "sev"}, {"key": "vuln", "title": "Уязвимость", "type": "mono"}, {"key": "cve", "title": "CVE / идентификаторы", "type": "mono"},
              {"key": "product", "title": "Программа", "type": "text"}, {"key": "installed_version", "title": "Версия", "type": "mono"}, {"key": "fix", "title": "Исправление", "type": "text"},
              {"key": "detected", "title": "Обнаружена (UTC)", "type": "date"}, {"key": "triage", "title": "Обработка", "type": "text"}]
    e_cols = [{"key": "severity_ru", "title": "Опасность", "type": "sev"}, {"key": "vuln", "title": "Уязвимость", "type": "mono"}, {"key": "title", "title": "Название", "type": "text"},
              {"key": "kev", "title": "KEV", "type": "text"}, {"key": "product", "title": "Программа", "type": "text"}, {"key": "installed_version", "title": "Версия", "type": "mono"},
              {"key": "status_ru", "title": "Сопоставление", "type": "text"}, {"key": "basis", "title": "Основание", "type": "text"}, {"key": "triage", "title": "Обработка", "type": "text"}]
    x_cols = [{"key": "severity_ru", "title": "Опасность", "type": "sev"}, {"key": "vuln", "title": "Уязвимость", "type": "mono"}, {"key": "product", "title": "Программа", "type": "text"},
              {"key": "origin_ru", "title": "Откуда", "type": "text"}, {"key": "triage_status", "title": "Решение", "type": "text"}, {"key": "triage_reason", "title": "Основание", "type": "text"},
              {"key": "triage_comment", "title": "Комментарий", "type": "text"}, {"key": "triage_by", "title": "Кто", "type": "text"}, {"key": "triage_until", "title": "Пересмотр до", "type": "date"}]
    out = [f'<section class="host" id="{esc(d["anchor"], quote=True)}"><span class="back"><a href="#problems">↑ к списку</a></span><header><h3>{esc(d["name"])}</h3><span class="m nw">{esc(d["ip"])}</span>'
           f'<span class="sev {_sev_class(d["max_sev"])}">{esc(d["max_sev"] or "без уязвимостей")}</span><span class="m">{esc(d["os"])} · подключение к KSC: {esc(_fmt(d["last_connected"], "date"))} · {esc(d["online"])}'
           f'{" · " + esc(d["zone"]) if d.get("zone") else ""}</span></header><div class="m" style="font-size:12.5px">{esc(d["summary"])}</div>']
    if d["ksc"]:
        out.append("<h4>Уязвимости, подтверждённые KSC</h4>" + _table(v_cols, d["ksc"]))
    if d["ext"]:
        out.append("<h4>Потенциальные уязвимости по внешним базам (не подтверждены KSC)</h4>" + _table(e_cols, d["ext"]))
    if d.get("ksc_more") or d.get("ext_more"):
        out.append(f'<p class="tnote">Показаны самые опасные записи; ещё в карточке не показано: уязвимостей KSC — {d.get("ksc_more", 0)}, потенциальных совпадений — {d.get("ext_more", 0)}. Полный список — в таблицах ниже и в файле Excel.</p>')
    if d["protection"]:
        out.append("<h4>Проблемы защиты</h4>" + _table([{"key": "problem", "title": "Проблема", "type": "text"}, {"key": "detail", "title": "Подробности", "type": "text"}], d["protection"]))
    if d["accepted"]:
        out.append("<h4>Принятые риски</h4>" + _table(x_cols, d["accepted"]))
    if d["excluded"]:
        out.append("<h4>Исключённые обнаружения (ложные срабатывания, неактуальные)</h4>" + _table(x_cols, d["excluded"]))
    out.append("</section>")
    return "".join(out)


def render_html(doc: dict) -> str:
    esc = html.escape
    org = org_lines(doc)
    blocks = [b for b in L.resolve(doc) if b["entry"].get("html") != "never" and not (b["entry"].get("html") == "technical" and doc.get("level") == "management")]
    summary = [b for b in blocks if b["section"] == "summary"]
    detail = [b for b in blocks if b["section"] != "summary"]
    details = doc.get("host_details") or []
    shown_details = details[:HOST_DETAIL_LIMIT]
    anchors = {d["anchor"] for d in shown_details}
    gen = esc(_fmt(doc.get("generated_at"), "date").replace("T", " "))
    out = [f'<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{esc(doc["title"])}</title><style>{CSS}</style></head><body><div class="wrap">']
    out.append('<header class="doc">')
    if org["name"] or org["logo"]:
        out.append('<div class="org">' + (f'<img src="{esc(org["logo"], quote=True)}" alt="">' if org["logo"] else "") + "<div>" + (f'<div class="on">{esc(org["name"])}</div>' if org["name"] else "")
                   + (f'<div class="ou">{esc(" · ".join(x for x in (org["full"], org["unit"]) if x))}</div>' if org["full"] or org["unit"] else "") + "</div>"
                   + (f'<span class="cls">{esc(org["classification"])}</span>' if org["classification"] else "") + "</div>")
    elif org["classification"]:
        out.append(f'<div class="org"><span class="cls">{esc(org["classification"])}</span></div>')
    out.append(f'<h1>{esc(doc["title"])}</h1>' + (f'<p class="sub">{esc(doc["subtitle"])}</p>' if doc.get("subtitle") else ""))
    meta = [("Сформирован", f"{gen} UTC"), ("Источник KSC", doc.get("source") or "")] + [(m["label"], m["text"]) for m in doc.get("meta") or []]
    out.append('<dl class="meta">' + "".join(f"<div><dt>{esc(k)}:</dt><dd>{esc(str(v))}</dd></div>" for k, v in meta if v) + "</dl>")
    nav = [("#summary", "Сводка")] + ([("#problems", summary[0]["title"])] if summary else []) + ([("#details", "Подробности")] if detail or details else []) + [("#method", "Методика")]
    if len(nav) >= 3:
        out.append('<nav class="toc">' + "".join(f'<a href="{h}">{esc(t)}</a>' for h, t in nav) + "</nav>")
    out.append("</header>")
    cuts = [(b["title"], len(b["rows"])) for b in blocks if len(b["rows"]) > HTML_ROW_LIMIT]
    if cuts or len(details) > HOST_DETAIL_LIMIT:
        out.append('<div class="cutwarn" role="note"><b>В этом HTML — сокращённая выборка.</b> '
                   + "; ".join(f"таблица «{esc(n)}»: первые {HTML_ROW_LIMIT} из {total} строк" for n, total in cuts)
                   + (f"; подробные карточки: первые {HOST_DETAIL_LIMIT} из {len(details)} компьютеров" if len(details) > HOST_DETAIL_LIMIT else "")
                   + ". Полный результат — в файле Excel. Показатели подсчитаны по <b>полному</b> результату отчёта.</div>")
    out.append('<section id="summary"><div class="cards">' + "".join(f'<div class="card {esc(m.get("tone") or "")}"><div class="l">{esc(m["label"])}</div><div class="v">{esc(str(m["value"]))}</div>'
                                                             + (f'<div class="h">{esc(m["hint"])}</div>' if m.get("hint") else "") + "</div>" for m in doc["metrics"]) + "</div>")
    if doc.get("severity"):
        lv = doc["severity"]["levels"]
        tot = sum(x["value"] for x in lv) or 1
        out.append(f'<h2>{esc(doc["severity"]["title"])}</h2><div class="panel"><div class="bar" role="img" aria-label="распределение">'
                   + "".join(f'<i style="width:{x["value"] / tot * 100:.2f}%;background:{LEVEL_COLOR.get(x["key"], "#777")}"></i>' for x in lv if x["value"]) + '</div><div class="legend">'
                   + "".join(f'<span><i class="sw" style="background:{LEVEL_COLOR.get(x["key"], "#777")}"></i>{esc(x["label"])}: <b>{x["value"]}</b>' + (f' <span style="color:#59636e">({esc(x["hint"])})</span>' if x.get("hint") else "") + "</span>" for x in lv)
                   + "</div></div>")
    out.append('<h2>Условия проверки</h2><div class="panel"><dl class="cond">' + "".join(f'<div><dt>{esc(c["label"])}</dt><dd>{esc(c["text"])}</dd></div>' for c in doc["conditions"]) + "</dl></div></section>")

    def block(b: dict, idx: int) -> None:
        rows = b["rows"]
        out.append(f'<h2>{esc(b["title"])} <span class="cnt">· {len(rows)}</span></h2>')
        if b.get("note"):
            out.append(f'<p class="tnote">{esc(b["note"])}</p>')
        if len(rows) > HTML_ROW_LIMIT:
            out.append(f'<p class="tnote">Показаны первые {HTML_ROW_LIMIT} строк из {len(rows)} — сокращённая выборка; полный список — в файле Excel.</p>')
        out.append(_table(b["columns"], rows, anchors=anchors) if rows else '<div class="panel">Нет данных.</div>')

    if summary:
        out.append('<section id="problems">')
        for i, b in enumerate(summary):
            block(b, i)
        out.append("</section>")
    if detail or details:
        out.append('<section id="details">')
        if details:
            out.append(f'<h2>Подробно по компьютерам <span class="cnt">· {len(details)}</span></h2>' + "".join(_host_card(d) for d in shown_details))
        for i, b in enumerate(detail):
            block(b, i)
        out.append("</section>")
    out.append('<section id="method"><h2>Методика, источники и ограничения</h2><div class="panel"><ul class="notes">' + "".join(f"<li>{esc(n)}</li>" for n in doc["notes"]) + "</ul></div></section>"
               if doc["notes"] else '<section id="method"></section>')
    foot = [f"<p>KAV Checker · отчёт сформирован {gen} UTC · данные Kaspersky Security Center «{esc(doc.get('source') or '')}». Файл самодостаточен: открывается без подключения к приложению, для PDF используйте печать браузера.</p>"]
    if org["footnote"]:
        foot.append(f"<p>{esc(org['footnote'])}</p>")
    who = " · ".join(x for x in (org["signature"], org["email"], org["contacts"]) if x)
    if who:
        foot.append(f"<p>{esc(who)}</p>")
    out.append("<footer>" + "".join(foot) + "</footer></div></body></html>")
    return "".join(out)


def write_html(path: Path, doc: dict) -> None:
    path.write_text(render_html(doc), encoding="utf-8")


_ = _text
