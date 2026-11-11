"""HTML-отчёт по компьютерам с вкладками, как карточка компьютера: общие сведения, состояние защиты, установленное ПО, уязвимости, EOL, события, аппаратная часть.

Вкладки переключаются без сценариев (переключатели и CSS), поэтому отчёт читается и без JavaScript. Сценарий добавляет поиск по таблице, сортировку по столбцу и
порции строк («Показать ещё»): длинный список ПО не превращается в одну огромную страницу. Всё внутри файла: стили, сценарий, данные; внешних ресурсов нет.
Значения экранируются при выводе; сценарий работает с текстом ячеек и не вставляет разметку из данных."""
from __future__ import annotations

import html

from .quick_export import CSS as BASE_CSS
from .quick_export import _fmt, org_lines

esc = html.escape
PAGE = 200                     # строк в порции; остальные — по «Показать ещё» или при печати
HTML_TAB_LIMIT = 20_000        # строк одной вкладки в HTML (десятки тысяч строк браузер держит плохо)
CSS_TABS = """
.tabs { position: relative; margin-top: 14px; }
.kt-r { position: absolute; opacity: 0; pointer-events: none; }
.kt-bar { display: flex; flex-wrap: wrap; gap: 4px; border-bottom: 1px solid var(--line); margin-bottom: 12px; }
.kt-tab { cursor: pointer; padding: 8px 12px; border-bottom: 2px solid transparent; color: var(--muted); font-weight: 600; user-select: none; }
.kt-tab:hover { color: var(--ink); }
.kt-n { font-weight: 400; font-size: 12px; background: #eef1f4; border-radius: 10px; padding: 0 7px; margin-left: 4px; }
.kt-panel { display: none; background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; }
.kt-sum { margin: 0 0 10px; color: var(--ink2); }
.kt-sum b { font-weight: 600; }
.kt-tools { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 8px; }
.kt-tools input { font: inherit; padding: 6px 9px; border: 1px solid #c3cad2; border-radius: 6px; min-width: 240px; flex: 1; max-width: 420px; }
.kt-count { color: var(--muted); font-size: 12.5px; }
.kt-table-wrap { overflow-x: auto; }
.kt-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.kt-table th, .kt-table td { border-bottom: 1px solid #edf0f3; padding: 5px 8px; text-align: left; vertical-align: top; }
.kt-table th { background: #f6f7f9; font-weight: 600; position: sticky; top: 0; white-space: nowrap; }
.kt-table th.kt-sortable { cursor: pointer; }
.kt-table th.kt-sortable:hover { color: var(--accent); }
.kt-table td.num { text-align: right; font-variant-numeric: tabular-nums; }
.kt-table td.mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.kt-table tr.kt-off { display: none; }
.kt-empty { color: var(--muted); padding: 10px 0; }
.kt-more { margin: 10px 0 0; }
.kt-more button { font: inherit; border: 1px solid #c3cad2; background: #fff; border-radius: 6px; padding: 5px 12px; cursor: pointer; }
.kt-r:focus-visible + .kt-bar .kt-tab { outline: none; }
#kt-0:checked ~ .kt-bar .kt-tab[for="kt-0"], #kt-1:checked ~ .kt-bar .kt-tab[for="kt-1"], #kt-2:checked ~ .kt-bar .kt-tab[for="kt-2"],
#kt-3:checked ~ .kt-bar .kt-tab[for="kt-3"], #kt-4:checked ~ .kt-bar .kt-tab[for="kt-4"], #kt-5:checked ~ .kt-bar .kt-tab[for="kt-5"],
#kt-6:checked ~ .kt-bar .kt-tab[for="kt-6"], #kt-7:checked ~ .kt-bar .kt-tab[for="kt-7"], #kt-8:checked ~ .kt-bar .kt-tab[for="kt-8"], #kt-9:checked ~ .kt-bar .kt-tab[for="kt-9"]
{ color: var(--accent); border-bottom-color: var(--accent); }
#kt-0:checked ~ .kt-panels #kp-0, #kt-1:checked ~ .kt-panels #kp-1, #kt-2:checked ~ .kt-panels #kp-2, #kt-3:checked ~ .kt-panels #kp-3, #kt-4:checked ~ .kt-panels #kp-4,
#kt-5:checked ~ .kt-panels #kp-5, #kt-6:checked ~ .kt-panels #kp-6, #kt-7:checked ~ .kt-panels #kp-7, #kt-8:checked ~ .kt-panels #kp-8, #kt-9:checked ~ .kt-panels #kp-9
{ display: block; }
@media print {
  .kt-r, .kt-bar, .kt-tools, .kt-more { display: none !important; }
  .kt-panel { display: block !important; break-before: page; border: 0; padding: 0; }
  .kt-table tr.kt-off { display: table-row !important; }
  .kt-table-wrap { overflow: visible; }
}
.chips { display: grid; grid-template-columns: repeat(auto-fill, minmax(168px, 1fr)); gap: 8px; margin: 12px 0 4px; }
.chip { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; display: flex; flex-direction: column; min-width: 0; }
.chip .l { color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
.chip b { font-size: 18px; font-variant-numeric: tabular-nums; }
.chip .h { color: var(--muted); font-size: 11.5px; }
.chip.bad b { color: var(--crit); } .chip.warn b { color: var(--warn); } .chip.ok b { color: var(--ok); }
.sevbar { display: flex; height: 12px; border-radius: 6px; overflow: hidden; background: #e6e9ed; margin: 6px 0; }
.sevbar i { display: block; height: 100%; }
.legend { display: flex; gap: 14px; flex-wrap: wrap; font-size: 12.5px; margin: 4px 0 10px; }
.legend .sw { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 5px; vertical-align: -1px; }
@media (max-width: 760px) { .kt-tools input { min-width: 0; width: 100%; max-width: none; } .kt-table { font-size: 12px; } }
"""
SCRIPT = """
(function () {
  var PAGE = %d;
  function num(t) { var n = parseFloat(t.replace(/\\s/g, '').replace(',', '.')); return isNaN(n) ? null : n; }
  document.querySelectorAll('.kt-panel').forEach(function (panel) {
    var table = panel.querySelector('table'), tb = table.tBodies[0], rows = Array.prototype.slice.call(tb.rows);
    var q = panel.querySelector('.kt-q'), count = panel.querySelector('.kt-count'), more = panel.querySelector('.kt-more button'), shown = PAGE;
    function refresh() {
      var t = (q.value || '').trim().toLowerCase(), hits = 0;
      rows.forEach(function (r) { var ok = !t || r.textContent.toLowerCase().indexOf(t) >= 0; r.hidden = !ok; if (ok) hits++; });
      var k = 0;
      rows.forEach(function (r) { if (!r.hidden) { k++; r.classList.toggle('kt-off', k > shown); } else { r.classList.remove('kt-off'); } });
      count.textContent = 'Показано ' + Math.min(hits, shown) + ' из ' + hits + (hits !== rows.length ? ' (всего ' + rows.length + ')' : '');
      more.parentNode.hidden = hits <= shown;
    }
    q.addEventListener('input', function () { shown = PAGE; refresh(); });
    more.addEventListener('click', function () { shown += PAGE; refresh(); });
    Array.prototype.forEach.call(table.tHead.rows[0].cells, function (th, col) {
      th.classList.add('kt-sortable');
      th.addEventListener('click', function () {
        var dir = th.getAttribute('data-dir') === 'asc' ? -1 : 1;
        Array.prototype.forEach.call(table.tHead.rows[0].cells, function (o) { o.removeAttribute('data-dir'); });
        th.setAttribute('data-dir', dir === 1 ? 'asc' : 'desc');
        rows.sort(function (a, b) {
          var x = a.cells[col].textContent.trim(), y = b.cells[col].textContent.trim(), nx = num(x), ny = num(y);
          var rx = a.cells[col].getAttribute('data-v'), ry = b.cells[col].getAttribute('data-v');
          var c = rx !== null ? Number(rx) - Number(ry) : (nx !== null && ny !== null) ? nx - ny : x.localeCompare(y, 'ru');
          return c * dir;
        });
        rows.forEach(function (r) { tb.appendChild(r); });
        refresh();
      });
    });
    window.addEventListener('beforeprint', function () { shown = 1e9; refresh(); });
    window.addEventListener('afterprint', function () { shown = PAGE; refresh(); });
    refresh();
  });
})();
"""
SUMMARY_KEY = {"vulns": "severity_ru", "eol": "status_ru", "events": "type_ru", "protection": "problems"}      # по какому столбцу показать распределение во вкладке


SEV_RANK_TEXT = {"Критическая": 3, "Высокая": 2, "Предупреждение": 1, "Средняя и ниже": 1}     # сортировка по опасности — по важности, а не по алфавиту


def _cell(v, col: dict) -> str:
    text = "—" if v is None and col["type"] == "num" else _fmt(v, col["type"])
    cls = " ".join(x for x in ("num" if col["type"] == "num" else "", "mono" if col["type"] == "mono" else "") if x)
    attr = f' data-v="{SEV_RANK_TEXT.get(str(v), 0)}"' if col["type"] == "sev" else ""
    return f'<td class="{cls}"{attr}>{esc(str(text))}</td>' if cls or attr else f"<td>{esc(str(text))}</td>"


def _panel(i: int, t: dict) -> str:
    cols, rows = t["columns"], t["rows"]
    head = "".join(f'<th class="{"num" if c["type"] == "num" else ""}">{esc(c["title"])}</th>' for c in cols)
    body = "".join("<tr>" + "".join(_cell(r.get(c["key"]), c) for c in cols) + "</tr>" for r in rows[:HTML_TAB_LIMIT])
    key = SUMMARY_KEY.get(t["id"])
    summary = f"<b>{len(rows):,}</b> записей".replace(",", " ")
    if key and rows:
        dist: dict[str, int] = {}
        for r in rows:
            v = str(r.get(key) or "—")
            dist[v] = dist.get(v, 0) + 1
        summary += " · " + "; ".join(f"{esc(k)}: {n}" for k, n in sorted(dist.items(), key=lambda kv: -kv[1])[:6])
    note = f'<p class="sub">{esc(t["note"])}</p>' if t.get("note") else ""
    if len(rows) > HTML_TAB_LIMIT:                                   # файл остаётся открываемым в браузере; полный список — в Excel
        note += f'<p class="sub"><b>В этом файле показаны первые {HTML_TAB_LIMIT:,} из {len(rows):,} строк</b> (самые важные первыми); полный список — в файле Excel.</p>'.replace(",", " ")
    empty = '<p class="kt-empty">Нет записей.</p>' if not rows else ""
    return (f'<section class="kt-panel" id="kp-{i}" aria-label="{esc(t["title"])}">{note}<p class="kt-sum">{summary}</p>{empty}'
            f'<div class="kt-tools"><input class="kt-q" type="search" placeholder="Поиск в таблице" aria-label="Поиск в таблице: {esc(t["title"])}"><span class="kt-count"></span></div>'
            f'<div class="kt-table-wrap"><table class="kt-table"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'
            f'<p class="kt-more" hidden><button type="button">Показать ещё {PAGE}</button></p></section>')


def render(doc: dict) -> str:
    org = org_lines(doc)
    by_id = {t["id"]: t for t in doc["tables"]}
    tabs = [(tab["id"], tab["title"], by_id[tab["id"]]) for tab in doc.get("tabs") or [] if tab["id"] in by_id]
    if not tabs:                                                # краткий вариант без построчных вкладок: каждая таблица — отдельная вкладка
        tabs = [(t["id"], t["title"], t) for t in doc["tables"]]
    gen = esc(_fmt(doc.get("generated_at"), "date").replace("T", " "))
    parts = [f'<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
             f'<title>{esc(doc["title"])}</title><style>{BASE_CSS}{CSS_TABS}</style></head><body><div class="wrap">',
             '<header class="doc">']
    if org["name"] or org["logo"]:
        parts.append('<div class="org">' + (f'<img src="{esc(org["logo"], quote=True)}" alt="">' if org["logo"] else "") + "<div>"
                     + (f'<div class="on">{esc(org["name"])}</div>' if org["name"] else "") + "</div>"
                     + (f'<span class="cls">{esc(org["classification"])}</span>' if org["classification"] else "") + "</div>")
    parts.append(f'<h1>{esc(doc["title"])}</h1>' + (f'<p class="sub">{esc(doc["subtitle"])}</p>' if doc.get("subtitle") else ""))
    meta = [("Сформирован", f"{gen} UTC"), ("Источник KSC", doc.get("source") or "")] + [(m["label"], m["text"]) for m in doc.get("meta") or []]
    parts.append('<dl class="meta">' + "".join(f"<div><dt>{esc(k)}:</dt><dd>{esc(str(v))}</dd></div>" for k, v in meta if v) + "</dl>")
    parts.append("</header>")
    parts.append('<section class="chips" aria-label="Показатели">' + "".join(
        f'<div class="chip {esc(m.get("tone") or "")}"><span class="l">{esc(m["label"])}</span><b>{esc(str(m["value"]))}</b>'
        + (f'<span class="h">{esc(m["hint"])}</span>' if m.get("hint") else "") + "</div>" for m in doc.get("metrics") or []) + "</section>")
    sev = doc.get("severity")
    if sev:
        tot = sum(x["value"] for x in sev["levels"]) or 1
        colors = {"critical": "#b3261e", "high": "#c25a00", "warning": "#9a7b00"}
        parts.append(f'<h2>{esc(sev["title"])}</h2><div class="sevbar" role="img" aria-label="распределение">'
                     + "".join(f'<i style="width:{x["value"] / tot * 100:.2f}%;background:{colors.get(x["key"], "#777")}"></i>' for x in sev["levels"] if x["value"]) + "</div>"
                     + '<div class="legend">' + "".join(f'<span><i class="sw" style="background:{colors.get(x["key"], "#777")}"></i>{esc(x["label"])}: <b>{x["value"]}</b></span>' for x in sev["levels"]) + "</div>")
    if doc.get("conditions"):
        parts.append('<h2>Условия</h2><dl class="cond">' + "".join(f'<div><dt>{esc(c["label"])}</dt><dd>{esc(c["text"])}</dd></div>' for c in doc["conditions"]) + "</dl>")
    notes = doc.get("notes") or []
    parts.append('<div class="tabs">')
    for i, (tid, title, t) in enumerate(tabs):
        parts.append(f'<input class="kt-r" type="radio" name="kt" id="kt-{i}"{" checked" if i == 0 else ""}>')
    parts.append('<nav class="kt-bar" role="tablist">' + "".join(
        f'<label class="kt-tab" for="kt-{i}" role="tab">{esc(title)}<span class="kt-n">{len(t["rows"]):,}</span></label>'.replace(",", " ") for i, (tid, title, t) in enumerate(tabs)) + "</nav>")
    parts.append('<div class="kt-panels">' + "".join(_panel(i, t) for i, (tid, title, t) in enumerate(tabs)) + "</div></div>")
    parts.append('<h2>Методика, источники и ограничения</h2><div class="panel"><ul class="notes">' + "".join(f"<li>{esc(n)}</li>" for n in notes) + "</ul></div>")
    foot = [f"<p>KAV Checker · отчёт сформирован {gen} UTC · данные Kaspersky Security Center «{esc(doc.get('source') or '')}». Файл самодостаточен: открывается без подключения к приложению; для PDF используйте печать браузером.</p>"]
    who = " · ".join(x for x in (org["signature"], org["email"], org["contacts"]) if x)
    if who:
        foot.append(f"<p>{esc(who)}</p>")
    parts.append("<footer>" + "".join(foot) + "</footer></div>")
    parts.append(f"<script>{SCRIPT % PAGE}</script></body></html>")
    return "".join(parts)
