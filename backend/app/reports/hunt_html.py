"""Самостоятельный HTML отчёта CVE Hunt: встроенные стили и скрипт, без внешних ресурсов; поиск, сортировка по столбцам и быстрые фильтры по результату; печатная версия."""
from __future__ import annotations

import html

from .quick_export import _fmt, org_lines

CSS = """
:root{--ink:#16202a;--muted:#5b6670;--line:#dde2e7;--bg:#f4f6f8;--card:#fff;--accent:#0e6a8a;--crit:#b3261e;--high:#a85a00;--warn:#6b5f1a;--ok:#1b6e46}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.wrap{max-width:1280px;margin:0 auto;padding:20px 20px 48px}h1{margin:.1em 0 .1em;font-size:1.55rem;letter-spacing:-.01em}.sub{margin:0 0 14px;color:var(--muted)}
.org{display:flex;align-items:center;gap:12px;margin-bottom:6px}.org img{max-height:42px}.org .on{font-weight:700}.cls{margin-left:auto;border:1px solid var(--line);border-radius:4px;padding:2px 8px;font-size:.8rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:0 0 14px}
dl.cond{display:grid;grid-template-columns:minmax(150px,230px) 1fr;gap:4px 16px;margin:0}dl.cond dt{color:var(--muted)}dl.cond dd{margin:0;overflow-wrap:anywhere}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:0 0 14px}.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.kpi b{display:block;font-size:1.5rem;font-variant-numeric:tabular-nums}.kpi span{color:var(--muted);font-size:.82rem}.kpi.danger b{color:var(--crit)}.kpi.warn b{color:var(--high)}.kpi.ok b{color:var(--ok)}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 10px}.tools input{flex:1;min-width:220px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;font:inherit}
.chip{border:1px solid var(--line);background:#fff;border-radius:99px;padding:5px 12px;cursor:pointer;font:inherit}.chip[aria-pressed=true]{background:var(--accent);border-color:var(--accent);color:#fff}
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse}th,td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:.9rem}
th{position:sticky;top:0;background:#eef2f5;cursor:pointer;white-space:nowrap;user-select:none}th[aria-sort=ascending]::after{content:" ▲"}th[aria-sort=descending]::after{content:" ▼"}
td.m{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.84rem}.st{border-radius:4px;padding:1px 7px;font-size:.8rem;white-space:nowrap}.st-confirmed{background:#fde8e6;color:var(--crit)}.st-probable{background:#fff1d9;color:var(--high)}.st-needs_check{background:#f3efc7;color:var(--warn)}
.note{color:var(--muted);font-size:.85rem}.warnbox{border-left:4px solid var(--high);background:#fff7ea;padding:10px 12px;border-radius:6px;margin:0 0 14px}
details.ev summary{cursor:pointer;color:var(--accent)}details.ev div{margin-top:4px;color:var(--ink);overflow-wrap:anywhere}.empty{padding:22px;text-align:center;color:var(--muted)}
@media(max-width:640px){.wrap{padding:12px}dl.cond{grid-template-columns:1fr}}
@media print{body{background:#fff}.tools{display:none}.card,.kpi{break-inside:avoid}th{position:static}.wrap{max-width:none;padding:0}details.ev{display:block}}
"""
JS = """
(function(){var t=document.getElementById('hits');if(!t)return;var rows=[].slice.call(t.tBodies[0].rows),q=document.getElementById('q'),chips=[].slice.call(document.querySelectorAll('.chip')),on={};
chips.forEach(function(c){on[c.dataset.s]=true;c.addEventListener('click',function(){on[c.dataset.s]=!on[c.dataset.s];c.setAttribute('aria-pressed',on[c.dataset.s]);f()})});
function f(){var s=(q.value||'').toLowerCase(),n=0;rows.forEach(function(r){var ok=on[r.dataset.s]!==false&&(!s||r.textContent.toLowerCase().indexOf(s)>-1);r.hidden=!ok;if(ok)n++});document.getElementById('cnt').textContent=n}
q.addEventListener('input',f);[].slice.call(t.tHead.rows[0].cells).forEach(function(h,i){h.addEventListener('click',function(){var d=h.getAttribute('aria-sort')==='ascending'?-1:1;
[].forEach.call(t.tHead.rows[0].cells,function(x){x.removeAttribute('aria-sort')});h.setAttribute('aria-sort',d>0?'ascending':'descending');
rows.sort(function(a,b){var x=a.cells[i].textContent.trim().toLowerCase(),y=b.cells[i].textContent.trim().toLowerCase(),nx=parseFloat(x),ny=parseFloat(y);return(isNaN(nx)||isNaN(ny)?x.localeCompare(y,'ru'):nx-ny)*d});rows.forEach(function(r){t.tBodies[0].appendChild(r)})})});f()})();
"""


def render(doc: dict) -> str:
    esc = html.escape
    org = org_lines(doc)
    main = doc["tables"][0]
    cols = main["columns"]
    ev_i = next((i for i, c in enumerate(cols) if c["key"] == "evidence"), -1)
    out = [f'<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(doc["title"])}</title><style>{CSS}</style></head><body><div class="wrap">']
    if org["name"] or org["logo"]:
        out.append('<div class="org">' + (f'<img src="{esc(org["logo"], quote=True)}" alt="">' if org["logo"] else "") + (f'<div class="on">{esc(org["name"])}</div>' if org["name"] else "")
                   + (f'<span class="cls">{esc(org["classification"])}</span>' if org["classification"] else "") + "</div>")
    out.append(f'<h1>{esc(doc["title"])}</h1><p class="sub">{esc(doc.get("subtitle") or "")}</p>')
    out.append('<section class="card"><dl class="cond">' + "".join(f"<dt>{esc(c['label'])}</dt><dd>{esc(c['text'])}</dd>" for c in doc["conditions"]) + "</dl></section>")
    out.append('<div class="kpis">' + "".join(f'<div class="kpi {esc(m.get("tone") or "")}" title="{esc(m.get("hint") or "")}"><b>{esc(str(m["value"]))}</b><span>{esc(m["label"])}</span></div>' for m in doc["metrics"]) + "</div>")
    out.append(f'<div class="warnbox">{esc(doc["notes"][0])}</div>')
    out.append('<section class="card"><h2 style="margin:0 0 10px;font-size:1.1rem">' + esc(main["title"]) + '</h2><div class="tools"><input id="q" type="search" placeholder="Поиск: компьютер, пользователь, зона, IP, продукт" aria-label="Поиск">'
               + "".join(f'<button type="button" class="chip" data-s="{esc(f["key"])}" aria-pressed="true">{esc(f["label"])} · {f["n"]}</button>' for f in doc.get("hunt_filters", []))
               + '<span class="note">Показано: <b id="cnt">0</b></span></div>')
    if not main["rows"]:
        out.append('<div class="empty">По выбранным критериям и статусам затронутых компьютеров не найдено.</div>')
    else:
        out.append('<div class="tw"><table id="hits"><thead><tr>' + "".join(f'<th scope="col">{esc(c["title"])}</th>' for c in cols) + "</tr></thead><tbody>")
        for r in main["rows"]:
            tds = []
            for i, c in enumerate(cols):
                v = r.get(c["key"])
                if c["key"] == "status_ru":
                    tds.append(f'<td><span class="st st-{esc(r["status"])}">{esc(str(v))}</span></td>')
                elif i == ev_i and v:
                    short = str(v)[:70] + ("…" if len(str(v)) > 70 else "")
                    tds.append(f'<td><details class="ev"><summary>{esc(short)}</summary><div>{esc(str(v))}</div></details></td>' if len(str(v)) > 70 else f"<td>{esc(str(v))}</td>")
                else:
                    tds.append(f'<td class="{"m" if c["type"] == "mono" else ""}">{esc(_fmt(v, c["type"]) if v not in (None, "") else "—")}</td>')
            out.append(f'<tr data-s="{esc(r["status"])}">' + "".join(tds) + "</tr>")
        out.append("</tbody></table></div>")
    out.append(f'<p class="note">{esc(main.get("note", ""))}</p></section>')
    for t in doc["tables"][1:]:
        out.append(f'<section class="card"><h2 style="margin:0 0 10px;font-size:1.1rem">{esc(t["title"])}</h2><div class="tw"><table><thead><tr>' + "".join(f"<th>{esc(c['title'])}</th>" for c in t["columns"]) + "</tr></thead><tbody>"
                   + "".join("<tr>" + "".join(f'<td class="{"m" if c["type"] == "mono" else ""}">{esc(_fmt(r.get(c["key"]), c["type"]) if r.get(c["key"]) not in (None, "") else "—")}</td>' for c in t["columns"]) + "</tr>" for r in t["rows"])
                   + f'</tbody></table></div><p class="note">{esc(t.get("note", ""))}</p></section>')
    out.append("".join(f'<p class="note">{esc(n)}</p>' for n in doc["notes"][1:]))
    out.append(f'<p class="note">Сформировано KAV Checker: {esc(str(doc.get("generated_at", "")).replace("T", " "))} UTC.</p>')
    out.append(f"</div><script>{JS}</script></body></html>")
    return "".join(out)
