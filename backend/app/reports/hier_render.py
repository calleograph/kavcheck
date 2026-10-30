"""Отрисовка структуры подчинения в готовых документах отчёта «Иерархия. Предприятие» (вид tree): разворачиваемое дерево в HTML и таблица с отступами и цветом подразделения в PDF.
Вход — `doc["chart"]`: {"depts": [{name, hue, n}], "main": [узел], "lone": [узел]}, узел — {lv, name, title, dept, n, k}; узлы идут в порядке обхода сверху вниз, `lv` — глубина.
Структура рисуется целиком, без «+N»: полный список остаётся и в Excel. Глубина вложенности ограничена (`DEPTH`): браузер не разбирает вложенность глубже ~500 уровней."""
from __future__ import annotations

import colorsys
import html

DEPTH = 40
CSS = """
.oc-legend { display:flex; flex-wrap:wrap; gap:4px 14px; margin:6px 0 10px; font-size:12px; color:var(--ink2); }
.oc-legend i { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:5px; vertical-align:-1px; }
.oc-bar { display:flex; gap:8px; margin:0 0 8px; } .oc-bar button { font:inherit; font-size:12px; padding:3px 10px; border:1px solid var(--line); background:#fff; border-radius:6px; cursor:pointer; color:var(--ink); }
.oc { background:#fff; border:1px solid var(--line); border-radius:8px; padding:10px 12px; overflow-x:auto; }
.oc details { margin:0 0 0 14px; padding-left:10px; border-left:2px solid var(--line); } .oc > details, .oc > .ol { margin-left:0; }
.oc summary { cursor:pointer; list-style:none; display:flex; align-items:center; gap:8px; padding:1px 0; } .oc summary::-webkit-details-marker { display:none; }
.oc summary::before { content:"▸"; color:var(--muted); width:12px; flex:none; } .oc details[open] > summary::before { content:"▾"; }
.ol { margin:0 0 0 14px; padding:1px 0 1px 32px; }
.oc-c { display:inline-flex; flex-direction:column; border:1px solid var(--line); border-left-width:5px; border-radius:6px; padding:2px 9px; background:#fff; line-height:1.3; }
.oc-c b { font-weight:600; } .oc-c span { font-size:11.5px; color:var(--muted); }
.oc-n { font-size:11.5px; color:var(--muted); white-space:nowrap; }
@media print { .oc-bar { display:none; } .oc { overflow:visible; } }
"""
SCRIPT = ("<script>(function(){var d=document;function all(o){d.querySelectorAll('.oc details').forEach(function(x){x.open=o})}"
          "d.querySelectorAll('[data-oc]').forEach(function(b){b.onclick=function(){all(b.dataset.oc==='1')}});window.addEventListener('beforeprint',function(){all(true)})})()</script>")


def _plural(n: int) -> str:
    return "подчинённый" if n % 10 == 1 and n % 100 != 11 else "подчинённых"


def _tree(nodes: list[dict], depts: list[dict], open_to: int) -> str:
    esc = html.escape
    out, stack = [], []
    for x in nodes:
        lv = min(x["lv"], DEPTH)
        while stack and stack[-1] >= lv:
            out.append("</details>")
            stack.pop()
        card = (f'<span class="oc-c" style="border-left-color:hsl({depts[x["dept"]]["hue"]} 55% 42%)"><b>{esc(x["name"])}</b>'
                f'<span>{esc(x["title"] or "должность не указана")} · {esc(depts[x["dept"]]["name"])}</span></span>')
        if x["k"]:
            out.append(f'<details{" open" if lv < open_to else ""}><summary>{card}<span class="oc-n">{x["n"]} {_plural(x["n"])}</span></summary>')
            stack.append(lv)
        else:
            out.append(f'<div class="ol">{card}</div>')
    out.append("</details>" * len(stack))
    return "".join(out)


def html_section(doc: dict) -> str:
    org = doc["chart"]
    esc = html.escape
    used = sorted({x["dept"] for x in org["main"] + org["lone"]})
    out = ['<section id="chart"><h2>Структура подчинения</h2>',
           '<p class="tnote">Цвет полоски слева — подразделение. Стрелка раскрывает ветку; при печати раскрываются все ветки. Полный список с почтой и цепочками руководителей — в Excel и CSV.</p>',
           '<div class="oc-bar"><button type="button" data-oc="1">Раскрыть всё</button><button type="button" data-oc="0">Свернуть всё</button></div>',
           '<div class="oc-legend">' + "".join(f'<span><i style="background:hsl({org["depts"][d]["hue"]} 55% 42%)"></i>{esc(org["depts"][d]["name"])}</span>' for d in used) + "</div>",
           f'<div class="oc">{_tree(org["main"], org["depts"], 2)}</div>']
    if org["lone"]:
        out.append(f'<h2>Руководитель не указан или не найден <span class="cnt">· {len(org["lone"])}</span></h2>'
                   '<p class="tnote">Этих людей нельзя поставить в структуру: в почте не заполнено или не найдено поле «Руководитель».</p>'
                   f'<div class="oc">{_tree(org["lone"], org["depts"], 1)}</div>')
    out.append("</section>" + SCRIPT)
    return "".join(out)


def _hex(h: int) -> str:
    r, g, b = colorsys.hls_to_rgb(h / 360, 0.42, 0.55)
    return f"#{round(r * 255):02x}{round(g * 255):02x}{round(b * 255):02x}"


def pdf_story(doc: dict, avail: float, base, small, h2, muted, th, esc) -> list:
    """Структура для PDF: строка на человека, отступ по уровню, цветная полоска подразделения. Страниц много — это полный перечень (в PDF таблицы обычно усечены, структура — нет)."""
    from reportlab.lib import colors  # noqa: PLC0415
    from reportlab.lib.styles import ParagraphStyle  # noqa: PLC0415
    from reportlab.platypus import Paragraph, Table, TableStyle  # noqa: PLC0415

    org = doc["chart"]
    story: list = []
    styles: dict[int, ParagraphStyle] = {}
    for title, nodes in (("Структура подчинения", org["main"]), ("Руководитель не указан или не найден", org["lone"])):
        if not nodes:
            continue
        story.append(Paragraph(f"{esc(title)} <font color='#59636e' size='8'>· {len(nodes)}</font>", h2))
        cells = [[Paragraph("", th), Paragraph("Сотрудник", th), Paragraph("Подразделение", th), Paragraph("Подчинённых", th)]]
        st = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b232d")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 1), (-1, -1), 0.2, colors.HexColor("#dee2e7")),
              ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5), ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3), ("LEFTPADDING", (0, 0), (0, -1), 0), ("RIGHTPADDING", (0, 0), (0, -1), 0)]
        for r, x in enumerate(nodes, 1):
            lv = min(x["lv"], DEPTH)
            sty = styles.setdefault(lv, ParagraphStyle(f"lv{lv}", parent=small, leftIndent=min(lv, 14) * 9))
            d = org["depts"][x["dept"]]
            cells.append(["", Paragraph(f"<b>{esc(x['name'])}</b> <font color='#59636e'>{esc(x['title'])}</font>", sty), Paragraph(esc(d["name"]), small), Paragraph(str(x["n"]) if x["k"] else "", small)])
            st.append(("BACKGROUND", (0, r), (0, r), colors.HexColor(_hex(d["hue"]))))
        t = Table(cells, colWidths=[4, avail * 0.56, avail * 0.30, avail * 0.10 - 4], repeatRows=1)
        t.setStyle(TableStyle(st))
        story.append(t)
    return story
