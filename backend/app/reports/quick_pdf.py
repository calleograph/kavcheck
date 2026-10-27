"""PDF отчёта (reportlab): тот же документ, что у XLSX, HTML и CSV, — для просмотра и передачи. Книжная ориентация не используется: таблицы широкие, лист — A4 альбомный.

Порядок подачи — как в HTML (reports/layout.py): шапка организации и условия → показатели → сводные таблицы → подробности. В PDF у таблицы не больше `MAX_COLS` столбцов (краткий состав из layout
либо первые) и не больше `ROW_LIMIT` строк: PDF предназначен для чтения, полный набор данных — в Excel и CSV (это написано в самом файле). Кириллица — встроенный шрифт DejaVu Sans (лицензия — рядом).
Подробные карточки (`doc["cards"]`) выводятся блоками по одной находке: в них доказательства и рекомендации, которые не помещаются в строку таблицы."""
from __future__ import annotations

import re
from pathlib import Path
from xml.sax.saxutils import escape

from . import layout as L
from .quick_export import _fmt, org_lines

FONTS = Path(__file__).resolve().parent.parent / "assets" / "fonts"
ROW_LIMIT = 1500
CARD_LIMIT = 600
MAX_COLS = 9
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_registered = False


def _fonts() -> None:
    global _registered
    if _registered:
        return
    from reportlab.pdfbase import pdfmetrics  # noqa: PLC0415
    from reportlab.pdfbase.ttfonts import TTFont  # noqa: PLC0415

    pdfmetrics.registerFont(TTFont("DV", str(FONTS / "DejaVuSans.ttf")))
    pdfmetrics.registerFont(TTFont("DV-B", str(FONTS / "DejaVuSans-Bold.ttf")))
    pdfmetrics.registerFontFamily("DV", normal="DV", bold="DV-B", italic="DV", boldItalic="DV-B")
    _registered = True


def _t(v, kind: str = "text", cap: int = 700) -> str:
    if isinstance(v, bool):
        s = "да" if v else "нет"
    elif isinstance(v, int):
        s = f"{v:,}".replace(",", " ")
    elif isinstance(v, float):
        s = str(round(v, 2))
    else:
        s = _fmt(v, kind)
    s = _CTRL.sub("", s)
    return escape(s if len(s) <= cap else s[:cap] + "…")


def write_pdf(path: Path, doc: dict) -> None:
    _fonts()
    from reportlab.lib import colors  # noqa: PLC0415
    from reportlab.lib.pagesizes import A4, landscape  # noqa: PLC0415
    from reportlab.lib.styles import ParagraphStyle  # noqa: PLC0415
    from reportlab.lib.units import mm  # noqa: PLC0415
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # noqa: PLC0415

    W, _H = landscape(A4)
    m = 12 * mm
    avail = W - 2 * m
    base = ParagraphStyle("b", fontName="DV", fontSize=8.5, leading=11, textColor=colors.HexColor("#14181d"))
    small = ParagraphStyle("s", parent=base, fontSize=7, leading=8.8)
    muted = ParagraphStyle("m", parent=base, fontSize=8, textColor=colors.HexColor("#59636e"))
    h1 = ParagraphStyle("h1", parent=base, fontName="DV-B", fontSize=17, leading=21, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=base, fontName="DV-B", fontSize=11.5, leading=14, spaceBefore=10, spaceAfter=4)
    h3 = ParagraphStyle("h3", parent=base, fontName="DV-B", fontSize=9.5, leading=12, spaceBefore=6, spaceAfter=2)
    th = ParagraphStyle("th", parent=small, fontName="DV-B", textColor=colors.white)
    org = org_lines(doc)
    story: list = []
    if org["name"] or org["classification"]:
        story.append(Paragraph(_t(" · ".join(x for x in (org["name"], org["full"], org["unit"], org["classification"]) if x)), muted))
        story.append(Spacer(1, 3))
    story.append(Paragraph(_t(doc["title"]), h1))
    if doc.get("subtitle"):
        story.append(Paragraph(_t(doc["subtitle"]), muted))
    gen = _t(_fmt(doc.get("generated_at"), "date").replace("T", " "))
    meta = [("Сформирован", f"{gen} UTC"), ("Источник данных", doc.get("source") or "")] + [(c["label"], c["text"]) for c in doc.get("meta") or []]
    cond = [(c["label"], c["text"]) for c in doc.get("conditions") or []]
    rows = [[Paragraph(f"<b>{_t(k)}</b>", small), Paragraph(_t(v), small)] for k, v in [*meta, *cond] if v]
    if rows:
        t = Table(rows, colWidths=[avail * 0.22, avail * 0.78])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#dee2e7")), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        story += [Spacer(1, 6), t]
    # показатели: плитки по четыре в ряд
    ms = doc.get("metrics") or []
    if ms:
        cell = []
        for x in ms:
            col = {"danger": "#b3261e", "ok": "#1b6e46", "warn": "#a8690a"}.get(x.get("tone") or "", "#14181d")
            val = _t(x["value"])
            cell.append([Paragraph(f'<font color="{col}">{val}</font>', ParagraphStyle("val", parent=base, fontName="DV-B", fontSize=15, leading=19)), Paragraph(_t(x["label"]), small)] + ([Paragraph(_t(x["hint"], cap=140), ParagraphStyle("hh", parent=small, textColor=colors.HexColor("#59636e")))] if x.get("hint") else []))
        grid = [cell[i:i + 4] + [""] * (4 - len(cell[i:i + 4])) for i in range(0, len(cell), 4)]
        g = Table(grid, colWidths=[avail / 4] * 4)
        g.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#c3cad2")), ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dee2e7")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f6f7f9")), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story += [Paragraph("Сводка", h2), g]
    sev = doc.get("severity")
    if sev:
        story += [Paragraph(_t(sev["title"]), h3), Paragraph("; ".join(f"{_t(l['label'])}: <b>{l['value']}</b>" for l in sev["levels"]), base)]
    for n in doc.get("notes") or []:
        story.append(Paragraph("• " + _t(n, cap=900), small))

    def table(b: dict) -> list:
        cols = [c for c in b["columns"]]
        if not b["entry"].get("cols") and len(cols) > MAX_COLS:
            cols = cols[:MAX_COLS]
        data = b["rows"][:ROW_LIMIT]
        out: list = [Paragraph(f"{_t(b['title'])} <font color='#59636e' size='8'>· {len(b['rows'])}</font>", h2)]
        if b.get("note"):
            out.append(Paragraph(_t(b["note"]), muted))
        if len(b["rows"]) > ROW_LIMIT or len(b["columns"]) > len(cols):
            out.append(Paragraph(f"В PDF показаны первые {min(len(b['rows']), ROW_LIMIT)} из {len(b['rows'])} строк и {len(cols)} из {len(b['columns'])} столбцов; полный набор — в файлах Excel и CSV.", muted))
        if not data:
            return out + [Paragraph("Нет данных.", base)]
        weights = []
        for c in cols:
            sample = [len(str(r.get(c["key"]) or "")) for r in data[:40]]
            weights.append(min(40, max(7, len(c["title"]) * 0.95, (sum(sample) / max(1, len(sample))) * 1.0, max(sample or [0]) * 0.35)))
        k = avail / sum(weights)
        cells = [[Paragraph(_t(c["title"], cap=80), th) for c in cols]]
        for r in data:
            cells.append([Paragraph(_t(r.get(c["key"]), c["type"], cap=500), small) for c in cols])
        t = Table(cells, colWidths=[w * k for w in weights], repeatRows=1)
        st = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b232d")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dee2e7")),
              ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2), ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]
        for i in range(2, len(cells), 2):
            st.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f6f7f9")))
        t.setStyle(TableStyle(st))
        return out + [t]

    blocks = L.resolve(doc)
    for b in [x for x in blocks if x["section"] == "summary"] + [x for x in blocks if x["section"] != "summary"]:
        story += table(b)
    cards = doc.get("cards") or []
    if cards:
        story.append(Paragraph(f"Подробные сведения по находкам · {len(cards)}", h2))
        if len(cards) > CARD_LIMIT:
            story.append(Paragraph(f"В PDF показаны первые {CARD_LIMIT} из {len(cards)} карточек; все — в Excel.", muted))
        for c in cards[:CARD_LIMIT]:
            body = [[Paragraph(f"<b>{_t(k)}</b>", small), Paragraph(_t(v, cap=2500), small)] for k, v in c["rows"] if v not in (None, "")]
            t = Table(body, colWidths=[avail * 0.2, avail * 0.8])
            t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#dee2e7")), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
            story.append(KeepTogether([Paragraph(_t(c["title"], cap=300), h3), t]))
    if org["footnote"] or org["signature"]:
        story.append(Spacer(1, 8))
        story.append(Paragraph(_t(" · ".join(x for x in (org["footnote"], org["signature"], org["email"]) if x)), muted))

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("DV", 7)
        canvas.setFillColor(colors.HexColor("#59636e"))
        canvas.drawString(m, 7 * mm, f"KAV Checker · {doc['title'][:90]} · {gen} UTC")
        canvas.drawRightString(W - m, 7 * mm, f"Стр. {d.page}")
        canvas.restoreState()

    SimpleDocTemplate(str(path), pagesize=landscape(A4), leftMargin=m, rightMargin=m, topMargin=m, bottomMargin=13 * mm, title=doc["title"][:200], author="KAV Checker").build(story, onFirstPage=footer, onLaterPages=footer)

