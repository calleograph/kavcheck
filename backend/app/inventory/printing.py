"""Печатные формы документов (акты, накладная перемещения, наряд, направление в ремонт) в трёх видах: HTML для печати из браузера, PDF и DOCX (для правки в редакторе).

Состав формы — из настроек раздела (заголовок, вводный текст, столбцы, свойства, подписи), по умолчанию — встроенный (model.FORMS_DEFAULT). В форме только сведения документа:
название, номер и дата, стороны, основание, таблица оборудования, места для подписей. Технических полей KSC в актах нет. DOCX собирается без внешних библиотек (WordprocessingML)."""
from __future__ import annotations

import html
import io
import zipfile
from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape as xesc

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import InvAsset, InvDoc, InvDocItem, InvLocation, InvPerson, InvProp
from ..services.settings import InventorySettings
from . import core as C
from . import model as M

FONTS = Path(__file__).resolve().parent.parent / "assets" / "fonts"
MONTHS = ("января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря")


def ru_date(d: date) -> str:
    return f"«{d.day:02d}» {MONTHS[d.month - 1]} {d.year} г."


def form_of(cfg: InventorySettings, kind: str) -> dict:
    base = dict(M.FORMS_DEFAULT.get(kind) or M.FORMS_DEFAULT["accept"])
    own = cfg.forms.get(kind)
    if own is not None:
        for k, v in own.model_dump().items():
            if v:                                                   # пустое поле настройки — встроенное значение
                base[k] = v
    return base


async def build(db: AsyncSession, doc: InvDoc, cfg: InventorySettings, org: dict) -> dict:
    """Структура печатной формы (общая для HTML, PDF и DOCX)."""
    f = form_of(cfg, doc.kind)
    items = list((await db.execute(select(InvDocItem).where(InvDocItem.doc_id == doc.id).order_by(InvDocItem.id))).scalars())
    assets = {a.id: a for a in (await db.execute(select(InvAsset).where(InvAsset.id.in_([i.asset_id for i in items])))).scalars()} if items else {}
    pdefs = {p.code: p for p in (await db.execute(select(InvProp).where(InvProp.code.in_(f.get("props") or ["-"])))).scalars()}
    people = {p.id: p for p in (await db.execute(select(InvPerson).where(InvPerson.id.in_({doc.from_person_id, doc.to_person_id, doc.resp_id} - {None})))).scalars()}
    locs = {x.id: x for x in (await db.execute(select(InvLocation).where(InvLocation.id.in_({doc.from_location_id, doc.to_location_id} - {None})))).scalars()}

    def pname(i):
        p = people.get(i)
        return f"{p.name}{', ' + p.title if p and p.title else ''}" if p else "________________"

    item_locs = {(i.snap or {}).get("location") or "" for i in items}
    from_loc = locs[doc.from_location_id].path if doc.from_location_id in locs else (item_locs.pop() if len(item_locs) == 1 and "" not in item_locs else "см. таблицу")
    subst = {"from_person": pname(doc.from_person_id), "to_person": pname(doc.to_person_id), "from_location": from_loc,
             "to_location": locs[doc.to_location_id].path if doc.to_location_id in locs else "—", "no": doc.no, "date": ru_date(doc.doc_date)}

    def fill(t: str) -> str:
        for k, v in subst.items():
            t = t.replace("{" + k + "}", v)
        return t

    cols = [(c, M.DOC_COLUMNS.get(c, c)) for c in (f.get("columns") or []) if c in M.DOC_COLUMNS] + [(f"p.{c}", pdefs[c].name) for c in (f.get("props") or []) if c in pdefs]
    rows = []
    if not items and doc.kind == "receipt":                        # поступление до приёмки: строки заказа (карточек ещё нет)
        n = 0
        for ln in (doc.data or {}).get("lines") or []:
            n += 1
            nm = ln.get("name") or ""
            rows.append({"n": str(n), "inv_no": "", "acc_no": "", "name": f"{nm} × {ln.get('qty', 1)}".strip(" ×") if nm else f"× {ln.get('qty', 1)}", "type": "", "model": "",
                         "serial": ", ".join(ln.get("serials") or []), "location": "", "condition": "", "cost": C.money_str(int(round((ln.get("cost") or 0) * 100))) if ln.get("cost") else "", "note": ""})
    for n, it in enumerate(items, 1):
        s = it.snap or {}
        a = assets.get(it.asset_id)
        r = {"n": str(n), "inv_no": s.get("inv_no", ""), "acc_no": s.get("acc_no", ""), "name": s.get("name", ""), "type": s.get("type", ""), "model": s.get("model", ""),
             "serial": s.get("serial", ""), "location": s.get("location", ""), "condition": it.condition, "cost": C.money_str(s.get("cost")), "note": it.note}
        for c in f.get("props") or []:
            r[f"p.{c}"] = C.prop_text(pdefs.get(c), (a.props or {}).get(c) if a else None)
        rows.append(r)
    d = doc.data or {}
    parties = []
    if doc.from_person_id:
        parties.append(("Передающая сторона" if doc.kind not in ("return",) else "Сотрудник", pname(doc.from_person_id)))
    if doc.to_person_id:
        parties.append(("Принимающая сторона" if doc.kind not in ("issue",) else "Сотрудник", pname(doc.to_person_id)))
    if doc.from_location_id:
        parties.append(("Откуда", subst["from_location"]))
    if doc.to_location_id:
        parties.append(("Куда", subst["to_location"]))
    if doc.resp_id:
        parties.append(("Ответственный", pname(doc.resp_id)))
    if doc.kind == "repair":
        parties += [(k, v) for k, v in (("Неисправность", d.get("fault")), ("Дата обнаружения", _rd(d.get("found_at"))), ("Исполнитель", d.get("vendor")),
                                        ("Гарантийный ремонт", "да" if d.get("warranty") else ""), ("Результат", d.get("result")), ("Стоимость", C.money_str(d.get("cost"))),
                                        ("Использованные комплектующие", d.get("parts")), ("Дата возврата", _rd(d.get("returned_at")))) if v]
    if doc.kind == "work":
        parties += [(k, v) for k, v in (("Вид работ", M.WORK_KINDS.get(d.get("work_kind", ""), "")), ("Исполнитель", d.get("executor")), ("Срок", _rd(d.get("due"))),
                                        ("Описание", d.get("description")), ("Результат", d.get("result"))) if v]
    if doc.basis:
        parties.append(("Основание", doc.basis))
    lines = M.FORMS_DEFAULT.get(doc.kind, {}).get("signatures") if not f.get("signatures") else f["signatures"]
    sig_names = {0: subst["from_person"] if doc.from_person_id else "", 1: subst["to_person"] if doc.to_person_id else ""}
    org_name = (org.get("short_name") or org.get("full_name") or "").strip()
    return {"title": f.get("title") or M.DOC_RU.get(doc.kind, ""), "no": doc.no, "date": ru_date(doc.doc_date), "org": org_name, "org_full": (org.get("full_name") or "").strip(),
            "unit": (org.get("unit") or "").strip(), "intro": fill(f.get("intro") or ""), "footer": fill(f.get("footer") or ""), "parties": parties, "columns": cols, "rows": rows,
            "signatures": [(lb, sig_names.get(i, "").split(",")[0] if sig_names.get(i) and "_" not in sig_names.get(i, "") else "") for i, lb in enumerate(lines or [])],
            "comment": doc.comment, "status": M.DOC_STATUS_RU.get(doc.status, doc.status), "draft": doc.status in ("draft", "cancelled")}


def _rd(v) -> str:
    try:
        return date.fromisoformat(str(v)[:10]).strftime("%d.%m.%Y") if v else ""
    except ValueError:
        return str(v)


# ------------------------------------------------------------------------------------------------ HTML
CSS = """
@page { size: A4 portrait; margin: 15mm 14mm 16mm 20mm; }
* { box-sizing: border-box; }
body { margin: 0; background: #e9ecef; color: #111; font: 12.5px/1.45 "Times New Roman", "Liberation Serif", Georgia, serif; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.sheet { width: 210mm; min-height: 297mm; margin: 12px auto; background: #fff; padding: 15mm 14mm 16mm 20mm; box-shadow: 0 1px 3px rgba(0,0,0,.15); }
.org { text-align: right; font-size: 11.5px; color: #333; } .org b { font-size: 12.5px; color: #111; }
h1 { text-align: center; font-size: 16px; margin: 18px 0 2px; letter-spacing: .01em; }
.no { text-align: center; margin: 0 0 14px; }
.draft { text-align: center; color: #9a3412; font: 600 11px system-ui, sans-serif; letter-spacing: .04em; margin-top: -8px; margin-bottom: 10px; }
table.parties { border-collapse: collapse; margin: 0 0 12px; width: 100%; } table.parties td { padding: 2px 0; vertical-align: top; } table.parties td:first-child { width: 34%; color: #333; padding-right: 10px; }
p.intro { margin: 0 0 10px; text-align: justify; }
table.items { width: 100%; border-collapse: collapse; margin: 6px 0 12px; font-size: 11.5px; }
table.items th, table.items td { border: 1px solid #555; padding: 3px 5px; text-align: left; vertical-align: top; } table.items th { background: #f1f3f5; font-weight: 600; }
table.items td.n { text-align: right; width: 26px; } .total { margin: -6px 0 12px; font-size: 11.5px; }
p.footer { margin: 0 0 12px; text-align: justify; } p.comment { margin: 0 0 12px; color: #333; }
.sigs { display: grid; grid-template-columns: 1fr 1fr; gap: 22px 36px; margin-top: 26px; break-inside: avoid; }
.sig .l { font-size: 11.5px; color: #333; } .sig .line { border-bottom: 1px solid #111; height: 26px; display: flex; align-items: flex-end; justify-content: flex-end; font-size: 11.5px; padding-bottom: 1px; }
.sig .hint { display: flex; justify-content: space-between; font-size: 9.5px; color: #555; } .sig .d { margin-top: 6px; font-size: 11px; color: #333; }
.toolbar { width: 210mm; margin: 10px auto 0; display: flex; gap: 8px; justify-content: flex-end; font: 13px system-ui, sans-serif; }
.toolbar button { font: inherit; padding: 6px 14px; border-radius: 6px; border: 1px solid #adb5bd; background: #fff; cursor: pointer; } .toolbar button.p { background: #0f6a8b; color: #fff; border-color: #0f6a8b; }
@media print { body { background: #fff; } .sheet { margin: 0; box-shadow: none; padding: 0; width: auto; min-height: 0; } .toolbar { display: none; } }
@media (max-width: 820px) { .sheet { width: auto; min-height: 0; margin: 0; padding: 14px; } .toolbar { width: auto; padding: 0 12px; } .sigs { grid-template-columns: 1fr; } table.items { font-size: 10.5px; } }
"""


def render_html(p: dict) -> str:
    e = html.escape
    out = [f'<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{e(p["title"])} № {e(p["no"])}</title>'
           f'<style>{CSS}</style></head><body><div class="toolbar"><button class="p" onclick="window.print()">Печать</button></div><div class="sheet">']
    if p["org"]:
        out.append(f'<div class="org"><b>{e(p["org"])}</b>' + (f'<br>{e(p["org_full"])}' if p["org_full"] and p["org_full"] != p["org"] else "") + (f'<br>{e(p["unit"])}' if p["unit"] else "") + "</div>")
    out.append(f'<h1>{e(p["title"])}</h1><p class="no">№ {e(p["no"])} от {e(p["date"])}</p>')
    if p["draft"]:
        out.append(f'<p class="draft">ДОКУМЕНТ НЕ ПРОВЕДЁН · {e(p["status"].upper())}</p>')
    if p["parties"]:
        out.append('<table class="parties">' + "".join(f"<tr><td>{e(k)}</td><td>{e(str(v))}</td></tr>" for k, v in p["parties"]) + "</table>")
    if p["intro"]:
        out.append(f'<p class="intro">{e(p["intro"])}</p>')
    out.append('<table class="items"><thead><tr>' + "".join(f"<th>{e(t)}</th>" for _k, t in p["columns"]) + "</tr></thead><tbody>")
    for r in p["rows"]:
        out.append("<tr>" + "".join(f'<td{" class=n" if k == "n" else ""}>{e(str(r.get(k, "")))}</td>' for k, _t in p["columns"]) + "</tr>")
    out.append("</tbody></table>")
    out.append(f'<p class="total">Всего наименований: {len(p["rows"])}</p>')
    if p["footer"]:
        out.append(f'<p class="footer">{e(p["footer"])}</p>')
    if p["comment"]:
        out.append(f'<p class="comment">Примечание: {e(p["comment"])}</p>')
    out.append('<div class="sigs">')
    for lb, nm in p["signatures"]:
        out.append(f'<div class="sig"><div class="l">{e(lb)}</div><div class="line">{e(nm)}</div><div class="hint"><span>подпись</span><span>расшифровка подписи</span></div>'
                   f'<div class="d">«___» ____________ 20__ г.</div></div>')
    out.append("</div></div></body></html>")
    return "".join(out)


# ------------------------------------------------------------------------------------------------ PDF
def render_pdf(p: dict) -> bytes:
    from reportlab.lib import colors  # noqa: PLC0415
    from reportlab.lib.pagesizes import A4  # noqa: PLC0415
    from reportlab.lib.styles import ParagraphStyle  # noqa: PLC0415
    from reportlab.lib.units import mm  # noqa: PLC0415
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # noqa: PLC0415

    from ..reports.quick_pdf import _fonts  # noqa: PLC0415

    _fonts()
    buf = io.BytesIO()
    d = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=14 * mm, topMargin=15 * mm, bottomMargin=16 * mm, title=f'{p["title"]} № {p["no"]}')
    st = {"n": ParagraphStyle("n", fontName="DV", fontSize=9.5, leading=12.5), "s": ParagraphStyle("s", fontName="DV", fontSize=8.2, leading=10.5),
          "h": ParagraphStyle("h", fontName="DV-B", fontSize=13, leading=16, alignment=1, spaceBefore=8), "c": ParagraphStyle("c", fontName="DV", fontSize=9.5, leading=12, alignment=1),
          "r": ParagraphStyle("r", fontName="DV", fontSize=8.5, leading=11, alignment=2), "w": ParagraphStyle("w", fontName="DV-B", fontSize=8, leading=10, alignment=1, textColor=colors.HexColor("#9a3412"))}
    x = xesc
    story = []
    if p["org"]:
        story.append(Paragraph("<b>" + x(p["org"]) + "</b>" + (("<br/>" + x(p["unit"])) if p["unit"] else ""), st["r"]))
    story += [Paragraph(x(p["title"]), st["h"]), Paragraph(f'№ {x(p["no"])} от {x(p["date"])}', st["c"]), Spacer(1, 3 * mm)]
    if p["draft"]:
        story += [Paragraph("ДОКУМЕНТ НЕ ПРОВЕДЁН · " + x(p["status"].upper()), st["w"]), Spacer(1, 2 * mm)]
    if p["parties"]:
        t = Table([[Paragraph(x(k), st["n"]), Paragraph(x(str(v)), st["n"])] for k, v in p["parties"]], colWidths=[58 * mm, None])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#333333")), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        story += [t, Spacer(1, 3 * mm)]
    if p["intro"]:
        story += [Paragraph(x(p["intro"]), st["n"]), Spacer(1, 2 * mm)]
    head = [Paragraph("<b>" + x(t) + "</b>", st["s"]) for _k, t in p["columns"]]
    body = [[Paragraph(x(str(r.get(k, ""))), st["s"]) for k, _t in p["columns"]] for r in p["rows"]]
    widths = {"n": 8 * mm, "inv_no": 24 * mm, "acc_no": 22 * mm, "serial": 30 * mm, "cost": 22 * mm, "condition": 26 * mm}
    cw = [widths.get(k) for k, _t in p["columns"]]
    free = (A4[0] - 34 * mm - sum(w for w in cw if w)) / max(1, sum(1 for w in cw if not w))
    t = Table([head, *body], colWidths=[w or free for w in cw], repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#555555")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f3f5")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t, Spacer(1, 1.5 * mm), Paragraph(f'Всего наименований: {len(p["rows"])}', st["s"]), Spacer(1, 3 * mm)]
    if p["footer"]:
        story += [Paragraph(x(p["footer"]), st["n"]), Spacer(1, 2 * mm)]
    if p["comment"]:
        story += [Paragraph("Примечание: " + x(p["comment"]), st["n"]), Spacer(1, 2 * mm)]
    cells = []
    for lb, nm in p["signatures"]:
        cells.append([Paragraph(x(lb), st["s"]), Spacer(1, 6 * mm), Table([[Paragraph(x(nm), st["r"])]], colWidths=[78 * mm], style=[("LINEBELOW", (0, 0), (-1, -1), 0.7, colors.black)]),
                      Paragraph("подпись / расшифровка подписи", st["s"]), Spacer(1, 1.5 * mm), Paragraph("«___» ____________ 20__ г.", st["s"])])
    grid = [cells[i:i + 2] for i in range(0, len(cells), 2)]
    if grid:
        if len(grid[-1]) == 1:
            grid[-1].append("")
        story += [Spacer(1, 7 * mm), KeepTogether(Table(grid, colWidths=[86 * mm, 86 * mm], style=[("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))]
    d.build(story)
    return buf.getvalue()


# ------------------------------------------------------------------------------------------------ DOCX (минимальный WordprocessingML)
def _run(text: str, *, bold: bool = False, size: int | None = None) -> str:
    rpr = ("<w:b/>" if bold else "") + (f'<w:sz w:val="{size}"/>' if size else "")
    return f'<w:r>{"<w:rPr>" + rpr + "</w:rPr>" if rpr else ""}<w:t xml:space="preserve">{xesc(text)}</w:t></w:r>'


def _par(text: str = "", *, bold: bool = False, size: int | None = None, align: str = "", after: int = 80) -> str:
    ppr = f'<w:pPr><w:spacing w:after="{after}"/>{f"<w:jc w:val=" + chr(34) + align + chr(34) + "/>" if align else ""}</w:pPr>'
    return f"<w:p>{ppr}{_run(text, bold=bold, size=size) if text else ''}</w:p>"


def _table(rows: list[list[str]], *, header: bool = True, borders: bool = True, widths: list[int] | None = None) -> str:
    b = ('<w:tblBorders>' + "".join(f'<w:{s} w:val="single" w:sz="4" w:color="555555"/>' for s in ("top", "left", "bottom", "right", "insideH", "insideV")) + "</w:tblBorders>") if borders else ""
    grid = "<w:tblGrid>" + "".join(f'<w:gridCol w:w="{w}"/>' for w in (widths or [])) + "</w:tblGrid>" if widths else ""
    out = [f'<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/>{b}</w:tblPr>{grid}']
    for i, r in enumerate(rows):
        out.append("<w:tr>" + ('<w:trPr><w:tblHeader/></w:trPr>' if header and i == 0 else ""))
        for c in r:
            shade = '<w:shd w:val="clear" w:color="auto" w:fill="F1F3F5"/>' if header and i == 0 else ""
            out.append(f"<w:tc><w:tcPr>{shade}</w:tcPr><w:p><w:pPr><w:spacing w:after=\"0\"/></w:pPr>{_run(c, bold=header and i == 0, size=19)}</w:p></w:tc>")
        out.append("</w:tr>")
    out.append("</w:tbl>")
    return "".join(out)


def render_docx(p: dict) -> bytes:
    body = []
    if p["org"]:
        body.append(_par(p["org"], bold=True, align="right", after=0))
        if p["unit"]:
            body.append(_par(p["unit"], align="right", after=0))
    body += [_par(p["title"], bold=True, size=28, align="center", after=40), _par(f'№ {p["no"]} от {p["date"]}', align="center", after=200)]
    if p["draft"]:
        body.append(_par("Документ не проведён: " + p["status"].lower(), align="center"))
    if p["parties"]:
        body.append(_table([[k, str(v)] for k, v in p["parties"]], header=False, borders=False, widths=[3200, 6400]))
        body.append(_par(after=60))
    if p["intro"]:
        body.append(_par(p["intro"], after=120))
    body.append(_table([[t for _k, t in p["columns"]], *[[str(r.get(k, "")) for k, _t in p["columns"]] for r in p["rows"]]]))
    body.append(_par(f'Всего наименований: {len(p["rows"])}', size=19, after=160))
    if p["footer"]:
        body.append(_par(p["footer"], after=120))
    if p["comment"]:
        body.append(_par("Примечание: " + p["comment"], after=120))
    sig_rows = []
    for lb, nm in p["signatures"]:
        sig_rows.append([lb, f"________________ / {nm or '________________'} /", "«___» __________ 20__ г."])
    if sig_rows:
        body.append(_par(after=200))
        body.append(_table(sig_rows, header=False, borders=False, widths=[2800, 4200, 2600]))
    sect = '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="850" w:right="794" w:bottom="907" w:left="1134" w:header="0" w:footer="0" w:gutter="0"/></w:sectPr>'
    document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
                + "".join(body) + sect + "</w:body></w:document>")
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr>'
              '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman"/><w:sz w:val="22"/><w:lang w:val="ru-RU"/></w:rPr></w:rPrDefault></w:docDefaults></w:styles>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                   '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        z.writestr("word/_rels/document.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
        z.writestr("word/document.xml", document)
        z.writestr("word/styles.xml", styles)
    return buf.getvalue()
