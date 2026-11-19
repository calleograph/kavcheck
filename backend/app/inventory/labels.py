"""Этикетки учётных единиц и местоположений: PDF (страница на этикетку — для принтера этикеток через драйвер, или лист A4 с сеткой — для клеящейся бумаги) и ZPL (Zebra и совместимые).

На этикетке — строка организации, выбранные поля (наименование, инвентарный и серийный номер, имя компьютера, местоположение) и код: QR со ссылкой на карточку (сканер телефона
открывает её сразу) и/или Code 128 с инвентарным номером (ручной сканер вводит номер в поиск). Этикетка местоположения несёт код «LOC:<id>» — при инвентаризации он переключает помещение."""
from __future__ import annotations

import io
from dataclasses import dataclass

from ..services.settings import InventorySettings

FIELD_RU = {"name": "", "inv_no": "Инв. №", "serial": "S/N", "hostname": "Имя", "location": "Место", "user": "Пользователь", "acc_no": "Бух. №"}


@dataclass
class Label:
    title: str
    lines: list[tuple[str, str]]               # (подпись, значение)
    qr: str                                     # содержимое QR (ссылка на карточку)
    code: str                                   # содержимое Code 128 (инвентарный номер)


def asset_label(row: dict, cfg: InventorySettings, base_url: str, org: str) -> Label:
    lines = []
    for f in cfg.label_fields:
        v = row.get(f) or ""
        if v:
            lines.append((FIELD_RU.get(f, ""), str(v)))
    return Label(title=cfg.label_title or org, lines=lines, qr=f"{base_url.rstrip('/')}/inventory/a/{row['uid']}", code=row["inv_no"])


def location_label(loc: dict, cfg: InventorySettings, org: str) -> Label:
    return Label(title=cfg.label_title or org, lines=[("", loc["path"]), ("Код", f"LOC:{loc['id']}")], qr=f"LOC:{loc['id']}", code=f"LOC:{loc['id']}")


def render_pdf(labels: list[Label], cfg: InventorySettings) -> bytes:
    from reportlab.graphics import renderPDF  # noqa: PLC0415
    from reportlab.graphics.barcode import code128, qr  # noqa: PLC0415
    from reportlab.graphics.shapes import Drawing  # noqa: PLC0415
    from reportlab.lib.pagesizes import A4  # noqa: PLC0415
    from reportlab.lib.units import mm  # noqa: PLC0415
    from reportlab.pdfbase.pdfmetrics import stringWidth  # noqa: PLC0415
    from reportlab.pdfgen import canvas  # noqa: PLC0415

    from ..reports.quick_pdf import _fonts  # noqa: PLC0415

    _fonts()
    w, h = cfg.label_w_mm * mm, cfg.label_h_mm * mm
    buf = io.BytesIO()
    if cfg.label_sheet == "a4":
        c = canvas.Canvas(buf, pagesize=A4)
        cols, rows = cfg.a4_cols, cfg.a4_rows
        cw, ch = A4[0] / cols, A4[1] / rows
        w, h = min(w, cw - 2 * mm), min(h, ch - 2 * mm)
    else:
        c = canvas.Canvas(buf, pagesize=(w, h))
        cols = rows = 1
        cw, ch = w, h
    pad = 1.6 * mm
    c.setTitle("Этикетки учётных единиц")

    def fit(t: str, size: float, maxw: float, font: str = "DV") -> str:
        while t and stringWidth(t, font, size) > maxw:
            t = t[:-2] + "…" if len(t) > 2 else ""
        return t

    def one(lb: Label, x0: float, y0: float) -> None:
        code_h = 0.0
        want_qr = cfg.label_code in ("qr", "both")
        want_bar = cfg.label_code in ("code128", "both")
        qr_side = min(h - 2 * pad - (7 * mm if want_bar else 0), w * 0.45) if want_qr else 0
        if want_bar:
            bc = code128.Code128(lb.code, barHeight=min(6 * mm, h * 0.18), barWidth=max(0.18 * mm, min(0.33 * mm, (w - 2 * pad) / max(60, len(lb.code) * 13))), humanReadable=False)
            bx = x0 + (w - bc.width) / 2 if bc.width < w - 2 * pad else x0 + pad
            bc.drawOn(c, bx, y0 + pad)
            code_h = bc.barHeight + 1 * mm
        if want_qr and qr_side > 6 * mm:
            q = qr.QrCodeWidget(lb.qr, barLevel="M")
            b = q.getBounds()
            d = Drawing(qr_side, qr_side, transform=[qr_side / (b[2] - b[0]), 0, 0, qr_side / (b[3] - b[1]), 0, 0])
            d.add(q)
            renderPDF.draw(d, c, x0 + pad, y0 + code_h + (h - code_h - qr_side) / 2)          # QR по центру свободной высоты
        tx = x0 + pad + (qr_side + 1.5 * mm if qr_side > 6 * mm else 0)
        tw = x0 + w - pad - tx
        y = y0 + h - pad
        if lb.title:
            y -= 6.2
            c.setFont("DV-B", 6.2)
            c.drawString(tx, y, fit(lb.title, 6.2, tw, "DV-B"))
        size = 7.6 if h >= 30 * mm else 6.6
        for i, (k, v) in enumerate(lb.lines):
            font = "DV-B" if i == 0 else "DV"
            text = f"{k} {v}".strip() if k else v
            parts = [text]
            if i == 0 and stringWidth(text, font, size) > tw:              # наименование — в две строки по словам, затем многоточие
                words, first = text.split(), ""
                while words and stringWidth((first + " " + words[0]).strip(), font, size) <= tw:
                    first = (first + " " + words.pop(0)).strip()
                parts = [first or text, " ".join(words)] if words else [text]
            for part in parts:
                if y - size < y0 + pad + code_h:
                    break
                y -= size + 1.4
                c.setFont(font, size)
                c.drawString(tx, y, fit(part, size, tw, font))

    per = cols * rows
    for i, lb in enumerate(labels):
        k = i % per
        if i and k == 0:
            c.showPage()
        x0 = (k % cols) * cw + (cw - w) / 2
        y0 = (A4[1] if cfg.label_sheet == "a4" else ch) - (k // cols + 1) * ch + (ch - h) / 2
        one(lb, x0, y0)
    c.showPage()
    c.save()
    return buf.getvalue()


def _zpl_text(s: str) -> str:
    return s.replace("^", " ").replace("~", " ").replace("\\", "/")


def render_zpl(labels: list[Label], cfg: InventorySettings, dpmm: int = 8) -> str:
    """ZPL II для принтеров Zebra (203 dpi = 8 точек/мм): кириллица — шрифт ^A@ (CI28, UTF-8), код — ^BQ (QR) и/или ^BC (Code 128)."""
    W, H = cfg.label_w_mm * dpmm, cfg.label_h_mm * dpmm
    out = []
    for lb in labels:
        z = [f"^XA^CI28^PW{W}^LL{H}"]
        x = 12
        if cfg.label_code in ("qr", "both"):
            mag = 3 if H < 300 else 4
            z.append(f"^FO10,10^BQN,2,{mag}^FDMA,{_zpl_text(lb.qr)}^FS")
            x = 10 + mag * 33
        y = 14
        if lb.title:
            z.append(f"^FO{x},{y}^A@N,20,20^FD{_zpl_text(lb.title)}^FS")
            y += 26
        for i, (k, v) in enumerate(lb.lines):
            t = f"{k} {v}".strip() if k else v
            z.append(f"^FO{x},{y}^A@N,{26 if i == 0 else 22},{26 if i == 0 else 22}^FD{_zpl_text(t)[:60]}^FS")
            y += 30
        if cfg.label_code in ("code128", "both"):
            z.append(f"^FO{x},{H - 70}^BY2^BCN,50,N,N,N^FD{_zpl_text(lb.code)}^FS")
        z.append("^XZ")
        out.append("".join(z))
    return "\n".join(out)
