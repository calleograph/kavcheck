"""Экспорт отчёта: JSONL (постраничный просмотр), CSV (UTF-8 с BOM, «;») и XLSX с листами «Установки/Компьютеры», «Версии», «Компьютеры» (сводка), «Параметры»."""
from __future__ import annotations

import csv
import json
import re
from datetime import date, datetime
from pathlib import Path

from .builder import HOST_COLUMNS, SOFTWARE_COLUMNS


_NUMBER = re.compile(r"^[+-]?\d+([.,]\d+)?$")


def safe_text(s: str) -> str:
    """Защита от формул при открытии в Excel (CSV-инъекция): начало с = + - @ или табуляции экранируется апострофом; числа с знаком не трогаются."""
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") and not _NUMBER.match(s) else s


def _cell(v):
    if isinstance(v, str):
        return safe_text(v)
    if isinstance(v, datetime):
        return v.replace(tzinfo=None)
    if isinstance(v, date):
        return v
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return v


def _text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    return str(v)


def _json_default(v):
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    return str(v)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, default=_json_default) + "\n")


def read_all_jsonl(path: Path, cap: int = 500_000) -> list[dict]:
    out = []
    with path.open("r", encoding="utf-8") as f:
        for n, line in enumerate(f):
            if n >= cap:
                break
            out.append(json.loads(line))
    return out


def read_jsonl(path: Path, offset: int, limit: int) -> list[dict]:
    out = []
    with path.open("r", encoding="utf-8") as f:
        for n, line in enumerate(f):
            if n < offset:
                continue
            if len(out) >= limit:
                break
            out.append(json.loads(line))
    return out


def write_csv(path: Path, rows: list[dict], columns: list[tuple[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow([title for _, title in columns])
        for r in rows:
            w.writerow([safe_text(_text(r.get(k))) for k, _ in columns])


def _autosize(ws, columns: list[tuple[str, str]], rows: list[dict]) -> None:
    from openpyxl.utils import get_column_letter  # noqa: PLC0415

    for i, (k, t) in enumerate(columns, 1):
        width = max([len(t)] + [len(_text(r.get(k))) for r in rows[:2000]]) + 2
        ws.column_dimensions[get_column_letter(i)].width = min(60, max(10, width))


def org_header(ws, org: dict | None, title: str = "") -> int:
    """Шапка организации на листе Excel (пустые поля не выводятся). Возвращает число добавленных строк."""
    from openpyxl.styles import Font  # noqa: PLC0415

    o = org or {}
    lines = [(o.get("short_name") or o.get("full_name") or "", Font(bold=True, size=12)), ((o.get("full_name") or "") if o.get("short_name") else "", None), (o.get("unit") or "", None),
             (o.get("classification") or "", Font(italic=True))]
    n = 0
    for text, font in lines:
        if text:
            ws.append([text])
            if font:
                ws.cell(row=ws.max_row, column=1).font = font
            n += 1
    if n and title:
        ws.append([title])
        ws.cell(row=ws.max_row, column=1).font = Font(bold=True, size=13)
        ws.append([])
        n += 2
    return n


def org_footer(ws, org: dict | None) -> None:
    for x in ((org or {}).get("footnote"), (org or {}).get("signature"), (org or {}).get("contact_email"), (org or {}).get("contacts")):
        if x:
            ws.append([x])


def _write_audit(path: Path, rows: list[dict], summary: dict, meta: dict) -> None:
    """Проверка версий: «Итог» (программа × источник), «Компьютеры» (что обновить и где), «Версии», «Найденные пакеты» (что найдено и что подходит под условие), «Параметры»."""
    from openpyxl import Workbook  # noqa: PLC0415
    from openpyxl.styles import Font  # noqa: PLC0415

    from .audit import AUDIT_COLUMNS  # noqa: PLC0415

    org = meta.pop("_org", None)
    wb = Workbook()
    it = wb.active
    it.title = "Итог"
    org_header(it, org, meta.get("Отчёт") or "")
    sources = [s["source"] for s in summary.get("sources", [])]
    it.append(["Программа", "Условие проверки", "Целевая версия", "Компьютеров (уникальных)", *[f"{s}: компьютеров" for s in sources], "Пояснение"])
    for c in it[it.max_row]:
        c.font = Font(bold=True)
    for p in summary.get("programs", []):
        by = {b["source"]: b["hosts"] for b in p.get("by_source", [])}
        it.append([p["program"], p["condition"], p["target_version"], p["hosts"], *[by.get(s, 0) for s in sources], p.get("explain") or ""])
    it.append([])
    it.append(["Всего строк", summary.get("rows")])
    it.append(["Компьютеров (уникальных в пределах источника)", summary.get("hosts")])
    it.append(["Скрыто давно не подключавшихся компьютеров", summary.get("hidden_inactive_hosts")])
    for n in summary.get("notes") or []:
        it.append(["Примечание", n])
    for col, w in zip("ABCDEFGH", (40, 40, 22, 18, 22, 22, 22, 22)):
        it.column_dimensions[col].width = w
    ws = wb.create_sheet("Компьютеры")
    ws.append([t for _, t in AUDIT_COLUMNS])
    for c in ws[1]:
        c.font = Font(bold=True)
    for r in rows:
        ws.append([_cell(r.get(k)) for k, _ in AUDIT_COLUMNS])
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    _autosize(ws, AUDIT_COLUMNS, rows)
    vs = wb.create_sheet("Версии")
    vs.append(["Источник KSC", "Программа", "Версия", "Установок"])
    for s in summary.get("sources", []):
        for i in s.get("items", []):
            for v, cnt in i.get("versions", []):
                vs.append([s["source"], i["program"], v, cnt])
    vs.freeze_panes = "A2"
    vs.auto_filter.ref = vs.dimensions
    for col, w in zip("ABCD", (30, 40, 30, 12)):
        vs.column_dimensions[col].width = w
    fs = wb.create_sheet("Найденные пакеты")
    fs.append(["Источник KSC", "Программа", "Продукт каталога", "Запись реестра KSC", "Производитель", "Версия", "Сравниваемая версия", "Подходит под условие"])
    for c in fs[1]:
        c.font = Font(bold=True)
    for s in summary.get("sources", []):
        for i in s.get("items", []):
            for f in i.get("found", []):
                fs.append([s["source"], i["program"], f.get("product") or "", f["name"], f.get("publisher") or "", f["version"], f.get("compared_version") or "", "да" if f["matched"] else "нет"])
    fs.freeze_panes = "A2"
    fs.auto_filter.ref = fs.dimensions
    for col, w in zip("ABCDEFGH", (24, 30, 26, 40, 24, 22, 20, 12)):
        fs.column_dimensions[col].width = w
    m = wb.create_sheet("Параметры отчёта")
    for k, v in meta.items():
        m.append([k, _text(v) if not isinstance(v, (int, float)) else v])
    m.append([])
    org_footer(m, org)
    m.column_dimensions["A"].width, m.column_dimensions["B"].width = 44, 110
    wb.save(path)


def write_xlsx(path: Path, kind: str, rows: list[dict], summary: dict, meta: dict) -> None:
    from openpyxl import Workbook  # noqa: PLC0415
    from openpyxl.utils import get_column_letter  # noqa: PLC0415

    if kind == "version_audit":
        _write_audit(path, rows, summary, meta)
        return
    org = meta.pop("_org", None)
    columns = SOFTWARE_COLUMNS if kind == "software_hosts" else HOST_COLUMNS
    wb = Workbook()
    sm = wb.active
    sm.title = "Сводка"                                  # сначала краткие итоги, затем разбивка по версиям и компьютерам, подробный перечень установок — ниже
    org_header(sm, org, meta.get("Отчёт") or "")
    for k in ("Источник KSC", "Данные получены (UTC)", "Сформировал"):
        if meta.get(k):
            sm.append([k, _text(meta[k])])
    sm.append(["Строк в подробном листе", len(rows)])
    sm.append(["Уникальных компьютеров", len({r["host_id"] for r in rows})])
    if kind == "software_hosts":
        sm.append(["Веток / версий", len(summary.get("branches", []))])
    sm.column_dimensions["A"].width, sm.column_dimensions["B"].width = 44, 70
    if kind == "software_hosts":
        vs = wb.create_sheet("Версии")
        vs.append(["Ветка", "Установок", "Уникальных компьютеров", "Пакеты"])
        for b in summary.get("branches", []):
            vs.append([b["branch"], b["installs"], b["hosts"], ", ".join(b["packages"])[:30000]])
        hs = wb.create_sheet("Компьютеры")
        hs.append(["Компьютер", "FQDN", "IP-адрес", "ОС", "Дистрибутив Linux", "Группа", "Последнее подключение (UTC)", "Активность", "Ветки", "Пакетов", "Пакеты и версии"])
        by_host: dict[int, list[dict]] = {}
        for r in rows:
            by_host.setdefault(r["host_id"], []).append(r)
        for rs in sorted(by_host.values(), key=lambda rs: rs[0]["name"].lower()):
            f = rs[0]
            branches = sorted({r["branch"] for r in rs if r["branch"]})
            hs.append([f["name"], f["fqdn"], f["ip"], f["os"], f["linux_release"], f["group"], _cell(f["last_connected"]), f["activity"], ", ".join(branches), len(rs),
                       "; ".join(f"{r['app_name']} {r['app_version']}" for r in rs)[:30000]])
        for sheet in (vs, hs):
            sheet.freeze_panes = "A2"
            sheet.auto_filter.ref = sheet.dimensions
    ws = wb.create_sheet("Установки" if kind == "software_hosts" else "Компьютеры")
    ws.append([t for _, t in columns])
    for r in rows:
        ws.append([_cell(r.get(k)) for k, _ in columns])
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    for i, (k, t) in enumerate(columns, 1):
        width = max([len(t)] + [len(_text(r.get(k))) for r in rows[:2000]]) + 2
        ws.column_dimensions[get_column_letter(i)].width = min(60, max(10, width))
    m = wb.create_sheet("Параметры отчёта")
    for k, v in meta.items():
        m.append([k, _text(v) if not isinstance(v, (int, float)) else v])
    m.append([])
    org_footer(m, org)
    m.column_dimensions["A"].width, m.column_dimensions["B"].width = 40, 100
    wb.save(path)
