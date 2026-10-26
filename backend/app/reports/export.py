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


def _autosize(columns: list[tuple[str, str]], rows: list[dict], key=lambda c: c) -> list[float]:
    """Ширины столбцов по заголовкам и первым 2000 строкам (потоковая запись требует знать их до первой строки)."""
    return [min(60, max(10, max([len(t)] + [len(_text(r.get(k))) for r in rows[:2000]]) + 2)) for k, t in columns]


def org_header(ws, org: dict | None, title: str = "") -> int:
    """Шапка организации на листе Excel (пустые поля не выводятся). Возвращает число добавленных строк."""
    from openpyxl.styles import Font  # noqa: PLC0415

    o = org or {}
    lines = [(o.get("short_name") or o.get("full_name") or "", Font(bold=True, size=12)), ((o.get("full_name") or "") if o.get("short_name") else "", None), (o.get("unit") or "", None),
             (o.get("classification") or "", Font(italic=True))]
    n = 0
    for text, font in lines:
        if text:
            ws.append([text], font=font)
            n += 1
    if n and title:
        ws.append([title], font=Font(bold=True, size=13))
        ws.append([])
        n += 2
    return n


def org_footer(ws, org: dict | None) -> None:
    for x in ((org or {}).get("footnote"), (org or {}).get("signature"), (org or {}).get("contact_email"), (org or {}).get("contacts")):
        if x:
            ws.append([x])


def _write_audit(path: Path, rows: list[dict], summary: dict, meta: dict) -> None:
    """Проверка версий: «Итог» (программа × источник), «Компьютеры» (что обновить и где), «Версии», «Найденные пакеты» (что найдено и что подходит под условие), «Параметры». Запись потоковая."""
    from openpyxl.styles import Font  # noqa: PLC0415

    from .audit import AUDIT_COLUMNS  # noqa: PLC0415
    from .xlsx import Book  # noqa: PLC0415

    org = meta.pop("_org", None)
    bold = Font(bold=True)
    bk = Book()
    it = bk.sheet("Итог")
    it.widths(40, 40, 22, 18, 22, 22, 22, 22)
    org_header(it, org, meta.get("Отчёт") or "")
    sources = [s["source"] for s in summary.get("sources", [])]
    it.append(["Программа", "Условие проверки", "Целевая версия", "Компьютеров (уникальных)", *[f"{s}: компьютеров" for s in sources], "Пояснение"], font=bold)
    for p in summary.get("programs", []):
        by = {b["source"]: b["hosts"] for b in p.get("by_source", [])}
        it.append([p["program"], p["condition"], p["target_version"], p["hosts"], *[by.get(s, 0) for s in sources], p.get("explain") or ""])
    it.append([])
    it.append(["Всего строк", summary.get("rows")])
    it.append(["Компьютеров (уникальных в пределах источника)", summary.get("hosts")])
    it.append(["Скрыто давно не подключавшихся компьютеров", summary.get("hidden_inactive_hosts")])
    for n in summary.get("notes") or []:
        it.append(["Примечание", n])
    ws = bk.sheet("Компьютеры")
    ws.widths(*_autosize(AUDIT_COLUMNS, rows))
    ws.freeze()
    ws.append([t for _, t in AUDIT_COLUMNS], font=bold)
    for r in rows:
        ws.append([_cell(r.get(k)) for k, _ in AUDIT_COLUMNS])
    ws.filter(len(AUDIT_COLUMNS))
    vs = bk.sheet("Версии")
    vs.widths(30, 40, 30, 12)
    vs.freeze()
    vs.append(["Источник KSC", "Программа", "Версия", "Установок"])
    for s in summary.get("sources", []):
        for i in s.get("items", []):
            for v, cnt in i.get("versions", []):
                vs.append([s["source"], i["program"], v, cnt])
    vs.filter(4)
    fs = bk.sheet("Найденные пакеты")
    fs.widths(24, 30, 26, 40, 24, 22, 20, 12)
    fs.freeze()
    fs.append(["Источник KSC", "Программа", "Продукт каталога", "Запись реестра KSC", "Производитель", "Версия", "Сравниваемая версия", "Подходит под условие"], font=bold)
    for s in summary.get("sources", []):
        for i in s.get("items", []):
            for f in i.get("found", []):
                fs.append([s["source"], i["program"], f.get("product") or "", f["name"], f.get("publisher") or "", f["version"], f.get("compared_version") or "", "да" if f["matched"] else "нет"])
    fs.filter(8)
    m = bk.sheet("Параметры отчёта")
    m.widths(44, 110)
    for k, v in meta.items():
        m.append([k, _text(v) if not isinstance(v, (int, float)) else v])
    m.append([])
    org_footer(m, org)
    bk.save(path)


def write_xlsx(path: Path, kind: str, rows: list[dict], summary: dict, meta: dict) -> None:
    from .xlsx import Book  # noqa: PLC0415

    if kind == "version_audit":
        _write_audit(path, rows, summary, meta)
        return
    org = meta.pop("_org", None)
    columns = SOFTWARE_COLUMNS if kind == "software_hosts" else HOST_COLUMNS
    bk = Book()
    sm = bk.sheet("Сводка")                              # сначала краткие итоги, затем разбивка по версиям и компьютерам, подробный перечень установок — ниже
    sm.widths(44, 70)
    org_header(sm, org, meta.get("Отчёт") or "")
    for k in ("Источник KSC", "Данные получены (UTC)", "Сформировал"):
        if meta.get(k):
            sm.append([k, _text(meta[k])])
    sm.append(["Строк в подробном листе", len(rows)])
    sm.append(["Уникальных компьютеров", len({r["host_id"] for r in rows})])
    if kind == "software_hosts":
        sm.append(["Веток / версий", len(summary.get("branches", []))])
        vs = bk.sheet("Версии")
        vs.freeze()
        vs.append(["Ветка", "Установок", "Уникальных компьютеров", "Пакеты"])
        for b in summary.get("branches", []):
            vs.append([b["branch"], b["installs"], b["hosts"], ", ".join(b["packages"])[:30000]])
        vs.filter(4)
        hs = bk.sheet("Компьютеры")
        hs.freeze()
        hs.append(["Компьютер", "FQDN", "IP-адрес", "ОС", "Дистрибутив Linux", "Группа", "Последнее подключение (UTC)", "Активность", "Ветки", "Пакетов", "Пакеты и версии"])
        by_host: dict[int, list[dict]] = {}
        for r in rows:
            by_host.setdefault(r["host_id"], []).append(r)
        for rs in sorted(by_host.values(), key=lambda rs: rs[0]["name"].lower()):
            f = rs[0]
            branches = sorted({r["branch"] for r in rs if r["branch"]})
            hs.append([f["name"], f["fqdn"], f["ip"], f["os"], f["linux_release"], f["group"], _cell(f["last_connected"]), f["activity"], ", ".join(branches), len(rs),
                       "; ".join(f"{r['app_name']} {r['app_version']}" for r in rs)[:30000]])
        hs.filter(11)
    ws = bk.sheet("Установки" if kind == "software_hosts" else "Компьютеры")
    ws.widths(*_autosize(columns, rows))
    ws.freeze()
    ws.append([t for _, t in columns])
    for r in rows:
        ws.append([_cell(r.get(k)) for k, _ in columns])
    ws.filter(len(columns))
    m = bk.sheet("Параметры отчёта")
    m.widths(40, 100)
    for k, v in meta.items():
        m.append([k, _text(v) if not isinstance(v, (int, float)) else v])
    m.append([])
    org_footer(m, org)
    bk.save(path)
