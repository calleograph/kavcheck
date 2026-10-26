"""Определение продукта и ветки endoflife.date по операционной системе устройства KSC (название ОС, версия и номер сборки из `v_akpub_host`).

ОС не определяется «по последней версии»: у Windows ветка выбирается по номеру сборки и редакции (Pro/Home — «W», Enterprise/Education — «E»), у Windows Server — по году выпуска,
у Ubuntu, Debian, RHEL-семейства — по номеру выпуска из названия. Неопознанная ОС (например, «Linux» без версии, Astra Linux — её нет в endoflife.date) даёт None: EOL не присваивается."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class OsHit:
    product: str            # слаг endoflife.date
    release: str            # ветка
    confidence: str         # high — название и версия однозначны; name — выбор сделан по неполным признакам (например, неизвестна редакция Windows)
    note: str = ""


_WS_YEAR = re.compile(r"windows\s+server\s+(2003|2008|2012|2016|2019|2022|2025)(\s*r2)?", re.I)
_WS_SAC = re.compile(r"windows\s+server\s+(?:version\s+)?(\d{4}|\d{2}h\d)\b", re.I)
_WIN = re.compile(r"windows\s+(11|10|8\.1|8|7|vista|xp)\b", re.I)
_UBUNTU = re.compile(r"ubuntu\s+(\d{2}\.\d{2})", re.I)
_DEBIAN = re.compile(r"debian(?:\s+gnu/linux)?\s+(\d{1,2})(?:\.\d+)?", re.I)
_RHEL = re.compile(r"(red\s*hat\s+enterprise\s+linux|rhel)[^\d]*(\d+)", re.I)
_CENTOS_STREAM = re.compile(r"centos\s+stream[^\d]*(\d+)", re.I)
_CENTOS = re.compile(r"centos(?:\s+linux)?[^\d]*(\d+)", re.I)
_ALMA = re.compile(r"alma\s*linux[^\d]*(\d+)", re.I)
_ROCKY = re.compile(r"rocky\s+linux[^\d]*(\d+)", re.I)
_ORACLE = re.compile(r"oracle\s+linux[^\d]*(\d+)", re.I)
_SLES = re.compile(r"suse\s+linux\s+enterprise\s+server\s+(\d+)(?:\s*sp\s*(\d+))?", re.I)


def windows_release(releases: list[dict], name: str, major, minor, build) -> OsHit | None:
    """Ветка Windows клиента по сборке (`latest` ветки = «10.0.<сборка>») и редакции. releases — [{name, latest_name}] продукта `windows`."""
    m = _WIN.search(name or "")
    if not m or build in (None, 0, "0", ""):
        return None
    fam = m.group(1).lower()
    full = f"{major or 10}.{minor or 0}.{build}"
    cand = [r for r in releases if r.get("latest_name") == full]
    if fam in ("10", "11"):
        cand = [r for r in cand if r["name"].startswith(fam + "-")] or cand
    if not cand:
        return None
    low = (name or "").lower()
    ent = any(x in low for x in ("enterprise", "education", "корпоратив"))
    lts = any(x in low for x in ("ltsc", "ltsb", "iot"))
    iot = "iot" in low

    def kind(r: dict) -> str:
        n = r["name"]
        return "lts" if "lts" in n else "e" if n.endswith("-e") else "w" if n.endswith("-w") else "x"
    pick = None
    for want in (("lts",) if lts else ()) + (("e",) if ent else ("w",)) + ("x",):
        sel = [r for r in cand if kind(r) == want and (("iot" in r["name"]) == iot or want != "lts")]
        if sel:
            pick = sel[0]
            break
    if pick is None:
        pick = cand[0]
    known = ent or any(x in low for x in ("pro", "home", "professional", "домашн", "pro n", "business"))
    return OsHit("windows", pick["name"], "high" if known or kind(pick) == "x" else "name", "" if known or kind(pick) == "x" else "Редакция Windows не указана в KSC: принята Pro/Home («W»)")


def os_release(name: str, major=None, minor=None, build=None, *, windows_releases: list[dict] | None = None) -> OsHit | None:
    """Продукт и ветка endoflife.date для ОС устройства или None, если определить нельзя."""
    n = (name or "").strip()
    if not n:
        return None
    m = _WS_YEAR.search(n)
    if m:
        return OsHit("windows-server", m.group(1) + ("-r2" if m.group(2) else ""), "high")
    if re.search(r"windows\s+server", n, re.I):
        return None                                           # Server Core/SAC без года в названии — по номеру сборки не определяется надёжно
    if _WIN.search(n):
        return windows_release(windows_releases or [], n, major, minor, build)
    m = _UBUNTU.search(n)
    if m:
        return OsHit("ubuntu", m.group(1), "high")
    m = _DEBIAN.search(n)
    if m:
        return OsHit("debian", m.group(1), "high")
    m = _CENTOS_STREAM.search(n)
    if m:
        return OsHit("centos-stream", m.group(1), "high")
    for rx, prod in ((_RHEL, "rhel"), (_ALMA, "almalinux"), (_ROCKY, "rocky-linux"), (_ORACLE, "oracle-linux"), (_CENTOS, "centos")):
        m = rx.search(n)
        if m:
            return OsHit(prod, m.group(m.lastindex), "high")
    m = _SLES.search(n)
    if m:
        return OsHit("sles", m.group(1) + (f".{m.group(2)}" if m.group(2) else ""), "high")
    return None
