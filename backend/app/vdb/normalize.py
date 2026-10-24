"""Нормализация названий и идентификаторов: ключи продуктов, разбор CPE 2.3 и Package URL, оценки опасности."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}
SEV_RU = {"critical": "Критическая", "high": "Высокая", "medium": "Средняя", "low": "Низкая", "": "Нет оценки"}
STOP = {"the", "for", "of", "and", "inc", "llc", "ltd", "corp", "corporation", "gmbh", "co", "company", "group", "foundation", "project", "team", "software", "systems",
        "windows", "win", "win32", "win64", "x64", "x86", "amd64", "i386", "64", "32", "bit", "64bit", "32bit", "edition", "version", "update", "runtime", "release",
        "ооо", "зао", "ао", "компания", "и"}
_NONWORD = re.compile(r"[^0-9a-zа-яё]+", re.I)


def norm(s: str) -> str:
    """Ключ для сравнения: строчные буквы и цифры, слова через «_»."""
    return _NONWORD.sub("_", (s or "").lower()).strip("_")


def tokens(s: str) -> list[str]:
    """Значимые слова названия: без номеров версий, разрядности, организационных форм."""
    out = []
    for t in _NONWORD.split((s or "").lower()):
        if not t or t in STOP or t.isdigit() or re.fullmatch(r"v?\d+(\.\d+)*", t):
            continue
        out.append(t)
    return out


def sev_from_score(score: float | None) -> str:
    if score is None:
        return ""
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else ""


def parse_dt(v) -> datetime | None:
    """Дата из источника (ISO, с зоной или без; «2024-03-29»; «29.03.2024»); без зоны — UTC."""
    if not v:
        return None
    s = str(v).strip()
    if re.fullmatch(r"\d{2}\.\d{2}\.\d{4}", s):
        return datetime.strptime(s, "%d.%m.%Y").replace(tzinfo=timezone.utc)
    return _iso(s)


def _iso(s: str) -> datetime | None:
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def parse_cpe(cpe: str) -> dict:
    """CPE 2.3 (`cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other`) → поля; экранирование `\\:` снимается."""
    parts = re.split(r"(?<!\\):", cpe or "")
    if len(parts) < 6 or parts[0] != "cpe":
        return {}
    un = lambda x: re.sub(r"\\(.)", r"\1", x)  # noqa: E731
    g = lambda i: un(parts[i]) if len(parts) > i else "*"  # noqa: E731
    return {"part": g(2), "vendor": g(3), "product": g(4), "version": g(5), "update": g(6), "target_sw": g(10)}


def parse_purl(purl: str) -> dict:
    """Package URL `pkg:type/namespace/name@version?qualifiers` → type, namespace, name, version."""
    m = re.match(r"pkg:([^/]+)/(?:(.+)/)?([^/@?#]+)(?:@([^?#]*))?", purl or "")
    return {"type": m.group(1), "namespace": m.group(2) or "", "name": m.group(3), "version": m.group(4) or ""} if m else {}


PLATFORMS = {"windows": "windows", "windows_10": "windows", "windows_11": "windows", "windows_server": "windows", "microsoft_windows": "windows",
             "linux": "linux", "linux_kernel": "linux", "debian": "linux", "ubuntu": "linux", "redhat": "linux", "centos": "linux", "alt": "linux",
             "macos": "macos", "mac_os_x": "macos", "macos_x": "macos", "android": "android", "iphone_os": "ios", "ios": "ios"}


def platform_of(target_sw: str) -> str:
    """Целевая среда CPE: операционная система (windows/linux/…) либо имя продукта, для которого это плагин или модуль; `*` и `-` — не задана."""
    t = norm(target_sw)
    if t in ("", "*", "-"):
        return ""
    if t in PLATFORMS:
        return PLATFORMS[t]
    if t.startswith("windows") or t.startswith("microsoft_windows"):
        return "windows"
    if t.startswith(("linux", "debian", "ubuntu", "redhat", "red_hat", "centos", "suse", "fedora")):
        return "linux"
    return "plugin:" + t


@dataclass
class Aff:
    vendor: str = ""
    product: str = ""
    cpe: str = ""
    purl: str = ""
    ecosystem: str = ""
    pkg_name: str = ""
    platform: str = ""
    exact: str = ""
    v_start: str = ""
    v_start_incl: bool = True
    v_end: str = ""
    v_end_incl: bool = False
    fixed: str = ""
    versions_all: bool = False
    version_text: str = ""
    conditional: bool = False


@dataclass
class Rec:
    source: str
    ext_id: str
    vuln_key: str
    aliases: list[str] = field(default_factory=list)
    title: str = ""
    description: str = ""
    severity: str = ""
    score: float | None = None
    vector: str = ""
    published: datetime | None = None
    modified: datetime | None = None
    exploited: bool = False
    fix_available: bool | None = None
    fix_text: str = ""
    status: str = ""
    refs: list[dict] = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    affected: list[Aff] = field(default_factory=list)


_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44}, "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}


def cvss3_score(vector: str) -> float | None:
    """Базовая оценка CVSS 3.x по вектору (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`); None, если вектор не v3 или неполный. Нужна для источников, дающих только вектор (OSV)."""
    import math  # noqa: PLC0415

    m = dict(p.split(":", 1) for p in (vector or "").split("/") if ":" in p)
    if not str(m.get("CVSS", "")).startswith("3"):
        return None
    try:
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = min(1.08 * (impact + expl), 10) if changed else min(impact + expl, 10)
    return math.ceil(raw * 10 - 1e-9) / 10
