"""Нормализация названий и идентификаторов: ключи продуктов, разбор CPE 2.3 и Package URL, оценки опасности."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0, "none": 0}
SEV_RU = {"critical": "Критическая", "high": "Высокая", "medium": "Средняя", "low": "Низкая", "none": "Нет (None)", "": "Нет данных"}
# Основная оценка CVSS (порядок выбора): 1) CVSS 3.x и 4.0 важнее 2.0; 2) оценка аналитиков NVD или БДУ (primary) важнее оценки поставщика (CNA) и вычисленной по вектору;
# 3) из равных — более новая методика (4.0 → 3.1 → 3.0); 4) затем источник (NVD → БДУ → OSV).
VERSION_RANK = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}
SCORE_SOURCES = ("nvd", "bdu", "osv")
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


def sev_from_score(score: float | None, version: str = "3.1") -> str:
    """Уровень по оценке: CVSS 3.x и 4.0 — None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0; CVSS 2.0 не имеет уровней None и Critical (High — от 7.0). Нет оценки — пустая строка."""
    if score is None:
        return ""
    if score <= 0:
        return "none"
    if version == "2.0":
        return "high" if score >= 7 else "medium" if score >= 4 else "low"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def cvss_version(vector: str, default: str = "") -> str:
    """Версия методики по вектору: префикс `CVSS:3.1/`; вектор CVSS 2.0 без префикса (`AV:N/AC:L/Au:N/…`). Неизвестная — `default`."""
    m = re.match(r"CVSS:(\d\.\d)/", vector or "")
    if m:
        return m.group(1) if m.group(1) in VERSION_RANK else default
    if re.search(r"(^|/)Au:[NSM]", vector or ""):
        return "2.0"
    return "3.0" if re.search(r"(^|/)PR:[NLH]/UI:[NR]", vector or "") else default      # БДУ даёт векторы CVSS 3.0 без префикса


def make_score(version: str, score, vector: str = "", *, source: str, origin: str = "", kind: str = "", updated: datetime | None = None) -> dict | None:
    """Одна оценка CVSS для хранения. Недостоверные значения (не число, вне 0–10, неизвестная методика) отбрасываются — ноль вместо отсутствующей оценки не подставляется."""
    try:
        val = round(float(score), 1)
    except (TypeError, ValueError):
        return None
    version = cvss_version(vector, version) or version
    if version not in VERSION_RANK or not 0 <= val <= 10:
        return None
    return {"version": version, "score": val, "vector": (vector or "")[:200], "severity": sev_from_score(val, version), "source": source, "origin": origin[:80], "kind": kind,
            "updated": updated.isoformat() if updated else None}


def score_key(s: dict):
    src = SCORE_SOURCES.index(s["source"]) if s.get("source") in SCORE_SOURCES else len(SCORE_SOURCES)
    return (s["version"] == "2.0", s.get("kind") != "primary", -VERSION_RANK.get(s["version"], 0), src, -s["score"])


def pick_primary(scores: list[dict]) -> dict | None:
    """Основная оценка из всех известных (правило — у VERSION_RANK); остальные остаются в списке и показываются в карточке."""
    return min(scores, key=score_key) if scores else None


def legacy_score(source: str, score, vector: str, updated: datetime | None) -> dict | None:
    """Оценка записи, загруженной до появления списка оценок: версия — по вектору (NVD без префикса — CVSS 2.0), источник оценки — сама запись."""
    return make_score("", score, vector, source=source, kind="primary" if source == "nvd" else "", updated=updated)


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


def set_scores(rec: "Rec", scores: list[dict | None]) -> None:
    """Записать все оценки и по основной из них заполнить score/vector/severity записи; без числовых оценок остаётся уровень, который назвал источник (severity)."""
    rec.scores = [s for s in scores if s]
    main = pick_primary(rec.scores)
    if main:
        rec.score, rec.vector, rec.severity = main["score"], main["vector"], main["severity"]


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
    scores: list[dict] = field(default_factory=list)      # все оценки CVSS записи (см. make_score); score/vector — основная из них
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
