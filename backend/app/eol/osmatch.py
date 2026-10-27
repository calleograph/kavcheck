"""Определение продукта и ветки endoflife.date по операционной системе устройства KSC.

ОС — самостоятельный объект инвентаризации, а не программа из реестра ПО. Источники сведений (в порядке надёжности):
* название, версия и номер сборки из `v_akpub_host` — для Windows и тех Linux, у которых KSC указывает дистрибутив в названии;
* пакеты `base-files` и `*-release` из реестра ПО — для Linux, у которых KSC отдаёт просто «Linux».

ОС не определяется «по последней версии»: у Windows ветка выбирается по номеру сборки и редакции (Pro/Home — «W», Enterprise/Education — «E», LTSC), у Windows Server — по году выпуска
или, если в названии года нет, по версии и сборке; у Ubuntu, Debian и RHEL-семейства — по номеру выпуска. Если определить нельзя, возвращается `OsMiss` с кодом и понятной причиной:
такое устройство не получает ни ложного «Поддерживается», ни ложного EOL, а видно в списке как «Не удалось определить EOL»."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class OsHit:
    product: str            # слаг endoflife.date
    release: str            # ветка
    confidence: str         # high — название и версия однозначны; name — выбор сделан по неполным признакам (например, неизвестна редакция Windows)
    note: str = ""
    label: str = ""         # человекочитаемое имя ОС для объединения устройств («Ubuntu 22.04»); пусто — берётся название из KSC


@dataclass(frozen=True)
class OsMiss:
    code: str               # no_os | no_build | build_unknown | no_year | linux_no_info | ambiguous | vendor_absent | unrecognized
    reason: str             # причина для пользователя: что именно не удалось и что проверить
    label: str = ""         # лучшее известное имя ОС (для группировки в списке)


OsResult = OsHit | OsMiss

_TM = re.compile(r"[®™©]|\((?:r|tm|c)\)", re.I)
_WS_YEAR = re.compile(r"windows\s+(?:nt\s+)?server\s*(?:version\s+)?(2000|2003|2008|2012|2016|2019|2022|2025)(\s*r2)?", re.I)
_WS_SAC = re.compile(r"windows\s+server\s*,?\s*version\s+(\d{4}|\d{2}h\d)\b", re.I)
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
_NOT_IN_EOL = re.compile(r"astra|альт|\balt\b|red\s*os|ред\s*ос|\brosa\b|роса|гослинукс|goslinux|аврора|aurora", re.I)

# версии клиентских Windows 7–XP не различают редакции: ветка одна; (главная.дополнительная) → семейство, если сборка не передана
_OLD_CLIENT = {"7": "7-sp1", "8.1": "8.1", "8": "8", "vista": "6-sp2", "xp": "5-sp3"}
# серверные Windows по версии ядра, когда года в названии нет: (major, minor) → (год, R2)
_SERVER_BY_KERNEL = {(5, 2): ("2003", False), (6, 0): ("2008", False), (6, 1): ("2008", True), (6, 2): ("2012", False), (6, 3): ("2012", True)}
# base-files Ubuntu: начало версии пакета → выпуск. Интерим-выпуски (22.10, 23.04…) используют соседние номера, поэтому однозначны только перечисленные формы
_UBUNTU_BASE_FILES = ((re.compile(r"^6\.5ubuntu"), "12.04"), (re.compile(r"^7\.2ubuntu"), "14.04"), (re.compile(r"^9\.4ubuntu"), "16.04"), (re.compile(r"^10\.1ubuntu"), "18.04"),
                      (re.compile(r"^11ubuntu"), "20.04"), (re.compile(r"^12ubuntu"), "22.04"), (re.compile(r"^13ubuntu10(?:\.|$)"), "24.04"))
_RELEASE_PACKAGES = {                      # пакет → (продукт endoflife.date, подпись)
    "centos-stream-release": ("centos-stream", "CentOS Stream"), "centos-release": ("centos", "CentOS"), "almalinux-release": ("almalinux", "AlmaLinux"), "rocky-release": ("rocky-linux", "Rocky Linux"),
    "oraclelinux-release": ("oracle-linux", "Oracle Linux"), "redhat-release": ("rhel", "Red Hat Enterprise Linux"), "redhat-release-server": ("rhel", "Red Hat Enterprise Linux"),
    "redhat-release-workstation": ("rhel", "Red Hat Enterprise Linux"), "redhat-release-client": ("rhel", "Red Hat Enterprise Linux"), "redhat-release-computenode": ("rhel", "Red Hat Enterprise Linux"),
    "fedora-release": ("fedora", "Fedora"), "sles-release": ("sles", "SUSE Linux Enterprise Server"), "sled-release": ("sles", "SUSE Linux Enterprise Server"),
}
RELEASE_PACKAGE_NAMES = tuple(["base-files", "astra-version", *_RELEASE_PACKAGES])      # какие пакеты читать из реестра ПО Linux-устройств


def clean_name(name) -> str:
    """Название ОС без знаков товарных марок, лишних пробелов и приставки производителя: «Microsoft® Windows® Server 2008 R2» → «Windows Server 2008 R2»."""
    n = _TM.sub("", str(name or ""))
    n = re.sub(r"\s+", " ", n).strip()
    return re.sub(r"^(microsoft|майкрософт)\s+", "", n, flags=re.I)


def display_name(name) -> str:
    n = clean_name(name)
    return f"Microsoft {n}" if n.lower().startswith("windows") else n


def _names(releases: dict | None, product: str) -> list[str]:
    return [r["name"] for r in (releases or {}).get(product, [])]


def _pick_server(names: list[str], year: str, r2: bool) -> str | None:
    """Ветка Windows Server по году: у 2003/2008/2008 R2 endoflife.date хранит ветки с Service Pack (`2008-sp2`, `2008-r2-sp1`), у остальных — просто год. Берётся последний Service Pack."""
    base = year + ("-r2" if r2 else "")
    sp = sorted((n for n in names if n.startswith(base + "-sp") and (r2 or "r2" not in n)), key=lambda n: int(re.sub(r"\D", "", n.rsplit("-sp", 1)[1]) or 0), reverse=True)
    if sp:
        return sp[0]
    return base if base in names or not names else None


def server_release(releases: dict | None, name: str, major, minor, build) -> OsResult:
    names = _names(releases, "windows-server")
    m = _WS_YEAR.search(name)
    label = f"Windows Server {m.group(1)}{' R2' if m.group(2) else ''}" if m else "Windows Server"
    if m:
        rel = _pick_server(names, m.group(1), bool(m.group(2)))
        if rel is None:
            return OsMiss("build_unknown", f"Ветка «{label}» отсутствует в базе endoflife.date: обновите базу EOL", label)
        return OsHit("windows-server", rel, "high", "", label)
    if _WS_SAC.search(name):
        v = _WS_SAC.search(name).group(1).lower()                          # полугодовой канал: «Windows Server, version 1809»
        for cand in (f"{v}-sac", v):
            if cand in names:
                return OsHit("windows-server", cand, "high", "", f"Windows Server {v.upper()} (SAC)")
    try:
        key = (int(major), int(minor))
    except (TypeError, ValueError):
        key = (0, 0)
    if key in _SERVER_BY_KERNEL:
        year, r2 = _SERVER_BY_KERNEL[key]
        rel = _pick_server(names, year, r2)
        if rel:
            lab = f"Windows Server {year}{' R2' if r2 else ''}"
            return OsHit("windows-server", rel, "name", "Год выпуска Windows Server определён по версии ядра, а не по названию", lab)
    if key == (10, 0) and build not in (None, 0, "0", ""):
        full = f"10.0.{build}"
        cand = [r for r in (releases or {}).get("windows-server", []) if r.get("latest_name") == full]
        cand = [r for r in cand if "sac" not in r["name"] and not r["name"].endswith("-ac")] or cand
        if cand:
            return OsHit("windows-server", cand[0]["name"], "name", "Выпуск Windows Server определён по номеру сборки, а не по названию", f"Windows Server {cand[0]['name'].upper()}")
        return OsMiss("build_unknown", f"Сборка Windows Server 10.0.{build} отсутствует в базе endoflife.date (возможно, вышла позже последнего обновления базы)", "Windows Server")
    return OsMiss("no_year", "В названии Windows Server нет года выпуска, а версия ядра и номер сборки не позволяют определить выпуск", "Windows Server")


def windows_release(releases: list[dict], name: str, major, minor, build) -> OsResult:
    """Ветка Windows клиента по сборке (`latest` ветки = «10.0.<сборка>») и редакции. releases — [{name, latest_name}] продукта `windows`."""
    m = _WIN.search(name or "")
    if not m:
        return OsMiss("unrecognized", f"Название «{name}» не распознано как Windows", name)
    fam = m.group(1).lower()
    label = f"Windows {m.group(1)}"
    if fam in _OLD_CLIENT and _OLD_CLIENT[fam] in {r["name"] for r in releases}:
        return OsHit("windows", _OLD_CLIENT[fam], "high", "", label)       # у этих версий ветка одна (последний Service Pack)
    if build in (None, 0, "0", ""):
        return OsMiss("no_build", f"KSC не передал номер сборки {label}: выпуск (например, 22H2) без него определить нельзя, а у Windows 10 и 11 сроки поддержки зависят от выпуска", label)
    full = f"{major or 10}.{minor or 0}.{build}"
    cand = [r for r in releases if r.get("latest_name") == full]
    if fam in ("10", "11"):
        cand = [r for r in cand if r["name"].startswith(fam + "-")] or [r for r in cand if r["name"].startswith(("10-", "11-"))] or cand
    if not cand:
        return OsMiss("build_unknown", f"Сборка {full} ({label}) отсутствует в базе endoflife.date: возможно, выпуск вышел позже последнего обновления базы EOL или это сборка предварительной версии", label)
    low = (name or "").lower()
    ent = any(x in low for x in ("enterprise", "education", "корпоратив", "образоват"))
    lts = any(x in low for x in ("ltsc", "ltsb", "iot", "long-term", "длительн"))
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
    known = ent or any(x in low for x in ("pro", "home", "professional", "домашн", "профессиональ", "business", "starter", "ultimate"))
    return OsHit("windows", pick["name"], "high" if known or kind(pick) == "x" else "name", "" if known or kind(pick) == "x" else "Редакция Windows не указана в KSC: принята Pro/Home («W»)", label)


def linux_release(packages) -> OsResult:
    """Дистрибутив Linux по пакетам реестра ПО: [(имя пакета, версия)]. Сначала `*-release` (точнее), затем `base-files` (Debian: `+debNNu`, Ubuntu: известные формы версии)."""
    pk = {str(n).lower(): str(v or "") for n, v in packages or ()}
    if not pk:
        return OsMiss("linux_no_info", "KSC передаёт для Linux-устройства только название «Linux», а пакетов base-files и *-release в реестре ПО нет (опрос ПО Агентом не выполнен или дистрибутив нестандартный): дистрибутив и версия неизвестны", "Linux")
    for pkg, (prod, title) in _RELEASE_PACKAGES.items():
        v = pk.get(pkg)
        if v is None:
            continue
        m = re.match(r"(\d+(?:\.\d+)?)", v)
        if not m:
            return OsMiss("unrecognized", f"Не удалось разобрать версию пакета {pkg} «{v}»", title)
        rel = m.group(1)
        if prod in ("sles",):
            pass                                                           # 15.4 — ветка endoflife.date как есть
        elif prod == "fedora":
            rel = rel.split(".")[0]
        else:
            rel = rel.split(".")[0]                                        # мажорная версия: 7.9 → 7, 9.3 → 9
        return OsHit(prod, rel, "high", "", f"{title} {rel}")
    if "astra-version" in pk:
        return OsMiss("vendor_absent", "Astra Linux отсутствует в базе endoflife.date: срок поддержки нужно задать вручную", "Astra Linux")
    bf = pk.get("base-files")
    if bf is not None:
        m = re.search(r"\+deb(\d+)u", bf)
        if m:
            return OsHit("debian", m.group(1), "high", "", f"Debian {m.group(1)}")
        if "ubuntu" in bf:
            for rx, rel in _UBUNTU_BASE_FILES:
                if rx.search(bf):
                    return OsHit("ubuntu", rel, "high", "", f"Ubuntu {rel}")
            return OsMiss("ambiguous", f"Версия base-files «{bf}» подходит нескольким выпускам Ubuntu (в том числе промежуточным): точный выпуск не определён", "Ubuntu")
        return OsMiss("ambiguous", f"Версия base-files «{bf}» не позволяет определить дистрибутив (это не Debian-стабильный выпуск и не Ubuntu известной версии)", "Linux")
    return OsMiss("linux_no_info", "Не найден ни один из пакетов base-files или *-release: дистрибутив Linux не определён", "Linux")


def os_release(name: str, major=None, minor=None, build=None, *, platform=None, packages=None, releases: dict | None = None, windows_releases: list[dict] | None = None) -> OsResult:
    """Продукт и ветка endoflife.date для ОС устройства либо `OsMiss` с причиной. releases — {продукт: [{name, latest_name}]} для windows и windows-server (если передать;
    windows_releases — прежняя форма только для windows)."""
    rel = dict(releases or {})
    if windows_releases is not None and "windows" not in rel:
        rel["windows"] = windows_releases
    n = clean_name(name)
    if not n:
        return OsMiss("no_os", "KSC не передал название ОС устройства", "ОС не указана")
    if re.search(r"windows\s+(?:nt\s+)?server|windows\s+server", n, re.I):
        return server_release(rel, n, major, minor, build)
    if _WIN.search(n):
        return windows_release(rel.get("windows", []), n, major, minor, build)
    if re.match(r"windows\b", n, re.I):
        return OsMiss("unrecognized", f"Не удалось определить выпуск Windows по названию «{n}»", display_name(n))
    m = _UBUNTU.search(n)
    if m:
        return OsHit("ubuntu", m.group(1), "high", "", f"Ubuntu {m.group(1)}")
    m = _DEBIAN.search(n)
    if m:
        return OsHit("debian", m.group(1), "high", "", f"Debian {m.group(1)}")
    m = _CENTOS_STREAM.search(n)
    if m:
        return OsHit("centos-stream", m.group(1), "high", "", f"CentOS Stream {m.group(1)}")
    for rx, prod, title in ((_RHEL, "rhel", "Red Hat Enterprise Linux"), (_ALMA, "almalinux", "AlmaLinux"), (_ROCKY, "rocky-linux", "Rocky Linux"), (_ORACLE, "oracle-linux", "Oracle Linux"), (_CENTOS, "centos", "CentOS")):
        m = rx.search(n)
        if m:
            return OsHit(prod, m.group(m.lastindex), "high", "", f"{title} {m.group(m.lastindex)}")
    m = _SLES.search(n)
    if m:
        v = m.group(1) + (f".{m.group(2)}" if m.group(2) else "")
        return OsHit("sles", v, "high", "", f"SUSE Linux Enterprise Server {v}")
    if _NOT_IN_EOL.search(n):
        return OsMiss("vendor_absent", f"«{n}» отсутствует в базе endoflife.date: срок поддержки нужно задать вручную", n)
    if str(platform) == "6" or n.lower().startswith("linux"):
        return linux_release(packages)
    return OsMiss("unrecognized", f"Название ОС «{n}» не распознано: сопоставление с жизненным циклом не выполнено", n)
