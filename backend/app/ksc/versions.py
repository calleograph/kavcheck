"""Сравнение версий по алгоритму dpkg: epoch:upstream-revision, '~' меньше конца строки, числа сравниваются как числа.
Для Windows и RPM тот же алгоритм правильно сравнивает точечные версии (8.10 > 8.9).
shortcut: отличия rpmvercmp (буквы против цифр, '^') не учтены — уточнить при появлении таких версий."""
from __future__ import annotations

import re
from functools import cmp_to_key


def _order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_fragment(a: str, b: str) -> int:
    while a or b:
        na, nb = re.match(r"\D*", a).group(), re.match(r"\D*", b).group()
        for i in range(max(len(na), len(nb))):
            oa = _order(na[i]) if i < len(na) else 0
            ob = _order(nb[i]) if i < len(nb) else 0
            if oa != ob:
                return -1 if oa < ob else 1
        a, b = a[len(na):], b[len(nb):]
        da, db = re.match(r"\d*", a).group(), re.match(r"\d*", b).group()
        if int(da or 0) != int(db or 0):
            return -1 if int(da or 0) < int(db or 0) else 1
        a, b = a[len(da):], b[len(db):]
    return 0


def split(v: str) -> tuple[int, str, str]:
    v = (v or "").strip()
    epoch, _, rest = v.rpartition(":") if re.match(r"^\d+:", v) else ("0", "", v)
    upstream, sep, revision = rest.rpartition("-")
    if not sep:
        upstream, revision = rest, ""
    return int(epoch), upstream, revision


def compare(a: str, b: str) -> int:
    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _cmp_fragment(ua, ub) or _cmp_fragment(ra, rb)


sort_key = cmp_to_key(compare)


def upstream(v: str) -> str:
    """Версия без эпохи и ревизии пакета: '2:8.1+92ubuntu1' -> '8.1+92ubuntu1'; '7.1.33-14+0~2020' -> '7.1.33'."""
    return split(v)[1]


def branch_of(version: str, parts: int = 2) -> str:
    """Ветка major.minor из версии: '7.1.33' -> '7.1'; '70+deb' -> '70' (одна числовая часть — ветка не определена, если parts > 1)."""
    m = re.match(r"(\d+(?:\.\d+){0,%d})" % (parts - 1), upstream(version))
    if not m:
        return ""
    b = m.group(1)
    return b if b.count(".") >= parts - 1 else ""


def compared_version(name: str, version: str, branch_regex: re.Pattern | None) -> str:
    """Версия для фильтров и сводок. Если ветка продукта записана в имени пакета (php7.4-xdebug, libapache2-mod-php8.1, php74-php-cli, rh-php73),
    версия пакета может быть версией расширения (xdebug 3.2) — берём ветку из имени; если версия пакета начинается с этой ветки
    (php7.1-cli 7.1.33), оставляем точную версию. Для остальных пакетов — upstream(version)."""
    up = upstream(version)
    m = branch_regex.match(name or "") if branch_regex else None
    if not m:
        return up
    br = m.group(1) if m.group(1) else ".".join(g for g in m.groups()[1:] if g)
    if not br:
        return up
    return up if re.match(rf"{re.escape(br)}(\.|$|[^\d])", up) else br


def in_range(v: str, min_version: str | None, max_version: str | None, below_version: str | None) -> bool:
    """min ≤ v ≤ max и v < below (диапазон «7.x»: min=7, below=8; граница 7.99 неверна — пропускает 7.100)."""
    if min_version and compare(v, min_version) < 0:
        return False
    if max_version and compare(v, max_version) > 0:
        return False
    return not (below_version and compare(v, below_version) >= 0)
