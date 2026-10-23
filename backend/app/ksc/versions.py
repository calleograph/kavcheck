"""Сравнение версий. Один алгоритм на все программы не годится, поэтому схем две:
* dpkg — пакеты Linux: epoch:upstream-revision, '~' меньше конца строки, числа сравниваются как числа (8.10 > 8.9);
* numeric — программы Windows и прочие точечные версии: части сравниваются как числа, недостающие части равны нулю (130 = 130.0.0.0),
  буквенный хвост после чисел — предварительная версия (rc, beta…) меньше выпуска, а прочие буквы (1.1.1w, 9.6p1) — исправление, больше выпуска.
Нестандартная нумерация приводится к обычной преобразованием (transform) до сравнения: Java для Windows пишет 8u401 как 8.0.4010.7,
Python для Windows — 3.12.3 как 3.12.3150.0, пакеты Java 8 в Linux — 1.8.0.392.
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


# ------------------------------------------------------------------------------------------------ схемы и преобразования
SCHEMES = ("dpkg", "numeric")
_PRE = {"alpha", "a", "beta", "b", "rc", "pre", "preview", "dev", "snapshot", "ea", "m"}


def _tokens(v: str) -> list[str]:
    return re.findall(r"\d+|[A-Za-z]+", v or "")


def compare_numeric(a: str, b: str) -> int:
    ta, tb = _tokens(a), _tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else None
        y = tb[i] if i < len(tb) else None
        if x == y:
            continue
        if x is None or y is None:
            other, sign = (y, 1) if x is None else (x, -1)      # sign: какой знак вернуть, если «лишняя» часть делает версию больше
            if other.isdigit():
                if int(other) == 0 and all((t.isdigit() and int(t) == 0) for t in (tb if x is None else ta)[i:]):
                    return 0
                return -sign
            return sign if other.lower() in _PRE else -sign
        if x.isdigit() and y.isdigit():
            if int(x) != int(y):
                return -1 if int(x) < int(y) else 1
            continue
        if x.isdigit() != y.isdigit():                         # число против букв: предварительная версия меньше
            alpha = y if x.isdigit() else x
            if alpha.lower() in _PRE:
                return 1 if x.isdigit() else -1
            return 1 if x.isdigit() else -1
        if x.lower() != y.lower():
            xp, yp = x.lower() in _PRE, y.lower() in _PRE
            if xp != yp:
                return -1 if xp else 1
            return -1 if x.lower() < y.lower() else 1
    return 0


def transform(version: str, kind: str | None) -> str:
    """Приведение нестандартной нумерации к обычной (до сравнения)."""
    v = (version or "").strip()
    if not kind or not v:
        return v
    if kind == "java":
        m = re.match(r"^1\.(\d+)\.(.*)$", v)                     # 1.8.0.392 / 1.8.0_401 → 8.0.392
        if m and int(m.group(1)) <= 8:
            v = f"{m.group(1)}.{m.group(2)}".replace("_", ".")
        m = re.match(r"^([78])\.0\.(\d{2,})\d\.\d+$", v)          # Windows: 8.0.4010.7 → 8.0.401
        if m:
            return f"{m.group(1)}.0.{m.group(2)}"
        return v
    if kind == "python":
        m = re.match(r"^(\d+)\.(\d+)\.(\d{4,})(?:\.\d+)?$", v)       # Windows: 3.12.3150.0 → 3.12.3
        if m:
            return f"{m.group(1)}.{m.group(2)}.{int(m.group(3)) // 1000}"
        return v
    return v


def effective(version: str, scheme: str, kind: str | None = None, full: bool = False) -> str:
    """Версия для сравнения: для dpkg — без эпохи и ревизии пакета (full=True — полная строка), затем преобразование."""
    v = (version or "").strip()
    if scheme == "dpkg" and not full:
        v = upstream(v)
    return transform(v, kind)


def compare_by(a: str, b: str, scheme: str) -> int:
    return compare(a, b) if scheme == "dpkg" else compare_numeric(a, b)


def scheme_for(platform_mask: int | None, override: str | None = None) -> str:
    """Схема записи реестра: пакеты Linux (маска 2) — dpkg, остальное — numeric."""
    if override in SCHEMES:
        return override
    return "dpkg" if int(platform_mask or 0) & 2 and not int(platform_mask or 0) & 1 else "numeric"


# ------------------------------------------------------------------------------------------------ условия проверки
OPS = ("lt", "le", "eq", "ge", "gt", "range", "any")
OP_TITLES = {"lt": "ниже", "le": "ниже или равна", "eq": "равна", "ge": "не ниже", "gt": "выше", "range": "в диапазоне", "any": "любая"}


def condition_text(op: str, value: str | None = None, vmin: str | None = None, vmax: str | None = None) -> str:
    if op == "range":
        return f"от {vmin or '…'} до {vmax or '…'} включительно"
    if op == "any":
        return "любая версия"
    return f"{OP_TITLES.get(op, op)} {value or ''}".strip()


def _needs_full(threshold: str | None) -> bool:
    """Граница с ревизией или эпохой (7.4.33-1+deb11u5, 1:9.6p1) сравнивается с полной версией пакета."""
    return bool(threshold) and ("-" in threshold or re.match(r"^\d+:", threshold) is not None)


def matches(version: str, op: str, value: str | None = None, vmin: str | None = None, vmax: str | None = None, *,
            scheme: str = "numeric", kind: str | None = None) -> bool:
    """Подходит ли версия под условие. Сравнивается версия записи после приведения (effective) с границей, приведённой тем же способом."""
    if op == "any":
        return True
    bounds = [x for x in (value, vmin, vmax) if x]
    full = scheme == "dpkg" and any(_needs_full(x) for x in bounds)
    v = effective(version, scheme, kind, full=full)
    if not v:
        return False

    def c(t: str) -> int:
        return compare_by(v, transform(t.strip(), kind), scheme)

    if op == "range":
        return (not vmin or c(vmin) >= 0) and (not vmax or c(vmax) <= 0)
    if not value:
        return False
    r = c(value)
    return {"lt": r < 0, "le": r <= 0, "eq": r == 0, "ge": r >= 0, "gt": r > 0}.get(op, False)


def excluded(version: str, excludes: list[str] | None, *, scheme: str = "numeric", kind: str | None = None) -> bool:
    """Исключение конкретной сборки (7.4.33) или ветки (7.4, 7.4.*): ветка — совпадение начала версии по границе части."""
    if not excludes:
        return False
    full_v = (version or "").strip()
    v = effective(version, scheme, kind)
    for raw in excludes:
        e = (raw or "").strip().rstrip("*").rstrip(".").strip()
        if not e:
            continue
        if full_v == e or v == e or compare_by(v, transform(e, kind), scheme) == 0:
            return True
        if re.match(rf"^{re.escape(e)}([.\-+~_:]|$)", v) or re.match(rf"^{re.escape(e)}([.\-+~_:]|$)", full_v):
            return True
    return False


def in_range(v: str, min_version: str | None, max_version: str | None, below_version: str | None) -> bool:
    """min ≤ v ≤ max и v < below (диапазон «7.x»: min=7, below=8; граница 7.99 неверна — пропускает 7.100)."""
    if min_version and compare(v, min_version) < 0:
        return False
    if max_version and compare(v, max_version) > 0:
        return False
    return not (below_version and compare(v, below_version) >= 0)
