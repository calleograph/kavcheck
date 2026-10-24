"""Сопоставление затронутых продуктов из баз уязвимостей с каталогом установленного ПО и оценка версий.

Вывод по каждой паре «уязвимость × продукт каталога × версия» — один из статусов:
  confirmed    подтверждено источником — продукт сопоставлен надёжно (встроенное соответствие, решение администратора или точное совпадение названия и производителя),
               а источник явно указывает диапазон или версию, в которую входит установленная;
  potential    потенциально затронуто — версия входит в диапазон источника, но продукт сопоставлен только по названию (производитель не подтверждён);
  clarify      требуется уточнение — источник не указывает версии (CISA KEV), уязвимость зависит от среды или редакции, версию нельзя сравнить, пакет Linux (исправление могло быть перенесено в версию дистрибутива);
  fixed        исправлено — источник (OSV для пакета дистрибутива) указывает версию с исправлением, установленная не ниже;
  insufficient данных недостаточно — продукт найден, но у установленной записи нет пригодной версии.
Совпадение по одному названию никогда не даёт «подтверждено»."""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ksc import versions as V
from ..models import CatalogProduct, VdbAffected, VdbMapping, VdbSource
from .aliases import ALIASES
from .normalize import norm, tokens
from .store import active

STATUS_RU = {"confirmed": "Подтверждено источником", "potential": "Потенциально затронуто", "clarify": "Требуется уточнение", "fixed": "Исправлено", "insufficient": "Данных недостаточно"}
STATUS_RANK = {"confirmed": 5, "potential": 4, "clarify": 3, "insufficient": 2, "fixed": 1}
AFFECTED = ("confirmed", "potential", "clarify", "insufficient")      # статусы, при которых компьютеры попадают в результат проверки
_SAFE_VER = re.compile(r"^[0-9]+([.\-_+~:][0-9a-z]+)*$", re.I)
_JAVA_U = re.compile(r"^\d+u\d+$", re.I)


@dataclass
class CatProd:
    key: str
    name: str
    publisher: str
    publisher_key: str
    platforms: int
    scheme: str
    family_key: str
    component: bool
    names: list[str]
    versions: list[dict]
    hosts_active: int
    installs_active: int
    tokens: set[str] = field(default_factory=set)
    sigs: set[str] = field(default_factory=set)

    @property
    def root(self) -> bool:
        return not self.family_key or self.family_key == self.key


def load_catalog(rows: list[CatalogProduct]) -> list[CatProd]:
    out = []
    for r in rows:
        pub_tokens = set(tokens(r.publisher)) | set(tokens(r.publisher_key.replace("-", " ")))
        name_tokens = [t for t in tokens(r.name) if t not in pub_tokens] or tokens(r.name)
        p = CatProd(key=r.key, name=r.name, publisher=r.publisher, publisher_key=r.publisher_key, platforms=r.platforms, scheme=r.scheme, family_key=r.family_key, component=r.component,
                    names=[n[0] if isinstance(n, list) else str(n) for n in (r.names or [])][:40], versions=r.versions or [], hosts_active=r.hosts_active, installs_active=r.installs_active)
        p.tokens = set(name_tokens)
        p.sigs = {norm(" ".join(name_tokens)), norm(r.name), norm(r.key)} - {""}
        if r.platforms & 2:
            p.sigs |= {norm(n) for n in p.names}
        out.append(p)
    return out


@dataclass
class Link:
    prod: CatProd
    confidence: str          # mapped | high | medium


class Matcher:
    def __init__(self, products: list[CatProd], mappings: list[VdbMapping]):
        self.by_key = {p.key: p for p in products}
        self.by_sig: dict[str, list[CatProd]] = {}
        self.by_token: dict[str, list[CatProd]] = {}
        for p in products:
            for s in p.sigs:
                self.by_sig.setdefault(s, []).append(p)
            if p.root and not p.component:
                for t in p.tokens:
                    self.by_token.setdefault(t, []).append(p)
        self.maps: dict[tuple[str, str], list[str]] = {}
        self.excl: set[tuple[str, str, str]] = set()
        for m in mappings:
            if m.action == "exclude":
                self.excl.add((m.vendor_key, m.product_key, m.catalog_key))
            else:
                self.maps.setdefault((m.vendor_key, m.product_key), []).append(m.catalog_key)

    def links(self, vendor: str, product: str, pkg_name: str = "", ecosystem: str = "") -> list[Link]:
        vk, pk = norm(vendor), norm(product or pkg_name)
        out: dict[str, Link] = {}

        def add(p: CatProd | None, conf: str) -> None:
            if p is not None and (vk, pk, p.key) not in self.excl and ("", pk, p.key) not in self.excl:
                cur = out.get(p.key)
                if cur is None or ("mapped", "high", "medium").index(conf) < ("mapped", "high", "medium").index(cur.confidence):
                    out[p.key] = Link(p, conf)
        for key in self.maps.get((vk, pk), []) + self.maps.get(("", pk), []):
            add(self.by_key.get(key), "mapped")
        add(self.by_key.get(ALIASES.get((vk, pk), "")), "high")
        if ecosystem and pkg_name:                      # пакет дистрибутива: точное имя пакета среди продуктов Linux
            for p in self.by_sig.get(norm(pkg_name), []):
                if p.platforms & 2:
                    add(p, "high")
        if not out:
            vtok = set(tokens(vendor))
            for p in self.by_sig.get(pk, []):
                pub = set(tokens(p.publisher)) | set(tokens(p.publisher_key.replace("-", " ")))
                vendor_ok = bool(vtok & pub) or bool(vtok & p.tokens) or not p.publisher
                add(p, "high" if vendor_ok and p.publisher else "medium")
            if not out:
                ptok = set(tokens(product or pkg_name))
                if ptok:
                    cands = None
                    for t in ptok:
                        s = {p.key for p in self.by_token.get(t, [])}
                        cands = s if cands is None else cands & s
                    for k in sorted(cands or [])[:5]:
                        add(self.by_key[k], "medium")
        return list(out.values())


# ------------------------------------------------------------------------------------------------ версии
def comparable(v: str) -> bool:
    return bool(v) and bool(_SAFE_VER.match(v)) and not _JAVA_U.match(v)


def verdict(version: str, scheme: str, a) -> tuple[str, str]:
    """Входит ли установленная версия в затронутые: ('yes'|'no'|'unknown', пояснение). `a` — строка vdb_affected."""
    if not version or not re.search(r"\d", version):
        return "unknown", "у установленной записи нет пригодной версии"
    cmp = lambda x, y: V.compare_by(x, y, scheme)  # noqa: E731
    try:
        if a.exact:
            if not comparable(a.exact):
                return "unknown", f"версия «{a.exact}» источника не сопоставима с номером установленной"
            return ("yes", f"точная версия {a.exact}") if cmp(version, a.exact) == 0 else ("no", "")
        if a.v_start or a.v_end:
            for b in (a.v_start, a.v_end):
                if b and not comparable(b):
                    return "unknown", f"граница «{b}» источника не сопоставима с номером установленной версии"
            if a.v_start and (cmp(version, a.v_start) < 0 or (cmp(version, a.v_start) == 0 and not a.v_start_incl)):
                return "no", ""
            if a.v_end:
                c = cmp(version, a.v_end)
                if c > 0 or (c == 0 and not a.v_end_incl):
                    return "no", ("fixed" if a.fixed else "")
            lo = f"{'≥' if a.v_start_incl else '>'} {a.v_start}" if a.v_start else ""
            hi = f"{'≤' if a.v_end_incl else '<'} {a.v_end}" if a.v_end else ""
            return "yes", "версия " + " и ".join(x for x in (lo, hi) if x)
    except Exception:  # noqa: BLE001 — нестандартные номера не должны ронять анализ
        return "unknown", "версию не удалось сравнить"
    if a.versions_all:
        return "yes", "источник не ограничивает версии: затронуты все" if not a.version_text else a.version_text
    return "unknown", a.version_text or "границы версий не указаны"


def platform_ok(a, mask: int) -> bool | None:
    """Совпадает ли платформа записи источника с платформой установленного ПО (None — не задана)."""
    p = a.platform
    if not p or p.startswith("plugin:"):
        return None
    bit = {"windows": 1, "linux": 2}.get(p)
    return None if bit is None else bool(mask & bit)


@dataclass
class Claim:
    source: str
    ext_id: str
    status: str
    basis: str
    confidence: str


def evaluate(version: dict, prod: CatProd, link: Link, a) -> Claim | None:
    """Оценка одной записи источника для одной версии каталога; None — запись версию не затрагивает."""
    ver = version.get("version") or ""
    scheme = version.get("scheme") or prod.scheme
    mask = int(version.get("platform") or prod.platforms or 0)
    if platform_ok(a, mask) is False:
        return None
    rel = re.match(r"^Debian:(\d+)$", a.ecosystem or "")
    mm = re.search(r"~deb(\d+)u", ver)
    if rel and mm and rel.group(1) != mm.group(1):        # исправление другого выпуска дистрибутива к этой сборке не относится
        return None
    v, basis = verdict(ver, scheme, a)
    if v == "no":
        if basis == "fixed":
            return Claim(a.source, a.ext_id, "fixed", f"исправлено в {a.fixed} (дистрибутив)", link.confidence) if mask & 2 else None
        return None
    if v == "unknown":
        return Claim(a.source, a.ext_id, "insufficient" if not ver or not re.search(r"\d", ver) else "clarify", basis, link.confidence)
    if a.conditional or a.platform.startswith("plugin:"):
        env = f" (среда: {a.platform[7:]})" if a.platform.startswith("plugin:") else ""
        return Claim(a.source, a.ext_id, "clarify", f"{basis}; уязвимость зависит от среды или редакции{env}" + (f"; {a.version_text}" if a.version_text else ""), link.confidence)
    upstream = a.source in ("nvd", "bdu", "kev") and bool(mask & 2) and not a.ecosystem
    if upstream:
        return Claim(a.source, a.ext_id, "clarify", f"{basis}; пакет Linux: исправление могло быть перенесено в версию дистрибутива — сверьте с бюллетенем дистрибутива", link.confidence)
    if a.versions_all and not (a.v_start or a.v_end or a.exact):      # источник называет только продукт (CISA KEV): версия неизвестна — решение за специалистом
        return Claim(a.source, a.ext_id, "clarify", f"{basis}; сверьте версию с описанием уязвимости", link.confidence)
    if link.confidence in ("mapped", "high"):
        return Claim(a.source, a.ext_id, "confirmed", basis, link.confidence)
    return Claim(a.source, a.ext_id, "potential", f"{basis}; продукт сопоставлен только по названию", link.confidence)


@dataclass
class Match:
    vuln_key: str
    product_key: str
    product_name: str
    version: str
    product_ids: list[int]
    status: str
    confidence: str
    claims: list[Claim]
    hosts_active: int
    installs_active: int
    basis: str = ""


def combine(claims: list[Claim]) -> tuple[str, str]:
    """Итоговый статус: исправление дистрибутива (OSV) важнее данных об upstream; иначе — сильнейший из остальных."""
    if any(c.status == "fixed" for c in claims):
        affected = [c for c in claims if c.status in ("confirmed", "potential") and c.source == "osv"]
        if not affected:
            fx = next(c for c in claims if c.status == "fixed")
            return "fixed", fx.basis
    best = max(claims, key=lambda c: STATUS_RANK[c.status])
    return best.status, best.basis


async def load_context(db: AsyncSession, source_id: uuid.UUID | None) -> tuple[list[CatProd], list[VdbMapping]]:
    rows = (await db.execute(select(CatalogProduct).where(CatalogProduct.source_id == source_id))).scalars().all() if source_id else []
    maps = (await db.execute(select(VdbMapping))).scalars().all()
    return load_catalog(rows), list(maps)


async def affected_for(db: AsyncSession, keys: list[str]) -> list[VdbAffected]:
    out: list[VdbAffected] = []
    for i in range(0, len(keys), 400):
        out += (await db.execute(select(VdbAffected).join(VdbSource, active(VdbAffected)).where(VdbAffected.vuln_key.in_(keys[i:i + 400])))).scalars().all()
    return out


def matches_from(matcher: Matcher, affs: list[VdbAffected], *, only_active: bool = True) -> list[Match]:
    """Все сопоставления для набора записей источников. Версии, которых нет на компьютерах за период активности, пропускаются (only_active)."""
    grouped: dict[tuple[str, str, str], list[Claim]] = {}
    meta: dict[tuple[str, str, str], tuple[CatProd, dict, str]] = {}
    link_cache: dict[tuple[str, str, str, str], list[Link]] = {}
    def links_of(a) -> list[Link]:
        lk = (a.vendor, a.product, a.pkg_name, a.ecosystem)
        if lk not in link_cache:
            link_cache[lk] = matcher.links(a.vendor, a.product, a.pkg_name, a.ecosystem)
        return link_cache[lk]

    # CISA KEV называет только производителя и продукт, без версий: он отмечает эксплуатацию, но не расширяет круг версий, если другой источник уже указал границы для этого продукта
    covered = {(a.vuln_key, link.prod.key) for a in affs if a.source != "kev" for link in links_of(a)}
    for a in affs:
        for link in links_of(a):
            if a.source == "kev" and (a.vuln_key, link.prod.key) in covered:
                continue
            for ver in link.prod.versions:
                if only_active and not ver.get("hosts_active"):
                    continue
                claim = evaluate(ver, link.prod, link, a)
                if claim is None:
                    continue
                k = (a.vuln_key, link.prod.key, ver.get("version") or "")
                grouped.setdefault(k, []).append(claim)
                meta[k] = (link.prod, ver, link.confidence)
    out = []
    for k, claims in grouped.items():
        prod, ver, conf = meta[k]
        status, basis = combine(claims)
        out.append(Match(k[0], prod.key, prod.name, k[2], list(ver.get("product_ids") or []), status, conf, claims, int(ver.get("hosts_active") or 0), int(ver.get("installs_active") or 0), basis))
    return out


def candidate_product_keys(prods: list[M.CatProd]) -> set[str]:
    """Значения vdb_affected.product_key, которые могут относиться к продуктам каталога (для обратного поиска без перебора всей базы)."""
    keys: set[str] = set()
    rev: dict[str, list[str]] = {}
    for (_v, pk), ck in ALIASES.items():
        rev.setdefault(ck, []).append(pk)
    for p in prods:
        keys |= p.sigs | set(rev.get(p.key, []))
        toks = sorted(p.tokens)
        keys |= set(toks)
        words = [t for t in tokens(p.name)]
        for i in range(len(words)):
            for j in range(i + 1, min(len(words), i + 3) + 1):
                keys.add(norm("_".join(words[i:j])))
    return {k for k in keys if k}



async def reverse_affected(db: AsyncSession, prods: list[CatProd], maps: list[VdbMapping] | tuple = ()) -> list[VdbAffected]:
    """Записи источников, которые могут относиться к продуктам каталога (поиск по индексам product_key и pkg_name), дополненные всеми записями найденных уязвимостей:
    подтверждение или исправление может прийти из другого источника."""
    have = {p.key for p in prods}
    cand = sorted(candidate_product_keys(prods) | {x.product_key for x in maps if x.action == "map" and x.catalog_key in have})     # решения администратора добавляют свои названия
    pkgs = sorted({norm(x) for p in prods if p.platforms & 2 for x in p.names} - {""})
    found: set[str] = set()
    for i in range(0, len(cand), 400):
        found |= set((await db.execute(select(VdbAffected.vuln_key).join(VdbSource, active(VdbAffected)).where(VdbAffected.product_key.in_(cand[i:i + 400])).distinct())).scalars().all())
    for i in range(0, len(pkgs), 400):
        found |= set((await db.execute(select(VdbAffected.vuln_key).join(VdbSource, active(VdbAffected)).where(VdbAffected.pkg_name.in_(pkgs[i:i + 400])).distinct())).scalars().all())
    return await affected_for(db, sorted(found))
