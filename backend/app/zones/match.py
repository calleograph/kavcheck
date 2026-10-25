"""Принадлежность компьютера зоне ответственности.

Зона — набор признаков (сеть/диапазон/адрес, группа KSC, имя) и исключений. Компьютер подходит зоне, если подходит хотя бы одному признаку и не попал в исключение.
Пересечения не прячутся. Порядок решения: закрепление администратором → единственная подходящая зона → зона с единственным наименьшим приоритетом →
иначе «спор»: компьютер виден во всех подходящих зонах с пометкой, а в итогах организации считается один раз.
Сети ищутся по предварительно построенному списку непересекающихся отрезков (бинарный поиск), поэтому тысячи правил и сотни тысяч компьютеров не замедляют разбор."""
from __future__ import annotations

import ipaddress
import re
from bisect import bisect_right
from dataclasses import dataclass, field

from ..search import matcher

KINDS = ("net", "exclude", "group", "name")
KIND_TITLE = {"net": "Сеть или адреса", "exclude": "Исключение", "group": "Группа KSC", "name": "Имя компьютера"}
MAX_RULE_LEN = 300


class RuleError(ValueError):
    """Признак записан неверно; сообщение показывается пользователю."""


V6_BASE = 1 << 32          # IPv6 лежит выше всего IPv4 в одной числовой оси: один индекс обслуживает оба семейства


def _key(addr) -> int:
    return int(addr) if addr.version == 4 else V6_BASE + int(addr)


def _addr(text: str):
    return ipaddress.ip_address(text.strip().strip("[]").split("%", 1)[0])


def parse_net(text: str) -> tuple[int, int]:
    """«192.0.2.0/24», «2001:db8::/32», «192.0.2.10», «192.0.2.10-192.0.2.50», «192.0.2.10-50» → (первый, последний) числами общей оси IPv4+IPv6."""
    t = (text or "").strip().replace(" ", "")
    if not t:
        raise RuleError("пустое значение")
    try:
        if "-" in t:
            a, b = t.split("-", 1)
            first = _addr(a)
            if b.isdigit() and first.version == 4:                 # «…10-50» — последний октет
                lo = _key(first)
                hi = (lo & ~255) | int(b)
                if int(b) > 255:
                    raise ValueError(b)
            else:
                last = _addr(b)
                if last.version != first.version:
                    raise ValueError("смесь IPv4 и IPv6")
                lo, hi = _key(first), _key(last)
        elif "/" in t:
            n = ipaddress.ip_network(t.strip("[]").replace("]/", "/"), strict=False)
            lo, hi = _key(n.network_address), _key(n.broadcast_address)
        else:
            lo = hi = _key(_addr(t))
    except ValueError:
        raise RuleError(f"«{text.strip()}» — не сеть, адрес и не диапазон (примеры: 192.0.2.0/24, 192.0.2.5, 192.0.2.10-192.0.2.50, 2001:db8::/32)") from None
    if hi < lo:
        raise RuleError(f"«{text.strip()}»: конец диапазона меньше начала")
    return lo, hi


def normalize_rule(kind: str, value: str) -> tuple[str, str]:
    """Проверка и приведение признака к единому виду (сеть — к границам CIDR, диапазон — «первый-последний»). Возвращает (вид, значение)."""
    kind = (kind or "").strip().lower()
    v = re.sub(r"\s+", " ", (value or "").strip())
    if kind not in KINDS:
        raise RuleError(f"неизвестный вид признака «{kind}» (допустимо: {', '.join(KINDS)})")
    if not v or len(v) > MAX_RULE_LEN:
        raise RuleError("значение пустое или длиннее 300 символов")
    if kind == "net" or (kind == "exclude" and _looks_net(v)):
        lo, hi = parse_net(v)
        t = v.replace(" ", "")
        v = str(ipaddress.ip_network(t.strip("[]").replace("]/", "/"), strict=False)) if "/" in t and "-" not in t else _range_text(lo, hi)
    else:
        v = re.sub(r"\*{2,}", "*", v)
    return kind, v


def _looks_net(v: str) -> bool:
    """Исключение — адрес или имя? Строка из цифр, a-f, точек, двоеточий, дефисов и косых черт с точкой или двоеточием считается адресом (и тогда проверяется строго)."""
    return bool(re.fullmatch(r"[0-9a-fA-F:./\-\[\] ]+", v)) and ("." in v or ":" in v)


def _unkey(n: int):
    return ipaddress.IPv4Address(n) if n < V6_BASE else ipaddress.IPv6Address(n - V6_BASE)


def _range_text(lo: int, hi: int) -> str:
    a = _unkey(lo)
    return str(a) if lo == hi else f"{a}-{_unkey(hi)}"


def ip_int(ip: str) -> int | None:
    try:
        return _key(_addr(ip or ""))
    except ValueError:
        return None


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(spans):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def _subtract(spans: list[tuple[int, int]], cut: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out = []
    cut = _merge(cut)
    for lo, hi in spans:
        cur = lo
        for clo, chi in cut:
            if chi < cur or clo > hi:
                continue
            if clo > cur:
                out.append((cur, clo - 1))
            cur = max(cur, chi + 1)
            if cur > hi:
                break
        if cur <= hi:
            out.append((cur, hi))
    return out


@dataclass
class ZoneDef:
    id: str
    name: str
    priority: int = 100
    rules: list[tuple[str, str]] = field(default_factory=list)
    enabled: bool = True


@dataclass
class Assignment:
    zone_ids: list[str]                  # пусто — вне зон
    conflict: bool = False               # подходит нескольким зонам и спор не решён
    pinned: bool = False
    candidates: list[str] = field(default_factory=list)   # все подходящие зоны (для показа спора)
    via: str = ""                        # pin | single | priority | conflict | none


class ZoneIndex:
    def __init__(self, zones: list[ZoneDef], pins: dict[tuple[str, int], str] | None = None):
        self.zones = {z.id: z for z in zones if z.enabled}
        self.pins = pins or {}
        self._starts: list[int] = []
        self._sets: list[frozenset[str]] = []
        self._text: dict[str, list] = {}           # зона → [(kind, matcher)] для групп и имён
        self._excl_text: dict[str, list] = {}
        spans: dict[str, list[tuple[int, int]]] = {}
        cuts: dict[str, list[tuple[int, int]]] = {}
        for z in self.zones.values():
            for kind, value in z.rules:
                if kind == "net":
                    spans.setdefault(z.id, []).append(parse_net(value))
                elif kind == "exclude":
                    if _looks_net(value):
                        cuts.setdefault(z.id, []).append(parse_net(value))
                    else:
                        self._excl_text.setdefault(z.id, []).append(matcher(value))
                else:
                    self._text.setdefault(z.id, []).append((kind, matcher(value)))
        events: list[tuple[int, int, str]] = []                  # (граница, +1/-1, зона)
        for zid, sp in spans.items():
            for lo, hi in _subtract(_merge(sp), cuts.get(zid, [])):
                events += [(lo, 1, zid), (hi + 1, -1, zid)]
        events.sort(key=lambda e: (e[0], e[1]))
        cur: dict[str, int] = {}
        i = 0
        while i < len(events):
            pos = events[i][0]
            while i < len(events) and events[i][0] == pos:
                _, d, zid = events[i]
                cur[zid] = cur.get(zid, 0) + d
                if cur[zid] <= 0:
                    cur.pop(zid)
                i += 1
            self._starts.append(pos)
            self._sets.append(frozenset(cur))
        self._cuts = {zid: _merge(c) for zid, c in cuts.items()}

    def _net_hits(self, ips: list[str]) -> set[str]:
        out: set[str] = set()
        for ip in ips:
            n = ip_int(ip)
            if n is None or not self._starts:
                continue
            k = bisect_right(self._starts, n) - 1
            if k >= 0:
                out |= self._sets[k]
        return out

    def candidates(self, *, name: str = "", fqdn: str = "", group: str = "", ips: list[str] | None = None) -> list[str]:
        hits = self._net_hits(ips or [])
        names = [x for x in (name, fqdn) if x]
        for zid, rules in self._text.items():
            if zid in hits:
                continue
            for kind, m in rules:
                if m is None:
                    continue
                if (kind == "group" and m(group)) or (kind == "name" and any(m(x) for x in names)):
                    hits.add(zid)
                    break
        for zid, ms in self._excl_text.items():                  # исключения по имени действуют на любой признак
            if zid in hits and any(m and m(x) for m in ms for x in names):
                hits.discard(zid)
        for zid, cut in self._cuts.items():                      # исключённый адрес выводит и из совпавших по группе/имени
            if zid in hits and any(lo <= (ip_int(ip) or -1) <= hi for ip in (ips or []) for lo, hi in cut):
                hits.discard(zid)
        return sorted(hits, key=lambda z: (self.zones[z].priority, self.zones[z].name.lower()))

    def assign(self, host_id: int | None, source_id: str, *, name: str = "", fqdn: str = "", group: str = "", ips: list[str] | None = None) -> Assignment:
        cand = self.candidates(name=name, fqdn=fqdn, group=group, ips=ips)
        pin = self.pins.get((source_id, int(host_id))) if host_id is not None else None
        if pin and pin in self.zones:
            return Assignment([pin], False, True, cand or [pin], "pin")
        if not cand:
            return Assignment([], via="none")
        if len(cand) == 1:
            return Assignment(cand, candidates=cand, via="single")
        best = [z for z in cand if self.zones[z].priority == self.zones[cand[0]].priority]
        if len(best) == 1:
            return Assignment(best, candidates=cand, via="priority")
        return Assignment(best, True, False, cand, "conflict")


def annotate(records: list[dict], index: ZoneIndex, source_id: str) -> list[dict]:
    """Добавляет каждой записи компьютера zones (идентификаторы), zone_conflict, zone_pinned, zone_candidates. Исходные записи не изменяются."""
    out = []
    for r in records:
        ips = r.get("ips") or ([r["ip"]] if r.get("ip") else [])
        a = index.assign(r.get("host_id"), source_id, name=r.get("name") or "", fqdn=r.get("fqdn") or "", group=r.get("group") or "", ips=ips)
        out.append({**r, "zones": a.zone_ids, "zone_conflict": a.conflict, "zone_pinned": a.pinned, "zone_candidates": a.candidates, "zone_via": a.via})
    return out
