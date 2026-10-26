"""Единый поиск по устройствам: имя, FQDN, IP-адрес, логин — в одной строке. Несколько значений через пробел, запятую или точку с запятой (любое из них подходит).
Адреса IPv4: один адрес, сеть CIDR (`10.20.0.0/16`), диапазон (`10.1.2.5-10.1.2.40`, `10.1.2.5-40`), маска по октетам (`10.1.*`, `10.1.2.*`); адрес в KSC хранится числом
(первый октет в старшем байте), поэтому отбор — по диапазону чисел, а не по тексту. Всё остальное — текст с масками `*` (правила — в search.py). Пределы: не более 20 значений."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .search import MaskError, clean

MAX_TOKENS = 20
_IP = r"(?:\d{1,3}\.){3}\d{1,3}"
_RANGE_FULL = re.compile(rf"^({_IP})-({_IP})$")
_RANGE_SHORT = re.compile(rf"^((?:\d{{1,3}}\.){{3}})(\d{{1,3}})-(\d{{1,3}})$")
_OCTET_MASK = re.compile(r"^(\d{1,3})(?:\.(\d{1,3}|\*)){0,3}$")


@dataclass(frozen=True)
class Token:
    text: str                  # исходное значение (для текстового поиска)
    lo: int | None = None      # границы числового диапазона адресов (включительно); None — текстовое значение
    hi: int | None = None

    @property
    def is_net(self) -> bool:
        return self.lo is not None


def _ip(s: str) -> int:
    return int(ipaddress.IPv4Address(s))


def parse_token(t: str) -> Token:
    try:
        if "/" in t:
            net = ipaddress.IPv4Network(t, strict=False)
            return Token(t, int(net.network_address), int(net.broadcast_address))
        m = _RANGE_FULL.match(t)
        if m:
            lo, hi = _ip(m.group(1)), _ip(m.group(2))
            if lo > hi:
                raise MaskError(f"Диапазон «{t}»: начало больше конца")
            return Token(t, lo, hi)
        m = _RANGE_SHORT.match(t)
        if m:
            lo, hi = _ip(m.group(1) + m.group(2)), _ip(m.group(1) + m.group(3))
            if lo > hi:
                raise MaskError(f"Диапазон «{t}»: начало больше конца")
            return Token(t, lo, hi)
        if re.fullmatch(_IP, t):
            a = _ip(t)
            return Token(t, a, a)
        if "*" in t and _OCTET_MASK.match(t):                        # «10.1.*», «10.*.*.5» не поддерживается: звёздочка допустима только в конце
            parts = t.split(".")
            fixed = [p for p in parts if p != "*"]
            if "*" in parts and parts.index("*") == len(fixed) and len(parts) <= 4:
                base = [int(p) for p in fixed] + [0] * (4 - len(fixed))
                top = [int(p) for p in fixed] + [255] * (4 - len(fixed))
                lo, hi = _ip(".".join(map(str, base))), _ip(".".join(map(str, top)))
                return Token(t, lo, hi)
    except MaskError:
        raise
    except ipaddress.AddressValueError as exc:
        raise MaskError(f"Некорректный адрес «{t}»") from exc
    except ipaddress.NetmaskValueError as exc:
        raise MaskError(f"Некорректная маска сети «{t}»") from exc
    except ValueError as exc:
        raise MaskError(f"Некорректное значение «{t}»") from exc
    return Token(t)


def parse(text: str | None) -> list[Token]:
    """Значения запроса; пустой запрос — пустой список (отбор не нужен)."""
    raw = (text or "").strip()
    if not raw:
        return []
    parts = [p for p in re.split(r"[\s,;]+", raw) if p]
    if len(parts) > MAX_TOKENS:
        raise MaskError(f"Не более {MAX_TOKENS} значений в одном поиске")
    if any(not clean(p) for p in parts):           # «*» подходит всему: при условии «любое из значений» отбор не нужен
        return []
    return [parse_token(clean(p)) for p in parts]
