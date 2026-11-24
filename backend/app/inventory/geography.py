"""Сетевое наблюдение и правила принадлежности. Учётная карточка здесь не меняется."""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from pathlib import Path
from typing import Literal, NotRequired, TypedDict
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import and_, func, select

from ..models import InvAsset, InvGeo, InvGeoRule, InvLocation
from ..search import matcher
from ..zones.match import ip_int, normalize_rule, parse_net

FRESH = timedelta(days=7)
LABELS = {"unknown": "Недостаточно данных", "site": "Площадка по правилу", "approx": "Примерно по IP подключения",
          "vpn": "VPN или прокси по правилу", "conflict": "Противоречивые правила"}


class Rule(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    enabled: bool = True
    priority: int = Field(default=100, ge=0, le=10000)
    networks: list[str] = Field(default_factory=list, max_length=24)
    ip_kind: Literal["any", "connection", "device"] = "any"
    source_id: UUID | None = None
    host: str = Field(default="", max_length=200)
    group: str = Field(default="", max_length=300)
    domain: str = Field(default="", max_length=200)
    network_location: str = Field(default="", max_length=200)
    network_id: str = Field(default="", max_length=200)
    type_id: int | None = Field(default=None, gt=0)
    infra_source_id: int | None = Field(default=None, gt=0)
    infra_site: str = Field(default="", max_length=200)
    vpn: bool = False
    site_id: int | None = Field(default=None, gt=0)
    location_id: int | None = Field(default=None, gt=0)
    branch_id: int | None = Field(default=None, gt=0)
    dept_id: int | None = Field(default=None, gt=0)
    resp_id: int | None = Field(default=None, gt=0)
    zone_id: UUID | None = None

    @field_validator("networks")
    @classmethod
    def normalize(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_rule("net", value)[1] for value in values))

    @model_validator(mode="after")
    def complete(self):
        self.name = self.name.strip()
        if not self.name:
            raise ValueError("Укажите название правила")
        if not any(getattr(self, field) for field in ("networks", "source_id", "type_id", "infra_source_id", "infra_site", *MASKS)):
            raise ValueError("Укажите хотя бы один признак")
        if not (self.vpn or self.site_id or self.proposals()):
            raise ValueError("Укажите результат правила")
        if self.site_id and not (self.networks or self.network_id or self.network_location or self.infra_site):
            raise ValueError("Для сетевой площадки нужен сетевой признак или площадка связанного объекта инфраструктуры")
        for field in (*MASKS, "infra_site"):
            matcher(getattr(self, field))
        return self

    def proposals(self) -> dict:
        return {field: str(value) if isinstance(value, UUID) else value
                for field in ("location_id", "branch_id", "dept_id", "resp_id", "zone_id")
                if (value := getattr(self, field)) is not None}


MASKS = {"host": "name", "group": "group", "domain": "domain", "network_location": "network_location", "network_id": "network_id"}


@dataclass
class Compiled:
    id: int
    rule: Rule

    def __post_init__(self):
        self.spans = [(parse_net(value), value) for value in self.rule.networks]
        self.masks = [(key, match) for field, key in MASKS.items() if (match := matcher(getattr(self.rule, field)))]
        self.infra_mask = matcher(self.rule.infra_site)

    def match(self, evidence: dict, source_id: UUID, type_id: int | None, addresses: list[tuple[int, str]]):
        r = self.rule
        if not r.enabled or (r.source_id and r.source_id != source_id) or (r.type_id and r.type_id != type_id):
            return None
        if any(not fn(str(evidence.get(key) or "")) for key, fn in self.masks):
            return None
        if r.infra_source_id or self.infra_mask:
            if not any((not r.infra_source_id or r.infra_source_id == row["source_id"]) and
                       (not self.infra_mask or self.infra_mask(row.get("site") or "")) for row in evidence.get("infra", [])):
                return None
        width, network = 1 << 129, ""
        if self.spans:
            hits = [(hi - lo, text) for (lo, hi), text in self.spans if any(lo <= ip <= hi and
                    (r.ip_kind == "any" or kind == r.ip_kind) for ip, kind in addresses)]
            if not hits:
                return None
            width, network = min(hits)
        return r.priority, width, network


async def rules_for(db) -> list[Compiled]:
    return [Compiled(row.id, Rule.model_validate(row.data)) for row in (await db.scalars(select(InvGeoRule).order_by(InvGeoRule.id))).all()]


AddressScope = Literal["public", "private", "shared", "special"]
IPScope = Literal[AddressScope, "missing", "ambiguous"]
PRIVATE = tuple(map(ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")))
SHARED = ip_network("100.64.0.0/10")  # private-data: ignore — RFC 6598


class ConnectionObservation(TypedDict):
    scope: IPScope
    ip: NotRequired[str]
    source: NotRequired[str]
    observed_at: NotRequired[str | None]


def _parse_ip(value) -> IPv4Address | IPv6Address | None:
    try:
        ip = ip_address(value)
    except ValueError:
        return None
    return ip.ipv4_mapped if isinstance(ip, IPv6Address) and ip.ipv4_mapped else ip


def _ip_scope(ip: IPv4Address | IPv6Address) -> AddressScope:
    if ip in SHARED:
        return "shared"
    if any(ip in net for net in PRIVATE):
        return "private"
    if ip.is_global and not (ip.is_multicast or ip.is_reserved or getattr(ip, "is_site_local", False)):
        return "public"
    return "special"


def address_scope(value: str) -> AddressScope | None:
    ip = _parse_ip(value)
    return _ip_scope(ip) if ip is not None else None


def connection_observation(evidence: dict) -> ConnectionObservation:
    """Оценивается поле подключения. Сводный, сообщённый и обнаруженный адреса имеют другой смысл."""
    addresses = {}
    for row in evidence.get("addresses", []):
        if row.get("kind") != "connection":
            continue
        if (ip := _parse_ip(row.get("ip"))) is not None:
            addresses.setdefault(ip, row)
    if not addresses:
        return {"scope": "missing"}
    if len(addresses) > 1:
        return {"scope": "ambiguous"}
    ip, row = next(iter(addresses.items()))
    return {"scope": _ip_scope(ip), "ip": str(ip), "source": row.get("source", ""), "observed_at": row.get("observed_at")}


def public_connection(evidence: dict) -> str:
    route = connection_observation(evidence)
    return route.get("ip", "") if route["scope"] == "public" else ""


def locate(evidence: dict, source_id: UUID, type_id: int | None, rules: list[Compiled], lookup) -> dict:
    addresses = [(ip, a["kind"]) for a in evidence.get("addresses", []) if (ip := ip_int(a["ip"])) is not None]
    hits = [(rank[:2], rank[2], r) for r in rules if (rank := r.match(evidence, source_id, type_id, addresses)) is not None]
    hits.sort(key=lambda x: (x[0], x[2].id))
    best = [r for rank, _, r in hits if rank == hits[0][0]] if hits else []
    signatures = {(r.rule.vpn, r.rule.site_id, tuple(r.rule.proposals().items())) for r in best}
    result = {"status": "unknown", "confidence": "", "network": hits[0][1] if hits else "",
              "rules": [{"id": r.id, "name": r.rule.name} for r in best], "proposals": {}}
    vpn = next((r for _, _, r in hits if r.rule.vpn), None)
    if vpn:
        result.update(status="vpn", confidence="rule", rules=[{"id": vpn.id, "name": vpn.rule.name}],
                      network=next(net for _, net, r in hits if r is vpn))
        return result
    if len(signatures) > 1:
        result.update(status="conflict", confidence="review")
        return result
    if best:
        winner = best[0].rule
        result["proposals"] = winner.proposals()
        if winner.site_id:
            result.update(status="site", confidence="rule", site_id=winner.site_id)
            return result
    address = public_connection(evidence)
    if address:
        geo = lookup(address)
        if geo:
            result.update(geo)
            if geo.get("country") or geo.get("lat") is not None:
                result.update(status="approx", confidence="low")
    return result


def time_of(evidence: dict) -> datetime | None:
    raw = evidence.get("last_connected") or evidence.get("last_info_update")
    return datetime.fromisoformat(raw) if raw else None


def fresh(observed_at: datetime | None, now: datetime) -> bool:
    return observed_at is not None and observed_at >= now - FRESH


def link_filter():
    return and_(InvAsset.ksc_source_id == InvGeo.source_id, InvAsset.ksc_host_id == InvGeo.host_id,
                InvAsset.ksc_link.in_(("auto", "confirmed")))


def source_filter(source_ids: list[UUID] | None):
    return InvGeo.source_id.in_(source_ids) if source_ids is not None else True


def selection(source_ids: list[UUID] | None):
    return and_(InvAsset.id == InvGeo.asset_id, link_filter(), source_filter(source_ids))


async def site_fields(db, rules: list[Compiled]) -> dict:
    ids = {r.rule.site_id for r in rules if r.rule.site_id}
    if not ids:
        return {}
    rows = {r.id: r for r in (await db.scalars(select(InvLocation).where(InvLocation.id.in_(ids), InvLocation.active.is_(True)))).all()}
    ancestry = {sid: [int(i) for i in row.ids_path.strip("/").split("/") if i] for sid, row in rows.items()}
    parents = {r.id: r for r in (await db.scalars(select(InvLocation).where(InvLocation.id.in_({i for path in ancestry.values() for i in path})))).all()}
    out = {}
    for sid, ids_path in ancestry.items():
        lineage = [parents[i] for i in ids_path if i in parents]
        place = {r.kind: r.name for r in lineage if r.kind in ("country", "region", "city")}
        coord = rows[sid].data or {}
        place.update(lat=coord.get("lat"), lon=coord.get("lon"))
        out[sid] = place
    return out


def geo_where(filters, now: datetime) -> list:
    r = InvGeo.result
    out = [r[key].as_string() == value for key in ("country", "region", "city", "network") if (value := getattr(filters, key))]
    if filters.status:
        out.append(func.coalesce(r["status"].as_string(), "unknown") == filters.status)
    if filters.site_id:
        out.append(r["site_id"].as_integer() == filters.site_id)
    if filters.observation_source:
        out.append(InvGeo.source_id == filters.observation_source)
    if filters.freshness == "fresh":
        out.append(InvGeo.observed_at >= now - FRESH)
    elif filters.freshness == "stale":
        out.append(InvGeo.observed_at < now - FRESH)
    elif filters.freshness == "unknown":
        out.append(InvGeo.observed_at.is_(None))
    return out


class GeoFilters(BaseModel):
    country: str = Field(default="", max_length=200)
    region: str = Field(default="", max_length=200)
    city: str = Field(default="", max_length=200)
    network: str = Field(default="", max_length=300)
    status: Literal["", "unknown", "site", "approx", "vpn", "conflict"] = ""
    site_id: int | None = Field(default=None, gt=0)
    observation_source: UUID | None = None
    freshness: Literal["", "fresh", "stale", "unknown"] = ""


class GeoIP(ExitStack):
    """Чтение локальных MMDB и кэш публичных адресов на расчёт. Каталог обновляется на хосте."""
    def __init__(self, directory: Path):
        super().__init__()
        import maxminddb

        self.city, self.asn = None, None
        self.errors = []
        for key, filename in (("city", "GeoLite2-City.mmdb"), ("asn", "GeoLite2-ASN.mmdb")):
            try:
                setattr(self, key, self.enter_context(maxminddb.open_database(str(directory / filename))))
            except FileNotFoundError:
                continue
            except (OSError, ValueError, maxminddb.InvalidDatabaseError):
                self.errors.append(filename)
        self.lookup = lru_cache(maxsize=32768)(self._lookup)

    def _lookup(self, ip: str) -> dict:
        city = (self.city.get(ip) or {}) if self.city else {}
        asn = (self.asn.get(ip) or {}) if self.asn else {}
        if not city and not asn:
            return {}
        location = city.get("location") or {}
        subdivisions = city.get("subdivisions") or [{}]
        def name(row: dict) -> str:
            names = (row or {}).get("names") or {}
            return str(names.get("ru") or names.get("en") or (row or {}).get("iso_code") or "")[:200]

        return {"country": name(city.get("country")), "region": name(subdivisions[0]), "city": name(city.get("city")),
                "country_code": (city.get("country") or {}).get("iso_code"), "lat": location.get("latitude"), "lon": location.get("longitude"),
                "radius_km": location.get("accuracy_radius"), "asn": asn.get("autonomous_system_number"),
                "operator": str(asn.get("autonomous_system_organization") or "")[:300], "provider": "GeoLite2",
                "database_at": datetime.fromtimestamp(self.city.metadata().build_epoch if self.city else self.asn.metadata().build_epoch, timezone.utc).date().isoformat()}
