"""Сетевые наблюдения KSC для связанных карточек оборудования, чтение партиями по nId."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from . import queries as q
from .driver import KscError, SourceClient
from .hosts import group_path, ip_str

_BATCH = 500
_INTS = {"int", "bigint"}
_ADAPTER_TYPES = (
    ("vpn", re.compile(r"\bvpn\b|wireguard|openvpn|wintun|anyconnect|forticlient|globalprotect|\b(?:tun|tap)\d*\b", re.I)),
    ("virtual", re.compile(r"virtual|hyper-v|vmware|virtualbox|veth|docker|loopback|\blo\b|bridge", re.I)),
    ("wifi", re.compile(r"wi-?fi|wireless|wlan|802\.11", re.I)),
    ("mobile", re.compile(r"mobile broadband|wwan|\b(?:lte|5g modem)\b", re.I)),
    ("ethernet", re.compile(r"ethernet|^eth\d+\b", re.I)),
)


async def capabilities(client: SourceClient) -> frozenset[str]:
    """Проверки метаданных и доступности чтения выполняются один раз на источник за расчёт."""
    cols: dict[str, dict[str, str]] = {}
    for row in await client.run(q.NETWORK_COLUMNS, max_rows=2000):
        cols.setdefault(row["tbl"].casefold(), {})[row["col"].casefold()] = row["typ"].casefold()
    hosts = cols.get("v_akpub_host", {})
    if not {"nid", "wstrdisplayname", "wstrdnsdomain", "ngroup", "nip", "tmlastnagentconnected", "tmlastinfoupdate", "tmlastvisible"} <= hosts.keys():
        raise KscError("unsupported", "Сетевые сведения недоступны: не хватает полей в dbo.v_akpub_host или прав чтения")
    base = cols.get("hosts", {})
    caps = set()
    if {"nid", "wstrname", "nparentid"} <= cols.get("v_akpub_adm_group", {}).keys():
        caps.add("groups")
    if "wstrwindomain" in hosts:
        caps.add("windows_domain")
    if hosts.get("nconnectionip") in _INTS:
        caps.add("public_connection")
    if base.get("nid") in _INTS:
        for column, feature in (("nippeer", "peer_ip"), ("nipaddress", "device_ip"), ("nnsaip", "discovered_ip")):
            if base.get(column) in _INTS:
                caps.add(feature)
    if {"nid", "nhost", "wstrname", "wstrdescription", "strmac"} <= cols.get("v_akpub_hwinv", {}).keys():
        caps.add("nic_public")
    elif ({"nid", "nhostid", "ndevtype", "nnameid", "ndescrid", "xpar1", "bdeleted"} <= cols.get("hst_hwinv_dev", {}).keys()
          and {"nid", "wstrname"} <= cols.get("hwinv_dev_name", {}).keys()
          and {"nid", "wstrdescr"} <= cols.get("hwinv_dev_descr", {}).keys()):
        caps.add("nic_internal")
    return frozenset(caps)


def _ipv4(value) -> str:
    # SQL Server может хранить IPv4 как знаковый int. В обоих вариантах первым идёт старший октет.
    return ip_str(value) if isinstance(value, int) and -0x80000000 <= value < 0xFFFFFFFF and value not in (0, -1) else ""


def _iso(value) -> str | None:
    if isinstance(value, datetime) and value.year > 1970:
        return (value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()
    return None


def _host(row: dict, groups: dict[int, dict]) -> dict:
    connected, updated = _iso(row["last_connected"]), _iso(row["last_info_update"])
    conn = _ipv4(row["connection"])
    addresses = []
    for kind, ip, source, at in (
        ("connection", conn or _ipv4(row["peer"]), "v_akpub_host.nConnectionIp" if conn else "Hosts.nIpPeer", connected),
        ("device", _ipv4(row["device"]), "Hosts.nIpAddress", updated),
        ("discovered", _ipv4(row["discovered"]), "Hosts.nNsaIp", None),
        ("reported", _ipv4(row["reported"]), "v_akpub_host.nIp", None),
    ):
        if ip:
            addresses.append({"ip": ip, "kind": kind, "source": source, "observed_at": at})
    return {
        "name": row["name"] or "", "domain": row["dns_domain"] or row["win_domain"] or "",
        "group_id": row["group_id"], "group": group_path(groups, row["group_id"]), "addresses": addresses, "interfaces": [],
        "last_connected": connected, "last_info_update": updated, "last_visible": _iso(row["last_visible"]),
        "inventory_location": "", "network_location": "", "network_id": None,
    }


def _adapter(row: dict) -> dict:
    name = str(row["name"] or "").strip()
    desc = str(row["descr"] or "").strip()
    mac = re.sub(r"[-:.\s]", "", str(row["mac"] or "")).lower()
    if re.fullmatch(r"[0-9a-f]{12}", mac) and mac not in {"000000000000", "ffffffffffff"}:
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    else:
        mac = ""
    kind = next((kind for kind, pattern in _ADAPTER_TYPES if pattern.search(f"{name} {desc}")), "unknown")
    return {"name": name or desc, "mac": mac, "type": kind}


async def read(client: SourceClient, host_ids: list[int], caps: frozenset[str], groups: dict[int, dict] | None = None) -> dict[int, dict]:
    """На входе связанные nId одного источника. При отсутствии строки KSC результат для неё отсутствует."""
    ids = list(dict.fromkeys(int(i) for i in host_ids))
    out: dict[int, dict] = {}
    nics = q.NETWORK_NICS_PUBLIC if "nic_public" in caps else q.NETWORK_NICS_INTERNAL if "nic_internal" in caps else ""
    for start in range(0, len(ids), _BATCH):
        batch = ids[start:start + _BATCH]
        rows = await client.run(q.network_hosts(batch, caps), max_rows=len(batch))
        page = {int(row["host_id"]): _host(row, groups or {}) for row in rows}
        if page and nics:
            for row in await client.run(nics.format(ids=q.ids_list(page)), max_rows=64 * len(page)):
                adapter = _adapter(row)
                items = page[int(row["host_id"])]["interfaces"]
                if adapter not in items:
                    items.append(adapter)
        out.update(page)
    return out
