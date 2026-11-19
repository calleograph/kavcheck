"""Коннекторы источников инфраструктуры — только чтение, штатные API. Каждый возвращает объекты в едином виде:

    {ext_id, kind, name, fqdn, ips, macs, bios_uuid, serial, parent_ext, attrs}

kind: server (физический сервер или хост виртуализации), vm, cluster, network (сетевое устройство), monitor (узел мониторинга), ip, prefix, vlan, site, rack,
backup (защищаемый резервным копированием объект), resource (внешний ресурс). attrs — cpu, ram_mb, disk_gb, os, power (on/off), available (True/False/None), monitored,
cluster, site, host, status, groups, tags, last_backup.

Разбор ответов — чистые функции (`parse_*`): проверяются тестами на образцах ответов. Сеть — httpx с тайм-аутом; учётные данные не попадают в журналы и ошибки."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

KINDS_RU = {"zabbix": "Мониторинг (Zabbix)", "vsphere": "VMware vSphere", "proxmox": "Proxmox VE", "ovirt": "oVirt / zVirt", "netbox": "Реестр инфраструктуры (NetBox)",
            "hyperv": "Hyper-V (выгрузка скриптом)", "backup": "Резервное копирование (JSON или выгрузка)", "generic": "Произвольный JSON по HTTP (провайдер)"}
OBJ_RU = {"server": "Сервер / хост виртуализации", "vm": "Виртуальная машина", "cluster": "Кластер", "network": "Сетевое устройство", "monitor": "Узел мониторинга", "ip": "IP-адрес",
          "prefix": "Подсеть", "vlan": "VLAN", "site": "Площадка", "rack": "Стойка", "backup": "Резервное копирование", "resource": "Внешний ресурс"}
MAX_OBJECTS = 50_000
TIMEOUT = 30.0


class SourceError(Exception):
    """Ошибка источника с понятной причиной (без секретов)."""


def obj(ext_id, kind: str, name: str = "", *, fqdn: str = "", ips=None, macs=None, bios_uuid: str = "", serial: str = "", parent_ext: str = "", **attrs) -> dict:
    return {"ext_id": str(ext_id)[:200], "kind": kind, "name": (name or "")[:300], "fqdn": (fqdn or "")[:300], "ips": sorted({i for i in (ips or []) if i})[:64],
            "macs": sorted({norm_mac(m) for m in (macs or []) if norm_mac(m)})[:64], "bios_uuid": norm_uuid(bios_uuid), "serial": (serial or "").strip()[:120], "parent_ext": str(parent_ext or "")[:200],
            "attrs": {k: v for k, v in attrs.items() if v not in (None, "", [], {})}}


def norm_mac(m) -> str:
    h = re.sub(r"[^0-9a-f]", "", str(m or "").lower())
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 and h != "000000000000" else ""


def norm_uuid(u) -> str:
    h = re.sub(r"[^0-9a-f]", "", str(u or "").lower())
    return h if len(h) == 32 and h.strip("0") else ""


def uuid_variants(u: str) -> set[str]:
    """SMBIOS UUID в обоих порядках байт: VMware хранит первые три группы иначе, чем видят Windows и Linux внутри гостя."""
    h = norm_uuid(u)
    if not h:
        return set()
    sw = "".join(reversed([h[i:i + 2] for i in range(0, 8, 2)])) + "".join(reversed([h[i:i + 2] for i in range(8, 12, 2)])) + "".join(reversed([h[i:i + 2] for i in range(12, 16, 2)])) + h[16:]
    return {h, sw}


def strip_ip(v) -> str:
    return str(v or "").split("/")[0].strip()


async def _get(c: httpx.AsyncClient, url: str, **kw) -> Any:
    r = await c.get(url, **kw)
    if r.status_code in (401, 403):
        raise SourceError(f"Доступ отклонён ({r.status_code}): проверьте учётные данные и права только на чтение")
    if r.status_code >= 400:
        raise SourceError(f"Ответ {r.status_code} на {url.split('?')[0]}")
    try:
        return r.json()
    except ValueError:
        raise SourceError(f"Не JSON в ответе {url.split('?')[0]}") from None


# ------------------------------------------------------------------------------------------------ Zabbix (JSON-RPC, токен API)
def parse_zabbix(hosts: list[dict]) -> list[dict]:
    out = []
    for h in hosts:
        ifs = h.get("interfaces") or []
        av = [str(i.get("available")) for i in ifs]
        avail = True if "1" in av else False if av and all(a == "2" for a in av) else None
        if str(h.get("active_available", "")) == "1":
            avail = True
        inv = h.get("inventory") if isinstance(h.get("inventory"), dict) else {}
        dns = [i.get("dns") for i in ifs if i.get("dns")]
        out.append(obj(f"host:{h.get('hostid')}", "monitor", h.get("name") or h.get("host") or "", fqdn=(dns[0] if dns else h.get("host") or ""),
                       ips=[i.get("ip") for i in ifs if i.get("ip") and i.get("ip") != "127.0.0.1"], macs=[inv.get("macaddress_a"), inv.get("macaddress_b")],
                       serial=inv.get("serialno_a") or "", technical=h.get("host") or "", monitored=str(h.get("status", "0")) == "0", available=avail,
                       os=inv.get("os") or "", groups=[g.get("name") for g in (h.get("hostgroups") or h.get("groups") or []) if g.get("name")][:20]))
    return out


async def fetch_zabbix(src, secret: str, c: httpx.AsyncClient) -> list[dict]:
    url = src.url.rstrip("/")
    url = url if url.endswith("api_jsonrpc.php") else url + "/api_jsonrpc.php"
    body = {"jsonrpc": "2.0", "method": "host.get", "id": 1, "params": {"output": ["hostid", "host", "name", "status", "active_available"], "selectInterfaces": ["ip", "dns", "available", "type", "main"],
            "selectInventory": ["serialno_a", "macaddress_a", "macaddress_b", "os"], "selectHostGroups": ["name"], "limit": MAX_OBJECTS}}
    r = await c.post(url, json=body, headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json-rpc"})
    if r.status_code >= 400:
        raise SourceError(f"Ответ {r.status_code} от API Zabbix")
    d = r.json()
    if "error" in d:
        msg = str((d["error"] or {}).get("data") or (d["error"] or {}).get("message") or "ошибка API")
        raise SourceError(f"Zabbix: {msg[:200]}")
    return parse_zabbix(d.get("result") or [])


# ------------------------------------------------------------------------------------------------ Proxmox VE (токен API, роль PVEAuditor)
def parse_proxmox(resources: list[dict], configs: dict[str, dict]) -> list[dict]:
    out = []
    for r in resources:
        t = r.get("type")
        if t == "node":
            out.append(obj(f"node:{r.get('node')}", "server", r.get("node") or "", cpu=r.get("maxcpu"), ram_mb=_mb(r.get("maxmem")), disk_gb=_gb(r.get("maxdisk")),
                           power="on" if r.get("status") == "online" else "off", hypervisor="Proxmox VE"))
        elif t in ("qemu", "lxc") and not r.get("template"):
            cfg = configs.get(f"{r.get('node')}/{r.get('vmid')}") or {}
            smb = re.search(r"uuid=([0-9a-fA-F-]{36})", str(cfg.get("smbios1") or ""))
            macs = [m.group(1) for k, v in cfg.items() if k.startswith("net") for m in [re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", str(v))] if m]
            ips = [strip_ip(m.group(1)) for k, v in cfg.items() if k.startswith("ipconfig") for m in [re.search(r"ip=([0-9.]+)", str(v))] if m]
            out.append(obj(f"vm:{r.get('vmid')}", "vm", r.get("name") or f"vm{r.get('vmid')}", ips=ips, macs=macs, bios_uuid=smb.group(1) if smb else "", parent_ext=f"node:{r.get('node')}",
                           cpu=r.get("maxcpu"), ram_mb=_mb(r.get("maxmem")), disk_gb=_gb(r.get("maxdisk")), power="on" if r.get("status") == "running" else "off", host=r.get("node"),
                           container=t == "lxc", tags=r.get("tags") or ""))
    return out


async def fetch_proxmox(src, secret: str, c: httpx.AsyncClient) -> list[dict]:
    base = src.url.rstrip("/")
    h = {"Authorization": f"PVEAPIToken={src.username}={secret}"}
    res = (await _get(c, f"{base}/api2/json/cluster/resources", headers=h)).get("data") or []
    sem = asyncio.Semaphore(4)
    configs: dict[str, dict] = {}

    async def one(r):
        async with sem:
            try:
                configs[f"{r['node']}/{r['vmid']}"] = (await _get(c, f"{base}/api2/json/nodes/{r['node']}/{r['type']}/{r['vmid']}/config", headers=h)).get("data") or {}
            except SourceError:
                pass                                                   # без конфигурации — без UUID и MAC, остальное есть
    await asyncio.gather(*[one(r) for r in res if r.get("type") in ("qemu", "lxc")][:MAX_OBJECTS])
    return parse_proxmox(res, configs)


# ------------------------------------------------------------------------------------------------ VMware vSphere (REST /api, сессия по логину)
def parse_vsphere(vms: list[dict], details: dict[str, dict], hosts: list[dict], clusters: list[dict]) -> list[dict]:
    out = [obj(f"cluster:{c.get('cluster')}", "cluster", c.get("name") or "", ha=c.get("ha_enabled"), drs=c.get("drs_enabled")) for c in clusters]
    out += [obj(f"host:{h.get('host')}", "server", h.get("name") or "", power="on" if h.get("power_state") == "POWERED_ON" else "off", hypervisor="VMware ESXi",
                status=h.get("connection_state") or "") for h in hosts]
    for v in vms:
        d = details.get(v.get("vm")) or {}
        ident = d.get("identity") or {}
        nics = d.get("nics") or {}
        macs = [n.get("mac_address") for n in (nics.values() if isinstance(nics, dict) else nics)]
        disks = d.get("disks") or {}
        disk_gb = round(sum(int((x or {}).get("capacity") or 0) for x in (disks.values() if isinstance(disks, dict) else disks)) / 1e9, 1) or None
        out.append(obj(f"vm:{v.get('vm')}", "vm", v.get("name") or "", fqdn=(d.get("guest") or {}).get("host_name", ""), ips=(d.get("guest") or {}).get("ips") or [], macs=macs,
                       bios_uuid=ident.get("bios_uuid") or "", parent_ext=f"host:{d.get('host')}" if d.get("host") else "", cpu=v.get("cpu_count"), ram_mb=v.get("memory_size_MiB"),
                       disk_gb=disk_gb, power="on" if v.get("power_state") == "POWERED_ON" else "off", os=(d.get("guest_OS") or ""), instance_uuid=ident.get("instance_uuid") or ""))
    return out


async def fetch_vsphere(src, secret: str, c: httpx.AsyncClient) -> list[dict]:
    base = src.url.rstrip("/")
    r = await c.post(f"{base}/api/session", auth=(src.username, secret))
    if r.status_code in (401, 403):
        raise SourceError("vCenter отклонил вход: проверьте учётную запись (достаточно роли «только чтение»)")
    if r.status_code >= 400:
        raise SourceError(f"Ответ {r.status_code} от vCenter при входе")
    h = {"vmware-api-session-id": r.json() if isinstance(r.json(), str) else str(r.json())}
    vms = await _get(c, f"{base}/api/vcenter/vm", headers=h)
    hosts = await _get(c, f"{base}/api/vcenter/host", headers=h)
    clusters = await _get(c, f"{base}/api/vcenter/cluster", headers=h)
    sem = asyncio.Semaphore(4)
    details: dict[str, dict] = {}

    async def one(v):
        async with sem:
            try:
                d = await _get(c, f"{base}/api/vcenter/vm/{v['vm']}", headers=h)
                try:
                    g = await _get(c, f"{base}/api/vcenter/vm/{v['vm']}/guest/identity", headers=h)
                    d["guest"] = {"host_name": g.get("host_name") or "", "ips": [g.get("ip_address")] if g.get("ip_address") else []}
                except SourceError:
                    pass                                               # нет VMware Tools — без гостевого имени и адреса
                details[v["vm"]] = d
            except SourceError:
                pass
    await asyncio.gather(*[one(v) for v in vms[:MAX_OBJECTS]])
    try:
        await c.delete(f"{base}/api/session", headers=h)
    except httpx.HTTPError:
        pass
    return parse_vsphere(vms, details, hosts, clusters)


# ------------------------------------------------------------------------------------------------ oVirt / zVirt (REST, JSON)
def parse_ovirt(vms: list[dict], hosts: list[dict], clusters: list[dict]) -> list[dict]:
    out = [obj(f"cluster:{c.get('id')}", "cluster", c.get("name") or "") for c in clusters]
    out += [obj(f"host:{h.get('id')}", "server", h.get("name") or "", fqdn=h.get("address") or "", serial=((h.get("hardware_information") or {}).get("serial_number") or ""),
                bios_uuid=((h.get("hardware_information") or {}).get("uuid") or ""), power="on" if h.get("status") == "up" else "off", hypervisor="oVirt",
                cluster=(h.get("cluster") or {}).get("id")) for h in hosts]
    for v in vms:
        topo = (v.get("cpu") or {}).get("topology") or {}
        cpu = int(topo.get("sockets") or 1) * int(topo.get("cores") or 1) * int(topo.get("threads") or 1) if topo else None
        nics = ((v.get("nics") or {}).get("nic") or []) if isinstance(v.get("nics"), dict) else (v.get("nics") or [])
        macs = [(n.get("mac") or {}).get("address") for n in nics]
        out.append(obj(f"vm:{v.get('id')}", "vm", v.get("name") or "", fqdn=v.get("fqdn") or "", macs=macs, bios_uuid=v.get("id") or "",       # гость видит в SMBIOS идентификатор ВМ
                       parent_ext=f"host:{(v.get('host') or {}).get('id')}" if (v.get("host") or {}).get("id") else "", cpu=cpu, ram_mb=_mb(v.get("memory")),
                       power="on" if v.get("status") == "up" else "off", os=((v.get("os") or {}).get("type") or ""), cluster=(v.get("cluster") or {}).get("id")))
    return out


async def fetch_ovirt(src, secret: str, c: httpx.AsyncClient) -> list[dict]:
    base = src.url.rstrip("/")
    base = base if base.endswith("/api") else base + "/ovirt-engine/api"
    h = {"Accept": "application/json", "Version": "4"}
    vms = (await _get(c, f"{base}/vms?follow=nics", headers=h, auth=(src.username, secret))).get("vm") or []
    hosts = (await _get(c, f"{base}/hosts", headers=h, auth=(src.username, secret))).get("host") or []
    cls = (await _get(c, f"{base}/clusters", headers=h, auth=(src.username, secret))).get("cluster") or []
    return parse_ovirt(vms, hosts, cls)


# ------------------------------------------------------------------------------------------------ реестр инфраструктуры (NetBox REST, токен)
def parse_netbox(devices, vms, ips, prefixes, vlans, sites, racks) -> list[dict]:
    out = [obj(f"site:{s['id']}", "site", s.get("name") or "", status=_lbl(s.get("status"))) for s in sites]
    out += [obj(f"rack:{r['id']}", "rack", r.get("name") or "", site=(r.get("site") or {}).get("name"), units=r.get("u_height")) for r in racks]
    ip_by_dev: dict[str, list[str]] = {}
    for ip in ips:
        ao = ip.get("assigned_object") or {}
        dev = (ao.get("device") or {}).get("id") or (ao.get("virtual_machine") or {}).get("id")
        kind = "device" if ao.get("device") else "vm" if ao.get("virtual_machine") else ""
        if dev:
            ip_by_dev.setdefault(f"{kind}:{dev}", []).append(strip_ip(ip.get("address")))
        out.append(obj(f"ip:{ip['id']}", "ip", strip_ip(ip.get("address")), ips=[strip_ip(ip.get("address"))], status=_lbl(ip.get("status")), dns=ip.get("dns_name") or "",
                       assigned=f"{kind}:{dev}" if dev else ""))
    for d in devices:
        role = ((d.get("role") or d.get("device_role") or {}).get("slug") or "").lower()
        k = "network" if any(x in role for x in ("switch", "router", "firewall", "network", "коммут", "маршрут")) else "server"
        out.append(obj(f"device:{d['id']}", k, d.get("name") or "", ips=ip_by_dev.get(f"device:{d['id']}", []) + [strip_ip((d.get("primary_ip") or {}).get("address"))], serial=d.get("serial") or "",
                       site=(d.get("site") or {}).get("name"), rack=(d.get("rack") or {}).get("name"), position=d.get("position"), status=_lbl(d.get("status")),
                       model=((d.get("device_type") or {}).get("model") or ""), asset_tag=d.get("asset_tag") or ""))
    for v in vms:
        out.append(obj(f"vm:{v['id']}", "vm", v.get("name") or "", ips=ip_by_dev.get(f"vm:{v['id']}", []) + [strip_ip((v.get("primary_ip") or {}).get("address"))],
                       cpu=v.get("vcpus"), ram_mb=v.get("memory"), disk_gb=v.get("disk"), status=_lbl(v.get("status")), cluster=(v.get("cluster") or {}).get("name")))
    out += [obj(f"prefix:{p['id']}", "prefix", p.get("prefix") or "", vlan=(p.get("vlan") or {}).get("vid"), site=((p.get("site") or p.get("scope") or {}) or {}).get("name"),
                status=_lbl(p.get("status"))) for p in prefixes]
    out += [obj(f"vlan:{v['id']}", "vlan", f"{v.get('vid')} {v.get('name') or ''}".strip(), vid=v.get("vid"), site=(v.get("site") or {}).get("name")) for v in vlans]
    return out


async def fetch_netbox(src, secret: str, c: httpx.AsyncClient) -> list[dict]:
    base = src.url.rstrip("/")
    h = {"Authorization": f"Token {secret}", "Accept": "application/json"}

    async def all_of(path: str) -> list[dict]:
        out, url = [], f"{base}{path}?limit=1000"
        while url and len(out) < MAX_OBJECTS:
            d = await _get(c, url, headers=h)
            out += d.get("results") or []
            url = d.get("next")
        return out
    return parse_netbox(await all_of("/api/dcim/devices/"), await all_of("/api/virtualization/virtual-machines/"), await all_of("/api/ipam/ip-addresses/"),
                        await all_of("/api/ipam/prefixes/"), await all_of("/api/ipam/vlans/"), await all_of("/api/dcim/sites/"), await all_of("/api/dcim/racks/"))


# ------------------------------------------------------------------------------------------------ выгрузки (Hyper-V скриптом, резервное копирование) и произвольный JSON
def parse_hyperv(doc: dict) -> list[dict]:
    """Выгрузка scripts/windows/Export-KavHyperV.ps1: формат kavcheck-hyperv/1 (хосты и ВМ, BIOSGUID — то, что видит гость)."""
    if not isinstance(doc, dict) or doc.get("format") != "kavcheck-hyperv/1":
        raise SourceError("Неверный файл: ожидается выгрузка Export-KavHyperV.ps1 (format kavcheck-hyperv/1)")
    out = []
    for h in doc.get("hosts") or []:
        out.append(obj(f"host:{h.get('name')}", "server", h.get("name") or "", fqdn=h.get("fqdn") or "", serial=h.get("serial") or "", bios_uuid=h.get("uuid") or "",
                       cpu=h.get("cpu"), ram_mb=h.get("ram_mb"), hypervisor="Hyper-V", power="on", cluster=h.get("cluster") or ""))
    for v in doc.get("vms") or []:
        out.append(obj(f"vm:{v.get('id')}", "vm", v.get("name") or "", ips=v.get("ips") or [], macs=v.get("macs") or [], bios_uuid=v.get("bios_guid") or "", parent_ext=f"host:{v.get('host')}",
                       cpu=v.get("cpu"), ram_mb=v.get("ram_mb"), disk_gb=v.get("disk_gb"), power="on" if str(v.get("state", "")).lower() == "running" else "off", host=v.get("host")))
    return out


def by_path(d: Any, path: str) -> Any:
    for part in [p for p in path.split(".") if p]:
        if isinstance(d, list):
            try:
                d = d[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(d, dict):
            d = d.get(part)
        else:
            return None
    return d


def parse_generic(data: Any, opts: dict, default_kind: str = "resource") -> list[dict]:
    """Список объектов из JSON по настраиваемым путям полей: items (путь к массиву), id, name, ip, mac, uuid, serial, cpu, ram_mb, disk_gb, status, last_backup."""
    items = by_path(data, opts.get("items", "")) if opts.get("items") else data
    if not isinstance(items, list):
        raise SourceError("В ответе нет списка объектов: проверьте путь к массиву (поле «items»)")
    f = {k: opts.get(k) or k for k in ("id", "name", "ip", "mac", "uuid", "serial", "cpu", "ram_mb", "disk_gb", "status", "last_backup", "fqdn")}
    out = []
    for it in items[:MAX_OBJECTS]:
        ext = by_path(it, f["id"]) or by_path(it, f["name"])
        if ext is None:
            continue
        ipv = by_path(it, f["ip"])
        out.append(obj(ext, opts.get("kind") or default_kind, str(by_path(it, f["name"]) or ext), fqdn=str(by_path(it, f["fqdn"]) or ""),
                       ips=[strip_ip(x) for x in (ipv if isinstance(ipv, list) else [ipv])], macs=[by_path(it, f["mac"])], bios_uuid=str(by_path(it, f["uuid"]) or ""),
                       serial=str(by_path(it, f["serial"]) or ""), cpu=by_path(it, f["cpu"]), ram_mb=by_path(it, f["ram_mb"]), disk_gb=by_path(it, f["disk_gb"]),
                       status=by_path(it, f["status"]), last_backup=by_path(it, f["last_backup"])))
    return out


async def fetch_generic(src, secret: str, c: httpx.AsyncClient) -> list[dict]:
    h = {"Accept": "application/json"}
    if secret:
        h[src.options.get("auth_header") or "Authorization"] = (src.options.get("auth_prefix", "Bearer") + " " + secret).strip()
    return parse_generic(await _get(c, src.url, headers=h), src.options or {}, "backup" if src.kind == "backup" else "resource")


FETCH = {"zabbix": fetch_zabbix, "proxmox": fetch_proxmox, "vsphere": fetch_vsphere, "ovirt": fetch_ovirt, "netbox": fetch_netbox, "generic": fetch_generic, "backup": fetch_generic}
UPLOAD = {"hyperv", "backup"}                    # можно загрузить файлом (backup — JSON выгрузки системы резервного копирования по тем же путям полей)


async def fetch(src, secret: str, transport: httpx.AsyncBaseTransport | None = None) -> list[dict]:
    """Получить объекты источника. transport — для тестов (httpx.MockTransport)."""
    if src.kind not in FETCH:
        raise SourceError("Этот источник загружается файлом (выгрузка), а не по сети")
    if not src.url.lower().startswith(("https://", "http://")):
        raise SourceError("Адрес источника должен начинаться с https:// или http://")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=bool(src.verify_tls), transport=transport, follow_redirects=False) as c:
            return await FETCH[src.kind](src, secret, c)
    except SourceError:
        raise
    except httpx.ConnectError as exc:
        raise SourceError(f"Нет соединения с {src.url.split('/')[2] if '//' in src.url else src.url}: {type(exc).__name__}") from None
    except httpx.TimeoutException:
        raise SourceError(f"Источник не ответил за {int(TIMEOUT)} с") from None
    except httpx.HTTPError as exc:
        raise SourceError(f"Ошибка HTTP: {type(exc).__name__}") from None
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SourceError(f"Ответ источника не разобран: {type(exc).__name__}") from None


def _mb(b) -> int | None:
    try:
        return int(int(b) / 1048576) if b else None
    except (TypeError, ValueError):
        return None


def _gb(b) -> float | None:
    try:
        return round(int(b) / 1073741824, 1) if b else None
    except (TypeError, ValueError):
        return None


def _lbl(v) -> str:
    return (v.get("value") or v.get("label") or "") if isinstance(v, dict) else str(v or "")
