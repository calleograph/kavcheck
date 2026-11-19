"""Инфраструктура: коннекторы на образцах ответов (Zabbix, Proxmox, vSphere, oVirt, NetBox, Hyper-V, произвольный JSON) и сценарий приёмки —
обнаружение новой ВМ, связь с мониторингом, приоритет источников, изменения CPU и IP, нет мониторинга, исчезновение, вывод из эксплуатации, без дублей,
ошибка одного источника не останавливает другие. Все имена и адреса вымышленные (example.local, 192.0.2.0/24)."""
from __future__ import annotations

import json

import httpx
import pytest

from app.infra import connectors as K
from app.infra import sync as S
from app.models import InfraFinding, InfraObject, InfraSource, InvAsset
from tests.conftest import login

API = "/api/v1/inv"
UUID_VMX = "4238d4b6-0090-3e75-9406-b310eafa2b1e"


def test_uuid_byte_order_variants_match():
    win = "B6D43842-9000-753E-9406-B310EAFA2B1E"                                   # так видит Windows внутри гостя VMware
    assert K.uuid_variants(UUID_VMX) & K.uuid_variants(win)
    assert K.norm_mac("00-50-56-AB-CD-EF") == "00:50:56:ab:cd:ef" and K.norm_mac("00:00:00:00:00:00") == ""


class Fake:
    """Подставные API: состояние меняется между синхронизациями."""
    def __init__(self):
        self.vms = [{"type": "qemu", "vmid": 101, "node": "pve1", "name": "app-db01", "status": "running", "maxcpu": 4, "maxmem": 8 * 1073741824, "maxdisk": 50 * 1073741824},
                    {"type": "qemu", "vmid": 102, "node": "pve1", "name": "app-web01", "status": "running", "maxcpu": 2, "maxmem": 4 * 1073741824, "maxdisk": 20 * 1073741824}]
        self.ip = {101: "192.0.2.21", 102: "192.0.2.22"}
        self.zbx = [{"hostid": "10501", "host": "app-db01.example.local", "name": "app-db01", "status": "0", "interfaces": [{"ip": "192.0.2.21", "dns": "app-db01.example.local", "available": "1"}],
                     "inventory": {}, "hostgroups": [{"name": "Linux servers"}]}]
        self.calls: dict[str, int] = {}

    def handler(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path
        self.calls[p] = self.calls.get(p, 0) + 1
        if p.endswith("/api_jsonrpc.php"):
            body = json.loads(req.content)
            assert req.headers["authorization"] == "Bearer zbx-token" and body["method"] == "host.get"
            return httpx.Response(200, json={"jsonrpc": "2.0", "result": self.zbx, "id": 1})
        if p == "/api2/json/cluster/resources":
            assert req.headers["authorization"].startswith("PVEAPIToken=reader@pve!kav=")
            return httpx.Response(200, json={"data": [{"type": "node", "node": "pve1", "status": "online", "maxcpu": 32, "maxmem": 256 * 1073741824}, *self.vms]})
        if p.startswith("/api2/json/nodes/pve1/qemu/") and p.endswith("/config"):
            vid = int(p.split("/")[-2])
            return httpx.Response(200, json={"data": {"smbios1": f"uuid=0000000{vid}-1111-2222-3333-444455556666", "net0": f"virtio=BC:24:11:00:00:{vid % 100:02d},bridge=vmbr0",
                                                      "ipconfig0": f"ip={self.ip[vid]}/24,gw=192.0.2.1"}})
        return httpx.Response(404)


async def sync(app, src_id: int, fake: Fake):
    async with app.state.session_maker() as db:
        s = await db.get(InfraSource, src_id)
        secret = app.state.settings_svc.decrypt(s.secret_enc, f"infra.{s.id}")
        objs = await K.fetch(s, secret, transport=httpx.MockTransport(fake.handler))
        st = await S.sync_source(db, s, objs)
        rc = await S.reconcile(db)
        await db.commit()
        return st, rc


async def findings(app, code: str) -> list[InfraFinding]:
    async with app.state.session_maker() as db:
        from sqlalchemy import select

        return list((await db.execute(select(InfraFinding).where(InfraFinding.code == code, InfraFinding.status.in_(("attention", "review"))))).scalars())


async def test_infra_acceptance(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    fake = Fake()
    pve = (await client.post(f"{API}/infra/sources", json={"kind": "proxmox", "name": "Виртуализация (пример)", "url": "https://pve.example.local:8006", "username": "reader@pve!kav", "secret": "tok-1"})).json()
    zbx = (await client.post(f"{API}/infra/sources", json={"kind": "zabbix", "name": "Мониторинг (пример)", "url": "https://zbx.example.local", "secret": "zbx-token"})).json()
    assert pve["secret_set"] and "tok-1" not in json.dumps(pve)
    # 1. новая ВМ обнаружена и получила карточку; 2. мониторинг связан с той же карточкой
    st, _ = await sync(app, pve["id"], fake)
    assert st["new"] == 3 and st["created"] == 3                                        # хост и две ВМ
    await sync(app, zbx["id"], fake)
    vm = (await client.get(f"{API}/assets", params={"q": "app-db01"})).json()["items"][0]
    assert vm["cls"] == "vm" and vm["ext_ids"]["bios_uuid"]
    inf = (await client.get(f"{API}/assets/{vm['id']}/infra")).json()
    assert {o["source"] for o in inf["objects"]} == {"Виртуализация (пример)", "Мониторинг (пример)"}
    zo = next(o for o in inf["objects"] if o["source_kind"] == "zabbix")
    assert zo["match"] == "auto" and zo["match_basis"] == "имя и IP-адрес"
    # 3. технические сведения — по приоритету источников
    res = {r["attr"]: r for r in inf["resolved"]}
    assert res["cpu"]["value"] == "4" and res["cpu"]["source"] == "Виртуализация (пример)" and res["available"]["value"] == "да"
    host = (await client.get(f"{API}/assets/{vm['id']}")).json()
    assert host["rel"] == "vm" and host["parent"]                                        # ВМ размещена на хосте виртуализации
    # 7. сервер не на мониторинге — расхождение
    assert any(f.asset_id != vm["id"] for f in await findings(app, "no_monitoring"))
    assert not any(f.asset_id == vm["id"] for f in await findings(app, "no_monitoring"))
    # 4. администратор заполняет назначение и ответственного — расхождения закрываются сверкой
    p = (await client.post(f"{API}/people", json={"name": "Администратор (пример)"})).json()
    await client.put(f"{API}/assets/{vm['id']}", json={"data": {"purpose": "СУБД учётной системы", "it_id": p["id"]}, "version": host["version"]})
    await client.post(f"{API}/infra/reconcile")
    assert not any(f.asset_id == vm["id"] for f in await findings(app, "no_admin") + await findings(app, "no_purpose"))
    # 5. и 6. изменения CPU и IP отражаются и попадают в расхождения на подтверждение
    fake.vms[0]["maxcpu"] = 8
    fake.ip[101] = "192.0.2.31"
    st, _ = await sync(app, pve["id"], fake)
    assert st["changed"] == 1 and st["created"] == 0
    inf = (await client.get(f"{API}/assets/{vm['id']}/infra")).json()
    assert {c["field"] for c in inf["changes"]} >= {"cpu", "ips"} and {r["attr"]: r for r in inf["resolved"]}["cpu"]["value"] == "8"
    assert await findings(app, "config_changed") and await findings(app, "ip_changed")
    # 11. повторная синхронизация не создаёт дублей
    n_before = (await client.get(f"{API}/assets", params={"cls": "vm,server"})).json()["total"]
    await sync(app, pve["id"], fake)
    await sync(app, zbx["id"], fake)
    assert (await client.get(f"{API}/assets", params={"cls": "vm,server"})).json()["total"] == n_before
    async with app.state.session_maker() as db:
        from sqlalchemy import func, select

        assert (await db.execute(select(func.count()).select_from(InfraObject))).scalar_one() == 4
    # 9. исчезнувшая ВМ сохраняется с историей и попадает в «исчез из источников»
    web = (await client.get(f"{API}/assets", params={"q": "app-web01"})).json()["items"][0]
    fake.vms = fake.vms[:1]
    st, _ = await sync(app, pve["id"], fake)
    assert st["gone"] == 1
    assert any(f.asset_id == web["id"] for f in await findings(app, "gone"))
    assert (await client.get(f"{API}/assets/{web['id']}")).status_code == 200
    # 10. вывод из эксплуатации: статус, связь с хостом снята; мониторинг ещё видит узел — расхождение
    d = (await client.post(f"{API}/docs", json={"kind": "decom", "basis": "Приказ (пример)", "data": {"checklist": {"backup": True}}, "items": [{"asset_id": vm["id"]}]})).json()
    assert (await client.post(f"{API}/docs/{d['id']}/status", json={"to": "done"})).status_code == 200
    after = (await client.get(f"{API}/assets/{vm['id']}")).json()
    assert after["st_cls"] == "decom" and after["parent_id"] is None
    await client.post(f"{API}/infra/reconcile")
    assert any(f.asset_id == vm["id"] for f in await findings(app, "decom_monitored"))
    # решения по расхождениям: исключение — только с основанием
    f = (await findings(app, "decom_monitored"))[0]
    assert (await client.put(f"{API}/infra/findings", json={"ids": [f.id], "status": "exception"})).status_code == 422
    assert (await client.put(f"{API}/infra/findings", json={"ids": [f.id], "status": "exception", "comment": "узел нужен для архива (пример)"})).json()["updated"] == 1
    await client.post(f"{API}/infra/reconcile")
    assert not await findings(app, "decom_monitored")                                    # исключение сверка не трогает
    ov = (await client.get(f"{API}/infra/overview")).json()
    assert ov["counts"]["vm"] >= 1 and ov["counts"]["decom"] == 1 and ov["source_errors"] == 0
    ips = (await client.get(f"{API}/infra/ips")).json()
    assert any(i["ip"] == "192.0.2.31" for i in ips["items"])
    for view in ("infra_registry", "infra_findings", "infra_changes", "infra_sync", "infra_ips", "infra_hypervisors", "infra_racks", "infra_review", "infra_decom", "infra_asof", "infra_new_gone"):
        r = await client.post("/api/v1/quick/preview", json={"kind": "quick_inv", "params": {"view": view}})
        assert r.status_code == 200, (view, r.text)


async def test_failing_source_does_not_stop_others(client, app, monkeypatch):
    await login(client, "admin", "Admin-Passw0rd-123")
    bad = (await client.post(f"{API}/infra/sources", json={"kind": "zabbix", "name": "Недоступный (пример)", "url": "https://down.example.local", "secret": "x"})).json()
    good = (await client.post(f"{API}/infra/sources", json={"kind": "proxmox", "name": "Рабочий (пример)", "url": "https://pve.example.local", "username": "reader@pve!kav", "secret": "y"})).json()
    fake = Fake()

    async def fetch(src, secret, transport=None):
        if src.kind == "zabbix":
            raise K.SourceError("Нет соединения с down.example.local: ConnectError")
        return await K.FETCH[src.kind](src, secret, httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)))
    monkeypatch.setattr(K, "fetch", fetch)
    from app.inventory.service import InvService

    svc = InvService(app.state.session_maker, app.state.settings_svc, None, None)
    await svc.infra_tick(force=True)
    srcs = {s["id"]: s for s in (await client.get(f"{API}/infra/sources")).json()["items"]}
    assert "down.example.local" in srcs[bad["id"]]["last_error"] and srcs[bad["id"]]["last_ok_at"] is None
    assert srcs[good["id"]]["last_error"] == "" and srcs[good["id"]]["objects"] == 3


def test_parsers_on_samples():
    vs = K.parse_vsphere([{"vm": "vm-1", "name": "web01", "cpu_count": 2, "memory_size_MiB": 4096, "power_state": "POWERED_ON"}],
                         {"vm-1": {"identity": {"bios_uuid": UUID_VMX, "instance_uuid": "5038"}, "host": "host-9", "nics": {"4000": {"mac_address": "00:50:56:aa:bb:cc"}},
                                   "disks": {"2000": {"capacity": 40_000_000_000}}, "guest": {"host_name": "web01.example.local", "ips": ["192.0.2.40"]}}},
                         [{"host": "host-9", "name": "esx01", "power_state": "POWERED_ON"}], [{"cluster": "domain-c7", "name": "Кластер А"}])
    vm = next(o for o in vs if o["kind"] == "vm")
    assert vm["parent_ext"] == "host:host-9" and vm["attrs"]["ram_mb"] == 4096 and vm["macs"] == ["00:50:56:aa:bb:cc"] and vm["attrs"]["disk_gb"] == 40.0
    ov = K.parse_ovirt([{"id": "1f2e3d4c-0000-1111-2222-333344445555", "name": "erp", "memory": 8589934592, "cpu": {"topology": {"sockets": 2, "cores": 2, "threads": 1}}, "status": "up",
                         "host": {"id": "h1"}, "nics": {"nic": [{"mac": {"address": "56:6f:00:00:00:01"}}]}}], [{"id": "h1", "name": "kvm1", "status": "up"}], [])
    assert next(o for o in ov if o["kind"] == "vm")["attrs"]["cpu"] == 4
    nb = K.parse_netbox([{"id": 5, "name": "sw-core", "role": {"slug": "core-switch"}, "serial": "SN1", "site": {"name": "ЦОД"}, "rack": {"name": "A1"}, "position": 40}],
                        [{"id": 7, "name": "vm-erp", "vcpus": 4, "memory": 8192}], [{"id": 1, "address": "192.0.2.50/24", "assigned_object": {"virtual_machine": {"id": 7}}}],
                        [{"id": 2, "prefix": "192.0.2.0/24", "vlan": {"vid": 10}}], [{"id": 3, "vid": 10, "name": "srv"}], [{"id": 4, "name": "ЦОД"}], [{"id": 6, "name": "A1", "u_height": 42}])
    kinds = {o["kind"] for o in nb}
    assert kinds == {"site", "rack", "ip", "network", "vm", "prefix", "vlan"} and next(o for o in nb if o["kind"] == "vm")["ips"] == ["192.0.2.50"]
    hv = K.parse_hyperv({"format": "kavcheck-hyperv/1", "hosts": [{"name": "hv1"}], "vms": [{"id": "g-1", "name": "fs01", "host": "hv1", "bios_guid": UUID_VMX, "state": "Running", "cpu": 2}]})
    assert next(o for o in hv if o["kind"] == "vm")["attrs"]["power"] == "on"
    with pytest.raises(K.SourceError):
        K.parse_hyperv({"format": "other"})
    gen = K.parse_generic({"data": {"items": [{"host": "app-db01", "lastOk": "2026-11-18"}]}}, {"items": "data.items", "id": "host", "name": "host", "last_backup": "lastOk"}, "backup")
    assert gen[0]["kind"] == "backup" and gen[0]["attrs"]["last_backup"] == "2026-11-18"
