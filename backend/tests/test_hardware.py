"""Аппаратные характеристики и контроль ресурсов Linux-серверов: сводка по данным KSC, пороги CPU и ОЗУ, только Linux, неполные данные, зоны."""
from datetime import datetime, timezone

from app.ksc import hardware as HW
from app.ksc import protection as P
from app.services.settings import HardwareSettings
from app.zones import snapshot as SN
from tests.conftest import login

GB = 10**9


def row(t, name="", **kw):
    base = {"dev_type": t, "name": name, "descr": "", "manuf": "", "dev_id": name, "serial": "", "x1": "", "x2": 0, "x3": 0, "cpu_mhz": None, "cpu_cores": None, "cpu_threads": None,
            "bios_manuf": "", "bios_version": "", "bios_date": None}
    return {**base, **kw}


def server(cores=4, ram_mb=8192, disks=((120, 40),)):
    rows = [row(1, "Intel Xeon", dev_id="cpu0", cpu_cores=cores, cpu_threads=cores * 2, cpu_mhz=2400), row(0, "Board", manuf="QEMU", bios_manuf="SeaBIOS", bios_version="1.16")]
    rows += [row(2, f"Physical Memory {i}", dev_id=f"m{i}", x3=(ram_mb // 2) * 1048576) for i in range(2)]
    rows += [row(3, f"/dev/vd{chr(97 + i)}", dev_id=f"d{i}", x2=t * GB, x3=f * GB, x1=f"SN{i}") for i, (t, f) in enumerate(disks)]
    return rows


def test_summary_line_virtual_and_no_double_counting_of_disks():
    rows = server(2, 4096, ((100, 30),)) + [row(3, "/dev/vda1", dev_id="p1", x2=99 * GB, x3=29 * GB), row(3, "lvm-root", dev_id="p2", x2=50 * GB), row(3, "/dev/dm-0", dev_id="p3", x2=50 * GB),
                                           row(3, "/dev/vda", dev_id="d0", x2=100 * GB, x3=30 * GB, x1="SN0")]               # последняя — повтор той же строки
    h = HW.finish(HW.summarize(rows))
    assert h["cores"] == 2 and h["ram_mb"] == 4096 and h["disk_total_gb"] == 100.0 and h["disk_free_gb"] == 30.0 and len(h["disks"]) == 1 and len(h["logical"]) == 3
    assert h["virtual"] and h["line"] == "Диски: 100 ГБ · CPU: 2 ядра · ОЗУ: 4 ГБ"


def test_missing_data_is_shown_as_no_data_and_never_evaluated():
    h = HW.finish(HW.summarize([]))
    assert h["line"] == "Нет данных" and not h["known"]
    part = HW.finish(HW.summarize([row(2, "m", x3=2048 * 1048576)]))                      # процессор без числа ядер, дисков нет
    assert part["cores"] is None and part["disk_total_gb"] is None and part["line"] == "Диски: Нет данных · CPU: Нет данных · ОЗУ: 2 ГБ"
    cfg = HardwareSettings()
    assert HW.evaluate(part, cfg) == [] and HW.evaluate(None, cfg) == []                  # ядер нет — «Мало ядер» не выдумывается; ОЗУ 2 ГБ при пороге 2 048 МБ — норма


def test_cpu_and_ram_thresholds_and_exclusions():
    cfg = HardwareSettings()
    ev = lambda cores=None, ram=None, name="": [(p["key"], p["level"]) for p in HW.evaluate({"cores": cores, "ram_mb": ram}, cfg, name)]  # noqa: E731
    assert ev(4, 8192) == [] and ev(3, 8192) == []                                          # три и больше — норма
    assert ev(2, 8192) == [("hw_cpu", "warning")] and ev(1, 8192) == [("hw_cpu", "critical")]
    assert ev(4, 1024) == [("hw_ram", "warning")] and ev(1, 512) == [("hw_cpu", "critical"), ("hw_ram", "warning")]
    p = HW.evaluate({"cores": 2, "ram_mb": 1024}, cfg)
    assert p[0]["title"] == "Мало ядер CPU" and p[0]["actual"] == 2 and p[0]["threshold"] == 3 and p[1]["title"] == "Недостаточно ОЗУ" and p[1]["actual"] == 1024 and "порог" in p[1]["text"]
    assert HW.evaluate({"cores": 1, "ram_mb": 100}, HardwareSettings(enabled=False)) == []
    assert ev(1, 100, "lab-srv-01") != [] and HW.evaluate({"cores": 1}, HardwareSettings(exclude_masks=["lab-*"]), "lab-srv-01") == []
    assert HW.evaluate({"cores": 2, "ram_mb": 3000}, HardwareSettings(cpu_ok_cores=2, ram_min_mb=4096))[0]["key"] == "hw_ram"      # пороги настраиваются


def rec(host_id, platform):
    return {"host_id": host_id, "name": f"h{host_id}", "platform": platform, "av": None, "mask": 0, "rtp_state": None, "uncured": 0, "last_full_scan": None, "ip": "192.0.2.1", "days_since_connection": 1}


def test_only_linux_gets_resource_problems_and_they_flow_into_protection_and_zone_columns():
    recs = [rec(1, "Linux"), rec(2, "Windows"), rec(3, "Linux")]
    agg = {1: {"known": True, "cores": 1, "ram_mb": 1024}, 2: {"known": True, "cores": 1, "ram_mb": 512}}      # у Windows-узла 2 данные есть, но правила к нему не применяются; у Linux-узла 3 данных нет
    HW.attach(recs, agg, HardwareSettings())
    now = datetime.now(timezone.utc)
    assert [r["hw"] is not None for r in recs] == [True, False, False]
    assert P.problems(recs[0], now, bases_days=3, scan_days=30)[-2:] == ["hw_cpu", "hw_ram"] and "hw_cpu" not in P.problems(recs[1], now, bases_days=3, scan_days=30)
    assert not {"hw_cpu", "hw_ram"} & set(P.problems(recs[2], now, bases_days=3, scan_days=30))                # нет данных — нет проблемы
    cols = SN.host_columns(recs[0], now, 30)
    assert cols["p_hwc"] and cols["p_hwr"] and cols["hw_crit"] and not SN.host_columns(recs[1], now, 30)["p_hwc"]


async def test_host_hardware_endpoint_with_full_partial_and_missing_data(client, app, monkeypatch):
    await login(client, "admin", "Admin-Passw0rd-123")
    s = (await client.post("/api/v1/admin/sources", json={"name": "KSC-A", "host": "a.example.local", "database": "KAV", "username": "u", "password": "p"})).json()
    await client.post("/api/v1/auth/source", json={"source_id": s["id"]})
    data = {7: (server(2, 1024), 6), 8: ([row(2, "m", x3=4096 * 1048576)], 6), 9: ([], 6), 10: (server(1, 512), 2)}

    class Fake:
        async def run(self, sql, params=None, max_rows=0):
            rows, plat = data[int(params["id"])]
            return rows if "hst_hwinv_dev" in sql else [{"host_id": params["id"], "name": f"host-{params['id']}", "platform_type": plat}]

    monkeypatch.setattr(app.state.sources, "client", lambda src: Fake())
    r = (await client.get("/api/v1/hosts/7/hardware")).json()
    assert r["linux"] and r["hw"]["line"].startswith("Диски: 120 ГБ · CPU: 2 ядра") and [p["key"] for p in r["problems"]] == ["hw_cpu", "hw_ram"] and r["thresholds"]["ram_min_mb"] == 2048
    r = (await client.get("/api/v1/hosts/8/hardware")).json()
    assert r["problems"] == [] and r["hw"]["cores"] is None                                 # ядер нет — оценка пропущена
    r = (await client.get("/api/v1/hosts/9/hardware")).json()
    assert r["hw"]["line"] == "Нет данных" and r["problems"] == []
    assert (await client.get("/api/v1/hosts/10/hardware")).json()["problems"] == []          # Windows: правила не применяются


async def test_zone_counts_and_filters_list_hardware_problems_separately_from_vulnerabilities(app):
    import uuid

    from app.models import KscSource, ZcHost, ZcHostZone, ZcSource
    from app.zones import zread as ZR

    sid = uuid.uuid4()
    async with app.state.session_maker() as db:
        db.add(KscSource(id=sid, name="KSC-A", host="a.example.local", port=1433, database="KAV", username="u", password_enc="x", is_active=True))
        await db.flush()
        db.add(ZcSource(source_id=sid, gen=1, status="ready"))
        for hid, hwc, hwr, crit in ((1, True, True, True), (2, False, True, False), (3, False, False, False)):
            hw = {"problems": ([{"key": "hw_cpu", "level": "critical", "text": "ядер процессора: 1"}] if hwc else []) + ([{"key": "hw_ram", "level": "warning", "text": "ОЗУ: 1024 МБ"}] if hwr else [])}
            db.add(ZcHost(source_id=sid, host_id=hid, gen=1, name=f"srv-{hid}", days_since=1.0, active=True, p_hwc=hwc, p_hwr=hwr, hw_crit=crit, data={"hw": hw, "zones": ["z1"]}))
            db.add(ZcHostZone(source_id=sid, host_id=hid, gen=1, zone_id="z1"))
        await db.commit()
        st = (await ZR.group_stats(db, sids=[sid], zone_id="z1"))["z1"]
        probs = {p["key"]: p["hosts"] for p in st["problems"]}
        assert probs["hw_cpu"] == 1 and probs["hw_ram"] == 2 and st["protection"] == 2 and st["critical"] == 0 and st["vulns"]["critical"] == 0      # уязвимости не затронуты
        total, items = await ZR.hosts_page(db, "z1", [sid], bd=3, sd=30, ext=True, default_days=30, zone_days={}, problem="hw_ram")
        assert total == 2 and {i["name"] for i in items} == {"srv-1", "srv-2"}
        row = next(i for i in items if i["name"] == "srv-1")
        assert {p["key"]: (p["level"], p["detail"]) for p in row["problems"]}["hw_cpu"] == ("critical", "ядер процессора: 1")
