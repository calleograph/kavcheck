"""EOL операционных систем: Windows (клиент и сервер), Ubuntu, Debian, RHEL-семейство в форматах, которые отдаёт Kaspersky Security Center (название ОС, версия ядра, номер сборки,
пакеты base-files и *-release для Linux). Данные жизненного цикла — реальный срез endoflife.date (tests/fixtures/eol_os.json), названия синтетические и общие, без привязки к какой-либо установке.
Главное: ОС анализируется как самостоятельный объект; не определённая ОС не скрывается и не получает ни «Поддерживается», ни ложный EOL."""
import json
import uuid
from datetime import date
from pathlib import Path

import pytest
from sqlalchemy import select

from app.eol import compute as C
from app.eol.osmatch import OsHit, OsMiss, clean_name, linux_release, os_release
from app.eol.sync import apply_products
from app.models import CatalogState, EolFinding, EolHost, KscSource, utcnow
from tests.conftest import login
from tests.test_eol_compute import FakeKsc

DOC = json.loads((Path(__file__).parent / "fixtures" / "eol_os.json").read_text(encoding="utf-8"))
PROD = {p["name"]: p for p in DOC["result"]}
TODAY = date(2026, 10, 26)
REL = {p: [{"name": r["name"], "latest_name": (r.get("latest") or {}).get("name")} for r in PROD[p]["releases"]] for p in ("windows", "windows-server")}


def match(name, major=None, minor=None, build=None, **kw):
    return os_release(name, major, minor, build, releases=REL, **kw)


# ---- названия и версии Windows
@pytest.mark.parametrize("name,major,minor,build,release", [
    ("Microsoft Windows 10 Pro", 10, 0, 19045, "10-22h2"),
    ("Microsoft Windows 10 Home", 10, 0, 19045, "10-22h2"),
    ("Microsoft Windows 10 Enterprise", 10, 0, 19044, "10-21h2-e"),
    ("Microsoft Windows 10 Pro", 10, 0, 19044, "10-21h2-w"),
    ("Microsoft Windows 10 Enterprise LTSC 2019", 10, 0, 17763, "10-1809-e-lts"),
    ("Microsoft Windows 10 Корпоративная", 10, 0, 19044, "10-21h2-e"),
    ("Microsoft Windows 11 Pro", 10, 0, 22631, "11-23h2-w"),
    ("Microsoft Windows 11 Enterprise", 10, 0, 22631, "11-23h2-e"),
    ("Microsoft Windows 11 Education", 10, 0, 26100, "11-24h2-e"),
    ("Microsoft Windows 7 Professional", 6, 1, 7601, "7-sp1"),
    ("Microsoft Windows 7 Enterprise", 6, 1, 7601, "7-sp1"),
    ("Microsoft Windows 8.1 Pro", 6, 3, 9600, "8.1"),
    ("Microsoft Windows 8 Pro", 6, 2, 9200, "8"),
    ("Microsoft Windows XP Professional", 5, 1, 2600, "5-sp3"),
    ("Microsoft Windows Vista Business", 6, 0, 6002, "6-sp2"),
])
def test_windows_client_names_and_builds(name, major, minor, build, release):
    h = match(name, major, minor, build)
    assert isinstance(h, OsHit) and (h.product, h.release) == ("windows", release), h


def test_windows_10_and_11_are_never_matched_by_family_alone():
    """Без номера сборки выпуск Windows 10/11 не угадывается: раньше такие устройства молча пропадали, теперь видны с причиной."""
    for name in ("Microsoft Windows 10 Pro", "Microsoft Windows 11 Pro"):
        m = match(name, 10, 0, 0)
        assert isinstance(m, OsMiss) and m.code == "no_build" and "сборки" in m.reason
        m = match(name, 10, 0, 99999)
        assert isinstance(m, OsMiss) and m.code == "build_unknown" and "99999" in m.reason
    unk = match("Microsoft Windows 11", 10, 0, 22631)
    assert unk.release == "11-23h2-w" and unk.confidence == "name" and "Редакция" in unk.note


# ---- Windows Server
@pytest.mark.parametrize("name,major,minor,build,release", [
    ("Microsoft® Windows Server® 2003, Standard Edition", 5, 2, 3790, "2003-sp2"),
    ("Microsoft(R) Windows(R) Server 2003 Enterprise Edition", 5, 2, 3790, "2003-sp2"),
    ("Microsoft® Windows Server® 2008 Standard", 6, 0, 6002, "2008-sp2"),
    ("Microsoft Windows Server 2008 R2 Standard", 6, 1, 7601, "2008-r2-sp1"),
    ("Microsoft® Windows Server® 2008 R2 Enterprise", 6, 1, 7601, "2008-r2-sp1"),
    ("Microsoft Windows Server 2012 Standard", 6, 2, 9200, "2012"),
    ("Microsoft Windows Server 2012 R2 Datacenter", 6, 3, 9600, "2012-r2"),
    ("Microsoft Windows Server 2016 Standard", 10, 0, 14393, "2016"),
    ("Microsoft Windows Server 2019 Datacenter", 10, 0, 17763, "2019"),
    ("Microsoft Windows Server 2022 Standard", 10, 0, 20348, "2022"),
    ("Microsoft Windows Server 2025 Standard", 10, 0, 26100, "2025"),
    ("Windows Server 2019 Стандартный", 10, 0, 17763, "2019"),
    ("Microsoft Windows Server, version 1809", 10, 0, 17763, "1809-sac"),
])
def test_windows_server_names(name, major, minor, build, release):
    h = match(name, major, minor, build)
    assert isinstance(h, OsHit) and (h.product, h.release) == ("windows-server", release), h


def test_windows_server_without_year_in_name_is_resolved_by_kernel_and_build_but_marked_uncertain():
    for name, ma, mi, b, release in (("Microsoft Windows Server Standard", 6, 1, 7601, "2008-r2-sp1"), ("Windows Server", 6, 3, 9600, "2012-r2"), ("Windows Server", 10, 0, 17763, "2019"),
                                     ("Windows Server", 10, 0, 20348, "2022"), ("Windows Server", 10, 0, 14393, "2016")):
        h = match(name, ma, mi, b)
        assert isinstance(h, OsHit) and h.release == release and h.confidence == "name" and "не по названию" in h.note, (name, h)
    assert match("Windows Server", 10, 0, 99999).code == "build_unknown" and match("Windows Server", 0, 0, 0).code == "no_year"


# ---- Linux по названию
@pytest.mark.parametrize("name,product,release", [
    ("Ubuntu 18.04.6 LTS", "ubuntu", "18.04"), ("Ubuntu 20.04.6 LTS", "ubuntu", "20.04"), ("Ubuntu 22.04.3 LTS", "ubuntu", "22.04"), ("Ubuntu 24.04 LTS", "ubuntu", "24.04"),
    ("Ubuntu 16.04.7 LTS", "ubuntu", "16.04"), ("Ubuntu 23.10", "ubuntu", "23.10"),
    ("Debian GNU/Linux 12 (bookworm)", "debian", "12"), ("Debian GNU/Linux 9 (stretch)", "debian", "9"),
    ("CentOS Linux release 7.9.2009 (Core)", "centos", "7"), ("CentOS Stream release 9", "centos-stream", "9"),
    ("Red Hat Enterprise Linux Server release 7.9 (Maipo)", "rhel", "7"), ("Red Hat Enterprise Linux 9.3 (Plow)", "rhel", "9"),
    ("AlmaLinux 9.3 (Shamrock Pampas Cat)", "almalinux", "9"), ("Rocky Linux 8.8 (Green Obsidian)", "rocky-linux", "8"), ("Oracle Linux Server 8.8", "oracle-linux", "8"),
    ("SUSE Linux Enterprise Server 15 SP4", "sles", "15.4"),
])
def test_linux_named_in_ksc(name, product, release):
    h = match(name, 5, 15, 0, platform=6)
    assert isinstance(h, OsHit) and (h.product, h.release) == (product, release), h


# ---- Linux: KSC отдаёт просто «Linux», дистрибутив — по пакетам
@pytest.mark.parametrize("pkgs,product,release", [
    ([("base-files", "7.2ubuntu5.5")], "ubuntu", "14.04"), ([("base-files", "9.4ubuntu4.14")], "ubuntu", "16.04"), ([("base-files", "10.1ubuntu2.12")], "ubuntu", "18.04"),
    ([("base-files", "11ubuntu5.8")], "ubuntu", "20.04"), ([("base-files", "12ubuntu4.6")], "ubuntu", "22.04"), ([("base-files", "13ubuntu10.1")], "ubuntu", "24.04"),
    ([("base-files", "9.9+deb9u13")], "debian", "9"), ([("base-files", "10.3+deb10u13")], "debian", "10"), ([("base-files", "11.1+deb11u10")], "debian", "11"), ([("base-files", "12.4+deb12u7")], "debian", "12"),
    ([("redhat-release", "9.3-0.5.el9")], "rhel", "9"), ([("redhat-release-server", "7.9-9.el7")], "rhel", "7"),
    ([("centos-release", "7-9.2009.1.el7.centos")], "centos", "7"), ([("centos-stream-release", "9.0-24.el9")], "centos-stream", "9"),
    ([("almalinux-release", "9.3-1.el9")], "almalinux", "9"), ([("rocky-release", "8.8-1.8.el8")], "rocky-linux", "8"), ([("oraclelinux-release", "8.8-1.0.8.el8")], "oracle-linux", "8"),
    ([("sles-release", "15.4")], "sles", "15.4"),
    ([("base-files", "11.1+deb11u1"), ("centos-release", "7-9.el7")], "centos", "7"),            # *-release точнее base-files
])
def test_linux_reported_as_plain_linux_is_resolved_from_packages(pkgs, product, release):
    h = match("Linux", 5, 15, 0, platform=6, packages=pkgs)
    assert isinstance(h, OsHit) and (h.product, h.release, h.confidence) == (product, release, "high"), h
    assert h.label and release in h.label


def test_linux_without_distribution_data_is_reported_with_the_reason_not_hidden():
    none = match("Linux", 5, 15, 0, platform=6, packages=[])
    assert isinstance(none, OsMiss) and none.code == "linux_no_info" and "base-files" in none.reason
    amb = match("Linux", 5, 15, 0, platform=6, packages=[("base-files", "13ubuntu11")])           # интерим-выпуск Ubuntu: сказать «24.04» нельзя
    assert amb.code == "ambiguous" and "Ubuntu" in amb.reason
    other = match("Linux", 5, 15, 0, platform=6, packages=[("base-files", "2021.1")])
    assert other.code == "ambiguous"
    for n in ("Astra Linux (Smolensk) 1.7", "ALT Linux 10", "РЕД ОС 7.3"):
        m = match(n, 5, 15, 0, platform=6)
        assert isinstance(m, OsMiss) and m.code == "vendor_absent" and "endoflife.date" in m.reason, n
    assert match("Linux", 5, 4, 0, platform=6, packages=[("astra-version", "1.7")]).code == "vendor_absent"
    assert match("", 0, 0, 0).code == "no_os" and match("Solaris 11", 5, 11, 0).code == "unrecognized"


def test_marks_and_prefixes_are_cleaned():
    assert clean_name("Microsoft® Windows Server® 2008 R2 Standard") == "Windows Server 2008 R2 Standard"
    assert clean_name("Microsoft(R) Windows(R) XP") == "Windows XP" and linux_release([]).code == "linux_no_info"


# ---- расчёт целиком: KSC → находки → устройства
def os_hosts():
    def h(i, name, ma, mi, b, plat=2):
        return {"host_id": i, "os_name": name, "os_major": ma, "os_minor": mi, "os_build": b, "platform": plat, "active": 1}
    return [h(1, "Microsoft® Windows Server® 2008 R2 Standard", 6, 1, 7601), h(2, "Microsoft Windows Server 2012 R2 Datacenter", 6, 3, 9600), h(3, "Microsoft Windows Server 2016 Standard", 10, 0, 14393),
            h(4, "Microsoft Windows Server 2022 Standard", 10, 0, 20348), h(5, "Microsoft Windows 7 Professional", 6, 1, 7601), h(6, "Microsoft Windows 10 Pro", 10, 0, 19045),
            h(7, "Microsoft Windows 11 Pro", 10, 0, 26200), h(8, "Microsoft Windows 10 Pro", 10, 0, 0),
            h(10, "Linux", 5, 4, 0, 6), h(11, "Linux", 5, 15, 0, 6), h(12, "Linux", 6, 8, 0, 6), h(13, "Linux", 5, 10, 0, 6), h(14, "Linux", 5, 10, 0, 6), h(15, "Linux", 4, 19, 0, 6),
            h(16, "Linux", 5, 15, 0, 6), h(17, "Astra Linux (Smolensk) 1.7", 5, 10, 0, 6), h(18, "Ubuntu 22.04.3 LTS", 5, 15, 0, 6), h(19, "", 0, 0, 0)]


PKGS = {10: [("base-files", "9.4ubuntu4.14")], 11: [("base-files", "10.1ubuntu2.12")], 12: [("base-files", "12ubuntu4.6")], 13: [("centos-release", "7-9.2009.1.el7.centos")],
        14: [("centos-release", "7-9.2009.1.el7.centos")], 15: [("base-files", "11.1+deb11u10")], 16: []}


async def seed_os(app):
    sm = app.state.session_maker
    sample = json.loads((Path(__file__).parent / "fixtures" / "eol_sample.json").read_text(encoding="utf-8"))["result"]
    await apply_products(sm, DOC["result"] + [p for p in sample if p["name"] not in PROD])               # документ должен быть «полным» (не меньше 20 продуктов)
    sid = uuid.uuid4()
    async with sm() as db:
        db.add(KscSource(id=sid, name="KSC-OS", host="os.example.local", port=1433, database="KAV", username="u", password_enc="x", is_active=True))
        await db.flush()
        db.add(CatalogState(source_id=sid, status="ready", built_at=utcnow(), activity_days=30))
        await db.commit()
    return sid


async def compute_os(app, sid, hosts=None, pkgs=None):
    sm = app.state.session_maker
    async with sm() as db:
        src = await db.get(KscSource, sid)
    ksc = FakeKsc({}, hosts or os_hosts(), PKGS if pkgs is None else pkgs)
    res = await C.compute_source(sm, ksc, src, activity_days=30, today=TODAY)
    async with sm() as db:
        found = {(f.subject, f.version): f for f in (await db.execute(select(EolFinding).where(EolFinding.source_id == sid, EolFinding.kind == "os"))).scalars()}
        links = {}
        for h in (await db.execute(select(EolHost).where(EolHost.source_id == sid, EolHost.kind == "os"))).scalars():
            links.setdefault((h.subject, h.version), []).append(h.host_id)
    return res, found, links


async def test_outdated_operating_systems_get_eol_and_unknown_ones_are_shown_not_hidden(app):
    sid = await seed_os(app)
    res, found, links = await compute_os(app, sid)
    st = {k[0]: (f.status, f.severity, f.confirmed, f.eol_product, f.eol_release) for k, f in found.items()}
    assert st["Microsoft Windows Server 2008 R2 Standard"] == ("eol", "critical", True, "windows-server", "2008-r2-sp1")
    assert st["Microsoft Windows Server 2012 R2 Datacenter"][:3] == ("eol", "critical", True)         # и обычная, и расширенная поддержка закончились
    assert st["Microsoft Windows Server 2016 Standard"][0] == "upcoming"                                # до 12.01.2027
    assert "Microsoft Windows Server 2022 Standard" not in st                                           # поддерживается: проблем нет
    assert st["Microsoft Windows 7 Professional"][:3] == ("eol", "critical", True)
    win10 = st["Microsoft Windows 10 Pro"]
    assert win10[0] == "extended" and win10[2] is False                                                 # платная ESU: подписку по данным KSC подтвердить нельзя — не считается ни EOL, ни поддержкой
    assert "расширенн" in found[("Microsoft Windows 10 Pro", "10.0.19045")].condition.lower()
    assert "Microsoft Windows 11 Pro" not in st
    assert st["Ubuntu 16.04"][:3] == ("eol", "critical", True) and st["Ubuntu 18.04"][0] == "extended" and "Ubuntu 22.04" not in st
    assert st["CentOS 7"][:3] == ("eol", "critical", True) and st["Debian 11"][0] == "extended"
    assert sorted(links[("CentOS 7", "7")]) == [13, 14]                                                  # устройства разных пакетов объединены в одну находку
    und = {k: f for k, f in found.items() if f.status == "undetermined"}
    assert {f.os_key["code"] for f in und.values()} == {"no_build", "linux_no_info", "vendor_absent", "no_os"}
    for f in und.values():
        assert f.severity == "" and not f.confirmed and f.condition.startswith("Не удалось определить EOL.") and f.hosts_all >= 1
    assert res["diag"]["os_undetermined"]["hosts"] == 4 and res["diag"]["os_undetermined"]["reasons"] == {"no_build": 1, "linux_no_info": 1, "vendor_absent": 1, "no_os": 1}
    assert all(f.status != "supported" for f in found.values())                                         # ложного «Поддерживается» нет нигде


async def test_os_is_analysed_independently_of_the_software_list(app):
    """В реестре ПО нет ни одной программы, каталог пуст — ОС всё равно сопоставляется."""
    sid = await seed_os(app)
    _, found, _ = await compute_os(app, sid, pkgs={})
    assert ("Microsoft Windows Server 2008 R2 Standard", "6.1.7601") in found and found[("Microsoft Windows Server 2008 R2 Standard", "6.1.7601")].status == "eol"
    assert found[("Linux", "—")].hosts_all == 7 and found[("Linux", "—")].status == "undetermined"       # без пакетов дистрибутив неизвестен для всех семи Linux «Linux»


async def test_api_lists_unsupported_operating_systems_and_undetermined_with_reason(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await seed_os(app)
    await compute_os(app, sid)
    h = {"X-Source-Id": str(sid)}
    r = (await client.get("/api/v1/eol/infra", params={"kind": "os"}, headers=h)).json()
    names = {i["subject"]: i for i in r["items"]}
    assert r["by_status"]["eol"] >= 3 and r["by_status"]["undetermined"] == 4
    assert names["Microsoft Windows Server 2008 R2 Standard"]["status"] == "eol" and names["Microsoft Windows Server 2008 R2 Standard"]["severity"] == "critical"
    assert names["Linux"]["status"] == "undetermined" and names["Linux"]["status_ru"] == "Не удалось определить EOL" and "base-files" in names["Linux"]["condition"] and names["Linux"]["severity"] == ""
    only = (await client.get("/api/v1/eol/infra", params={"kind": "os", "status": "undetermined"}, headers=h)).json()
    assert only["total"] == 4 and {i["status"] for i in only["items"]} == {"undetermined"}
    apps = (await client.get("/api/v1/eol/infra", params={"kind": "app"}, headers=h)).json()
    assert apps["total"] == 0                                                                           # категория «Программы» ОС не содержит
    s = (await client.get("/api/v1/eol/summary", headers=h)).json()
    assert s["os_undetermined"] == {"items": 4, "devices": 4} and s["kinds"]["os"] >= 6 and s["findings"]["eol"] >= 5
    hosts = (await client.get("/api/v1/eol/infra/hosts", params={"source_id": str(sid), "kind": "os", "subject": "Linux", "version": "—"}, headers=h)).json()
    assert hosts["total"] == 1                                                                          # только устройство 16 (у остальных «Linux» дистрибутив определён)


async def test_report_constructor_detail_columns_finding_context_and_templates(client, app):
    """Единый конструктор: подробность (краткий/подробный), состав столбцов, отчёт по одной находке из боковой панели, шаблон с быстрым видом отчёта."""
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await seed_os(app)
    await compute_os(app, sid)
    h = {"X-Source-Id": str(sid)}

    async def preview(params):
        r = await client.post("/api/v1/quick/preview", json={"kind": "quick_eol", "params": {"kinds": ["os"], **params}, "source_ids": [str(sid)]}, headers=h)
        assert r.status_code == 200, r.text
        return r.json()

    full = await preview({"statuses": ["eol", "extended", "upcoming", "undetermined"]})
    assert [t["id"] for t in full["doc"]["tables"]] == ["rows", "devices"] and full["total"] == 13 and {c["key"] for c in full["doc"]["columns_all"]} >= {"title", "hosts", "condition"}
    short = await preview({"statuses": ["eol", "extended", "upcoming", "undetermined"], "detail": "summary"})
    assert [t["id"] for t in short["doc"]["tables"]] == ["rows", "summary"] and short["total"] == full["total"]       # краткий: сводные таблицы без построчного списка устройств
    assert any("Краткий отчёт" in n for n in short["doc"]["notes"])
    cols = await preview({"statuses": ["eol"], "columns": ["title", "hosts", "nonexistent"]})
    assert [c["key"] for c in cols["columns"]] == ["title", "hosts"] and set(cols["items"][0]) >= {"title", "hosts", "condition"}      # в таблицу попадают выбранные, строки остаются полными
    one = await preview({"statuses": ["eol"], "finding": {"source_id": str(sid), "kind": "os", "subject": "Microsoft Windows Server 2008 R2 Standard", "version": "6.1.7601"}})
    assert one["total"] == 1 and one["items"][0]["title"] == "Microsoft Windows Server 2008 R2 Standard"
    und = await preview({"statuses": ["undetermined"]})
    assert und["total"] == 4 and any(m["key"] == "undetermined" and m["value"] == 4 for m in und["doc"]["metrics"])
    bad = await client.post("/api/v1/quick/preview", json={"kind": "quick_eol", "params": {"detail": "huge"}, "source_ids": [str(sid)]}, headers=h)
    assert bad.status_code == 422
    t = await client.post("/api/v1/report-templates", json={"name": "ОС без поддержки: кратко", "kind": "quick_eol", "params": {"kinds": ["os"], "statuses": ["eol"], "detail": "summary"}})
    assert t.status_code == 201 and t.json()["params"]["detail"] == "summary" and t.json()["params"]["kinds"] == ["os"]


async def test_finding_devices_panel_is_searchable_sortable_and_paged_on_the_server(client, app):
    """Боковая панель устройств находки: поиск, сортировка и страницы выполняет сервер (а не страница в браузере), устройства без подготовленных данных зон не пропадают."""
    from datetime import datetime, timedelta, timezone

    from app.models import ZcHost, ZcSource

    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await seed_os(app)
    await compute_os(app, sid)
    async with app.state.session_maker() as db:
        db.add(ZcSource(source_id=sid, gen=1, status="ready"))
        now = datetime.now(timezone.utc)
        for hid, name, os_, ago in ((13, "zeta-host", "Linux", 5), (14, "alpha-host", "Linux", 1)):
            db.add(ZcHost(source_id=sid, host_id=hid, gen=1, name=name, search=name, ip_num=1, os=os_, active=True, last_connected=now - timedelta(hours=ago), data={"ip": "192.0.2.9", "group": "Серверы", "zones": []}))
        await db.commit()
    h = {"X-Source-Id": str(sid)}
    base = {"source_id": str(sid), "kind": "os", "subject": "CentOS 7", "version": "7"}

    async def names(**p):
        r = (await client.get("/api/v1/eol/infra/hosts", params={**base, **p}, headers=h)).json()
        return [i["name"] for i in r["items"]], r["total"]

    assert await names() == (["alpha-host", "zeta-host"], 2)                                  # по имени по умолчанию
    assert (await names(desc=True))[0] == ["zeta-host", "alpha-host"] and (await names(sort="last_connected"))[0] == ["zeta-host", "alpha-host"]
    assert await names(q="alp*") == (["alpha-host"], 1)                                      # поиск — на сервере
    assert await names(limit=1, offset=1) == (["zeta-host"], 2)                              # страница, а не весь список
    assert (await client.get("/api/v1/eol/infra/hosts", params={**base, "sort": "bogus"}, headers=h)).status_code == 422
    # у находки без подготовленных данных зон устройства всё равно перечислены (по идентификаторам)
    lin = (await client.get("/api/v1/eol/infra/hosts", params={**{**base, "subject": "Ubuntu 16.04", "version": "16.04"}}, headers=h)).json()
    assert lin["total"] == 1 and lin["items"][0]["host_id"] == 10


def test_template_keeps_report_settings_but_not_page_context():
    from app.api.reports import template_settings

    got = template_settings({"detail": "summary", "columns": ["name"], "statuses": ["eol"], "host_ids": [1, 2], "q": "srv", "zone": "z1", "finding": {"a": 1}, "nested": {"x": 1}, "long": "x" * 500})
    assert got == {"detail": "summary", "columns": ["name"], "statuses": ["eol"]}


async def test_system_status_lists_jobs_per_source_including_catalog(client, app):
    """Регрессия 0.9.6: «Состояние системы» падало с ошибкой 500, как только в системе есть хотя бы один источник (не был импортирован CatalogState)."""
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await seed_os(app)
    await compute_os(app, sid)
    r = await client.get("/api/v1/admin/system")
    assert r.status_code == 200, r.text
    src = r.json()["jobs"]["sources"]
    assert len(src) == 1 and src[0]["source"] == "KSC-OS" and src[0]["catalog"]["status"] == "ready"
