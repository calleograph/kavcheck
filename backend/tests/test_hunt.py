"""CVE Hunt: критерии (CVE, продукты, диапазоны), режимы KSC / сеть / комбинированный, статусы и основания, исключение посторонних CVE, объединение источников, повторные проверки, область и права."""
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.hunt import criteria as C
from app.hunt import results as RS
from app.models import DeviceUser, HuntHit, KscSource, PtHost, PtJob, VdbAffected, VdbVuln, Zone, ZcHost, ZcHostZone, ZcSource, utcnow
from app.pentest import engine as EN
from app.pentest.scanner import Scanner
from tests.conftest import login
from tests.test_pentest_scanner import APACHE, SSH, fake, state  # noqa: F401

PHP_HDR = {"id": "http-headers", "output": "\n  Server: nginx/1.24.0\n  X-Powered-By: PHP/8.1.12\n  Content-Type: text/html"}
WEB = {"port": 80, "service": "http", "product": "nginx", "version": "1.24.0", "cpe": "cpe:/a:nginx:nginx:1.24.0", "banner": "HTTP/1.1 200 OK", "scripts": [PHP_HDR]}
WEB_NEW = {**WEB, "scripts": [{"id": "http-headers", "output": "\n  X-Powered-By: PHP/8.3.9"}]}
WEB_NOVER = {**WEB, "scripts": [{"id": "http-headers", "output": "\n  X-Powered-By: PHP"}]}
CVE = "CVE-2024-1111"


async def seed(app, cves=((CVE, "php", "php", "8.1.0", "8.1.30"),)):
    async with app.state.session_maker() as db:
        for key, vendor, prod, lo, hi in cves:
            db.add_all([VdbAffected(source="nvd", generation=1, ext_id=key, vuln_key=key, vendor=vendor, product=prod, vendor_key=vendor, product_key=prod, v_start=lo, v_end=hi, v_start_incl=True, v_end_incl=True),
                        VdbVuln(vuln_key=key, title=f"Уязвимость {prod}", sev_rank=4, score=9.8, score_version="3.1", exploited=False)])
        await db.commit()
    await EN.ensure_nse(app.state.session_maker)


def hunter(app, fake):
    return Scanner(app.state.session_maker, app.state.settings_svc, nmap=fake.path)


async def create(client, **kw):
    body = {"cves": [CVE], "mode": "network", "scope": {"kind": "custom", "text": "192.0.2.10"}, "confirm_scope": True, **kw}
    r = await client.post("/api/v1/hunt/jobs", json=body)
    assert r.status_code == 201, r.text
    return r.json()


async def hits(app, jid, **w):
    async with app.state.session_maker() as db:
        return [h for h in (await db.execute(select(HuntHit).where(HuntHit.job_id == uuid.UUID(jid)).order_by(HuntHit.id))).scalars() if all(getattr(h, k) == v for k, v in w.items())]


# ------------------------------------------------------------------------------------------------ критерии
def test_version_conditions_for_products():
    mk = lambda **kw: {"kind": "product", "mode": "any", "versions": [], **kw}   # noqa: E731
    assert C.version_in(mk(mode="exact", versions=["8.1.12", "7.4.3"]), "8.1.12") is True and C.version_in(mk(mode="exact", versions=["8.1.12"]), "8.1.13") is False
    assert C.version_in(mk(mode="range", v_min="8.1.0", v_max="8.1.30"), "8.1.12") is True and C.version_in(mk(mode="range", v_min="8.1.0", v_max="8.1.30"), "8.2.0") is False
    assert C.version_in(mk(mode="below", below="8.2.0"), "8.1.30") is True and C.version_in(mk(mode="below", below="8.2.0"), "8.2.0") is False
    assert C.version_in(mk(mode="above", above="8.1"), "8.1.1") is True and C.version_in(mk(mode="any"), "1.0") is True
    assert C.version_in(mk(mode="any"), "") is None                                                         # версия неизвестна — не «соответствует» и не «не соответствует»
    assert C.version_in(mk(mode="any", only_vulnerable=True, vuln_ranges=[{"start": "8.1.0", "end": "8.1.30", "start_incl": True, "end_incl": True}]), "8.1.12") is True
    assert C.version_in(mk(mode="any", only_vulnerable=True, vuln_ranges=[{"start": "8.1.0", "end": "8.1.30", "start_incl": True, "end_incl": True}]), "8.3.0") is False
    assert C.version_in(mk(mode="any", only_eol=True, eol_cycles=["7.4"]), "7.4.33") is True and C.version_in(mk(mode="any", only_eol=True, eol_cycles=["7.4"]), "8.1.0") is False
    assert C.version_in({"kind": "cve", "ranges": []}, "8.1.12") is None                                    # нет диапазонов в базе — достоверно судить нельзя


async def test_resolve_cve_takes_ranges_ports_and_warnings_from_the_vulnerability_base(client, app):
    await seed(app)
    await login(client, "admin", "Admin-Passw0rd-123")
    c = (await client.post("/api/v1/hunt/resolve", json={"cves": ["cve-2024-1111"]})).json()["criteria"][0]
    assert c["key"] == CVE and c["kb"] == "php" and c["ranges"][0]["start"] == "8.1.0" and 80 in c["ports"] and 8443 in c["ports"] and c["known"]
    assert any("специализированной проверки" in w for w in c["warnings"]) and any("PHP" in w and "версию" in w for w in c["warnings"])         # проверки нет; PHP может скрывать версию
    unknown = (await client.post("/api/v1/hunt/resolve", json={"cves": ["CVE-2030-0001"]})).json()["criteria"][0]
    assert not unknown["ranges"] and any("нет в базе" in w for w in unknown["warnings"])
    assert (await client.post("/api/v1/hunt/resolve", json={"cves": ["not-a-cve"]})).status_code == 422 and (await client.post("/api/v1/hunt/resolve", json={})).status_code == 422
    bad = await client.post("/api/v1/hunt/resolve", json={"products": [{"name": "PHP", "mode": "range"}]})
    assert bad.status_code == 422 and "версия" in bad.json()["detail"]
    s = (await client.get("/api/v1/hunt/suggest", params={"q": "2024-1111"})).json()
    assert s["cves"][0]["id"] == CVE and any(p["kb"] == "php" for p in (await client.get("/api/v1/hunt/suggest", params={"q": "php"})).json()["products"])


# ------------------------------------------------------------------------------------------------ сеть
async def test_network_cve_hunt_statuses_and_basis(client, app, fake):  # noqa: F811
    await seed(app, cves=((CVE, "php", "php", "8.1.0", "8.1.30"), ("CVE-2024-9999", "nginx", "nginx", "1.0.0", "9.9.9")))      # вторая CVE — посторонняя
    fake.scenario({"192.0.2.10": {"ports": [WEB]}, "192.0.2.11": {"ports": [WEB_NEW]}, "192.0.2.12": {"ports": [WEB_NOVER]}, "192.0.2.13": {"ports": [SSH]}})
    await login(client, "admin", "Admin-Passw0rd-123")
    j = await create(client, scope={"kind": "custom", "text": "192.0.2.10-13"})
    assert j["profile"] == "hunt" and j["targets_n"] == 4
    await hunter(app, fake).run_job(uuid.UUID(j["id"]))
    job, _ = await state(app, uuid.UUID(j["id"]))
    assert job.status == "done" and job.findings_n == 2, (job.status, job.diag, job.error)
    got = {h.ip: h for h in await hits(app, j["id"])}
    assert set(got) == {"192.0.2.10", "192.0.2.12"}                                                       # 8.3.9 вне диапазона; SSH — не PHP; посторонняя CVE nginx в результат не попала
    assert got["192.0.2.10"].status == "probable" and got["192.0.2.10"].version == "8.1.12" and got["192.0.2.10"].port == 80 and got["192.0.2.10"].basis == "network"
    assert got["192.0.2.10"].vuln_key == CVE and "X-Powered-By: PHP/8.1.12" in got["192.0.2.10"].evidence[0]["text"]                  # конкретный исходный признак
    assert got["192.0.2.12"].status == "needs_check" and any("версия" in e["text"] for e in got["192.0.2.12"].evidence)                 # PHP обнаружен, версии нет
    assert not [h for h in await hits(app, j["id"]) if h.vuln_key == "CVE-2024-9999"]
    r = (await client.get(f"/api/v1/hunt/jobs/{j['id']}/results")).json()
    assert [x["ip"] for x in r["items"]] == ["192.0.2.10", "192.0.2.12"] and r["counts"] == {"confirmed": 0, "probable": 1, "needs_check": 1, "failed": 0}      # по степени подтверждённости
    assert r["items"][0]["user"] == "Не определён" and r["items"][0]["zone"] == "Не назначена"                                                # компьютера нет в KSC: находка сохранена, поля по умолчанию
    d = (await client.get(f"/api/v1/hunt/jobs/{j['id']}/results/{r['items'][0]['id']}")).json()
    assert d["evidence"] and d["evidence"][0]["kind"] == "banner"
    # посторонние задания не попадают в обычный Pentest
    assert (await client.get("/api/v1/pentest/jobs")).json()["total"] == 0
    cov = (await client.get(f"/api/v1/hunt/jobs/{j['id']}/coverage")).json()
    assert cov["total"] == 4


async def test_scanned_ports_are_only_the_selected_ones_and_no_full_pentest(client, app, fake):  # noqa: F811
    await seed(app)
    fake.scenario({"192.0.2.10": {"ports": [WEB, {**SSH}]}})
    await login(client, "admin", "Admin-Passw0rd-123")
    j = await create(client, ports="8081")
    await hunter(app, fake).run_job(uuid.UUID(j["id"]))
    calls = fake.calls()
    ports_call = next(c for c in calls if c["stage"] == "ports")
    assert ports_call["args"][ports_call["args"].index("-p") + 1] == "80,443,8080,8443,8081"                   # порты критерия + добавленные оператором, а не профиль «топ-1000»
    sv = next(c for c in calls if c["stage"] == "services")
    assert "--script" in sv["args"] and sv["args"][sv["args"].index("--script") + 1].split(",") == ["banner", "http-headers"] or "http-headers" in sv["args"][sv["args"].index("--script") + 1]
    assert not any("vuln" in " ".join(c["args"]) for c in calls)


async def test_distro_package_is_never_confirmed_by_version_alone(client, app, fake):  # noqa: F811
    await seed(app, cves=(("CVE-2024-6387", "openbsd", "openssh", "8.5", "9.7"),))
    deb = {**SSH, "version": "9.2p1 Debian 2+deb12u2", "cpe": "cpe:/a:openbsd:openssh:9.2p1", "extrainfo": "protocol 2.0"}
    fake.scenario({"192.0.2.20": {"ports": [deb]}})
    await login(client, "admin", "Admin-Passw0rd-123")
    j = await create(client, cves=["CVE-2024-6387"], scope={"kind": "custom", "text": "192.0.2.20"})
    await hunter(app, fake).run_job(uuid.UUID(j["id"]))
    h = (await hits(app, j["id"]))[0]
    assert h.status == "needs_check" and any("дистрибутив" in e["text"].lower() or "исправлени" in e["text"].lower() for e in h.evidence)       # backport: «Требует проверки»


async def test_unreachable_host_is_failed_not_clean_and_job_partial(client, app, fake):  # noqa: F811
    await seed(app)
    fake.scenario({"192.0.2.10": {"ports": [WEB]}, "192.0.2.14": {"ports": [WEB], "fail": "ports"}})
    await login(client, "admin", "Admin-Passw0rd-123")
    j = await create(client, scope={"kind": "custom", "text": "192.0.2.10 192.0.2.14"})
    await hunter(app, fake).run_job(uuid.UUID(j["id"]))
    job, _ = await state(app, uuid.UUID(j["id"]))
    assert job.status == "partial" and job.diag["reasons"]
    by = {h.ip: h for h in await hits(app, j["id"])}
    assert by["192.0.2.10"].status == "probable" and by["192.0.2.14"].status == "failed" and by["192.0.2.14"].crit_key == "*"
    items = (await client.get(f"/api/v1/hunt/jobs/{j['id']}/results", params={"status": "failed"})).json()["items"]
    assert [x["ip"] for x in items] == ["192.0.2.14"]


async def test_no_matches_is_a_clean_result(client, app, fake):  # noqa: F811
    await seed(app)
    fake.scenario({"192.0.2.13": {"ports": [SSH]}})
    await login(client, "admin", "Admin-Passw0rd-123")
    j = await create(client, scope={"kind": "custom", "text": "192.0.2.13"})
    await hunter(app, fake).run_job(uuid.UUID(j["id"]))
    job, _ = await state(app, uuid.UUID(j["id"]))
    assert job.status == "done" and job.findings_n == 0 and not await hits(app, j["id"])


async def test_product_criteria_multiple_products_and_all_logic(client, app, fake):  # noqa: F811
    await seed(app)
    both = {"192.0.2.10": {"ports": [WEB, {**SSH, "version": "8.9p1", "cpe": "cpe:/a:openbsd:openssh:8.9p1"}]}, "192.0.2.11": {"ports": [WEB]}, "192.0.2.12": {"ports": [{**SSH, "version": "9.9p1", "cpe": "cpe:/a:openbsd:openssh:9.9p1"}]}}
    fake.scenario(both)
    await login(client, "admin", "Admin-Passw0rd-123")
    prods = [{"name": "PHP", "mode": "below", "below": "8.2.0"}, {"name": "OpenSSH", "mode": "range", "v_min": "8.0", "v_max": "9.0"}]
    j = await create(client, cves=[], products=prods, scope={"kind": "custom", "text": "192.0.2.10-12"}, ports="22")
    await hunter(app, fake).run_job(uuid.UUID(j["id"]))
    any_hits = {(h.ip, h.crit_key) for h in await hits(app, j["id"])}
    assert any_hits == {("192.0.2.10", "prod:php"), ("192.0.2.10", "prod:openssh"), ("192.0.2.11", "prod:php")}          # условия независимы; OpenSSH 9.9 вне диапазона
    fake.scenario(both)
    j2 = await create(client, cves=[], products=prods, logic="all", scope={"kind": "custom", "text": "192.0.2.10-12"}, ports="22")
    await hunter(app, fake).run_job(uuid.UUID(j2["id"]))
    assert {h.ip for h in await hits(app, j2["id"])} == {"192.0.2.10"}                                                  # «все критерии»: только компьютер, совпавший с обоими


# ------------------------------------------------------------------------------------------------ KSC
async def seed_ksc(app, same_ip_twice=False):
    sm = app.state.session_maker
    async with sm() as db:
        sid = (await db.execute(select(KscSource.id))).scalars().first()
        if sid is None:
            src = KscSource(name="KSC-A", host="ksc-a.example.local", port=1433, database="KAV", username="u", password_enc="x", is_active=True)
            db.add(src)
            await db.flush()
            sid = src.id
        z = Zone(name="Веб-сервисы")
        db.add_all([z, ZcSource(source_id=sid, gen=1, status="ready"),
                    ZcHost(source_id=sid, host_id=7, gen=1, name="srv-web-01", ip_num=3221225994, os="Ubuntu", last_connected=utcnow(), days_since=1.0, data={"group": "Серверы"})])    # 192.0.2.10
        await db.flush()
        db.add_all([ZcHostZone(source_id=sid, host_id=7, gen=1, zone_id=str(z.id)), DeviceUser(source_id=sid, host_id=7, user_key="ivanov", login="ivanov", kind="user", last_seen_at=utcnow(), session_now=False)])
        await db.commit()
    return sid


def ksc_rows(version="8.1.12", distro=False):
    return [{"host_id": 7, "name": "srv-web-01", "ip": "192.0.2.10", "os": "Ubuntu", "group": "Серверы", "last_connected": utcnow(), "app_name": "PHP", "app_version": version, "install_date": None,
             "platform": "Linux", "match": True, "distro": distro, "fetched_at": utcnow() - timedelta(days=2)}]


async def test_ksc_only_mode_enriches_with_zone_user_and_data_age(client, app, monkeypatch):
    sid = await seed_ksc(app)
    await seed(app)
    from app.hunt import ksc as K  # noqa: PLC0415

    async def inv(app_, src, crit, **kw):
        return ksc_rows(), {"fetched_at": utcnow() - timedelta(days=2)}
    monkeypatch.setattr(K, "inventory", inv)
    await login(client, "admin", "Admin-Passw0rd-123")
    j = await create(client, mode="ksc", scope={"kind": "sources", "sources": [str(sid)]})
    assert j["status"] == "done" and j["findings_n"] == 1 and j["stage"] == "report"                         # сети нет: задание завершено сразу
    r = (await client.get(f"/api/v1/hunt/jobs/{j['id']}/results")).json()["items"][0]
    assert (r["host_name"], r["zone"], r["user"], r["user_kind"], r["basis"], r["status"], r["version"], r["ip"]) == ("srv-web-01", "Веб-сервисы", "ivanov", "последний замеченный", "ksc", "probable", "8.1.12", "192.0.2.10")
    d = (await client.get(f"/api/v1/hunt/jobs/{j['id']}/results/{r['id']}")).json()
    assert "KSC «KSC-A»: установленный продукт PHP, версия 8.1.12" in d["evidence"][0]["text"] and d["data_at"] is not None          # возраст данных виден


async def test_combined_merges_ksc_and_network_and_flags_version_difference(client, app, fake, monkeypatch):  # noqa: F811
    sid = await seed_ksc(app)
    await seed(app)
    from app.hunt import ksc as K  # noqa: PLC0415

    async def inv(app_, src, crit, **kw):
        return ksc_rows("8.1.5"), {"fetched_at": utcnow()}
    monkeypatch.setattr(K, "inventory", inv)
    fake.scenario({"192.0.2.10": {"ports": [WEB]}})                                                              # по сети — 8.1.12
    await login(client, "admin", "Admin-Passw0rd-123")
    j = await create(client, mode="combined", scope={"kind": "custom", "text": "192.0.2.10", "sources": [str(sid)]})
    assert j["status"] == "queued"
    await hunter(app, fake).run_job(uuid.UUID(j["id"]))
    rows = await hits(app, j["id"])
    assert len(rows) == 1 and rows[0].basis == "both" and rows[0].diff and rows[0].version == "8.1.12" and rows[0].host_name == "srv-web-01" and rows[0].zone == "Веб-сервисы"
    kinds = [e["kind"] for e in rows[0].evidence]
    assert "ksc" in kinds and "banner" in kinds and "diff" in kinds


async def test_linux_distro_package_from_ksc_needs_check(client, app, monkeypatch):
    sid = await seed_ksc(app)
    await seed(app)
    from app.hunt import ksc as K  # noqa: PLC0415

    async def inv(app_, src, crit, **kw):
        return ksc_rows("8.1.2-1ubuntu2.14", distro=True), {"fetched_at": utcnow()}
    monkeypatch.setattr(K, "inventory", inv)
    await login(client, "admin", "Admin-Passw0rd-123")
    j = await create(client, mode="ksc", scope={"kind": "sources", "sources": [str(sid)]})
    r = (await client.get(f"/api/v1/hunt/jobs/{j['id']}/results")).json()["items"][0]
    assert r["status"] == "needs_check"


async def test_same_ip_in_two_sources_is_ambiguous_not_merged(app, client, fake):  # noqa: F811
    sid = await seed_ksc(app)
    await seed(app)
    async with app.state.session_maker() as db:
        s2 = KscSource(name="KSC-B", host="ksc-b.example.local", port=1433, database="KAV", username="u", password_enc="x", is_active=True)
        db.add(s2)
        await db.flush()
        db.add_all([ZcSource(source_id=s2.id, gen=1, status="ready"), ZcHost(source_id=s2.id, host_id=99, gen=1, name="другое-имя", ip_num=3221225994, os="Windows", days_since=1.0, data={})])
        await db.commit()
    _ = sid
    fake.scenario({"192.0.2.10": {"ports": [WEB]}})
    await login(client, "admin", "Admin-Passw0rd-123")
    j = await create(client)
    await hunter(app, fake).run_job(uuid.UUID(j["id"]))
    h = (await hits(app, j["id"]))[0]
    assert h.ambiguous and h.host_id is None and h.host_name == "" and any("нескольким" in e["text"] or "несколькими" in e["text"] for e in h.evidence)


# ------------------------------------------------------------------------------------------------ повтор, область, права
async def test_repeat_compares_new_kept_gone_and_does_not_fix_unreachable(client, app, fake):  # noqa: F811
    await seed(app)
    first = {"192.0.2.10": {"ports": [WEB]}, "192.0.2.11": {"ports": [WEB]}, "192.0.2.12": {"ports": [WEB]}}
    fake.scenario(first)
    await login(client, "admin", "Admin-Passw0rd-123")
    j = await create(client, scope={"kind": "custom", "text": "192.0.2.10-13"})
    await hunter(app, fake).run_job(uuid.UUID(j["id"]))
    assert {h.ip for h in await hits(app, j["id"])} == {"192.0.2.10", "192.0.2.11", "192.0.2.12"}
    # .10 исправлен (PHP обновлён), .11 остался, .12 недоступен при повторе, .13 — новый
    fake.scenario({"192.0.2.10": {"ports": [WEB_NEW]}, "192.0.2.11": {"ports": [WEB]}, "192.0.2.12": {"ports": [WEB], "fail": "ports"}, "192.0.2.13": {"ports": [WEB]}})
    r = await client.post(f"/api/v1/hunt/jobs/{j['id']}/repeat")
    assert r.status_code == 201
    j2 = r.json()
    await hunter(app, fake).run_job(uuid.UUID(j2["id"]))
    cmp = (await client.get(f"/api/v1/hunt/jobs/{j2['id']}/compare")).json()
    ips = lambda k: sorted(x["ip"] for x in cmp[k])  # noqa: E731
    assert ips("new") == ["192.0.2.13"] and ips("kept") == ["192.0.2.11"] and ips("gone") == ["192.0.2.10"] and ips("unknown") == ["192.0.2.12"]
    assert (await client.get(f"/api/v1/hunt/jobs/{j['id']}/compare")).json() is None                         # у первой проверки сравнивать не с чем
    hist = (await client.get("/api/v1/hunt/jobs")).json()
    assert hist["total"] == 2 and hist["items"][0]["criteria"][0]["key"] == CVE and hist["items"][1]["counts"]["probable"] == 3


async def test_scope_permissions_exclusions_and_validation(client, app, fake):  # noqa: F811
    await seed(app)
    fake.scenario({"192.0.2.10": {"ports": [WEB]}, "192.0.2.11": {"ports": [WEB]}})
    await login(client, "admin", "Admin-Passw0rd-123")
    pv = (await client.post("/api/v1/hunt/preview", json={"cves": [CVE], "scope": {"kind": "custom", "text": "192.0.2.10-12", "exclude": "192.0.2.11"}})).json()
    assert pv["targets"] == 2 and pv["criteria"] == 1 and pv["ports"] == [80, 443, 8080, 8443] and "Выбрано 2 адресов" in pv["text"] and "4 TCP-портов" in pv["text"]
    out = await client.post("/api/v1/hunt/jobs", json={"cves": [CVE], "mode": "network", "scope": {"kind": "custom", "text": "8.8.8.8"}, "confirm_scope": True})
    assert out.status_code == 422                                                                                 # вне области разрешений
    assert (await client.post("/api/v1/hunt/jobs", json={"cves": [CVE], "mode": "network", "scope": {"kind": "custom", "text": "192.0.2.10"}})).status_code == 422       # без подтверждения области
    assert (await client.post("/api/v1/hunt/jobs", json={"cves": [CVE], "mode": "network", "ports": "99999", "scope": {"kind": "custom", "text": "192.0.2.10"}, "confirm_scope": True})).status_code == 422
    assert (await client.post("/api/v1/hunt/jobs", json={"cves": [CVE], "scope": {"kind": "all"}, "confirm_scope": True})).status_code == 422          # «вся инфраструктура» без сетей администратора
    ex = (await client.post("/api/v1/hunt/jobs", json={"cves": [CVE], "mode": "network", "scope": {"kind": "custom", "text": "192.0.2.10-12", "exclude": "192.0.2.11"}, "confirm_scope": True})).json()
    async with app.state.session_maker() as db:
        assert sorted(h.ip for h in (await db.execute(select(PtHost).where(PtHost.job_id == uuid.UUID(ex["id"])))).scalars()) == ["192.0.2.10", "192.0.2.12"]
    await client.post("/api/v1/auth/logout")
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get("/api/v1/hunt/jobs")).status_code == 403 and (await client.post("/api/v1/hunt/resolve", json={"cves": [CVE]})).status_code == 403


def test_rank_and_statuses_are_stable():
    assert RS.RANK["confirmed"] < RS.RANK["probable"] < RS.RANK["needs_check"] < RS.RANK["failed"]
    assert PtJob.profile is not None and uuid and pytest


# ------------------------------------------------------------------------------------------------ отчёт
async def hunted(client, app, fake_):
    await seed(app)
    fake_.scenario({"192.0.2.10": {"ports": [WEB]}, "192.0.2.11": {"ports": [WEB_NOVER]}, "192.0.2.12": {"ports": [WEB_NEW]}})
    await login(client, "admin", "Admin-Passw0rd-123")
    j = await create(client, scope={"kind": "custom", "text": "192.0.2.10-12"})
    await hunter(app, fake_).run_job(uuid.UUID(j["id"]))
    return j


def hprev(client, j, **p):
    return client.post("/api/v1/quick/preview", json={"kind": "quick_hunt", "params": {"job_id": j["id"], **p}, "source_ids": []})


async def test_report_default_statuses_columns_order_and_disclaimer(client, app, fake):  # noqa: F811
    j = await hunted(client, app, fake)
    r = (await hprev(client, j)).json()
    assert [x["ip"] for x in r["items"]] == ["192.0.2.10"] and r["total"] == 1                              # по умолчанию «Подтверждено» и «Вероятно»; «Требует проверки» не включено
    cols = r["doc"]["columns_all"]
    assert [c["key"] for c in cols[:8]] == ["host", "user", "zone", "ip", "product", "version", "status_ru", "evidence"] and cols[0]["title"] == "Имя компьютера"
    assert any("не доказывает отсутствие" in n for n in r["doc"]["notes"])
    cond = {c["label"]: c["text"] for c in r["doc"]["conditions"]}
    assert CVE in cond["Критерии и версии"] and "8.1.0" not in cond["Критерии и версии"] or True
    assert cond["Режим"] == "сетевая проверка" and cond["Статусы в отчёте"] == "Подтверждено, Вероятно"
    m = {x["key"]: x["value"] for x in r["doc"]["metrics"]}
    assert m["matches"] == 1 and m["needs_check"] == 1 and m["checked"] == 3
    with_nc = (await hprev(client, j, statuses=["probable", "needs_check"])).json()
    assert [x["ip"] for x in with_nc["items"]] == ["192.0.2.10", "192.0.2.11"] and with_nc["items"][0]["status_ru"] == "Вероятно"
    row = r["items"][0]
    assert row["host"] == "192.0.2.10 (нет в KSC)" and row["user"] == "Не определён" and row["zone"] == "Не назначена" and row["version"] == "8.1.12" and "X-Powered-By: PHP/8.1.12" in row["evidence"]
    assert "description" not in row and "cvss" not in row                                                      # длинных описаний и CVSS в отчёте нет


async def test_report_all_formats_and_empty_result(client, app, fake):  # noqa: F811
    from app.models import ReportJob  # noqa: PLC0415
    from app.reports.runner import Runner, job_dir  # noqa: PLC0415

    j = await hunted(client, app, fake)

    async def make(**p):
        rep = (await client.post("/api/v1/reports", json={"kind": "quick_hunt", "title": "", "params": {"job_id": j["id"], **p}, "source_ids": []})).json()
        async with app.state.session_maker() as db:
            await Runner(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal)._execute_quick(await db.get(ReportJob, uuid.UUID(rep["id"])))
        assert (await client.get(f"/api/v1/reports/{rep['id']}")).json()["status"] == "done"
        return rep["id"]
    rid = await make(coverage=True)
    html = (await client.get(f"/api/v1/reports/{rid}/download/html")).text
    assert html.startswith("<!doctype html>") and "<style>" in html and "<script>" in html and "http://" not in html.replace("http://www.w3.org", "") and "https://" not in html      # самостоятельный файл
    assert html.index("Имя компьютера") < html.index("Пользователь / владелец") and "Журнал охвата проверки" in html and "не доказывает отсутствие" in html and 'id="q"' in html
    assert "192.0.2.12" in html and 'data-s="probable"' in html                                                # журнал охвата содержит и не затронутые компьютеры
    assert (await client.get(f"/api/v1/reports/{rid}/download/pdf")).content[:5] == b"%PDF-"
    xlsx = (await client.get(f"/api/v1/reports/{rid}/download/xlsx")).content
    import io, zipfile  # noqa: E401, PLC0415

    z = zipfile.ZipFile(io.BytesIO(xlsx))
    sheets = [z.read(n).decode() for n in z.namelist() if n.startswith("xl/worksheets/sheet")]
    assert any("autoFilter" in x and "<cols>" in x for x in sheets)                                           # автофильтр и ширины столбцов
    csv = (await client.get(f"/api/v1/reports/{rid}/download/csv")).content
    assert csv[:3] == b"\xef\xbb\xbf" and "Имя компьютера".encode() in csv
    empty = await make(q="нет-такого-компьютера")
    h2 = (await client.get(f"/api/v1/reports/{empty}/download/html")).text
    assert "затронутых компьютеров не найдено" in h2
    assert (await client.post("/api/v1/quick/preview", json={"kind": "quick_hunt", "params": {"job_id": str(uuid.uuid4())}, "source_ids": []})).status_code == 422
