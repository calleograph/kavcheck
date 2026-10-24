"""Интеграционная проверка SQL-шаблонов на синтетической базе «как KSC» (tests/ksc_synthetic). Пропускается, если KSC_TEST_HOST не задан."""
import asyncio
import os

import pytest

from app.ksc import hosts as H
from app.ksc import queries as q
from app.ksc import schema, software, vulns
from app.ksc.driver import ConnParams, Session, SourceClient
from app.ksc.grouping import PHP_BRANCH_REGEX, PHP_NAME_LIKE, PHP_NAME_REGEX, Rule
from app.reports import builder

HOST = os.environ.get("KSC_TEST_HOST")
pytestmark = pytest.mark.skipif(not HOST, reason="нет синтетической базы KSC (KSC_TEST_HOST)")


def params() -> ConnParams:
    return ConnParams(host=HOST, port=int(os.environ.get("KSC_TEST_PORT", "11433")), database=os.environ.get("KSC_TEST_DB", "KAVTEST"), username=os.environ.get("KSC_TEST_USER", "kavcheck_ro"),
                      password=os.environ.get("KSC_TEST_PASSWORD", "KavCheck-Test-Pass-1"), tls_mode="request", trust_server_cert=True)


def test_diagnose():
    d = schema.diagnose(params())
    assert d["ok"], d
    assert all(f["ok"] for f in d["features"].values()), d["features"]
    assert d["ksc_version"] == "15.1.0.22239" and d["hosts"] == 8 and d["roles"]["datareader"] and not d["roles"]["datawriter"]


def test_registry_and_counts():
    client = SourceClient(params(), name="test")
    page = asyncio.run(software.registry_page(client, offset=0, limit=50, qtext="php"))
    names = {p["name"] for p in page["items"]}
    assert "php7.4-cli" in names and "PhpStorm 2024.1" in names and page["total"] >= 10
    cli = next(p for p in page["items"] if p["name"] == "php7.4-cli")
    assert cli["installs"] == 1 and cli["hosts"] == 1           # удалённая установка (bDeleted=1) не считается
    page2 = asyncio.run(software.registry_page(client, offset=0, limit=10, qtext="chrome", platform="windows", sort="version", desc=True))
    assert [p["version"] for p in page2["items"]] == ["124.0.6367.60", "120.0.6099.130"]


def test_grouped_php():
    client = SourceClient(params(), name="test")
    rule = Rule("php", "PHP", PHP_NAME_LIKE, PHP_NAME_REGEX, PHP_BRANCH_REGEX)
    g = asyncio.run(software.grouped_view(client, rule))
    br = {b["branch"]: b for b in g["branches"]}
    assert set(br) == {"7.4", "8.1", "8.3", "5.6", "8.0", None}, set(br)
    assert br["7.4"]["installs"] == 3 and br["7.4"]["hosts"] == 1          # cli, fpm, xdebug (ветка из имени)
    assert br["8.3"]["hosts"] == 2                                          # ws-001 и кластер SQL-CL-01 (в группировке не фильтруется)
    assert br[None]["installs"] == 3                                        # php-common 2:76 на трёх компьютерах
    assert "PhpStorm 2024.1" not in {p["name"] for b in g["branches"] for p in b["packages"]}


def test_hosts_and_activity():
    client = SourceClient(params(), name="test")
    where, p = H.hosts_where(active_days=7)
    rows = asyncio.run(client.run(q.HOSTS_PAGE.format(where=where, order=H.hosts_order("name", False)), {**p, "offset": 0, "limit": 50}, max_rows=50))
    assert {r["name"] for r in rows} == {"ksc-server", "web-01.example.local", "web-02.example.local", "ws-001"}
    where, p = H.hosts_where(active_days=7, inactive_only=True)
    rows = asyncio.run(client.run(q.HOSTS_PAGE.format(where=where, order=H.hosts_order("name", False)), {**p, "offset": 0, "limit": 50}, max_rows=50))
    assert {r["name"] for r in rows} == {"app-01.example.local", "old-srv.example.local", "ws-002", "ws-003"}   # кластер исключён
    h = asyncio.run(client.run(q.HOST_ONE, {"id": 2}, max_rows=1))[0]
    assert H.ip_str(h["ip_int"]) == "192.0.2.21"
    sw = asyncio.run(client.run(q.SOFTWARE_ON_HOST, {"id": 2}, max_rows=100))
    assert len(sw) == 8
    st = asyncio.run(client.run(q.HOST_STATUS, {"id": 7}, max_rows=1))[0]
    assert st["status"] == 1 and st["mask"] & 16384


def test_vulnerabilities():
    client = SourceClient(params(), name="test")
    page = asyncio.run(vulns.page(client, offset=0, limit=50, product="Chrome"))
    assert len(page["items"]) == 4       # KLA10001 с двумя CVE на ws-002 и ws-003 = 4 строки; закрытое обнаружение не входит
    assert {v["cve"] for v in page["items"]} == {"CVE-2024-0001", "CVE-2024-0002"}
    assert any(v["product"] == "Google Chrome" and v["product_version"] == "120.0.6099.130" for v in page["items"])


def test_report_php_7x_builder():
    rule = Rule("php", "PHP", PHP_NAME_LIKE, PHP_NAME_REGEX, PHP_BRANCH_REGEX)
    with Session(params()) as conn:
        rows, summary = builder.build_software(conn, {"rule": "php", "min_version": "7", "below_version": "8", "active_days": 7}, rule, max_rows=10_000, exclude_slaves=True, progress=lambda t: None, cancelled=lambda: False)
    assert {r["app_name"] for r in rows} == {"php7.4-cli", "php7.4-fpm", "php7.4-xdebug"} and summary["hosts"] == 1
    assert rows[0]["linux_release"] == "base-files 11.1+deb11u9" and rows[0]["group"] == "Управляемые устройства / Серверы / Web"
    with Session(params()) as conn:
        rows, summary = builder.build_software(conn, {"rule": "php", "include_inactive": True, "active_days": 7}, rule, max_rows=10_000, exclude_slaves=True, progress=lambda t: None, cancelled=lambda: False)
    assert summary["hosts"] == 5 and summary["excluded_not_computers"] == 2        # кластер SQL-CL-01: 2 установки исключены
    assert {b["branch"] for b in summary["branches"]} == {"7.4", "8.1", "8.3", "5.6", "8.0", "(не определена)"}
    with Session(params()) as conn:
        rows, summary = builder.build_hosts(conn, {"active_days": 7, "inactive_only": True}, max_rows=1000, exclude_slaves=True, progress=lambda t: None, cancelled=lambda: False)
    assert summary["rows"] == 4


def test_guard_blocks_write_even_with_rights():
    from app.ksc.driver import KscError
    from app.ksc.guard import UnsafeQuery

    client = SourceClient(params(), name="test")
    with pytest.raises(UnsafeQuery):
        asyncio.run(client.run("DELETE FROM dbo.v_akpub_host", max_rows=1))
    with pytest.raises(KscError):
        asyncio.run(client.run("SELECT * FROM dbo.no_such_table", max_rows=1))


def test_vuln_aggregates():
    client = SourceClient(params(), name="test")
    hosts = {r["host_id"]: r for r in asyncio.run(vulns.hosts_aggregate(client))}
    assert set(hosts) == {1, 6, 7, 8}
    assert (hosts[1]["critical"], hosts[1]["warning"], hosts[1]["total"], hosts[1]["patchable"]) == (1, 1, 2, 1)     # Java 8u391 на ksc-server
    assert hosts[7]["critical"] == 1 and hosts[6]["high"] == 1
    only_java = asyncio.run(vulns.hosts_aggregate(client, cve="CVE-2024-2222"))
    assert [int(r["host_id"]) for r in only_java] == [1]
    prods = {r["name"]: r for r in asyncio.run(vulns.products_aggregate(client, active_days=None))}
    assert prods["Google Chrome"]["hosts"] == 2 and prods["Oracle Java"]["critical"] == 1 and prods["Mozilla Firefox"]["high"] == 1
    active = {r["name"] for r in asyncio.run(vulns.products_aggregate(client, active_days=7))}
    assert "Google Chrome" not in active and "Oracle Java" in active         # Chrome уязвим только на давно не подключавшихся ws-002 и ws-003
    on1 = asyncio.run(vulns.on_host(client, 1))
    j = next(v for v in on1 if v["kla_id"] == "KLA10004")
    assert j["cve"] == ["CVE-2024-2222"] and j["kb"] == ["KB5034441"] and j["severity"] == "critical" and j["app_name"] == "Java 8 Update 391 (64-bit)"


def test_catalog_build():
    from app.ksc import catalog_build as CB

    with Session(params()) as s:
        fams, stats = CB.build(s, activity_days=7)
        sig = CB.signature(s)
    by = {f["key"]: f for f in fams}
    assert sig and stats["slaves"] == 1
    assert by["google-chrome"]["hosts_all"] == 3 and by["google-chrome"]["hosts_active"] == 1             # ws-001 активен, ws-002/ws-003 — нет
    ff = by["mozilla-firefox"]
    assert {v["version"] for v in ff["versions"]} == {"125.0.3", "115.10.0"} and [b["branch"] for b in ff["branches"]] == ["125", "115"]
    assert "mozilla-maintenance-service" in by                                                                 # служебная запись — отдельно
    java = by["java"]
    assert {v["version"] for v in java["versions"]} == {"8.0.401", "8.0.391"} and java["hosts_all"] == 3
    py = by["python"]
    assert py["hosts_all"] == 1 and py["installs_all"] == 2 and py["versions"][0]["version"] == "3.12.3"     # два компонента установщика — один компьютер
    php = by["php"]
    assert {b["branch"] for b in php["branches"]} >= {"7.4", "8.1", "8.3", "5.6", "8.0", ""}
    assert by["openssl"]["hosts_all"] == 3 and {v["version"] for v in by["openssl"]["versions"]} == {"1.1.1w", "3.0.13"}
    assert by["notepad-plus-plus"]["name"] == "Notepad++"
    ov = CB.Overrides(merge={"mozilla-maintenance-service": "mozilla-firefox"}, rename={"notepad-plus-plus": ("Notepad++ (редактор)", None)})
    with Session(params()) as s:
        fams2, _ = CB.build(s, activity_days=7, overrides=ov)
    by2 = {f["key"]: f for f in fams2}
    assert "mozilla-maintenance-service" not in by2 and by2["mozilla-firefox"]["installs_all"] == 3 and by2["notepad-plus-plus"]["name"] == "Notepad++ (редактор)"


def test_version_audit_builder():
    from app.ksc import catalog_build as CB
    from app.reports import audit

    with Session(params()) as s:
        fams, _ = CB.build(s, activity_days=7)
    ids = {f["key"]: sorted({p for v in f["versions"] for p in v["product_ids"]}) for f in fams}

    def run(items, **kw):
        with Session(params()) as conn:
            return audit.build_source(conn, source_name="KSC-1", items=items, rules={}, active_days=kw.get("active_days", 7), include_inactive=kw.get("include_inactive", False),
                                      max_rows=10_000, progress=lambda t: None, cancelled=lambda: False)

    rows, summ = run([{"kind": "product", "product_key": "google-chrome", "product_name": "Google Chrome", "op": "lt", "value": "124", "product_ids": ids["google-chrome"]}],
                     include_inactive=True)
    assert {r["name"] for r in rows} == {"ws-002", "ws-003"} and rows[0]["target_version"] == "124 или выше" and rows[0]["source"] == "KSC-1"
    rows, summ = run([{"kind": "product", "product_key": "google-chrome", "op": "lt", "value": "124", "product_ids": ids["google-chrome"]}])
    assert rows == [] and summ["hidden_inactive_hosts"] == 2                    # давно не подключавшиеся скрыты глобальным фильтром
    # Java 8: 8.0.4010.7 = 8u401, 8.0.3910.13 = 8u391
    rows, _ = run([{"kind": "product", "product_key": "java", "op": "lt", "value": "8.0.401", "product_ids": ids["java"]}], include_inactive=True)
    assert {(r["name"], r["compared_version"]) for r in rows} == {("ksc-server", "8.0.391"), ("ws-002", "8.0.391")}
    # исключение ветки и диапазон
    rows, _ = run([{"kind": "product", "product_key": "mozilla-firefox", "op": "lt", "value": "126", "exclude": ["115"], "product_ids": ids["mozilla-firefox"]}], include_inactive=True)
    assert {r["name"] for r in rows} == {"ws-001"}
    rows, _ = run([{"kind": "product", "product_key": "php", "op": "range", "min": "7", "max": "7.99.99", "branches": ["7.4"], "product_ids": ids["php"]}])
    assert {r["app_name"] for r in rows} == {"php7.4-cli", "php7.4-fpm", "php7.4-xdebug"}
    # пакет Linux: граница с ревизией сравнивается с полной версией
    rows, _ = run([{"kind": "product", "product_key": "openssl", "op": "lt", "value": "1.1.1w-0+deb11u2", "product_ids": ids["openssl"]}], include_inactive=True)
    assert {r["name"] for r in rows} == {"web-01.example.local", "web-02.example.local"}
    # несколько программ сразу и шаблон из дополнительных настроек
    rows, summ = run([{"kind": "product", "product_key": "python", "op": "lt", "value": "3.13", "product_ids": ids["python"]},
                      {"kind": "pattern", "name_like": "%Edge%", "product_name": "Edge", "op": "lt", "value": "125"}])
    assert {(r["program"], r["name"]) for r in rows} == {("Python", "ws-001"), ("Edge", "ws-001"), ("Edge", "ksc-server")}
    assert summ["items"][0]["hosts"] == 1 and summ["items"][1]["hosts"] == 2


def test_protection_and_events():
    from datetime import datetime, timezone

    from app.ksc import events, protection
    client = SourceClient(params(), name="test")
    recs = {r["host_id"]: r for r in asyncio.run(protection.load(client, exclude_slaves=True, groups=None))}
    now = datetime.now(timezone.utc)

    def pr(h):
        return protection.problems(recs[h], now, bases_days=3, scan_days=30)
    assert recs[6]["av"]["build"] == "12.6.0.438" and recs[6]["agent_build"] == "15.1.0.22239"
    assert "no_av" in pr(1) and "no_av" in pr(8)                 # сервер без антивируса; статус KSC «антивирус не установлен»
    assert {"rtp_off", "bases_old"} <= set(pr(7)) and "bases_old" not in pr(2)
    # «в сети» — флаг KSC «видимо» (бит 0 nStatus), а не давность подключения: в синтетике nStatus 5 и 29 — в сети, 4, 0, 64 — нет
    assert {h for h, r in recs.items() if r["online"]} and all(r["online"] in (True, False) for r in recs.values())
    assert all(r["online"] == bool(int(r.get("status_bits") or 0) & 1) for r in recs.values() if "status_bits" in r)
    vers = {v["code"]: v for v in protection.versions(list(recs.values()))}
    assert vers["1103"]["latest"] == "15.1.0.22239" and vers["KES"]["versions"][0]["build"] == "12.6.0.438"
    s = asyncio.run(events.summary(client, days=7))
    t = {x["key"]: x["n"] for x in s["types"]}
    assert (t["detected"], t["notcured"], t["attack"], t["deleted"]) == (2, 1, 1, 1)   # события старше периода и служебные не учитываются
    assert s["hosts"]["notcured"] == 1 and any(x["name"] == "EICAR-Test-File" for x in s["top_threats"]) and sum(b["detections"] for b in s["trend"]) == 2
    page = asyncio.run(events.page(client, days=7, types=["attack"], offset=0, limit=10))
    assert page["total"] == 1 and page["items"][0]["attacker"] == "198.51.100.120" and page["items"][0]["port"] == "22"
    assert asyncio.run(events.page(client, days=30, types=[], qtext="sample.bin", offset=0, limit=10))["total"] == 2
