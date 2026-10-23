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
    assert len(sw) == 6
    st = asyncio.run(client.run(q.HOST_STATUS, {"id": 7}, max_rows=1))[0]
    assert st["status"] == 1 and st["mask"] & 16384


def test_vulnerabilities():
    client = SourceClient(params(), name="test")
    page = asyncio.run(vulns.page(client, offset=0, limit=50))
    assert page["total"] == 4 and len(page["items"]) == 4       # KLA10001 с двумя CVE на ws-002 и ws-003 = 4 строки; закрытое обнаружение не входит
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
