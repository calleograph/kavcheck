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
    assert len(sw) == 9
    st = asyncio.run(client.run(q.HOST_STATUS, {"id": 7}, max_rows=1))[0]
    assert st["status"] == 1 and st["mask"] & 16384


def test_vulnerabilities():
    client = SourceClient(params(), name="test")
    page = asyncio.run(vulns.page(client, offset=0, limit=50, product="Chrome"))
    # KLA10001 (две CVE) на компьютерах 7, 8, 6, 5, 9 = 10 строк и KLA10002 (одна CVE) на компьютере 6; закрытое обнаружение не входит
    assert len(page["items"]) == 11
    assert {v["cve"] for v in page["items"]} == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2023-9999"}
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
    assert set(hosts) == {1, 2, 5, 6, 7, 8, 9}
    # ksc-server: Java 8u391 (критическая и предупреждение) и Contoso Agent (KLA10001, критическая)
    assert (hosts[1]["critical"], hosts[1]["warning"], hosts[1]["total"], hosts[1]["patchable"]) == (2, 1, 3, 1)
    assert hosts[7]["critical"] == 1 and hosts[6]["high"] == 2
    only_java = asyncio.run(vulns.hosts_aggregate(client, cve="CVE-2024-2222"))
    assert [int(r["host_id"]) for r in only_java] == [1]
    prods = {r["name"]: r for r in asyncio.run(vulns.products_aggregate(client, active_days=None))}
    assert prods["Google Chrome"]["hosts"] == 4 and prods["Oracle Java"]["critical"] == 1 and prods["Mozilla Firefox"]["high"] == 1     # кластер 9 не считается
    active = {r["name"]: r for r in asyncio.run(vulns.products_aggregate(client, active_days=7))}
    assert active["Google Chrome"]["hosts"] == 1 and "Oracle Java" in active         # за 7 суток Chrome уязвим только на ws-001; ws-002 (20 суток) и ws-003 — нет
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
    assert (t["detected"], t["notcured"], t["attack"], t["deleted"]) == (3, 1, 1, 1)   # события старше периода и служебные не учитываются
    assert s["hosts"]["notcured"] == 1 and any(x["name"] == "EICAR-Test-File" for x in s["top_threats"]) and sum(b["detections"] for b in s["trend"]) == 3
    page = asyncio.run(events.page(client, days=7, types=["attack"], offset=0, limit=10))
    assert page["total"] == 1 and page["items"][0]["attacker"] == "198.51.100.120" and page["items"][0]["port"] == "22"
    assert asyncio.run(events.page(client, days=30, types=[], qtext="sample.bin", offset=0, limit=10))["total"] == 2
    # устройство, которого нет в KSC (событие 8): идентификатор вместо имени и явная пометка, что данных нет
    gone = [e for e in asyncio.run(events.page(client, days=7, types=["detected"], offset=0, limit=10))["items"] if e["host_id"] == 9901][0]
    assert gone["host_known"] is False and "9901" in gone["host"] and "имя неизвестно" in gone["host"] and gone["ip"] == ""
    full = asyncio.run(events.all_rows(client, days=7, types=[], max_rows=100))                 # одним запросом, те же строки, что постранично
    assert len(full) == asyncio.run(events.page(client, days=7, types=[], offset=0, limit=100))["total"] == 6


# --------------------------------------------------------------------------------------------- условия версий: сквозная проверка
# Contoso Agent (tests/ksc_synthetic/schema.sql): активные ≤30 сут — компьютеры 1, 2, 3, 4, 6, 7; без связи — 5 и 8; 9 — кластер; ключ каталога contoso-agent
#   8.4.14: 1, 5, 9 · 8.4.15: 2, 3 · 8.4.16: 4, 6 · 8.9: 7 · 8.10: 6 (второй раз), 8; удалённая установка 8.10 на 1 не считается
CONTOSO = [  # (оператор, значение, мин, макс, исключения, ветки) → (компьютеры, установки) среди активных
    ("lt", "8.4.15", None, None, [], [], {1}, 1), ("le", "8.4.15", None, None, [], [], {1, 2, 3}, 3), ("eq", "8.4.15", None, None, [], [], {2, 3}, 2),
    ("ge", "8.4.15", None, None, [], [], {2, 3, 4, 6, 7}, 6), ("gt", "8.4.15", None, None, [], [], {4, 6, 7}, 4),
    ("range", None, "8.4.15", "8.9", [], [], {2, 3, 4, 6, 7}, 5), ("range", None, "8.4.16", None, [], [], {4, 6, 7}, 4),
    ("lt", "8.10", None, None, [], [], {1, 2, 3, 4, 6, 7}, 6),                       # 8.9 < 8.10 (число, а не строка)
    ("gt", "8.9", None, None, [], [], {6}, 1), ("le", "8.9", None, None, [], [], {1, 2, 3, 4, 6, 7}, 6),
    ("ge", "8.4.15", None, None, ["8.4"], [], {6, 7}, 2),                            # исключена ветка 8.4: остаются 8.9 и 8.10
    ("any", None, None, None, [], ["8"], {1, 2, 3, 4, 6, 7}, 7), ("any", None, None, None, [], ["9"], set(), 0),        # ветка по умолчанию — первая часть версии
    ("lt", "9", None, None, [], [], {1, 2, 3, 4, 6, 7}, 7), ("gt", "9", None, None, [], [], set(), 0),
]


def _plan(op, value, vmin, vmax, exclude, branches):
    return [{"kind": "pattern", "name_like": "Contoso Agent%", "product_name": "Contoso Agent", "op": op, "value": value, "min": vmin, "max": vmax, "exclude": exclude, "branches": branches}]


@pytest.mark.parametrize("case", CONTOSO, ids=lambda c: f"{c[0]} {c[1] or ''}{c[2] or ''}..{c[3] or ''} excl={c[4]} br={c[5]}")
def test_version_conditions_end_to_end(case):
    from app.reports import audit

    op, value, vmin, vmax, excl, br, hosts, installs = case
    items = _plan(op, value, vmin, vmax, excl, br)
    for include_inactive in (False, True):
        with Session(params()) as s:
            rows, summ = audit.build_source(s, source_name="KAVTEST", items=items, rules={}, active_days=30, include_inactive=include_inactive, max_rows=10_000,
                                            progress=lambda t: None, cancelled=lambda: False)
        # независимый эталон: версии-числа из таблицы «как в KSC» и ожидаемые наборы выше
        expect = set(hosts)
        if include_inactive:
            inactive = {5: "8.4.14", 8: "8.10"}                                                  # 9 — кластер (исключён всегда), удалённая установка не считается
            from app.ksc import versions as V
            for h, v in inactive.items():
                if V.matches(v, op, value, vmin, vmax) and not V.excluded(v, excl) and (not br or v.split(".")[0] in br):
                    expect.add(h)
        assert {r["host_id"] for r in rows} == {h for h in expect}, (case, include_inactive)
        assert summ["hosts"] == len(expect) and len({r["host_id"] for r in rows}) == summ["hosts"]
        if not include_inactive:
            assert len(rows) == installs == summ["rows"], case
        assert all(r["condition"] == audit.item_condition(items[0]) for r in rows)             # условие в строках — ровно заданное


# ------------------------------------------------------------------------------------------------ поиск со звёздочкой на SQL Server
def _host_names(**filters) -> set[str]:
    client = SourceClient(params(), name="test")
    where, p = H.hosts_where(exclude_slaves=False, **filters)
    rows = asyncio.run(client.run(q.HOSTS_PAGE.format(where=where, order=H.hosts_order("name", False)), {**p, "offset": 0, "limit": 50}, max_rows=50))
    return {r["name"] for r in rows}


def test_mask_hosts_begin_middle_end_multiple():
    assert _host_names(qtext="*SQL*") == {"SQL-CL-01"} and _host_names(qtext="sql*") == {"SQL-CL-01"} and _host_names(qtext="SQL") == {"SQL-CL-01"}      # регистр не важен
    assert _host_names(qtext="web-*") == {"web-01.example.local", "web-02.example.local"}
    assert _host_names(qtext="*-01") == {"SQL-CL-01", "web-01.example.local", "app-01.example.local"}        # поиск идёт и по DNS-имени (web-01)
    assert _host_names(qtext="*.example.local") == {"web-01.example.local", "web-02.example.local", "app-01.example.local", "old-srv.example.local"}
    assert _host_names(qtext="w*-0*1*") >= {"web-01.example.local", "ws-001"} and _host_names(qtext="ws-*-1") == set()
    assert _host_names(qtext="*") == _host_names() and len(_host_names()) == 9 and _host_names(qtext="   ") == _host_names()          # «*» и пустой запрос — без отбора


def test_search_injection_text_is_only_parameters():
    # несколько значений через «;» и пробел — отдельные поисковые значения; текст никогда не попадает в SQL, только в параметры
    assert "ws-001" in _host_names(qtext="ws-001; DROP TABLE x") and "DROP" not in H.hosts_where(qtext="ws-001; DROP TABLE x")[0]


def test_mask_special_characters_are_literal():
    for bad in ("ws_001", "ws-00%", "ws-0[0]1", "ws-0[0-9]1", "%", "_", "[", "ws-001'--"):
        assert _host_names(qtext=bad) == set(), bad                      # %, _ и [ из запроса — обычные символы, а не шаблон LIKE
    assert _host_names(qtext="ws-00_*") == set()


def test_mask_group_and_os_filters():
    assert _host_names(os_contains="Microsoft Windows 1*") >= {"ws-001", "ws-002"} and "ksc-server" not in _host_names(os_contains="Microsoft Windows 1*")
    assert _host_names(os_contains="Windows 1*") == set()                      # маска сопоставляется со всей строкой: «Windows 1*» не найдёт «Microsoft Windows 11»
    assert _host_names(os_contains="*Server 2019") == {"SQL-CL-01"}


def test_mask_registry_and_vulnerabilities():
    client = SourceClient(params(), name="test")
    names = lambda **kw: {p["name"] for p in asyncio.run(software.registry_page(client, offset=0, limit=200, installed_only=False, **kw))["items"]}    # noqa: E731
    assert names(qtext="php*-cli") == {"php7.4-cli", "php8.1-cli", "php-cli"} and names(qtext="PHP7.4-*") == {"php7.4-cli", "php7.4-fpm", "php7.4-xdebug"}
    assert names(qtext="*xdebug") == {"php7.4-xdebug"} and names(qtext="php7.4") >= {"php7.4-cli"}                                                         # без звёздочки — по части строки
    assert names(qtext="php*", publisher="Ubuntu*") == {"php", "php8.3-fpm"}
    assert {p["version"] for p in asyncio.run(software.registry_page(client, offset=0, limit=50, version="8.1", installed_only=False))["items"]} >= {"8.1.27-1+0~20231221.46+debian11~1.gbp8e7a4e"}
    got = {v["cve"] for v in asyncio.run(vulns.page(client, offset=0, limit=50, cve="CVE-2024-*"))["items"]}
    assert {"CVE-2024-0001", "CVE-2024-0002"} <= got and all(c.startswith("CVE-2024-") for c in got) and "CVE-2023-9999" not in got
    assert {v["cve"] for v in asyncio.run(vulns.page(client, offset=0, limit=50, cve="*9999"))["items"]} == {"CVE-2023-9999"}
    assert {v["cve"] for v in asyncio.run(vulns.page(client, offset=0, limit=50, cve="*2023*9"))["items"]} == {"CVE-2023-9999"}


def test_users_visited_query_and_unified_search():
    """Пользователи устройств (KSC 15.1): выборка порциями по nId; единый поиск — имя, IP по числовому диапазону (CIDR, диапазон, маска) и логин."""
    client = SourceClient(params(), name="test")
    rows = asyncio.run(client.run(q.USERS_VISITED, {"n": 4, "after": 0}, max_rows=10))
    assert len(rows) == 4 and rows[0]["row_id"] < rows[-1]["row_id"] and rows[0]["sid_hash"].startswith("0x")
    rest = asyncio.run(client.run(q.USERS_VISITED, {"n": 100, "after": rows[-1]["row_id"]}, max_rows=200))
    got = rows + rest
    assert len(got) == 9 and {r["login"] for r in got if r["login"]} >= {"ivanov", "petrova", "svc_backup", "DWM-1", "SYSTEM", "root"}
    assert any(r["user_id"] is None for r in got)                       # запись без сопоставленной учётной записи
    assert sum(1 for r in got if r["actual"]) == 5

    def names(text, users=False, **kw):
        where, p = H.hosts_where(qtext=text, search_users=users, **kw)
        return {r["name"] for r in asyncio.run(client.run(q.HOSTS_PAGE.format(where=where, order=H.hosts_order("name", False)), {**p, "offset": 0, "limit": 50}, max_rows=50))}

    assert names("192.0.2.20/30") == {"web-01.example.local", "web-02.example.local", "app-01.example.local"}           # .20–.23
    assert names("192.0.2.21-22") == {"web-01.example.local", "web-02.example.local"} and names("192.0.2.101") == {"ws-001"}
    assert names("192.0.2.*") >= {"ksc-server", "ws-001"} and names("10.0.0.0/8") == set()
    assert names("ws-001 192.0.2.10") == {"ws-001", "ksc-server"} and names("ws-00*") == {"ws-001", "ws-002", "ws-003"}
    assert names("ivanov", users=True) == {"ws-001", "ws-002", "web-01.example.local"} and names("ivanov") == set()          # логин ищется, только если источник отдаёт таблицы пользователей


def test_hardware_queries():
    """Оборудование (hst_hwinv_dev): компоненты хоста, агрегаты по Linux и по списку; Windows в агрегат Linux не попадает."""
    from app.ksc import hardware as HW

    client = SourceClient(params(), name="test")
    agg = asyncio.run(HW.load_linux(client))
    assert set(agg) == {2, 3, 4} and (agg[2]["cores"], agg[2]["ram_mb"]) == (2, 4096) and (agg[3]["cores"], agg[3]["ram_mb"]) == (1, 1024) and agg[4]["cores"] == 4
    assert set(asyncio.run(HW.load_for(client, [2, 6, 99]))) == {2, 6}       # по списку — любая платформа; нет данных — нет записи
    h = HW.finish(HW.summarize(asyncio.run(client.run(q.HW_HOST, {"id": 3}, max_rows=500))))
    assert h["known"] and h["cores"] == 1 and h["ram_mb"] == 1024 and h["disk_total_gb"] == 50 and h["logical"] and "CPU: 1 ядро" in h["line"]
    assert HW.summarize(asyncio.run(client.run(q.HW_HOST, {"id": 5}, max_rows=500)))["known"] is False
