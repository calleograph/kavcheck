"""Единый список уязвимостей компьютера: данные KSC и внешних баз в одной таблице, без дублей, с различием подтверждённого и потенциального."""
from app.services import hostvulns as HV
from tests.conftest import login


def ksc(cve, kla="KLA1", app="Google Chrome", ver="124.0.6367.60", sev="high", occ=1):
    return {"occurrence_id": occ, "kla_id": kla, "severity": sev, "url": f"https://threats.kaspersky.com/{kla}", "product": app, "app_name": app, "app_version": ver, "product_version": ver,
            "cve": cve, "kb": [], "patches_available": True, "detected": None}


def ext(key, product="Google Chrome", ver="124.0.6367.60", rank=3, status="potential", ids=None, sources=("nvd",), exploited=False):
    return {"key": key, "title": "t", "sev_rank": rank, "exploited": exploited, "product": product, "version": ver, "status": status, "status_ru": status, "basis": "версия попадает в диапазон",
            "sources": list(sources), "ids": ids or [key]}


def test_same_vulnerability_from_both_sources_is_one_row_with_both_sources():
    rows = HV.merge([ksc(["CVE-2024-1"])], [ext("CVE-2024-1", rank=4, sources=("nvd", "kev"), exploited=True)])
    assert len(rows) == 1
    r = rows[0]
    assert r["detected_by"] == ["ksc", "external"] and r["sources"] == ["KSC", "nvd", "kev"] and r["verdict"] == "confirmed_ksc" and r["severity"] == "critical" and r["exploited"]
    assert r["ksc"]["url"] and r["external"]["key"] == "CVE-2024-1"                              # ссылки на описание KSC и запись внешней базы сохраняются


def test_external_only_match_is_potential_and_never_looks_like_ksc_confirmation():
    rows = HV.merge([], [ext("CVE-2024-2"), ext("CVE-2024-3", status="confirmed", rank=2)])
    by = {r["keys"][0]: r for r in rows}
    assert by["CVE-2024-2"]["verdict"] == "potential" and by["CVE-2024-2"]["detected_by"] == ["external"] and by["CVE-2024-2"]["ksc"] is None
    assert by["CVE-2024-3"]["verdict"] == "confirmed_ext" and by["CVE-2024-3"]["verdict_ru"] == "Подтверждено внешней базой" and by["CVE-2024-2"]["verdict_ru"] == "Потенциальная"
    c = HV.counts(rows)
    assert c == {"total": 2, "confirmed_ksc": 0, "confirmed_ext": 1, "potential": 1, "critical": 0, "high": 1, "warning": 1}


def test_same_cve_in_another_version_is_not_merged_and_version_prefix_matches():
    rows = HV.merge([ksc(["CVE-2024-4"], ver="1.2.3")], [ext("CVE-2024-4", ver="2.0.0"), ext("CVE-2024-4", ver="1.2")])       # вторая установка и «1.2» (начало «1.2.3») совпадают по версии
    kinds = sorted((r["version"], r["verdict"]) for r in rows)
    assert kinds == [("1.2.3", "confirmed_ksc"), ("2.0.0", "potential")] and len(rows) == 2


def test_alias_ids_and_kla_only_rows_and_ordering():
    rows = HV.merge([ksc([], kla="KLA9", sev="warning"), ksc(["CVE-2024-5"], kla="KLA5", sev="critical", occ=2)], [ext("GHSA-xxxx", ids=["GHSA-XXXX", "CVE-2024-5"], rank=3)])
    assert [r["keys"][0] for r in rows] == ["CVE-2024-5", "KLA9"] and rows[0]["detected_by"] == ["ksc", "external"]
    assert rows[1]["keys"] == ["KLA9"]                                                          # у записи KSC без CVE идентификатор — KLA


async def test_host_vulnerabilities_endpoint_merges_and_survives_one_source_failing(client, app, monkeypatch):
    from app.ksc import vulns as V
    from app.ksc.driver import KscError

    await login(client, "admin", "Admin-Passw0rd-123")
    s = (await client.post("/api/v1/admin/sources", json={"name": "KSC-A", "host": "a.example.local", "database": "KAV", "username": "u", "password": "p"})).json()
    await client.post("/api/v1/auth/source", json={"source_id": s["id"]})

    async def on_host(_client, _hid):
        return [ksc(["CVE-2024-1"])]

    async def ext_ok(_db, _client, _sid, _hid):
        return [ext("CVE-2024-1", rank=3), ext("CVE-2024-9", rank=2)], True

    monkeypatch.setattr(V, "on_host", on_host)
    import app.api.vdb as vdb_api
    monkeypatch.setattr(vdb_api, "host_ext_items", ext_ok)
    r = (await client.get("/api/v1/hosts/7/vulnerabilities")).json()
    assert r["counts"]["total"] == 2 and r["counts"]["confirmed_ksc"] == 1 and r["counts"]["potential"] == 1 and not r["notes"]
    only_ksc = (await client.get("/api/v1/hosts/7/vulnerabilities?external=false")).json()                 # быстрый запрос страницы: только данные KSC
    assert only_ksc["counts"]["total"] == 1 and only_ksc["external_checked"] is False

    async def ext_down(*_a):
        raise KscError("query", "SQL Server недоступен")

    monkeypatch.setattr(vdb_api, "host_ext_items", ext_down)
    r = (await client.get("/api/v1/hosts/8/vulnerabilities")).json()                      # другой компьютер: результат первого кэширован
    assert r["counts"]["total"] == 1 and r["items"][0]["verdict"] == "confirmed_ksc" and "внешним базам не выполнена" in r["notes"][0]      # KSC-часть не теряется


def test_groups_are_compact_views_that_lose_nothing():
    """Одна строка на продукт и версию: уникальные идентификаторы и KEV считаются по всем строкам, в образце — не больше трёх, полный список группы доступен."""
    def row(i, key, sev="warning", exploited=False, product="Google Chrome", version="120.0.1"):
        return {"id": f"ksc:{i}", "keys": [key], "kla_id": "", "title": "", "severity": sev, "severity_ru": HV.SEV_RU[sev], "product": product, "version": version, "detected_by": ["ksc"],
                "verdict": "confirmed_ksc", "exploited": exploited}
    rows = [row(i, f"CVE-2026-{1000 + i}", "critical" if i == 0 else "high", exploited=i == 3) for i in range(30)] + [row(99, "CVE-2026-1000", "warning"), row(100, "CVE-2025-1", product="7-Zip", version="23.01")]
    gs = HV.groups(rows, [{"title": "Google Chrome", "version": "120.0.1", "status": "eol", "status_ru": "EOL", "severity": "critical"}])
    chrome = next(g for g in gs if g["product"] == "Google Chrome")
    assert len(gs) == 2 and chrome["cves"] == 30 and chrome["rows"] == 31 and chrome["kev"] == 1 and chrome["severity"] == "critical"       # дубль CVE-2026-1000 — один идентификатор
    assert len(chrome["sample"]) == 3 and chrome["more"] == 27 and chrome["eol"]["status"] == "eol" and next(g for g in gs if g["product"] == "7-Zip")["eol"] is None
    assert len(HV.group_rows(rows, "Google Chrome", "120.0.1")) == 31                                    # полный список строк группы не сокращён


async def test_host_vulnerabilities_grouped_by_product_with_paginated_items(client, app, monkeypatch):
    from app.ksc import vulns as V

    await login(client, "admin", "Admin-Passw0rd-123")
    s = (await client.post("/api/v1/admin/sources", json={"name": "KSC-B", "host": "b.example.local", "database": "KAV", "username": "u", "password": "p"})).json()
    await client.post("/api/v1/auth/source", json={"source_id": s["id"]})

    async def on_host(_c, _h):
        return [ksc([f"CVE-2026-{i:04d}"], kla=f"KLA{i}", occ=i, sev="critical" if i == 0 else "high") for i in range(60)] + [ksc(["CVE-2025-1"], kla="KLA999", app="7-Zip", ver="23.01", occ=999, sev="warning")]

    async def ext_ok(*_a):
        return [], True

    monkeypatch.setattr(V, "on_host", on_host)
    import app.api.vdb as vdb_api
    monkeypatch.setattr(vdb_api, "host_ext_items", ext_ok)
    g = (await client.get("/api/v1/hosts/21/vulnerabilities", params={"group": "product"})).json()
    assert g["groups_total"] == 2 and g["counts"]["total"] == 61 and "items" not in g
    chrome = g["groups"][0]
    assert chrome["product"] == "Google Chrome" and chrome["cves"] == 60 and len(chrome["sample"]) == 3 and chrome["more"] == 57 and chrome["severity"] == "critical"
    p1 = (await client.get("/api/v1/hosts/21/vulnerabilities/items", params={"product": "Google Chrome", "version": chrome["version"], "limit": 25})).json()
    p3 = (await client.get("/api/v1/hosts/21/vulnerabilities/items", params={"product": "Google Chrome", "version": chrome["version"], "limit": 25, "offset": 50})).json()
    assert p1["total"] == 60 and len(p1["items"]) == 25 and len(p3["items"]) == 10                       # серверная пагинация, ничего не потеряно
    page = (await client.get("/api/v1/hosts/21/vulnerabilities", params={"group": "product", "limit": 1, "offset": 1})).json()
    assert [x["product"] for x in page["groups"]] == ["7-Zip"] and page["groups_total"] == 2
