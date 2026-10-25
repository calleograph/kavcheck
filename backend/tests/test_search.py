"""Поиск со звёздочкой: единые правила (app/search.py) и их применение в API — каталог, база уязвимостей, пользователи. SQL Server проверяет tests/test_ksc_live.py."""
import pytest

from app import search as S
from app.models import VdbVuln
from tests.conftest import login
from tests.test_catalog_api import _seed_catalog, _source


# ------------------------------------------------------------------------------------------------ правила
@pytest.mark.parametrize("text,mode,mssql,local", [
    ("chrome", "contains", "%chrome%", "%chrome%"),
    ("chrome", "prefix", "chrome%", "chrome%"),
    ("SRV-*", "contains", "SRV-%", "srv-%"),
    ("*-DB", "contains", "%-DB", "%-db"),
    ("*2026*", "contains", "%2026%", "%2026%"),
    ("SRV-*-DB*", "contains", "SRV-%-DB%", "srv-%-db%"),
    ("8.1*", "prefix", "8.1%", "8.1%"),
    ("a%b_c[d", "contains", "%a[%]b[_]c[[]d%", "%a\\%b\\_c[d%"),
    ("100%*", "contains", "100[%]%", "100\\%%"),
    ("a\\b*", "contains", "a\\b%", "a\\\\b%"),
])
def test_patterns(text, mode, mssql, local):
    assert S.mssql_like(text, mode) == mssql and S.local_like(text, mode) == local


@pytest.mark.parametrize("empty", [None, "", "   ", "*", " * ", "***"])
def test_empty_and_only_star_mean_no_filter(empty):
    assert S.mssql_like(empty) is None and S.local_like(empty) is None and S.matcher(empty) is None and S.any_field(empty) is None


def test_stars_are_collapsed_and_limited():
    assert S.clean("a***b") == "a*b"
    assert S.clean("*" * 50 + "x") == "*x"
    with pytest.raises(S.MaskError):
        S.clean("a*b*c*d*e*f*g*h")                      # семь звёздочек
    with pytest.raises(S.MaskError):
        S.clean("x" * 201)


def test_matcher_rules_case_cyrillic_and_literals():
    m = lambda text, s, mode="contains": S.matcher(text, mode)(s)      # noqa: E731
    assert m("*2026*", "CVE-2026-0001") and m("CVE-2026-*", "cve-2026-0001") and not m("CVE-2026-*", "xCVE-2026-1") and m("*-DB", "SRV-1-db") and not m("*-DB", "SRV-DB-1")
    assert m("SRV-*-DB*", "SRV-01-DB-main") and not m("SRV-*-DB*", "SRV-01-WEB") and m("*SQL*", "my-sql-01") and m("SRV-*", "SRV-")
    assert m("сервер*", "СЕРВЕР-1С") and m("*бд", "Сервер БД") and not m("*бд", "БД сервер")                         # кириллица и регистр
    assert m("a.b*", "A.B.c") and not m("a.b*", "axb") and m("1+1*", "1+1=2") and m("(x)*", "(X) y") and m("a?b*", "a?b!") and not m("a?b*", "aab")   # спецсимволы — обычные
    assert m("chrome", "Google Chrome 120") and not m("chrome", "Chromium") and m("8.1", "8.1.27", "prefix") and not m("1.2", "8.1.27", "prefix")      # без звёздочки — по части строки
    assert S.any_field("*db")("a", None, "x-DB") and not S.any_field("*db")("a", None, 5)


# ------------------------------------------------------------------------------------------------ API
async def test_catalog_masks(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    src = await _source(client)
    await client.post("/api/v1/auth/source", json={"source_id": src["id"]})
    await _seed_catalog(app, src["id"])
    get = lambda q, path="/api/v1/catalog": client.get(path, params={"q": q, "all_hosts": True})   # noqa: E731
    assert [i["key"] for i in (await get("goo*")).json()["items"]] == ["google-chrome"]
    assert [i["key"] for i in (await get("*chrome")).json()["items"]] == ["google-chrome"]
    assert [i["key"] for i in (await get("*-zip*")).json()["items"]] == ["7-zip"]
    assert (await get("chrome*google")).json()["total"] == 0 and (await get("g*e*c*e")).json()["total"] == 1
    assert (await get("Acme*")).json()["total"] == 1                                    # по производителю
    assert (await get("ZIP*")).json()["total"] == 0 and (await get("*ZIP")).json()["total"] == 1       # регистр не важен
    assert (await get("*")).json()["total"] == 3 and (await get("")).json()["total"] == 3
    assert (await get("%")).json()["total"] == 0 and (await get("_")).json()["total"] == 0
    assert (await get("a*b*c*d*e*f*g*h")).status_code == 422
    pub = (await client.get("/api/v1/catalog/publishers", params={"q": "goo*", "all_hosts": True})).json()
    assert [p["publisher"] for p in pub["items"]] == ["Google"]
    assert [i["key"] for i in (await client.get("/api/v1/catalog/search", params={"q": "*zip"})).json()["items"]] == ["7-zip"]


async def _seed_vulns(app) -> None:
    async with app.state.session_maker() as db:
        for key, title, prods in (("CVE-2025-1111", "сервер печати: переполнение буфера", "acme printd"), ("CVE-2026-0001", "SQL injection in report", "contoso reporting"),
                                  ("CVE-2026-0002", "Heap overflow", "contoso sqlserver"), ("CVE-2027-0003", "Info leak, 2026 patch level", "fabrikam viewer")):
            db.add(VdbVuln(vuln_key=key, title=title, ids_text=f"bdu:2026-9{key[-1]} {key.lower()}" if key.endswith("1") else key.lower(), products_text=prods, description=title))
        await db.commit()


async def test_vdb_search_masks(app, client):
    await _seed_vulns(app)
    await login(client, "admin", "Admin-Passw0rd-123")
    keys = lambda q, **p: client.get("/api/v1/vdb/vulns", params={"q": q, "sort": "key", "desc": "false", **p})      # noqa: E731

    async def found(q, **p):
        r = await keys(q, **p)
        assert r.status_code == 200, r.text
        return [i["key"] for i in r.json()["items"]]
    assert await found("CVE-2026-*") == ["CVE-2026-0001", "CVE-2026-0002"]                                    # начало идентификатора
    assert await found("cve-2026-*") == ["CVE-2026-0001", "CVE-2026-0002"]                                    # регистр
    assert await found("*2026*") == ["CVE-2025-1111", "CVE-2026-0001", "CVE-2026-0002", "CVE-2027-0003"]      # 2026 в идентификаторе (BDU:2026-… у CVE-2025-1111 и в описании CVE-2027)
    assert await found("*-0002") == ["CVE-2026-0002"] and await found("*0001") == ["CVE-2026-0001"]
    assert await found("CVE-*-0003") == ["CVE-2027-0003"] and await found("CVE-2026-*-0001") == []
    assert await found("BDU:2026-*") == ["CVE-2025-1111", "CVE-2026-0001"]                                                   # второй идентификатор записи
    assert await found("*sql*") == ["CVE-2026-0001", "CVE-2026-0002"] and await found("contoso*sql*") == ["CVE-2026-0002"]
    assert await found("сервер*") == ["CVE-2025-1111"]                                                         # кириллица (строчные: SQLite приводит к нижнему регистру только ASCII)
    assert await found("sql injection") == ["CVE-2026-0001"] and await found("injection sql") == ["CVE-2026-0001"]      # без звёздочки — прежнее поведение: все слова в любом порядке
    assert await found("%") == [] and await found("_") == [] and await found("cve_2026") == []                # спецсимволы LIKE — обычные
    assert await found("CVE-*", exploited="false") == ["CVE-2025-1111", "CVE-2026-0001", "CVE-2026-0002", "CVE-2027-0003"] and await found("*") == await found("")
    assert (await keys("a*b*c*d*e*f*g*h")).status_code == 422


async def test_admin_users_mask(client):
    await login(client, "admin", "Admin-Passw0rd-123")
    names = lambda q: client.get("/api/v1/admin/users", params={"q": q})      # noqa: E731
    assert [u["username"] for u in (await names("ad*")).json()["items"]] == ["admin"]
    assert [u["username"] for u in (await names("*wer")).json()["items"]] == ["viewer"]
    assert (await names("*")).json()["items"].__len__() == 2 and (await names("dm")).json()["items"].__len__() == 1 and (await names("%")).json()["items"] == []
    assert (await names("a*b*c*d*e*f*g*h")).status_code == 422
