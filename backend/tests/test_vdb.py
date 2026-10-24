"""База уязвимостей: разбор форматов (реальные образцы NVD/KEV/OSV, синтетический БДУ), хранение и замена данных, сопоставление с каталогом (ложные совпадения, backport, старые ветки,
противоречия источников), синхронизация через подставной HTTP и API. Без сети и без KSC."""
import io
import json
import uuid
import zipfile
from pathlib import Path

import httpx
import pytest

from app.models import CatalogProduct, CatalogState, VdbFinding, VdbMapping, VdbRecord, VdbSource, VdbVuln, utcnow
from app.vdb import match as M
from app.vdb import parsers, store
from app.vdb.fetch import Http
from app.vdb.normalize import Aff, Rec, parse_cpe, parse_purl
from app.vdb.sync import VdbSync, analyze
from tests.conftest import login

FIX = Path(__file__).parent / "fixtures" / "vdb"
NVD, KEV, OSV = (json.loads((FIX / n).read_text()) for n in ("nvd.json", "kev.json", "osv.json"))


# ------------------------------------------------------------------------------------------------ разбор
def test_cpe_and_purl():
    c = parse_cpe(r"cpe:2.3:a:google:chrome:116.0.1:*:*:*:*:wordpress:*:*")
    assert (c["part"], c["vendor"], c["product"], c["version"], c["target_sw"]) == ("a", "google", "chrome", "116.0.1", "wordpress")
    assert parse_cpe(r"cpe:2.3:a:vendor:a\:b:1.0:*:*:*:*:*:*:*")["product"] == "a:b" and parse_cpe("bad") == {}
    assert parse_purl("pkg:deb/debian/openssl@3.0.11?arch=amd64") == {"type": "deb", "namespace": "debian", "name": "openssl", "version": "3.0.11"}


def test_parse_nvd_real_samples():
    recs = {r.vuln_key: r for r in (parsers.parse_nvd(i) for i in NVD["vulnerabilities"])}
    chrome = next(a for a in recs["CVE-2023-4863"].affected if a.product == "chrome")
    assert (chrome.vendor, chrome.v_end, chrome.v_end_incl, chrome.v_start) == ("google", "116.0.5845.187", False, "") and not chrome.versions_all
    assert recs["CVE-2023-4863"].severity == "high" and recs["CVE-2023-4863"].score == 8.8 and recs["CVE-2023-4863"].published.year == 2023
    assert recs["CVE-2024-3094"].severity == "critical" and {a.exact for a in recs["CVE-2024-3094"].affected} == {"5.6.0", "5.6.1"}
    assert all(a.conditional for a in recs["CVE-2021-44228"].affected[:3])           # конфигурация «И» (приложение на определённой платформе) — зависит от среды


def test_parse_kev_flags_exploitation():
    recs = list(parsers.parse_kev(KEV))
    assert len(recs) == 4 and all(r.exploited and r.affected[0].versions_all for r in recs)
    assert next(r for r in recs if r.vuln_key == "CVE-2021-44228").affected[0].product == "Log4j2"


def test_parse_osv_uses_upstream_and_ranges():
    r = parsers.parse_osv(OSV)
    assert r.vuln_key == "CVE-2023-4863" and "DEBIAN-CVE-2023-4863" in (r.aliases + [r.ext_id]) and r.fix_available
    a = next(x for x in r.affected if x.ecosystem == "Debian:12")
    assert (a.pkg_name, a.v_end, a.fixed, a.v_start) == ("chromium", "117.0.5938.62-1", "117.0.5938.62-1", "") and not a.exact


def test_parse_bdu_versions_and_ids():
    recs = {r.ext_id: r for r in parsers.parse_bdu(io.BytesIO((FIX / "bdu.xml").read_bytes()))}
    a = recs["BDU:2024-00001"]
    assert a.vuln_key == "CVE-2024-99001" and a.severity == "critical" and a.score == 9.8 and a.fix_available and "BDU:2024-00001" in a.aliases
    assert [(x.v_end, x.v_end_incl, x.v_start, x.platform) for x in a.affected] == [("8.4.15", False, "", "windows"), ("9.2", True, "9.0", "windows")]
    b = recs["BDU:2024-00002"]
    assert b.vuln_key == "BDU:2024-00002" and b.severity == "medium" and b.fix_available is False
    assert (b.affected[0].v_end, b.affected[0].v_end_incl) == ("2.0", True) and b.affected[1].version_text.startswith("неопределённая")


# ------------------------------------------------------------------------------------------------ каталог и сопоставление
def prod(key, name, publisher, versions, *, platforms=1, scheme="numeric", family="", component=False, names=None):
    vs = [{"version": v, "scheme": scheme, "platform": platforms, "hosts_active": h, "installs_active": h, "product_ids": [hash((key, v)) % 100000], "raw": [v], "names": [name]} for v, h in versions]
    return CatalogProduct(source_id=uuid.uuid4(), key=key, name=name, publisher=publisher, publisher_key=publisher.lower().replace(" ", "-"), origin="builtin", component=component,
                          family_key=family or key, platforms=platforms, names=[[n, 1] for n in (names or [name])], versions=vs, scheme=scheme, hosts_active=sum(h for _, h in versions),
                          installs_active=sum(h for _, h in versions), search=name.lower())


def aff(source="nvd", **kw) -> object:
    kw.setdefault("ext_id", "X")
    from types import SimpleNamespace  # noqa: PLC0415

    base = dict(source=source, vuln_key="CVE-1", vendor="", product="", pkg_name="", ecosystem="", platform="", exact="", v_start="", v_start_incl=True, v_end="", v_end_incl=False, fixed="",
                versions_all=False, version_text="", conditional=False)
    return SimpleNamespace(**{**base, **kw})


CATALOG = M.load_catalog([
    prod("google-chrome", "Google Chrome", "Google", [("115.0.5790.0", 5), ("116.0.5845.187", 2), ("117.0.1", 3)]),
    prod("contoso-agent", "Contoso Agent", "Contoso", [("8.9", 4), ("8.10.1", 2), ("8.4.14", 1)]),
    prod("trueconf-server", "TrueConf Server", "TrueConf", [("5.4", 1)]), prod("trueconf-client", "TrueConf Client", "TrueConf", [("8.1", 7)]),
    prod("php", "PHP", "The PHP Group", [("8.1.2", 3)]), prod("php-xml", "php-xml", "", [("8.1.2", 3)], platforms=2, family="php", component=True, scheme="dpkg"),
    prod("openssl", "openssl", "", [("3.0.11-1~deb12u2", 4), ("", 1)], platforms=2, scheme="dpkg", names=["openssl"]),
    prod("java", "Java (Oracle)", "Oracle", [("8.0.391", 2)]),
])
MAT = M.Matcher(CATALOG, [])


def run(affs, matcher=MAT, only_active=True):
    return {(m.product_key, m.version): m for m in M.matches_from(matcher, [a for a in affs], only_active=only_active)}


def test_range_confirmed_only_for_affected_versions_and_reliable_product():
    out = run([aff(vendor="google", product="chrome", v_end="116.0.5845.187")])
    assert {k[1] for k in out} == {"115.0.5790.0"} and out[("google-chrome", "115.0.5790.0")].status == "confirmed"          # граница исключена: 116.0.5845.187 и новее — не затронуты
    assert out[("google-chrome", "115.0.5790.0")].confidence == "high"


def test_name_only_match_is_never_confirmed():
    out = run([aff(vendor="unknown_corp", product="chrome", v_end="130")])           # то же название, другой производитель
    assert {m.status for m in out.values()} == {"potential"} and all(m.confidence == "medium" for m in out.values()) and "только по названию" in next(iter(out.values())).basis


def test_no_false_matches_on_similar_names():
    assert run([aff(vendor="contoso", product="agent_manager", versions_all=True)]) == {}                      # название длиннее — другой продукт
    assert run([aff(vendor="contoso", product="chrome_agent", versions_all=True)]) == {}
    out = run([aff(vendor="trueconf", product="trueconf_server", versions_all=True)])
    assert {k[0] for k in out} == {"trueconf-server"}                                                          # сервер не путается с клиентом
    out = run([aff(vendor="php", product="php", v_end="8.1.20")])
    assert {k[0] for k in out} == {"php"}                                                                      # компоненты семейства (php-xml) отдельно не совпадают по названию


def test_version_ordering_is_numeric_not_textual():
    out = run([aff(vendor="contoso", product="agent", v_end="8.10", v_end_incl=False)])
    assert {k[1] for k in out} == {"8.9", "8.4.14"}                                                             # 8.9 < 8.10, а 8.10.1 уже нет
    out = run([aff(vendor="contoso", product="agent", v_start="8.5", v_end="8.10", v_end_incl=True)])
    assert {k[1] for k in out} == {"8.9"}


def test_unbounded_and_environment_dependent_need_review():
    out = run([aff(source="kev", vendor="Contoso", product="Agent", versions_all=True, version_text="версии не указаны в каталоге KEV")])
    assert {m.status for m in out.values()} == {"clarify"}                                                      # KEV версии не указывает: не «подтверждено» и не «потенциально» — уточнить
    out = run([aff(vendor="contoso", product="agent", v_end="9", conditional=True)])
    assert {m.status for m in out.values()} == {"clarify"} and "среды" in next(iter(out.values())).basis
    out = run([aff(vendor="contoso", product="agent", v_end="9", platform="plugin:wordpress")])
    assert {m.status for m in out.values()} == {"clarify"}
    out = run([aff(vendor="contoso", product="agent", platform="linux", v_end="9")])
    assert out == {}                                                                                           # источник говорит о Linux, установлен Windows


def test_linux_backport_and_distro_fix():
    up = aff(vendor="openssl", product="openssl", v_end="3.0.12")                                                # данные upstream: версия ниже 3.0.12
    out = run([up])
    assert out[("openssl", "3.0.11-1~deb12u2")].status == "clarify" and "перенесено" in out[("openssl", "3.0.11-1~deb12u2")].basis
    fixed = aff(source="osv", ecosystem="Debian:12", pkg_name="openssl", product="openssl", v_end="3.0.11-1~deb12u2", fixed="3.0.11-1~deb12u2", ext_id="DEBIAN-CVE-1")
    out = run([up, fixed])
    assert out[("openssl", "3.0.11-1~deb12u2")].status == "fixed"                                                # исправление дистрибутива важнее upstream
    open_ = aff(source="osv", ecosystem="Debian:12", pkg_name="openssl", product="openssl", v_end="3.0.13-1~deb12u1", fixed="3.0.13-1~deb12u1", ext_id="DEBIAN-CVE-1")
    out = run([up, open_])
    assert out[("openssl", "3.0.11-1~deb12u2")].status == "confirmed"                                            # пакет дистрибутива ниже исправленной версии
    other_release = aff(source="osv", ecosystem="Debian:11", pkg_name="openssl", product="openssl", v_end="3.0.13-1~deb11u1", fixed="3.0.13-1~deb11u1")
    assert ("openssl", "3.0.11-1~deb12u2") not in run([other_release])                                          # исправление другого выпуска дистрибутива к сборке deb12 не относится


def test_insufficient_when_installed_version_unusable():
    out = run([aff(vendor="openssl", product="openssl", v_end="3.0.12")])
    assert out[("openssl", "")].status == "insufficient"


def test_admin_mapping_and_exclusion_survive():
    a = aff(vendor="acme", product="widget", v_end="9")
    assert run([a]) == {}
    mapped = M.Matcher(CATALOG, [VdbMapping(vendor_key="acme", product_key="widget", catalog_key="contoso-agent", action="map")])
    out = run([a], mapped)
    assert {m.status for m in out.values()} == {"confirmed"} and {m.confidence for m in out.values()} == {"mapped"}
    excl = M.Matcher(CATALOG, [VdbMapping(vendor_key="google", product_key="chrome", catalog_key="google-chrome", action="exclude")])
    assert run([aff(vendor="google", product="chrome", v_end="130")], excl) == {}


def test_java_update_notation_is_not_guessed():
    out = run([aff(vendor="oracle", product="jre", v_end="8u401")])                                              # 8u401 нельзя сравнить с 8.0.391 числами
    assert {m.status for m in out.values()} == {"clarify"} and "не сопоставима" in next(iter(out.values())).basis


# ------------------------------------------------------------------------------------------------ хранение
def rec(source, ext, key=None, **kw):
    return Rec(source=source, ext_id=ext, vuln_key=key or ext, **kw)


async def test_store_idempotent_merge_and_swap(app):
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        n, keys = await store.save_batch(db, 1, [rec("nvd", "CVE-1", severity="high", score=8.1, title="t")])
        n2, _ = await store.save_batch(db, 1, [rec("nvd", "CVE-1", severity="high", score=8.1, title="t")])
        assert (n, n2) == (1, 0) or n2 == 1                                      # без даты изменения запись считается новой: повторная загрузка допустима, но дублей быть не должно
        await store.save_batch(db, 1, [rec("kev", "CVE-1", exploited=True), rec("bdu", "BDU:1", "CVE-1", severity="critical", score=9.8, fix_available=True)])
        await store.refresh_vulns(db, {"CVE-1"})
        await db.commit()
        v = await db.get(VdbVuln, "CVE-1")
        assert v.exploited and v.sev_rank == 4 and v.score == 9.8 and v.sources == "bdu,kev,nvd" and "bdu:1" in v.ids_text
        src = await db.get(VdbSource, "kev")
        old = src.active_generation
        gen = await store.next_generation(db, "kev")
        with pytest.raises(store.IntegrityError):                                # пустая выгрузка не заменяет действующую
            await store.swap_generation(db, src, gen)
        await store.save_batch(db, gen, [rec("kev", f"CVE-2-{i}", exploited=True) for i in range(120)])
        await store.swap_generation(db, src, gen)
        assert src.active_generation == gen and src.prev_generation == old and src.records == 120
        gen2 = await store.next_generation(db, "kev")
        await store.save_batch(db, gen2, [rec("kev", "CVE-3-1")] * 3)         # слишком мало записей по сравнению с действующей копией
        with pytest.raises(store.IntegrityError):
            await store.swap_generation(db, src, gen2)
        keys = await store.restore_previous(db, src)
        assert src.active_generation == old and "CVE-1" in keys


# ------------------------------------------------------------------------------------------------ синхронизация
def mock_transport(counter: dict):
    def handler(req: httpx.Request) -> httpx.Response:
        u = str(req.url)
        counter[u.split("?")[0]] = counter.get(u.split("?")[0], 0) + 1
        if "known_exploited" in u:
            return httpx.Response(200, json=KEV)
        if "nvd.nist.gov/rest/json/cves" in u:
            if "cveId=" in u:
                return httpx.Response(200, json={"vulnerabilities": []})
            return httpx.Response(200, json=NVD)
        if "osv.dev/v1/vulns/" in u:
            return httpx.Response(200, json=OSV)
        if "querybatch" in u:
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "DEBIAN-CVE-2023-4863"}]}]})
        if "bdu.fstec.ru" in u:
            return httpx.Response(200, content=_bdu_zip())
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def _bdu_zip() -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("export/export.xml", (FIX / "bdu.xml").read_bytes())
    return b.getvalue()


def make_sync(app, counter=None):
    async def nosleep(_s):
        return None
    return VdbSync(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal,
                   http_factory=lambda key: Http(transport=mock_transport(counter if counter is not None else {}), sleep=nosleep), sleep=nosleep)


async def test_sync_all_sources_merge_one_card(app, client):
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        (await db.get(VdbSource, "osv")).settings = {"ecosystems": [], "enrich": True, "max_per_run": 20}
        await db.commit()
    calls: dict = {}
    sync = make_sync(app, calls)
    for key in ("kev", "nvd", "osv", "bdu"):
        assert await sync.run_source(key, "manual"), key
    async with app.state.session_maker() as db:
        rows = {r.key: r for r in (await db.execute(VdbSource.__table__.select())).all()}
        srcs = {s.key: s for s in (await db.execute(__import__("sqlalchemy").select(VdbSource))).scalars().all()}
        assert all(s.status == "ok" and s.last_ok_at for s in srcs.values()) and srcs["kev"].records == 4 and srcs["bdu"].records == 2 and srcs["nvd"].records == 3
        v = await db.get(VdbVuln, "CVE-2023-4863")
        assert v.exploited and set(v.sources.split(",")) >= {"nvd", "kev"}
        assert (await db.get(VdbVuln, "CVE-2024-99001")).sources == "bdu"
    await login(client, "admin", "Admin-Passw0rd-123")
    card = (await client.get("/api/v1/vdb/vulns/CVE-2023-4863")).json()
    assert {r["source"] for r in card["records"]} >= {"nvd", "kev"} and card["exploited"] and card["records"][0]["affected"] is not None
    assert (await client.get("/api/v1/vdb/vulns/BDU:2024-00001")).json()["key"] == "CVE-2024-99001"                  # карточка открывается по любому идентификатору
    s = (await client.get("/api/v1/vdb/sources")).json()
    assert [i["key"] for i in s["items"]] == ["bdu", "kev", "nvd", "osv"] and s["vulns"] >= 6 and s["items"][1]["runs"][0]["status"] == "ok"


async def test_failed_update_keeps_last_good_data(app):
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        await db.commit()
    sync = make_sync(app)
    assert await sync.run_source("kev", "manual")
    mode = {"v": "500"}

    def bad(key):
        async def nosleep(_s):
            return None

        def handler(r):
            return httpx.Response(500) if mode["v"] == "500" else httpx.Response(200, json={"unexpected": True})
        return Http(transport=httpx.MockTransport(handler), sleep=nosleep)
    sync._http_factory = bad
    assert not await sync.run_source("kev", "manual")                  # источник недоступен
    mode["v"] = "junk"
    assert not await sync.run_source("kev", "manual")                  # ответ не похож на каталог
    async with app.state.session_maker() as db:
        s = await db.get(VdbSource, "kev")
        assert s.status == "error" and s.last_error and s.records == 4 and s.last_ok_at
        keys = set((await db.execute(__import__("sqlalchemy").select(VdbRecord.ext_id).where(VdbRecord.source == "kev", VdbRecord.generation == s.active_generation))).scalars().all())
        assert "CVE-2021-44228" in keys                                # действующая копия цела, поиск продолжает работать
        assert (await db.get(VdbVuln, "CVE-2021-44228")) is not None


async def test_bdu_manual_file_and_corrupt_file(app, tmp_path):
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        await db.commit()
    sync = make_sync(app)
    f = tmp_path / "bdu.zip"
    f.write_bytes(_bdu_zip())
    assert await sync.run_source("bdu", "file", file=f)
    bad = tmp_path / "bad.xml"
    bad.write_text("<vulnerabilities><vul><identifier>BDU:1</identifier>")
    assert not await sync.run_source("bdu", "file", file=bad)
    async with app.state.session_maker() as db:
        s = await db.get(VdbSource, "bdu")
        assert s.status == "error" and "XML" in s.last_error and s.records == 2          # прежняя копия осталась в работе


async def test_nvd_incremental_cursor(app):
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        (await db.get(VdbSource, "nvd")).settings = {"history_days": 30}
        await db.commit()
    calls: dict = {}
    sync = make_sync(app, calls)
    assert await sync.run_source("nvd", "manual")
    first = sum(v for k, v in calls.items() if "nvd" in k)
    assert await sync.run_source("nvd", "manual")
    async with app.state.session_maker() as db:
        s = await db.get(VdbSource, "nvd")
        assert s.cursor and s.cursor.get("last_mod")
        rows = (await db.execute(__import__("sqlalchemy").select(VdbRecord.ext_id).where(VdbRecord.source == "nvd"))).scalars().all()
        assert sorted(rows) == ["CVE-2021-44228", "CVE-2023-4863", "CVE-2024-3094"]           # повторная загрузка не дублирует записи
    assert first >= 1


# ------------------------------------------------------------------------------------------------ API, находки, решения
async def _ksc_source(client, app) -> str:
    src = (await client.post("/api/v1/admin/sources", json={"name": "KSC-A", "host": "a.example.local", "database": "KAV", "username": "u", "password": "p"})).json()
    await client.post("/api/v1/auth/source", json={"source_id": src["id"]})
    sid = uuid.UUID(src["id"])
    async with app.state.session_maker() as db:
        db.add(CatalogState(source_id=sid, status="ready", built_at=utcnow(), activity_days=30))
        for p in CATALOG:
            db.add(CatalogProduct(source_id=sid, key=p.key, name=p.name, publisher=p.publisher, publisher_key=p.publisher_key, origin="builtin", component=p.component, family_key=p.family_key,
                                  platforms=p.platforms, names=[[n, 1] for n in p.names], versions=p.versions, scheme=p.scheme, hosts_active=p.hosts_active, hosts_all=p.hosts_active,
                                  installs_active=p.installs_active, installs_all=p.installs_active, search=p.name.lower(), built_at=utcnow()))
        await db.commit()
    return src["id"]


async def test_findings_new_serious_and_seen_flow(app, client):
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await _ksc_source(client, app)
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        a = Rec(source="nvd", ext_id="CVE-2099-1", vuln_key="CVE-2099-1", severity="critical", score=9.8, title="Chrome RCE", published=utcnow(), modified=utcnow(),
                affected=[Aff(vendor="google", product="chrome", v_end="116.0.5845.187")])
        k = Rec(source="kev", ext_id="CVE-2099-1", vuln_key="CVE-2099-1", exploited=True, published=utcnow(), modified=utcnow(), affected=[Aff(vendor="Google", product="Chrome", versions_all=True)])
        low = Rec(source="nvd", ext_id="CVE-2099-2", vuln_key="CVE-2099-2", severity="low", score=2.0, title="Not ours", published=utcnow(), modified=utcnow(),
                  affected=[Aff(vendor="nobody", product="nothing", v_end="1")])
        await store.save_batch(db, 1, [a, low])
        await store.save_batch(db, 1, [k])
        await store.refresh_vulns(db, {"CVE-2099-1", "CVE-2099-2"})
        n = await analyze(db, uuid.UUID(sid), keys=None)
        await db.commit()
    assert n == 1
    f = (await client.get("/api/v1/vdb/findings")).json()
    assert f["total"] == 1 and f["summary"] == {"total": 1, "new": 1, "new_exploited": 1, "new_critical": 1, "new_serious": 1}
    it = f["items"][0]
    assert it["key"] == "CVE-2099-1" and it["exploited"] and it["finding"]["status"] == "confirmed" and it["finding"]["new"] and it["finding"]["installs"] == 5          # KEV версий не называет и не расширяет границы NVD
    search = (await client.get("/api/v1/vdb/vulns", params={"q": "chrome"})).json()
    assert [i["key"] for i in search["items"]] == ["CVE-2099-1"]
    assert (await client.get("/api/v1/vdb/vulns", params={"affects": True})).json()["total"] == 1
    assert (await client.get("/api/v1/vdb/vulns", params={"exploited": True})).json()["total"] == 1
    assert (await client.get("/api/v1/vdb/vulns", params={"min_severity": "high"})).json()["items"][0]["key"] == "CVE-2099-1"
    assert (await client.post("/api/v1/vdb/findings/seen", json={"keys": ["CVE-2099-1"]})).json()["new"] == 0
    cc = (await client.get("/api/v1/vdb/catalog-counts", params={"keys": "google-chrome,php"})).json()["items"]
    assert cc["google-chrome"] == {"total": 1, "kev": 1, "critical": 1, "confirmed": 1} and cc["php"]["total"] == 0
    pv = (await client.get("/api/v1/vdb/products/google-chrome")).json()
    assert pv["total"] == 1 and pv["items"][0]["versions"] == ["115.0.5790.0"]
    card = (await client.get("/api/v1/vdb/vulns/CVE-2099-1")).json()
    assert card["infrastructure"]["catalog"] and {m["status"] for m in card["infrastructure"]["matches"]} == {"confirmed"}


async def test_mappings_exclusion_changes_findings_and_permissions(app, client):
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await _ksc_source(client, app)
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        await store.save_batch(db, 1, [Rec(source="nvd", ext_id="CVE-2099-3", vuln_key="CVE-2099-3", severity="high", title="Widget", published=utcnow(), modified=utcnow(),
                                           affected=[Aff(vendor="acme", product="widget", v_end="9")])])
        await store.refresh_vulns(db, {"CVE-2099-3"})
        assert await analyze(db, uuid.UUID(sid), keys=None) == 0
        await db.commit()
    r = await client.post("/api/v1/vdb/mappings", json={"vendor_key": "acme", "product": "Widget", "catalog_key": "contoso-agent", "action": "map", "note": "тест"})
    assert r.status_code == 201
    assert (await client.get("/api/v1/vdb/findings")).json()["items"][0]["finding"]["status"] == "confirmed"       # находки пересчитаны сразу после решения
    mid = (await client.get("/api/v1/vdb/mappings")).json()["items"][0]["id"]
    assert (await client.delete(f"/api/v1/vdb/mappings/{mid}")).status_code == 204
    assert (await client.get("/api/v1/vdb/findings")).json()["total"] == 0
    # настройки и запуск источников — только администратору
    assert (await client.put("/api/v1/vdb/sources/nvd", json={"enabled": True, "interval_hours": 12, "settings": {"history_days": 90}, "api_key": "k" * 36})).json()["secret_set"]
    assert (await client.post("/api/v1/vdb/sources/kev/sync")).status_code == 202
    assert (await client.put("/api/v1/vdb/sources/bdu", json={"settings": {"url": "http://insecure"}})).status_code == 422
    c2 = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")
    async with c2:
        await login(c2, "viewer", "Viewer-Passw0rd-123")
        assert (await c2.put("/api/v1/vdb/sources/nvd", json={"enabled": False})).status_code == 403
        assert (await c2.post("/api/v1/vdb/mappings", json={"product": "x", "catalog_key": "y"})).status_code == 403
        assert (await c2.get("/api/v1/vdb/vulns")).status_code == 200


def test_cvss3_scores_match_specification():
    from app.vdb.normalize import cvss3_score  # noqa: PLC0415

    for vec, score in (("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
                       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5)):
        assert cvss3_score(vec) == score
    assert cvss3_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None and cvss3_score("") is None


def test_osv_score_from_vector():
    d = {**OSV, "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}]}
    r = parsers.parse_osv(d)
    assert r.score == 8.8 and r.severity == "high"


async def test_unchanged_records_are_skipped_on_reload(app):
    now = utcnow()
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        batch = lambda: [rec("nvd", f"CVE-2098-{i}", severity="low", modified=now, affected=[Aff(vendor="v", product="p", v_end="1")]) for i in range(50)]  # noqa: E731
        assert (await store.save_batch(db, 1, batch()))[0] == 50
        assert (await store.save_batch(db, 1, batch()))[0] == 0                   # та же дата изменения — запись не перезаписывается
        changed = batch()
        changed[0].modified = now.replace(year=now.year + 1) if False else now.__class__.fromtimestamp(now.timestamp() + 3600, now.tzinfo)
        n, keys = await store.save_batch(db, 1, changed)
        assert n == 1 and keys == {"CVE-2098-0"}
        await db.commit()


async def test_old_findings_are_backlog_not_news(app, client):
    await login(client, "admin", "Admin-Passw0rd-123")
    sid = await _ksc_source(client, app)
    old = utcnow().replace(year=utcnow().year - 3)
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        await store.save_batch(db, 1, [Rec(source="nvd", ext_id="CVE-2020-1", vuln_key="CVE-2020-1", severity="critical", published=old, modified=old, affected=[Aff(vendor="google", product="chrome", v_end="130")])])
        await store.refresh_vulns(db, {"CVE-2020-1"})
        await analyze(db, uuid.UUID(sid), keys=None)
        await db.commit()
    f = (await client.get("/api/v1/vdb/findings")).json()
    assert f["total"] == 1 and f["summary"]["new"] == 0 and not f["items"][0]["finding"]["new"]               # давняя уязвимость — исходное состояние, а не новость
    assert (await client.get("/api/v1/vdb/findings", params={"new_only": True})).json()["total"] == 0
