"""Загрузчики источников базы уязвимостей: потоковый JSON, ленты NVD (контрольные суммы, первая загрузка и обновления), каналы и их переключение, архивы и изменения OSV,
БДУ (условный запрос, сертификаты Минцифры), сохранность действующей базы при обрыве, повреждении и нехватке места, очистка временных файлов. Без сети."""
import io
import json
import ssl
import time
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select

from app.models import VdbRecord, VdbSource, VdbVuln, utcnow
from app.vdb import store, stream
from app.vdb.fetch import Http, builtin_ca, make_ssl
from app.vdb.sync import VdbSync
from tests.conftest import login
from tests.vdbmock import KEV, NVD, OSV, bdu_zip, nvd_feed, osv_zip


# ------------------------------------------------------------------------------------------------ потоковый JSON
def _doc(n: int) -> bytes:
    text = "текст ] } , \"кавычки\" %d ёж"
    return json.dumps({"resultsPerPage": n, "format": "NVD_CVE", "vulnerabilities": [{"cve": {"id": f"CVE-2026-{i:04d}", "descriptions": [{"value": text % i}]}} for i in range(n)], "tail": [1]},
                      ensure_ascii=False).encode()


@pytest.mark.parametrize("chunk", [7, 64, 1 << 20])
def test_iter_array_across_chunk_boundaries(monkeypatch, chunk):
    monkeypatch.setattr(stream, "CHUNK", chunk)
    items = list(stream.iter_array(io.BytesIO(_doc(40)), "vulnerabilities"))
    assert [i["cve"]["id"] for i in items] == [f"CVE-2026-{i:04d}" for i in range(40)] and "ёж" in items[3]["cve"]["descriptions"][0]["value"]


def test_iter_array_rejects_truncated_and_missing():
    raw = _doc(10)
    with pytest.raises(ValueError):
        list(stream.iter_array(io.BytesIO(raw[: len(raw) // 2]), "vulnerabilities"))
    with pytest.raises(ValueError):
        list(stream.iter_array(io.BytesIO(raw), "nothing"))
    assert list(stream.iter_array(io.BytesIO(b'{"vulnerabilities": []}'), "vulnerabilities")) == []


def test_iter_array_memory_is_bounded():
    import tracemalloc  # noqa: PLC0415

    big = _doc(30000)                                    # ≈ 5 МБ
    tracemalloc.start()
    n = 0
    for _ in stream.iter_array(io.BytesIO(big), "vulnerabilities"):
        n += 1
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert n == 30000 and peak < len(big) * 1.5 + 12 * 1024 * 1024         # память не растёт с размером файла


# ------------------------------------------------------------------------------------------------ сертификаты БДУ
def test_builtin_ca_chain_is_the_official_ministry_chain():
    import hashlib  # noqa: PLC0415
    import re  # noqa: PLC0415
    import base64  # noqa: PLC0415

    pems = builtin_ca("russian_trusted_chain")
    fps = {hashlib.sha256(base64.b64decode(re.sub(r"-----.*?-----|\s", "", p))).hexdigest().upper() for p in pems}
    assert "D26D2D0231B7C39F92CC738512BA54103519E4405D68B5BD703E9788CA8ECF31" in fps and len(pems) == 3          # корневой «Russian Trusted Root CA» и промежуточные
    ctx = make_ssl(pems, True)
    assert isinstance(ctx, ssl.SSLContext) and ctx.verify_mode == ssl.CERT_REQUIRED
    assert make_ssl(pems, False) is False


# ------------------------------------------------------------------------------------------------ вспомогательное
def make_sync(app, handler):
    async def nosleep(_s):
        return None
    return VdbSync(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal,
                   http_factory=lambda key: Http(transport=httpx.MockTransport(handler), sleep=nosleep), sleep=nosleep)


async def src(app, key):
    async with app.state.session_maker() as db:
        return await db.get(VdbSource, key)


async def count(app, key):
    async with app.state.session_maker() as db:
        s = await db.get(VdbSource, key)
        return int((await db.execute(select(func.count()).select_from(VdbRecord).where(VdbRecord.source == key, VdbRecord.generation == s.active_generation))).scalar_one())


async def init(app, **settings):
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        for k, v in settings.items():
            (await db.get(VdbSource, k)).settings = v
        await db.commit()


def tmp_empty(app) -> bool:
    d = Path(app.state.settings.data_dir) / "vdb" / "tmp"
    return not d.exists() or not any(d.iterdir())


# ------------------------------------------------------------------------------------------------ NVD
async def test_nvd_feeds_initial_then_changes_only(app):
    await init(app, nvd={"years_back": 2})
    calls: list[str] = []

    def handler(r):
        calls.append(str(r.url))
        if "/feeds/json/cve/2.0/" in str(r.url):
            return nvd_feed(str(r.url))
        return httpx.Response(200, json={"vulnerabilities": []})
    sync = make_sync(app, handler)
    assert await sync.run_source("nvd", "manual")
    s = await src(app, "nvd")
    feeds1 = sorted({u.rsplit("/", 1)[1] for u in calls if "/feeds/" in u and u.endswith(".json.gz")})
    year = utcnow().year
    assert s.channel == "feeds" and s.cursor["feed"] == "feeds" and s.cursor["years_from"] == year - 1 and await count(app, "nvd") == 3
    assert feeds1 == [f"nvdcve-2.0-{year - 1}.json.gz", f"nvdcve-2.0-{year}.json.gz", "nvdcve-2.0-modified.json.gz"] and s.active_generation == 2       # первая загрузка — новое поколение
    assert tmp_empty(app) and [a["ok"] for a in s.diag] == [True]
    calls.clear()
    assert await sync.run_source("nvd", "manual")
    assert sorted({u.rsplit("/", 1)[1] for u in calls if u.endswith(".json.gz")}) == ["nvdcve-2.0-modified.json.gz"]           # обновление — только изменённые
    assert (await src(app, "nvd")).active_generation == 2 and await count(app, "nvd") == 3


async def test_nvd_corrupt_feed_falls_back_to_api_and_never_breaks_good_data(app):
    await init(app, nvd={"years_back": 1, "history_days": 30})
    mode = {"feeds": "ok"}

    def handler(r):
        u = str(r.url)
        if "/feeds/json/cve/2.0/" in u:
            if mode["feeds"] == "ok":
                return nvd_feed(u)
            if mode["feeds"] == "truncated":
                return nvd_feed(u, corrupt=True)
            if mode["feeds"] == "badsum":
                good = nvd_feed(u)
                return httpx.Response(200, text=good.text.replace("sha256:", "sha256:00")) if u.endswith(".meta") else good
            return httpx.Response(503)
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})
    sync = make_sync(app, handler)
    assert await sync.run_source("nvd", "manual") and await count(app, "nvd") == 3
    gen = (await src(app, "nvd")).active_generation
    async with app.state.session_maker() as db:                      # давно не обновлялись: нужны ленты года, а они повреждены
        s = await db.get(VdbSource, "nvd")
        s.cursor = {**s.cursor, "last_mod": "2020-01-01T00:00:00+00:00"}
        await db.commit()
    for bad in ("truncated", "badsum", "down"):
        mode["feeds"] = bad
        assert await sync.run_source("nvd", "manual")                # запасной канал API отработал
        s = await src(app, "nvd")
        assert s.channel == "api" and [a["ok"] for a in s.diag[:2]] == [False, True] and s.diag[0]["channel"] == "feeds" and s.diag[0]["error"]
        assert await count(app, "nvd") == 3 and s.active_generation == gen                # действующая база цела
        async with app.state.session_maker() as db:
            s = await db.get(VdbSource, "nvd")
            s.cursor = {**s.cursor, "last_mod": "2020-01-01T00:00:00+00:00", "feed": "feeds"}
            await db.commit()
    assert tmp_empty(app)


async def test_nvd_initial_corrupt_feed_leaves_no_partial_generation(app):
    await init(app, nvd={"years_back": 2})

    def handler(r):
        u = str(r.url)
        if "/feeds/json/cve/2.0/" in u:
            return nvd_feed(u, corrupt=u.endswith(f"{utcnow().year}.json.gz"))        # первый год получен, второй оборван
        raise httpx.ConnectError("нет сети")
    sync = make_sync(app, handler)
    assert not await sync.run_source("nvd", "manual")
    s = await src(app, "nvd")
    assert s.status == "error" and s.records == 0 and "получен не полностью" in s.last_error and [a["channel"] for a in s.diag] == ["feeds", "api"]
    async with app.state.session_maker() as db:
        assert int((await db.execute(select(func.count()).select_from(VdbRecord).where(VdbRecord.source == "nvd"))).scalar_one()) == 0         # недозагруженное поколение удалено
        assert int((await db.execute(select(func.count()).select_from(VdbVuln))).scalar_one()) == 0
    assert tmp_empty(app)


# ------------------------------------------------------------------------------------------------ KEV, каналы
async def test_kev_switches_to_github_channel_and_records_attempts(app):
    await init(app)

    def handler(r):
        return httpx.Response(503) if "cisa.gov" in str(r.url) else httpx.Response(200, json=KEV)
    assert await make_sync(app, handler).run_source("kev", "manual")
    s = await src(app, "kev")
    assert s.channel == "github" and s.records == 4 and [(a["channel"], a["ok"]) for a in s.diag] == [("cisa", False), ("github", True)]
    assert "503" in s.diag[0]["error"] or "недоступен" in s.diag[0]["error"]


async def test_offline_keeps_last_good_base_and_search_works(app, client):
    await init(app)
    assert await make_sync(app, lambda r: httpx.Response(200, json=KEV)).run_source("kev", "manual")

    def offline(r):
        raise httpx.ConnectError("Temporary failure in name resolution")
    assert not await make_sync(app, offline).run_source("kev", "manual")
    s = await src(app, "kev")
    assert s.status == "error" and s.records == 4 and s.last_ok_at and "ни одним каналом" in s.last_error and len(s.diag) == 2
    await login(client, "admin", "Admin-Passw0rd-123")
    assert (await client.get("/api/v1/vdb/vulns", params={"q": "CVE-2021-44228"})).json()["total"] == 1          # без интернета поиск идёт по последней копии
    out = (await client.get("/api/v1/vdb/sources")).json()["items"]
    kev = next(i for i in out if i["key"] == "kev")
    assert kev["status"] == "error" and kev["records"] == 4 and kev["attempts"][0]["channel"] == "cisa" and kev["runs"][0]["attempts"]


async def test_small_katalog_does_not_replace_good_one(app):
    await init(app)
    big = {**KEV, "vulnerabilities": [{**KEV["vulnerabilities"][0], "cveID": f"CVE-2020-{i:04d}"} for i in range(300)]}
    assert await make_sync(app, lambda r: httpx.Response(200, json=big)).run_source("kev", "manual") and (await src(app, "kev")).records == 300
    assert not await make_sync(app, lambda r: httpx.Response(200, json=KEV)).run_source("kev", "manual")          # 4 записи против 300 — файл неполный
    s = await src(app, "kev")
    assert s.records == 300 and "неполный" in s.last_error and await count(app, "kev") == 300


# ------------------------------------------------------------------------------------------------ OSV
def osv_doc(i: str, modified: str, cve: str = "CVE-2026-9001") -> dict:
    return {**OSV, "id": i, "upstream": [cve], "aliases": [], "modified": modified}


async def test_osv_archive_then_modified_records_and_ecosystem_change(app):
    await init(app, osv={"ecosystems": ["Debian"]})
    state = {"docs": [osv_doc("DEBIAN-CVE-2026-9001", "2026-01-01T00:00:00Z"), osv_doc("DEBIAN-CVE-2026-9002", "2026-01-02T00:00:00Z", "CVE-2026-9002")], "csv_calls": 0, "zip_calls": []}

    def handler(r):
        u = str(r.url)
        if u.endswith("/Debian/all.zip") or u.endswith("/Ubuntu/all.zip"):
            state["zip_calls"].append(u.split("/")[-2])
            return httpx.Response(200, content=osv_zip(state["docs"]))
        if u.endswith("modified_id.csv"):
            state["csv_calls"] += 1
            return httpx.Response(200, text="\n".join(f"{d['modified']},{d['id']}" for d in sorted(state["docs"], key=lambda d: d["modified"], reverse=True)) + "\n")
        for d in state["docs"]:
            if u.endswith(f"/{d['id']}.json"):
                return httpx.Response(200, json=d)
        return httpx.Response(404)
    sync = make_sync(app, handler)
    assert await sync.run_source("osv", "manual")
    s = await src(app, "osv")
    assert await count(app, "osv") == 2 and s.cursor["modified"]["Debian"] == "2026-01-02T00:00:00Z" and state["zip_calls"] == ["Debian"] and s.active_generation == 2
    state["docs"].append(osv_doc("DEBIAN-CVE-2026-9003", "2026-03-01T00:00:00Z", "CVE-2026-9003"))
    assert await sync.run_source("osv", "manual")                    # обновление: архив не скачивается, берётся одна новая запись
    assert state["zip_calls"] == ["Debian"] and await count(app, "osv") == 3 and (await src(app, "osv")).cursor["modified"]["Debian"] == "2026-03-01T00:00:00Z"
    async with app.state.session_maker() as db:
        assert (await db.get(VdbVuln, "CVE-2026-9003")) is not None
        (await db.get(VdbSource, "osv")).settings = {"ecosystems": ["Debian", "Ubuntu"]}
        await db.commit()
    assert await sync.run_source("osv", "manual")                    # состав экосистем изменён — перезагрузка архивами в новое поколение
    assert state["zip_calls"] == ["Debian", "Debian", "Ubuntu"] and (await src(app, "osv")).active_generation == 3 and tmp_empty(app)


async def test_osv_broken_archive_keeps_previous_data(app):
    await init(app, osv={"ecosystems": ["Debian"]})
    mode = {"zip": osv_zip([osv_doc("DEBIAN-CVE-2026-9001", "2026-01-01T00:00:00Z")])}

    def handler(r):
        u = str(r.url)
        return httpx.Response(200, content=mode["zip"]) if u.endswith("all.zip") else httpx.Response(404)
    sync = make_sync(app, handler)
    assert await sync.run_source("osv", "manual") and await count(app, "osv") == 1
    async with app.state.session_maker() as db:                     # ecosystems изменён → перезагрузка, а архив оборван
        (await db.get(VdbSource, "osv")).settings = {"ecosystems": ["Debian", "Ubuntu"]}
        await db.commit()
    mode["zip"] = mode["zip"][:60]
    assert not await sync.run_source("osv", "manual")
    s = await src(app, "osv")
    assert s.status == "error" and s.records == 1 and s.active_generation == 2 and await count(app, "osv") == 1 and tmp_empty(app)


# ------------------------------------------------------------------------------------------------ БДУ
async def test_bdu_site_conditional_request_and_bad_download(app):
    await init(app)
    st = {"mode": "ok", "etag": '"v1"', "calls": []}

    def handler(r):
        st["calls"].append(dict(r.headers))
        if st["mode"] == "ok":
            if r.headers.get("if-none-match") == st["etag"]:
                return httpx.Response(304)
            body = bdu_zip()
            return httpx.Response(200, content=body, headers={"etag": st["etag"], "last-modified": "Fri, 23 Oct 2026 14:13:37 GMT", "content-length": str(len(body))})
        return httpx.Response(200, content=b"PK\x03\x04 not an archive", headers={"etag": '"v2"'})
    sync = make_sync(app, handler)
    assert await sync.run_source("bdu", "manual") and await count(app, "bdu") == 2
    s = await src(app, "bdu")
    assert s.channel == "site" and s.cursor["etag"] == '"v1"' and s.active_generation == 2
    assert await sync.run_source("bdu", "schedule")                  # по расписанию, на сайте ничего не менялось: 304, данные и поколение прежние
    assert (await src(app, "bdu")).active_generation == 2 and st["calls"][-1].get("if-none-match") == '"v1"'
    assert await sync.run_source("bdu", "manual")                    # «Обновить сейчас» всегда читает выгрузку заново
    assert not st["calls"][-1].get("if-none-match") and (await src(app, "bdu")).active_generation == 3
    st.update(mode="bad", etag='"v2"')
    assert not await sync.run_source("bdu", "schedule")
    s = await src(app, "bdu")
    assert s.status == "error" and s.records == 2 and await count(app, "bdu") == 2 and s.channel == "site" and s.cursor["etag"] == '"v1"'


async def test_bdu_upload_uses_file_channel(app, tmp_path):
    await init(app)
    f = tmp_path / "up.zip"
    f.write_bytes(bdu_zip())

    def deny(r):
        raise AssertionError("сайт не должен опрашиваться при ручной загрузке файла")
    assert await make_sync(app, deny).run_source("bdu", "file", file=f)
    s = await src(app, "bdu")
    assert s.channel == "file" and s.records == 2


# ------------------------------------------------------------------------------------------------ место на диске и включение
async def test_not_enough_disk_space_is_reported_before_download(app, monkeypatch):
    from app.vdb import fetch  # noqa: PLC0415

    await init(app, osv={"ecosystems": ["Debian"]})
    monkeypatch.setattr(fetch, "free_bytes", lambda p: 10 * 1024 * 1024)
    big = b"x" * 1000

    def handler(r):
        return httpx.Response(200, content=big, headers={"content-length": str(900 * 1024 * 1024)})
    assert not await make_sync(app, handler).run_source("osv", "manual")
    s = await src(app, "osv")
    assert "Недостаточно места" in s.last_error and s.records == 0 and tmp_empty(app)


async def test_enabling_a_source_queues_first_load_and_settings_are_validated(app, client):
    await init(app)
    await login(client, "admin", "Admin-Passw0rd-123")
    r = (await client.put("/api/v1/vdb/sources/nvd", json={"enabled": True, "settings": {"years_back": 99}})).json()
    assert r["enabled"] and r["requested"] and r["settings"]["years_back"] == 30 and len(r["channels"]) == 2          # одна кнопка: загрузка ставится в очередь
    r = (await client.put("/api/v1/vdb/sources/osv", json={"settings": {"ecosystems": ["Debian", "Нет-такой", "Go"], "all_ecosystems": True}})).json()
    assert r["settings"]["ecosystems"] == ["Debian", "Go"] and r["settings"]["all_ecosystems"] is True and not r["requested"]
    assert (await client.put("/api/v1/vdb/sources/bdu", json={"settings": {"url": "http://plain.example"}})).status_code == 422
    s = (await client.get("/api/v1/vdb/sources")).json()
    assert "Ubuntu" in s["ecosystems"] and len(s["ecosystems"]) > 30


async def test_search_by_product_and_version(app, client):
    await init(app)
    assert await make_sync(app, lambda r: nvd_feed(str(r.url)) if "/feeds/" in str(r.url) else httpx.Response(200, json={"vulnerabilities": []})).run_source("nvd", "manual")
    await login(client, "admin", "Admin-Passw0rd-123")
    get = lambda **p: client.get("/api/v1/vdb/vulns", params=p)      # noqa: E731
    r = (await get(q="chrome", version="115.0.5790.100")).json()
    assert [i["key"] for i in r["items"]] == ["CVE-2023-4863"] and r["items"][0]["version_match"] == "yes"           # chrome < 116.0.5845.187
    assert (await get(q="chrome", version="117.0.1")).json()["total"] == 0                                          # исправленная версия не затронута
    assert (await get(q="chrome", version="abc")).status_code == 422
    assert (await get(version="1.0")).status_code == 422                                                           # версия без названия программы
    assert (await get(q="*chrom*", version="115.0.1")).json()["total"] == 1                                            # маска в названии работает и здесь


@pytest.mark.parametrize("text,want", [
    ("от 0.0.0 до 1.16.4", [{"start": "0.0.0", "start_incl": True, "end": "1.16.4", "end_incl": False}]),
    ("от 0.0.1 до 0.0.12 включительно", [{"start": "0.0.1", "start_incl": True, "end": "0.0.12", "end_incl": True}]),
    ("10.04 LTS", [{"exact": "10.04"}]),
    ("до 3.0.1", [{"end": "3.0.1", "end_incl": False}]),
    ("2.0 и более ранние", [{"end": "2.0", "end_incl": True}]),
    ("Server 10", [{"text": "Server 10"}]),                                  # непонятное остаётся текстом: «требуется уточнение», а не догадка
])
def test_bdu_version_phrases_from_real_export(text, want):
    from app.vdb.parsers import _bdu_versions  # noqa: PLC0415

    assert _bdu_versions(text) == want


async def test_restart_clears_running_status_and_orphan_generations(app):
    await init(app)
    sync = make_sync(app, lambda r: httpx.Response(200, json=KEV))
    assert await sync.run_source("kev", "manual")
    async with app.state.session_maker() as db:
        s = await db.get(VdbSource, "kev")
        active = s.active_generation
        s.status = "running"                                                    # служба перезапущена посреди загрузки
        await store.save_batch(db, active + 5, [store.Rec(source="kev", ext_id="CVE-2000-0001", vuln_key="CVE-2000-0001", title="недозагружено")])
        await db.commit()
    assert await sync.recover_interrupted() == 1
    s = await src(app, "kev")
    assert s.status == "error" and "прервана" in s.last_error and s.records == 4 and await count(app, "kev") == 4
    async with app.state.session_maker() as db:
        left = (await db.execute(select(func.count()).select_from(VdbRecord).where(VdbRecord.source == "kev", VdbRecord.generation == active + 5))).scalar_one()
        assert left == 0


async def test_low_disk_space_stops_scheduled_load_with_clear_message(app, monkeypatch):
    from app.vdb import sync as sync_mod  # noqa: PLC0415

    await init(app)
    called = []
    monkeypatch.setattr(sync_mod.shutil, "disk_usage", lambda p: type("U", (), {"free": 100 << 20, "total": 1 << 40, "used": 0})())
    assert not await make_sync(app, lambda r: called.append(1) or httpx.Response(200, json=KEV)).run_source("kev", "schedule")
    s = await src(app, "kev")
    assert s.status == "error" and "Недостаточно места" in s.last_error and not called


async def test_big_sources_do_not_keep_previous_copy_but_kev_does(app, tmp_path):
    await init(app)
    f = tmp_path / "up.zip"
    f.write_bytes(bdu_zip())
    sync = make_sync(app, lambda r: httpx.Response(200, json=KEV))
    for _ in range(3):
        assert await sync.run_source("bdu", "file", file=f) and await sync.run_source("kev", "manual")
    async with app.state.session_maker() as db:
        gens = {k: sorted((await db.execute(select(VdbRecord.generation).where(VdbRecord.source == k).distinct())).scalars().all()) for k in ("bdu", "kev")}
        bdu, kev = await db.get(VdbSource, "bdu"), await db.get(VdbSource, "kev")
    assert gens["bdu"] == [bdu.active_generation] and bdu.prev_generation is None            # одна копия: диск не растёт при каждом обновлении
    assert len(gens["kev"]) == 2 and kev.prev_generation is not None                         # KEV крошечный: предыдущая копия хранится для отката


async def test_withdrawn_records_are_removed_on_update(app):
    await init(app, nvd={"years_back": 1})
    mode = {"rejected": False}

    def handler(r):
        u = str(r.url)
        if "/feeds/json/cve/2.0/" in u:
            doc = json.loads(json.dumps(NVD))
            if mode["rejected"] and u.endswith("modified.json.gz") or (mode["rejected"] and u.endswith("modified.meta")):
                doc["vulnerabilities"] = [{"cve": {"id": "CVE-2024-3094", "vulnStatus": "Rejected", "descriptions": []}}]
            return nvd_feed(u, doc)
        return httpx.Response(200, json={"vulnerabilities": []})
    sync = make_sync(app, handler)
    assert await sync.run_source("nvd", "manual") and await count(app, "nvd") == 3
    mode["rejected"] = True
    assert await sync.run_source("nvd", "manual")
    assert await count(app, "nvd") == 2
    async with app.state.session_maker() as db:
        assert (await db.get(VdbVuln, "CVE-2024-3094")) is None            # отозванная запись пропала и из сводки


async def test_sync_all_and_storage_info(app, client):
    await init(app)
    await login(client, "admin", "Admin-Passw0rd-123")
    await client.put("/api/v1/vdb/sources/nvd", json={"enabled": True})
    r = (await client.post("/api/v1/vdb/sync-all")).json()
    assert "nvd" in r["queued"] and "kev" in r["queued"] and "bdu" not in r["queued"]          # только включённые
    st = (await client.get("/api/v1/vdb/sources")).json()["storage"]
    assert st["free_bytes"] > 0 and st["tmp_bytes"] == 0 and "db_bytes" in st
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.post("/api/v1/vdb/sync-all")).status_code == 403
