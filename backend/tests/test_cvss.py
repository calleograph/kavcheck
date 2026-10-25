"""Оценки CVSS: разбор нескольких оценок и выбор основной, уровни по баллу, хранение и повторное получение без дублей, API списка (сортировка, диапазоны, «нет данных») и карточки."""
import httpx
import pytest
from sqlalchemy import func, select

from app.models import VdbRecord, VdbSource, VdbVuln, utcnow
from app.vdb import parsers, store
from app.vdb.fetch import Http
from app.vdb.normalize import Rec, make_score, pick_primary, sev_from_score
from app.vdb.sync import VdbSync
from tests.conftest import login
from tests.vdbmock import nvd_feed

V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V2 = "AV:N/AC:L/Au:N/C:P/I:P/A:P"


def metric(ver: str, score, vector: str, source="nvd-analyst.example", typ="Primary") -> dict:
    return {"source": source, "type": typ, "cvssData": {"version": ver, "vectorString": vector, "baseScore": score}}


def nvd_item(cid: str, metrics: dict | None = None, modified="2024-05-01T00:00:00.000") -> dict:
    return {"cve": {"id": cid, "vulnStatus": "Analyzed", "published": "2024-01-01T00:00:00.000", "lastModified": modified, "descriptions": [{"lang": "en", "value": f"Описание {cid}"}],
                    "metrics": metrics or {}, "references": []}}


# ------------------------------------------------------------------------------------------------ уровни и выбор основной оценки
@pytest.mark.parametrize("version", ["3.0", "3.1", "4.0"])
@pytest.mark.parametrize("score,level", [(0.0, "none"), (0.1, "low"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"), (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10.0, "critical")])
def test_levels_by_score(version, score, level):
    assert sev_from_score(score, version) == level


def test_cvss2_levels_have_no_critical_and_no_score_is_not_zero():
    assert [sev_from_score(s, "2.0") for s in (3.9, 4.0, 6.9, 7.0, 10.0)] == ["low", "medium", "medium", "high", "high"]
    assert sev_from_score(None) == "" and make_score("3.1", None, source="nvd") is None


@pytest.mark.parametrize("bad", [None, "", "abc", -0.1, 10.1, float("nan")])
def test_unreliable_scores_are_dropped(bad):
    assert make_score("3.1", bad, V31, source="nvd") is None


def test_unknown_methodology_is_dropped():
    assert make_score("5.0", 7.0, "", source="nvd") is None and make_score("", 7.0, "", source="nvd") is None


def test_nvd_keeps_every_score_and_picks_by_documented_order():
    metrics = {"cvssMetricV2": [metric("2.0", 7.5, V2)], "cvssMetricV30": [metric("3.0", 7.0, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L")],
               "cvssMetricV31": [metric("3.1", 9.8, V31, "cna@vendor.example", "Secondary"), metric("3.1", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N")]}
    r = parsers.parse_nvd(nvd_item("CVE-2099-1001", metrics))
    assert len(r.scores) == 4
    assert (r.score, r.severity, r.vector[:8]) == (6.5, "medium", "CVSS:3.1")             # 3.1: оценка самого NVD (primary) раньше оценки поставщика
    assert {(s["version"], s["score"], s["kind"]) for s in r.scores} >= {("3.1", 9.8, "secondary"), ("2.0", 7.5, "primary"), ("3.0", 7.0, "primary")}
    metrics["cvssMetricV40"] = [metric("4.0", 5.0, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", "cna@vendor.example", "Secondary")]
    r4 = parsers.parse_nvd(nvd_item("CVE-2099-1001", metrics))
    assert len(r4.scores) == 5 and (r4.score, r4.severity) == (6.5, "medium")                          # оценка поставщика по 4.0 не вытесняет оценку аналитиков NVD по 3.1
    both = [make_score("4.0", 5.0, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", source="nvd", kind="primary"), make_score("3.1", 9.8, V31, source="nvd", kind="primary")]
    assert pick_primary(both)["version"] == "4.0"                                                       # из равных (обе primary) побеждает более новая методика
    old = [make_score("2.0", 10.0, V2, source="nvd", kind="primary"), make_score("3.1", 4.0, V31, source="nvd", kind="secondary")]
    assert pick_primary(old)["version"] == "3.1" and pick_primary(old[:1])["version"] == "2.0"           # CVSS 2.0 — только если других оценок нет


def test_cve_without_metrics_has_no_score_not_zero():
    r = parsers.parse_nvd(nvd_item("CVE-2099-1002"))
    assert r.score is None and r.scores == [] and r.severity == ""


def test_zero_score_is_none_level_not_missing():
    r = parsers.parse_nvd(nvd_item("CVE-2099-1003", {"cvssMetricV31": [metric("3.1", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")]}))
    assert r.score == 0.0 and r.severity == "none"


def test_bdu_has_both_methodologies():
    import io
    xml = ('<?xml version="1.0"?><vulnerabilities><vul><identifier>BDU:2099-00001</identifier><name>t</name><severity>Высокий уровень опасности</severity>'
           '<cvss><vector score="7.5">AV:N/AC:L/Au:N/C:P/I:P/A:P</vector></cvss><cvss3><vector score="9.8">AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</vector></cvss3></vul></vulnerabilities>').encode()
    r = next(parsers.parse_bdu(io.BytesIO(xml)))
    assert {(s["version"], s["score"]) for s in r.scores} == {("3.0", 9.8), ("2.0", 7.5)} and (r.score, r.severity) == (9.8, "critical")


# ------------------------------------------------------------------------------------------------ хранение и API
async def _seed(app, items: dict[str, dict | None]) -> None:
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        recs = [parsers.parse_nvd(nvd_item(k, m)) for k, m in items.items()]
        await store.save_batch(db, 1, recs)
        await store.refresh_vulns(db, set(items))
        await db.commit()


SEED = {
    "CVE-2099-0001": {"cvssMetricV31": [metric("3.1", 3.1, "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")]},
    "CVE-2099-0002": {"cvssMetricV31": [metric("3.1", 5.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H")]},
    "CVE-2099-0003": {"cvssMetricV31": [metric("3.1", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")]},
    "CVE-2099-0004": {"cvssMetricV31": [metric("3.1", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")]},
    "CVE-2099-0005": {"cvssMetricV2": [metric("2.0", 9.3, "AV:N/AC:M/Au:N/C:C/I:C/A:C")], "cvssMetricV30": [metric("3.0", 8.8, "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")]},
    "CVE-2099-0006": None,
    "CVE-2099-0007": {"cvssMetricV31": [metric("3.1", 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")]},
}


async def test_list_sort_filter_and_no_data(app, client):
    await _seed(app, SEED)
    await login(client, "admin", "Admin-Passw0rd-123")
    get = lambda **p: client.get("/api/v1/vdb/vulns", params=p)      # noqa: E731
    keys = lambda r: [i["key"][-4:] for i in r.json()["items"]]     # noqa: E731
    assert keys(await get(sort="score", desc="true")) == ["0004", "0005", "0003", "0002", "0001", "0007", "0006"]        # по убыванию; без оценки — в конце
    assert keys(await get(sort="score", desc="false")) == ["0007", "0001", "0002", "0003", "0005", "0004", "0006"]       # по возрастанию; без оценки всё равно в конце
    assert keys(await get(sort="score", score_min=9, score_max=10)) == ["0004"]
    assert keys(await get(sort="score", score_min=7, score_max=8.9)) == ["0005", "0003"]                                   # границы включены, 9.0 и выше не попадает
    assert keys(await get(sort="score", score_min=0.1, score_max=3.9)) == ["0001"]
    assert sorted(keys(await get(no_score=True))) == ["0006"]
    assert keys(await get(score_min=0, score_max=0)) == ["0007"]                                                           # 0.0 — это оценка None, а не «нет данных»
    assert (await get(score_min=11)).status_code == 422 and (await get(score_max=-1)).status_code == 422
    assert sorted(keys(await get(min_severity="critical"))) == ["0004"] and sorted(keys(await get(min_severity="high"))) == ["0003", "0004", "0005"]
    items = {i["key"][-4:]: i for i in (await get()).json()["items"]}
    assert (items["0005"]["score"], items["0005"]["score_version"], items["0005"]["score_source"], items["0005"]["severity"]) == (8.8, "3.0", "nvd", "high")    # 3.0 важнее 2.0 (9.3)
    assert (items["0004"]["severity"], items["0004"]["severity_basis"]) == ("critical", "cvss")
    assert (items["0006"]["score"], items["0006"]["severity"], items["0006"]["severity_ru"]) == (None, "", "Нет данных")
    assert (items["0007"]["score"], items["0007"]["severity"]) == (0.0, "none")
    # поиск по маске не ломает фильтры
    assert sorted(keys(await get(q="CVE-2099-000*", score_min=7))) == ["0003", "0004", "0005"] and keys(await get(q="*0004", score_min=9)) == ["0004"]


async def test_card_shows_primary_all_scores_origin_and_link(app, client):
    await _seed(app, SEED | {"CVE-2099-0008": {"cvssMetricV31": [metric("3.1", 9.8, V31, "cna@vendor.example", "Secondary"), metric("3.1", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N")],
                                               "cvssMetricV2": [metric("2.0", 7.5, V2)]}})
    await login(client, "admin", "Admin-Passw0rd-123")
    c = (await client.get("/api/v1/vdb/vulns/CVE-2099-0008")).json()
    p = c["cvss"]["primary"]
    assert (p["score"], p["version"], p["severity"], p["origin_label"], p["source_title"]) == (6.5, "3.1", "medium", "NVD (NIST)", "NVD (NIST)")
    assert p["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2099-0008" and p["updated"].startswith("2024-05-01")
    assert [(s["version"], s["score"], s["primary"]) for s in c["cvss"]["all"]] == [("3.1", 6.5, True), ("3.1", 9.8, False), ("2.0", 7.5, False)]
    assert c["cvss"]["all"][1]["origin_label"].startswith("CNA: cna@vendor.example")
    none = (await client.get("/api/v1/vdb/vulns/CVE-2099-0006")).json()
    assert none["cvss"] is None and none["score"] is None


# ------------------------------------------------------------------------------------------------ прежние записи и повторное получение
async def test_upgrade_converts_legacy_scores_once(app):
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        legacy = lambda ext, **kw: Rec(source="nvd", ext_id=ext, vuln_key=ext, title="t", **kw)    # noqa: E731
        await store.save_batch(db, 1, [legacy("CVE-2098-1", score=8.8, severity="high", vector=V31), legacy("CVE-2098-2", score=7.5, severity="high", vector=V2),
                                       legacy("CVE-2098-3", score=5.0, severity="medium", vector="")])
        await db.flush()
        for r in (await db.execute(select(VdbRecord))).scalars().all():
            r.scores, r.scores_at = [], None                                  # как у записей, загруженных до появления списка оценок
        await db.commit()
        assert await store.upgrade_scores(db) == 3
        await db.commit()
        v = {x.vuln_key: x for x in (await db.execute(select(VdbVuln))).scalars().all()}
        assert (v["CVE-2098-1"].score, v["CVE-2098-1"].score_version) == (8.8, "3.1") and (v["CVE-2098-2"].score, v["CVE-2098-2"].score_version) == (7.5, "2.0")
        assert v["CVE-2098-3"].score is None                                    # версию методики определить нельзя — оценка недостоверна, число не показывается
        assert await store.upgrade_scores(db) == 0                               # повторный запуск ничего не меняет
        assert int((await db.execute(select(func.count()).select_from(VdbRecord))).scalar_one()) == 3


async def _count(app, ext_id: str) -> int:
    async with app.state.session_maker() as db:
        return int((await db.execute(select(func.count()).select_from(VdbRecord).where(VdbRecord.ext_id == ext_id))).scalar_one())


async def test_nvd_rescore_big_window_saves_only_known_records(app):
    from datetime import datetime, timezone  # noqa: PLC0415

    pub = datetime(2024, 1, 1, tzinfo=timezone.utc)
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        src = await db.get(VdbSource, "nvd")
        src.settings, src.cursor = {"history_days": 30}, {"last_mod": datetime.now(timezone.utc).isoformat(), "feed": "feeds", "years_from": 2024}
        src.records, src.last_ok_at = 12, utcnow()
        await store.save_batch(db, 1, [Rec(source="nvd", ext_id=f"CVE-2099-02{i:02d}", vuln_key=f"CVE-2099-02{i:02d}", title="t", published=pub) for i in range(12)])
        for r in (await db.execute(select(VdbRecord))).scalars().all():
            r.scores_at = None
        await db.commit()

    def handler(req: httpx.Request) -> httpx.Response:
        if "/feeds/json/cve/2.0/" in str(req.url):
            return nvd_feed(str(req.url), {"vulnerabilities": []})
        if "pubStartDate" in str(req.url):          # окно возвращает 12 известных записей и 3 чужие
            ids = [f"CVE-2099-02{i:02d}" for i in range(12)] + ["CVE-2099-9001", "CVE-2099-9002", "CVE-2099-9003"]
            return httpx.Response(200, json={"vulnerabilities": [nvd_item(i, {"cvssMetricV31": [metric("3.1", 7.5, V31)]}) for i in ids], "totalResults": len(ids)})
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})

    async def nosleep(_s):
        return None
    sync = VdbSync(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal,
                   http_factory=lambda key: Http(transport=httpx.MockTransport(handler), sleep=nosleep), sleep=nosleep)
    assert await sync.run_source("nvd", "manual")
    async with app.state.session_maker() as db:
        rows = (await db.execute(select(VdbRecord).where(VdbRecord.source == "nvd"))).scalars().all()
        assert len(rows) == 12 and all(r.scores and r.scores_at for r in rows)         # 12 известных обновлены, чужих трёх в базе нет


async def test_nvd_rescore_refetches_missing_scores_without_duplicates(app):
    from datetime import datetime, timezone  # noqa: PLC0415

    pub = datetime(2024, 1, 1, tzinfo=timezone.utc)
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
        src = await db.get(VdbSource, "nvd")
        src.settings, src.cursor = {"history_days": 30}, {"last_mod": datetime.now(timezone.utc).isoformat(), "feed": "feeds", "years_from": 2024}      # обычная загрузка по изменениям пуста: проверяем только повторное получение
        src.records, src.last_ok_at = 2, utcnow()
        await store.save_batch(db, 1, [Rec(source="nvd", ext_id="CVE-2099-0100", vuln_key="CVE-2099-0100", title="t", published=pub),
                                       Rec(source="nvd", ext_id="CVE-2099-0101", vuln_key="CVE-2099-0101", title="отозвана", published=pub)])
        for r in (await db.execute(select(VdbRecord))).scalars().all():
            r.scores_at = None
        await store.refresh_vulns(db, {"CVE-2099-0100", "CVE-2099-0101"})
        await db.commit()
        assert (await db.get(VdbVuln, "CVE-2099-0100")).score is None
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        if "/feeds/json/cve/2.0/" in str(req.url):
            return nvd_feed(str(req.url), {"vulnerabilities": []})
        if "cveId=CVE-2099-0100" in str(req.url):   # ждущих записей мало — запрос по одной CVE; отозванную (0101) NVD не отдаёт
            return httpx.Response(200, json={"vulnerabilities": [nvd_item("CVE-2099-0100", {"cvssMetricV31": [metric("3.1", 9.8, V31)]})], "totalResults": 1})
        if "pubStartDate" in str(req.url):          # окно по дате публикации: чужие CVE из окна в базу не попадают
            return httpx.Response(200, json={"vulnerabilities": [nvd_item("CVE-2099-7777", {"cvssMetricV31": [metric("3.1", 5.0, V31)]})], "totalResults": 1})
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})

    async def nosleep(_s):
        return None
    sync = VdbSync(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal,
                   http_factory=lambda key: Http(transport=httpx.MockTransport(handler), sleep=nosleep), sleep=nosleep)
    assert await sync.run_source("nvd", "manual")
    async with app.state.session_maker() as db:
        v = await db.get(VdbVuln, "CVE-2099-0100")
        assert (v.score, v.score_version, v.score_source, v.sev_rank) == (9.8, "3.1", "nvd", 4)
        assert (await db.get(VdbVuln, "CVE-2099-0101")).score is None            # нет оценки — «Нет данных», а не ноль
        rows = (await db.execute(select(VdbRecord).where(VdbRecord.ext_id.like("CVE-2099-010%")))).scalars().all()
        assert len(rows) == 2 and all(r.scores_at is not None for r in rows)          # дублей нет, отозванная запись помечена проверенной
        assert next(r for r in rows if r.ext_id.endswith("0100")).scores[0]["origin"] == "nvd-analyst.example"
    assert (await _count(app, "CVE-2099-7777")) == 0                                  # чужая CVE из окна не загружена
    n = len([c for c in calls if "cveId=" in c])
    assert n >= 1 and await sync.run_source("nvd", "manual")
    assert len([c for c in calls if "cveId=" in c]) == n                        # всё проверено: повторных запросов за оценками нет


async def test_kev_and_viewer_see_scores(app, client):
    await _seed(app, {"CVE-2099-0009": SEED["CVE-2099-0004"]})
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get("/api/v1/vdb/vulns", params={"sort": "score"})).json()["items"][0]["score"] == 10.0
