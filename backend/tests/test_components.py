"""Реестр компонентов: состав сверяется с зависимостями и Dockerfile (обязательная процедура выпуска), статусы по совместимым веткам, отложенные решения, проверка версий без интернета и при сбое источников."""
import json
import re
from pathlib import Path

import httpx
import pytest

from app.models import CompCheck, PtEngine, utcnow
from app.services import components as C
from tests.conftest import login

ROOT = Path(__file__).resolve().parents[2]


def spec(**kw):
    return {"key": "x", "installed": "static", "verified": "1.0.0", "decision": {"status": "ok", "reason": "", "note": ""}, **kw}


def chk(latest="", error=""):
    return CompCheck(key="x", latest=latest, url="", error=error, checked_at=utcnow())


def test_registry_covers_requirements_and_dockerfile_and_versions_fit_bounds():
    """Новая зависимость или смена закреплённой версии без обновления реестра ломает CI: разработчик обязан рассмотреть каждый компонент."""
    reg = {c["key"]: c for c in C.load()["components"]}
    for line in (ROOT / "backend/requirements.txt").read_text().splitlines():
        line = line.split("#")[0].strip()
        m = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?(.*)", line)
        if not m or not line or line.startswith("-r"):
            continue
        pkg, bounds = m.group(1), m.group(3)
        if pkg == "tzdata":
            continue
        key = "py_" + pkg.lower().replace("-", "_")
        assert key in reg, f"{pkg} из requirements.txt отсутствует в реестре компонентов (backend/app/components.json)"
        v = reg[key]["verified"]
        for op, bound in re.findall(r"(>=|<)\s*([0-9][0-9.]*)", bounds):
            c = C.compare(v, bound)
            assert (c >= 0) if op == ">=" else (c < 0), f"{pkg}: проверенная версия {v} вне диапазона {bounds}"
    docker = (ROOT / "backend/Dockerfile").read_text()
    assert reg["nuclei"]["verified"] == re.search(r"ARG NUCLEI_VERSION=(\S+)", docker).group(1)
    assert reg["nuclei_templates"]["verified"] == re.search(r"ARG NUCLEI_TEMPLATES_VERSION=(\S+)", docker).group(1)
    pkg = json.loads((ROOT / "frontend/package.json").read_text())
    for name in {**pkg["dependencies"], **pkg["devDependencies"]}:
        if not name.startswith("@types/") and name != "@vitejs/plugin-react":
            assert "npm_" + name.replace("@", "").replace("/", "_").replace("-", "_") in reg, f"{name} отсутствует в реестре компонентов"


def test_release_review_is_recorded_for_current_version():
    v = (ROOT / "VERSION").read_text().strip()
    reg = C.load()
    assert re.fullmatch(r"\d+\.\d+\.\d+", reg["reviewed_for"]) and C.compare(reg["reviewed_for"], v) >= 0     # реестр рассмотрен для текущего или следующего выпуска
    for c in reg["components"]:
        assert c["release_notes"].startswith("https://") and "utm_" not in c["release_notes"] and "?" not in c["release_notes"].replace("?activeTab=versions", "")      # официальные страницы без трекинга
        if c["decision"]["status"] == "deferred":
            assert c["decision"]["reason"], f"{c['key']}: отложенное обновление без причины"


def test_status_rules_branches_stable_deferred_and_unavailable():
    assert C.status_of(spec(), "1.0.0", chk("1.0.0"))[0] == "current"
    assert C.status_of(spec(), "1.0.0", chk("1.0.3"))[0] == "update"                                         # тот же основной выпуск — обновление
    assert C.status_of(spec(), "1.0.0", chk("2.0.0"))[0] == "review"                                         # новая основная версия — не «устарел», а «требует проверки»
    d = spec(decision={"status": "deferred", "reason": "несовместимое API", "note": ""})
    assert C.status_of(d, "1.0.0", chk("2.0.0")) == ("deferred", "несовместимое API")
    assert C.status_of(d, "1.0.0", chk("1.0.0"))[0] == "current"                                             # отложено только то, что есть
    assert C.status_of(spec(decision={"status": "incompatible", "reason": "r", "note": ""}), "1.0.0", chk("1.0.1"))[0] == "incompatible"
    assert C.status_of(spec(), None, chk("1.0.1"))[0] == "unknown"
    assert C.status_of(spec(), "1.0.0", None)[0] == "unavailable" and C.status_of(spec(), "1.0.0", chk("", "ConnectError"))[1] == "ConnectError"
    pg = spec(branch="16", decision={"status": "deferred", "reason": "основная версия", "note": ""})
    assert C.status_of(pg, "16.4", chk("16.15"))[0] == "deferred" and C.status_of(spec(branch="16"), "16.4", chk("16.15"))[0] == "update"     # внутри ветки — обычное обновление
    assert C.status_of(pg, "16.15", chk("16.15"))[0] == "current"


async def test_check_all_survives_unreachable_sources_and_keeps_previous_value(app, monkeypatch):
    sm = app.state.session_maker
    async with sm() as db:
        db.add(CompCheck(key="py_fastapi", latest="0.100.0", checked_at=utcnow()))
        await db.commit()

    async def boom(client, spec):
        raise httpx.ConnectError("нет сети")
    monkeypatch.setattr(C, "fetch_latest", boom)
    res = await C.check_all(sm)
    assert res["ok"] == 0 and res["failed"] > 5
    async with sm() as db:
        row = await db.get(CompCheck, "py_fastapi")
        assert row.latest == "0.100.0" and "ConnectError" in row.error and row.checked_at is not None          # найденная ранее версия сохранена, причина видна
        t = await C.table(db, app.state.settings)
    assert next(r for r in t["items"] if r["key"] == "py_fastapi")["check_error"].startswith("ConnectError")
    assert next(r for r in t["items"] if r["key"] == "py_httpx")["status"] == "unavailable"                  # без доступа в интернет: «проверка недоступна», а не «устарел»


async def test_check_all_stores_fetched_versions(app, monkeypatch):
    async def ok(client, spec):
        return {"latest": "9.9.9", "url": "https://example.org/r", "published_at": "2026-10-01T00:00:00Z" if spec["key"] != "postgresql" else "2026-08-10"}      # endoflife.date — только дата
    monkeypatch.setattr(C, "fetch_latest", ok)
    res = await C.check_all(app.state.session_maker)
    assert res["failed"] == 0 and res["ok"] >= 25
    async with app.state.session_maker() as db:
        t = await C.table(db, app.state.settings)
    r = next(x for x in t["items"] if x["key"] == "py_fastapi")
    assert next(x for x in t["items"] if x["key"] == "postgresql")["published_at"].tzinfo is not None
    assert r["latest"] == "9.9.9" and r["status"] == "review" and r["latest_url"] == "https://example.org/r" and r["published_at"].year == 2026


async def test_installed_versions_and_running_state(app):
    async with app.state.session_maker() as db:
        db.add(PtEngine(key="nuclei", version="3.11.1", templates_ver="10.5.1"))
        await db.commit()
        t = await C.table(db, app.state.settings)
    by = {r["key"]: r for r in t["items"]}
    assert by["backend"]["running"] is True and by["nuclei"]["installed"] == "3.11.1" and by["nuclei"]["running"] is True and by["nuclei_templates"]["installed"] == "10.5.1"
    assert by["py_fastapi"]["installed"] and by["py_fastapi"]["running"] is None and by["worker"]["running"] is False       # пульса worker в тесте нет
    assert by["nginx"]["installed"] == "1.27"                                                                  # версия, зафиксированная в образе, — из реестра


async def test_api_admin_only_and_pentest_tools_block(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    t = (await client.get("/api/v1/admin/components")).json()
    assert t["reviewed_for"] and len(t["items"]) >= 25 and set(t["counts"]) == set(C.STATUS_RU)
    one = (await client.get("/api/v1/admin/components/postgresql")).json()
    assert one["decision"]["status"] == "deferred" and one["decision"]["reason"] and one["release_notes"].startswith("https://www.postgresql.org")
    assert (await client.get("/api/v1/admin/components/nope")).status_code == 404
    assert (await client.post("/api/v1/admin/components/check")).status_code == 202 and (await client.get("/api/v1/admin/components")).json()["requested"]
    tools = (await client.get("/api/v1/pentest/overview")).json()["tools"]
    assert [x["key"] for x in tools] == ["nmap", "nse", "nuclei", "nuclei_templates"]
    await client.post("/api/v1/auth/logout")
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get("/api/v1/admin/components")).status_code == 403 and (await client.post("/api/v1/admin/components/check")).status_code == 403


@pytest.mark.parametrize("src,ref,expect", [("gh-tags", "nmap/nmap", None)])
def test_tag_selection_ignores_non_release_tags(src, ref, expect):
    import asyncio  # noqa: PLC0415

    class R:
        def __init__(self, data): self.data = data
        def raise_for_status(self): return self
        def json(self): return self.data

    class Cl:
        async def get(self, url): return R([{"name": "nightly"}, {"name": "v7.99"}, {"name": "v7.992"}, {"name": "v7.100-rc1"}])
    got = asyncio.run(C.fetch_latest(Cl(), {"source": f"{src}:{ref}"}))
    assert got["latest"] == "7.992"
