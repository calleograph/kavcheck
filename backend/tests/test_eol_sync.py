"""Загрузка базы endoflife.date как источника подсистемы баз: условный запрос (ETag), записываются только изменившиеся продукты, при сбое остаётся прежняя копия."""
import copy
import json
from pathlib import Path

import httpx
from sqlalchemy import func, select

from app.models import EolProduct, EolRelease, VdbSource
from app.vdb import store
from app.vdb.fetch import Http
from app.vdb.sync import VdbSync

DOC = json.loads((Path(__file__).parent / "fixtures" / "eol_sample.json").read_text(encoding="utf-8"))


def make(app, state: dict):
    async def nosleep(_s):
        return None

    def handler(req: httpx.Request) -> httpx.Response:
        state["calls"] = state.get("calls", 0) + 1
        state["inm"] = req.headers.get("if-none-match", "")
        if state.get("fail"):
            return httpx.Response(503, text="maintenance")
        if state["inm"] == state["etag"]:
            return httpx.Response(304)
        return httpx.Response(200, json=state["doc"], headers={"etag": state["etag"]})
    return VdbSync(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal, http_factory=lambda key: Http(transport=httpx.MockTransport(handler), sleep=nosleep), sleep=nosleep)


async def counts(app):
    async with app.state.session_maker() as db:
        return (int((await db.execute(select(func.count()).select_from(EolProduct))).scalar_one()), int((await db.execute(select(func.count()).select_from(EolRelease))).scalar_one()),
                (await db.get(VdbSource, "eol")))


async def test_incremental_load_etag_changes_removals_and_failure_keeps_old_copy(app):
    async with app.state.session_maker() as db:
        await store.ensure_sources(db)
    st = {"doc": copy.deepcopy(DOC), "etag": '"v1"'}
    sync = make(app, st)
    assert await sync.run_source("eol", "manual")
    n, rel, src = await counts(app)
    assert n == len(DOC["result"]) and rel > 100 and src.status == "ok" and src.records == n and src.cursor["etag"] == '"v1"'
    # ничего не изменилось: условный запрос, 304, записей не затронуто
    assert await sync.run_source("eol", "schedule") and st["inm"] == '"v1"'
    # изменился один продукт и исчез другой: переписывается один, удаляется один
    st["doc"] = copy.deepcopy(DOC)
    st["doc"]["result"] = [p for p in st["doc"]["result"] if p["name"] != "mysql"]
    next(p for p in st["doc"]["result"] if p["name"] == "php")["label"] = "PHP (изм.)"
    st["etag"] = '"v2"'
    assert await sync.run_source("eol", "schedule")
    async with app.state.session_maker() as db:
        names = set((await db.execute(select(EolProduct.name))).scalars())
        php = await db.get(EolProduct, "php")
        src = await db.get(VdbSource, "eol")
    assert "mysql" not in names and php.label == "PHP (изм.)" and src.cursor["added"] == 0 and src.cursor["removed"] == 1 and src.records == n - 1
    # сайт недоступен: загрузка помечена ошибкой, прежняя копия остаётся и используется
    st["fail"] = True
    assert not await sync.run_source("eol", "schedule")
    n2, _rel2, src = await counts(app)
    assert n2 == n - 1 and src.status == "error" and src.last_error and src.last_ok_at
    # документ неверного формата тоже не портит копию
    st["fail"], st["doc"], st["etag"] = False, {"result": "это не список продуктов"}, '"v3"'
    assert not await sync.run_source("eol", "schedule")
    assert (await counts(app))[0] == n - 1
