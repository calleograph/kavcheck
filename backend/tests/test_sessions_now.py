"""«Сейчас в системе»: только пользователи в ТЕКУЩЕМ списке вошедших KSC (bActual), а не «входившие когда-либо»; фильтры по пользователю и компьютеру; служебные скрыты; выгрузка."""
import uuid

import pytest
from openpyxl import load_workbook

from app.reports.runner import job_dir
from tests.test_audit_e2e import _run, _setup
from tests.test_ksc_live import HOST

live = pytest.mark.skipif(not HOST, reason="нет синтетической базы KSC (KSC_TEST_HOST)")


@live
async def test_sessions_now_shows_only_current_logons(client, app):
    sid, runner = await _setup(client, app)
    r = (await client.get("/api/v1/devices/sessions", params={"online": "false"})).json()
    got = {(x["login"].lower(), x["host"]) for x in r["items"]}
    assert ("petrova", "ws-001") in got and all(x["kind"] == "user" for x in r["items"])                       # служебные и системные скрыты
    assert r["sources"][0]["error"] == "" and "ТЕКУЩЕМ" in r["note"]
    from app.ksc import queries as q
    from app.models import KscSource
    async with app.state.session_maker() as db:
        src = await db.get(KscSource, uuid.UUID(sid))
    rows = await app.state.sources.client(src).run(q.USERS_VISITED, {"n": 100000, "after": 0}, max_rows=100000)
    past_only = {(r["login"] or "").lower() for r in rows if r["login"]} - {(r["login"] or "").lower() for r in rows if r["actual"]}
    assert past_only and not (past_only & {x[0] for x in got})                                                       # «входившие ранее» в «сейчас» не попадают
    one = (await client.get("/api/v1/devices/sessions", params={"q": "petr*", "online": "false"})).json()["items"]
    assert one and all("petr" in x["login"].lower() for x in one)
    assert (await client.get("/api/v1/devices/sessions", params={"q": "nobody-here", "online": "false"})).json()["items"] == []
    host = (await client.get("/api/v1/devices/sessions", params={"host": "ws-001", "online": "false", "show_service": "true"})).json()["items"]
    assert host and {x["host"] for x in host} == {"ws-001"} and any(x["kind"] != "user" for x in host)            # с показом служебных — видны и системные сеансы
    # выгрузка: предпросмотр и файл — тот же состав
    pv = (await client.post("/api/v1/quick/preview", json={"kind": "quick_sessions", "params": {"online_only": False}})).json()
    assert pv["total"] == len(r["items"]) and pv["doc"]["title"] == "Сейчас в системе"
    job = (await client.post("/api/v1/reports", json={"kind": "quick_sessions", "title": "", "params": {"online_only": False}, "source_ids": [sid]})).json()
    await _run(app, runner, job["id"])
    wb = load_workbook(job_dir(app.state.settings, uuid.UUID(job["id"])) / "report.xlsx", read_only=True)
    sheet = list(wb[wb.sheetnames[-1]].iter_rows(values_only=True)) if "Вошли сейчас" not in wb.sheetnames else list(wb["Вошли сейчас"].iter_rows(values_only=True))
    assert len(sheet) - 1 == len(r["items"])


async def test_service_sessions_ahead_of_users_do_not_hide_them(monkeypatch):
    """Служебные сеансы (SYSTEM, DWM-N…) отсеиваются после чтения: если их больше предела выдачи, пользователи всё равно находятся (чтение постраничное)."""
    from app.devices import sessions as SN

    data = [{"kind": "service"}] * 7 + [{"kind": "user"}] * 3

    class Client:
        async def run(self, _sql, params, max_rows):
            return data[params["offset"]:params["offset"] + params["limit"]]

    monkeypatch.setattr(SN, "CHUNK", 4)
    monkeypatch.setattr(SN, "row_out", lambda r, _g, _m: r)
    rows, more = await SN.fetch(Client(), top=2)
    assert rows == [{"kind": "user"}] * 2 and more
    rows, more = await SN.fetch(Client(), top=5)
    assert len(rows) == 3 and not more


def test_address_typed_as_user_still_filters():
    from app.devices import sessions as SN

    params: dict = {}
    sql = SN.where("192.0.2.10", "", online_only=False, params=params)
    assert "wstrSamAccountName LIKE" in sql and params
