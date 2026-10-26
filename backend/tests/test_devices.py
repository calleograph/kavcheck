"""Устройства и пользователи: классификация учётных записей, накопление наблюдений (честные «сейчас», «последний», «7 суток»), единый поиск с масками и CIDR, права и «Все источники»."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.devices import users as U
from app.models import DeviceUser, DevicesState, KscSource, ZcHost, ZcHostZone, ZcSource
from app.netsearch import parse
from app.search import MaskError
from tests.conftest import login

MASKS = ["svc*", "*_svc", "krbtgt"]


class FakeUsers:
    """Отвечает на USERS_VISITED порциями по nId (как SQL Server: TOP (n) … WHERE nId > after)."""
    def __init__(self, rows: list[dict]):
        self.rows = sorted(rows, key=lambda r: r["row_id"])
        self.queries = []

    async def run(self, sql, params=None, *, max_rows=0):
        self.queries.append(sql)
        return [r for r in self.rows if r["row_id"] > int(params["after"])][: int(params["n"])]


def vrow(i, host, login, actual, upn="", sid="0xA1", user_id=1):
    return {"row_id": i, "host_id": host, "user_id": user_id if login else None, "actual": actual, "sid_hash": sid, "login": login, "upn": upn, "display_name": "", "local_host": None}


def test_accounts_are_classified_and_unresolved_ones_are_not_invented():
    c = lambda n, d="": U.classify(n, d, MASKS)  # noqa: E731
    assert c("ivanov") == "user" and c("SYSTEM") == "system" and c("DWM-1") == "system" and c("WS-001$") == "system" and c("root") == "system"
    assert c("svc_backup") == "service" and c("backup_svc") == "service" and c("KRBTGT") == "service" and c("petrova", "example.local") == "user"
    assert U.split_login("EXAMPLE\\ivanov", "") == ("ivanov", "example") and U.split_login("ivanov", "ivanov@example.local") == ("ivanov", "example.local")
    assert U.user_key("Ivanov", "0x01") == ("ivanov", True) and U.user_key("", "0xB7")[1] is False and U.user_key("", "0xB7")[0].startswith("h:")


def test_unified_search_parses_ip_cidr_ranges_masks_and_rejects_garbage():
    t = parse("ivanov, 192.0.2.0/30  192.0.2.10-20 192.0.* srv-*")
    assert [x.is_net for x in t] == [False, True, True, True, False] and (t[1].lo, t[1].hi) == (3221225984, 3221225987) and t[2].hi - t[2].lo == 10 and t[3].hi - t[3].lo == 65535
    assert parse("") == [] and parse("   ") == [] and parse("*") == [] and parse("srv-* *") == []
    for bad in ("10.1.2.300", "10.0.0.0/33", "10.1.2.9-10.1.2.1", " ".join(f"h{i}" for i in range(21))):
        with pytest.raises(MaskError):
            parse(bad)


async def _src(app, name="KSC-A"):
    sid = uuid.uuid4()
    async with app.state.session_maker() as db:
        db.add(KscSource(id=sid, name=name, host=f"{name.lower()}.example.local", port=1433, database="KAV", username="u", password_enc="x", is_active=True))
        await db.commit()
        return await db.get(KscSource, sid)


async def test_poll_accumulates_observations_and_never_invents_dates(app):
    sm = app.state.session_maker
    src = await _src(app)
    # первый опрос: ivanov в истории (дата входа неизвестна), petrova вошла сейчас, служебная и системная записи, запись без логина
    first = FakeUsers([vrow(1, 6, "petrova", True, "petrova@example.local", "0xA2", 2), vrow(2, 6, "ivanov", False, "ivanov@example.local", "0xA1", 1), vrow(3, 6, "DWM-1", True, "", "0xA4", 4),
                       vrow(4, 1, "svc_backup", True, "", "0xA3", 3), vrow(5, 3, "", False, "", "0xB7")])
    r1 = await U.poll_source(sm, first, src, MASKS)
    assert r1["initial"] and r1["rows"] == 5
    async with sm() as db:
        us = {(u.host_id, u.user_key): u for u in (await db.execute(select(DeviceUser))).scalars()}
        st = await db.get(DevicesState, src.id)
    assert us[(6, "petrova")].session_now and us[(6, "petrova")].last_session_at is not None and us[(6, "petrova")].kind == "user"
    assert us[(6, "ivanov")].initial and us[(6, "ivanov")].last_session_at is None and not us[(6, "ivanov")].session_now         # история без даты: даты не выдумываются
    assert us[(6, "dwm-1")].kind == "system" and us[(1, "svc_backup")].kind == "service"
    unresolved = next(u for k, u in us.items() if k[0] == 3)
    assert not unresolved.resolved and unresolved.login == "" and st.first_poll_at and st.polled_at
    # второй опрос: petrova вышла (осталась в истории), ivanov вошёл, появился новый пользователь sidorov (в истории)
    second = FakeUsers([vrow(1, 6, "petrova", False, "", "0xA2", 2), vrow(2, 6, "ivanov", True, "", "0xA1", 1), vrow(6, 6, "sidorov", False, "", "0xA5", 5)])
    r2 = await U.poll_source(sm, second, src, MASKS)
    assert not r2["initial"]
    async with sm() as db:
        us = {(u.host_id, u.user_key): u for u in (await db.execute(select(DeviceUser))).scalars()}
    assert not us[(6, "petrova")].session_now and us[(6, "petrova")].last_session_at is not None                  # «последний замеченный» сохраняется после выхода
    assert us[(6, "ivanov")].session_now and us[(6, "ivanov")].last_session_at is not None
    assert not us[(6, "sidorov")].initial and us[(6, "sidorov")].last_session_at is None                           # новый в истории: входил между опросами, но не «сейчас»
    assert not us[(1, "svc_backup")].session_now                                                                    # хост 1 больше не отдаёт запись — сеанс не считается идущим
    assert second.queries and all("hst_user_visited" in s for s in second.queries)
    from app.ksc import guard

    for s in second.queries:
        guard.check(s)


async def _zone_data(app, src, hosts):
    async with app.state.session_maker() as db:
        db.add(ZcSource(source_id=src.id, gen=1, status="ready"))
        for hid, name, ip, os_, active, zone in hosts:
            db.add(ZcHost(source_id=src.id, host_id=hid, gen=1, name=name, search=f"{name} {name}.example.local 192.0.2.{ip}".lower(), ip_num=3221225984 + ip, os=os_, active=active,
                          last_connected=datetime.now(timezone.utc) - timedelta(hours=ip), data={"ip": f"192.0.2.{ip}", "group": "Серверы", "zones": [zone]}))
            db.add(ZcHostZone(source_id=src.id, host_id=hid, gen=1, zone_id=zone))
        await db.commit()


async def test_devices_api_search_users_zone_and_all_sources(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    sm = app.state.session_maker
    a, b = await _src(app, "KSC-A"), await _src(app, "KSC-B")
    await _zone_data(app, a, [(6, "ws-001", 101, "Windows 11", True, "z1"), (7, "ws-002", 102, "Windows 10", True, "z2"), (8, "old-pc", 103, "Windows 7", False, "z1")])
    await _zone_data(app, b, [(6, "b-ws-001", 201 - 100 + 100, "Windows 11", True, "z1")])
    await U.poll_source(sm, FakeUsers([vrow(1, 6, "petrova", True, "", "0xA2", 2), vrow(2, 6, "ivanov", False, "", "0xA1", 1), vrow(3, 7, "svc_x", True, "", "0xA3", 3), vrow(4, 6, "DWM-1", True, "", "0xA4", 4)]), a, MASKS)
    h = {"X-Source-Id": str(a.id)}
    r = (await client.get("/api/v1/devices", headers=h)).json()
    assert r["total"] == 2 and [i["name"] for i in r["items"]] == ["ws-001", "ws-002"]                              # неактивный old-pc скрыт, как и в других разделах
    ws1 = r["items"][0]
    assert [u["login"] for u in ws1["current"]] == ["petrova"] and ws1["last_user"]["login"] == "petrova" and [u["login"] for u in ws1["week"]] == ["petrova"]
    assert [u["login"] for u in ws1["history"]] == ["ivanov"] and ws1["history"][0]["last_session_at"] is None and "DWM-1" not in str(ws1)       # системная скрыта, история без дат
    shown = (await client.get("/api/v1/devices", params={"show_service": True}, headers=h)).json()["items"][0]["current"]
    assert {u["kind"] for u in shown} == {"user", "system"}                                                                         # по запросу показываются и системные записи

    async def names(**p):
        return [i["name"] for i in (await client.get("/api/v1/devices", params=p, headers=h)).json()["items"]]

    assert await names(q="192.0.2.100/31") == ["ws-001"] and await names(q="192.0.2.102/31") == ["ws-002"] and await names(q="192.0.2.96/29") == ["ws-001", "ws-002"]     # CIDR — диапазон чисел
    assert await names(q="192.0.2.101-102") == ["ws-001", "ws-002"] and await names(q="192.0.*") == ["ws-001", "ws-002"] and await names(q="192.1.*") == []
    assert await names(q="192.0.2.102 192.0.2.101") == ["ws-001", "ws-002"]                                                      # несколько адресов — подходит любой
    assert await names(q="petr*") == ["ws-001"]                                                                                      # поиск по логину
    assert await names(q="ws-00*") == ["ws-001", "ws-002"] and await names(q="*-001") == ["ws-001"]
    assert (await client.get("/api/v1/devices", params={"zone": "z2"}, headers=h)).json()["total"] == 1
    assert (await client.get("/api/v1/devices", params={"q": "10.0.0.0/99"}, headers=h)).status_code == 422
    allr = (await client.get("/api/v1/devices", headers={"X-Source-Id": "all"})).json()
    assert allr["total"] == 3 and {i["source"] for i in allr["items"]} == {"KSC-A", "KSC-B"} and allr["not_ready"] == []
    card = (await client.get(f"/api/v1/devices/{a.id}/6", headers=h)).json()
    assert card["name"] == "ws-001" and card["hidden_service"] == 1 and card["limits"]
    st = (await client.get("/api/v1/devices/status", headers=h)).json()
    assert st["items"][0]["polled_at"] and st["items"][0]["supported"]
    assert (await client.post("/api/v1/devices/poll", headers=h)).status_code == 202
    await client.post("/api/v1/auth/logout")
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.post("/api/v1/devices/poll", headers=h)).status_code == 403
