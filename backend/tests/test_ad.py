"""Просмотр Active Directory: фильтры поиска и защита от инъекций, карточки, группы (непосредственные / первичная / вложенные отдельно), участники, сопоставление с Exchange, кэш и права."""
import asyncio

import pytest

from app.ad import client as C
from app.ad import filters as F
from app.ad.service import AdService
from app.auth.ldap import LdapConfig, LdapError
from tests.ad_fake import BASE, Dir, group, user
from tests.conftest import login
from tests.hier_data import DOMAIN
from tests.test_hier import upload, users as mk_users

CFG = LdapConfig(name="Домен", host="dc.example.local", base_dn=BASE, user_filter="(&(objectCategory=person)(objectClass=user))")


def build():
    g_all = f"CN=Все сотрудники,OU=Groups,{BASE}"
    g_sup = f"CN=Support,OU=Groups,{BASE}"
    g_adm = f"CN=Admins,OU=Groups,{BASE}"
    ivan = user("Иван Иванов", "ivanov", f"ivanov@{DOMAIN}", "Служба поддержки", "Инженер", member_of=[g_sup], primary=513)
    petr = user("Пётр Петров", "petrov", f"petrov@{DOMAIN}", "Отдел продаж", "Менеджер", uac=514, member_of=[g_all])
    lock = user("Лев Замков", "zamkov", f"zamkov@{DOMAIN}", "Отдел продаж", uac=512, lockoutTime="133700000000000000", **{"msDS-User-Account-Control-Computed": "16"})
    dup1 = user("Дубль Первый", "dub1", f"same@{DOMAIN}")
    dup2 = user("Дубль Второй", "dub2", f"same@{DOMAIN}")
    ent = [ivan, petr, lock, dup1, dup2,
           user("Сервис поддержки", "support01", f"support@{DOMAIN}", "Support", "служебная"),
           group("Domain Users", 513, [], gtype=-2147483646, desc="Все пользователи домена"),
           group("Support", 2001, [ivan["dn"]], desc="Служба поддержки"),
           group("Все сотрудники", 2002, [petr["dn"], g_sup], gtype=-2147483640),
           group("Admins", 2003, [g_all], gtype=-2147483644)]
    ent[7]["attrs"]["memberOf"] = [g_all.encode()]          # Support входит в «Все сотрудники», та — в Admins
    ent[8]["attrs"]["memberOf"] = [g_adm.encode()]
    ivan["attrs"]["memberOf"] = [g_sup.encode()]
    return Dir(ent)


@pytest.fixture
def d(monkeypatch):
    dr = build()

    def fake(cfg, base, flt, attrs, scope="SUBTREE", max_n=500, time_limit=15, page=500):
        return dr.search(base, flt, attrs, scope, max_n)

    monkeypatch.setattr(C, "run_search", fake)
    monkeypatch.setattr(C, "read_dns", lambda cfg, dns, attrs: [x for dn in dns for x in dr.search(dn, "(objectClass=*)", attrs, "BASE", 1)[0]])
    return dr


# ------------------------------------------------------------------------------------------------ фильтры
def test_masks_and_fields(d):
    names = lambda q: [r["login"] for r in C.search_users(CFG, q, 100)[0]]                 # noqa: E731
    assert names("ivanov") == ["ivanov"] and names("ivan*") == ["ivanov"] and names("*ivanov*") == ["ivanov"]
    assert names(f"ivanov@*") == ["ivanov"]                                                 # по почте
    assert names("*support*") == ["support01"]   # подразделение «Служба поддержки» и логин
    assert names("Иван Иванов") == ["ivanov"] and names("инженер") == ["ivanov"]            # ФИО, должность без учёта регистра
    assert names("ivanov@corp.example.local") == ["ivanov"] and names(f"CN=Иван Иванов,OU=Users,{BASE}") == ["ivanov"]   # UPN и DN целиком
    assert names("prefix-not-found") == []


def test_wide_masks_and_injection_are_rejected_or_escaped(d):
    for bad in ("", "*", "a*", "**", "*a*"):
        with pytest.raises(F.AdQueryError):
            F.user_search_filter(bad, "(objectClass=user)")
    f = F.user_search_filter("x)(uid=*)(abc", "(objectClass=user)")
    assert "\\29" in f and "\\28" in f and "(uid=*)" not in f
    assert C.search_users(CFG, "*)(objectClass=*", 100)[0] == []                            # скобки — обычные символы
    rows, trunc = C.search_users(CFG, "*example*", 1)                                            # предел выдачи
    assert len(rows) == 1 and trunc


# ------------------------------------------------------------------------------------------------ карточка
def test_user_card_state_attributes_and_secrets(d):
    ref = C.search_users(CFG, "petrov", 5)[0][0]["ref"]
    card = C.user_card(CFG, ref)
    assert card["state"]["disabled"] and not card["state"]["locked"] and card["state"]["pwd_last_set"].startswith("2024-09") and card["state"]["expires"] is None
    assert card["main"]["login"] == "petrov" and card["main"]["department"] == "Отдел продаж" and card["state"]["created"].startswith("2024-03-01")
    names = {a["name"].lower() for a in card["attributes"]}
    assert "userpassword" not in names and "unicodepwd" not in names and card["hidden_n"] == 2 and "pwdlastset" in names     # секреты скрыты, дата смены пароля видна
    assert "SECRET" not in str(card) and "objectguid" in names
    locked = C.user_card(CFG, C.search_users(CFG, "zamkov", 5)[0][0]["ref"])
    assert locked["state"]["locked"] and not locked["state"]["disabled"]


def test_ref_roundtrip_by_guid_and_dn(d):
    row = C.search_users(CFG, "ivanov", 5)[0][0]
    assert C.user_card(CFG, row["ref"])["dn"] == row["dn"]
    assert C.user_card(CFG, "d:" + F.b64(row["dn"]))["guid"] == row["ref"]
    with pytest.raises(LdapError):
        C.user_card(CFG, "00000000-0000-0000-0000-000000000000")
    with pytest.raises(F.AdQueryError):
        C.user_card(CFG, "not-a-guid")
    with pytest.raises(F.AdQueryError):
        C.user_card(CFG, "d:" + F.b64("CN=Чужой,DC=other,DC=local"))                    # вне Base DN


# ------------------------------------------------------------------------------------------------ группы
def test_direct_primary_and_nested_membership_are_separate(d):
    ref = C.search_users(CFG, "ivanov", 5)[0][0]["ref"]
    g = C.user_groups(CFG, ref)
    assert [x["cn"] for x in g["direct"]] == ["Support"] and g["primary"]["cn"] == "Domain Users" and g["direct_basis"] == "атрибут memberOf"
    assert g["direct"][0]["type"] == "Безопасности" and g["direct"][0]["scope"] == "Глобальная"
    n = C.nested_groups(CFG, ref)
    assert {x["cn"] for x in n["items"]} == {"Support", "Все сотрудники", "Admins", "Domain Users"} and "tokenGroups" in n["method"]


def test_group_card_members_and_directory_without_memberof(d):
    g = C.search_groups(CFG, "support", 10)[0][0]
    card = C.group_card(CFG, g["ref"])
    assert card["main"]["description"] == "Служба поддержки" and "member_dns" in card
    got = C.group_members(CFG, g["ref"], 100)
    assert [m["login"] for m in got["items"]] == ["ivanov"] and got["basis"] == "memberOf участников"
    allg = C.group_members(CFG, C.search_groups(CFG, "Все сотрудники", 5)[0][0]["ref"], 100)
    assert {m["kind"] for m in allg["items"]} == {"user", "group"}                           # участники — пользователи и вложенные группы
    # каталог без memberOf: участники берутся из member группы
    for x in d.e.values():
        x["attrs"]["memberOf"] = []                                                           # ldap3 возвращает пустой список, а не отсутствие атрибута
    got = C.group_members(CFG, g["ref"], 100)
    assert [m["login"] for m in got["items"]] == ["ivanov"] and got["basis"] == "атрибут member группы"
    assert C.user_groups(CFG, C.search_users(CFG, "ivanov", 5)[0][0]["ref"])["direct"][0]["cn"] == "Support"


# ------------------------------------------------------------------------------------------------ сопоставление с Exchange
def test_account_matching_never_by_name(d):
    assert C.find_accounts(CFG, f"ivanov@{DOMAIN}")["status"] == "exact"
    assert C.find_accounts(CFG, f"same@{DOMAIN}")["status"] == "multiple"
    only_login = C.find_accounts(CFG, "ivanov@other.example", "ivanov")
    assert only_login["status"] == "manual" and "логин" in only_login["basis"]
    assert C.find_accounts(CFG, "nobody@other.example", "nobody")["status"] == "none"
    assert C.find_accounts(CFG, "ivan.ivanov@other.example", "")["status"] == "none"          # совпадение ФИО в адресе — не основание


# ------------------------------------------------------------------------------------------------ служба
async def test_identical_concurrent_queries_run_once_and_cache_expires():
    svc = AdService(None, None)
    n = [0]

    def slow():
        import time
        n[0] += 1
        time.sleep(0.2)
        return n[0]

    res = await asyncio.gather(*(svc.call(("k",), 60, slow) for _ in range(8)))
    assert res == [1] * 8 and n[0] == 1                                                      # один запрос на всех
    assert await svc.call(("k",), 60, slow) == 1                                              # из кэша
    assert await svc.call(("k",), 60, slow, refresh=True) == 1                                # «Обновить» чаще раза в 5 с отдаёт кэш
    svc._cache[("k",)] = (0, 0, 1)                                                           # noqa: SLF001
    assert await svc.call(("k",), 60, slow) == 2
    boom = AdService(None, None)

    def fail():
        raise LdapError("server_unavailable")

    for _ in range(2):
        with pytest.raises(LdapError):
            await boom.call(("e",), 60, fail)                                                # ошибка не кэшируется


# ------------------------------------------------------------------------------------------------ API и права
async def setup(client, app, monkeypatch, d, roles=None):
    await mk_users(app)
    await login(client, "admin", "Admin-Passw0rd-123")
    await client.put("/api/v1/admin/settings/hier", json={"internal_domains": [DOMAIN], "roles": ["viewer", "analyst", "admin"], **({"ad_roles": roles} if roles else {})})

    async def cfg(db, c=None):
        return CFG

    monkeypatch.setattr(app.state.ad, "config", cfg)
    app.state.ad.forget()


async def test_api_search_card_groups_members_and_audit(client, app, monkeypatch, d):
    await setup(client, app, monkeypatch, d)
    r = await client.get("/api/v1/ad/users", params={"q": "ivan*"})
    assert r.status_code == 200 and [x["login"] for x in r.json()["items"]] == ["ivanov"] and r.json()["total"] == 1 and not r.json()["has_more"]
    assert (await client.get("/api/v1/ad/users", params={"q": "*"})).status_code == 422                       # слишком широкая маска
    ref = r.json()["items"][0]["ref"]
    card = (await client.get(f"/api/v1/ad/users/{ref}")).json()
    assert card["main"]["login"] == "ivanov" and "unicodepwd" not in str(card).lower() and card["exchange"]["status"] == "none"
    g = (await client.get(f"/api/v1/ad/users/{ref}/groups", params={"nested": True})).json()
    assert [x["cn"] for x in g["direct"]] == ["Support"] and g["primary"]["cn"] == "Domain Users" and {x["cn"] for x in g["nested"]["items"]} == {"Все сотрудники", "Admins"}
    gref = g["direct"][0]["ref"]
    assert (await client.get(f"/api/v1/ad/groups/{gref}")).json()["main"]["description"] == "Служба поддержки"
    assert [m["login"] for m in (await client.get(f"/api/v1/ad/groups/{gref}/members")).json()["items"]] == ["ivanov"]
    assert (await client.get("/api/v1/ad/status")).json()["ok"] in (True, False)
    from sqlalchemy import select
    from app.models import AuditLog
    async with app.state.session_maker() as db:
        acts = {a.action for a in (await db.execute(select(AuditLog))).scalars()}
    assert {"ad.search", "ad.open"} <= acts


async def test_api_exchange_link_both_ways_and_unavailable_directory(client, app, monkeypatch, d):
    await setup(client, app, monkeypatch, d)
    from tests.hier_data import demo_records
    rows = demo_records()
    rows[0]["Email"] = f"ivanov@{DOMAIN}"
    up = await upload(client, rows)
    assert up.status_code == 200
    data = (await client.get("/api/v1/hier/data")).json()
    pid = next(p[0] for p in data["people"] if p[2] == f"ivanov@{DOMAIN}")
    m = (await client.get(f"/api/v1/ad/match/{pid}")).json()
    assert m["status"] == "exact" and m["items"][0]["login"] == "ivanov"
    card = (await client.get(f"/api/v1/ad/users/{m['items'][0]['ref']}")).json()
    assert card["exchange"]["status"] == "linked" and card["exchange"]["person"]["id"] == pid        # обратный переход
    assert (await client.get("/api/v1/ad/match/0000000000")).status_code == 404

    def down(*a, **k):
        raise LdapError("server_unavailable", "ConnectError")

    monkeypatch.setattr(C, "run_search", down)
    app.state.ad.forget()
    r = await client.get("/api/v1/ad/users", params={"q": "ivanov"})
    assert r.status_code == 503 and "не отвечает" in r.json()["detail"]
    st = (await client.get("/api/v1/ad/status")).json()
    assert st["ok"] is False and "не отвечает" in st["message"]


async def test_ad_roles_are_enforced(client, app, monkeypatch, d):
    await setup(client, app, monkeypatch, d, roles=["admin"])
    assert (await client.get("/api/v1/ad/users", params={"q": "ivanov"})).status_code == 200
    assert (await client.get("/api/v1/hier/data")).json()["ad"] is True
    await login(client, "analyst1", "Analyst-Passw0rd-123")
    assert (await client.get("/api/v1/ad/users", params={"q": "ivanov"})).status_code == 403
    assert (await client.get("/api/v1/hier/data")).json()["ad"] is False
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get("/api/v1/ad/groups", params={"q": "support"})).status_code == 403


# ------------------------------------------------------------------------------------------------ отчёты
def report_dir(monkeypatch):
    from datetime import datetime, timedelta, timezone

    from app.ad import filters as FF

    dr = build()
    soon = FF.to_filetime(datetime.now(timezone.utc) + timedelta(days=10))
    far = FF.to_filetime(datetime.now(timezone.utc) + timedelta(days=400))
    for x in dr.e.values():
        if b"zamkov" in x["attrs"].get("sAMAccountName", [b""])[0]:
            x["attrs"]["accountExpires"] = [str(soon).encode()]
        if b"dub1" in x["attrs"].get("sAMAccountName", [b""])[0]:
            x["attrs"]["accountExpires"] = [str(far).encode()]
    monkeypatch.setattr(C, "run_search", lambda cfg, base, flt, attrs, scope="SUBTREE", max_n=500, time_limit=15, page=500: dr.search(base, flt, attrs, scope, max_n))
    return dr


async def test_ad_reports_views_filters_and_job_files(client, app, monkeypatch):
    report_dir(monkeypatch)
    await mk_users(app)
    await login(client, "admin", "Admin-Passw0rd-123")
    await client.put("/api/v1/admin/settings/hier", json={"internal_domains": [DOMAIN], "roles": ["viewer", "analyst", "admin"]})

    async def cfg(self, db, c=None):
        return CFG

    monkeypatch.setattr(AdService, "config", cfg)

    async def rows(view, **p):
        r = await client.post("/api/v1/quick/preview", json={"kind": "quick_ad", "params": {"view": view, **p}})
        assert r.status_code == 200, (view, r.text)
        return r.json()

    users = await rows("users")
    assert users["total"] == 6 and users["doc"]["title"] == "Пользователи Active Directory" and any("только чтение" in n for n in users["doc"]["notes"])
    assert {r["login"] for r in (await rows("users", q="*support*"))["items"]} == {"support01"}
    assert [r["login"] for r in (await rows("disabled"))["items"]] == ["petrov"]
    assert [r["login"] for r in (await rows("locked"))["items"]] == ["zamkov"]
    assert [r["login"] for r in (await rows("expiring", days=30))["items"]] == ["zamkov"]                  # через 10 суток — да, через 400 — нет
    mem = await rows("memberships")
    assert {(r["login"], r["group"]) for r in mem["items"]} == {("ivanov", "Support"), ("petrov", "Все сотрудники")} and any("первичная" in n.lower() for n in mem["doc"]["notes"])
    gref = C.search_groups(CFG, "support", 5)[0][0]["ref"]
    gm = await rows("group_members", group=gref)
    assert [r["login"] for r in gm["items"]] == ["ivanov"] and gm["items"][0]["method"] == "Непосредственный"
    allg = C.search_groups(CFG, "Admins", 5)[0][0]["ref"]
    assert (await rows("group_members", group=allg))["total"] == 1                                         # непосредственно — только вложенная группа
    assert (await client.post("/api/v1/quick/preview", json={"kind": "quick_ad", "params": {"view": "group_members"}})).status_code == 422      # группа не выбрана
    assert (await client.post("/api/v1/quick/preview", json={"kind": "quick_ad", "params": {"view": "users", "q": "*"}})).status_code == 422     # слишком широкая маска

    from tests.hier_data import demo_records

    assert (await upload(client, demo_records())).status_code == 200
    mm = await rows("mismatch")
    assert mm["total"] >= 1 and all(r["kind"] for r in mm["items"]) and any("по ФИО не используется" in n or "не используется" in n for n in mm["doc"]["notes"])

    made = await client.post("/api/v1/reports", json={"kind": "quick_ad", "params": {"view": "group_members", "group": gref}})
    assert made.status_code == 201
    from app.models import ReportJob
    from app.reports.runner import Runner
    import uuid
    rid = made.json()["id"]
    async with app.state.session_maker() as db:
        await Runner(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal)._execute_quick(await db.get(ReportJob, uuid.UUID(rid)))
    assert (await client.get(f"/api/v1/reports/{rid}")).json()["status"] == "done"
    csv = (await client.get(f"/api/v1/reports/{rid}/download/csv")).content.decode("utf-8-sig")
    assert "ivanov" in csv and "Как определено" in csv and "SECRET" not in csv
    for fmt, magic in (("xlsx", b"PK"), ("pdf", b"%PDF"), ("html", b"<!doctype")):
        assert (await client.get(f"/api/v1/reports/{rid}/download/{fmt}")).content[:len(magic)].lower() == magic.lower()
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.post("/api/v1/quick/preview", json={"kind": "quick_ad", "params": {"view": "users"}})).status_code == 403
    assert (await client.get(f"/api/v1/reports/{rid}")).status_code == 404                                  # viewer не видит отчёт с учётными записями


def test_values_accepts_ldap3_response_types():
    """ldap3 отдаёт raw_attributes как CaseInsensitiveDict, а не dict: с обычным dict в тестах это не видно."""
    from ldap3.utils.ciDict import CaseInsensitiveDict

    e = {"dn": "uid=a,dc=x", "raw_attributes": CaseInsensitiveDict({"displayName": [b"\xd0\x98\xd0\xb2\xd0\xb0\xd0\xbd"], "objectGUID": [b"\x01" * 16]}), "attributes": CaseInsensitiveDict({})}
    v = F.values(e)
    assert F.first(v, "DISPLAYNAME") == "Иван" and F.first(v, "objectGUID") == "01010101-0101-0101-0101-010101010101"
    assert C.user_row(e)["name"] == "Иван" and C.user_row(e)["ref"] == "01010101-0101-0101-0101-010101010101"


def test_other_directories_use_the_connection_login_attribute(monkeypatch):
    """Не AD (например, OpenLDAP): логин берётся из атрибута подключения, поиск идёт и по нему."""
    from tests.ad_fake import entry

    dr = Dir([entry(f"uid=user0265,ou=People,{BASE}", uid="user0265", cn="Олег Савин", mail=f"user0265@{DOMAIN}", objectClass=["inetOrgPerson"], objectCategory="person")])
    monkeypatch.setattr(C, "run_search", lambda cfg, base, flt, attrs, scope="SUBTREE", max_n=500, time_limit=15, page=500: dr.search(base, flt, attrs, scope, max_n))
    cfg = LdapConfig(name="LDAP", host="x", base_dn=BASE, login_attribute="uid", user_filter="(objectCategory=person)")
    rows, _t = C.search_users(cfg, "user02*", 10)
    assert [r["login"] for r in rows] == ["user0265"] and rows[0]["ref"].startswith("d:")            # без objectGUID идентификатор — DN
    assert C.user_card(cfg, rows[0]["ref"])["main"]["login"] == "user0265"
