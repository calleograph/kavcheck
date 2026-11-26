"""Аудит домена на синтетическом каталоге: категории (без вывода только по имени), сроки паролей по категориям, точный последний вход по контроллерам,
смена и сброс пароля по событиям 4723/4724 без ложных выводов при отсутствии журналов, снимки проверок, решения, перенос замечаний, отчёты и права. Все данные вымышленные."""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.ad import client as C
from app.ad import filters as F
from app.adaudit import checks as K
from app.adaudit import events as EV
from app.adaudit import service as AS
from app.auth.ldap import LdapConfig
from app.services.jobs import JOBS
from app.services.settings import AdAuditSettings
from tests.ad_fake import BASE, DOM_SID, Dir, entry, group, user
from tests.conftest import login

NOW = datetime(2026, 11, 19, 10, 0, tzinfo=timezone.utc)


def ft(d: datetime) -> str:
    return str(F.to_filetime(d))


def gt(d: datetime) -> str:
    return d.strftime("%Y%m%d%H%M%S.0Z")


def ago(n: int) -> datetime:
    return NOW - timedelta(days=n)


DN = lambda cn: f"CN={cn},OU=Users,{BASE}"      # noqa: E731
U = {
    "ivanova": dict(cn="Иванова Анна", pwd=20, llt=3, created=400),                                                   # обычная, всё в порядке
    "petrov": dict(cn="Петров Пётр", pwd=200, llt=200, created=900),                                                  # обычная: старый пароль, давно не входила (по llt), но DC знает свежий вход
    "adm.sidorov": dict(cn="Сидоров (адм.)", pwd=45, llt=2, created=300, uac=512 | 0x10000),                         # в Domain Admins: административная, бессрочный пароль, пароль старше 30 дн.
    "svc_backup": dict(cn="svc_backup", pwd=100, llt=1, created=800, uac=512 | 0x10000, servicePrincipalName="MSSQLSvc/db1.example.local", description="Служба резервного копирования"),
    "svc_old": dict(cn="svc_old", pwd=220, llt=1, created=800, uac=512 | 0x10000, servicePrincipalName="HTTP/app.example.local"),
    "svc_lonely": dict(cn="svc_lonely", pwd=10, llt=1, created=100),                                                  # только по имени похожа на сервисную — «не определено»
    "podr.kuzmin": dict(cn="Кузьмин (подрядчик)", pwd=10, llt=1, created=60, employeeType="contractor"),            # подрядчик без срока действия
    "new.user": dict(cn="Новый Сотрудник", pwd=None, llt=None, created=5),                                          # новая: пароль выдан, ещё не входила — без замечаний
    "stale.user": dict(cn="Давний Неактивный", pwd=None, llt=None, created=300),                                    # пароль не сменён, ни разу не входила
    "off.user": dict(cn="Уволенный", pwd=500, llt=500, created=900, uac=514),                                       # отключена
    "reset.me": dict(cn="Сброшенный Пароль", pwd=10, llt=9, created=500),                                           # последний — сброс администратором
    "changed.me": dict(cn="Сменивший Пароль", pwd=12, llt=1, created=500),                                         # сброс, затем смена пользователем
    "nolog.me": dict(cn="Без Журнала", pwd=40, llt=2, created=500),                                                 # пароль сменён в охваченный период, события нет
}
DC_LAST = {"dc1.corp.example.local": {"petrov": 5}, "dc2.corp.example.local": {"petrov": 30}}


def directory() -> Dir:
    ents = []
    for sam, x in U.items():
        extra = {k: v for k, v in x.items() if k not in ("cn", "pwd", "llt", "created", "uac")}
        ents.append(user(x["cn"], sam, f"{sam}@corp.example.local", uac=x.get("uac", 512), pwdLastSet=ft(ago(x["pwd"])) if x["pwd"] is not None else "0",
                         lastLogonTimestamp=ft(ago(x["llt"])) if x["llt"] is not None else "", whenCreated=gt(ago(x["created"])), **extra))
    ents.append(group("Domain Admins", 512, [DN("Сидоров (адм.)")]))
    ents.append(group("Protected Users", 525, []))
    ents.append(group("Backup Operators", 551, []))
    ents.append(entry(f"CN=Administrators,CN=Builtin,{BASE}", cn="Administrators", objectClass=["top", "group"], objectSid=F.sid_bytes("S-1-5-32-544"), member=[f"CN=Domain Admins,OU=Groups,{BASE}"]))
    for dc in DC_LAST:
        ents.append(entry(f"CN={dc.split('.')[0].upper()},OU=Domain Controllers,{BASE}", cn=dc.split(".")[0].upper(), objectClass=["top", "computer"], objectCategory="computer",
                          userAccountControl="532480", dNSHostName=dc))
    return Dir(ents)


@pytest.fixture()
def dirfake(monkeypatch):
    dr = directory()

    def fake(cfg, base, flt, attrs, scope="SUBTREE", max_n=500, time_limit=15, page=500):
        got, trunc = dr.search(base, flt, attrs, scope, max_n)
        if "lastLogon" in attrs and cfg.host in DC_LAST:              # lastLogon у каждого контроллера свой
            out = []
            for e in got:
                sam = dr.e[e["dn"].lower()]["attrs"]["sAMAccountName"][0].decode()
                d = DC_LAST[cfg.host].get(sam)
                out.append({**e, "raw_attributes": {**e["raw_attributes"], **({"lastLogon": [ft(ago(d)).encode()]} if d is not None else {})}})
            got = out
        return got, trunc
    monkeypatch.setattr(C, "run_search", fake)
    return dr


CFG = LdapConfig(id="c1", name="Домен", host="dc1.corp.example.local", base_dn=BASE, domain_dns="corp.example.local")


def events_doc(covered_dcs=("dc1.corp.example.local", "dc2.corp.example.local"), since=60) -> bytes:
    sid = lambda sam: F.sid_str(next(e for e in directory().e.values() if e["attrs"].get("sAMAccountName", [b""])[0].decode() == sam)["attrs"]["objectSid"][0])   # noqa: E731
    ev = [
        {"dc": "dc1.corp.example.local", "record_id": 1, "id": 4724, "time_utc": (ago(10) + timedelta(minutes=2)).isoformat(), "success": True, "target_user": "reset.me", "target_domain": "CORP",
         "target_sid": sid("reset.me"), "subject_user": "helpdesk1", "subject_domain": "CORP", "subject_sid": f"{DOM_SID}-9001"},
        {"dc": "dc2.corp.example.local", "record_id": 2, "id": 4724, "time_utc": ago(20).isoformat(), "success": True, "target_user": "changed.me", "target_domain": "CORP", "target_sid": sid("changed.me"),
         "subject_user": "helpdesk1", "subject_domain": "CORP"},
        {"dc": "dc1.corp.example.local", "record_id": 3, "id": 4723, "time_utc": ago(12).isoformat(), "success": True, "target_user": "changed.me", "target_domain": "CORP", "target_sid": sid("changed.me"),
         "subject_user": "changed.me", "subject_domain": "CORP"},
        {"dc": "dc1.corp.example.local", "record_id": 4, "id": 4724, "time_utc": ago(11).isoformat(), "success": False, "target_user": "ivanova", "target_domain": "CORP", "target_sid": sid("ivanova"),
         "subject_user": "intruder", "subject_domain": "CORP"},
    ]
    dcs = [{"name": d, "log_from": ago(since).isoformat(), "log_to": NOW.isoformat(), "error": ""} for d in covered_dcs]
    return json.dumps({"format": EV.FORMAT, "generated_at": NOW.isoformat(), "dcs": dcs, "events": ev}).encode()


# ------------------------------------------------------------------------------------------------ чистые функции
def test_category_is_not_decided_by_name_alone():
    rules = [K.Rule(r.category, r.kind, r.value) for r in AdAuditSettings().rules]
    base = {"groups": [], "special": [], "group_dns": [], "dn": DN("x"), "upn": "", "description": "", "attrs": {}, "privileged": [], "spn": False}
    assert K.classify({**base, "login": "svc_lonely"}, rules)[0] == "undefined"                                          # одно имя — не доказательство
    assert K.classify({**base, "login": "svc_backup", "spn": True}, rules)[0] == "service"                              # имя и SPN согласны
    assert K.classify({**base, "login": "x", "privileged": ["Domain Admins"]}, rules)[0] == "admin"
    assert K.classify({**base, "login": "x", "attrs": {"employeetype": ["contractor"]}}, rules)[0] == "contractor"
    both = [*rules, K.Rule("service", "ou", "OU=Users," + BASE)]
    cat, why = K.classify({**base, "login": "x", "privileged": ["Domain Admins"]}, both)
    assert cat == "undefined" and "противоречивые" in why[0]
    assert K.classify({**base, "login": "ivanova"}, rules)[0] == "user"
    assert K.classify({**base, "login": "svc_lonely"}, rules, {"category": "service", "note": "по служебной записке"}) == ("service", ["решение администратора: по служебной записке"])
    assert [K.bucket(x) for x in (0, 30, 31, 90, 91, 180, 181, None)] == ["le30", "le30", "le90", "le90", "le180", "le180", "gt180", "unknown"]


def test_ou_path_is_readable_container_path():
    assert F.ou_path(f"CN=Иванов\\, И.,OU=Бухгалтерия,OU=Офис,{BASE}") == "Офис/Бухгалтерия"
    assert F.ou_path(f"CN=svc,CN=Users,{BASE}") == "Users"
    assert F.ou_path(f"CN=root,{BASE}") == "" and F.ou_path("") == ""


def test_no_conclusion_about_password_method_without_logs():
    acc = {"pwd_last_set": ago(10)}
    reset = [{"kind": "reset", "success": True, "at": ago(10), "by": "CORP\\hd", "dc": "dc1"}]
    full = K.Coverage({"dc1": (ago(60), NOW), "dc2": (ago(60), NOW)}, ["dc1.corp.example.local", "dc2.corp.example.local"])
    assert K.last_pwd_op(acc, reset, full)["reset_pending"] is True
    assert K.last_pwd_op(acc, [], K.Coverage())["state"] == "no_logs"                                                       # журналы не загружены
    part = K.Coverage({"dc1": (ago(60), NOW)}, ["dc1.corp.example.local", "dc2.corp.example.local"])
    op = K.last_pwd_op(acc, [], part)
    assert op["state"] == "no_logs" and "dc2" in op["basis"]                                                               # журнала второго контроллера нет — вывода нет
    assert K.last_pwd_op({"pwd_last_set": ago(100)}, [], full)["state"] == "before_logs"
    assert K.last_pwd_op(acc, [], full)["state"] == "no_event"
    failed = [{"kind": "reset", "success": False, "at": ago(10), "by": "x", "dc": "dc1"}]
    assert K.last_pwd_op(acc, failed, full)["state"] == "no_event"                                                         # неуспешная попытка — не операция


def test_events_file_is_validated():
    with pytest.raises(EV.EventsError):
        EV.parse(b"not json")
    with pytest.raises(EV.EventsError):
        EV.parse(json.dumps({"format": "other"}).encode())
    p = EV.parse(events_doc())
    assert len(p["events"]) == 4 and {e["kind"] for e in p["events"]} == {"reset", "change"} and p["dcs"][0]["log_from"] is not None
    ps = '﻿' + json.dumps({"format": EV.FORMAT, "dcs": [{"name": "DC1"}], "events": [{"id": 4724, "time_utc": "/Date(1763546400000)/", "target_user": "a", "success": True, "dc": "DC1", "record_id": 7}]})
    p = EV.parse(ps.encode("utf-8"))
    assert p["events"][0]["at"].year == 2025 and p["dcs"][0]["name"] == "dc1"                                              # Windows PowerShell 5.1: BOM и /Date(…)/


# ------------------------------------------------------------------------------------------------ проверка целиком и API
async def _users(client):
    await login(client, "admin", "Admin-Passw0rd-123")
    for name, role in (("sec1", "security"), ("an1", "analyst")):
        await client.post("/api/v1/admin/users", json={"username": name, "password": "Sec-Passw0rd-1234", "role": role, "must_change_password": False})


async def _run(app, monkeypatch, now=NOW):
    sm = app.state.session_maker
    JOBS.configure(sm, ttl=60)
    svc = AS.AdAuditService(sm, app.state.settings, app.state.settings_svc, app.state.ldap)

    async def cfg(_c):
        return CFG
    monkeypatch.setattr(svc, "_ldap_cfg", cfg)
    return await svc.run("manual", "Тест", now=now)


async def test_full_audit_run_findings_decisions_reports_and_access(client, app, monkeypatch, dirfake):
    await _users(client)
    r = await client.post("/api/v1/adaudit/events/import", content=events_doc(), headers={"X-File-Name": "pwd.json"})
    assert r.status_code == 200 and r.json()["added"] == 4
    assert (await client.post("/api/v1/adaudit/events/import", content=events_doc())).json()["added"] == 0           # повторная загрузка не дублирует
    run = await _run(app, monkeypatch)
    assert run.status == "ok", run.message
    st = (await client.get("/api/v1/adaudit/state")).json()
    s = st["latest"]["stats"]
    assert s["accounts"] == len(U) - 1 and not s.get("disabled") and st["latest"]["coverage"]["dc_logon_ok"] == list(DC_LAST)
    accs = {a["login"]: a for a in (await client.get("/api/v1/adaudit/accounts", params={"limit": 100})).json()["items"]}
    assert accs["adm.sidorov"]["category"] == "admin" and accs["svc_backup"]["category"] == "service" and accs["svc_lonely"]["category"] == "undefined"
    assert accs["podr.kuzmin"]["category"] == "contractor"
    assert accs["petrov"]["last_logon_src"] == "dc" and accs["petrov"]["idle_days"] == 5                                    # lastLogon контроллера свежее lastLogonTimestamp
    assert accs["petrov"]["pwd_bucket"] == "gt180" and accs["stale.user"]["pwd_bucket"] == "unknown"
    assert accs["reset.me"]["pwd_op"]["state"] == "reset" and accs["changed.me"]["pwd_op"]["state"] == "change"
    assert accs["nolog.me"]["pwd_op"]["state"] == "no_event" and "off.user" not in accs
    all_accounts = (await client.get("/api/v1/adaudit/accounts", params={"include_inactive": True, "q": "off.user"})).json()["items"]
    assert all_accounts[0]["pwd_op"]["state"] == "before_logs"
    codes = {}
    for f in (await client.get("/api/v1/adaudit/findings", params={"limit": 500})).json()["items"]:
        codes.setdefault(f["login"], set()).add(f["code"])
    assert {"pne", "pwd_age", "not_protected"} <= codes["adm.sidorov"]
    assert "pne" in codes["svc_backup"] and "pwd_age" not in codes["svc_backup"]                                           # сервисная, 100 дн. < 180: исключение под вопросом, не нарушение срока
    sv = next(f for f in (await client.get("/api/v1/adaudit/findings", params={"q": "svc_backup", "code": "pne"})).json()["items"])
    assert sv["status"] == "review"
    assert {"pne", "service_no_owner"} <= codes["svc_old"] and next(f for f in (await client.get("/api/v1/adaudit/findings", params={"q": "svc_old", "code": "pne"})).json()["items"])["status"] == "violation"
    assert "pwd_age" in codes["petrov"] and "inactive" not in codes["petrov"]
    assert "undefined" in codes["svc_lonely"] and "no_expiry" in codes["podr.kuzmin"]
    assert "new.user" not in codes                                                                                        # новой учётной записи даётся срок
    assert {"pwd_not_set", "never_logon"} <= codes["stale.user"]
    assert "reset" in codes["reset.me"] and "reset" not in codes.get("changed.me", set()) and "reset" not in codes.get("ivanova", set())   # неуспешный сброс — не операция
    assert codes.get("off.user", set()) == set()                                                                         # отключённая: только опасные флаги
    # подразделение (OU): в замечаниях, отборе, перечне подразделений и карточке
    assert accs["petrov"]["ou"] == "Users"
    users_f = (await client.get("/api/v1/adaudit/findings", params={"ou": "users", "limit": 500})).json()
    assert users_f["total"] > 0 and all(f["ou"] == "Users" and f["enabled"] is not None for f in users_f["items"])
    assert (await client.get("/api/v1/adaudit/findings", params={"ou": "Бухгалтерия"})).json()["total"] == 0
    assert (await client.get("/api/v1/adaudit/findings", params={"q": "users", "limit": 500})).json()["total"] == users_f["total"]   # поиск — и по OU
    assert (await client.get("/api/v1/adaudit/findings", params={"state": "disabled"})).json()["total"] == 0                        # у отключённой нет замечаний
    assert (await client.get("/api/v1/adaudit/accounts", params={"ou": "Users*"})).json()["total"] == len(U) - 1
    ous = (await client.get("/api/v1/adaudit/ous")).json()["items"]
    assert ous[0]["ou"] == "Users" and ous[0]["accounts"] == len(U) - 1 and ous[0]["open"] == users_f["total"] and ous[0]["high"] > 0
    # решения
    key = next(f["key"] for f in (await client.get("/api/v1/adaudit/findings", params={"q": "svc_backup", "code": "pne"})).json()["items"])
    assert (await client.put("/api/v1/adaudit/decisions", json={"keys": [key], "state": "exception"})).status_code == 422     # исключение — только с основанием
    assert (await client.put("/api/v1/adaudit/decisions", json={"keys": [key], "state": "exception", "comment": "Согласовано ИБ 01.11", "owner": "Отдел ИТ", "due": "2027-05-01"})).json()["updated"] == 1
    assert (await client.get("/api/v1/adaudit/state")).json()["exceptions"] == 1
    assert not any(f["key"] == key for f in (await client.get("/api/v1/adaudit/findings", params={"decision": "unresolved", "limit": 500})).json()["items"])
    card = (await client.get(f"/api/v1/adaudit/accounts/{accs['reset.me']['guid']}")).json()
    assert any(e["kind"] == "reset" and e["by"] == "CORP\\helpdesk1" for e in card["events"]) and any(f["code"] == "reset" for f in card["findings"])
    assert (await client.put(f"/api/v1/adaudit/accounts/{accs['svc_lonely']['guid']}/category", json={"category": "service", "note": "заявка 12"})).status_code == 200
    # политика из раздела: срок для администраторов 90 дней с основанием; применяется со следующей проверки, история — по проверкам
    r = await client.put("/api/v1/adaudit/policy", json={"pwd_days": {"admin": 90}, "inactive_days": 90, "new_days": 30, "grace_days": 14, "protected_users": True, "policy_note": "Приказ № 12 от 01.10.2026"})
    assert r.status_code == 200 and r.json()["policy"]["pwd_days"]["admin"] == 90 and r.json()["policy"]["pwd_days"]["user"] == 90
    assert (await client.put("/api/v1/adaudit/policy", json={"pwd_days": {"robot": 5}, "inactive_days": 90, "new_days": 30, "grace_days": 14})).status_code == 422
    st = (await client.get("/api/v1/adaudit/state")).json()
    assert st["policy"]["policy_note"] == "Приказ № 12 от 01.10.2026"
    grp = (await client.get("/api/v1/adaudit/groups")).json()
    da = next(g for g in grp["items"] if g["group"] == "Domain Admins")
    assert [m["login"] for m in da["members"]] == ["adm.sidorov"] and grp["prev"] is None
    assert (await client.get("/api/v1/adaudit/changes")).json()["prev"] is None                                          # первая проверка — сравнивать не с чем
    # вторая проверка через месяц: замечания переносятся, устранённые видны
    U["petrov"]["pwd"] = 3
    app.state.__dict__.pop("_unused", None)
    dirfake.e.clear()
    dirfake.e.update(directory().e)
    run2 = await _run(app, monkeypatch, now=NOW + timedelta(days=30))
    U["petrov"]["pwd"] = 200
    assert run2.status == "ok"
    accs2 = {a["login"]: a for a in (await client.get("/api/v1/adaudit/accounts", params={"limit": 100})).json()["items"]}
    assert accs2["svc_lonely"]["category"] == "service"                                                                  # ручная классификация применена
    carried = (await client.get("/api/v1/adaudit/findings", params={"carried": True, "limit": 500})).json()["items"]
    assert carried and all(f["runs_n"] == 2 for f in carried)
    pols = (await client.get("/api/v1/adaudit/policies")).json()["items"]
    assert pols[0]["policy"]["pwd_days"]["admin"] == 90 and pols[0]["policy"]["policy_note"] and pols[1]["policy"]["pwd_days"]["admin"] == 30
    assert not any(f["login"] == "adm.sidorov" and f["code"] == "pwd_age" for f in (await client.get("/api/v1/adaudit/findings", params={"limit": 500})).json()["items"])   # 75 дн. < 90
    ch = (await client.get("/api/v1/adaudit/changes")).json()
    assert ch["prev"] and any(x["kind"] == "category" and x["login"] == "svc_lonely" and x["after"] == "Сервисная" for x in ch["items"])
    assert ch["counts"].get("new", 0) == 0 and ch["counts"].get("removed", 0) == 0
    gone = (await client.get("/api/v1/adaudit/findings", params={"gone": True, "limit": 500})).json()["items"]
    assert any(f["login"] == "petrov" and f["code"] == "pwd_age" for f in gone)
    assert len((await client.get("/api/v1/adaudit/runs")).json()["items"]) == 2
    # отчёты: все виды строятся, в строках — основания и решения
    for view in ("accounts", "active", "pne", "pwd_age", "resets", "unused", "privileged", "findings", "audit", "summary", "groups", "changes"):
        r = await client.post("/api/v1/quick/preview", json={"kind": "quick_adaudit", "params": {"view": view}})
        assert r.status_code == 200, (view, r.text)
    doc = (await client.post("/api/v1/quick/preview", json={"kind": "quick_adaudit", "params": {"view": "findings"}})).json()
    rows = doc["items"]
    assert any(x.get("decision") == "согласованное исключение" and x.get("comment") == "Согласовано ИБ 01.11" for x in rows)
    assert all(x.get("ou") == "Users" and x.get("acc_state") for x in rows)
    doc = (await client.post("/api/v1/quick/preview", json={"kind": "quick_adaudit", "params": {"view": "groups"}})).json()
    assert any(x["group"] == "Domain Admins" and x["login"] == "adm.sidorov" for x in doc["items"])
    doc = (await client.post("/api/v1/quick/preview", json={"kind": "quick_adaudit", "params": {"view": "findings", "ou": "нет-такого"}})).json()
    assert doc["items"] == []
    doc = (await client.post("/api/v1/quick/preview", json={"kind": "quick_adaudit", "params": {"view": "pne", "ou": "users"}})).json()
    assert doc["items"] and all(x["ou"] == "Users" for x in doc["items"])
    # права: аналитику раздел и отчёт недоступны, специалисту по ИБ — доступны
    await login(client, "an1", "Sec-Passw0rd-1234")
    assert (await client.get("/api/v1/adaudit/state")).status_code == 403
    assert (await client.post("/api/v1/quick/preview", json={"kind": "quick_adaudit", "params": {"view": "summary"}})).status_code == 403
    await login(client, "sec1", "Sec-Passw0rd-1234")
    assert (await client.get("/api/v1/adaudit/state")).status_code == 200
    assert (await client.post("/api/v1/adaudit/run", json={"kind": "quarterly"})).status_code == 202
    assert (await client.put("/api/v1/adaudit/policy", json={"pwd_days": {"admin": 60}, "inactive_days": 90, "new_days": 30, "grace_days": 14})).status_code == 403   # политику меняет администратор
    assert (await client.get("/api/v1/ad/status")).status_code != 403                                                  # каталог AD — в разделе аудита


async def test_active_scope_applies_to_stored_audit_views_and_reports(client, app):
    from app.models import AdAuditAccount, AdAuditFinding, AdAuditRun, AdEventImport, AdPwdEvent

    await _users(client)
    accounts = {
        "active.user": {"pwd_expired": True, "expires": NOW + timedelta(days=1)},
        "disabled.user": {"enabled": False},
        "locked.user": {"locked": True},
        "expired.user": {"expires": NOW},
    }
    active = {"active.user"}
    async with app.state.session_maker() as db:
        prev, run = (AdAuditRun(started_at=at, status="ok", stats={"accounts": len(accounts)}) for at in (ago(7), NOW))
        uploaded = AdEventImport(file_name="example.json")
        db.add_all([prev, run, uploaded])
        await db.flush()
        for i, (name, values) in enumerate(accounts.items()):
            sid = f"{DOM_SID}-{5000 + i}"
            for snapshot in (prev, run):
                db.add(AdAuditAccount(run_id=snapshot.id, guid=name, sid=sid, login=name, name=name, ou="Users",
                                      privileged=["Domain Admins"], created=ago(10 if snapshot is prev else 5), idle_days=120,
                                      pwd_bucket="gt180", **values))
                if snapshot is run:
                    db.add(AdAuditFinding(run_id=run.id, key=f"{name}:test", guid=name, login=name, code="pwd_age", title="Старый пароль",
                                          category="user", severity="high", sev_rank=3, status="violation", first_seen=NOW))
            db.add(AdPwdEvent(import_id=uploaded.id, dc="dc1.corp.example.local", record_id=i + 1, at=ago(2), target=name,
                              target_sid=sid, kind="reset", success=True))
        await db.commit()
        run_id = str(run.id)

    async def get(path, **params):
        response = await client.get(f"/api/v1/adaudit/{path}", params=params)
        assert response.status_code == 200, response.text
        return response.json()

    async def report(view, include_inactive=False, **params):
        response = await client.post("/api/v1/quick/preview", json={"kind": "quick_adaudit", "params": {
            "view": view, "run": run_id, "include_inactive": include_inactive, **params}})
        assert response.status_code == 200, response.text
        return response.json()

    for include, expected in ((False, active), (True, set(accounts))):
        p = {"include_inactive": include, "run": run_id}
        assert {r["login"] for r in (await get("accounts", **p))["items"]} == expected
        assert {r["login"] for r in (await get("findings", **p))["items"]} == expected
        assert {r["login"] for r in (await get("groups", **p))["items"][0]["members"]} == expected
        assert {r["target"] for r in (await get("events", **p))["items"]} == expected
        assert (await get("state", **p))["viewed"]["stats"]["accounts"] == len(expected)
        assert (await get("ous", **p))["items"][0]["accounts"] == len(expected)
        for view in ("accounts", "findings", "groups", "pwd_age"):
            rows = (await report(view, include))["items"]
            assert {r["login"] for r in rows} == expected, view
        assert {r["target"] for r in (await report("events", include, event_kind="reset"))["items"]} == expected
        summary = (await report("summary", include))["doc"]
        assert next(m["value"] for m in summary["metrics"] if m["key"] == "accounts") == len(expected)
    assert (await client.get("/api/v1/adaudit/accounts/locked.user")).status_code == 404
    assert (await get("accounts/locked.user", include_inactive=True))["state"] == "заблокирована"
    assert (await get("accounts/expired.user", include_inactive=True))["state"] == "истёк срок действия"


async def test_without_logs_no_reset_is_claimed_and_failed_directory_is_reported(client, app, monkeypatch, dirfake):
    await _users(client)
    run = await _run(app, monkeypatch)
    assert run.status == "ok"
    fs = (await client.get("/api/v1/adaudit/findings", params={"code": "reset"})).json()
    assert fs["total"] == 0                                                                                               # журналов нет — сбросов не «находим»
    acc = next(a for a in (await client.get("/api/v1/adaudit/accounts", params={"q": "reset.me"})).json()["items"])
    assert acc["pwd_op"]["state"] == "no_logs" and "не загружены" in acc["pwd_op"]["basis"]
    from app.auth.ldap import LdapError

    def down(*a, **k):
        raise LdapError("server_unavailable", "Контроллер домена не отвечает")
    monkeypatch.setattr(C, "run_search", down)
    bad = await _run(app, monkeypatch, now=NOW + timedelta(hours=1))
    assert bad.status == "failed" and "не отвечает" in bad.message
    st = (await client.get("/api/v1/adaudit/state")).json()
    assert st["latest"]["id"] == str(run.id) and st["last"]["status"] == "failed"                                         # пользователи видят последнюю успешную проверку


async def test_schedule_monthly_and_quarterly(app):
    cfg = AdAuditSettings(day_of_month=5, schedule_time="03:00", timezone="Europe/Moscow")
    nxt = AS.next_run(cfg, datetime(2026, 11, 19, tzinfo=timezone.utc))
    assert nxt == datetime(2026, 12, 5, 0, 0, tzinfo=timezone.utc)
    assert AS.next_run(cfg, datetime(2026, 12, 31, 23, tzinfo=timezone.utc)) == datetime(2027, 1, 5, 0, 0, tzinfo=timezone.utc)
    _ = asyncio
