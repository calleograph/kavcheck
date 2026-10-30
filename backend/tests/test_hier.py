"""«Иерархия. Предприятие»: очистка и построение структуры на вымышленной выгрузке (352 → 279), подключение к каталогу (подставное), публикация снимков и защита от сокращения,
хранение без дублей, расписание, доступ по ролям (проверка на сервере), журнал открытия."""
import asyncio
import json
import time
from datetime import timedelta

from sqlalchemy import select

from app.hier import process as P
from app.hier import service as HS
from app.hier import sources as S
from app.models import AuditLog, HierSnapshot, utcnow
from app.services import local_admin as la
from app.services.jobs import JOBS
from tests.conftest import login
from tests.hier_data import DOMAIN, demo_records

RULES = P.Rules(domains=(DOMAIN,), dept_map={"ИТ": "Отдел информационных технологий"})


def recs(rows=None):
    return [[r[k] for k in P.FIELDS] for r in (rows if rows is not None else demo_records())]


def by_name(res):
    return {p["name"]: p for p in res.people}


# ---------------------------------------------------------------------------------------------------------------- очистка и структура
def test_cleaning_matches_control_numbers():
    res = P.build(recs(), RULES)
    assert res.raw_n == 352 and len(res.people) == 279
    assert res.excluded == {"внешний домен": 22, "пустая карточка": 40, "имя с «_»": 8, "служебная учётная запись": 3}


def test_hierarchy_special_cases_do_not_hang_and_are_marked():
    res = P.build(recs(), RULES)
    p = by_name(res)
    ceo = p["Ершов Павел Павлович"]
    assert ceo["self"] and ceo["head"] and ceo["mgr"] < 0 and ceo["reach"] and res.heads == [res.people.index(ceo)]            # самоссылка — верхний уровень, не ошибка
    a, b = p["Кругов Алексей Алексеевич"], p["Кругова Анна Андреевна"]
    assert a["why"] == b["why"] == "cycle" and not a["reach"] and not b["reach"] and len(res.cycles) == 1                      # круг — в группу «руководитель не указан»
    assert "Круги в подчинении: 1" in res.warnings[0]
    assert p["Безадресов0 Олег Олегович"]["why"] == "text" and not p["Безадресов0 Олег Олегович"]["reach"]                    # руководитель только текстом, не найден
    assert p["Двойнов Борис Борисович"]["why"] == "ambig"                                                                       # два человека с таким ФИО — выбрать нельзя
    assert p["Внешнеруков Фёдор Фёдорович"]["why"] == "outside"                                                                # руководитель указан адресом вне выгрузки
    assert p["Безруков0 Роман Романович"]["why"] == "none"
    found = p["Поискови Тимур Тимурович"]                                                                                      # единственное совпадение по ФИО — связь строится
    assert found["mgr"] >= 0 and found["reach"] and res.people[found["mgr"]]["name"].startswith("Руководов00")
    assert not any(q["reach"] for q in res.people if q["why"] in ("text", "ambig", "outside", "cycle"))                                                                  # все «без связи» — вне дерева
    assert len(res.lone) == sum(1 for q in res.people if not q["reach"])


def test_name_lookup_can_be_switched_off():
    res = P.build(recs(), P.Rules(domains=(DOMAIN,), name_lookup=False))
    assert by_name(res)["Поискови Тимур Тимурович"]["why"] == "text"


def test_departments_mapping_and_inheritance_by_manager():
    res = P.build(recs(), RULES)
    names = [d["name"] for d in res.depts]
    assert "ИТ" not in names and "Отдел информационных технологий" in names                                                    # синонимы объединены при показе, исходное значение в выгрузке не меняется
    inh = [q for q in res.people if q["inh"]]
    assert inh and all(res.depts[q["dept"]]["name"] == res.depts[res.people[q["mgr"]]["dept"]]["name"] or res.people[q["mgr"]]["inh"] for q in inh if q["mgr"] >= 0)
    plain = P.build(recs(), P.Rules(domains=(DOMAIN,)))
    assert "ИТ" in [d["name"] for d in plain.depts]
    assert res.depts[-1]["name"] != P.NO_DEPT or res.depts[-1]["n"] > 0
    lonely = P.build([["Одинокий Сергей Сергеевич", f"a@{DOMAIN}", "Инженер", "", "", "", "", ""]], RULES)
    assert lonely.depts[0]["name"] == P.NO_DEPT and not lonely.people[0]["inh"]


def test_ids_are_stable_and_sorted_names_short():
    a, b = P.build(recs(), RULES), P.build(list(reversed(recs())), RULES)
    assert [q["id"] for q in a.people] == [q["id"] for q in b.people] and len({q["id"] for q in a.people}) == 279                 # от адреса, не от порядка
    assert P.short_name("Ершов Павел Павлович") == "Ершов П. П." and P.hue("Финансовый отдел") == P.hue(" финансовый  отдел")


def test_long_chain_and_big_cycle_are_linear_and_safe():
    n = 30_000
    chain = [[f"Ч{i:05d} А А", f"c{i}@{DOMAIN}", "Инженер", "Отдел", "", "", "", f"c{i - 1}@{DOMAIN}" if i else f"c0@{DOMAIN}"] for i in range(n)]          # c0 — сам себе руководитель
    t0 = time.time()
    res = P.build(chain, P.Rules())
    assert len(res.heads) == 1 and res.people[res.heads[0]]["size"] == n and time.time() - t0 < 10                              # без рекурсии: цепочка в тысячи уровней не роняет
    ring = [[f"К{i:04d} А А", f"k{i}@{DOMAIN}", "Инженер", "Отдел", "", "", "", f"k{(i + 1) % 2000}@{DOMAIN}"] for i in range(2000)]
    res = P.build(ring, P.Rules())
    assert len(res.cycles) == 1 and len(res.cycles[0]) == 2000 and not res.heads and len(res.lone) == 2000


def test_rules_are_configurable():
    r = P.Rules(domains=(DOMAIN, "partner0.example"), drop_empty=False, drop_underscore=False, drop_service=False)
    res = P.build(recs(), r)
    assert res.excluded == {"внешний домен": 16} and len(res.people) == 352 - 16
    assert P.build([["Тестов Иван Иванович", f"testov@{DOMAIN}", "Инженер", "Отдел", "", "", "", ""]], P.Rules(service_prefixes=("test",))).excluded == {"служебная учётная запись": 1}


# ---------------------------------------------------------------------------------------------------------------- каталог (подставное соединение)
class FakeConn:
    def __init__(self, entries, extra=None):
        self.entries, self.extra, self.result, self.response = entries, extra or {}, {"result": 0}, []
        self.extend = type("E", (), {"standard": type("S", (), {"paged_search": staticmethod(lambda *a, **k: iter(self.entries))})()})()

    def search(self, base, flt, search_scope=None, attributes=None, size_limit=0):
        e = self.extra.get(base.lower())
        self.response = [e] if e else []
        self.result = {"result": 0}

    def unbind(self):
        pass


def ent(dn, mail, name="", title="", dept="", mgr="", uac=512, prox=None):
    a = {"displayName": [name] if name else [], "mail": [mail], "title": [title] if title else [], "department": [dept] if dept else [], "manager": [mgr] if mgr else [], "userAccountControl": [str(uac)],                                          # ldap3 без схемы отдаёт строки
         "proxyAddresses": prox or []}
    return {"type": "searchResEntry", "dn": dn, "attributes": a}


def test_ldap_read_resolves_manager_dn_skips_disabled_and_survives_bad_entry(monkeypatch):
    from app.auth import ldap as L

    boss = ent("CN=Boss,OU=x,DC=d", "boss@demo-company.example", "Босс Б. Б.", "Директор", "Руководство")
    me = ent("CN=Me,OU=x,DC=d", "old@demo-company.example", "Я Я. Я.", "Инженер", "Отдел", "CN=Boss,OU=x,DC=d", prox=["smtp:alias@demo-company.example", "SMTP:me@demo-company.example"])
    gone = ent("CN=Gone,OU=x,DC=d", "gone@demo-company.example", "Ушёл У. У.", "Инженер", "Отдел", "CN=Boss,OU=x,DC=d", uac=514)                            # отключена
    far = ent("CN=Far,OU=x,DC=d", "far@demo-company.example", "Дальний Д. Д.", "Инженер", "Отдел", "CN=Outside,OU=y,DC=d")                                        # руководитель вне выборки
    bad = {"type": "searchResEntry", "dn": "CN=Bad,DC=d", "attributes": 5}                                    # запись с ошибкой
    outside = ent("CN=Outside,OU=y,DC=d", "outside@demo-company.example", "Внешний В. В.")
    conn = FakeConn([boss, me, gone, far, bad, {"type": "searchResRef"}], extra={"cn=outside,ou=y,dc=d": outside})
    monkeypatch.setattr(L, "_service", lambda cfg: conn)
    got = S.read_ldap(L.LdapConfig(name="Домен", host="dc", base_dn="DC=d"))
    byemail = {r[P.EMAIL]: r for r in got.records}
    assert set(byemail) == {"boss@demo-company.example", "me@demo-company.example", "far@demo-company.example"}                                       # основной SMTP, отключённый пропущен
    assert byemail["me@demo-company.example"][P.MANAGER_EMAIL] == "boss@demo-company.example" and byemail["me@demo-company.example"][P.MANAGER] == "Босс Б. Б."
    assert byemail["far@demo-company.example"][P.MANAGER_EMAIL] == "outside@demo-company.example"                                                          # руководитель прочитан напрямую по DN
    assert got.errors_n == 1 and any("Отключённых учётных записей пропущено: 1" in n for n in got.notes)                                                     # плохая запись — в ошибках, сбор идёт дальше


def test_ldap_check_reports_missing_manager(monkeypatch):
    from app.auth import ldap as L

    class C(FakeConn):
        def search(self, base, flt, search_scope=None, attributes=None, size_limit=0):
            self.response, self.result = self.entries, {"result": 0}

    monkeypatch.setattr(L, "_service", lambda cfg: C([ent("CN=A,DC=d", "a@x.example", "А", "Инженер", "Отдел"), ent("CN=B,DC=d", "b@x.example", "Б", "Инженер", "Отдел")]))
    r = S.check_ldap(L.LdapConfig(name="Домен", host="dc", base_dn="DC=d"))
    assert not r["ok"] and r["steps"][-1]["name"] == "Поле «Руководитель»" and "нет права читать" in r["steps"][-1]["text"]
    monkeypatch.setattr(L, "_service", lambda cfg: C([ent("CN=A,DC=d", "a@x.example", "А", "Инженер", "Отдел", "CN=B,DC=d")]))
    assert S.check_ldap(L.LdapConfig(name="Домен", host="dc", base_dn="DC=d"))["ok"]
    monkeypatch.setattr(L, "_service", lambda cfg: (_ for _ in ()).throw(L.LdapError("tls_error")))
    assert not S.check_ldap(L.LdapConfig(name="Домен", host="dc", base_dn="DC=d"))["ok"]


def test_file_parser_validates():
    ok = S.parse_file(json.dumps(demo_records()).encode())
    assert len(ok.records) == 352 and ok.errors_n == 0
    for bad in (b"not json", b"{}", b"[]", "﻿[1, 2]".encode()):
        try:
            res = S.parse_file(bad)
            assert res.errors_n == 2 and not [r for r in res.records if r[P.EMAIL]]
        except S.SourceError:
            pass


# ---------------------------------------------------------------------------------------------------------------- API, публикация, права
async def users(app):
    async with app.state.session_maker() as db:
        await la.create_local(db, "analyst1", "Analyst-Passw0rd-123", role="analyst", must_change=False)
        await db.commit()


async def upload(client, rows=None):
    return await client.post("/api/v1/hier/admin/upload", content=json.dumps(rows if rows is not None else demo_records()).encode(), headers={"Content-Type": "application/octet-stream"})


async def test_access_is_enforced_on_the_server_and_opening_is_audited(client, app):
    await users(app)
    assert (await client.get("/api/v1/hier/data")).status_code == 401
    await login(client, "admin", "Admin-Passw0rd-123")
    await client.put("/api/v1/admin/settings/hier", json={"internal_domains": [DOMAIN], "dept_map": {"ИТ": "Отдел информационных технологий"}})
    up = await upload(client)
    assert up.status_code == 200 and up.json()["status"] == "ok" and up.json()["raw_n"] == 352
    d = (await client.get("/api/v1/hier/data")).json()
    assert d["state"] == "ok" and d["snapshot"]["raw_n"] == 352 and d["snapshot"]["kept"] == 279 and d["snapshot"]["excluded"] == 73 and len(d["people"]) == 279 and d["can_admin"]
    assert len(d["people"][0]) == 11 and d["depts"][0]["n"] >= d["depts"][1]["n"]
    async with app.state.session_maker() as db:
        assert (await db.execute(select(AuditLog).where(AuditLog.action == "hier.open"))).scalars().first() is not None              # открытие раздела — в журнале
        assert (await db.execute(select(AuditLog).where(AuditLog.action == "hier.upload"))).scalars().first() is not None
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get("/api/v1/hier/access")).json() == {"allowed": False, "admin": False}
    assert (await client.get("/api/v1/hier/data")).status_code == 403                                                              # прямой запрос без роли — отказ, данных нет
    assert (await client.post("/api/v1/hier/admin/run")).status_code == 403
    await login(client, "analyst1", "Analyst-Passw0rd-123")
    r = await client.get("/api/v1/hier/data")
    assert r.status_code == 200 and not r.json()["can_admin"] and r.json()["snapshot"]["source_name"] == ""                          # аналитик видит структуру, но не подробности источника
    assert (await client.get("/api/v1/hier/admin")).status_code == 403
    await login(client, "admin", "Admin-Passw0rd-123")
    await client.put("/api/v1/admin/settings/hier", json={"roles": ["viewer", "admin"]})                                             # администратор меняет роли
    await login(client, "analyst1", "Analyst-Passw0rd-123")
    assert (await client.get("/api/v1/hier/data")).status_code == 403
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get("/api/v1/hier/data")).status_code == 200


async def test_rules_and_mapping_apply_without_new_collection(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    await client.put("/api/v1/admin/settings/hier", json={"internal_domains": [DOMAIN]})
    await upload(client)
    before = (await client.get("/api/v1/hier/data")).json()
    assert "ИТ" in " ".join(d["name"] for d in before["depts"])
    await client.put("/api/v1/admin/settings/hier", json={"dept_map": {"ИТ": "Отдел информационных технологий"}})
    after = (await client.get("/api/v1/hier/data")).json()
    assert "ИТ" not in [d["name"] for d in after["depts"]] and len(after["depts"]) == len(before["depts"]) - 1                         # исходные записи те же, показ изменился сразу
    adm = (await client.get("/api/v1/hier/admin")).json()
    assert any(x["raw"] == "ИТ" and x["shown"] == "Отдел информационных технологий" for x in adm["depts"]) and adm["domains"][0]["domain"] == DOMAIN


async def test_identical_snapshots_are_not_duplicated_and_pruning_keeps_data(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    await upload(client)
    await upload(client)
    await upload(client, demo_records()[:300])
    async with app.state.session_maker() as db:
        s = list((await db.execute(select(HierSnapshot).order_by(HierSnapshot.started_at))).scalars())
        assert [x.status for x in s] == ["ok", "ok", "ok"] and s[0].records is not None and s[1].records is None and s[1].same_as_id == s[0].id and s[2].records is not None
        s[0].started_at = utcnow() - timedelta(days=200)                                                                              # самый старый (хранит данные второго) уходит по сроку
        await db.commit()
        assert await HS.prune(db, 90) == 1
        await db.commit()
        rest = list((await db.execute(select(HierSnapshot).order_by(HierSnapshot.started_at))).scalars())
        assert len(rest) == 2 and rest[0].records is not None and rest[0].same_as_id is None and len(await HS.records_of(db, rest[0])) == 352     # данные не потеряны


async def test_shrinking_or_failed_collection_keeps_previous_snapshot_with_warning(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    await client.put("/api/v1/admin/settings/hier", json={"internal_domains": [DOMAIN]})
    await upload(client)
    sm, svc = app.state.session_maker, app.state.settings_svc

    async def collect(rows, trigger="schedule"):
        async with sm() as db:
            snap = HierSnapshot(status="running", trigger=trigger, source="ldap")
            db.add(snap)
            await db.commit()
        c = S.Collected(name="Домен")
        c.records = [[r[k] for k in P.FIELDS] for r in rows]
        return await HS.publish(sm, svc, snap.id, c, trigger)

    small = await collect(demo_records()[:200])                                                                                      # на 43 % меньше при пороге 10 %
    assert small.status == "rejected" and "не опубликован" in small.message and small.records is None
    d = (await client.get("/api/v1/hier/data")).json()
    assert d["snapshot"]["raw_n"] == 352 and d["warning"]["status"] == "rejected" and d["warning"]["last_ok_at"]                       # пользователи видят прежний снимок и предупреждение
    assert (await collect([])).status == "failed"
    ok = await collect(demo_records()[:340])                                                                                          # в пределах порога — публикуется
    assert ok.status == "ok"
    assert (await client.get("/api/v1/hier/data")).json()["warning"] is None
    forced = await collect(demo_records()[:100], trigger="upload")                                                                    # ручная загрузка порогом не ограничена
    assert forced.status == "ok"


async def test_scheduler_runs_on_time_retries_after_failure_and_serves_manual_request(client, app, monkeypatch):
    sm, svc = app.state.session_maker, app.state.settings_svc
    JOBS.configure(sm, ttl=60)
    from app.api.hier import _CACHE

    _CACHE.clear()
    await login(client, "admin", "Admin-Passw0rd-123")
    await client.put("/api/v1/admin/settings/hier", json={"enabled": True, "schedule_time": "03:10", "timezone": "Europe/Moscow", "internal_domains": [DOMAIN]})
    hs = HierService = HS.HierService(sm, app.state.settings, svc, app.state.ldap, app.state.journal)
    calls = []

    async def fake_collect(cfg, lease):
        calls.append(1)
        if len(calls) == 1:
            raise S.SourceError("Подключение LDAPS «Домен»: Контроллер домена не отвечает.")
        c = S.Collected(name="Домен")
        c.records = [[r[k] for k in P.FIELDS] for r in demo_records()]
        return c

    monkeypatch.setattr(hs, "_collect", fake_collect)
    await hs.tick()                                                                                                                  # первый такт только назначает время (по часовому поясу настройки)
    st = await HS.get_state(sm)
    assert st["sig"] == "03:10|Europe/Moscow" and st["next_run"] and not calls
    await HS.set_state(sm, next_run=(utcnow() - timedelta(minutes=1)).isoformat())
    await hs.tick()
    await asyncio.gather(*list(hs._tasks))                                                                                           # noqa: SLF001
    async with sm() as db:
        first = (await db.execute(select(HierSnapshot))).scalars().one()
    assert first.status == "failed" and "не отвечает" in first.message
    st = await HS.get_state(sm)
    assert st["retry_n"] == 1 and timedelta(minutes=25) < __import__("datetime").datetime.fromisoformat(st["next_run"]) - utcnow() < timedelta(minutes=31)      # повтор через 30 минут
    await login(client, "admin", "Admin-Passw0rd-123")
    assert (await client.post("/api/v1/hier/admin/run")).status_code == 202                                                          # «Обновить сейчас»
    await hs.tick()
    await asyncio.gather(*list(hs._tasks))                                                                                           # noqa: SLF001
    async with sm() as db:
        snaps = list((await db.execute(select(HierSnapshot).order_by(HierSnapshot.started_at))).scalars())
    assert [s.status for s in snaps] == ["failed", "ok"] and snaps[1].trigger == "manual" and snaps[1].by == "Локальный администратор" or snaps[1].trigger == "manual"
    assert not (await HS.get_state(sm)).get("retry_n") and not (await HS.get_state(sm)).get("requested")
    _ = hs


async def test_recover_marks_interrupted_runs(app):
    sm = app.state.session_maker
    async with sm() as db:
        db.add(HierSnapshot(status="running", trigger="schedule", source="ldap"))
        await db.commit()
    hs = HS.HierService(sm, app.state.settings, app.state.settings_svc, app.state.ldap)
    assert await hs.recover() == 1
    async with sm() as db:
        s = (await db.execute(select(HierSnapshot))).scalars().one()
    assert s.status == "failed" and "прерван" in s.message


async def test_admin_check_explains_when_no_connection(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    r = (await client.post("/api/v1/hier/admin/check")).json()
    assert not r["ok"] and "LDAPS" in r["message"] and "SMTP" in r["message"]


def test_ldap_size_limit_is_an_error_not_a_partial_snapshot(monkeypatch):
    from app.auth import ldap as L

    conn = FakeConn([ent(f"CN=U{i},DC=d", f"u{i}@demo-company.example", f"Ю{i}", "Инженер", "Отдел") for i in range(5)])
    conn.result = {"result": 4}                                                                                                    # sizeLimitExceeded: каталог отдал часть записей
    monkeypatch.setattr(L, "_service", lambda cfg: conn)
    try:
        S.read_ldap(L.LdapConfig(name="Домен", host="dc", base_dn="DC=d"))
        raise AssertionError("неполная выгрузка не должна приниматься")
    except S.SourceError as exc:
        assert "не все записи" in str(exc) and "MaxResultSetSize" in str(exc)
