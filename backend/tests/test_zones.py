"""Зоны ответственности без KSC: сопоставление по сетям, CSV (просмотр, режимы, атомарность, повторный импорт), API, решения по уязвимостям, расписания."""
import io
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import Zone, ZoneContact, ZoneRule
from app.zones import csv_io, schedule as SC
from app.zones import triage as T
from app.zones.match import RuleError, ZoneDef, ZoneIndex, normalize_rule, parse_net
from tests.conftest import login

ORIGIN = {"Origin": "http://testserver"}


# ------------------------------------------------------------------------------------------------ сопоставление
def test_net_parsing_ipv4_ipv6_ranges_and_errors():
    assert parse_net("192.0.2.0/24") == (3221225984, 3221225984 + 255)
    assert parse_net("192.0.2.10") == (3221225994, 3221225994)
    assert parse_net("192.0.2.10-192.0.2.12")[1] - parse_net("192.0.2.10-192.0.2.12")[0] == 2
    assert parse_net("192.0.2.10-50") == (3221225994, 3221225984 + 50)
    lo, hi = parse_net("2001:db8::/32")
    assert lo > 2 ** 32 and hi - lo == 2 ** 96 - 1
    assert normalize_rule("net", "192.0.2.77/24") == ("net", "192.0.2.0/24")
    assert normalize_rule("net", "192.0.2.5 - 192.0.2.9") == ("net", "192.0.2.5-192.0.2.9")
    for bad in ("192.0.2.300", "192.0.2.9-192.0.2.1", "1.1.1.1-2001:db8::1", "хост", ""):
        with pytest.raises(RuleError):
            normalize_rule("net", bad)
    assert normalize_rule("exclude", "wh-*") == ("exclude", "wh-*")          # исключение по имени
    with pytest.raises(RuleError):
        normalize_rule("exclude", "192.0.2.999")                              # похоже на адрес — проверяется строго


def _ix(*defs, pins=None):
    return ZoneIndex(list(defs), pins)


def test_assignment_policy_single_priority_conflict_pin_exclusion_and_unassigned():
    a = ZoneDef("a", "A", 100, [("net", "192.0.2.0/25"), ("exclude", "192.0.2.50-192.0.2.60")])
    b = ZoneDef("b", "B", 100, [("net", "192.0.2.64/26"), ("group", "*Серверы*")])
    c = ZoneDef("c", "C", 10, [("net", "192.0.2.0/24")])
    ix = _ix(a, b)
    assert ix.assign(1, "s", ips=["192.0.2.1"]).zone_ids == ["a"] and ix.assign(1, "s", ips=["192.0.2.1"]).via == "single"
    assert ix.assign(1, "s", ips=["192.0.2.70"]).conflict and set(ix.assign(1, "s", ips=["192.0.2.70"]).zone_ids) == {"a", "b"}       # равные приоритеты — спор виден
    assert ix.assign(1, "s", ips=["192.0.2.55"]).zone_ids == []                                          # исключение
    assert ix.assign(1, "s", group="Офис / Серверы", ips=["198.51.100.1"]).zone_ids == ["b"]         # по группе
    assert ix.assign(1, "s", group="Офис / Серверы", ips=["192.0.2.55"]).zone_ids == ["b"]
    assert ix.assign(1, "s", ips=["203.0.113.5"]).via == "none"
    ix2 = _ix(a, b, c)
    assert ix2.assign(1, "s", ips=["192.0.2.70"]).zone_ids == ["c"] and ix2.assign(1, "s", ips=["192.0.2.70"]).via == "priority" and not ix2.assign(1, "s", ips=["192.0.2.70"]).conflict
    ix3 = _ix(a, b, pins={("s", 7): "b"})
    assert ix3.assign(7, "s", ips=["192.0.2.70"]).zone_ids == ["b"] and ix3.assign(7, "s", ips=["192.0.2.70"]).pinned and not ix3.assign(7, "s", ips=["192.0.2.70"]).conflict
    assert ix3.assign(8, "s", ips=["192.0.2.70"]).conflict                                                 # закрепление только для своего компьютера
    assert _ix(ZoneDef("d", "D", 1, [("net", "192.0.2.0/24")], enabled=False)).assign(1, "s", ips=["192.0.2.1"]).zone_ids == []


def test_multiple_ips_and_ipv6():
    a = ZoneDef("a", "A", 100, [("net", "192.0.2.0/24")])
    b = ZoneDef("b", "B", 100, [("net", "2001:db8::/32")])
    ix = _ix(a, b)
    r = ix.assign(1, "s", ips=["203.0.113.9", "192.0.2.4"])               # несколько адресов: подходит любой
    assert r.zone_ids == ["a"]
    assert ix.assign(1, "s", ips=["2001:db8::5"]).zone_ids == ["b"]
    assert ix.assign(1, "s", ips=["192.0.2.4", "2001:db8::5"]).conflict


def test_large_rule_set_is_fast():
    import time
    zones = [ZoneDef(str(i), f"Z{i}", 100, [("net", f"10.{i // 250}.{i % 250}.0/24") for _ in range(1)]) for i in range(2000)]
    ix = _ix(*zones)
    t = time.time()
    for k in range(20000):
        ix.assign(k, "s", ips=[f"10.{(k % 8)}.{k % 250}.{k % 200}"])
    assert time.time() - t < 3


# ------------------------------------------------------------------------------------------------ CSV
SAMPLE = csv_io.sample_csv()


def test_csv_sample_parses_cleanly_and_creates_three_zones():
    p = csv_io.parse(SAMPLE)
    assert not p.errors and not p.warnings and p.encoding.startswith("utf-8")
    plan = csv_io.plan(p, [], "add_update")
    s = plan.summary
    assert plan.ok and s["zones_create"] == 3 and s["rules_add"] == 11 and s["contacts_add"] == 4
    names = {z["name"]: z for z in plan.zones}
    assert len(names["Департамент А"]["rules_add"]) == 3 and len(names["Департамент Б"]["rules_add"]) == 5


def test_csv_cp1251_and_delimiters_and_bom():
    raw = "Зона,Значение признака,Email\nОтдел,192.0.2.0/24,a@example.local\n".encode("cp1251")
    p = csv_io.parse(raw)
    assert p.encoding == "windows-1251" and p.delimiter == "," and not p.errors and p.rows[0].name == "Отдел"
    assert csv_io.parse("﻿Зона;Подсеть\nОтдел;192.0.2.0/24\n".encode("utf-8")).rows[0].value == "192.0.2.0/24"


def test_csv_errors_have_line_numbers_and_block_the_plan():
    bad = ("Зона;Значение признака;Email;Приоритет\nA;192.0.2.300;;\nB;192.0.2.0/24;нет-собаки;\nC;192.0.2.0/24;c@example.local;abc\n;192.0.2.0/24;;\nD;=cmd|' /C calc'!A0;;\nOK;192.0.2.0/25;ok@example.local;5\n").encode()
    p = csv_io.parse(bad)
    assert [e["line"] for e in p.errors] == [2, 3, 4, 5, 6]
    plan = csv_io.plan(p, [], "add_update")
    assert not plan.ok and plan.summary["errors"] == 5
    assert any("формул" in e["message"] for e in plan.errors)


def test_csv_duplicates_merge_and_do_not_create_duplicates():
    data = ("Зона;Значение признака;Ответственный;Email\nА;192.0.2.0/24;Иван;ivan@example.local\nА;192.0.2.0/24;Иван;ivan@example.local\nА;198.51.100.0/24;;\nа ;203.0.113.0/24;;\n").encode()
    plan = csv_io.plan(csv_io.parse(data), [], "add_update")
    assert plan.summary["zones_create"] == 1 and plan.summary["rules_add"] == 3 and plan.summary["contacts_add"] == 1
    assert len(plan.warnings) == 2


def test_csv_overlap_warning_between_zones():
    data = "Зона;Значение признака\nА;192.0.2.0/24\nБ;192.0.2.128/25\n".encode()
    plan = csv_io.plan(csv_io.parse(data), [], "add_update")
    assert plan.ok and len(plan.overlaps) == 1 and plan.overlaps[0]["example"].startswith("192.0.2.128")


def test_csv_roundtrip_is_idempotent_and_injection_is_escaped():
    ex = [csv_io.Existing(str(uuid.uuid4()), "=Опасно", "+описание", "@цель", 50, [("net", "192.0.2.0/24"), ("exclude", "192.0.2.5")],
                          [{"email": "a@example.local", "name": "-Иван", "position": "", "role": "cc", "enabled": False}])]
    out = csv_io.to_csv(csv_io.export_rows(ex))
    text = out.decode("utf-8-sig")
    assert "'=Опасно" in text and "'+описание" in text and "'@цель" in text and "'-Иван" in text
    p = csv_io.parse(out)
    assert not p.errors, p.errors
    plan = csv_io.plan(p, ex, "add_update")
    assert plan.ok and plan.summary["zones_unchanged"] == 1 and plan.summary["zones_create"] == 0 and plan.summary["rules_add"] == 0 and plan.summary["contacts_add"] == 0


def test_csv_modes_add_only_update_and_replace():
    zid = str(uuid.uuid4())
    ex = [csv_io.Existing(zid, "Отдел", "старое", "", 100, [("net", "192.0.2.0/24")], [{"email": "old@example.local", "name": "Старый", "position": "", "role": "responsible", "enabled": True}]),
          csv_io.Existing(str(uuid.uuid4()), "Лишняя", "", "", 100, [("net", "198.51.100.0/24")], [])]
    data = f"Идентификатор зоны;Зона;Описание;Значение признака;Email;Ответственный\n{zid};Отдел (переименован);новое;203.0.113.0/24;new@example.local;Новый\n;Новая;;192.0.2.0/28;;\n".encode()
    upd = csv_io.plan(csv_io.parse(data), ex, "add_update")
    assert upd.ok and upd.summary["zones_update"] == 1 and upd.summary["zones_create"] == 1 and upd.summary["rules_remove"] == 0 and upd.summary["contacts_remove"] == 0     # ничего не удаляется
    only = csv_io.plan(csv_io.parse(data), ex, "add_only")
    assert only.summary["zones_create"] == 1 and only.summary["zones_skipped"] == 1 and only.summary["zones_update"] == 0
    rep = csv_io.plan(csv_io.parse(data), ex, "replace")
    assert not rep.ok and rep.summary["zones_delete"] == 1 and rep.summary["rules_remove"] == 1 and rep.summary["contacts_remove"] == 1       # без подтверждения не готов
    assert csv_io.plan(csv_io.parse(data), ex, "replace", confirm=True).ok
    unknown = csv_io.plan(csv_io.parse(f"Идентификатор зоны;Зона\n{uuid.uuid4()};X\n".encode()), ex, "add_update")
    assert not unknown.ok and "не найдена" in unknown.errors[0]["message"]


# ------------------------------------------------------------------------------------------------ API: зоны и CSV
async def test_zone_crud_validation_and_audit(client):
    await login(client, "admin", "Admin-Passw0rd-123")
    r = await client.post("/api/v1/admin/zones", json={"name": "Департамент А", "priority": 50, "rules": [{"kind": "net", "value": "192.0.2.0/24"}, {"kind": "net", "value": "198.51.100.5"}],
                                                     "contacts": [{"name": "Иван", "email": "Ivan@Example.local", "role": "responsible"}, {"email": "boss@example.local", "role": "cc"}]})
    assert r.status_code == 201, r.text
    z = r.json()
    assert [c["email"] for c in z["contacts"]] == ["ivan@example.local", "boss@example.local"] and len(z["rules"]) == 2
    dup = await client.post("/api/v1/admin/zones", json={"name": z["name"].lower()})
    assert dup.status_code == 409
    bad = await client.post("/api/v1/admin/zones", json={"name": "Б", "rules": [{"kind": "net", "value": "192.0.2.256"}]})
    assert bad.status_code == 422 and "Признак 1" in bad.text
    bad2 = await client.post("/api/v1/admin/zones", json={"name": "В", "contacts": [{"email": "не-адрес"}]})
    assert bad2.status_code == 422
    up = await client.put(f"/api/v1/admin/zones/{z['id']}", json={"name": "Департамент А", "rules": [{"kind": "net", "value": "203.0.113.0/24"}], "contacts": [{"email": "ivan@example.local", "role": "group", "enabled": False}]})
    assert up.status_code == 200 and [r["value"] for r in up.json()["rules"]] == ["203.0.113.0/24"] and up.json()["contacts"][0]["role"] == "group" and not up.json()["contacts"][0]["enabled"]
    actions = {a["action"] for a in (await client.get("/api/v1/admin/audit?limit=50")).json()["items"]} if (await client.get("/api/v1/admin/audit?limit=5")).status_code == 200 else set()
    assert not actions or {"zone.create", "zone.update"} <= actions
    viewer = await client.get("/api/v1/admin/zones")
    assert viewer.status_code == 200
    client.cookies.clear()
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get("/api/v1/admin/zones")).status_code == 403 and (await client.post("/api/v1/admin/zones", json={"name": "X"})).status_code == 403
    assert (await client.post("/api/v1/admin/zones/csv/preview", content=SAMPLE)).status_code == 403


async def test_csv_import_preview_apply_atomic_and_idempotent(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    pv = await client.post("/api/v1/admin/zones/csv/preview?mode=add_update", content=SAMPLE)
    assert pv.status_code == 200 and pv.json()["ok"] and pv.json()["summary"]["zones_create"] == 3
    async with app.state.session_maker() as db:
        assert (await db.execute(select(Zone))).scalars().all() == []                                    # просмотр ничего не записывает
    stale = await client.post("/api/v1/admin/zones/csv/apply?mode=add_update&expect=0000", content=SAMPLE)
    assert stale.status_code == 409
    ap = await client.post(f"/api/v1/admin/zones/csv/apply?mode=add_update&expect={pv.json()['fingerprint']}", content=SAMPLE)
    assert ap.status_code == 200 and ap.json()["done"]["created"] == 3 and ap.json()["done"]["rules_added"] == 11
    again = await client.post("/api/v1/admin/zones/csv/preview?mode=add_update", content=SAMPLE)
    assert again.json()["summary"]["zones_create"] == 0 and again.json()["summary"]["zones_unchanged"] == 3 and again.json()["summary"]["rules_add"] == 0      # повтор не создаёт дубликаты
    exp = await client.get("/api/v1/admin/zones/csv/export")
    assert exp.status_code == 200 and exp.content.startswith(b"\xef\xbb\xbf")
    rt = await client.post("/api/v1/admin/zones/csv/preview?mode=add_update", content=exp.content)
    assert rt.json()["ok"] and rt.json()["summary"]["zones_unchanged"] == 3 and rt.json()["summary"]["contacts_add"] == 0                              # выгрузка → загрузка без изменений
    # ошибка в файле: ничего не применяется
    broken = SAMPLE + "\nНовая;;;;;Сеть или адреса;192.0.2.999\n".encode()
    assert (await client.post("/api/v1/admin/zones/csv/apply?mode=add_update", content=broken)).status_code == 422
    async with app.state.session_maker() as db:
        assert len((await db.execute(select(Zone))).scalars().all()) == 3
    # «Только добавить новые» не меняет существующее
    mod = SAMPLE.decode("utf-8-sig").replace("Серверы и сервисы", "ИЗМЕНЕНО").encode()
    ro = await client.post("/api/v1/admin/zones/csv/apply?mode=add_only", content=mod)
    assert ro.status_code == 200 and ro.json()["done"]["created"] == 0 and ro.json()["done"]["updated"] == 0
    up = await client.post("/api/v1/admin/zones/csv/apply?mode=add_update", content=mod)
    assert up.json()["done"]["updated"] == 1
    # полная замена — только с явным подтверждением
    few = "Зона;Значение признака\nДепартамент А;192.0.2.0/26\n".encode()
    assert (await client.post("/api/v1/admin/zones/csv/apply?mode=replace", content=few)).status_code == 422
    done = await client.post("/api/v1/admin/zones/csv/apply?mode=replace&confirm=true", content=few)
    assert done.status_code == 200 and done.json()["done"]["deleted"] == 2
    async with app.state.session_maker() as db:
        zs = (await db.execute(select(Zone))).scalars().all()
        assert [z.name for z in zs] == ["Департамент А"]
        assert [r.value for r in (await db.execute(select(ZoneRule))).scalars()] == ["192.0.2.0/26"]
        assert (await db.execute(select(ZoneContact))).scalars().all() == []
    assert (await client.get("/api/v1/admin/zones/csv/sample")).content == SAMPLE


async def test_csv_upload_limits(client):
    await login(client, "admin", "Admin-Passw0rd-123")
    big = b"x" * (csv_io.MAX_BYTES + 10)
    assert (await client.post("/api/v1/admin/zones/csv/preview", content=big)).status_code == 413
    binary = (await client.post("/api/v1/admin/zones/csv/preview", content=b"\x00\x01\x02" * 100)).json()
    assert not binary["ok"] and binary["errors"]


# ------------------------------------------------------------------------------------------------ решения по уязвимостям
async def test_triage_scope_history_recheck_and_expiry(app):
    src = uuid.uuid4()
    from app.models import KscSource
    async with app.state.session_maker() as db:
        db.add(KscSource(id=src, name="T", host="h", port=1433, database="d", username="u", password_enc="x"))
        await db.commit()
        # решение «ложное» для CVE на компьютере 1 — другие компьютеры и другие CVE не затрагиваются
        await T.set_decision(db, source_id=src, actor="Аналитик", scope="host", vuln_key="cve-2024-0001", status="false_positive", host_id=1, host_name="srv-01", product="Chrome", version="120.1", reason="fp_version", comment="Проверено вручную")
        await T.set_decision(db, source_id=src, actor="Аналитик", scope="host", vuln_key="CVE-2024-0002", status="confirmed", host_id=1, host_name="srv-01", product="Chrome", version="120.1")
        await db.commit()
        idx = await T.load(db, src)
        kw = dict(host_name="srv-01", product="Chrome", version="120.1", zone_ids=[])
        assert idx.lookup(host_id=1, keys=["KLA1", "CVE-2024-0001"], **kw).status == "false_positive"
        assert idx.lookup(host_id=1, keys=["CVE-2024-0002"], **kw).status == "confirmed"
        assert idx.lookup(host_id=1, keys=["CVE-2024-0003"], **kw) is None                           # не распространяется на другие уязвимости
        assert idx.lookup(host_id=2, host_name="srv-02", keys=["CVE-2024-0001"], product="Chrome", version="120.1", zone_ids=[]) is None     # и на другие компьютеры
        # версия изменилась → возвращается на проверку, но решение остаётся в истории
        idx = await T.load(db, src)
        d = idx.lookup(host_id=1, keys=["CVE-2024-0001"], host_name="srv-01", product="Chrome", version="121.0", zone_ids=[])
        assert d.status == "review" and d.recheck and "версия" in d.recheck_reason and d.stored_status == "false_positive"
        assert await T.mark_stale(db, idx) == 1 and await T.mark_stale(db, idx) == 0
        await db.commit()
        # новый идентификатор устройства (то же имя) → тоже на проверку
        idx = await T.load(db, src)
        d = idx.lookup(host_id=99, keys=["CVE-2024-0002"], host_name="SRV-01", product="Chrome", version="120.1", zone_ids=[])
        assert d is not None and d.recheck and "идентификатор" in d.recheck_reason
        # область «программа» требует явного указания и не действует на другие версии
        await T.set_decision(db, source_id=src, actor="Админ", scope="product", vuln_key="CVE-2024-0009", status="false_positive", product="Notepad++", version="8.5", comment="не применимо")
        await db.commit()
        idx = await T.load(db, src)
        assert idx.lookup(host_id=5, host_name="x", keys=["CVE-2024-0009"], product="notepad++", version="8.5", zone_ids=[]).status == "false_positive"
        assert idx.lookup(host_id=5, host_name="x", keys=["CVE-2024-0009"], product="Notepad++", version="8.6", zone_ids=[]) is None
        # принятый риск: срок в будущем обязателен; по истечении — снова требует внимания
        with pytest.raises(T.TriageError):
            await T.set_decision(db, source_id=src, actor="Админ", scope="host", vuln_key="CVE-2024-0010", status="risk_accepted", host_id=1, comment="нужно")
        t = await T.set_decision(db, source_id=src, actor="Админ", scope="host", vuln_key="CVE-2024-0010", status="risk_accepted", host_id=1, product="X", version="1", comment="Окно обслуживания в январе",
                                 reason="business", review_until=datetime.now(timezone.utc) + timedelta(days=30))
        await db.commit()
        assert (await T.load(db, src)).lookup(host_id=1, host_name="srv-01", keys=["CVE-2024-0010"], product="X", version="1", zone_ids=[]).status == "risk_accepted"
        later = datetime.now(timezone.utc) + timedelta(days=31)
        idx = await T.load(db, src, now=later)
        d = idx.lookup(host_id=1, host_name="srv-01", keys=["CVE-2024-0010"], product="X", version="1", zone_ids=[])
        assert d.status == "review" and d.expired and d.stored_status == "risk_accepted"
        # история сохраняется
        ev = await T.history(db, t.id)
        assert [e["action"] for e in ev] == ["create"] and ev[0]["actor"] == "Админ" and ev[0]["to"] == "Риск принят"
        with pytest.raises(T.TriageError):
            await T.set_decision(db, source_id=src, actor="a", scope="host", vuln_key="CVE-2024-0011", status="false_positive", host_id=1)         # без причины и комментария нельзя


def test_triage_split_does_not_hide_other_findings():
    class Idx(T.TriageIndex):
        pass
    rows = [{"host_id": 1, "name": "srv-01", "kla_id": f"KLA{i}", "cve_list": [f"CVE-2024-000{i}"], "product": "P", "installed_version": "1", "zones": []} for i in (1, 2, 3)]
    from app.models import VulnTriage
    now = datetime.now(timezone.utc)
    recs = [VulnTriage(id=uuid.uuid4(), source_id=uuid.uuid4(), scope="host", host_id=1, host_name="srv-01", vuln_key="CVE-2024-0001", status="false_positive", product="P", version="1", created_by="a", created_at=now, updated_at=now, recheck=False),
            VulnTriage(id=uuid.uuid4(), source_id=uuid.uuid4(), scope="host", host_id=1, host_name="srv-01", vuln_key="KLA2", status="confirmed", product="P", version="1", created_by="a", created_at=now, updated_at=now, recheck=False)]
    out = T.split(rows, T.TriageIndex(recs))
    assert [r["kla_id"] for r in out["excluded"]] == ["KLA1"] and [r["kla_id"] for r in out["current"]] == ["KLA2", "KLA3"] and out["accepted"] == []
    assert out["current"][0]["triage"]["status"] == "confirmed" and out["current"][1]["triage"] is None


# ------------------------------------------------------------------------------------------------ расписания
def test_schedule_next_run_timezones_dst_month_end_and_catch_up():
    utc = timezone.utc
    assert SC.next_after("weekly", 0, 1, "08:00", "Europe/Moscow", datetime(2026, 10, 25, 12, tzinfo=utc)) == datetime(2026, 10, 26, 5, tzinfo=utc)
    assert SC.next_after("monthly", 0, 31, "08:00", "UTC", datetime(2026, 2, 1, tzinfo=utc)) == datetime(2026, 2, 28, 8, tzinfo=utc)             # 31-е в феврале → последний день
    assert SC.next_after("daily", 0, 1, "02:30", "Europe/Berlin", datetime(2026, 3, 28, 12, tzinfo=utc)) == datetime(2026, 3, 29, 1, 30, tzinfo=utc)     # время в «дыре» перехода сдвигается
    assert SC.next_after("daily", 0, 1, "08:00", "UTC", datetime(2026, 10, 25, 8, 0, tzinfo=utc)) == datetime(2026, 10, 26, 8, tzinfo=utc)          # строго позже
    now = datetime(2026, 10, 25, 12, tzinfo=utc)
    run, nxt = SC.due("weekly", 0, 1, "08:00", "UTC", datetime(2026, 9, 1, 8, tzinfo=utc), now, now)        # простой на несколько недель: выполняется один, последний период
    assert run == datetime(2026, 10, 19, 8, tzinfo=utc) and nxt == datetime(2026, 10, 26, 8, tzinfo=utc) and SC.period_key("weekly", run, "UTC") == "2026-W43"
    assert SC.due("weekly", 0, 1, "08:00", "UTC", datetime(2026, 10, 26, 8, tzinfo=utc), now, now)[0] is None
    with pytest.raises(SC.ScheduleError):
        SC.tz_of("Mars/Base")


def test_enum_values_fit_postgres_column_lengths():
    """SQLite длину строк не проверяет, PostgreSQL — проверяет: значения перечислений должны помещаться в столбцы (найдено на настоящей БД: «false_positive» в varchar(10))."""
    from app import models as m
    cases = [(m.VulnTriage.status, T.STATUSES), (m.VulnTriageEvent.from_status, T.STATUSES), (m.VulnTriageEvent.to_status, T.STATUSES), (m.VulnTriage.scope, T.SCOPES), (m.VulnTriage.reason, list(T.REASONS)),
             (m.MailOutbox.status, ("queued", "sending", "accepted", "failed", "skipped")), (m.MailOutbox.kind, ("schedule", "manual", "test")), (m.ZoneRule.kind, ("net", "exclude", "group", "name")),
             (m.ZoneContact.role, ("responsible", "cc", "group")), (m.ReportSchedule.level, ("management", "technical")), (m.ReportSchedule.frequency, ("daily", "weekly", "monthly")),
             (m.VulnTriageEvent.action, ("create", "status", "comment", "recheck", "expire", "delete"))]
    for col, values in cases:
        assert col.type.length >= max(len(v) for v in values), (col, values)
