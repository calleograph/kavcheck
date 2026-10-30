"""Готовые отчёты по иерархии на синтетической структуре (1 222 записи → 1 156 сотрудников, 51 подразделение): численность согласуется с правилами, проверки показывают основание, а не выводы."""
import uuid
from datetime import datetime, timezone

import openpyxl
import pytest

from app.hier import process as P
from app.reports import quick, quick_export
from app.reports.quick_hier import build_doc
from app.services.settings import HierSettings
from tests.conftest import login
from tests.hier_big import big_records
from tests.hier_data import DOMAIN
from tests.test_hier import RULES, upload, users

NOW = datetime(2026, 10, 30, 9, 0, tzinfo=timezone.utc)
CFG = HierSettings(internal_domains=[DOMAIN], big_group=40)


@pytest.fixture(scope="module")
def data():
    rows, exp = big_records()
    return P.build([[r[k] for k in P.FIELDS] for r in rows], RULES), exp


def tb(res, view, cfg=CFG, ext=None, **p):
    d = build_doc(res, {"view": view, **p}, NOW, "файл", cfg, ext)
    return d, {t["id"]: t["rows"] for t in d["tables"]}


def test_counts_agree_with_inclusion_rules(data):
    res, exp = data
    assert exp["raw"] == res.raw_n == len(res.people) + sum(res.excluded.values()) == len(res.people) + len(res.dropped)
    d, t = tb(res, "people")
    assert len(t["rows"]) == len(res.people) == 1156 and d["metrics"][0]["value"] == 1156
    _, q = tb(res, "quality")
    summ = {r["metric"]: r["value"] for r in q["summary"]}
    assert summ["Записей в адресной книге"] == 1222 and summ["Включено в структуру"] == 1156
    assert summ["Исключено: внешний домен"] == 25 and summ["Исключено: пустая карточка"] == 30 and summ["Исключено: служебная учётная запись"] == 10
    assert summ["Карточек заполнено полностью"] + summ["Карточек с пропусками"] == 1156
    # происхождение подразделения учитывается отдельно и пустое поле карточки не скрывается подстановкой
    assert summ["Подразделение: определено по руководителю"] >= 30
    miss = [r for r in q["rows"] if r["issue"] == "Нет подразделения в карточке"]
    assert len(miss) >= 30 and all(r["origin"] in ("Определено по руководителю", "Не определено") for r in miss)
    assert sum(summ[k] for k in ("Подразделение: из карточки", "Подразделение: определено по руководителю", "Подразделение: не определено")) == 1156
    issues = {r["issue"] for r in q["rows"]}
    assert {"Руководитель не указан", "Круг в подчинении", "Руководитель не найден", "Нет должности", "Подразделение не подтверждено"} <= issues


def test_filters_modes_sum_up(data):
    res, _ = data
    whole = len(tb(res, "people")[1]["rows"])
    names = [d["name"] for d in res.depts]
    by_dept = sum(len(tb(res, "people", dept=n)[1]["rows"]) for n in names)
    assert by_dept == whole                                                                                      # подразделения не пересекаются и не теряют людей
    head = next(p for p in res.people if p["head"])
    branch = tb(res, "people", branch=head["id"])[1]["rows"]
    direct = tb(res, "people", branch=head["id"], direct=True)[1]["rows"]
    assert len(direct) == sum(1 for p in res.people if p["mgr"] >= 0 and res.people[p["mgr"]]["id"] == head["id"]) + 1 and len(branch) == head["size"]


def test_departments_variants_not_merged_until_admin_confirms(data):
    res, _ = data
    d, t = tb(res, "depts")
    var = next(r for r in t["variants"] if "Департамент продаж" in r["spellings"])
    assert var["variants"] >= 3 and var["state"].startswith("Требует проверки") and "Отдел Продаж" in var["spellings"]
    assert any(r["dept"] == "Департамент продаж" for r in t["rows"]) and any(r["dept"] == "Отдел Продаж" for r in t["rows"])          # не объединены сами
    lead = next(r for r in t["rows"] if r["dept"] == "Отдел Закупок")
    assert lead["n"] > 60 and lead["lead_direct"] > 60 and lead["card"] + lead["inherited"] + lead["undef"] == lead["n"]
    conf = HierSettings(internal_domains=[DOMAIN], dept_map={"Департамент продаж": "Отдел Продаж", "отдел  продаж ": "Отдел Продаж"})
    res2 = P.build([[r[k] for k in P.FIELDS] for r in big_records()[0]], P.Rules(domains=(DOMAIN,), dept_map=conf.dept_map))
    _, t2 = tb(res2, "depts", conf)
    assert next(r for r in t2["variants"] if "Департамент продаж" in r["spellings"])["state"].startswith("Подтверждено")
    assert sum(1 for r in t2["rows"] if "продаж" in r["dept"].lower()) == 1


def test_managers_roles_crossdept_dups(data):
    res, _ = data
    _, m = tb(res, "managers")
    top = m["rows"][0]
    assert top["direct"] >= 65 and "большая группа" in top["flags"] and top["verdict"] == "Требует проверки" and [r["direct"] for r in m["rows"]] == sorted((r["direct"] for r in m["rows"]), reverse=True)
    assert top["depth"] >= 1
    _, r = tb(res, "roles")
    kinds = {x["finding"] for x in r["rows"]}
    assert any("подчинённых в выгрузке нет" in k for k in kinds) and any("должность обычно неруководящая" in k for k in kinds) and all(x["status"] == "Требует проверки" for x in r["rows"])
    assert any(x["name"].startswith("Директор по") or x["title"] == "Директор по развитию" for x in r["rows"])
    _, c = tb(res, "crossdept")
    big = max(c["rows"], key=lambda x: x["pair_n"])
    assert big["pair_n"] == 12 and any(x["pair_n"] == 1 for x in c["rows"]) and all(x["status"] == "Требует проверки" for x in c["rows"])
    one = next(x for x in c["rows"] if x["pair_n"] == 1)
    hid = next(p["id"] for p in res.people if p["email"] == one["email"])
    cfg = HierSettings(internal_domains=[DOMAIN], reviewed=[hid])
    _, c2 = tb(res, "crossdept", cfg)
    assert len(c2["rows"]) == len(c["rows"]) - 1 and one["email"] not in {x["email"] for x in c2["rows"]}                        # проверенное исключение не возвращается
    _, c3 = tb(res, "crossdept", cfg, include_reviewed=True)
    assert len(c3["rows"]) == len(c["rows"]) and next(x for x in c3["rows"] if x["email"] == one["email"])["status"] == "Проверено, исключение"
    _, d = tb(res, "dups")
    bs = [x["basis"] for x in d["rows"]]
    assert any(b.startswith("Одинаковое ФИО у 2") for b in bs) and any("Повторяющийся адрес" in b for b in bs) and any("нескольких сотрудников" in b for b in bs)
    assert all(x["status"] == "Требует проверки" for x in d["rows"]) and "не означают" in d_note(res)


def d_note(res):
    return build_doc(res, {"view": "dups"}, NOW, "файл", CFG)["tables"][0]["note"]


def test_service_report_explains_every_exclusion(data):
    res, _ = data
    d, t = tb(res, "service")
    exc = [r for r in t["rows"] if r["kind"] == "Исключена из структуры"]
    assert len(exc) == len(res.dropped) == 66 and all(r["explain"] for r in exc)
    assert any("support" in r["explain"] and r["reason"] == "Совпало правило служебной записи" for r in exc)
    assert any("partner.example" in r["explain"] for r in exc)
    person = [r for r in exc if r["person"].startswith("да")]
    assert 5 <= len(person) <= 40                                                                                            # среди исключённых есть люди, которых стоит проверить
    assert sum(r["n"] for r in t["by_reason"]) == 66
    inc = [r for r in t["rows"] if r["kind"] == "Включена, неполная"]
    assert inc and all(r["explain"].startswith("не хватает") for r in inc)


def test_changes_between_snapshots(data):
    res, _ = data
    rows, _ = big_records()
    rows = [dict(r) for r in rows]
    victim = next(r for r in rows if r["JobTitle"] == "Инженер" and r["Department"].startswith("Отдел") and r["Email"].endswith(DOMAIN))
    gone = next(r for r in rows if r["JobTitle"] == "Аналитик" and r["Email"].endswith(DOMAIN) and r["Manager"] and r["Manager"] != r["Name"])
    victim["JobTitle"] = "Ведущий инженер"
    victim["Department"] = "Отдел Закупок"
    rows.remove(gone)
    mover = next(r for r in rows if r["JobTitle"] == "Начальник отдела Логистики")
    other = next(r for r in rows if r["JobTitle"] == "Начальник отдела Продаж")
    mover["Manager"], mover["ManagerEmail"] = other["Name"], other["Email"]
    rows.append({**gone, "Email": "new1@" + DOMAIN, "Name": "Новиков Новый Новикович"})
    new = P.build([[r[k] for k in P.FIELDS] for r in rows], RULES)
    old, _ = data
    d, t = tb(new, "changes", CFG, ext={"base": (old, NOW), "raw_emails": {r["Email"].lower() for r in rows}})
    kinds = {r["kind"] for r in t["rows"]}
    assert {"Появилась карточка", "Исчезла карточка", "Изменился руководитель", "Перемещена ветка", "Изменилась должность"} <= kinds
    assert all("не кадровое событие" in r["note"] or "не означает" in r["note"] or "Изменение данных Exchange" in r["note"] for r in t["rows"])
    assert any("не означает увольнение" in r["note"] for r in t["rows"] if r["kind"] == "Исчезла карточка")
    assert next(r for r in t["rows"] if r["kind"] == "Перемещена ветка")["new"] == other["Name"]
    with pytest.raises(Exception, match="предыдущей"):
        tb(new, "changes", CFG)


def test_pack_has_a_sheet_per_analytic_report_and_xlsx_roundtrip(data, tmp_path):
    res, _ = data
    old, _ = data
    d = build_doc(res, {"view": "pack"}, NOW, "файл", CFG, {"base": (old, NOW), "raw_emails": set()})
    ids = [t["id"] for t in d["tables"]]
    assert {"depts_rows", "depts_variants", "managers_rows", "roles_rows", "crossdept_rows", "dups_rows", "service_rows", "service_by_reason", "quality_rows", "quality_summary", "changes_rows"} <= set(ids)
    full = quick.shape("quick_hier", {**d, "kind": "quick_hier", "generated_at": NOW.isoformat(), "source": "", "meta": []}, {})
    f = tmp_path / "pack.xlsx"
    quick_export.write_xlsx(f, full)
    names = openpyxl.load_workbook(f, read_only=True).sheetnames
    assert len(names) >= 10 and any("Руководители" in n for n in names) and any("Качество" in n for n in names)
    html = quick_export.render_html(full)
    assert "Дубликаты и подозрительные карточки" in html and "Требует проверки" in html


def test_sort_and_group_apply_to_any_view(data):
    res, _ = data
    d = build_doc(res, {"view": "people"}, NOW, "файл", CFG)
    out = quick.shape("quick_hier", d, {"sort": "branch", "desc": True, "group": "dept_origin"})
    rows = out["tables"][0]["rows"]
    assert [r["dept_origin"] for r in rows] == sorted(r["dept_origin"] for r in rows)
    first = [r["branch"] for r in rows if r["dept_origin"] == rows[0]["dept_origin"]]
    assert first == sorted(first, reverse=True)
    g = next(t for t in out["tables"] if t["id"] == "grouped")
    assert sum(r["n"] for r in g["rows"]) == len(rows)
    assert len(quick.shape("quick_hier", d, {"sort": "нет_такого"})["tables"]) == len(d["tables"])           # неизвестный столбец игнорируется


async def test_api_views_snapshots_review_and_permissions(client, app):
    await users(app)
    await login(client, "admin", "Admin-Passw0rd-123")
    await client.put("/api/v1/admin/settings/hier", json={"internal_domains": [DOMAIN], "roles": ["analyst", "admin"], "big_group": 40})
    import json as js
    rows, _ = big_records()
    up = await client.post("/api/v1/hier/admin/upload", content=js.dumps(rows).encode(), headers={"Content-Type": "application/octet-stream"})
    assert up.status_code == 200 and up.json()["status"] == "ok"
    for view in ("people", "tree", "depts", "managers", "roles", "crossdept", "dups", "service", "quality", "problems", "pack"):
        r = await client.post("/api/v1/quick/preview", json={"kind": "quick_hier", "params": {"view": view}})
        assert r.status_code == 200, (view, r.text)
    ch = await client.post("/api/v1/quick/preview", json={"kind": "quick_hier", "params": {"view": "changes"}})
    assert ch.status_code == 409 and "предыдущей" in ch.text                                                          # одна выгрузка: сравнивать не с чем, причина названа
    assert len((await client.get("/api/v1/hier/snapshots")).json()["items"]) == 1
    data = (await client.get("/api/v1/hier/data")).json()
    pid = next(p[0] for p in data["people"])
    assert (await client.post("/api/v1/hier/review", json={"id": pid, "on": True})).json()["reviewed"] == 1
    assert (await client.get("/api/v1/hier/data")).json()["reviewed"] == [pid]
    assert (await client.post("/api/v1/hier/review", json={"id": "0" * 10, "on": True})).status_code == 404
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.post("/api/v1/hier/review", json={"id": pid, "on": False})).status_code == 403
    assert (await client.get("/api/v1/hier/snapshots")).status_code == 403
