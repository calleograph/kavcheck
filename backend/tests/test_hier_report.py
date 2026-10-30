"""Отчёты раздела «Иерархия. Предприятие» (вид quick_hier): содержание на вымышленной выгрузке, фильтры страницы, структура в HTML и PDF, права по ролям."""
import uuid
from datetime import datetime, timezone

from app.hier import process as P
from app.reports import quick, quick_export, quick_pdf
from app.reports.quick_hier import build_doc
from tests.conftest import login
from tests.hier_data import DOMAIN, demo_records
from tests.test_hier import RULES, recs, upload, users

NOW = datetime(2026, 10, 30, 9, 0, tzinfo=timezone.utc)


def test_people_report_has_everyone_with_chain_and_no_truncation():
    d = build_doc(P.build(recs(), RULES), {"view": "people"}, NOW, "файл")
    rows = d["tables"][0]["rows"]
    assert len(rows) == 279 and d["metrics"][0]["value"] == 279
    by = {r["name"]: r for r in rows}
    ceo = by["Ершов Павел Павлович"]
    assert ceo["status"] == "верхний руководитель" and ceo["level"] == 1 and ceo["branch"] > 100 and ceo["manager"] == ""
    sub = next(r for r in rows if r["name"].startswith("Руководов00"))
    assert sub["level"] == 3 and sub["top"] == "Ершов Павел Павлович" and sub["chain"].count("→") == 1 and "Ершов П. П." in sub["chain"]
    assert by["Кругов Алексей Алексеевич"]["status"] == "круг в подчинении" and by["Кругов Алексей Алексеевич"]["level"] is None
    assert "+" not in "".join(str(r["chain"]) for r in rows[:50])


def test_filters_match_the_page():
    res = P.build(recs(), RULES)
    ceo_id = next(x["id"] for x in res.people if x["head"])
    branch = build_doc(res, {"view": "people", "branch": ceo_id}, NOW, "файл")["tables"][0]["rows"]
    assert 100 < len(branch) < 279                                                                  # ветка верхнего руководителя — без людей вне структуры
    q = build_doc(res, {"view": "people", "q": "руководов00"}, NOW, "файл")["tables"][0]["rows"]
    assert q and all("руководов00" in r["name"].casefold() for r in q)
    dept = res.depts[0]["name"]
    only = build_doc(res, {"view": "people", "dept": dept}, NOW, "файл")["tables"][0]["rows"]
    assert len(only) == res.depts[0]["n"] and all(r["dept"].startswith(dept) for r in only)


def test_problems_and_depts_views():
    res = P.build(recs(), RULES)
    pr = build_doc(res, {"view": "problems"}, NOW, "файл")["tables"][0]["rows"]
    assert len(pr) == len(res.lone) and {"Кругов Алексей Алексеевич", "Двойнов Борис Борисович"} <= {r["name"] for r in pr} and all(r["why"] for r in pr)
    dp = build_doc(res, {"view": "depts"}, NOW, "файл")["tables"][0]["rows"]
    assert sum(r["n"] for r in dp) == 279 and dp[0]["n"] >= dp[1]["n"]


def test_tree_has_complete_chart_in_html_and_pdf(tmp_path):
    d = build_doc(P.build(recs(), RULES), {"view": "tree"}, NOW, "файл")
    org = d["chart"]
    assert len(org["main"]) + len(org["lone"]) == 279 and org["main"][0]["lv"] == 0 and org["main"][0]["name"] == "Ершов Павел Павлович"
    full = quick.shape("quick_hier", {**d, "kind": "quick_hier", "generated_at": NOW.isoformat(), "source": "", "meta": []}, {})
    out = quick_export.render_html(full)
    assert out.count('class="oc-c"') == 279 and out.count("<details") == out.count("</details>") and 'id="chart"' in out
    assert "Ершов Павел Павлович" in out and "Руководитель не указан или не найден" in out and "<table" not in out.split('id="chart"')[1].split("</section>")[0]
    pdf = tmp_path / "t.pdf"
    quick_pdf.write_pdf(pdf, full)
    assert pdf.read_bytes()[:4] == b"%PDF" and pdf.stat().st_size > 5000
    xl = tmp_path / "t.xlsx"
    quick_export.write_xlsx(xl, full)
    assert xl.stat().st_size > 3000


def test_deep_chain_does_not_break_html_or_recursion():
    n = 3000
    rows = [[f"Ч{i:04d} Иван Иванович", f"c{i}@{DOMAIN}", "Должность", "Отдел", "", "", f"Ч{i - 1:04d} Иван Иванович" if i else "", f"c{i - 1}@{DOMAIN}" if i else f"c0@{DOMAIN}"] for i in range(n)]
    d = build_doc(P.build(rows, P.Rules(domains=(DOMAIN,))), {"view": "tree"}, NOW, "файл")
    out = quick_export.render_html(quick.shape("quick_hier", {**d, "kind": "quick_hier", "generated_at": NOW.isoformat(), "source": "", "meta": []}, {}))
    assert out.count('class="oc-c"') == n and out.count("<details") == out.count("</details>")
    assert max(len(r["chain"]) for r in d["tables"][0]["rows"]) < 25 * 40


async def test_preview_and_job_are_limited_to_allowed_roles(client, app):
    await users(app)
    await login(client, "admin", "Admin-Passw0rd-123")
    await client.put("/api/v1/admin/settings/hier", json={"internal_domains": [DOMAIN], "roles": ["analyst", "admin"]})
    assert (await upload(client)).status_code == 200
    ok = await client.post("/api/v1/quick/preview", json={"kind": "quick_hier", "params": {"view": "tree"}})
    j = ok.json()
    assert ok.status_code == 200 and j["total"] == 279 and "chart" not in j["doc"] and j["doc"]["title"] == "Структура подчинения"
    assert (await client.post("/api/v1/quick/preview", json={"kind": "quick_hier", "params": {"view": "bad"}})).status_code == 422
    made = await client.post("/api/v1/reports", json={"kind": "quick_hier", "params": {"view": "tree"}})
    assert made.status_code == 201 and made.json()["kind"] == "quick_hier"
    from app.models import ReportJob  # noqa: PLC0415
    from app.reports.runner import Runner  # noqa: PLC0415

    rid = made.json()["id"]
    async with app.state.session_maker() as db:                                                       # задание исполняет worker: полный путь от параметров до файлов
        await Runner(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal)._execute_quick(await db.get(ReportJob, uuid.UUID(rid)))
    assert (await client.get(f"/api/v1/reports/{rid}")).json()["status"] == "done"
    page = (await client.get(f"/api/v1/reports/{rid}/download/html")).text
    assert page.count('class="oc-c"') == 279 and "KAV Checker" in page
    assert (await client.get(f"/api/v1/reports/{rid}/download/pdf")).content[:5] == b"%PDF-" and (await client.get(f"/api/v1/reports/{rid}/download/xlsx")).content[:2] == b"PK"
    assert "Прямых подчинённых".encode() in (await client.get(f"/api/v1/reports/{rid}/download/csv")).content
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.post("/api/v1/quick/preview", json={"kind": "quick_hier", "params": {}})).status_code == 403
    await login(client, "admin", "Admin-Passw0rd-123")
    await client.put("/api/v1/admin/settings/hier", json={"roles": ["viewer", "admin"]})
    await login(client, "analyst1", "Analyst-Passw0rd-123")
    assert (await client.post("/api/v1/quick/preview", json={"kind": "quick_hier", "params": {}})).status_code == 403            # роль убрана — отчёт недоступен так же, как раздел
    assert (await client.post("/api/v1/reports", json={"kind": "quick_hier", "params": {}})).status_code == 403
