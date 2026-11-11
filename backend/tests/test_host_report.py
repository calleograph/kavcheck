"""Отчёт по компьютеру совпадает с карточкой: ПО, защита, уязвимости KSC и по внешним базам, EOL, события за 30 суток, аппаратная часть.
Источник отчёта — источник открытой страницы (заголовок X-Source-Id). Недоступные разделы названы явно, а не показаны нулями."""
import uuid

import pytest
from sqlalchemy import func, select

from app.eol import compute as C
from app.eol.sync import apply_products
from app.models import KscSource
from app.reports.runner import job_dir
from tests.test_audit_e2e import _run, _setup
from tests.test_eol_compute import DOC, TODAY
from tests.test_ksc_live import HOST, params

pytestmark = pytest.mark.skipif(not HOST, reason="нет синтетической базы KSC (KSC_TEST_HOST)")
HOSTS = (1, 5, 6, 7)                       # ksc-server (ОС без данных), old-srv, ws-001, ws-002: разные состояния защиты, уязвимости, ПО и EOL


async def _job(client, app, runner, sid, host_id, sections=None, header=None):
    body = {"kind": "quick_hosts", "title": "", "params": {"host_ids": [host_id], **({"sections": sections} if sections is not None else {})}, "source_ids": []}
    r = await client.post("/api/v1/reports", json=body, headers={"X-Source-Id": str(header or sid)})
    assert r.status_code == 201, r.text
    job = r.json()
    await _run(app, runner, job["id"])
    done = (await client.get(f"/api/v1/reports/{job['id']}")).json()
    assert done["status"] == "done", done
    return job["id"]


def _tables(rid, app):  # noqa: D103
    from openpyxl import load_workbook
    return load_workbook(job_dir(app.state.settings, uuid.UUID(rid)) / "report.xlsx", read_only=True)


async def test_host_report_matches_the_card(client, app):
    sid, runner = await _setup(client, app)
    sm = app.state.session_maker
    await apply_products(sm, DOC["result"])
    async with sm() as db:
        src = await db.get(KscSource, uuid.UUID(sid))
    await C.compute_source(sm, app.state.sources.client(src), src, activity_days=30, today=TODAY)          # EOL по этому источнику (как ночной расчёт)
    from app.vdb.sync import analyze                                                                             # подготовленные результаты внешних баз (как расчёт воркера)
    async with sm() as db:
        await analyze(db, uuid.UUID(sid), None)
        await db.commit()
    totals = []
    for hid in HOSTS:
        card = (await client.get(f"/api/v1/hosts/{hid}")).json()
        vul = (await client.get(f"/api/v1/hosts/{hid}/vulnerabilities")).json()["counts"]                    # как в карточке: KSC и внешние базы
        eol = (await client.get(f"/api/v1/eol/hosts/{sid}/{hid}")).json()["items"]
        ev = (await client.get("/api/v1/events", params={"days": 30, "host_id": hid, "limit": 50})).json()["total"]
        hw = (await client.get(f"/api/v1/hosts/{hid}/hardware")).json()["hw"]
        rid = await _job(client, app, runner, sid, hid)
        wb = _tables(rid, app)
        rows = {t: list(wb[t].iter_rows(values_only=True)) for t in wb.sheetnames}
        host = next(r for r in (await client.get(f"/api/v1/reports/{rid}/rows", params={"limit": 5})).json()["items"])
        assert host["software"] == len(card["software"]), (hid, "ПО")
        assert host["v_total"] == vul["total"] and host["v_critical"] == vul["critical"] and host["v_high"] == vul["high"] and host["v_warning"] == vul["warning"], (hid, "уязвимости", host, vul)
        assert host["eol_n"] == len(eol), (hid, "EOL")
        assert host["events_n"] == ev, (hid, "события")
        assert host["hardware"] == hw["line"], (hid, "аппаратная часть")
        assert host["problems_n"] == len(card["host"]["protection"]["problems"] if card["host"].get("protection") else []), (hid, "защита")
        assert len(rows["Установленное ПО"]) - 1 == len(card["software"]), "ПО в Excel полностью"
        assert len(rows["Уязвимости"]) - 1 == vul["total"], "уязвимости в Excel полностью"
        if eol:
            assert len(rows["EOL"]) - 1 == len(eol), "EOL в Excel полностью"
        totals.append((hid, host["software"], vul["total"], len(eol), ev, host["hardware"]))
    assert any(t[3] for t in totals) and any(t[4] for t in totals) and any(t[2] for t in totals), "на тестовых компьютерах есть EOL, события и уязвимости"
    # HTML: вкладки как в карточке, автономно, строки вкладок совпадают с таблицами
    rid = await _job(client, app, runner, sid, 6)
    page = (await client.get(f"/api/v1/reports/{rid}/download/html")).text
    for tab in ("Общие сведения", "Состояние защиты", "Установленное ПО", "Уязвимости", "EOL", "События безопасности", "Аппаратная часть"):
        assert f'<span class="kt-n">' in page and f">{tab}<" in page, tab
    assert "<link " not in page and 'src="http' not in page and "<script>" in page                       # без внешних ресурсов; сценарий встроен
    assert page.count('class="kt-panel"') == page.count('class="kt-tab"') == 7                            # полный набор разделов — семь вкладок
    assert "Уязвимостей в объединённом списке" in page and "kt-table" in page
    d = job_dir(app.state.settings, uuid.UUID(rid))
    assert (d / "report.pdf").read_bytes()[:4] == b"%PDF" and (d / "report.csv").stat().st_size > 50       # PDF и CSV строятся из того же документа


async def test_unavailable_sections_are_named_not_zeroed(client, app):
    """EOL не рассчитан на источнике и нет объектов уязвимостей — разделы не выводятся с нулями, а в примечании сказано почему."""
    sid, runner = await _setup(client, app)
    p = params()
    other = (await client.post("/api/v1/admin/sources", json={"name": "KAVTEST-EOL-NONE", "host": p.host, "port": p.port, "database": p.database, "username": p.username,
                                                             "password": p.password, "tls_mode": "request", "trust_server_cert": True})).json()["id"]
    rid = await _job(client, app, runner, sid, 6, header=other)                  # источник без расчёта EOL: раздел не включён
    done = (await client.get(f"/api/v1/reports/{rid}")).json()
    assert "eol" not in [t["id"] for t in done["summary"].get("tables", [])] if done["summary"].get("tables") else True
    wb = _tables(rid, app)
    assert "EOL" not in wb.sheetnames
    notes = " ".join(str(x) for x in (await client.get(f"/api/v1/reports/{rid}")).json()["summary"].get("notes", []))
    assert "EOL для этого источника ещё не рассчитан" in notes
    async with app.state.session_maker() as db:
        src = await db.get(KscSource, uuid.UUID(sid))
    src.last_check = {**(src.last_check or {}), "features": {"vulnerabilities": {"ok": False, "title": "Уязвимости", "missing": ["vapm_vulnerability_occurence"]}}}
    async with app.state.session_maker() as db:
        db.add(src)
        await db.commit()
    rid2 = await _job(client, app, runner, sid, 6, sections=["vulns", "software"])
    notes2 = " ".join(str(x) for x in (await client.get(f"/api/v1/reports/{rid2}")).json()["summary"].get("notes", []))
    assert "Уязвимости KSC на этом источнике недоступны" in notes2
    assert "Уязвимости" not in _tables(rid2, app).sheetnames


async def test_unprepared_external_results_are_not_zeros(client, app):
    """Пока расчёт внешних баз не завершён, счётчики уязвимостей в отчёте — «нет данных», а не 0; причина названа, строки KSC остаются."""
    sid, runner = await _setup(client, app)
    rid = await _job(client, app, runner, sid, 6)
    host = next(r for r in (await client.get(f"/api/v1/reports/{rid}/rows", params={"limit": 5})).json()["items"])
    assert host["v_total"] is None and host["v_critical"] is None                                                # не «0»
    notes = (await client.get(f"/api/v1/hosts/6/vulnerabilities")).json()["notes"]
    assert any("не подготовлена" in n for n in notes)                                                            # причина названа и в карточке
    wb = _tables(rid, app)
    assert "Уязвимости" in wb.sheetnames                                                                         # раздел остаётся: подтверждённые KSC видны
