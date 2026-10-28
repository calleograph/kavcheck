"""Хранение журналов: срок, объём, сжатые архивы с ротацией по размеру, квота, аудит не теряется, отложенная очистка при сканировании, API только для администратора."""
import gzip
import json
from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, func, select

from app.models import AuditLog, EventLog, PtEvent, PtJob, utcnow
from app.services import retention as R
from app.services.settings import LogsSettings
from tests.conftest import login


def cfg(**kw):
    return LogsSettings(**kw)


async def seed(app, n_old=30, n_new=5, audit_old=10):
    old, new = utcnow() - timedelta(days=45), utcnow() - timedelta(days=1)
    async with app.state.session_maker() as db:
        await db.execute(delete(EventLog))                                                                    # без записей, оставленных запуском приложения
        db.add_all([EventLog(at=old, level="warn", category="ksc", event="x", message=f"старое {i}") for i in range(n_old)])
        db.add_all([EventLog(at=new, level="warn", category="ksc", event="x", message=f"новое {i}") for i in range(n_new)])
        db.add_all([EventLog(at=old, level="info", category="auth", event="login", message="вход") for _ in range(3)])
        db.add_all([AuditLog(at=utcnow() - timedelta(days=400), actor="a", action="old.action", target_type="t", target_id="1") for _ in range(audit_old)])
        await db.commit()


async def count(app, model, *w):
    async with app.state.session_maker() as db:
        return int((await db.execute(select(func.count()).select_from(model).where(*w))).scalar_one())


async def test_retention_by_age_archives_and_rotates_by_size(app, tmp_path):
    await seed(app, n_old=400)
    c = cfg(journal_days=30, journal_archive=True, archive_file_mb=1)
    rep = await R.run(app.state.session_maker, c, str(tmp_path))
    assert rep["moved"]["journal"]["rows"] == 403 and await count(app, EventLog) == 5                    # старше 30 суток ушло, свежее осталось
    files = [a for a in R.list_archives(R.archive_dir(str(tmp_path))) if a["type"] == "journal"]
    assert files and all(a["gz"] for a in files)
    lines = [json.loads(x) for f in files for x in gzip.open(R.archive_dir(str(tmp_path)) / f["name"], "rt", encoding="utf-8")]
    assert len(lines) == 403 and {x["category"] for x in lines} == {"ksc", "auth"}                         # архив читается, записи не потеряны
    assert await count(app, AuditLog) == 10                                                                 # аудит по умолчанию не удаляется


async def test_per_category_retention_and_no_archive_means_plain_delete(app, tmp_path):
    await seed(app, n_old=5)
    rep = await R.run(app.state.session_maker, cfg(journal_days=90, journal_by_category={"auth": 7}), str(tmp_path))
    assert await count(app, EventLog, EventLog.category == "auth") == 0 and await count(app, EventLog, EventLog.category == "ksc") == 10     # 45 суток < 90, а auth — срок 7
    assert rep["moved"]["journal"]["files"] == [] and not R.list_archives(R.archive_dir(str(tmp_path)))


async def test_audit_is_deleted_only_after_archive_and_never_by_size(app, tmp_path):
    await seed(app)
    rep = await R.run(app.state.session_maker, cfg(audit_days=365, audit_max_mb=0), str(tmp_path))
    arcs = [a for a in R.list_archives(R.archive_dir(str(tmp_path))) if a["type"] == "audit"]
    assert await count(app, AuditLog) == 0 and arcs                                                         # удалено только то, что записано в архив
    assert sum(1 for f in arcs for _ in gzip.open(R.archive_dir(str(tmp_path)) / f["name"], "rt")) == 10
    assert rep["moved"]["audit"]["rows"] == 10
    # предел объёма аудита только предупреждает
    async with app.state.session_maker() as db:
        db.add_all([AuditLog(actor="a", action="new", target_type="t", target_id=str(i)) for i in range(20)])
        await db.commit()
    rep2 = await R.run(app.state.session_maker, cfg(audit_days=0, audit_max_mb=0), str(tmp_path))
    assert await count(app, AuditLog) == 20 and not rep2["warnings"]


async def test_size_cap_drops_oldest_rows_of_operational_logs(app, tmp_path, monkeypatch):
    await seed(app, n_old=0, n_new=0, audit_old=0)
    async with app.state.session_maker() as db:
        db.add_all([EventLog(at=utcnow() - timedelta(hours=i), level="warn", category="ksc", event="x", message=f"m{i}") for i in range(200)])
        await db.commit()
    monkeypatch.setattr(R, "table_stats", _fake_stats({"journal": 2 * 1024 * 1024}))                          # таблица «занимает» 2 МБ при пределе 1 МБ
    rep = await R.run(app.state.session_maker, cfg(journal_days=30, journal_max_mb=1), str(tmp_path))
    left = await count(app, EventLog)
    assert 80 <= left <= 120 and any("объём превышал" in w for w in rep["warnings"])                           # осталось около половины (до 90 % предела)


def _fake_stats(sizes):
    real = R.table_stats

    async def fake(db, key):
        st = await real(db, key)
        return {**st, "bytes": sizes.get(key, st["bytes"])}
    return fake


async def test_quota_compresses_then_removes_only_expired_archives_and_warns(app, tmp_path, monkeypatch):
    await seed(app, n_old=0, n_new=0, audit_old=0)
    async with app.state.session_maker() as db:
        await db.execute(delete(EventLog))
        await db.commit()
    d = R.archive_dir(str(tmp_path))
    d.mkdir(parents=True)
    old = d / "journal-20200101-000000-01.ndjson.gz"
    old.write_bytes(b"x" * 2048)
    import os  # noqa: PLC0415

    os.utime(old, (utcnow().timestamp() - 400 * 86400,) * 2)
    audit_arc = d / "audit-20200101-000000-01.ndjson.gz"
    audit_arc.write_bytes(b"y" * 2048)
    async with app.state.session_maker() as db:
        db.add_all([EventLog(at=utcnow() - timedelta(days=20), level="warn", category="ksc", event="x", message="m") for _ in range(10)])
        await db.commit()
    monkeypatch.setattr(R, "usage", _usage_seq([5 * 1024 * 1024, 3 * 1024 * 1024, 3 * 1024 * 1024]))
    rep = await R.run(app.state.session_maker, cfg(journal_days=30, quota_mb=1, archive_days=1000), str(tmp_path))
    assert not old.exists() and rep["deleted_archives"] == [old.name] and audit_arc.exists()                  # архив аудита квотой не удаляется
    assert await count(app, EventLog) == 0 and any(a["type"] == "journal" for a in R.list_archives(d))          # записи старше половины срока сжаты в архив
    assert any("Квота" in w and "без нарушения правил" in w for w in rep["warnings"])                          # место освободить нельзя — предупреждение, а не молчаливая потеря


def _usage_seq(vals):
    it = iter(vals + [vals[-1]] * 5)

    async def u(sm, directory):
        return next(it)
    return u


async def test_archive_expiry_and_file_count_limit(app, tmp_path):
    d = R.archive_dir(str(tmp_path))
    d.mkdir(parents=True)
    import os  # noqa: PLC0415

    for i in range(5):
        f = d / f"journal-2026010{i + 1}-000000-01.ndjson.gz"
        f.write_bytes(b"z")
        os.utime(f, (utcnow().timestamp() - i * 3600,) * 2)
    rep = await R.run(app.state.session_maker, cfg(archive_max_files=3), str(tmp_path))
    assert len(rep["deleted_archives"]) == 2 and len(R.list_archives(d)) == 3


async def test_cleanup_is_deferred_while_pentest_runs_unless_forced(app, tmp_path):
    await seed(app)
    rep = await R.run(app.state.session_maker, cfg(), str(tmp_path), busy=True)
    assert rep["deferred"] and await count(app, EventLog) == 38 and "Pentest" in rep["warnings"][0]
    rep = await R.run(app.state.session_maker, cfg(), str(tmp_path), busy=True, force=True)
    assert not rep["deferred"] and await count(app, EventLog) == 5


async def test_pentest_events_retention_keeps_job_results(app, tmp_path):
    async with app.state.session_maker() as db:
        job = PtJob(title="t", status="done")
        db.add(job)
        await db.flush()
        db.add_all([PtEvent(job_id=job.id, at=utcnow() - timedelta(days=100), level="info", message="старое"), PtEvent(job_id=job.id, level="info", message="новое")])
        await db.commit()
    await R.run(app.state.session_maker, cfg(pt_events_days=90), str(tmp_path))
    assert await count(app, PtEvent) == 1 and await count(app, PtJob) == 1                                   # задание и его результаты остались


async def test_auto_clean_off_changes_nothing_and_settings_validation():
    c = cfg(auto_clean=False)
    assert c.audit_days == 0 and c.journal_days == 30
    for bad in ({"audit_days": 30}, {"journal_by_category": {"a b": 5}}, {"journal_days": 0}):
        try:
            cfg(**bad)
        except ValueError:
            continue
        raise AssertionError(bad)


async def test_api_admin_only_download_validation_and_run(client, app, tmp_path):
    await login(client, "admin", "Admin-Passw0rd-123")
    d = R.archive_dir(app.state.settings.reports_dir)
    d.mkdir(parents=True, exist_ok=True)
    f = d / "journal-20260101-000000-01.ndjson.gz"
    f.write_bytes(gzip.compress(b'{"a": 1}\n'))
    try:
        ov = (await client.get("/api/v1/admin/logs")).json()
        assert {i["key"] for i in ov["items"]} == {"journal", "audit", "pt_events"} and ov["external"][0]["key"] == "docker" and ov["totals"]["files"] == 1
        assert next(i for i in ov["items"] if i["key"] == "audit")["mandatory"] and ov["settings"]["journal_days"] == 30 and ov["disk"]["free"] is not None
        assert (await client.put("/api/v1/admin/logs/settings", json={"journal_days": 14, "quota_mb": 2048})).json()["changed"] == ["journal_days", "quota_mb"]
        assert (await client.put("/api/v1/admin/logs/settings", json={"audit_days": 10})).status_code == 422
        assert (await client.put("/api/v1/admin/logs/settings", json={"nope": 1})).status_code == 422
        r = await client.get(f"/api/v1/admin/logs/archives/{f.name}")
        assert r.status_code == 200 and gzip.decompress(r.content) == b'{"a": 1}\n'
        assert (await client.get("/api/v1/admin/logs/archives/..%2F..%2Fetc%2Fpasswd")).status_code == 404 and (await client.get("/api/v1/admin/logs/archives/other.txt")).status_code == 404
        assert (await client.post("/api/v1/admin/logs/run")).status_code == 202 and (await client.get("/api/v1/admin/logs")).json()["requested"]
        audit = (await client.get("/api/v1/admin/audit")).json()
        assert any(a["action"] == "logs.archive_download" for a in audit["items"]) and any(a["action"] == "logs.settings" for a in audit["items"])
        await client.post("/api/v1/auth/logout")
        await login(client, "viewer", "Viewer-Passw0rd-123")
        assert (await client.get("/api/v1/admin/logs")).status_code == 403 and (await client.put("/api/v1/admin/logs/settings", json={"journal_days": 5})).status_code == 403
        assert (await client.get(f"/api/v1/admin/logs/archives/{f.name}")).status_code == 403
    finally:
        f.unlink(missing_ok=True)
