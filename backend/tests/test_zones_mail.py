"""Рассылка отчётов по зонам: расписание → очередь → SMTP → история. Настоящий SMTP-протокол (tests/smtpmock.py), синтетическая база KSC: отправка нескольким получателям,
изоляция зон, ошибки сервера (временные, постоянные, отклонённые адреса), повторные попытки, отсутствие дублей после перезапуска, ручная отправка и повтор."""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import MailOutbox, ReportSchedule
from app.zones import mailer
from app.zones.reporter import ZoneData
from tests.smtpmock import FakeSMTP
from tests.test_ksc_live import HOST
from tests.test_zones_live import mk_zone, setup

pytestmark = pytest.mark.skipif(not HOST, reason="нет синтетической базы KSC (KSC_TEST_HOST)")


def new_mailer(app) -> mailer.Mailer:
    """Новый экземпляр = «перезапуск воркера»: никакого состояния в памяти, всё — в БД."""
    return mailer.Mailer(app.state.session_maker, app.state.settings, app.state.settings_svc, ZoneData(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.sources), app.state.journal)


async def smtp_on(client, srv: FakeSMTP, **extra):
    cfg = {"enabled": True, "host": "127.0.0.1", "port": srv.port, "security": "none", "from_addr": "kav@example.local", "from_name": "KAV Checker", "retry_max": 3, "retry_minutes": 1,
           "alert_email": "ib@example.local", "base_url": "https://kav.example.local", **extra}
    r = await client.put("/api/v1/admin/settings/smtp", json=cfg)
    assert r.status_code == 200, r.text


async def outbox(app) -> list[MailOutbox]:
    async with app.state.session_maker() as db:
        return list((await db.execute(select(MailOutbox).order_by(MailOutbox.zone_name))).scalars())


async def make_schedule(client, **kw):
    body = {"name": "Еженедельно", "frequency": "weekly", "weekday": 0, "at_time": "08:00", "tz": "Europe/Moscow", "attach_html": True, **kw}
    r = await client.post("/api/v1/admin/mail/schedules", json=body)
    assert r.status_code == 201, r.text
    return r.json()


async def make_due(app, sid: str, hours: int = 1):
    async with app.state.session_maker() as db:
        s = await db.get(ReportSchedule, uuid.UUID(sid))
        s.next_run_at = datetime.now(timezone.utc) - timedelta(hours=hours)
        await db.commit()


@pytest.fixture
async def smtp():
    s = FakeSMTP()
    await s.start()
    yield s
    await s.stop()


async def prepare(client, app, smtp, **sched):
    sid, runner, z_srv, z_arm = await setup(client, app)
    await client.post(f"/api/v1/admin/zones/{z_srv}", json={}) if False else None
    await client.put(f"/api/v1/admin/zones/{z_srv}", json={"name": "Серверы", "rules": [{"kind": "net", "value": "192.0.2.10-192.0.2.23"}],
                                                          "contacts": [{"name": "Иван Петров", "position": "Начальник ИТ", "email": "petrov@example.local", "role": "responsible"},
                                                                       {"name": "Мария Сидорова", "email": "boss@example.local", "role": "cc"}, {"email": "off@example.local", "role": "responsible", "enabled": False}]})
    await smtp_on(client, smtp)
    s = await make_schedule(client, **sched)
    return sid, z_srv, z_arm, s


async def test_weekly_mail_goes_to_each_zone_only_and_contains_summary(client, app, smtp):
    sid, z_srv, z_arm, s = await prepare(client, app, smtp)
    await make_due(app, s["id"])
    m = new_mailer(app)
    assert await m.tick_schedules() == 2
    assert await m.process_queue() == 2
    assert len(smtp.messages) == 2
    by = {tuple(sorted(x["rcpts"])): x for x in smtp.messages}
    srv = by[("boss@example.local", "petrov@example.local")]                                  # отключённый получатель пропущен; копия получает то же письмо
    arm = by[("arm@example.local",)]
    assert srv["msg"]["Subject"].startswith("Серверы: проблемных компьютеров") and arm["msg"]["Subject"].startswith("АРМ:")
    body = srv["msg"].get_body(("plain",)).get_content()
    assert "Всего компьютеров: 4" in body and "ksc-server" in body and "ws-001" not in body and "АРМ" not in body       # чужие зоны и компьютеры не раскрываются
    arm_body = arm["msg"].get_body(("plain",)).get_content()
    assert "ws-001" in arm_body and "Серверы" not in arm_body and "petrov" not in arm_body
    atts = [p for p in arm["msg"].iter_attachments()]
    assert len(atts) == 1 and atts[0].get_filename() == "АРМ.html" and b"ws-001" in atts[0].get_content().encode() if isinstance(atts[0].get_content(), str) else True
    assert "https://kav.example.local/zones/" in body
    rows = await outbox(app)
    assert {r.status for r in rows} == {"accepted"} and all(r.sent_at and r.attempts == 1 and r.body_path is None for r in rows)
    assert all(r.stats["total"] for r in rows)
    async with app.state.session_maker() as db:
        sch = await db.get(ReportSchedule, uuid.UUID(s["id"]))
        assert sch.last_period and sch.next_run_at > datetime.now(timezone.utc).replace(tzinfo=None) if sch.next_run_at.tzinfo is None else sch.next_run_at > datetime.now(timezone.utc)


async def test_no_duplicates_after_restart_or_rerun_of_same_period(client, app, smtp):
    sid, z_srv, z_arm, s = await prepare(client, app, smtp)
    await make_due(app, s["id"])
    await new_mailer(app).tick_schedules()
    await new_mailer(app).process_queue()
    assert len(smtp.messages) == 2
    await make_due(app, s["id"], hours=1)                      # тот же период (расписание «откатили»): повторной постановки нет
    assert await new_mailer(app).tick_schedules() == 0
    await new_mailer(app).process_queue()
    assert len(smtp.messages) == 2 and len(await outbox(app)) == 2
    # прямая повторная постановка того же периода (два воркера одновременно) — уникальный ключ отсекает
    async with app.state.session_maker() as db:
        sch = await db.get(ReportSchedule, uuid.UUID(s["id"]))
        res = await new_mailer(app).enqueue(db, sch, period=sch.last_period)
        await db.commit()
    assert res["queued"] == 0 and res["duplicates"] == 2 and len(await outbox(app)) == 2


async def test_catch_up_after_downtime_sends_one_report_per_zone_not_a_flood(client, app, smtp):
    sid, z_srv, z_arm, s = await prepare(client, app, smtp)
    await make_due(app, s["id"], hours=24 * 40)                # воркер «лежал» 40 суток
    m = new_mailer(app)
    assert await m.tick_schedules() == 2
    await m.process_queue()
    assert len(smtp.messages) == 2


async def test_temporary_error_retries_with_same_message_then_succeeds(client, app, smtp):
    sid, z_srv, z_arm, s = await prepare(client, app, smtp)
    smtp.mode = "tempfail"
    await make_due(app, s["id"])
    m = new_mailer(app)
    await m.tick_schedules()
    await m.process_queue()
    rows = await outbox(app)
    assert {r.status for r in rows} == {"queued"} and all(r.attempts == 1 and "451" in (r.last_error or "") and r.body_path for r in rows)
    eml_before = {r.id: open(r.body_path, "rb").read() for r in rows}
    assert await m.process_queue() == 0                        # пауза перед повтором не вышла
    async with app.state.session_maker() as db:
        for r in (await db.execute(select(MailOutbox))).scalars():
            r.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()
    smtp.mode = "ok"
    await new_mailer(app).process_queue()
    rows = await outbox(app)
    assert {r.status for r in rows} == {"accepted"} and all(r.attempts == 2 for r in rows) and len(smtp.messages) == 2
    sent = {m_["msg"]["Message-ID"] for m_ in smtp.messages}
    assert sent == {__import__("email").message_from_bytes(b, policy=__import__("email").policy.default)["Message-ID"] for b in eml_before.values()}      # отправлено то же письмо, отчёт не пересобирался


async def test_permanent_errors_do_not_retry_and_admin_is_alerted(client, app, smtp):
    srv = FakeSMTP(user="kav", password="right-pass-1")  # private-data: ignore
    await srv.start()
    try:
        sid, z_srv, z_arm, s = await prepare(client, app, smtp)
        await smtp_on(client, srv, username="kav", password="wrong-pass-1")  # private-data: ignore
        await make_due(app, s["id"])
        m = new_mailer(app)
        await m.tick_schedules()
        await m.process_queue()
        rows = await outbox(app)
        assert {r.status for r in rows} == {"failed"} and all(r.attempts == 1 and "имя или пароль" in r.last_error for r in rows) and not srv.messages
        assert all("wrong-pass-1" not in (r.last_error or "") for r in rows)                  # пароль в ошибках не светится
        # администратор исправляет пароль и повторяет отправку из интерфейса
        await smtp_on(client, srv, username="kav", password="right-pass-1")  # private-data: ignore
        r = await client.post(f"/api/v1/admin/mail/outbox/{rows[0].id}/retry")
        assert r.status_code == 200 and r.json()["status"] == "queued"
        await new_mailer(app).process_queue()
        assert len(srv.messages) == 1 and (await outbox(app))[0].status == "accepted"
        assert (await client.post(f"/api/v1/admin/mail/outbox/{rows[0].id}/retry")).status_code == 409          # принятое повторять нельзя
    finally:
        await srv.stop()


async def test_refused_recipient_is_reported_but_report_is_accepted(client, app, smtp):
    sid, z_srv, z_arm, s = await prepare(client, app, smtp)
    smtp.reject = {"boss@example.local"}
    await make_due(app, s["id"])
    m = new_mailer(app)
    await m.tick_schedules()
    await m.process_queue()
    srv_row = next(r for r in await outbox(app) if r.zone_name == "Серверы")
    assert srv_row.status == "accepted" and srv_row.refused and srv_row.refused[0]["address"] == "boss@example.local" and "unknown" in srv_row.refused[0]["reply"].lower()
    smtp.messages.clear()
    smtp.mode = "permfail"                                                                    # сервер отклонил всех получателей — это ошибка, а не «принято»
    async with app.state.session_maker() as db:
        sch = await db.get(ReportSchedule, uuid.UUID(s["id"]))
        await new_mailer(app).enqueue(db, sch, period="manual-x", kind="manual", zone_ids=[z_arm])
        await db.commit()
    await new_mailer(app).process_queue()
    row = next(r for r in await outbox(app) if r.period_key == "manual-x")
    assert row.status == "failed" and "отклонил" in row.last_error


async def test_retries_are_bounded_then_failed(client, app, smtp):
    sid, z_srv, z_arm, s = await prepare(client, app, smtp)
    smtp.mode = "drop"
    await make_due(app, s["id"])
    m = new_mailer(app)
    await m.tick_schedules()
    for _ in range(5):
        await m.process_queue()
        async with app.state.session_maker() as db:
            for r in (await db.execute(select(MailOutbox).where(MailOutbox.status == "queued"))).scalars():
                r.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            await db.commit()
    rows = await outbox(app)
    assert {r.status for r in rows} == {"failed"} and all(r.attempts == 3 for r in rows)      # retry_max=3
    h = (await client.get("/api/v1/admin/mail/outbox?status=failed")).json()
    assert h["total"] == 2 and h["items"][0]["last_error"]


async def test_skip_empty_no_recipients_disable_manual_run_and_history(client, app, smtp):
    sid, z_srv, z_arm, s = await prepare(client, app, smtp, skip_empty=True, sections=["ksc_critical"])
    z_quiet = await mk_zone(client, "Тихая", [("net", "198.51.100.0/24")], contacts=[{"email": "quiet@example.local", "role": "responsible"}])
    z_nobody = await mk_zone(client, "Без адресатов", [("net", "203.0.113.0/24")])
    await make_due(app, s["id"])
    m = new_mailer(app)
    await m.tick_schedules()
    await m.process_queue()
    st = {r.zone_name: r for r in await outbox(app)}
    assert st["Тихая"].status == "skipped" and "Проблем нет" in st["Тихая"].last_error                    # зона без проблем — письмо не уходит
    assert st["Без адресатов"].status == "skipped" and "нет получателей" in st["Без адресатов"].last_error.lower()
    assert st["АРМ"].status == "accepted" and st["Серверы"].status == "accepted"
    n = len(smtp.messages)
    # расписание можно отключить: следующий запуск пропадает, ничего не отправляется
    t = (await client.post(f"/api/v1/admin/mail/schedules/{s['id']}/toggle", params={"enabled": False})).json()
    assert t["enabled"] is False and t["next_run_at"] is None
    await make_due(app, s["id"], hours=24 * 8)
    assert await new_mailer(app).tick_schedules() == 0
    # ручная отправка выбранной зоне
    run = (await client.post(f"/api/v1/admin/mail/schedules/{s['id']}/run", json={"zone_ids": [z_arm]})).json()
    assert run["queued"] == 1
    await new_mailer(app).process_queue()
    assert len(smtp.messages) == n + 1
    hist = (await client.get("/api/v1/admin/mail/outbox")).json()
    assert hist["counts"]["accepted"] >= 3 and any(i["kind"] == "manual" for i in hist["items"])
    assert (await client.get("/api/v1/admin/mail/summary")).json()["smtp_ready"] is True


async def test_big_attachment_is_replaced_by_link_and_stuck_sending_is_recovered(client, app, smtp):
    sid, z_srv, z_arm, s = await prepare(client, app, smtp)
    await smtp_on(client, smtp, max_attach_mb=1)
    async with app.state.session_maker() as db:
        from app.models import Zone
        z = await db.get(Zone, uuid.UUID(z_arm))
        z.description = "x" * 10
        await db.commit()
    orig = mailer.quick_export.write_html
    mailer.quick_export.write_html = lambda p, doc: p.write_bytes(b"A" * (2 * 1024 * 1024))
    try:
        await make_due(app, s["id"])
        m = new_mailer(app)
        await m.tick_schedules()
        await m.process_queue()
    finally:
        mailer.quick_export.write_html = orig
    msg = smtp.messages[0]["msg"]
    assert not list(msg.iter_attachments()) and "больше 1 МБ" in msg.get_body(("plain",)).get_content()
    # «упавший» воркер: запись осталась в состоянии «отправляется» — через 20 минут возвращается в очередь
    async with app.state.session_maker() as db:
        r = (await db.execute(select(MailOutbox))).scalars().first()
        r.status, r.next_attempt_at = "sending", datetime.now(timezone.utc) - timedelta(minutes=30)
        await db.commit()
    assert await new_mailer(app).recover_stuck() == 1


async def test_smtp_settings_check_and_test_mail(client, app, smtp):
    await __import__("tests.conftest", fromlist=["login"]).login(client, "admin", "Admin-Passw0rd-123")
    await smtp_on(client, smtp)
    ok = (await client.post("/api/v1/admin/mail/check")).json()
    assert ok["ok"]
    t = (await client.post("/api/v1/admin/mail/test", json={"to": "me@example.local"})).json()
    assert t["ok"] and smtp.messages[-1]["rcpts"] == ["me@example.local"] and "не означает" in t["note"]
    assert (await client.post("/api/v1/admin/mail/test", json={"to": "не-адрес"})).status_code == 422
    smtp.mode = "drop"
    bad = (await client.post("/api/v1/admin/mail/check")).json()
    assert not bad["ok"] and bad["transient"]
    got = (await client.get("/api/v1/admin/settings/smtp")).json()
    assert "password" not in got and got["password_set"] is False
