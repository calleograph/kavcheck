"""Рассылка отчётов по зонам: расписания → устойчивая очередь (mail_outbox) → отправка → история.

Гарантии:
* расписание и очередь хранятся в БД: переживают перезагрузку, перезапуск воркера и обновление KAV Checker;
* одно письмо = зона × правило × отчётный период (UNIQUE): повторный запуск того же периода, перезапуск воркера или второй воркер дубликата не создают;
* письмо собирается один раз и сохраняется до успешной отправки — повторные попытки отправляют то же самое, не пересобирая отчёт;
* временные ошибки повторяются с удвоением паузы, постоянные — нет; после последней попытки администратору уходит уведомление и запись в журнале;
* «принято сервером» — состояние `accepted`: это не доставка и не прочтение.
Если процесс остановился после передачи письма серверу, но до записи результата, письмо может быть отправлено повторно (отправка «не менее одного раза»); окно — доли секунды."""
from __future__ import annotations

import asyncio
import email
import html
import logging
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from email import policy
from pathlib import Path

from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import MailOutbox, ReportSchedule, Zone
from ..reports import quick_export
from ..services import mail as M
from ..services.audit import Journal
from . import report as R
from . import schedule as SC
from .reporter import UNASSIGNED, ZoneData

log = logging.getLogger("app.zones.mail")
STUCK_AFTER = timedelta(minutes=20)
KEEP_DAYS = 180
MAX_BATCH = 20


def recipients(contacts: list[dict]) -> tuple[list[str], list[str]]:
    """Кому и в копию. Отключённые получатели пропускаются; если ответственных нет, письмо уходит копийным получателям."""
    on = [c for c in contacts if c.get("enabled", True)]
    to = [c["email"] for c in on if c["role"] in ("responsible", "group")]
    cc = [c["email"] for c in on if c["role"] == "cc"]
    if not to:
        to, cc = cc, []
    return list(dict.fromkeys(to)), [a for a in dict.fromkeys(cc) if a not in to]


def _file_dir(cfg) -> Path:
    d = Path(cfg.data_dir) / "mail"
    d.mkdir(parents=True, exist_ok=True)
    return d


def body(doc: dict, zone_name: str, base_url: str, zone_id: str, attach_note: str) -> tuple[str, str, str]:
    """(тема, текст, HTML): сводка читается прямо в письме; чужие зоны и подробности уязвимостей в тело не попадают."""
    c = R.counts_for_mail(doc)
    when = (doc.get("generated_at") or "")[:10]
    try:
        when = datetime.fromisoformat(doc["generated_at"]).strftime("%d.%m.%Y")
    except (ValueError, KeyError):
        pass
    subject = f"{zone_name}: проблемных компьютеров {c['problem_hosts']} из {c['total']} ({when})"
    org = doc.get("org") or {}
    head = " · ".join(x for x in ((org.get("short_name") or org.get("full_name") or ""), org.get("unit") or "") if x)
    lines = [("Всего компьютеров", c["total"]), ("Активных за период", c["active"]), ("С критическими уязвимостями", c["critical"]), ("С другими уязвимостями", c["other"]),
             ("С проблемами защиты", c["protection"]), ("Без выявленных проблем", c["ok"])]
    if c["potential"]:
        lines.append(("С потенциальными уязвимостями (внешние базы)", c["potential"]))
    if c["accepted"] or c["excluded"]:
        lines.append(("Принято рисков / исключено обработкой", f"{c['accepted']} / {c['excluded']}"))
    rows = doc["tables"][0]["rows"][:10]
    link = f"{base_url}/zones/{zone_id}" if base_url else ""
    text = "\n".join(([head] if head else []) + [f"Зона ответственности: {zone_name}", f"Состояние на {when}", ""] + [f"{k}: {v}" for k, v in lines] + ["", "Наиболее важные компьютеры:"]
                     + [f"  {r['name']} ({r['ip']}) — {r['max_sev'] or 'без уязвимостей'}: {r['summary']}" for r in rows] + (["  …"] if len(doc["tables"][0]["rows"]) > 10 else [])
                     + ["", attach_note] + ([f"Открыть в KAV Checker: {link}"] if link else []))
    e = html.escape
    tr = "".join(f'<tr><td style="padding:3px 8px;border-bottom:1px solid #e3e7eb">{e(r["name"])}<br><span style="color:#59636e;font-size:12px">{e(r["ip"])}</span></td>'
                 f'<td style="padding:3px 8px;border-bottom:1px solid #e3e7eb;white-space:nowrap">{e(r["max_sev"] or "—")}</td><td style="padding:3px 8px;border-bottom:1px solid #e3e7eb">{e(r["summary"])}</td></tr>' for r in rows)
    kv = "".join(f'<tr><td style="padding:2px 14px 2px 0;color:#59636e">{e(k)}</td><td style="padding:2px 0;font-weight:600">{e(str(v))}</td></tr>' for k, v in lines)
    htm = (f'<div style="font:14px/1.45 Segoe UI,Arial,sans-serif;color:#14181d;max-width:760px">' + (f'<div style="color:#59636e;font-size:12.5px">{e(head)}</div>' if head else "")
           + f'<h2 style="margin:4px 0 2px;font-size:18px">{e(zone_name)}</h2><div style="color:#59636e;margin-bottom:10px">Состояние безопасности на {e(when)}</div><table style="border-collapse:collapse">{kv}</table>'
           + (f'<h3 style="font-size:14px;margin:14px 0 4px">Наиболее важные компьютеры</h3><table style="border-collapse:collapse;font-size:13px">{tr}</table>' if rows else "")
           + f'<p style="color:#39424c;margin-top:12px">{e(attach_note)}</p>' + (f'<p><a href="{e(link, quote=True)}">Открыть в KAV Checker</a></p>' if link else "")
           + (f'<p style="color:#59636e;font-size:12px">{e(org["footnote"])}</p>' if org.get("footnote") else "") + "</div>")
    return subject, text, htm


class Mailer:
    def __init__(self, sm: async_sessionmaker, cfg, svc, data: ZoneData, journal: Journal):
        self.sm, self.cfg, self.svc, self.data, self.journal = sm, cfg, svc, data, journal
        self._wake = asyncio.Event()

    # ---------------------------------------------------------------- постановка в очередь
    async def enqueue(self, db: AsyncSession, sched: ReportSchedule, *, period: str, kind: str = "schedule", zone_ids: list[str] | None = None) -> dict:
        ids = zone_ids if zone_ids is not None else [str(z) for z in (sched.zone_ids or [])]
        zq = select(Zone).where(Zone.enabled.is_(True))
        if ids:
            zq = zq.where(Zone.id.in_([uuid.UUID(i) for i in ids]))
        zones = (await db.execute(zq.order_by(Zone.name))).scalars().all()
        info = {z["id"]: z for z in await self.data.zones_info(db, [str(z.id) for z in zones])}
        made = dup = skipped = 0
        for z in zones:
            to, cc = recipients(info[str(z.id)]["contacts"])
            row = MailOutbox(id=uuid.uuid4(), schedule_id=sched.id, zone_id=z.id, zone_name=z.name, period_key=period, kind=kind, status="queued" if to else "skipped",
                             to_addrs=to, cc_addrs=cc, last_error=None if to else "У зоны нет получателей с включённой рассылкой", created_at=datetime.now(timezone.utc),
                             next_attempt_at=datetime.now(timezone.utc))
            try:
                async with db.begin_nested():
                    db.add(row)
                    await db.flush()
                made += 1
                skipped += 0 if to else 1
            except IntegrityError:
                dup += 1
        if sched.include_unassigned:
            smtp = await self.svc.get(db, "smtp")
            if smtp.alert_email:
                try:
                    async with db.begin_nested():
                        db.add(MailOutbox(id=uuid.uuid4(), schedule_id=sched.id, zone_id=None, zone_name="Без ответственного", period_key=period, kind=kind, status="queued", to_addrs=[smtp.alert_email],
                                          cc_addrs=[], created_at=datetime.now(timezone.utc), next_attempt_at=datetime.now(timezone.utc)))
                        await db.flush()
                    made += 1
                except IntegrityError:
                    dup += 1
        self._wake.set()
        return {"queued": made - skipped, "skipped": skipped, "duplicates": dup}

    async def tick_schedules(self) -> int:
        now = datetime.now(timezone.utc)
        n = 0
        async with self.sm() as db:
            rows = (await db.execute(select(ReportSchedule).where(ReportSchedule.enabled.is_(True), or_(ReportSchedule.next_run_at.is_(None), ReportSchedule.next_run_at <= now)))).scalars().all()
            for s in rows:
                try:
                    run_at, nxt = SC.due(s.frequency, s.weekday, s.monthday, s.at_time, s.tz, s.next_run_at, now, s.created_at)
                except SC.ScheduleError as exc:
                    log.warning("Расписание «%s» неверно: %s", s.name, exc)
                    s.enabled = False
                    continue
                s.next_run_at = nxt
                if run_at is None:
                    continue
                period = SC.period_key(s.frequency, run_at, s.tz)
                if s.last_period == period:
                    continue
                res = await self.enqueue(db, s, period=period)
                s.last_period, s.last_run_at = period, now
                n += res["queued"]
                await self.journal.emit("report", "mail_scheduled", message=f"{s.name}: период {period}, в очереди {res['queued']}, без получателей {res['skipped']}", data={"schedule": str(s.id), **res})
            await db.commit()
        return n

    # ---------------------------------------------------------------- отправка
    async def recover_stuck(self) -> int:
        async with self.sm() as db:
            res = await db.execute(update(MailOutbox).where(MailOutbox.status == "sending", MailOutbox.next_attempt_at < datetime.now(timezone.utc) - STUCK_AFTER)
                                   .values(status="queued", last_error="Отправка прервана перезапуском; повтор"))
            await db.commit()
            return res.rowcount or 0

    async def _claim(self) -> uuid.UUID | None:
        now = datetime.now(timezone.utc)
        async with self.sm() as db:
            row = (await db.execute(select(MailOutbox).where(MailOutbox.status == "queued", or_(MailOutbox.next_attempt_at.is_(None), MailOutbox.next_attempt_at <= now))
                                    .order_by(MailOutbox.created_at).limit(1))).scalar_one_or_none()
            if row is None:
                return None
            res = await db.execute(update(MailOutbox).where(MailOutbox.id == row.id, MailOutbox.status == "queued").values(status="sending", attempts=MailOutbox.attempts + 1, next_attempt_at=now))
            await db.commit()
            return row.id if res.rowcount == 1 else None

    async def process_one(self) -> bool:
        oid = await self._claim()
        if oid is None:
            return False
        await self._send_row(oid)
        return True

    async def process_queue(self, limit: int = MAX_BATCH) -> int:
        n = 0
        while n < limit and await self.process_one():
            n += 1
        return n

    async def _prepare(self, db: AsyncSession, row: MailOutbox, smtp) -> tuple[bytes | None, str | None, bool]:
        """(письмо в байтах, причина пропуска, нужен ли отчёт) — собирает письмо один раз; при повторе читает сохранённое."""
        if row.body_path and Path(row.body_path).exists():
            return Path(row.body_path).read_bytes(), None, False
        sched = await db.get(ReportSchedule, row.schedule_id) if row.schedule_id else None
        f = (sched.filters if sched else {}) or {}
        params = {"categories": (sched.sections if sched and sched.sections else R.DEFAULT_CATEGORIES), "level": sched.level if sched else "management", "severity": f.get("severity", ""),
                  "include_inactive": bool(f.get("include_inactive")), "online_only": bool(f.get("online_only")), "bases_days": f.get("bases_days", 3), "scan_days": f.get("scan_days", 30),
                  "show_excluded": bool(f.get("show_excluded"))}
        zone_ids = [str(row.zone_id)] if row.zone_id else [UNASSIGNED]
        doc = await self.data.zone_doc(db, zone_ids=zone_ids, params=params, source_ids=f.get("source_ids") or None, recipients=", ".join(row.to_addrs or []), hide_other_zones=True)
        c = R.counts_for_mail(doc)
        row.stats = c
        if sched and sched.skip_empty and not c["problem_hosts"]:
            return None, "Проблем нет, отправка пропущена по настройке «не отправлять, если проблем нет»", True
        attach, note = [], "Подробности — во вложении."
        limit = smtp.max_attach_mb * 1024 * 1024
        with tempfile.TemporaryDirectory() as td:
            if sched is None or sched.attach_html:
                p = Path(td) / "r.html"
                quick_export.write_html(p, doc)
                attach.append((f"{row.zone_name or 'report'}.html".replace("/", "_"), p.read_bytes(), "text/html"))
            if sched and sched.attach_xlsx:
                p = Path(td) / "r.xlsx"
                quick_export.write_xlsx(p, doc)
                attach.append((f"{row.zone_name or 'report'}.xlsx".replace("/", "_"), p.read_bytes(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
        if sum(len(a[1]) for a in attach) > limit:
            attach, note = [], f"Подробный отчёт больше {smtp.max_attach_mb} МБ и не приложен: откройте его в KAV Checker." if smtp.base_url else \
                f"Подробный отчёт больше {smtp.max_attach_mb} МБ и не приложен: сформируйте его в KAV Checker."
        elif not attach:
            note = "Подробный отчёт можно сформировать в KAV Checker."
        subject, text, htm = body(doc, row.zone_name or "Без ответственного", smtp.base_url, str(row.zone_id or UNASSIGNED), note)
        row.subject = subject
        msg = M.compose(smtp, to=row.to_addrs or [], cc=row.cc_addrs or [], subject=subject, text=text, html=htm, attachments=attach)
        raw = msg.as_bytes()
        path = _file_dir(self.cfg) / f"{row.id}.eml"
        path.write_bytes(raw)
        row.body_path = str(path)
        return raw, None, True

    async def _send_row(self, oid: uuid.UUID) -> None:
        async with self.sm() as db:
            row = await db.get(MailOutbox, oid)
            smtp = await self.svc.get(db, "smtp")
            try:
                if not smtp.enabled:
                    raise _Fail("Отправка почты выключена в настройках SMTP", transient=True)
                raw, skip, _ = await self._prepare(db, row, smtp)
                await db.commit()
                if skip:
                    row.status, row.last_error = "skipped", skip
                    await db.commit()
                    return
                msg = email.message_from_bytes(raw, policy=policy.default)
                rc = list(dict.fromkeys((row.to_addrs or []) + (row.cc_addrs or [])))
                res = await M.send(smtp, msg, rc)
            except _Fail as f:
                res = M.SendResult(False, f.transient, str(f))
            except Exception as exc:  # noqa: BLE001
                log.exception("Сбой подготовки письма", extra={"outbox": str(oid)})
                res = M.SendResult(False, False, f"Не удалось подготовить отчёт: {type(exc).__name__}: {str(exc)[:200]}")
            row = await db.get(MailOutbox, oid)
            row.refused = [{"address": a, "reply": r} for a, r in (res.refused or {}).items()]
            if res.ok:
                row.status, row.sent_at, row.last_error, row.message_id = "accepted", datetime.now(timezone.utc), None, res.message_id
                row.next_attempt_at = None
                if row.body_path:
                    Path(row.body_path).unlink(missing_ok=True)
                    row.body_path = None
                await db.commit()
                await self.journal.emit("report", "mail_accepted", message=f"{row.zone_name}: принято сервером SMTP ({len(row.to_addrs or [])} адресатов)", data={"outbox": str(oid), "refused": len(row.refused)})
                return
            row.last_error = res.error
            if res.transient and row.attempts < smtp.retry_max:
                row.status = "queued"
                row.next_attempt_at = datetime.now(timezone.utc) + timedelta(minutes=smtp.retry_minutes * 2 ** (row.attempts - 1))
                await db.commit()
                await self.journal.emit("report", "mail_retry", level="warn", message=f"{row.zone_name}: {res.error[:200]}; повтор {row.next_attempt_at:%H:%M} UTC", data={"outbox": str(oid), "attempt": row.attempts})
                return
            row.status, row.next_attempt_at = "failed", None
            await db.commit()
            await self.journal.emit("report", "mail_failed", level="error", message=f"{row.zone_name}: отчёт не отправлен — {res.error[:300]}", data={"outbox": str(oid), "attempts": row.attempts})
            await self._alert(smtp, row)

    async def _alert(self, smtp, row: MailOutbox) -> None:
        if not smtp.alert_email or not smtp.enabled:
            return
        msg = M.compose(smtp, to=[smtp.alert_email], cc=[], subject=f"KAV Checker: отчёт «{row.zone_name}» не отправлен",
                        text=f"Отчёт по зоне «{row.zone_name}» (период {row.period_key}) не отправлен после {row.attempts} попыток.\nПричина: {row.last_error}\nПовторите отправку в KAV Checker: Администрирование → Рассылки отчётов.",
                        html=f"<p>Отчёт по зоне «{html.escape(row.zone_name)}» (период {html.escape(row.period_key)}) не отправлен после {row.attempts} попыток.</p><p>Причина: {html.escape(row.last_error or '')}</p>"
                              "<p>Повторите отправку в KAV Checker: Администрирование → Рассылки отчётов.</p>")
        await M.send(smtp, msg, [smtp.alert_email])

    async def purge(self) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)
        async with self.sm() as db:
            old = (await db.execute(select(MailOutbox).where(MailOutbox.created_at < cutoff, MailOutbox.status.in_(("accepted", "failed", "skipped"))))).scalars().all()
            for r in old:
                if r.body_path:
                    Path(r.body_path).unlink(missing_ok=True)
                await db.delete(r)
            await db.commit()
            return len(old)

    async def loop(self) -> None:
        """Опрос раз в 30 секунд: расписания → очередь → отправка. Сбой цикла не останавливает рассылку."""
        await asyncio.sleep(5)
        last_purge = 0.0
        while True:
            try:
                await self.recover_stuck()
                await self.tick_schedules()
                await self.process_queue()
                if asyncio.get_running_loop().time() - last_purge > 86400:
                    last_purge = asyncio.get_running_loop().time()
                    await self.purge()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("Сбой цикла рассылки")
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=30)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()


class _Fail(Exception):
    def __init__(self, text: str, transient: bool):
        super().__init__(text)
        self.transient = transient
