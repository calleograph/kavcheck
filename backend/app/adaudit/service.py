"""Проверка домена (worker): расписание (раз в месяц, в квартальные месяцы — квартальная), запуск по кнопке, сбор под арендой, запись снимка одной транзакцией.

* Сбор — `JOBS.run_heavy("adaudit")`, полоса `bi` (чтение справочника не ждёт тяжёлых расчётов KSC); две проверки одновременно невозможны.
* Снимок: учётные записи (состояние, категория, способ последней операции с паролем) и замечания; замечание прослеживается между проверками
  по ключу guid:code (впервые обнаружено, сколько проверок подряд). Решения администратора хранятся отдельно и к снимку не привязаны.
* Хранятся последние `keep_runs` проверок; события паролей — `events_keep_days` суток."""
from __future__ import annotations

import asyncio
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import delete, select

from ..auth.ldap import LdapError
from ..models import AdAuditAccount, AdAuditFinding, AdAuditRun, AdClassOverride, AdEventImport, AdPwdEvent, AppSetting, utcnow
from ..services.settings import AdAuditSettings
from . import checks as K
from . import collect as COL
from . import query as Q

log = logging.getLogger("app.adaudit")
STATE_KEY = "adaudit_state"
TICK_S = 60
BATCH = 2000
KIND_RU = {"manual": "внеплановая", "monthly": "ежемесячная", "quarterly": "квартальная"}


class AuditError(Exception):
    """Проверка не выполнена (понятное сообщение)."""


async def get_state(sm) -> dict:
    async with sm() as db:
        row = await db.get(AppSetting, STATE_KEY)
        return dict(row.value or {}) if row else {}


async def set_state(sm, **kv) -> None:
    async with sm() as db:
        row = await db.get(AppSetting, STATE_KEY)
        cur = dict(row.value or {}) if row else {}
        for k, v in kv.items():
            if v is None:
                cur.pop(k, None)
            else:
                cur[k] = v
        if row is None:
            db.add(AppSetting(group=STATE_KEY, value=cur))
        else:
            row.value = cur
        await db.commit()


def next_run(cfg: AdAuditSettings, after: datetime) -> datetime:
    """Ближайшее плановое время строго после `after`: день месяца и время — в часовом поясе настроек."""
    tz = ZoneInfo(cfg.timezone)
    h, m = (int(x) for x in cfg.schedule_time.split(":"))
    local = after.astimezone(tz)
    cand = local.replace(day=cfg.day_of_month, hour=h, minute=m, second=0, microsecond=0)
    if cand <= local:
        y, mo = (local.year + 1, 1) if local.month == 12 else (local.year, local.month + 1)
        cand = cand.replace(year=y, month=mo)
    return cand.astimezone(timezone.utc)


POLICY_FIELDS = {"pwd_days", "inactive_days", "new_days", "grace_days", "protected_users", "policy_note", "admin_groups", "per_dc_logon", "ldap_filter"}     # политика, сохраняемая в каждой проверке


def policy_of(cfg: AdAuditSettings) -> K.Policy:
    return K.Policy(pwd_days=dict(cfg.pwd_days), inactive_days=cfg.inactive_days, new_days=cfg.new_days, grace_days=cfg.grace_days, protected_users=cfg.protected_users)


def rules_of(cfg: AdAuditSettings) -> list[K.Rule]:
    return [K.Rule(r.category, r.kind, r.value, r.note) for r in cfg.rules]


async def coverage(db) -> K.Coverage:
    """Охват загруженных журналов по контроллерам: самое раннее начало и самый поздний конец среди загрузок."""
    cov = K.Coverage()
    for (dcs,) in (await db.execute(select(AdEventImport.dcs))).all():
        for d in dcs or []:
            if d.get("error") or not d.get("log_from") or not d.get("log_to"):
                continue
            a, b = datetime.fromisoformat(d["log_from"]), datetime.fromisoformat(d["log_to"])
            cur = cov.dcs.get(d["name"])
            cov.dcs[d["name"]] = (min(a, cur[0]), max(b, cur[1])) if cur else (a, b)
    return cov


async def events_by_target(db, since: datetime) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """События по SID цели и (если SID в событии нет) по логину — по возрастанию времени."""
    by_sid: dict[str, list[dict]] = defaultdict(list)
    by_login: dict[str, list[dict]] = defaultdict(list)
    q = select(AdPwdEvent.target_sid, AdPwdEvent.target, AdPwdEvent.kind, AdPwdEvent.success, AdPwdEvent.at, AdPwdEvent.by, AdPwdEvent.by_domain, AdPwdEvent.dc).where(AdPwdEvent.at >= since).order_by(AdPwdEvent.at)
    for sid, tgt, kind, ok, at, by, by_dom, dc in (await db.execute(q)).all():
        e = {"kind": kind, "success": ok, "at": at, "by": f"{by_dom}\\{by}" if by_dom and by else by, "dc": dc}
        (by_sid[sid] if sid else by_login[(tgt or "").casefold()]).append(e)
    return by_sid, by_login


@dataclass
class Evaluated:
    rows: list[dict]
    findings: list[dict]
    stats: dict


def evaluate_all(accounts: list[dict], cfg: AdAuditSettings, overrides: dict[str, dict], ev_sid: dict, ev_login: dict, cov: K.Coverage, now: datetime) -> Evaluated:
    """Категория, замечания и сводка по всем учётным записям (чистая функция: проверяется тестами без каталога)."""
    pol, rules = policy_of(cfg), rules_of(cfg)
    rows, findings = [], []
    st: Counter = Counter()
    have_logs = bool(cov.dcs)
    for a in accounts:
        cat, basis = K.classify(a, rules, overrides.get(a["guid"]))
        evs = ev_sid.get(a["sid"]) or ev_login.get(a["login"].casefold()) or []
        op = K.last_pwd_op(a, evs, cov)
        fs = K.evaluate(a, cat, pol, now, op)
        age, idle = K.days(now, a["pwd_last_set"]), K.days(now, a["last_logon"])
        rows.append({**a, "category": cat, "category_basis": basis, "pwd_age": age, "pwd_bucket": K.bucket(age) if not a["must_change"] else "unknown", "idle_days": idle,
                     "pwd_op": {**op, "at": op["at"].isoformat() if op["at"] else None}, "findings_n": len(fs), "max_sev": max((K.SEV_RANK[f["severity"]] for f in fs), default=0)})
        for f in fs:
            findings.append({**f, "guid": a["guid"], "login": a["login"], "name": a["name"], "category": cat})
        en = a["enabled"]
        st["accounts"] += 1
        st["enabled" if en else "disabled"] += 1
        st[f"cat_{cat}"] += 1
        if en:
            st["locked"] += a["locked"]
            st["pne"] += a["pne"]
            st["must_change"] += a["must_change"]
            st[f"pwd_{K.bucket(age) if not a['must_change'] else 'unknown'}"] += 1
            st["inactive"] += bool((idle is not None and idle > cfg.inactive_days) or (a["last_logon"] is None and (K.days(now, a["created"]) or 0) > cfg.inactive_days))
            st["privileged"] += bool(a["privileged"])
            st["expired"] += bool(a["expires"] and a["expires"] < now)
        st["new"] += bool(a["created"] and K.days(now, a["created"]) <= cfg.new_days)
        st["reset_pending"] += bool(any(f["code"] == "reset" for f in fs))
        st["op_" + op["state"]] += 1
    for f in findings:
        st[f"f_{f['status']}"] += 1
        st[f"sev_{f['severity']}"] += 1
    st["findings"] = len(findings)
    st["accounts_with_findings"] = len({f["guid"] for f in findings})
    st["have_logs"] = int(have_logs)
    return Evaluated(rows, findings, dict(st))


class AdAuditService:
    def __init__(self, sm, settings, svc, ldap, journal=None):
        self._sm, self._settings, self._svc, self._ldap, self._journal = sm, settings, svc, ldap, journal
        self._stop = asyncio.Event()
        self._tasks: set[asyncio.Task] = set()
        self.current: str | None = None

    def stop(self) -> None:
        self._stop.set()

    async def cfg(self) -> AdAuditSettings:
        async with self._sm() as db:
            return await self._svc.get(db, "adaudit")                                # type: ignore[return-value]

    async def _emit(self, event: str, message: str, level: str = "info", user: str | None = None) -> None:
        if self._journal is not None:
            await self._journal.emit("adaudit", event, level=level, user=user, message=message[:600])

    async def recover(self) -> int:
        async with self._sm() as db:
            rows = list((await db.execute(select(AdAuditRun).where(AdAuditRun.status == "running"))).scalars())
            for r in rows:
                r.status, r.finished_at, r.message = "failed", utcnow(), "Проверка прервана перезапуском службы; запустите её снова."
            await db.commit()
        return len(rows)

    async def tick(self) -> None:
        cfg, st, now = await self.cfg(), await get_state(self._sm), utcnow()
        if st.get("requested"):
            req = st["requested"] if isinstance(st["requested"], dict) else {}
            await set_state(self._sm, requested=None)
            self._spawn(self.run("manual" if req.get("kind") != "quarterly" else "quarterly", str(req.get("by") or "")))
            return
        if not cfg.enabled:
            return
        sig = f"{cfg.day_of_month}|{cfg.schedule_time}|{cfg.timezone}"
        due = st.get("next_run")
        if st.get("sig") != sig or not due:
            await set_state(self._sm, sig=sig, next_run=next_run(cfg, now).isoformat())
            return
        if now >= datetime.fromisoformat(due):
            await set_state(self._sm, next_run=next_run(cfg, now).isoformat())
            local = now.astimezone(ZoneInfo(cfg.timezone))
            self._spawn(self.run("quarterly" if local.month in cfg.quarter_months else "monthly", ""))

    def _spawn(self, coro) -> None:
        t = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def loop(self) -> None:
        await asyncio.sleep(25)
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка цикла «Аудит домена»")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=TICK_S)
            except asyncio.TimeoutError:
                pass

    async def _ldap_cfg(self, cfg: AdAuditSettings):
        async with self._sm() as db:
            conns = [c for c in await self._ldap.connections(db) if c.enabled and c.host]
            pick = [c for c in conns if str(c.id) == cfg.connection] or conns
            if not pick:
                raise AuditError("Подключение LDAPS не настроено или выключено: Администрирование → LDAPS. Раздел использует его же, отдельные логин и пароль не нужны.")
            return self._ldap.config(pick[0], await self._ldap.ca_bundle(db))

    async def run(self, kind: str = "manual", by: str = "", *, now: datetime | None = None) -> AdAuditRun | None:
        from ..services.jobs import JOBS  # noqa: PLC0415

        if JOBS.busy_here("adaudit", ""):
            return None
        cfg = await self.cfg()
        async with JOBS.run_heavy("adaudit", "", "в очереди", task="Аудит домена: проверка учётных записей", lane="bi") as lease:
            if lease is None:
                return None
            now = now or utcnow()
            async with self._sm() as db:
                run = AdAuditRun(started_at=now, status="running", kind=kind, by=by[:160], period=f"{now:%Y-%m}", policy=cfg.model_dump(include=POLICY_FIELDS))
                db.add(run)
                await db.commit()
                rid = run.id
            self.current = str(rid)
            await self._emit("run_start", f"Проверка домена начата: {KIND_RU[kind]}", user=by or None)
            try:
                lcfg = await self._ldap_cfg(cfg)
                loop = asyncio.get_running_loop()
                prog = lambda t: loop.call_soon_threadsafe(lambda: asyncio.ensure_future(lease.stage(t)))   # noqa: E731
                attr_names = sorted({r.value.split("=", 1)[0] for r in cfg.rules if r.kind == "attribute"})
                rule_groups = sorted({r.value for r in cfg.rules if r.kind == "group" and "*" not in r.value})
                got = await asyncio.to_thread(COL.read_domain, lcfg, extra_filter=cfg.ldap_filter, admin_groups=list(cfg.admin_groups), rule_groups=rule_groups,
                                              attr_names=attr_names, per_dc=cfg.per_dc_logon, progress=prog)
                if not got.accounts:
                    raise AuditError("Каталог не вернул ни одной учётной записи: проверьте Base DN и фильтр пользователей подключения LDAPS.")
                await lease.stage("проверка учётных записей")
                async with self._sm() as db:
                    overrides = {o.guid: {"category": o.category, "note": o.note} for o in (await db.execute(select(AdClassOverride))).scalars()}
                    cov = await coverage(db)
                    cov.expected = list(got.dcs)
                    ev_sid, ev_login = await events_by_target(db, now - timedelta(days=cfg.events_keep_days))
                ev = await asyncio.to_thread(evaluate_all, got.accounts, cfg, overrides, ev_sid, ev_login, cov, now)
                await lease.stage("запись результатов")
                await self._store(rid, lcfg, got, ev, cov, lease)
            except Exception as exc:  # noqa: BLE001
                msg = str(exc) if isinstance(exc, AuditError) else exc.message if isinstance(exc, LdapError) else f"Непредвиденная ошибка: {type(exc).__name__}. Подробности — в журнале службы worker."
                if not isinstance(exc, (AuditError, LdapError)):
                    log.exception("Проверка домена не удалась")
                async with self._sm() as db:
                    r = await db.get(AdAuditRun, rid)
                    r.status, r.finished_at, r.message = "failed", utcnow(), msg[:1000]
                    await db.commit()
                await self._emit("run_failed", msg, level="error")
                return r
            finally:
                self.current = None
            async with self._sm() as db:
                r = await db.get(AdAuditRun, rid)
            await self._emit("run_done", f"Проверка домена завершена: учётных записей {r.stats.get('accounts', 0)}, замечаний {r.stats.get('findings', 0)}", user=by or None)
            return r

    async def _store(self, rid, lcfg, got: COL.Collected, ev: Evaluated, cov: K.Coverage, lease) -> None:
        cfg = await self.cfg()
        async with self._sm() as db:
            prev = (await db.execute(select(AdAuditRun.id).where(AdAuditRun.status == "ok").order_by(AdAuditRun.started_at.desc()).limit(1))).scalar_one_or_none()
            carry = {k: (fs, n) for k, fs, n in (await db.execute(select(AdAuditFinding.key, AdAuditFinding.first_seen, AdAuditFinding.runs_n).where(AdAuditFinding.run_id == prev))).all()} if prev else {}
            run = await db.get(AdAuditRun, rid)
            await lease.fence(db)
            cols = {c.key for c in AdAuditAccount.__table__.columns} - {"id", "run_id"}
            buf = [AdAuditAccount(run_id=rid, **{k: v for k, v in r.items() if k in cols}) for r in ev.rows]
            for i in range(0, len(buf), BATCH):
                db.add_all(buf[i:i + BATCH])
                await db.flush()
            now = run.started_at
            for i in range(0, len(ev.findings), BATCH):
                part = []
                for f in ev.findings[i:i + BATCH]:
                    key = f"{f['guid']}:{f['code']}"
                    first, n = carry.get(key, (now, 0))
                    part.append(AdAuditFinding(run_id=rid, key=key, guid=f["guid"], login=f["login"][:256], name=f["name"][:300], category=f["category"], code=f["code"], severity=f["severity"],
                                               sev_rank=K.SEV_RANK[f["severity"]], status=f["status"], title=f["title"][:200], basis=f["basis"], first_seen=first, runs_n=n + 1))
                db.add_all(part)
                await db.flush()
            gone = len(set(carry) - {f"{f['guid']}:{f['code']}" for f in ev.findings})
            run.stats = {**ev.stats, "fixed_since_prev": gone, "new_since_prev": sum(1 for f in ev.findings if f"{f['guid']}:{f['code']}" not in carry), "prev_run": str(prev) if prev else None}
            run.stats = {**run.stats, "active_scope": await Q.stats(db, run)}
            run.coverage = {"dcs": got.dcs, "dc_logon_ok": got.dc_ok, "logs": {k: [a.isoformat(), b.isoformat()] for k, (a, b) in cov.dcs.items()}, "logs_missing": cov.missing(),
                            "window": [x.isoformat() for x in cov.window()] if cov.window() else None}
            run.notes, run.domain = got.notes, f"{lcfg.name} ({lcfg.base_dn})"
            run.status, run.finished_at = "ok", utcnow()
            await db.commit()
        await self._prune(cfg)

    async def _prune(self, cfg: AdAuditSettings) -> None:
        async with self._sm() as db:
            ids = [r for (r,) in (await db.execute(select(AdAuditRun.id).order_by(AdAuditRun.started_at.desc()))).all()][cfg.keep_runs:]
            for i in range(0, len(ids), 50):
                part = ids[i:i + 50]
                await db.execute(delete(AdAuditFinding).where(AdAuditFinding.run_id.in_(part)))
                await db.execute(delete(AdAuditAccount).where(AdAuditAccount.run_id.in_(part)))
                await db.execute(delete(AdAuditRun).where(AdAuditRun.id.in_(part)))
            await db.execute(delete(AdPwdEvent).where(AdPwdEvent.at < utcnow() - timedelta(days=cfg.events_keep_days)))
            await db.commit()


async def import_events(sm, parsed: dict, *, file_name: str, by: str) -> AdEventImport:
    """Записать загруженные события (повторы по контроллеру и номеру записи пропускаются) и охват журналов."""
    async with sm() as db:
        imp = AdEventImport(by=by[:160], file_name=file_name[:300], events=len(parsed["events"]), skipped=parsed["skipped"],
                            dcs=[{**d, "log_from": d["log_from"].isoformat() if d["log_from"] else None, "log_to": d["log_to"].isoformat() if d["log_to"] else None} for d in parsed["dcs"]])
        db.add(imp)
        await db.flush()
        added = 0
        evs = parsed["events"]
        for i in range(0, len(evs), BATCH):
            part = evs[i:i + BATCH]
            keys = {(e["dc"], e["record_id"]) for e in part}
            have = set((await db.execute(select(AdPwdEvent.dc, AdPwdEvent.record_id).where(AdPwdEvent.dc.in_({d for d, _r in keys}), AdPwdEvent.record_id.in_({r for _d, r in keys})))).all())
            new = [e for e in part if (e["dc"], e["record_id"]) not in have]
            seen: set = set()
            for e in new:
                if (e["dc"], e["record_id"]) in seen:
                    continue
                seen.add((e["dc"], e["record_id"]))
                db.add(AdPwdEvent(import_id=imp.id, **e))
                added += 1
            await db.flush()
        imp.added = added
        await db.commit()
        return imp
