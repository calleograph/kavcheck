"""Фоновые задачи раздела «Инвентаризация» (worker, под арендой):

* сверка связей с KSC по подготовленным данным (KSC не опрашивается): исчезнувший компьютер — связь «утрачена» (карточка остаётся), вернувшийся — связь восстанавливается,
  имя обновляется; карточке компьютера без связи предлагается связь «предполагаемая», только если имя совпало ровно с одним компьютером всех источников и тот ни с чем не связан;
* подсчёт использования лицензий: компьютеры, где установлена программа по маскам лицензии (запросы к KSC порциями, по одному на маску и источник).
Каждое изменение карточки — событие истории («Связь с KSC»)."""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import select

from ..models import AppSetting, InvAsset, InvLicense, KscSource, ZcHost, ZcSource, utcnow
from ..search import mssql_like
from ..services.jobs import JOBS
from . import core as C
from . import model as M

log = logging.getLogger("kavcheck.inventory")
STATE_KEY = "inv_state"
EVERY_S = 300
LIC_EVERY = timedelta(hours=6)


async def get_state(sm) -> dict:
    async with sm() as db:
        row = await db.get(AppSetting, STATE_KEY)
        return dict(row.value or {}) if row else {}


async def set_state(sm, **kv) -> None:
    async with sm() as db:
        row = await db.get(AppSetting, STATE_KEY)
        cur = dict(row.value or {}) if row else {}
        cur.update({k: v for k, v in kv.items() if v is not None})
        for k in [k for k, v in kv.items() if v is None]:
            cur.pop(k, None)
        if row is None:
            db.add(AppSetting(group=STATE_KEY, value=cur))
        else:
            row.value = cur
        await db.commit()


async def sync_links(db, by: str = "KAV Checker (сверка с KSC)", auto: bool = True) -> dict:
    """Сверка связей карточек с компьютерами KSC по последнему поколению подготовленных данных каждого источника."""
    gens = dict((await db.execute(select(ZcSource.source_id, ZcSource.gen).where(ZcSource.gen > 0))).all())
    stats = {"lost": 0, "restored": 0, "renamed": 0, "auto": 0}
    linked = (await db.execute(select(InvAsset).where(InvAsset.ksc_host_id.is_not(None)))).scalars().all()
    by_src: dict = defaultdict(list)
    for a in linked:
        by_src[a.ksc_source_id].append(a)
    for sid, assets in by_src.items():
        gen = gens.get(sid)
        if not gen:
            continue                                                       # данных источника нет — о пропаже судить нельзя
        for i in range(0, len(assets), 1000):
            part = assets[i:i + 1000]
            names = dict((await db.execute(select(ZcHost.host_id, ZcHost.name).where(ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.host_id.in_([a.ksc_host_id for a in part])))).all())
            for a in part:
                nm = names.get(a.ksc_host_id)
                if nm is None and a.ksc_link != "lost":
                    old = a.ksc_link
                    a.ksc_link = "lost"
                    await C.record(db, a, "link", [{"f": "ksc", "label": "Компьютер KSC", "old": a.ksc_name, "new": "нет в KSC"}], by,
                                   title="Компьютер больше не найден в KSC: связь отмечена утраченной", comment=f"прежнее состояние связи: {old}")
                    stats["lost"] += 1
                elif nm is not None and a.ksc_link == "lost":
                    a.ksc_link = "confirmed" if a.linked_at else "auto"
                    await C.record(db, a, "link", [{"f": "ksc", "label": "Компьютер KSC", "old": "нет в KSC", "new": nm}], by, title="Компьютер снова найден в KSC: связь восстановлена")
                    stats["restored"] += 1
                if nm is not None and nm != a.ksc_name:
                    a.ksc_name = nm[:300]
                    stats["renamed"] += 1
    if auto:
        cands = (await db.execute(select(InvAsset).where(InvAsset.ksc_host_id.is_(None), InvAsset.hostname != "", InvAsset.cls.in_(M.COMPUTERS),
                                                         InvAsset.st_cls.in_(M.ST_ACTIVE)).limit(20000))).scalars().all()
        taken = {(a.ksc_source_id, a.ksc_host_id) for a in linked}
        short = defaultdict(list)
        for a in cands:
            short[a.hostname.split(".")[0]].append(a)
        dup_assets = {k for k, v in short.items() if len(v) > 1}            # две карточки с одним именем — не решаем за администратора
        names = [k for k in short if k not in dup_assets]
        for i in range(0, len(names), 500):
            chunk = names[i:i + 500]
            hits: dict = defaultdict(list)
            for sid, gen in gens.items():
                rows = (await db.execute(select(ZcHost.host_id, ZcHost.name).where(ZcHost.source_id == sid, ZcHost.gen == gen, ZcHost.name.in_(chunk + [c.upper() for c in chunk])))).all()
                for hid, nm in rows:
                    hits[nm.split(".")[0].casefold()].append((sid, hid, nm))
            for k in chunk:
                h = hits.get(k, [])
                if len(h) != 1 or (h[0][0], h[0][1]) in taken:
                    continue
                a = short[k][0]
                sid, hid, nm = h[0]
                a.ksc_source_id, a.ksc_host_id, a.ksc_link, a.ksc_name = sid, hid, "auto", nm[:300]
                taken.add((sid, hid))
                await C.record(db, a, "link", [{"f": "ksc", "label": "Компьютер KSC", "old": "", "new": f"{nm} ({hid})"}], by,
                               title="Предполагаемая связь с компьютером KSC по имени (единственное совпадение) — требует подтверждения")
                stats["auto"] += 1
    return stats


async def license_usage(db, sources, activity_days: int, lic_ids: list[int] | None = None) -> int:
    """Использование лицензий: компьютеры (активные за период) с программой по маскам лицензии во всех источниках KSC. Ошибка источника записывается в лицензию, остальные считаются."""
    stmt = select(InvLicense).where(InvLicense.active.is_(True))
    if lic_ids:
        stmt = stmt.where(InvLicense.id.in_(lic_ids))
    lics = [x for x in (await db.execute(stmt)).scalars().all() if x.match]
    if not lics:
        return 0
    srcs = (await db.execute(select(KscSource))).scalars().all()
    since = utcnow() - timedelta(days=activity_days)
    from ..ksc import queries as q  # noqa: PLC0415
    from ..ksc.driver import KscError  # noqa: PLC0415

    for lc in lics:
        hosts: set = set()
        by_src: dict[str, int] = {}
        errors = []
        for s in srcs:
            client = sources.client(s)
            got: set = set()
            for mask in lc.match[:10]:
                p = mssql_like(mask)
                if not p:
                    continue
                try:
                    rows = await client.run(q.LIC_HOSTS, {"p": p, "since": since, "n": 20000}, max_rows=20000)
                except KscError as exc:
                    errors.append(f"{s.name}: {exc}")
                    break
                got |= {int(r["host_id"]) for r in rows}
            by_src[s.name] = len(got)
            hosts |= {(str(s.id), h) for h in got}
        lc.usage = {"at": utcnow().isoformat(), "installs": len(hosts), "by_source": by_src, "errors": errors[:5], "days": activity_days}
        await asyncio.sleep(0)
    await db.commit()
    return len(lics)


class InvService:
    def __init__(self, sm, svc, sources, journal=None):
        self.sm, self.svc, self.sources, self.journal = sm, svc, sources, journal
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    async def tick(self) -> None:
        st = await get_state(self.sm)
        async with JOBS.run("inv_sync", "") as lease:
            if lease is None:
                return
            async with self.sm() as db:
                cfg = await self.svc.get(db, "inventory")
                lease.stage("сверка связей с KSC")
                stats = await sync_links(db, auto=cfg.ksc_auto_link)
                await lease.fence(db)
                await db.commit()
            if any(stats.values()):
                log.info("Инвентаризация: сверка связей с KSC %s", stats)
            last = st.get("lic_at")
            due = st.get("lic_requested") or not last or datetime.fromisoformat(last) < utcnow() - LIC_EVERY
            if due:
                lease.stage("подсчёт использования лицензий")
                async with self.sm() as db:
                    general = await self.svc.get(db, "general")
                    n = await license_usage(db, self.sources, general.activity_days)
                await set_state(self.sm, lic_at=utcnow().isoformat(), lic_requested=None, lic_count=n)
            await set_state(self.sm, sync_at=utcnow().isoformat(), sync_stats=stats)
            lease.stage("источники инфраструктуры")
            async with JOBS.run("inv_infra", "") as il:
                if il is not None:
                    await self.infra_tick()
            async with self.sm() as db:
                cfg = await self.svc.get(db, "inventory")
            st = await get_state(self.sm)
            if await notify_due(cfg, st, utcnow()):
                lease.stage("сводка сроков на почту")
                r = await send_digest(self.sm, self.svc)
                from zoneinfo import ZoneInfo  # noqa: PLC0415

                try:
                    day = utcnow().astimezone(ZoneInfo(cfg.notify_timezone)).date().isoformat()
                except Exception:  # noqa: BLE001
                    day = utcnow().date().isoformat()
                await set_state(self.sm, notify_at=utcnow().isoformat(), notify_result=r, **({"notify_day": day} if r["sent"] or not r["error"] else {}))
                if self.journal is not None and r["error"]:
                    await self.journal.emit("inventory", "notify_failed", level="warn", message=f"Сводка инвентаризации не отправлена: {r['error']}")

    async def infra_tick(self, force: bool = False) -> dict:
        """Синхронизация источников инфраструктуры, срок которых подошёл (или запрошенных): каждый — отдельно, ошибка одного не останавливает остальные; затем сверка."""
        from ..infra import connectors as IK  # noqa: PLC0415
        from ..infra import sync as IS  # noqa: PLC0415
        from ..models import InfraSource  # noqa: PLC0415

        async with self.sm() as db:
            srcs = list((await db.execute(select(InfraSource).where(InfraSource.enabled.is_(True)))).scalars())
            cfg = await self.svc.get(db, "inventory")
        now = utcnow()
        ran = 0
        for s in srcs:
            due = force or s.requested or s.last_try_at is None or s.last_try_at < now - timedelta(minutes=max(5, s.every_min))
            if not due or s.kind not in IK.FETCH:
                continue
            ran += 1
            secret = self.svc.decrypt(s.secret_enc, f"infra.{s.id}") if s.secret_enc else ""
            err, objects = "", None
            try:
                objects = await IK.fetch(s, secret)
            except IK.SourceError as exc:
                err = str(exc)
            except Exception as exc:  # noqa: BLE001 — неожиданный сбой коннектора не должен останавливать остальные источники
                log.exception("Инфраструктура: сбой источника %s", s.name)
                err = f"Внутренняя ошибка: {type(exc).__name__}"
            async with self.sm() as db:
                row = await db.get(InfraSource, s.id)
                if row is None:
                    continue
                row.last_try_at, row.requested = utcnow(), False
                if objects is not None:
                    st = await IS.sync_source(db, row, objects)
                    row.last_ok_at, row.last_error, row.last_stats = utcnow(), "", st
                else:
                    row.last_error = err[:2000]
                await db.commit()
            if err and self.journal is not None:
                await self.journal.emit("inventory", "infra_source_failed", level="warn", message=f"Источник «{s.name}»: {err}"[:500])
        if ran or force:
            async with self.sm() as db:
                st = await IS.reconcile(db, cfg.infra_stale_days)
                await db.commit()
            return st
        return {}

    async def loop(self) -> None:
        """Полный проход (связи с KSC, лицензии, источники, сводка) — раз в EVERY_S; между ними раз в 30 с — запрошенные и подошедшие по сроку источники инфраструктуры."""
        await asyncio.sleep(20)
        last_full = 0.0
        while not self._stop.is_set():
            now = asyncio.get_running_loop().time()
            try:
                if now - last_full >= EVERY_S or (await get_state(self.sm)).get("lic_requested"):
                    await self.tick()
                    last_full = now
                else:
                    async with JOBS.run("inv_infra", "") as lease:
                        if lease is not None:
                            await self.infra_tick()
            except Exception:  # noqa: BLE001 — фоновая задача не должна останавливать worker
                log.exception("Инвентаризация: фоновая сверка не выполнена")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=30)
            except asyncio.TimeoutError:
                pass


# ------------------------------------------------------------------------------------------------ уведомления (ежедневная сводка сроков)
async def digest(db, cfg) -> list[dict]:
    """Разделы сводки: что истекает или просрочено. Пустые разделы не включаются. Только чтение внутренней базы."""
    from datetime import date  # noqa: PLC0415

    from sqlalchemy import func  # noqa: PLC0415

    from ..models import InvCount, InvDoc  # noqa: PLC0415

    today = date.today()
    out: list[dict] = []
    act = InvAsset.st_cls.in_(M.ST_ACTIVE)
    w = (await db.execute(select(InvAsset.inv_no, InvAsset.name, InvAsset.warranty_until).where(act, InvAsset.warranty_until >= today, InvAsset.warranty_until <= today + timedelta(days=cfg.warranty_days))
                          .order_by(InvAsset.warranty_until).limit(200))).all()
    if w:
        out.append({"title": f"Гарантия заканчивается в ближайшие {cfg.warranty_days} дн.", "rows": [f"{no} {nm or ''} — до {d:%d.%m.%Y}".replace("  ", " ") for no, nm, d in w]})
    lic = (await db.execute(select(InvLicense.name, InvLicense.valid_until).where(InvLicense.active.is_(True), InvLicense.valid_until.is_not(None),
                                                                                InvLicense.valid_until <= today + timedelta(days=cfg.license_days)).order_by(InvLicense.valid_until))).all()
    if lic:
        out.append({"title": "Лицензии: срок истёк или истекает", "rows": [f"{nm} — {'истекла' if d < today else 'до'} {d:%d.%m.%Y}" for nm, d in lic]})
    tr = (await db.execute(select(InvDoc.no, InvDoc.doc_date).where(InvDoc.kind == "move", InvDoc.status == "sent", InvDoc.doc_date < today - timedelta(days=cfg.transit_days)))).all()
    if tr:
        out.append({"title": f"Перемещения «в пути» дольше {cfg.transit_days} дн.", "rows": [f"{no} от {d:%d.%m.%Y}" for no, d in tr]})
    rp = (await db.execute(select(InvDoc.no, InvDoc.doc_date, InvDoc.data).where(InvDoc.kind == "repair", InvDoc.status == "sent", InvDoc.doc_date < today - timedelta(days=cfg.repair_days)))).all()
    if rp:
        out.append({"title": f"В ремонте дольше {cfg.repair_days} дн.", "rows": [f"{no} от {d:%d.%m.%Y}{(' — ' + (dt or {}).get('vendor', '')) if (dt or {}).get('vendor') else ''}" for no, d, dt in rp]})
    cn = (await db.execute(select(InvCount.no, InvCount.title, InvCount.started_at).where(InvCount.status == "active", InvCount.started_at < utcnow() - timedelta(days=7)))).all()
    if cn:
        out.append({"title": "Незавершённые инвентаризации (дольше недели)", "rows": [f"{no} {t} — начата {s:%d.%m.%Y}" for no, t, s in cn]})
    stale = (await db.execute(select(func.count()).select_from(InvAsset).where(act, InvAsset.updated_at < utcnow() - timedelta(days=cfg.stale_days)))).scalar_one()
    if stale:
        out.append({"title": "Учётные сведения давно не обновлялись", "rows": [f"{stale} карточек не менялись более {cfg.stale_days} дн."]})
    lost = (await db.execute(select(func.count()).select_from(InvAsset).where(act, InvAsset.ksc_link == "lost"))).scalar_one()
    if lost:
        out.append({"title": "Компьютеры пропали из KSC", "rows": [f"{lost} действующих карточек связаны с компьютерами, которых больше нет в KSC"]})
    return out


def digest_mail(sections: list[dict], base_url: str) -> tuple[str, str, str]:
    import html as H  # noqa: PLC0415

    n = sum(len(s["rows"]) for s in sections)
    subject = f"Инвентаризация: требует внимания — {n}" if sections else "Инвентаризация: сроки в порядке"
    lines = ["Ежедневная сводка раздела «Инвентаризация».", ""]
    parts = ["<p>Ежедневная сводка раздела «Инвентаризация».</p>"]
    for s in sections:
        lines += [s["title"] + ":", *[f"  • {r}" for r in s["rows"][:50]], *([f"  … и ещё {len(s['rows']) - 50}"] if len(s["rows"]) > 50 else []), ""]
        parts.append(f"<h3 style='margin:14px 0 4px;font-size:14px'>{H.escape(s['title'])}</h3><ul style='margin:0;padding-left:18px'>" + "".join(f"<li>{H.escape(r)}</li>" for r in s["rows"][:50]) + "</ul>")
    if not sections:
        lines.append("Истекающих сроков и просроченных операций нет.")
        parts.append("<p>Истекающих сроков и просроченных операций нет.</p>")
    if base_url:
        lines.append(f"Открыть: {base_url.rstrip('/')}/inventory")
        parts.append(f"<p><a href='{H.escape(base_url.rstrip('/'))}/inventory'>Открыть раздел</a></p>")
    return subject, "\n".join(lines), "".join(parts)


async def notify_due(cfg, st: dict, now) -> bool:
    from zoneinfo import ZoneInfo  # noqa: PLC0415

    try:
        local = now.astimezone(ZoneInfo(cfg.notify_timezone))
    except Exception:  # noqa: BLE001 — неверный часовой пояс: считаем по UTC
        local = now
    hh, mm = (int(x) for x in cfg.notify_time.split(":"))
    return cfg.notify_enabled and bool(cfg.notify_emails) and (local.hour, local.minute) >= (hh, mm) and st.get("notify_day") != local.date().isoformat()


async def send_digest(sm, svc, by: str = "") -> dict:
    """Собрать и отправить сводку получателям из настроек. Возвращает {sent, sections, error}."""
    from ..services import mail as MAIL  # noqa: PLC0415

    async with sm() as db:
        cfg = await svc.get(db, "inventory")
        smtp = await svc.get(db, "smtp")
        sections = await digest(db, cfg)
    if not cfg.notify_emails:
        return {"sent": False, "sections": len(sections), "error": "Не указаны получатели"}
    if not sections and not cfg.notify_empty and not by:
        return {"sent": False, "sections": 0, "error": ""}
    subject, text, htm = digest_mail(sections, getattr(smtp, "base_url", "") or "")
    try:
        msg = MAIL.compose(smtp, to=list(cfg.notify_emails), cc=[], subject=subject, text=text, html=htm)
        res = await MAIL.send(smtp, msg, list(cfg.notify_emails))
    except Exception as exc:  # noqa: BLE001 — SMTP не настроен или недоступен: причина видна в «Настройках»
        return {"sent": False, "sections": len(sections), "error": str(exc)[:300]}
    return {"sent": res.ok, "sections": len(sections), "error": res.error}
