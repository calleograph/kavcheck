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
EVERY_S = 900
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

    async def loop(self) -> None:
        await asyncio.sleep(20)
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001 — фоновая задача не должна останавливать worker
                log.exception("Инвентаризация: фоновая сверка не выполнена")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=EVERY_S if not (await get_state(self.sm)).get("lic_requested") else 30)
            except asyncio.TimeoutError:
                pass
