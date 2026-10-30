"""Сбор и публикация снимков раздела «Иерархия. Предприятие» (worker): расписание (раз в сутки, время и часовой пояс настраиваются), «Обновить сейчас», защита опубликованного снимка.

* Сбор — под арендой (`JOBS.run_heavy`, полоса `bi`: плановое чтение справочника не ждёт тяжёлые расчёты); два сбора одновременно невозможны. Каталог читается страницами в потоке.
* Снимок публикуется, только если сбор завершился успешно и записей не заметно меньше, чем в последнем успешном (порог в настройках); иначе пользователи видят прежний снимок,
  а на странице — предупреждение с датой последнего успешного. После ошибки плановый сбор повторяется через 30 минут (до трёх раз).
* Одинаковое содержимое не дублируется (`same_as_id`); снимки старше срока хранения удаляются, последний успешный остаётся всегда."""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..bi.service import next_run
from ..db import xact_lock
from ..ksc.driver import KscError
from ..models import AppSetting, HierSnapshot, utcnow
from ..services.settings import HierSettings
from . import process as P
from . import sources as S

log = logging.getLogger("app.hier")
STATE_KEY = "hier_state"
TICK_S = 30
RETRY_MIN = 30
RETRIES = 3


def rules_of(cfg: HierSettings) -> P.Rules:
    return P.Rules(domains=tuple(cfg.internal_domains), drop_empty=cfg.drop_empty, drop_underscore=cfg.drop_underscore, drop_service=cfg.drop_service, service_words=tuple(cfg.service_words),
                   service_prefixes=tuple(cfg.service_prefixes), name_lookup=cfg.name_lookup, dept_map=dict(cfg.dept_map))


async def get_state(sm: async_sessionmaker[AsyncSession]) -> dict:
    async with sm() as db:
        row = await db.get(AppSetting, STATE_KEY)
        return dict(row.value or {}) if row else {}


async def set_state(sm: async_sessionmaker[AsyncSession], **kv) -> None:
    async with sm() as db:
        row = await db.get(AppSetting, STATE_KEY)
        if row is None:
            db.add(AppSetting(group=STATE_KEY, value={k: v for k, v in kv.items() if v is not None}))
        else:
            cur = dict(row.value or {})
            for k, v in kv.items():
                if v is None:
                    cur.pop(k, None)
                else:
                    cur[k] = v
            row.value = cur
        await db.commit()


async def latest_ok(db: AsyncSession) -> HierSnapshot | None:
    return (await db.execute(select(HierSnapshot).where(HierSnapshot.status == "ok").order_by(HierSnapshot.finished_at.desc()).limit(1))).scalar_one_or_none()


async def ok_snapshots(db: AsyncSession, limit: int = 60) -> list[HierSnapshot]:
    """Успешные снимки с различным содержимым, от новых к старым (одинаковые подряд — один раз): список для сравнения выгрузок."""
    rows = (await db.execute(select(HierSnapshot).where(HierSnapshot.status == "ok").order_by(HierSnapshot.finished_at.desc()).limit(limit * 3))).scalars().all()
    out: list[HierSnapshot] = []
    for s in rows:
        if not out or s.content_hash != out[-1].content_hash:
            out.append(s)
    return out[:limit]


async def previous_ok(db: AsyncSession, snap: HierSnapshot, base_id: str = "") -> HierSnapshot | None:
    """С чем сравнивать текущий снимок: указанный (`base_id`) либо ближайший более ранний с другим содержимым."""
    if base_id:
        try:
            got = await db.get(HierSnapshot, uuid.UUID(base_id))
        except ValueError:
            raise KscError("params", "Некорректный идентификатор выгрузки для сравнения") from None
        if got is None or got.status != "ok":
            raise KscError("params", "Выгрузка для сравнения не найдена (возможно, удалена по сроку хранения)")
        return got
    return next((s for s in await ok_snapshots(db) if s.finished_at < snap.finished_at and s.content_hash != snap.content_hash), None)


async def records_of(db: AsyncSession, snap: HierSnapshot) -> list[list[str]]:
    """Записи снимка: свои либо снимка, где они хранятся (одинаковое содержимое не дублируется)."""
    if snap.records is not None:
        return snap.records
    holder = await db.get(HierSnapshot, snap.same_as_id) if snap.same_as_id else None
    return (holder.records or []) if holder is not None else []


_CACHE: dict[tuple, P.Result] = {}                                       # обработанный снимок: (снимок, правила) → результат; не больше нескольких штук


async def processed(db: AsyncSession, snap: HierSnapshot, cfg: HierSettings) -> P.Result:
    rules = rules_of(cfg)
    key = (str(snap.id), rules.signature())
    if key not in _CACHE:
        res = await asyncio.to_thread(P.build, await records_of(db, snap), rules)
        if len(_CACHE) >= 4:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = res
    return _CACHE[key]


async def prune(db: AsyncSession, keep_days: int) -> int:
    """Снимки старше срока хранения (кроме последнего успешного). Записи удаляемого снимка, на которые ссылаются оставшиеся, переходят к самому раннему из них."""
    cutoff = utcnow() - timedelta(days=keep_days)
    keep = await latest_ok(db)
    old = list((await db.execute(select(HierSnapshot).where(HierSnapshot.started_at < cutoff, HierSnapshot.status != "running").order_by(HierSnapshot.started_at))).scalars())
    old = [s for s in old if keep is None or s.id != keep.id]
    gone = {s.id for s in old}
    for s in old:
        if s.records is not None:
            refs = [r for r in (await db.execute(select(HierSnapshot).where(HierSnapshot.same_as_id == s.id).order_by(HierSnapshot.started_at))).scalars() if r.id not in gone]
            if refs:
                refs[0].records, refs[0].same_as_id = s.records, None
                for r in refs[1:]:
                    r.same_as_id = refs[0].id
        await db.flush()
    if gone:
        await db.execute(delete(HierSnapshot).where(HierSnapshot.id.in_(gone)))
    return len(gone)


class HierService:
    def __init__(self, sm: async_sessionmaker[AsyncSession], settings, svc, ldap, journal=None):
        self._sm, self._settings, self._svc, self._ldap, self._journal = sm, settings, svc, ldap, journal
        self._stop = asyncio.Event()
        self._tasks: set[asyncio.Task] = set()
        self.current: str | None = None

    def stop(self) -> None:
        self._stop.set()

    async def cfg(self) -> HierSettings:
        async with self._sm() as db:
            return await self._svc.get(db, "hier")                                  # type: ignore[return-value]

    async def _emit(self, event: str, message: str, level: str = "info", user: str | None = None) -> None:
        if self._journal is not None:
            await self._journal.emit("hier", event, level=level, user=user, message=message[:600])

    async def recover(self) -> int:
        """После перезапуска: снимки в состоянии «идёт сбор» завершаются понятным статусом."""
        async with self._sm() as db:
            rows = list((await db.execute(select(HierSnapshot).where(HierSnapshot.status == "running"))).scalars())
            for r in rows:
                r.status, r.finished_at, r.message = "failed", utcnow(), "Сбор прерван перезапуском службы; повторится по расписанию или по кнопке «Обновить сейчас»."
            await db.commit()
        return len(rows)

    # ------------------------------------------------------------------------------------------ расписание
    async def tick(self) -> None:
        cfg, st, now = await self.cfg(), await get_state(self._sm), utcnow()
        if st.get("requested"):
            by = str(st["requested"]) if isinstance(st["requested"], str) else ""
            await set_state(self._sm, requested=None)
            self._spawn(self.run("manual", by))
            return
        if not cfg.enabled or cfg.source != "ldap":
            return
        sig = f"{cfg.schedule_time}|{cfg.timezone}"
        due = st.get("next_run")
        if st.get("sig") != sig or not due:                                         # расписание изменилось или ещё не задано: следующий запуск по новому времени
            await set_state(self._sm, sig=sig, next_run=next_run(cfg.schedule_time, ZoneInfo(cfg.timezone), now).isoformat())
            return
        from datetime import datetime  # noqa: PLC0415

        if now >= datetime.fromisoformat(due):
            await set_state(self._sm, next_run=next_run(cfg.schedule_time, ZoneInfo(cfg.timezone), now).isoformat())
            self._spawn(self.run("schedule", ""))

    def _spawn(self, coro) -> None:
        t = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def loop(self) -> None:
        await asyncio.sleep(20)
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка цикла раздела «Иерархия»")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=TICK_S)
            except asyncio.TimeoutError:
                pass

    # ------------------------------------------------------------------------------------------ сбор
    async def _collect(self, cfg: HierSettings, lease) -> S.Collected:
        if cfg.source != "ldap":
            raise S.SourceError("Источник «файл»: загрузите файл выгрузки в настройках раздела — автоматический сбор для него не выполняется.")
        async with self._sm() as db:
            conns = [c for c in await self._ldap.connections(db) if c.enabled and (not cfg.ldap_connections or str(c.id) in cfg.ldap_connections)]
            bundle = await self._ldap.ca_bundle(db)
            cfgs = [self._ldap.config(c, bundle) for c in conns]
        if not cfgs:
            raise S.SourceError("Подключение LDAPS не настроено или выключено: Администрирование → LDAPS. Раздел использует его же, отдельные логин и пароль не нужны.")
        total = S.Collected(name=", ".join(c.name for c in cfgs))
        for c in cfgs:
            await lease.stage(f"чтение каталога «{c.name}»")
            part = await asyncio.to_thread(S.read_ldap, c, cfg.ldap_filter)
            total.records += part.records
            total.errors += part.errors
            total.errors_n += part.errors_n
            total.notes += part.notes
        return total

    async def run(self, trigger: str = "schedule", by: str = "") -> HierSnapshot | None:
        from ..services.jobs import JOBS  # noqa: PLC0415

        if JOBS.busy_here("hier", ""):
            return None
        cfg = await self.cfg()
        async with JOBS.run_heavy("hier", "", "в очереди", task="Иерархия: сбор адресной книги", lane="bi") as lease:
            if lease is None:                                                       # уже выполняется (другим исполнителем)
                return None
            started = utcnow()
            async with self._sm() as db:
                snap = HierSnapshot(started_at=started, status="running", trigger=trigger, by=by[:160], source=cfg.source)
                db.add(snap)
                await db.commit()
                sid = snap.id
            self.current = str(sid)
            await self._emit("collect_start", f"Сбор адресной книги начат ({'вручную' if trigger == 'manual' else 'по расписанию'})", user=by or None)
            try:
                coll = await self._collect(cfg, lease)
            except S.SourceError as exc:
                return await self._fail(sid, str(exc), trigger, cfg)
            except Exception as exc:  # noqa: BLE001
                log.exception("Сбор адресной книги не удался")
                return await self._fail(sid, f"Непредвиденная ошибка сбора: {type(exc).__name__}. Подробности — в журнале службы worker.", trigger, cfg)
            finally:
                self.current = None
            await lease.stage("публикация снимка")
            done = await publish(self._sm, self._svc, sid, coll, trigger, self._journal, by)
            if done.status == "ok":
                await set_state(self._sm, retry_n=None)
            elif done.status == "rejected" and trigger == "schedule":                  # заметное сокращение выгрузки: повтор через 30 минут (каталог мог отвечать не полностью)
                await self._retry_later()
            return done

    async def _retry_later(self) -> None:
        n = int((await get_state(self._sm)).get("retry_n") or 0)
        if n < RETRIES:
            await set_state(self._sm, retry_n=n + 1, next_run=(utcnow() + timedelta(minutes=RETRY_MIN)).isoformat())
        else:
            await set_state(self._sm, retry_n=None)

    async def _fail(self, sid, message: str, trigger: str, cfg: HierSettings) -> HierSnapshot:
        async with self._sm() as db:
            snap = await db.get(HierSnapshot, sid)
            snap.status, snap.finished_at, snap.message = "failed", utcnow(), message[:1000]
            await db.commit()
        await self._emit("collect_failed", message, level="error")
        if trigger == "schedule":
            await self._retry_later()                                               # повтор через 30 минут, не дожидаясь следующих суток
        return snap


async def publish(sm: async_sessionmaker[AsyncSession], svc, sid, coll: S.Collected, trigger: str, journal=None, by: str = "") -> HierSnapshot:
    """Проверки и публикация собранного: ошибка, пустой результат и заметное уменьшение выгрузки снимок не публикуют."""
    async with sm() as db:
        cfg: HierSettings = await svc.get(db, "hier")                               # type: ignore[assignment]
    result = await asyncio.to_thread(P.build, coll.records, rules_of(cfg)) if coll.records else None
    async with sm() as db:
        await xact_lock(db, "hier-publish")
        snap = await db.get(HierSnapshot, sid)
        prev = await latest_ok(db)
        n = len(coll.records)
        h = P.content_hash(coll.records)
        status, msg = "ok", ""
        if n == 0:
            status, msg = "failed", "Каталог вернул 0 записей: проверьте Base DN и фильтр пользователей подключения LDAPS."
        elif trigger != "upload" and cfg.drop_threshold_pct and prev is not None and prev.raw_n and n < prev.raw_n * (100 - cfg.drop_threshold_pct) / 100:
            status = "rejected"
            msg = (f"Записей {n}, в последнем успешном снимке {prev.raw_n}: на {round(100 * (prev.raw_n - n) / prev.raw_n)} % меньше (порог {cfg.drop_threshold_pct} %). "
                   "Снимок не опубликован, показывается предыдущий. Если сокращение настоящее, загрузите выгрузку вручную.")
        snap.raw_n, snap.errors_n, snap.content_hash, snap.finished_at, snap.status = n, coll.errors_n, h, utcnow(), status
        snap.source_name = coll.name[:300]
        snap.warnings = [*(result.warnings if result and status == "ok" else []), *coll.notes][:30]
        snap.stats = result.stats() if result and status == "ok" else {}
        if coll.errors:
            snap.stats = {**snap.stats, "errors": coll.errors[:MAX_ERR]}
        if not msg:
            msg = f"Опубликовано: записей {n}, после очистки {len(result.people)}" + (f", ошибок по записям {coll.errors_n}" if coll.errors_n else "")
        snap.message = msg
        if status == "ok":
            if prev is not None and prev.content_hash == h:
                snap.records, snap.same_as_id = None, prev.same_as_id or prev.id
            else:
                snap.records, snap.same_as_id = coll.records, None
        await db.flush()
        await prune(db, cfg.keep_days)
        await db.commit()
        out_status, out_msg, out_warn = snap.status, snap.message, list(snap.warnings or [])
    if journal is not None:
        await journal.emit("hier", "collect_ok" if out_status == "ok" else f"collect_{out_status}", level="info" if out_status == "ok" else "warn", user=by or None, message=out_msg)
        for w in out_warn:
            await journal.emit("hier", "collect_warning", level="warn", message=w.split(".")[0][:200])
    if coll.errors_n:
        log.warning("Сбор адресной книги: ошибок по отдельным записям %s", coll.errors_n)
    return snap


MAX_ERR = 20
