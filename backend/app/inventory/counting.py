"""Инвентаризация (сверка наличия): ожидаемый список, отметка найденного по коду (QR, инвентарный, серийный номер), расхождения и решения.

Сканирование только отмечает факт: учётные данные меняются лишь решением по расхождению (apply — принять фактическое местоположение и пользователя,
lost — утрачено), каждое — событием истории карточки со ссылкой на номер инвентаризации. Повторный скан не дублирует строку; результат по коду однозначен."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import InvAsset, InvCount, InvCountItem, InvLocation, InvPerson, utcnow
from . import core as C
from . import model as M


def _via(a: InvAsset, code: str) -> str:
    c = code.strip().casefold()
    if c == a.inv_no.casefold():
        return "inv_no"
    if a.serial and c == a.serial.casefold():
        return "serial"
    return "uid"


async def scope_assets(db: AsyncSession, cnt: InvCount, acc: C.Access) -> list[InvAsset]:
    """Ожидаемые единицы: действующие, подлежащие инвентаризации, в узле с вложенными (и в области учёта пользователя), нужных классов."""
    w = [InvAsset.st_cls.in_(M.ST_ACTIVE), InvAsset.no_count.is_(False)]
    if cnt.location_id:
        loc = await db.get(InvLocation, cnt.location_id)
        w.append(InvAsset.location_id.in_(select(InvLocation.id).where(InvLocation.ids_path.like((loc.ids_path if loc else "/-/") + "%"))))
    if cnt.cls:
        w.append(InvAsset.cls.in_([c for c in cnt.cls.split(",") if c in M.CLS_RU]))
    if (af := acc.asset_filter()) is not None:
        w.append(af)
    return list((await db.execute(select(InvAsset).where(*w).order_by(InvAsset.location_id, InvAsset.inv_no).limit(200_000))).scalars())


def snap_of(a: InvAsset, n: C.Names) -> dict:
    return {"inv_no": a.inv_no, "serial": a.serial, "name": C.label(a, n).rsplit(" (", 1)[0], "uid": str(a.uid), "location": n.loc(a.location_id), "user": n.person(a.user_id),
            "resp": n.person(a.resp_id), "cls": a.cls}


async def start(db: AsyncSession, cnt: InvCount, acc: C.Access) -> int:
    if cnt.status != "draft":
        raise HTTPException(status_code=409, detail="Инвентаризация уже начата")
    assets = await scope_assets(db, cnt, acc)
    for i in range(0, len(assets), 1000):
        part = assets[i:i + 1000]
        n = await C.names_for(db, part, props=False)
        db.add_all([InvCountItem(count_id=cnt.id, asset_id=a.id, expected=True, exp_location_id=a.location_id, exp_user_id=a.user_id, snap=snap_of(a, n), state="pending") for a in part])
    cnt.status, cnt.started_at = "active", utcnow()
    cnt.stats = {"expected": len(assets)}
    return len(assets)


async def scan(db: AsyncSession, cnt: InvCount, code: str, location_id: int | None, by: str, *, user_id: int | None = None, at: datetime | None = None) -> dict:
    """Отметка найденного. result: found | moved | extra | unknown | again (уже отмечено) — и строка для показа."""
    if cnt.status != "active":
        raise HTTPException(status_code=409, detail="Сканирование возможно только в начатой инвентаризации")
    code = (code or "").strip()[:200]
    if not code:
        raise HTTPException(status_code=422, detail="Пустой код")
    a = await C.asset_by_code(db, code)
    when = at or utcnow()
    if a is None:
        it = (await db.execute(select(InvCountItem).where(InvCountItem.count_id == cnt.id, InvCountItem.asset_id.is_(None), or_(InvCountItem.code == code, func.lower(InvCountItem.code) == code.casefold())))).scalar_one_or_none()
        if it is None:
            it = InvCountItem(count_id=cnt.id, code=code, expected=False, state="unknown", found_location_id=location_id, found_at=when, found_by=by, found_via="code", snap={"code": code})
            db.add(it)
            await db.flush()
            return {"result": "unknown", "item": item_out(it)}
        return {"result": "again", "item": item_out(it)}
    it = (await db.execute(select(InvCountItem).where(InvCountItem.count_id == cnt.id, InvCountItem.asset_id == a.id))).scalar_one_or_none()
    if it is not None and it.found_at is not None and it.found_location_id == location_id and (user_id is None or it.found_user_id == user_id):
        return {"result": "again", "item": item_out(it)}
    if it is None:                                                                    # не было в ожидаемом списке (другое помещение, не та область, не числилось действующим)
        n = await C.names_for(db, [a], props=False)
        it = InvCountItem(count_id=cnt.id, asset_id=a.id, expected=False, exp_location_id=a.location_id, exp_user_id=a.user_id, snap=snap_of(a, n))
        db.add(it)
    it.found_location_id, it.found_at, it.found_by, it.found_via = location_id, when, by, _via(a, code)
    if user_id is not None:
        it.found_user_id = user_id
    it.state = "extra" if not it.expected else ("moved" if location_id is not None and it.exp_location_id != location_id else "found")
    it.decision = ""
    await db.flush()
    return {"result": it.state, "item": item_out(it)}


def item_out(it: InvCountItem, locs: dict | None = None, people: dict | None = None) -> dict:
    s = it.snap or {}
    user_diff = it.found_user_id is not None and it.found_user_id != it.exp_user_id
    return {"id": it.id, "asset_id": it.asset_id, "code": it.code, "expected": it.expected, "state": it.state, "state_ru": M.COUNT_STATE_RU.get(it.state, it.state),
            "inv_no": s.get("inv_no", ""), "serial": s.get("serial", ""), "name": s.get("name", s.get("code", "")), "uid": s.get("uid", ""), "exp_location_id": it.exp_location_id,
            "exp_location": (locs or {}).get(it.exp_location_id, s.get("location", "")), "found_location_id": it.found_location_id, "found_location": (locs or {}).get(it.found_location_id, ""),
            "user": s.get("user", ""), "found_user_id": it.found_user_id, "found_user": (people or {}).get(it.found_user_id, ""), "user_diff": user_diff,
            "found_at": C._iso(it.found_at), "found_by": it.found_by, "found_via": it.found_via, "decision": it.decision, "decision_ru": M.COUNT_DECISION_RU.get(it.decision, ""),
            "decided_by": it.decided_by, "note": it.note,
            "discrepancy": it.state in ("moved", "extra", "unknown", "missing") or user_diff}


async def names(db: AsyncSession, items: list[InvCountItem]) -> tuple[dict, dict]:
    lids = {x for it in items for x in (it.exp_location_id, it.found_location_id)} - {None}
    pids = {it.found_user_id for it in items} - {None}
    locs = dict((await db.execute(select(InvLocation.id, InvLocation.path).where(InvLocation.id.in_(lids)))).all()) if lids else {}
    people = dict((await db.execute(select(InvPerson.id, InvPerson.name).where(InvPerson.id.in_(pids)))).all()) if pids else {}
    return locs, people


async def stats(db: AsyncSession, cnt: InvCount) -> dict:
    """Итоги по состояниям и по местоположениям (ожидалось, найдено на месте, осталось) — для вкладки «Статистика» и показателей."""
    by_state = dict((await db.execute(select(InvCountItem.state, func.count()).where(InvCountItem.count_id == cnt.id).group_by(InvCountItem.state))).all())
    rows = (await db.execute(select(InvCountItem.exp_location_id, InvCountItem.state, InvCountItem.expected, func.count()).where(InvCountItem.count_id == cnt.id)
                             .group_by(InvCountItem.exp_location_id, InvCountItem.state, InvCountItem.expected))).all()
    per: dict = defaultdict(lambda: {"expected": 0, "found": 0, "left": 0, "moved_out": 0})
    for lid, st, exp, n in rows:
        if not exp:
            continue
        p = per[lid]
        p["expected"] += n
        if st == "found":
            p["found"] += n
        elif st in ("pending", "missing"):
            p["left"] += n
        elif st == "moved":
            p["moved_out"] += n
    lids = [k for k in per if k is not None]
    paths = dict((await db.execute(select(InvLocation.id, InvLocation.path).where(InvLocation.id.in_(lids)))).all()) if lids else {}
    users = (await db.execute(select(func.count()).select_from(InvCountItem).where(InvCountItem.count_id == cnt.id, InvCountItem.found_user_id.is_not(None),
                                                                                    or_(InvCountItem.exp_user_id.is_(None), InvCountItem.found_user_id != InvCountItem.exp_user_id)))).scalar_one()
    locs = sorted(({"location_id": k, "location": paths.get(k, "Без местоположения"), **v, "done": v["left"] == 0} for k, v in per.items()), key=lambda x: x["location"])
    expected = sum(v["expected"] for v in per.values())
    return {"by_state": {k: by_state.get(k, 0) for k in M.COUNT_STATE_RU}, "expected": expected, "checked": expected - sum(v["left"] for v in per.values()), "user_diff": users, "locations": locs}


async def close(db: AsyncSession, cnt: InvCount, by: str) -> None:
    if cnt.status != "active":
        raise HTTPException(status_code=409, detail="Завершить можно только начатую инвентаризацию")
    for it in (await db.execute(select(InvCountItem).where(InvCountItem.count_id == cnt.id, InvCountItem.state == "pending"))).scalars():
        it.state = "missing"
    cnt.status, cnt.closed_at, cnt.closed_by = "closed", utcnow(), by
    await db.flush()
    cnt.stats = await stats(db, cnt)


async def decide(db: AsyncSession, cnt: InvCount, item_ids: list[int], decision: str, acc: C.Access, by: str, note: str = "") -> int:
    """Решение по расхождениям. apply: местоположение и (если отмечен) пользователь — как найдено; lost: статус «Утрачено»; keep / ignore — учёт не меняется.
    Изменения карточек — событием истории с номером инвентаризации в основании."""
    if decision not in M.COUNT_DECISION_RU:
        raise HTTPException(status_code=422, detail="Неизвестное решение")
    items = list((await db.execute(select(InvCountItem).where(InvCountItem.count_id == cnt.id, InvCountItem.id.in_(item_ids)))).scalars())
    changed = 0
    full = C.Access(acc.perms | {"edit", "location", "people"}, acc.scopes, acc.scope_ids)
    for it in items:
        if decision in ("apply", "lost") and it.asset_id is None:
            raise HTTPException(status_code=422, detail=f"Код «{it.code}» не найден в учёте: создайте карточку и отсканируйте снова")
        if decision == "lost" and it.state != "missing":
            raise HTTPException(status_code=422, detail="«Утрачено» — только для не найденного")
        if decision in ("apply", "lost"):
            a = await db.get(InvAsset, it.asset_id, with_for_update=True)
            data: dict = {}
            if decision == "apply":
                if it.found_location_id and it.found_location_id != a.location_id:
                    data["location_id"] = it.found_location_id
                if it.found_user_id and it.found_user_id != a.user_id:
                    data["user_id"] = it.found_user_id
            else:
                st = await C.default_status(db, "lost")
                if st is None:
                    raise HTTPException(status_code=409, detail="В справочнике статусов нет статуса «Утрачено»")
                data["status_id"] = st.id
            ch = await C.apply_changes(db, a, data, full) if data else []
            if ch:
                await C.record(db, a, "count", ch, by, basis=f"Инвентаризация {cnt.no}", comment=note, title=f"Инвентаризация {cnt.no}: {M.COUNT_DECISION_RU[decision].lower()}")
                changed += 1
        it.decision, it.decided_by, it.decided_at = decision, by, utcnow()
        if note:
            it.note = note[:500]
    return changed
