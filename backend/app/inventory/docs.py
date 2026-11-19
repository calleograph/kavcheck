"""Документы и операции: выдача, возврат, перемещение, приём-передача, передача МЦ, приём неисправного, ремонт, списание, работы.

Документ меняет карточки только на «своём» этапе (как в учётных системах — изменение по факту подтверждения):
* перемещение: «Отправлен» — оборудование «в пути» (`transit_doc_id`), «Принят» — новое местоположение и ответственные; отмена отправленного снимает «в пути»;
* ремонт: «Отправлен» — статус «В ремонте» (прежний статус запоминается в строке), «Завершён» — прежний статус возвращается;
* остальные — при проведении («Завершён»). Каждое изменение — событие истории карточки со ссылкой на документ."""
from __future__ import annotations

from datetime import date

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import InvAsset, InvDoc, InvDocItem, InvLocation, InvPerson, InvRef, utcnow
from ..services.settings import InventorySettings
from . import core as C
from . import model as M

ROLE_FIELD = {"user": "user_id", "owner": "owner_id", "resp": "resp_id", "mol": "mol_id", "it": "it_id"}
# кого назначает документ по умолчанию: выдача — пользователь, передача МЦ — МОЛ, приём-передача — ответственный
DEFAULT_ROLE = {"issue": "user", "handover": "mol", "accept": "resp", "move": ""}


def perm_of(kind: str) -> str:
    return M.DOC_PERM.get(kind, "docs")


def flow_of(kind: str) -> dict:
    return M.DOC_FLOW.get(kind, M.DOC_FLOW_DEFAULT)


async def snap(db: AsyncSession, a: InvAsset) -> dict:
    n = await C.names_for(db, [a], props=False)
    return {"inv_no": a.inv_no, "acc_no": a.acc_no, "serial": a.serial, "name": a.name or n.ref(a.type_id) or M.CLS_RU.get(a.cls, ""),
            "type": n.ref(a.type_id), "model": " ".join(x for x in (n.ref(a.manufacturer_id), n.ref(a.model_id)) if x), "location": n.loc(a.location_id), "cost": a.cost,
            "user": n.person(a.user_id), "status": n.ref(a.status_id)}


async def set_items(db: AsyncSession, doc: InvDoc, items: list[dict], acc: C.Access) -> None:
    """Состав черновика: [{asset_id, condition, note}]. Проверяет область учёта и занятость карточек другими незавершёнными перемещениями."""
    ids = list(dict.fromkeys(int(i["asset_id"]) for i in items))
    if len(ids) > 2000:
        raise HTTPException(status_code=422, detail="В документе не больше 2000 строк")
    assets = {a.id: a for a in (await db.execute(select(InvAsset).where(InvAsset.id.in_(ids)))).scalars()} if ids else {}
    missing = [i for i in ids if i not in assets]
    if missing:
        raise HTTPException(status_code=422, detail=f"Карточки не найдены: {', '.join(map(str, missing[:10]))}")
    if acc.scopes:
        locs = {x.id: x for x in (await db.execute(select(InvLocation).where(InvLocation.id.in_({a.location_id for a in assets.values()} - {None})))).scalars()}
        out = [a.inv_no for a in assets.values() if not acc.loc_ok(locs.get(a.location_id))]
        if out:
            raise HTTPException(status_code=403, detail=f"Вне вашей области учёта: {', '.join(out[:10])}")
    busy = [a.inv_no for a in assets.values() if a.transit_doc_id and a.transit_doc_id != doc.id]
    if busy and doc.kind in ("move", "issue", "return", "writeoff"):
        raise HTTPException(status_code=409, detail=f"В пути по другому перемещению: {', '.join(busy[:10])}")
    if doc.kind in ("issue", "move", "accept", "handover"):
        gone = [a.inv_no for a in assets.values() if a.st_cls in ("writeoff", "decom", "lost")]
        if gone:
            raise HTTPException(status_code=409, detail=f"Списано или выведено из эксплуатации: {', '.join(gone[:10])}")
    have = {it.asset_id: it for it in (await db.execute(select(InvDocItem).where(InvDocItem.doc_id == doc.id))).scalars()}
    keep = set(ids)
    for aid, it in have.items():
        if aid not in keep:
            await db.delete(it)
    by = {int(i["asset_id"]): i for i in items}
    for aid in ids:
        src = by[aid]
        it = have.get(aid)
        s = await snap(db, assets[aid])
        if it is None:
            db.add(InvDocItem(doc_id=doc.id, asset_id=aid, snap=s, condition=str(src.get("condition") or "")[:200], note=str(src.get("note") or "")[:500]))
        else:
            it.snap = {**s, **{k: v for k, v in (it.snap or {}).items() if k.startswith("prev_")}}
            it.condition, it.note = str(src.get("condition") or "")[:200], str(src.get("note") or "")[:500]


async def _status_of(db: AsyncSession, cls: str) -> InvRef:
    st = await C.default_status(db, cls)
    if st is None:
        raise HTTPException(status_code=409, detail=f"В справочнике статусов нет статуса с состоянием «{M.ST_RU.get(cls, cls)}»")
    return st


async def transition(db: AsyncSession, doc: InvDoc, to: str, acc: C.Access, by: str, comment: str = "") -> list[int]:
    """Переход документа на этап `to` с применением изменений к карточкам. Возвращает изменённые карточки. Ошибка — HTTPException (транзакция не фиксируется)."""
    allowed = flow_of(doc.kind).get(doc.status, ())
    if to not in allowed:
        raise HTTPException(status_code=409, detail=f"Из этапа «{M.DOC_STATUS_RU.get(doc.status)}» нельзя перейти в «{M.DOC_STATUS_RU.get(to, to)}»")
    items = list((await db.execute(select(InvDocItem).where(InvDocItem.doc_id == doc.id).order_by(InvDocItem.id))).scalars())
    if not items and to not in ("cancelled", "draft"):
        raise HTTPException(status_code=422, detail="В документе нет оборудования")
    assets = {a.id: a for a in (await db.execute(select(InvAsset).where(InvAsset.id.in_([i.asset_id for i in items])).with_for_update())).scalars()} if items else {}
    full = C.Access(acc.perms | {"edit", "location", "people"}, acc.scopes, acc.scope_ids)       # право на сам документ уже проверено; область учёта — прежняя
    title = f"{M.DOC_SHORT[doc.kind]} {doc.no}"
    touched: list[int] = []
    d = doc.data or {}

    async def change(a: InvAsset, data: dict, kind: str = "doc", what: str = "") -> None:
        ch = await C.apply_changes(db, a, data, full)
        if ch or what:
            await C.record(db, a, kind, ch, by, comment=comment, basis=doc.basis, doc_id=doc.id, title=f"{title}{': ' + what if what else ''}")
            touched.append(a.id)

    to_person = await db.get(InvPerson, doc.to_person_id) if doc.to_person_id else None
    role = d.get("role", DEFAULT_ROLE.get(doc.kind, ""))
    extra_status = d.get("status_id")

    def target(a: InvAsset, *, with_loc: bool = True) -> dict:
        data: dict = {}
        if with_loc and doc.to_location_id and a.location_id != doc.to_location_id:
            data["location_id"] = doc.to_location_id
        if role in ROLE_FIELD and to_person is not None:
            data[ROLE_FIELD[role]] = to_person.id
        for r in d.get("also_roles") or []:                      # назначить того же сотрудника и на другие роли (например, пользователь и владелец)
            if r in ROLE_FIELD and to_person is not None:
                data[ROLE_FIELD[r]] = to_person.id
        if extra_status:
            data["status_id"] = int(extra_status)
        return data

    if doc.kind == "move":
        if to == "sent":
            for it in items:
                a = assets[it.asset_id]
                a.transit_doc_id = doc.id
                await C.record(db, a, "doc", [], by, comment=comment, basis=doc.basis, doc_id=doc.id, title=f"{title}: отправлено в «{(await _loc_path(db, doc.to_location_id))}»")
                touched.append(a.id)
        elif to == "accepted":
            if not doc.to_location_id:
                raise HTTPException(status_code=422, detail="Укажите, куда перемещается оборудование")
            for it in items:
                a = assets[it.asset_id]
                a.transit_doc_id = None
                await change(a, target(a), "move", "принято")
        elif to == "cancelled" and doc.status == "sent":
            for it in items:
                a = assets[it.asset_id]
                if a.transit_doc_id == doc.id:
                    a.transit_doc_id = None
                    await C.record(db, a, "doc", [], by, comment=comment, doc_id=doc.id, title=f"{title}: перемещение отменено")
                    touched.append(a.id)
    elif doc.kind == "repair":
        if to == "sent":
            rep = await _status_of(db, "repair")
            for it in items:
                a = assets[it.asset_id]
                it.snap = {**(it.snap or {}), "prev_status_id": a.status_id}
                await change(a, {"status_id": rep.id}, "repair", f"передано в ремонт ({d.get('vendor') or 'исполнитель не указан'})")
        elif to == "done":
            for it in items:
                a = assets[it.asset_id]
                prev = (it.snap or {}).get("prev_status_id")
                if extra_status:
                    prev = int(extra_status)
                if prev is None or prev == a.status_id:
                    prev = (await _status_of(db, "use" if a.user_id else "stock")).id
                await change(a, {"status_id": prev}, "repair", f"возвращено из ремонта{(': ' + d['result']) if d.get('result') else ''}")
    elif to == "done":
        for it in items:
            a = assets[it.asset_id]
            if doc.kind == "issue":
                if to_person is None:
                    raise HTTPException(status_code=422, detail="Укажите сотрудника, которому выдаётся оборудование")
                data = target(a)
                data.setdefault("status_id", (await _status_of(db, "use")).id)
                await change(a, data, "doc", f"выдано: {to_person.name}")
            elif doc.kind == "return":
                data = target(a)
                for r in ["user", *(d.get("clear_roles") or [])]:
                    if r in ROLE_FIELD:
                        data[ROLE_FIELD[r]] = None
                data.setdefault("status_id", (await _status_of(db, "stock")).id)
                await change(a, data, "doc", "возвращено")
            elif doc.kind == "writeoff":
                acc.need("writeoff")
                data = {"status_id": int(extra_status) if extra_status else (await _status_of(db, "writeoff")).id, "user_id": None}
                await change(a, data, "writeoff", "списано")
            elif doc.kind == "work":
                await change(a, {}, "doc", f"работа выполнена: {M.WORK_KINDS.get(d.get('work_kind', ''), 'работа')}{(' — ' + d['result']) if d.get('result') else ''}")
            else:                                                     # accept, handover, defect
                await change(a, target(a), "doc", "проведено")
    if to in ("done", "cancelled"):
        doc.done_at = utcnow()
    doc.history = [*(doc.history or []), {"at": utcnow().isoformat(), "by": by, "from": doc.status, "to": to, "comment": comment}][-100:]
    doc.status = to
    doc.updated_at = utcnow()
    return touched


async def _loc_path(db: AsyncSession, lid: int | None) -> str:
    loc = await db.get(InvLocation, lid) if lid else None
    return loc.path if loc else "—"


async def new_number(db: AsyncSession, cfg: InventorySettings, kind: str, d: date) -> str:
    pre = (cfg.doc_prefix.get(kind) or M.DOC_PREFIX[kind]) + f"-{d.year}-"
    return await C.next_number(db, InvDoc.no, pre, 5)
