"""Сопоставление устройств BI с компьютерами KSC. Главное правило — не объединять ошибочно.

* Данные KSC — подготовленные данные зон (текущее поколение каждого источника): KSC не опрашивается.
* Одинаковое имя само по себе не доказывает идентичность: имя должно быть единственным среди всех источников KSC и подкреплено ещё одним признаком
  (совпадает семейство ОС, полное имя FQDN или учётная запись KSC на компьютере совпадает с почтой сотрудника) — тогда «предполагаемое» (auto).
  Только имя — «кандидат»; несколько компьютеров — «неоднозначно»; ОС противоречит — «противоречие». Всё это — «не сопоставлено», решение за администратором.
* IP-адрес не используется: адреса переиспользуются. Условные имена («Личный ПК») по имени не сопоставляются.
* Решения администратора (confirmed/rejected) не пересчитываются; отклонённая пара больше не предлагается."""
from __future__ import annotations

import logging
from collections import defaultdict

from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..db import xact_lock
from ..ksc.protection import PROBLEMS
from ..models import BiDevice, BiMatch, BiOwner, BiPerson, BiSource, DeviceUser, KscSource, ZcHost, ZcSource, utcnow
from .profile import os_family, short_name

log = logging.getLogger("app.bi")
LINKED = ("auto", "confirmed")
MANUAL = ("confirmed", "rejected")
LEVEL_RU = {"confirmed": "Надёжное (подтверждено администратором)", "auto": "Предполагаемое", "candidate": "Не сопоставлено: совпадает только имя",
            "ambiguous": "Не сопоставлено: несколько компьютеров с этим именем", "conflict": "Не сопоставлено: признаки противоречат", "rejected": "Отклонено администратором"}
OS_RU = {"windows": "Windows", "linux": "Linux", "mac": "macOS"}
CHUNK = 1000


async def ksc_gens(db: AsyncSession) -> dict:
    return {sid: int(g) for sid, g in (await db.execute(select(ZcSource.source_id, ZcSource.gen).join(KscSource, KscSource.id == ZcSource.source_id)
                                                        .where(KscSource.is_active.is_(True), ZcSource.gen > 0))).all()}


def gens_stamp(gens: dict) -> str:
    return ",".join(f"{s}:{g}" for s, g in sorted(gens.items(), key=lambda x: str(x[0])))


async def ksc_index(db: AsyncSession, gens: dict, shorts: set[str], fqdns: set[str], extra: set[tuple]) -> tuple[dict, dict, dict]:
    """(короткое имя → компьютеры, FQDN → компьютеры, (источник, компьютер) → сведения) только для компьютеров с именами устройств BI и пар с решением администратора.
    Имена читаются потоком (в памяти — лишь совпавшие), подробности — порциями для найденных: источники в сотни тысяч компьютеров не загружаются целиком.
    Кандидаты ищутся по короткому имени (у FQDN оно то же); FQDN — признак, проверяемый для найденных."""
    by_short: dict[str, list] = defaultdict(list)
    by_fqdn: dict[str, list] = defaultdict(list)
    hosts: dict[tuple, dict] = {}
    H = ZcHost
    for sid, gen in sorted(gens.items(), key=lambda x: str(x[0])):
        want = {hid for s_, hid in extra if s_ == sid}
        found: list[int] = []
        res = await db.stream(select(H.host_id, H.name).where(H.source_id == sid, H.gen == gen).execution_options(yield_per=10000))
        async for part in res.partitions():                  # порциями, без разбора JSON: 520 тыс. компьютеров стенда — 4 с вместо 37 с построчно
            for hid, name in part:
                if (name and short_name(name) in shorts) or hid in want:
                    found.append(int(hid))
        for i in range(0, len(found), CHUNK):
            q = select(H.host_id, H.name, H.data["fqdn"].as_string(), H.os, H.has_av, H.p_no_av, H.p_rtp, H.active).where(H.source_id == sid, H.gen == gen, H.host_id.in_(found[i:i + CHUNK]))
            for hid, name, fqdn, os, has_av, no_av, rtp, active in (await db.execute(q)).all():
                h = {"sid": sid, "hid": int(hid), "name": name or "", "fqdn": (fqdn or "").lower(), "os": os or "", "has_av": bool(has_av), "no_av": bool(no_av), "rtp": bool(rtp), "active": bool(active)}
                hosts[(sid, h["hid"])] = h
                if h["name"] and short_name(h["name"]) in shorts:
                    by_short[short_name(h["name"])].append(h)
                if h["fqdn"] and h["fqdn"] in fqdns:
                    by_fqdn[h["fqdn"]].append(h)
    return by_short, by_fqdn, hosts


def issues(dev: dict, h: dict, owner_locals: set[str], logins: set[str]) -> list[dict]:
    """Расхождения BI и KSC для сопоставленной пары. Сведения BI об антивирусе не подменяют состояние защиты KSC — расхождение только показывается."""
    out = []
    av = dev.get("av") or {}
    if av.get("uses") is True and h["no_av"]:
        out.append({"code": "av_missing", "text": f"BI: антивирус используется; KSC: {PROBLEMS['no_av'][0].lower()}"})
    if av.get("uses") is True and h["rtp"]:
        out.append({"code": "av_broken", "text": "BI: антивирус используется; KSC: защита не работает"})
    if av.get("uses") is False and h["has_av"] and not h["rtp"]:
        out.append({"code": "av_present", "text": "BI: антивирус не используется; KSC: Kaspersky установлен и защита работает"})
    if av.get("other") and h["has_av"]:
        out.append({"code": "av_other", "text": f"BI: указан сторонний антивирус ({av['other'][:60]}); KSC: установлен Kaspersky"})
    fb, fk = dev.get("os_family") or "", os_family(h["os"])
    if fb and fk and fb != fk:
        out.append({"code": "os", "text": f"ОС различается: BI — {OS_RU[fb]}, KSC — {OS_RU[fk]}"})
    if owner_locals and logins and not owner_locals & logins:
        out.append({"code": "user", "text": "Учётные записи KSC на компьютере не совпадают с почтой владельца по BI"})
    return out


def decide(dev: dict, cands: list[dict], owner_locals: set[str], logins_of, same_name: int = 0) -> tuple[str, list[str]]:
    """Уровень и основание для единственного кандидата (или нескольких)."""
    n = max(len(cands), same_name)
    if n > 1:
        return "ambiguous", [f"имя «{dev['short']}» есть у {n} компьютеров KSC"]
    h = cands[0]
    sig = [f"имя «{dev['short']}» единственное среди источников KSC"]
    strong = False
    fb, fk = dev.get("os_family") or "", os_family(h["os"])
    if fb and fk:
        if fb != fk:
            return "conflict", [*sig, f"ОС различается: BI — {OS_RU[fb]}, KSC — {OS_RU[fk]}"]
        sig.append(f"семейство ОС совпадает ({OS_RU[fb]})")
        strong = True
    if "." in dev["name"] and dev["name"].lower() == h["fqdn"]:
        sig.append("полное имя (FQDN) совпадает")
        strong = True
    if owner_locals & logins_of(h):
        sig.append("учётная запись KSC совпадает с почтой сотрудника")
        strong = True
    return ("auto" if strong else "candidate"), sig


async def run(sm: async_sessionmaker[AsyncSession], bi_source_id, *, force: bool = False, lease=None) -> dict | None:
    """Пересчитать сопоставление источника BI. Без изменений в снимке и данных KSC — пропуск (если не force)."""
    async with sm() as db:
        src = await db.get(BiSource, bi_source_id)
        if src is None or src.last_import_id is None:
            return None
        gens = await ksc_gens(db)
        stamp = f"{src.last_import_id}|{gens_stamp(gens)}"[:600]
        if stamp == src.match_stamp and not force:
            return None
        devs = [dict(id=i, name=n, short=s, names=ns or [], os_family=f, av=av or {}) for i, n, s, ns, f, av in (await db.execute(
            select(BiDevice.id, BiDevice.name, BiDevice.short, BiDevice.names, BiDevice.os_family, BiDevice.av).where(BiDevice.source_id == bi_source_id, BiDevice.generic.is_(False)))).all()]
        locals_: dict[int, set] = defaultdict(set)
        for d, email in (await db.execute(select(BiOwner.device_id, BiPerson.email).join(BiPerson, BiPerson.id == BiOwner.person_id).where(BiOwner.source_id == bi_source_id, BiPerson.email != ""))).all():
            locals_[int(d)].add(email.split("@", 1)[0].lower())
        manual = {(m.device_id, m.ksc_source_id, m.host_id): m for m in (await db.execute(select(BiMatch).where(BiMatch.bi_source_id == bi_source_id, BiMatch.level.in_(MANUAL)))).scalars()}
        shorts = {d["short"] for d in devs if d["short"]} | {short_name(x["name"]) for d in devs for x in d["names"]}
        by_short, by_fqdn, hosts = await ksc_index(db, gens, shorts, {d["name"].lower() for d in devs if "." in d["name"]}, {(s_, h_) for _d, s_, h_ in manual})
        confirmed = {k[0] for k, m in manual.items() if m.level == "confirmed"}
        cands: dict[int, list] = {}
        same_name: dict[int, int] = {}                                  # всех компьютеров с этим именем, включая отклонённые: отказ от одного не делает имя другого единственным
        for d in devs:
            seen, out = set(), []
            for nm in [d["short"], *(short_name(x["name"]) for x in d["names"])]:
                for h in by_short.get(nm, []) + (by_fqdn.get(d["name"].lower(), []) if "." in d["name"] else []):
                    k = (h["sid"], h["hid"])
                    if k not in seen:
                        seen.add(k)
                        if (d["id"], *k) not in manual:
                            out.append(h)
            cands[d["id"]], same_name[d["id"]] = out, len(seen)
        need: dict = defaultdict(set)                                   # учётные записи KSC нужны только для компьютеров-кандидатов
        for out in cands.values():
            for h in out:
                need[h["sid"]].add(h["hid"])
        for (_d, s, hid) in manual:
            need[s].add(hid)
        logins: dict[tuple, set] = defaultdict(set)
        for s, hids in need.items():
            ids = sorted(hids)
            for i in range(0, len(ids), CHUNK):
                for hid, login in (await db.execute(select(DeviceUser.host_id, DeviceUser.login).where(DeviceUser.source_id == s, DeviceUser.host_id.in_(ids[i:i + CHUNK]), DeviceUser.kind == "user",
                                                                                                         DeviceUser.resolved.is_(True)))).all():
                    logins[(s, int(hid))].add(login.lower())
        rows, n = [], defaultdict(int)
        now = utcnow()
        for d in devs:
            out = cands[d["id"]]
            if d["id"] in confirmed or not out:
                n["confirmed" if d["id"] in confirmed else "none"] += 1
                continue
            level, sig = decide(d, out, locals_[d["id"]], lambda h: logins[(h["sid"], h["hid"])], same_name[d["id"]])
            n[level] += 1
            for h in out:
                iss = issues(d, h, locals_[d["id"]], logins[(h["sid"], h["hid"])]) if level == "auto" else []
                rows.append({"device_id": d["id"], "bi_source_id": bi_source_id, "ksc_source_id": h["sid"], "host_id": h["hid"], "host_name": h["name"][:300], "level": level, "signals": sig,
                             "issues": iss, "decided_by": "", "decided_at": None, "note": "", "updated_at": now})
        dev_by_id = {d["id"]: d for d in devs}
        await xact_lock(db, f"bi-match:{bi_source_id}")
        if lease is not None:
            await lease.fence(db)
        await db.execute(delete(BiMatch).where(BiMatch.bi_source_id == bi_source_id, BiMatch.level.notin_(MANUAL)))
        for i in range(0, len(rows), CHUNK):
            await db.execute(insert(BiMatch), rows[i:i + CHUNK])
        for (dv, s, hid), m in manual.items():                           # решения администратора сохраняются; для подтверждённых обновляются расхождения
            h = hosts.get((s, hid))
            if m.level == "confirmed" and dv in dev_by_id:
                await db.execute(update(BiMatch).where(BiMatch.id == m.id).values(issues=issues(dev_by_id[dv], h, locals_[dv], logins[(s, hid)]) if h else [{"code": "gone", "text": "Компьютер больше не найден в данных KSC"}],
                                                                                 host_name=(h["name"] if h else m.host_name)[:300], updated_at=now))
        src.match_stamp, src.matched_at = stamp, now
        await db.commit()
    log.info("Сопоставление BI выполнено", extra={"source": str(bi_source_id), "counts": dict(n)})
    return dict(n)
