"""Сопоставление устройств BI с компьютерами KSC. Главное правило — не объединять ошибочно.

* Данные KSC — подготовленные данные зон (текущее поколение каждого источника): KSC не опрашивается.
* Одинаковое имя само по себе не доказывает идентичность: имя должно быть единственным среди всех источников KSC и подкреплено ещё одним признаком
  (совпадает семейство ОС, полное имя FQDN или учётная запись KSC на компьютере совпадает с почтой сотрудника) — тогда «предполагаемое» (auto).
  Только имя — «кандидат»; несколько компьютеров — «неоднозначно»; ОС противоречит — «противоречие». Всё это — «не сопоставлено», решение за администратором.
* IP-адрес не используется: адреса переиспользуются. Условные имена («Личный ПК») по имени не сопоставляются.
* Решения администратора (confirmed/rejected) не пересчитываются; отклонённая пара больше не предлагается.
* Активность (0.19.0). Записи с одним именем в разных источниках KSC не объединяются: у каждой своя дата последнего подключения Агента (tmLastNagentConnected, поле
  главного признака активности, см. docs/ksc/DEVICES.md). Актуальной считается запись, активная за период (по умолчанию 30 дней): единственная — сразу, при нескольких — с более
  поздним подключением, если разница не меньше порога (по умолчанию 3 дня) и данные источников свежи. Давно не подключавшиеся записи (stale) не мешают. Нет активных — «актуальный
  компьютер KSC не найден» (inactive); даты в будущем, почти равные даты, устаревший срез данных — ручное решение с объяснением. Подтверждённые связи автоматически не переключаются:
  связь по правилу при переходе компьютера обновляется с сохранением прежней (history), подтверждённая администратором — только предложением «переход между KSC»."""
from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter, defaultdict
from datetime import timedelta

from sqlalchemy import and_, delete, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..db import xact_lock
from ..ksc.protection import PROBLEMS
from ..models import BiDevice, BiMatch, BiOwner, BiPerson, BiSource, DeviceUser, KscSource, ZcHost, ZcSource, utcnow
from .profile import os_family, short_name

log = logging.getLogger("app.bi")
LINKED = ("auto", "confirmed")
MANUAL = ("confirmed", "rejected", "manual")          # manual — автоподтверждение отменено администратором: пара больше не подтверждается правилом, решение — вручную
RULE = "правило: точное совпадение имени"
RULE_NOTE = "Подтверждено автоматически по правилу точного совпадения имени и активности (однозначная актуальная запись KSC; физическая идентичность устройства этим не доказана)"
DEFAULT_DAYS = 30                                     # период активности, суток
DEFAULT_MARGIN = 3                                    # записи, активные в пределах периода, различаются по дате подключения не меньше чем на столько суток, чтобы выбрать позднюю
KEEP = MANUAL + ("history",)                          # строки, которые пересчёт не удаляет
_ZW = re.compile(r"[\s\u200b\u200c\u200d\ufeff]+")


def norm_name(name: str) -> str:
    """Имя для точного сравнения: без учёта регистра и технических пробелов (неразрывные, нулевой ширины, по краям). Короткое имя и FQDN — разные имена."""
    return _ZW.sub("", name or "").lower()
LEVEL_RU = {"confirmed": "Надёжное (подтверждено)", "auto": "Предполагаемое", "candidate": "Не сопоставлено: совпадает только имя",
            "ambiguous": "Не сопоставлено: несколько компьютеров с этим именем", "conflict": "Не сопоставлено: признаки противоречат", "rejected": "Отклонено администратором",
            "manual": "Требуется ручное решение: автоподтверждение отменено", "stale": "Устаревшая запись KSC", "inactive": "Актуальный компьютер KSC не найден",
            "history": "Прежнее соответствие"}
NAME_RU = {"exact": "Точное совпадение имени", "exact_dup": "Точное совпадение имени, но есть конкурирующие записи", "short": "Совпадает короткое имя (имя ↔ FQDN)",
           "moved": "Возможный переход между источниками KSC", "": ""}
ACT_RU = {"active": "активен", "stale": "не подключался более заданного периода", "none": "нет сведений о подключении Агента", "future": "дата подключения недостоверна (в будущем)", "": ""}
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
            q = select(H.host_id, H.name, H.data["fqdn"].as_string(), H.os, H.has_av, H.p_no_av, H.p_rtp, H.active, H.last_connected).where(H.source_id == sid, H.gen == gen, H.host_id.in_(found[i:i + CHUNK]))
            for hid, name, fqdn, os, has_av, no_av, rtp, active, last in (await db.execute(q)).all():
                h = {"sid": sid, "hid": int(hid), "name": name or "", "fqdn": (fqdn or "").lower(), "os": os or "", "has_av": bool(has_av), "no_av": bool(no_av), "rtp": bool(rtp), "active": bool(active),
                     "last": last, "act": ""}
                hosts[(sid, h["hid"])] = h
                if h["name"] and short_name(h["name"]) in shorts:
                    by_short[short_name(h["name"])].append(h)
                if h["fqdn"] and h["fqdn"] in fqdns:
                    by_fqdn[h["fqdn"]].append(h)
    return by_short, by_fqdn, hosts


def fmt_d(t) -> str:
    return t.strftime("%d.%m.%Y") if t else "—"


def dn(n: int) -> str:
    """«1 день», «3 дня», «30 дней»."""
    return f"{n} " + ("день" if n % 10 == 1 and n % 100 != 11 else "дня" if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14 else "дней")


def classify_host(h: dict, now, days: int) -> str:
    """Состояние записи KSC по последнему подключению Агента: active — за `days` суток; stale — давнее; none — сведений нет (Агент не подключался); future — дата в будущем (часы, ошибка данных)."""
    last = h.get("last")
    if last is None:
        return "none"
    if last > now + timedelta(days=1):
        return "future"
    return "active" if last >= now - timedelta(days=days) else "stale"


def pick_current(hosts: list[dict], now, days: int, margin_days: int, built: dict, names: dict) -> dict:
    """Какая из записей KSC с одним именем актуальна. Записи разных источников не объединяются — выбирается актуальный источник управления компьютером.
    Результат: verdict — single (одна активная), latest (активны несколько, одна подключалась заметно позже), none_active / no_data (актуальной нет), tie (даты почти равны),
    old_data (срез данных источника старше последнего подключения победителя), dubious (дата в будущем); winner — запись или None; short — основание для интерфейса; reason — полное объяснение.
    Автоматически выбирается только single и latest; иное — ручное решение с причиной."""
    def lbl(h: dict) -> str:
        return f"«{names.get(h['sid'], '?')}»"
    for h in hosts:
        h["act"] = h.get("act") or classify_host(h, now, days)
    future = [h for h in hosts if h["act"] == "future"]
    if future:
        h = future[0]
        r = f"недостоверная дата подключения {fmt_d(h['last'])} (в будущем) у компьютера в источнике {lbl(h)}: актуальная запись автоматически не определяется"
        return {"verdict": "dubious", "winner": None, "short": r, "reason": r}
    active = sorted((h for h in hosts if h["act"] == "active"), key=lambda h: h["last"], reverse=True)
    if not active:
        dated = [h for h in hosts if h["last"] is not None]
        if not dated:
            r = "ни у одной записи KSC нет сведений о подключении Агента: актуальный компьютер не определён"
            return {"verdict": "no_data", "winner": None, "short": r, "reason": r}
        h = max(dated, key=lambda x: x["last"])
        r = f"актуальный компьютер KSC не найден: ни одна запись не подключалась за {dn(days)} (последнее подключение {fmt_d(h['last'])}, источник {lbl(h)})"
        return {"verdict": "none_active", "winner": None, "short": r, "reason": r}
    if len(active) == 1:
        w = active[0]
        return {"verdict": "single", "winner": w, "short": f"единственный активный источник KSC за {dn(days)}",
                "reason": f"единственная активная запись за {dn(days)}: источник {lbl(w)}, подключение {fmt_d(w['last'])}"}
    a, b = active[0], active[1]
    listing = "; ".join(f"{lbl(h)} — {fmt_d(h['last'])}" for h in active)
    if a["last"] - b["last"] < timedelta(days=margin_days):
        r = f"активны несколько записей ({listing}), даты подключения различаются менее чем на {dn(margin_days)}: актуальную запись автоматически выбрать нельзя"
        return {"verdict": "tie", "winner": None, "short": r, "reason": r}
    for o in active[1:]:
        bt = built.get(o["sid"])
        if bt is None or bt < a["last"] - timedelta(days=1):
            r = (f"данные источника {lbl(o)} получены {fmt_d(bt)}, раньше последнего подключения на {lbl(a)} ({fmt_d(a['last'])}): "
                 "после этого компьютер мог подключиться и к нему — актуальность не подтверждена")
            return {"verdict": "old_data", "winner": None, "short": r, "reason": r}
    return {"verdict": "latest", "winner": a, "short": f"активен на нескольких источниках KSC, на {lbl(a)} подключение позже ({fmt_d(a['last'])}, на {lbl(b)} — {fmt_d(b['last'])})",
            "reason": f"активны несколько записей ({listing}); подключение на {lbl(a)} позже не менее чем на {dn(margin_days)}, данные источников свежи"}


def other_reason(h: dict, w: dict | None, days: int, names: dict, *, src: bool = False) -> str:
    """Почему запись не актуальна (для строки «устаревшая запись»). Источник называется, только если строка показывается без него (src=True)."""
    at = f" в источнике «{names.get(h['sid'], '?')}»" if src else ""
    if h["act"] == "stale":
        return f"не подключалась более {dn(days)}{at} (последнее подключение {fmt_d(h['last'])})"
    if h["act"] == "none":
        return f"нет сведений о подключении Агента{at}: актуальной считается другая запись"
    if w is not None and h["act"] == "active":
        return f"уступает по дате подключения: {fmt_d(h['last'])}{at} против {fmt_d(w['last'])} у актуальной записи («{names.get(w['sid'], '?')}»)"
    return "не актуальна"


def settings_of(src) -> tuple[bool, int, int]:
    """(автоподтверждение, период активности в сутках, порог различия дат в сутках) из настроек BI-источника."""
    o = src.options or {}
    margin = o.get("activity_margin_days")
    return bool(o.get("auto_exact")), int(o.get("activity_days") or DEFAULT_DAYS), DEFAULT_MARGIN if margin is None else int(margin)


def make_stamp(src, gens: dict, now) -> str:
    """Отпечаток исходных данных сопоставления: снимок BI, поколения данных KSC, настройки и текущие сутки (активность зависит от даты: без новых данных пересчёт раз в сутки)."""
    auto, days, margin = settings_of(src)
    return hashlib.sha1(f"{src.last_import_id}|{gens_stamp(gens)}|{int(auto)}|{days}|{margin}|{now:%Y-%m-%d}".encode()).hexdigest()


async def ksc_meta(db: AsyncSession, gens: dict) -> tuple[dict, dict]:
    """(источник → название, источник → срез данных KSC): свежесть среза нужна, чтобы не считать запись устаревшей по данным, полученным раньше последнего подключения."""
    names = {i: n for i, n in (await db.execute(select(KscSource.id, KscSource.name))).all()}
    built = {i: (b or f) for i, b, f in (await db.execute(select(ZcSource.source_id, ZcSource.built_at, ZcSource.finished_at).where(ZcSource.source_id.in_(list(gens) or [None])))).all()}
    return names, built


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


def decide(dev: dict, cands: list[dict], owner_locals: set[str], logins_of, same_name: int = 0, lead: str = "") -> tuple[str, list[str]]:
    """Уровень и основание для единственного кандидата (или нескольких). lead — основание выбора актуальной записи (активность); без него — прежнее: имя единственное среди источников."""
    n = max(len(cands), same_name)
    if n > 1:
        return "ambiguous", [f"имя «{dev['short']}» есть у {n} компьютеров KSC"]
    h = cands[0]
    sig = [lead or f"имя «{dev['short']}» единственное среди источников KSC"]
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


async def stale(sm: async_sessionmaker[AsyncSession], bi_source_id) -> bool:
    """Нужно ли пересопоставление: снимок BI, поколение данных KSC, настройки или сутки изменились (два лёгких запроса; без аренды и записи в журнал заданий)."""
    async with sm() as db:
        src = await db.get(BiSource, bi_source_id)
        if src is None or src.last_import_id is None:
            return False
        return make_stamp(src, await ksc_gens(db), utcnow()) != src.match_stamp


def row_of(d: dict, h: dict, bi_source_id, now, level: str, sig: list, iss: list, nm: str, **extra) -> dict:
    return {"device_id": d["id"], "bi_source_id": bi_source_id, "ksc_source_id": h["sid"], "host_id": h["hid"], "host_name": h["name"][:300], "level": level, "signals": sig, "issues": iss,
            "decided_by": "", "decided_at": None, "note": "", "updated_at": now, "name_match": nm, "host_last_connected": h.get("last"), "activity": h.get("act", ""), **extra}


async def run(sm: async_sessionmaker[AsyncSession], bi_source_id, *, force: bool = False, lease=None) -> dict | None:
    """Пересчитать сопоставление источника BI. Без изменений в снимке, данных KSC, настройках и сутках — пропуск (если не force)."""
    async with sm() as db:
        src = await db.get(BiSource, bi_source_id)
        if src is None or src.last_import_id is None:
            return None
        gens = await ksc_gens(db)
        now = utcnow()
        stamp = make_stamp(src, gens, now)
        if stamp == src.match_stamp and not force:
            return None
        auto_exact, days, margin = settings_of(src)
        devs = [dict(id=i, name=n, short=s, names=ns or [], os_family=f, av=av or {}) for i, n, s, ns, f, av in (await db.execute(
            select(BiDevice.id, BiDevice.name, BiDevice.short, BiDevice.names, BiDevice.os_family, BiDevice.av).where(BiDevice.source_id == bi_source_id, BiDevice.generic.is_(False)))).all()]
        locals_: dict[int, set] = defaultdict(set)
        for d, email in (await db.execute(select(BiOwner.device_id, BiPerson.email).join(BiPerson, BiPerson.id == BiOwner.person_id).where(BiOwner.source_id == bi_source_id, BiPerson.email != ""))).all():
            locals_[int(d)].add(email.split("@", 1)[0].lower())
        kept = list((await db.execute(select(BiMatch).where(BiMatch.bi_source_id == bi_source_id, BiMatch.level.in_(KEEP)))).scalars())
        prior = {m.device_id: m for m in kept if m.level == "confirmed" and m.decided_by == RULE}      # связи по правилу пересматриваются каждый раз, но не переключаются без явной причины
        manual = {(m.device_id, m.ksc_source_id, m.host_id): m for m in kept if m.level in MANUAL and m.id not in {p.id for p in prior.values()}}
        history = {(m.device_id, m.ksc_source_id, m.host_id): m for m in kept if m.level == "history"}
        names, built = await ksc_meta(db, gens)
        shorts = {d["short"] for d in devs if d["short"]} | {short_name(x["name"]) for d in devs for x in d["names"]}
        want = {(s_, h_) for _d, s_, h_ in manual} | {(m.ksc_source_id, m.host_id) for m in prior.values()}
        by_short, by_fqdn, hosts = await ksc_index(db, gens, shorts, {d["name"].lower() for d in devs if "." in d["name"]}, want)
        for h in hosts.values():
            h["act"] = classify_host(h, now, days)
        confirmed = {k[0] for k, m in manual.items() if m.level == "confirmed"}
        cands: dict[int, list] = {}
        universe: dict[int, list] = {}                                  # все записи с этим именем, включая отклонённые: отказ от одной не делает другую единственной
        for d in devs:
            seen, out, uni = set(), [], []
            for nm in [d["short"], *(short_name(x["name"]) for x in d["names"])]:
                for h in by_short.get(nm, []) + (by_fqdn.get(d["name"].lower(), []) if "." in d["name"] else []):
                    k = (h["sid"], h["hid"])
                    if k not in seen:
                        seen.add(k)
                        uni.append(h)
                        if (d["id"], *k) not in manual:
                            out.append(h)
            cands[d["id"]], universe[d["id"]] = out, uni
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
        bi_names = Counter(norm_name(d["name"]) for d in devs)                     # точное совпадение — только если имя единственное и среди устройств BI источника
        taken = {(s_, int(h_)): dv for s_, h_, dv in (await db.execute(select(BiMatch.ksc_source_id, BiMatch.host_id, BiMatch.device_id).where(BiMatch.level == "confirmed"))).all()}
        for d in devs:
            did = d["id"]
            out, uni = cands[did], universe[did]
            pr = prior.get(did)
            pk = (pr.ksc_source_id, pr.host_id) if pr is not None else None
            lg = lambda h: logins[(h["sid"], h["hid"])]                       # noqa: E731
            if did in confirmed:                                            # подтверждено администратором: не переключается; при явном переходе — только предложение
                n["confirmed"] += 1
                mk = next((m for k, m in manual.items() if k[0] == did and m.level == "confirmed"), None)
                cur = hosts.get((mk.ksc_source_id, mk.host_id)) if mk else None
                pick = pick_current(uni, now, days, margin, built, names)
                w = pick["winner"]
                if cur is not None and w is not None and (w["sid"], w["hid"]) != (cur["sid"], cur["hid"]) and w in out and taken.get((w["sid"], w["hid"]), did) == did:
                    exact = norm_name(d["name"]) in (norm_name(w["name"]), w["fqdn"] if "." in d["name"] else "\0")
                    rows.append(row_of(d, w, bi_source_id, now, "candidate", [f"возможный переход между источниками KSC: подтверждённая запись {other_reason(cur, w, days, names, src=True)}",
                                                                              f"на источнике «{names.get(w['sid'], '?')}» — {pick['short']}"], [], "moved" if exact else "short"))
                    n["moved"] += 1
                continue
            if not out:
                if pr is not None:                                          # компьютер больше не найден: связь по правилу остаётся в истории
                    rows.append({"device_id": did, "bi_source_id": bi_source_id, "ksc_source_id": pr.ksc_source_id, "host_id": pr.host_id, "host_name": pr.host_name, "level": "history", "signals": pr.signals,
                                 "issues": [], "decided_by": pr.decided_by, "decided_at": pr.decided_at, "note": "Прежнее соответствие: компьютер больше не найден в данных KSC", "updated_at": now,
                                 "name_match": pr.name_match, "host_last_connected": pr.host_last_connected, "activity": pr.activity})
                n["none"] += 1
                continue
            pick = pick_current(uni, now, days, margin, built, names)
            w = pick["winner"]
            keep_prior = forced = False
            done_key = None                                                 # пара уже записана как «прежнее соответствие» — второй строкой не дублируется
            if pr is not None:
                prior_host = next((h for h in out if (h["sid"], h["hid"]) == pk), None)
                if prior_host is None:
                    rows.append({"device_id": did, "bi_source_id": bi_source_id, "ksc_source_id": pr.ksc_source_id, "host_id": pr.host_id, "host_name": pr.host_name, "level": "history",
                                 "signals": pr.signals, "issues": [], "decided_by": pr.decided_by, "decided_at": pr.decided_at, "note": "Прежнее соответствие: компьютер больше не найден в данных KSC",
                                 "updated_at": now, "name_match": pr.name_match, "host_last_connected": pr.host_last_connected, "activity": pr.activity})
                elif w is None or (w["sid"], w["hid"]) == pk:
                    keep_prior, forced, w = True, w is None, prior_host    # актуальна та же запись или данных для смены недостаточно: связь остаётся (и при выключенном автоподтверждении)
                else:                                                       # явный переход на другой источник: связь обновляется, прежняя сохраняется в истории
                    rows.append({"device_id": did, "bi_source_id": bi_source_id, "ksc_source_id": pr.ksc_source_id, "host_id": pr.host_id, "host_name": prior_host["name"][:300], "level": "history",
                                 "signals": pr.signals, "issues": [], "decided_by": pr.decided_by, "decided_at": pr.decided_at, "updated_at": now, "name_match": pr.name_match,
                                 "note": f"Прежнее соответствие: запись {other_reason(prior_host, w, days, names, src=True)}; связь обновлена на источник «{names.get(w['sid'], '?')}»",
                                 "host_last_connected": prior_host.get("last"), "activity": prior_host.get("act", "")})
                    n["migrated"] += 1
                    done_key = pk
            wk = (w["sid"], w["hid"]) if w is not None else None
            if w is not None and wk in {(h["sid"], h["hid"]) for h in out}:
                exact = norm_name(d["name"]) in (norm_name(w["name"]), w["fqdn"] if "." in d["name"] else "\0")
                lead = f"{'Точное совпадение имени' if exact else 'Совпадает короткое имя'}, {'прежняя связь сохранена: данных для смены недостаточно (' + pick['short'] + ')' if forced else pick['short']}"
                level, sig = decide(d, [w], locals_[did], lg, 1, lead)
                if pick["verdict"] == "latest" and not forced:
                    sig.append(pick["reason"])                              # у единственной активной записи основание уже названо первой строкой
                clean = (pick["verdict"] in ("single", "latest") and level in ("auto", "candidate") and bi_names[norm_name(d["name"])] == 1 and taken.get(wk, did) == did)
                nm = ("exact" if clean else "exact_dup") if exact else "short"
                iss = issues(d, w, locals_[did], logins[wk]) if level == "auto" or nm == "exact" or keep_prior else []
                if nm == "exact" and any(i["code"] == "os" for i in iss):
                    nm = "exact_dup"                                        # известный признак различия (ОС) — только ручное решение
                by_rule = (nm == "exact" and auto_exact) or (keep_prior and level != "conflict")
                row = row_of(d, w, bi_source_id, now, "confirmed" if by_rule else level, sig, iss, nm)
                if by_rule:
                    row.update(decided_by=RULE, decided_at=now, note=RULE_NOTE)
                    n["auto_confirmed"] += 1
                else:
                    n[level] += 1
                rows.append(row)
                for h in out:
                    if (h["sid"], h["hid"]) not in (wk, done_key):
                        rows.append(row_of(d, h, bi_source_id, now, "stale", [other_reason(h, w, days, names)], [], "exact" if norm_name(d["name"]) in (norm_name(h["name"]), h["fqdn"] if "." in d["name"] else "\0") else "short"))
                        n["stale_rows"] += 1
                continue
            if w is not None:                                               # актуальна запись, отклонённая администратором для этого устройства: прочие — устаревшие
                for h in out:
                    rows.append(row_of(d, h, bi_source_id, now, "stale", [f"актуальная запись KSC («{names.get(w['sid'], '?')}», {fmt_d(w['last'])}) отклонена администратором для этого устройства"], [], "short"))
                n["stale"] += 1
                continue
            if pick["verdict"] in ("none_active", "no_data"):               # актуального компьютера нет: ничего не подтверждается, причина — в основании
                for h in out:
                    rows.append(row_of(d, h, bi_source_id, now, "inactive", [pick["reason"]], [], "exact" if norm_name(d["name"]) in (norm_name(h["name"]), h["fqdn"] if "." in d["name"] else "\0") else "short"))
                n["inactive"] += 1
                continue
            for h in out:                                                   # tie / old_data / dubious: спорные записи — на ручное решение, остальные устарели
                exact = norm_name(d["name"]) in (norm_name(h["name"]), h["fqdn"] if "." in d["name"] else "\0")
                if h["act"] in ("active", "future"):
                    rows.append(row_of(d, h, bi_source_id, now, "ambiguous", [pick["reason"]], [], "exact_dup" if exact else "short"))
                else:
                    rows.append(row_of(d, h, bi_source_id, now, "stale", [other_reason(h, None, days, names)], [], "exact" if exact else "short"))
                    n["stale_rows"] += 1
            n["ambiguous"] += 1
        dev_by_id = {d["id"]: d for d in devs}
        await xact_lock(db, f"bi-match:{bi_source_id}")
        if lease is not None:
            await lease.fence(db)
        await db.execute(delete(BiMatch).where(BiMatch.bi_source_id == bi_source_id, or_(BiMatch.level.notin_(KEEP), and_(BiMatch.level == "confirmed", BiMatch.decided_by == RULE))))
        key = lambda r: (r["device_id"], r["ksc_source_id"], r["host_id"])         # noqa: E731
        rows = [r for r in rows if not (r["level"] in ("stale", "inactive") and key(r) in history)]       # устаревшая запись с прежней связью остаётся «прежним соответствием»
        gone = [history[key(r)].id for r in rows if key(r) in history and r["level"] != "history"]
        if gone:                                                        # запись снова живая (актуальная или спорная): строка истории заменяется новой
            await db.execute(delete(BiMatch).where(BiMatch.id.in_(gone)))
        for (dv, s, hid), m in history.items():                         # у остающихся прежних соответствий обновляются дата и состояние активности
            h = hosts.get((s, hid))
            if h is not None and m.id not in gone:
                await db.execute(update(BiMatch).where(BiMatch.id == m.id).values(host_last_connected=h["last"], activity=h["act"]))
        for i in range(0, len(rows), CHUNK):
            await db.execute(insert(BiMatch), rows[i:i + CHUNK])
        for (dv, s, hid), m in manual.items():                           # решения администратора сохраняются; обновляются расхождения, дата и состояние активности
            h = hosts.get((s, hid))
            if m.level == "confirmed" and dv in dev_by_id:
                await db.execute(update(BiMatch).where(BiMatch.id == m.id).values(issues=issues(dev_by_id[dv], h, locals_[dv], logins[(s, hid)]) if h else [{"code": "gone", "text": "Компьютер больше не найден в данных KSC"}],
                                                                                 host_name=(h["name"] if h else m.host_name)[:300], updated_at=now,
                                                                                 **({"host_last_connected": h["last"], "activity": h["act"]} if h else {})))
            elif h is not None:
                await db.execute(update(BiMatch).where(BiMatch.id == m.id).values(host_last_connected=h["last"], activity=h["act"]))
        src.match_stamp, src.matched_at = stamp, now
        await db.commit()
    log.info("Сопоставление BI выполнено", extra={"source": str(bi_source_id), "counts": dict(n)})
    return dict(n)
