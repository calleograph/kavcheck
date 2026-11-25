"""Пользователи устройств по данным KSC 15.1.

Что есть в KSC: `hst_user_visited` — для каждого устройства пользователи «в текущем списке вошедших» (`bActual = 1`) и «входившие ранее» (`bActual = 0`); учётные записи — `ak_users`.
Чего нет: ни времени входа, ни «последнего пользователя» (ни в этих таблицах, ни в карточке устройства). Поэтому KAV Checker опрашивает списки по расписанию и накапливает наблюдения (`dev_users`):
  * «сейчас вошёл» — пользователь в списке вошедших при последнем опросе;
  * «последний замеченный в сеансе» — последний опрос, на котором пользователь был в списке вошедших (дата наблюдения, а не точное время входа);
  * «за 7 суток» — замечен в списке вошедших за 7 суток либо впервые появился в списках после начала наблюдений (значит, входил между опросами); записи, существовавшие при первом опросе, без даты в «7 суток» не попадают;
  * короткие сеансы между опросами не видны; история начинается с первого опроса источника."""
from __future__ import annotations

import hashlib
import logging
import re
import time
from datetime import timedelta, timezone

from sqlalchemy import delete, func, insert, select, tuple_, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..ksc import queries as q
from ..models import DevicesState, DeviceSession, DeviceUser, KscSource, utcnow
from ..search import matcher

log = logging.getLogger("app.devices")
PAGE = 10000
VERIFIED_DAYS = 30
SYSTEM_RE = re.compile(r"^(system|local ?service|network ?service|localsystem|anonymous logon|defaultaccount|wdagutilityaccount|guest|dwm-\d+|umfd-\d+|font driver host.*|window manager.*|"
                       r"nt authority.*|nt service.*|root|daemon|bin|sys|nobody|gdm|sddm|lightdm|www-data|systemd-.*|messagebus|polkitd|sshd|avahi|colord|rtkit)$", re.I)


def qualified_address(value: str | None) -> str:
    value = (value or "").strip().casefold()
    return value if re.fullmatch(r"[^@\s]+@[^@\s]+", value) else ""


def split_login(login: str, upn: str) -> tuple[str, str]:
    """(логин, домен): «DOMAIN\\user» и «user@domain» разделяются; домен — по суффиксу UPN, если логин без домена."""
    upn = qualified_address(upn)
    login = (login or "").strip() or upn
    domain = ""
    if "\\" in login:
        domain, login = login.split("\\", 1)
    elif "@" in login:
        login, domain = login.split("@", 1)
    if not domain and upn:
        domain = upn.split("@", 1)[1]
    return login, domain.lower()


def classify(login: str, domain: str, masks: list[str], *, local: bool = False) -> str:
    """user | service | system. Машинные учётные записи («имя$»), системные сеансы Windows и Linux — system; по маскам настройки — service."""
    n = (login or "").strip()
    if not n or n.endswith("$") or SYSTEM_RE.match(n) or SYSTEM_RE.match(f"{domain}\\{n}"):
        return "system"
    for m in masks:
        f = matcher(m)
        if f is not None and f(n):
            return "service"
    return "user"


def user_key(login: str, sid_hash: str) -> tuple[str, bool]:
    """Ключ записи: логин в нижнем регистре; если KSC не сопоставил учётную запись — хэш SID (стабильный ключ, но без логина)."""
    if login:
        return login.lower()[:80], True
    return "h:" + hashlib.sha1((sid_hash or "?").encode()).hexdigest()[:20], False


async def poll_source(sm: async_sessionmaker[AsyncSession], client, src: KscSource, masks: list[str], *, retention_days: int = 90, res=None) -> dict:
    """Один опрос источника: порциями читает списки KSC и обновляет наблюдения. Память — одна порция; ошибка не затрагивает накопленное."""
    t0 = time.monotonic()
    started = utcnow()
    sid = src.id
    async with sm() as db:
        st = await db.get(DevicesState, sid)
        first = st is None or st.first_poll_at is None
        prev_poll = None if st is None else st.polled_at
        if st is None:
            st = DevicesState(source_id=sid, first_poll_at=started)
            db.add(st)
        elif st.first_poll_at is None:
            st.first_poll_at = started
        await db.commit()
    async with sm() as db:                                # кто числился «вошёл сейчас» до опроса: после опроса те, кого в списке вошедших не застали, помечаются вышедшими
        active_before = {(int(h), k) for h, k in (await db.execute(select(DeviceUser.host_id, DeviceUser.user_key).where(DeviceUser.source_id == sid, DeviceUser.session_now.is_(True)))).all()}
    seen_active: set[tuple[int, str]] = set()
    user_active: set[tuple[int, str]] = set()             # сеансы ведутся только для пользователей (служебные и системные сеансы есть на каждом компьютере постоянно)
    after, seen_rows, touched, written = 0, 0, 0, 0
    stale = started - timedelta(hours=12)                 # без изменений строка переписывается раз в 12 часов (для срока хранения), а не при каждом опросе: писать сотни тысяч строк ежечасно незачем
    while True:
        rows = await client.run(q.USERS_VISITED, {"n": PAGE, "after": after}, max_rows=PAGE + 10)
        if not rows:
            break
        seen_rows += len(rows)
        after = int(rows[-1]["row_id"])
        agg: dict[tuple[int, str], dict] = {}
        for r in rows:
            remote = r.get("local_host") is None
            upn = qualified_address(r.get("upn")) if remote else ""
            login, domain = split_login(r.get("login") or "", upn)
            if not remote:
                domain = "локальная"
            key, resolved = user_key(login, r.get("sid_hash") or "")
            k = (int(r["host_id"]), key)
            a = agg.get(k)
            actual = bool(r.get("actual"))
            verified = actual and resolved and bool(domain) and remote
            if a is None or (actual and not a["actual"]):
                agg[k] = {"login": login, "domain": domain, "resolved": resolved, "actual": actual, "kind": classify(login, domain, masks) if resolved else "user",
                          "verified": verified, "remote": remote, "upn": upn}
            elif actual:
                if not verified or a["domain"] != domain or (a["upn"] and upn and a["upn"] != upn):
                    a["verified"] = False
                elif not a["upn"]:
                    a["upn"] = upn
        seen_active |= {k for k, a in agg.items() if a["actual"]}
        user_active |= {k for k, a in agg.items() if a["actual"] and a["kind"] == "user" and a["resolved"]}
        hosts = sorted({h for h, _ in agg})
        async with sm() as db:
            have = {(u.host_id, u.user_key): u for u in (await db.execute(select(DeviceUser).where(DeviceUser.source_id == sid, DeviceUser.host_id.in_(hosts)))).scalars()}
            for (h, key), a in agg.items():
                touched += 1
                u = have.get((h, key))
                if u is None:
                    db.add(DeviceUser(source_id=sid, host_id=h, user_key=key, login=a["login"][:256], domain=a["domain"][:256], kind=a["kind"], resolved=a["resolved"], first_seen_at=started,
                                      last_seen_at=started, seen_n=1, initial=first, session_now=a["actual"], last_session_at=started if a["actual"] else None,
                                      identity_verified=a["verified"], verified_observations={"upn": a["upn"]} if a["upn"] else None))
                    written += 1
                    continue
                ls = u.last_seen_at.replace(tzinfo=timezone.utc) if u.last_seen_at.tzinfo is None else u.last_seen_at
                same_identity = u.login.casefold() == a["login"][:256].casefold() and u.domain == a["domain"][:256]
                previous_upn = (u.verified_observations or {}).get("upn", "")
                upn = a["upn"] or (previous_upn if same_identity and a["remote"] else "")
                same_identity = same_identity and (not previous_upn or not upn or previous_upn == upn)
                seen_this_poll = u.last_session_at == started
                if seen_this_poll and not a["actual"]:
                    continue
                # Один короткий логин может принадлежать нескольким доменам, включая две страницы одного опроса.
                verified = a["verified"] and (not seen_this_poll or (u.identity_verified and same_identity)) if a["actual"] else (u.identity_verified and same_identity and a["remote"])
                if (u.session_now != a["actual"] or a["actual"] or u.kind != a["kind"] or u.login != a["login"][:256] or u.domain != a["domain"][:256] or ls < stale
                        or u.identity_verified != verified or upn != previous_upn):
                    u.session_now, u.last_seen_at, u.seen_n = a["actual"], started, (u.seen_n or 0) + 1
                    if a["actual"]:
                        u.last_session_at = started
                    if not same_identity or upn != previous_upn:
                        u.verified_observations = {"upn": upn} if upn else None
                    u.identity_verified = verified
                    u.kind, u.login, u.domain = a["kind"], a["login"][:256], a["domain"][:256]
                    written += 1
            await db.commit()
        if res is not None:
            await res.breathe("опрос пользователей")
        if len(rows) < PAGE:
            break
    gone = sorted(active_before - seen_active)
    async with sm() as db:
        for i in range(0, len(gone), 2000):
            await db.execute(update(DeviceUser).where(DeviceUser.source_id == sid, tuple_(DeviceUser.host_id, DeviceUser.user_key).in_(gone[i:i + 2000])).values(session_now=False))
        await db.execute(delete(DeviceUser).where(DeviceUser.source_id == sid, DeviceUser.last_seen_at < started - timedelta(days=retention_days)))
        await track_sessions(db, sid, user_active, active_before, started, prev_poll, first=first, retention_days=retention_days)
        if user_active:
            await record_verified_observations(db, sid, started, res)
        st = await db.get(DevicesState, sid)
        st.polled_at, st.duration_ms, st.rows_seen, st.users_n, st.error, st.error_at, st.requested_at = started, int((time.monotonic() - t0) * 1000), seen_rows, touched, None, None, None
        await db.commit()
    return {"rows": seen_rows, "users": touched, "written": written, "seconds": round(time.monotonic() - t0, 1), "initial": first}


async def record_verified_observations(db: AsyncSession, source_id, now, res) -> None:
    """Записывает один подтверждённый опрос в сутки вместе с публикацией состояния источника."""
    day = now.date().isoformat()
    stamp = now.isoformat()
    cutoff = (now - timedelta(days=VERIFIED_DAYS)).isoformat()
    U = DeviceUser
    query = select(U.host_id, U.user_key, U.verified_observations).where(
        U.source_id == source_id, U.last_session_at == now, U.kind == "user", U.identity_verified.is_(True),
        func.coalesce(U.verified_observations["day"].as_string(), "") != day)
    async for rows in (await db.stream(query.execution_options(yield_per=1000))).partitions(1000):
        updates = []
        for host_id, user_key, data in rows:
            stamps = [value for value in (data or {}).get("stamps", []) if cutoff <= value < stamp]
            updates.append({"source_id": source_id, "host_id": host_id, "user_key": user_key,
                            "verified_observations": {**(data or {}), "day": day, "stamps": [*stamps, stamp]}})
        await db.execute(update(U), updates)
        if res is not None:
            await res.breathe("подтверждённые наблюдения пользователей")



async def track_sessions(db: AsyncSession, sid, active: set[tuple[int, str]], active_before: set[tuple[int, str]], now, prev_poll, *, first: bool, retention_days: int) -> None:
    """Границы сеансов по двум соседним опросам: появился в списке вошедших — сеанс начат (между прошлым и этим опросом), пропал — завершён.
    Был в списке ещё до начала ведения сеансов (первый опрос, обновление версии) — начало неизвестно."""
    open_ = {(int(h), k): i for i, h, k in (await db.execute(select(DeviceSession.id, DeviceSession.host_id, DeviceSession.user_key)
                                                                 .where(DeviceSession.source_id == sid, DeviceSession.ended_at.is_(None)))).all()}
    ended = [i for k, i in open_.items() if k not in active]
    for j in range(0, len(ended), 2000):                  # последний опрос, где пользователь ещё был в списке, — предыдущий
        await db.execute(update(DeviceSession).where(DeviceSession.id.in_(ended[j:j + 2000])).values(ended_at=now, last_active_at=prev_poll or now))
    new = [{"source_id": sid, "host_id": h, "user_key": k, "start_after": None if first or (h, k) in active_before or prev_poll is None else prev_poll,
            "started_at": now, "last_active_at": now} for h, k in sorted(active - open_.keys())]
    for j in range(0, len(new), 2000):
        await db.execute(insert(DeviceSession), new[j:j + 2000])
    await db.execute(delete(DeviceSession).where(DeviceSession.source_id == sid, DeviceSession.ended_at < now - timedelta(days=retention_days)))
