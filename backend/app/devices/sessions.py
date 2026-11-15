"""Кто вошёл в систему сейчас — живой запрос к KSC по одному или нескольким источникам.

KSC хранит для каждого устройства «текущий список вошедших» (`hst_user_visited.bActual <> 0`) — его обновляет Агент администрирования при синхронизации; дат входа нет.
Здесь берётся именно этот список (не «входившие когда-либо»), по умолчанию — только на компьютерах, которые KSC сейчас видит в сети (бит 0 `nStatus`), без служебных и
системных учётных записей. Поиск — по логину, UPN и имени пользователя с масками `*`, при необходимости — по компьютеру или IP. Только чтение, TOP и параметры."""
from __future__ import annotations

import asyncio

from ..ksc import hosts as H
from ..ksc import queries as q
from ..ksc.driver import KscError
from ..netsearch import parse as parse_query
from ..search import mssql_like
from .users import classify, split_login

MAX_TOKENS = 20


def where(user_q: str, host_q: str, *, online_only: bool, params: dict) -> str:
    """Отбор для SESSIONS_NOW: несколько значений через запятую или пробел — подходит любое; значения только параметрами."""
    parts = []
    conds = []
    for i, t in enumerate(parse_query(user_q)[:MAX_TOKENS]):
        if t.is_net:
            continue
        params[f"u{i}"] = mssql_like(t.text)
        conds.append(f"u.wstrSamAccountName LIKE %(u{i})s OR u.wstrUserPrincipalName LIKE %(u{i})s OR u.wstrDisplayName LIKE %(u{i})s")
    if conds:
        parts.append("(" + " OR ".join(f"({c})" for c in conds) + ")")
    hw = H.search_where(host_q, params) if (host_q or "").strip() else None
    if hw:
        parts.append(hw)
    if online_only:
        parts.append("(h.nStatus & 1) = 1")
    return "".join(f" AND {p}" for p in parts)


def row_out(r: dict, groups: dict | None, masks: list[str]) -> dict:
    h = H.host_row(r, groups)
    login, domain = split_login(r.get("login") or "", r.get("upn") or "")
    local = r.get("local_host") is not None
    return {"login": login, "domain": domain or ("локальная" if local else ""), "upn": r.get("upn") or "", "user_name": r.get("user_display") or "",
            "kind": classify(login, domain, masks, local=local), "local": local, "host_id": h["host_id"], "host": h["name"], "fqdn": h["fqdn"], "ip": h["ip"], "os": h["os"],
            "group": h["group"] or (r.get("group_name") or ""), "online": h["online"], "last_connected": h["last_connected"]}


CHUNK = 2000
SCAN_MAX = 50_000          # строк KSC за один запрос страницы: служебные сеансы (SYSTEM, DWM-N…) отсеиваются здесь, и на крупной базе их тысячи впереди пользователей


async def fetch(client, *, user_q: str = "", host_q: str = "", online_only: bool = True, show_service: bool = False, masks: list[str] | None = None, top: int = 500,
                groups: dict | None = None) -> tuple[list[dict], bool]:
    """Строки одного источника и признак «есть ещё» (выдача упёрлась в предел). Читается постранично, пока не набрано `top` строк нужного вида или не кончились данные."""
    params: dict = {}
    sql = q.SESSIONS_NOW.format(where=where(user_q, host_q, online_only=online_only, params=params))
    out: list[dict] = []
    offset = 0
    while True:
        page = await client.run(sql, {**params, "offset": offset, "limit": CHUNK}, max_rows=CHUNK)
        offset += len(page)
        out += [r for r in (row_out(x, groups, masks or []) for x in page) if show_service or r["kind"] == "user"]
        if len(out) > top:
            return out[:top], True
        if len(page) < CHUNK:
            return out, False
        if offset >= SCAN_MAX:
            return out, True


async def fetch_many(sources: list, client_for, **kw) -> tuple[list[dict], list[dict]]:
    """По нескольким источникам параллельно; ошибка одного источника не скрывает остальные. Возвращает (строки с именем источника, состояние по источникам)."""
    async def one(src):
        try:
            client = client_for(src)
            groups = await H.groups_map(client)
            rows, more = await fetch(client, groups=groups, **kw)
            return src, rows, {"source_id": str(src.id), "source": src.name, "rows": len(rows), "more": more, "error": ""}
        except KscError as exc:
            return src, [], {"source_id": str(src.id), "source": src.name, "rows": 0, "more": False, "error": exc.message}
    out: list[dict] = []
    states: list[dict] = []
    for src, rows, st in await asyncio.gather(*(one(s) for s in sources)):
        out += [{**r, "source_id": str(src.id), "source": src.name} for r in rows]
        states.append(st)
    out.sort(key=lambda r: ((r["login"] or "").lower(), (r["host"] or "").lower(), r["source"]))
    return out, states
