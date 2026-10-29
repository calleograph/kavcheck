"""Быстрый отчёт «Устройства и пользователи»: все устройства, подходящие под условия страницы (поиск по имени, IP, сети CIDR и логину, зона, ОС, пользователь, состояние EOL, источник),
с зонами, пользователями (вошедшие сейчас, последний замеченный, за 7 суток, входившие ранее — полными списками, без сокращений «+N») и числом проблем поддержки EOL.
Данные берутся из подготовленных данных зон и наблюдений в PostgreSQL; к KSC отчёт не обращается."""
from __future__ import annotations

import uuid
from collections import Counter

from ..devices import read as D
from ..ksc.driver import KscError, SourceClient
from ..models import KscSource
from sqlalchemy import select
from .quick import Ctx, col, metric

PAGE = 500
COLS = [col("source", "Источник"), col("name", "Устройство"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("group", "Группа администрирования"), col("zones", "Зоны ответственности"),
        col("last_connected", "Последнее подключение к KSC (UTC)", "date"), col("active", "Связь за период"), col("online_ru", "В сети сейчас"),
        col("users_now", "Вошли сейчас"), col("last_user", "Последний замеченный в сеансе"), col("users_week", "Пользователи за 7 суток"), col("users_before", "Входили ранее"),
        col("eol", "Проблем поддержки (EOL)", "num"), col("eol_crit", "Из них критических", "num"), col("eol_level_ru", "Наихудшее состояние поддержки")]
EOL_RU = {"eol": "EOL: поддержка закончилась", "extended": "Только расширенная поддержка", "upcoming": "Скоро EOL", "": ""}


def who(u: dict) -> str:
    if not u.get("resolved"):
        return "учётная запись не сопоставлена в KSC"
    name = f"{u['domain']}\\{u['login']}" if u.get("domain") else u["login"]
    return name + (" (служебная)" if u.get("kind") == "service" else " (системная)" if u.get("kind") == "system" else "")


UCOLS = [col("login", "Учётная запись"), col("domain", "Домен"), col("hosts", "Компьютеров", "num"), col("host_names", "Компьютеры"), col("last_session_at", "Последний сеанс (UTC)", "date"),
         col("now", "В сеансе сейчас"), col("bi", "Сотрудник по BI")]


async def _users(sids: list, names: dict, p: dict, ctx: Ctx) -> dict:
    from ..bi.read import ksc_users  # noqa: PLC0415

    rows: list[dict] = []
    async with ctx.sm() as db:
        while True:
            page = await ksc_users(db, sids, q=p.get("q") or "", all_os=bool(p.get("all_os")), offset=len(rows), limit=PAGE, names_max=None)
            rows += [{"login": u["login"], "domain": u["domain"] or "", "hosts": u["hosts"], "host_names": "; ".join(u["host_names"]), "last_session_at": u["last_session_at"], "now": "да" if u["now"] else "",
                      "bi": (f"{u['bi_person']['name']} ({u['bi_person']['department']})" if u["bi_person"]["department"] else u["bi_person"]["name"]) if u["bi_person"] and p.get("pd", True) else ""}
                     for u in page["items"]]
            ctx.progress(f"учётных записей: {len(rows)}")
            if len(rows) > ctx.max_rows:
                raise KscError("too_many_rows", f"Учётных записей больше предела отчёта ({ctx.max_rows}): сузьте условия")
            if len(page["items"]) < PAGE:
                break
    cols = UCOLS if p.get("pd", True) else UCOLS[:-1]
    cond = [{"label": "Источники", "text": ", ".join(names.get(s, "?") for s in sids)}, {"label": "Компьютеры", "text": "все ОС" if p.get("all_os") else "только Windows"}]
    if p.get("q"):
        cond.append({"label": "Поиск", "text": f"«{p['q']}»"})
    return {"title": "Пользователи KSC", "subtitle": "Учётные записи из списков вошедших KSC и компьютеры, на которых они работали", "conditions": cond, "severity": None,
            "metrics": [metric("users", "Учётных записей", len(rows)), metric("now", "В сеансе сейчас", sum(1 for r in rows if r["now"])),
                        *([metric("bi", "Сопоставлено с сотрудником BI", sum(1 for r in rows if r["bi"]), "по почте сотрудника")] if p.get("pd", True) else [])],
            "notes": [page.get("note") or "", "KSC не хранит даты входа: «последний сеанс» — по наблюдениям KAV Checker. Списки компьютеров полные, без сокращений «+N»."],
            "tables": [{"id": "devices", "title": "Учётные записи", "columns": cols, "rows": rows}]}


async def build_devices(client: SourceClient, p: dict, ctx: Ctx) -> dict:
    if ctx.sm is None or not (ctx.source_ids or ctx.source_id):
        raise KscError("params", "Отчёт по устройствам недоступен: нет доступа к локальной базе")
    sids = list(ctx.source_ids or [ctx.source_id])
    if p.get("source_id"):
        try:
            one = uuid.UUID(str(p["source_id"]))
        except ValueError:
            raise KscError("params", "Неверный источник") from None
        sids = [one] if one in sids else sids
    if p.get("view") == "users":
        async with ctx.sm() as db:
            names = {s.id: s.name for s in (await db.execute(select(KscSource).where(KscSource.id.in_(sids)))).scalars()}
        return await _users(sids, names, p, ctx)
    rows: list[dict] = []
    async with ctx.sm() as db:
        names = {s.id: s.name for s in (await db.execute(select(KscSource).where(KscSource.id.in_(sids)))).scalars()}
        offset = 0
        while True:
            page = await D.list_devices(db, sids, names, q=p.get("q") or "", zone=p.get("zone") or "", os_q=p.get("os") or "", user_q=p.get("user") or "", eol=p.get("eol") or "",
                                        all_hosts=bool(p.get("include_inactive")), show_service=bool(p.get("show_service")), offset=offset, limit=PAGE, history_limit=None)
            for d in page["items"]:
                rows.append({"host_id": d["host_id"], "source_id": d["source_id"], "source": d["source"], "name": d["name"], "ip": d["ip"], "os": d["os"], "group": d["group"], "zones": "; ".join(d["zones"]),
                             "last_connected": d["last_connected"], "active": "да" if d["active"] else "нет", "online_ru": {True: "в сети", False: "не в сети", None: "нет данных"}[d["online"]],
                             "users_now": "; ".join(who(u) for u in d["current"]), "last_user": who(d["last_user"]) if d["last_user"] else "",
                             "users_week": "; ".join(who(u) for u in d["week"]), "users_before": "; ".join(who(u) for u in d["history"]),
                             "eol": d["eol"], "eol_crit": d["eol_crit"], "eol_level_ru": EOL_RU.get(d["eol_level"], d["eol_level"])})
            offset += PAGE
            ctx.progress(f"устройств: {len(rows)}")
            if len(rows) > ctx.max_rows:
                raise KscError("too_many_rows", f"Устройств больше предела отчёта ({ctx.max_rows}): сузьте условия или повысьте предел в «Администрирование → Общие настройки»")
            if len(page["items"]) < PAGE:
                break
    by_os = Counter(r["os"] or "не указана" for r in rows)
    metrics = [metric("hosts", "Устройств в отчёте", len(rows)), metric("active", "Со связью за период", sum(1 for r in rows if r["active"] == "да")),
               metric("with_users", "С известными пользователями", sum(1 for r in rows if r["users_now"] or r["last_user"] or r["users_week"] or r["users_before"]), "по наблюдениям: KSC не хранит даты входа"),
               metric("eol", "С проблемами поддержки (EOL)", sum(1 for r in rows if r["eol"]), "", "danger" if any(r["eol"] for r in rows) else "ok"),
               metric("eol_crit", "Из них с критической", sum(1 for r in rows if r["eol_crit"]))]
    cond = [{"label": "Источники", "text": ", ".join(names.get(s, "?") for s in sids)}]
    for label, key in (("Поиск", "q"), ("ОС", "os"), ("Пользователь", "user")):
        if p.get(key):
            cond.append({"label": label, "text": f"«{p[key]}»"})
    if p.get("zone"):
        cond.append({"label": "Зона ответственности", "text": "Без ответственного" if p["zone"] == "none" else p["zone"]})
    if p.get("eol"):
        cond.append({"label": "EOL", "text": {"any": "с проблемами поддержки", "eol": "с закончившейся поддержкой", "none": "без проблем поддержки"}[p["eol"]]})
    cond.append({"label": "Связь с KSC", "text": "все устройства" if p.get("include_inactive") else "только со связью за период активности"})
    return {"title": "Устройства и пользователи", "subtitle": "Устройства с пользователями, зонами ответственности и признаком EOL", "conditions": cond, "metrics": metrics, "severity": None,
            "notes": ["Пользователи накапливаются по наблюдениям: KSC не хранит даты входа и «последнего пользователя». Списки в отчёте полные, без сокращений «+N»."],
            "tables": [{"id": "devices", "title": "Устройства", "columns": COLS, "rows": rows, "note": "Одна строка — устройство."},
                       {"id": "by_os", "title": "Распределение по операционным системам", "columns": [col("os", "ОС"), col("n", "Устройств", "num")], "rows": [{"os": k, "n": v} for k, v in by_os.most_common()]}]}
