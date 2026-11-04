"""Отчёты по Active Directory (вид `quick_ad`, вид — параметр `view`): users — пользователи; disabled — отключённые; locked — заблокированные; expiring — срок учётной записи истекает;
memberships — непосредственное членство в группах (строка на пару «пользователь — группа»); group_members — состав группы (+ вложенные по запросу); mismatch — расхождения Exchange и AD.

Чтение — только из каталога через подключение LDAPS продукта, постранично, до 50 000 записей; даты — UTC. Непосредственные группы не выдаются за эффективное членство. Отчёт содержит персональные данные."""
from __future__ import annotations

import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from ..ad import client as C
from ..ad import filters as F
from ..auth.ldap import LdapError
from ..hier import service as HS
from ..ksc.driver import KscError
from .quick import Ctx, col, metric

TITLE = {"users": "Пользователи Active Directory", "disabled": "Отключённые учётные записи AD", "locked": "Заблокированные учётные записи AD", "expiring": "Учётные записи AD с истекающим сроком",
         "memberships": "Членство пользователей AD в группах", "group_members": "Состав группы AD", "mismatch": "Расхождения Exchange и Active Directory"}
USER_COLS = [col("name", "ФИО"), col("login", "Логин"), col("upn", "UPN"), col("mail", "Почта"), col("department", "Подразделение"), col("title", "Должность"), col("company", "Компания"), col("state", "Состояние"),
             col("locked", "Блокировка"), col("created", "Создана (UTC)", "date"), col("pwd_last_set", "Пароль изменён (UTC)", "date"), col("expires", "Срок учётной записи (UTC)", "date"),
             col("last_logon", "Последний вход (UTC)", "date"), col("manager", "Руководитель"), col("dn", "DistinguishedName")]


def _user(r: dict) -> dict:
    return {**r, "state": "Отключена" if r["disabled"] else "Активна", "locked": "заблокирована" if r["locked"] else "нет"}


def _q(p: dict, login_attr: str = "sAMAccountName") -> str:
    t = (p.get("q") or "").strip()
    return F.user_search_filter(t, "(objectClass=*)", login_attr)[len("(&(objectClass=*)"):-1] if t else ""


async def build_ad(client, p: dict, ctx: Ctx) -> dict:
    if ctx.ad is None or ctx.sm is None or ctx.hier_cfg is None:
        raise KscError("params", "Отчёт недоступен: нет доступа к каталогу")
    view = p.get("view") or "users"
    if view not in TITLE:
        raise KscError("params", "Неизвестный вид отчёта AD")
    try:
        async with ctx.sm() as db:
            cfg = await ctx.ad.config(db, ctx.hier_cfg)
            people = None
            if view == "mismatch":
                snap = await HS.latest_ok(db)
                if snap is None:
                    raise KscError("no_data", "Структура Exchange ещё не загружена: сравнивать не с чем.")
                people = (await HS.processed(db, snap, ctx.hier_cfg)).people
        key = ("report", view, p.get("q", ""), p.get("group", ""), int(p.get("days") or 30), bool(p.get("nested")))
        ttl = ctx.hier_cfg.ad_cache_seconds
        tables, cond, notes, truncated = await ctx.ad.call((cfg.id, *key), ttl, lambda: _tables(cfg, view, p, people), False)
    except LdapError as exc:
        raise KscError("ad", exc.message) from None
    except F.AdQueryError as exc:
        raise KscError("params", str(exc)) from None
    main = tables[0]["rows"]
    notes = ["Данные прочитаны из Active Directory в режиме «только чтение» сервисной учётной записью; время — UTC. Отчёт содержит персональные данные: передавайте его только тем, кому они необходимы.", *notes]
    if truncated:
        notes.append(f"Каталог вернул больше {C.REPORT_LIMIT} записей: в отчёт вошли первые {C.REPORT_LIMIT}. Сузьте запрос.")
    return {"title": TITLE[view], "subtitle": f"Каталог: {cfg.name}", "conditions": [{"label": "Вид отчёта", "text": TITLE[view]}, {"label": "Каталог", "text": f"{cfg.name} ({cfg.base_dn})"}, *cond],
            "severity": None, "notes": notes, "metrics": [metric("rows", "Строк в отчёте", len(main))] + _extra_metrics(view, main), "tables": tables}


def _extra_metrics(view: str, rows: list[dict]) -> list[dict]:
    if view in ("users", "disabled", "locked", "expiring"):
        return [metric("disabled", "Отключено", sum(1 for r in rows if r.get("state") == "Отключена")), metric("locked", "Заблокировано", sum(1 for r in rows if r.get("locked") == "заблокирована"), "", "warn")]
    if view == "memberships":
        return [metric("users", "Пользователей", len({r["login"] for r in rows})), metric("groups", "Групп", len({r["group_dn"] for r in rows}))]
    if view == "mismatch":
        cnt = Counter(r["kind"] for r in rows)
        return [metric("kinds", k, v) for k, v in cnt.most_common(3)]
    return []


def _tables(cfg, view: str, p: dict, people) -> tuple[list[dict], list[dict], list[str], bool]:
    """Синхронно (в потоке): чтение каталога и сборка таблиц."""
    cond = [{"label": "Фильтр", "text": p["q"]}] if p.get("q") else []
    notes: list[str] = []
    extra = _q(p, cfg.login_attribute)
    if view in ("users", "disabled", "locked", "expiring"):
        narrow = {"disabled": "(userAccountControl:1.2.840.113556.1.4.803:=2)", "locked": "(lockoutTime>=1)", "expiring": "(accountExpires>=1)"}.get(view, "")
        rows, trunc = C.read_users(cfg, extra, narrow=narrow)
        if view == "disabled":
            rows = [r for r in rows if r["disabled"]]
        elif view == "locked":
            rows = [r for r in rows if r["locked"]]
            notes.append("Блокировка определяется по msDS-User-Account-Control-Computed, а если атрибута нет — по lockoutTime (без учёта срока блокировки).")
        elif view == "expiring":
            days = int(p.get("days") or 30)
            now = datetime.now(timezone.utc)
            end = now + timedelta(days=days)
            rows = [r for r in rows if r["expires"] and now <= datetime.fromisoformat(r["expires"]) <= end]
            rows.sort(key=lambda r: r["expires"])
            cond.append({"label": "Срок истекает", "text": f"в ближайшие {days} сут (до {end:%d.%m.%Y})"})
        if view != "expiring":
            rows.sort(key=lambda r: (r["name"].casefold(), r["login"]))
        out = [_user(r) for r in rows]
        notes.append("«Последний вход» — lastLogonTimestamp: контроллер домена обновляет его не чаще раза в ~14 суток.")
        return [{"id": "rows", "title": TITLE[view], "columns": USER_COLS, "rows": out, "note": "Одна строка — учётная запись."}], cond, notes, trunc
    if view == "memberships":
        rows, trunc = C.read_users(cfg, extra)
        out = [{"name": r["name"], "login": r["login"], "mail": r["mail"], "state": "Отключена" if r["disabled"] else "Активна", "group": F.cn_of(g), "group_dn": g, "kind": "Непосредственное (memberOf)"}
               for r in sorted(rows, key=lambda r: (r["name"].casefold(), r["login"])) for g in sorted(r["member_of"], key=str.casefold)]
        notes.append("Показано непосредственное членство (memberOf). Первичная группа и вложенное членство в отчёт не входят: их показывает карточка пользователя.")
        cols = [col("name", "ФИО"), col("login", "Логин"), col("mail", "Почта"), col("state", "Состояние"), col("group", "Группа (CN)"), col("group_dn", "Группа (DN)"), col("kind", "Вид членства")]
        return [{"id": "rows", "title": TITLE[view], "columns": cols, "rows": out, "note": "Одна строка — пара «пользователь — группа»."}], cond, notes, trunc
    if view == "group_members":
        ref = p.get("group") or ""
        if not ref:
            raise F.AdQueryError("Выберите группу.")
        got = C.group_members(cfg, ref, C.REPORT_LIMIT)
        card = got["group"]
        cond.append({"label": "Группа", "text": f"{card['cn']} — {card['dn']}"})
        rows = [{"name": m["name"], "login": m["login"], "mail": m["mail"], "kind": {"user": "пользователь", "group": "группа", "computer": "компьютер", "contact": "контакт"}.get(m["kind"], m["kind"]),
                 "title": m["title"], "department": m["department"], "state": "Отключена" if m["disabled"] else "Активна", "method": "Непосредственный", "dn": m["dn"]} for m in got["items"]]
        if p.get("nested"):
            have = {r["dn"].lower() for r in rows}
            eff, _t = C.effective_members(cfg, card["dn"], f"(&{C._flt(cfg.user_filter)})", C.REPORT_LIMIT)           # noqa: SLF001
            rows += [{"name": m["name"], "login": m["login"], "mail": m["mail"], "kind": "пользователь", "title": m["title"], "department": m["department"], "state": "Отключена" if m["disabled"] else "Активна",
                      "method": "Вложенный (через группы)", "dn": m["dn"]} for m in eff if m["dn"].lower() not in have]
            notes.append("Вложенные участники определены правилом LDAP_MATCHING_RULE_IN_CHAIN (только Active Directory).")
        else:
            notes.append("Показаны непосредственные участники. Вложенные группы и пользователи, для которых это первичная группа, не включены (включите «с вложенными»).")
        cols = [col("name", "Имя"), col("login", "Логин"), col("mail", "Почта"), col("kind", "Тип"), col("title", "Должность"), col("department", "Подразделение"), col("state", "Состояние"), col("method", "Как определено"), col("dn", "DistinguishedName")]
        return [{"id": "rows", "title": TITLE[view], "columns": cols, "rows": rows, "note": f"Группа «{card['cn']}»."}], cond, notes, got["truncated"]
    # mismatch: Exchange ↔ AD
    rows, trunc = C.read_users(cfg, "")
    by: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        for e in r["emails"]:
            by[e].append(r)
    ex = {x["email"]: x for x in people or []}
    out = []
    for e, x in ex.items():
        hit = by.get(e, [])
        if not hit:
            out.append({"kind": "Есть в Exchange, нет учётной записи AD", "name": x["name"], "email": e, "login": "", "state": "", "dn": "", "note": "Адрес не найден в mail, UPN и адресах Exchange учётных записей"})
        elif len({h["dn"] for h in hit}) > 1:
            out.append({"kind": "Адрес у нескольких учётных записей AD", "name": x["name"], "email": e, "login": ", ".join(h["login"] for h in hit[:5]), "state": "", "dn": hit[0]["dn"], "note": "Нужно выбрать вручную"})
        elif hit[0]["disabled"]:
            out.append({"kind": "В AD учётная запись отключена", "name": x["name"], "email": e, "login": hit[0]["login"], "state": "Отключена", "dn": hit[0]["dn"], "note": "Сотрудник есть в Exchange, а учётная запись отключена"})
    for r in rows:
        if r["disabled"] or not r["mail"] or any(e in ex for e in r["emails"]):
            continue
        out.append({"kind": "Активна в AD, нет в структуре Exchange", "name": r["name"], "email": r["mail"], "login": r["login"], "state": "Активна", "dn": r["dn"], "note": "Возможно служебный ящик или сотрудник вне структуры: требует проверки"})
    out.sort(key=lambda r: (r["kind"], r["name"].casefold()))
    notes.append("Сопоставление — только по адресу (mail, UPN, адреса Exchange); совпадение по ФИО не используется. Все строки — «Требует проверки»: адресная книга Exchange не эталон штатной структуры.")
    cols = [col("kind", "Расхождение"), col("name", "ФИО"), col("email", "Почта"), col("login", "Логин AD"), col("state", "Состояние в AD"), col("note", "Примечание"), col("dn", "DistinguishedName")]
    return [{"id": "rows", "title": TITLE[view], "columns": cols, "rows": out, "note": "Одна строка — расхождение."}], cond, notes, trunc
