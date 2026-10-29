"""Отчёты по таблицам администрирования (только администратор; данные — внутренняя база, KSC не читается). Вид — параметр `view`:

* licenses — лицензии всех источников без двойного счёта (как «Администрирование → Лицензии»);
* journal — журнал событий с фильтрами страницы (текст, уровень, компонент, период);
* audit — журнал действий (текст, действие, период);
* users — учётные записи, роли, доступ к источникам, 2FA, последний вход;
* components — компоненты, установленные и доступные версии, решения по обновлению;
* bi_imports — журнал импорта BI-источника.

Фильтры совпадают с таблицами страниц (общие выборки `services/logq.py`), записей — сколько подходит под условия, в пределах предела строк отчёта."""
from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime

from sqlalchemy import select

from ..ksc.driver import KscError, SourceClient
from ..models import AuditLog, BiImport, BiSource, EventLog, KscSource, User
from ..services.logq import SPANS, audit_stmt, journal_stmt
from .quick import Ctx, col, metric

TITLE = {"licenses": "Лицензии", "journal": "Журнал событий", "audit": "Журнал действий", "users": "Пользователи KAV Checker", "components": "Компоненты", "bi_imports": "Журнал импорта BI"}
LIC_STATE = {"active": "действует", "expiring": "скоро истекает", "expired": "истекла", "perpetual": "бессрочная", "unknown": "срок неизвестен"}
LEVEL_RU = {"debug": "отладка", "info": "сведения", "warn": "предупреждение", "error": "ошибка"}
ROLE_RU = {"admin": "Администратор", "analyst": "Аналитик", "viewer": "Просмотр"}
RESULT_RU = {"success": "успех", "denied": "отказ", "error": "ошибка"}
RANGE_RU = {"1h": "за час", "24h": "за сутки", "7d": "за 7 суток", "30d": "за 30 суток"}
PAGE = 2000


def _cap(n: int, ctx: Ctx) -> None:
    if n > ctx.max_rows:
        raise KscError("too_many_rows", f"Записей больше предела отчёта ({ctx.max_rows}): сузьте условия или повысьте предел в «Администрирование → Общие настройки»")


async def _paged(db, stmt, order, ctx: Ctx) -> list:
    out, offset = [], 0
    while True:
        part = (await db.execute(stmt.order_by(order).offset(offset).limit(PAGE))).scalars().all()
        out += part
        _cap(len(out), ctx)
        ctx.progress(f"записей: {len(out)}")
        if len(part) < PAGE:
            return out
        offset += PAGE


async def _licenses(db, p: dict, ctx: Ctx) -> dict:
    from ..overview.service import licenses_block  # noqa: PLC0415

    srcs = (await db.execute(select(KscSource).order_by(KscSource.position, KscSource.name))).scalars().all()
    lic = await licenses_block(db, list(srcs))
    rows = [{"product": g["product"], "kind": g["kind"], "limit": g["limit"], "used": g["used"], "free": g["free"], "expires_at": g["expires_at"], "state_ru": LIC_STATE.get(g["state"], g["state"]),
             "sources": "; ".join(s["name"] for s in g["sources"]), "pool": g["pool"] or ("общий ключ" if g["shared"] else "один ключ"), "origin": ", ".join("вручную" if o == "manual" else "KSC" for o in g["origin"])}
            for g in lic["groups"]]
    t = lic["totals"]
    by_state = Counter(r["state_ru"] for r in rows)
    nd = "нет данных"                                                   # неизвестное не заменяется нулём и не остаётся пустой ячейкой
    return {"metrics": [metric("limit", "Лимит действующих лицензий", nd if t.get("limit") is None else t["limit"], "истёкшие не входят"),
                        metric("used", "Использовано", nd if t.get("used") is None else t["used"], "только известные значения"),
                        metric("free", "Свободно", nd if t.get("free") is None else t["free"], "использование известно не по всем действующим" if t.get("free") is None else ""), metric("expired", "Истекли", by_state.get("истекла", 0), "", "danger" if by_state.get("истекла") else "ok"),
                        metric("expiring", "Скоро истекают", by_state.get("скоро истекает", 0))],
            "notes": ["Одна лицензия на нескольких серверах KSC считается один раз (по отпечатку или объединению в пул). Неизвестное использование не заменяется нулём."],
            "conditions": [{"label": "Источники", "text": "все источники KSC"}],
            "tables": [{"id": "rows", "title": "Лицензии", "columns": [col("product", "Продукт"), col("kind", "Тип"), col("limit", "Лимит", "num"), col("used", "Использовано", "num"), col("free", "Свободно", "num"),
                                                                    col("expires_at", "Срок (UTC)", "date"), col("state_ru", "Состояние"), col("sources", "Источники"), col("pool", "Пул"), col("origin", "Сведения")], "rows": rows}]}


async def _journal(db, p: dict, ctx: Ctx) -> dict:
    try:
        since, until = (datetime.fromisoformat(str(x)) if x else None for x in (p.get("since"), p.get("until")))
    except ValueError:
        raise KscError("params", "Неверная дата периода") from None
    stmt = journal_stmt(p.get("q") or "", p.get("level") or "", p.get("category") or "", p.get("range") or "24h", since, until)
    rows = [{"at": r.at, "level_ru": LEVEL_RU.get(r.level, r.level), "category": r.category, "event": r.event, "user": r.user or "", "source": r.source or "", "message": r.message or "",
             "duration_ms": r.duration_ms, "ip": r.ip or ""} for r in await _paged(db, stmt, EventLog.id.desc(), ctx)]
    lv = Counter(r["level_ru"] for r in rows)
    cond = [{"label": "Период", "text": f"{since:%d.%m.%Y %H:%M} — {until:%d.%m.%Y %H:%M} UTC" if since and until else RANGE_RU.get(p.get("range") or "24h", "за сутки")}]
    cond += [{"label": k, "text": v} for k, v in (("Поиск", f"«{p['q']}»" if p.get("q") else ""), ("Уровень", "предупреждения и ошибки" if p.get("level") == "warn" else LEVEL_RU.get(p.get("level") or "", "")),
                                                   ("Компонент", p.get("category") or "")) if v]
    return {"metrics": [metric("n", "Записей", len(rows)), metric("errors", "Ошибок", lv.get("ошибка", 0), "", "danger" if lv.get("ошибка") else "ok"), metric("warn", "Предупреждений", lv.get("предупреждение", 0))],
            "conditions": cond, "notes": ["Время — UTC."],
            "tables": [{"id": "rows", "title": "События", "columns": [col("at", "Время (UTC)", "date"), col("level_ru", "Уровень"), col("category", "Компонент"), col("event", "Событие", "mono"), col("user", "Пользователь"),
                                                                   col("source", "Источник"), col("message", "Сообщение"), col("duration_ms", "мс", "num"), col("ip", "IP", "mono")], "rows": rows},
                       {"id": "by_event", "title": "Чаще всего", "columns": [col("event", "Событие", "mono"), col("n", "Записей", "num")],
                        "rows": [{"event": k, "n": v} for k, v in Counter(r["event"] for r in rows).most_common(20)]}]}


async def _audit(db, p: dict, ctx: Ctx) -> dict:
    span = SPANS.get(p.get("range") or "")
    from datetime import timedelta  # noqa: PLC0415

    stmt = audit_stmt(p.get("q") or "", p.get("action") or "", since=(ctx.now - timedelta(hours=span)) if span else None)
    rows = [{"at": r.at, "actor": r.actor, "action": r.action, "target": f"{r.target_type} {r.target_id}".strip(), "details": "; ".join(f"{k}: {v}" for k, v in (r.details or {}).items() if v not in (None, "")),
             "result_ru": RESULT_RU.get(r.result, r.result), "ip": r.ip or "", "duration_ms": r.duration_ms} for r in await _paged(db, stmt, AuditLog.id.desc(), ctx)]
    cond = [{"label": k, "text": v} for k, v in (("Поиск", f"«{p['q']}»" if p.get("q") else ""), ("Действие", f"{p['action']}…" if p.get("action") else ""), ("Период", RANGE_RU.get(p.get("range") or "", "весь журнал"))) if v]
    return {"metrics": [metric("n", "Действий", len(rows)), metric("actors", "Пользователей", len({r["actor"] for r in rows})),
                        metric("denied", "Отказов и ошибок", sum(1 for r in rows if r["result_ru"] != "успех"))],
            "conditions": cond, "notes": ["Пароли и секреты в журнал действий не записываются. Время — UTC."],
            "tables": [{"id": "rows", "title": "Действия", "columns": [col("at", "Время (UTC)", "date"), col("actor", "Кто"), col("action", "Действие", "mono"), col("target", "Объект", "mono"), col("details", "Подробности"),
                                                                    col("result_ru", "Результат"), col("ip", "IP", "mono"), col("duration_ms", "мс", "num")], "rows": rows}]}


async def _users(db, p: dict, ctx: Ctx) -> dict:
    from ..search import any_of  # noqa: PLC0415

    stmt = select(User).order_by(User.display_name)
    if (cond := any_of(p.get("q") or "", User.display_name, User.username)) is not None:
        stmt = stmt.where(cond)
    names = {s.id: s.name for s in (await db.execute(select(KscSource))).scalars()}
    rows = [{"name": u.display_name, "login": u.username, "email": u.email or "", "auth": "локальная" if u.auth_source == "local" else "каталог (LDAPS)", "role": ROLE_RU.get(u.role, u.role),
             "sources": "все" if u.all_sources else "; ".join(names.get(uuid.UUID(str(x)), str(x)) for x in (u.source_ids or [])) or "нет", "totp": "включена" if u.totp_enabled else "нет",
             "last_login_at": u.last_login_at, "active": "активен" if u.is_active else "отключён"} for u in (await db.execute(stmt)).scalars()]
    roles = Counter(r["role"] for r in rows)
    return {"metrics": [metric("n", "Учётных записей", len(rows)), metric("admins", "Администраторов", roles.get("Администратор", 0)), metric("totp", "С 2FA", sum(1 for r in rows if r["totp"] == "включена")),
                        metric("off", "Отключено", sum(1 for r in rows if r["active"] == "отключён"))],
            "conditions": [{"label": "Поиск", "text": f"«{p['q']}»"}] if p.get("q") else [], "notes": ["Пароли и секреты второго фактора в отчёт не входят."],
            "tables": [{"id": "rows", "title": "Учётные записи", "columns": [col("name", "Пользователь"), col("login", "Логин", "mono"), col("email", "Почта"), col("auth", "Вход"), col("role", "Роль"),
                                                                          col("sources", "Источники KSC"), col("totp", "2FA"), col("last_login_at", "Последний вход (UTC)", "date"), col("active", "Статус")], "rows": rows}]}


async def _components(db, p: dict, ctx: Ctx) -> dict:
    from ..services import components as C  # noqa: PLC0415

    t = await C.table(db, ctx.settings)
    items = [i for i in t["items"] if not p.get("status") or i["status"] == p["status"]]
    rows = [{"title": i["title"], "group": i["group"], "running": "да" if i["running"] else "нет" if i["running"] is False else "—", "installed": i["installed"] or "", "latest": i["latest"] or "",
             "status_ru": i["status_ru"], "why": i["why"] or "", "decision": i["decision"] or ""} for i in items]
    st = Counter(r["status_ru"] for r in rows)
    return {"metrics": [metric("n", "Компонентов", len(rows)), *[metric(f"s{n}", k, v) for n, (k, v) in enumerate(st.most_common())]],
            "conditions": [{"label": "Реестр рассмотрен для выпуска", "text": t["reviewed_for"]}], "notes": ["Доступные версии проверяет фоновая служба раз в сутки; обновление приложения — только проверенным выпуском."],
            "tables": [{"id": "rows", "title": "Компоненты", "columns": [col("title", "Компонент"), col("group", "Группа"), col("running", "Работает"), col("installed", "Установлена", "mono"), col("latest", "Доступна", "mono"),
                                                                      col("status_ru", "Статус"), col("why", "Пояснение"), col("decision", "Решение")], "rows": rows}]}


async def _bi_imports(db, p: dict, ctx: Ctx) -> dict:
    from ..api.bi import imp_out  # noqa: PLC0415

    try:
        sid = uuid.UUID(str(p.get("source_id") or ""))
    except ValueError:
        raise KscError("params", "Выберите BI-источник") from None
    src = await db.get(BiSource, sid)
    if src is None:
        raise KscError("params", "BI-источник не найден")
    imps = [imp_out(i) for i in (await db.execute(select(BiImport).where(BiImport.source_id == sid).order_by(BiImport.started_at.desc()).limit(ctx.max_rows))).scalars()]
    rows = [{"started_at": i["started_at"], "file": i["file_name"] or "", "trigger": i["trigger"], "by": i["by"], "status_ru": i["status_ru"], "rows_read": i["rows_read"], "rows_valid": i["rows_valid"],
             "rows_new": i["rows_new"], "rows_changed": i["rows_changed"], "rows_rejected": i["rows_rejected"], "warnings": i["warnings_n"], "ms": i["ms"], "message": i["message"] or ""} for i in imps]
    st = Counter(r["status_ru"] for r in rows)
    return {"metrics": [metric("n", "Импортов", len(rows)), *[metric(f"s{n}", k, v) for n, (k, v) in enumerate(st.most_common())]],
            "conditions": [{"label": "BI-источник", "text": src.name}], "notes": ["Отклонённый импорт не меняет опубликованные данные: страницы показывают последний успешный снимок."],
            "tables": [{"id": "rows", "title": "Импорты", "columns": [col("started_at", "Начало (UTC)", "date"), col("file", "Файл"), col("trigger", "Запуск"), col("by", "Кто"), col("status_ru", "Итог"),
                                                                   col("rows_read", "Строк", "num"), col("rows_valid", "Записей", "num"), col("rows_new", "Новых", "num"), col("rows_changed", "Изменено", "num"),
                                                                   col("rows_rejected", "Отклонено", "num"), col("warnings", "Предупреждений", "num"), col("ms", "мс", "num"), col("message", "Сообщение")], "rows": rows}]}


VIEWS = {"licenses": _licenses, "journal": _journal, "audit": _audit, "users": _users, "components": _components, "bi_imports": _bi_imports}


async def build_admin(client: SourceClient, p: dict, ctx: Ctx) -> dict:
    view = p.get("view") or "journal"
    if ctx.sm is None or view not in VIEWS:
        raise KscError("params", "Отчёт администрирования недоступен")
    async with ctx.sm() as db:
        doc = await VIEWS[view](db, p, ctx)
    return {"title": TITLE[view], "subtitle": "Администрирование KAV Checker", "severity": None, "conditions": [], "notes": [], **doc}
