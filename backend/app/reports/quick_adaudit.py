"""Отчёты раздела «Аудит домена» (вид `quick_adaudit`, вид — параметр `view`). Данные — сохранённая проверка (по умолчанию последняя), каталог не читается.

* accounts — все учётные записи; active — включённые; pne — пароль без срока действия; pwd_age — давность смены пароля по группам;
  resets — сброс пароля (события 4724 и учётные записи с несменённым после сброса паролем); unused — неиспользуемые (квартальная проверка: и давние пароли);
  privileged — административные и сервисные; findings — все замечания с решениями; audit — результаты проверки (замечания, оставшиеся с прошлых проверок, устранённые);
  summary — сводка для руководства (состояние домена, замечания по видам и категориям, динамика по проверкам, самые существенные нарушения).

В строках — учётные записи, даты, основания, категория, статус проверки и решение администратора (комментарий, ответственный, срок). Отчёт содержит персональные данные."""
from __future__ import annotations

import uuid
from collections import Counter
from datetime import date

from sqlalchemy import select

from ..adaudit import checks as K
from ..adaudit import diff as DF
from ..adaudit import query as Q
from ..adaudit.service import KIND_RU
from ..ksc.driver import KscError
from ..models import AdAuditAccount as A
from ..models import AdAuditFinding as Fd
from ..models import AdAuditRun, AdPwdEvent
from ..search import matcher
from .quick import Ctx, col, metric

TITLE = {"accounts": "Учётные записи домена", "active": "Активные учётные записи домена", "pne": "Пароль без срока действия (Password Never Expires)", "pwd_age": "Давность смены паролей",
         "resets": "Сброс пароля (Reset Password)", "events": "События смены и сброса пароля", "unused": "Неиспользуемые учётные записи и давние пароли", "privileged": "Административные и сервисные учётные записи",
         "findings": "Замечания аудита домена", "audit": "Результаты проверки домена", "summary": "Аудит домена: сводка для руководства",
         "groups": "Привилегированные группы домена", "changes": "Изменения учётных записей домена с прошлой проверки"}
DEC_RU = {"open": "открыто", "in_progress": "в работе", "fixed": "отмечено устранённым", "exception": "согласованное исключение"}
ACC_COLS = [col("login", "Логин"), col("name", "Отображаемое имя"), col("ou", "Подразделение (OU)"), col("category_ru", "Категория"), col("state", "Состояние"), col("description", "Описание"), col("created", "Создана (UTC)", "date"),
            col("pwd_last_set", "Пароль изменён (UTC)", "date"), col("pwd_age", "Дней с смены пароля", "num"), col("pne", "Бессрочный пароль"), col("last_logon", "Последний вход (UTC)", "date"),
            col("idle_days", "Дней без входа", "num"), col("logon_src", "Источник даты входа"), col("pwd_op", "Последняя операция с паролем"), col("findings", "Замечания")]
FIND_COLS = [col("severity_ru", "Важность", "sev"), col("login", "Логин"), col("name", "Имя"), col("ou", "Подразделение (OU)"), col("acc_state", "Состояние учётной записи"), col("category_ru", "Категория"), col("title", "Замечание"), col("status_ru", "Статус проверки"),
             col("basis", "Основание"), col("first_seen", "Впервые обнаружено", "date"), col("runs_n", "Проверок подряд", "num"), col("decision", "Решение"), col("owner", "Ответственный"),
             col("due", "Срок"), col("comment", "Комментарий администратора")]
OP_RU = {"change": "смена пользователем", "reset": "сброс", "no_event": "событие не найдено", "before_logs": "раньше сохранённых журналов", "no_logs": "нет журналов", "no_pwd": "пароль не задан"}
SRC_RU = {"dc": "lastLogon всех контроллеров", "llt": "lastLogonTimestamp (±14 дн.)", "none": "нет данных"}


def _d(x):
    return x.isoformat() if x else None


def _acc_row(a: A, at, fcount: dict[str, list[str]]) -> dict:
    st = Q.account_state(a.enabled, a.locked, a.expires, at)
    op = a.pwd_op or {}
    return {"login": a.login, "name": a.name, "ou": a.ou, "category_ru": K.CATEGORY_RU.get(a.category, a.category), "state": st, "description": a.description, "created": _d(a.created),
            "pwd_last_set": _d(a.pwd_last_set), "pwd_age": a.pwd_age, "pne": "да" if a.pne else "нет", "last_logon": _d(a.last_logon), "idle_days": a.idle_days,
            "logon_src": SRC_RU.get(a.last_logon_src, a.last_logon_src), "pwd_op": OP_RU.get(op.get("state", ""), "") + (f" ({op['basis']})" if op.get("basis") else ""),
            "findings": "; ".join(fcount.get(a.guid, [])), "dn": a.dn, "bucket": K.BUCKET_RU.get(a.pwd_bucket, ""), "privileged": ", ".join(a.privileged or []),
            "protected": "" if a.protected is None else ("да" if a.protected else "нет"), "category_basis": "; ".join(a.category_basis or [])}


def _find_row(row, at) -> dict:
    f, d, ou, en, locked, expires = row
    exp = d is not None and d.state == "exception" and d.due is not None and d.due < date.today()
    st = Q.account_state(en, locked, expires, at)
    return {"severity_ru": K.SEV_RU.get(f.severity, f.severity), "login": f.login, "name": f.name, "ou": ou or "", "acc_state": st, "category_ru": K.CATEGORY_RU.get(f.category, f.category), "title": f.title,
            "status_ru": K.STATUS_RU.get(f.status, f.status), "basis": f.basis, "first_seen": _d(f.first_seen), "runs_n": f.runs_n,
            "decision": (DEC_RU.get(d.state, d.state) + (" (срок исключения истёк)" if exp else "")) if d else "решения нет", "owner": d.owner if d else "", "due": d.due.isoformat() if d and d.due else "",
            "comment": d.comment if d else "", "code": f.code, "sev_rank": f.sev_rank}


async def build_adaudit(_client, p: dict, ctx: Ctx) -> dict:
    if ctx.sm is None:
        raise KscError("params", "Отчёт недоступен")
    view = p.get("view") or "findings"
    if view not in TITLE:
        raise KscError("params", "Неизвестный вид отчёта аудита домена")
    async with ctx.sm() as db:
        if p.get("run"):
            try:
                run = await db.get(AdAuditRun, uuid.UUID(str(p["run"])))
            except ValueError:
                run = None
        else:
            run = (await db.execute(select(AdAuditRun).where(AdAuditRun.status == "ok").order_by(AdAuditRun.started_at.desc()).limit(1))).scalar_one_or_none()
        if run is None or run.status != "ok":
            raise KscError("no_data", "Проверок домена ещё не было: запустите проверку в разделе «Аудит домена».")
        pol = run.policy or {}
        cond = [{"label": "Проверка", "text": f"{KIND_RU.get(run.kind, run.kind)} от {run.started_at:%d.%m.%Y %H:%M} UTC, {run.domain}"}]
        cond.append({"label": "Политика проверки", "text": policy_text(pol)})
        notes = ["Данные — снимок проверки домена (только чтение каталога). Время — UTC. Отчёт содержит персональные данные: передавайте его только тем, кому они необходимы.", *(run.notes or [])]
        include = p.get("include_inactive", False)
        q = (p.get("q") or "").strip()
        cat, ou, state = (p.get(k) or "" for k in ("category", "ou", "state"))
        text_ok = matcher(q) or (lambda _s: True)
        ou_ok = matcher(ou) or (lambda _s: True)
        cond.append({"label": "Учётные записи", "text": "Только отключённые" if state == "disabled" or p.get("account_view") == "disabled"
                     else "Только заблокированные" if p.get("account_view") == "locked"
                     else "Только с истёкшим сроком действия" if p.get("account_view") == "expired"
                     else "Только активные" if not include or state == "enabled" or view == "active" else "Все состояния"})
        order = (Fd.sev_rank.desc(), Fd.runs_n.desc(), Fd.login)

        async def findings(snapshot, *, resolved=False, **kwargs):
            stmt = Q.findings(snapshot, include_inactive=include, **kwargs)
            if resolved:
                stmt = Q.resolved(stmt, run, include_inactive=include, state=kwargs.get("state", ""))
            return (await db.execute(stmt.order_by(*order))).all()

        filters = {k: p[k] for k in ("q", "ou", "category", "code", "severity", "status", "decision", "carried", "state") if p.get(k)}
        async def accs(acc_view="", *, bucket="", where=True):
            stmt = Q.accounts(run, include_inactive=include, q=q, category=cat, view=acc_view, bucket=bucket, ou=ou).where(where)
            fcount: dict[str, list[str]] = {}
            fq = select(Fd.guid, Fd.title).where(Fd.run_id == run.id, Fd.guid.in_(stmt.with_only_columns(A.guid))).order_by(Fd.sev_rank.desc())
            for guid, title in (await db.execute(fq)).all():
                fcount.setdefault(guid, []).append(title)
            return [_acc_row(a, run.started_at, fcount) for a in (await db.execute(stmt.order_by(A.login))).scalars()]
        tables, metrics = [], []
        if view in ("accounts", "active", "pne", "privileged"):
            acc_view = p.get("account_view") or {"accounts": "", "active": "enabled", "pne": "pne", "privileged": "" if cat else "privileged"}[view]
            rows = await accs(acc_view)
            cols = ACC_COLS + ([col("privileged", "Привилегированные группы"), col("protected", "В Protected Users"), col("category_basis", "Основание категории")] if view == "privileged" else [col("dn", "DistinguishedName")])
            tables.append({"id": "rows", "title": TITLE[view], "columns": cols, "rows": rows, "note": "Одна строка — учётная запись."})
            cnt = Counter(r["category_ru"] for r in rows)
            metrics = [metric("rows", "Учётных записей", len(rows)), *[metric(f"c{i}", k, v) for i, (k, v) in enumerate(cnt.most_common(4))]]
            if view == "pne":
                act = sum(1 for r in rows if r["state"] == "активна")
                metrics.insert(1, metric("active", "Из них активных", act, "", "warn" if act else ""))
        elif view == "pwd_age":
            rows = await accs(bucket=p.get("bucket") or "")
            rows.sort(key=lambda r: -(r["pwd_age"] if r["pwd_age"] is not None else 10 ** 6))
            tables.append({"id": "rows", "title": TITLE[view], "columns": [col("bucket", "Давность"), *ACC_COLS], "rows": rows, "note": f"Сроки по категориям: {', '.join(f'{K.CATEGORY_RU[k]} — {v} дн.' for k, v in (pol.get('pwd_days') or {}).items())}."})
            b = Counter(r["bucket"] for r in rows)
            metrics = [metric(k, v, b.get(v, 0), "", "warn" if k in ("gt180", "unknown") and b.get(v) else "") for k, v in K.BUCKETS]
        elif view == "unused":
            inact = int(pol.get("inactive_days") or 90)
            rows = await accs(where=(A.idle_days > inact) | A.last_logon.is_(None))
            tables.append({"id": "rows", "title": f"Не входили более {inact} дн. или ни разу", "columns": ACC_COLS, "rows": rows, "note": "Источник даты входа указан в строке."})
            old = await accs(bucket="gt180")
            tables.append({"id": "old_pwd", "title": "Пароль не менялся более 180 дней", "columns": ACC_COLS, "rows": old})
            metrics = [metric("unused", "Неиспользуемых", len(rows), "", "warn" if rows else ""), metric("old", "Пароль старше 180 дней", len(old), "", "warn" if old else "")]
        elif view in ("resets", "events"):
            if view == "resets":
                pend = [_find_row(row, run.started_at) for row in await findings(run, code="reset", q=q)]
                tables.append({"id": "rows", "title": "Последняя операция — сброс пароля, пользователь пароль не сменил", "columns": FIND_COLS, "rows": pend,
                               "note": "Штатный порядок — смена пароля пользователем (Change Password, событие 4723). Сброс (4724) требует проверки."})
                metrics.append(metric("pending", "Сброс без последующей смены", len(pend), "", "bad" if pend else ""))
            stmt = Q.event_query(run, include_inactive=include, kind="reset" if view == "resets" else p.get("event_kind") or "", q=q)
            evs = (await db.execute(stmt.order_by(AdPwdEvent.at.desc()).limit(ctx.max_rows + 1))).scalars().all()
            if len(evs) > ctx.max_rows:
                raise KscError("params", f"Событий больше {ctx.max_rows}. Уточните отбор.")
            erows = [{"at": _d(e.at), "target": f"{e.target_domain}\\{e.target}" if e.target_domain else e.target, "by": f"{e.by_domain}\\{e.by}" if e.by_domain else e.by, "dc": e.dc,
                      "result": "успешно" if e.success else "отказ", "event": "Смена (4723)" if e.kind == "change" else "Сброс (4724)"} for e in evs]
            tables.append({"id": "events" if view == "resets" else "rows", "title": "События сброса пароля (4724)" if view == "resets" else TITLE[view],
                           "columns": [col("at", "Время (UTC)", "date"), col("event", "Операция"), col("target", "Учётная запись"), col("by", "Инициатор"), col("dc", "Контроллер"), col("result", "Результат")], "rows": erows})
            cov = (run.coverage or {}).get("logs") or {}
            if not cov:
                notes.append("Журналы безопасности контроллеров не загружены: способ смены пароля неизвестен, сбросы не выявляются. Загрузите выгрузку скрипта Export-KavPasswordEvents.ps1.")
            metrics.extend((metric("events", "Событий", len(erows)), metric("dcs", "Контроллеров с журналами", len(cov))))
        elif view in ("findings", "audit"):
            snapshot = await DF.prev_run(db, run) if p.get("gone") else run
            rows = [_find_row(row, snapshot.started_at) for row in await findings(snapshot, resolved=p.get("gone", False), **filters)] if snapshot else []
            tables.append({"id": "rows", "title": "Устранены с предыдущей проверки" if p.get("gone") else "Замечания", "columns": FIND_COLS, "rows": rows,
                           "note": "Одна строка — замечание (учётная запись × проверка)."})
            if view == "audit":
                carried = [r for r in rows if r["runs_n"] > 1]
                tables.append({"id": "carried", "title": "Остались с предыдущих проверок", "columns": FIND_COLS, "rows": carried})
                prev = await DF.prev_run(db, run)
                gone = [_find_row(row, prev.started_at) for row in await findings(prev, resolved=True, **filters)] if prev else []
                tables.append({"id": "gone", "title": "Устранены с предыдущей проверки", "columns": FIND_COLS[:9], "rows": gone})
                metrics = [metric("all", "Замечаний", len(rows)), metric("carried", "Остались с прошлых проверок", len(carried), "", "warn" if carried else ""), metric("gone", "Устранено", len(gone), "", "ok" if gone else "")]
            else:
                sev = Counter(r["severity_ru"] for r in rows)
                metrics = [metric("all", "Замечаний", len(rows)), *[metric(k, f"Важность: {k}", v) for k, v in sev.most_common(4)]]
        elif view == "groups":
            g = await DF.groups(db, run, include_inactive=include)
            rows = []
            for grp in g["items"]:
                rows += [{"group": grp["group"], **m, "change": "добавлена с прошлой проверки" if m["added"] else ""} for m in grp["members"] if ou_ok(m["ou"]) and (text_ok(m["login"]) or text_ok(m["name"]))]
                rows += [{"group": grp["group"], **m, "change": "исключена с прошлой проверки"} for m in grp["removed"] if ou_ok(m["ou"]) and (text_ok(m["login"]) or text_ok(m["name"]))]
            for r in rows:
                r["pne"] = "да" if r["pne"] else "нет"
                r["protected"] = "" if r["protected"] is None else ("да" if r["protected"] else "нет")
            tables.append({"id": "rows", "title": TITLE[view], "columns": [col("group", "Группа"), col("login", "Логин"), col("name", "Имя"), col("ou", "Подразделение (OU)"), col("state", "Состояние"),
                           col("category_ru", "Категория"), col("last_logon", "Последний вход (UTC)", "date"), col("pwd_age", "Дней с смены пароля", "num"), col("pne", "Бессрочный пароль"),
                           col("protected", "В Protected Users"), col("change", "Изменение")], "rows": rows,
                           "note": "Членство — с учётом вложенных групп и первичной группы. " + (f"Изменения — по сравнению с проверкой от {g['prev'][:10]}." if g["prev"] else "Предыдущей проверки нет: изменения не определяются.")})
            metrics = [metric("groups", "Групп", len(g["items"])), metric("members", "Участников (уникальных)", len({r["guid"] for r in rows if r["change"] != "исключена с прошлой проверки"})),
                       metric("added", "Добавлено", sum(1 for r in rows if r["change"].startswith("добавлена")), "", "warn"), metric("removed", "Исключено", sum(1 for r in rows if r["change"].startswith("исключена")))]
        elif view == "changes":
            c = await DF.changes(db, run, include_inactive=include, limit=ctx.max_rows)
            rows = [x for x in c["items"] if ou_ok(x["ou"]) and (text_ok(x["login"]) or text_ok(x["name"])) and (not p.get("change_kind") or x["kind"] == p["change_kind"])]
            tables.append({"id": "rows", "title": TITLE[view], "columns": [col("kind_ru", "Изменение"), col("login", "Логин"), col("name", "Имя"), col("ou", "Подразделение (OU)"), col("category_ru", "Категория"),
                           col("before", "Было"), col("after", "Стало"), col("state", "Состояние сейчас"), col("created", "Создана (UTC)", "date")], "rows": rows,
                           "note": (f"По сравнению с проверкой от {c['prev'][:10]}." if c["prev"] else "Предыдущей проверки нет: изменения не определяются.") + (f" Показаны первые {ctx.max_rows} записей каждого вида." if c["truncated"] else "")})
            metrics = [metric(k, DF.KIND_RU[k], v) for k, v in Counter(r["kind"] for r in rows).items() if v]
        else:
            tables, metrics, more = await _summary(db, run, await findings(run), include_inactive=include)
            notes += more
    return {"title": TITLE[view], "subtitle": run.domain, "conditions": cond + ([{"label": "Отбор", "text": p["q"]}] if p.get("q") else []) + ([{"label": "Категория", "text": K.CATEGORY_RU.get(cat, cat)}] if cat else [])
            + ([{"label": "Подразделение (OU)", "text": p["ou"]}] if p.get("ou") else []),
            "severity": None, "notes": notes, "metrics": metrics, "tables": tables}


def policy_text(pol: dict) -> str:
    """Политика, по которой выполнена проверка, одной строкой — для шапки отчёта (сроки могли меняться между проверками)."""
    parts = [("срок пароля: " + ", ".join(f"{K.CATEGORY_RU.get(k, k).lower()} — {v} дн." for k, v in (pol.get("pwd_days") or {}).items())) if pol.get("pwd_days") else ""]
    if pol.get("inactive_days"):
        parts.append(f"неиспользуемая — без входа более {pol['inactive_days']} дн.")
    if pol.get("policy_note"):
        parts.append(f"основание: {pol['policy_note']}")
    return "; ".join(p for p in parts if p) or "не сохранена (проверка до версии 0.38.0)"


async def _summary(db, run: AdAuditRun, fl, *, include_inactive: bool) -> tuple[list[dict], list[dict], list[str]]:
    s = await Q.stats(db, run, include_inactive=include_inactive)
    today = date.today()
    active = [row for row in fl if not ((d := row[1]) is not None and d.state == "exception" and (d.due is None or d.due >= today))]
    state_rows = [{"k": k, "v": s.get(key, 0)} for k, key in (("Учётных записей", "accounts"), ("Активных", "enabled"), ("Отключённых", "disabled"), ("Заблокированных", "locked"),
                  ("Пароль без срока действия", "pne"), ("Пароль старше 180 дней", "pwd_gt180"), ("Неиспользуемых", "inactive"),
                  ("Привилегированных", "privileged"), ("Сброс пароля без последующей смены", "reset_pending"), ("Недавно созданных", "new")) if include_inactive or key not in ("disabled", "locked")]
    by_code = Counter((f.code, f.title, f.severity) for f, *_rest in active)
    code_rows = [{"title": t, "severity_ru": K.SEV_RU[sv], "n": n} for (c, t, sv), n in sorted(by_code.items(), key=lambda x: (-K.SEV_RANK[x[0][2]], -x[1]))]
    by_cat = Counter(K.CATEGORY_RU.get(f.category, f.category) for f, *_rest in active)
    runs = (await db.execute(select(AdAuditRun).where(AdAuditRun.status == "ok", AdAuditRun.started_at <= run.started_at).order_by(AdAuditRun.started_at.desc()).limit(12))).scalars().all()
    totals = {r.id: (r.stats or {}) for r in runs} if include_inactive else await Q.totals(db, runs)
    dyn = [{"at": _d(r.started_at), "kind": KIND_RU.get(r.kind, r.kind), "accounts": totals[r.id].get("accounts", 0),
            "findings": totals[r.id].get("findings", 0), "violations": totals[r.id].get("f_violation", 0),
            "new": totals[r.id].get("new_since_prev"), "fixed": totals[r.id].get("fixed_since_prev")} for r in reversed(runs)]
    top = [_find_row(row, run.started_at) for row in active if row[0].status == "violation" and row[0].sev_rank >= 3][:30]
    by_ou: dict[str, dict] = {}
    for f, _dec, ou, *_rest in active:
        o = by_ou.setdefault(ou or "", {"n": 0, "viol": 0, "high": 0, "accs": set()})
        o["n"] += 1
        o["viol"] += f.status == "violation"
        o["high"] += f.sev_rank >= 3
        o["accs"].add(f.guid)
    ou_rows = sorted(({"ou": k or "(корень домена)", "n": v["n"], "viol": v["viol"], "high": v["high"], "accs": len(v["accs"])} for k, v in by_ou.items()), key=lambda r: (-r["high"], -r["n"], r["ou"]))
    tables = [{"id": "top", "title": "Наиболее существенные нарушения", "columns": FIND_COLS[:9], "rows": top},
              {"id": "state", "title": "Состояние домена", "columns": [col("k", "Показатель"), col("v", "Значение", "num")], "rows": state_rows},
              {"id": "codes", "title": "Замечания по видам (без согласованных исключений)", "columns": [col("title", "Замечание"), col("severity_ru", "Важность", "sev"), col("n", "Количество", "num")], "rows": code_rows},
              {"id": "ous", "title": "Замечания по подразделениям (OU)", "columns": [col("ou", "Подразделение (OU)"), col("n", "Замечаний", "num"), col("viol", "Нарушений", "num"), col("high", "Критических и высоких", "num"),
                                                                              col("accs", "Учётных записей с замечаниями", "num")], "rows": ou_rows[:50],
               "note": "Без согласованных исключений; первые 50 подразделений по числу критических и высоких замечаний." if len(ou_rows) > 50 else "Без согласованных исключений."},
              {"id": "cats", "title": "Замечания по категориям учётных записей", "columns": [col("k", "Категория"), col("v", "Замечаний", "num")], "rows": [{"k": k, "v": v} for k, v in by_cat.most_common()]},
              {"id": "dyn", "title": "Динамика по проверкам", "columns": [col("at", "Проверка (UTC)", "date"), col("kind", "Вид"), col("accounts", "Учётных записей", "num"), col("findings", "Замечаний", "num"),
                           col("violations", "Нарушений", "num"), col("new", "Новых", "num"), col("fixed", "Устранено", "num")], "rows": dyn}]
    metrics = [metric("accounts", "Учётных записей", s.get("accounts", 0)), metric("violations", "Нарушений", sum(1 for f, *_rest in active if f.status == "violation"), "", "bad"),
               metric("critical", "Критических и высоких", sum(1 for f, *_rest in active if f.sev_rank >= 3), "", "bad"), metric("exceptions", "Согласованных исключений", len(fl) - len(active)),
               metric("fixed", "Устранено с прошлой проверки", s.get("fixed_since_prev", 0), "", "ok")]
    notes = [] if (run.coverage or {}).get("logs") else ["Журналы безопасности контроллеров не загружены: проверка способа смены пароля (Reset Password) не выполнялась."]
    return tables, metrics, notes
