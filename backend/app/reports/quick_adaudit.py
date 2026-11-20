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
from ..adaudit.service import KIND_RU
from ..ksc.driver import KscError
from ..models import AdAuditAccount as A
from ..models import AdAuditDecision as D
from ..models import AdAuditFinding as Fd
from ..models import AdAuditRun, AdPwdEvent
from ..search import matcher
from .quick import Ctx, col, metric

TITLE = {"accounts": "Учётные записи домена", "active": "Активные учётные записи домена", "pne": "Пароль без срока действия (Password Never Expires)", "pwd_age": "Давность смены паролей",
         "resets": "Сброс пароля (Reset Password)", "unused": "Неиспользуемые учётные записи и давние пароли", "privileged": "Административные и сервисные учётные записи",
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


def _state(a: A) -> str:
    return "отключена" if not a.enabled else "заблокирована" if a.locked else "активна"


def _acc_row(a: A, fcount: dict[str, list[str]]) -> dict:
    st = _state(a)
    op = a.pwd_op or {}
    return {"login": a.login, "name": a.name, "ou": a.ou, "category_ru": K.CATEGORY_RU.get(a.category, a.category), "state": st, "description": a.description, "created": _d(a.created),
            "pwd_last_set": _d(a.pwd_last_set), "pwd_age": a.pwd_age, "pne": "да" if a.pne else "нет", "last_logon": _d(a.last_logon), "idle_days": a.idle_days,
            "logon_src": SRC_RU.get(a.last_logon_src, a.last_logon_src), "pwd_op": OP_RU.get(op.get("state", ""), "") + (f" ({op['basis']})" if op.get("basis") else ""),
            "findings": "; ".join(fcount.get(a.guid, [])), "dn": a.dn, "bucket": K.BUCKET_RU.get(a.pwd_bucket, ""), "privileged": ", ".join(a.privileged or []),
            "protected": "" if a.protected is None else ("да" if a.protected else "нет"), "category_basis": "; ".join(a.category_basis or [])}


def _find_row(f: Fd, d: D | None, acc: dict[str, tuple[str, str]] | None = None) -> dict:
    exp = d is not None and d.state == "exception" and d.due is not None and d.due < date.today()
    ou, st = (acc or {}).get(f.guid, ("", ""))
    return {"severity_ru": K.SEV_RU.get(f.severity, f.severity), "login": f.login, "name": f.name, "ou": ou, "acc_state": st, "category_ru": K.CATEGORY_RU.get(f.category, f.category), "title": f.title,
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
        fl = (await db.execute(select(Fd, D).outerjoin(D, D.key == Fd.key).where(Fd.run_id == run.id).order_by(Fd.sev_rank.desc(), Fd.login))).all()
        fcount: dict[str, list[str]] = {}
        for f, _d0 in fl:
            fcount.setdefault(f.guid, []).append(f.title)
        accinfo = await _acc_info(db, run.id)
        q = (p.get("q") or "").strip().casefold()
        cat = p.get("category") or ""
        ou_ok = matcher(p.get("ou")) or (lambda _s: True)
        state = p.get("state") or ""

        def acc_ok(a: A) -> bool:
            return (not cat or a.category == cat) and (not q or q in a.login.casefold() or q in a.name.casefold() or q in a.ou.casefold()) and ou_ok(a.ou)

        def f_ok(f: Fd) -> bool:
            ou, st = accinfo.get(f.guid, ("", ""))
            return (not cat or f.category == cat) and (not q or q in f.login.casefold() or q in f.name.casefold() or q in ou.casefold()) and ou_ok(ou) \
                and (not state or (st == "отключена") == (state == "disabled"))

        async def accs(*where) -> list[A]:
            return [a for a in (await db.execute(select(A).where(A.run_id == run.id, *where).order_by(A.login))).scalars().all() if acc_ok(a)]

        tables, metrics = [], []
        if view in ("accounts", "active", "pne", "privileged"):
            where = {"accounts": (), "active": (A.enabled.is_(True),), "pne": (A.pne.is_(True),), "privileged": (A.category.in_(("admin", "service")),)}[view]
            rows = [_acc_row(a, fcount) for a in await accs(*where)]
            cols = ACC_COLS + ([col("privileged", "Привилегированные группы"), col("protected", "В Protected Users"), col("category_basis", "Основание категории")] if view == "privileged" else [col("dn", "DistinguishedName")])
            tables.append({"id": "rows", "title": TITLE[view], "columns": cols, "rows": rows, "note": "Одна строка — учётная запись."})
            cnt = Counter(r["category_ru"] for r in rows)
            metrics = [metric("rows", "Учётных записей", len(rows)), *[metric(f"c{i}", k, v) for i, (k, v) in enumerate(cnt.most_common(4))]]
            if view == "pne":
                act = sum(1 for r in rows if r["state"] != "отключена")
                metrics.insert(1, metric("active", "Из них активных", act, "", "warn" if act else ""))
        elif view == "pwd_age":
            rows = [_acc_row(a, fcount) for a in await accs(A.enabled.is_(True))]
            rows.sort(key=lambda r: -(r["pwd_age"] if r["pwd_age"] is not None else 10 ** 6))
            tables.append({"id": "rows", "title": TITLE[view], "columns": [col("bucket", "Давность"), *ACC_COLS], "rows": rows, "note": f"Только включённые. Сроки по категориям: {', '.join(f'{K.CATEGORY_RU[k]} — {v} дн.' for k, v in (pol.get('pwd_days') or {}).items())}."})
            b = Counter(r["bucket"] for r in rows)
            metrics = [metric(k, v, b.get(v, 0), "", "warn" if k in ("gt180", "unknown") and b.get(v) else "") for k, v in K.BUCKETS]
        elif view == "unused":
            inact = int(pol.get("inactive_days") or 90)
            rows = [_acc_row(a, fcount) for a in await accs(A.enabled.is_(True)) if (a.idle_days is not None and a.idle_days > inact) or (a.last_logon is None)]
            tables.append({"id": "rows", "title": f"Не входили более {inact} дн. или ни разу", "columns": ACC_COLS, "rows": rows, "note": "Включённые учётные записи. Источник даты входа указан в строке."})
            old = [_acc_row(a, fcount) for a in await accs(A.enabled.is_(True), A.pwd_bucket == "gt180")]
            tables.append({"id": "old_pwd", "title": "Пароль не менялся более 180 дней", "columns": ACC_COLS, "rows": old})
            metrics = [metric("unused", "Неиспользуемых", len(rows), "", "warn" if rows else ""), metric("old", "Пароль старше 180 дней", len(old), "", "warn" if old else "")]
        elif view == "resets":
            pend = [_find_row(f, d, accinfo) for f, d in fl if f.code == "reset" and f_ok(f)]
            tables.append({"id": "rows", "title": "Последняя операция — сброс пароля, пользователь пароль не сменил", "columns": FIND_COLS, "rows": pend,
                           "note": "Штатный порядок — смена пароля пользователем (Change Password, событие 4723). Сброс (4724) требует проверки."})
            evs = (await db.execute(select(AdPwdEvent).where(AdPwdEvent.kind == "reset").order_by(AdPwdEvent.at.desc()).limit(ctx.max_rows))).scalars().all()
            erows = [{"at": _d(e.at), "target": f"{e.target_domain}\\{e.target}" if e.target_domain else e.target, "by": f"{e.by_domain}\\{e.by}" if e.by_domain else e.by, "dc": e.dc,
                      "result": "успешно" if e.success else "отказ"} for e in evs if not q or q in (e.target or "").casefold() or q in (e.by or "").casefold()]
            tables.append({"id": "events", "title": "События сброса пароля (4724)", "columns": [col("at", "Время (UTC)", "date"), col("target", "Учётная запись"), col("by", "Кто сбросил"), col("dc", "Контроллер"), col("result", "Результат")], "rows": erows})
            cov = (run.coverage or {}).get("logs") or {}
            if not cov:
                notes.append("Журналы безопасности контроллеров не загружены: способ смены пароля неизвестен, сбросы не выявляются. Загрузите выгрузку скрипта Export-KavPasswordEvents.ps1.")
            metrics = [metric("pending", "Сброс без последующей смены", len(pend), "", "bad" if pend else ""), metric("events", "Событий сброса", len(erows)), metric("dcs", "Контроллеров с журналами", len(cov))]
        elif view in ("findings", "audit"):
            sel = [(f, d) for f, d in fl if f_ok(f) and (not p.get("code") or f.code == p["code"]) and (not p.get("severity") or f.severity == p["severity"])]
            rows = [_find_row(f, d, accinfo) for f, d in sel]
            tables.append({"id": "rows", "title": "Замечания", "columns": FIND_COLS, "rows": rows, "note": "Одна строка — замечание (учётная запись × проверка)."})
            if view == "audit":
                carried = [r for r in rows if r["runs_n"] > 1]
                tables.append({"id": "carried", "title": "Остались с предыдущих проверок", "columns": FIND_COLS, "rows": carried})
                prev = (await db.execute(select(AdAuditRun.id).where(AdAuditRun.status == "ok", AdAuditRun.started_at < run.started_at).order_by(AdAuditRun.started_at.desc()).limit(1))).scalar_one_or_none()
                gone = []
                if prev is not None:
                    keys = {f.key for f, _d1 in fl}
                    pinfo = await _acc_info(db, prev)
                    gone = [_find_row(f, d, pinfo) for f, d in (await db.execute(select(Fd, D).outerjoin(D, D.key == Fd.key).where(Fd.run_id == prev).order_by(Fd.sev_rank.desc()))).all() if f.key not in keys]
                tables.append({"id": "gone", "title": "Устранены с предыдущей проверки", "columns": FIND_COLS[:9], "rows": gone})
                metrics = [metric("all", "Замечаний", len(rows)), metric("carried", "Остались с прошлых проверок", len(carried), "", "warn" if carried else ""), metric("gone", "Устранено", len(gone), "", "ok" if gone else "")]
            else:
                sev = Counter(r["severity_ru"] for r in rows)
                metrics = [metric("all", "Замечаний", len(rows)), *[metric(k, f"Важность: {k}", v) for k, v in sev.most_common(4)]]
        elif view == "groups":
            g = await DF.groups(db, run)
            rows = []
            for grp in g["items"]:
                rows += [{"group": grp["group"], **m, "change": "добавлена с прошлой проверки" if m["added"] else ""} for m in grp["members"] if ou_ok(m["ou"]) and (not q or q in m["login"].casefold() or q in m["name"].casefold())]
                rows += [{"group": grp["group"], **m, "change": "исключена с прошлой проверки"} for m in grp["removed"] if ou_ok(m["ou"])]
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
            c = await DF.changes(db, run)
            rows = [x for x in c["items"] if ou_ok(x["ou"]) and (not q or q in x["login"].casefold() or q in x["name"].casefold())]
            tables.append({"id": "rows", "title": TITLE[view], "columns": [col("kind_ru", "Изменение"), col("login", "Логин"), col("name", "Имя"), col("ou", "Подразделение (OU)"), col("category_ru", "Категория"),
                           col("before", "Было"), col("after", "Стало"), col("state", "Состояние сейчас"), col("created", "Создана (UTC)", "date")], "rows": rows,
                           "note": (f"По сравнению с проверкой от {c['prev'][:10]}." if c["prev"] else "Предыдущей проверки нет: изменения не определяются.") + (f" Показаны первые {DF.LIMIT} записей каждого вида." if c["truncated"] else "")})
            metrics = [metric(k, DF.KIND_RU[k], v) for k, v in c["counts"].items() if v]
        else:
            tables, metrics, more = await _summary(db, run, fl, accinfo)
            notes += more
    return {"title": TITLE[view], "subtitle": run.domain, "conditions": cond + ([{"label": "Отбор", "text": p["q"]}] if p.get("q") else []) + ([{"label": "Категория", "text": K.CATEGORY_RU.get(cat, cat)}] if cat else [])
            + ([{"label": "Подразделение (OU)", "text": p["ou"]}] if p.get("ou") else []) + ([{"label": "Учётные записи", "text": "только активные" if state == "enabled" else "только отключённые"}] if state else []),
            "severity": None, "notes": notes, "metrics": metrics, "tables": tables}


def policy_text(pol: dict) -> str:
    """Политика, по которой выполнена проверка, одной строкой — для шапки отчёта (сроки могли меняться между проверками)."""
    parts = [("срок пароля: " + ", ".join(f"{K.CATEGORY_RU.get(k, k).lower()} — {v} дн." for k, v in (pol.get("pwd_days") or {}).items())) if pol.get("pwd_days") else ""]
    if pol.get("inactive_days"):
        parts.append(f"неиспользуемая — без входа более {pol['inactive_days']} дн.")
    if pol.get("policy_note"):
        parts.append(f"основание: {pol['policy_note']}")
    return "; ".join(p for p in parts if p) or "не сохранена (проверка до версии 0.38.0)"


async def _acc_info(db, run_id) -> dict[str, tuple[str, str]]:
    """Подразделение и состояние учётных записей проверки (guid → (OU, состояние)) — для строк замечаний."""
    rows = (await db.execute(select(A.guid, A.ou, A.enabled, A.locked).where(A.run_id == run_id))).all()
    return {g: (ou, "отключена" if not en else "заблокирована" if lk else "активна") for g, ou, en, lk in rows}


async def _summary(db, run: AdAuditRun, fl, accinfo: dict[str, tuple[str, str]]) -> tuple[list[dict], list[dict], list[str]]:
    s = run.stats or {}
    today = date.today()
    active = [(f, d) for f, d in fl if not (d is not None and d.state == "exception" and (d.due is None or d.due >= today))]
    state_rows = [{"k": k, "v": s.get(key, 0)} for k, key in (("Учётных записей", "accounts"), ("Активных", "enabled"), ("Отключённых", "disabled"), ("Заблокированных", "locked"),
                  ("Пароль без срока действия (активные)", "pne"), ("Пароль старше 180 дней (активные)", "pwd_gt180"), ("Неиспользуемых (активные)", "inactive"),
                  ("Привилегированных", "privileged"), ("Сброс пароля без последующей смены", "reset_pending"), ("Недавно созданных", "new"))]
    by_code = Counter((f.code, f.title, f.severity) for f, _d in active)
    code_rows = [{"title": t, "severity_ru": K.SEV_RU[sv], "n": n} for (c, t, sv), n in sorted(by_code.items(), key=lambda x: (-K.SEV_RANK[x[0][2]], -x[1]))]
    by_cat = Counter(K.CATEGORY_RU.get(f.category, f.category) for f, _d in active)
    runs = (await db.execute(select(AdAuditRun).where(AdAuditRun.status == "ok", AdAuditRun.started_at <= run.started_at).order_by(AdAuditRun.started_at.desc()).limit(12))).scalars().all()
    dyn = [{"at": _d(r.started_at), "kind": KIND_RU.get(r.kind, r.kind), "accounts": (r.stats or {}).get("accounts", 0), "findings": (r.stats or {}).get("findings", 0),
            "violations": (r.stats or {}).get("f_violation", 0), "new": (r.stats or {}).get("new_since_prev", 0), "fixed": (r.stats or {}).get("fixed_since_prev", 0)} for r in reversed(runs)]
    top = [_find_row(f, d, accinfo) for f, d in active if f.status == "violation" and f.sev_rank >= 3][:30]
    by_ou: dict[str, dict] = {}
    for f, _dec in active:
        o = by_ou.setdefault(accinfo.get(f.guid, ("", ""))[0], {"n": 0, "viol": 0, "high": 0, "accs": set()})
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
    metrics = [metric("accounts", "Учётных записей", s.get("accounts", 0)), metric("violations", "Нарушений", sum(1 for f, _d in active if f.status == "violation"), "", "bad"),
               metric("critical", "Критических и высоких", sum(1 for f, _d in active if f.sev_rank >= 3), "", "bad"), metric("exceptions", "Согласованных исключений", len(fl) - len(active)),
               metric("fixed", "Устранено с прошлой проверки", s.get("fixed_since_prev", 0), "", "ok")]
    notes = [] if (run.coverage or {}).get("logs") else ["Журналы безопасности контроллеров не загружены: проверка способа смены пароля (Reset Password) не выполнялась."]
    return tables, metrics, notes
