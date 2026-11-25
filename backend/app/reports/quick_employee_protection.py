"""Сводка и детализация защиты сотрудников по серверному отбору дашборда."""
from sqlalchemy import text

from ..employee_protection import classify, read
from ..employee_protection.filters import Filters
from ..ksc.driver import KscError
from ..services.resources import RES
from .quick import Ctx, col, metric

TITLE = "Антивирусная защита сотрудников"
PEOPLE = [col("name", "Сотрудник"), col("login", "Доменная учётная запись"), col("email", "Рабочая почта"),
          col("organization", "Организация"), col("department", "Департамент"), col("division", "Подразделение"),
          col("title", "Должность"), col("account_created", "Дата создания учётной записи", "date"),
          col("device_count", "Известные устройства", "num"), col("installed_devices", "Установлен антивирус", "num"),
          col("protected_devices", "Защищённые устройства", "num"), col("status", "Состояние защиты"),
          col("reason", "Основание"), col("freshness", "Актуальность"), col("last_seen", "Последнее подключение", "date")]
DEVICES = [col("name", "Компьютер"), col("ip", "IP-адрес"), col("users", "Связанные сотрудники"), col("evidence", "Основания связи"),
           col("assigned_employee", "Закреплённый сотрудник"), col("assignment_basis", "Основание закрепления"),
           col("kind", "Тип"), col("ownership", "Тип собственности"), col("ownership_basis", "Источник типа собственности"), col("zones_text", "Зоны ответственности"),
           col("os", "ОС"), col("os_version", "Версия ОС"), col("av_product", "Защитный продукт"), col("av_version", "Версия продукта"),
           col("installed", "Установка подтверждена"), col("status", "Состояние защиты"), col("reason", "Основание"),
           col("freshness", "Актуальность"), col("last_connected", "Последнее подключение", "date")]
WORKPLACES = [col("employee", "Сотрудник"), col("login", "Учётная запись"), col("department", "Подразделение"),
              col("device", "Компьютер"), col("confidence", "Оценка связи"), col("evidence", "Основания"),
              col("primary", "Основное рабочее место"), col("assignment_basis", "Закрепление сотрудника"),
              col("observed_days", "Дни наблюдений", "num"), col("span_days", "Интервал наблюдений, дни", "num"), col("first_seen_at", "Первое наблюдение", "date"),
              col("last_seen_at", "Последнее наблюдение", "date"), col("decision", "Решение администратора"),
              col("decided_at", "Дата решения", "date"), col("proposals", "Предложения по учёту")]
DIAGNOSTICS = [col("source_name", "Источник KSC"), col("polled_at", "Опрос пользователей (UTC)", "date"),
               col("snapshot_at", "Срез KSC (UTC)", "date"), col("observed", "Устройства с наблюдениями", "num"),
               col("current", "С текущим доменным сеансом", "num"), col("matched", "Со связями", "num"),
               col("eligible", "В расчёте", "num"), col("av_known", "Защита определена", "num"),
               col("possible", "Только на проверку", "num"), col("reason", "Состояние")]
METRICS = {"employees": "Сотрудники", "uses_av": "С установленным антивирусом", "protected": "Полностью защищены",
           "partial": "Частично защищены", "no_av": "Подтверждено отсутствие", "insufficient": "Недостаточно данных",
           "devices": "Известные устройства", "corporate": "Корпоративные", "personal": "Личные"}


def _export(row, devices):
    out = {**row, "status": (classify.DEVICE_LABELS if devices else classify.EMPLOYEE_LABELS)[row["status"]],
           "reason": classify.REASON_LABELS[row["reason"]], "freshness": read.FRESHNESS[row["freshness"]]}
    if row["reason"] == "workplace_review":
        out["status"] = "Рабочее место требует проверки"
    if devices:
        assignment = row.get("assignment") or {}
        out.update(users=", ".join(p["name"] for p in row["employees"]),
                   evidence=" / ".join(f"{p['name']}: {', '.join(p['evidence'])}" for p in row["employees"]),
                   assigned_employee=assignment.get("employee_name", ""),
                   assignment_basis=read.ASSIGNMENT.get(assignment.get("basis"), read.ASSIGNMENT["unassigned"]),
                   zones_text=", ".join(z["name"] for z in row["zones"]),
                   ownership=read.OWNERSHIP.get(row["ownership"], read.OWNERSHIP["unknown"]),
                   ownership_basis=read.OWNERSHIP_BASIS.get(row.get("ownership_basis"), ""),
                   installed={True: "Да", False: "Нет", None: "Недостаточно данных"}[row["installed"]])
    return out


def _table(id, title, columns, rows):
    return {"id": id, "title": title, "columns": columns, "rows": rows}


def _workplace_export(row):
    p, d = row["employee"], row["device"]
    return {**{k: row.get(k) for k in ("observed_days", "span_days", "first_seen_at", "last_seen_at", "decided_at")},
            "employee": p["name"], "login": p.get("login"), "department": p.get("department"), "device": d["name"],
            "confidence": read.CONFIDENCE[row["confidence"]],
            "decision": "Закреплён" if row.get("decision") == "assigned" else read.CONFIDENCE.get(row.get("decision"), ""),
            "assignment_basis": read.ASSIGNMENT.get(row.get("assignment_basis"), ""),
            "primary": "Да" if row["primary"] else "",
            "evidence": " · ".join(row["evidence"]),
            "proposals": " · ".join(f"{f['label']} — {f['value']}" for f in row.get("proposals", {}).values())}


async def build_employee_protection(_client, p: dict, ctx: Ctx) -> dict:
    view = p.get("view", "employees")
    filters = Filters.model_validate(p)
    workplaces = view == "workplaces"
    async with ctx.sm() as db:
        if db.bind.dialect.name == "postgresql":
            await db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
        if view == "diagnostics":
            data = await read.diagnostics(db, source_id=p.get("source_id", "").lower(), q=filters.q)
            conditions = [{"label": "Поиск", "text": filters.q}] if filters.q else []
            if p.get("source_id") and data["items"]:
                conditions.append({"label": "Источник KSC", "text": data["items"][0]["source_name"]})
            return {"title": "Диагностика защиты сотрудников", "data_at": data["built_at"], "conditions": conditions,
                    "metrics": [metric("sources", "Источники", data["total"])], "notes": data["warnings"],
                    "tables": [_table("rows", "Источники KSC", DIAGNOSTICS, data["items"])], "severity": None}
        generation, meta = await read.snapshot(db)
        if generation is None:
            raise KscError("no_data", "Для формирования отчёта нужен готовый срез защиты сотрудников")
        selection = read.Selection(generation, filters, workplaces=workplaces, pairs=p.get("pairs") or [])
        n = await read.workplace_count(db, selection) if workplaces else await read.count(db, selection, view)
        if n > ctx.max_rows and not ctx.light and p.get("detail") != "summary":
            raise KscError("params", f"В выборке {n} строк. Уточните фильтры до {ctx.max_rows} строк или выберите краткий отчёт")
        summary = None if workplaces else await read.summary(db, filters, prepared=(generation, meta))
        rows = []
        if p.get("detail") != "summary":
            for offset in range(0, min(n, 20) if ctx.light else n, 500):
                if ctx.cancelled():
                    raise KscError("cancelled", "Формирование отчёта отменено")
                limit = 20 if ctx.light else 500
                if workplaces:
                    rows.extend(map(_workplace_export, await read.workplace_rows(db, selection, offset, limit)))
                else:
                    rows.extend(_export(row, view == "devices") for row in await read.rows(db, selection, view, offset, limit))
                if not ctx.light:
                    await RES.breathe("отчёт защиты сотрудников")
    conditions = [{"label": "Срез аналитики", "text": meta["built_at"]}, {"label": "Список сотрудников по аудиту AD", "text": meta["census_at"]}]
    names = {"q": "Поиск", "organization": "Организация", "department": "Департамент", "division": "Подразделение",
             "zone": "Зона", "kind": "Тип оборудования", "ownership": "Тип собственности", "assignment": "Закрепление сотрудника", "os": "ОС", "status": "Состояние сотрудников",
             "device_status": "Состояние устройств", "freshness": "Актуальность", "employee_id": "Сотрудник", "device_id": "Устройство", "metric": "Показатель",
             "confidence": "Оценка связи", "asset_id": "Карточка учёта"}
    values = {"ownership": read.OWNERSHIP, "assignment": read.ASSIGNMENT, "status": classify.EMPLOYEE_LABELS, "device_status": classify.DEVICE_LABELS,
              "freshness": read.FRESHNESS, "metric": METRICS, "confidence": read.CONFIDENCE}
    conditions += [{"label": label, "text": values.get(k, {}).get(p[k], "Не указано" if p[k] == read.EMPTY else str(p[k]))} for k, label in names.items() if p.get(k)]
    if workplaces:
        if filters.inventory:
            conditions.append({"label": "Оборудование", "text": "С действующей карточкой учёта"})
        if p.get("pairs"):
            conditions.append({"label": "Отбор", "text": "Выбранные связи"})
        return {"title": "Рабочие места сотрудников", "conditions": conditions, "data_at": meta["built_at"],
                "metrics": [metric("workplaces", "Связи", n)], "notes": meta["warnings"],
                "tables": [_table("rows", "Рабочие места", WORKPLACES, rows)], "severity": None,
                **({"selection_total": n} if ctx.light and p.get("detail") != "summary" else {})}
    totals = summary["totals"]
    metrics = [metric(k, title, totals[k]) for k, title in METRICS.items()]
    if totals["employees"]:
        for key in ("uses_av", "protected"):
            if totals[key] or totals["insufficient"] < totals["employees"]:
                metrics.append(metric(f"{key}_pct", f"{METRICS[key]}, %", round(totals[key] * 100 / totals["employees"], 1)))
    group_cols = [col("label", "Департамент"), col("total", "Сотрудники", "num")]
    group_cols += [col(k, METRICS[k], "num") for k in ("uses_av", "protected", "partial", "no_av", "insufficient")]
    os_cols = [col("label", "ОС"), col("total", "Устройства", "num"), col("protected", "Защищены", "num"),
               col("problems", "Проблемы", "num"), col("no_av", "Подтверждено отсутствие", "num")]
    tables = [_table("rows", "Устройства сотрудников" if view == "devices" else "Сотрудники", DEVICES if view == "devices" else PEOPLE, rows),
              _table("statuses", "По состоянию защиты", [col("label", "Состояние"), col("count", "Сотрудники", "num")], summary["statuses"]),
              _table("departments", "По департаментам", group_cols, summary["by_department"]),
              _table("systems", "По операционным системам", os_cols, summary["by_os"])]
    return {"title": TITLE, "subtitle": "Подготовленные данные KAV Checker", "conditions": conditions, "metrics": metrics, "data_at": meta["built_at"],
            "notes": ["Список сотрудников сформирован по успешной проверке AD в пределах её области. На сотрудника влияют все его известные устройства.",
                      "Установка и работоспособность антивируса оцениваются отдельно. Отсутствие связи с записью KSC требует проверки.",
                      *meta["warnings"]], "tables": tables, "severity": None,
            **({"selection_total": n} if ctx.light and p.get("detail") != "summary" else {})}
