"""Сводка и детализация защиты сотрудников по серверному отбору дашборда."""
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
           col("kind", "Тип"), col("ownership", "Принадлежность"), col("zones_text", "Зоны ответственности"),
           col("os", "ОС"), col("os_version", "Версия ОС"), col("av_product", "Защитный продукт"), col("av_version", "Версия продукта"),
           col("installed", "Установка подтверждена"), col("status", "Состояние защиты"), col("reason", "Основание"),
           col("freshness", "Актуальность"), col("last_connected", "Последнее подключение", "date")]
METRICS = {"employees": "Сотрудники", "uses_av": "С установленным антивирусом", "protected": "Полностью защищены",
           "partial": "Частично защищены", "no_av": "Подтверждено отсутствие", "insufficient": "Недостаточно данных",
           "devices": "Известные устройства", "corporate": "Корпоративные", "personal": "Личные"}


def _export(row, devices):
    out = {**row, "status": (classify.DEVICE_LABELS if devices else classify.EMPLOYEE_LABELS)[row["status"]],
           "reason": classify.REASON_LABELS[row["reason"]], "freshness": read.FRESHNESS[row["freshness"]]}
    if devices:
        out.update(users=", ".join(p["name"] for p in row["employees"]),
                   evidence=" / ".join(f"{p['name']}: {', '.join(p['evidence'])}" for p in row["employees"]),
                   zones_text=", ".join(z["name"] for z in row["zones"]),
                   ownership=read.OWNERSHIP.get(row["ownership"], read.OWNERSHIP["unknown"]),
                   installed={True: "Да", False: "Нет", None: "Недостаточно данных"}[row["installed"]])
    return out


def _table(id, title, columns, rows):
    return {"id": id, "title": title, "columns": columns, "rows": rows}


async def build_employee_protection(_client, p: dict, ctx: Ctx) -> dict:
    view = p.get("view", "employees")
    filters = Filters.model_validate(p)
    async with ctx.sm() as db:
        generation, meta = await read.snapshot(db)
        if generation is None:
            raise KscError("no_data", "Для формирования отчёта нужен готовый срез защиты сотрудников")
        selection = read.Selection(generation, filters)
        n = await read.count(db, selection, view)
        if n > ctx.max_rows and not ctx.light and p.get("detail") != "summary":
            raise KscError("params", f"В выборке {n} строк. Уточните фильтры до {ctx.max_rows} строк или выберите краткий отчёт")
        summary = await read.summary(db, filters, prepared=(generation, meta))
        rows = []
        if p.get("detail") != "summary":
            for offset in range(0, min(n, 20) if ctx.light else n, 500):
                if ctx.cancelled():
                    raise KscError("cancelled", "Формирование отчёта отменено")
                rows.extend(_export(row, view == "devices") for row in await read.rows(db, selection, view, offset, 20 if ctx.light else 500))
                if not ctx.light:
                    await RES.breathe("отчёт защиты сотрудников")
    conditions = [{"label": "Срез аналитики", "text": meta["built_at"]}, {"label": "Список сотрудников по аудиту AD", "text": meta["census_at"]}]
    names = {"q": "Поиск", "organization": "Организация", "department": "Департамент", "division": "Подразделение",
             "zone": "Зона", "kind": "Тип оборудования", "ownership": "Принадлежность", "os": "ОС", "status": "Состояние сотрудников",
             "device_status": "Состояние устройств", "freshness": "Актуальность", "employee_id": "Сотрудник", "device_id": "Устройство", "metric": "Показатель"}
    values = {"ownership": read.OWNERSHIP, "status": classify.EMPLOYEE_LABELS, "device_status": classify.DEVICE_LABELS,
              "freshness": read.FRESHNESS, "metric": METRICS}
    conditions += [{"label": label, "text": values.get(k, {}).get(p[k], "Не указано" if p[k] == read.EMPTY else p[k])} for k, label in names.items() if p.get(k)]
    totals = summary["totals"]
    metrics = [metric(k, title, totals[k]) for k, title in METRICS.items()]
    if totals["employees"]:
        for key in ("uses_av", "protected"):
            metrics.append(metric(f"{key}_pct", f"{METRICS[key]}, %", round(totals[key] * 100 / totals["employees"], 1)))
    group_cols = [col("label", "Департамент"), col("total", "Сотрудники", "num")]
    group_cols += [col(k, METRICS[k], "num") for k in ("uses_av", "protected", "partial", "no_av", "insufficient")]
    os_cols = [col("label", "ОС"), col("total", "Устройства", "num"), col("protected", "Защищены", "num"),
               col("problems", "Проблемы", "num"), col("no_av", "Подтверждено отсутствие", "num")]
    tables = [_table("rows", "Устройства сотрудников" if view == "devices" else "Сотрудники", DEVICES if view == "devices" else PEOPLE, rows),
              _table("departments", "По департаментам", group_cols, summary["by_department"]),
              _table("systems", "По операционным системам", os_cols, summary["by_os"])]
    return {"title": TITLE, "subtitle": "Подготовленные данные KAV Checker", "conditions": conditions, "metrics": metrics,
            "notes": ["Список сотрудников сформирован по успешной проверке AD в пределах её области. На сотрудника влияют все его известные устройства.",
                      "Установка и работоспособность антивируса оцениваются отдельно. Отсутствие связи с записью KSC требует проверки.",
                      *meta["warnings"]], "tables": tables, "severity": None,
            **({"selection_total": n} if ctx.light and p.get("detail") != "summary" else {})}
