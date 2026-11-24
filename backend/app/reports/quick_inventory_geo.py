"""Детализация сетевых наблюдений и правил для отчётов инвентаризации."""
from __future__ import annotations

from sqlalchemy import select

from ..inventory import geography as G
from ..models import InvLocation
from .quick import col

ADDRESS_KIND = {"reported": "Сводный IP KSC", "device": "IP, сообщённый устройством", "discovered": "IP сетевого опроса", "connection": "IP подключения агента"}
ADDRESS_SCOPE = {"public": "Публичный", "private": "Частный", "shared": "Общий диапазон операторов (CGNAT)", "special": "Служебный",
                 "missing": "Адрес отсутствует", "ambiguous": "Несколько адресов подключения"}
RULE_LABELS = {"name": "Правило", "enabled": "Включено", "priority": "Приоритет", "networks": "Адреса и сети", "ip_kind": "Вид адреса",
               "source_id": "Источник KSC", "type_id": "Тип оборудования", "infra_source_id": "Источник инфраструктуры", "infra_site": "Площадка инфраструктуры",
               "host": "Имя компьютера", "group": "Группа KSC", "domain": "Домен", "network_location": "Сетевое местоположение KSC", "network_id": "Идентификатор сети KSC",
               "vpn": "VPN или прокси", "site_id": "Сетевая площадка", "location_id": "Учётное местоположение", "branch_id": "Филиал", "dept_id": "Подразделение",
               "resp_id": "Ответственный", "zone_id": "Зона ответственности"}


def table(key, title, labels, rows):
    return {"id": key, "title": title, "columns": [col(k, label, *kind) for k, label, *kind in labels], "rows": rows}


async def rules_table(db, rules=None):
    rules = sorted(await G.rules_for(db) if rules is None else rules, key=lambda row: (row.rule.priority, row.rule.name.casefold(), row.id))
    names = {}
    for model in set(G.RULE_REFS.values()):
        ids = {getattr(row.rule, key) for row in rules for key, target in G.RULE_REFS.items() if target is model} - {None}
        label = model.path if model is InvLocation else model.name
        names[model] = dict((await db.execute(select(model.id, label).where(model.id.in_(ids)))).all()) if ids else {}
    rows = []
    for item in rules:
        rule = item.rule
        row = rule.model_dump()
        for key, model in G.RULE_REFS.items():
            row[key] = names[model].get(row[key], str(row[key]) if row[key] is not None else "")
        row.update(enabled="Да" if rule.enabled else "Нет", vpn="Да" if rule.vpn else "Нет", networks=", ".join(rule.networks),
                   ip_kind={"any": "Устройство и подключение", "connection": "Подключение агента", "device": "Устройство"}[rule.ip_kind])
        rows.append(row)
    return table("rows", "Правила принадлежности", [(key, label, "num" if key == "priority" else "text") for key, label in RULE_LABELS.items()], rows)


async def observation_tables(db, asset, observation):
    evidence = observation.evidence
    facts = (("group", "Группа KSC"), ("domain", "Домен или рабочая группа"), ("inventory_location", "Местоположение из KSC"),
             ("network_location", "Сетевое местоположение"), ("network_id", "Идентификатор сети"), ("last_info_update", "Обновление сведений (UTC)"))
    addresses = []
    for item in evidence.get("addresses", []):
        addresses.append({**item, "kind": ADDRESS_KIND.get(item.get("kind"), item.get("kind")), "scope": ADDRESS_SCOPE.get(G.address_scope(item["ip"]), "")})
    proposals = await G.proposal_fields(db, asset, observation.result.get("proposals", {}))
    return [section for section in (
        table("network_details", "Сетевые сведения", [("label", "Сведение"), ("value", "Значение")],
              [{"label": label, "value": evidence[key]} for key, label in facts if evidence.get(key)]),
        table("addresses", "Адреса", [("ip", "IP"), ("kind", "Вид"), ("scope", "Область"), ("source", "Источник"), ("observed_at", "Наблюдение (UTC)", "date")], addresses),
        table("interfaces", "Сетевые интерфейсы", [("name", "Имя"), ("mac", "MAC"), ("type", "Тип")], evidence.get("interfaces", [])),
        table("infra", "Связанные наблюдения инфраструктуры", [("source", "Источник"), ("site", "Площадка"), ("at", "Наблюдение (UTC)", "date")], evidence.get("infra", [])),
        table("proposals", "Предлагаемые учётные значения", [("label", "Поле"), ("value", "Предложение"), ("state", "Состояние поля")],
              [{**field, "state": "Пустое" if field["empty"] else "Заполнено"} for field in proposals.values()]),
    ) if section["rows"]]
