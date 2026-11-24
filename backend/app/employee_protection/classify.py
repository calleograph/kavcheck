"""Оценка защиты по последнему наблюдению KSC и сводка по известным устройствам сотрудника."""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta

from ..ksc import protection as P
from ..ksc.hosts import _utc

DEVICE_LABELS = {
    "protected": "Защита работает",
    "problems": "Проблемы защиты",
    "no_av": "KSC сообщает об отсутствии антивируса",
    "outside_ksc": "Нет связи с записью KSC",
    "stale": "Сведения устарели",
    "unknown": "Требует проверки",
}
EMPLOYEE_LABELS = {
    "protected": "Все известные устройства защищены",
    "partial": "Защищена часть известных устройств",
    "problems": "Установлен антивирус с проблемами защиты",
    "no_av": "KSC сообщает об отсутствии антивируса на всех известных устройствах",
    "outside_ksc": "Известные устройства не связаны с KSC",
    "stale": "Сведения об оборудовании устарели",
    "no_devices": "Оборудование не определено",
    "unknown": "Недостаточно данных о защите",
}
REASON_LABELS = {
    "running": "KSC сообщает о работающих антивирусе и постоянной защите. Базы актуальны",
    "rtp_off": "KSC сообщает об остановке, приостановке или сбое постоянной защиты",
    "rtp_policy": "Постоянная защита не соответствует настройкам KSC",
    "license": "По данным KSC срок действия лицензии истёк",
    "infected": "KSC сообщает о превышении порога обнаружений или невылеченных объектах",
    "bases_old": "Антивирусные базы старше порога или KSC сообщает о нарушении срока обновления",
    "reboot": "KSC сообщает о необходимости перезагрузки",
    "no_av_reported": "KSC явно сообщает, что управляемый антивирус не установлен",
    "not_in_ksc": "Существующую запись KSC не удалось связать с этим устройством",
    "ksc_data_missing": "Устройство связано с KSC. Готовые сведения о защите пока отсутствуют",
    "no_contact": "Дата последнего подключения Агента KSC неизвестна или некорректна",
    "old_contact": "Последнее подключение Агента KSC старше порога актуальности",
    "old_snapshot": "Снимок состояния из KSC старше порога актуальности",
    "conflicting_product": "KSC сообщает об отсутствии антивируса и одновременно передаёт сведения о защитном продукте",
    "av_unknown": "KSC не передал сведения о защитном продукте и явный признак его отсутствия",
    "offline_stop": "Компьютер не на связи. Признак остановки может быть связан с выключением",
    "rtp_unknown": "Установка подтверждена. Работу постоянной защиты требуется проверить",
    "bases_unknown": "Дата антивирусных баз неизвестна или некорректна",
    "all_protected": "Работа защиты подтверждена для каждого известного устройства",
    "some_protected": "Работа защиты подтверждена только для части известных устройств",
    "known_problems": "Минимум на одном устройстве подтверждены проблемы установленного антивируса",
    "all_no_av": "Для каждого известного устройства есть актуальный признак отсутствия управляемого антивируса в KSC",
    "all_outside_ksc": "Нет подтверждённой связи известных устройств с KSC",
    "some_stale": "По одному или нескольким устройствам сведения устарели",
    "no_devices": "Связь сотрудника с оборудованием не установлена",
    "insufficient_evidence": "Доступных наблюдений недостаточно для общего вывода о защите",
    "conflicting_device_records": "Записи об одном устройстве содержат противоречивые признаки",
}

RTP_ACTIVE = {4, 5, 6, 7, 8}


def _result(status: str, reason: str, installed: bool | None = None, freshness: str = "unknown") -> dict:
    return {"status": status, "reason": reason, "installed": installed, "freshness": freshness}


def device_status(record: dict | None, now: datetime, *, activity_days: int, bases_days: int = 3,
                  matched_ksc: bool = False, snapshot_at: datetime | None = None) -> dict:
    if record is None:
        return _result("unknown", "ksc_data_missing") if matched_ksc else _result("outside_ksc", "not_in_ksc")
    cutoff = now - timedelta(days=activity_days)
    if snapshot_at is not None and _utc(snapshot_at) < cutoff:
        return _result("stale", "old_snapshot", freshness="stale")
    contact = _utc(record.get("last_connected"))
    if contact is None or contact > now:
        return _result("unknown", "no_contact")
    if contact < cutoff:
        return _result("stale", "old_contact", freshness="stale")

    av, mask = record.get("av"), record.get("mask") or 0
    if mask & 32:
        if av:
            return _result("unknown", "conflicting_product", freshness="fresh")
        return _result("no_av", "no_av_reported", False, "fresh")
    if not av:
        return _result("unknown", "av_unknown", freshness="fresh")

    telemetry = {**record, "mask": mask}
    bases = _utc(av.get("bases"))
    for has_problem, reason in (
        (P.rtp_off(telemetry, now), "rtp_off"),
        (mask & 16, "rtp_policy"),
        (mask & 512, "license"),
        (record.get("uncured") or mask & (8 | 1024), "infected"),
        (mask & 128 or (bases is not None and now - bases > timedelta(days=bases_days)), "bases_old"),
        (mask & 2048, "reboot"),
    ):
        if has_problem:
            return _result("problems", reason, True, "fresh")
    if P.state_unknown(telemetry, now):
        return _result("unknown", "offline_stop", True, "fresh")
    if not av.get("has_rtp") or av.get("state") != 3 or record.get("rtp_state") not in RTP_ACTIVE:
        return _result("unknown", "rtp_unknown", True, "fresh")
    if bases is None or bases > now:
        return _result("unknown", "bases_unknown", True, "fresh")
    return _result("protected", "running", True, "fresh")


def employee_status(devices: Iterable[dict]) -> dict:
    keyed: dict = {}
    unkeyed = []
    for device in devices:
        key = device.get("key")
        if key is None:
            unkeyed.append(device)
            continue
        previous = keyed.setdefault(key, device)
        if any(previous[field] != device[field] for field in ("status", "installed", "freshness")):
            freshness = "stale" if "stale" in (previous["freshness"], device["freshness"]) else "unknown"
            keyed[key] = _result("unknown", "conflicting_device_records", freshness=freshness)

    unique = [*keyed.values(), *unkeyed]
    total = len(unique)
    installed = sum(device["installed"] is True for device in unique)
    protected = sum(device["status"] == "protected" for device in unique)
    statuses = {device["status"] for device in unique}
    ages = {device["freshness"] for device in unique}
    freshness = "stale" if "stale" in ages else "fresh" if ages == {"fresh"} else "unknown"
    if not total:
        status, reason = "no_devices", "no_devices"
    elif protected == total:
        status, reason = "protected", "all_protected"
    elif protected:
        status, reason = "partial", "some_protected"
    elif "problems" in statuses:
        status, reason = "problems", "known_problems"
    elif statuses == {"no_av"}:
        status, reason = "no_av", "all_no_av"
    elif statuses == {"outside_ksc"}:
        status, reason = "outside_ksc", "all_outside_ksc"
    elif "stale" in statuses:
        status, reason = "stale", "some_stale"
    else:
        status, reason = "unknown", "insufficient_evidence"
    return {"status": status, "reason": reason, "freshness": freshness, "uses_av": bool(installed),
            "device_count": total, "installed_devices": installed, "protected_devices": protected}
