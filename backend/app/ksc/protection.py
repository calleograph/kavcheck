"""Состояние защиты: защитный продукт Kaspersky, постоянная защита, базы, полная проверка, лицензия и статус KSC по каждому компьютеру.

Читаются две небольшие таблицы (компьютеры со статусом и продукты Kaspersky); проверки с порогами пользователя считаются в приложении по
кэшированному набору, поэтому смена порога или фильтра не нагружает SQL Server. Перечисления — docs/ksc/PROTECTION.md."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import cmp_to_key

from ..search import any_field, matcher
from . import hosts as H
from . import queries as q
from .driver import SourceClient
from .versions import compare_numeric

STATUS_MASK = {1: "Агент в сети, но неактивен", 2: "постоянная защита не запущена", 4: "антивирус не запущен", 8: "слишком много вирусов", 16: "состояние постоянной защиты не соответствует заданному",
               32: "антивирус не установлен", 64: "полная проверка давно не выполнялась", 128: "базы давно не обновлялись", 256: "Агент неактивен слишком долго", 512: "лицензия истекла",
               1024: "много невылеченных объектов", 2048: "требуется перезагрузка", 4096: "несовместимые программы", 8192: "есть неустранённая уязвимость",
               16384: "поиск обновлений Windows давно не запускался", 32768: "шифрование не соответствует требованиям", 131072: "есть необработанный инцидент", 524288: "мало места на диске"}
KSC_STATUS = {0: "OK", 1: "критический", 2: "предупреждение"}
RTP = {0: "неизвестно", 1: "остановлена", 2: "приостановлена", 3: "запускается", 4: "выполняется", 5: "максимальная защита", 6: "максимальная скорость", 7: "рекомендуемые параметры", 8: "пользовательские параметры", 9: "сбой"}
PRODUCT_STATE = {0: "не запущен", 1: "только что запущен", 2: "инициализация", 3: "запущен", 4: "приостановлен", 5: "деинициализация", 6: "критическая ошибка", 7: "завершает работу", 8: "удаляется"}
RTP_BAD = {1, 2, 9}
STATE_BAD = {0, 4, 6, 7, 8}
# Выключенный компьютер последним отчётом сообщает «остановлена / не запущен / завершает работу»: это следствие выключения, а не отказ защиты.
# Приостановка и сбой (RTP 2, 9; продукт 4, 6) сохраняются и без связи — их «жёсткие» признаки. Остальные признаки учитываются только пока компьютер на связи.
RTP_HARD = {2, 9}
STATE_HARD = {4, 6}
CONNECTED_WITHIN = timedelta(minutes=30)          # запасной признак «на связи», если KSC не передаёт флаг «видимо»: Агент синхронизируется раз в 15 мин по умолчанию
AGENT = "1103"

# порядок — по важности для специалиста ИБ: сначала то, что означает отсутствие защиты
PROBLEMS = {
    "no_av": ("Нет антивируса", "нет продукта Kaspersky или KSC не получал о нём сведений"),
    "rtp_off": ("Защита не работает", "постоянная защита остановлена, в сбое или антивирус не запущен"),
    "infected": ("Невылеченные объекты", "объекты не удалось вылечить или удалить"),
    "bases_old": ("Устаревшие базы", "антивирусные базы старше выбранного порога"),
    "license": ("Лицензия истекла", "по статусу KSC"),
    "scan_old": ("Нет свежей полной проверки", "полная проверка не выполнялась дольше выбранного порога"),
    "reboot": ("Требуется перезагрузка", "по статусу KSC"),
    "hw_cpu": ("Недостаточно ядер CPU", "Linux-сервер: мало ядер процессора (по оборудованию из KSC, пороги — в настройках)"),
    "hw_ram": ("Недостаточно ОЗУ", "Linux-сервер: мало оперативной памяти (по оборудованию из KSC, порог — в настройках)"),
}


_utc = H._utc


def _primary_av(products: list[dict]) -> dict | None:
    """Основной защитный продукт: обеспечивающий постоянную защиту, затем с самыми свежими базами."""
    av = [p for p in products if p.get("is_av")]
    if not av:
        return None
    floor = datetime.min.replace(tzinfo=timezone.utc)
    return max(av, key=lambda p: (bool(p.get("has_rtp")), _utc(p.get("bases")) or floor))


def record(h: dict, products: list[dict], groups: dict | None, now: datetime) -> dict:
    """Компьютер с полями защиты (без порогов: их применяет problems)."""
    row = H.host_row(h, groups, now)
    av = _primary_av(products)
    agent = next((p for p in products if p.get("code") == AGENT), None)
    return {**{k: row[k] for k in ("host_id", "name", "fqdn", "ip", "os", "os_version", "platform", "group", "last_connected", "last_visible", "last_info_update", "days_since_connection",
                                   "activity", "last_full_scan", "is_slave", "online")},
            "av": {"code": av.get("code") or "", "product": av.get("name") or av.get("code") or "", "build": av.get("build") or "", "state": av.get("state"),
                   "state_label": PRODUCT_STATE.get(av.get("state"), "") if av.get("state") is not None else "", "bases": _utc(av.get("bases")), "has_rtp": bool(av.get("has_rtp"))} if av else None,
            "agent_build": (agent or {}).get("build") or "", "rtp_state": h.get("rtp_state"), "rtp_label": RTP.get(h.get("rtp_state"), "") if h.get("rtp_state") is not None else "",
            "ksc_status": KSC_STATUS.get(h.get("ksc_status")) if h.get("ksc_status") is not None else None, "mask": int(h.get("status_mask") or 0),
            "uncured": int(h.get("uncured") or 0)}


def connected(r: dict, now: datetime) -> bool:
    """Компьютер на связи сейчас. Связь и состояние антивируса — независимые признаки: по первому нельзя судить о втором.
    Основа — флаг KSC «видимо» (`online`); нет флага — подключение Агента не старше CONNECTED_WITHIN."""
    if r.get("online") is not None:
        return bool(r["online"])
    last = _utc(r.get("last_connected"))
    return last is not None and now - last <= CONNECTED_WITHIN


def stop_signal(r: dict) -> str:
    """Что сообщает KSC о постоянной защите: "hard" (приостановлена, сбой), "soft" (остановлена, не запущен, завершает работу — как при выключении) или "" (нет признаков)."""
    av = r.get("av")
    if not av:
        return ""
    if r.get("rtp_state") in RTP_HARD or av.get("state") in STATE_HARD:
        return "hard"
    return "soft" if r.get("rtp_state") in RTP_BAD or av.get("state") in STATE_BAD or r["mask"] & (2 | 4) else ""


def rtp_off(r: dict, now: datetime) -> bool:
    """«Защита не работает»: KSC сообщает остановку, и этому можно верить — сбой/приостановка в любом случае, остальное — только у компьютера на связи."""
    sig = stop_signal(r)
    return sig == "hard" or (sig == "soft" and connected(r, now))


def state_unknown(r: dict, now: datetime) -> bool:
    """«Состояние неизвестно»: последний отчёт похож на остановку, но компьютер не на связи, а отличить отказ от выключения нельзя."""
    return stop_signal(r) == "soft" and not connected(r, now)


def no_av(r: dict) -> bool:
    """«Без защиты» — KSC сообщает «антивирус не установлен» либо Агент уже передавал сведения, а защитного продукта среди них нет (устройство без подключений Агента — нет данных, не «без защиты»)."""
    return bool(r["mask"] & 32) or (not r["av"] and r.get("last_connected") is not None)


def problems(r: dict, now: datetime, *, bases_days: int, scan_days: int) -> list[str]:
    out, av, mask = [], r["av"], r["mask"]
    if no_av(r):
        out.append("no_av")
    if av:
        if rtp_off(r, now):
            out.append("rtp_off")
        if not av["bases"] or now - av["bases"] > timedelta(days=bases_days):
            out.append("bases_old")
    if r["uncured"] or mask & (8 | 1024):
        out.append("infected")
    if mask & 512:
        out.append("license")
    if av and (not r["last_full_scan"] or now - r["last_full_scan"] > timedelta(days=scan_days)):
        out.append("scan_old")
    if mask & 2048:
        out.append("reboot")
    out += [p["key"] for p in ((r.get("hw") or {}).get("problems") or [])]          # аппаратные ресурсы Linux-серверов: отдельная проблема, не связанная с уязвимостями
    return sorted(set(out), key=list(PROBLEMS).index)


def _by_version(counter: Counter) -> list[dict]:
    items = [{"build": b, "hosts": n} for b, n in counter.items()]
    items.sort(key=cmp_to_key(lambda a, b: compare_numeric(b["build"] or "0", a["build"] or "0")))
    return items


def versions(records: list[dict]) -> list[dict]:
    """Спектр версий защитных продуктов и Агента: сколько компьютеров на каждой сборке, первой — самая новая."""
    av: dict[str, tuple[str, Counter]] = {}
    agent: Counter = Counter()
    for r in records:
        if r["av"]:
            name, c = av.setdefault(r["av"]["code"], (r["av"]["product"], Counter()))
            c[r["av"]["build"]] += 1
        if r["agent_build"]:
            agent[r["agent_build"]] += 1
    out = [{"code": code, "product": name, "hosts": sum(c.values()), "versions": _by_version(c)} for code, (name, c) in av.items()]
    out.sort(key=lambda x: -x["hosts"])
    if agent:
        out.append({"code": AGENT, "product": "Агент администрирования", "hosts": sum(agent.values()), "versions": _by_version(agent)})
    for p in out:
        p["latest"] = p["versions"][0]["build"] if p["versions"] else ""
        p["on_latest"] = p["versions"][0]["hosts"] if p["versions"] else 0
    return out


async def load(client: SourceClient, *, exclude_slaves: bool, groups: dict | None, hw_cfg=None) -> list[dict]:
    hosts = await client.run(q.PROTECTION_HOSTS.format(where="h.bIsSlaveServer = 0" if exclude_slaves else "1 = 1"), max_rows=500_000)
    by_host: dict[int, list[dict]] = {}
    for p in await client.run(q.PROTECTION_PRODUCTS, max_rows=2_000_000):
        by_host.setdefault(int(p["host_id"]), []).append(p)
    now = datetime.now(timezone.utc)
    recs = [record(h, by_host.get(int(h["host_id"]), []), groups, now) for h in hosts]
    if hw_cfg is not None and hw_cfg.enabled:                      # оборудование Linux-серверов одним запросом; нет объектов или данных — оценка не выполняется
        from . import hardware as HW  # noqa: PLC0415

        try:
            HW.attach(recs, await HW.load_linux(client), hw_cfg)
        except Exception:  # noqa: BLE001 — старый KSC без таблицы оборудования: защита показывается без оценки ресурсов
            pass
    return recs


def scope(base: list[dict], *, now: datetime, activity_days: int, include_inactive: bool, online_only: bool, bases_days: int, scan_days: int) -> tuple[list[dict], dict]:
    """Компьютеры в области отчёта: активность (связывались с KSC за N суток) и, отдельно, «в сети сейчас» (флаг KSC «видимо»); проблемы по порогам.
    Возвращает (компьютеры с problems, счётчики: hidden — без связи, offline — не в сети, online_data — передаёт ли KSC статус сети)."""
    online_data = any(r.get("online") is not None for r in base)
    out, hidden, offline = [], 0, 0
    for r in base:
        if not include_inactive and (r["days_since_connection"] is None or r["days_since_connection"] > activity_days):
            hidden += 1
            continue
        if online_only and online_data and r.get("online") is not True:
            offline += 1
            continue
        out.append({**r, "problems": problems(r, now, bases_days=bases_days, scan_days=scan_days), "state_unknown": state_unknown(r, now)})
    return out, {"hidden": hidden, "offline": offline, "online_data": online_data, "online_only": bool(online_only and online_data)}


def pick(hosts: list[dict], *, problem: str = "", product: str = "", build: str = "", q: str = "", group: str = "", host_ids: list[int] | None = None, hw_level: str = "") -> list[dict]:
    """Отбор компьютеров по категории проблемы, версии продукта, тексту, группе и выбранным строкам (одинаково для страницы и отчёта)."""
    items = hosts
    if host_ids:
        ids = set(host_ids)
        items = [h for h in items if h["host_id"] in ids]
    if problem == "ok":
        items = [h for h in items if not h["problems"]]
    elif problem == "hw":                                            # любая нехватка аппаратных ресурсов (Linux-серверы)
        items = [h for h in items if {"hw_cpu", "hw_ram"} & set(h["problems"])]
    elif problem:
        items = [h for h in items if problem in h["problems"]]
    if hw_level:                                                     # критичность проблемы ресурсов: critical — недостаточно ядер CPU; warning — остальное
        items = [h for h in items if any(x["level"] == hw_level for x in ((h.get("hw") or {}).get("problems") or []))]
    if product:
        def ver(h: dict) -> str | None:
            av = h["av"] or {}
            return h["agent_build"] if product == AGENT else av.get("build") if av.get("code") == product else None
        items = [h for h in items if ver(h) and (not build or ver(h) == build)]
    if (f := any_field(q)):
        items = [h for h in items if f(h["name"], h["fqdn"], h["ip"])]
    if (g := matcher(group)):
        items = [h for h in items if g(h["group"])]
    return items


def host_protection(h: dict, products: list[dict], status: dict | None, now: datetime, *, bases_days: int = 3, scan_days: int = 30) -> dict:
    """Проблемы защиты одного компьютера (карточка): те же правила, что и в разделе «Состояние защиты»."""
    raw = {**h, "ksc_status": (status or {}).get("status"), "status_mask": (status or {}).get("mask")}
    prods = [{"code": p.get("product_code"), "name": p.get("product"), "build": p.get("build"), "state": p.get("state"), "bases": p.get("av_bases_date"),
              "is_av": p.get("is_av"), "has_rtp": p.get("has_rtp")} for p in products]
    r = record(raw, prods, None, now)
    return {"problems": problems(r, now, bases_days=bases_days, scan_days=scan_days), "bases_days": bases_days, "scan_days": scan_days}
