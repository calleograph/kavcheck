"""Показатели главной страницы по записям защиты источника (те же записи, что у раздела «Состояние защиты»): активность за 7/30/60/90 суток, серверы и рабочие станции, защита.

Методика (описана и в интерфейсе, docs/DASHBOARD.md):
* **Активный компьютер** — Агент администрирования подключался к Серверу администрирования за последние N суток (`tmLastNagentConnected`). Это единственный признак активности;
  остальные признаки считаются отдельно и не подменяют его: «виден в сети» (`tmLastVisible`), «Агент установлен» (есть Агент в списке продуктов), «защитный продукт установлен»,
  «защита работает» (постоянная защита и состояние продукта), «лицензия истекла по статусу KSC».
* **Сервер / рабочая станция** — по названию ОС (Windows Server, …Server, «Сервер» — сервер; остальные Windows и macOS — станция). Linux в KSC приходит как «Linux» без редакции: такие
  компьютеры считаются отдельно («тип не определён»), а не относятся к серверам или станциям наугад.
* **Связь и защита — независимые признаки.** «Нет связи» — активные за период компьютеры, которых KSC сейчас не видит; сам по себе этот признак не означает, что защита остановлена.
  «Защита не работает» — KSC сообщает остановку (приостановка/сбой — всегда; «остановлена/не запущен/завершает работу» — только у компьютера на связи, иначе это след выключения).
  Если последний отчёт похож на остановку, а компьютер не на связи, — «Состояние неизвестно». «Устаревшие базы» считаются по фактической дате баз независимо от связи.
  «Без защиты» — KSC сообщает отсутствие антивируса либо Агент передавал сведения, а защитного продукта среди них нет.
* Показатели защиты считаются среди активных компьютеров; «давно не поступали сведения» — активные, у которых KSC не обновлял сведения об устройстве дольше `STALE_DAYS`.
Один предикат на показатель используется и для числа, и для списка (боковая панель), поэтому они всегда совпадают."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from ..ksc import protection as P

PERIODS = (7, 30, 60, 90)
STALE_DAYS = 7
BASES_DAYS = 3
_SERVER = re.compile(r"server|сервер", re.I)
_DESKTOP = re.compile(r"windows|macos|mac os|os x|desktop|workstation|рабоч", re.I)


def kind_of(r: dict) -> str:
    """server | workstation | other (тип не определён: например, «Linux» без редакции)."""
    os_name = r.get("os") or ""
    if _SERVER.search(os_name):
        return "server"
    if r.get("platform") == "Linux" or (not os_name):
        return "other"
    return "workstation" if _DESKTOP.search(os_name) or r.get("platform") == "Windows" else "other"


def is_active(r: dict, days: int) -> bool:
    d = r.get("days_since_connection")
    return d is not None and d <= days


def _av_ok(r: dict) -> bool:
    return bool(r.get("av")) and not (r["mask"] & 32)


def bases_old(r: dict, now: datetime) -> bool:
    av = r.get("av")
    return bool(av) and (not av.get("bases") or now - av["bases"] > timedelta(days=BASES_DAYS))


def info_stale(r: dict, now: datetime) -> bool:
    li = r.get("last_info_update")
    return li is None or now - li > timedelta(days=STALE_DAYS)


# ключ → (подпись, предикат(r, days, now)); «all» — все записи источника, остальные — среди активных
METRICS: dict[str, tuple[str, object]] = {
    "total": ("Всего объектов в KSC", lambda r, d, n: True),
    "active": ("Активные компьютеры", lambda r, d, n: is_active(r, d)),
    "inactive": ("Неактивные компьютеры", lambda r, d, n: not is_active(r, d)),
    "never": ("Агент ни разу не подключался", lambda r, d, n: r.get("last_connected") is None),
    "servers": ("Активные серверы", lambda r, d, n: is_active(r, d) and kind_of(r) == "server"),
    "workstations": ("Активные рабочие станции", lambda r, d, n: is_active(r, d) and kind_of(r) == "workstation"),
    "other_os": ("Активные, тип ОС не определён", lambda r, d, n: is_active(r, d) and kind_of(r) == "other"),
    "av_installed": ("С установленной защитой", lambda r, d, n: is_active(r, d) and _av_ok(r)),
    "no_av": ("Без защиты", lambda r, d, n: is_active(r, d) and P.no_av(r)),
    "rtp_off": ("Защита не работает", lambda r, d, n: is_active(r, d) and _av_ok(r) and P.rtp_off(r, n)),
    "offline": ("Нет связи", lambda r, d, n: is_active(r, d) and not P.connected(r, n)),
    "unknown": ("Состояние неизвестно", lambda r, d, n: is_active(r, d) and _av_ok(r) and P.state_unknown(r, n)),
    "bases_old": ("С устаревшими базами", lambda r, d, n: is_active(r, d) and _av_ok(r) and bases_old(r, n)),
    "stale_info": ("Сведения давно не поступали", lambda r, d, n: is_active(r, d) and info_stale(r, n)),
    "protected": ("Защищены", lambda r, d, n: is_active(r, d) and _av_ok(r) and not P.rtp_off(r, n) and not P.state_unknown(r, n) and not bases_old(r, n)),
    "license_expired": ("Лицензия истекла (статус KSC)", lambda r, d, n: is_active(r, d) and bool(r["mask"] & 512)),
}


def pick(records: list[dict], metric: str, days: int, now: datetime | None = None) -> list[dict]:
    pred = METRICS[metric][1]
    n = now or datetime.now(timezone.utc)
    return [r for r in records if pred(r, days, n)]


def summarize(records: list[dict], days: int, now: datetime | None = None) -> dict:
    """Все счётчики источника за период `days` и сравнение признаков для каждого из периодов (раздельные характеристики)."""
    n = now or datetime.now(timezone.utc)
    out = {k: sum(1 for r in records if pred(r, days, n)) for k, (_t, pred) in METRICS.items()}
    periods = []
    for d in PERIODS:
        act = [r for r in records if is_active(r, d)]
        periods.append({"days": d, "connected": len(act), "visible": sum(1 for r in records if r.get("last_visible") and (n - r["last_visible"]).days <= d),
                        "av_installed": sum(1 for r in act if _av_ok(r)), "av_running": sum(1 for r in act if _av_ok(r) and not P.rtp_off(r, n) and not P.state_unknown(r, n)),
                        "servers": sum(1 for r in act if kind_of(r) == "server"), "workstations": sum(1 for r in act if kind_of(r) == "workstation")})
    out["periods"] = periods
    out["agent_installed"] = sum(1 for r in records if r.get("agent_build"))
    out["av_any"] = sum(1 for r in records if _av_ok(r))
    return out


def sort_key(sort: str):
    floor = datetime.min.replace(tzinfo=timezone.utc)
    return {"name": lambda r: (r.get("name") or "").lower(), "last_connected": lambda r: r.get("last_connected") or floor, "os": lambda r: (r.get("os") or "").lower(),
            "ip": lambda r: tuple(int(x) for x in re.findall(r"\d+", r.get("ip") or "")) or (0,), "group": lambda r: (r.get("group") or "").lower()}[sort]
