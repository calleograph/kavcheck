"""Расписания рассылок: вычисление моментов запуска с учётом часового пояса и переводов часов, ключ периода для защиты от повторной отправки."""
from __future__ import annotations

import calendar
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

FREQ = ("daily", "weekly", "monthly")
FREQ_RU = {"daily": "ежедневно", "weekly": "еженедельно", "monthly": "ежемесячно"}
WEEKDAYS = ["понедельникам", "вторникам", "средам", "четвергам", "пятницам", "субботам", "воскресеньям"]


class ScheduleError(ValueError):
    pass


def tz_of(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        raise ScheduleError(f"Неизвестный часовой пояс «{name}» (пример: Europe/Moscow)") from None


def parse_time(v: str) -> time:
    try:
        h, m = v.split(":")
        return time(int(h), int(m))
    except (ValueError, AttributeError):
        raise ScheduleError("Время записывается как ЧЧ:ММ (пример: 08:00)") from None


def _local(d: date, t: time, tz: ZoneInfo) -> datetime:
    """Местное время → UTC. Несуществующее время (переход на летнее) сдвигается вперёд, неоднозначное (обратный переход) берётся первое."""
    naive = datetime.combine(d, t)
    aware = naive.replace(tzinfo=tz, fold=0)
    back = aware.astimezone(timezone.utc).astimezone(tz)
    if back.replace(tzinfo=None) != naive:                   # такого времени в этот день нет
        aware = (naive + timedelta(hours=1)).replace(tzinfo=tz, fold=0)
    return aware.astimezone(timezone.utc)


def occurrence_date(freq: str, weekday: int, monthday: int, day: date) -> bool:
    if freq == "daily":
        return True
    if freq == "weekly":
        return day.weekday() == weekday
    last = calendar.monthrange(day.year, day.month)[1]
    return day.day == min(monthday, last)                   # 31-е в коротком месяце — последний день


def next_after(freq: str, weekday: int, monthday: int, at_time: str, tz_name: str, after: datetime) -> datetime:
    """Ближайший запуск строго позже `after` (UTC)."""
    if freq not in FREQ:
        raise ScheduleError("Периодичность: ежедневно, еженедельно или ежемесячно")
    tz, t = tz_of(tz_name), parse_time(at_time)
    after = after.astimezone(timezone.utc) if after.tzinfo else after.replace(tzinfo=timezone.utc)
    day = after.astimezone(tz).date() - timedelta(days=1)
    for _ in range(400):
        day += timedelta(days=1)
        if occurrence_date(freq, weekday, monthday, day):
            at = _local(day, t, tz)
            if at > after:
                return at
    raise ScheduleError("Не удалось вычислить следующий запуск")


def period_key(freq: str, scheduled_utc: datetime, tz_name: str) -> str:
    """Ключ отчётного периода по запланированному (а не фактическому) времени: после простоя нагоняется ровно один период, повтор в том же периоде невозможен."""
    d = scheduled_utc.astimezone(tz_of(tz_name)).date()
    if freq == "daily":
        return d.isoformat()
    if freq == "weekly":
        y, w, _ = d.isocalendar()
        return f"{y}-W{w:02d}"
    return f"{d.year}-{d.month:02d}"


def due(freq: str, weekday: int, monthday: int, at_time: str, tz_name: str, next_run_at: datetime | None, now: datetime, created_at: datetime) -> tuple[datetime | None, datetime]:
    """(время запуска, которое пора выполнить, или None; следующий запуск после него). Если пропущено несколько запусков — выполняется последний, остальные пропускаются."""
    nxt = next_run_at or next_after(freq, weekday, monthday, at_time, tz_name, created_at)
    if nxt.tzinfo is None:
        nxt = nxt.replace(tzinfo=timezone.utc)
    if nxt > now:
        return None, nxt
    last = nxt
    cur = next_after(freq, weekday, monthday, at_time, tz_name, nxt)
    while cur <= now:
        last, cur = cur, next_after(freq, weekday, monthday, at_time, tz_name, cur)
    return last, cur


def describe(freq: str, weekday: int, monthday: int, at_time: str, tz_name: str) -> str:
    base = {"daily": "каждый день", "weekly": f"по {WEEKDAYS[weekday % 7]}", "monthly": f"{monthday}-го числа" if monthday < 29 else "в последний день месяца" if monthday > 30 else f"{monthday}-го числа"}[freq]
    return f"{base} в {at_time} ({tz_name})"
