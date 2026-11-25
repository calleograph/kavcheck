"""Оценка связи сотрудника с рабочим местом по наблюдениям, без изменения учёта."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..devices.users import VERIFIED_DAYS
from ..overview.calc import kind_of

SESSION_AGE = timedelta(days=VERIFIED_DAYS)
CURRENT_AGE = timedelta(days=3)
HISTORY_AGE = timedelta(days=90)
MIN_USAGE_DAYS = 3
MIN_USAGE_SPAN_DAYS = 14
ASSIGNMENT_SPAN_DAYS = 21
SESSION = "Наблюдение сеанса KSC"
CURRENT_SESSION = "Сотрудник был в списке вошедших при последнем успешном опросе KSC"
HISTORY = "Список пользователей KSC без даты входа"
EXACT_ACCOUNT = "Доменная учётная запись KSC совпала с AD"
UNVERIFIED_ACCOUNT = "Доменная учётная запись совпала с AD, личность в наблюдении не подтверждена"
SHORT_ACCOUNT = "Короткий логин однозначен в снимке AD, домен наблюдения неизвестен"
REGULAR = "Регулярные наблюдения за последние 30 суток"
SERVER = "Сервер или терминальный узел"
SHARED = "Есть основания связи с несколькими сотрудниками"
BI_ASSIGNMENT = "Закрепление по выгрузке BI"
INVENTORY_USER = "Назначенный пользователь по учёту"
INVENTORY_OWNER = "Владелец по учёту"
OBSERVED_ASSIGNMENT = "Закреплено по подтверждённым доменным наблюдениям за период более трёх недель"


@dataclass(frozen=True)
class Usage:
    account: str
    observed: tuple[datetime, ...]
    recent: tuple[datetime, ...]
    current: bool = False

    @property
    def days(self) -> int:
        return len({stamp.date() for stamp in self.recent})

    @property
    def span_days(self) -> int:
        return (self.recent[-1].date() - self.recent[0].date()).days if self.recent else 0

    @property
    def regular(self) -> bool:
        return (self.account == EXACT_ACCOUNT and self.days >= MIN_USAGE_DAYS
                and self.span_days >= MIN_USAGE_SPAN_DAYS)

    def assignment_eligible(self, now: datetime) -> bool:
        return (self.regular and self.span_days > ASSIGNMENT_SPAN_DAYS
                and now - CURRENT_AGE <= self.recent[-1] <= now)


def assess(assigned, usage: Usage | None = None, shared: str = "", *, fresh_workstation: bool = False) -> dict:
    evidence = list(assigned)
    if usage:
        evidence.extend([usage.account, SESSION if usage.observed else HISTORY])
        if usage.regular:
            evidence.append(REGULAR)
        if usage.current:
            evidence.append(CURRENT_SESSION)
    if shared:
        evidence.append(shared)
    likely = usage and (usage.regular or (usage.current and fresh_workstation and not shared))
    return {
        "confidence": "confirmed" if assigned else "likely" if likely else "possible",
        "evidence": sorted(set(evidence)),
        "regular": bool(usage and usage.regular),
        "current_session": bool(usage and usage.current),
        "observed_days": usage.days if usage else 0,
        "span_days": usage.span_days if usage else 0,
        "last_verified_at": usage.recent[-1].isoformat() if usage and usage.recent else None,
        "first_seen_at": usage.observed[0].isoformat() if usage and usage.observed else None,
        "last_seen_at": usage.observed[-1].isoformat() if usage and usage.observed else None,
        "shared": bool(shared),
    }


def assignment_for(pairs: dict, shared: str) -> tuple[str, str] | None:
    accepted = {pid: pair for pid, pair in pairs.items() if pair["confidence"] != "rejected"}
    manual = [pid for pid, pair in accepted.items() if pair.get("decision") == "assigned"]
    if manual:
        return (manual[0], "manual") if len(manual) == 1 else None
    for basis, evidence in (("inventory", INVENTORY_USER), ("bi", BI_ASSIGNMENT), ("inventory", INVENTORY_OWNER)):
        declared = [pid for pid, pair in accepted.items() if evidence in pair["evidence"]]
        if declared:
            return (declared[0], basis) if len(declared) == 1 else None
    if shared:
        return None
    confirmed = [pid for pid, pair in accepted.items() if pair["confidence"] == "confirmed"]
    if confirmed:
        if len(confirmed) == 1 and accepted[confirmed[0]].get("decision") == "confirmed":
            return confirmed[0], "manual"
        return None
    stable = [pid for pid, pair in accepted.items() if pair.get("_stable_assignment")]
    return (stable[0], "observed") if len(stable) == 1 else None


def shared_reason(asset, os: str, participants=()) -> str:
    description = f"{os} {asset.purpose if asset else ''}".casefold()
    if ((asset and asset.cls in {"server", "vm"}) or kind_of({"os": os}) == "server"
            or any(label in description for label in ("терминал", "terminal", "multi-session"))):
        return SERVER
    return SHARED if len(participants) > 1 else ""
