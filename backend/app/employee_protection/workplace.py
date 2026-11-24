"""Оценка связи сотрудника с рабочим местом по наблюдениям, без изменения учёта."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..overview.calc import kind_of

SESSION_AGE = timedelta(days=30)
HISTORY_AGE = timedelta(days=90)
MIN_USAGE_DAYS = 3
MIN_USAGE_SPAN = timedelta(days=14)
SESSION = "Наблюдение сеанса KSC"
HISTORY = "Список пользователей KSC без даты входа"
EXACT_ACCOUNT = "Доменная учётная запись KSC совпала с AD"
UNVERIFIED_ACCOUNT = "Доменная учётная запись совпала с AD, личность в наблюдении не подтверждена"
SHORT_ACCOUNT = "Короткий логин однозначен в снимке AD, домен наблюдения неизвестен"
REGULAR = "Регулярные наблюдения за последние 30 суток"
SERVER = "Сервер или терминальный узел"
SHARED = "Регулярно используется несколькими сотрудниками"


@dataclass(frozen=True)
class Usage:
    account: str
    observed: tuple[datetime, ...]
    recent: tuple[datetime, ...]

    @property
    def days(self) -> int:
        return len({stamp.date() for stamp in self.recent})

    @property
    def regular(self) -> bool:
        return (self.account == EXACT_ACCOUNT and self.days >= MIN_USAGE_DAYS
                and self.recent[-1].date() - self.recent[0].date() >= MIN_USAGE_SPAN)


def assess(assigned, usage: Usage | None = None, shared: str = "") -> dict:
    evidence = list(assigned)
    if usage:
        evidence.extend([usage.account, SESSION if usage.observed else HISTORY])
        if usage.regular:
            evidence.append(REGULAR)
    if shared:
        evidence.append(shared)
    return {
        "confidence": "confirmed" if assigned else "likely" if usage and usage.regular else "possible",
        "evidence": sorted(set(evidence)),
        "regular": bool(usage and usage.regular),
        "observed_days": usage.days if usage else 0,
        "first_seen_at": usage.observed[0].isoformat() if usage and usage.observed else None,
        "last_seen_at": usage.observed[-1].isoformat() if usage and usage.observed else None,
        "shared": bool(shared),
    }


def shared_reason(asset, os: str, usage) -> str:
    description = f"{os} {asset.purpose if asset else ''}".casefold()
    if ((asset and asset.cls in {"server", "vm"}) or kind_of({"os": os}) == "server"
            or any(label in description for label in ("терминал", "terminal", "multi-session"))):
        return SERVER
    return SHARED if sum(item.regular for item in usage) > 1 else ""
