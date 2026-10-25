"""Единый поиск по тексту со звёздочкой: `*` — любое число символов, включая ноль; без звёздочек — поиск по части строки (или по началу — режим prefix).
Регистр не учитывается. Маска со звёздочкой сопоставляется со всей строкой целиком: `SRV-*` — начинается с, `*-DB` — заканчивается на, `*2026*` — содержит, `SRV-*-DB*` — несколько звёздочек.
Все поля поиска строят условия только через этот модуль: экранирование спецсимволов LIKE, предел длины и числа звёздочек — в одном месте."""
from __future__ import annotations

import re
from typing import Callable

from sqlalchemy import func, or_

MAX_LEN = 200
MAX_STARS = 6


class MaskError(ValueError):
    """Недопустимый поисковый запрос (слишком длинный или слишком много звёздочек): API отвечает 422."""


def clean(text: str | None) -> str:
    """Запрос без краевых пробелов; подряд идущие звёздочки сводятся к одной. Пустая строка и «*» — без отбора."""
    t = re.sub(r"\*{2,}", "*", (text or "").strip())
    if len(t) > MAX_LEN:
        raise MaskError(f"Запрос длиннее {MAX_LEN} символов")
    if t.count("*") > MAX_STARS:
        raise MaskError(f"В маске не больше {MAX_STARS} звёздочек")
    return "" if t == "*" else t


def is_mask(text: str | None) -> bool:
    return "*" in (text or "")


def mssql_like(text: str | None, mode: str = "contains") -> str | None:
    """Шаблон для `LIKE %(p)s` в SQL Server (базы KSC) или None, если отбор не нужен. `%`, `_` и `[` из запроса экранируются скобками, `*` становится `%`.
    Регистр определяет сортировка столбца в KSC (по умолчанию без учёта регистра)."""
    t = clean(text)
    if not t:
        return None
    body = re.sub(r"[%_\[*]", lambda m: "%" if m.group() == "*" else f"[{m.group()}]", t)
    if is_mask(t):
        return body
    return body + "%" if mode == "prefix" else f"%{body}%"


def local_like(text: str | None, mode: str = "contains") -> str | None:
    """Шаблон для внутренней базы (PostgreSQL, SQLite): строчные буквы, экранирование обратной косой чертой — используется вместе с `escape="\\\\"` и `func.lower(столбец)`."""
    t = clean(text).lower()
    if not t:
        return None
    body = re.sub(r"[\\%_*]", lambda m: "%" if m.group() == "*" else "\\" + m.group(), t)
    if is_mask(t):
        return body
    return body + "%" if mode == "prefix" else f"%{body}%"


def column_like(column, text: str | None, mode: str = "contains"):
    """Условие SQLAlchemy `lower(column) LIKE …` или None (отбор не нужен)."""
    p = local_like(text, mode)
    return None if p is None else func.lower(column).like(p, escape="\\")


def any_of(text: str | None, *columns, mode: str = "contains"):
    """Условие «любой из столбцов подходит» или None (отбор не нужен)."""
    p = local_like(text, mode)
    return None if p is None else or_(*(func.lower(c).like(p, escape="\\") for c in columns))


def matcher(text: str | None, mode: str = "contains") -> Callable[[str], bool] | None:
    """Проверка строки в памяти (для данных, уже загруженных порцией: сводки, строки отчёта) с теми же правилами; None — отбор не нужен."""
    t = clean(text).lower()
    if not t:
        return None
    if not is_mask(t):
        return (lambda s: (s or "").lower().startswith(t)) if mode == "prefix" else (lambda s: t in (s or "").lower())
    rx = re.compile("^" + ".*".join(re.escape(p) for p in t.split("*")) + "$", re.S)
    return lambda s: rx.match((s or "").lower()) is not None


def any_field(text: str | None, mode: str = "contains") -> Callable[..., bool] | None:
    """Проверка «подходит хотя бы одно из значений»: `f = any_field(q); f(a, b, c)`."""
    m = matcher(text, mode)
    return None if m is None else (lambda *vals: any(m(str(v)) for v in vals if v is not None))
