"""Ошибки расчёта EOL: понятное сообщение для пользователя и техническая причина для администратора.

Пользователь видит только `friendly` (без SQL, идентификаторов и значений ключей); `technical` — этап, операция и ключ конфликта — хранится в состоянии расчёта и журнале и показывается администратору."""
from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import exc as sa_exc

from ..ksc.driver import KscError
from ..services.resources import MemoryPressure

_KEY = re.compile(r"Key \((?P<cols>[^)]*)\)=\((?P<vals>.*)\) already exists", re.S)
_CONSTRAINT = re.compile(r'constraint "(?P<name>[^"]+)"')


@dataclass
class Described:
    code: str                  # conflict | ksc | database | memory | internal
    friendly: str              # для пользователя
    technical: str             # для администратора
    transient: bool = False    # имеет смысл повторить сразу (блокировка, обрыв соединения)


def _short(v: str, n: int = 200) -> str:
    v = v.replace("\n", " ")
    return v if len(v) <= n else v[:n] + "…"


def describe(exc: BaseException, stage: str = "", operation: str = "") -> Described:
    where = f"этап «{stage}»" if stage else "расчёт"
    op = f", операция: {operation}" if operation else ""
    if isinstance(exc, MemoryPressure):
        return Described("memory", "Расчёт EOL отложен: не хватает оперативной памяти. Предыдущие результаты сохранены; расчёт будет повторён.", f"{where}{op}: {_short(str(exc))}", True)
    if isinstance(exc, KscError):
        return Described("ksc", "Не удалось получить данные из KSC для расчёта EOL. Предыдущие результаты сохранены; повтор через 15 минут.", f"{where}{op}: KscError {exc.code}: {_short(exc.message)}")
    if isinstance(exc, sa_exc.IntegrityError):
        orig = getattr(exc, "orig", None)
        text = f"{getattr(orig, 'detail', '') or ''} {orig or ''}"
        c = _CONSTRAINT.search(text)
        k = _KEY.search(text)
        key = f"; ключ ({k['cols']}) = ({_short(k['vals'], 160)})" if k else ""
        return Described("conflict", "Не удалось рассчитать EOL для источника. Обнаружен конфликт данных при сохранении результатов. Предыдущие результаты сохранены.",
                         f"{where}{op}: нарушение ограничения {c['name'] if c else '?'}{key}")
    if isinstance(exc, sa_exc.DBAPIError):
        transient = bool(getattr(exc, "connection_invalidated", False) or isinstance(exc, sa_exc.OperationalError))
        return Described("database", "Не удалось сохранить результаты расчёта EOL: внутренняя база данных временно недоступна или занята. Предыдущие результаты сохранены; расчёт будет повторён.",
                         f"{where}{op}: {type(exc).__name__}: {_short(str(getattr(exc, 'orig', exc)))}", transient)
    return Described("internal", "Расчёт EOL завершился внутренней ошибкой. Предыдущие результаты сохранены. Подробности — в журнале событий (для администратора).", f"{where}{op}: {type(exc).__name__}: {_short(str(exc))}")
