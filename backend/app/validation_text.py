"""Понятные русские сообщения вместо сырого списка ошибок валидации (pydantic): какое поле и что не так."""
from __future__ import annotations

LABELS = {"zone": "Зона ответственности", "zone_ids": "Зоны", "items": "Условия проверки", "source_ids": "Источники KSC", "active_days": "Давность связи, суток", "group_contains": "Группа",
          "name_like": "Шаблон названия", "version": "Версия", "value": "Версия", "min": "Нижняя граница", "max": "Верхняя граница", "host_ids": "Компьютеры", "title": "Название",
          "q": "Поиск", "email": "Адрес почты", "name": "Название", "password": "Пароль", "login": "Логин"}
SKIP = {"body", "query", "path", "params", "header"}


def _field(loc: tuple) -> str:
    names = [str(x) for x in loc if isinstance(x, str) and x not in SKIP]
    for n in reversed(names):
        if n in LABELS:
            return LABELS[n]
    return names[-1] if names else "Запрос"


def _text(e: dict) -> str:
    t, ctx = e.get("type", ""), e.get("ctx") or {}
    if t == "missing":
        return "поле обязательно"
    if t in ("string_type", "int_type", "bool_type", "list_type", "dict_type"):
        return "значение не заполнено или имеет неверный тип"
    if t in ("int_parsing", "int_from_float", "float_parsing"):
        return "нужно число"
    if t == "bool_parsing":
        return "нужно «да» или «нет»"
    if t == "string_too_long":
        return f"не длиннее {ctx.get('max_length', '?')} символов"
    if t == "string_too_short":
        return f"не короче {ctx.get('min_length', '?')} символов" if ctx.get("min_length", 0) > 1 else "поле не должно быть пустым"
    if t == "too_long":
        return f"не больше {ctx.get('max_length', '?')} элементов"
    if t == "too_short":
        return "нужно выбрать хотя бы один элемент"
    if t in ("greater_than_equal", "greater_than"):
        return f"не меньше {ctx.get('ge', ctx.get('gt', '?'))}"
    if t in ("less_than_equal", "less_than"):
        return f"не больше {ctx.get('le', ctx.get('lt', '?'))}"
    if t == "string_pattern_mismatch":
        return "недопустимое значение"
    if t in ("literal_error", "enum"):
        return "значение не из списка допустимых"
    if t == "value_error":
        msg = str(e.get("msg", ""))
        return msg[len("Value error, "):] if msg.startswith("Value error, ") else msg
    if t == "json_invalid":
        return "тело запроса не разобрано"
    return str(e.get("msg", "некорректное значение"))


def explain(errors: list[dict]) -> str:
    """«Зона ответственности: значение не заполнено…; Версия: нужно число» — не больше пяти пунктов."""
    out: list[str] = []
    for e in errors:
        text = _text(e)
        f = _field(tuple(e.get("loc") or ()))
        line = text if e.get("type") == "value_error" and f == "Запрос" else f"{f}: {text}"
        if e.get("type") == "value_error" and f != "Запрос" and not any(c in text for c in ":«»"):
            line = f"{f}: {text}"
        if line not in out:
            out.append(line)
    return "; ".join(out[:5]) + (f" (и ещё {len(out) - 5})" if len(out) > 5 else "")
