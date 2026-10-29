"""Профиль сопоставления столбцов и нормализация строки выгрузки.

Внутренняя модель не зависит от названий столбцов конкретной организации: администратор сопоставляет заголовки файла с полями ниже (подсказка — `suggest`).
Значения не «исправляются» молча: недостоверная дата (например, из будущего) сохраняется как есть с пометкой и не используется как дата наблюдения."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

# поле → (подпись, синонимы заголовков). Короткие синонимы (до 3 букв) ищутся целым словом.
FIELDS: dict[str, tuple[str, tuple[str, ...]]] = {
    "person_name": ("Пользователь (ФИО)", ("фио", "сотрудник", "пользователь", "владелец", "full name", "employee", "owner", "user")),
    "email": ("Рабочая почта", ("рабочая почта", "почта", "e-mail", "email", "mail")),
    "department": ("Подразделение", ("департамент", "подразделение", "отдел", "управление", "department", "division")),
    "account_created": ("Дата создания учётной записи", ("создания уз", "создания учет", "создания учёт", "account created")),
    "device_name": ("Имя компьютера", ("имя рабочей станции", "имя компьютера", "рабочая станция", "имя устройства", "компьютер", "hostname", "host name", "computer", "workstation")),
    "device_uid": ("Устойчивый идентификатор устройства", ("серийный номер", "инвентарный номер", "идентификатор устройства", "serial", "guid", "uuid", "asset")),
    "os": ("ОС", ("версия ос", "операционная система", "ос", "os")),
    "personal": ("Тип собственности (личное устройство)", ("личная техника", "личное устройство", "личный", "personal", "byod", "собственност")),
    "av_uses": ("Состояние антивируса по BI", ("использует антивирус", "антивирус", "antivirus")),
    "av_other": ("Сторонний антивирус", ("сторонний антивирус", "другой антивирус", "third-party")),
    "observed_at": ("Дата наблюдения в источнике", ("дата установления связи", "дата связи", "последняя связь", "дата наблюдения", "last seen")),
    "manual_at": ("Дата ручного исправления", ("ручного исправления", "дата исправления", "дата корректировки")),
    "owned_from": ("Начало владения (если источник его передаёт)", ("начало владения", "дата выдачи", "assigned")),
    "owned_to": ("Окончание владения (если источник его передаёт)", ("окончание владения", "дата возврата", "returned")),
}
DATE_FIELDS = ("account_created", "observed_at", "manual_at", "owned_from", "owned_to")
TEXT_FIELDS = ("person_name", "email", "department", "device_name", "device_uid", "os", "av_other")
GENERIC_NAMES = ("личный пк", "личный компьютер", "личный ноутбук", "личное устройство", "домашний пк")
# «нет значения» в текстовых столбцах: ОС «Нет» — ОС неизвестна, компьютер «Нет» — у сотрудника нет устройства (строка не отклоняется и устройство не создаётся)
NULLS = {"нет", "н/д", "n/a", "na", "none", "null", "unknown", "-", "—", "?", "отсутствует", "нет данных", "не указано", "не указан"}
_LIST = re.compile(r"[,;\r\n]+")
MAX_LIST = 50
FUTURE_SLACK = timedelta(days=1)
OLD = datetime(1990, 1, 1, tzinfo=timezone.utc)
TRUE = {"да", "yes", "true", "1", "+", "y", "д", "истина", "есть", "используется", "использует", "x", "✓"}
FALSE = {"нет", "no", "false", "0", "-", "n", "н", "ложь", "отсутствует", "не используется", "не использует"}
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DATE_FORMATS = ("%d.%m.%Y %H:%M:%S", "%d.%m.%Y %H:%M", "%d.%m.%Y", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%d/%m/%Y %H:%M", "%d/%m/%Y", "%d.%m.%y")
MAX_TEXT = 300
_last_fmt: list[str | None] = [None]
_SPACE = re.compile(r"[\s\x00-\x1f\x7f]+")                 # пробелы и управляющие символы → один пробел
MAX_EXTRA = 20


class ProfileError(ValueError):
    pass


def norm_header(h: object) -> str:
    return re.sub(r"\s+", " ", str(h or "")).strip()


def _key(h: str) -> str:
    return norm_header(h).lower().replace("ё", "е")


def _hits(header: str, syn: str) -> bool:
    syn = syn.replace("ё", "е")
    return bool(re.search(rf"(^|[^\w]){re.escape(syn)}($|[^\w])", header)) if len(syn) <= 3 else syn in header


def suggest(headers: list[str]) -> dict:
    """Подсказка профиля по заголовкам: каждому полю — заголовок с самым длинным совпавшим синонимом; флаги «Из …» и «Источник …» — происхождение сведений."""
    pairs = sorted(((max((len(s) for s in syns if _hits(_key(h), s)), default=0), f, h) for h in headers for f, (_t, syns) in FIELDS.items()), key=lambda x: -x[0])
    columns: dict[str, str] = {}
    for score, f, h in pairs:
        if score and f not in columns and h not in columns.values():
            columns[f] = h
    used = set(columns.values())
    origin = [h for h in headers if h not in used and (_key(h).startswith("из ") or "источник" in _key(h))]
    return {"columns": columns, "origin": origin, "generic_names": list(GENERIC_NAMES), "header_row": 0, "sheet": ""}


def validate_profile(p: dict) -> dict:
    cols = {k: norm_header(v) for k, v in (p.get("columns") or {}).items() if k in FIELDS and norm_header(v)}
    if not (cols.get("device_name") or cols.get("device_uid")):
        raise ProfileError("Сопоставьте столбец «Имя компьютера» или «Устойчивый идентификатор устройства»")
    if not (cols.get("person_name") or cols.get("email")):
        raise ProfileError("Сопоставьте столбец «Пользователь (ФИО)» или «Рабочая почта»: без сотрудника история принадлежности не строится")
    dup = [h for h in set(cols.values()) if list(cols.values()).count(h) > 1]
    if dup:
        raise ProfileError(f"Столбец «{dup[0]}» сопоставлен нескольким полям")
    origin = [norm_header(h) for h in (p.get("origin") or []) if norm_header(h)][:10]
    generic = [str(g).strip().lower() for g in (p.get("generic_names") if p.get("generic_names") is not None else GENERIC_NAMES) if str(g).strip()][:200]
    return {"sheet": norm_header(p.get("sheet"))[:120], "header_row": max(0, min(int(p.get("header_row") or 0), 50)), "columns": cols, "origin": origin, "generic_names": generic,
            "extra": bool(p.get("extra", True))}


def required_headers(p: dict) -> list[str]:
    return [h for f, h in p["columns"].items() if f in ("device_name", "device_uid", "person_name", "email")]


def text(v: object) -> str:
    if v is None:
        return ""
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return _SPACE.sub(" ", str(v)).strip()[:MAX_TEXT]


def items(v: object) -> list[str]:
    """Ячейка как список значений: в выгрузке «строка на сотрудника» компьютеры перечисляются через запятую («WS-1, WS-2»)."""
    return [t for t in (text(x) for x in _LIST.split(v)[:MAX_LIST]) if t] if isinstance(v, str) else [t] if (t := text(v)) else []


def boolish(v: object) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and v in (0, 1):
        return bool(v)
    t = text(v).lower().replace("ё", "е")
    return True if t in TRUE else False if t in FALSE else None


def parse_date(v: object, tz: ZoneInfo) -> tuple[datetime | None, bool]:
    """(дата UTC, распознана ли). Дата без пояса — в часовом поясе источника; число — серийная дата Excel."""
    if v is None or (isinstance(v, str) and (not v.strip() or v.strip().lower() in NULLS)):
        return None, True
    d = None
    if isinstance(v, datetime):
        d = v
    elif isinstance(v, date):
        d = datetime(v.year, v.month, v.day)
    elif isinstance(v, (int, float)) and 1 < v < 2958466:
        d = datetime(1899, 12, 30) + timedelta(days=float(v))
    else:
        s = text(v)
        for f in (_last_fmt[0], *DATE_FORMATS) if _last_fmt[0] else DATE_FORMATS:          # в выгрузке все даты обычно в одном формате: сначала — подошедший в прошлый раз
            try:
                d = datetime.strptime(s, f)
                _last_fmt[0] = f
                break
            except ValueError:
                continue
    if d is None:
        return None, False
    if d.tzinfo is None:
        d = d.replace(tzinfo=tz)
    return d.astimezone(timezone.utc), True


def short_name(name: str) -> str:
    n = name.strip().lower().replace("ё", "е")
    if "\\" in n:
        n = n.rsplit("\\", 1)[1]
    return n if IPV4.match(n) else n.split(".", 1)[0]


def is_generic(name: str, generic: list[str]) -> bool:
    n = name.strip().lower().replace("ё", "е")
    return not n or n in generic or bool(re.search(r"\s", n)) or not re.search(r"\w", n)


def os_family(os: str) -> str:
    o = os.lower()
    if "windows" in o or o.startswith("win"):
        return "windows"
    if any(x in o for x in ("mac", "os x", "darwin")):
        return "mac"
    if any(x in o for x in ("linux", "astra", "debian", "ubuntu", "centos", "red hat", "rhel", "alt ", "альт", "redos", "ред ос", "rosa", "suse", "fedora", "oracle", "rocky", "alma", "unix")):
        return "linux"
    return ""


def person_key(name: str, email: str) -> str:
    if email:
        return "e:" + email.lower()
    n = re.sub(r"\s+", " ", name.lower().replace("ё", "е")).strip()
    return "n:" + n if n else ""


def _iso(d: datetime | None) -> str | None:
    return d.isoformat(timespec="seconds") if d else None


def parse_row(values: dict[str, object], prof: dict, tz: ZoneInfo, snapshot_at: datetime) -> tuple[list[dict], str, list[dict]]:
    """Строка → (нормализованные записи, причина отклонения, предупреждения [{code, field}]). Пустая строка — ([], "", []).
    Несколько компьютеров в ячейке — по записи на каждый; ОС и дополнительные столбцы со списком той же длины раскладываются по позиции, иначе значение общее."""
    if all(v is None or (isinstance(v, str) and not v.strip()) for v in values.values()):
        return [], "", []
    cols = prof["columns"]
    get = lambda f: values.get(cols[f]) if f in cols else None  # noqa: E731
    r: dict = {f: "" if (t := text(get(f))).lower() in NULLS else t for f in TEXT_FIELDS}
    warns: list[dict] = []
    if r["email"] and not EMAIL.match(r["email"]):
        warns.append({"code": "bad_email", "field": "email"})
        r["email"] = ""
    r["email"] = r["email"].lower()
    r["personal"] = boolish(get("personal")) if "personal" in cols else None
    av_raw = text(get("av_uses"))
    r["av_uses"] = boolish(get("av_uses")) if av_raw else None
    other = get("av_other")
    ob = boolish(other) if text(other) else None
    r["av_other"] = "" if ob is False else ("да" if ob is True else r["av_other"])
    r["origin"] = [h for h in prof.get("origin", []) if boolish(values.get(h))]
    flags: list[str] = []
    for f in DATE_FIELDS:
        if f not in cols:
            r[f] = None
            continue
        raw = get(f)
        d, ok = parse_date(raw, tz)
        if not ok:
            warns.append({"code": "bad_date", "field": f})
            r[f], r[f + "_raw"] = None, text(raw)
            continue
        if d and d > snapshot_at + FUTURE_SLACK:
            flags.append(f"future:{f}")
            warns.append({"code": "future_date", "field": f, "value": f"{d.astimezone(tz):%d.%m.%Y}"})
        elif d and d < OLD:
            flags.append(f"old:{f}")
            warns.append({"code": "old_date", "field": f, "value": f"{d.astimezone(tz):%d.%m.%Y}"})
        r[f] = _iso(d)
    if prof.get("extra", True):
        used = set(cols.values()) | set(prof.get("origin", []))
        r["extra"] = {h: text(v) for h, v in list(values.items()) if h not in used and text(v)}
        if len(r["extra"]) > MAX_EXTRA:
            r["extra"] = dict(list(r["extra"].items())[:MAX_EXTRA])
    pk = person_key(r["person_name"], r["email"])
    if r["device_uid"]:
        names = [r["device_name"]]
    else:
        uniq: dict[str, str] = {}
        for n in items(get("device_name")):
            if n.lower() not in NULLS:
                uniq.setdefault(short_name(n), n)                         # «WS-1, ws-1.example.local» — одно устройство
        names = list(uniq.values())
        if not names:
            if pk and text(get("device_name")):                          # только «Нет» и подобные метки
                return [], "", [*warns, {"code": "no_device", "field": "device_name"}]
            return [], "нет имени компьютера и идентификатора устройства", warns
    generic_names = prof.get("generic_names", list(GENERIC_NAMES))
    split = {h: items(v) for h, v in [("\0os", get("os")), *(r.get("extra") or {}).items()]} if len(names) > 1 else {}
    out = []
    for i, name in enumerate(names):
        x = dict(r, device_name=name)
        if split:
            if len(split["\0os"]) == len(names):
                x["os"] = "" if split["\0os"][i].lower() in NULLS else split["\0os"][i]
            if "extra" in r:
                x["extra"] = {h: (split[h][i] if len(split[h]) == len(names) else v) for h, v in r["extra"].items()}
        x["generic"] = not x["device_uid"] and is_generic(name, generic_names)
        if x["generic"] and not pk:
            continue
        x["short"] = short_name(name) if name else ""
        x["dkey"] = ("u:" + x["device_uid"].lower()) if x["device_uid"] else ("g:" + pk + ":" + name.lower()) if x["generic"] else ("n:" + x["short"])
        x["pkey"] = pk
        body = dict(x)
        x["flags"] = flags
        x["rhash"] = hashlib.sha1(json.dumps(body, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()
        x["rkey"] = hashlib.sha1(f"{x['dkey']}|{pk}".encode()).hexdigest()
        out.append(x)
    if not out:
        return [], "условное имя устройства без сотрудника: запись не с чем связать", warns
    return out, "", warns


def trusted(r: dict, f: str) -> datetime | None:
    """Дата поля, пригодная как дата наблюдения: без пометки «из будущего» или «слишком старая»."""
    v = r.get(f)
    if not v or f"future:{f}" in r.get("flags", ()) or f"old:{f}" in r.get("flags", ()):
        return None
    return datetime.fromisoformat(v)


def confidence(r: dict) -> str:
    if r["generic"] or not r["email"]:
        return "low"
    return "high" if r["device_uid"] else "medium"
