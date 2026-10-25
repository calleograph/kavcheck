"""Массовый импорт и экспорт зон ответственности в CSV (длинный формат: одна строка — один признак и/или один получатель зоны).

Формат удобен для Excel: ни JSON, ни списков в ячейках. Зона повторяется в каждой своей строке; сведения о зоне (описание, назначение, приоритет) берутся из первой заполненной.
Импорт сначала разбирается в план (`plan`) без обращений к базе записи — по нему строится предварительный просмотр; применение (в `service.apply_plan`) выполняется одной транзакцией.
Безопасность: размер и число строк ограничены; ячейки с формулами (= @) отклоняются; при выгрузке опасные начала экранируются апострофом, а при загрузке он снимается — повторный импорт выгрузки не меняет данных."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
from dataclasses import dataclass, field

from .match import KIND_TITLE, RuleError, ZoneDef, ZoneIndex, normalize_rule, parse_net

MAX_BYTES = 5 * 1024 * 1024
MAX_ROWS = 20000
MODES = ("add_update", "add_only", "replace")
MODE_TITLE = {"add_update": "Добавить новые и обновить существующие", "add_only": "Только добавить новые", "replace": "Полная замена (опасно)"}

COLUMNS = ["Идентификатор зоны", "Зона", "Описание", "Назначение", "Приоритет", "Тип признака", "Значение признака", "Комментарий к признаку",
           "Ответственный", "Должность", "Email", "Роль получателя", "Рассылка"]
_ALIASES = {
    "zone_id": ["идентификатор зоны", "идентификатор", "id", "zone_id", "uuid"],
    "name": ["зона", "департамент", "название", "название зоны", "подразделение", "zone", "name", "department"],
    "description": ["описание", "description"],
    "purpose": ["назначение", "purpose"],
    "priority": ["приоритет", "priority"],
    "kind": ["тип признака", "тип", "kind", "type"],
    "value": ["значение признака", "значение", "подсеть", "сеть", "ip", "подсеть или диапазон", "value", "network", "subnet", "cidr"],
    "note": ["комментарий к признаку", "комментарий", "note", "comment"],
    "contact": ["ответственный", "фио", "фио ответственного", "контакт", "contact", "responsible"],
    "position": ["должность", "position"],
    "email": ["email", "e-mail", "почта", "электронная почта", "адрес электронной почты", "mail"],
    "role": ["роль получателя", "роль", "role"],
    "enabled": ["рассылка", "рассылка включена", "enabled", "send"],
}
KIND_WORDS = {"net": ("сеть", "сеть или адреса", "net", "подсеть", "диапазон", "ip", "адрес", ""), "exclude": ("исключение", "exclude", "исключить"), "group": ("группа ksc", "группа", "group"),
              "name": ("имя компьютера", "имя", "name", "компьютер")}
ROLE_WORDS = {"responsible": ("ответственный", "responsible", "исполнитель", ""), "cc": ("копия", "cc", "руководитель", "дополнительный", "получатель"), "group": ("группа рассылки", "группа", "group", "рассылка")}
ROLE_TITLE = {"responsible": "Ответственный", "cc": "Копия", "group": "Группа рассылки"}
EMAIL_RE = re.compile(r"^[^\s@<>()\[\],;:\\\"]+@[^\s@<>()\[\],;:\\\"]+\.[^\s@<>()\[\],;:\\\"]{2,}$")
YES = {"да", "yes", "true", "1", "y", "вкл", "+", ""}
NO = {"нет", "no", "false", "0", "n", "выкл", "-"}


def valid_email(v: str) -> bool:
    return len(v) <= 254 and bool(EMAIL_RE.match(v))


def safe_cell(v) -> str:
    """Значение ячейки для выгрузки: начало с = + - @ или управляющего символа экранируется апострофом (CSV-инъекция при открытии в Excel)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _unsafe(s: str) -> str:
    return s[1:] if s[:1] == "'" and s[1:2] in ("=", "+", "-", "@") else s


@dataclass
class Row:
    line: int
    zone_id: str = ""
    name: str = ""
    description: str = ""
    purpose: str = ""
    priority: int | None = None
    kind: str = ""
    value: str = ""
    note: str = ""
    contact: str = ""
    position: str = ""
    email: str = ""
    role: str = "responsible"
    enabled: bool = True


@dataclass
class Parsed:
    rows: list[Row] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    encoding: str = "utf-8"
    delimiter: str = ";"
    total_lines: int = 0


def _err(lst: list[dict], line: int, text: str, column: str = "") -> None:
    lst.append({"line": line, "column": column, "message": text})


def _decode(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8"), "utf-8 (BOM)"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("cp1251", errors="replace"), "windows-1251"           # Excel с русской локалью сохраняет «CSV» в ANSI


def _delimiter(text: str) -> str:
    head = "\n".join(text.splitlines()[:5])
    counts = {d: head.count(d) for d in (";", ",", "\t", "|")}
    best = max(counts, key=counts.get)
    return best if counts[best] else ";"


def _kind(raw: str) -> str | None:
    t = raw.strip().lower()
    return next((k for k, words in KIND_WORDS.items() if t in words), None)


def _role(raw: str) -> str | None:
    t = raw.strip().lower()
    return next((k for k, words in ROLE_WORDS.items() if t in words), None)


def parse(data: bytes) -> Parsed:
    out = Parsed()
    if len(data) > MAX_BYTES:
        _err(out.errors, 0, f"Файл больше {MAX_BYTES // (1024 * 1024)} МБ")
        return out
    if b"\x00" in data[:4096]:
        _err(out.errors, 0, "Файл не похож на текстовый CSV (двоичное содержимое). Сохраните таблицу как «CSV UTF-8».")
        return out
    text, out.encoding = _decode(data)
    out.delimiter = _delimiter(text)
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=out.delimiter)
    try:
        header = next(reader)
    except StopIteration:
        _err(out.errors, 0, "Файл пуст")
        return out
    names = [h.strip().lower().lstrip("﻿") for h in header]
    col: dict[str, int] = {}
    for key, aliases in _ALIASES.items():
        for a in aliases:
            if a in names:
                col[key] = names.index(a)
                break
    if "name" not in col and "zone_id" not in col:
        _err(out.errors, 1, "Не найден столбец «Зона». Скачайте пример CSV и сохраните заголовки без изменений.", "Зона")
        return out
    for line_no, rec in enumerate(reader, start=2):
        out.total_lines = line_no
        if line_no - 1 > MAX_ROWS:
            _err(out.errors, line_no, f"Слишком много строк (максимум {MAX_ROWS})")
            break
        if not any(c.strip() for c in rec):
            continue
        raw = lambda k: rec[col[k]].strip() if k in col and col[k] < len(rec) else ""  # noqa: E731
        g = lambda k: _unsafe(raw(k))  # noqa: E731
        r = Row(line=line_no, zone_id=g("zone_id"), name=re.sub(r"\s+", " ", g("name")), description=g("description"), purpose=g("purpose"), note=g("note"),
                contact=g("contact"), position=g("position"), email=g("email").lower(), value=g("value"))
        bad = False
        for label, key in (("Зона", "name"), ("Описание", "description"), ("Значение признака", "value"), ("Ответственный", "contact"), ("Email", "email")):
            v = raw(key)
            if v[:1] in ("=", "@"):          # формула в ячейке; экранированное апострофом значение («'=…») принимается как текст
                _err(out.errors, line_no, f"Ячейка начинается с «{v[:1]}» и похожа на формулу. Уберите символ или поставьте перед ним апостроф.", label)
                bad = True
        if bad:
            continue
        if not r.name and not r.zone_id:
            _err(out.errors, line_no, "Не указана зона (ни название, ни идентификатор)", "Зона")
            continue
        if r.zone_id:
            try:
                r.zone_id = str(uuid.UUID(r.zone_id))
            except ValueError:
                _err(out.errors, line_no, f"Идентификатор зоны «{r.zone_id}» не является UUID. Оставьте ячейку пустой для новой зоны.", "Идентификатор зоны")
                continue
        if len(r.name) > 120:
            _err(out.errors, line_no, "Название зоны длиннее 120 символов", "Зона")
            continue
        pr = g("priority")
        if pr:
            try:
                r.priority = int(pr)
                if not 1 <= r.priority <= 1000:
                    raise ValueError
            except ValueError:
                _err(out.errors, line_no, f"Приоритет «{pr}» — нужно целое число от 1 до 1000 (меньше — главнее)", "Приоритет")
                continue
        kind_raw = g("kind")
        kind = _kind(kind_raw)
        if kind is None:
            _err(out.errors, line_no, f"Неизвестный тип признака «{kind_raw}». Допустимо: Сеть, Исключение, Группа KSC, Имя компьютера", "Тип признака")
            continue
        r.kind = kind
        role_raw = g("role")
        role = _role(role_raw)
        if role is None:
            _err(out.errors, line_no, f"Неизвестная роль «{role_raw}». Допустимо: Ответственный, Копия, Группа рассылки", "Роль получателя")
            continue
        r.role = role
        en = g("enabled").lower()
        if en not in YES and en not in NO:
            _err(out.errors, line_no, f"В столбце «Рассылка» ожидается «да» или «нет», найдено «{en}»", "Рассылка")
            continue
        r.enabled = en not in NO
        if r.value:
            try:
                r.kind, r.value = normalize_rule(kind, r.value)
            except RuleError as e:
                _err(out.errors, line_no, str(e), "Значение признака")
                continue
        elif r.note and not (r.email or r.contact):
            _err(out.warnings, line_no, "Комментарий к признаку без значения — строка пропущена", "Комментарий к признаку")
        if r.email:
            if not valid_email(r.email):
                _err(out.errors, line_no, f"Адрес электронной почты «{r.email}» записан неверно", "Email")
                continue
        elif r.contact or r.position:
            _err(out.warnings, line_no, "Указан ответственный без адреса электронной почты: получателем он не станет, строка пропущена", "Email")
            r.contact = r.position = ""
        out.rows.append(r)
    return out


# ------------------------------------------------------------------------------------------------ план
@dataclass
class Existing:
    id: str
    name: str
    description: str = ""
    purpose: str = ""
    priority: int = 100
    rules: list[tuple[str, str]] = field(default_factory=list)
    contacts: list[dict] = field(default_factory=list)     # email, name, position, role, enabled


@dataclass
class Plan:
    mode: str
    zones: list[dict] = field(default_factory=list)        # по зоне: action, changes
    summary: dict = field(default_factory=dict)
    errors: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    overlaps: list[dict] = field(default_factory=list)
    ok: bool = False
    desired: dict = field(default_factory=dict)          # для применения; наружу не отдаётся

    def fingerprint(self) -> str:
        """Отпечаток плана: если между просмотром и применением данные изменились, отпечаток другой и применение отклоняется."""
        return hashlib.sha1(json.dumps([self.mode, self.summary, self.zones], sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()[:16]

    def public(self) -> dict:
        return {"mode": self.mode, "fingerprint": self.fingerprint(), "summary": self.summary, "zones": self.zones, "errors": self.errors, "warnings": self.warnings, "overlaps": self.overlaps, "ok": self.ok}


def _group(parsed: Parsed, existing: list[Existing], plan: Plan) -> dict[str, dict]:
    """Строки → желаемые зоны. Ключ — идентификатор существующей зоны, либо «new:<название в нижнем регистре>»."""
    by_id = {e.id: e for e in existing}
    by_name = {e.name.lower(): e for e in existing}
    desired: dict[str, dict] = {}
    name_of_key: dict[str, str] = {}
    for r in parsed.rows:
        ex = None
        if r.zone_id:
            ex = by_id.get(r.zone_id)
            if ex is None:
                _err(plan.errors, r.line, f"Зона с идентификатором {r.zone_id} не найдена. Для новой зоны оставьте идентификатор пустым.", "Идентификатор зоны")
                continue
            if r.name and r.name.lower() != ex.name.lower():
                other = by_name.get(r.name.lower())
                if other and other.id != ex.id:
                    _err(plan.errors, r.line, f"Нельзя переименовать «{ex.name}» в «{r.name}»: такая зона уже есть", "Зона")
                    continue
        else:
            if not r.name:
                continue
            ex = by_name.get(r.name.lower())
        key = ex.id if ex else "new:" + r.name.lower()
        d = desired.setdefault(key, {"existing": ex, "name": ex.name if ex and not r.zone_id else (r.name or (ex.name if ex else "")), "by_id": bool(r.zone_id), "description": None, "purpose": None,
                                     "priority": None, "rules": [], "contacts": {}, "lines": []})
        if r.zone_id:
            d["by_id"] = True
            if r.name:
                d["name"] = r.name
        elif not ex:
            d["name"] = d["name"] or r.name
        d["lines"].append(r.line)
        for fld in ("description", "purpose", "priority"):
            v = getattr(r, fld)
            if v not in ("", None):
                if d[fld] in (None, v):
                    d[fld] = v
                else:
                    _err(plan.warnings, r.line, f"Для зоны «{d['name']}» значение поля «{fld}» в строках отличается; использовано первое", fld)
        if r.value:
            item = (r.kind, r.value)
            if item in d["rules"]:
                _err(plan.warnings, r.line, f"Повтор признака «{r.value}» в зоне «{d['name']}» — учтён один раз", "Значение признака")
            else:
                d["rules"].append(item)
                d.setdefault("rule_notes", {})[item] = r.note
        if r.email:
            c = d["contacts"].get(r.email)
            new = {"email": r.email, "name": r.contact, "position": r.position, "role": r.role, "enabled": r.enabled}
            if c is None:
                d["contacts"][r.email] = new
            else:
                _err(plan.warnings, r.line, f"Повтор получателя {r.email} в зоне «{d['name']}» — учтён один раз", "Email")
                for k in ("name", "position"):
                    c[k] = c[k] or new[k]
    return desired


def plan(parsed: Parsed, existing: list[Existing], mode: str, *, confirm: bool = False) -> Plan:
    if mode not in MODES:
        raise ValueError("неизвестный режим импорта")
    p = Plan(mode=mode, errors=list(parsed.errors), warnings=list(parsed.warnings))
    desired = _group(parsed, existing, p)
    if not desired and not p.errors:
        _err(p.errors, 0, "В файле нет ни одной зоны")
    created = updated = unchanged = skipped = rules_add = rules_rm = contacts_add = contacts_upd = contacts_rm = deleted = 0
    result_defs: list[ZoneDef] = []
    names_seen: dict[str, int] = {}
    for key, d in desired.items():
        ex: Existing | None = d["existing"]
        z = {"id": ex.id if ex else "", "name": d["name"], "action": "", "rules_add": [], "rules_remove": [], "contacts_add": [], "contacts_update": [], "contacts_remove": [], "fields": [], "lines": d["lines"][:5]}
        if not ex:
            if d["name"].lower() in names_seen:
                _err(p.errors, d["lines"][0], f"Зона «{d['name']}» встречается под разными идентификаторами", "Зона")
            names_seen[d["name"].lower()] = 1
            z["action"] = "create"
            created += 1
            z["rules_add"] = [f"{KIND_TITLE[k]}: {v}" for k, v in d["rules"]]
            z["contacts_add"] = [f"{c['email']}" + (f" ({c['name']})" if c["name"] else "") for c in d["contacts"].values()]
            rules_add += len(d["rules"])
            contacts_add += len(d["contacts"])
            result_defs.append(ZoneDef(key, d["name"], d["priority"] or 100, list(d["rules"])))
        elif mode == "add_only":
            z["action"] = "skip"
            skipped += 1
            result_defs.append(ZoneDef(ex.id, ex.name, ex.priority, list(ex.rules)))
        else:
            for fld, label in (("description", "Описание"), ("purpose", "Назначение"), ("priority", "Приоритет")):
                if d[fld] is not None and d[fld] != getattr(ex, fld):
                    z["fields"].append(f"{label}: «{getattr(ex, fld)}» → «{d[fld]}»")
            if d["name"] != ex.name:
                z["fields"].append(f"Название: «{ex.name}» → «{d['name']}»")
            have = set(ex.rules)
            z["rules_add"] = [f"{KIND_TITLE[k]}: {v}" for k, v in d["rules"] if (k, v) not in have]
            want_rules = set(d["rules"])
            rules = list(ex.rules) + [r for r in d["rules"] if r not in have]
            if mode == "replace":
                z["rules_remove"] = [f"{KIND_TITLE[k]}: {v}" for k, v in ex.rules if (k, v) not in want_rules]
                rules = list(d["rules"])
            have_c = {c["email"].lower(): c for c in ex.contacts}
            for em, c in d["contacts"].items():
                old = have_c.get(em)
                if old is None:
                    z["contacts_add"].append(em + (f" ({c['name']})" if c["name"] else ""))
                else:
                    ch = [lbl for k, lbl in (("name", "ФИО"), ("position", "должность"), ("role", "роль"), ("enabled", "рассылка")) if c[k] not in ("", None) and c[k] != old.get(k)]
                    if ch:
                        z["contacts_update"].append(f"{em}: {', '.join(ch)}")
            if mode == "replace":
                z["contacts_remove"] = [em for em in have_c if em not in d["contacts"]]
            rules_add += len(z["rules_add"])
            rules_rm += len(z["rules_remove"])
            contacts_add += len(z["contacts_add"])
            contacts_upd += len(z["contacts_update"])
            contacts_rm += len(z["contacts_remove"])
            changed = any(z[k] for k in ("fields", "rules_add", "rules_remove", "contacts_add", "contacts_update", "contacts_remove"))
            z["action"] = "update" if changed else "unchanged"
            updated += changed
            unchanged += not changed
            result_defs.append(ZoneDef(ex.id, d["name"], d["priority"] or ex.priority, rules))
        p.zones.append(z)
    if mode == "replace":
        in_file = {k for k in desired if not k.startswith("new:")}
        for e in existing:
            if e.id not in in_file:
                deleted += 1
                p.zones.append({"id": e.id, "name": e.name, "action": "delete", "rules_add": [], "rules_remove": [f"{KIND_TITLE[k]}: {v}" for k, v in e.rules], "contacts_add": [],
                                "contacts_update": [], "contacts_remove": [c["email"] for c in e.contacts], "fields": [], "lines": []})
        if not confirm:
            _err(p.warnings, 0, "Режим полной замены удаляет всё, чего нет в файле (включая зоны). Подтвердите явно, просмотрев список изменений.")
    else:
        in_file = {k for k in desired if not k.startswith("new:")}
        result_defs += [ZoneDef(e.id, e.name, e.priority, list(e.rules)) for e in existing if e.id not in in_file]
    p.overlaps = overlaps(result_defs)
    for o in p.overlaps:
        _err(p.warnings, 0, f"Сети зон «{o['a']}» и «{o['b']}» пересекаются ({o['example']}). Компьютеры из пересечения будут видны в обеих зонах, пока не задан приоритет или закрепление.")
    p.summary = {"rows": len(parsed.rows), "zones_in_file": len(desired), "zones_create": created, "zones_update": updated, "zones_unchanged": unchanged, "zones_skipped": skipped,
                 "zones_delete": deleted, "rules_add": rules_add, "rules_remove": rules_rm, "contacts_add": contacts_add, "contacts_update": contacts_upd, "contacts_remove": contacts_rm,
                 "errors": len(p.errors), "warnings": len(p.warnings), "encoding": parsed.encoding, "delimiter": parsed.delimiter}
    p.desired = desired
    p.ok = not p.errors and (mode != "replace" or confirm)
    return p


def overlaps(defs: list[ZoneDef], limit: int = 50) -> list[dict]:
    """Пересекающиеся сети разных зон (с учётом исключений зоны). Одинаковые приоритеты — спор; разные — решается приоритетом, но тоже показывается."""
    spans = []
    for z in defs:
        cuts = []
        mine = []
        for k, v in z.rules:
            if k == "net":
                mine.append(parse_net(v))
            elif k == "exclude":
                try:
                    cuts.append(parse_net(v))
                except RuleError:
                    pass
        from .match import _merge, _subtract  # noqa: PLC0415
        for lo, hi in _subtract(_merge(mine), cuts):
            spans.append((lo, hi, z))
    spans.sort(key=lambda s: s[0])
    out, seen = [], set()
    active: list[tuple[int, int, ZoneDef]] = []
    from .match import _unkey  # noqa: PLC0415
    for lo, hi, z in spans:
        active = [a for a in active if a[1] >= lo]
        for alo, ahi, az in active:
            if az.id != z.id and (az.id, z.id) not in seen and (z.id, az.id) not in seen:
                seen.add((az.id, z.id))
                a, b = max(lo, alo), min(hi, ahi)
                out.append({"a": az.name, "b": z.name, "example": f"{_unkey(a)}" + (f" – {_unkey(b)}" if a != b else ""), "resolved": az.priority != z.priority})
                if len(out) >= limit:
                    return out
        active.append((lo, hi, z))
    return out


# ------------------------------------------------------------------------------------------------ экспорт и пример
def export_rows(zones: list[Existing]) -> list[list[str]]:
    rows = []
    for z in sorted(zones, key=lambda z: z.name.lower()):
        rules = [(k, v) for k, v in z.rules]
        contacts = list(z.contacts)
        n = max(len(rules), len(contacts), 1)
        for i in range(n):
            k, v = rules[i] if i < len(rules) else ("", "")
            c = contacts[i] if i < len(contacts) else None
            rows.append([z.id, z.name, z.description if i == 0 else "", z.purpose if i == 0 else "", str(z.priority) if i == 0 else "", KIND_TITLE.get(k, "") if k else KIND_TITLE["net"], v, "",
                         c["name"] if c else "", c["position"] if c else "", c["email"] if c else "", ROLE_TITLE[c["role"]] if c else "",
                         ("да" if c["enabled"] else "нет") if c else ""])
    return rows


def to_csv(rows: list[list[str]], delimiter: str = ";") -> bytes:
    buf = io.StringIO(newline="")
    w = csv.writer(buf, delimiter=delimiter, lineterminator="\r\n")
    w.writerow(COLUMNS)
    for r in rows:
        w.writerow([safe_cell(c) for c in r])
    return ("﻿" + buf.getvalue()).encode("utf-8")      # BOM — чтобы Excel открыл кириллицу правильно


def sample_csv() -> bytes:
    """Полный пример: Департамент А — три сети и два ответственных; Департамент Б — пять сетей и общая почтовая группа; серверная — диапазон, группа KSC и исключение."""
    a = Existing("", "Департамент А", "Бухгалтерия и финансы", "Рабочие станции сотрудников", 100,
                 [("net", "192.0.2.0/26"), ("net", "192.0.2.64/26"), ("net", "192.0.2.128/26")],
                 [{"name": "Иван Петров", "position": "Начальник отдела ИТ", "email": "petrov@example.local", "role": "responsible", "enabled": True},
                  {"name": "Мария Сидорова", "position": "Руководитель департамента", "email": "sidorova@example.local", "role": "cc", "enabled": True}])
    b = Existing("", "Департамент Б", "Производство", "Рабочие станции и станки с ЧПУ", 100,
                 [("net", "198.51.100.0/27"), ("net", "198.51.100.32/27"), ("net", "198.51.100.64/27"), ("net", "198.51.100.96/27"), ("net", "198.51.100.128-198.51.100.200")],
                 [{"name": "Группа ИТ производства", "position": "", "email": "it-prod@example.local", "role": "group", "enabled": True}])
    c = Existing("", "Серверная инфраструктура", "Серверы и сервисы", "Контроль серверного парка", 10,
                 [("net", "203.0.113.0/28"), ("group", "Серверы*"), ("exclude", "203.0.113.5")],
                 [{"name": "Алексей Смирнов", "position": "Системный администратор", "email": "smirnov@example.local", "role": "responsible", "enabled": True}])
    return to_csv(export_rows([a, b, c]))
