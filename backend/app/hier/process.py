"""Раздел «Иерархия. Предприятие»: очистка выгрузки адресной книги и построение подчинения. Чистые функции без обращений к базе и сети — проверяются на данных.

Запись выгрузки — список из восьми полей (порядок как в ТЗ): Name, Email, JobTitle, Department, Company, Office, Manager, ManagerEmail. Выгрузка хранится как собрана
(без исправлений); правила очистки и таблица названий подразделений применяются при чтении, поэтому изменение правил действует сразу, без повторного сбора.

Порядок исключения: внешний адрес → пустая карточка → имя с «_» → служебная запись → повтор адреса; запись считается по первой сработавшей причине.
Связь с руководителем — по ManagerEmail; руководитель — он сам: верхний уровень; ManagerEmail пуст, а Manager заполнен — поиск по ФИО (только при единственном совпадении);
не найден или круг — группа «Руководитель в почте не указан» с причиной. Подразделение пусто — подразделение ближайшего вышестоящего, у которого оно заполнено («по руководителю»)."""
from __future__ import annotations

import hashlib
import re
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field

FIELDS = ("Name", "Email", "JobTitle", "Department", "Company", "Office", "Manager", "ManagerEmail")
NAME, EMAIL, TITLE, DEPT, COMPANY, OFFICE, MANAGER, MANAGER_EMAIL = range(8)
NO_DEPT = "Подразделение не указано"
EXCLUDE_RU = {"external": "внешний домен", "empty": "пустая карточка", "underscore": "имя с «_»", "service": "служебная учётная запись", "dup": "повтор адреса", "noaddr": "нет адреса"}
WHY_RU = {"": "", "self": "Руководитель верхнего уровня: в почте в поле «Руководитель» указан он сам.",
          "none": "В почте поле «Руководитель» не заполнено: структура не может показать, кому подчиняется сотрудник.",
          "text": "В почте указан руководитель только текстом, найти его в выгрузке не удалось.",
          "ambig": "В почте указан руководитель только текстом, и в выгрузке несколько человек с таким именем: выбрать нельзя.",
          "outside": "Руководитель указан адресом, которого нет среди сотрудников выгрузки (отключён, исключён или внешний адрес).",
          "cycle": "Подчинение образует круг: руководители указаны друг у друга, верх структуры не найден."}
DEFAULT_SERVICE_WORDS = ("служебная", "тестовая", "учётная запись", "робот")
DEFAULT_SERVICE_PREFIXES = ("support", "test", "svc", "noreply", "info", "admin")


def norm(s: str) -> str:
    """Для сравнения: без регистра, «ё» = «е», лишние пробелы убраны."""
    return re.sub(r"\s+", " ", (s or "").replace("ё", "е").replace("Ё", "Е").strip()).casefold()


def short_name(name: str) -> str:
    """«Фамилия И. О.»."""
    t = (name or "").split()
    return name if len(t) < 2 else t[0] + " " + " ".join(x[0].upper() + "." for x in t[1:3])


def person_id(email: str) -> str:
    """Стабильный идентификатор записи: от адреса, не зависит от порядка и снимка (ссылка #p<id> переживает обновления)."""
    return hashlib.sha1(email.strip().lower().encode()).hexdigest()[:10]


def hue(name: str) -> int:
    """Цвет подразделения — по названию, а не по номеру в списке: не меняется между снимками."""
    return zlib.crc32(norm(name).encode()) % 360


@dataclass
class Rules:
    domains: tuple[str, ...] = ()
    drop_empty: bool = True
    drop_underscore: bool = True
    drop_service: bool = True
    service_words: tuple[str, ...] = DEFAULT_SERVICE_WORDS
    service_prefixes: tuple[str, ...] = DEFAULT_SERVICE_PREFIXES
    name_lookup: bool = True
    dept_map: dict[str, str] = field(default_factory=dict)

    def signature(self) -> str:
        raw = repr((sorted(self.domains), self.drop_empty, self.drop_underscore, self.drop_service, self.service_words, self.service_prefixes, self.name_lookup, sorted(self.dept_map.items())))
        return hashlib.sha1(raw.encode()).hexdigest()[:16]


@dataclass
class Result:
    people: list[dict]                       # порядок = индексы в manager/kids
    depts: list[dict]                        # [{name, hue, n}] от больших к меньшим, «не указано» последним
    excluded: dict[str, int]
    raw_n: int
    heads: list[int]
    lone: list[int]
    cycles: list[list[int]]
    warnings: list[str]
    raw_depts: list[tuple[str, int]]         # как написано в почте → число людей (для таблицы соответствий)
    domains: list[tuple[str, int]]           # домены адресов выгрузки (подсказка для настройки внутренних доменов)

    def stats(self) -> dict:
        return {"raw": self.raw_n, "kept": len(self.people), "excluded": self.excluded, "heads": len(self.heads), "lone": len(self.lone), "cycles": sum(len(c) for c in self.cycles),
                "unresolved": sum(1 for p in self.people if p["why"] in ("text", "ambig", "outside"))}


def _domain_ok(email: str, domains: tuple[str, ...]) -> bool:
    if not domains:
        return True
    d = email.rsplit("@", 1)[-1]
    return any(d == x or d.endswith("." + x) for x in domains)


def _service(r: list[str], email: str, rules: Rules) -> bool:
    title = norm(r[TITLE])
    if any(norm(w) in title for w in rules.service_words if w.strip()):
        return True
    local = email.split("@", 1)[0]
    return any(local.startswith(p.strip().lower()) for p in rules.service_prefixes if p.strip())


def clean(records: list[list[str]], rules: Rules) -> tuple[list[list[str]], Counter]:
    """Оставшиеся записи (в порядке выгрузки) и число исключённых по причинам."""
    out: list[list[str]] = []
    why: Counter = Counter()
    seen: set[str] = set()
    domains = tuple(d.strip().lower().lstrip("@") for d in rules.domains if d.strip())
    for rec in records:
        r = [str(x or "").strip() for x in (list(rec) + [""] * 8)[:8]]
        email = r[EMAIL].lower()
        if not email or "@" not in email:
            why["noaddr"] += 1
        elif domains and not _domain_ok(email, domains):
            why["external"] += 1
        elif rules.drop_empty and not (r[TITLE] or r[DEPT] or r[MANAGER] or r[MANAGER_EMAIL]):
            why["empty"] += 1
        elif rules.drop_underscore and r[NAME].startswith("_"):
            why["underscore"] += 1
        elif rules.drop_service and _service(r, email, rules):
            why["service"] += 1
        elif email in seen:
            why["dup"] += 1
        else:
            seen.add(email)
            r[EMAIL] = email
            r[MANAGER_EMAIL] = r[MANAGER_EMAIL].lower()
            out.append(r)
    return out, why


def build(records: list[list[str]], rules: Rules) -> Result:
    kept, why = clean(records, rules)
    kept.sort(key=lambda r: (norm(r[NAME]), r[EMAIL]))
    n = len(kept)
    idx = {r[EMAIL]: i for i, r in enumerate(kept)}
    by_name: dict[str, list[int]] = defaultdict(list)
    for i, r in enumerate(kept):
        by_name[norm(r[NAME])].append(i)

    mgr = [-1] * n
    reason = [""] * n
    for i, r in enumerate(kept):                                        # руководитель
        me, mt = r[MANAGER_EMAIL], r[MANAGER]
        if me:
            if me == r[EMAIL]:
                reason[i] = "self"
            elif me in idx:
                mgr[i] = idx[me]
            else:
                reason[i] = "outside"
        elif mt:
            hits = [j for j in by_name.get(norm(mt), []) if j != i] if rules.name_lookup else []
            if len(hits) == 1:
                mgr[i] = hits[0]
            else:
                reason[i] = "ambig" if len(hits) > 1 else "text"
        else:
            reason[i] = "none"

    color = [0] * n                                                     # круги: у каждого не больше одного руководителя — обход цепочек
    cycles: list[list[int]] = []
    for s in range(n):
        if color[s]:
            continue
        path, v = [], s
        while v >= 0 and color[v] == 0:
            color[v] = 1
            path.append(v)
            v = mgr[v]
        if v >= 0 and color[v] == 1:
            cyc = path[path.index(v):]
            cycles.append(cyc)
        for u in path:
            color[u] = 2
    for cyc in cycles:
        for u in cyc:
            mgr[u], reason[u] = -1, "cycle"                             # круг разорван: верх не найден, люди круга — в группе «Руководитель в почте не указан»

    kids: list[list[int]] = [[] for _ in range(n)]
    for i, m in enumerate(mgr):
        if m >= 0:
            kids[m].append(i)
    heads = [i for i in range(n) if mgr[i] < 0 and reason[i] in ("self", "none") and kids[i]]
    size = [0] * n
    reach = [False] * n
    order: list[int] = []                                               # обход от верхних руководителей (без рекурсии: цепочки бывают длинными)
    stack = list(heads)
    for h in heads:
        reach[h] = True
    while stack:
        v = stack.pop()
        order.append(v)
        for k in kids[v]:
            if not reach[k]:
                reach[k] = True
                stack.append(k)
    for v in reversed(order):
        size[v] = 1 + sum(size[k] for k in kids[v] if reach[k])
    lone = [i for i in range(n) if not reach[i]]
    for k in range(n):
        kids[k].sort(key=lambda j: (-size[j], norm(kept[j][NAME])))
    heads.sort(key=lambda j: (-size[j], norm(kept[j][NAME])))

    dmap = {norm(k): v.strip() for k, v in rules.dept_map.items() if k.strip() and v.strip()}
    raw_dept = [r[DEPT] for r in kept]
    own = [dmap.get(norm(d), d) if d else "" for d in raw_dept]          # название «как показывать»; исходное значение остаётся в выгрузке

    def effective(i: int) -> tuple[str, bool]:
        if own[i]:
            return own[i], False
        j, guard = mgr[i], 0
        while j >= 0 and guard < 100:
            if own[j]:
                return own[j], True
            j, guard = mgr[j], guard + 1
        return NO_DEPT, False

    eff = [effective(i) for i in range(n)]
    cnt = Counter(e[0] for e in eff)
    names = sorted((d for d in cnt if d != NO_DEPT), key=lambda d: (-cnt[d], norm(d))) + ([NO_DEPT] if NO_DEPT in cnt else [])
    pos = {d: k for k, d in enumerate(names)}
    head_set = set(heads)
    people = []
    for i, r in enumerate(kept):
        people.append({"id": person_id(r[EMAIL]), "name": r[NAME], "email": r[EMAIL], "title": r[TITLE], "dept": pos[eff[i][0]], "inh": eff[i][1], "mgr": mgr[i], "mgr_text": r[MANAGER],
                       "self": reason[i] == "self", "why": reason[i] if mgr[i] < 0 else "", "reach": reach[i], "head": i in head_set, "size": size[i], "company": r[COMPANY], "office": r[OFFICE]})
    warnings = []
    if cycles:
        warnings.append(f"Круги в подчинении: {len(cycles)} (людей: {sum(len(c) for c in cycles)}). Например: " + " → ".join(short_name(kept[u][NAME]) for u in cycles[0][:6]) + (" → …" if len(cycles[0]) > 6 else ""))
    dom = Counter(r[EMAIL].rsplit("@", 1)[-1] for r in kept)
    return Result(people, [{"name": d, "hue": hue(d), "n": cnt[d]} for d in names], {EXCLUDE_RU[k]: v for k, v in why.items()}, len(records), heads, lone, cycles, warnings,
                  sorted(Counter(raw_dept[i] for i in range(n) if raw_dept[i]).items(), key=lambda x: (-x[1], x[0])), dom.most_common(8))


def content_hash(records: list[list[str]]) -> str:
    h = hashlib.sha1()
    for r in records:
        h.update("\x1f".join(str(x or "") for x in r).encode())
        h.update(b"\x1e")
    return h.hexdigest()
