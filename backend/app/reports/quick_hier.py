"""Отчёты раздела «Иерархия. Предприятие» (вид `quick_hier`, вид отчёта — параметр `view`):

* people — «Сотрудники и руководители»; tree — «Структура подчинения» (в HTML и PDF рисуется структура); chain — «Карточка и цепочка руководителей»;
* depts — «Подразделения» (+ различные написания названий); managers — «Руководители»; roles — «Должности и роль в иерархии»; crossdept — «Подразделения и подчинённость»;
* dups — «Дубликаты и подозрительные карточки»; service — «Служебные и неполные карточки» (в том числе что и почему исключено); quality — «Качество данных иерархии»;
* changes — «Изменения между выгрузками»; problems — «Руководитель не указан или не найден»; pack — все аналитические отчёты одной книгой (по вкладке на отчёт).

Режимы отбора — как на странице: вся организация, подразделение (`dept`), руководитель (`branch`: вся ветка или только непосредственные подчинённые — `direct`), поиск (`q`).
Все результаты проверок — «Требует проверки»: адресная книга Exchange не эталон штатной структуры, а правила (руководящие должности, порог группы) — настройки администратора.
Отчёт содержит персональные данные."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from ..hier import process as P
from ..hier import service as HS
from ..ksc.driver import KscError
from ..services.settings import HierSettings
from .quick import Ctx, col, metric

TITLE = {"people": "Сотрудники и руководители", "tree": "Структура подчинения", "chain": "Карточка и цепочка руководителей", "depts": "Подразделения", "managers": "Руководители",
         "roles": "Должности и роль в иерархии", "crossdept": "Подразделения и подчинённость", "dups": "Дубликаты и подозрительные карточки", "service": "Служебные и неполные карточки",
         "quality": "Качество данных иерархии", "changes": "Изменения между выгрузками", "problems": "Руководитель не указан или не найден", "pack": "Все отчёты по иерархии (книга)"}
PACK = ("depts", "managers", "roles", "crossdept", "dups", "service", "quality", "changes")
CHECK = "Требует проверки"
STATUS = {"self": "руководитель верхнего уровня (указан сам)", "none": "руководитель в почте не указан", "text": "руководитель указан текстом, в выгрузке не найден", "ambig": "имя руководителя неоднозначно",
          "outside": "руководитель вне выгрузки (отключён или внешний адрес)", "cycle": "круг в подчинении"}
CHAIN_CAP = 25                  # длина столбца «цепочка»: предел против выгрузок с цепочками в тысячи уровней; прямой руководитель и верхний — отдельными столбцами
EXCLUDE_WHY = {"external": "Адрес вне внутренних доменов", "empty": "Нет ни должности, ни подразделения, ни руководителя", "underscore": "Имя начинается с «_»",
               "service": "Совпало правило служебной записи", "dup": "Адрес уже есть в структуре (повтор)", "noaddr": "Нет адреса почты"}
DEPT_NOISE = {"отдел", "департамент", "управление", "служба", "группа", "центр", "сектор", "дирекция", "и", "по", "в", "на"}
PERSON = re.compile(r"^[A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё\-.']*$")


@dataclass
class L:                                         # раскладка структуры: обход сверху вниз, уровни, размеры и высота веток
    order: list[int]
    level: list[int]
    sub: list[int]
    height: list[int]
    kids: list[list[int]]
    direct: list[int]


def _layout(res: P.Result) -> L:
    people = res.people
    n = len(people)
    kids: list[list[int]] = [[] for _ in range(n)]
    for i, x in enumerate(people):
        if x["mgr"] >= 0:
            kids[x["mgr"]].append(i)
    key = lambda j: (-people[j]["size"], P.norm(people[j]["name"]))      # noqa: E731
    for k in kids:
        k.sort(key=key)
    roots = list(res.heads) + sorted((i for i in range(n) if people[i]["mgr"] < 0 and not people[i]["head"]), key=lambda j: P.norm(people[j]["name"]))
    order, level, stack = [], [0] * n, [(r, 0) for r in reversed(roots)]
    while stack:                                                            # без рекурсии: цепочки бывают длинными
        v, lv = stack.pop()
        order.append(v)
        level[v] = lv
        stack += [(k, lv + 1) for k in reversed(kids[v])]
    sub, height = [1] * n, [1] * n
    for v in reversed(order):
        m = people[v]["mgr"]
        if m >= 0:
            sub[m] += sub[v]
            height[m] = max(height[m], height[v] + 1)
    return L(order, level, sub, height, kids, [len(k) for k in kids])


def _select(res: P.Result, p: dict, lay: L, with_parents: bool) -> tuple[list[int], list[dict]]:
    people = res.people
    keep = set(range(len(people)))
    cond = []
    if p.get("branch") and p.get("view") != "chain":
        top = next((i for i, x in enumerate(people) if x["id"] == p["branch"]), None)
        if top is None:
            raise KscError("params", "Сотрудник для ветки не найден в последней выгрузке")
        if p.get("direct"):
            sub = {top, *lay.kids[top]}
        else:
            sub, stack = set(), [top]
            while stack:
                v = stack.pop()
                sub.add(v)
                stack += lay.kids[v]
        keep &= sub
        cond.append({"label": "Руководитель", "text": f"{people[top]['name']}: " + ("он сам и непосредственные подчинённые" if p.get("direct") else "он сам и вся его ветка подчинения")})
    names = [d["name"] for d in res.depts]
    if p.get("dept"):
        keep &= {i for i, x in enumerate(people) if names[x["dept"]] == p["dept"]}
        cond.append({"label": "Подразделение", "text": p["dept"] + " (в выгрузке нет дерева подразделений: вложенные подразделения не выделяются)"})
    if p.get("q"):
        t = p["q"].strip().casefold()
        keep &= {i for i, x in enumerate(people) if t in f"{x['name']} {x['title']} {x['email']} {names[x['dept']]}".casefold()}
        cond.append({"label": "Поиск", "text": f"«{p['q'].strip()}»"})
    if not cond:
        cond.append({"label": "Охват", "text": "вся организация: все сотрудники текущей структуры"})
    if with_parents and len(keep) < len(people):                            # в дереве у выбранных остаются вышестоящие руководители: иначе ветка теряет связность
        for i in list(keep):
            j, guard = people[i]["mgr"], 0
            while j >= 0 and j not in keep and guard < len(people):
                keep.add(j)
                j, guard = people[j]["mgr"], guard + 1
        cond.append({"label": "Вышестоящие", "text": "добавлены руководители выбранных людей, чтобы структура осталась связной"})
    return [i for i in lay.order if i in keep], cond


def _origin(x: dict, depts: list[str]) -> str:
    return "Определено по руководителю" if x["inh"] else ("Не определено" if depts[x["dept"]] == P.NO_DEPT else "Из карточки")


def _status(x: dict) -> str:
    if x["head"]:
        return "верхний руководитель"
    if x["reach"]:
        return "в структуре"
    return STATUS.get(x["why"]) or "подчинён сотруднику, у которого руководитель в почте не найден"


def _hits(title: str, words) -> list[str]:
    t = P.norm(title)
    return [w for w in words if P.norm(w) and P.norm(w) in t]


def _dkey(raw: str) -> str:
    toks = [w for w in re.split(r"[^0-9a-zа-я]+", P.norm(raw)) if w and w not in DEPT_NOISE]
    return " ".join(sorted(toks))


class X:
    """Всё, что нужно видам отчёта: результат очистки, раскладка, выбранные люди и настройки правил."""

    def __init__(self, res: P.Result, p: dict, cfg: HierSettings, ids: list[int], lay: L, ext: dict):
        self.res, self.p, self.cfg, self.ids, self.lay, self.ext = res, p, cfg, ids, lay, ext
        self.people = res.people
        self.depts = [d["name"] for d in res.depts]
        self.chosen = set(ids)
        self.top_of: dict[int, int] = {}
        self.lead_words = [w for w in cfg.lead_words if P.norm(w)]
        self.non_words = [w for w in cfg.nonlead_words if P.norm(w)]

    def top(self, i: int) -> int:
        path, v = [], i
        while v not in self.top_of and self.people[v]["mgr"] >= 0:
            path.append(v)
            v = self.people[v]["mgr"]
        t = self.top_of.get(v, v)
        for u in path:
            self.top_of[u] = t
        return t

    def chain(self, i: int) -> str:
        names, v = [], self.people[i]["mgr"]
        while v >= 0 and len(names) <= CHAIN_CAP:
            names.append(P.short_name(self.people[v]["name"]))
            v = self.people[v]["mgr"]
        return ("… → " if v >= 0 else "") + " → ".join(reversed(names[:CHAIN_CAP]))

    def d(self, i: int) -> str:
        return self.depts[self.people[i]["dept"]]

    def row(self, i: int) -> dict:
        x, lay = self.people[i], self.lay
        m = self.people[x["mgr"]] if x["mgr"] >= 0 else None
        return {"name": x["name"], "title": x["title"], "dept": self.d(i), "dept_origin": _origin(x, self.depts), "email": x["email"], "company": x["company"], "office": x["office"],
                "manager": m["name"] if m else (x["mgr_text"] if x["mgr_text"] and x["mgr_text"] != x["name"] else ""), "manager_email": m["email"] if m else "",
                "top": self.people[self.top(i)]["name"] if x["mgr"] >= 0 else "", "level": lay.level[i] + 1 if x["reach"] else None, "direct": lay.direct[i], "branch": lay.sub[i] - 1,
                "chain": self.chain(i), "status": _status(x)}


# ------------------------------------------------------------------------------------------------ виды
def _t_people(x: X, view: str) -> tuple[list[dict], list[str]]:
    ids, lay = x.ids, x.lay
    rows = [x.row(i) for i in ids]
    cols = [col("name", "Сотрудник"), col("title", "Должность"), col("dept", "Подразделение"), col("dept_origin", "Происхождение подразделения"), col("email", "Рабочая почта"), col("manager", "Руководитель"),
            col("top", "Верхний руководитель"), col("level", "Уровень", "num"), col("direct", "Прямых подчинённых", "num"), col("branch", "Всего в ветке", "num"), col("chain", "Цепочка руководителей"),
            col("status", "Положение в структуре"), col("company", "Компания"), col("office", "Офис")]
    if view == "tree":
        for r, i in zip(rows, ids):
            r["name"] = "  " * min(lay.level[i], 12) + ("└ " if lay.level[i] else "") + r["name"]
        cols = [col("name", "Сотрудник"), col("title", "Должность"), col("dept", "Подразделение"), col("level", "Уровень", "num"), col("direct", "Прямых подчинённых", "num"), col("branch", "Всего в ветке", "num"), col("email", "Рабочая почта")]
    return [{"id": "rows", "title": TITLE[view], "columns": cols, "rows": rows,
             "note": "Одна строка — сотрудник; порядок — сверху вниз по подчинению." if view == "tree" else "Одна строка — сотрудник. Уровень 1 — верхний руководитель."}], []


def _t_chain(x: X) -> tuple[list[dict], list[str]]:
    top = next((i for i, q in enumerate(x.people) if q["id"] == x.p.get("branch")), None)
    if top is None:
        raise KscError("params", "Для карточки укажите сотрудника (ссылка из карточки на странице)")
    path, v = [], top
    while v >= 0 and len(path) < 500:
        path.append(v)
        v = x.people[v]["mgr"]
    rows = []
    for k, i in enumerate(reversed(path), 1):
        r = x.row(i)
        r["role"] = "сотрудник" if i == top else ("верхний руководитель" if x.people[i]["mgr"] < 0 else "руководитель")
        r["step"] = k
        rows.append(r)
    cols = [col("step", "№", "num"), col("role", "Роль в цепочке"), col("name", "ФИО"), col("title", "Должность"), col("dept", "Подразделение"), col("dept_origin", "Происхождение подразделения"), col("email", "Рабочая почта"),
            col("direct", "Прямых подчинённых", "num"), col("branch", "Всего в ветке", "num"), col("status", "Положение в структуре")]
    return [{"id": "rows", "title": TITLE["chain"], "columns": cols, "rows": rows, "note": "Сверху вниз: от верхнего руководителя до выбранного сотрудника."}], []


def _variants(x: X) -> dict:
    """Различные написания названий, которые потенциально относятся к одному подразделению. Не объединяются автоматически: подтверждает администратор (таблица названий подразделений)."""
    cnt = Counter(x.people[i]["raw_dept"] for i in x.ids if x.people[i]["raw_dept"])
    dmap = {P.norm(k): v.strip() for k, v in x.cfg.dept_map.items() if k.strip() and v.strip()}
    groups: dict[str, list[str]] = defaultdict(list)
    for raw in cnt:
        groups[_dkey(raw) or P.norm(raw)].append(raw)
    rows = []
    for raws in groups.values():
        if len(raws) < 2:
            continue
        shown = {dmap.get(P.norm(r), r) for r in raws}
        done = len(shown) == 1
        rows.append({"spellings": "; ".join(f"{r} ({cnt[r]})" for r in sorted(raws, key=lambda r: -cnt[r])), "variants": len(raws), "n": sum(cnt[r] for r in raws), "shown": "; ".join(sorted(shown)),
                     "state": "Подтверждено администратором: показываются как «" + next(iter(shown)) + "»" if done else CHECK + ": в интерфейсе это разные подразделения",
                     "todo": "" if done else "Если это одно подразделение — добавьте соответствие: Администрирование → Иерархия предприятия → Названия подразделений"})
    rows.sort(key=lambda r: (r["state"].startswith("Подтверждено"), -r["n"]))
    return {"id": "variants", "title": "Различные написания названий подразделений", "rows": rows, "note": "Группы похожих названий (без учёта регистра, слов «отдел/департамент/управление…» и порядка слов). Автоматически не объединяются.",
            "columns": [col("spellings", "Написания (число сотрудников)"), col("variants", "Написаний", "num"), col("n", "Сотрудников", "num"), col("shown", "Как показываются сейчас"), col("state", "Состояние"), col("todo", "Что сделать")]}


def _t_depts(x: X) -> tuple[list[dict], list[str]]:
    people, lay = x.people, x.lay
    lead: dict[int, int] = {}
    for i in x.ids:
        q = people[i]
        if q["mgr"] < 0 or people[q["mgr"]]["dept"] != q["dept"]:
            if q["dept"] not in lead or lay.sub[i] > lay.sub[lead[q["dept"]]]:
                lead[q["dept"]] = i
    rows = []
    for k, name in enumerate(x.depts):
        mem = [i for i in x.ids if people[i]["dept"] == k]
        if not mem:
            continue
        ld = lead.get(k)
        has = ld is not None and lay.sub[ld] > 1
        org = Counter(_origin(people[i], x.depts) for i in mem)
        sp = Counter(people[i]["raw_dept"] for i in mem if people[i]["raw_dept"])
        rows.append({"dept": name, "n": len(mem), "leaders": sum(1 for i in mem if lay.direct[i]), "lead": people[ld]["name"] if has else "не определён", "lead_title": people[ld]["title"] if has else "",
                     "lead_direct": lay.direct[ld] if has else 0, "lead_nested": lay.sub[ld] - 1 - lay.direct[ld] if has else 0, "card": org["Из карточки"], "inherited": org["Определено по руководителю"],
                     "undef": org["Не определено"], "spellings": "; ".join(f"{r} ({c})" for r, c in sp.most_common()) if len(sp) > 1 or any(r != name for r in sp) else "", "lone": sum(1 for i in mem if not people[i]["reach"])})
    cols = [col("dept", "Подразделение"), col("n", "Сотрудников", "num"), col("leaders", "Из них с подчинёнными", "num"), col("lead", "Руководитель подразделения"), col("lead_title", "Должность руководителя"),
            col("lead_direct", "Его непосредственных подчинённых", "num"), col("lead_nested", "Вложенных подчинённых", "num"), col("card", "Подразделение из карточки", "num"), col("inherited", "Определено по руководителю", "num"),
            col("undef", "Не определено", "num"), col("lone", "Без руководителя в почте", "num"), col("spellings", "Написания в почте")]
    return [{"id": "rows", "title": TITLE["depts"], "columns": cols, "rows": rows,
             "note": "Руководитель подразделения — человек с самой большой веткой среди тех, чей руководитель вне подразделения."}, _variants(x)], [
        "Названия не объединяются автоматически: похожие написания показаны отдельной таблицей и ждут решения администратора."]


def _t_managers(x: X) -> tuple[list[dict], list[str]]:
    people, lay, big = x.people, x.lay, x.cfg.big_group
    rows = []
    for i in x.ids:
        if not lay.direct[i]:
            continue
        q = people[i]
        fl = []
        if lay.direct[i] > big:
            fl.append(f"большая группа: {lay.direct[i]} непосредственных (порог {big})")
            if sum(1 for k in lay.kids[i] if not lay.direct[k]) >= 0.9 * lay.direct[i]:
                fl.append("плоская группа: у почти всех подчинённых нет своих — возможно, нет промежуточных звеньев")
        if _hits(q["title"], x.non_words) and not _hits(q["title"], x.lead_words):
            fl.append("должность обычно неруководящая")
        if lay.direct[i] >= 3 and sum(1 for k in lay.kids[i] if people[k]["dept"] != q["dept"]) * 2 >= lay.direct[i]:
            fl.append("половина и более подчинённых — из других подразделений")
        if not q["reach"]:
            fl.append("руководитель сам вне структуры: " + _status(q))
        rows.append({**x.row(i), "depth": lay.height[i] - 1, "flags": "; ".join(fl), "verdict": CHECK if fl else "в пределах нормы"})
    rows.sort(key=lambda r: (-r["direct"], r["name"]))
    cols = [col("name", "Руководитель"), col("title", "Должность"), col("dept", "Подразделение"), col("direct", "Непосредственных подчинённых", "num"), col("branch", "Всего в ветке", "num"), col("depth", "Глубина ветки (уровней ниже)", "num"),
            col("level", "Уровень в структуре", "num"), col("manager", "Его руководитель"), col("flags", "Основание проверки"), col("verdict", "Вывод"), col("email", "Рабочая почта")]
    return [{"id": "rows", "title": TITLE["managers"], "columns": cols, "rows": rows, "note": "Сортировка — по числу непосредственных подчинённых. Большая группа — повод для проверки, а не установленная ошибка."}], [
        f"Порог большой группы — {big} непосредственных подчинённых (настройка «Иерархия предприятия»); признаки «плоская группа» и «возможно нет промежуточных звеньев» — подсказки, не выводы."]


def _t_roles(x: X) -> tuple[list[dict], list[str]]:
    people, lay = x.people, x.lay
    rows = []
    for i in x.ids:
        q = people[i]
        if not q["title"]:
            continue
        lead, non = _hits(q["title"], x.lead_words), _hits(q["title"], x.non_words)
        if lead and not lay.direct[i]:
            f, b = "Должность предполагает руководство, подчинённых в выгрузке нет", "слово в должности: " + ", ".join(f"«{w}»" for w in lead)
        elif non and not lead and lay.direct[i]:
            f, b = "Есть подчинённые, должность обычно неруководящая", "слово в должности: " + ", ".join(f"«{w}»" for w in non)
        else:
            continue
        rows.append({"finding": f, "basis": b, "name": q["name"], "title": q["title"], "dept": x.d(i), "email": q["email"], "direct": lay.direct[i], "branch": lay.sub[i] - 1, "manager": x.row(i)["manager"], "status": CHECK})
    rows.sort(key=lambda r: (r["finding"], r["name"]))
    cols = [col("finding", "Что обнаружено"), col("basis", "Основание"), col("name", "Сотрудник"), col("title", "Должность"), col("dept", "Подразделение"), col("direct", "Подчинённых", "num"), col("manager", "Руководитель"),
            col("status", "Вывод"), col("email", "Рабочая почта")]
    return [{"id": "rows", "title": TITLE["roles"], "columns": cols, "rows": rows, "note": "Должность и подчинённые в почте могут не совпадать по законным причинам: все строки — «Требует проверки»."}], [
        "Руководящие и неруководящие должности определяются словами из настроек раздела («Иерархия предприятия»): " + ", ".join(x.lead_words) + " / " + ", ".join(x.non_words) + "."]


def _t_cross(x: X) -> tuple[list[dict], list[str]]:
    people = x.people
    pairs: Counter = Counter()
    other: Counter = Counter()
    cand = []
    for i in x.ids:
        q = people[i]
        m = q["mgr"]
        if m < 0 or q["inh"] or people[m]["inh"] or x.d(i) == P.NO_DEPT or x.d(m) == P.NO_DEPT or q["dept"] == people[m]["dept"]:
            continue
        cand.append(i)
        pairs[(q["dept"], people[m]["dept"])] += 1
        other[m] += 1
    seen = set(x.cfg.reviewed)
    rows, hidden = [], 0
    for i in cand:
        q = people[i]
        m = q["mgr"]
        rev = q["id"] in seen
        if rev and not x.p.get("include_reviewed"):
            hidden += 1
            continue
        rows.append({"name": q["name"], "title": q["title"], "dept": x.d(i), "manager": people[m]["name"], "manager_title": people[m]["title"], "manager_dept": x.d(m), "pair_n": pairs[(q["dept"], people[m]["dept"])],
                     "mgr_other": other[m], "reviewed": "да" if rev else "нет", "status": "Проверено, исключение" if rev else CHECK, "email": q["email"]})
    rows.sort(key=lambda r: (-r["pair_n"], r["dept"], r["name"]))
    cols = [col("name", "Сотрудник"), col("title", "Должность"), col("dept", "Подразделение сотрудника"), col("manager", "Руководитель"), col("manager_title", "Должность руководителя"), col("manager_dept", "Подразделение руководителя"),
            col("pair_n", "Таких пар «подразделение — подразделение руководителя»", "num"), col("mgr_other", "Подчинённых этого руководителя из других подразделений", "num"), col("reviewed", "Проверено"), col("status", "Вывод"), col("email", "Рабочая почта")]
    notes = ["Сравниваются только подразделения, указанные в карточках (подставленные по руководителю не сравниваются). Много одинаковых пар — признак нормального функционального или матричного подчинения; единичные — повод для проверки."]
    if hidden:
        notes.append(f"Скрыто как проверенные исключения: {hidden}. Показать их — «Включить проверенные исключения».")
    return [{"id": "rows", "title": TITLE["crossdept"], "columns": cols, "rows": rows, "note": "Одна строка — сотрудник, подчинённый руководителю из другого подразделения. Исключение отмечается в карточке сотрудника."}], notes


def _t_dups(x: X) -> tuple[list[dict], list[str]]:
    people = x.people
    rows = []
    by: dict[str, list[int]] = defaultdict(list)
    for i, q in enumerate(people):
        by[P.norm(q["name"])].append(i)
    for grp in by.values():
        if len(grp) < 2:
            continue
        for i in (g for g in grp if g in x.chosen):
            same = [j for j in grp if j != i]
            ev = [w for w, f in (("должность", lambda j: people[j]["title"] == people[i]["title"] and people[i]["title"]), ("подразделение", lambda j: x.d(j) == x.d(i))) if any(f(j) for j in same)]
            rows.append({"basis": f"Одинаковое ФИО у {len(grp)} сотрудников" + (f"; совпадают также: {', '.join(ev)}" if ev else "; должность и подразделение различаются"), "name": people[i]["name"], "email": people[i]["email"],
                         "title": people[i]["title"], "dept": x.d(i), "group_n": len(grp), "others": "; ".join(people[j]["email"] for j in same), "status": CHECK})
    idx = {q["email"]: i for i, q in enumerate(people)}
    t = (x.p.get("q") or "").strip().casefold()
    for rec, why in x.res.dropped:
        if why == "dup" and (not t or t in " ".join(rec).casefold()):
            k = idx.get(rec[P.EMAIL])
            rows.append({"basis": "Повторяющийся адрес: вторая запись с тем же адресом исключена", "name": rec[P.NAME], "email": rec[P.EMAIL], "title": rec[P.TITLE], "dept": rec[P.DEPT],
                         "group_n": 2, "others": f"в структуре: {people[k]['name']}" if k is not None else "", "status": CHECK})
    for i in x.ids:
        q = people[i]
        why = []
        if q["why"] == "ambig":
            why.append("ФИО руководителя из почты совпадает у нескольких сотрудников: руководитель не выбран")
        if len(q["name"].split()) < 2:
            why.append("ФИО из одного слова")
        if re.search(r"\d", q["name"]):
            why.append("в ФИО есть цифры")
        if not q["title"] and not q["raw_dept"] and not q["mgr_text"]:
            why.append("нет должности, подразделения и руководителя")
        rows += [{"basis": w, "name": q["name"], "email": q["email"], "title": q["title"], "dept": x.d(i), "group_n": 1, "others": "", "status": CHECK} for w in why]
    cols = [col("basis", "Основание проверки"), col("name", "ФИО"), col("email", "Рабочая почта"), col("title", "Должность"), col("dept", "Подразделение"), col("group_n", "Записей в группе", "num"), col("others", "Другие адреса / записи"), col("status", "Вывод")]
    return [{"id": "rows", "title": TITLE["dups"], "columns": cols, "rows": rows, "note": "Основание проверки — признак, а не вывод: одинаковые ФИО сами по себе не означают одного человека."}], []


def _service_hit(rec: list[str], words, prefixes) -> str:
    out = [f"слово «{w}» в должности" for w in _hits(rec[P.TITLE], words)]
    local = rec[P.EMAIL].split("@", 1)[0].lower()
    return "; ".join(out + [f"адрес начинается с «{pr}»" for pr in prefixes if pr.strip() and local.startswith(pr.strip().lower())])


def _looks_person(rec: list[str], cfg: HierSettings) -> bool:
    toks = rec[P.NAME].split()
    return len(toks) >= 2 and all(PERSON.match(t) for t in toks) and not _hits(rec[P.NAME], cfg.service_words)


def _t_service(x: X) -> tuple[list[dict], list[str]]:
    people, cfg = x.people, x.cfg
    q = (x.p.get("q") or "").strip().casefold()
    rows = []
    reasons: Counter = Counter()
    for rec, why in x.res.dropped:
        if q and q not in " ".join(rec).casefold():
            continue
        det = EXCLUDE_WHY[why]
        if why == "service":
            det += ": " + (_service_hit(rec, cfg.service_words, cfg.service_prefixes) or "по правилам")
        if why == "external" and "@" in rec[P.EMAIL]:
            det += f" (домен {rec[P.EMAIL].rsplit('@', 1)[-1]})"
        lp = _looks_person(rec, cfg)
        reasons[(why, lp)] += 1
        rows.append({"kind": "Исключена из структуры", "reason": EXCLUDE_WHY[why], "explain": det, "name": rec[P.NAME], "email": rec[P.EMAIL], "title": rec[P.TITLE], "dept": rec[P.DEPT], "manager": rec[P.MANAGER],
                     "person": "да — проверьте" if lp else "нет", "status": CHECK if lp and why in ("external", "empty", "underscore") else "исключена по правилу"})
    for i in x.ids:
        r = people[i]
        miss = []
        if not r["title"]:
            miss.append("должность")
        if not r["raw_dept"]:
            miss.append("подразделение" + (f" (подставлено «{x.d(i)}» по руководителю)" if r["inh"] else ""))
        if r["why"] in ("none", "text", "ambig", "outside", "cycle"):
            miss.append("руководитель: " + STATUS[r["why"]])
        if miss:
            rows.append({"kind": "Включена, неполная", "reason": "В структуре, но не хватает данных", "explain": "не хватает: " + ", ".join(miss), "name": r["name"], "email": r["email"], "title": r["title"],
                         "dept": r["raw_dept"], "manager": r["mgr_text"], "person": "да", "status": CHECK})
    by = [{"reason": EXCLUDE_WHY[w], "person": "похоже на сотрудника" if lp else "служебная или не человек", "n": n} for (w, lp), n in sorted(reasons.items(), key=lambda kv: -kv[1])]
    cols = [col("kind", "Запись"), col("reason", "Причина"), col("explain", "Пояснение"), col("name", "ФИО / название"), col("email", "Почта"), col("title", "Должность"), col("dept", "Подразделение (как в почте)"),
            col("manager", "Руководитель (как в почте)"), col("person", "Похоже на сотрудника"), col("status", "Вывод")]
    return [{"id": "rows", "title": TITLE["service"], "columns": cols, "rows": rows, "note": "Исключённые записи и включённые с пропусками. «Похоже на сотрудника» — по виду ФИО (два слова и больше, только буквы): подсказка для ручной проверки."},
            {"id": "by_reason", "title": "Из чего состоит исключение", "rows": by, "columns": [col("reason", "Причина исключения"), col("person", "Вид записи"), col("n", "Записей", "num")],
             "note": "Всего исключено: " + str(len(x.res.dropped))}], ["Правила исключения (внутренние домены, служебные слова и префиксы) меняются в настройках раздела; изменение действует сразу, без повторного сбора."]


def _t_quality(x: X) -> tuple[list[dict], list[str]]:
    people, res, ids = x.people, x.res, x.ids
    rows: list[dict] = []
    todo = {s.rsplit(" (", 1)[0] for r in _variants(x)["rows"] if not r["state"].startswith("Подтверждено") for s in r["spellings"].split("; ")}
    full, ocnt = 0, Counter()
    for i in ids:
        q = people[i]
        o = _origin(q, x.depts)
        ocnt[o] += 1
        before = len(rows)
        found: list[tuple[str, str]] = []
        if q["why"] == "none":
            found.append(("Руководитель не указан", "поле «Руководитель» в почте пусто"))
        elif q["why"] in ("text", "ambig", "outside"):
            found.append(("Руководитель не найден", STATUS[q["why"]]))
        elif q["why"] == "cycle":
            found.append(("Круг в подчинении", "руководители указаны друг у друга"))
        elif not q["reach"] and q["mgr"] >= 0:
            found.append(("Разорванная цепочка", "цепочка руководителей не доходит до верхнего уровня"))
        if not q["title"]:
            found.append(("Нет должности", "поле «Должность» пусто"))
        if not q["raw_dept"]:
            found.append(("Нет подразделения в карточке", f"подставлено: «{x.d(i)}»" + (" (по руководителю)" if q["inh"] else "")))
        if q["raw_dept"] and q["raw_dept"] in todo:
            found.append(("Подразделение не подтверждено", "есть похожие написания: решение администратора ещё не принято"))
        rows += [{"issue": a, "details": b, "name": q["name"], "email": q["email"], "title": q["title"], "dept": x.d(i), "origin": o} for a, b in found]
        full += 0 if len(rows) > before else 1
    ex = Counter(P.EXCLUDE_RU[why] for _r, why in res.dropped)
    n = len(ids)
    ic = Counter(r["issue"] for r in rows)
    sm = [("Записей в адресной книге", res.raw_n, "всё, что получено из каталога"), ("Включено в структуру", len(people), "после очистки"), ("В отчёте (с учётом фильтров)", n, "")]
    sm += [(f"Исключено: {k}", v, "") for k, v in sorted(ex.items(), key=lambda kv: -kv[1])]
    sm += [("Карточек заполнено полностью", full, "должность, подразделение в карточке, руководитель найден"), ("Карточек с пропусками", n - full, ""),
           ("Подразделение: из карточки", ocnt["Из карточки"], ""), ("Подразделение: определено по руководителю", ocnt["Определено по руководителю"], "значение восстановлено; пустое поле в карточке остаётся замечанием"),
           ("Подразделение: не определено", ocnt["Не определено"], ""), ("Без связи с основной структурой", sum(1 for i in ids if not people[i]["reach"]), "")]
    sm += [(f"Замечаний: {k}", v, "") for k, v in sorted(ic.items(), key=lambda kv: -kv[1])]
    cols = [col("issue", "Замечание"), col("details", "Подробности"), col("name", "Сотрудник"), col("title", "Должность"), col("dept", "Подразделение"), col("origin", "Происхождение подразделения"), col("email", "Рабочая почта")]
    return [{"id": "rows", "title": "Замечания по карточкам", "columns": cols, "rows": rows, "note": "Одна строка — замечание по карточке (у одной карточки их может быть несколько)."},
            {"id": "summary", "title": "Сводка по состоянию исходных данных", "columns": [col("metric", "Показатель"), col("value", "Значение", "num"), col("hint", "Пояснение")],
             "rows": [{"metric": a, "value": b, "hint": c} for a, b, c in sm], "note": ""}], [
        "Сверка с Active Directory и кадровыми данными не выполняется: адресная книга Exchange не является эталоном штатной структуры, а надёжного кадрового источника в продукте нет."]


def _t_changes(x: X) -> tuple[list[dict], list[str]]:
    base = x.ext.get("base")
    if not base:
        raise KscError("no_data", "Нет предыдущей выгрузки для сравнения: нужны два успешных снимка.")
    old, old_at = base
    new = x.res
    o = {q["email"]: q for q in old.people}
    cur = {q["email"]: i for i, q in enumerate(new.people)}
    raw_new = x.ext.get("raw_emails") or set()
    note = "Изменение данных Exchange, а не кадровое событие"

    def mg(res: P.Result, q: dict) -> str:
        return res.people[q["mgr"]]["name"] if q["mgr"] >= 0 else (q["mgr_text"] or "")

    def dp(res: P.Result, q: dict) -> str:
        return res.depts[q["dept"]]["name"] + (" (по руководителю)" if q["inh"] else "")

    rows, moved = [], []
    for e, i in cur.items():
        q = new.people[i]
        a = o.get(e)
        if a is None:
            rows.append({"kind": "Появилась карточка", "name": q["name"], "email": e, "old": "", "new": f"{q['title']} · {dp(new, q)}", "note": note + ": новая запись в адресной книге или карточка стала проходить правила очистки"})
            continue
        if mg(old, a) != mg(new, q):
            rows.append({"kind": "Изменился руководитель", "name": q["name"], "email": e, "old": mg(old, a), "new": mg(new, q), "note": note})
            if x.lay.direct[i]:
                moved.append({"kind": "Перемещена ветка", "name": q["name"], "email": e, "old": mg(old, a), "new": mg(new, q), "note": f"{x.lay.sub[i] - 1} человек в ветке переходят вместе с руководителем; {note}"})
        if a["raw_dept"] != q["raw_dept"] or dp(old, a) != dp(new, q):
            rows.append({"kind": "Изменилось подразделение", "name": q["name"], "email": e, "old": dp(old, a), "new": dp(new, q), "note": note})
        if a["title"] != q["title"]:
            rows.append({"kind": "Изменилась должность", "name": q["name"], "email": e, "old": a["title"], "new": q["title"], "note": note})
    for e, a in o.items():
        if e not in cur:
            still = e in raw_new
            rows.append({"kind": "Исключена правилами очистки" if still else "Исчезла карточка", "name": a["name"], "email": e, "old": f"{a['title']} · {dp(old, a)}", "new": "",
                         "note": note + (": карточка в выгрузке есть, но сейчас исключена правилами" if still else ": карточки нет в адресной книге; это не означает увольнение")})
    rows = moved + rows
    cnt = Counter(r["kind"] for r in rows)
    cols = [col("kind", "Изменение"), col("name", "Сотрудник"), col("old", "Было"), col("new", "Стало"), col("email", "Рабочая почта"), col("note", "Примечание")]
    summ = [{"metric": k, "value": v, "hint": ""} for k, v in sorted(cnt.items(), key=lambda kv: -kv[1])] or [{"metric": "Различий нет", "value": 0, "hint": ""}]
    return [{"id": "rows", "title": TITLE["changes"], "columns": cols, "rows": rows, "note": f"Сравнение выгрузки от {old_at:%d.%m.%Y %H:%M} UTC с текущей."},
            {"id": "summary", "title": "Сводка изменений", "columns": [col("metric", "Изменение"), col("value", "Записей", "num"), col("hint", "Пояснение")], "rows": summ, "note": ""}], [
        "Исчезновение карточки из адресной книги — изменение данных Exchange, а не увольнение. История ограничена сроком хранения снимков (настройка «Срок хранения»)."]


def _t_problems(x: X) -> tuple[list[dict], list[str]]:
    lone = [i for i in x.ids if not x.people[i]["reach"]]
    rows = [{**x.row(i), "why": P.WHY_RU.get(x.people[i]["why"]) or "Руководитель этого сотрудника сам не имеет руководителя в почте."} for i in lone]
    cols = [col("name", "Сотрудник"), col("title", "Должность"), col("dept", "Подразделение"), col("email", "Рабочая почта"), col("manager", "Руководитель по записи в почте"), col("why", "Почему не в структуре"), col("branch", "Подчинённых", "num")]
    return [{"id": "rows", "title": TITLE["problems"], "columns": cols, "rows": rows, "note": "Людям из этого списка нужно заполнить поле «Руководитель» в почтовой карточке."}], []


VIEWS = {"depts": _t_depts, "managers": _t_managers, "roles": _t_roles, "crossdept": _t_cross, "dups": _t_dups, "service": _t_service, "quality": _t_quality, "changes": _t_changes, "problems": _t_problems}


def build_doc(res: P.Result, p: dict, snap_at, source: str, cfg: HierSettings | None = None, ext: dict | None = None) -> dict:
    view = p.get("view") or "people"
    if view not in TITLE:
        raise KscError("params", "Неизвестный вид отчёта «Иерархия»")
    lay = _layout(res)
    ids, cond = _select(res, {**p, "view": view}, lay, view == "tree")
    x = X(res, p, cfg or HierSettings(), ids, lay, ext or {})
    people = res.people
    chosen = set(ids)
    lone = [i for i in ids if not people[i]["reach"]]
    notes = ["Структура построена по адресной книге почты на дату выгрузки: подчинение — как указано в карточках сотрудников («Руководитель»), а не по штатному расписанию. Адресная книга Exchange не является эталоном штатной структуры.",
             "Подразделение, не заполненное в почте, берётся у ближайшего вышестоящего руководителя (в отчётах помечено «Определено по руководителю» и учитывается отдельно).",
             "Отчёт содержит персональные данные (ФИО, должности, рабочая почта): передавайте его только тем, кому они необходимы."]
    if res.excluded:
        notes.append("Из адресной книги исключено при очистке: " + ", ".join(f"{k} — {v}" for k, v in res.excluded.items()) + ".")
    cond = [{"label": "Вид отчёта", "text": TITLE[view]}, {"label": "Выгрузка адресной книги", "text": f"{snap_at.strftime('%d.%m.%Y %H:%M')} UTC; в книге {res.raw_n}, в структуре {len(people)}"}, {"label": "Источник", "text": source}, *cond]
    ms = [metric("people", "Сотрудников в отчёте", len(ids), f"всего в структуре {len(people)}"), metric("depts", "Подразделений", len({people[i]["dept"] for i in ids})),
          metric("heads", "Верхних руководителей", sum(1 for i in ids if people[i]["head"])), metric("lone", "Руководитель не указан или не найден", len(lone), "", "warn" if lone else "ok")]
    doc: dict = {"title": TITLE[view], "subtitle": f"Структура организации по адресной книге почты на {snap_at.strftime('%d.%m.%Y')}", "conditions": cond, "severity": None, "notes": notes, "metrics": ms}
    tables: list[dict] = []
    if view == "pack":
        for v in PACK:
            try:
                t, nn = VIEWS[v](x)
            except KscError:
                notes.append(f"Отчёт «{TITLE[v]}» в книгу не вошёл: нет данных (для сравнения нужны два снимка).")
                continue
            tables += [{**tb, "id": f"{v}_{tb['id']}", "title": TITLE[v] if k == 0 else tb["title"]} for k, tb in enumerate(t)]
            notes += nn
        doc["layout"] = [{"id": tb["id"], "section": "detail", "title": tb["title"]} for tb in tables]
    elif view == "chain":
        tables, nn = _t_chain(x)
    elif view in VIEWS:
        tables, nn = VIEWS[view](x)
        notes += nn
        if view in ("quality", "changes"):
            doc["layout"] = [{"id": "summary", "section": "summary", "title": tables[1]["title"]}, {"id": "rows", "section": "detail", "title": tables[0]["title"]}]
    else:
        tables, nn = _t_people(x, view)
        if view == "tree":
            def node(i: int) -> dict:
                q = people[i]
                return {"lv": lay.level[i], "name": q["name"], "title": q["title"], "dept": q["dept"], "n": lay.sub[i] - 1, "k": sum(1 for k in lay.kids[i] if k in chosen)}

            doc["layout"] = [{"id": "rows", "section": "detail", "title": TITLE[view], "html": "never", "pdf": "never"}]          # в HTML и PDF — нарисованная структура, таблица остаётся в Excel и CSV
            doc["chart"] = {"depts": res.depts, "main": [node(i) for i in ids if people[i]["reach"]], "lone": [node(i) for i in lone]}
    doc["tables"] = tables
    if view == "depts":
        pending = any(r["state"].startswith(CHECK) for r in tables[1]["rows"])
        doc["metrics"] = [*ms[:2], metric("spell", "Написаний названий в почте", len({people[i]["raw_dept"] for i in ids if people[i]["raw_dept"]}), "различных строк в карточках"),
                          metric("var", "Групп похожих названий", len(tables[1]["rows"]), "ждут решения администратора" if pending else "", "warn" if pending else "ok")]
    elif view in ("managers", "roles", "crossdept", "dups", "service", "quality", "changes"):
        doc["metrics"] = [*ms[:2], metric("rows", "Строк в отчёте", len(tables[0]["rows"]))]
    return doc


async def build_hier(client, p: dict, ctx: Ctx) -> dict:
    if ctx.sm is None or ctx.hier_cfg is None:
        raise KscError("params", "Отчёт недоступен: нет доступа к локальной базе")
    ext: dict = {}
    async with ctx.sm() as db:
        snap = await HS.latest_ok(db)
        if snap is None:
            raise KscError("no_data", "Структура ещё не загружена: нет ни одного успешного снимка.")
        res = await HS.processed(db, snap, ctx.hier_cfg)
        if p.get("view") in ("changes", "pack"):
            prev = await HS.previous_ok(db, snap, p.get("base") or "")
            if prev is not None:
                ext["base"] = (await HS.processed(db, prev, ctx.hier_cfg), prev.finished_at)
                ext["raw_emails"] = {str(r[P.EMAIL]).strip().lower() for r in await HS.records_of(db, snap)}
    return build_doc(res, p, snap.finished_at, "файл выгрузки" if snap.source == "file" else "адресная книга почты (каталог LDAPS)", ctx.hier_cfg, ext)
