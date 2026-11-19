"""Импорт учётных карточек из Excel (XLSX) и CSV: предварительный просмотр с сопоставлением столбцов, проверка значений и дублей, затем запись с отчётом об ошибках.

Совпадение с существующей карточкой — по инвентарному номеру, иначе по серийному номеру (если он однозначен). Режим «только новые» не меняет существующие карточки,
«новые и обновление» — меняет только сопоставленные столбцы (пустая ячейка значение не стирает). Справочные значения (тип, модель, статус, подразделение…) ищутся по названию;
отсутствующие создаются, если это разрешено. Местоположение — путь «Регион / Город / … / Помещение»: недостающие узлы создаются. Сотрудники — по почте, затем по ФИО."""
from __future__ import annotations

import contextlib
import csv
import io
import tempfile
import uuid
from pathlib import Path

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import InvAsset, InvLocation, InvPerson, InvProp, InvRef
from . import core as C
from . import model as M

MAX_ROWS = 20_000
MAX_BYTES = 30 * 1024 * 1024
FIELDS = {"inv_no": "Инвентарный номер", "acc_no": "Бухгалтерский номер", "serial": "Серийный номер", "name": "Наименование", "hostname": "Имя компьютера", "type": "Тип",
          "manufacturer": "Производитель", "model": "Модель", "status": "Статус", "location": "Местоположение (путь)", "loc_detail": "Уточнение местоположения",
          "user": "Пользователь", "owner": "Владелец", "resp": "Ответственный", "mol": "МОЛ", "it": "ИТ-специалист", "dept": "Подразделение", "branch": "Филиал",
          "purchase_date": "Дата приобретения", "received_date": "Дата поступления", "commissioned_date": "Ввод в эксплуатацию", "warranty_until": "Гарантия до", "cost": "Стоимость",
          "supplier": "Поставщик", "purchase_doc": "Документ приобретения", "note": "Примечание"}
SYN = {"inv_no": ("инвентарный", "инв. номер", "инв номер", "инв.№", "инв №", "inventory"), "acc_no": ("бухгалтер", "бух."), "serial": ("серийн", "serial", "s/n", "sn"),
       "name": ("наименование", "название", "name"), "hostname": ("имя компьютера", "сетевое имя", "hostname", "netbios"), "type": ("тип",), "manufacturer": ("производ", "vendor", "manufacturer"),
       "model": ("модель", "model"), "status": ("статус", "состояние"), "location": ("местоположение", "расположение", "помещение", "кабинет", "location"), "loc_detail": ("уточнение",),
       "user": ("пользователь", "сотрудник", "user"), "owner": ("владелец", "owner"), "resp": ("ответственн",), "mol": ("мол", "материально"), "it": ("ит-специалист", "ит специалист"),
       "dept": ("подразделен", "отдел", "department"), "branch": ("филиал", "branch"), "purchase_date": ("дата приобретения", "дата покупки", "куплен"), "received_date": ("дата поступления",),
       "commissioned_date": ("ввод в эксплуатацию", "дата ввода"), "warranty_until": ("гарантия", "warranty"), "cost": ("стоимость", "цена", "cost"), "supplier": ("поставщик", "supplier"),
       "purchase_doc": ("документ", "накладная", "счёт", "счет"), "note": ("примечание", "комментарий", "описание", "note")}
REF_OF = {"type": "type", "manufacturer": "manufacturer", "model": "model", "status": "status", "dept": "dept", "branch": "branch", "supplier": "supplier"}


HINTS = {"inv_no": "пусто — номер присвоится по шаблону; по нему же ищется карточка при обновлении", "serial": "по нему ищется карточка, если нет инвентарного номера",
         "type": "значение справочника «Типы оборудования»; новое создаётся, если разрешено", "status": "например «На складе», «В эксплуатации»",
         "location": "путь через «/»: Регион / Город / Здание / Помещение — недостающие уровни создаются",
         "user": "ФИО или адрес почты; новый сотрудник создаётся", "purchase_date": "ДД.ММ.ГГГГ или ГГГГ-ММ-ДД", "received_date": "ДД.ММ.ГГГГ", "commissioned_date": "ДД.ММ.ГГГГ",
         "warranty_until": "ДД.ММ.ГГГГ", "cost": "число, копейки через запятую или точку"}
EXAMPLE = [  # вымышленные данные
    {"inv_no": "", "serial": "SN-EX-000101", "name": "Ноутбук бухгалтерии", "hostname": "nb-buh-01", "type": "Ноутбук", "manufacturer": "Пример-Тех", "model": "PT-14",
     "status": "В эксплуатации", "location": "Центральный офис / Здание 1 / Каб. 101", "user": "Иванова Анна Сергеевна", "resp": "Петров Олег Игоревич", "dept": "Бухгалтерия",
     "purchase_date": "15.03.2025", "warranty_until": "15.03.2028", "cost": "84500,00", "supplier": "ООО «Поставщик-Пример»", "purchase_doc": "Накладная № 17 от 15.03.2025",
     "note": "пример строки — удалите перед импортом"},
    {"inv_no": "", "serial": "SN-EX-000202", "name": "МФУ на этаже", "type": "Принтер и МФУ", "manufacturer": "Пример-Принт", "model": "MF-300",
     "status": "В эксплуатации", "location": "Центральный офис / Здание 1 / Этаж 2", "resp": "Петров Олег Игоревич", "purchase_date": "2024-11-01", "cost": "36990"},
    {"inv_no": "", "serial": "SN-EX-000303", "name": "Монитор 24\"", "type": "Монитор", "manufacturer": "Пример-Тех", "status": "На складе", "location": "Склад ИТ"},
]


def template(fmt: str, example: bool, props: list[InvProp]) -> bytes:
    """Шаблон файла импорта: столбцы — поля карточки и активные доп. свойства; example — с вымышленными строками. CSV — «;» и UTF-8 с BOM (открывается в Excel)."""
    cols = [(f, t) for f, t in FIELDS.items()] + [(f"prop:{p.code}", p.name) for p in props]
    rows = [[r.get(f, "") for f, _t in cols] for r in EXAMPLE] if example else []
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
        w.writerow([t for _f, t in cols])
        w.writerows(rows)
        return ("\ufeff" + buf.getvalue()).encode("utf-8")
    from openpyxl import Workbook  # noqa: PLC0415
    from openpyxl.styles import Font  # noqa: PLC0415

    wb = Workbook()
    ws = wb.active
    ws.title = "Оборудование"
    ws.append([t for _f, t in cols])
    for c in ws[1]:
        c.font = Font(bold=True)
    for r in rows:
        ws.append(r)
    for i, (_f, t) in enumerate(cols, 1):
        ws.column_dimensions[ws.cell(1, i).column_letter].width = max(14, min(40, len(t) + 4))
    ws.freeze_panes = "A2"
    d = wb.create_sheet("Описание полей")
    d.append(["Столбец", "Что указывать"])
    for c in d[1]:
        c.font = Font(bold=True)
    for f, t in cols:
        d.append([t, HINTS.get(f, "доп. свойство" if f.startswith("prop:") else "")])
    d.append([])
    d.append(["Импортируется первый лист. Обязательных столбцов нет; столбцы можно удалять и переставлять — сопоставление проверяется перед загрузкой."])
    d.column_dimensions["A"].width, d.column_dimensions["B"].width = 30, 90
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


class ImportError_(ValueError):
    pass


def ieq(column, v: str):
    """Равенство без учёта регистра; точное совпадение — отдельно (SQLite в тестах не приводит кириллицу к нижнему регистру)."""
    return or_(column == v, func.lower(column) == v.casefold())


def read_table(data: bytes, name: str) -> tuple[list[str], list[list[str]]]:
    """Заголовки и строки (строки — текст). XLSX — через безопасное чтение книги (bi/xlsx.py), CSV — UTF-8 или Windows-1251, разделитель определяется по первой строке."""
    if len(data) > MAX_BYTES:
        raise ImportError_("Файл больше 30 МБ")
    if name.lower().endswith((".xlsx", ".xlsm")) or data[:2] == b"PK":
        from ..bi import xlsx as X  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "book.xlsx"
            p.write_bytes(data)
            try:
                X.check_archive(p)
                wb = X.open_book(p)
                ws = X.pick_sheet(wb, "")
                hn, hdr = X.headers(ws)
                rows = []
                for i, (_n, r) in enumerate(X.rows(ws, hn, hdr)):
                    if i >= MAX_ROWS:
                        raise ImportError_(f"В файле больше {MAX_ROWS} строк: разделите его")
                    vals = ["" if r.get(h) is None else (r[h].date().isoformat() if hasattr(r[h], "date") and hasattr(r[h], "hour") else str(r[h]).strip()) for h in hdr]
                    if any(vals):
                        rows.append(vals)
                wb.close()
            except X.XlsxError as exc:
                raise ImportError_(str(exc)) from None
        return [str(h) for h in hdr], rows
    for enc in ("utf-8-sig", "cp1251"):
        try:
            text = data.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise ImportError_("Кодировка CSV не распознана: сохраните файл в UTF-8")
    first = text.splitlines()[0] if text else ""
    delim = max((";", ",", "\t"), key=first.count)
    try:
        rd = list(csv.reader(io.StringIO(text), delimiter=delim))
    except csv.Error:
        raise ImportError_("Файл не похож на таблицу CSV: сохраните его в Excel (XLSX) или CSV с разделителем «;»") from None
    if not rd:
        raise ImportError_("Файл пуст")
    if len(rd) > MAX_ROWS + 1:
        raise ImportError_(f"В файле больше {MAX_ROWS} строк: разделите его")
    hdr = [h.strip() for h in rd[0]]
    return hdr, [[c.strip() for c in r] + [""] * (len(hdr) - len(r)) for r in rd[1:] if any(c.strip() for c in r)]


def suggest(headers: list[str], props: list[InvProp]) -> dict[str, str]:
    """Заголовок файла → поле карточки (или «prop:<код>»): по точному названию, затем по ключевым словам."""
    out: dict[str, str] = {}
    used: set[str] = set()
    for h in headers:
        hl = h.casefold().strip()
        hit = next((f for f, t in FIELDS.items() if t.casefold() == hl), None) or next((f"prop:{p.code}" for p in props if p.name.casefold() == hl), None)
        if hit is None:
            hit = next((f for f, keys in SYN.items() if f not in used and any(k in hl for k in keys)), None)
        if hit and hit not in used:
            out[h] = hit
            used.add(hit)
    return out


class Resolver:
    """Поиск и (при разрешении) создание справочных значений, местоположений и сотрудников — с кэшем на время импорта."""

    def __init__(self, db: AsyncSession, create: bool, acc: C.Access):
        self.db, self.create, self.acc = db, create, acc
        self.refs: dict[tuple, int | None] = {}
        self.locs: dict[str, int | None] = {}
        self.people: dict[str, int | None] = {}
        self.created = {"refs": 0, "locations": 0, "people": 0}
        self.fresh: list[tuple[dict | None, object, str]] = []        # созданное в текущей строке: (кэш, ключ, счётчик)

    def drop(self) -> None:
        """Строка откатилась: созданных в ней значений больше нет — убрать их из кэша и счётчиков."""
        for d, k, c in self.fresh:
            if d is not None:
                d.pop(k, None)
            self.created[c] -= 1
        self.fresh = []

    async def ref(self, kind: str, name: str, parent: int | None = None) -> int | None:
        key = (kind, name.casefold(), parent)
        if key in self.refs:
            return self.refs[key]
        stmt = select(InvRef.id).where(InvRef.kind == kind, ieq(InvRef.name, name))
        if kind == "model" and parent:
            stmt = stmt.where(InvRef.parent_id == parent)
        rid = (await self.db.execute(stmt.limit(1))).scalar_one_or_none()
        if rid is None and self.create and kind not in ("type", "status"):              # классы типов и состояния статусов задаёт администратор
            if kind == "model" and not parent:
                raise ValueError(f"Модель «{name}»: укажите производителя")
            r = InvRef(kind=kind, name=name[:300], parent_id=parent if kind == "model" else None, data={})
            self.db.add(r)
            await self.db.flush()
            rid = r.id
            self.created["refs"] += 1
            self.fresh.append((self.refs, key, "refs"))
        if rid is None:
            raise ValueError(f"{M.REF_RU.get(kind, kind)}: значения «{name}» нет в справочнике")
        self.refs[key] = rid
        return rid

    async def location(self, path: str) -> int:
        key = " / ".join(x.strip() for x in path.replace("\\", "/").split("/") if x.strip())
        if key.casefold() in self.locs:
            return self.locs[key.casefold()]
        x = (await self.db.execute(select(InvLocation).where(ieq(InvLocation.path, key)).limit(1))).scalar_one_or_none()
        if x is None:
            if not self.create:
                raise ValueError(f"Местоположения «{key}» нет в справочнике")
            parent = None
            parts = key.split(" / ")
            kinds = ["region", "city", "address", "building", "floor", "room", "workplace"]
            for i, part in enumerate(parts):
                sub = " / ".join(parts[:i + 1])
                found = (await self.db.execute(select(InvLocation).where(ieq(InvLocation.path, sub)).limit(1))).scalar_one_or_none()
                if found is None:
                    found = InvLocation(parent_id=parent.id if parent else None, kind=kinds[min(i + max(0, 7 - len(parts)), 6)], name=part[:200])
                    self.db.add(found)
                    await self.db.flush()
                    found.path = f"{parent.path} / {part}" if parent else part
                    found.ids_path = f"{parent.ids_path if parent else '/'}{found.id}/"
                    self.created["locations"] += 1
                    self.fresh.append((self.locs, key.casefold(), "locations"))
                parent = found
            x = parent
        if not self.acc.loc_ok(x):
            raise ValueError(f"Местоположение «{key}» вне вашей области учёта")
        self.locs[key.casefold()] = x.id
        return x.id

    async def person(self, v: str) -> int:
        k = v.strip().casefold()
        if k in self.people:
            return self.people[k]
        if "@" in k:
            pid = (await self.db.execute(select(InvPerson.id).where(ieq(InvPerson.email, v.strip())).limit(1))).scalar_one_or_none()
        else:
            ids = (await self.db.execute(select(InvPerson.id).where(ieq(InvPerson.name, v.strip())).limit(2))).scalars().all()
            if len(ids) > 1:
                raise ValueError(f"Сотрудников «{v}» несколько: укажите почту")
            pid = ids[0] if ids else None
        if pid is None:
            if not self.create:
                raise ValueError(f"Сотрудник «{v}» не найден")
            p = InvPerson(name=v.strip()[:300] if "@" not in v else v.split("@")[0], email=v.strip() if "@" in v else "", source="manual")
            p.search = " ".join(x for x in (p.name, p.email) if x).casefold()
            self.db.add(p)
            await self.db.flush()
            pid = p.id
            self.created["people"] += 1
            self.fresh.append((self.people, k, "people"))
        self.people[k] = pid
        return pid


async def to_data(row: dict[str, str], res: Resolver, props: dict[str, InvProp]) -> dict:
    """Строка файла (поле → текст) → данные для apply_changes; пустые ячейки пропускаются."""
    d: dict = {}
    for f in ("inv_no", "acc_no", "serial", "name", "hostname", "loc_detail", "purchase_doc", "note", "cost", *M.DATE_FIELDS):
        if row.get(f):
            d[f] = row[f]
    man = None
    if row.get("manufacturer"):
        man = d["manufacturer_id"] = await res.ref("manufacturer", row["manufacturer"])
    if row.get("model"):
        d["model_id"] = await res.ref("model", row["model"], man)
    for f in ("type", "status", "dept", "branch", "supplier"):
        if row.get(f):
            d[f"{f}_id"] = await res.ref(REF_OF[f], row[f])
    if row.get("location"):
        d["location_id"] = await res.location(row["location"])
    for f in ("user", "owner", "resp", "mol", "it"):
        if row.get(f):
            d[f"{f}_id"] = await res.person(row[f])
    pv = {code: row[f"prop:{code}"] for code in props if row.get(f"prop:{code}")}
    if pv:
        d["props"] = pv
    return d


async def run(db: AsyncSession, headers: list[str], rows: list[list[str]], mapping: dict[str, str], *, mode: str, create_refs: bool, acc: C.Access, cfg, by: str,
              dry_run: bool) -> dict:
    """Проверка (dry_run) или запись. Ошибка в строке не останавливает импорт: строка пропускается и попадает в отчёт."""
    props = {p.code: p for p in (await db.execute(select(InvProp).where(InvProp.active.is_(True)))).scalars()}
    idx = {f: headers.index(h) for h, f in mapping.items() if h in headers and (f in FIELDS or (f.startswith("prop:") and f[5:] in props))}
    if not idx:
        raise ImportError_("Не сопоставлено ни одного столбца")
    res = Resolver(db, create_refs, acc)
    st = {"rows": len(rows), "created": 0, "updated": 0, "unchanged": 0, "skipped": 0, "errors": []}
    seen_inv: dict[str, int] = {}
    default_type = await C.type_for_cls(db, "other")
    names = C.Names()                                                              # общий кэш имён на весь файл
    for n, r in enumerate(rows, start=2):
        row = {f: (r[i] if i < len(r) else "").strip() for f, i in idx.items()}
        inv = row.get("inv_no", "")
        if inv:
            if inv.casefold() in seen_inv:
                st["errors"].append({"row": n, "error": f"Инвентарный номер {inv} повторяется в файле (строка {seen_inv[inv.casefold()]})"})
                st["skipped"] += 1
                continue
            seen_inv[inv.casefold()] = n
        res.fresh = []
        try:
            async with (contextlib.nullcontext() if dry_run else db.begin_nested()):        # проверка откатывается целиком; при записи строка с ошибкой откатывается одна
                existing = None
                if inv:
                    existing = (await db.execute(select(InvAsset).where(ieq(InvAsset.inv_no, inv)))).scalar_one_or_none()
                if existing is None and row.get("serial"):
                    same = (await db.execute(select(InvAsset).where(ieq(InvAsset.serial, row["serial"])).limit(2))).scalars().all()
                    if len(same) == 1 and not inv:
                        existing = same[0]
                    elif len(same) >= 1 and inv:
                        raise ValueError(f"Серийный номер {row['serial']} уже есть в карточке {same[0].inv_no}")
                if existing is not None and mode == "create":
                    st["skipped"] += 1
                    continue
                if existing is not None and (af := acc.asset_filter()) is not None and not (await db.execute(select(InvAsset.id).where(InvAsset.id == existing.id, af))).first():
                    raise ValueError("Карточка вне вашей области учёта")
                data = await to_data(row, res, props)
                if existing is None:
                    if not data.get("inv_no"):
                        data["inv_no"] = await C.next_inv_no(db, cfg)
                    data.setdefault("type_id", default_type.id if default_type else None)
                    if not data.get("status_id"):
                        s0 = await C.default_status(db, "use" if data.get("user_id") else "stock")
                        data["status_id"] = s0.id if s0 else None
                    a = InvAsset(uid=uuid.uuid4(), inv_no="-", created_by=by, updated_by=by, version=1)
                    db.add(a)
                    ch = await C.apply_changes(db, a, data, acc, creating=True, names=names)
                    await db.flush()
                    await C.record(db, a, "import", ch, by, title="Создание карточки при импорте", names=names)
                    st["created"] += 1
                else:
                    if "props" in data:
                        data["props"] = {**(existing.props or {}), **data["props"]}
                    data.pop("inv_no", None)
                    ch = await C.apply_changes(db, existing, data, C.Access(acc.perms | {"edit", "location", "people"}, acc.scopes, acc.scope_ids), names=names)
                    if ch:
                        await C.record(db, existing, "import", ch, by, title="Изменение при импорте", names=names)
                        st["updated"] += 1
                    else:
                        st["unchanged"] += 1
        except (C.Invalid, ValueError) as exc:
            st["errors"].append({"row": n, "error": "; ".join(exc.errors.values()) if isinstance(exc, C.Invalid) else str(exc)})
            st["skipped"] += 1
            if not dry_run:                                                        # строка откатилась вместе с созданными в ней значениями справочников
                res.drop()
                names = C.Names()
    st["created_refs"] = res.created
    st["errors"] = st["errors"][:500]
    return st
