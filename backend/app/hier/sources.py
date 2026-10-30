"""Сменные модули сбора адресной книги для раздела «Иерархия. Предприятие»: каждый возвращает один общий результат — записи по восемь полей (process.FIELDS) и ошибки по отдельным записям.

* `ldap` — уже настроенные в продукте подключения LDAPS к Active Directory (сервисная учётная запись, только чтение): в каталоге физически лежат поля адресной книги Exchange —
  manager (руководитель), title, department, company, physicalDeliveryOfficeName, proxyAddresses (основной SMTP-адрес). Читает страницами по 500 записей, не по запросу на человека.
* `file` — файл в формате выгрузки адресной книги (JSON-массив записей): проверка правил очистки, работа без каталога, ручная загрузка.
Протоколы чтения почты IMAP, POP3 и SMTP поле «Руководитель» не отдают, поэтому подключения SMTP продукта для этого раздела не подходят.
Microsoft Graph и EWS добавляются как ещё один модуль с тем же результатом (подключения к ним в продукте пока нет). Сбор только читает и ничего не меняет в каталоге."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..auth import ldap as L
from .process import COMPANY, DEPT, EMAIL, FIELDS, MANAGER, MANAGER_EMAIL, NAME, OFFICE, TITLE

PAGE = 500
MAX_RECORDS = 300_000
MAX_ERRORS = 50
_UAC_DISABLED = 2
ATTRS = ["displayName", "cn", "mail", "proxyAddresses", "title", "department", "company", "physicalDeliveryOfficeName", "manager", "userAccountControl"]


class SourceError(Exception):
    """Сбор невозможен: понятное администратору сообщение (что случилось и что проверить)."""


@dataclass
class Collected:
    records: list[list[str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)          # по отдельным записям; первые MAX_ERRORS
    errors_n: int = 0
    notes: list[str] = field(default_factory=list)           # замечания сбора (например, отключённые учётные записи пропущены)
    name: str = ""

    def error(self, text: str) -> None:
        self.errors_n += 1
        if len(self.errors) < MAX_ERRORS:
            self.errors.append(text[:300])


def _first(v) -> str:
    v = v[0] if isinstance(v, list) and v else ("" if isinstance(v, list) else v)
    return str(v).strip() if v not in (None, "") else ""


def _int(v) -> int:
    """Число из значения атрибута: ldap3 без схемы каталога отдаёт строки (['514']), с форматтером — числа."""
    v = v[0] if isinstance(v, list) and v else v
    if isinstance(v, (bytes, bytearray)):
        v = v.decode("ascii", "ignore")
    try:
        return int(str(v).strip())
    except ValueError:
        return 0


def primary_smtp(attrs: dict) -> str:
    """Основной SMTP-адрес: в proxyAddresses он помечен «SMTP:» (заглавными); иначе — mail."""
    prox = attrs.get("proxyAddresses") or []
    for x in prox if isinstance(prox, list) else [prox]:
        if isinstance(x, str) and x.startswith("SMTP:"):
            return x[5:].strip().lower()
    return _first(attrs.get("mail")).lower()


def parse_entry(entry: dict) -> tuple[str, list[str] | None, str, bool]:
    """(DN, запись или None, DN руководителя, отключена ли учётная запись). Запись без адреса не создаётся."""
    a = entry.get("attributes", {}) or {}
    dn = str(entry.get("dn", ""))
    disabled = bool(_int(a.get("userAccountControl")) & _UAC_DISABLED)
    email = primary_smtp(a)
    if not email:
        return dn, None, "", disabled
    rec = [""] * len(FIELDS)
    rec[NAME] = _first(a.get("displayName")) or _first(a.get("cn"))
    rec[EMAIL], rec[TITLE], rec[DEPT] = email, _first(a.get("title")), _first(a.get("department"))
    rec[COMPANY], rec[OFFICE] = _first(a.get("company")), _first(a.get("physicalDeliveryOfficeName"))
    return dn, rec, _first(a.get("manager")), disabled


def read_ldap(cfg: L.LdapConfig, extra_filter: str = "", progress=None) -> Collected:
    """Все записи пользователей с адресом из одного подключения LDAPS (синхронно: вызывается в потоке). Отключённые учётные записи не попадают в выгрузку, но служат для поиска руководителя."""
    from ldap3 import BASE, SUBTREE  # noqa: PLC0415
    from ldap3.core.exceptions import LDAPException  # noqa: PLC0415

    out = Collected(name=cfg.name)
    try:
        conn = L._service(cfg)                                                  # noqa: SLF001 — то же подключение, что и вход доменных пользователей
    except L.LdapError as exc:
        raise SourceError(f"Подключение LDAPS «{cfg.name}»: {exc.message}") from None
    flt = f"(&{cfg.user_filter}(mail=*){extra_filter.strip()})" if extra_filter.strip() else f"(&{cfg.user_filter}(mail=*))"
    by_dn: dict[str, tuple[str, str]] = {}
    pending: list[tuple[list[str], str]] = []
    disabled_n = 0
    try:
        gen = conn.extend.standard.paged_search(cfg.base_dn, flt, search_scope=SUBTREE, attributes=ATTRS, paged_size=PAGE, generator=True)
        for entry in gen:
            if entry.get("type") != "searchResEntry":
                continue
            try:
                dn, rec, mdn, disabled = parse_entry(entry)
            except Exception as exc:  # noqa: BLE001 — одна запись не останавливает сбор
                out.error(f"запись не разобрана: {type(exc).__name__}")
                continue
            if rec is not None:
                by_dn[dn.lower()] = (rec[NAME], rec[EMAIL])
                if disabled:
                    disabled_n += 1
                else:
                    pending.append((rec, mdn))
            if len(pending) > MAX_RECORDS:
                raise SourceError(f"Каталог вернул больше {MAX_RECORDS} записей: уточните Base DN или фильтр.")
            if progress is not None and len(pending) % 1000 == 0:
                progress(len(pending))
        res = conn.result or {}
        code = res.get("result")
        if code == 4:                                                                # сервер оборвал выдачу по лимиту: неполную выгрузку публиковать нельзя
            raise SourceError(f"Каталог вернул не все записи: сервер ограничил размер ответа (получено {len(by_dn)}). Увеличьте лимит выдачи для сервисной учётной записи "
                              "(в Active Directory — политика LDAP MaxResultSetSize, по умолчанию 262144) либо сузьте Base DN и фильтр.")
        if code not in (0, None) and not pending:
            raise SourceError({10: f"Base DN «{cfg.base_dn}» обслуживает другой сервер: укажите контроллер этого домена.", 32: f"Base DN «{cfg.base_dn}» не найден в каталоге.",
                               50: "У сервисной учётной записи нет прав на чтение каталога."}.get(code, f"Каталог вернул ошибку: {res.get('description') or code}"))
        unknown = {m.lower(): m for _r, m in pending if m and m.lower() not in by_dn}
        for low, mdn in list(unknown.items())[:500]:                                 # руководитель вне основной выборки (другой раздел каталога, отключён): читаем его запись напрямую
            try:
                conn.search(mdn, "(objectClass=*)", search_scope=BASE, attributes=ATTRS)
                for e in conn.response or []:
                    if e.get("type") == "searchResEntry":
                        _dn, r, _m, _d = parse_entry(e)
                        if r is not None:
                            by_dn[low] = (r[NAME], r[EMAIL])
            except LDAPException:
                out.error("запись руководителя не прочитана")
        if len(unknown) > 500:
            out.notes.append(f"Руководителей вне основной выборки больше 500: для части подчинённых адрес руководителя не определён ({len(unknown) - 500}).")
    except SourceError:
        raise
    except LDAPException as exc:
        raise SourceError(L.MESSAGES["server_unavailable"] + f" ({type(exc).__name__})") from None
    finally:
        L._close(conn)                                                              # noqa: SLF001
    for rec, mdn in pending:
        if mdn:
            name, email = by_dn.get(mdn.lower(), ("", ""))
            rec[MANAGER], rec[MANAGER_EMAIL] = name, email
            if not email:
                out.error("руководитель указан, но его адрес не найден")
        out.records.append(rec)
    if disabled_n:
        out.notes.append(f"Отключённых учётных записей пропущено: {disabled_n}.")
    return out


def check_ldap(cfg: L.LdapConfig, extra_filter: str = "") -> dict:
    """Проверка при настройке: соединение, права, наличие полей. Читает не больше 200 записей."""
    from ldap3 import SUBTREE  # noqa: PLC0415
    from ldap3.core.exceptions import LDAPException  # noqa: PLC0415

    res: dict = {"name": cfg.name, "ok": False, "steps": [], "sample": 0}

    def step(name: str, ok: bool | None, text: str) -> None:
        res["steps"].append({"name": name, "ok": ok, "text": text})

    try:
        conn = L._service(cfg)                                                      # noqa: SLF001
    except L.LdapError as exc:
        step("Подключение", False, exc.message)
        return res
    step("Подключение", True, f"{cfg.url}, сервисная учётная запись принята")
    flt = f"(&{cfg.user_filter}(mail=*){extra_filter.strip()})" if extra_filter.strip() else f"(&{cfg.user_filter}(mail=*))"
    try:
        conn.search(cfg.base_dn, flt, search_scope=SUBTREE, attributes=ATTRS, size_limit=200)
        entries = [e for e in (conn.response or []) if e.get("type") == "searchResEntry"]
        code = (conn.result or {}).get("result")
        if not entries and code not in (0, 4):
            step("Чтение каталога", False, {10: "Base DN обслуживает другой сервер.", 32: f"Base DN «{cfg.base_dn}» не найден.", 50: "У сервисной учётной записи нет прав на чтение."}.get(code, f"Ошибка каталога {code}."))
            return res
    except LDAPException as exc:
        step("Чтение каталога", False, L.MESSAGES["server_unavailable"] + f" ({type(exc).__name__})")
        return res
    finally:
        L._close(conn)                                                              # noqa: SLF001
    n = len(entries)
    res["sample"] = n
    if not n:
        step("Чтение каталога", False, f"В Base DN «{cfg.base_dn}» нет пользователей с адресом по фильтру: проверьте Base DN и фильтр пользователей подключения.")
        return res
    step("Чтение каталога", True, f"Прочитано записей для проверки: {n}")
    have = {k: 0 for k in ("manager", "title", "department")}
    for e in entries:
        a = e.get("attributes", {}) or {}
        for k in have:
            if _first(a.get(k)):
                have[k] += 1
    if not have["manager"]:
        step("Поле «Руководитель»", False, f"Ни у одной из {n} проверенных записей поле manager не вернулось: оно не заполнено в Active Directory либо у сервисной учётной записи нет права читать этот атрибут. "
                                           "Без него структура не строится.")
        return res
    step("Поле «Руководитель»", True, f"Заполнено у {have['manager']} из {n}")
    step("Должность и подразделение", None if min(have["title"], have["department"]) == 0 else True, f"Должность: {have['title']} из {n}, подразделение: {have['department']} из {n}")
    res["ok"] = True
    return res


def parse_file(data: bytes, limit: int = 40_000_000) -> Collected:
    """Файл в формате выгрузки адресной книги: JSON-массив объектов с полями Name, Email, JobTitle, Department, Company, Office, Manager, ManagerEmail."""
    if len(data) > limit:
        raise SourceError("Файл больше 40 МБ.")
    try:
        text = data.decode("utf-8-sig")
        raw = json.loads(text)
    except (UnicodeDecodeError, ValueError):
        raise SourceError("Файл не прочитан: нужен JSON в кодировке UTF-8 (массив записей с полями Name, Email, JobTitle, Department, Company, Office, Manager, ManagerEmail).") from None
    if isinstance(raw, dict) and isinstance(raw.get("people"), list):
        raw = raw["people"]
    if not isinstance(raw, list):
        raise SourceError("В файле должен быть массив записей.")
    if len(raw) > MAX_RECORDS:
        raise SourceError(f"В файле больше {MAX_RECORDS} записей.")
    out = Collected(name="загруженный файл")
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            out.error(f"запись {i + 1}: не объект")
            continue
        rec = [re.sub(r"\s+", " ", str(item.get(k) or "")).strip() for k in FIELDS]
        if not rec[EMAIL]:
            out.error(f"запись {i + 1}: нет поля Email")
        out.records.append(rec)
    if not out.records:
        raise SourceError("В файле нет записей.")
    return out
