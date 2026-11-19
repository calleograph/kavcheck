"""Сбор сведений об учётных записях домена для аудита (синхронно, в потоке worker): только чтение, постранично, через подключение LDAPS продукта.

* Пользователи — одним постраничным поиском (атрибуты состояния, паролей, входа, членства; секретные атрибуты не запрашиваются).
* Привилегированные группы (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account/Server/Backup/Print Operators и группы из настроек)
  и Protected Users — с учётом вложенности (LDAP_MATCHING_RULE_IN_CHAIN) и первичной группы.
* Точный последний вход: lastLogon не реплицируется, поэтому читается с каждого контроллера домена (то же подключение, другой узел)
  и берётся максимум; если ответили не все контроллеры, используется lastLogonTimestamp (реплицируется с задержкой до ~14 суток) — источник указывается."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime

from ..ad import client as C
from ..ad import filters as F
from ..auth.ldap import LdapConfig, LdapError, escape_filter

MAX_USERS = 300_000
CHAIN = "1.2.840.113556.1.4.1941"
ATTRS = ["sAMAccountName", "displayName", "cn", "userPrincipalName", "mail", "description", "title", "department", "company", "manager", "info", "userAccountControl",
         "msDS-User-Account-Control-Computed", "pwdLastSet", "accountExpires", "lastLogonTimestamp", "whenCreated", "whenChanged", "lockoutTime", "memberOf", "primaryGroupID",
         "objectGUID", "objectSid", "servicePrincipalName", "userWorkstations", "adminCount"]
PRIV_RIDS = {512: "Domain Admins", 518: "Schema Admins", 519: "Enterprise Admins"}
PRIV_BUILTIN = {"S-1-5-32-544": "Administrators", "S-1-5-32-548": "Account Operators", "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators", "S-1-5-32-551": "Backup Operators"}
PROTECTED_RID = 525


@dataclass
class Collected:
    accounts: list[dict] = field(default_factory=list)
    dcs: list[str] = field(default_factory=list)
    dc_ok: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    truncated: bool = False
    domain: str = ""


def _dt(iso: str | None) -> datetime | None:
    return datetime.fromisoformat(iso) if iso else None


def _members(cfg: LdapConfig, dn: str) -> set[str]:
    ents, _t = C.run_search(cfg, cfg.base_dn, f"(&(objectClass=user)(memberOf:{CHAIN}:={escape_filter(dn)}))", ["distinguishedName"], max_n=MAX_USERS, page=1000, time_limit=120)
    return {str(e.get("dn") or "").lower() for e in ents}


def _groups(cfg: LdapConfig, flt: str) -> list[tuple[str, str]]:
    ents, _t = C.run_search(cfg, cfg.base_dn, f"(&(objectClass=group){flt})", ["cn", "objectSid"], max_n=50)
    return [(str(e.get("dn") or ""), F.first(F.values(e), "cn") or F.cn_of(str(e.get("dn") or ""))) for e in ents]


def account(e: dict, login_attr: str, priv: dict[str, set[str]], protected: set[str] | None, special: dict[str, set[str]], attr_names: list[str]) -> dict:
    v = F.values(e)
    dn = str(e.get("dn") or "")
    low = dn.lower()
    uac = F.int_of(v, "userAccountControl") or 0
    comp = F.int_of(v, "msDS-User-Account-Control-Computed")
    pwd_raw = F.first(v, "pwdLastSet")
    locked = bool(comp & F.UAC_LOCKOUT) if comp is not None else bool(F.filetime(F.first(v, "lockoutTime")))
    privileged = sorted(g for g, members in priv.items() if low in members)
    if F.int_of(v, "primaryGroupID") == 512 and "Domain Admins" not in privileged:
        privileged.append("Domain Admins")
    member_of = F.many(v, "memberOf")
    return {"guid": F.first(v, "objectGUID")[:40], "sid": F.first(v, "objectSid")[:190], "dn": dn, "ou": dn.split(",", 1)[1] if "," in dn else "",
            "login": (F.first(v, login_attr) or F.first(v, "sAMAccountName"))[:256], "name": (F.first(v, "displayName") or F.first(v, "cn"))[:300], "upn": F.first(v, "userPrincipalName")[:300],
            "mail": F.first(v, "mail")[:300], "description": F.first(v, "description")[:500], "title": F.first(v, "title")[:300], "department": F.first(v, "department")[:300], "company": F.first(v, "company")[:300],
            "manager": (F.cn_of(F.first(v, "manager")) if F.first(v, "manager") else "")[:300], "info": F.first(v, "info")[:300],
            "uac": uac, "enabled": not uac & F.UAC_DISABLED, "locked": locked, "pne": bool(uac & F.UAC_NO_EXPIRE), "pwd_expired": bool(comp is not None and comp & F.UAC_PWD_EXPIRED),
            "must_change": pwd_raw == "0", "pwd_last_set": _dt(F.filetime(pwd_raw)), "expires": _dt(F.filetime(F.first(v, "accountExpires"))),
            "llt": _dt(F.filetime(F.first(v, "lastLogonTimestamp"))), "created": _dt(F.gen_time(F.first(v, "whenCreated"))), "changed": _dt(F.gen_time(F.first(v, "whenChanged"))),
            "groups": [F.cn_of(d) for d in member_of][:200], "group_dns": [d.lower() for d in member_of][:500], "privileged": privileged,
            "protected": None if protected is None else low in protected, "special": sorted(k for k, m in special.items() if low in m),
            "spn": bool(F.many(v, "servicePrincipalName")), "workstations": F.first(v, "userWorkstations")[:300], "admin_count": F.int_of(v, "adminCount") or 0,
            "attrs": {a.lower(): F.many(v, a) for a in attr_names}}


def read_domain(cfg: LdapConfig, *, extra_filter: str = "", admin_groups: list[str] = (), rule_groups: list[str] = (), attr_names: list[str] = (), per_dc: bool = True,
                progress=lambda _t: None) -> Collected:
    out = Collected(domain=cfg.domain_dns or cfg.base_dn)
    base_flt = cfg.user_filter or "(&(objectCategory=person)(objectClass=user))"
    progress("чтение учётных записей")
    attrs = list(dict.fromkeys([*ATTRS, cfg.login_attribute, *attr_names]))
    ents, out.truncated = C.run_search(cfg, cfg.base_dn, f"(&{base_flt}{extra_filter})", attrs, max_n=MAX_USERS, page=1000, time_limit=600)
    if out.truncated:
        out.notes.append(f"Каталог вернул больше {MAX_USERS} учётных записей: проверены первые {MAX_USERS}. Сузьте фильтр в настройках раздела.")
    dom_sid = next((F.domain_sid(F.first(F.values(e), "objectSid")) for e in ents if F.first(F.values(e), "objectSid")), "")
    progress("привилегированные группы")
    priv: dict[str, set[str]] = {}
    wanted = [(f"{dom_sid}-{rid}", name) for rid, name in PRIV_RIDS.items()] if dom_sid else []
    wanted += list(PRIV_BUILTIN.items())
    for sid, name in wanted:
        try:
            for dn, _cn in _groups(cfg, f"(objectSid={F.esc_bytes(F.sid_bytes(sid))})"):
                priv[name] = _members(cfg, dn)
        except LdapError as exc:
            out.notes.append(f"Группа «{name}» не прочитана: {exc.message}")
    for g in admin_groups:
        try:
            found = _groups(cfg, f"(|(cn={escape_filter(g)})(distinguishedName={escape_filter(g)}))")
        except LdapError as exc:
            out.notes.append(f"Группа «{g}» из настроек не прочитана: {exc.message}")
            continue
        if not found:
            out.notes.append(f"Группа «{g}» из настроек не найдена в каталоге")
        for dn, cn in found:
            priv[cn] = _members(cfg, dn)
    protected: set[str] | None = None
    if dom_sid:
        try:
            pg = _groups(cfg, f"(objectSid={F.esc_bytes(F.sid_bytes(f'{dom_sid}-{PROTECTED_RID}'))})")
            protected = _members(cfg, pg[0][0]) if pg else None
        except LdapError:
            protected = None
    if protected is None:
        out.notes.append("Группа Protected Users не найдена или недоступна: проверка членства административных учётных записей не выполнялась.")
    special: dict[str, set[str]] = {}
    for g in rule_groups:                                                     # группы из правил классификации: членство с учётом вложенности
        try:
            for dn, cn in _groups(cfg, f"(|(cn={escape_filter(g)})(distinguishedName={escape_filter(g)}))"):
                special[cn] = _members(cfg, dn)
        except LdapError as exc:
            out.notes.append(f"Группа правила «{g}» не прочитана: {exc.message}")
    out.accounts = [account(e, cfg.login_attribute, priv, protected, special, list(attr_names)) for e in ents]
    progress("контроллеры домена")
    try:
        dcs, _t = C.run_search(cfg, cfg.base_dn, "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", ["dNSHostName", "cn"], max_n=200)
        out.dcs = sorted({(F.first(F.values(d), "dNSHostName") or F.first(F.values(d), "cn")).lower() for d in dcs} - {""})
    except LdapError as exc:
        out.notes.append(f"Список контроллеров домена не получен: {exc.message}")
    for a in out.accounts:
        a["last_logon"], a["last_logon_src"] = a["llt"], "llt" if a["llt"] else "none"
    if per_dc and out.dcs:
        best: dict[str, datetime] = {}
        for dc in out.dcs:
            progress(f"последний вход: {dc}")
            try:
                part, _t = C.run_search(replace(cfg, host=dc), cfg.base_dn, f"(&{base_flt}{extra_filter})", ["objectGUID", "lastLogon"], max_n=MAX_USERS, page=1000, time_limit=600)
            except LdapError as exc:
                out.notes.append(f"Контроллер {dc}: lastLogon не прочитан ({exc.message})")
                continue
            out.dc_ok.append(dc)
            for e in part:
                v = F.values(e)
                t = _dt(F.filetime(F.first(v, "lastLogon")))
                g = F.first(v, "objectGUID")
                if t and (g not in best or t > best[g]):
                    best[g] = t
        if len(out.dc_ok) == len(out.dcs):
            for a in out.accounts:
                cand = [x for x in (best.get(a["guid"]), a["llt"]) if x]
                a["last_logon"], a["last_logon_src"] = (max(cand), "dc") if cand else (None, "dc")
        else:
            out.notes.append(f"lastLogon прочитан не со всех контроллеров ({len(out.dc_ok)} из {len(out.dcs)}): дата последнего входа — по lastLogonTimestamp (точность до ~14 суток).")
    elif not per_dc:
        out.notes.append("Опрос контроллеров выключен в настройках: дата последнего входа — по lastLogonTimestamp (точность до ~14 суток).")
    return out
