"""Запросы к каталогу (синхронные, выполняются в потоках): поиск, карточки, группы, участники. Только чтение; каждый вызов — отдельное соединение сервисной учётной записи с проверкой сертификата.
Все выборки ограничены по числу записей и времени; подробные атрибуты читаются только при открытии карточки."""
from __future__ import annotations

from ..auth import ldap as L
from ..auth.ldap import LdapConfig, LdapError, escape_filter
from . import filters as F

MAX_VALUES = 100
MAX_VALUE_LEN = 1500
USER_LIST_ATTRS = ["cn", "displayName", "sAMAccountName", "userPrincipalName", "mail", "title", "department", "userAccountControl", "objectGUID", "distinguishedName"]
GROUP_LIST_ATTRS = ["cn", "description", "groupType", "sAMAccountName", "objectGUID", "objectClass", "objectSid"]
CARD_ATTRS = ["*", "createTimestamp", "modifyTimestamp", "entryUUID", "msDS-User-Account-Control-Computed"]
PERSON_CLASSES = "(|(objectClass=user)(objectClass=group)(objectClass=contact)(objectClass=computer)(objectClass=inetOrgPerson)(objectClass=groupOfNames))"
CHAIN = "1.2.840.113556.1.4.1941"


def run_search(cfg: LdapConfig, base: str, flt: str, attrs: list[str], scope: str = "SUBTREE", max_n: int = 500, time_limit: int = 15, page: int = 500) -> tuple[list[dict], bool]:
    """Постраничный поиск (LDAP paged results): до `max_n` записей; возвращает записи и признак «выдача обрезана по лимиту»."""
    from ldap3 import BASE, SUBTREE  # noqa: PLC0415
    from ldap3.core.exceptions import LDAPException  # noqa: PLC0415

    conn = L._service(cfg)                                                                  # noqa: SLF001
    out: list[dict] = []
    truncated = False
    try:
        gen = conn.extend.standard.paged_search(base, flt, search_scope=BASE if scope == "BASE" else SUBTREE, attributes=attrs, paged_size=min(page, max_n + 1), time_limit=time_limit,
                                                 size_limit=max_n + 1, generator=True)
        for e in gen:
            if e.get("type") != "searchResEntry":
                continue
            if len(out) >= max_n:
                truncated = True
                break
            out.append(e)
        res = conn.result or {}
        code = res.get("result")
        if code == 4:
            truncated = True
        elif code not in (0, None) and not out:
            raise LdapError("search_error", {10: "Base DN обслуживает другой сервер", 32: "объект не найден", 50: "недостаточно прав на чтение"}.get(code, str(res.get("description") or code)))
    except LdapError:
        raise
    except LDAPException as exc:
        raise L._transport_error(exc) from None                                              # noqa: SLF001
    finally:
        L._close(conn)                                                                       # noqa: SLF001
    return out, truncated


def list_attrs(cfg: LdapConfig) -> list[str]:
    return USER_LIST_ATTRS if cfg.login_attribute.lower() in ("samaccountname", "") else [*USER_LIST_ATTRS, cfg.login_attribute]


def _flt(user_filter: str) -> str:
    return user_filter or "(&(objectCategory=person)(objectClass=user))"


def user_row(e: dict, login_attr: str = "sAMAccountName") -> dict:
    v = F.values(e)
    uac = F.int_of(v, "userAccountControl")
    guid = F.first(v, "objectGUID")
    dn = str(e.get("dn") or "")
    return {"ref": F.make_ref(guid, dn), "dn": dn, "name": F.first(v, "displayName") or F.first(v, "cn"), "cn": F.first(v, "cn"), "login": F.first(v, login_attr) or F.first(v, "sAMAccountName") or F.first(v, "uid"),
            "upn": F.first(v, "userPrincipalName"), "mail": F.first(v, "mail"), "title": F.first(v, "title"), "department": F.first(v, "department"),
            "disabled": bool(uac is not None and uac & F.UAC_DISABLED)}


def search_users(cfg: LdapConfig, text: str, max_n: int) -> tuple[list[dict], bool]:
    entries, trunc = run_search(cfg, cfg.base_dn, F.user_search_filter(text, _flt(cfg.user_filter), cfg.login_attribute), list_attrs(cfg), max_n=max_n)
    rows = [user_row(e, cfg.login_attribute) for e in entries]
    rows.sort(key=lambda r: (r["name"].casefold(), r["login"].casefold()))
    return rows, trunc


def group_info(e: dict) -> dict:
    v = F.values(e)
    guid = F.first(v, "objectGUID")
    dn = str(e.get("dn") or "")
    typ, scope = F.group_kind(F.int_of(v, "groupType"), F.many(v, "objectClass"))
    return {"ref": F.make_ref(guid, dn), "dn": dn, "cn": F.first(v, "cn") or F.cn_of(dn), "sam": F.first(v, "sAMAccountName"), "description": F.first(v, "description"), "type": typ, "scope": scope}


def search_groups(cfg: LdapConfig, text: str, max_n: int) -> tuple[list[dict], bool]:
    entries, trunc = run_search(cfg, cfg.base_dn, F.group_search_filter(text), GROUP_LIST_ATTRS, max_n=max_n)
    rows = [group_info(e) for e in entries]
    rows.sort(key=lambda r: r["cn"].casefold())
    return rows, trunc


def entry_by_ref(cfg: LdapConfig, ref: str, attrs: list[str]) -> dict:
    """Запись по идентификатору (objectGUID или DN); не найдена — LdapError."""
    try:
        if ref.startswith("d:"):
            dn = F.unb64(ref[2:])
            if not (dn.lower() == cfg.base_dn.lower() or dn.lower().endswith("," + cfg.base_dn.lower())):
                raise F.AdQueryError("Объект вне Base DN подключения")                         # читаются только записи выбранной ветки каталога
            found, _t = run_search(cfg, dn, "(objectClass=*)", attrs, scope="BASE", max_n=1)
        else:
            found, _t = run_search(cfg, cfg.base_dn, F.guid_filter(ref), attrs, max_n=1)
    except (ValueError, UnicodeDecodeError):
        raise F.AdQueryError("Некорректный идентификатор объекта") from None
    if not found:
        raise LdapError("search_error", "объект не найден (возможно, удалён или нет прав на чтение)")
    return found[0]


def _attributes(v: dict) -> tuple[list[dict], int]:
    items, hidden = [], 0
    for low in sorted(v):
        name, raws = v[low]
        if F.is_secret(name):
            hidden += 1
            continue
        vals = [F.text_of(name, r) for r in raws[:MAX_VALUES]]
        vals = [x if len(x) <= MAX_VALUE_LEN else x[:MAX_VALUE_LEN] + "…" for x in vals]
        items.append({"name": name, "values": vals, "more": max(0, len(raws) - MAX_VALUES)})
    return items, hidden


def user_card(cfg: LdapConfig, ref: str) -> dict:
    e = entry_by_ref(cfg, ref, CARD_ATTRS)
    v = F.values(e)
    dn = str(e.get("dn") or "")
    uac = F.int_of(v, "userAccountControl") or 0
    comp = F.int_of(v, "msDS-User-Account-Control-Computed")
    lock_raw = F.first(v, "lockoutTime")
    if comp is not None:
        locked, how = bool(comp & F.UAC_LOCKOUT), "msDS-User-Account-Control-Computed"
    else:
        locked, how = bool(lock_raw and F.filetime(lock_raw)), "lockoutTime (без учёта срока блокировки)"
    guid = F.first(v, "objectGUID")
    attrs, hidden = _attributes(v)
    main = {"name": F.first(v, "displayName") or F.first(v, "cn"), "given": F.first(v, "givenName"), "surname": F.first(v, "sn"), "login": F.first(v, cfg.login_attribute) or F.first(v, "sAMAccountName") or F.first(v, "uid"), "cn": F.first(v, "cn"),
            "upn": F.first(v, "userPrincipalName"), "mail": F.first(v, "mail"), "dn": dn, "department": F.first(v, "department"), "title": F.first(v, "title"), "company": F.first(v, "company"),
            "office": F.first(v, "physicalDeliveryOfficeName"), "phone": F.first(v, "telephoneNumber"), "mobile": F.first(v, "mobile"), "description": F.first(v, "description"), "employee_id": F.first(v, "employeeID")}
    state = {"disabled": bool(uac & F.UAC_DISABLED), "locked": locked, "locked_basis": how, "created": F.gen_time(F.first(v, "whenCreated")) or F.gen_time(F.first(v, "createTimestamp")),
             "changed": F.gen_time(F.first(v, "whenChanged")) or F.gen_time(F.first(v, "modifyTimestamp")), "pwd_last_set": F.filetime(F.first(v, "pwdLastSet")),
             "expires": F.filetime(F.first(v, "accountExpires")), "last_logon": F.filetime(F.first(v, "lastLogonTimestamp")), "last_logon_note": "lastLogonTimestamp обновляется контроллером домена не чаще раза в ~14 суток",
             "password_expired": bool(comp is not None and comp & F.UAC_PWD_EXPIRED), "pwd_never_expires": bool(uac & F.UAC_NO_EXPIRE), "uac": uac or None}
    return {"kind": "user", "ref": F.make_ref(guid, dn), "guid": guid, "dn": dn, "main": main, "state": state, "manager_dn": F.first(v, "manager"), "member_of_n": len(F.many(v, "memberOf")),
            "has_member_of": "memberof" in v, "primary_group_id": F.int_of(v, "primaryGroupID"), "sid": F.first(v, "objectSid"), "emails": _emails(v), "attributes": attrs, "hidden_n": hidden}


def _emails(v: dict) -> list[str]:
    out = [x.lower() for x in (F.first(v, "mail"), F.first(v, "userPrincipalName")) if x]
    out += [p.split(":", 1)[1].lower() for p in F.many(v, "proxyAddresses") if p.lower().startswith("smtp:")]
    return list(dict.fromkeys(out))


def resolve_groups_by_dn(cfg: LdapConfig, dns: list[str]) -> list[dict]:
    """Свойства групп по их DN (пачками): группа вне прав чтения остаётся записью с CN из DN."""
    found: dict[str, dict] = {}
    for i in range(0, len(dns), 15):
        part = dns[i:i + 15]
        flt = "(|" + "".join(f"(distinguishedName={escape_filter(d)})" for d in part) + ")"
        try:
            entries, _t = run_search(cfg, cfg.base_dn, flt, GROUP_LIST_ATTRS, max_n=len(part))
        except LdapError:
            entries = []
        for e in entries:
            found[str(e.get("dn") or "").lower()] = group_info(e)
    return [found.get(d.lower()) or {"ref": "d:" + F.b64(d), "dn": d, "cn": F.cn_of(d), "sam": "", "description": "", "type": "", "scope": ""} for d in dns]


def groups_by_sid(cfg: LdapConfig, sids: list[str]) -> list[dict]:
    out: list[dict] = []
    for i in range(0, len(sids), 20):
        flt = "(|" + "".join(f"(objectSid={F.esc_bytes(F.sid_bytes(s))})" for s in sids[i:i + 20]) + ")"
        entries, _t = run_search(cfg, cfg.base_dn, flt, GROUP_LIST_ATTRS, max_n=40)
        out += [group_info(e) for e in entries]
    return out


def user_groups(cfg: LdapConfig, ref: str) -> dict:
    """Непосредственное членство (memberOf) и первичная группа (primaryGroupID) — отдельными списками; вложенное считается по запросу (`nested_groups`)."""
    e = entry_by_ref(cfg, ref, ["memberOf", "primaryGroupID", "objectSid", "distinguishedName"])
    v = F.values(e)
    dn = str(e.get("dn") or "")
    dns = F.many(v, "memberOf")
    if not dns:                                                                                # нет memberOf (не AD или пользователь не состоит в группах): группы, где он указан участником
        entries, _t = run_search(cfg, cfg.base_dn, f"(&(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))(member={escape_filter(dn)}))", GROUP_LIST_ATTRS, max_n=500)
        direct, basis = [group_info(x) for x in entries], "поиск групп с этим участником (memberOf пуст или отсутствует)"
    else:
        direct, basis = resolve_groups_by_dn(cfg, dns), "атрибут memberOf"
    primary = None
    rid, sid = F.int_of(v, "primaryGroupID"), F.first(v, "objectSid")
    if rid is not None and sid:
        got = groups_by_sid(cfg, [f"{F.domain_sid(sid)}-{rid}"])
        primary = got[0] if got else {"ref": "", "dn": "", "cn": f"Первичная группа (RID {rid})", "sam": "", "description": "нет прав на чтение группы", "type": "", "scope": ""}
    direct.sort(key=lambda g: g["cn"].casefold())
    return {"direct": direct, "direct_basis": basis, "primary": primary}


def nested_groups(cfg: LdapConfig, ref: str) -> dict:
    """Эффективное членство: tokenGroups (контроллер домена сам разворачивает вложенность и первичную группу) либо правило LDAP_MATCHING_RULE_IN_CHAIN."""
    e = entry_by_ref(cfg, ref, ["distinguishedName"])
    dn = str(e.get("dn") or "")
    try:
        toks, _t = run_search(cfg, dn, "(objectClass=*)", ["tokenGroups"], scope="BASE", max_n=1)
        raws = F.values(toks[0]).get("tokengroups", ("", []))[1] if toks else []
        sids = [F.sid_str(r) for r in raws]
        if sids:
            return {"items": sorted(groups_by_sid(cfg, sids), key=lambda g: g["cn"].casefold()), "method": "tokenGroups: список эффективных групп вычисляет контроллер домена (вложенность и первичная группа)"}
    except LdapError:
        pass
    try:
        entries, trunc = run_search(cfg, cfg.base_dn, f"(&(objectClass=group)(member:{CHAIN}:={escape_filter(dn)}))", GROUP_LIST_ATTRS, max_n=1000)
        return {"items": sorted((group_info(x) for x in entries), key=lambda g: g["cn"].casefold()), "method": "правило LDAP_MATCHING_RULE_IN_CHAIN (вложенность без первичной группы)", "truncated": trunc}
    except LdapError:
        raise F.AdQueryError("Каталог не поддерживает расчёт вложенного членства (нужен Active Directory).") from None


def group_card(cfg: LdapConfig, ref: str) -> dict:
    e = entry_by_ref(cfg, ref, ["*", "createTimestamp", "modifyTimestamp"])
    v = F.values(e)
    info = group_info(e)
    attrs, hidden = _attributes(v)
    members_n = sum(len(vs) for k, (_n, vs) in v.items() if k.startswith("member") and not k.startswith("memberof"))
    managed = F.first(v, "managedBy")
    return {"kind": "group", **info, "guid": F.first(v, "objectGUID"), "main": {"cn": info["cn"], "sam": info["sam"], "dn": info["dn"], "description": info["description"], "mail": F.first(v, "mail"), "managed_by": managed,
            "type": info["type"], "scope": info["scope"], "created": F.gen_time(F.first(v, "whenCreated")) or F.gen_time(F.first(v, "createTimestamp")),
            "changed": F.gen_time(F.first(v, "whenChanged")) or F.gen_time(F.first(v, "modifyTimestamp")), "note": F.first(v, "info")},
            "sid": F.first(v, "objectSid"), "members_attr_n": members_n, "member_dns": F.many(v, "member")[:2000], "attributes": attrs, "hidden_n": hidden}


def member_row(e: dict, login_attr: str = "sAMAccountName") -> dict:
    v = F.values(e)
    classes = [c.lower() for c in F.many(v, "objectClass")]
    kind = "group" if "group" in classes or "groupofnames" in classes else "computer" if "computer" in classes else "contact" if "contact" in classes and "user" not in classes else "user"
    r = user_row(e, login_attr)
    return {**r, "kind": kind, "name": r["name"] or F.cn_of(r["dn"])}


def read_dns(cfg: LdapConfig, dns: list[str], attrs: list[str]) -> list[dict]:
    """Записи по списку DN одним соединением (каталоги без memberOf: участники берутся из атрибута member группы)."""
    from ldap3 import BASE  # noqa: PLC0415
    from ldap3.core.exceptions import LDAPException  # noqa: PLC0415

    conn = L._service(cfg)                                                                  # noqa: SLF001
    out: list[dict] = []
    try:
        for d in dns:
            try:
                conn.search(d, "(objectClass=*)", search_scope=BASE, attributes=attrs, size_limit=1)
            except LDAPException:
                continue
            out += [e for e in (conn.response or []) if e.get("type") == "searchResEntry"]
    finally:
        L._close(conn)                                                                       # noqa: SLF001
    return out


def group_members(cfg: LdapConfig, ref: str, max_n: int) -> dict:
    """Участники группы: непосредственные (memberOf участника) и те, для кого она первичная (primaryGroupID); вложенные — отдельным запросом `effective_members`."""
    card = group_card(cfg, ref)
    entries, trunc = run_search(cfg, cfg.base_dn, f"(&{PERSON_CLASSES}(memberOf={escape_filter(card['dn'])}))", list_attrs(cfg) + ["objectClass"], max_n=max_n)
    rows = [member_row(e, cfg.login_attribute) for e in entries]
    basis = "memberOf участников"
    if not rows and card["member_dns"]:                                                      # каталог без memberOf (не AD): участники из атрибута member группы
        rows = [member_row(x, cfg.login_attribute) for x in read_dns(cfg, card["member_dns"][:max_n], list_attrs(cfg) + ["objectClass"])]
        basis, trunc = "атрибут member группы", card["members_attr_n"] > max_n
    primary_n = 0
    if card["sid"]:
        rid = card["sid"].rsplit("-", 1)[-1]
        pe, _t = run_search(cfg, cfg.base_dn, f"(&(objectCategory=person)(primaryGroupID={escape_filter(rid)}))", ["cn"], max_n=1)
        primary_n = len(pe)
    rows.sort(key=lambda r: (r["kind"], r["name"].casefold()))
    return {"items": rows, "truncated": trunc, "basis": basis, "primary_exists": bool(primary_n), "group": card}


def effective_members(cfg: LdapConfig, dn: str, flt_users: str, max_n: int) -> tuple[list[dict], bool]:
    entries, trunc = run_search(cfg, cfg.base_dn, f"(&{flt_users}(memberOf:{CHAIN}:={escape_filter(dn)}))", list_attrs(cfg), max_n=max_n)
    return [user_row(e, cfg.login_attribute) for e in entries], trunc


def find_accounts(cfg: LdapConfig, email: str, login: str = "") -> dict:
    """Сопоставление сотрудника Exchange с учётной записью: адрес в mail, userPrincipalName или proxyAddresses — основание; логин — только кандидат. По ФИО не сопоставляется."""
    e = escape_filter(email)
    flt = f"(&{_flt(cfg.user_filter)}(|(mail={e})(userPrincipalName={e})(proxyAddresses=smtp:{e})(proxyAddresses=SMTP:{e})))"
    hits, _t = run_search(cfg, cfg.base_dn, flt, list_attrs(cfg), max_n=6)
    rows = [user_row(x, cfg.login_attribute) for x in hits]
    if len(rows) == 1:
        return {"status": "exact", "items": rows, "basis": "адрес совпал с mail, UPN или адресом Exchange"}
    if len(rows) > 1:
        return {"status": "multiple", "items": rows, "basis": "адрес указан у нескольких учётных записей"}
    if login:
        by, _t = run_search(cfg, cfg.base_dn, f"(&{_flt(cfg.user_filter)}({cfg.login_attribute or "sAMAccountName"}={escape_filter(login)}))", list_attrs(cfg), max_n=3)
        if by:
            return {"status": "manual", "items": [user_row(x, cfg.login_attribute) for x in by], "basis": "совпал только логин (часть адреса до «@»): нужно подтвердить вручную"}
    return {"status": "none", "items": [], "basis": "учётной записи с таким адресом нет"}


def status(cfg: LdapConfig) -> dict:
    """Проверка доступности: соединение, вход сервисной учётной записи, чтение Base DN."""
    import time  # noqa: PLC0415

    t0 = time.monotonic()
    try:
        _e, _t = run_search(cfg, cfg.base_dn, "(objectClass=*)", ["distinguishedName"], scope="BASE", max_n=1, time_limit=8)
    except LdapError as exc:
        return {"ok": False, "name": cfg.name, "url": cfg.url, "base_dn": cfg.base_dn, "message": exc.message}
    return {"ok": True, "name": cfg.name, "url": cfg.url, "base_dn": cfg.base_dn, "message": "Каталог доступен, сервисная учётная запись принята", "ms": int((time.monotonic() - t0) * 1000)}


# ------------------------------------------------------------------------------------------------ чтение для отчётов (в worker, постранично, до REPORT_LIMIT записей)
REPORT_LIMIT = 50_000
REPORT_ATTRS = ["cn", "displayName", "sAMAccountName", "userPrincipalName", "mail", "department", "title", "company", "userAccountControl", "msDS-User-Account-Control-Computed", "lockoutTime", "whenCreated",
                "whenChanged", "pwdLastSet", "accountExpires", "lastLogonTimestamp", "manager", "memberOf", "proxyAddresses", "objectGUID"]


def report_row(e: dict, login_attr: str = "sAMAccountName") -> dict:
    v = F.values(e)
    dn = str(e.get("dn") or "")
    uac = F.int_of(v, "userAccountControl") or 0
    comp = F.int_of(v, "msDS-User-Account-Control-Computed")
    lock = bool(comp & F.UAC_LOCKOUT) if comp is not None else bool(F.filetime(F.first(v, "lockoutTime")))
    return {"name": F.first(v, "displayName") or F.first(v, "cn"), "login": F.first(v, login_attr) or F.first(v, "sAMAccountName") or F.first(v, "uid"), "upn": F.first(v, "userPrincipalName"), "mail": F.first(v, "mail"),
            "department": F.first(v, "department"), "title": F.first(v, "title"), "company": F.first(v, "company"), "disabled": bool(uac & F.UAC_DISABLED), "locked": lock,
            "created": F.gen_time(F.first(v, "whenCreated")), "changed": F.gen_time(F.first(v, "whenChanged")), "pwd_last_set": F.filetime(F.first(v, "pwdLastSet")), "expires": F.filetime(F.first(v, "accountExpires")),
            "last_logon": F.filetime(F.first(v, "lastLogonTimestamp")), "manager": F.cn_of(F.first(v, "manager")) if F.first(v, "manager") else "", "dn": dn, "member_of": F.many(v, "memberOf"),
            "emails": _emails(v), "ref": F.make_ref(F.first(v, "objectGUID"), dn)}


def read_users(cfg: LdapConfig, extra: str = "", max_n: int = REPORT_LIMIT, narrow: str = "") -> tuple[list[dict], bool]:
    """Пользователи для отчёта; `narrow` — серверное сужение (например, по биту ACCOUNTDISABLE): если каталог его не поддерживает, читаются все и отбор делается в приложении."""
    base = f"(&{_flt(cfg.user_filter)}{extra})"
    if narrow:
        try:
            ents, trunc = run_search(cfg, cfg.base_dn, f"(&{base}{narrow})", [*REPORT_ATTRS, cfg.login_attribute], max_n=max_n, page=1000, time_limit=120)
            return [report_row(e, cfg.login_attribute) for e in ents], trunc
        except LdapError:
            pass
    ents, trunc = run_search(cfg, cfg.base_dn, base, [*REPORT_ATTRS, cfg.login_attribute], max_n=max_n, page=1000, time_limit=120)
    return [report_row(e, cfg.login_attribute) for e in ents], trunc
