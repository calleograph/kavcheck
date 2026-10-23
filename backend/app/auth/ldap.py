"""LDAP/LDAPS-клиент (ldap3). Пароль пользователя проверяется bind'ом от имени найденного DN и нигде не сохраняется.
Группы читаются с учётом вложенности (LDAP_MATCHING_RULE_IN_CHAIN для AD; для других каталогов — memberOf)."""
from __future__ import annotations

import ssl
import time
import uuid
from dataclasses import dataclass, field

LDAP_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"


class LdapError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, detail


@dataclass(frozen=True)
class LdapIdentity:
    guid: str
    dn: str
    username: str
    display_name: str
    email: str | None
    groups: frozenset[str]      # DN групп в нижнем регистре


@dataclass
class LdapConfig:
    enabled: bool = False
    host: str = ""
    port: int = 636
    protocol: str = "ldaps"       # ldaps | starttls | ldap
    base_dn: str = ""
    bind_dn: str = ""
    bind_password: str = field(default="", repr=False)
    user_filter: str = "(&(objectClass=user)(sAMAccountName={login}))"
    group_filter: str = "(objectClass=group)"
    login_attribute: str = "sAMAccountName"
    display_name_attribute: str = "displayName"
    email_attribute: str = "mail"
    guid_attribute: str = "objectGUID"
    admin_group_dn: str = ""
    analyst_group_dn: str = ""
    viewer_group_dn: str = ""
    verify_cert: bool = True
    ca_pem: str = ""
    timeout_s: int = 5
    nested_groups: bool = True


def escape_filter(value: str) -> str:
    return "".join(f"\\{ord(c):02x}" if c in "\\*()\0" else c for c in value)


def _tls(cfg: LdapConfig):
    from ldap3 import Tls  # noqa: PLC0415

    if not cfg.verify_cert:
        return Tls(validate=ssl.CERT_NONE)
    kw = {"validate": ssl.CERT_REQUIRED}
    if cfg.ca_pem.strip():
        kw["ca_certs_data"] = cfg.ca_pem
    return Tls(**kw)


def _server(cfg: LdapConfig):
    from ldap3 import Server  # noqa: PLC0415

    use_ssl = cfg.protocol == "ldaps"
    return Server(cfg.host, port=cfg.port, use_ssl=use_ssl, tls=_tls(cfg) if cfg.protocol != "ldap" else None, connect_timeout=cfg.timeout_s, get_info="NO_INFO")


def _connect(cfg: LdapConfig, user: str, password: str):
    from ldap3 import Connection  # noqa: PLC0415

    conn = Connection(_server(cfg), user=user, password=password, auto_bind=False, receive_timeout=cfg.timeout_s, raise_exceptions=False)
    if cfg.protocol == "starttls":
        conn.open()
        if not conn.start_tls():
            raise LdapError("tls", "STARTTLS не удался")
    if not conn.bind():
        raise LdapError("bind", str(conn.result.get("description") or ""), ) if user != cfg.bind_dn else LdapError("service_bind", str(conn.result.get("description") or ""))
    return conn


def _guid(value) -> str:
    if isinstance(value, (bytes, bytearray)) and len(value) == 16:
        return str(uuid.UUID(bytes_le=bytes(value)))
    return str(value)


def _groups_of(conn, cfg: LdapConfig, user_dn: str, member_of: list[str]) -> frozenset[str]:
    groups = {g.lower() for g in member_of}
    if cfg.nested_groups:
        try:
            if conn.search(cfg.base_dn, f"(&{cfg.group_filter}(member:{LDAP_MATCHING_RULE_IN_CHAIN}:={escape_filter(user_dn)}))", attributes=["distinguishedName"], size_limit=2000):
                groups |= {e.entry_dn.lower() for e in conn.entries}
        except Exception:  # noqa: BLE001 — каталог без поддержки правила: остаются прямые группы
            pass
    return frozenset(groups)


def authenticate(cfg: LdapConfig, login: str, password: str) -> LdapIdentity:
    """1) сервисная учётка ищет пользователя; 2) bind от имени найденного DN; 3) атрибуты и группы."""
    if not cfg.enabled or not cfg.host:
        raise LdapError("not_configured")
    attrs = [cfg.login_attribute, cfg.display_name_attribute, cfg.email_attribute, cfg.guid_attribute, "memberOf", "userAccountControl"]
    svc = _connect(cfg, cfg.bind_dn, cfg.bind_password)
    try:
        flt = cfg.user_filter.replace("{login}", escape_filter(login))
        if not svc.search(cfg.base_dn, flt, attributes=attrs, size_limit=2) or len(svc.entries) != 1:
            raise LdapError("user_not_found")
        e = svc.entries[0]
        uac = e["userAccountControl"].value if "userAccountControl" in e else None
        if isinstance(uac, int) and uac & 0x2:
            raise LdapError("account_disabled")
        user_dn = e.entry_dn
        member_of = list(e["memberOf"].values) if "memberOf" in e else []
    finally:
        svc.unbind()
    try:
        uc = _connect(cfg, user_dn, password)
    except LdapError as exc:
        raise LdapError("invalid_credentials", exc.detail) from None
    uc.unbind()
    svc = _connect(cfg, cfg.bind_dn, cfg.bind_password)
    try:
        groups = _groups_of(svc, cfg, user_dn, member_of)
    finally:
        svc.unbind()
    display = str(e[cfg.display_name_attribute].value or "") if cfg.display_name_attribute in e else ""
    email = str(e[cfg.email_attribute].value) if cfg.email_attribute in e and e[cfg.email_attribute].value else None
    guid = _guid(e[cfg.guid_attribute].value) if cfg.guid_attribute in e and e[cfg.guid_attribute].value else user_dn.lower()
    uname = str(e[cfg.login_attribute].value) if cfg.login_attribute in e and e[cfg.login_attribute].value else login
    return LdapIdentity(guid=guid, dn=user_dn, username=uname, display_name=display or uname, email=email, groups=groups)


def diagnose(cfg: LdapConfig, test_login: str = "", test_password: str = "") -> dict:
    """Пошаговая проверка: TCP/TLS → вход сервисной записи → чтение Base DN → (необязательно) тестовый вход пользователя."""
    stages: list[dict] = []

    def stage(name: str, ok: bool | None, message: str, started: float) -> None:
        stages.append({"stage": name, "ok": ok, "message": message, "ms": int((time.perf_counter() - started) * 1000)})

    t = time.perf_counter()
    try:
        svc = _connect(cfg, cfg.bind_dn, cfg.bind_password)
    except LdapError as exc:
        stage("connect", False, f"Подключение или вход сервисной записи не удались: {exc.detail or exc.code}", t)
        return {"ok": False, "stages": stages}
    except Exception as exc:  # noqa: BLE001
        stage("connect", False, f"Сервер недоступен: {type(exc).__name__}", t)
        return {"ok": False, "stages": stages}
    stage("connect", True, f"Соединение {cfg.protocol.upper()} установлено, сервисная запись вошла", t)
    t = time.perf_counter()
    try:
        ok = svc.search(cfg.base_dn, "(objectClass=*)", search_scope="BASE", attributes=["objectClass"], size_limit=1)
        stage("base_dn", bool(ok), "Base DN читается" if ok else f"Base DN не читается: {svc.result.get('description')}", t)
    except Exception as exc:  # noqa: BLE001
        stage("base_dn", False, f"Ошибка чтения Base DN: {type(exc).__name__}", t)
    svc.unbind()
    if test_login:
        t = time.perf_counter()
        try:
            ident = authenticate(cfg, test_login, test_password)
            stage("auth", True, f"Пользователь {ident.display_name} вошёл; групп: {len(ident.groups)}", t)
        except LdapError as exc:
            stage("auth", False, f"Тестовый вход не удался: {exc.code} {exc.detail}".strip(), t)
    return {"ok": all(s["ok"] for s in stages), "stages": stages}
