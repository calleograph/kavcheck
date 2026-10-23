"""Каталог LDAP/LDAPS (ldap3): несколько подключений, проверка сертификата обязательна, пароль пользователя проверяется bind'ом и нигде не сохраняется.

* Сертификат сервера проверяется по загруженным доверенным CA (раздел «LDAP → Сертификаты»), а если их нет — по системному хранилищу;
  имя узла сверяется с сертификатом. Отключить проверку нельзя.
* Группы — с учётом вложенности (LDAP_MATCHING_RULE_IN_CHAIN, Active Directory); для других каталогов — memberOf.
* Коды ошибок AD (data 52e/530/531/532/533/701/773/775) переводятся в понятные причины.
Решения по доступу (роль, источники) принимает auth/service.py по правилам групп."""
from __future__ import annotations

import re
import socket
import ssl
import time
import uuid
from dataclasses import dataclass, field

LDAP_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"
_UAC_DISABLED = 0x2

MESSAGES = {
    "not_configured": "Вход доменной учётной записью не настроен.",
    "user_not_found": "Пользователь не найден в каталоге.",
    "ambiguous_user": "Под логин подходит несколько записей каталога — уточните фильтр пользователей.",
    "invalid_credentials": "Неверный логин или пароль.",
    "account_disabled": "Учётная запись отключена в каталоге.",
    "account_locked": "Учётная запись заблокирована в каталоге (слишком много неудачных попыток).",
    "password_expired": "Срок действия пароля истёк — смените пароль в домене.",
    "password_must_change": "Требуется сменить пароль при следующем входе в домен.",
    "account_restriction": "Вход ограничен политикой учётной записи (время входа, рабочие станции или срок действия).",
    "server_unavailable": "Контроллер домена не отвечает.",
    "tls_error": "Защищённое соединение не установлено: сертификат сервера не прошёл проверку.",
    "service_account_error": "Сервисная учётная запись не может войти: проверьте DN или логин и пароль.",
    "config_error": "Подключение настроено неполностью.",
    "unknown": "Ошибка каталога.",
}


class LdapError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, detail

    @property
    def message(self) -> str:
        return MESSAGES.get(self.code, MESSAGES["unknown"]) + (f" ({self.detail})" if self.detail else "")


@dataclass(frozen=True)
class LdapIdentity:
    guid: str
    dn: str
    username: str
    upn: str | None
    display_name: str
    email: str | None
    groups: frozenset[str]          # DN групп в нижнем регистре, включая вложенные
    connection_id: str = ""
    connection: str = ""
    disabled: bool = False


@dataclass
class LdapConfig:
    id: str = ""
    name: str = ""
    enabled: bool = True
    protocol: str = "ldaps"         # ldaps | starttls
    host: str = ""
    port: int = 636
    ldap_version: int = 3
    timeout_s: int = 5
    base_dn: str = ""
    domain_dns: str = ""
    netbios: str = ""
    bind_dn: str = ""
    bind_password: str = field(default="", repr=False)
    login_attribute: str = "sAMAccountName"
    display_name_attribute: str = "displayName"
    email_attribute: str = "mail"
    user_filter: str = "(&(objectCategory=person)(objectClass=user))"
    nested_groups: bool = True
    ca_pem: str = field(default="", repr=False)   # доверенные CA (PEM, несколько); пусто — системное хранилище

    @property
    def url(self) -> str:
        return f"ldaps://{self.host}:{self.port}" if self.protocol == "ldaps" else f"ldap://{self.host}:{self.port} (STARTTLS)"


_LOGIN_PART = re.compile(r"^\w[\w.\-]{0,63}$")
_UPN_DOMAIN = re.compile(r"^\w[\w.\-]{0,252}$")


def parse_login(raw: str) -> tuple[str, bool, str]:
    """(значение для поиска, это UPN, NetBIOS-домен). Принимает user, DOMAIN\\user, user@domain."""
    login, netbios = (raw or "").strip(), ""
    if "\\" in login:
        netbios, login = login.split("\\", 1)
        if not _LOGIN_PART.match(netbios):
            raise LdapError("invalid_credentials")
    is_upn = "@" in login
    name, _, dom = login.partition("@")
    if login.count("@") > 1 or len(login) > 256 or not _LOGIN_PART.match(name) or (is_upn and not _UPN_DOMAIN.match(dom)):
        raise LdapError("invalid_credentials")
    return login, is_upn, netbios


def escape_filter(value: str) -> str:
    return "".join(f"\\{ord(c):02x}" if c in "\\*()\0" else c for c in value)


def classify_bind(result: dict | None) -> str:
    result = result or {}
    desc, message = str(result.get("description", "")).lower(), str(result.get("message", "")).lower()
    if result.get("result") == 49 or "invalidcredentials" in desc:
        for needle, code in (("data 775", "account_locked"), ("data 533", "account_disabled"), ("data 701", "account_disabled"), ("data 532", "password_expired"),
                             ("data 773", "password_must_change"), ("data 52f", "account_restriction"), ("data 530", "account_restriction"), ("data 531", "account_restriction")):
            if needle in message:
                return code
        return "invalid_credentials"
    if result.get("result") in (51, 52, 81) or "unavailable" in desc or "busy" in desc:
        return "server_unavailable"
    return "unknown"


def _tls(cfg: LdapConfig):
    from ldap3 import Tls  # noqa: PLC0415

    kw: dict = {"validate": ssl.CERT_REQUIRED, "version": ssl.PROTOCOL_TLS_CLIENT}
    if cfg.ca_pem.strip():
        kw["ca_certs_data"] = cfg.ca_pem
    return Tls(**kw)


def _transport_error(exc: Exception) -> LdapError:
    text = f"{type(exc).__name__}: {exc}".lower()
    if any(w in text for w in ("ssl", "certificate", "tls", "hostname")):
        return LdapError("tls_error", type(exc).__name__)
    return LdapError("server_unavailable", type(exc).__name__)


def _connection(cfg: LdapConfig, user: str, password: str):
    from ldap3 import SIMPLE, Connection, Server  # noqa: PLC0415
    from ldap3.core.exceptions import LDAPException  # noqa: PLC0415

    if not cfg.host:
        raise LdapError("config_error", "адрес контроллера домена не задан")
    if not password:
        raise LdapError("invalid_credentials")             # пустой пароль = анонимный bind: не допускаем
    server = Server(cfg.host, port=cfg.port, use_ssl=cfg.protocol == "ldaps", tls=_tls(cfg), connect_timeout=cfg.timeout_s, get_info="NO_INFO")
    conn = Connection(server, user=user, password=password, authentication=SIMPLE, version=cfg.ldap_version, auto_bind=False, raise_exceptions=False,
                      read_only=True, receive_timeout=cfg.timeout_s)
    try:
        if cfg.protocol == "starttls":
            conn.open()
            if not conn.start_tls():
                raise LdapError("tls_error", "STARTTLS не выполнен")
        ok = conn.bind()
    except LdapError:
        raise
    except LDAPException as exc:
        raise _transport_error(exc) from None
    except OSError as exc:
        raise _transport_error(exc) from None
    if not ok:
        raise LdapError(classify_bind(conn.result))
    return conn


def _service(cfg: LdapConfig):
    try:
        return _connection(cfg, cfg.bind_dn, cfg.bind_password)
    except LdapError as exc:
        if exc.code in ("server_unavailable", "tls_error", "config_error"):
            raise
        raise LdapError("service_account_error") from None


def _guid(raw) -> str:
    if isinstance(raw, (bytes, bytearray)) and len(raw) == 16:
        return str(uuid.UUID(bytes_le=bytes(raw)))
    return ""


def _find(svc, cfg: LdapConfig, login: str) -> dict:
    from ldap3 import SUBTREE  # noqa: PLC0415

    value, is_upn, _nb = parse_login(login)
    if is_upn:
        local, _, suffix = value.partition("@")
        cond = f"(userPrincipalName={escape_filter(value)})"
        if cfg.domain_dns and suffix.lower() == cfg.domain_dns.lower():      # логин@домен этого подключения — также по атрибуту логина
            cond = f"(|{cond}({cfg.login_attribute}={escape_filter(local)}))"
    else:
        cond = f"({cfg.login_attribute}={escape_filter(value)})"
    flt = f"(&{cfg.user_filter or '(objectClass=user)'}{cond})"
    attrs = ["objectGUID", "sAMAccountName", "userPrincipalName", cfg.display_name_attribute, cfg.email_attribute, "userAccountControl", "memberOf"]
    svc.search(cfg.base_dn, flt, search_scope=SUBTREE, attributes=attrs, size_limit=2)
    entries = [e for e in (svc.response or []) if e.get("type") == "searchResEntry"]
    if not entries:
        raise LdapError("user_not_found")
    if len(entries) > 1:
        raise LdapError("ambiguous_user")
    return entries[0]


def _groups(svc, cfg: LdapConfig, dn: str, member_of: list[str]) -> frozenset[str]:
    from ldap3 import SUBTREE  # noqa: PLC0415

    groups = {str(g).lower() for g in member_of}
    if cfg.nested_groups:
        try:
            for item in svc.extend.standard.paged_search(cfg.base_dn, f"(&(objectClass=group)(member:{LDAP_MATCHING_RULE_IN_CHAIN}:={escape_filter(dn)}))",
                                                          search_scope=SUBTREE, attributes=["distinguishedName"], paged_size=500, generator=True):
                if item.get("type") == "searchResEntry":
                    groups.add(str(item["dn"]).lower())
        except Exception:  # noqa: BLE001 — каталог без правила вложенности: остаются прямые группы
            pass
    return frozenset(groups)


def _identity(cfg: LdapConfig, entry: dict, groups: frozenset[str], login: str) -> LdapIdentity:
    vals, raw = entry.get("attributes", {}), entry.get("raw_attributes", {})

    def first(name: str) -> str | None:
        v = vals.get(name)
        v = v[0] if isinstance(v, list) and v else (None if isinstance(v, list) else v)
        return str(v).strip() if v not in (None, "") else None

    uac = vals.get("userAccountControl")
    sam = first("sAMAccountName") or first(cfg.login_attribute) or parse_login(login)[0].split("@")[0]
    guid = _guid((raw.get("objectGUID") or [b""])[0]) or str(entry["dn"]).lower()
    return LdapIdentity(guid=guid, dn=str(entry["dn"]), username=sam, upn=first("userPrincipalName"), display_name=first(cfg.display_name_attribute) or sam,
                        email=first(cfg.email_attribute), groups=groups, connection_id=cfg.id, connection=cfg.name,
                        disabled=bool(isinstance(uac, int) and uac & _UAC_DISABLED))


def lookup(cfg: LdapConfig, login: str) -> LdapIdentity:
    """Пользователь и его группы без проверки пароля (проверка правил доступа администратором)."""
    svc = _service(cfg)
    try:
        e = _find(svc, cfg, login)
        vals = e.get("attributes", {})
        return _identity(cfg, e, _groups(svc, cfg, str(e["dn"]), list(vals.get("memberOf") or [])), login)
    finally:
        svc.unbind()


def authenticate(cfg: LdapConfig, login: str, password: str) -> LdapIdentity:
    if not password:
        raise LdapError("invalid_credentials")
    svc = _service(cfg)
    try:
        e = _find(svc, cfg, login)
        ident = _identity(cfg, e, frozenset(), login)
        if ident.disabled:
            raise LdapError("account_disabled")
        _connection(cfg, str(e["dn"]), password).unbind()      # проверка пароля: bind от имени пользователя
        groups = _groups(svc, cfg, str(e["dn"]), list(e.get("attributes", {}).get("memberOf") or []))
        return LdapIdentity(**{**ident.__dict__, "groups": groups})
    finally:
        try:
            svc.unbind()
        except Exception:  # noqa: BLE001
            pass


class Directory:
    """Несколько подключений: сначала подходящие по домену из логина (DOMAIN\\user, user@domain), затем основное, затем остальные."""

    def __init__(self, configs: list[LdapConfig]):
        self.configs = [c for c in configs if c.enabled and c.host]

    def candidates(self, login: str) -> list[LdapConfig]:
        _v, is_upn, nb = parse_login(login)
        suffix = login.rsplit("@", 1)[1].lower() if is_upn else ""
        if nb:
            m = [c for c in self.configs if c.netbios.lower() == nb.lower()]
            if m:
                return m
        if suffix:
            m = [c for c in self.configs if c.domain_dns.lower() == suffix]
            if m:
                return m
        return list(self.configs)

    def _each(self, login: str, fn):
        cands = self.candidates(login)
        if not cands:
            raise LdapError("not_configured")
        unavailable: LdapError | None = None
        for c in cands:
            try:
                return fn(c)
            except LdapError as exc:
                if exc.code == "user_not_found":
                    continue
                if exc.code in ("server_unavailable", "tls_error", "service_account_error", "config_error"):
                    unavailable = exc
                    continue
                raise
        raise unavailable or LdapError("user_not_found")

    def authenticate(self, login: str, password: str) -> LdapIdentity:
        return self._each(login, lambda c: authenticate(c, login, password))

    def lookup(self, login: str) -> LdapIdentity:
        return self._each(login, lambda c: lookup(c, login))


# ------------------------------------------------------------------------------------------------ диагностика
def _cert_summary(der: bytes) -> dict:
    from cryptography import x509  # noqa: PLC0415

    c = x509.load_der_x509_certificate(der)
    try:
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after
    return {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(), "not_after": na.strftime("%d.%m.%Y"), "san": san[:10]}


def diagnose(cfg: LdapConfig, test_login: str = "", test_password: str = "") -> dict:
    """Пошагово: настройка → DNS → TCP → TLS (сертификат и цепочка) → вход сервисной записи → Base DN → поиск пользователя → группы → (необязательно) вход с паролем.
    Каждый этап — с понятной причиной; пароли в ответ не попадают."""
    stages: list[dict] = []
    out: dict = {"ok": False, "stages": stages}

    def add(name: str, ok: bool | None, message: str, t0: float | None = None) -> bool:
        stages.append({"stage": name, "ok": ok, "message": message, "ms": int((time.perf_counter() - t0) * 1000) if t0 else 0})
        return ok is not False

    missing = [n for n, v in (("адрес контроллера домена", cfg.host), ("Base DN", cfg.base_dn), ("сервисная учётная запись", cfg.bind_dn)) if not v]
    if missing:
        add("config", False, "Не заполнено: " + ", ".join(missing) + ".")
        return out
    if not cfg.bind_password:
        add("config", False, "Пароль сервисной учётной записи не задан (или удалён). Без него поиск пользователей и групп невозможен.")
        return out
    add("config", True, f"{cfg.url}, LDAP v{cfg.ldap_version}, тайм-аут {cfg.timeout_s} с; доверенные сертификаты: {'загруженные CA' if cfg.ca_pem.strip() else 'системное хранилище'}.")
    t = time.perf_counter()
    try:
        infos = socket.getaddrinfo(cfg.host, cfg.port, type=socket.SOCK_STREAM)
        add("dns", True, f"{cfg.host} → {infos[0][4][0]}", t)
    except OSError as exc:
        add("dns", False, f"Имя «{cfg.host}» не найдено в DNS ({exc.strerror or type(exc).__name__}). Проверьте имя контроллера и DNS на сервере KAV Checker.", t)
        return out
    t = time.perf_counter()
    try:
        sock = socket.create_connection((cfg.host, cfg.port), timeout=cfg.timeout_s)
        add("tcp", True, f"Порт {cfg.port} доступен.", t)
    except OSError as exc:
        add("tcp", False, f"Нет соединения с {cfg.host}:{cfg.port} ({exc.strerror or type(exc).__name__}). Проверьте порт ({'636 для LDAPS' if cfg.protocol == 'ldaps' else '389 для STARTTLS'}), межсетевой экран и маршрут.", t)
        return out
    if cfg.protocol == "ldaps":
        t = time.perf_counter()
        ctx = ssl.create_default_context()
        if cfg.ca_pem.strip():
            ctx = ssl.create_default_context(cadata=cfg.ca_pem)
        try:
            with ctx.wrap_socket(sock, server_hostname=cfg.host) as tls:
                der = tls.getpeercert(binary_form=True) or b""
                info = _cert_summary(der) if der else {}
                out["server_certificate"] = info
                add("tls", True, f"{tls.version()}: сертификат сервера проверен (выдан «{info.get('issuer', '?')}», действует до {info.get('not_after', '?')}).", t)
        except ssl.SSLCertVerificationError as exc:
            reason = (getattr(exc, "verify_message", "") or str(exc)).lower()
            info = {}
            try:  # повторное соединение без проверки — только чтобы показать, какой сертификат предъявляет сервер (данные не передаются)
                raw_ctx = ssl.create_default_context()
                raw_ctx.check_hostname, raw_ctx.verify_mode = False, ssl.CERT_NONE
                with socket.create_connection((cfg.host, cfg.port), timeout=cfg.timeout_s) as s2, raw_ctx.wrap_socket(s2, server_hostname=cfg.host) as tls2:
                    info = _cert_summary(tls2.getpeercert(binary_form=True) or b"")
                    out["server_certificate"] = info
            except Exception:  # noqa: BLE001
                pass
            if "hostname" in reason or "match" in reason:
                hint = f"имя «{cfg.host}» не совпадает с именами в сертификате ({', '.join(info.get('san') or []) or info.get('subject', '?')}). Подключайтесь по имени из сертификата"
            elif "expired" in reason:
                hint = f"срок действия сертификата сервера истёк ({info.get('not_after', '?')})"
            elif "self" in reason or "unable to get" in reason or "unknown" in reason:
                hint = f"цепочка не доверена: загрузите корневой и, если есть, промежуточный сертификат CA, которым выдан сертификат сервера (издатель: «{info.get('issuer', '?')}»)"
            else:
                hint = getattr(exc, "verify_message", "") or "проверка не пройдена"
            add("tls", False, f"Сертификат сервера не прошёл проверку: {hint}.", t)
            return out
        except (ssl.SSLError, OSError) as exc:
            add("tls", False, f"Защищённое соединение не установлено ({type(exc).__name__}). Убедитесь, что на порту {cfg.port} работает LDAPS.", t)
            return out
    else:
        sock.close()
        add("tls", None, "STARTTLS проверяется вместе со входом сервисной учётной записи.")
    t = time.perf_counter()
    try:
        svc = _service(cfg)
        add("bind", True, "Сервисная учётная запись вошла" + (" (защита STARTTLS включена)." if cfg.protocol == "starttls" else "."), t)
    except LdapError as exc:
        add("bind", False, {"service_account_error": "Вход сервисной учётной записи отклонён: проверьте DN или логин (user@домен) и пароль.",
                            "tls_error": "STARTTLS или сертификат не приняты: загрузите сертификат CA и проверьте имя узла.",
                            "server_unavailable": "Контроллер домена не ответил на вход."}.get(exc.code, exc.message), t)
        return out
    try:
        from ldap3 import BASE  # noqa: PLC0415

        t = time.perf_counter()
        ok = svc.search(cfg.base_dn, "(objectClass=*)", search_scope=BASE, attributes=["objectClass"], size_limit=1)
        if not add("base_dn", bool(ok) or svc.result.get("result") == 0, "Base DN доступен для чтения." if ok or svc.result.get("result") == 0
                   else f"Base DN не читается ({svc.result.get('description', 'ошибка поиска')}): проверьте значение и права сервисной записи.", t):
            return out
        if test_login:
            t = time.perf_counter()
            try:
                e = _find(svc, cfg, test_login)
                ident = _identity(cfg, e, frozenset(), test_login)
                add("user", True, f"Найден: {ident.display_name} ({ident.username}){', учётная запись ОТКЛЮЧЕНА' if ident.disabled else ''}.", t)
                t = time.perf_counter()
                groups = _groups(svc, cfg, str(e["dn"]), list(e.get("attributes", {}).get("memberOf") or []))
                out["test_user"] = {"display_name": ident.display_name, "username": ident.username, "email": ident.email, "groups": sorted(groups)[:200], "disabled": ident.disabled}
                add("groups", True, f"Групп с учётом вложенности: {len(groups)}.", t)
            except LdapError as exc:
                add("user", False, f"Пользователь «{test_login}»: {exc.message}", t)
            if test_password:
                t = time.perf_counter()
                try:
                    authenticate(cfg, test_login, test_password)
                    add("auth", True, "Пароль пользователя принят.", t)
                except LdapError as exc:
                    add("auth", False, exc.message, t)
    finally:
        try:
            svc.unbind()
        except Exception:  # noqa: BLE001
            pass
    out["ok"] = all(s["ok"] is not False for s in stages)
    return out


def search_groups(cfg: LdapConfig, query: str, limit: int = 20) -> list[dict]:
    """Группы каталога по части названия — для выбора DN в правилах доступа (сервисная учётная запись, только чтение)."""
    from ldap3 import SUBTREE  # noqa: PLC0415

    q = escape_filter(query.strip())
    if len(q) < 2:
        return []
    svc = _service(cfg)
    try:
        classes = "(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"
        svc.search(cfg.base_dn, f"(&{classes}(|(cn=*{q}*)(sAMAccountName=*{q}*)(displayName=*{q}*)))", search_scope=SUBTREE,
                   attributes=["cn", "description"], size_limit=limit)
        out = []
        for e in svc.response or []:
            if e.get("type") != "searchResEntry":
                continue
            vals = e.get("attributes", {})
            cn = vals.get("cn")
            desc = vals.get("description")
            out.append({"dn": str(e["dn"]), "name": str(cn[0] if isinstance(cn, list) and cn else cn or ""),
                        "description": str(desc[0] if isinstance(desc, list) and desc else desc or ""), "connection": cfg.name})
        return out[:limit]
    finally:
        try:
            svc.unbind()
        except Exception:  # noqa: BLE001
            pass
