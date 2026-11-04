"""Чистые функции: фильтры поиска, идентификаторы, разбор значений атрибутов. Пользовательские значения экранируются; секретные атрибуты не выдаются."""
from __future__ import annotations

import base64
import re
import struct
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from ..auth.ldap import escape_filter
from ..search import MaskError, clean

MIN_FIXED = 3                      # минимум значимых символов в запросе: «*» и «a*» перегружают контроллер домена
USER_ATTRS = ("cn", "displayName", "sAMAccountName", "userPrincipalName", "mail", "givenName", "sn", "title", "department")
GROUP_ATTRS = ("cn", "sAMAccountName", "displayName")
DN_RE = re.compile(r"^(cn|ou|dc|uid)=[^,]+,", re.I)
UAC_DISABLED, UAC_LOCKOUT, UAC_NO_EXPIRE, UAC_PWD_EXPIRED, UAC_SMARTCARD, UAC_NO_PREAUTH = 0x2, 0x10, 0x10000, 0x800000, 0x40000, 0x400000
FILETIME_NEVER = (0, 9223372036854775807)
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

BINARY = {"objectguid", "objectsid", "tokengroups", "tokengroupsglobalanduniversal", "usercertificate", "thumbnailphoto", "jpegphoto", "ntsecuritydescriptor", "msexchmailboxguid",
          "msexchmailboxsecuritydescriptor", "logonhours", "msexchmailboxsecuritydescriptor", "msds-generationid", "sidhistory", "mscom-userpartitionsetlink"}
SECRET = re.compile(r"(password|passwd|pwdhistory|unicodepwd|credential|secret|admpwd|laps|managedpassword|keycredential|pkcs12)", re.I)
SAFE = {"pwdlastset", "badpwdcount", "badpasswordtime"}          # даты и счётчики, не секреты


class AdQueryError(Exception):
    """Запрос пользователя не принят (понятное сообщение для интерфейса)."""


def is_secret(name: str) -> bool:
    low = name.lower()
    return low not in SAFE and bool(SECRET.search(name))


def _pattern(t: str) -> tuple[str, bool]:
    """Шаблон значения: без «*» — начало значения (как «начинается с» в консоли AD), с «*» — как введено. Возвращает (шаблон, была ли маска)."""
    star = "*" in t
    p = "*".join(escape_filter(x) for x in t.split("*"))
    return (p if star else p + "*"), star


def query_text(text: str | None) -> str:
    try:
        t = clean(text)
    except MaskError as exc:
        raise AdQueryError(str(exc)) from None
    if not t:
        raise AdQueryError("Введите запрос: имя, логин, почту, часть названия подразделения или должности. Звёздочка * заменяет любые символы.")
    if len(t.replace("*", "")) < MIN_FIXED:
        raise AdQueryError(f"Запрос слишком широкий: нужно хотя бы {MIN_FIXED} символа без звёздочки.")
    return t


def user_search_filter(text: str | None, base_filter: str, login_attr: str = "sAMAccountName") -> str:
    t = query_text(text)
    if DN_RE.match(t):                                                  # DN сравнивается только целиком
        return f"(&{base_filter}(distinguishedName={escape_filter(t)}))"
    p, _star = _pattern(t)
    attrs = USER_ATTRS if login_attr.lower() == "samaccountname" or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,40}", login_attr) else (*USER_ATTRS, login_attr)       # логин подключения (в других каталогах — uid)
    return f"(&{base_filter}(|{''.join(f'({a}={p})' for a in attrs)}))"


def group_search_filter(text: str | None) -> str:
    t = query_text(text)
    if DN_RE.match(t):
        return f"(&(objectClass=group)(distinguishedName={escape_filter(t)}))"
    p, _star = _pattern(t)
    return f"(&(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))(|{''.join(f'({a}={p})' for a in GROUP_ATTRS)}))"


def esc_bytes(b: bytes) -> str:
    return "".join(f"\\{x:02x}" for x in b)


def guid_filter(guid: str) -> str:
    return f"(objectGUID={esc_bytes(uuid.UUID(guid).bytes_le)})"


def b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def unb64(s: str) -> str:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode()


def make_ref(guid: str, dn: str) -> str:
    """Идентификатор объекта для адреса: objectGUID, а в каталогах без него — DN в base64."""
    return guid or "d:" + b64(dn)


def sid_str(raw: bytes) -> str:
    if len(raw) < 8:
        return ""
    rev, n = raw[0], raw[1]
    auth = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack("<" + "I" * n, raw[8:8 + 4 * n]) if len(raw) >= 8 + 4 * n else ()
    return f"S-{rev}-{auth}" + "".join(f"-{s}" for s in subs)


def sid_bytes(sid: str) -> bytes:
    p = sid.split("-")
    subs = [int(x) for x in p[3:]]
    return bytes([int(p[1]), len(subs)]) + int(p[2]).to_bytes(6, "big") + b"".join(struct.pack("<I", s) for s in subs)


def domain_sid(user_sid: str) -> str:
    return user_sid.rsplit("-", 1)[0]


def gen_time(v: str) -> str | None:
    m = re.match(r"^(\d{14})", v or "")
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat(timespec="seconds")


def filetime(v: str | int | None) -> str | None:
    """FILETIME (100 нс от 1601 г., UTC): 0 и «максимум» — значение не задано."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    if n in FILETIME_NEVER or n < 0:
        return None
    try:
        return (_EPOCH + timedelta(microseconds=n // 10)).isoformat(timespec="seconds")
    except OverflowError:
        return None


def to_filetime(dt: datetime) -> int:
    return int((dt.astimezone(timezone.utc) - _EPOCH).total_seconds() * 10_000_000)


def group_kind(group_type: int | None, classes: list[str]) -> tuple[str, str]:
    """(тип, область) группы: в AD — по битам groupType, в других каталогах — по классу объекта."""
    if group_type is None:
        return ("Группа каталога", "") if classes else ("", "")
    gt = group_type & 0xFFFFFFFF
    scope = "Глобальная" if gt & 0x2 else "Локальная в домене" if gt & 0x4 else "Универсальная" if gt & 0x8 else ""
    return ("Безопасности" if gt & 0x80000000 else "Рассылки"), scope


def cn_of(dn: str) -> str:
    m = re.match(r"^(?:cn|ou|uid)=((?:\\.|[^,])+)", dn, re.I)
    return re.sub(r"\\(.)", r"\1", m.group(1)) if m else dn


def values(entry: dict) -> dict[str, tuple[str, list[bytes]]]:
    """Атрибуты записи: имя в нижнем регистре → (исходное имя, значения в байтах)."""
    raw = entry.get("raw_attributes")
    if not isinstance(raw, Mapping):                                    # ldap3 отдаёт CaseInsensitiveDict, а не dict
        attrs = entry.get("attributes")
        raw = {k: ([v] if not isinstance(v, list) else v) for k, v in attrs.items()} if isinstance(attrs, Mapping) else {}
    out = {}
    for k, vs in raw.items():
        out[k.lower()] = (k, [v if isinstance(v, (bytes, bytearray)) else str(v).encode() for v in (vs if isinstance(vs, list) else [vs])])
    return out


def text_of(name: str, raw: bytes) -> str:
    low = name.lower()
    if low == "objectguid" and len(raw) == 16:
        return str(uuid.UUID(bytes_le=bytes(raw)))
    if low in ("objectsid", "sidhistory"):
        return sid_str(bytes(raw))
    if low in BINARY:
        return f"(двоичные данные, {len(raw)} байт)"
    try:
        return bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        return f"(двоичные данные, {len(raw)} байт)"


def first(vals: dict, name: str) -> str:
    got = vals.get(name.lower())
    return text_of(got[0], got[1][0]) if got and got[1] else ""


def many(vals: dict, name: str) -> list[str]:
    got = vals.get(name.lower())
    return [text_of(got[0], v) for v in got[1]] if got else []


def int_of(vals: dict, name: str) -> int | None:
    try:
        return int(first(vals, name))
    except ValueError:
        return None
