"""Чистые функции аудита домена: категория учётной записи, давность пароля, способ последней операции с паролем (по событиям 4723/4724), замечания.

Учётная запись — словарь, собранный `collect.account` (даты — datetime UTC или None). Ничего не выдумывается: нет данных — статус «нет данных»,
проверка, которую нельзя выполнить по атрибутам AD, — «требует дополнительной проверки» (status=review), а не нарушение."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import datetime, timedelta

CATEGORY_RU = {"user": "Пользователь", "admin": "Административная", "service": "Сервисная", "temp": "Временная", "contractor": "Подрядчик", "undefined": "Не определено"}
SEV_RU = {"critical": "критическое", "high": "высокое", "medium": "среднее", "low": "низкое"}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
STATUS_RU = {"violation": "Нарушение", "review": "Требует дополнительной проверки"}
KIND_RU = {"group": "группа", "ou": "подразделение (OU)", "name": "имя", "description": "описание", "attribute": "атрибут"}
STRONG = {"group", "ou", "attribute"}
BUCKETS = (("le30", "до 30 дней"), ("le90", "30–90 дней"), ("le180", "90–180 дней"), ("gt180", "более 180 дней"), ("unknown", "дата неизвестна"))
BUCKET_RU = dict(BUCKETS)
CHECK_RU = {
    "pne": "Пароль без срока действия (Password Never Expires)",
    "pwd_age": "Пароль не менялся дольше срока категории",
    "pwd_not_set": "Пароль не сменён после выдачи («сменить при следующем входе»)",
    "pwd_expired": "Срок пароля истёк, учётная запись включена",
    "inactive": "Учётная запись не используется",
    "never_logon": "Учётная запись ни разу не использовалась",
    "expired_enabled": "Срок действия учётной записи истёк",
    "no_expiry": "Временная или подрядная учётная запись без срока действия",
    "pwd_not_required": "Пароль не обязателен (PASSWD_NOTREQD)",
    "reversible": "Пароль хранится с обратимым шифрованием",
    "no_preauth": "Отключена предварительная проверка Kerberos",
    "not_protected": "Административная учётная запись вне группы Protected Users",
    "logon_restrict": "Ограничение интерактивного входа не подтверждено",
    "service_no_desc": "Сервисная учётная запись без описания назначения",
    "service_no_owner": "Сервисная учётная запись без ответственного",
    "service_privileged": "Сервисная учётная запись в привилегированной группе",
    "undefined": "Категория не определена",
    "reset": "Последняя операция с паролем — сброс (Reset Password)",
    "pwd_changed_no_event": "Пароль изменён, событие смены не найдено",
}
TOLERANCE = timedelta(minutes=10)          # событие и pwdLastSet пишут разные компоненты; репликация и часы контроллеров дают расхождение


@dataclass
class Rule:
    category: str
    kind: str
    value: str
    note: str = ""


@dataclass
class Policy:
    pwd_days: dict[str, int]
    inactive_days: int = 90
    new_days: int = 30
    grace_days: int = 14
    protected_users: bool = True


def _m(pattern: str, value: str) -> bool:
    return bool(value) and fnmatch.fnmatchcase(value.casefold(), pattern.casefold())


def rule_hits(acc: dict, r: Rule) -> bool:
    v = r.value
    if r.kind == "group":
        names = [*acc.get("groups", []), *acc.get("special", [])]
        return any(_m(v, g) for g in names) or any(_m(v, d) for d in acc.get("group_dns", []))
    if r.kind == "ou":
        dn = acc.get("dn", "").casefold()
        return _m(v, dn) if "*" in v else dn.endswith("," + v.casefold())
    if r.kind == "name":
        return _m(v, acc.get("login", "")) or _m(v, acc.get("upn", "").split("@")[0])
    if r.kind == "description":
        return _m(v, acc.get("description", ""))
    if r.kind == "attribute":
        name, _, pat = v.partition("=")
        return any(_m(pat, x) for x in (acc.get("attrs") or {}).get(name.casefold(), []))
    return False


def classify(acc: dict, rules: list[Rule], override: dict | None = None) -> tuple[str, list[str]]:
    """Категория и основания. Решение администратора важнее правил; привилегированная группа — сильный признак «административная»;
    противоречивые сильные признаки и одиночный слабый признак (имя или описание) — «Не определено»."""
    if override:
        return override["category"], [f"решение администратора{': ' + override['note'] if override.get('note') else ''}"]
    sig: list[tuple[str, str, bool]] = []
    for g in acc.get("privileged", []):
        sig.append(("admin", f"член привилегированной группы «{g}»", True))
    if acc.get("spn"):
        sig.append(("service", "есть servicePrincipalName (учётная запись службы)", False))
    for r in rules:
        if rule_hits(acc, r):
            sig.append((r.category, f"{KIND_RU[r.kind]} «{r.value}»" + (f" ({r.note})" if r.note else ""), r.kind in STRONG))
    strong = {c for c, _b, s in sig if s}
    if len(strong) == 1:
        c = next(iter(strong))
        return c, [b for cc, b, s in sig if cc == c]
    if len(strong) > 1:
        return "undefined", ["противоречивые признаки: " + "; ".join(f"{CATEGORY_RU[c]} — {b}" for c, b, s in sig if s)]
    weak = [(c, b) for c, b, _s in sig]
    cats = {c for c, _b in weak}
    if len(cats) == 1 and len(weak) >= 2:
        return weak[0][0], [b for _c, b in weak]
    if weak:
        return "undefined", ["слабые признаки недостаточны для вывода: " + "; ".join(f"{CATEGORY_RU[c]} — {b}" for c, b in weak)]
    return "user", ["признаков особой категории нет"]


def days(now: datetime, d: datetime | None) -> int | None:
    return None if d is None else max(0, (now - d).days)


def bucket(age: int | None) -> str:
    if age is None:
        return "unknown"
    return "le30" if age <= 30 else "le90" if age <= 90 else "le180" if age <= 180 else "gt180"


# ------------------------------------------------------------------------------------------------ события смены и сброса пароля
@dataclass
class Coverage:
    """Охват загруженных журналов: по каждому контроллеру — первое и последнее сохранённое событие журнала Security."""
    dcs: dict[str, tuple[datetime, datetime]] = field(default_factory=dict)
    expected: list[str] = field(default_factory=list)          # контроллеры домена по данным каталога

    def missing(self) -> list[str]:
        have = {d.split(".")[0].casefold() for d in self.dcs}
        return [d for d in self.expected if d.split(".")[0].casefold() not in have]

    def window(self) -> tuple[datetime, datetime] | None:
        """Период, за который есть журналы всех известных контроллеров (иначе операция могла пройти на контроллере без журнала)."""
        if not self.dcs or self.missing():
            return None
        lo, hi = max(a for a, _b in self.dcs.values()), min(b for _a, b in self.dcs.values())
        return (lo, hi) if lo <= hi else None


def last_pwd_op(acc: dict, events: list[dict], cov: Coverage) -> dict:
    """Способ последней операции с паролем. events — события этой учётной записи (4723 change / 4724 reset), по возрастанию времени.
    Результат: state = change | reset | no_event | before_logs | no_logs | no_pwd; reset_pending — последний успешный сброс без последующей смены пользователем."""
    ok = [e for e in events if e["success"]]
    last = ok[-1] if ok else None
    pls = acc.get("pwd_last_set")
    out = {"state": "no_logs", "at": None, "kind": None, "by": "", "dc": "", "reset_pending": False, "basis": "", "attempts_failed": sum(1 for e in events if not e["success"])}
    if last:
        out.update(at=last["at"], kind=last["kind"], by=last["by"], dc=last["dc"])
    if pls is None:
        out.update(state="no_pwd", basis="pwdLastSet не задан: пароль должен быть сменён при следующем входе")
        if last and last["kind"] == "reset":
            out.update(reset_pending=True, basis=f"сброс {last['at']:%d.%m.%Y %H:%M} UTC ({last['by'] or 'инициатор не указан'}), пользователь пароль ещё не сменил")
        return out
    near = [e for e in ok if abs(e["at"] - pls) <= TOLERANCE]
    if near:
        e = near[-1]
        out.update(state=e["kind"], at=e["at"], kind=e["kind"], by=e["by"], dc=e["dc"],
                   basis=f"{'сброс' if e['kind'] == 'reset' else 'смена пользователем'} {e['at']:%d.%m.%Y %H:%M} UTC на {e['dc'] or 'контроллере'}; совпадает с pwdLastSet")
        out["reset_pending"] = e["kind"] == "reset" and not any(x["kind"] == "change" and x["at"] > e["at"] for x in ok)
        return out
    win = cov.window()
    if not cov.dcs:
        out.update(state="no_logs", basis="журналы безопасности контроллеров не загружены: способ смены пароля неизвестен")
    elif win is None:
        miss = cov.missing()
        out.update(state="no_logs", basis="нет журналов контроллеров: " + ", ".join(miss) if miss else "журналы контроллеров не перекрываются по времени")
    elif pls < win[0]:
        out.update(state="before_logs", basis=f"пароль изменён {pls:%d.%m.%Y} — раньше начала сохранённых журналов ({win[0]:%d.%m.%Y})")
    elif pls > win[1]:
        out.update(state="no_logs", basis=f"пароль изменён {pls:%d.%m.%Y} — позже последней загрузки журналов ({win[1]:%d.%m.%Y})")
    else:
        out.update(state="no_event", basis="пароль изменён в период, охваченный журналами, но события 4723/4724 нет (аудит управления учётными записями на контроллере мог быть выключен)")
    return out


# ------------------------------------------------------------------------------------------------ проверки
def _f(code: str, sev: str, basis: str, status: str = "violation") -> dict:
    return {"code": code, "severity": sev, "status": status, "title": CHECK_RU[code], "basis": basis}


def evaluate(acc: dict, category: str, pol: Policy, now: datetime, op: dict | None = None) -> list[dict]:
    """Замечания по одной учётной записи. Отключённые проверяются только на признаки, опасные и при отключении (пароль не обязателен)."""
    out: list[dict] = []
    enabled = acc.get("enabled", False)
    pls, age = acc.get("pwd_last_set"), days(now, acc.get("pwd_last_set"))
    created_age = days(now, acc.get("created"))
    uac = int(acc.get("uac") or 0)
    if uac & 0x20:
        out.append(_f("pwd_not_required", "high", "в userAccountControl установлен флаг PASSWD_NOTREQD: политика паролей к учётной записи может не применяться"))
    if not enabled:
        return out
    if uac & 0x80:
        out.append(_f("reversible", "high", "в userAccountControl установлен флаг ENCRYPTED_TEXT_PWD_ALLOWED"))
    if uac & 0x400000:
        out.append(_f("no_preauth", "high", "флаг DONT_REQ_PREAUTH: хеш пароля можно получить без аутентификации (AS-REP)"))
    limit = pol.pwd_days.get(category if category in pol.pwd_days else "user", 90)
    since = f"пароль не менялся с {pls:%d.%m.%Y} ({age} дн.)" if pls else "дата смены пароля неизвестна"
    if acc.get("pne"):
        if category == "service":
            if age is not None and age > limit:
                out.append(_f("pne", "high", f"сервисная учётная запись с бессрочным паролем: {since}, допускается ручная смена не реже раза в {limit} дн."))
            else:
                out.append(_f("pne", "medium", f"сервисная учётная запись с бессрочным паролем ({since}): допустимо только как согласованное исключение с ручной сменой не реже раза в {limit} дн.", "review"))
        else:
            out.append(_f("pne", "critical" if category == "admin" else "high", f"флаг DONT_EXPIRE_PASSWORD у категории «{CATEGORY_RU[category]}»; {since}"))
    if pls is None:
        if created_age is not None and created_age > pol.grace_days:
            out.append(_f("pwd_not_set", "medium", f"учётная запись создана {created_age} дн. назад, пароль, выданный при создании или сбросе, пользователем не сменён"))
    elif age is not None and age > limit and not (acc.get("pne") and category == "service"):
        out.append(_f("pwd_age", "high" if category in ("admin", "service") else "medium", f"{since}; срок для категории «{CATEGORY_RU[category]}» — {limit} дн."))
    if acc.get("pwd_expired") and not acc.get("pne"):
        out.append(_f("pwd_expired", "low", "срок пароля истёк (msDS-User-Account-Control-Computed): при входе будет запрошена смена", "review"))
    ll, src = acc.get("last_logon"), acc.get("last_logon_src", "none")
    if ll is None:
        if created_age is not None and created_age > pol.inactive_days:
            out.append(_f("never_logon", "high", f"включена, создана {acc['created']:%d.%m.%Y} ({created_age} дн. назад), входов не зафиксировано" + ("" if src == "dc" else " (по lastLogonTimestamp)")))
    else:
        idle = days(now, ll) or 0
        if idle > pol.inactive_days:
            out.append(_f("inactive", "high", f"последний вход {ll:%d.%m.%Y} ({idle} дн. назад), порог — {pol.inactive_days} дн.; источник: {'lastLogon всех контроллеров' if src == 'dc' else 'lastLogonTimestamp (точность до ~14 дн.)'}"))
    exp = acc.get("expires")
    if exp is not None and exp < now:
        out.append(_f("expired_enabled", "low", f"срок действия истёк {exp:%d.%m.%Y}: вход запрещён, но учётная запись не отключена", "review"))
    if category in ("temp", "contractor") and exp is None:
        out.append(_f("no_expiry", "high", f"категория «{CATEGORY_RU[category]}» требует срока действия (accountExpires), он не задан"))
    if category == "admin":
        if pol.protected_users and acc.get("protected") is False:
            out.append(_f("not_protected", "medium", "учётная запись не входит в группу Protected Users (с учётом вложенности)"))
        if not acc.get("workstations"):
            out.append(_f("logon_restrict", "low", "в атрибутах не задан список компьютеров для входа (userWorkstations); запрет интерактивного входа задаётся групповыми политиками — проверьте их", "review"))
    if category == "service":
        if not acc.get("description"):
            out.append(_f("service_no_desc", "medium", "поле Description пусто: назначение учётной записи не указано"))
        if not acc.get("manager") and not acc.get("info"):
            out.append(_f("service_no_owner", "medium", "не указан ответственный (атрибуты manager и info пусты)"))
        if acc.get("privileged"):
            out.append(_f("service_privileged", "high", "состоит в привилегированных группах: " + ", ".join(acc["privileged"])))
        if not acc.get("workstations"):
            out.append(_f("logon_restrict", "low", "ограничение интерактивного входа (userWorkstations, политики «Запретить локальный вход») по атрибутам не подтверждается", "review"))
    if category == "undefined":
        out.append(_f("undefined", "low", "назначьте категорию вручную: от неё зависят сроки и проверки", "review"))
    if op is not None:
        fresh = created_age is not None and created_age <= pol.grace_days           # пароль новой учётной записи выдаётся сбросом: у неё есть срок на первый вход
        if op.get("reset_pending") and not fresh:
            out.append(_f("reset", "high", op["basis"] or "последняя успешная операция — сброс пароля, смены пользователем после неё нет"))
        elif op.get("state") == "no_event":
            out.append(_f("pwd_changed_no_event", "low", op["basis"], "review"))
    return out
