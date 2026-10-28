"""Лицензии Kaspersky из базы KSC: поиск подходящих таблиц по структуре и безопасное чтение без секретов.

Схема лицензионных таблиц зависит от версии KSC и в публичной документации не описана полностью, поэтому столбцы определяются по каталогу базы (`INFORMATION_SCHEMA`):
берутся таблицы `keys`, `keys_installed` и представления с «lic» в имени, из них — столбцы по смыслу (продукт, тип, срок действия, лимит, использовано, серийный номер).
Бинарные столбцы и столбцы с данными ключа не читаются никогда. Серийный номер нужен только для «отпечатка» (HMAC), по которому находится один и тот же ключ на разных KSC;
в базу приложения и в интерфейс он не попадает. Не нашлись нужные столбцы — источник честно помечается «лицензии из KSC недоступны» с перечнем найденного, а значения вносит администратор вручную."""
from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timezone

from .driver import KscError, SourceClient

OBJECTS = "SELECT o.name AS name FROM sys.objects o WHERE o.schema_id = SCHEMA_ID('dbo') AND o.type IN ('U','V')"
COLUMNS = "SELECT c.TABLE_NAME AS tbl, c.COLUMN_NAME AS col, c.DATA_TYPE AS typ FROM INFORMATION_SCHEMA.COLUMNS c WHERE c.TABLE_SCHEMA = 'dbo' AND c.TABLE_NAME IN ({names})"
READ = "SELECT TOP (500) {cols} FROM dbo.[{table}]"
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
BINARY = {"binary", "varbinary", "image", "timestamp", "rowversion", "xml", "sql_variant"}
SECRET_COLS = re.compile(r"(data|blob|bin|secret|passw|token|body|content)", re.I)
# роль столбца → признаки имени (по порядку: более точные первыми); столбцы с «expir» не считаются лимитом
ROLES: list[tuple[str, tuple[str, ...]]] = [
    ("expires", (r"^tm.*expir", r"expir", r"valid.*(to|until)", r"end.*date")),
    ("limit", (r"^n(lic|license)?(count|limit|max)", r"(lic|license).*(count|limit)", r"max.*(host|count|dev)", r"^n?limit$", r"^n?count$")),
    ("used", (r"(used|inuse|in_use|usage|occupied|taken)",)),
    ("product", (r"^wstr(product|app|lic).*name", r"product.*name", r"^wstr(name|title)$", r"app.*name", r"^name$")),
    ("kind", (r"(lic|key).*type", r"^n?type$", r"^n?kind$", r"licensetype")),
    ("serial", (r"serial", r"key.*(num|id)$", r"^wstr(key|lickey)")),
]
KIND_RU = {0: "не указан", 1: "коммерческая", 2: "пробная", 3: "бета", 4: "ознакомительная", 5: "для тестирования", 6: "OEM", 7: "подписка"}


def map_columns(cols: list[tuple[str, str]]) -> dict[str, str]:
    """Роль → имя столбца таблицы по именам; каждый столбец получает не больше одной роли, бинарные и «секретные» пропускаются."""
    usable = [c for c, t in cols if t.lower() not in BINARY and IDENT.match(c) and not SECRET_COLS.search(c)]
    out: dict[str, str] = {}
    used: set[str] = set()
    for role, pats in ROLES:
        for pat in pats:
            hit = next((c for c in usable if c not in used and re.search(pat, c, re.I) and not (role == "limit" and re.search("expir", c, re.I))), None)
            if hit:
                out[role], _ = hit, used.add(hit)
                break
    return out


def fingerprint(serial: str, secret: str) -> str:
    """Отпечаток ключа (HMAC с мастер-ключом приложения): по нему узнаётся один и тот же ключ на разных KSC; восстановить по нему ключ нельзя."""
    s = re.sub(r"[\s-]+", "", str(serial or "")).upper()
    return hmac.new((secret or "kavcheck").encode(), s.encode(), hashlib.sha256).hexdigest()[:20] if s else ""


def _int(v) -> int | None:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if 0 <= n < 10**9 else None                 # служебные «бесконечные» значения не считаются лимитом


def _dt(v) -> datetime | None:
    if isinstance(v, datetime):
        d = v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        return d if 1971 < d.year < 2100 else None
    return None


def is_perpetual(v) -> bool:
    """Дата 2100 года и позже — служебное значение KSC «без срока». Нулевая дата (1970) и пустое значение — срок не указан, а не бессрочность."""
    return isinstance(v, datetime) and v.year >= 2100


def state_of(expires: datetime | None, now: datetime, soon_days: int = 60, perpetual: bool = False) -> str:
    if expires is None:
        return "perpetual" if perpetual else "unknown"
    return "expired" if expires <= now else "expiring" if (expires - now).days <= soon_days else "active"


def to_records(rows: list[dict], mapping: dict[str, str], table: str, secret: str, now: datetime) -> list[dict]:
    out = []
    for r in rows:
        raw = r.get(mapping.get("expires", ""))
        exp, lim, used = _dt(raw), _int(r.get(mapping.get("limit", ""))), _int(r.get(mapping.get("used", "")))
        if exp is None and lim is None:
            continue
        kind = r.get(mapping.get("kind", ""))
        kind = KIND_RU.get(kind, str(kind)) if isinstance(kind, int) else str(kind or "")
        product = str(r.get(mapping.get("product", "")) or "").strip() or "Продукт Kaspersky (название не указано в KSC)"
        fp = fingerprint(r.get(mapping.get("serial", "")), secret)
        out.append({"product": product[:200], "kind": kind[:80], "expires_at": exp, "limit_n": lim, "used_n": used, "state": state_of(exp, now, perpetual=is_perpetual(raw)), "fp": fp, "table": table})
    return out


async def read(client: SourceClient, secret: str = "") -> dict:
    """{records, diag}. diag: найденные таблицы и сопоставление столбцов — показывается администратору, когда лицензии прочитать не удалось."""
    now = datetime.now(timezone.utc)
    diag: dict = {"tables": [], "mapped": {}, "note": ""}
    try:
        names = [str(r["name"]) for r in await client.run(OBJECTS, max_rows=20000)]
    except KscError:
        raise                                                  # источник недоступен — это не «лицензий нет»: прежние записи не заменяются пустыми (служба фиксирует ошибку)
    cands = sorted(n for n in names if IDENT.match(n) and (n.lower() in ("keys", "keys_installed") or re.search(r"lic|serial", n, re.I) and not re.search(r"hst_|events?|policy|task", n, re.I)))[:12]
    diag["tables"] = cands
    if not cands:
        diag["note"] = "в базе KSC нет таблиц лицензий, доступных этой учётной записи"
        return {"records": [], "diag": diag}
    cols: dict[str, list[tuple[str, str]]] = {}
    try:
        for r in await client.run(COLUMNS.format(names=", ".join(f"N'{n}'" for n in cands)), max_rows=5000):
            cols.setdefault(str(r["tbl"]), []).append((str(r["col"]), str(r["typ"])))
    except KscError:
        raise
    records: list[dict] = []
    for table in cands:
        mp = map_columns(cols.get(table, []))
        diag["mapped"][table] = mp
        if "expires" not in mp and "limit" not in mp:
            continue
        sel = sorted(set(mp.values()))
        try:
            rows = await client.run(READ.format(cols=", ".join(f"[{c}]" for c in sel), table=table), max_rows=500)
        except KscError as exc:
            diag.setdefault("errors", {})[table] = exc.message
            continue
        records += to_records(rows, mp, table, secret, now)
    if not records and diag.get("errors"):                      # таблицы найдены, но ни одну прочитать не удалось: сбой чтения, а не отсутствие лицензий
        raise KscError("query", "Таблицы лицензий не прочитаны: " + "; ".join(f"{t}: {m}" for t, m in diag["errors"].items())[:300])
    if not records:
        diag["note"] = "таблицы лицензий найдены, но нужных значений (срок, лимит) в них нет или столбцы не распознаны"
    # одна и та же запись в двух таблицах (ключ и установленный ключ) не должна считаться дважды
    seen, uniq = set(), []
    for r in records:
        k = (r["fp"] or r["product"], r["expires_at"], r["limit_n"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return {"records": uniq, "diag": diag}

