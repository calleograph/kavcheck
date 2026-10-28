"""Данные KSC для CVE Hunt: компьютеры с установленным продуктом по реестру программ (то же чтение, что у раздела «Программы»), с возрастом данных. Только чтение."""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

from ..ksc import versions as V
from ..ksc.driver import Session
from ..reports import builder
from . import criteria as C

_DISTRO = re.compile(r"(ubuntu|deb\d|\+deb|~|\.el\d|\.fc\d|\.amzn|suse|\.git)", re.I)


def masks(c: dict) -> list[str]:
    return [m for m in c.get("catalog", []) if m]


async def inventory(app, src, crit: dict, *, active_days: int, max_rows: int = 20_000) -> tuple[list[dict], dict]:
    """Строки реестра по критерию: [{host_id, name, ip, os, group, last_connected, app_name, app_version, install_date, status, distro}] и сведения о срезе."""
    ms = masks(crit)
    if not ms:
        return [], {"note": "для критерия не определён шаблон названия программы"}
    client = app.state.sources.client(src)
    rows: list[dict] = []
    fetched = datetime.now(timezone.utc)
    for m in ms:
        params = {"name_like": m, "active_days": active_days, "include_inactive": False, "product_ids": [], "branches": []}

        def work(params=params):
            with Session(app.state.sources.params(src)) as conn:
                return builder.build_software(conn, params, None, max_rows=max_rows, exclude_slaves=True, progress=lambda _t: None, cancelled=lambda: False)

        async with client._sem:  # noqa: SLF001 — один слот источника
            got, summary = await asyncio.to_thread(work)
        fetched = datetime.fromisoformat(summary["fetched_at"]).replace(tzinfo=timezone.utc) if summary.get("fetched_at") else fetched
        rows += got
    seen, out = set(), []
    for r in rows:
        k = (r["host_id"], r["app_name"], r["app_version"])
        if k in seen:
            continue
        seen.add(k)
        ver = r["app_version"] or ""
        res = C.version_in(crit, ver)
        if res is False:
            continue
        out.append({**{k2: r[k2] for k2 in ("host_id", "name", "ip", "os", "group", "last_connected", "app_name", "app_version", "install_date", "platform")}, "match": res,
                    "distro": bool(_DISTRO.search(ver)) or (r.get("platform") == "Linux" and bool(_DISTRO.search(r.get("linux_release") or ""))), "fetched_at": fetched})
    return out, {"fetched_at": fetched, "products": len(ms)}


def status_of(crit: dict, row: dict) -> tuple[str, str]:
    """Статус по данным KSC: версия в условии → «Вероятно»; версия неизвестна → «Требует проверки»; пакет дистрибутива Linux для CVE — исправление могло быть перенесено → «Требует проверки»."""
    if row["match"] is None:
        return "needs_check", "в реестре KSC версия не указана или не сопоставляется"
    if crit["kind"] == "cve" and row["distro"]:
        return "needs_check", "пакет дистрибутива: исправление могло быть перенесено без смены основной версии — сверьте с бюллетенем дистрибутива"
    return "probable", ""


_ = V
