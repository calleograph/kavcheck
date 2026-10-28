"""Реестр компонентов KAV Checker: что установлено, что доступно у разработчика, решение по обновлению.

* Состав и решения разработчика — `app/components.json` (проверяется при подготовке каждого выпуска, см. docs/RELEASE.md; тест сверяет реестр с requirements.txt и Dockerfile).
* Установленные версии определяются на месте (пакеты Python, PostgreSQL, пульс сканера и worker); версии, зафиксированные при сборке образа, берутся из реестра.
* Доступные версии проверяются **в фоне** (worker) раз в сутки и по запросу, с тайм-аутом и кэшем в базе: страница внешних сервисов не опрашивает, недоступность GitHub/PyPI/npm её не замедляет.
* Обновления приложения идут только через проверенный выпуск KAV Checker; здесь ничего не устанавливается."""
from __future__ import annotations

import asyncio
import importlib.metadata as md
import json
import logging
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..ksc.versions import compare
from ..models import AppSetting, CompCheck, PtEngine, ServiceHeartbeat, utcnow

log = logging.getLogger("app.components")
REGISTRY = Path(__file__).resolve().parent.parent / "components.json"
TIMEOUT = 8.0
INTERVAL = timedelta(hours=24)
RETRY = timedelta(hours=2)
STATUS_RU = {"current": "Актуален", "update": "Доступно обновление", "deferred": "Обновление отложено", "incompatible": "Несовместимо", "review": "Требует проверки", "unknown": "Версия неизвестна",
             "unavailable": "Проверка обновлений недоступна"}
STATE_KEY = "components_state"


def load() -> dict:
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def _norm(v: str) -> str:
    return re.sub(r"^[vV]", "", (v or "").strip())


def _major(v: str) -> str:
    return re.split(r"[.\-+]", _norm(v), 1)[0]


def _branch_ok(v: str, branch: str) -> bool:
    return not branch or _norm(v) == branch or _norm(v).startswith(branch + ".")


# ------------------------------------------------------------------------------------------------ установленные версии
async def installed(db: AsyncSession, spec: dict, settings) -> tuple[str | None, bool | None]:
    """(версия, работает). Работает: True/False для служб, None — не применимо (библиотека, версия зафиксирована в образе)."""
    how = spec["installed"]
    now = utcnow()
    if how == "app":
        return settings.app_version, True
    if how == "worker":
        hb = await db.get(ServiceHeartbeat, "worker")
        alive = bool(hb and (now - hb.at).total_seconds() < 180)
        return ((hb.data or {}).get("version") if hb else None), alive
    if how == "nmap":
        hb = await db.get(ServiceHeartbeat, "pentest")
        alive = bool(hb and (now - hb.at).total_seconds() < 120)
        return ((hb.data or {}).get("nmap") if hb else None) or None, alive
    if how in ("nuclei", "templates"):
        row = await db.get(PtEngine, "nuclei")
        if row is None:
            return None, False
        ready = bool(row.version and row.templates_ver)
        return ((row.version if how == "nuclei" else row.templates_ver) or None), ready
    if how == "pg":
        v = (await db.execute(text("SHOW server_version"))).scalar_one() if db.bind.dialect.name == "postgresql" else None
        return (re.match(r"[\d.]+", v).group(0) if v else None), True
    if how == "python":
        return ".".join(str(x) for x in sys.version_info[:3]), True
    if how.startswith("py:"):
        try:
            return md.version(how[3:]), None
        except md.PackageNotFoundError:
            return None, None
    return (spec.get("verified") or None), None                       # зафиксировано при сборке образа


# ------------------------------------------------------------------------------------------------ доступные версии (фон)
async def fetch_latest(client: httpx.AsyncClient, spec: dict) -> dict:
    """{latest, url, published_at}; исключения — на вызывающем. Только стабильные выпуски: пре-релизы не считаются обновлением."""
    kind, _, ref = spec["source"].partition(":")
    if kind == "github":
        j = (await client.get(f"https://api.github.com/repos/{ref}/releases/latest")).raise_for_status().json()
        return {"latest": _norm(j["tag_name"]), "url": j.get("html_url") or "", "published_at": j.get("published_at")}
    if kind == "gh-tags":
        tags = (await client.get(f"https://api.github.com/repos/{ref}/tags?per_page=30")).raise_for_status().json()
        names = [t["name"] for t in tags if re.fullmatch(r"v?\d+\.\d+(\.\d+)?", t["name"])]
        if not names:
            raise ValueError("не найден стабильный тег")
        return {"latest": _norm(max(names, key=lambda n: [int(x) for x in _norm(n).split(".")])), "url": f"https://github.com/{ref}/tags", "published_at": None}
    if kind == "pypi":
        j = (await client.get(f"https://pypi.org/pypi/{ref}/json")).raise_for_status().json()
        return {"latest": j["info"]["version"], "url": f"https://pypi.org/project/{ref}/", "published_at": None}
    if kind == "npm":
        j = (await client.get(f"https://registry.npmjs.org/{ref.replace('/', '%2F')}/latest")).raise_for_status().json()
        return {"latest": j["version"], "url": f"https://www.npmjs.com/package/{ref}", "published_at": None}
    if kind == "eol":
        rows = (await client.get(f"https://endoflife.date/api/{ref}.json")).raise_for_status().json()
        branch = spec.get("branch") or ""
        row = next((r for r in rows if str(r["cycle"]) == branch), rows[0])
        newer = [r["cycle"] for r in rows if branch and compare(str(r["cycle"]), branch) > 0][:3]
        return {"latest": str(row["latest"]), "url": f"https://endoflife.date/{ref}", "published_at": row.get("latestReleaseDate"), "newer_branches": newer}
    raise ValueError("источник не задан")


async def check_all(sm: async_sessionmaker[AsyncSession]) -> dict:
    """Один проход: каждый источник опрашивается независимо; ошибка одного не мешает остальным."""
    reg = load()
    ok = fail = 0
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": "kavcheck-components", "Accept": "application/json"}, follow_redirects=True) as client:
        sem = asyncio.Semaphore(4)

        async def one(spec: dict) -> tuple[str, dict | None, str]:
            if not spec.get("source") or spec["source"].startswith("none"):
                return spec["key"], None, ""
            async with sem:
                try:
                    return spec["key"], await fetch_latest(client, spec), ""
                except Exception as exc:  # noqa: BLE001 — недоступность источника не ошибка приложения
                    return spec["key"], None, f"{type(exc).__name__}: {str(exc)[:200]}"
        results = await asyncio.gather(*[one(s) for s in reg["components"]])
    async with sm() as db:
        for key, got, err in results:
            row = await db.get(CompCheck, key)
            if row is None:
                row = CompCheck(key=key)
                db.add(row)
            row.checked_at = utcnow()
            if got:
                ok += 1
                pub = None
                if got.get("published_at"):
                    try:
                        pub = datetime.fromisoformat(str(got["published_at"]).replace("Z", "+00:00"))
                        if pub.tzinfo is None:                     # endoflife.date отдаёт только дату: считаем UTC (приложение не принимает naive-время)
                            pub = pub.replace(tzinfo=timezone.utc)
                    except ValueError:
                        pub = None
                row.latest, row.url, row.published_at, row.error = got["latest"][:80], got["url"][:300], pub, ""
            elif err:
                fail += 1
                row.error = err[:300]                              # прежняя найденная версия остаётся: показывается с датой проверки
        await db.commit()
    return {"ok": ok, "failed": fail}


# ------------------------------------------------------------------------------------------------ статус
def status_of(spec: dict, inst: str | None, chk: CompCheck | None) -> tuple[str, str]:
    """(код статуса, пояснение). Стабильные выпуски и совместимые ветки: новая основная версия не делает компонент «устаревшим»."""
    dec = spec.get("decision") or {}
    if dec.get("status") == "incompatible":
        return "incompatible", dec.get("reason", "")
    if not inst:
        return "unknown", ""
    latest = chk.latest if chk and chk.latest else ""
    if not latest:
        return "unavailable", (chk.error if chk and chk.error else "проверка ещё не выполнялась")
    ref = inst
    if spec.get("branch") and not _branch_ok(inst, spec["branch"]):
        ref = spec["branch"]
    if compare(_norm(latest), _norm(ref)) <= 0:
        return "current", ""
    same_major = _major(latest) == _major(ref) and (not spec.get("branch") or _branch_ok(latest, spec["branch"]))
    if dec.get("status") == "deferred":
        return "deferred", dec.get("reason", "")
    if dec.get("status") == "review":
        return "review", dec.get("reason", "")
    return ("update", "") if same_major else ("review", "Новая основная версия: совместимость не проверена")


async def table(db: AsyncSession, settings) -> dict:
    reg = load()
    checks = {c.key: c for c in (await db.execute(select(CompCheck))).scalars()}
    rows = []
    for spec in reg["components"]:
        inst, running = await installed(db, spec, settings)
        chk = checks.get(spec["key"])
        code, why = status_of(spec, inst, chk)
        rows.append({"key": spec["key"], "title": spec["title"], "group": spec["group"], "purpose": spec["purpose"], "running": running, "installed": inst, "verified": spec.get("verified") or inst,
                     "latest": chk.latest if chk and chk.latest else None, "latest_url": chk.url if chk and chk.url else None, "published_at": chk.published_at if chk else None,
                     "checked_at": chk.checked_at if chk else None, "check_error": chk.error if chk else "", "status": code, "status_ru": STATUS_RU[code], "why": why,
                     "release_notes": spec["release_notes"], "compat": spec["compat"], "limits": spec["limits"], "decision": spec["decision"], "branch": spec.get("branch") or ""})
    st = await get_state(db)
    return {"items": rows, "reviewed_for": reg["reviewed_for"], "reviewed_at": reg["reviewed_at"], "note": reg["note"], "checked_at": st.get("last_run"), "requested": bool(st.get("requested")),
            "counts": {k: sum(1 for r in rows if r["status"] == k) for k in STATUS_RU}}


async def get_state(db: AsyncSession) -> dict:
    row = await db.get(AppSetting, STATE_KEY)
    return dict(row.value or {}) if row else {}


async def set_state(sm: async_sessionmaker[AsyncSession], **kv) -> None:
    async with sm() as db:
        row = await db.get(AppSetting, STATE_KEY)
        if row is None:
            db.add(AppSetting(group=STATE_KEY, value=kv))
        else:
            row.value = {**(row.value or {}), **kv}
        await db.commit()


class Checker:
    """Фоновая проверка доступных версий (worker): раз в сутки, по запросу администратора; после сбоя — повтор через RETRY."""

    def __init__(self, sm: async_sessionmaker[AsyncSession], svc):
        self._sm, self._svc = sm, svc
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    async def tick(self) -> bool:
        async with self._sm() as db:
            st = await get_state(db)
            enabled = (await self._svc.get(db, "general")).components_check
        if not enabled and not st.get("requested"):
            return False
        last = datetime.fromisoformat(st["last_run"]) if st.get("last_run") else None
        gap = RETRY if st.get("last_failed") else INTERVAL
        if not (st.get("requested") or last is None or utcnow() - last >= gap):
            return False
        res = await check_all(self._sm)
        await set_state(self._sm, last_run=utcnow().isoformat(), requested=False, last_failed=res["ok"] == 0 and res["failed"] > 0, last_result=res)
        return True

    async def loop(self) -> None:
        await asyncio.sleep(90)
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Ошибка проверки версий компонентов")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass
