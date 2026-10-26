"""Быстрый отчёт «Уязвимости по внешним базам»: выбранные уязвимости (CVE, БДУ) или продукты каталога → компьютеры KSC с потенциально затронутым ПО.

Сопоставление выполняется по каталогу установленного ПО (vdb/match.py), компьютеры берутся из реестра ПО KSC (только чтение) по записям реестра подходящих версий.
Это НЕ уязвимости, подтверждённые KSC: статус каждого совпадения («подтверждено источником», «потенциально затронуто», «требуется уточнение», «исправлено», «данных недостаточно»)
и его основание указаны в каждой строке."""
from __future__ import annotations

import asyncio

from sqlalchemy import select

from ..ksc import queries as q
from ..ksc.driver import KscError, Session, SourceClient
from ..models import VdbFinding, VdbSource, VdbVuln
from ..vdb import match as M
from ..vdb.normalize import SEV_RANK, SEV_RU
from . import audit
from .quick import Ctx, col, metric, apply_scope, host_part, scope_conditions, scope_notes

LEVEL = {4: "critical", 3: "high"}
EXT_COLS = [col("severity_ru", "Опасность", "sev"), col("vuln_key", "Уязвимость", "mono"), col("ids", "Идентификаторы", "mono"), col("title", "Название"), col("kev", "В каталоге CISA KEV"),
            col("status_ru", "Результат сопоставления"), col("basis", "Основание"), col("program", "Программа"), col("installed_version", "Установленная версия", "mono"),
            col("name", "Компьютер"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("group", "Группа администрирования"), col("last_connected", "Последнее подключение к KSC (UTC)", "date"),
            col("active", "Связь за период"), col("online", "В сети сейчас"), col("sources", "Источники сведений"), col("fix", "Исправление")]
SEV_LABEL = {"critical": "Критическая", "high": "Высокая", "warning": "Средняя и ниже"}


def _level(rank: int) -> str:
    return LEVEL.get(rank, "warning")


async def resolve_keys(db, ids: list[str]) -> tuple[list[str], list[str]]:
    """Общие ключи уязвимостей по введённым идентификаторам (CVE, BDU:…, OSV/GHSA…): любой идентификатор записи подходит. Возвращает (найденные, не найденные).
    Сначала одним запросом по точному ключу; поиск по псевдонимам (медленный, по тексту) — только для не найденных."""
    want = list(dict.fromkeys(i.strip().upper() for i in ids if i and i.strip()))
    have: set[str] = set()
    for i in range(0, len(want), 400):
        have |= set((await db.execute(select(VdbVuln.vuln_key).where(VdbVuln.vuln_key.in_(want[i:i + 400])))).scalars().all())
    found, missing = [], []
    for raw in want:
        if raw in have:
            found.append(raw)
            continue
        t = like_escape(raw.lower())
        row = (await db.execute(select(VdbVuln.vuln_key).where(VdbVuln.ids_text.like(f"% {t} %", escape="\\") | VdbVuln.ids_text.like(f"{t} %", escape="\\")
                                                              | VdbVuln.ids_text.like(f"% {t}", escape="\\") | (VdbVuln.ids_text == raw.lower())).limit(1))).scalar_one_or_none()
        (found if row else missing).append(row or raw)
    return found, missing


def like_escape(t: str) -> str:
    return t.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def summarize_hosts(out: list[dict]) -> list[dict]:
    """Строки таблицы «Компьютеры»: единица подсчёта во всех столбцах — уникальная уязвимость (общий ключ CVE/БДУ/OSV); несколько установок одной программы не удваивают число,
    поэтому «из них в KEV» и «из них подтверждено» — подмножества «уязвимостей». «Обнаружений» — строки таблицы обнаружений (установка × уязвимость)."""
    by_host: dict[int, dict] = {}
    for r in out:
        h = by_host.setdefault(r["host_id"], {**{k: r[k] for k in ("name", "ip", "os", "group", "last_connected", "active", "online")}, "rank": 0, "vulns": set(), "kev": set(), "confirmed": set(), "rows": 0, "programs": set()})
        h["rank"] = max(h["rank"], r["rank"])
        h["vulns"].add(r["vuln_key"])                    # единица подсчёта во всех столбцах — уникальная уязвимость (общий ключ CVE/БДУ/OSV): повторы из-за нескольких установок не удваивают число
        h["rows"] += 1
        if r["kev"]:
            h["kev"].add(r["vuln_key"])
        if r["status"] == "confirmed":
            h["confirmed"].add(r["vuln_key"])
        h["programs"].add(f"{r['program']} {r['installed_version']}")

    def _list(keys: set[str], cap: int = 12) -> str:
        ks = sorted(keys)
        return ", ".join(ks[:cap]) + (f" и ещё {len(ks) - cap}" if len(ks) > cap else "")

    host_rows = sorted(({**{k: v for k, v in h.items() if k != "kev"}, "worst": SEV_RU[next((k for k, v in SEV_RANK.items() if v == h["rank"]), "")], "vulns": len(h["vulns"]), "kev_n": len(h["kev"]), "confirmed": len(h["confirmed"]),
                         "kev_list": _list(h["kev"]), "vuln_list": _list(h["vulns"], 20), "programs": "; ".join(sorted(h["programs"]))[:300]} for h in by_host.values()),
                       key=lambda h: (-int(h["kev_n"] > 0), -h["rank"], h["name"].lower()))
    return host_rows


async def build_extvulns(client: SourceClient, p: dict, ctx: Ctx) -> dict:
    if ctx.sm is None or ctx.source_id is None:
        raise KscError("params", "Отчёт по внешним базам недоступен: нет доступа к локальной базе уязвимостей")
    notes: list[str] = []
    want = set(p.get("statuses") or M.AFFECTED)
    async with ctx.sm() as db:
        prods, maps = await M.load_context(db, ctx.source_id)
        if not prods:
            raise KscError("params", "Каталог программ источника ещё не построен: сопоставление невозможно. Дождитесь построения каталога (Программы → Каталог).")
        matcher = M.Matcher(prods, maps)
        pkeys = [k for k in p.get("product_keys") or [] if k]
        keys, missing = await resolve_keys(db, p.get("vuln_keys") or [])
        if p.get("all_known"):              # отчёт по зоне: все известные находки источника (оценка по каталогу), без выбора уязвимостей
            keys = list((await db.execute(select(VdbFinding.vuln_key).where(VdbFinding.source_id == ctx.source_id))).scalars().all())
        if missing:
            notes.append(f"В локальной базе нет уязвимости с идентификатором: {', '.join(missing)}. Обновите базу (Администрирование → База уязвимостей) или проверьте идентификатор.")
        if pkeys:
            sel = [x for x in prods if x.key in set(pkeys)]
            keys = sorted(set(keys) | {a.vuln_key for a in await M.reverse_affected(db, sel, maps)})
        affs = await M.affected_for(db, keys)
        matches = [m for m in M.matches_from(matcher, affs) if m.status in want and (not pkeys or m.product_key in set(pkeys))]
        meta = {v.vuln_key: v for i in range(0, len(keys), 400) for v in (await db.execute(select(VdbVuln).where(VdbVuln.vuln_key.in_(keys[i:i + 400])))).scalars().all()}
        states = {s.key: s for s in (await db.execute(select(VdbSource))).scalars().all()}
        aff_ids: dict[str, set[str]] = {}
        for a in affs:
            aff_ids.setdefault(a.vuln_key, set()).add(a.source)
    min_rank = SEV_RANK.get(p.get("min_severity") or "", 0)
    if min_rank or p.get("exploited_only"):
        matches = [m for m in matches if (meta.get(m.vuln_key) is not None and meta[m.vuln_key].sev_rank >= min_rank) and (not p.get("exploited_only") or meta[m.vuln_key].exploited)]
    groups: dict[tuple[str, str], list[M.Match]] = {}
    for m in matches:
        groups.setdefault((m.product_key, m.version), []).append(m)
    items = [{"kind": "product", "product_key": k[0], "product_name": g[0].product_name, "op": "any", "value": None, "branches": [], "product_ids": sorted(set(g[0].product_ids))}
             for k, g in groups.items() if g[0].product_ids]
    glist = [g for k, g in groups.items() if g[0].product_ids]
    rows_src: list[dict] = []
    if items:
        ctx.progress(f"чтение реестра ПО KSC: версий для проверки {len(items)}")

        def work():
            with Session(client.params) as conn:
                return audit.build_source(conn, source_name=ctx.source_name, items=items, rules={}, active_days=None, include_inactive=True, exclude_slaves=ctx.exclude_slaves,
                                          max_rows=ctx.max_rows, progress=ctx.progress, cancelled=ctx.cancelled)

        async with client._sem:  # noqa: SLF001
            rows_src, summ = await asyncio.to_thread(work)
        if summ.get("excluded_not_computers"):
            notes.append(f"Не вошли записи кластеров и подчинённых серверов (не компьютеры): {summ['excluded_not_computers']}.")
    only = {int(i) for i in p.get("host_ids") or []}
    if only:
        rows_src = [r for r in rows_src if int(r["host_id"]) in only]
    hosts = {}
    for r in rows_src:
        hosts.setdefault(r["host_id"], r)
    keep, info = apply_scope(hosts, p, ctx)
    notes += scope_notes(info, p, ctx)
    out: list[dict] = []
    seen: set[tuple] = set()
    for r in rows_src:
        if r["host_id"] not in keep:
            continue
        hp = host_part({**r, "os_version": ""}, p, ctx)
        for m in glist[r["item"]]:
            k = (r["host_id"], r["product_id"], m.vuln_key)
            if k in seen:
                continue
            seen.add(k)
            v = meta.get(m.vuln_key)
            rank = v.sev_rank if v else 0
            srcs = sorted(aff_ids.get(m.vuln_key, set()))
            out.append({**hp, "vuln_key": m.vuln_key, "ids": (v.ids_text.upper() if v else m.vuln_key)[:120], "title": (v.title if v else "")[:200], "severity": _level(rank), "rank": rank,
                        "severity_ru": SEV_RU[next((k2 for k2, r2 in SEV_RANK.items() if r2 == rank), "")], "kev": "да" if v and v.exploited else "", "status": m.status,
                        "status_ru": M.STATUS_RU[m.status], "basis": m.basis, "program": m.product_name, "installed_version": r["app_version"], "sources": ", ".join(srcs),
                        "fix": "есть сведения об исправлении" if v and v.has_fix else "нет сведений", "product_id": r["product_id"], "score": v.score if v else None})
    if len(out) > ctx.max_rows:
        raise KscError("too_many_rows", f"Обнаружений больше предела отчёта ({ctx.max_rows}): выберите меньше уязвимостей, повысьте порог опасности или сузьте статусы")
    out.sort(key=lambda x: (-int(bool(x["kev"])), -x["rank"], x["vuln_key"], x["name"].lower()))
    hosts_u = {r["host_id"] for r in out}
    installs = {(r["host_id"], r["product_id"]) for r in out}
    vulns_u = {r["vuln_key"] for r in out}
    by_status = {s: len({r["host_id"] for r in out if r["status"] == s}) for s in M.AFFECTED}
    kev_hosts = len({r["host_id"] for r in out if r["kev"]})
    worst: dict[int, str] = {}
    for r in out:
        lvl = "critical" if r["kev"] or r["rank"] >= 4 else _level(r["rank"])        # наличие в каталоге CISA KEV — наивысший приоритет независимо от оценки
        cur = worst.get(r["host_id"], "warning")
        worst[r["host_id"]] = lvl if ("warning", "high", "critical").index(lvl) > ("warning", "high", "critical").index(cur) else cur
    lv = {k: sum(1 for w in worst.values() if w == k) for k in ("critical", "high", "warning")}
    last_ok = [states[k].last_ok_at for k in states if states[k].enabled and states[k].last_ok_at]
    label = ", ".join(sorted(vulns_u)[:3]) + (f" и ещё {len(vulns_u) - 3}" if len(vulns_u) > 3 else "") if vulns_u else (", ".join(p.get("vuln_keys") or [])[:60] or "по продуктам")
    conds = [{"label": "Что проверено", "text": f"все известные уязвимости из внешних баз (с находками по каталогу источника): {len(keys)}" if p.get("all_known") else
             ("уязвимости: " + ", ".join((keys or p.get("vuln_keys") or [])[:10])) if keys and not pkeys else
             ("программы: " + ", ".join(x.name for x in prods if x.key in set(pkeys))[:300]) if pkeys else "—"},
             {"label": "Источники сведений", "text": ", ".join(f"{k.upper()} (обновлено {s.last_ok_at:%d.%m.%Y %H:%M} UTC)" for k, s in sorted(states.items()) if s.enabled and s.last_ok_at) or "локальная база пуста — загрузите источники"},
             {"label": "Статусы сопоставления", "text": ", ".join(M.STATUS_RU[s] for s in M.AFFECTED if s in want)}]
    conds += scope_conditions(p, ctx)
    if p.get("min_severity"):
        conds.append({"label": "Опасность не ниже", "text": SEV_RU[p["min_severity"]]})
    if p.get("exploited_only"):
        conds.append({"label": "Каталог CISA KEV", "text": "только уязвимости из каталога CISA KEV (известна эксплуатация в реальных атаках)"})
    notes = ["Это потенциальные уязвимости, найденные KAV Checker по внешним базам (NVD, CISA KEV, OSV, БДУ ФСТЭК) и каталогу установленного ПО; они НЕ подтверждены Kaspersky Security Center. "
             "Статус сопоставления и основание указаны в каждой строке; совпадение по одному названию программы подтверждением не считается."] + notes
    if by_status["clarify"] or by_status["potential"]:
        notes.append(f"Требуют ручной проверки: «потенциально затронуто» — компьютеров {by_status['potential']}, «требуется уточнение» — {by_status['clarify']} "
                     "(зависимость от среды или редакции, пакеты Linux с возможным переносом исправлений, версии без границ).")
    if not out:
        notes.append("По выбранным условиям затронутых компьютеров не найдено: нет совпадающих версий ПО в каталоге, либо версии исправлены, либо устройства вне периода связи.")
    metrics = [metric("hosts", "Затронуто компьютеров (уникальных)", len(hosts_u), "компьютер с несколькими уязвимостями или программами считается один раз", "danger" if hosts_u else "ok"),
               metric("installs", "Затронутых установок (компьютер × программа)", len(installs)), metric("vulns", "Различных уязвимостей", len(vulns_u)),
               metric("rows", "Обнаружений (компьютер × уязвимость × установка)", len(out)), metric("kev", "Компьютеров с уязвимостями из каталога CISA KEV", kev_hosts, "каталог CISA KEV — уязвимости с известной эксплуатацией в реальных атаках; это не означает, что эксплуатация идёт на этом компьютере", "danger" if kev_hosts else ""),
               metric("confirmed", "Подтверждено источником (компьютеров)", by_status["confirmed"]), metric("online", "Из затронутых в сети сейчас", sum(1 for h in hosts_u if hosts[h].get("online") is True),
                                                                                                                 f"не в сети: {sum(1 for h in hosts_u if hosts[h].get('online') is False)}; нет данных: {sum(1 for h in hosts_u if hosts[h].get('online') is None)}")]
    host_rows = summarize_hosts(out)
    by_prog: dict[tuple, dict] = {}
    for r in out:
        g = by_prog.setdefault((r["program"], r["installed_version"]), {"program": r["program"], "installed_version": r["installed_version"], "hosts": set(), "vulns": set(), "rank": 0, "best": ""})
        g["hosts"].add(r["host_id"])
        g["vulns"].add(r["vuln_key"])
        g["rank"] = max(g["rank"], r["rank"])
        g["best"] = max([g["best"] or "insufficient", r["status"]], key=lambda s: M.STATUS_RANK[s])
    prog_rows = sorted(({"program": g["program"], "installed_version": g["installed_version"], "hosts": len(g["hosts"]), "vulns": len(g["vulns"]), "status_ru": M.STATUS_RU[g["best"]],
                         "worst": SEV_RU[next((k for k, v in SEV_RANK.items() if v == g["rank"]), "")]} for g in by_prog.values()), key=lambda g: (-g["hosts"], g["program"].lower()))
    by_vuln: dict[str, dict] = {}
    for r in out:
        g = by_vuln.setdefault(r["vuln_key"], {"vuln_key": r["vuln_key"], "ids": r["ids"], "title": r["title"], "severity_ru": r["severity_ru"], "rank": r["rank"], "kev": r["kev"], "score": r["score"],
                                                "hosts": set(), "installs": set(), "best": "insufficient", "sources": r["sources"], "fix": r["fix"]})
        g["hosts"].add(r["host_id"])
        g["installs"].add((r["host_id"], r["product_id"]))
        g["best"] = max([g["best"], r["status"]], key=lambda s: M.STATUS_RANK[s])
    vuln_rows = sorted(({**{k: g[k] for k in ("vuln_key", "ids", "title", "severity_ru", "kev", "score", "sources", "fix")}, "hosts": len(g["hosts"]), "installs": len(g["installs"]),
                         "status_ru": M.STATUS_RU[g["best"]], "_r": g["rank"], "_k": bool(g["kev"])} for g in by_vuln.values()), key=lambda g: (-int(g["_k"]), -g["_r"], -g["hosts"]))
    for g in vuln_rows:
        g.pop("_r"), g.pop("_k")
    return {"title": f"Уязвимости по внешним базам: {label}", "subtitle": "Потенциально затронутые компьютеры по сведениям NVD, CISA KEV, OSV и БДУ ФСТЭК и каталогу установленного ПО",
            "conditions": conds, "metrics": metrics,
            "severity": {"title": "Компьютеры по наивысшему приоритету (сумма = затронуто компьютеров; наличие уязвимости в каталоге CISA KEV приравнено к критической)",
                         "levels": [{"key": k, "label": SEV_LABEL[k], "value": lv[k], "hint": ""} for k in ("critical", "high", "warning")]},
            "notes": notes, "tables": [
                {"id": "rows", "title": "Обнаружения", "columns": EXT_COLS, "rows": out, "note": "Одна строка — компьютер × уязвимость × установленная программа; у каждой строки указаны статус сопоставления и его основание. В таблице «Компьютеры» уязвимости считаются уникально (одна уязвимость на нескольких установках — одна), «Обнаружений» — строки этой таблицы."},
                {"id": "hosts", "title": "Компьютеры", "columns": [col("name", "Компьютер"), col("ip", "IP-адрес", "mono"), col("os", "ОС"), col("group", "Группа администрирования"), col("worst", "Наивысшая опасность", "sev"),
                                                                   col("vulns", "Уязвимостей (уникальных)", "num"), col("kev_n", "Из них в каталоге CISA KEV", "num"), col("confirmed", "Из них подтверждено источником", "num"), col("rows", "Обнаружений (установка × уязвимость)", "num"),
                                                                   col("kev_list", "Какие из них в KEV", "mono"), col("vuln_list", "Идентификаторы уязвимостей", "mono"), col("programs", "Программы и версии"),
                                                                   col("last_connected", "Последнее подключение к KSC (UTC)", "date"), col("active", "Связь за период"), col("online", "В сети сейчас")], "rows": host_rows},
                {"id": "programs", "title": "Программы", "columns": [col("program", "Программа"), col("installed_version", "Установленная версия", "mono"), col("hosts", "Компьютеров", "num"), col("vulns", "Уязвимостей", "num"),
                                                                    col("status_ru", "Лучший статус"), col("worst", "Наивысшая опасность", "sev")], "rows": prog_rows},
                {"id": "vulns", "title": "Уязвимости", "columns": [col("vuln_key", "Уязвимость", "mono"), col("ids", "Идентификаторы", "mono"), col("title", "Название"), col("severity_ru", "Опасность", "sev"), col("score", "CVSS", "num"),
                                                                    col("kev", "В каталоге CISA KEV"), col("hosts", "Компьютеров", "num"), col("installs", "Установок", "num"), col("status_ru", "Лучший статус"),
                                                                    col("sources", "Источники"), col("fix", "Исправление")], "rows": vuln_rows}]}


class ExtIndex:
    """Сопоставление «установленная запись реестра → потенциальные уязвимости» для источника: считается один раз на состояние баз и каталога порциями (без загрузки всех записей источников в память).
    Хранится компактно: запись реестра → номер версии каталога → кортежи (уязвимость, статус, основание); сведения об уязвимостях читаются позже только для найденных у компьютеров."""

    def __init__(self, by_pid: dict[int, int], versions: list[tuple[str, str]], hits: dict[int, list[tuple]], srcs: dict[str, str], notes: list[str], pnames: dict[str, str] | None = None):
        self.by_pid, self.versions, self.hits, self.srcs, self.notes, self.pnames = by_pid, versions, hits, srcs, notes, pnames or {}

    def matches_for(self, pid: int) -> list[tuple]:
        vid = self.by_pid.get(pid)
        return self.hits.get(vid, ()) if vid is not None else ()

    def stats(self) -> dict:
        return {"installs": len(self.by_pid), "versions": len(self.versions), "matches": sum(len(v) for v in self.hits.values()), "vulns": len(self.srcs)}


async def build_ext_index(ctx: Ctx, statuses: tuple[str, ...] = M.AFFECTED, *, res=None) -> ExtIndex:
    if ctx.sm is None or ctx.source_id is None:
        return ExtIndex({}, [], {}, {}, ["Внешние базы недоступны: нет доступа к локальной базе уязвимостей"])
    async with ctx.sm() as db:
        prods, maps = await M.load_context(db, ctx.source_id)
        if not prods:
            return ExtIndex({}, [], {}, {}, ["Каталог программ источника ещё не построен: потенциальные совпадения с внешними базами не рассчитаны"])
        matcher = M.Matcher(prods, maps)
        keys = sorted((await db.execute(select(VdbFinding.vuln_key).where(VdbFinding.source_id == ctx.source_id))).scalars().all())
        vid_of: dict[tuple[str, str], int] = {}
        versions: list[tuple[str, str]] = []
        by_pid: dict[int, int] = {}
        hits: dict[int, list[tuple]] = {}
        srcs: dict[str, str] = {}
        pnames: dict[str, str] = {}
        async for _part, rows in M.iter_affected(db, keys, 200):             # порциями по уязвимостям: в памяти только порция и компактный результат
            ms = [m for m in M.matches_from(matcher, rows) if m.status in statuses]
            if ms:
                by_src: dict[str, set[str]] = {}
                for a in rows:
                    by_src.setdefault(a.vuln_key, set()).add(a.source)
                for m in ms:
                    k = (m.product_key, m.version)
                    vid = vid_of.get(k)
                    if vid is None:
                        vid = vid_of[k] = len(versions)
                        versions.append(k)
                        for pid in m.product_ids:
                            by_pid[int(pid)] = vid
                    pnames[m.product_key] = m.product_name
                    hits.setdefault(vid, []).append((m.vuln_key, m.status, m.basis))
                    if m.vuln_key not in srcs:
                        srcs[m.vuln_key] = ", ".join(sorted(by_src.get(m.vuln_key, set())))
            del rows, ms
            if res is not None:
                await res.breathe("индекс внешних баз")
            if ctx.cancelled():
                raise RuntimeError("cancelled")
    return ExtIndex(by_pid, versions, hits, srcs, [], pnames)


async def ext_rows_for_hosts(client: SourceClient, ctx: Ctx, host_ids: list[int], *, index: ExtIndex | None = None, chunk: int = 400) -> tuple[list[dict], list[str]]:
    """Потенциальные совпадения с внешними базами для выбранных компьютеров (страницы и отчёты по зонам).
    Не обходит весь источник: сопоставление «уязвимость × версия каталога» берётся из индекса источника, затем читаются установки только выбранных компьютеров.
    Строки — как в build_extvulns, без полей компьютера (имя, адрес добавляет вызывающий по host_id). Возвращает (строки, замечания)."""
    index = index or await build_ext_index(ctx)
    if index.notes:
        return [], index.notes
    hits: list[tuple[dict, tuple]] = []
    seen: set[tuple] = set()
    for i in range(0, len(host_ids), chunk):
        if ctx.cancelled():
            raise RuntimeError("cancelled")
        for r in await client.run(q.INSTALLS_FOR_HOSTS.format(ids=q.ids_list(host_ids[i:i + chunk])), max_rows=2_000_000):
            pid = int(r["product_id"])
            vid = index.by_pid.get(pid)
            for m in (index.hits.get(vid, ()) if vid is not None else ()):
                k = (r["host_id"], pid, m[0])
                if k not in seen:
                    seen.add(k)
                    hits.append((r, (*m, index.versions[vid][0])))
        ctx.progress(f"внешние базы: совпадений {len(hits)}, компьютеров проверено {min(i + chunk, len(host_ids))} из {len(host_ids)}")
    need = sorted({m[0] for _, m in hits})
    meta: dict[str, VdbVuln] = {}
    async with ctx.sm() as db:
        for i in range(0, len(need), 400):
            for v in (await db.execute(select(VdbVuln).where(VdbVuln.vuln_key.in_(need[i:i + 400])))).scalars().all():
                meta[v.vuln_key] = v
    out: list[dict] = []
    for r, (vuln_key, status, basis, pkey) in hits:
        v = meta.get(vuln_key)
        rank = v.sev_rank if v else 0
        out.append({"host_id": int(r["host_id"]), "vuln_key": vuln_key, "ids": (v.ids_text.upper() if v else vuln_key)[:120], "title": (v.title if v else "")[:200],
                    "severity": "critical" if (v and v.exploited) or rank >= 4 else _level(rank), "rank": rank, "severity_ru": SEV_RU[next((k2 for k2, r2 in SEV_RANK.items() if r2 == rank), "")],
                    "kev": "да" if v and v.exploited else "", "status": status, "status_ru": M.STATUS_RU[status], "basis": basis, "program": index.pnames.get(pkey, pkey), "installed_version": r.get("version") or "",
                    "sources": index.srcs.get(vuln_key, ""), "fix": "есть сведения об исправлении" if v and v.has_fix else "нет сведений", "product_id": int(r["product_id"]),
                    "score": v.score if v else None, "app_name": r.get("name") or "", "publisher": r.get("publisher") or ""})
    return out, []
