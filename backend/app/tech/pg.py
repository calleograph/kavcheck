"""PostgreSQL внутренней базы: доступность, соединения, активные и ожидающие запросы, блокировки, долгие транзакции, размеры таблиц, autovacuum, кеш.

Только системные представления (pg_stat_*, pg_class), никаких COUNT(*): число строк — оценка планировщика (reltuples). Вызывающий кэширует результат
(`activity` — десятки секунд, `tables` — минуты): страница не нагружает базу. Тексты запросов наружу — только обезличенные (`mask_sql`).
"""
from __future__ import annotations

import re
import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

APPS = {"kavcheck": "Backend (страницы и API)", "kavcheck-worker": "Worker (фоновые задания)", "kavcheck-pentest": "Сканер Pentest", "psql": "psql (вручную)"}
_STR = re.compile(r"'(?:[^']|'')*'")
_NUM = re.compile(r"(?<![\w$.])-?\d+(?:\.\d+)?\b")
_LIST = re.compile(r"\((?:\s*\?\s*,)+\s*\?\s*\)")
_KIND = re.compile(r"^\s*(?:/\*.*?\*/\s*)?(WITH|SELECT|INSERT|UPDATE|DELETE|COPY|VACUUM|ANALYZE|CREATE|ALTER|DROP|TRUNCATE|BEGIN|COMMIT|LOCK|REINDEX|REFRESH)\b", re.I | re.S)
_TABLE = re.compile(r"\b(?:FROM|INTO|UPDATE|JOIN|TABLE)\s+\"?([a-z_][a-z0-9_]*)\"?", re.I)


def mask_sql(q: str | None, limit: int = 600) -> str:
    """Текст запроса без значений: строки, числа и списки значений заменены на «?» (персональные данные, имена компьютеров и адреса из параметров не видны)."""
    if not q:
        return ""
    q = _STR.sub("?", q)
    q = _NUM.sub("?", q)
    q = _LIST.sub("(…)", q)
    q = re.sub(r"\s+", " ", q).strip()
    return q[:limit] + ("…" if len(q) > limit else "")


def kind_of(q: str | None) -> str:
    m = _KIND.match(q or "")
    return m.group(1).upper() if m else ("—" if not q else "другое")


def table_of(q: str | None) -> str:
    m = _TABLE.search(q or "")
    return m.group(1) if m else ""


async def activity(db: AsyncSession, *, long_s: float = 30.0) -> dict[str, Any]:
    """Соединения и запросы сейчас (кроме этого): по состояниям и службам, активные дольше `long_s`, ожидающие, блокировки «кто кого держит», долгие транзакции."""
    t0 = time.perf_counter()
    await db.execute(text("SELECT 1"))
    ping_ms = round((time.perf_counter() - t0) * 1000, 1)
    ver = (await db.execute(text("SHOW server_version"))).scalar_one()
    maxc = int((await db.execute(text("SHOW max_connections"))).scalar_one())
    rows = (await db.execute(text(
        "SELECT pid, COALESCE(application_name, ''), COALESCE(state, ''), COALESCE(wait_event_type, ''), COALESCE(wait_event, ''), COALESCE(backend_type, ''), "
        "EXTRACT(EPOCH FROM now() - query_start)::float8, EXTRACT(EPOCH FROM now() - xact_start)::float8, pg_blocking_pids(pid), left(query, 4000) "
        "FROM pg_stat_activity WHERE (datname = current_database() OR backend_type = 'autovacuum worker') AND pid <> pg_backend_pid()"))).all()
    by_state: dict[str, int] = {}
    by_app: dict[str, int] = {}
    procs: dict[int, dict] = {}
    for pid, app, state, wtype, wev, btype, q_s, x_s, blocked, q in rows:
        if btype not in ("client backend", "autovacuum worker"):
            continue
        app_ru = "autovacuum" if btype == "autovacuum worker" else APPS.get(app, app or "без имени")
        by_state[state or "—"] = by_state.get(state or "—", 0) + 1
        by_app[app_ru] = by_app.get(app_ru, 0) + 1
        procs[pid] = {"pid": pid, "app": app_ru, "state": state, "wait": f"{wtype}: {wev}" if wtype else "", "wait_type": wtype, "query_s": round(q_s or 0, 1), "xact_s": round(x_s or 0, 1) if x_s else None,
                      "kind": "VACUUM" if app_ru == "autovacuum" else kind_of(q), "table": (q or "").split()[-1].split(".")[-1] if app_ru == "autovacuum" and q else table_of(q),
                      "sql": mask_sql(q), "blocked_by": list(blocked or [])}
    active = sorted((p for p in procs.values() if p["state"] == "active"), key=lambda p: -p["query_s"])
    waiting = [p for p in procs.values() if p["blocked_by"] or (p["state"] == "active" and p["wait_type"] == "Lock")]
    locks = []
    for w in waiting:
        for b in w["blocked_by"]:
            h = procs.get(b, {"pid": b, "app": "другой процесс", "state": "", "kind": "", "table": "", "query_s": None, "xact_s": None})
            locks.append({"waiting": {k: w[k] for k in ("pid", "app", "kind", "table", "query_s")}, "holder": {k: h.get(k) for k in ("pid", "app", "state", "kind", "table", "query_s", "xact_s")}})
    long_x = sorted((p for p in procs.values() if (p["xact_s"] or 0) >= 60), key=lambda p: -(p["xact_s"] or 0))
    st = (await db.execute(text("SELECT blks_read, blks_hit, temp_files, temp_bytes, deadlocks, xact_commit, xact_rollback, pg_database_size(current_database()) "
                                "FROM pg_stat_database WHERE datname = current_database()"))).first()
    stats = None
    if st:
        reads, hits = int(st[0] or 0), int(st[1] or 0)
        stats = {"blks_read": reads, "blks_hit": hits, "cache_hit_pct": round(100.0 * hits / (hits + reads), 2) if hits + reads else None, "temp_files": int(st[2] or 0), "temp_bytes": int(st[3] or 0),
                 "deadlocks": int(st[4] or 0), "commits": int(st[5] or 0), "rollbacks": int(st[6] or 0), "size": int(st[7] or 0)}
    return {"ok": True, "version": ver, "ping_ms": ping_ms, "max_connections": maxc, "connections": sum(by_state.values()), "by_state": by_state, "by_app": by_app,
            "active": len(active), "long": [p for p in active if p["query_s"] >= long_s][:15], "waiting": len(waiting), "locks": locks[:20], "long_xact": long_x[:10],
            "autovacuum": [{"table": p["table"], "query_s": p["query_s"]} for p in procs.values() if p["app"] == "autovacuum"], "stats": stats, "at": time.time()}


async def tables(db: AsyncSession, n: int = 20) -> dict[str, Any]:
    """Крупнейшие таблицы и индексы: размер, оценка числа строк, мёртвые строки, последний autovacuum/analyze. Не чаще раза в несколько минут (pg_total_relation_size обходит файлы)."""
    rows = (await db.execute(text(
        "SELECT c.relname, GREATEST(c.reltuples, 0)::bigint, pg_total_relation_size(c.oid), pg_relation_size(c.oid), pg_indexes_size(c.oid), "
        "COALESCE(s.n_live_tup, 0), COALESCE(s.n_dead_tup, 0), s.last_autovacuum, s.last_vacuum, s.last_autoanalyze, COALESCE(s.seq_scan, 0), COALESCE(s.idx_scan, 0) "
        "FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid "
        "WHERE c.relkind IN ('r', 'p') AND ns.nspname = current_schema() ORDER BY pg_total_relation_size(c.oid) DESC LIMIT :n"), {"n": n})).all()
    items = []
    for name, est, total, heap, idx, live, dead, av, v, aa, seq, iscan in rows:
        items.append({"table": name, "rows_est": int(est), "total": int(total), "heap": int(heap), "indexes": int(idx), "dead": int(dead),
                      "dead_pct": round(100.0 * dead / (live + dead), 1) if live + dead else 0.0, "last_vacuum": max((x for x in (av, v) if x), default=None), "last_analyze": aa,
                      "seq_scan": int(seq), "idx_scan": int(iscan)})
    idx = (await db.execute(text(
        "SELECT i.relname, t.relname, pg_relation_size(i.oid), COALESCE(s.idx_scan, 0) FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_class t ON t.oid = x.indrelid "
        "JOIN pg_namespace ns ON ns.oid = i.relnamespace LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = i.oid WHERE ns.nspname = current_schema() "
        "ORDER BY pg_relation_size(i.oid) DESC LIMIT 10"))).all()
    return {"items": items, "indexes": [{"index": a, "table": b, "size": int(c), "scans": int(d)} for a, b, c, d in idx], "at": time.time()}
