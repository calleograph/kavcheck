"""Лицензии без двойного счёта. Одна и та же лицензия на нескольких KSC (общий пул) считается один раз: лимит общий, использование — сумма по серверам.

Что объединяется: (1) записи с одним отпечатком ключа (HMAC серийного номера — ключ узнаётся без хранения самого ключа); (2) записи, которые администратор отнёс к одному пулу вручную
(исходные данные KSC не меняются). Всё остальное — независимые лицензии каждого источника, они показываются раздельно и суммируются. Нет значения — «нет данных», а не ноль."""
from __future__ import annotations

from datetime import datetime

STATE_RANK = {"expired": 3, "expiring": 2, "active": 1, "unknown": 0}


def group_key(r: dict, overrides: dict[tuple[str, str], str]) -> tuple[str, str]:
    pool = overrides.get((str(r["source_id"]), r["lic_key"]))
    if pool:
        return "admin", f"pool:{pool.strip().lower()}"
    if r.get("fp"):
        return "fp", f"fp:{r['fp']}"
    return "own", f"own:{r['source_id']}:{r['lic_key']}"


def merge(records: list[dict], overrides: dict[tuple[str, str], str] | None = None) -> list[dict]:
    """Группы лицензий: product, kind, limit, used, free, expires_at, state, sources[], shared, basis, notes[]."""
    ov = overrides or {}
    groups: dict[str, dict] = {}
    for r in records:
        basis, key = group_key(r, ov)
        g = groups.setdefault(key, {"key": key, "basis": basis, "members": [], "pool": ov.get((str(r["source_id"]), r["lic_key"]), "")})
        g["members"].append(r)
    out = []
    for g in groups.values():
        ms: list[dict] = g["members"]
        limits = {m["limit_n"] for m in ms if m.get("limit_n") is not None}
        used_vals = [m["used_n"] for m in ms if m.get("used_n") is not None]
        exp = [m["expires_at"] for m in ms if isinstance(m.get("expires_at"), datetime)]
        shared = len({str(m["source_id"]) for m in ms}) > 1
        limit = max(limits) if limits else None
        notes = []
        if len(limits) > 1:
            notes.append(f"лимиты в источниках различаются ({', '.join(str(x) for x in sorted(limits))}): взят наибольший")
        used = sum(used_vals) if used_vals else None
        if used_vals and len(used_vals) < len(ms) and shared:
            notes.append("использование известно не по всем серверам пула: показана сумма известных")
        state = max((m.get("state") or "unknown" for m in ms), key=lambda s: STATE_RANK.get(s, 0))
        first = ms[0]
        out.append({"key": g["key"], "product": first.get("product") or "", "kind": ", ".join(sorted({m["kind"] for m in ms if m.get("kind")})), "limit": limit, "used": used,
                    "free": (max(0, limit - used) if limit is not None and used is not None else None), "over": bool(limit is not None and used is not None and used > limit),
                    "expires_at": min(exp) if exp else None, "state": state, "shared": shared, "basis": g["basis"], "pool": g["pool"], "notes": notes,
                    "origin": sorted({m.get("origin", "ksc") for m in ms}),
                    "sources": [{"id": str(m["source_id"]), "name": m.get("source_name", ""), "lic_key": m["lic_key"], "limit": m.get("limit_n"), "used": m.get("used_n"), "origin": m.get("origin", "ksc"),
                                 "updated_at": m.get("updated_at")} for m in ms]})
    out.sort(key=lambda x: (-STATE_RANK.get(x["state"], 0), x["product"].lower()))
    return out


def totals(groups: list[dict]) -> dict:
    """Итоги по группам: сумма известных лимитов и использования; complete=False, если у какой-то лицензии нет лимита или использования."""
    lim = [g["limit"] for g in groups if g["limit"] is not None]
    used = [g["used"] for g in groups if g["used"] is not None]
    known_both = [g for g in groups if g["limit"] is not None and g["used"] is not None]
    t_limit, t_used = sum(lim), sum(g["used"] for g in known_both)
    exp = [g["expires_at"] for g in groups if g["expires_at"] is not None and g["state"] != "expired"]
    return {"groups": len(groups), "limit": t_limit if lim else None, "used": sum(used) if used else None, "free": sum(g["free"] for g in known_both) if known_both else None,
            "share": round(100 * t_used / t_limit) if t_limit and known_both else None, "next_expiry": min(exp) if exp else None,
            "expired": sum(1 for g in groups if g["state"] == "expired"), "expiring": sum(1 for g in groups if g["state"] == "expiring"),
            "complete": all(g["limit"] is not None and g["used"] is not None for g in groups) and bool(groups), "shared": sum(1 for g in groups if g["shared"])}
