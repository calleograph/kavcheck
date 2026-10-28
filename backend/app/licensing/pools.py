"""Лицензии без двойного счёта. Одна и та же лицензия на нескольких KSC (общий пул) считается один раз: лимит общий, использование — сумма по серверам.

Что объединяется: (1) записи с одним отпечатком ключа (HMAC серийного номера — ключ узнаётся без хранения самого ключа); (2) записи, которые администратор отнёс к одному пулу вручную
(исходные данные KSC не меняются). Всё остальное — независимые лицензии каждого источника, они показываются раздельно и суммируются. Нет значения — «нет данных», а не ноль."""
from __future__ import annotations

from datetime import datetime

STATE_RANK = {"expired": 4, "expiring": 3, "unknown": 2, "active": 1, "perpetual": 0}
VALID = ("active", "expiring", "perpetual")          # действующие на сегодня; истёкшие и «срок неизвестен» в лимит действующих не входят


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
        dated = [m for m in ms if isinstance(m.get("expires_at"), datetime)]
        shared = len({str(m["source_id"]) for m in ms}) > 1
        limit = max(limits) if limits else None
        notes = []
        if len(limits) > 1:
            notes.append(f"лимиты в источниках различаются ({', '.join(str(x) for x in sorted(limits))}): взят наибольший")
        used = sum(used_vals) if used_vals else None
        if used_vals and len(used_vals) < len(ms) and shared:
            notes.append("использование известно не по всем серверам пула: показана сумма известных")
        # одна лицензия, записанная на нескольких серверах, имеет один срок; если сроки разошлись (продление), верна запись с самой поздней датой, бессрочная — выше любой даты
        latest = max(dated, key=lambda m: m["expires_at"]) if dated else None
        state = "perpetual" if any(m.get("state") == "perpetual" for m in ms) else (latest.get("state") or "unknown") if latest else "unknown"
        first = ms[0]
        out.append({"key": g["key"], "product": first.get("product") or "", "kind": ", ".join(sorted({m["kind"] for m in ms if m.get("kind")})), "limit": limit, "used": used,
                    "free": (max(0, limit - used) if limit is not None and used is not None else None), "over": bool(limit is not None and used is not None and used > limit),
                    "expires_at": None if state == "perpetual" else latest["expires_at"] if latest else None, "state": state, "shared": shared, "basis": g["basis"], "pool": g["pool"], "notes": notes,
                    "origin": sorted({m.get("origin", "ksc") for m in ms}),
                    "sources": [{"id": str(m["source_id"]), "name": m.get("source_name", ""), "lic_key": m["lic_key"], "limit": m.get("limit_n"), "used": m.get("used_n"), "origin": m.get("origin", "ksc"),
                                 "updated_at": m.get("updated_at")} for m in ms]})
    out.sort(key=lambda x: (-STATE_RANK.get(x["state"], 0), x["product"].lower()))
    return out


def totals(groups: list[dict]) -> dict:
    """Итоги. **limit — только действующие на сегодня лицензии** (действует, скоро истекает, бессрочная); истёкшие остаются в списке, но в сумму не входят, лицензии с неизвестным сроком
    считаются отдельно (unknown_limit). Использование и «свободно» — тоже по действующим; нет использования хотя бы у одной из них — «нет данных», а не предположение."""
    valid = [g for g in groups if g["state"] in VALID]
    unknown = [g for g in groups if g["state"] == "unknown"]
    expired = [g for g in groups if g["state"] == "expired"]
    lim = [g["limit"] for g in valid if g["limit"] is not None]
    used = [g["used"] for g in valid if g["used"] is not None]
    complete = bool(valid) and all(g["limit"] is not None and g["used"] is not None for g in valid)
    t_limit = sum(lim)
    exp = [g["expires_at"] for g in valid if g["expires_at"] is not None]
    ulim = [g["limit"] for g in unknown if g["limit"] is not None]
    elim = [g["limit"] for g in expired if g["limit"] is not None]
    return {"groups": len(groups), "valid": len(valid), "limit": t_limit if lim else (0 if groups and not valid else None), "used": sum(used) if used else None,
            "free": sum(g["free"] for g in valid) if complete else None, "share": round(100 * sum(used) / t_limit) if complete and t_limit else None,
            "next_expiry": min(exp) if exp else None, "expired": len(expired), "expired_limit": sum(elim) if elim else None, "expiring": sum(1 for g in valid if g["state"] == "expiring"),
            "perpetual": sum(1 for g in valid if g["state"] == "perpetual"), "unknown": len(unknown), "unknown_limit": sum(ulim) if ulim else None,
            "complete": complete, "shared": sum(1 for g in groups if g["shared"])}
