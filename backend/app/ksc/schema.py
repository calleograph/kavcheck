"""Проверка подключения и совместимости источника: версия SQL Server, база, версия KSC, наличие объектов для каждой функции, права учётной записи."""
from __future__ import annotations

import time

from . import queries as q
from .driver import ConnParams, KscError, Session

FEATURE_TITLES = {"hosts": "Компьютеры и активность", "software": "Реестр установленного ПО", "protection": "Состояние защиты",
                  "vulnerabilities": "Уязвимости (KSC)", "events": "События безопасности", "users": "Пользователи устройств", "hardware": "Оборудование устройств"}


def diagnose(params: ConnParams) -> dict:
    """Пошаговая диагностика. Выполняется в рабочем потоке; результат безопасен для показа и хранения (без пароля)."""
    stages: list[dict] = []
    out: dict = {"ok": False, "stages": stages, "features": {}, "warnings": []}

    def stage(name: str, ok: bool | None, message: str, started: float) -> None:
        stages.append({"stage": name, "ok": ok, "message": message, "ms": int((time.perf_counter() - started) * 1000)})

    t = time.perf_counter()
    try:
        s = Session(params).__enter__()
    except KscError as exc:
        stage("connect", False, exc.message, t)
        return out
    try:
        stage("connect", True, f"Соединение установлено (TLS: {params.tls_mode})", t)
        t = time.perf_counter()
        info = s.query(q.SERVER_INFO, max_rows=1)[0]
        out["server"] = {"version": str(info.get("version") or ""), "edition": str(info.get("edition") or ""), "database": str(info.get("db_name") or ""), "collation": str(info.get("collation") or "")}
        stage("server", True, f"SQL Server {out['server']['version']} {out['server']['edition']}, база {out['server']['database']}", t)
        t = time.perf_counter()
        wanted = sorted({n for names in q.FEATURE_OBJECTS.values() for n in names})
        present = {r["name"].lower() for r in s.query(q.OBJECTS_EXIST.format(names=", ".join(f"N'{n}'" for n in wanted)), max_rows=1000)}
        for feat, names in q.FEATURE_OBJECTS.items():
            missing = [n for n in names if n.lower() not in present]
            out["features"][feat] = {"ok": not missing, "title": FEATURE_TITLES[feat], "missing": missing}
        ok_feats = [FEATURE_TITLES[f] for f, v in out["features"].items() if v["ok"]]
        bad = [f"{FEATURE_TITLES[f]} (нет {', '.join(v['missing'])})" for f, v in out["features"].items() if not v["ok"]]
        stage("objects", bool(ok_feats), ("Доступны: " + ", ".join(ok_feats) if ok_feats else "Нужные объекты KSC не найдены") + ("; недоступны: " + "; ".join(bad) if bad else ""), t)
        t = time.perf_counter()
        try:
            roles = s.query(q.DB_ROLES, max_rows=1)[0]
            out["roles"] = {k: bool(roles.get(k)) for k in ("datareader", "datawriter", "owner", "ddladmin")}
            out["db_user"] = str(roles.get("db_user") or "")
            write = [n for n in ("datawriter", "owner", "ddladmin") if out["roles"][n]]
            if write:
                out["warnings"].append(f"У учётной записи есть права на запись ({', '.join(write)}). Рекомендуется отдельная учётная запись только с db_datareader.")
            stage("rights", True, "Права проверены: " + ("только чтение" if not write else "ЕСТЬ права на запись — " + ", ".join(write)), t)
        except KscError as exc:
            stage("rights", None, f"Права проверить не удалось: {exc.message}", t)
        t = time.perf_counter()
        try:
            rows = s.query(q.KSC_VERSION, max_rows=1) if out["features"]["protection"]["ok"] else []
            out["ksc_version"] = str(rows[0]["build"]) if rows else None
            stage("ksc", True, f"Версия KSC: {out['ksc_version']}" if out["ksc_version"] else "Версия KSC не определена", t)
        except KscError as exc:
            stage("ksc", None, f"Версия KSC не определена: {exc.message}", t)
        t = time.perf_counter()
        if out["features"]["hosts"]["ok"]:
            n = s.query(q.COUNT_HOSTS, max_rows=1)[0]["n"]
            out["hosts"] = int(n)
            stage("read", True, f"Пробное чтение: управляемых устройств {n}", t)
        out["ok"] = all(x["ok"] is not False for x in stages) and out["features"]["hosts"]["ok"] and out["features"]["software"]["ok"]
    except KscError as exc:
        stage("error", False, exc.message, t)
    finally:
        s.__exit__(None, None, None)
    return out
