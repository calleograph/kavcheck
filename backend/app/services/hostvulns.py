"""Единый список уязвимостей компьютера: данные KSC (подтверждённые) и результат проверки по внешним базам (потенциальные) в одной таблице.

Правила: уязвимость, найденная обоими источниками (тот же идентификатор CVE и та же версия программы), — одна строка с обоими источниками; отсутствие записи KSC не означает отсутствия уязвимости,
если внешняя база нашла совпадение; подтверждённое KSC и предварительное совпадение по версии различаются полем `verdict`."""
from __future__ import annotations

SEV_RU = {"critical": "Критическая", "high": "Высокая", "warning": "Средняя и ниже"}
SEV_ORDER = {"critical": 3, "high": 2, "warning": 1}


def ext_severity(rank: int) -> str:
    return "critical" if rank >= 4 else "high" if rank == 3 else "warning"


def _same_version(a: str, b: str) -> bool:
    """Версии одной установки: совпадают после нормализации либо одна — начало другой по границе «.», «-», «+», «~» (каталог мог отбросить эпоху и ревизию пакета)."""
    a, b = (a or "").strip().lower(), (b or "").strip().lower()
    if not a or not b or a == b:
        return True                                  # у одной из записей версии нет — сопоставляем только по идентификатору
    short, long = sorted((a, b), key=len)
    return long.startswith(short) and long[len(short)] in ".-+~:_"


def merge(ksc: list[dict], ext: list[dict]) -> list[dict]:
    """ksc — строки `ksc.vulns.on_host`, ext — строки `api.vdb.host_ext_items`. Возвращает объединённый список без дублей, самые важные первыми."""
    rows: list[dict] = []
    ksc_rows: list[tuple[dict, set[str]]] = []
    for k in ksc:
        sev = k.get("severity") or "warning"
        cves = [c.upper() for c in k.get("cve") or []]
        row = {"id": f"ksc:{k.get('occurrence_id') or k.get('kla_id')}", "keys": cves or [k.get("kla_id") or "—"], "kla_id": k.get("kla_id") or "", "title": "", "severity": sev, "severity_ru": SEV_RU.get(sev, ""),
               "product": k.get("product") or k.get("app_name") or "", "version": k.get("app_version") or k.get("product_version") or "", "detected_by": ["ksc"], "verdict": "confirmed_ksc",
               "verdict_ru": "Подтверждено KSC", "basis": "найдено Kaspersky Security Center", "ksc": {"url": k.get("url") or "", "patches_available": bool(k.get("patches_available")), "kb": k.get("kb") or [],
                                                                                                          "detected": k.get("detected")}, "external": None, "exploited": False, "sources": ["KSC"]}
        rows.append(row)
        ksc_rows.append((row, {c for c in cves} | {(k.get("kla_id") or "").upper()}))
    for e in ext:
        names = {str(e.get("key") or "").upper(), *(str(x).upper() for x in e.get("ids") or [])}
        sev = ext_severity(int(e.get("sev_rank") or 0))
        hit = [row for row, ids in ksc_rows if ids & names and _same_version(row["version"], e.get("version") or "")]
        ext_info = {"key": e.get("key"), "status": e.get("status"), "status_ru": e.get("status_ru"), "basis": e.get("basis"), "databases": e.get("sources") or []}
        if hit:
            for row in hit:                                  # то же найдено KSC: источник дополняется, критичность — наибольшая из двух, повторной строки нет
                row["detected_by"] = ["ksc", "external"]
                row["external"] = ext_info
                row["title"] = row["title"] or e.get("title") or ""
                row["exploited"] = row["exploited"] or bool(e.get("exploited"))
                row["sources"] = ["KSC", *ext_info["databases"]]
                if SEV_ORDER[sev] > SEV_ORDER[row["severity"]]:
                    row["severity"], row["severity_ru"] = sev, SEV_RU[sev]
            continue
        confirmed = e.get("status") == "confirmed"
        rows.append({"id": f"ext:{e.get('key')}:{e.get('product')}:{e.get('version')}", "keys": [e.get("key")], "kla_id": "", "title": e.get("title") or "", "severity": sev, "severity_ru": SEV_RU[sev],
                     "product": e.get("product") or "", "version": e.get("version") or "", "detected_by": ["external"], "verdict": "confirmed_ext" if confirmed else "potential",
                     "verdict_ru": "Подтверждено внешней базой" if confirmed else "Потенциальная", "basis": e.get("basis") or "", "ksc": None,
                     "external": ext_info, "exploited": bool(e.get("exploited")), "sources": list(ext_info["databases"])})
    rows.sort(key=lambda r: (-SEV_ORDER[r["severity"]], not r["exploited"], r["verdict"] != "confirmed_ksc", r["keys"][0] if r["keys"] else ""))
    return rows


def counts(rows: list[dict]) -> dict:
    return {"total": len(rows), "confirmed_ksc": sum(1 for r in rows if r["verdict"] == "confirmed_ksc"), "confirmed_ext": sum(1 for r in rows if r["verdict"] == "confirmed_ext"),
            "potential": sum(1 for r in rows if r["verdict"] == "potential"), "critical": sum(1 for r in rows if r["severity"] == "critical"), "high": sum(1 for r in rows if r["severity"] == "high"),
            "warning": sum(1 for r in rows if r["severity"] == "warning")}
