"""Критерии поиска: CVE (диапазоны уязвимых версий из базы уязвимостей) и продукты (условия по версии). Данные берутся из базы уязвимостей и каталога программ KAV Checker."""
from __future__ import annotations

import re
from collections import Counter

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ksc import versions as V
from ..models import CatalogProduct, PtCheck, PtPort, VdbAffected, VdbVuln
from . import kb as KB

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
MODES = ("any", "exact", "range", "below", "above")
PORT_CAP = 20


def _up(v: str) -> str:
    return V.upstream((v or "").strip())


def in_range(r: dict, ver: str) -> bool:
    """Версия входит в диапазон записи базы уязвимостей (границы по алгоритму dpkg; без границ — затронуты все версии)."""
    if r.get("all"):
        return True
    v = _up(ver)
    if r.get("exact"):
        return V.compare(v, _up(r["exact"])) == 0
    ok = False
    if r.get("start"):
        c = V.compare(v, _up(r["start"]))
        if c < 0 or (c == 0 and not r.get("start_incl", True)):
            return False
        ok = True
    if r.get("end"):
        c = V.compare(v, _up(r["end"]))
        if c > 0 or (c == 0 and not r.get("end_incl", False)):
            return False
        ok = True
    return ok


def version_in(c: dict, ver: str) -> bool | None:
    """Входит ли версия в условие критерия: True / False / None (версия неизвестна либо условия нельзя проверить)."""
    if not (ver or "").strip():
        return None
    v = _up(ver)
    if c.get("ranges"):
        return any(in_range(r, v) for r in c["ranges"])
    m = c.get("mode", "any")
    if c.get("kind") == "cve":
        return None                                                  # данных о диапазонах нет: достоверно судить нельзя
    if m == "any":
        res = True
    elif m == "exact":
        res = any(V.compare(v, _up(x)) == 0 for x in c.get("versions", []))
    elif m == "range":
        res = (not c.get("v_min") or V.compare(v, _up(c["v_min"])) >= 0) and (not c.get("v_max") or V.compare(v, _up(c["v_max"])) <= 0)
    elif m == "below":
        res = V.compare(v, _up(c.get("below", ""))) < 0
    elif m == "above":
        res = V.compare(v, _up(c.get("above", ""))) > 0
    else:
        return None
    if res and c.get("only_vulnerable") and c.get("vuln_ranges") is not None:
        res = any(in_range(r, v) for r in c["vuln_ranges"])
    if res and c.get("only_eol") and c.get("eol_cycles") is not None:
        res = any(v == x or v.startswith(x + ".") for x in c["eol_cycles"])
    return res


def _range_row(a: VdbAffected) -> dict:
    return {"vendor": a.vendor, "product": a.product, "exact": a.exact, "start": a.v_start, "start_incl": a.v_start_incl, "end": a.v_end, "end_incl": a.v_end_incl, "fixed": a.fixed,
            "all": a.versions_all or not (a.exact or a.v_start or a.v_end), "platform": a.platform, "conditional": a.conditional}


async def checks_for(db: AsyncSession, cve: str) -> list[dict]:
    """Безопасные специализированные проверки (разрешённые шаблоны Nuclei) для CVE."""
    rows = (await db.execute(select(PtCheck.check_id, PtCheck.name, PtCheck.cves).where(PtCheck.engine == "nuclei", PtCheck.state == "allowed", PtCheck.cves.is_not(None)))).all()
    return [{"id": r.check_id, "engine": "nuclei", "name": r.name} for r in rows if cve.upper() in [str(x).upper() for x in (r.cves or [])]][:5]


async def suggest_ports(db: AsyncSession, kb_key: str | None, aliases: list[str]) -> list[int]:
    """Порты: обычные для продукта и порты прежних сканирований, где сервис с таким названием уже находился (первые — самые частые)."""
    ports: list[int] = list(KB.KB.get(kb_key or "", {}).get("ports", []))
    if aliases:
        conds = [func.lower(PtPort.product).like(f"%{a.lower()}%") for a in aliases[:4]] + [func.lower(PtPort.service) == a.lower() for a in aliases[:4]]
        top = (await db.execute(select(PtPort.port, func.count()).where(or_(*conds), PtPort.proto == "tcp").group_by(PtPort.port).order_by(func.count().desc()).limit(5))).all()
        ports += [int(p) for p, _n in top]
    return list(dict.fromkeys(ports))[:PORT_CAP]


async def resolve_cve(db: AsyncSession, cve: str) -> dict:
    cve = cve.strip().upper()
    v = await db.get(VdbVuln, cve)
    aff = (await db.execute(select(VdbAffected).where(VdbAffected.vuln_key == cve).limit(400))).scalars().all()
    cpe = [a for a in aff if a.vendor_key or a.product_key]
    keyc = Counter(KB.kb_for_cpe(a.vendor_key, a.product_key) or KB.kb_for_text(a.product) for a in cpe)
    keyc.pop(None, None)
    kb_key = keyc.most_common(1)[0][0] if keyc else None
    rel = [a for a in cpe if (KB.kb_for_cpe(a.vendor_key, a.product_key) or KB.kb_for_text(a.product)) == kb_key] if kb_key else cpe
    ranges = [_range_row(a) for a in rel][:200]
    title = (v.title if v and v.title else cve)
    warns: list[str] = []
    checks = await checks_for(db, cve)
    if not v and not aff:
        warns.append("CVE нет в базе уязвимостей KAV Checker: диапазоны версий неизвестны, достоверно проверить удалённо нельзя.")
    if not ranges:
        warns.append("В базе нет диапазонов уязвимых версий для этой CVE: версия сервиса не сопоставляется. Доступны поиск продукта и данные KSC.")
    if any(r.get("conditional") for r in ranges):
        warns.append("Уязвимость зависит от конфигурации или среды выполнения: версии недостаточно, результат — «Вероятно» или «Требует проверки».")
    if not checks:
        warns.append("Безопасной специализированной проверки (Nuclei/NSE) для этой CVE нет: максимум — «Вероятно» по версии продукта.")
    if kb_key and KB.KB[kb_key]["note"]:
        warns.append(KB.KB[kb_key]["note"])
    prod = KB.KB[kb_key]["title"] if kb_key else (rel[0].product if rel else "")
    return {"key": cve, "kind": "cve", "title": f"{cve}: {title}"[:300], "cve": cve, "kb": kb_key or "", "product": prod, "mode": "ranges", "ranges": ranges, "versions": [], "catalog": KB.KB[kb_key]["catalog"] if kb_key else ([f"{prod}*"] if prod else []), "ports": await suggest_ports(db, kb_key, KB.KB[kb_key]["aliases"] if kb_key else []),
            "checks": checks, "warnings": warns, "known": bool(v), "severity": v.sev_rank if v else 0, "score": v.score if v else None, "exploited": bool(v and v.exploited)}


async def resolve_product(db: AsyncSession, spec: dict) -> dict:
    """Продукт из каталога программ (источник + ключ) либо по названию; условие по версии — как в запросе. Нормализация продуктов — каталог KAV Checker, а не отдельная база."""
    name = (spec.get("name") or "").strip()
    cat = None
    if spec.get("source_id") and spec.get("product_key"):
        cat = (await db.execute(select(CatalogProduct).where(CatalogProduct.source_id == spec["source_id"], CatalogProduct.key == spec["product_key"]))).scalar_one_or_none()
        if cat is not None:
            name = cat.name
    kb_key = spec.get("kb") or KB.kb_for_text(name)
    mode = spec.get("mode") if spec.get("mode") in MODES else "any"
    c: dict = {"key": f"prod:{kb_key or KB.norm(name)}"[:80], "kind": "product", "title": name or (KB.KB[kb_key]["title"] if kb_key else ""), "cve": "", "kb": kb_key or "", "product": name, "mode": mode,
               "versions": [v.strip() for v in spec.get("versions", []) if str(v).strip()][:50], "v_min": (spec.get("v_min") or "").strip(), "v_max": (spec.get("v_max") or "").strip(), "below": (spec.get("below") or "").strip(),
               "above": (spec.get("above") or "").strip(), "only_vulnerable": bool(spec.get("only_vulnerable")), "only_eol": bool(spec.get("only_eol")), "ranges": [], "checks": [], "warnings": [],
               "catalog": [cat.name + "*"] if cat is not None else (KB.KB[kb_key]["catalog"] if kb_key else ([name + "*"] if name else []))}
    if mode == "exact" and not c["versions"] or mode == "range" and not (c["v_min"] or c["v_max"]) or mode == "below" and not c["below"] or mode == "above" and not c["above"]:
        raise ValueError(f"Для условия «{mode}» не указана версия")
    if not (name or kb_key):
        raise ValueError("Не указан продукт")
    if c["only_vulnerable"] and kb_key:
        aff = (await db.execute(select(VdbAffected).where(VdbAffected.product_key.in_([KB.norm(p) for _v, p in KB.KB[kb_key]["cpe"]])).limit(1500))).scalars().all()
        c["vuln_ranges"] = [_range_row(a) for a in aff]
    elif c["only_vulnerable"]:
        c["warnings"].append("Для продукта нет сопоставления с базой уязвимостей: условие «только версии с уязвимостями» не применено.")
        c["only_vulnerable"] = False
    if c["only_eol"]:
        from ..models import EolFinding  # noqa: PLC0415

        rows = (await db.execute(select(EolFinding.version).where(EolFinding.kind == "app", EolFinding.status == "eol", func.lower(EolFinding.subject).like(f"%{(name or kb_key).lower()}%")).distinct().limit(200))).scalars().all()
        c["eol_cycles"] = [str(r) for r in rows]
        if not rows:
            c["warnings"].append("Версий этого продукта с завершённой поддержкой в данных EOL нет: условие не даёт совпадений.")
    c["ports"] = await suggest_ports(db, kb_key, KB.KB[kb_key]["aliases"] if kb_key else ([name.lower()] if name else []))
    if kb_key and KB.KB[kb_key]["note"]:
        c["warnings"].append(KB.KB[kb_key]["note"])
    if not kb_key:
        c["warnings"].append("Продукт не входит в список с известными признаками версии в ответах сервисов: сетевая проверка опирается на название, найденное Nmap; надёжнее данные KSC.")
    return c


def describe_condition(c: dict) -> str:
    if c["kind"] == "cve":
        return "версии из базы уязвимостей" if c.get("ranges") else "диапазоны неизвестны"
    m = c["mode"]
    return {"any": "любая версия", "exact": "версии: " + ", ".join(c["versions"]), "range": f"от {c['v_min'] or '…'} до {c['v_max'] or '…'}", "below": f"ниже {c['below']}", "above": f"выше {c['above']}"}[m] \
        + (", только с известными уязвимостями" if c.get("only_vulnerable") else "") + (", только с завершённой поддержкой" if c.get("only_eol") else "")
