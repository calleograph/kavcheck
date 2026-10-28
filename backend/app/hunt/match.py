"""Сопоставление результатов сетевой проверки с критериями CVE Hunt (этап «analysis» сканера в заданиях целевого поиска).

CVE-критерий: применимость, версии и исправления дистрибутива оценивает тот же анализ, что и в Pentest (`pentest/analyze.py`), результат фильтруется по выбранной CVE — посторонние CVE в результат не попадают.
Продукт-критерий: продукт определяется по CPE/названию Nmap либо по признаку в ответе (заголовок, баннер), версия сравнивается с условием. Подтверждает только проверка (Nuclei/NSE) для CVE; версия в диапазоне — «Вероятно»."""
from __future__ import annotations

import dataclasses
import re
from datetime import datetime

from sqlalchemy import delete, select

from ..models import HuntHit, PtHit, PtHost, PtPort, utcnow
from ..pentest import analyze as A
from ..pentest import applic as AP
from ..pentest.read import mask_secrets
from . import criteria as C
from . import kb as KB
from . import results as RS


def _blob(s: A.Svc) -> str:
    return "\n".join([s.banner or "", s.extrainfo or "", *[(x.get("output") or "") for x in s.scripts if x.get("id") != "nuclei"]])


def detect(c: dict, s: A.Svc, ident: A.Ident | None) -> dict:
    """Обнаружен ли продукт критерия на сервисе: {found, version, how, text}."""
    kb = c.get("kb") or ""
    blob = _blob(s)
    if ident is not None:
        if kb and (KB.kb_for_cpe(ident.vendor, ident.product) == kb or KB.kb_for_text(ident.product.replace("_", " ")) == kb or KB.kb_for_text(s.product) == kb):
            return {"found": True, "version": ident.version, "how": "nmap", "text": f"Nmap: служба {s.service or '—'}, продукт {s.product or ident.product} {s.version}".strip() + f" (метод: {s.method or '—'}, уверенность {s.conf}/10)"}
        pairs = {(KB.norm(r.get("vendor", "")), KB.norm(r.get("product", ""))) for r in c.get("ranges", [])}
        if not kb and (KB.norm(ident.vendor), KB.norm(ident.product)) in pairs:
            return {"found": True, "version": ident.version, "how": "nmap", "text": f"Nmap: продукт {ident.product} {ident.version} (по CPE)"}
    if kb:
        ok, ver = KB.version_from_text(kb, blob)
        if ok:
            line = next((ln.strip() for ln in blob.splitlines() if any(re.search(rx, ln, re.I) for rx in [*KB.KB[kb]["rx"], *KB.KB[kb].get("presence", [])])), "")
            return {"found": True, "version": ver, "how": "banner", "text": "Ответ сервиса: " + mask_secrets(line)[:200]}
    elif c.get("product"):
        name = KB.norm(c["product"])
        if name and (name in KB.norm(s.product) or name in KB.norm(ident.product if ident else "")):
            return {"found": True, "version": ident.version if ident else "", "how": "nmap", "text": f"Nmap: продукт {s.product} {s.version}".strip()}
    return {"found": False, "version": "", "how": "", "text": ""}


def _synthetic(c: dict, s: A.Svc, det: dict) -> A.Svc:
    """Если продукт найден по признаку в ответе (а не по CPE Nmap), анализу передаётся сервис с этим продуктом и версией: так применимость и исправления дистрибутива оцениваются единообразно."""
    kb = c.get("kb")
    if not (kb and det["found"] and det["how"] == "banner" and det["version"]):
        return s
    v, p = KB.KB[kb]["cpe"][0]
    return dataclasses.replace(s, product=KB.KB[kb]["title"], version=det["version"], cpe=[f"cpe:/a:{v}:{p}:{det['version']}"], method="probed")


async def run(sc, job, lease, cancel, counter, settings) -> None:
    hunt = (job.options or {}).get("hunt") or {}
    crits = hunt.get("criteria", [])
    has_cve = any(c["kind"] == "cve" for c in crits)
    mode = hunt.get("mode", "combined")
    hosts = [*await sc._hosts(job.id, "svc"), *await sc._hosts(job.id, "chk")]  # noqa: SLF001
    cache = A.Cache()
    now = utcnow()
    async with sc._sm() as db:  # noqa: SLF001
        requested = set(((await db.get(type(job), job.id)).engines or {}).get("nse_requested") or [])
        await db.execute(delete(HuntHit).where(HuntHit.job_id == job.id, HuntHit.basis == "network"))              # повторный заход после перезапуска не дублирует
        await db.commit()
    found_hosts = 0
    for i, ip in enumerate(hosts):
        if cancel.is_set():
            from ..pentest.scanner import Cancelled  # noqa: PLC0415

            raise Cancelled()
        try:
            async with sc._sm() as db:  # noqa: SLF001
                ports = (await db.execute(select(PtPort).where(PtPort.job_id == job.id, PtPort.ip == ip))).scalars().all()
                hit_rows = (await db.execute(select(PtHit).where(PtHit.job_id == job.id, PtHit.ip == ip))).scalars().all()
                hits: dict[int, list] = {}
                for hr in hit_rows:
                    hits.setdefault(hr.port, []).append({"check_id": hr.check_id, "name": hr.name, "sev": hr.sev, "cves": hr.cves or [], "tags": hr.tags or [], "matched_at": hr.matched_at, "vhost": hr.vhost,
                                                         "matchers": [], "extracted": hr.extracted or [], "evidence": hr.evidence, "info": hr.info or {}})
                plat, why = AP.host_platform([{"port": p.port, "ostype": p.ostype, "extrainfo": p.extrainfo, "version": p.version, "banner": p.banner, "scripts": p.scripts or []} for p in ports])
                ctx = A.HostCtx(platform=plat, platform_why=why, requested=requested, hits=hits)
                got = 0
                for p in ports:
                    s0 = A.Svc(ip=ip, port=p.port, proto=p.proto, service=p.service, product=p.product, version=p.version, extrainfo=p.extrainfo, ostype=p.ostype, cpe=p.cpe or [], method=p.method, conf=p.conf,
                               scripts=p.scripts or [], tunnel=p.tunnel, banner=p.banner)
                    ident0 = A.identify(s0)
                    findings = None
                    for c in crits:
                        det = detect(c, s0, ident0)
                        s1 = _synthetic(c, s0, det)
                        status, notes, vuln = "", [], c.get("cve", "")
                        ev = [RS.ev(det["how"] or "nmap", det["text"])] if det["found"] else []
                        if c["kind"] == "cve":
                            if findings is None or s1 is not s0:
                                fs, _meta = await A.analyze_service(db, s1, cache, ctx)
                                if s1 is s0:
                                    findings = fs
                            else:
                                fs = findings
                            f = next((x for x in fs if x.vuln_key.upper() == c["cve"].upper() and x.confidence != "not_confirmed"), None)
                            if f is not None:
                                status = f.confidence
                                det["found"], det["version"] = True, f.version or det["version"]
                                if "nuclei" in (f.engines or ""):
                                    tid = ((f.evidence or {}).get("template") or {}).get("id", "")
                                    ev.append(RS.ev("nuclei", f"Nuclei: выполнена проверка {tid or 'по идентификатору шаблона'}, обнаружен соответствующий признак"))
                                if "nse" in (f.engines or ""):
                                    ev.append(RS.ev("nse", "Nmap NSE: скрипт вернул состояние «уязвимо»"))
                                for n in ((f.evidence or {}).get("match") or {}).get("notes", [])[:3]:
                                    ev.append(RS.ev("note", n))
                            elif det["found"] and not det["version"]:
                                status = "needs_check"
                                ev.append(RS.ev("note", "Продукт обнаружен, но версия сервиса не определена: сопоставить с уязвимыми версиями нельзя"))
                        elif det["found"]:
                            res = C.version_in(c, det["version"])
                            if res is None:
                                status = "needs_check"
                                ev.append(RS.ev("note", "Продукт обнаружен, версия недоступна для сетевой проверки"))
                            elif res:
                                status = "probable"
                        if status:
                            got += 1
                            db.add(HuntHit(job_id=job.id, crit_key=c["key"], vuln_key=vuln, ip=ip, port=p.port, product=(KB.KB[c["kb"]]["title"] if c.get("kb") else s0.product or c["product"])[:200], version=(det["version"] or "")[:120],
                                           status=status, basis="network", evidence=ev, data_at=now))
                host = await db.get(PtHost, (job.id, ip))
                if host is not None:
                    host.findings_n, host.state, host.finished_at = got, "done", utcnow()
                await lease.fence(db)
                await db.commit()
                if got:
                    found_hosts += 1
                    if job.targets_n <= 40:
                        await sc._event(job.id, "info", "analysis", ip, f"Совпадений с критериями: {got}", counter, engine="match")  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001 — сбой разбора одного хоста не останавливает задание
            if type(exc).__name__ in ("LeaseLost", "Cancelled"):
                raise
            await sc._fail_host(job.id, ip, "analysis", f"Сопоставление: разбор хоста — внутренняя ошибка сканера ({type(exc).__name__})", counter, engine="match", retry="safe")  # noqa: SLF001
        if i % 5 == 0:
            await sc._stage(job.id, lease, "analysis", i / max(1, len(hosts)))  # noqa: SLF001
    # не удалось проверить: адреса с ошибкой этапа (недоступны, превышено время) — отдельной строкой, чтобы они не выглядели «чистыми»
    async with sc._sm() as db:  # noqa: SLF001
        bad = (await db.execute(select(PtHost.ip, PtHost.error).where(PtHost.job_id == job.id, PtHost.state == "error").limit(500))).all()
        for ip, err in bad:
            db.add(HuntHit(job_id=job.id, crit_key="*", ip=ip, status="failed", basis="network", product="", evidence=[RS.ev("error", err or "проверка не выполнена")], data_at=now))
        await db.commit()
    async with sc._sm() as db:  # noqa: SLF001
        await lease.fence(db)
        await RS.finalize(db, job.id, logic=hunt.get("logic", "any"), n_crit=len(crits))
        await db.commit()
    _ = has_cve, mode, datetime
