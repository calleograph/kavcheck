"""Поиск одной уязвимости во внешних базах «здесь и сейчас»: CVE.org (CVE List, запись поставщика), NVD API 2.0 и OSV.dev.

Локальная база обновляется по расписанию и хранит NVD за `years_back` лет, поэтому свежая (опубликованная несколько часов назад) или старая CVE
может отсутствовать. Запрос по одному идентификатору идёт напрямую в первоисточники; ответ не записывается в локальную базу (её ведёт worker) и
кэшируется в процессе на LIVE_TTL. Применимость к контуру считается теми же правилами, что и для загруженных данных (`match.matches_from`)."""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import asdict
from types import SimpleNamespace

from .fetch import FetchError, Http
from .normalize import Aff, Rec, make_score, norm, parse_dt, set_scores
from .parsers import CVE_RE, parse_nvd, parse_osv

CVE_ORG = "https://cveawg.mitre.org/api/cve/"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1/vulns/"
LIVE_TTL = 1800
TIMEOUT = 15
TITLES = {"cve": "CVE.org (запись поставщика)", "nvd": "NVD (NIST)", "osv": "OSV.dev"}
URLS = {"cve": "https://www.cve.org/CVERecord?id={id}", "nvd": "https://nvd.nist.gov/vuln/detail/{id}", "osv": "https://osv.dev/vulnerability/{id}"}

# идентификатор одной уязвимости: CVE, БДУ, GHSA и идентификаторы баз OSV (PYSEC-…, GO-…, RUSTSEC-…, DSA-…, USN-…)
ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|BDU:\d{4}-\d{5}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|(?!CVE-)[A-Z][A-Z0-9]{1,15}-(?=[A-Z0-9.:_-]*\d)[A-Z0-9][A-Z0-9.:_-]{2,40})$", re.I)
_EMPTY = {"", "*", "0", "n/a", "unspecified", "unknown", "-"}
_cache: dict[str, tuple[float, dict]] = {}       # порядок вставки = порядок времени: истёкшие и самые старые — в начале
CACHE_MAX = 1000


def is_id(text: str) -> bool:
    return bool(ID_RE.fullmatch((text or "").strip()))


def parse_cve5(doc: dict) -> Rec | None:
    """Запись CVE JSON 5.x (cveawg.mitre.org): описание, оценки CNA и ADP (CISA), затронутые продукты с диапазонами версий поставщика."""
    meta = doc.get("cveMetadata") or {}
    cid = str(meta.get("cveId") or "").upper()
    if not CVE_RE.fullmatch(cid) or str(meta.get("state") or "").upper() == "REJECTED":
        return None
    cont = doc.get("containers") or {}
    cna = cont.get("cna") or {}
    parts = [cna, *(cont.get("adp") or [])]
    desc = next((d.get("value") for d in cna.get("descriptions") or [] if str(d.get("lang", "")).startswith("en")), "") or next((d.get("value") for d in cna.get("descriptions") or []), "") or ""
    modified = parse_dt(meta.get("dateUpdated"))
    scores, exploited = [], False
    for part in parts:
        org = (part.get("providerMetadata") or {}).get("shortName") or ""
        for m in part.get("metrics") or []:
            for key, ver in (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0")):
                d = m.get(key)
                if d:
                    scores.append(make_score(d.get("version") or ver, d.get("baseScore"), d.get("vectorString", ""), source="cve", origin=org, kind="secondary", updated=modified))
            for o in ((m.get("other") or {}).get("content") or {}).get("options") or []:     # CISA SSVC: Exploitation = active
                if isinstance(o, dict) and str(o.get("Exploitation") or "").lower() == "active":
                    exploited = True
    refs = [{"url": r["url"], "tags": r.get("tags") or []} for r in cna.get("references") or [] if r.get("url")][:40]
    cwe = sorted({d.get("cweId") for pt in cna.get("problemTypes") or [] for d in pt.get("descriptions") or [] if d.get("cweId")})
    rec = Rec(source="cve", ext_id=cid, vuln_key=cid, title=(cna.get("title") or desc)[:160], description=desc, published=parse_dt(meta.get("datePublished")), modified=modified,
              exploited=exploited, fix_available=True if any("patch" in t for r in refs for t in r["tags"]) else None, status=str(meta.get("state") or "").title(), refs=refs, extra={"cwe": cwe})
    set_scores(rec, scores)
    for part in parts:
        for a in part.get("affected") or []:
            vendor, product = str(a.get("vendor") or ""), str(a.get("product") or a.get("packageName") or "")
            if norm(vendor) in ("n_a", "") and norm(product) in ("n_a", ""):
                continue
            base = dict(vendor=vendor if norm(vendor) != "n_a" else "", product=product if norm(product) != "n_a" else "", pkg_name=str(a.get("packageName") or ""))
            made = False
            for v in a.get("versions") or []:
                if str(v.get("status") or "").lower() != "affected":
                    continue
                ver, lt, lte = str(v.get("version") or ""), str(v.get("lessThan") or ""), str(v.get("lessThanOrEqual") or "")
                start = "" if ver.lower() in _EMPTY else ver
                if lt or lte:
                    end = "" if (lt or lte).lower() in _EMPTY else (lt or lte)
                    rec.affected.append(Aff(**base, v_start=start, v_end=end, v_end_incl=bool(lte) and not lt, versions_all=not start and not end))
                elif start:
                    rec.affected.append(Aff(**base, exact=start))
                else:
                    rec.affected.append(Aff(**base, versions_all=True))
                made = True
            if not made and str(a.get("defaultStatus") or "").lower() == "affected":
                rec.affected.append(Aff(**base, versions_all=True, version_text="поставщик не указал версии"))
    rec.affected = rec.affected[:400]
    return rec


async def _one(http: Http, src: str, ident: str, nvd_key: str) -> tuple[dict, list[Rec]]:
    """Один внешний источник: состояние запроса (найдено / нет / ошибка) и записи."""
    st = {"source": src, "title": TITLES[src], "found": False, "error": "", "url": URLS[src].format(id=ident)}
    try:
        if src == "cve":
            doc = await http.json(CVE_ORG + ident, ok404=True, retries=1)
            rec = parse_cve5(doc) if doc else None
            recs = [rec] if rec else []
        elif src == "nvd":
            http_h = {"apiKey": nvd_key} if nvd_key else None
            r = await http._c.get(NVD_API, params={"cveId": ident}, headers=http_h)  # noqa: SLF001 — один запрос без повторов: NVD ограничивает частоту
            if r.status_code >= 400:
                raise FetchError(f"services.nvd.nist.gov: HTTP {r.status_code}")
            recs = [x for x in (parse_nvd(i) for i in r.json().get("vulnerabilities") or []) if x]
        else:
            doc = await http.json(OSV_API + ident, ok404=True, retries=1)
            rec = parse_osv(doc) if doc else None
            recs = [rec] if rec else []
    except (FetchError, ValueError) as exc:
        st["error"] = str(exc)[:200]
        return st, []
    except Exception as exc:  # noqa: BLE001 — сеть недоступна, тайм-аут: остальные источники отвечают независимо
        st["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
        return st, []
    st["found"] = bool(recs)
    if recs and recs[0].status:
        st["status"] = recs[0].status
    return st, recs


async def fetch_live(ident: str, *, nvd_key: str = "", http: Http | None = None) -> dict:
    """Запрос во внешние базы параллельно. CVE — в CVE.org, NVD и OSV; прочие идентификаторы — только в OSV (БДУ онлайн-API не имеет: она загружается целиком)."""
    ident = ident.strip()
    if CVE_RE.fullmatch(ident) or ident.upper().startswith("BDU:"):
        ident = ident.upper()                  # регистр идентификаторов OSV (GHSA-xxxx-…) значим
    hit = _cache.get(ident)
    if hit and time.monotonic() - hit[0] < LIVE_TTL and http is None:
        return hit[1]
    own = http is None
    http = http or Http(timeout=TIMEOUT, sleep=lambda _s: asyncio.sleep(0))
    srcs = ["cve", "nvd", "osv"] if CVE_RE.fullmatch(ident) else [] if ident.startswith("BDU:") else ["osv"]
    try:
        res = await asyncio.gather(*(_one(http, s, ident, nvd_key) for s in srcs))
    finally:
        if own:
            await http.close()
    out = {"id": ident, "checked_at": time.time(), "sources": [st for st, _ in res], "records": [r for _, rs in res for r in rs]}
    if own and any(st["found"] or not st["error"] for st in out["sources"]):       # ошибки сети не кэшируем: следующий запрос повторит
        now = time.monotonic()
        _cache.pop(ident, None)
        while _cache and (len(_cache) >= CACHE_MAX or now - next(iter(_cache.values()))[0] >= LIVE_TTL):
            del _cache[next(iter(_cache))]
        _cache[ident] = (now, out)
    return out


def aff_rows(recs: list[Rec]) -> list[SimpleNamespace]:
    """Записи источников в виде строк vdb_affected — для `match.matches_from`."""
    out = []
    for r in recs:
        for a in r.affected:
            d = asdict(a)
            d.update(source=r.source, ext_id=r.ext_id, vuln_key=r.vuln_key, vendor_key=norm(a.vendor), product_key=norm(a.product))
            out.append(SimpleNamespace(**d))
    return out
