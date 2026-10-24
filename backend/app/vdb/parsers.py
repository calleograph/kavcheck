"""Разбор форматов источников в общую запись `Rec`: NVD API 2.0 (CVE JSON), каталог CISA KEV, OSV, XML-выгрузка БДУ ФСТЭК.
Разборщики не обращаются к сети и базе: на вход — уже загруженные данные, на выход — записи. Неизвестные или повреждённые элементы пропускаются, а не прерывают загрузку."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Iterator

from .normalize import Aff, Rec, SEV_RANK, cvss3_score, norm, parse_cpe, parse_dt, parse_purl, platform_of, sev_from_score

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _short(text: str, n: int = 200) -> str:
    t = re.sub(r"\s+", " ", text or "").strip()
    if len(t) <= n:
        return t
    cut = t[:n]
    return (cut[:cut.rfind(" ")] if " " in cut[n // 2:] else cut).rstrip(" ,;:") + "…"


# ------------------------------------------------------------------------------------------------ NVD
def _nvd_walk(node: dict, out: list[Aff], conditional: bool, platform_hint: str) -> None:
    op = (node.get("operator") or "OR").upper()
    for m in node.get("cpeMatch") or []:
        if not m.get("vulnerable"):
            continue
        p = parse_cpe(m.get("criteria", ""))
        if not p or p["part"] not in ("a", "o"):
            continue
        a = Aff(vendor=p["vendor"], product=p["product"], cpe=m["criteria"], platform=platform_of(p["target_sw"]) or platform_hint, conditional=conditional)
        v = p["version"]
        s_in, s_ex, e_in, e_ex = (m.get(k) or "" for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"))
        if s_in or s_ex or e_in or e_ex:
            a.v_start, a.v_start_incl = (s_in or s_ex), bool(s_in) or not s_ex
            a.v_end, a.v_end_incl = (e_in or e_ex), bool(e_in)
        elif v not in ("*", "-", ""):
            a.exact = v
            if p["update"] not in ("*", "-", ""):       # редакция или обновление (beta1, update391, sp1): точное сопоставление с номером версии невозможно
                a.conditional, a.version_text = True, f"обновление/редакция: {p['update']}"
        else:
            a.versions_all = True
        out.append(a)
    for ch in node.get("children") or []:
        _nvd_walk(ch, out, conditional or op == "AND", platform_hint)


def parse_nvd(item: dict) -> Rec | None:
    """Элемент `vulnerabilities[]` ответа NVD API 2.0. Отклонённые (Rejected) записи пропускаются."""
    c = item.get("cve") or item
    cid = (c.get("id") or "").upper()
    if not CVE_RE.fullmatch(cid):
        return None
    if str(c.get("vulnStatus") or "").lower() == "rejected":
        return None
    desc = next((d["value"] for d in c.get("descriptions") or [] if d.get("lang") == "en"), "") or next((d["value"] for d in c.get("descriptions") or []), "")
    score, vector, sev = None, "", ""
    metrics = c.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        ms = metrics.get(key) or []
        if ms:
            m = next((x for x in ms if x.get("type") == "Primary"), ms[0])
            d = m.get("cvssData") or {}
            score, vector = d.get("baseScore"), d.get("vectorString", "")
            sev = (d.get("baseSeverity") or m.get("baseSeverity") or "").lower() or sev_from_score(score)
            break
    sev = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(sev, sev_from_score(score))
    refs = [{"url": r["url"], "tags": r.get("tags") or []} for r in c.get("references") or [] if r.get("url")][:40]
    fix = any(t in ("Patch", "Vendor Advisory", "Mitigation") for r in refs for t in r["tags"])
    rec = Rec(source="nvd", ext_id=cid, vuln_key=cid, title=_short(desc, 160), description=desc, severity=sev, score=score, vector=vector, published=parse_dt(c.get("published")),
              modified=parse_dt(c.get("lastModified")), fix_available=True if fix else None, status=c.get("vulnStatus") or "", refs=refs,
              extra={"cwe": sorted({d["value"] for w in c.get("weaknesses") or [] for d in w.get("description") or [] if str(d.get("value", "")).startswith("CWE-")})})
    for cfg in c.get("configurations") or []:
        is_and = (cfg.get("operator") or "").upper() == "AND"
        hint = ""
        if is_and:      # приложение работает на указанной ОС: уязвимость зависит от среды — «требуется уточнение», а не подтверждение
            for node in cfg.get("nodes") or []:
                for m in node.get("cpeMatch") or []:
                    p = parse_cpe(m.get("criteria", "")) if not m.get("vulnerable") else {}
                    if p.get("part") == "o":
                        hint = platform_of(p["product"]) or hint
        for node in cfg.get("nodes") or []:
            _nvd_walk(node, rec.affected, is_and, hint)
    seen, uniq = set(), []
    for a in rec.affected:
        k = (a.cpe, a.v_start, a.v_end, a.exact, a.versions_all)
        if k not in seen:
            seen.add(k)
            uniq.append(a)
    rec.affected = uniq[:400]
    return rec


# ------------------------------------------------------------------------------------------------ CISA KEV
def parse_kev(doc: dict) -> Iterator[Rec]:
    """Каталог известных эксплуатируемых уязвимостей CISA: все записи — с отметкой подтверждённой эксплуатации."""
    for v in doc.get("vulnerabilities") or []:
        cid = (v.get("cveID") or "").upper()
        if not CVE_RE.fullmatch(cid):
            continue
        added = parse_dt(v.get("dateAdded"))
        rec = Rec(source="kev", ext_id=cid, vuln_key=cid, title=v.get("vulnerabilityName") or "", description=v.get("shortDescription") or "", severity="", published=added, modified=added,
                  exploited=True, status="Known exploited", fix_text=v.get("requiredAction") or "", fix_available=None,
                  refs=[{"url": f"https://nvd.nist.gov/vuln/detail/{cid}", "tags": ["NVD"]}] + ([{"url": u, "tags": ["KEV"]} for u in re.findall(r"https?://\S+", v.get("notes") or "")][:5]),
                  extra={"due_date": v.get("dueDate") or "", "ransomware": v.get("knownRansomwareCampaignUse") or "", "cwes": v.get("cwes") or [], "vendor": v.get("vendorProject") or "",
                         "product": v.get("product") or ""})
        rec.affected.append(Aff(vendor=v.get("vendorProject") or "", product=v.get("product") or "", versions_all=True, version_text="версии не указаны в каталоге KEV"))
        yield rec


# ------------------------------------------------------------------------------------------------ OSV
def parse_osv(doc: dict) -> Rec | None:
    """Запись OSV: идентификатор, псевдонимы (CVE…), затронутые пакеты с интервалами версий и исправлениями дистрибутива."""
    oid = doc.get("id") or ""
    if not oid or doc.get("withdrawn"):
        return None
    aliases = [a for a in (doc.get("aliases") or []) + (doc.get("upstream") or []) + (doc.get("related") or []) if a]
    cves = [a.upper() for a in aliases + [oid] if CVE_RE.fullmatch(a or "")]
    key = cves[0] if cves else oid
    vector = ""
    for s in doc.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS") and str(s.get("score") or "").startswith("CVSS:3"):
            vector = s.get("score") or ""
    db = doc.get("database_specific") or {}
    sev = str(db.get("severity") or "").lower().replace("moderate", "medium")
    score = cvss3_score(vector)
    sev = sev if sev in SEV_RANK and sev else sev_from_score(score)
    refs = [{"url": r["url"], "tags": [r.get("type", "")]} for r in doc.get("references") or [] if r.get("url")][:40]
    fixed_any = False
    rec = Rec(source="osv", ext_id=oid, vuln_key=key, aliases=sorted({oid, *aliases} - {key}), title=_short(doc.get("summary") or doc.get("details") or "", 160),
              description=doc.get("details") or doc.get("summary") or "", severity=sev, score=score, vector=vector, published=parse_dt(doc.get("published")),
              modified=parse_dt(doc.get("modified")), refs=refs, extra={"cwe": db.get("cwe_ids") or []})
    for a in doc.get("affected") or []:
        pk = a.get("package") or {}
        pu = parse_purl(pk.get("purl", ""))
        base = dict(ecosystem=str(pk.get("ecosystem") or "")[:60], purl=pk.get("purl") or "", pkg_name=pk.get("name") or pu.get("name", ""), product=pk.get("name") or pu.get("name", ""),
                    vendor=pu.get("namespace", ""))
        made = False
        for r in a.get("ranges") or []:
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            cur = None
            for ev in r.get("events") or []:
                if "introduced" in ev:
                    cur = Aff(**base, v_start="" if ev["introduced"] == "0" else ev["introduced"], v_start_incl=True)
                elif cur is not None and "fixed" in ev:
                    cur.v_end, cur.v_end_incl, cur.fixed = ev["fixed"], False, ev["fixed"]
                    rec.affected.append(cur)
                    fixed_any, made, cur = True, True, None
                elif cur is not None and "last_affected" in ev:
                    cur.v_end, cur.v_end_incl = ev["last_affected"], True
                    rec.affected.append(cur)
                    made, cur = True, None
            if cur is not None:      # интервал без исправления: затронуты все версии начиная с introduced
                cur.versions_all = not cur.v_start
                rec.affected.append(cur)
                made = True
        if not made:        # явный перечень версий нужен, только если интервалов нет (перечень у дистрибутивов огромный и дублирует интервалы)
            for v in (a.get("versions") or [])[:200]:
                rec.affected.append(Aff(**base, exact=v))
                made = True
        if not made and base["pkg_name"]:
            rec.affected.append(Aff(**base, versions_all=True))
    rec.fix_available = True if fixed_any else None
    return rec


# ------------------------------------------------------------------------------------------------ БДУ ФСТЭК
_BDU_SEV = (("критич", "critical"), ("высок", "high"), ("средн", "medium"), ("низк", "low"))
_VER_FULL = [
    (re.compile(r"^(?:до|ранее|менее|<)\s*([^\s,;]+)\s*(включительно)?$", re.I), "end"),
    (re.compile(r"^([^\s,;]+)\s*(?:и (?:более )?(?:ранн\w+|ниже)|и ранее)(?:\s+верси\w+)?$", re.I), "end_incl"),
    (re.compile(r"^([^\s,;]+)\s*(?:и (?:более )?(?:поздн\w+|выше)|и новее)(?:\s+верси\w+)?$", re.I), "start_incl"),
    (re.compile(r"^с\s*([^\s,;]+)\s*по\s*([^\s,;]+)$", re.I), "range"),
    (re.compile(r"^([^\s,;]+)\s*[-–—]\s*([^\s,;]+)$"), "range"),
    (re.compile(r"^(\d[^\s,;]*)$"), "exact"),
]


def _bdu_versions(text: str) -> list[dict]:
    """Версии из свободного текста БДУ («до 3.0.1», «с 1.2 по 1.5», «2.0 и более ранние»). Не разобранное — version_text без границ (требуется уточнение)."""
    out = []
    t = (text or "").strip()
    if t in ("", "-", "–", "—"):
        return [{"all": True}]
    for part in re.split(r"\s*(?:;|,\s(?=\D)|\bили\b)\s*", t):
        p = part.strip().rstrip(".")
        if not p:
            continue
        for rx, kind in _VER_FULL:
            m = rx.match(p)
            if not m:
                continue
            if kind == "end":
                out.append({"end": m.group(1), "end_incl": bool(m.group(2))})
            elif kind == "end_incl":
                out.append({"end": m.group(1), "end_incl": True})
            elif kind == "start_incl":
                out.append({"start": m.group(1), "start_incl": True, "open": True})
            elif kind == "range":
                out.append({"start": m.group(1), "start_incl": True, "end": m.group(2), "end_incl": True})
            else:
                out.append({"exact": m.group(1)})
            break
        else:
            out.append({"text": p})
    return out or [{"text": t}]


def _bdu_fixed(text: str) -> bool | None:
    """«Уязвимость устранена» / «Существует способ устранения» — исправление есть; «Информация об устранении отсутствует» / «не устранена» — нет."""
    t = (text or "").lower()
    if not t:
        return None
    if re.search(r"отсутств|не устран|нет информации|неизвестн", t):
        return False
    return bool(re.search(r"устранена|способ устранения|имеется|существует", t)) or None


def _txt(e: ET.Element | None) -> str:
    return (e.text or "").strip() if e is not None else ""


def _find(e: ET.Element, *names: str) -> ET.Element | None:
    for n in names:
        for c in e:
            if c.tag.split("}")[-1].lower() == n:
                return c
    return None


def parse_bdu(stream) -> Iterator[Rec]:
    """XML-выгрузка БДУ ФСТЭК (элементы `<vul>`): идентификатор, название, описание, ПО (производитель, название, версия, платформа), CVSS, степень опасности, способ устранения, CVE.
    Разбор потоковый — выгрузка занимает десятки мегабайт."""
    for _ev, el in ET.iterparse(stream, events=("end",)):
        if el.tag.split("}")[-1].lower() != "vul":
            continue
        ident = _txt(_find(el, "identifier"))
        if not ident:
            el.clear()
            continue
        cves = [c.upper() for c in (CVE_RE.findall(" ".join(_txt(i) for i in (_find(el, "identifiers") or []))) + CVE_RE.findall(ident))]
        key = cves[0] if cves else ident
        sev_text = _txt(_find(el, "severity")).lower()
        sev = next((v for k, v in _BDU_SEV if k in sev_text), "")
        score, vector = None, ""
        for tag in ("cvss3", "cvss"):
            c = _find(el, tag)
            vec = _find(c, "vector") if c is not None else None
            if vec is not None and _txt(vec):
                vector = _txt(vec)
                try:
                    score = float(vec.get("score"))
                except (TypeError, ValueError):
                    score = None
                break
        fix_status = _txt(_find(el, "fix_status"))
        solution = _txt(_find(el, "solution"))
        rec = Rec(source="bdu", ext_id=ident, vuln_key=key, aliases=sorted(set(cves) - {key}) + ([ident] if key != ident else []), title=_txt(_find(el, "name")),
                  description=_txt(_find(el, "description")), severity=sev or sev_from_score(score), score=score, vector=vector,
                  published=parse_dt(_txt(_find(el, "identify_date")) or _txt(_find(el, "publication_date"))), modified=parse_dt(_txt(_find(el, "last_upd_date")) or _txt(_find(el, "identify_date"))),
                  fix_available=_bdu_fixed(fix_status), fix_text=solution, status=_txt(_find(el, "vul_status")),
                  refs=[{"url": u, "tags": ["БДУ"]} for u in re.findall(r"https?://[^\s<>\"']+", _txt(_find(el, "sources")))][:20] + [{"url": f"https://bdu.fstec.ru/vul/{ident.split(':', 1)[-1]}", "tags": ["БДУ"]}],
                  extra={"exploit_status": _txt(_find(el, "exploit_status")), "fix_status": fix_status, "severity_text": _txt(_find(el, "severity")),
                         "cwe": [_txt(i) for c in el.iter() if c.tag.split("}")[-1].lower() == "cwe" for i in c if _txt(i)][:5]})
        for soft in (_find(el, "vulnerable_software") or []):
            vendor, name, version, platform = (_txt(_find(soft, n)) for n in ("vendor", "name", "version", "platform"))
            if not name:
                continue
            for v in _bdu_versions(version):
                a = Aff(vendor=vendor, product=name, platform=norm(platform) if norm(platform) in ("windows", "linux") else "")
                if v.get("all"):
                    a.versions_all = True
                elif "exact" in v:
                    a.exact = v["exact"]
                elif "text" in v:
                    a.version_text = v["text"]
                else:
                    a.v_start, a.v_start_incl = v.get("start", ""), v.get("start_incl", True)
                    a.v_end, a.v_end_incl = v.get("end", ""), v.get("end_incl", False)
                rec.affected.append(a)
        yield rec
        el.clear()
