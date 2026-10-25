import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type ApiError, type VdbAffectedRow, type VdbCard, type VdbScore, type VdbCounts, type VdbSourceInfo, type VdbVulnRow } from "../api";
import { NoSource, type Ctx } from "../App";
import { Fetched } from "../components/Common";
import { Modal } from "../components/Dialogs";
import { Icon } from "../components/Icons";
import { ListFoot, VirtualRows, useInfinite, useKept, type Chunk } from "../components/Infinite";
import { CheckAll, QuickReportPanel, ReportDock, useRowSel } from "../components/QuickReport";
import { useToast } from "../components/Toast";
import { CVSS_RANGES, CvssCell, Kev, LevelBadge, StatusBadge } from "../components/VdbBits";
import { Empty, PageHead, Segmented, SkelRows, SortTh, Tabs, MaskHint } from "../components/ui";
import { fmt, fmtDate, num, plural } from "../util";

type Tab = "search" | "mine" | "sources";
type Sev = "" | "critical" | "high" | "medium";
const SEV_OPTS: [Sev, string][] = [["", "Все"], ["critical", "Критические"], ["high", "Высокие и выше"], ["medium", "Средние и выше"]];
const SRC_TITLE: Record<string, string> = { nvd: "NVD", kev: "CISA KEV", osv: "OSV", bdu: "БДУ ФСТЭК" };

/** Параметры сервера для выбранного диапазона CVSS: готовый уровень или свои границы (свои важнее). */
function scoreParams(range: string, lo: string, hi: string): { score_min?: number; score_max?: number; no_score?: boolean } {
  const num = (s: string) => { const n = Number(s.replace(",", ".")); return s.trim() !== "" && Number.isFinite(n) ? Math.min(10, Math.max(0, n)) : undefined; };
  if (num(lo) !== undefined || num(hi) !== undefined) return { score_min: num(lo), score_max: num(hi) };
  const r = CVSS_RANGES.find((x) => x.id === range);
  return r?.none ? { no_score: true } : { score_min: r?.min, score_max: r?.max };
}

const rangeText = (a: VdbAffectedRow) => {
  if (a.exact) return `версия ${a.exact}`;
  if (a.from || a.to) return [a.from && `${a.from_incl ? "≥" : ">"} ${a.from}`, a.to && `${a.to_incl ? "≤" : "<"} ${a.to}`].filter(Boolean).join(" и ");
  return a.version_text || (a.all_versions ? "все версии (источник не ограничивает)" : "версии не указаны");
};

/** Раздел «База уязвимостей»: поиск по внешним базам, проверка применимости к установленному ПО, находки для специалиста ИБ, состояние источников. */
export default function VdbPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const tab = (["search", "mine", "sources"].includes(sp.get("tab") ?? "") ? sp.get("tab") : "search") as Tab;
  const [counts, setCounts] = useState<VdbCounts | null>(null);
  useEffect(() => { if (ctx.current) api.vdb.summary().then(setCounts).catch(() => setCounts(null)); }, [ctx.current, tab]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  return (
    <section>
      <PageHead title="База уязвимостей" lede="Сведения о новых уязвимостях из независимых баз (NVD, CISA KEV, OSV, БДУ ФСТЭК) и проверка, затрагивают ли они установленное в вашей организации ПО. Это потенциальные уязвимости: подтверждённые KSC — в разделе «Уязвимости»." />
      <Tabs label="Вид" value={tab} onChange={(t) => setSp((p) => { p.set("tab", t); p.delete("v"); return p; })}
        items={[{ id: "search", label: "Поиск" }, { id: "mine", label: "Затрагивают нашу инфраструктуру", count: counts?.new || undefined }, { id: "sources", label: "Источники и обновление" }]} />
      {tab === "search" ? <SearchView ctx={ctx} /> : tab === "mine" ? <MineView ctx={ctx} onCounts={setCounts} counts={counts} /> : <SourcesView ctx={ctx} />}
    </section>
  );
}

type Report = { title: string; keys: string[] };
function ReportHost({ ctx, report, onClose }: { ctx: Ctx; report: Report | null; onClose: () => void }) {
  if (!report) return null;
  return <QuickReportPanel kind="quick_extvulns" title={report.title} lede="Потенциально затронутые компьютеры по внешним базам и каталогу установленного ПО" options={{ scope: true, ext: true, zoneFilter: true }}
    params={{ vuln_keys: report.keys }} activityDays={ctx.me.activity_days} canReport={ctx.me.user.role !== "viewer"} onClose={onClose} />;
}

function SearchView({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const sid = ctx.current?.id ?? "";
  const [q, setQ] = useKept("vdb.q", sp.get("q") ?? ""); const [applied, setApplied] = useState(q);
  const urlQ = sp.get("q");
  useEffect(() => { if (urlQ !== null) { setQ(urlQ); setApplied(urlQ); } }, [urlQ]); // eslint-disable-line react-hooks/exhaustive-deps
  const [sev, setSev] = useKept<Sev>("vdb.sev", ""); const [kev, setKev] = useKept("vdb.kev", false); const [fix, setFix] = useKept("vdb.fix", false);
  const [mine, setMine] = useKept("vdb.mine", false); const [source, setSource] = useKept("vdb.source", "");
  const [pf, setPf] = useKept("vdb.pf", ""); const [pt, setPt] = useKept("vdb.pt", ""); const [mf, setMf] = useKept("vdb.mf", "");
  const [version, setVersion] = useKept("vdb.version", ""); const [appliedV, setAppliedV] = useState(version);
  const [range, setRange] = useKept("vdb.range", ""); const [lo, setLo] = useKept("vdb.lo", ""); const [hi, setHi] = useKept("vdb.hi", "");
  const [sort, setSort] = useKept("vdb.sort", "priority"); const [desc, setDesc] = useKept("vdb.desc", true);
  const sel = useRowSel<string>(); const [report, setReport] = useState<Report | null>(null);
  const canReport = ctx.me.user.role !== "viewer";
  useEffect(() => { const t = window.setTimeout(() => { setApplied(q); setAppliedV(version); }, 350); return () => window.clearTimeout(t); }, [q, version]);
  const list = useInfinite<VdbVulnRow>(`vdb:${sid}`, [applied, appliedV, sev, kev, fix, mine, source, pf, pt, mf, sort, desc, range, lo, hi],
    (offset, limit) => api.vdb.list({ q: applied, version: appliedV.trim() || undefined, min_severity: sev, ...scoreParams(range, lo, hi), exploited: kev || undefined, has_fix: fix || undefined, affects: mine || undefined, source, published_from: pf, published_to: pt, modified_from: mf, sort, desc, offset, limit }) as unknown as Promise<Chunk<VdbVulnRow>>);
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(true); } };
  const open = sp.get("v");
  const keys = list.items.map((v) => v.key);
  return (
    <>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="CVE-2024-…, CVE-2026-*, BDU:…, программа, производитель или текст описания" aria-label="Поиск уязвимости" /><MaskHint /></div>
        <input className="w-md" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="Версия программы" aria-label="Версия программы" title="Введите название программы в поле поиска и версию здесь: найдутся уязвимости, затрагивающие эту версию" />
        <Segmented<Sev> label="Уровень опасности" value={sev} onChange={setSev} options={SEV_OPTS} />
        <label className="field">CVSS<select value={range} onChange={(e) => { setRange(e.target.value); setLo(""); setHi(""); }}>{CVSS_RANGES.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}</select></label>
        <div className="toolbar-row">
          <label className="check inline-check"><input type="checkbox" className="switch" checked={kev} onChange={(e) => setKev(e.target.checked)} />Эксплуатируется (KEV)</label>
          <label className="check inline-check"><input type="checkbox" className="switch" checked={mine} onChange={(e) => setMine(e.target.checked)} />Затрагивает нашу инфраструктуру</label>
        </div>
        <details className="disclosure toolbar-more"><summary>Дополнительно</summary>
          <div className="toolbar-fields">
            <label className="field">CVSS от<input type="number" inputMode="decimal" min={0} max={10} step={0.1} value={lo} onChange={(e) => setLo(e.target.value)} placeholder="0.0" className="w-num" /></label>
            <label className="field">до<input type="number" inputMode="decimal" min={0} max={10} step={0.1} value={hi} onChange={(e) => setHi(e.target.value)} placeholder="10.0" className="w-num" /></label>
            <label className="check inline-check"><input type="checkbox" className="switch" checked={fix} onChange={(e) => setFix(e.target.checked)} />Есть исправление</label>
            <label className="field">Источник<select value={source} onChange={(e) => setSource(e.target.value)}><option value="">Любой</option>{Object.entries(SRC_TITLE).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
            <label className="field">Опубликована с<input type="date" value={pf} onChange={(e) => setPf(e.target.value)} /></label>
            <label className="field">по<input type="date" value={pt} onChange={(e) => setPt(e.target.value)} /></label>
            <label className="field">Изменена с<input type="date" value={mf} onChange={(e) => setMf(e.target.value)} /></label>
          </div>
        </details>
      </div>
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={7} /> : (
          <table className="table virt">
            <thead><tr><CheckAll all={sel.allOf(keys)} some={sel.someOf(keys)} onToggle={() => sel.toggleMany(keys)} /><SortTh k="key" label="Уязвимость" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="score" label="CVSS" sort={sort} desc={desc} onSort={onSort} /><SortTh k="priority" label="Критичность" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /><th className="hide-sm hide-lg">Продукты</th><th className="hide-md">Источники</th>
              <SortTh k="published" label="Опубликована" sort={sort} desc={desc} onSort={onSort} className="hide-md" /><th className="hide-sm">Наша инфраструктура</th><th className="hide-sm"><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>
              <VirtualRows list={list} colSpan={9} estimate={64} row={(v) => (
                <tr className={`clickable ${sel.has(v.key) ? "sel" : ""}`} onClick={(e) => { if (!(e.target as HTMLElement).closest("input, button, a")) setSp((p) => { p.set("v", v.key); return p; }); }}>
                  <td className="check"><input type="checkbox" aria-label={`Выбрать ${v.key}`} checked={sel.has(v.key)} onChange={() => sel.toggle(v.key)} /></td>
                  <td><button type="button" className="link-btn strong-link mono" onClick={() => setSp((p) => { p.set("v", v.key); return p; })}>{v.key}</button>{v.version_match && <span className={`badge ${v.version_match === "yes" ? "err" : "warn"} new-dot`}>{v.version_match === "yes" ? "затрагивает версию" : "версия требует уточнения"}</span>}
                    <span className="sub vdb-title">{v.title || v.description}</span>{v.ids.length > 1 && <span className="sub mono small">{v.ids.filter((i) => i !== v.key).slice(0, 3).join(", ")}</span>}</td>
                  <td className="nowrap"><CvssCell v={v} /><span className="sm-stack"><LevelBadge v={v} />{v.exploited && <Kev />}</span></td>
                  <td className="hide-sm"><LevelBadge v={v} />{v.exploited && <span className="block kev-line"><Kev /></span>}</td>
                  <td className="small hide-sm hide-lg vdb-prods">{v.products.slice(0, 3).join("; ")}</td>
                  <td className="hide-md">{v.sources.map((s) => <span key={s} className="chip tiny">{SRC_TITLE[s] ?? s}</span>)}</td>
                  <td className="nowrap small hide-md">{fmtDate(v.published)}</td>
                  <td className="hide-sm">{v.finding ? <><StatusBadge s={v.finding.status} label={v.finding.status_ru} /><span className="sub">{num(v.finding.installs)} уст.{v.finding.new ? " · новая" : ""}</span></> : <span className="muted small">не найдено</span>}</td>
                  <td className="actions hide-sm">{canReport && <button type="button" className="btn mini ghost row-act" onClick={() => setReport({ title: `Проверка инфраструктуры: ${v.key}`, keys: [v.key] })}><Icon name="target" size={15} />Проверить</button>}</td>
                </tr>)} />
              {!list.items.length && !list.loading && <tr><td colSpan={9}><Empty icon="search" title="Уязвимости не найдены">{applied || sev || kev || mine || range || lo || hi ? "Измените запрос или фильтры." : "Локальная база пуста: включите и загрузите источники в разделе «Источники и обновление»."}</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      <ReportDock label="Выбранные уязвимости" count={sel.count} noun={["уязвимость выбрана", "уязвимости выбраны", "уязвимостей выбрано"]} canReport={canReport} onClear={sel.clear}
        onReport={() => setReport({ title: `Проверка инфраструктуры: ${sel.count} ${plural(sel.count, "уязвимость", "уязвимости", "уязвимостей")}`, keys: sel.ids })} />
      {open && <VdbCardPanel ctx={ctx} id={open} onClose={() => setSp((p) => { p.delete("v"); return p; })} onReport={(r) => setReport(r)} />}
      <ReportHost ctx={ctx} report={report} onClose={() => setReport(null)} />
    </>
  );
}

const KIND_RU: Record<string, string> = { primary: "оценка NVD", secondary: "оценка поставщика (CNA)", calculated: "вычислена по вектору" };
/** Оценка CVSS в карточке: балл, уровень, методика, источник и первоисточник; остальные оценки — под раскрывающимся списком. Нет оценки — «Нет данных». */
function CvssBlock({ c }: { c: VdbCard }) {
  const p = c.cvss?.primary;
  if (!p) return (
    <div className="cvss-box"><div className="cvss-main"><span className="cvss-big muted">—</span><span className="cvss na">Нет данных</span>{c.severity_basis === "source" && <LevelBadge v={c} />}</div>
      <p className="muted small">{c.severity_basis === "source" ? "Числовой оценки CVSS в источниках нет; уровень назван самим источником. " : "Достоверной оценки CVSS в NVD, БДУ и OSV пока нет. "}
        Оценку не вычисляют по названию CVE: она появится после загрузки данных, когда источник её выставит.</p></div>);
  const others = (c.cvss?.all ?? []).filter((s) => !s.primary);
  return (
    <div className="cvss-box">
      <div className="cvss-main"><span className="cvss-big">{p.score.toFixed(1)}</span><LevelBadge v={{ severity: p.severity, severity_ru: p.severity_ru }} /><span className="small">CVSS {p.version}</span></div>
      <dl className="cvss-facts">
        <dt>Источник оценки</dt><dd>{p.source_title} — {p.origin_label}</dd>
        <dt>Вектор</dt><dd className="mono small">{p.vector || "—"}</dd>
        <dt>Обновлено</dt><dd>{fmtDate(p.updated)}</dd>
        {p.url && <><dt>Первоисточник</dt><dd><a href={p.url} target="_blank" rel="noopener noreferrer">{p.url.replace(/^https?:\/\//, "")}<Icon name="external" size={12} className="ext" /></a></dd></>}
      </dl>
      <p className="muted small">Основная оценка выбирается так: CVSS 3.x и 4.0 важнее 2.0; оценка аналитиков NVD или БДУ важнее оценки поставщика (CNA) и вычисленной по вектору; из равных — более новая методика, затем источник (NVD, БДУ, OSV).</p>
      {others.length > 0 && <details className="disclosure"><summary>Другие оценки ({others.length})</summary>
        <div className="table-scroll"><table className="table compact"><thead><tr><th>CVSS</th><th>Балл</th><th>Уровень</th><th>Кто выставил</th><th>Обновлено</th></tr></thead>
          <tbody>{others.map((s: VdbScore, i) => <tr key={i}><td className="mono">{s.version}</td><td className="mono"><b>{s.score.toFixed(1)}</b></td><td>{s.severity_ru}</td>
            <td className="small">{s.source_title} — {s.origin_label}{KIND_RU[s.kind] && s.source !== "osv" ? <span className="sub">{KIND_RU[s.kind]}</span> : null}{s.url && <a className="sub" href={s.url} target="_blank" rel="noopener noreferrer">первоисточник</a>}</td>
            <td className="nowrap small">{fmtDate(s.updated)}</td></tr>)}</tbody></table></div></details>}
    </div>
  );
}

/** Карточка уязвимости: общие сведения, различия между источниками, сопоставление с установленным ПО и сведения каждого источника отдельно. */
export function VdbCardPanel({ ctx, id, onClose, onReport }: { ctx: Ctx; id: string; onClose: () => void; onReport: (r: Report) => void }) {
  const [c, setC] = useState<VdbCard | null>(null); const [err, setErr] = useState("");
  useEffect(() => { setC(null); setErr(""); api.vdb.card(id).then(setC).catch((e) => setErr((e as ApiError).message)); }, [id, ctx.current?.id]);
  const canReport = ctx.me.user.role !== "viewer";
  const m = c?.infrastructure?.matches ?? [];
  const affected = m.filter((x) => x.status !== "fixed");
  return (
    <Modal side wide title={c?.key ?? id} lede={c?.title} onClose={onClose}
      footer={c && canReport ? <button className="btn primary" onClick={() => { onReport({ title: `Проверка инфраструктуры: ${c.key}`, keys: [c.key] }); onClose(); }}><Icon name="target" />Проверить инфраструктуру</button> : undefined}>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!c && !err && <SkelRows rows={6} cols={2} />}
      {c && <div className="vdb-card">
        <CvssBlock c={c} />
        <div className="vdb-badges">{c.exploited && <Kev />}{c.has_fix === true && <span className="badge ok">есть исправление</span>}{c.has_fix === false && <span className="badge">исправления нет</span>}
          {c.sources.map((s) => <span key={s} className="chip tiny">{SRC_TITLE[s] ?? s}</span>)}</div>
        <p className="vdb-dates muted small">Опубликована {fmtDate(c.published)} · изменена {fmtDate(c.modified)} · идентификаторы: <span className="mono">{c.ids.join(", ")}</span></p>
        {c.description && <p className="vdb-desc">{c.description}</p>}
        {c.differences.length > 0 && <div className="alert warn"><Icon name="info" /><div className="alert-body"><b>Источники расходятся:</b><ul>{c.differences.map((d) => <li key={d.field}>{d.field}: {Object.entries(d.values).map(([s, v]) => `${SRC_TITLE[s] ?? s} — ${v}`).join("; ")}</li>)}</ul></div></div>}
        <h3 className="vdb-h">Установленное ПО в «{ctx.current?.name}»</h3>
        {!c.infrastructure ? <p className="muted small">Источник KSC не выбран.</p> : !c.infrastructure.catalog ? <p className="muted small">Каталог программ источника ещё не построен: сопоставление невозможно.</p>
          : !m.length ? <p className="muted small">Совпадений с установленным ПО не найдено: продукты из описания не встречаются в каталоге или их версии вне затронутых.</p> : (
            <div className="table-scroll"><table className="table compact">
              <thead><tr><th>Программа</th><th>Версия</th><th>Результат</th><th className="num">Компьютеров</th></tr></thead>
              <tbody>{m.map((x, i) => <tr key={i}><td><Link to={`/software/p/${encodeURIComponent(x.product_key)}`}>{x.product}</Link></td><td className="mono">{x.version || "—"}</td>
                <td><StatusBadge s={x.status} label={x.status_ru} /><span className="sub small">{x.basis}</span></td><td className="num">{num(x.hosts)}</td></tr>)}</tbody></table></div>)}
        {c.infrastructure?.catalog && m.length > 0 && <p className="muted small">«Подтверждено источником» — продукт сопоставлен надёжно и версия входит в диапазон источника; «потенциально» и «требуется уточнение» требуют проверки специалистом.
          {affected.length === 0 && " Все найденные версии исправлены."} Компьютеры по версиям — кнопка «Проверить инфраструктуру».</p>}
        <h3 className="vdb-h">Данные источников</h3>
        {c.records.map((r) => (
          <details key={r.source} className="disclosure vdb-src" open={c.records.length === 1}>
            <summary><b>{r.title}</b> <span className="mono small">{r.ext_id}</span>{r.scores[0] ? <> · CVSS {r.scores[0].version}: {r.scores[0].score.toFixed(1)} ({r.scores[0].severity_ru})</> : r.severity ? <> · уровень по данным источника: {r.severity_ru}</> : null}</summary>
            <div className="vdb-src-body">
              <p className="muted small">Опубликована {fmtDate(r.published)} · изменена {fmtDate(r.modified)}{r.status ? ` · статус: ${r.status}` : ""}{r.vector ? ` · ${r.vector}` : ""}</p>
              {r.description && <p>{r.description}</p>}
              {r.fix_text && <p><b>Устранение:</b> {r.fix_text}</p>}
              {r.affected.length > 0 && <div className="table-scroll"><table className="table compact"><thead><tr><th>Производитель и продукт</th><th>Версии</th><th>Среда</th></tr></thead>
                <tbody>{r.affected.map((a, i) => <tr key={i}><td>{[a.vendor, a.product].filter(Boolean).join(" ")}{a.ecosystem && <span className="sub mono small">{a.ecosystem}</span>}</td><td className="mono small">{rangeText(a)}{a.fixed && <span className="sub">исправлено в {a.fixed}</span>}</td>
                  <td className="small">{a.conditional ? "зависит от среды" : a.platform || "—"}</td></tr>)}</tbody></table></div>}
              {r.affected_total > r.affected.length && <p className="muted small">Показано {r.affected.length} из {r.affected_total} записей.</p>}
              {r.refs.length > 0 && <p className="small vdb-refs">{r.refs.slice(0, 8).map((x) => <a key={x.url} href={x.url} target="_blank" rel="noopener noreferrer">{x.url.replace(/^https?:\/\//, "").slice(0, 60)}<Icon name="external" size={12} className="ext" /></a>)}</p>}
            </div>
          </details>))}
      </div>}
    </Modal>
  );
}

function MineView({ ctx, counts, onCounts }: { ctx: Ctx; counts: VdbCounts | null; onCounts: (c: VdbCounts) => void }) {
  const [sp, setSp] = useSearchParams();
  const sid = ctx.current?.id ?? "";
  const [newOnly, setNewOnly] = useKept("vdbm.new", true); const [sev, setSev] = useKept<Sev>("vdbm.sev", ""); const [kev, setKev] = useKept("vdbm.kev", false);
  const [range, setRange] = useKept("vdbm.range", ""); const [sort, setSort] = useKept("vdbm.sort", "priority"); const [desc, setDesc] = useKept("vdbm.desc", true);
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(true); } };
  const sel = useRowSel<string>(); const [report, setReport] = useState<Report | null>(null); const [toast, show] = useToast();
  const canReport = ctx.me.user.role !== "viewer";
  const list = useInfinite<VdbVulnRow>(`vdb-mine:${sid}`, [newOnly, sev, kev, range, sort, desc], (offset, limit) => api.vdb.findings({ new_only: newOnly || undefined, min_severity: sev, ...scoreParams(range, "", ""), sort, desc, exploited: kev || undefined, offset, limit }) as unknown as Promise<Chunk<VdbVulnRow>>);
  const extra = list.extra as { summary?: VdbCounts } | null;
  useEffect(() => { if (extra?.summary) onCounts(extra.summary); }, [extra?.summary]); // eslint-disable-line react-hooks/exhaustive-deps
  const s = extra?.summary ?? counts;
  const keys = list.items.map((v) => v.key);
  const mark = async (all: boolean) => { try { const c = await api.vdb.seen(sel.ids, all); onCounts(c); sel.clear(); list.reload(); show("Отмечено как просмотренное"); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <>
      <div className="meters">
        <div className="meter"><span className="l">Новых</span><span className={`v ${s?.new ? "warn-text" : ""}`}>{s ? num(s.new) : "…"}</span><span className="t">не просмотрены специалистом</span></div>
        <div className="meter"><span className="l">Из них эксплуатируются</span><span className={`v ${s?.new_exploited ? "bad-text" : ""}`}>{s ? num(s.new_exploited) : "…"}</span><span className="t">подтверждено CISA KEV</span></div>
        <div className="meter"><span className="l">Из них критических</span><span className={`v ${s?.new_critical ? "bad-text" : ""}`}>{s ? num(s.new_critical) : "…"}</span>{s && <span className="t">критических, высоких и эксплуатируемых — {num(s.new_serious)}, как в меню</span>}</div>
        <div className="meter"><span className="l">Всего затрагивают</span><span className="v">{s ? num(s.total) : "…"}</span><span className="t">по каталогу «{ctx.current?.name}»</span></div>
      </div>
      <div className="toolbar">
        <label className="check inline-check"><input type="checkbox" className="switch" checked={newOnly} onChange={(e) => setNewOnly(e.target.checked)} />Только новые</label>
        <Segmented<Sev> label="Уровень опасности" value={sev} onChange={setSev} options={SEV_OPTS} />
        <label className="field">CVSS<select value={range} onChange={(e) => setRange(e.target.value)}>{CVSS_RANGES.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}</select></label>
        <label className="check inline-check"><input type="checkbox" className="switch" checked={kev} onChange={(e) => setKev(e.target.checked)} />Только эксплуатируемые</label>
        <div className="toolbar-foot"><span className="muted small">Оценка по каталогу установленного ПО, без запросов к KSC; список компьютеров — по кнопке «Проверить».</span>
          {canReport && (s?.new ?? 0) > 0 && <button type="button" className="link-btn" onClick={() => mark(true)}>Отметить все просмотренными</button>}</div>
      </div>
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : (
          <table className="table virt">
            <thead><tr><CheckAll all={sel.allOf(keys)} some={sel.someOf(keys)} onToggle={() => sel.toggleMany(keys)} /><th>Уязвимость</th><SortTh k="score" label="CVSS" sort={sort} desc={desc} onSort={onSort} /><SortTh k="priority" label="Критичность" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /><th className="hide-sm">Результат</th><th className="hide-sm hide-lg">Затронутое ПО</th><th className="hide-sm"><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>
              <VirtualRows list={list} colSpan={7} estimate={64} row={(v) => (
                <tr className={`clickable ${sel.has(v.key) ? "sel" : ""}`} onClick={(e) => { if (!(e.target as HTMLElement).closest("input, button, a")) setSp((p) => { p.set("v", v.key); return p; }); }}>
                  <td className="check"><input type="checkbox" aria-label={`Выбрать ${v.key}`} checked={sel.has(v.key)} onChange={() => sel.toggle(v.key)} /></td>
                  <td><button type="button" className="link-btn strong-link mono" onClick={() => setSp((p) => { p.set("v", v.key); return p; })}>{v.key}</button>{v.finding?.new && <span className="badge accent new-dot">новая</span>}<span className="sub vdb-title">{v.title || v.description}</span><span className="sub small">найдена {fmtDate(v.finding?.first_seen_at)}</span>{v.finding && <span className="sm-stack"><StatusBadge s={v.finding.status} label={v.finding.status_ru} /></span>}</td>
                  <td className="nowrap"><CvssCell v={v} /><span className="sm-stack"><LevelBadge v={v} />{v.exploited && <Kev />}</span></td>
                  <td className="hide-sm"><LevelBadge v={v} />{v.exploited && <span className="block kev-line"><Kev /></span>}</td>
                  <td className="hide-sm">{v.finding && <StatusBadge s={v.finding.status} label={v.finding.status_ru} />}</td>
                  <td className="small hide-sm hide-lg vdb-prods">{v.finding?.products.slice(0, 3).map((p) => <span key={p.key} className="block">{p.name} <span className="muted mono nowrap">{p.versions.slice(0, 2).join(", ")}{p.versions.length > 2 ? "…" : ""}</span></span>)}
                    <span className="sub">до {num(v.finding?.hosts_max)} комп., {num(v.finding?.installs)} уст.</span></td>
                  <td className="actions hide-sm">{canReport && <button type="button" className="btn mini ghost row-act" onClick={() => setReport({ title: `Проверка инфраструктуры: ${v.key}`, keys: [v.key] })}><Icon name="target" size={15} />Проверить</button>}</td>
                </tr>)} />
              {!list.items.length && !list.loading && <tr><td colSpan={7}><Empty icon="checkCircle" title="Ничего не найдено">{newOnly ? "Новых уязвимостей, затрагивающих установленное ПО, нет. Выключите «Только новые», чтобы увидеть все." : "По этим условиям уязвимостей, затрагивающих установленное ПО, не найдено."}</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      <ReportDock label="Выбранные уязвимости" count={sel.count} noun={["уязвимость выбрана", "уязвимости выбраны", "уязвимостей выбрано"]} canReport={canReport} onClear={sel.clear}
        onReport={() => setReport({ title: `Проверка инфраструктуры: ${sel.count} ${plural(sel.count, "уязвимость", "уязвимости", "уязвимостей")}`, keys: sel.ids })} />
      {sel.count > 0 && canReport && <button className="btn mini seen-btn" onClick={() => mark(false)}><Icon name="check" size={15} />Отметить просмотренными</button>}
      {sp.get("v") && <VdbCardPanel ctx={ctx} id={sp.get("v")!} onClose={() => setSp((p) => { p.delete("v"); return p; })} onReport={(r) => setReport(r)} />}
      <ReportHost ctx={ctx} report={report} onClose={() => setReport(null)} />
      {toast}
    </>
  );
}

function SourcesView({ ctx }: { ctx: Ctx }) {
  const [d, setD] = useState<{ items: VdbSourceInfo[]; vulns: number } | null>(null);
  useEffect(() => { api.vdb.sources().then(setD).catch(() => setD({ items: [], vulns: 0 })); }, []);
  const stale = useMemo(() => (d?.items ?? []).filter((s) => s.enabled && s.last_ok_at && Date.now() - new Date(s.last_ok_at).getTime() > s.interval_hours * 3600_000 * 3), [d]);
  return (
    <>
      <div className="alert info"><Icon name="info" /><div className="alert-body">Локальная база работает без интернета: поиск и проверка идут по последней корректно загруженной копии. Источники включаются и настраиваются администратором.
        {ctx.me.user.is_admin && <> <Link to="/admin?tab=vdb">Настроить источники</Link></>}</div></div>
      {stale.length > 0 && <div className="alert warn"><Icon name="alert" /><div className="alert-body">Данные давно не обновлялись: {stale.map((s) => s.title).join(", ")}.</div></div>}
      <div className="table-scroll">
        {!d ? <SkelRows rows={4} cols={5} /> : (
          <table className="table"><thead><tr><th>Источник</th><th>Состояние</th><th>Последняя загрузка</th><th className="num">Записей</th><th className="hide-sm">Длительность</th></tr></thead>
            <tbody>{d.items.map((s) => (
              <tr key={s.key}><td><b>{s.title}</b><span className="sub small"><a href={s.url} target="_blank" rel="noopener noreferrer">{s.url.replace("https://", "")}</a></span></td>
                <td>{!s.enabled ? <span className="badge">выключен</span> : s.status === "ok" ? <span className="badge ok">загружен</span> : s.status === "running" ? <span className="badge accent">{s.progress ?? "идёт загрузка"}</span> : s.status === "error" ? <span className="badge err" title={s.last_error ?? ""}>ошибка</span> : <span className="badge warn">не загружался</span>}
                  {s.last_error && s.enabled && <span className="sub small err-text">{s.last_error.slice(0, 140)}</span>}</td>
                <td className="small nowrap">{s.last_ok_at ? <Fetched at={s.last_ok_at} prefix="" /> : "—"}</td><td className="num">{num(s.records)}</td>
                <td className="small hide-sm">{s.last_duration_ms != null ? `${(s.last_duration_ms / 1000).toFixed(1)} с` : "—"}</td></tr>))}
              {!d.items.length && <tr><td colSpan={5}><Empty icon="database" title="Источники не найдены">Миграции базы не применены?</Empty></td></tr>}</tbody></table>)}
      </div>
      {d && <p className="muted small mt-sm">Уязвимостей в локальной базе: <b>{num(d.vulns)}</b>. Время — {fmt(new Date().toISOString())}.</p>}
    </>
  );
}
