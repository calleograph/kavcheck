import { ZoneSelect, HostZones } from "../components/ZoneBits";
import { CompactList } from "../components/CompactList";
import { EolList } from "../components/EolList";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, type ApiError, type HostVuln, type QuickKind, type SavedCheck, type VulnDescr, type VulnHost, type VulnProduct, type VulnSummary } from "../api";
import { NoSource, type Ctx } from "../App";
import { Fetched } from "../components/Common";
import { CountButton, FilterBar } from "../components/FilterBar";
import { HostsDrawer, type DrawerHost } from "../components/HostsDrawer";
import { CheckAll, QuickReportPanel, ReportDock, useRowSel, type QuickScopeOpts } from "../components/QuickReport";
import { ExpandCell, ExpandTh, ExpandedRow, XGrid, XItem, useExpanded } from "../components/ExpandRow";
import { ListFoot, VirtualRows, useInfinite, useKept, usePanel, useStaticList, type Chunk } from "../components/Infinite";
import { Icon } from "../components/Icons";
import { useToast } from "../components/Toast";
import { maskMatcher } from "../mask";
import { Empty, HiddenNote, PageHead, Segmented, SevCounts, SkelRows, SortTh, Tabs, MaskHint, BackLink } from "../components/ui";
import { fmt, fmtDate, num } from "../util";
import { itemSummary } from "./AuditBuilder";

type Tab = "list" | "hosts" | "products" | "checks";
type Report = { kind: QuickKind; title: string; lede?: string; params: Record<string, unknown>; options?: QuickScopeOpts };
type Sev = "" | "critical" | "high" | "warning";
const SEV_OPTS: [Sev, string][] = [["", "Все"], ["critical", "Критические"], ["high", "Высокие"], ["warning", "Предупреждения"]];

/** Раздел «Уязвимости»: сначала самые проблемные компьютеры и программы (данные KSC), отдельно — проверки версий (условия пользователей). */
export default function VulnsPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const tab = (["list", "hosts", "products", "checks"].includes(sp.get("tab") ?? "") ? sp.get("tab") : "list") as Tab;
  const [type, setType] = useKept<"all" | "cve" | "eol">("vulns.type", "all");
  const [eol, setEol] = useState<Awaited<ReturnType<typeof api.eol.summary>> | null>(null);
  useEffect(() => { if (ctx.current) api.eol.summary("", ctx.current.id).then(setEol).catch(() => setEol(null)); }, [ctx.current?.id]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const eolOn = !!eol?.base.include_in_analytics;                 // EOL включён в аналитику — отдельный тип записей рядом с CVE, без двойного подсчёта
  const eolN = eol ? eol.findings.eol + eol.findings.extended + eol.findings.upcoming : 0;
  const kind: "all" | "cve" | "eol" = eolOn ? type : "cve";
  return (
    <section>
      <PageHead title="Уязвимости" lede="Уязвимости программ, найденные Kaspersky Security Center: какие компьютеры и программы требуют внимания в первую очередь. Проверки версий — ваши собственные условия — показаны отдельно." />
      {eolOn && <div className="toolbar"><Segmented<"all" | "cve" | "eol"> label="Тип записей" value={type} onChange={setType} options={[["all", "Все"], ["cve", "CVE"], ["eol", `EOL${eolN ? ` · ${eolN}` : ""}`]]} />
        <span className="muted small">EOL — окончание поддержки программы или ОС; это отдельный тип проблем, он не входит в число CVE.</span></div>}
      {kind === "eol" && <div className="vdb-eol"><h3 className="h3">EOL: программы и ОС без поддержки производителя{eol ? ` (${eolN})` : ""}</h3><EolList limit={100} sourceId={ctx.current.id} /></div>}
      {kind !== "eol" && <>
      <Tabs label="Вид" value={tab} onChange={(t) => setSp((p) => { p.set("tab", t); return p; })}
        items={[{ id: "list", label: "Уязвимости" }, { id: "products", label: "Уязвимые программы" }, { id: "hosts", label: "Компьютеры" }, { id: "checks", label: "Проверки версий" }]} />
      {tab === "list" ? <ListView ctx={ctx} /> : tab === "hosts" ? <HostsView ctx={ctx} /> : tab === "products" ? <ProductsView ctx={ctx} /> : <ChecksView ctx={ctx} />}
      </>}
    </section>
  );
}

function Unsupported({ missing }: { missing: string[] }) {
  return <div className="alert warn"><Icon name="alert" /><div className="alert-body">В базе источника нет объектов уязвимостей KSC ({missing.join(", ")}). Раздел недоступен для этого источника.</div></div>;
}

function HostsView({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const navigate = useNavigate();
  const sid = ctx.current?.id ?? "";
  const productId = sp.get("product_id"); const productName = sp.get("product_name"); const productTitle = sp.get("product_title");
  const [q, setQ] = useKept("vulns.q", ""); const [group, setGroup] = useKept("vulns.group", ""); const [product, setProduct] = useKept("vulns.product", ""); const [cve, setCve] = useKept("vulns.cve", "");
  const [applied, setApplied] = useState({ q, group, product, cve });
  const [severity, setSeverity] = useKept<Sev>("vulns.severity", ""); const [patchable, setPatchable] = useKept("vulns.patchable", false);
  const [all, setAll] = useKept("vulns.all", false); const [zone, setZone] = useKept("vulns.zone", sp.get("zone") ?? "");
  const [sort, setSort] = useKept("vulns.sort", "risk"); const [desc, setDesc] = useKept("vulns.desc", true);
  const sel = useRowSel<number>(); const [report, setReport] = useState<Report | null>(null);
  const canReport = ctx.me.user.role !== "viewer";
  const force = useRef(false);   // «Обновить» перечитывает данные KSC один раз, а не при каждой следующей порции
  useEffect(() => { const t = window.setTimeout(() => setApplied({ q, group, product, cve }), 350); return () => window.clearTimeout(t); }, [q, group, product, cve]);
  const list = useInfinite<VulnHost>(`vulns-hosts:${sid}`, [applied, productId, productName, severity, patchable, all, sort, desc, zone], (offset, limit) => {
    const refresh = (force.current && offset === 0) || undefined; force.current = false;
    return api.vulns.hosts({ ...applied, product_id: productId, product_name: productName, severity, patchable, all_hosts: all, zone, sort, desc, offset, limit, refresh }) as unknown as Promise<Chunk<VulnHost>>;
  });
  const extra = list.extra as { summary?: VulnSummary | null; unsupported?: string[] } | null;
  const s = extra?.summary ?? null;
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(k !== "name"); } };
  if (extra?.unsupported) return <Unsupported missing={extra.unsupported} />;
  return (
    <>
      <div className="meters">
        <div className="meter"><span className="l">Компьютеров с уязвимостями</span><span className="v">{s ? num(s.hosts) : "…"}</span><span className="t">{all ? "все устройства" : `активные за ${ctx.me.activity_days} сут`}</span></div>
        <div className="meter"><span className="l">С критическими</span><span className={`v ${s?.critical_hosts ? "bad-text" : ""}`}>{s ? num(s.critical_hosts) : "…"}</span><span className="t">{s ? `${num(s.critical)} уязвимостей` : ""}</span></div>
        <div className="meter"><span className="l">С высокими</span><span className={`v ${s?.high_hosts ? "warn-text" : ""}`}>{s ? num(s.high_hosts) : "…"}</span><span className="t">{s ? `${num(s.high)} уязвимостей` : ""}</span></div>
        <div className="meter"><span className="l">Можно исправить сейчас</span><span className="v">{s ? num(s.patchable) : "…"}</span><span className="t">{s ? `из ${num(s.total)} обнаружений` : ""}</span></div>
      </div>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Компьютер или IP-адрес", label: "Компьютер" }}
        primary={<><Segmented<Sev> label="Уровень опасности" value={severity} onChange={setSeverity} options={SEV_OPTS} /><ZoneSelect value={zone} onChange={setZone} /></>}
        more={<>
          <label className="field">Программа<input value={product} onChange={(e) => setProduct(e.target.value)} placeholder="Например, *Chrome*" /></label>
          <label className="field">CVE<input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2024-…" className="mono" /></label>
          <label className="field">Группа администрирования<input value={group} onChange={(e) => setGroup(e.target.value)} placeholder="Например, *Серверы*" /></label>
          <label className="check"><input type="checkbox" className="switch" checked={patchable} onChange={(e) => setPatchable(e.target.checked)} />Есть исправление</label>
          <label className="check"><input type="checkbox" className="switch" checked={all} onChange={(e) => setAll(e.target.checked)} />Учитывать давно не подключавшиеся устройства</label>
        </>}
        moreActive={[product, cve, group, patchable ? "1" : "", all ? "1" : ""].filter(Boolean).length}
        chips={[...(q ? [{ id: "q", label: `Компьютер: ${q}`, onRemove: () => setQ("") }] : []), ...(severity ? [{ id: "sev", label: `Опасность: ${SEV_OPTS.find((o) => o[0] === severity)?.[1]}`, onRemove: () => setSeverity("") }] : []),
          ...(zone ? [{ id: "zone", label: "Зона ответственности", onRemove: () => setZone("") }] : []), ...(product ? [{ id: "prod", label: `Программа: ${product}`, onRemove: () => setProduct("") }] : []),
          ...(cve ? [{ id: "cve", label: `CVE: ${cve}`, onRemove: () => setCve("") }] : []), ...(group ? [{ id: "grp", label: `Группа: ${group}`, onRemove: () => setGroup("") }] : []),
          ...(patchable ? [{ id: "fix", label: "Есть исправление", onRemove: () => setPatchable(false) }] : []), ...(all ? [{ id: "all", label: "Включая неактивные устройства", onRemove: () => setAll(false) }] : []),
          ...(productId || productName ? [{ id: "pid", label: `Программа: ${productTitle ?? productName ?? productId}`, onRemove: () => setSp((p) => { p.delete("product_id"); p.delete("product_name"); p.delete("product_title"); return p; }) }] : [])]}
        onReset={() => { setQ(""); setSeverity(""); setZone(""); setProduct(""); setCve(""); setGroup(""); setPatchable(false); setAll(false); setSp((p) => { p.delete("product_id"); p.delete("product_name"); p.delete("product_title"); return p; }); }}
        count={{ n: list.initial ? null : list.total, noun: ["компьютер", "компьютера", "компьютеров"], hint: s ? <> · <Fetched at={s.fetched_at} /></> : undefined }}
        onRefresh={() => { force.current = true; list.reload(); }} refreshing={list.loading}
        report={canReport ? { onClick: () => setReport({ kind: "quick_vulns", title: sel.count ? `Уязвимости выбранных компьютеров (${sel.count})` : "Уязвимости по условиям страницы", options: { scope: true, severity: true, patchable: true },
          params: sel.count ? { host_ids: sel.ids, severity, patchable, include_inactive: all } : { q: applied.q || undefined, group_contains: applied.group || undefined, product_like: applied.product || undefined, cves: applied.cve ? [applied.cve] : [],
            vp_ids: productId ? [Number(productId)] : [], product_names: productName ? [productName] : [], severity, patchable, zone: zone || undefined, include_inactive: all } }),
          title: sel.count ? "Отчёт по отмеченным компьютерам" : "Отчёт по всем уязвимостям, подходящим под фильтры страницы" } : null} />
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : (
          <table className="table virt">
            <thead><tr><CheckAll all={sel.allOf(list.items.map((h) => h.host_id))} some={sel.someOf(list.items.map((h) => h.host_id))} onToggle={() => sel.toggleMany(list.items.map((h) => h.host_id))} />
              <SortTh k="name" label="Компьютер" sort={sort} desc={desc} onSort={onSort} /><th className="hide-sm">ОС</th><th className="hide-sm">Группа</th><SortTh k="last_connected" label="Подключение к KSC" sort={sort} desc={desc} onSort={onSort} className="hide-sm" />
              <SortTh k="risk" label="Уязвимости" sort={sort} desc={desc} onSort={onSort} /><SortTh k="total" label="Всего" sort={sort} desc={desc} onSort={onSort} className="num" /><SortTh k="patchable" label="С исправлением" sort={sort} desc={desc} onSort={onSort} className="num hide-sm" /></tr></thead>
            <tbody>
              <VirtualRows list={list} colSpan={8} estimate={46} row={(h) => (
                <tr className={`clickable ${sel.has(h.host_id) ? "sel" : ""}`} onClick={(e) => { if (!(e.target as HTMLElement).closest("a, input")) navigate(`/vulnerabilities/hosts/${h.host_id}`); }}>
                  <td className="check"><input type="checkbox" aria-label={`Выбрать ${h.name}`} checked={sel.has(h.host_id)} onChange={() => sel.toggle(h.host_id)} /></td>
                  <td><Link to={`/vulnerabilities/hosts/${h.host_id}`} className="strong-link">{h.name}</Link><span className="sub mono">{h.ip}</span>{h.zone && <span className="sub zone-sub" title="Зона ответственности">{h.zone}</span>}</td>
                  <td className="small hide-sm">{h.os}</td><td className="small hide-sm">{h.group}</td><td className="nowrap small hide-sm">{fmt(h.last_connected)}</td>
                  <td><SevCounts critical={h.critical} high={h.high} warning={h.warning} compact /></td>
                  <td className="num"><b>{num(h.total)}</b><span className="sub">{num(h.products)} прогр.</span></td><td className="num hide-sm">{num(h.patchable)}</td>
                </tr>)} />
              {!list.items.length && !list.loading && <tr><td colSpan={8}><Empty icon="checkCircle" title="Компьютеров с уязвимостями нет">{applied.q || applied.product || applied.cve || applied.group || severity || patchable ? "По этим условиям ничего не найдено." : "KSC не нашёл неисправленных уязвимостей на учтённых компьютерах."}</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      {s && <HiddenNote hidden={s.hidden_hosts} days={s.activity_days} all={all} onToggle={() => setAll(!all)} />}
      <ReportDock label="Выбранные компьютеры" count={sel.count} noun={["компьютер выбран", "компьютера выбрано", "компьютеров выбрано"]} canReport={canReport} onClear={sel.clear}
        onReport={() => setReport({ kind: "quick_vulns", title: `Уязвимости выбранных компьютеров (${sel.count})`, options: { scope: true, severity: true, patchable: true },
          params: { host_ids: sel.ids, severity, patchable, include_inactive: all } })} />
      {report && <QuickReportPanel {...report} activityDays={ctx.me.activity_days} canReport={canReport} onClose={() => setReport(null)} />}
      <p className="muted small mt-sm">Действующие обнаружения: не исправлены и не игнорируются. KSC оценивает только программы из своего справочника; пакеты Linux и, например, PHP он не проверяет — для них используйте проверку версий.</p>
    </>
  );
}

/** Боковая панель компьютеров уязвимости или программы: серверные поиск, сортировка и страницы; имя ведёт в карточку, отчёт — по этим же компьютерам. */
function VulnHostsPanel({ title, lede, filters, all, ctx, onClose, report }: { title: string; lede: string; filters: Record<string, string | number | undefined>; all: boolean; ctx: Ctx; onClose: () => void; report?: () => void }) {
  return (
    <HostsDrawer title={title} lede={lede} listKey={`vuln-panel:${ctx.current?.id}:${JSON.stringify(filters)}:${all}`} deps={[filters, all]} search="Компьютер или IP-адрес" sortKeys={{ name: "name", last_connected: "last_connected" }}
      activityDays={ctx.me.activity_days} defaultSort="name"
      fetchPage={async (offset, limit, qy) => {
        const r = await api.vulns.hosts({ ...filters, q: qy.q, all_hosts: all, sort: qy.sort === "last_connected" ? "last_connected" : "name", desc: qy.desc, offset, limit }) as unknown as Chunk<VulnHost>;
        return { items: r.items.map((h) => ({ ...h, note: <span className="sub"><SevCounts critical={h.critical} high={h.high} warning={h.warning} compact /></span> })), total: r.total } as unknown as Chunk<DrawerHost>;
      }}
      report={report ? { onClick: report } : null} onClose={onClose} />
  );
}

/** Список уязвимостей KSC (KLA/CVE): найти новую CVE, выбрать одну или несколько записей и сразу получить отчёт о затронутых компьютерах. */
function ListView({ ctx }: { ctx: Ctx }) {
  const sid = ctx.current?.id ?? "";
  const [q, setQ] = useKept("vlist.q", ""); const [applied, setApplied] = useState(q);
  const [severity, setSeverity] = useKept<Sev>("vlist.severity", ""); const [patchable, setPatchable] = useKept("vlist.patchable", false); const [all, setAll] = useKept("vlist.all", false);
  const [sort, setSort] = useKept("vlist.sort", "risk"); const [desc, setDesc] = useKept("vlist.desc", true);
  const sel = useRowSel<number>(); const [report, setReport] = useState<Report | null>(null); const ex = useExpanded<number>();
  const canReport = ctx.me.user.role !== "viewer";
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 350); return () => window.clearTimeout(t); }, [q]);
  const list = useInfinite<VulnDescr>(`vulns-list:${sid}`, [applied, severity, patchable, all, sort, desc],
    (offset, limit) => api.vulns.list({ q: applied, severity, patchable, all_hosts: all, sort, desc, offset, limit }) as unknown as Promise<Chunk<VulnDescr>>);
  const extra = list.extra as { summary?: { vulns: number; critical: number; high: number; warning: number; patchable: number; fetched_at: string }; unsupported?: string[] } | null;
  const s = extra?.summary;
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(k !== "name"); } };
  const ids = list.items.map((v) => v.descr_id);
  const reportFor = (list_: number[], title: string): Report => ({ kind: "quick_vulns", title, options: { scope: true, severity: false, patchable: true }, params: { descr_ids: list_, include_inactive: all } });
  const [busy, setBusy] = useState(false); const [note, setNote] = useState(""); const [panel, setPanel] = usePanel<VulnDescr>("vuln");
  /** Отметка есть — отчёт по ней; иначе по всем найденным по условиям страницы: идентификаторы собираются порциями на сервере (не больше 5 000 уязвимостей в одном отчёте). */
  const reportAll = async () => {
    setNote("");
    if (sel.count) { setReport(reportFor(sel.ids, sel.count === 1 ? "Отчёт по выбранной уязвимости" : `Отчёт по выбранным уязвимостям (${sel.count})`)); return; }
    setBusy(true);
    try {
      const got: number[] = [];
      for (let off = 0; got.length < 5000; off += 500) {
        const r = await api.vulns.list({ q: applied, severity, patchable, all_hosts: all, sort, desc, offset: off, limit: 500 }) as unknown as Chunk<VulnDescr>;
        got.push(...r.items.map((v) => v.descr_id));
        if (r.items.length < 500 || got.length >= r.total) break;
      }
      if (!got.length) { setNote("По этим условиям уязвимостей нет."); return; }
      if (got.length > 5000 || list.total > 5000) setNote(`Найдено ${num(list.total)} уязвимостей: в отчёт войдут первые 5 000 — уточните фильтр.`);
      setReport(reportFor(got.slice(0, 5000), `Отчёт по найденным уязвимостям (${num(Math.min(got.length, 5000))})`));
    } catch (e) { setNote((e as Error).message); } finally { setBusy(false); }
  };
  if (extra?.unsupported) return <Unsupported missing={extra.unsupported} />;
  return (
    <>
      <div className="meters">
        <div className="meter"><span className="l">Уязвимостей в KSC</span><span className="v">{s ? num(s.vulns) : "…"}</span><span className="t">{all ? "по всем устройствам" : `по компьютерам, активным за ${ctx.me.activity_days} сут`}</span></div>
        <div className="meter"><span className="l">Критических</span><span className={`v ${s?.critical ? "bad-text" : ""}`}>{s ? num(s.critical) : "…"}</span></div>
        <div className="meter"><span className="l">Высоких</span><span className={`v ${s?.high ? "warn-text" : ""}`}>{s ? num(s.high) : "…"}</span></div>
        <div className="meter"><span className="l">С исправлением</span><span className="v">{s ? num(s.patchable) : "…"}</span></div>
      </div>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "CVE-2024-…, KLA или программа", label: "Поиск уязвимости" }}
        primary={<Segmented<Sev> label="Уровень опасности" value={severity} onChange={setSeverity} options={SEV_OPTS} />}
        more={<>
          <label className="check"><input type="checkbox" className="switch" checked={patchable} onChange={(e) => setPatchable(e.target.checked)} />Есть исправление</label>
          <label className="check"><input type="checkbox" className="switch" checked={all} onChange={(e) => setAll(e.target.checked)} />Учитывать давно не подключавшиеся устройства</label>
        </>}
        moreActive={[patchable ? "1" : "", all ? "1" : ""].filter(Boolean).length}
        chips={[...(q ? [{ id: "q", label: `Поиск: ${q}`, onRemove: () => setQ("") }] : []), ...(severity ? [{ id: "sev", label: `Опасность: ${SEV_OPTS.find((o) => o[0] === severity)?.[1]}`, onRemove: () => setSeverity("") }] : []),
          ...(patchable ? [{ id: "fix", label: "Есть исправление", onRemove: () => setPatchable(false) }] : []), ...(all ? [{ id: "all", label: "Включая неактивные устройства", onRemove: () => setAll(false) }] : [])]}
        onReset={() => { setQ(""); setSeverity(""); setPatchable(false); setAll(false); }}
        count={{ n: list.initial ? null : list.total, noun: ["уязвимость", "уязвимости", "уязвимостей"], hint: s ? <> · <Fetched at={s.fetched_at} /></> : undefined }} onRefresh={() => list.reload()} refreshing={list.loading}
        report={canReport ? { onClick: reportAll, disabled: busy, title: sel.count ? "Отчёт по отмеченным уязвимостям" : "Отчёт по всем найденным уязвимостям: затронутые компьютеры без повторов" } : null} />
      <p className="muted small fbar-note">Отметьте одну или несколько уязвимостей — отчёт покажет затронутые компьютеры без повторов.{note && <b className="warn-text"> {note}</b>}</p>
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : (
          <table className="table virt">
            <thead><tr><CheckAll all={sel.allOf(ids)} some={sel.someOf(ids)} onToggle={() => sel.toggleMany(ids)} /><ExpandTh />
              <SortTh k="name" label="Уязвимость" sort={sort} desc={desc} onSort={onSort} /><SortTh k="risk" label="Опасность" sort={sort} desc={desc} onSort={onSort} /><th className="hide-sm">Программы</th>
              <SortTh k="hosts" label="Компьютеров" sort={sort} desc={desc} onSort={onSort} className="num" /><SortTh k="total" label="Обнаружений" sort={sort} desc={desc} onSort={onSort} className="num hide-sm" /><th className="hide-sm">Исправление</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <VirtualRows group list={list} colSpan={9} estimate={58} row={(v) => (
              <>
                <tr className={sel.has(v.descr_id) ? "sel" : ""}>
                  <td className="check"><input type="checkbox" aria-label={`Выбрать ${v.kla_id}`} checked={sel.has(v.descr_id)} onChange={() => sel.toggle(v.descr_id)} /></td>
                  <ExpandCell id={`v${v.descr_id}`} open={ex.has(v.descr_id)} onToggle={() => ex.toggle(v.descr_id)} label={v.kla_id} />
                  <td>{v.url ? <a href={v.url} target="_blank" rel="noopener noreferrer" className="mono strong-link">{v.kla_id}<Icon name="external" size={13} className="ext" /></a> : <span className="mono">{v.kla_id}</span>}
                    <span className="sub mono">{v.cve.length ? <CompactList items={v.cve} label="CVE" /> : "без CVE"}</span></td>
                  <td><span className={`sev ${v.severity === "critical" ? "crit" : v.severity === "high" ? "high" : "warn"}`}>{v.severity_label}</span></td>
                  <td className="small hide-sm"><CompactList items={v.products} label="программы" /></td>
                  <td className="num"><CountButton n={v.hosts} onClick={() => setPanel(v)} label="Показать компьютеры с этой уязвимостью" /></td><td className="num hide-sm">{num(v.total)}</td>
                  <td className="hide-sm">{v.patchable ? <span className="badge ok">доступно</span> : <span className="muted small">нет</span>}</td>
                  <td className="actions">{canReport && <button type="button" className="btn mini ghost row-act" title="Отчёт по этой уязвимости: затронутые компьютеры" onClick={() => setReport(reportFor([v.descr_id], `Отчёт по уязвимости ${v.cve[0] ?? v.kla_id}`))}><Icon name="file" size={15} />Отчёт</button>}</td>
                </tr>
                <ExpandedRow id={`v${v.descr_id}`} open={ex.has(v.descr_id)} colSpan={9}>
                  <XGrid>
                    <XItem label="Идентификатор KSC">{v.kla_id}</XItem><XItem label="Опасность">{v.severity_label}</XItem>
                    <XItem label="Компьютеров">{num(v.hosts)} · обнаружений {num(v.total)}</XItem><XItem label="Исправление">{v.patchable ? `доступно для ${num(v.patchable)} обнаружений` : "нет"}</XItem>
                    <XItem label="Последнее обнаружение">{fmt(v.last_detected)}</XItem>
                    <XItem label="CVE" wide>{v.cve.length ? v.cve.map((c, i) => <span key={c}>{i > 0 && ", "}<a href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener noreferrer" className="mono">{c}</a></span>) : "без CVE"}</XItem>
                    <XItem label="Бюллетени и обновления">{v.kb.length ? v.kb.join(", ") : ""}</XItem>
                    <XItem label="Описание в первоисточнике">{v.url ? <a href={v.url} target="_blank" rel="noopener noreferrer">{v.url.replace(/^https?:\/\//, "").slice(0, 70)}</a> : ""}</XItem>
                    <XItem label="Затронутые программы" wide>{v.products.join("; ")}</XItem>
                  </XGrid>
                </ExpandedRow>
              </>)} />
            {!list.items.length && !list.loading && <tbody><tr><td colSpan={9}><Empty icon="checkCircle" title="Уязвимостей не найдено">{applied || severity || patchable ? "По этим условиям ничего нет. Проверьте написание CVE или включите «Все устройства»." : "KSC не нашёл неисправленных уязвимостей."}</Empty></td></tr></tbody>}
          </table>)}
      </div>
      <ListFoot list={list} />
      {s && <p className="hidden-note"><Icon name={all ? "eye" : "eyeOff"} size={15} /><span>{all ? "Счётчики учитывают все устройства." : `Счётчики учитывают компьютеры, подключавшиеся к KSC за ${ctx.me.activity_days} сут.`}</span>
        <button type="button" className="link-btn" onClick={() => setAll(!all)}>{all ? "Только активные" : "Учитывать все"}</button></p>}
      <ReportDock label="Выбранные уязвимости" count={sel.count} noun={["уязвимость выбрана", "уязвимости выбраны", "уязвимостей выбрано"]} canReport={canReport} onClear={sel.clear}
        onReport={() => setReport(reportFor(sel.ids, sel.count === 1 ? "Отчёт по выбранной уязвимости" : `Отчёт по выбранным уязвимостям (${sel.count})`))} />
      {panel && <VulnHostsPanel title={panel.cve[0] ?? panel.kla_id} lede={`${panel.severity_label ?? ""} · ${panel.products.slice(0, 3).join(", ")}${panel.products.length > 3 ? ` и ещё ${panel.products.length - 3}` : ""}. ${all ? "Все устройства" : `Компьютеры, подключавшиеся к KSC за ${ctx.me.activity_days} сут`}.`}
        filters={{ cve: panel.cve[0] ?? panel.kla_id }} all={all} ctx={ctx} onClose={() => setPanel(null)} report={canReport ? () => setReport(reportFor([panel.descr_id], `Отчёт по уязвимости ${panel.cve[0] ?? panel.kla_id}`)) : undefined} />}
      {report && <QuickReportPanel {...report} activityDays={ctx.me.activity_days} canReport={canReport} onClose={() => setReport(null)} />}
    </>
  );
}

function ProductsView({ ctx }: { ctx: Ctx }) {
  const [, setSp] = useSearchParams();
  const [q, setQ] = useKept("vprod.q", ""); const [cve, setCve] = useKept("vprod.cve", ""); const [applied, setApplied] = useState({ q, cve });
  const [severity, setSeverity] = useKept<Sev>("vprod.severity", ""); const [all, setAll] = useKept("vprod.all", false);
  const [sort, setSort] = useKept("vprod.sort", "risk"); const [desc, setDesc] = useKept("vprod.desc", true);
  useEffect(() => { const t = window.setTimeout(() => setApplied({ q, cve }), 350); return () => window.clearTimeout(t); }, [q, cve]);
  const list = useInfinite<VulnProduct>(`vulns-products:${ctx.current?.id}`, [applied, severity, all, sort, desc],
    (offset, limit) => api.vulns.products({ ...applied, severity, all_hosts: all, sort, desc, offset, limit }) as unknown as Promise<Chunk<VulnProduct>>);
  const extra = list.extra as { fetched_at?: string; unsupported?: string[] } | null;
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(k !== "name"); } };
  const sel = useRowSel<string>(); const [report, setReport] = useState<Report | null>(null); const [panel, setPanel] = usePanel<VulnProduct>("vuln-product");
  const canReport = ctx.me.user.role !== "viewer";
  const pk = (p: VulnProduct) => (p.product_id ? `id:${p.product_id}` : `name:${p.name}`);
  const reportFor = (keys: string[], title: string): Report => ({ kind: "quick_vulns", title, options: { scope: true, severity: true, patchable: true },
    params: { vp_ids: keys.filter((k) => k.startsWith("id:")).map((k) => Number(k.slice(3))), product_names: keys.filter((k) => k.startsWith("name:")).map((k) => k.slice(5)), severity, include_inactive: all } });
  // результат — список компьютеров на вкладке «Компьютеры»: открываем её сверху, где он виден сразу
  const open = (p: VulnProduct) => { setSp((x) => { x.set("tab", "hosts"); if (p.product_id) x.set("product_id", String(p.product_id)); else x.set("product_name", p.name); x.set("product_title", p.name); return x; }); window.scrollTo({ top: 0, behavior: "instant" }); };
  if (extra?.unsupported) return <Unsupported missing={extra.unsupported} />;
  return (
    <>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Программа, например Google Chrome", label: "Программа" }}
        primary={<Segmented<Sev> label="Уровень опасности" value={severity} onChange={setSeverity} options={SEV_OPTS} />}
        more={<>
          <label className="field">CVE<input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2024-…" className="mono" /></label>
          <label className="check"><input type="checkbox" className="switch" checked={all} onChange={(e) => setAll(e.target.checked)} />Учитывать давно не подключавшиеся устройства</label>
        </>}
        moreActive={[cve, all ? "1" : ""].filter(Boolean).length}
        chips={[...(q ? [{ id: "q", label: `Программа: ${q}`, onRemove: () => setQ("") }] : []), ...(severity ? [{ id: "sev", label: `Опасность: ${SEV_OPTS.find((o) => o[0] === severity)?.[1]}`, onRemove: () => setSeverity("") }] : []),
          ...(cve ? [{ id: "cve", label: `CVE: ${cve}`, onRemove: () => setCve("") }] : []), ...(all ? [{ id: "all", label: "Включая неактивные устройства", onRemove: () => setAll(false) }] : [])]}
        onReset={() => { setQ(""); setSeverity(""); setCve(""); setAll(false); }}
        count={{ n: list.initial ? null : list.total, noun: ["программа", "программы", "программ"], hint: extra?.fetched_at ? <> · <Fetched at={extra.fetched_at} /></> : undefined }} onRefresh={() => list.reload()} refreshing={list.loading}
        report={canReport ? { onClick: () => setReport({ kind: "quick_vulns", title: sel.count ? `Уязвимости выбранных программ (${sel.count})` : "Уязвимости программ по условиям страницы", options: { scope: true, severity: true, patchable: true },
          params: sel.count ? reportFor(sel.ids, "").params : { product_like: applied.q || undefined, cves: applied.cve ? [applied.cve] : [], severity, include_inactive: all } }),
          title: sel.count ? "Отчёт по отмеченным программам" : "Отчёт по всем уязвимым программам, подходящим под фильтры" } : null} />
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={5} /> : (
          <table className="table virt">
            <thead><tr><CheckAll all={sel.allOf(list.items.map(pk))} some={sel.someOf(list.items.map(pk))} onToggle={() => sel.toggleMany(list.items.map(pk))} />
              <SortTh k="name" label="Программа" sort={sort} desc={desc} onSort={onSort} /><SortTh k="hosts" label="Компьютеров" sort={sort} desc={desc} onSort={onSort} className="num" />
              <SortTh k="risk" label="Уровни опасности" sort={sort} desc={desc} onSort={onSort} /><th className="num">Уязвимостей</th><SortTh k="total" label="Обнаружений" sort={sort} desc={desc} onSort={onSort} className="num" /><th className="num">С исправлением</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>
              <VirtualRows list={list} colSpan={8} estimate={40} row={(p) => (
                <tr className={`clickable ${sel.has(pk(p)) ? "sel" : ""}`} onClick={(e) => { if (!(e.target as HTMLElement).closest("input, button")) open(p); }}>
                  <td className="check"><input type="checkbox" aria-label={`Выбрать ${p.name}`} checked={sel.has(pk(p))} onChange={() => sel.toggle(pk(p))} /></td>
                  <td><button type="button" className="link-btn strong-link" onClick={() => open(p)}>{p.name}</button></td><td className="num"><CountButton n={p.hosts} onClick={() => setPanel(p)} label="Показать компьютеры с этой программой" /></td>
                  <td><SevCounts critical={p.critical} high={p.high} warning={p.warning} compact /></td><td className="num">{num(p.vulns)}</td><td className="num">{num(p.total)}</td><td className="num">{num(p.patchable)}</td>
                  <td className="actions"><button type="button" className="btn mini ghost row-act" onClick={(e) => { e.stopPropagation(); open(p); }}><Icon name="monitor" size={15} />Компьютеры</button>
                    {canReport && <button type="button" className="btn mini ghost row-act" onClick={(e) => { e.stopPropagation(); setReport(reportFor([pk(p)], `Уязвимости программы: ${p.name}`)); }}><Icon name="file" size={15} />Отчёт</button>}</td>
                </tr>)} />
              {!list.items.length && !list.loading && <tr><td colSpan={8}><Empty icon="checkCircle" title="Уязвимых программ нет">По этим условиям KSC не нашёл неисправленных уязвимостей.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      <ReportDock label="Выбранные программы" count={sel.count} noun={["программа выбрана", "программы выбраны", "программ выбрано"]} canReport={canReport} onClear={sel.clear}
        onReport={() => setReport(reportFor(sel.ids, `Уязвимости выбранных программ (${sel.count})`))} />
      {panel && <VulnHostsPanel title={panel.name} lede={`${num(panel.total)} обнаружений. ${all ? "Все устройства" : `Компьютеры, подключавшиеся к KSC за ${ctx.me.activity_days} сут`}.`}
        filters={panel.product_id ? { product_id: panel.product_id, severity } : { product_name: panel.name, severity }} all={all} ctx={ctx} onClose={() => setPanel(null)}
        report={canReport ? () => setReport(reportFor([pk(panel)], `Уязвимости программы: ${panel.name}`)) : undefined} />}
      {report && <QuickReportPanel {...report} activityDays={ctx.me.activity_days} canReport={canReport} onClose={() => setReport(null)} />}
    </>
  );
}

function ChecksView({ ctx }: { ctx: Ctx }) {
  const navigate = useNavigate();
  const [checks, setChecks] = useState<SavedCheck[] | null>(null);
  const [toast, show] = useToast();
  useEffect(() => { api.checks.list().then((r) => setChecks(r.items)).catch(() => setChecks([])); }, []);
  const canEdit = ctx.me.user.role !== "viewer";
  return (
    <>
      <div className="alert info"><Icon name="info" /><div className="alert-body">Проверка версий находит компьютеры, где версия программы соответствует заданному вами условию (например, Google Chrome ниже 130). Это не подтверждённая уязвимость KSC, а ваша граница устаревших версий.</div>
        {canEdit && <Link className="btn mini primary" to="/reports"><Icon name="target" size={15} />Проверить версии программы</Link>}</div>
      <div className="table-scroll">
        {!checks ? <SkelRows rows={3} cols={4} /> : (
          <table className="table">
            <thead><tr><th>Проверка</th><th>Программы и условия</th><th>Источники</th><th>Последний запуск</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>
              {checks.map((c) => (
                <tr key={c.id}><td><b>{c.name}</b>{c.description && <span className="sub">{c.description}</span>}</td>
                  <td className="small">{c.kind === "legacy" ? "сценарий 0.1.0" : (c.params?.items ?? []).map(itemSummary).join("; ")}</td>
                  <td className="small">{c.source_names.join(", ")}</td><td className="small nowrap">{c.last_run_at ? fmt(c.last_run_at) : "—"}</td>
                  <td className="actions">{canEdit && <button className="btn mini primary" onClick={async () => { try { const j = await api.checks.run(c.id); navigate(`/reports/${j.id}`, { state: { toast: `Проверка «${c.name}» запущена` } }); } catch (e) { show((e as ApiError).message, "error"); } }}><Icon name="play" size={14} />Запустить</button>}
                    {c.last_job_id && <Link className="btn mini ghost" to={`/reports/${c.last_job_id}`}>Результат</Link>}
                    {canEdit && c.kind !== "legacy" && <Link className="btn mini ghost icon" to={`/reports?check=${c.id}`} aria-label={`Изменить проверку ${c.name}`}><Icon name="edit" size={15} /></Link>}</td></tr>))}
              {!checks.length && <tr><td colSpan={5}><Empty icon="target" title="Сохранённых проверок нет" action={canEdit ? <Link className="btn" to="/reports">Проверить версии программы</Link> : undefined}>
                Выберите программу и версию, ниже которой она считается устаревшей, затем сохраните проверку — её можно будет запускать повторно.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      {toast}
    </>
  );
}

/** Карточка уязвимостей компьютера: все действующие обнаружения с программой, версией, CVE, бюллетенями и исправлениями. */
export function VulnHostPage({ ctx }: { ctx: Ctx }) {
  const { hostId } = useParams();
  const [d, setD] = useState<Awaited<ReturnType<typeof api.vulns.host>> | null>(null);
  const [err, setErr] = useState(""); const [report, setReport] = useState(false);
  useEffect(() => { if (ctx.current && hostId) api.vulns.host(Number(hostId)).then(setD).catch((e) => setErr((e as ApiError).message)); }, [ctx.current, hostId]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const back = <BackLink to="/vulnerabilities" label="Уязвимости" />;
  if (err) return <section><PageHead title="Компьютер" back={back} /><div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div></section>;
  if (!d) return <section><PageHead title={<span className="skel skel-title" />} back={back} /><div className="card"><SkelRows rows={5} cols={5} /></div></section>;
  if (d.unsupported) return <section><PageHead title="Компьютер" back={back} /><Unsupported missing={d.unsupported} /></section>;
  const h = d.host;
  const programs = new Set(d.items.map((v) => v.product || v.app_name)).size;
  return (
    <section>
      <PageHead title={h.name} back={back} lede={<>{h.ip && <span className="mono">{h.ip}</span>} · {h.os} · {h.group} · подключение к KSC {fmt(h.last_connected)} · <HostZones sourceId={ctx.current?.id} hostId={h.host_id} /></>}>
        <Fetched at={d.fetched_at} /><Link className="btn" to={`/hosts/${h.host_id}`}><Icon name="monitor" />Карточка компьютера</Link>
        {ctx.me.user.role !== "viewer" && <button className="btn primary" onClick={() => setReport(true)}><Icon name="file" />Подробный отчёт</button>}
      </PageHead>
      {report && <QuickReportPanel kind="quick_vulns" title={`Уязвимости: ${h.name}`} lede="Все действующие уязвимости компьютера" options={{ scope: false, severity: true, patchable: true }}
        params={{ host_ids: [h.host_id] }} activityDays={ctx.me.activity_days} canReport onClose={() => setReport(false)} />}
      <div className="meters">
        <div className="meter"><span className="l">Критические</span><span className={`v ${d.counts.critical ? "bad-text" : ""}`}>{num(d.counts.critical)}</span></div>
        <div className="meter"><span className="l">Высокие</span><span className={`v ${d.counts.high ? "warn-text" : ""}`}>{num(d.counts.high)}</span></div>
        <div className="meter"><span className="l">Предупреждения</span><span className="v">{num(d.counts.warning)}</span></div>
        <div className="meter"><span className="l">Уязвимых программ</span><span className="v">{num(programs)}</span><span className="t">{num(d.items.filter((v) => v.patches_available).length)} с доступным исправлением</span></div>
      </div>
      <HostVulns items={d.items} />
    </section>
  );
}

/** Уязвимости компьютера с поиском и фильтром по опасности (страница уязвимостей компьютера и вкладка карточки). */
export function HostVulns({ items: all }: { items: HostVuln[] }) {
  const [q, setQ] = useState(""); const [severity, setSeverity] = useState<Sev>("");
  const items = useMemo(() => { const hit = maskMatcher(q); return all.filter((v) => (!severity || v.severity === severity) && (!hit || hit(v.kla_id, ...v.cve, v.product, v.app_name, ...v.kb))); }, [all, q, severity]);
  const list = useStaticList(`host-vulns:${q}:${severity}:${all.length}`, items);
  return (
    <>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="KLA, CVE, KB или программа" aria-label="Поиск уязвимости" /><MaskHint /></div>
        <Segmented<Sev> label="Уровень опасности" value={severity} onChange={setSeverity} options={SEV_OPTS} />
      </div>
      <div className="table-scroll">
        <table className="table virt">
          <thead><tr><th>Опасность</th><th>Уязвимость</th><th>Программа и версия</th><th className="hide-sm">CVE</th><th className="hide-sm">Обнаружена</th><th>Исправление</th></tr></thead>
          <tbody>
            <VirtualRows list={list} colSpan={6} estimate={56} row={(v) => (
              <tr>
                <td><span className={`sev ${v.severity === "critical" ? "crit" : v.severity === "high" ? "high" : "warn"}`}>{v.severity_label}</span></td>
                <td>{v.url ? <a href={v.url} target="_blank" rel="noopener noreferrer" className="mono">{v.kla_id}<Icon name="external" size={13} className="ext" /></a> : <span className="mono">{v.kla_id}</span>}</td>
                <td>{v.product || v.app_name}<span className="sub mono">{v.product_version || v.app_version}</span>{v.app_name && v.app_name !== v.product && <span className="sub">{v.app_name} {v.app_version}</span>}</td>
                <td className="mono small hide-sm">{v.cve.length ? v.cve.map((c) => <span key={c} className="nowrap block">{c}</span>) : <span className="muted">—</span>}</td>
                <td className="nowrap small hide-sm">{fmtDate(v.detected)}</td>
                <td>{v.patches_available ? <span className="badge ok">доступно</span> : <span className="muted small">нет</span>}{[...v.kb, ...v.mssb].length > 0 && <span className="sub mono">{[...v.kb, ...v.mssb].join(", ")}</span>}</td>
              </tr>)} />
            {!items.length && <tr><td colSpan={6}><Empty icon="checkCircle" title={all.length ? "Ничего не найдено" : "Уязвимостей нет"}>{all.length ? "Измените поиск или уровень опасности." : "KSC не нашёл на этом компьютере неисправленных уязвимостей."}</Empty></td></tr>}
          </tbody>
        </table>
      </div>
    </>
  );
}
