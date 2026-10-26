import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, type ApiError, type HostState, type ProblemKey, type ZoneDash, type ZoneHost, type ZoneHostCard, type ZoneVulnRow, type ZoneOverview, type TriageRow } from "../api";
import { NoSource, type Ctx } from "../App";
import { Charts } from "./zoneCharts";
import { OnlineBadge } from "../components/Common";
import { DataStamp, FreshnessNotes, RefreshButton } from "../components/ZoneBits";
import { Modal } from "../components/Dialogs";
import { Icon } from "../components/Icons";
import { ListFoot, VirtualRows, useInfinite, useKept, type Chunk } from "../components/Infinite";
import { CheckAll, QuickReportPanel, ReportDock, useRowSel } from "../components/QuickReport";
import { TriageBadge, TriageDialog, TriageHistory, type TriageTarget } from "../components/Triage";
import { Empty, PageHead, Segmented, SkelRows, SortTh, Tabs, MaskHint } from "../components/ui";
import { fmt, fmtDate, num, plural } from "../util";
import { DEFAULT_ZONE_CATS } from "./zoneCats";
import { PROBLEM_SHORT, PROBLEM_TONE } from "./ProtectionPage";

const STATE_TITLE: Record<HostState, string> = { critical: "Критические уязвимости", vulns: "Другие уязвимости", protection: "Только проблемы защиты", potential: "Только потенциальные", ok: "Без проблем" };
const SEV_CLASS: Record<string, string> = { critical: "crit", high: "high", warning: "warn" };
const SEV_RU: Record<string, string> = { critical: "Критическая", high: "Высокая", warning: "Предупреждение" };

export function StateBar({ state, total }: { state: Record<HostState, number>; total: number }) {
  if (!total) return <span className="muted small">нет компьютеров</span>;
  const order: HostState[] = ["critical", "vulns", "protection", "potential", "ok"];
  return <span className="state-bar" role="img" aria-label={order.map((k) => `${STATE_TITLE[k]}: ${state[k] ?? 0}`).join("; ")}>{order.filter((k) => state[k]).map((k) => <i key={k} className={`tone-${k}`} style={{ flexGrow: state[k] }} title={`${STATE_TITLE[k]}: ${state[k]}`} />)}</span>;
}

export default function ZonesPage({ ctx }: { ctx: Ctx }) {
  const { zid } = useParams();
  if (!ctx.sources.length) return <NoSource ctx={ctx} />;
  return zid ? <ZoneView ctx={ctx} zid={zid} /> : <ZonesHome ctx={ctx} />;
}

// ------------------------------------------------------------------------------------------------ список зон
function ZonesHome({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const tab = sp.get("tab") === "decisions" ? "decisions" : "zones";
  return (
    <section>
      <PageHead title="Зоны ответственности" lede="Кто отвечает за какие компьютеры и в каком они состоянии: уязвимости, защита, активность. Зоны задаёт администратор по сетям и группам KSC.">
        {ctx.me.user.is_admin && <Link className="btn" to="/admin?tab=zones"><Icon name="sliders" />Настроить зоны</Link>}
      </PageHead>
      <Tabs label="Раздел" value={tab} onChange={(v) => setSp(v === "zones" ? {} : { tab: v })} items={[{ id: "zones", label: "Зоны" }, { id: "decisions", label: "Решения по уязвимостям" }]} />
      <div className="mt-sm">{tab === "zones" ? <ZoneList ctx={ctx} /> : <Decisions ctx={ctx} />}</div>
    </section>
  );
}

function ZoneList({ ctx }: { ctx: Ctx }) {
  const navigate = useNavigate();
  const [data, setData] = useState<ZoneOverview | null>(null); const [err, setErr] = useState("");
  const [q, setQ] = useKept("zones.q", ""); const [state, setState] = useKept("zones.state", ""); const [sort, setSort] = useKept("zones.sort", "risk"); const [desc, setDesc] = useKept("zones.desc", true);
  const [force, setForce] = useState(0);
  const calc = !!data?.freshness.job && data.freshness.job.status !== "done";
  useEffect(() => { if (!calc) return; const t = window.setInterval(() => setForce((x) => x + 1), 4000); return () => window.clearInterval(t); }, [calc]);        // пока идёт расчёт, список обновляется сам
  useEffect(() => {
    let live = true; setErr("");
    const t = window.setTimeout(() => { api.zones.overview({ q, state, sort, desc }).then((r) => live && setData(r)).catch((e) => live && setErr((e as ApiError).message)); }, 200);
    return () => { live = false; window.clearTimeout(t); };
  }, [q, state, sort, desc, force]);
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(k !== "name"); } };
  return (<>
    <div className="toolbar">
      <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Зона или ответственный" aria-label="Поиск зоны" /><MaskHint /></div>
      <Segmented label="Состояние" value={state} onChange={setState} options={[["", "Все"], ["critical", "Критические"], ["vulns", "Уязвимости"], ["protection", "Защита"], ["ok", "Без проблем"]]} />
      <div className="spacer" />
      <DataStamp fr={data?.freshness} />
      {ctx.me.user.is_admin && <Link className="btn" to="/admin?tab=zcache" title="Расписание и состояние расчёта данных зон"><Icon name="clock" /><span>Расчёт данных</span></Link>}
    </div>
    <FreshnessNotes fr={data?.freshness} canRefresh={false} />
    {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
    {data && data.totals.conflicts > 0 && <div className="alert warn"><Icon name="alert" /><div className="alert-body">Компьютеров, подходящих нескольким зонам: <b>{num(data.totals.conflicts)}</b>. Они показаны в каждой зоне.{" "}
      {ctx.me.user.is_admin ? <Link to="/admin?tab=zones&view=conflicts">Разобрать пересечения</Link> : "Сообщите администратору."}</div></div>}
    {data?.notes.map((n) => <div key={n} className="alert info"><Icon name="info" /><div className="alert-body">{n}</div></div>)}
    <div className="table-scroll">
      {!data ? <SkelRows cols={8} /> : data.items.length <= 1 && !data.totals.zones ? (
        <Empty icon="grid" title="Зоны ещё не созданы" action={ctx.me.user.is_admin ? <Link className="btn primary" to="/admin?tab=zones"><Icon name="plus" />Создать зоны</Link> : undefined}>
          Зона — группа компьютеров по сетям или группам KSC с назначенными ответственными. Все компьютеры сейчас в категории «Без ответственного»: {num(data.totals.unassigned)}. Зоны можно создать вручную или загрузить из CSV.</Empty>
      ) : (
        <table className="table compact zones-table">
          <thead><tr><SortTh k="name" label="Зона" sort={sort} desc={desc} onSort={onSort} /><th className="hide-sm">Ответственные</th><SortTh k="hosts" label="Всего" sort={sort} desc={desc} onSort={onSort} className="num" /><th className="num" title={`Связывались с KSC за ${data.activity_days} сут`}>Активных</th>
            <th className="num hide-sm" title="Флаг KSC «видимо в сети» сейчас">В сети</th><SortTh k="critical" label="Критич." sort={sort} desc={desc} onSort={onSort} className="num" /><th className="num hide-sm" title="Высокие и предупреждения, без критических">Др. уязв.</th><SortTh k="protection" label="Защита" sort={sort} desc={desc} onSort={onSort} className="num" />
            <SortTh k="problems" label="Проблемных" sort={sort} desc={desc} onSort={onSort} className="num" /><th className="hide-sm">Состояние</th></tr></thead>
          <tbody>{data.items.map((z) => (
            <tr key={z.id} className="clickable" onClick={(e) => { if (!(e.target as HTMLElement).closest("a")) navigate(`/zones/${z.id}`); }}>
              <td><Link to={`/zones/${z.id}`} className="strong-link">{z.name}</Link>{!z.enabled && <span className="badge outline"> выключена</span>}{z.conflicts > 0 && <span className="zone-chip warn" title="Есть спорные компьютеры"> {z.conflicts} спорных</span>}<span className="sub">{z.description || z.purpose}</span></td>
              <td className="small hide-sm resp">{z.responsible.length ? <>{z.responsible[0].replace(/\s*\(.*\)$/, "")}{z.responsible.length > 1 ? ` +${z.responsible.length - 1}` : ""}<span className="sub" title={z.responsible.join(", ")}>{(z.responsible[0].match(/\((.*)\)$/) ?? [])[1] ?? ""}</span></> : z.id === "none" ? "—" : <span className="warn-text">не назначены</span>}</td>
              <td className="num">{num(z.stats.total)}</td><td className="num">{num(z.stats.active)}</td><td className="num hide-sm">{num(z.stats.online)}</td>
              <td className="num">{z.stats.critical ? <b className="bad-text">{num(z.stats.critical)}</b> : <span className="muted">0</span>}</td>
              <td className="num hide-sm">{num(z.stats.other_vulns)}</td><td className="num">{z.stats.protection ? <b className="warn-text">{num(z.stats.protection)}</b> : <span className="muted">0</span>}</td>
              <td className="num">{num(z.problem_hosts)}</td><td className="hide-sm"><StateBar state={z.stats.state} total={z.stats.active} /></td></tr>))}
          </tbody>
        </table>)}
    </div>
    {data && <p className="muted small mt-sm">Источники: {data.sources.join(", ") || "—"}. «Активен» — связывался с KSC за {data.activity_days} сут; «в сети» — флаг KSC «видимо в сети», это разные состояния. Категории не суммируются: компьютер может быть и с уязвимостью, и с проблемой защиты.</p>}
  </>);
}

// ------------------------------------------------------------------------------------------------ дашборд зоны
const PARAMS = ["state", "severity", "problem", "q", "online", "activity", "triage", "cve", "product", "source_id"] as const;

function ZoneView({ ctx, zid }: { ctx: Ctx; zid: string }) {
  const [sp, setSp] = useSearchParams();
  const f = Object.fromEntries(PARAMS.map((k) => [k, sp.get(k) ?? ""])) as Record<(typeof PARAMS)[number], string>;
  if (!f.activity) f.activity = "active"; if (!f.triage) f.triage = "attention";
  const [q, setQ] = useState(f.q); const [cve, setCve] = useState(f.cve); const [product, setProduct] = useState(f.product);
  const [sort, setSort] = useKept("zone.sort", "risk"); const [desc, setDesc] = useKept("zone.desc", true);
  const [ext, setExt] = useKept("zone.ext", true);
  const [open, setOpen] = useState<{ sid: string; hid: number } | null>(null);
  const [report, setReport] = useState<"all" | "sel" | null>(null);
  const [triage, setTriage] = useState<{ targets: TriageTarget[] } | null>(null);
  const sel = useRowSel<string>();
  const canReport = ctx.me.user.role !== "viewer";
  const setF = (kv: Partial<Record<(typeof PARAMS)[number], string>>) => setSp((p) => { for (const [k, v] of Object.entries(kv)) { if (v) p.set(k, v); else p.delete(k); } return p; }, { replace: true });
  useEffect(() => { const t = window.setTimeout(() => { if (q !== f.q || cve !== f.cve || product !== f.product) setF({ q, cve, product }); }, 350); return () => window.clearTimeout(t); }, [q, cve, product]); // eslint-disable-line react-hooks/exhaustive-deps
  const [forced, setForced] = useState(0);
  const [qbusy, setQbusy] = useState(false); const [qerr, setQerr] = useState("");
  const list = useInfinite<ZoneHost>(`zone:${zid}`, [zid, f, sort, desc, ext, forced], (offset, limit) =>
    api.zones.dashboard(zid, { ...f, ext, sort, desc, offset, limit }) as unknown as Promise<Chunk<ZoneHost>>, 50);
  const d = list.extra as Omit<ZoneDash, "items" | "total"> | null;
  const jobActive = !!d?.freshness.job && (d.freshness.job.status === "queued" || d.freshness.job.status === "running");
  useEffect(() => {          // пока идёт пересчёт, ход читается лёгким запросом; по завершении таблица и показатели перечитываются один раз
    if (!jobActive) return;
    let stop = false;
    const t = window.setInterval(() => { api.zones.refreshState(zid).then((r) => { if (!stop && !r.job) { setForced((x) => x + 1); } }).catch(() => undefined); }, 3000);
    return () => { stop = true; window.clearInterval(t); };
  }, [jobActive, zid]);
  const startRefresh = () => { setQbusy(true); setQerr(""); api.zones.refresh(zid).then(() => setForced((x) => x + 1)).catch((e) => setQerr((e as ApiError).message)).finally(() => setQbusy(false)); };
  const st = d?.stats;
  const zone = d?.zone;
  const canAdmin = ctx.me.user.is_admin;
  const key = (h: ZoneHost) => `${h.source_id}:${h.host_id}`;
  const filtered = !!(f.state || f.severity || f.problem || f.q || f.online || f.cve || f.product || f.source_id || f.triage !== "attention" || f.activity !== "active");
  const reset = () => { setQ(""); setCve(""); setProduct(""); setSp({}, { replace: true }); };
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(k !== "name" && k !== "ip"); } };
  const reveal = () => window.requestAnimationFrame(() => document.getElementById("zone-hosts")?.scrollIntoView({ behavior: "smooth", block: "start" }));
  const pick = (k: (typeof PARAMS)[number], v: string) => { setF({ [k]: f[k] === v ? "" : v }); if (f[k] !== v) reveal(); };
  const people = useMemo(() => (zone?.contacts ?? []).filter((c) => c.enabled), [zone]);
  if (list.error && list.initial) return <section><PageHead title="Зона ответственности" back={<Link to="/zones" className="btn ghost mini"><Icon name="arrowL" size={15} />Все зоны</Link>} /><div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div></section>;
  const reportParams = { zone_ids: [zid], categories: DEFAULT_ZONE_CATS, level: "technical", include_inactive: f.activity !== "active", hosts: report === "sel" ? sel.ids : [] };
  return (
    <section>
      <PageHead back={<Link to="/zones" className="btn ghost mini"><Icon name="arrowL" size={15} />Все зоны</Link>} title={zone?.name ?? "Зона ответственности"}
        lede={zone ? <>{zone.purpose || zone.description || "Описание не задано"}</> : undefined}>
        <DataStamp fr={d?.freshness} />
        {canReport && <RefreshButton fr={d?.freshness} onClick={startRefresh} busy={qbusy} />}
        {canReport && <button className="btn primary" onClick={() => setReport("all")} disabled={list.initial}><Icon name="file" />Отчёт по зоне</button>}
        {canAdmin && zid !== "none" && <Link className="btn" to={`/admin?tab=zones&zone=${zid}`}><Icon name="edit" />Настройки зоны</Link>}
      </PageHead>
      {zone && <div className="zone-people" aria-label="Ответственные">
        {people.length ? people.map((c) => <span key={c.email}>{c.name || c.email}{c.position ? `, ${c.position}` : ""}<span className="p-role">{c.role === "responsible" ? "" : c.role === "cc" ? "копия" : "рассылка"} {c.name ? c.email : ""}</span></span>)
          : zid === "none" ? <span className="muted">Компьютеры, не подошедшие ни одной зоне</span> : <span className="warn-text">Ответственные не назначены — рассылка этой зоне не уйдёт</span>}
      </div>}
      <FreshnessNotes fr={d?.freshness} canRefresh={canReport} onRefresh={startRefresh} busy={qbusy} zoneMode />
      {qerr && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{qerr}</div></div>}
      {d?.notes.map((n) => <div key={n} className="alert info"><Icon name="info" /><div className="alert-body">{n}</div></div>)}
      {d?.conflicts ? <div className="alert warn"><Icon name="alert" /><div className="alert-body">Спорных компьютеров в зоне: <b>{d.conflicts}</b> — они подходят и другим зонам, поэтому показаны в каждой.{canAdmin ? <> <Link to="/admin?tab=zones&view=conflicts">Разобрать</Link></> : null}</div></div> : null}

      <div className="meters dense">
        <div className="meter"><span className="l">Всего компьютеров</span><span className="v">{st ? num(st.total) : "…"}</span><span className="t">{st && st.inactive ? `без связи с KSC дольше ${d!.activity_days} сут: ${num(st.inactive)}` : "включая давно не подключавшиеся"}</span></div>
        <div className="meter"><span className="l">Активных за {d?.activity_days ?? "…"} сут</span><span className="v">{st ? num(st.active) : "…"}</span><span className="t">связывались с KSC</span></div>
        <div className="meter"><span className="l">В сети сейчас</span><span className="v">{st ? num(st.online) : "…"}</span><span className="t">{st ? `не в сети: ${num(st.offline)}${st.online_unknown ? `; нет данных: ${num(st.online_unknown)}` : ""}` : ""}</span></div>
        <button type="button" className={`meter meter-btn ${f.state === "critical" ? "on" : ""}`} aria-pressed={f.state === "critical"} onClick={() => pick("state", "critical")}><span className="l">С критическими уязвимостями</span><span className={`v ${st?.critical ? "bad-text" : ""}`}>{st ? num(st.critical) : "…"}</span><span className="t">подтверждены KSC</span></button>
        <button type="button" className={`meter meter-btn ${f.state === "vulns" ? "on" : ""}`} aria-pressed={f.state === "vulns"} onClick={() => pick("state", "vulns")}><span className="l">С другими уязвимостями</span><span className={`v ${st?.other_vulns ? "warn-text" : ""}`}>{st ? num(st.other_vulns) : "…"}</span><span className="t">высокие и предупреждения</span></button>
        <button type="button" className={`meter meter-btn ${f.state === "protection" ? "on" : ""}`} aria-pressed={f.state === "protection"} onClick={() => pick("state", "protection")}><span className="l">С проблемами защиты</span><span className={`v ${st?.protection ? "warn-text" : ""}`}>{st ? num(st.protection) : "…"}</span><span className="t">всего с проблемой защиты</span></button>
        <button type="button" className={`meter meter-btn ${f.state === "ok" ? "on" : ""}`} aria-pressed={f.state === "ok"} onClick={() => pick("state", "ok")}><span className="l">Без проблем</span><span className="v ok-text">{st ? num(st.ok) : "…"}</span><span className="t">среди активных</span></button>
      </div>
      {st && <Charts st={st} f={f} pick={pick} ext={ext} />}
      {st && ext && d?.ext_cap ? <p className="muted small mt-sm">Показатели потенциальных совпадений с внешними базами учитывают все совпадения; в списке компьютера сохранены до {d.ext_cap} самых опасных (сначала из каталога CISA KEV).</p> : null}
      {st && (st.excluded > 0 || st.accepted > 0 || st.review > 0) && <p className="muted small mt-sm">Решения специалистов: ложных и неактуальных обнаружений исключено <b>{num(st.excluded)}</b>, принятых рисков <b>{num(st.accepted)}</b> (учитываются отдельно), ждут проверки <b>{num(st.review)}</b>. Исходные сведения не удаляются.</p>}

      <div className="section-head" id="zone-hosts"><h2>Компьютеры</h2>{!list.initial && <span className="count">{num(list.total)}</span>}<div className="spacer" />
        {canReport && <button className="btn" onClick={() => setReport("all")} disabled={list.initial || !list.total}><Icon name="file" />Отчёт по этому списку</button>}</div>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Компьютер или IP-адрес" aria-label="Компьютер" /><MaskHint /></div>
        <input className="w-md" value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE или KLA" aria-label="Уязвимость" />
        <input className="w-md" value={product} onChange={(e) => setProduct(e.target.value)} placeholder="Программа" aria-label="Программа" />
        <select className="w-md" value={f.severity} onChange={(e) => setF({ severity: e.target.value })} aria-label="Критичность"><option value="">Любая критичность</option><option value="critical">Критическая</option><option value="high">Высокая</option><option value="warning">Предупреждение</option><option value="none">Без уязвимостей</option></select>
        <select className="w-md" value={f.problem} onChange={(e) => setF({ problem: e.target.value })} aria-label="Проблема защиты"><option value="">Любые проблемы защиты</option>{(st?.problems ?? []).map((p) => <option key={p.key} value={p.key}>{p.title}</option>)}</select>
        <select className="w-md" value={f.triage} onChange={(e) => setF({ triage: e.target.value === "attention" ? "" : e.target.value })} aria-label="Состояние обработки"><option value="attention">Требуют внимания</option><option value="all">Все, включая исключённые</option><option value="review">Требуют проверки</option><option value="confirmed">Подтверждённые</option><option value="false_positive">Ложные срабатывания</option><option value="obsolete">Неактуальные</option><option value="risk_accepted">Риск принят</option></select>
        <Segmented label="Связь с KSC" value={f.activity} onChange={(v) => setF({ activity: v === "active" ? "" : v })} options={[["active", "Активные"], ["all", "Все"], ["inactive", "Без связи"]]} />
        <Segmented label="В сети" value={f.online || "any"} onChange={(v) => setF({ online: v === "any" ? "" : v })} options={[["any", "Любые"], ["yes", "В сети"], ["no", "Не в сети"]]} />
        <label className="check inline-check" title="Потенциальные совпадения с NVD, БДУ ФСТЭК, OSV и CISA KEV по каталогу программ"><input type="checkbox" className="switch" checked={ext} onChange={(e) => setExt(e.target.checked)} />Внешние базы</label>
        {d && d.sources.length > 1 && <select className="w-md" value={f.source_id} onChange={(e) => setF({ source_id: e.target.value })} aria-label="Источник KSC"><option value="">Все источники</option>{d.sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select>}
        {filtered && <div className="toolbar-foot"><button type="button" className="link-btn" onClick={reset}>Сбросить все фильтры</button></div>}
      </div>
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={8} /> : (
          <table className="table virt">
            <thead><tr><CheckAll all={sel.allOf(list.items.map(key))} some={sel.someOf(list.items.map(key))} onToggle={() => sel.toggleMany(list.items.map(key))} />
              <SortTh k="name" label="Компьютер" sort={sort} desc={desc} onSort={onSort} /><SortTh k="ip" label="IP" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /><th className="hide-sm">ОС</th>
              <SortTh k="last_connected" label="Последняя активность" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /><th>В сети</th><SortTh k="risk" label="Критичность" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="vulns" label="Уязвимости" sort={sort} desc={desc} onSort={onSort} /><th>Защита</th></tr></thead>
            <tbody>
              <VirtualRows list={list} colSpan={9} estimate={48} row={(h) => (
                <tr className={`clickable ${sel.has(key(h)) ? "sel" : ""} ${h.active ? "" : "dim-row"}`} onClick={(e) => { if (!(e.target as HTMLElement).closest("a, input, button")) setOpen({ sid: h.source_id, hid: h.host_id }); }}>
                  <td className="check"><input type="checkbox" aria-label={`Выбрать ${h.name}`} checked={sel.has(key(h))} onChange={() => sel.toggle(key(h))} /></td>
                  <td><button type="button" className="link-btn strong-link" onClick={() => setOpen({ sid: h.source_id, hid: h.host_id })}>{h.name}</button>
                    {h.zone_conflict && <span className="zone-chip warn" title="Подходит нескольким зонам"> спорный</span>}{d && d.sources.length > 1 && <span className="sub">{h.source}</span>}</td>
                  <td className="mono small nowrap hide-sm">{h.ip || "—"}</td><td className="small hide-sm os-cell" title={h.os}>{h.os.replace(/^Microsoft /, "")}</td>
                  <td className="nowrap small hide-sm">{fmt(h.last_connected)}{!h.active && <span className="sub warn-text">нет связи за {d?.activity_days} сут</span>}</td>
                  <td><OnlineBadge online={h.online} /></td>
                  <td>{h.max_sev ? <span className={`sev ${SEV_CLASS[h.max_sev]}`}>{h.max_sev_ru}{h.max_sev_basis === "ext" ? <span className="mark" title="Потенциально, по внешним базам"> *</span> : null}</span> : <span className="muted">—</span>}</td>
                  <td className="nowrap small">{h.ksc.total ? <><span className="sev-row"><span className={`sev crit ${h.ksc.critical ? "" : "zero"}`} title="Критические"><b>{h.ksc.critical}</b></span><span className={`sev high ${h.ksc.high ? "" : "zero"}`} title="Высокие"><b>{h.ksc.high}</b></span><span className={`sev warn ${h.ksc.warning ? "" : "zero"}`} title="Предупреждения"><b>{h.ksc.warning}</b></span></span></> : <span className="muted">нет</span>}
                    {h.ext.total > 0 && <span className="sub" title="Потенциальные совпадения по внешним базам — не подтверждены KSC">потенц.: {h.ext.total}{h.ext.kev ? `, KEV ${h.ext.kev}` : ""}</span>}
                    {(h.ksc.accepted + h.ksc.excluded + h.ext.accepted + h.ext.excluded) > 0 && <span className="sub">обработано: {h.ksc.excluded + h.ext.excluded} искл., {h.ksc.accepted + h.ext.accepted} риск</span>}</td>
                  <td>{h.problems.length ? <span className="badges">{h.problems.slice(0, 3).map((p) => <span key={p.key} className={`badge ${PROBLEM_TONE[p.key as ProblemKey]}`}>{PROBLEM_SHORT[p.key as ProblemKey]}</span>)}{h.problems.length > 3 && <span className="badge outline">+{h.problems.length - 3}</span>}</span> : <span className="badge ok">в порядке</span>}</td>
                </tr>)} />
              {!list.items.length && !list.loading && <tr><td colSpan={9}><Empty icon="checkCircle" title={filtered ? "Ничего не найдено" : "Компьютеров нет"}>{filtered ? "По выбранным условиям компьютеров нет. Сбросьте фильтры или выберите другой сегмент диаграммы." : zid === "none" ? "Все компьютеры отнесены к зонам." : "Ни один компьютер не подошёл признакам зоны или активных за период нет. Проверьте сети в настройках зоны."}</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      <ReportDock label="Выбранные компьютеры" count={sel.count} noun={["компьютер выбран", "компьютера выбрано", "компьютеров выбрано"]} canReport={canReport} onClear={sel.clear} onReport={() => setReport("sel")} />
      {report && <QuickReportPanel kind="quick_zone" title={report === "sel" ? `Отчёт по выбранным компьютерам (${sel.count})` : `Отчёт: ${zone?.name ?? "зона"}`} lede="Тот же отчёт, что уходит по рассылке: сводка, список проблемных компьютеров, затем подробности" options={{ zone: true }}
        activityDays={d?.activity_days ?? ctx.me.activity_days} canReport={canReport} params={reportParams} onClose={() => setReport(null)} />}
      {open && <HostDrawer ctx={ctx} zid={zid} sid={open.sid} hid={open.hid} onClose={() => setOpen(null)} onTriage={(targets) => setTriage({ targets })} refreshKey={forced} />}
      {triage && <TriageDialog targets={triage.targets} onClose={() => setTriage(null)} onDone={() => { setTriage(null); setForced((x) => x + 1); }} />}
      <p className="muted small mt-sm">Критичность со звёздочкой (*) — потенциальная, по внешним базам; она не подтверждена KSC. Исключённые и принятые обнаружения не входят в показатели и отчёты по умолчанию.</p>
    </section>
  );
}

// ------------------------------------------------------------------------------------------------ карточка компьютера
function HostDrawer({ ctx, zid, sid, hid, onClose, onTriage, refreshKey }: { ctx: Ctx; zid: string; sid: string; hid: number; onClose: () => void; onTriage: (t: TriageTarget[]) => void; refreshKey: number }) {
  const [h, setH] = useState<ZoneHostCard | null>(null); const [err, setErr] = useState("");
  const [tab, setTab] = useState<"ksc" | "ext" | "done">("ksc");
  const [hist, setHist] = useState<string | null>(null);
  const [pick, setPick] = useState<string[]>([]);
  const canSet = ctx.me.user.role !== "viewer";
  useEffect(() => { setH(null); api.zones.host(zid, sid, hid).then(setH).catch((e) => setErr((e as ApiError).message)); }, [zid, sid, hid, refreshKey]);
  const zoneId = h?.zones_info[0]?.id; const zoneName = h?.zones_info[0]?.name;
  const target = (r: ZoneVulnRow, origin: "ksc" | "ext"): TriageTarget => ({ source_id: sid, host_id: hid, host_name: h?.name ?? "", vuln_key: (origin === "ksc" ? r.kla_id : r.vuln_key) ?? "", origin, product: r.product ?? "", version: r.installed_version, zone_id: zoneId, zone_name: zoneName });
  const rows = (o: "ksc" | "ext") => h?.rows[o].current ?? [];
  const done = h ? [...h.rows.ksc.accepted.map((r) => ({ r, o: "ksc" as const })), ...h.rows.ksc.excluded.map((r) => ({ r, o: "ksc" as const })), ...h.rows.ext.accepted.map((r) => ({ r, o: "ext" as const })), ...h.rows.ext.excluded.map((r) => ({ r, o: "ext" as const }))] : [];
  const list = tab === "done" ? [] : rows(tab);
  const rk = (r: ZoneVulnRow, o: string) => `${o}:${(o === "ksc" ? r.kla_id : r.vuln_key) ?? ""}:${r.product ?? ""}:${r.installed_version}`;
  const link = (r: ZoneVulnRow, o: "ksc" | "ext") => {
    const key = o === "ext" ? r.vuln_key : (r.cve_list?.[0] ?? (r.cve ? r.cve.split(", ")[0] : ""));
    return key ? <Link to={`/vdb?v=${encodeURIComponent(key)}`} className="mono strong-link" title="Открыть описание и источники сведений">{o === "ext" ? r.vuln_key : r.kla_id}</Link> : <span className="mono">{r.kla_id}</span>;
  };
  const table = (items: ZoneVulnRow[], o: "ksc" | "ext") => (
    <div className="table-scroll"><table className="table compact">
      <thead><tr>{canSet && <th className="check" />}<th>Опасность</th><th>Уязвимость</th><th>Программа и версия</th>{o === "ext" ? <th>Результат сопоставления</th> : <th>Исправление</th>}<th>Обработка</th>{canSet && <th />}</tr></thead>
      <tbody>{items.map((r) => { const k = rk(r, o); return (
        <tr key={k}>{canSet && <td className="check"><input type="checkbox" aria-label="Выбрать" checked={pick.includes(k)} onChange={() => setPick(pick.includes(k) ? pick.filter((x) => x !== k) : [...pick, k])} /></td>}
          <td><span className={`sev ${SEV_CLASS[r.severity]}`}>{SEV_RU[r.severity]}</span>{r.kev && <span className="badge err" title="Эксплуатация подтверждена CISA KEV"> KEV</span>}</td>
          <td>{link(r, o)}<span className="sub small">{o === "ext" ? r.title : r.cve}</span></td>
          <td className="small">{r.product || "—"}<span className="sub mono">{r.installed_version}</span></td>
          <td className="small">{o === "ext" ? <>{r.status_ru}<span className="sub" title={r.basis}>{r.basis}</span></> : r.fix}</td>
          <td><TriageBadge d={r.triage} />{r.triage && <button type="button" className="link-btn small" onClick={() => setHist(r.triage!.id)}> история</button>}</td>
          {canSet && <td className="nowrap"><span className="vrow-actions"><button type="button" className="btn mini" onClick={() => onTriage([target(r, o)])}>Отметить…</button></span></td>}</tr>); })}</tbody>
    </table></div>);
  const picked = [...rows("ksc").map((r) => ({ r, o: "ksc" as const })), ...rows("ext").map((r) => ({ r, o: "ext" as const }))].filter(({ r, o }) => pick.includes(rk(r, o)));
  return (
    <Modal side wide title={h?.name ?? "Компьютер"} onClose={onClose} guard={false}
      lede={h ? <span className="row tight" style={{ flexWrap: "wrap" }}><span className="mono">{h.ip}</span><span>{h.os}</span><OnlineBadge online={h.online} /></span> : undefined}
      footer={h && canSet && picked.length > 0 ? <><span className="muted small">Выбрано: {picked.length}</span><button className="btn primary" onClick={() => onTriage(picked.map(({ r, o }) => target(r, o)))}>Отметить выбранные…</button></> : undefined}>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!h && !err && <SkelRows rows={6} cols={4} />}
      {h && (<>
        <div className="host-card-head">
          {h.zones_info.length ? h.zones_info.map((z) => <span key={z.id} className="zone-chip">{z.name}{z.contacts.length ? ` · ${z.contacts.map((c) => c.name || c.email).slice(0, 2).join(", ")}` : ""}</span>) : <span className="zone-chip warn">Без ответственного</span>}
          {h.zone_conflict && <span className="zone-chip warn" title={h.candidates.map((c) => c.name).join(", ")}>подходит зонам: {h.candidates.map((c) => c.name).join(", ")}</span>}
          <span className="muted small">Подключение к KSC: {fmt(h.last_connected)} · группа KSC: {h.group || "—"} · источник: {h.source}</span>
        </div>
        <p className="small">{h.summary}.</p>
        {h.protection.length > 0 && <div className="card flush"><div className="card-head"><h3>Проблемы защиты</h3></div><ul className="rows">{h.protection.map((p) => <li key={p.key}><div className="r-main"><b>{p.title}</b><span className="muted small"> — {p.detail}</span></div></li>)}</ul></div>}
        <p className="muted small">Защитный продукт: {h.av.product ? `${h.av.product} ${h.av.build ?? ""}, ${h.av.state ?? ""}` : "не найден"}; базы: {fmtDate(h.av.bases)}; полная проверка: {fmtDate(h.av.last_full_scan)}; статус KSC: {h.av.ksc_status ?? "—"}.
          {" "}<Link to={`/vulnerabilities/hosts/${h.host_id}`}>Страница компьютера в разделе «Уязвимости»</Link></p>
        <Tabs label="Обнаружения" value={tab} onChange={setTab} items={[{ id: "ksc", label: "Подтверждены KSC", count: h.rows.ksc.current.length }, { id: "ext", label: "Потенциальные (внешние базы)", count: h.rows.ext.current.length }, { id: "done", label: "Обработанные", count: done.length }]} />
        <div className="mt-sm">
          {tab !== "done" && (list.length ? table(list, tab) : <Empty icon="checkCircle" title="Нет обнаружений">{tab === "ksc" ? "KSC не сообщает о действующих уязвимостях на этом компьютере (с учётом решений специалистов)." : "Совпадений с внешними базами не найдено или внешние базы не включены в фильтр."}</Empty>)}
          {tab === "ext" && list.length > 0 && <p className="muted small mt-sm">Это предположения по каталогу установленного ПО и внешним базам; KSC их не подтверждает. Основание — в столбце «Результат сопоставления».</p>}
          {tab === "done" && (done.length ? <div className="table-scroll"><table className="table compact"><thead><tr><th>Опасность</th><th>Уязвимость</th><th>Программа</th><th>Решение</th><th>Основание</th><th>Кто и когда</th></tr></thead>
            <tbody>{done.map(({ r, o }, i) => <tr key={i}><td><span className={`sev ${SEV_CLASS[r.severity]}`}>{SEV_RU[r.severity]}</span></td><td>{link(r, o)}<span className="sub">{o === "ext" ? "внешние базы" : "KSC"}</span></td><td className="small">{r.product}<span className="sub mono">{r.installed_version}</span></td>
              <td><TriageBadge d={r.triage} /><span className="sub">{r.triage?.scope_ru}</span></td><td className="small">{r.triage?.reason_ru}<span className="sub">{r.triage?.comment}</span></td><td className="small nowrap">{r.triage?.by}<span className="sub">{fmt(r.triage?.at)}</span>
                {canSet && <button type="button" className="link-btn small" onClick={() => onTriage([target(r, o)])}> изменить</button>} <button type="button" className="link-btn small" onClick={() => r.triage && setHist(r.triage.id)}>история</button></td></tr>)}</tbody></table></div>
            : <Empty icon="info" title="Решений по этому компьютеру нет">Ложные срабатывания, неактуальные уязвимости и принятые риски появятся здесь.</Empty>)}
        </div>
      </>)}
      {hist && <TriageHistory id={hist} onClose={() => setHist(null)} />}
    </Modal>
  );
}

// ------------------------------------------------------------------------------------------------ реестр решений
function Decisions({ ctx }: { ctx: Ctx }) {
  const src = ctx.current?.id;
  const [status, setStatus] = useState(""); const [q, setQ] = useState("");
  const [data, setData] = useState<{ items: TriageRow[]; total: number; counts: Record<string, number> } | null>(null); const [err, setErr] = useState("");
  const [hist, setHist] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!src) return; let live = true; setErr("");
    const t = window.setTimeout(() => { api.triage.list({ source_id: src, status, q, limit: 100 }).then((r) => live && setData(r)).catch((e) => live && setErr((e as ApiError).message)); }, 200);
    return () => { live = false; window.clearTimeout(t); };
  }, [src, status, q, tick]);
  if (!src) return <NoSource ctx={ctx} />;
  const c = data?.counts ?? {};
  const revert = async (r: TriageRow) => { try { await api.triage.set({ source_id: r.source_id, vuln_key: r.vuln_key, origin: r.origin, scope: r.scope, host_id: r.host_id ?? undefined, host_name: r.host_name, zone_id: r.zone_id ?? undefined, product: r.product, version: r.version, status: "review", comment: "Возвращено на проверку" }); setTick(tick + 1); } catch (e) { setErr((e as ApiError).message); } };
  return (<>
    <div className="toolbar">
      <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Уязвимость, компьютер, программа, комментарий" aria-label="Поиск решений" /><MaskHint /></div>
      <Segmented label="Статус" value={status} onChange={setStatus} options={[["", "Все"], ["false_positive", `Ложные ${c.false_positive ?? 0}`], ["obsolete", `Неактуальные ${c.obsolete ?? 0}`], ["risk_accepted", `Риск принят ${c.risk_accepted ?? 0}`], ["confirmed", `Подтверждённые ${c.confirmed ?? 0}`], ["recheck", "На повторной проверке"], ["expiring", "Скоро истекают"]]} />
    </div>
    {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
    <div className="table-scroll">{!data ? <SkelRows cols={6} /> : !data.items.length ? <Empty icon="checkCircle" title="Решений нет">Откройте компьютер в зоне и отметьте обнаружение: ложное срабатывание, неактуальную уязвимость или принятый риск. Все решения хранятся с автором, датой и основанием.</Empty> : (
      <table className="table compact"><thead><tr><th>Уязвимость</th><th>Область</th><th>Статус</th><th>Основание</th><th>Кто и когда</th><th>Пересмотр</th><th /></tr></thead>
        <tbody>{data.items.map((r) => (
          <tr key={r.id}><td className="mono nowrap">{r.vuln_key}<span className="sub">{r.origin === "ext" ? "внешние базы" : "KSC"}</span></td>
            <td className="small">{r.scope === "host" ? <>{r.host_name || `#${r.host_id}`}<span className="sub">{r.product} {r.version}</span></> : r.scope === "product" ? <>Программа: {r.product} {r.version}<span className="sub">все компьютеры источника</span></> : <>Вся зона<span className="sub">{r.zone_id}</span></>}</td>
            <td><span className={`tri ${r.status === "false_positive" ? "fp" : r.status === "risk_accepted" ? "risk" : r.status === "confirmed" ? "confirmed" : r.status === "obsolete" ? "obsolete" : "review"}`}>{r.status_ru}</span>{r.recheck && <span className="sub warn-text">{r.recheck_reason}</span>}</td>
            <td className="small">{r.reason_ru}<span className="sub">{r.comment}</span></td><td className="small nowrap">{r.created_by}<span className="sub">{fmt(r.updated_at)}</span></td>
            <td className="small nowrap">{r.review_until ? fmtDate(r.review_until) : "—"}</td>
            <td className="nowrap"><button type="button" className="link-btn small" onClick={() => setHist(r.id)}>история</button>{ctx.me.user.role !== "viewer" && r.stored_status !== "review" && <> · <button type="button" className="link-btn small" onClick={() => revert(r)}>вернуть на проверку</button></>}</td></tr>))}</tbody></table>)}</div>
    {data && <p className="muted small mt-sm">{num(data.total)} {plural(data.total, "решение", "решения", "решений")}. Решения сохраняются при обновлении баз уязвимостей, повторной синхронизации KSC и обновлении KAV Checker. Если установленная версия или идентификатор устройства изменились, запись возвращается на проверку.</p>}
    {hist && <TriageHistory id={hist} onClose={() => setHist(null)} />}
  </>);
}
