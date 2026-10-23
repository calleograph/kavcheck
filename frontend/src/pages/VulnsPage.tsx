import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, type ApiError, type HostVuln, type SavedCheck, type VulnHost, type VulnProduct, type VulnSummary } from "../api";
import { NoSource, type Ctx } from "../App";
import { Fetched, Pager } from "../components/Common";
import { Icon } from "../components/Icons";
import { useToast } from "../components/Toast";
import { Empty, HiddenNote, PageHead, Segmented, SevCounts, SkelRows, SortTh, Tabs } from "../components/ui";
import { fmt, fmtDate, num } from "../util";
import { itemSummary } from "./AuditBuilder";

type Tab = "hosts" | "products" | "checks";
type Sev = "" | "critical" | "high" | "warning";
const SEV_OPTS: [Sev, string][] = [["", "Все"], ["critical", "Критические"], ["high", "Высокие"], ["warning", "Предупреждения"]];

/** Раздел «Уязвимости»: сначала самые проблемные компьютеры и программы (данные KSC), отдельно — проверки версий (условия пользователей). */
export default function VulnsPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const tab = (["hosts", "products", "checks"].includes(sp.get("tab") ?? "") ? sp.get("tab") : "hosts") as Tab;
  if (!ctx.current) return <NoSource ctx={ctx} />;
  return (
    <section>
      <PageHead title="Уязвимости" lede="Уязвимости программ, найденные Kaspersky Security Center: какие компьютеры и программы требуют внимания в первую очередь. Проверки версий — ваши собственные условия — показаны отдельно." />
      <Tabs label="Вид" value={tab} onChange={(t) => setSp((p) => { p.set("tab", t); return p; })}
        items={[{ id: "hosts", label: "Компьютеры" }, { id: "products", label: "Уязвимые программы" }, { id: "checks", label: "Проверки версий" }]} />
      {tab === "hosts" ? <HostsView ctx={ctx} /> : tab === "products" ? <ProductsView ctx={ctx} /> : <ChecksView ctx={ctx} />}
    </section>
  );
}

function Unsupported({ missing }: { missing: string[] }) {
  return <div className="alert warn"><Icon name="alert" /><div className="alert-body">В базе источника нет объектов уязвимостей KSC ({missing.join(", ")}). Раздел недоступен для этого источника.</div></div>;
}

function HostsView({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const navigate = useNavigate();
  const productId = sp.get("product_id"); const productName = sp.get("product_name"); const productTitle = sp.get("product_title");
  const [q, setQ] = useState(""); const [group, setGroup] = useState(""); const [product, setProduct] = useState(""); const [cve, setCve] = useState("");
  const [applied, setApplied] = useState({ q: "", group: "", product: "", cve: "" });
  const [severity, setSeverity] = useState<Sev>(""); const [patchable, setPatchable] = useState(false);
  const [all, setAll] = useState(false);
  const [sort, setSort] = useState("risk"); const [desc, setDesc] = useState(true);
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ items: VulnHost[]; total: number; summary: VulnSummary | null; unsupported?: string[] } | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false); const [refresh, setRefresh] = useState(0);
  useEffect(() => { const t = window.setTimeout(() => { setApplied({ q, group, product, cve }); setOffset(0); }, 350); return () => window.clearTimeout(t); }, [q, group, product, cve]);
  useEffect(() => {
    setBusy(true);
    api.vulns.hosts({ ...applied, product_id: productId, product_name: productName, severity, patchable, all_hosts: all, sort, desc, offset, limit: 50, refresh: refresh > 0 ? true : undefined })
      .then((r) => { setData(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [applied, productId, productName, severity, patchable, all, sort, desc, offset, refresh]);
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(k !== "name"); } setOffset(0); };
  const s = data?.summary;
  if (data?.unsupported) return <Unsupported missing={data.unsupported} />;
  return (
    <>
      <div className="meters">
        <div className="meter"><span className="l">Компьютеров с уязвимостями</span><span className="v">{s ? num(s.hosts) : "…"}</span><span className="t">{all ? "все устройства" : `активные за ${ctx.me.activity_days} сут`}</span></div>
        <div className="meter"><span className="l">С критическими</span><span className={`v ${s?.critical_hosts ? "bad-text" : ""}`}>{s ? num(s.critical_hosts) : "…"}</span><span className="t">{s ? `${num(s.critical)} уязвимостей` : ""}</span></div>
        <div className="meter"><span className="l">С высокими</span><span className={`v ${s?.high_hosts ? "warn-text" : ""}`}>{s ? num(s.high_hosts) : "…"}</span><span className="t">{s ? `${num(s.high)} уязвимостей` : ""}</span></div>
        <div className="meter"><span className="l">Можно исправить сейчас</span><span className="v">{s ? num(s.patchable) : "…"}</span><span className="t">{s ? `из ${num(s.total)} обнаружений` : ""}</span></div>
      </div>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Компьютер или IP-адрес" aria-label="Компьютер" /></div>
        <input className="w-md" value={product} onChange={(e) => setProduct(e.target.value)} placeholder="Программа" aria-label="Программа" />
        <input className="w-md mono-ph" value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2024-…" aria-label="CVE" />
        <input className="w-md" value={group} onChange={(e) => setGroup(e.target.value)} placeholder="Группа" aria-label="Группа администрирования" />
        <Segmented<Sev> label="Уровень опасности" value={severity} onChange={(v) => { setSeverity(v); setOffset(0); }} options={SEV_OPTS} />
        <label className="check inline-check"><input type="checkbox" className="switch" checked={patchable} onChange={(e) => { setPatchable(e.target.checked); setOffset(0); }} />Есть исправление</label>
        <div className="toolbar-foot">
          {(productId || productName) && <span className="chip">Программа: <b>{productTitle ?? productName ?? productId}</b><button type="button" className="link-btn" onClick={() => setSp((p) => { p.delete("product_id"); p.delete("product_name"); p.delete("product_title"); return p; })}>сбросить</button></span>}
          {s && <Fetched at={s.fetched_at} />}<button type="button" className="link-btn" onClick={() => setRefresh((x) => x + 1)} disabled={busy}>Обновить</button>
        </div>
      </div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="table-scroll">
        {!data && busy ? <SkelRows cols={6} /> : (
          <table className="table">
            <thead><tr><SortTh k="name" label="Компьютер" sort={sort} desc={desc} onSort={onSort} /><th className="hide-sm">ОС</th><th className="hide-sm">Группа</th><SortTh k="last_connected" label="Подключение к KSC" sort={sort} desc={desc} onSort={onSort} className="hide-sm" />
              <SortTh k="risk" label="Уязвимости" sort={sort} desc={desc} onSort={onSort} /><SortTh k="total" label="Всего" sort={sort} desc={desc} onSort={onSort} className="num" /><SortTh k="patchable" label="С исправлением" sort={sort} desc={desc} onSort={onSort} className="num hide-sm" /></tr></thead>
            <tbody style={{ opacity: busy ? .55 : 1 }}>
              {(data?.items ?? []).map((h) => (
                <tr key={h.host_id} className="clickable" onClick={(e) => { if (!(e.target as HTMLElement).closest("a")) navigate(`/vulnerabilities/hosts/${h.host_id}`); }}>
                  <td><Link to={`/vulnerabilities/hosts/${h.host_id}`} className="strong-link">{h.name}</Link><span className="sub mono">{h.ip}</span></td>
                  <td className="small hide-sm">{h.os}</td><td className="small hide-sm">{h.group}</td><td className="nowrap small hide-sm">{fmt(h.last_connected)}</td>
                  <td><SevCounts critical={h.critical} high={h.high} warning={h.warning} compact /></td>
                  <td className="num"><b>{num(h.total)}</b><span className="sub">{num(h.products)} прогр.</span></td><td className="num hide-sm">{num(h.patchable)}</td>
                </tr>))}
              {data && !data.items.length && <tr><td colSpan={7}><Empty icon="checkCircle" title="Компьютеров с уязвимостями нет">{applied.q || applied.product || applied.cve || applied.group || severity || patchable ? "По этим условиям ничего не найдено." : "KSC не нашёл неисправленных уязвимостей на учтённых компьютерах."}</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      {data && <Pager total={data.total} offset={offset} limit={50} onPage={setOffset} />}
      {s && <HiddenNote hidden={s.hidden_hosts} days={s.activity_days} all={all} onToggle={() => { setAll(!all); setOffset(0); }} />}
      <p className="muted small mt-sm">Действующие обнаружения: не исправлены и не игнорируются. KSC оценивает только программы из своего справочника; пакеты Linux и, например, PHP он не проверяет — для них используйте проверку версий.</p>
    </>
  );
}

function ProductsView({ ctx }: { ctx: Ctx }) {
  const [, setSp] = useSearchParams();
  const [q, setQ] = useState(""); const [cve, setCve] = useState(""); const [applied, setApplied] = useState({ q: "", cve: "" });
  const [severity, setSeverity] = useState<Sev>(""); const [all, setAll] = useState(false);
  const [sort, setSort] = useState("risk"); const [desc, setDesc] = useState(true); const [offset, setOffset] = useState(0);
  const [data, setData] = useState<Awaited<ReturnType<typeof api.vulns.products>> | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { const t = window.setTimeout(() => { setApplied({ q, cve }); setOffset(0); }, 350); return () => window.clearTimeout(t); }, [q, cve]);
  useEffect(() => { setBusy(true); api.vulns.products({ ...applied, severity, all_hosts: all, sort, desc, offset, limit: 50 }).then((r) => { setData(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false)); }, [applied, severity, all, sort, desc, offset]);
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(k !== "name"); } setOffset(0); };
  const open = (p: VulnProduct) => setSp((x) => { x.set("tab", "hosts"); if (p.product_id) x.set("product_id", String(p.product_id)); else x.set("product_name", p.name); x.set("product_title", p.name); return x; });
  if (data?.unsupported) return <Unsupported missing={data.unsupported} />;
  return (
    <>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Программа, например Google Chrome" aria-label="Программа" /></div>
        <input className="w-md" value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2024-…" aria-label="CVE" />
        <Segmented<Sev> label="Уровень опасности" value={severity} onChange={(v) => { setSeverity(v); setOffset(0); }} options={SEV_OPTS} />
        <label className="check inline-check"><input type="checkbox" className="switch" checked={all} onChange={(e) => { setAll(e.target.checked); setOffset(0); }} />Все устройства</label>
        <div className="toolbar-foot">{data?.fetched_at && <Fetched at={data.fetched_at} />}<span className="muted small">{all ? "Учтены все устройства." : `Учтены компьютеры, активные за ${ctx.me.activity_days} сут.`}</span></div>
      </div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="table-scroll">
        {!data && busy ? <SkelRows cols={5} /> : (
          <table className="table">
            <thead><tr><SortTh k="name" label="Программа" sort={sort} desc={desc} onSort={onSort} /><SortTh k="hosts" label="Компьютеров" sort={sort} desc={desc} onSort={onSort} className="num" />
              <SortTh k="risk" label="Уровни опасности" sort={sort} desc={desc} onSort={onSort} /><th className="num">Уязвимостей</th><SortTh k="total" label="Обнаружений" sort={sort} desc={desc} onSort={onSort} className="num" /><th className="num">С исправлением</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody style={{ opacity: busy ? .55 : 1 }}>
              {(data?.items ?? []).map((p) => (
                <tr key={`${p.product_id}-${p.name}`} className="clickable" onClick={() => open(p)}>
                  <td><button type="button" className="link-btn strong-link" onClick={() => open(p)}>{p.name}</button></td><td className="num"><b>{num(p.hosts)}</b></td>
                  <td><SevCounts critical={p.critical} high={p.high} warning={p.warning} compact /></td><td className="num">{num(p.vulns)}</td><td className="num">{num(p.total)}</td><td className="num">{num(p.patchable)}</td>
                  <td className="actions"><button type="button" className="btn mini" onClick={(e) => { e.stopPropagation(); open(p); }}><Icon name="monitor" size={15} />Компьютеры</button></td>
                </tr>))}
              {data && !data.items.length && <tr><td colSpan={7}><Empty icon="checkCircle" title="Уязвимых программ нет">По этим условиям KSC не нашёл неисправленных уязвимостей.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      {data && <Pager total={data.total} offset={offset} limit={50} onPage={setOffset} />}
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
                  <td className="actions">{canEdit && <button className="btn mini primary" onClick={async () => { try { const j = await api.checks.run(c.id); navigate(`/reports/${j.id}`); } catch (e) { show((e as ApiError).message, "error"); } }}><Icon name="play" size={14} />Запустить</button>}
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
  const [err, setErr] = useState("");
  const [q, setQ] = useState(""); const [severity, setSeverity] = useState<Sev>("");
  useEffect(() => { if (ctx.current && hostId) api.vulns.host(Number(hostId)).then(setD).catch((e) => setErr((e as ApiError).message)); }, [ctx.current, hostId]);
  const items = useMemo(() => (d?.items ?? []).filter((v: HostVuln) => (!severity || v.severity === severity) && (!q || `${v.kla_id} ${v.cve.join(" ")} ${v.product} ${v.app_name} ${v.kb.join(" ")}`.toLowerCase().includes(q.toLowerCase()))), [d, q, severity]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const back = <Link className="back-link" to="/vulnerabilities"><Icon name="arrowL" size={15} />Уязвимости</Link>;
  if (err) return <section><PageHead title="Компьютер" back={back} /><div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div></section>;
  if (!d) return <section><PageHead title={<span className="skel" style={{ width: 240, height: 28 }} />} back={back} /><div className="card"><SkelRows rows={5} cols={5} /></div></section>;
  if (d.unsupported) return <section><PageHead title="Компьютер" back={back} /><Unsupported missing={d.unsupported} /></section>;
  const h = d.host;
  const programs = new Set(d.items.map((v) => v.product || v.app_name)).size;
  return (
    <section>
      <PageHead title={h.name} back={back} lede={<>{h.ip && <span className="mono">{h.ip}</span>} · {h.os} · {h.group} · подключение к KSC {fmt(h.last_connected)}</>}>
        <Fetched at={d.fetched_at} /><Link className="btn" to={`/hosts/${h.host_id}`}><Icon name="monitor" />Карточка компьютера</Link>
      </PageHead>
      <div className="meters">
        <div className="meter"><span className="l">Критические</span><span className={`v ${d.counts.critical ? "bad-text" : ""}`}>{num(d.counts.critical)}</span></div>
        <div className="meter"><span className="l">Высокие</span><span className={`v ${d.counts.high ? "warn-text" : ""}`}>{num(d.counts.high)}</span></div>
        <div className="meter"><span className="l">Предупреждения</span><span className="v">{num(d.counts.warning)}</span></div>
        <div className="meter"><span className="l">Уязвимых программ</span><span className="v">{num(programs)}</span><span className="t">{num(d.items.filter((v) => v.patches_available).length)} с доступным исправлением</span></div>
      </div>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="KLA, CVE, KB или программа" aria-label="Поиск уязвимости" /></div>
        <Segmented<Sev> label="Уровень опасности" value={severity} onChange={setSeverity} options={SEV_OPTS} />
      </div>
      <div className="table-scroll">
        <table className="table">
          <thead><tr><th>Опасность</th><th>Уязвимость</th><th>Программа и версия</th><th className="hide-sm">CVE</th><th className="hide-sm">Обнаружена</th><th>Исправление</th></tr></thead>
          <tbody>
            {items.map((v) => (
              <tr key={v.occurrence_id}>
                <td><span className={`sev ${v.severity === "critical" ? "crit" : v.severity === "high" ? "high" : "warn"}`}>{v.severity_label}</span></td>
                <td>{v.url ? <a href={v.url} target="_blank" rel="noopener noreferrer" className="mono">{v.kla_id}<Icon name="external" size={13} className="ext" /></a> : <span className="mono">{v.kla_id}</span>}</td>
                <td>{v.product || v.app_name}<span className="sub mono">{v.product_version || v.app_version}</span>{v.app_name && v.app_name !== v.product && <span className="sub">{v.app_name} {v.app_version}</span>}</td>
                <td className="mono small hide-sm">{v.cve.length ? v.cve.map((c) => <span key={c} className="nowrap block">{c}</span>) : <span className="muted">—</span>}</td>
                <td className="nowrap small hide-sm">{fmtDate(v.detected)}</td>
                <td>{v.patches_available ? <span className="badge ok">доступно</span> : <span className="muted small">нет</span>}{[...v.kb, ...v.mssb].length > 0 && <span className="sub mono">{[...v.kb, ...v.mssb].join(", ")}</span>}</td>
              </tr>))}
            {!items.length && <tr><td colSpan={6}><Empty icon="checkCircle" title={d.items.length ? "Ничего не найдено" : "Уязвимостей нет"}>{d.items.length ? "Измените поиск или уровень опасности." : "KSC не нашёл на этом компьютере неисправленных уязвимостей."}</Empty></td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  );
}
