import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type ApiError, type ProblemKey, type ProtHost, type ProtSummary } from "../api";
import { NoSource, type Ctx } from "../App";
import { Fetched, Pager } from "../components/Common";
import { Icon } from "../components/Icons";
import { Empty, HiddenNote, PageHead, Segmented, SkelRows, SortTh, Spectrum } from "../components/ui";
import { fmt, fmtDate, num } from "../util";

export const PROBLEM_TONE: Record<ProblemKey, "err" | "warn"> = { no_av: "err", rtp_off: "err", infected: "err", license: "err", bases_old: "warn", scan_old: "warn", reboot: "warn" };
export const PROBLEM_SHORT: Record<ProblemKey, string> = { no_av: "нет антивируса", rtp_off: "защита не работает", infected: "невылеченные объекты", bases_old: "старые базы", license: "лицензия истекла", scan_old: "нет полной проверки", reboot: "нужна перезагрузка" };
export const shortProduct = (s: string) => s.replace(/^Kaspersky\s+/, "").replace(" for ", " для ");
const daysAgo = (iso: string | null) => (iso ? Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 86400000)) : null);

/** Проблемы защиты компьютера: красные — защиты фактически нет, жёлтые — требуют внимания. */
export function ProblemBadges({ problems }: { problems: ProblemKey[] }) {
  if (!problems.length) return <span className="badge ok">защита в порядке</span>;
  return <span className="badges">{problems.map((p) => <span key={p} className={`badge ${PROBLEM_TONE[p]}`}>{PROBLEM_SHORT[p]}</span>)}</span>;
}

/** Раздел «Состояние защиты»: где защиты нет или она не работает, какие версии KES и Агента развёрнуты, что говорит статус KSC. */
export default function ProtectionPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const navigate = useNavigate();
  const problem = sp.get("problem") ?? ""; const product = sp.get("product") ?? ""; const build = sp.get("build") ?? "";
  const [basesDays, setBasesDays] = useState("3"); const [scanDays, setScanDays] = useState("30");
  const [q, setQ] = useState(""); const [group, setGroup] = useState(""); const [applied, setApplied] = useState({ q: "", group: "" });
  const [all, setAll] = useState(false); const [sort, setSort] = useState("risk"); const [desc, setDesc] = useState(true); const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ items: ProtHost[]; total: number; summary: ProtSummary | null; unsupported?: string[] } | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false); const [tick, setTick] = useState(0);
  const force = useRef(false);
  useEffect(() => { const t = window.setTimeout(() => { setApplied({ q, group }); setOffset(0); }, 350); return () => window.clearTimeout(t); }, [q, group]);
  useEffect(() => {
    if (!ctx.current) return;
    const refresh = force.current || undefined; force.current = false;
    setBusy(true);
    api.protection({ problem, product, build, bases_days: basesDays, scan_days: scanDays, ...applied, all_hosts: all, sort, desc, offset, limit: 50, refresh })
      .then((r) => { setData(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [ctx.current, problem, product, build, basesDays, scanDays, applied, all, sort, desc, offset, tick]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const setParams = (kv: Record<string, string>) => { setSp((p) => { for (const [k, v] of Object.entries(kv)) { if (v) p.set(k, v); else p.delete(k); } return p; }); setOffset(0); };
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(k !== "name"); } setOffset(0); };
  const s = data?.summary;
  const count = (k: ProblemKey) => s?.problems.find((p) => p.key === k)?.hosts ?? 0;
  const pct = (n: number) => (s?.hosts ? Math.round((n / s.hosts) * 100) : 0);
  const pTitle = s?.problems.find((p) => p.key === problem)?.title ?? (problem === "ok" ? "Без проблем" : problem);
  const vTitle = product ? `${shortProduct(s?.versions.find((v) => v.code === product)?.product ?? product)}${build ? ` ${build}` : ""}` : "";
  const filtered = !!(problem || product || applied.q || applied.group);
  if (data?.unsupported) return <section><PageHead title="Состояние защиты" /><div className="alert warn"><Icon name="alert" /><div className="alert-body">В базе источника нет объектов состояния защиты ({data.unsupported.join(", ")}). Раздел недоступен для этого источника.</div></div></section>;
  return (
    <section>
      <PageHead title="Состояние защиты" lede="Где защиты Kaspersky нет или она не работает, насколько свежи базы и какие версии продуктов развёрнуты. Учитываются компьютеры, подключавшиеся к KSC за порог активности.">
        {s && <Fetched at={s.fetched_at} />}
        <button className="btn" onClick={() => { force.current = true; setTick((x) => x + 1); }} aria-busy={busy && !!data}><Icon name="refresh" /><span>Обновить</span></button>
      </PageHead>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="meters">
        <div className="meter"><span className="l">Защищены</span><span className={`v ${s && pct(s.protected) < 90 ? "warn-text" : ""}`}>{s ? `${pct(s.protected)}%` : "…"}</span><span className="t">{s ? `${num(s.protected)} из ${num(s.hosts)}: антивирус работает, базы свежее ${s.bases_days} сут` : ""}</span></div>
        {([["no_av", "Без антивируса", "нет продукта Kaspersky"], ["rtp_off", "Защита не работает", "остановлена, в сбое или не запущена"], ["bases_old", "Устаревшие базы", `старше ${s?.bases_days ?? "…"} сут`]] as [ProblemKey, string, string][]).map(([k, l, t]) => (
          <button key={k} type="button" className={`meter meter-btn ${problem === k ? "on" : ""}`} aria-pressed={problem === k} onClick={() => setParams({ problem: problem === k ? "" : k })}>
            <span className="l">{l}</span><span className={`v ${s && count(k) ? (PROBLEM_TONE[k] === "err" ? "bad-text" : "warn-text") : ""}`}>{s ? num(count(k)) : "…"}</span><span className="t">{t}</span>
          </button>))}
      </div>

      <div className="split even mt">
        <div className="card flush">
          <div className="card-head"><h2>Проблемы защиты</h2><div className="spacer" />{s && <span className="muted small">из {num(s.hosts)} компьютеров</span>}</div>
          {!s ? <div className="pad"><SkelRows rows={5} cols={3} /></div> : (
            <ul className="ledger" aria-label="Проблемы защиты: выберите, чтобы показать компьютеры">
              {s.problems.map((p) => {
                const on = problem === p.key; const tone = p.hosts ? (PROBLEM_TONE[p.key] === "err" ? "bad" : "warn") : "ok";
                const hint = p.key === "bases_old" ? `базы старше ${s.bases_days} сут` : p.key === "scan_old" ? `полная проверка старше ${s.scan_days} сут или не выполнялась` : p.hint;
                return (
                  <li key={p.key}><button type="button" className={`ledger-row ${on ? "on" : ""}`} aria-pressed={on} onClick={() => setParams({ problem: on ? "" : p.key })}>
                    <span className={`dot ${tone}`} aria-hidden /><span className="lg-main"><b>{p.title}</b><span className="lg-sub">{hint}</span></span>
                    <span className="lg-bar" aria-hidden><i className={tone} style={{ width: `${p.hosts ? Math.max(2, pct(p.hosts)) : 0}%` }} /></span>
                    <span className="lg-n">{num(p.hosts)}<span className="lg-pct">{p.hosts ? `${pct(p.hosts)}%` : ""}</span></span>
                  </button></li>);
              })}
            </ul>)}
          <div className="card-foot">
            <span className="muted small">Пороги:</span>
            <span className="row tight"><span className="small">базы старше</span><Segmented label="Порог актуальности баз, суток" value={basesDays} onChange={(v) => { setBasesDays(v); setOffset(0); }} options={[["1", "1"], ["3", "3"], ["7", "7"]]} /><span className="small">сут</span></span>
            <span className="row tight"><span className="small">проверка старше</span><Segmented label="Порог полной проверки, суток" value={scanDays} onChange={(v) => { setScanDays(v); setOffset(0); }} options={[["7", "7"], ["30", "30"], ["90", "90"]]} /><span className="small">сут</span></span>
          </div>
          {s && s.reasons.length > 0 && (
            <details className="disclosure pad-x">
              <summary>Причины статуса в KSC: критический {num(s.ksc_status["критический"] ?? 0)}, предупреждение {num(s.ksc_status["предупреждение"] ?? 0)}</summary>
              <ul className="rows">{s.reasons.map((r) => <li key={r.bit}><div className="r-main"><span>{r.title}</span></div><span className="num small">{num(r.hosts)}</span></li>)}</ul>
            </details>)}
        </div>
        <div className="card">
          <div className="card-head"><h2>Версии продуктов</h2><div className="spacer" /><span className="muted small">выберите версию, чтобы увидеть компьютеры</span></div>
          {!s ? <SkelRows rows={4} cols={2} /> : !s.versions.length ? <Empty icon="shieldPulse" title="Нет сведений о продуктах">KSC не получал от Агентов данных о продуктах Kaspersky.</Empty> : (
            <div className="stack">
              {s.versions.map((v) => (
                <div key={v.code} className="ver-block">
                  <div className="ver-head"><b>{shortProduct(v.product)}</b><span className="muted small">{v.versions.length > 1 ? `${num(v.on_latest)} из ${num(v.hosts)} на новейшей ${v.latest}` : `все ${num(v.hosts)} на ${v.latest}`}</span></div>
                  <Spectrum label={`Версии: ${v.product}`} unit=" комп." segs={v.versions.map((x) => ({ key: x.build, label: x.build, value: x.hosts }))}
                    selected={product === v.code ? new Set([build]) : undefined} onToggle={(b) => setParams(product === v.code && build === b ? { product: "", build: "" } : { product: v.code, build: b })} />
                </div>))}
            </div>)}
        </div>
      </div>

      <div className="section-head"><h2>Компьютеры</h2>{data && <span className="count">{num(data.total)}</span>}</div>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Компьютер или IP-адрес" aria-label="Компьютер" /></div>
        <input className="w-md" value={group} onChange={(e) => setGroup(e.target.value)} placeholder="Группа" aria-label="Группа администрирования" />
        <Segmented label="Показать" value={problem === "ok" ? "ok" : problem ? "problem" : ""} onChange={(v) => setParams({ problem: v === "ok" ? "ok" : "" })}
          options={[["", "Все"], ["ok", "Без проблем"], ...(problem && problem !== "ok" ? [["problem", pTitle] as [string, string]] : [])]} />
        {(product || (problem && problem !== "ok")) && (
          <div className="toolbar-foot">
            {problem && problem !== "ok" && <span className="chip">Проблема: <b>{pTitle}</b><button type="button" className="link-btn" onClick={() => setParams({ problem: "" })}>сбросить</button></span>}
            {product && <span className="chip">Версия: <b>{vTitle}</b><button type="button" className="link-btn" onClick={() => setParams({ product: "", build: "" })}>сбросить</button></span>}
          </div>)}
      </div>
      <div className="table-scroll">
        {!data && busy ? <SkelRows cols={6} /> : (
          <table className="table">
            <thead><tr><SortTh k="name" label="Компьютер" sort={sort} desc={desc} onSort={onSort} /><th>Защитный продукт</th><th className="hide-sm">Постоянная защита</th>
              <SortTh k="bases" label="Базы" sort={sort} desc={desc} onSort={onSort} /><SortTh k="scan" label="Полная проверка" sort={sort} desc={desc} onSort={onSort} className="hide-sm" />
              <SortTh k="risk" label="Проблемы" sort={sort} desc={desc} onSort={onSort} /><SortTh k="last_connected" label="Подключение к KSC" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /></tr></thead>
            <tbody style={{ opacity: busy ? .55 : 1 }}>
              {(data?.items ?? []).map((h) => {
                const b = daysAgo(h.av?.bases ?? null); const old = h.problems.includes("bases_old");
                return (
                  <tr key={h.host_id} className="clickable" onClick={(e) => { if (!(e.target as HTMLElement).closest("a")) navigate(`/hosts/${h.host_id}`); }}>
                    <td><Link to={`/hosts/${h.host_id}`} className="strong-link">{h.name}</Link><span className="sub mono">{h.ip}</span></td>
                    <td>{h.av ? <>{shortProduct(h.av.product)}<span className="sub mono">{h.av.build}</span></> : <span className="bad-text">нет</span>}{h.agent_build && <span className="sub nowrap">Агент <span className="mono">{h.agent_build}</span></span>}</td>
                    <td className="small hide-sm">{h.av ? (h.problems.includes("rtp_off") ? <span className="bad-text">{h.av.state_label && h.av.state_label !== "запущен" ? `продукт ${h.av.state_label}` : h.rtp_label || "не работает"}</span> : h.rtp_label || h.av.state_label || "—") : "—"}</td>
                    <td className="nowrap">{h.av ? (h.av.bases ? <span className={old ? "warn-text" : ""}>{fmtDate(h.av.bases)}<span className="sub">{b === 0 ? "сегодня" : `${b} сут назад`}</span></span> : <span className="warn-text">нет сведений</span>) : "—"}</td>
                    <td className="nowrap small hide-sm">{h.av ? (h.last_full_scan ? <span className={h.problems.includes("scan_old") ? "warn-text" : ""}>{fmtDate(h.last_full_scan)}</span> : <span className="muted">не выполнялась</span>) : "—"}</td>
                    <td><ProblemBadges problems={h.problems} /></td>
                    <td className="nowrap small hide-sm">{fmt(h.last_connected)}</td>
                  </tr>);
              })}
              {data && !data.items.length && <tr><td colSpan={7}><Empty icon="checkCircle" title={filtered ? "Ничего не найдено" : "Компьютеров нет"}>{filtered ? "По выбранным условиям компьютеров нет." : "В источнике нет компьютеров, подключавшихся к KSC за порог активности."}</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      {data && <Pager total={data.total} offset={offset} limit={50} onPage={setOffset} />}
      {s && <HiddenNote hidden={s.hidden_hosts} days={s.activity_days} all={all} onToggle={() => { setAll(!all); setOffset(0); }} />}
      <p className="muted small mt-sm">Сведения — из последних отчётов Агентов администрирования в KSC; время — UTC, показано в вашем часовом поясе. «Нет антивируса» означает, что KSC не получал от Агента сведений о защитном продукте Kaspersky.</p>
    </section>
  );
}
