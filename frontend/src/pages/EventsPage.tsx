import { useEffect, useRef, useState } from "react";
import { ListFoot, VirtualRows, useInfinite, useKept, type Chunk } from "../components/Infinite";
import { Link, useSearchParams } from "react-router-dom";
import { api, type ApiError, type EvGroup, type EvSummary, type SecEvent } from "../api";
import { NoSource, type Ctx } from "../App";
import { Fetched } from "../components/Common";
import { Icon } from "../components/Icons";
import { CheckAll, QuickReportPanel, ReportDock, useRowSel } from "../components/QuickReport";
import { Empty, PageHead, Segmented, SkelRows, MaskHint } from "../components/ui";
import { fmt, num } from "../util";

const PERIODS: [string, string][] = [["1", "Сутки"], ["7", "7 суток"], ["30", "30 суток"]];
export type EvFilter = "" | EvGroup;
const GROUP_TYPES: Record<EvFilter, string> = { "": "", detections: "detected,suspicious", notcured: "notcured", resolved: "deleted,cured,quarantined", attacks: "attack" };
const GROUP_OPTS: [EvFilter, string][] = [["", "Все"], ["detections", "Обнаружения"], ["notcured", "Не вылечено"], ["resolved", "Обработано"], ["attacks", "Атаки"]];
const TYPE_TONE: Record<string, string> = { detected: "warn", suspicious: "warn", notcured: "err", attack: "err", deleted: "ok", cured: "ok", quarantined: "ok" };
const BAR: [EvGroup, string][] = [["detections", "обнаружения"], ["notcured", "не вылечено"], ["attacks", "сетевые атаки"]];
const bucketLabel = (iso: string, unit: "hour" | "day") => new Date(iso).toLocaleString("ru-RU", unit === "hour" ? { hour: "2-digit", minute: "2-digit" } : { day: "numeric", month: "short" });

/** Раздел «События безопасности»: что Kaspersky обнаружил за период, что осталось не вылеченным, где и какие угрозы. */
export default function EventsPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const days = ["1", "7", "30"].includes(sp.get("days") ?? "") ? Number(sp.get("days")) : 7;
  const group = (GROUP_OPTS.some(([k]) => k === sp.get("type")) ? sp.get("type") : "") as EvFilter;
  const threat = sp.get("threat") ?? "";
  const [s, setS] = useState<EvSummary | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false); const [tick, setTick] = useState(0);
  const force = useRef(false);
  useEffect(() => {
    if (!ctx.current) return;
    const refresh = force.current || undefined; force.current = false;
    setBusy(true);
    api.events.summary(days, refresh).then((r) => { setS(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [ctx.current, days, tick]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const set = (kv: Record<string, string>) => setSp((p) => { for (const [k, v] of Object.entries(kv)) { if (v) p.set(k, v); else p.delete(k); } return p; });
  // фильтр из показателя или списка угроз — к журналу, где виден результат
  const setShow = (kv: Record<string, string>) => { set(kv); if (Object.values(kv).some(Boolean)) window.requestAnimationFrame(() => document.getElementById("ev-journal")?.scrollIntoView({ behavior: "smooth", block: "start" })); };
  const per = days === 1 ? "за сутки" : `за ${days} суток`;
  const meter = (g: EvGroup, label: string, tone: string, foot: (n: number) => string) => {
    const n = s?.totals[g] ?? 0; const on = group === g;
    return (
      <button type="button" className={`meter meter-btn ${on ? "on" : ""}`} aria-pressed={on} onClick={() => setShow({ type: on ? "" : g })}>
        <span className="l">{label}</span><span className={`v ${n ? tone : ""}`}>{s ? num(n) : "…"}</span><span className="t">{s ? foot(s.hosts[g]) : ""}</span>
      </button>);
  };
  if (s?.unsupported) return <section><PageHead title="События безопасности" /><div className="alert warn"><Icon name="alert" /><div className="alert-body">В базе источника нет журнала событий KSC ({s.unsupported.join(", ")}). Раздел недоступен для этого источника.</div></div></section>;
  const max = Math.max(1, ...(s?.trend ?? []).map((b) => b.detections + b.notcured + b.attacks));
  const peak = s?.trend.reduce((a, b) => (b.detections + b.notcured + b.attacks > a.detections + a.notcured + a.attacks ? b : a), s.trend[0]);
  return (
    <section>
      <PageHead title="События безопасности" lede="Обнаружения угроз, результат их обработки и сетевые атаки из журнала событий KSC. Время события задаёт устройство; показано в вашем часовом поясе.">
        <Segmented label="Период" value={String(days)} onChange={(v) => set({ days: v === "7" ? "" : v })} options={PERIODS} />
        <button className="btn" onClick={() => { force.current = true; setTick((x) => x + 1); }} aria-busy={busy && !!s}><Icon name="refresh" /><span>Обновить</span></button>
      </PageHead>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="meters">
        {meter("detections", "Обнаружено угроз", "warn-text", (h) => `на ${num(h)} комп. ${per}`)}
        {meter("notcured", "Не вылечено", "bad-text", (h) => (h ? `угроза осталась на ${num(h)} комп.` : "все обнаружения обработаны"))}
        {meter("attacks", "Сетевые атаки", "bad-text", (h) => `на ${num(h)} комп.`)}
        {meter("resolved", "Обработано", "", () => "удалено, вылечено, в карантине")}
      </div>

      <div className="card mt">
        <div className="card-head"><h2>Динамика {per}</h2><div className="spacer" />
          <span className="tr-legend">{BAR.map(([g, l]) => <span key={g}><i className={`sw tr-${g}`} aria-hidden />{l}</span>)}</span>{s && <Fetched at={s.fetched_at} />}</div>
        {!s ? <span className="skel skel-chart" /> : (
          <>
            <div className="trend" role="img" aria-label={`Динамика событий ${per}: обнаружений ${s.totals.detections}, не вылечено ${s.totals.notcured}, атак ${s.totals.attacks}${peak ? `; наибольшее число — ${bucketLabel(peak.at, s.unit)}` : ""}`}>
              {s.trend.map((b) => {
                const t = b.detections + b.notcured + b.attacks;
                return (
                  <div key={b.at} className="tr-col" title={`${bucketLabel(b.at, s.unit)}: обнаружено ${b.detections}, не вылечено ${b.notcured}, атак ${b.attacks}, обработано ${b.resolved}`}>
                    {BAR.map(([g]) => b[g] > 0 && <i key={g} className={`tr-${g}`} style={{ height: `${(b[g] / max) * 100}%` }} />)}
                    {!t && <i className="tr-zero" />}
                  </div>);
              })}
            </div>
            <div className="tr-axis"><span>{bucketLabel(s.trend[0].at, s.unit)}</span><span>{s.unit === "hour" ? "по часам" : "по суткам"}</span><span>{bucketLabel(s.trend[s.trend.length - 1].at, s.unit)}</span></div>
          </>)}
      </div>

      <div className="split even mt">
        <div className="card flush">
          <div className="card-head"><h2>Компьютеры с наибольшим числом событий</h2></div>
          {!s ? <div className="pad"><SkelRows rows={5} cols={2} /></div> : !s.top_hosts.length ? <p className="muted small pad">Событий обнаружения {per} нет.</p> : (
            <ul className="rows pad-x">{s.top_hosts.map((h) => (
              <li key={h.host_id ?? h.name}>
                <div className="r-main">{h.host_id && !h.deleted ? <Link to={`/hosts/${h.host_id}?tab=events`} className="strong-link">{h.name}</Link> : <b>{h.deleted ? `Удалённое устройство (ID ${h.host_id ?? "?"}, имя неизвестно)` : h.name}</b>}
                  <span className="r-sub">{h.ip && <span className="mono">{h.ip} · </span>}последнее {fmt(h.last)}</span></div>
                {h.notcured > 0 && <span className="badge err">не вылечено {num(h.notcured)}</span>}{h.attacks > 0 && <span className="badge err">атаки {num(h.attacks)}</span>}
                <span className="num"><b>{num(h.n)}</b></span>
              </li>))}</ul>)}
        </div>
        <div className="card flush">
          <div className="card-head"><h2>Угрозы и атаки</h2><div className="spacer" /><span className="muted small">по числу компьютеров</span></div>
          {!s ? <div className="pad"><SkelRows rows={5} cols={2} /></div> : !s.top_threats.length ? <p className="muted small pad">Угроз {per} не обнаружено.</p> : (
            <ul className="rows pad-x">{s.top_threats.map((t) => (
              <li key={t.kind + t.name}>
                <div className="r-main"><button type="button" className={`link-btn threat-name ${threat === t.name ? "on" : ""}`} aria-pressed={threat === t.name} onClick={() => setShow({ threat: threat === t.name ? "" : t.name })}>{t.name}</button>
                  <span className="r-sub">{t.kind === "attack" ? "сетевая атака" : "угроза"} · {num(t.n)} событ. · последнее {fmt(t.last)}</span></div>
                <span className="num nowrap"><b>{num(t.hosts)}</b> <span className="muted small">комп.</span></span>
              </li>))}</ul>)}
        </div>
      </div>

      <div className="section-head" id="ev-journal"><h2>Журнал обнаружений {per}</h2></div>
      <EventList ctx={ctx} days={days} group={group} threat={threat} onGroup={(g) => set({ type: g })} onThreat={(t) => set({ threat: t })} />
    </section>
  );
}

/** Журнал событий обнаружения — непрерывный список с поиском и фильтром по результату; используется в разделе и в карточке компьютера. */
export function EventList({ ctx, days, hostId, group, threat, onGroup, onThreat }: { ctx: Ctx; days: number; hostId?: number; group: EvFilter; threat: string; onGroup: (g: EvFilter) => void; onThreat: (t: string) => void }) {
  const [q, setQ] = useKept(`events.q:${hostId ?? ""}`, ""); const [applied, setApplied] = useState(q);
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 350); return () => window.clearTimeout(t); }, [q]);
  const list = useInfinite<SecEvent>(`events:${hostId ?? "all"}`, [days, hostId, group, threat, applied],
    (offset, limit) => api.events.list({ days, host_id: hostId, type: GROUP_TYPES[group], q: applied, threat, offset, limit }) as unknown as Promise<Chunk<SecEvent>>);
  const unsupported = (list.extra as { unsupported?: string[] } | null)?.unsupported;
  const sel = useRowSel<number>(); const [report, setReport] = useState<"all" | "sel" | null>(null);
  const canReport = ctx.me.user.role !== "viewer";
  const evIds = list.items.map((e) => e.event_id);
  if (unsupported) return <div className="alert warn"><Icon name="alert" /><div className="alert-body">В базе источника нет журнала событий KSC ({unsupported.join(", ")}).</div></div>;
  return (
    <>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder={hostId ? "Угроза, объект или пользователь" : "Компьютер, угроза, объект или пользователь"} aria-label="Поиск событий" /><MaskHint /></div>
        <Segmented<EvFilter> label="Результат" value={group} onChange={onGroup} options={GROUP_OPTS} />
        {canReport && <button className="btn" onClick={() => setReport("all")} disabled={list.initial || !list.total}><Icon name="file" />Отчёт по списку</button>}
        {threat && <div className="toolbar-foot"><span className="chip">Угроза: <b className="mono">{threat}</b><button type="button" className="link-btn" onClick={() => onThreat("")}>сбросить</button></span></div>}
      </div>
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={5} /> : (
          <table className="table virt">
            <thead><tr><CheckAll all={sel.allOf(evIds)} some={sel.someOf(evIds)} onToggle={() => sel.toggleMany(evIds)} /><th>Время</th>{!hostId && <th>Компьютер</th>}<th>Событие</th><th>Угроза или атака</th><th>Объект</th><th className="hide-sm">Пользователь</th></tr></thead>
            <tbody>
              <VirtualRows list={list} colSpan={hostId ? 6 : 7} estimate={48} row={(e) => (
                <tr className={sel.has(e.event_id) ? "sel" : ""}>
                  <td className="check"><input type="checkbox" aria-label="Выбрать событие" checked={sel.has(e.event_id)} onChange={() => sel.toggle(e.event_id)} /></td>
                  <td className="nowrap small">{fmt(e.at)}</td>
                  {!hostId && <td>{e.host_known ? <Link to={`/hosts/${e.host_id}?tab=events`}>{e.host}</Link> : <span className="muted" title="Устройства уже нет в KSC: имя и IP-адрес на момент события недоступны">{e.host}</span>}{e.ip ? <span className="sub mono">{e.ip}</span> : <span className="sub muted">IP: нет данных</span>}</td>}
                  <td><span className={`badge ${TYPE_TONE[e.type] ?? ""}`}>{e.type_title}</span></td>
                  <td>{e.threat ? <button type="button" className="link-btn mono threat-name" onClick={() => onThreat(e.threat)} title="Показать события этой угрозы">{e.threat}</button> : <span className="muted">—</span>}{e.threat_kind && <span className="sub">{e.threat_kind}</span>}</td>
                  <td className="small obj">{e.type === "attack" ? <span className="mono">{e.attacker || "?"}{e.port ? ` → порт ${e.port}` : ""}{e.protocol ? ` (${e.protocol})` : ""}</span> : e.object ? <span className="mono" title={e.object}>{e.object}</span> : <span className="muted">—</span>}</td>
                  <td className="small hide-sm">{e.user || <span className="muted">—</span>}</td>
                </tr>)} />
              {!list.items.length && !list.loading && <tr><td colSpan={hostId ? 6 : 7}><Empty icon="checkCircle" title={applied || group || threat ? "Ничего не найдено" : "Событий нет"}>{applied || group || threat ? "Измените поиск или фильтр." : `Kaspersky не сообщал об обнаружениях ${days === 1 ? "за сутки" : `за ${days} суток`}.`}</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      <ReportDock label="Выбранные события" count={sel.count} noun={["событие выбрано", "события выбраны", "событий выбрано"]} canReport={canReport} onClear={sel.clear} onReport={() => setReport("sel")} />
      {report && <QuickReportPanel kind="quick_events" title={report === "sel" ? `События безопасности: выбранные (${sel.count})` : "События безопасности"} lede={report === "all" ? "Условия берутся из текущих фильтров страницы" : undefined}
        options={{ period: report === "all", scope: false }} activityDays={ctx.me.activity_days} canReport={canReport} onClose={() => setReport(null)}
        params={report === "sel" ? { days, event_ids: sel.ids } : { days, group, threat, q: applied, host_id: hostId ?? null }} />}
    </>
  );
}
