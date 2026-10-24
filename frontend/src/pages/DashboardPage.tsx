import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type Dashboard, type EvSummary, type ProtSummary } from "../api";
import { NoSource, type Ctx } from "../App";
import { Icon, type IconName } from "../components/Icons";
import { Empty, PageHead, Spectrum } from "../components/ui";
import { fmt, fmtTime, num } from "../util";

export const JOB_STATUS: Record<string, [string, string]> = { queued: ["в очереди", ""], running: ["формируется", "accent"], done: ["готов", "ok"], failed: ["ошибка", "err"], cancelled: ["отменён", "warn"] };

const ok = <T,>(x: T | null | "err"): x is T => !!x && x !== "err";

export default function DashboardPage({ ctx }: { ctx: Ctx }) {
  const [d, setD] = useState<Dashboard | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(async (refresh = false) => {
    if (!ctx.current) return;
    setBusy(true);
    try { setD(await api.dashboard(refresh)); setErr(""); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); }
  }, [ctx.current]);
  useEffect(() => { void load(); }, [load]);
  // защита и события — отдельными запросами: главная не ждёт тяжёлых сводок, а при их ошибке остаётся рабочей
  const [prot, setProt] = useState<ProtSummary | null | "err">(null);
  const [ev, setEv] = useState<EvSummary | null | "err">(null);
  useEffect(() => {
    if (!ctx.current) return;
    api.protection({ limit: 0 }).then((r) => setProt(r.summary ?? "err")).catch(() => setProt("err"));
    api.events.summary(7).then((r) => setEv(r.unsupported ? "err" : r)).catch(() => setEv("err"));
  }, [ctx.current]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const s = d?.summary;
  const t = s?.fetched_at ? `на ${fmtTime(s.fetched_at)}` : "данные ещё не получены";
  const meter = (label: string, v: number | null | undefined, foot: string = t) => (
    <div className="meter">
      <span className="l">{label}</span>
      {v === null || v === undefined ? <span className="v">{d ? <span className="empty-v">нет данных</span> : <span className="skel skel-v" />}</span> : <span className="v">{num(v)}</span>}
      <span className="t">{foot}</span>
    </div>
  );
  const src = d?.source;
  const kscVersion = s?.ksc_version ?? src?.ksc_version;
  const conn = src ? (src.last_check_ok === true ? ["ok", "подключение работает"] : src.last_check_ok === false ? ["bad", "ошибка проверки подключения"] : ["off", "подключение не проверялось"]) : null;
  const share = (n: number, of: number) => `${Math.round((n / Math.max(1, of)) * 100)}%`;
  const actions: { to: string; icon: IconName; title: string; sub: string }[] = [
    { to: "/reports", icon: "target", title: "Найти устаревшие версии", sub: "Программа из каталога и версия, ниже которой — устаревшая" },
    { to: "/software/p/php", icon: "branch", title: "PHP по веткам", sub: "Ветки и версии PHP, компьютеры с каждой из них" },
    { to: "/vulnerabilities", icon: "bug", title: "Уязвимости, найденные KSC", sub: "Компьютеры с критическими уязвимостями — первыми" },
    { to: "/hosts?activity=inactive", icon: "clock", title: "Компьютеры без связи с KSC", sub: `Агент не подключался дольше ${s?.activity_days ?? "…"} сут` },
  ];
  const protMeters: [string, string, number | string | null, string, string, "prot" | "ev"][] = [
    ["/protection", "Защищены", ok(prot) ? share(prot.protected, prot.hosts) : null, ok(prot) ? `${num(prot.protected)} из ${num(prot.hosts)} компьютеров` : "", "", "prot"],
    ["/protection?problem=no_av", "Без антивируса", ok(prot) ? prot.problems.find((p) => p.key === "no_av")?.hosts ?? 0 : null, "нет продукта Kaspersky", "bad-text", "prot"],
    ["/protection?problem=rtp_off", "Защита не работает", ok(prot) ? prot.problems.find((p) => p.key === "rtp_off")?.hosts ?? 0 : null, "остановлена или в сбое", "bad-text", "prot"],
    ["/events?type=notcured", "Не вылечено за 7 сут", ok(ev) ? ev.totals.notcured : null, ok(ev) ? `обнаружено угроз: ${num(ev.totals.detections)}` : "", "bad-text", "ev"],
  ];
  return (
    <section>
      <PageHead title="Главная" lede={
        <span className="src-line">
          {conn ? <><span className={`dot ${conn[0]}`} aria-hidden /><b>{ctx.current.name}</b><span>{conn[1]}{src?.last_check_at ? `, проверка ${fmt(src.last_check_at)}` : ""}</span>
            {kscVersion && <span className="badge accent">KSC {kscVersion}</span>}
            {conn[0] !== "ok" && ctx.me.user.is_admin && <Link to="/admin?tab=sources">Проверить источник</Link>}</>
            : <><b>{ctx.current.name}</b><span className="skel skel-line" /></>}
        </span>}>
        <button className="btn" onClick={() => void load(true)} aria-busy={busy && !!d}><Icon name="refresh" /><span>Обновить данные</span></button>
      </PageHead>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {d?.error && <div className="alert warn" role="status"><Icon name="alert" /><div className="alert-body">Источник сейчас недоступен: {d.error}. {s ? "Показаны последние полученные данные." : ""}</div></div>}

      <div className="section-head first"><h2>Защита и угрозы</h2><span className="muted small">активные компьютеры; события — за 7 суток</span></div>
      <div className="meters" aria-label="Защита и угрозы">
        {protMeters.map(([to, l, v, foot, tone, kind]) => (
          <Link key={to} to={to} className="meter meter-link">
            <span className="l">{l}</span>
            <span className={`v ${typeof v === "number" && v > 0 ? tone : ""}`}>{v === null ? ((kind === "ev" ? ev : prot) === "err" ? <span className="empty-v">нет данных</span> : <span className="skel skel-v" />) : typeof v === "number" ? num(v) : v}</span>
            <span className="t">{foot}</span>
          </Link>))}
      </div>

      <div className="section-head"><h2>Компьютеры и программы</h2><span className="muted small">{t}</span></div>
      <div className="meters three" aria-label="Компьютеры и программы">
        {meter("Управляемых компьютеров", s?.hosts_total, s?.hosts_active !== undefined ? `активны ${num(s.hosts_active)} — ${share(s.hosts_active, s.hosts_total ?? 0)}` : t)}
        {meter("Программ в реестре", s?.products, s?.software_error ?? "записей реестра KSC")}
        {meter("Установок ПО", s?.installs, "на всех компьютерах")}
        {s?.hosts_total !== undefined && s.hosts_active !== undefined && (
          <div className="meter wide">
            <span className="l">Связь с KSC за последние {s.activity_days} сут</span>
            <Spectrum label="Активность компьютеров" size="lg" segs={[
              { key: "on", label: "Активны", value: s.hosts_active, tone: "ok", note: share(s.hosts_active, s.hosts_total) },
              { key: "off", label: `Без связи дольше ${s.activity_days} сут`, value: s.hosts_inactive ?? 0, tone: "warn", note: share(s.hosts_inactive ?? 0, s.hosts_total) },
            ]} />
          </div>
        )}
      </div>

      <div className="split even mt">
        <div className="card">
          <div className="card-head"><h2>Последние отчёты</h2><div className="spacer" /><Link className="btn mini" to="/reports">Все отчёты</Link></div>
          {!d ? <div className="stack tight">{[80, 65, 50].map((w) => <span key={w} className="skel skel-text" style={{ width: `${w}%` }} />)}</div>
            : !d.recent_reports.length ? <Empty icon="file" title="Отчётов пока нет" action={ctx.me.user.role !== "viewer" ? <Link className="btn primary" to="/reports"><Icon name="target" />Найти устаревшие версии</Link> : undefined}>Отчёты по этому источнику появятся здесь.</Empty>
              : <ul className="rows">{d.recent_reports.map((r) => { const [l, c] = JOB_STATUS[r.status] ?? [r.status, ""]; return (
                <li key={r.id}><Icon name="file" className="muted" /><div className="r-main"><Link to={`/reports/${r.id}`}>{r.title}</Link><span className="r-sub">{fmt(r.created_at)}{r.rows != null ? `, строк: ${num(r.rows)}` : ""}</span></div><span className={`badge ${c}`}>{l}</span></li>); })}</ul>}
        </div>
        <div className="card">
          <div className="card-head"><h2>Частые задачи</h2></div>
          <nav aria-label="Частые задачи">
            {actions.map((a) => <Link key={a.to} to={a.to} className="action-row"><span className="a-ic"><Icon name={a.icon} /></span><span className="a-main"><b>{a.title}</b><span>{a.sub}</span></span><Icon name="chevronR" className="a-go" /></Link>)}
          </nav>
        </div>
      </div>
    </section>
  );
}
