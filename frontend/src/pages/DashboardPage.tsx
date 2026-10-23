import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type Dashboard } from "../api";
import { NoSource, type Ctx } from "../App";
import { Icon, type IconName } from "../components/Icons";
import { Empty, PageHead, Spectrum } from "../components/ui";
import { fmt, fmtTime, num } from "../util";

export const JOB_STATUS: Record<string, [string, string]> = { queued: ["в очереди", ""], running: ["формируется", "accent"], done: ["готов", "ok"], failed: ["ошибка", "err"], cancelled: ["отменён", "warn"] };

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
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const s = d?.summary;
  const t = s?.fetched_at ? `на ${fmtTime(s.fetched_at)}` : "данные ещё не получены";
  const meter = (label: string, v: number | string | null | undefined, foot: string = t, unit?: string) => (
    <div className="meter">
      <span className="l">{label}</span>
      {v === null || v === undefined ? <span className="v"><span className="empty-v">{d ? "нет данных" : <span className="skel" style={{ width: 70, height: 26 }} />}</span></span>
        : <span className={`v ${typeof v === "string" ? "text" : ""}`}>{typeof v === "number" ? num(v) : v}{unit && <span className="unit">{unit}</span>}</span>}
      <span className="t">{foot}</span>
    </div>
  );
  const src = d?.source;
  const conn = src ? (src.last_check_ok === true ? ["ok", "работает"] : src.last_check_ok === false ? ["bad", "ошибка проверки"] : ["off", "не проверялся"]) : null;
  const actions: { to: string; icon: IconName; title: string; sub: string }[] = [
    { to: "/software?mode=grouped&rule=php", icon: "branch", title: "Аудит PHP по веткам", sub: "Ветки 5.6–8.x, компьютеры с выбранными версиями" },
    { to: "/software", icon: "search", title: "Найти программу и её версии", sub: "Реестр приложений KSC с числом установок" },
    { to: "/hosts?activity=inactive", icon: "clock", title: "Компьютеры без связи с KSC", sub: `Агент не подключался дольше ${s?.activity_days ?? "…"} сут` },
    { to: "/vulnerabilities", icon: "bug", title: "Уязвимости, найденные KSC", sub: "Действующие обнаружения с CVE" },
  ];
  return (
    <section>
      <PageHead title="Главная" lede={<>Сводка по источнику <b>{ctx.current.name}</b>. Числа берутся из базы KSC и кэшируются; у каждого показано время получения.</>}>
        <button className="btn" onClick={() => void load(true)} aria-busy={busy && !!d}><Icon name="refresh" /><span>Обновить данные</span></button>
      </PageHead>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {d?.error && <div className="alert warn" role="status"><Icon name="alert" /><div className="alert-body">Источник сейчас недоступен: {d.error}. {s ? "Показаны последние полученные данные." : ""}</div></div>}

      <div className="meters three" aria-label="Показатели источника">
        <div className="meter">
          <span className="l">Подключение к KSC</span>
          <span className="v text">{conn ? <span className="row tight"><span className={`dot ${conn[0]}`} />{conn[1]}</span> : <span className="skel" style={{ width: 110, height: 22 }} />}</span>
          <span className="t">{src?.last_check_at ? `проверка ${fmt(src.last_check_at)}` : "проверьте в разделе «Источники KSC»"}</span>
        </div>
        {meter("Версия KSC", s?.ksc_version ?? src?.ksc_version ?? (d ? null : undefined), s?.ksc_version ? t : "не определена")}
        {meter("Управляемых компьютеров", s?.hosts_total)}
        {meter("Программ в реестре", s?.products, s?.software_error ?? t)}
        {meter("Установок ПО", s?.installs)}
        {meter("Отчётов по источнику", d?.reports_total, "сформировано всего")}
        {s?.hosts_total !== undefined && s.hosts_active !== undefined && (
          <div className="meter wide">
            <div className="row" style={{ justifyContent: "space-between" }}>
              <span className="l">Связь компьютеров с KSC за последние {s.activity_days} сут</span>
              <span className="t" style={{ padding: 0 }}>{t}</span>
            </div>
            <Spectrum label="Активность компьютеров" size="lg" segs={[
              { key: "on", label: "Активны", value: s.hosts_active, tone: "ok", note: `${Math.round((s.hosts_active / Math.max(1, s.hosts_total)) * 100)}%` },
              { key: "off", label: `Без связи дольше ${s.activity_days} сут`, value: s.hosts_inactive ?? 0, tone: "warn", note: `${Math.round(((s.hosts_inactive ?? 0) / Math.max(1, s.hosts_total)) * 100)}%` },
            ]} />
          </div>
        )}
      </div>

      <div className="split even" style={{ marginTop: 16 }}>
        <div className="card">
          <div className="card-head"><h2>Последние отчёты</h2><div className="spacer" /><Link className="btn mini" to="/reports">Все отчёты</Link></div>
          {!d ? <div className="stack" style={{ gap: 12 }}>{[0, 1, 2].map((i) => <span key={i} className="skel" style={{ height: 14, width: `${80 - i * 15}%` }} />)}</div>
            : !d.recent_reports.length ? <Empty icon="file" title="Отчётов пока нет" action={ctx.me.user.role !== "viewer" ? <Link className="btn primary" to="/reports"><Icon name="plus" />Сформировать отчёт</Link> : undefined}>Отчёты по этому источнику появятся здесь.</Empty>
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
