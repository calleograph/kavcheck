import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type Dashboard } from "../api";
import { NoSource, type Ctx } from "../App";
import { fmt, num } from "../util";

const STATUS: Record<string, string> = { queued: "в очереди", running: "формируется", done: "готов", failed: "ошибка", cancelled: "отменён" };

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
  const at = s?.fetched_at;
  const kpi = (label: string, v: number | string | null | undefined, hint?: string) => (
    <div className="card"><div className="l">{label}</div><div className="v">{v === null || v === undefined ? <span className="muted" style={{ fontSize: 15 }}>нет данных</span> : typeof v === "number" ? num(v) : v}</div><div className="t">{hint ?? (at ? `обновлено ${fmt(at)}` : "данные ещё не получены")}</div></div>
  );
  return (
    <section>
      <div className="row"><h1>Главная</h1><div className="spacer" />
        <button className="btn" onClick={() => void load(true)} disabled={busy}>{busy ? "Обновление…" : "Обновить данные"}</button></div>
      <p className="muted">Сводка по источнику <b>{ctx.current.name}</b>. Показатели кэшируются; у каждого указано время получения из базы KSC.</p>
      {err && <div className="alert error">{err}</div>}
      {d?.error && <div className="alert warn">Источник сейчас недоступен: {d.error}. {s ? "Показаны последние полученные данные." : ""}</div>}
      <div className="kpi">
        <div className="card"><div className="l">Подключение к KSC</div>
          <div className="v" style={{ fontSize: 17 }}>{d ? (d.source.last_check_ok === true ? <span className="ok-text">проверено, работает</span> : d.source.last_check_ok === false ? <span className="bad-text">ошибка проверки</span> : <span className="muted">не проверялось</span>) : "…"}</div>
          <div className="t">{d?.source.last_check_at ? `проверка ${fmt(d.source.last_check_at)}` : "проверьте подключение в разделе «Источники KSC»"}</div></div>
        {kpi("Версия KSC", s?.ksc_version ?? d?.source.ksc_version ?? null, s?.ksc_version ? undefined : "не удалось определить (нужен объект v_akpub_hst_prdstate)")}
        {kpi("Управляемых компьютеров", s?.hosts_total)}
        {kpi(`Активных (связь за ${s?.activity_days ?? "…"} сут)`, s?.hosts_active)}
        {kpi(`Без связи более ${s?.activity_days ?? "…"} сут`, s?.hosts_inactive)}
        {kpi("Программ в реестре", s?.products, s?.software_error ? s.software_error : undefined)}
        {kpi("Установок ПО", s?.installs)}
        {kpi("Отчётов сформировано", d?.reports_total, "по этому источнику, всего")}
      </div>
      <div className="grid">
        <div className="card">
          <h2>Последние отчёты</h2>
          {!d?.recent_reports.length ? <p className="muted">Отчётов по этому источнику пока нет. <Link to="/reports">Сформировать отчёт →</Link></p> : (
            <ul className="plain">{d.recent_reports.map((r) => <li key={r.id}><Link to={`/reports/${r.id}`}>{r.title}</Link> <span className="muted small">· {STATUS[r.status] ?? r.status}{r.rows != null ? ` · строк ${num(r.rows)}` : ""} · {fmt(r.created_at)}</span></li>)}</ul>)}
        </div>
        <div className="card">
          <h2>Быстрые действия</h2>
          <ul className="plain">
            <li><Link to="/software">Найти программу и её версии →</Link></li>
            <li><Link to="/software?mode=grouped&rule=php">Аудит PHP по веткам →</Link></li>
            <li><Link to="/hosts?activity=inactive">Компьютеры без связи с KSC →</Link></li>
            <li><Link to="/vulnerabilities">Уязвимости, подтверждённые KSC →</Link></li>
          </ul>
        </div>
        <div className="card planned">
          <h2>В следующих выпусках</h2>
          <p className="muted small">Показатели уязвимостей и состояния защиты появятся на главной после реализации соответствующих модулей.</p>
        </div>
      </div>
    </section>
  );
}
