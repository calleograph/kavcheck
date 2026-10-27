import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type Job, type OvLicenseGroup, type OvMetric, type Overview } from "../api";
import { NoSource, type Ctx } from "../App";
import { HBars, Trend } from "../components/Charts";
import { ReportButton } from "../components/FilterBar";
import { HostsDrawer, type DrawerHost } from "../components/HostsDrawer";
import { Icon } from "../components/Icons";
import type { Chunk } from "../components/Infinite";
import { QuickReportPanel } from "../components/QuickReport";
import { PageHead, Segmented, Spectrum } from "../components/ui";
import { fmt, fmtDate, num } from "../util";

export const JOB_STATUS: Record<string, [string, string]> = { queued: ["в очереди", ""], running: ["формируется", "accent"], done: ["готов", "ok"], failed: ["ошибка", "err"], cancelled: ["отменён", "warn"] };

const PERIODS = [7, 30, 60, 90];
const NO_DATA = <span className="empty-v">Нет данных</span>;
const pct = (n: number, of: number) => (of > 0 ? `${Math.round((n / of) * 100)}%` : "—");

interface Row { key: string; label: string; value: number | null; metric?: OvMetric; hint?: string; tone?: "bad" | "warn" | "ok"; to?: string; text?: string }

/** Показатель в карточке: число открывает боковую панель с устройствами, ссылка — раздел; нет достоверных данных — «Нет данных». */
function KpiRow({ r, onOpen, big, loading }: { r: Row; onOpen: (m: OvMetric, label: string) => void; big?: boolean; loading?: boolean }) {
  const val = r.text ?? (r.value === null ? null : num(r.value));
  const body = (
    <>
      <span className="kpi-l">{r.label}{r.hint && <span className="kpi-h">{r.hint}</span>}</span>
      <span className={`kpi-v ${r.tone ? `t-${r.tone}` : ""} ${r.value === 0 && r.tone ? "zero" : ""}`}>{val === null ? (loading ? <span className="skel skel-v" /> : NO_DATA) : val}</span>
    </>
  );
  if (r.metric && r.value) return <li><button type="button" className={`kpi ${big ? "kpi-big" : ""}`} onClick={() => onOpen(r.metric!, r.label)} aria-label={`${r.label}: ${val}. Показать устройства`}>{body}</button></li>;
  if (r.to && r.value !== null) return <li><Link className={`kpi ${big ? "kpi-big" : ""}`} to={r.to}>{body}</Link></li>;
  return <li><div className={`kpi static ${big ? "kpi-big" : ""}`}>{body}</div></li>;
}

function KpiCard({ title, sub, rows, onOpen, children, big, loading }: { title: string; sub?: string; rows: Row[]; onOpen: (m: OvMetric, label: string) => void; children?: React.ReactNode; big?: boolean; loading?: boolean }) {
  return (
    <section className="ov-card" aria-label={title}>
      <header className="ov-head"><h2>{title}</h2>{sub && <span>{sub}</span>}</header>
      <ul className="kpi-list">{rows.map((r, i) => <KpiRow key={r.key} r={r} onOpen={onOpen} big={big && i === 0} loading={loading} />)}</ul>
      {children}
    </section>
  );
}

const STATE_RU: Record<OvLicenseGroup["state"], string> = { active: "действует", expiring: "скоро истекает", expired: "истекла", unknown: "срок не указан" };

export default function DashboardPage({ ctx }: { ctx: Ctx }) {
  const [days, setDays] = useState<number>(() => { try { const v = Number(localStorage.getItem("kc:ov-days")); return PERIODS.includes(v) ? v : 30; } catch { return 30; } });
  const [d, setD] = useState<Overview | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [panel, setPanel] = useState<{ metric: OvMetric; title: string } | null>(null);
  const [report, setReport] = useState<{ metric?: OvMetric } | null>(null);
  const [recent, setRecent] = useState<Job[]>([]);
  const canReport = ctx.me.user.role !== "viewer";
  const load = useCallback(async (refresh = false) => {
    if (!ctx.current) return;
    setBusy(true);
    try { setD(await api.overview(days, refresh)); setErr(""); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); }
  }, [ctx.current, days]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { api.reports.list(!ctx.all).then((r) => setRecent(r.items.slice(0, 4))).catch(() => setRecent([])); }, [ctx.all]);
  const pick = (v: number) => { setDays(v); try { localStorage.setItem("kc:ov-days", String(v)); } catch { /* не запомнится */ } };
  const open = useCallback((metric: OvMetric, title: string) => setPanel({ metric, title }), []);
  const multi = ctx.all;
  const t = d?.totals ?? null;
  const sec = d?.security;
  const lic = d?.licenses.totals;
  const eol = sec?.eol;

  const infra: Row[] = useMemo(() => [
    { key: "active", label: `Активные за ${days} сут`, value: t ? t.active : null, metric: "active", hint: "Агент выходил на связь с KSC" },
    { key: "servers", label: "Активные серверы", value: t ? t.servers : null, metric: "servers" },
    { key: "workstations", label: "Активные рабочие станции", value: t ? t.workstations : null, metric: "workstations" },
    ...(t && t.other_os > 0 ? [{ key: "other", label: "Тип ОС не определён", value: t.other_os, metric: "other_os" as OvMetric }] : []),
    { key: "inactive", label: "Неактивные компьютеры", value: t ? t.inactive : null, metric: "inactive", tone: "warn" as const },
    { key: "total", label: "Всего объектов в KSC", value: t ? t.total : null, metric: "total" },
  ], [t, days]);
  const prot: Row[] = [
    { key: "protected", label: "Защищены", value: t ? t.protected : null, metric: "protected", tone: "ok" },
    { key: "av", label: "Защита установлена", value: t ? t.av_installed : null, metric: "av_installed" },
    { key: "noav", label: "Без защиты", value: t ? t.no_av : null, metric: "no_av", tone: "bad" },
    { key: "rtp", label: "Защита не работает", value: t ? t.rtp_off : null, metric: "rtp_off", tone: "bad" },
    { key: "bases", label: "Устаревшие базы", value: t ? t.bases_old : null, metric: "bases_old", tone: "warn" },
    { key: "stale", label: "Давно нет сведений", value: t ? t.stale_info : null, metric: "stale_info", tone: "warn" },
  ];
  const secRows: Row[] = [
    { key: "vulns", label: "Критические уязвимости", value: sec?.vulns ?? null, to: "/vulnerabilities", tone: sec?.vulns ? "bad" : undefined, hint: "найдены KSC" },
    { key: "vhosts", label: "Устройства с критическими", value: sec?.hosts_crit ?? null, metric: "crit_vuln", tone: sec?.hosts_crit ? "bad" : undefined, hint: sec?.ext_crit_hosts ? `+${num(sec.ext_crit_hosts)} по внешним базам` : undefined },
    { key: "eolos", label: "Устаревшие ОС (EOL)", value: eol && !eol.excluded && eol.os_devices !== undefined ? eol.os_devices : null, metric: "eol_os", tone: eol?.os_devices ? "bad" : undefined, hint: eol?.os_items ? `версий ОС: ${num(eol.os_items)}` : undefined },
    { key: "eolapp", label: "Программы без поддержки", value: eol && !eol.excluded && eol.app_items !== undefined ? eol.app_items : null, to: "/eol", tone: eol?.app_items ? "warn" : undefined, hint: "продуктов и версий" },
    { key: "pentest", label: "Результаты Pentest", value: d?.pentest ? d.pentest.jobs : null, to: "/pentest", hint: d?.pentest ? `находок: ${num(d.pentest.findings)}${d.pentest.confirmed ? `, подтверждено: ${num(d.pentest.confirmed)}` : ""}` : undefined },
  ];

  if (!ctx.current) return <NoSource ctx={ctx} />;
  const okSources = d?.sources.filter((s) => !s.duplicate_of) ?? [];
  const lede = (
    <span className="src-line">
      {multi ? <b>Все источники · {d ? d.scope.sources : ctx.sources.length}</b> : <b>{ctx.current.name}</b>}
      {d?.generated_at && <span>Показатели на {fmt(d.generated_at)}</span>}
    </span>
  );
  const structure = t ? [
    { key: "servers", label: "Серверы", value: t.servers },
    { key: "workstations", label: "Рабочие станции", value: t.workstations },
    { key: "other_os", label: "Тип не определён", value: t.other_os },
    { key: "inactive", label: "Неактивные", value: t.inactive, tone: "muted" as const },
  ] : [];
  const periodBars = d?.periods.map((p) => ({ key: String(p.days), label: `${p.days} дней`, value: p.connected, tone: p.days === days ? "protection" : "none", hint: `${num(p.connected)} подключались к KSC за ${p.days} сут` })) ?? [];
  const protBars = t ? [
    { key: "protected", label: "Защищены", value: t.protected, tone: "ok" }, { key: "rtp_off", label: "Защита не работает", value: t.rtp_off, tone: "critical" },
    { key: "bases_old", label: "Устаревшие базы", value: t.bases_old, tone: "high" }, { key: "no_av", label: "Без защиты", value: t.no_av, tone: "critical" },
  ] : [];

  return (
    <section className="ov">
      <PageHead title="Главная" lede={lede}>
        <Segmented<string> label="Период активности" value={String(days)} onChange={(v) => pick(Number(v))} options={PERIODS.map((p) => [String(p), `${p} дн.`, `Активные за ${p} суток`] as [string, string, string])} />
        <button className="btn" onClick={() => void load(true)} aria-busy={busy && !!d}><Icon name="refresh" /><span>Обновить</span></button>
        {canReport && <ReportButton onClick={() => setReport({})} title="Сформировать отчёт «Сводка инфраструктуры» с текущим периодом и источниками" />}
      </PageHead>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {d && d.scope.ok === 0 && <div className="alert warn" role="status"><Icon name="alert" /><div className="alert-body">Данные источников сейчас недоступны{d.sources[0]?.error ? `: ${d.sources[0].error}` : ""}. Показатели, которым нужен KSC, не рассчитаны.</div></div>}
      {d && Object.keys(d.scope.duplicates).length > 0 && <div className="alert info" role="status"><Icon name="info" /><div className="alert-body">Подключение к одному и тому же KSC добавлено дважды ({Object.entries(d.scope.duplicates).map(([, o]) => o).join(", ")}): в итоги оно входит один раз.</div></div>}

      <div className="ov-kpis">
        <KpiCard title="Инфраструктура" sub={multi ? "все источники" : undefined} rows={infra} onOpen={open} big loading={!d} />
        <KpiCard title="Антивирусная защита" sub={`среди активных за ${days} сут`} rows={prot} onOpen={open} loading={!d} />
        <section className="ov-card" aria-label="Лицензирование">
          <header className="ov-head"><h2>Лицензирование</h2><span>Kaspersky</span></header>
          {!d ? <div className="stack tight">{[70, 55, 60].map((w) => <span key={w} className="skel skel-text" style={{ width: `${w}%` }} />)}</div> : !lic || lic.groups === 0 ? (
            <div className="ov-empty"><b>Нет данных</b><span>KSC не передал сведения о лицензиях или они ещё не прочитаны.{ctx.me.user.is_admin ? <> Можно <Link to="/admin?tab=licenses">внести лицензии вручную</Link>.</> : " Обратитесь к администратору."}</span></div>
          ) : (
            <>
              <ul className="kpi-list">
                <KpiRow r={{ key: "limit", label: "Всего лицензий", value: lic.limit, hint: lic.shared ? `общих пулов: ${lic.shared}, каждый считается один раз` : undefined }} onOpen={open} big />
                <KpiRow r={{ key: "used", label: "Использовано", value: lic.used, hint: lic.used === null ? "KSC не сообщает использование" : !lic.complete ? "не по всем лицензиям" : undefined }} onOpen={open} />
                <KpiRow r={{ key: "free", label: "Свободно", value: lic.free, tone: lic.free === 0 ? "bad" : undefined, hint: !lic.complete && lic.free !== null ? "по лицензиям с известным использованием" : undefined }} onOpen={open} />
                <KpiRow r={{ key: "exp", label: "Ближайший срок", value: lic.next_expiry || lic.expired ? 0 : null, text: lic.next_expiry ? fmtDate(lic.next_expiry) : lic.expired ? "истёк" : undefined, tone: lic.expired ? "bad" : lic.expiring ? "warn" : undefined, hint: lic.expired ? `истекло: ${lic.expired}` : lic.expiring ? `скоро истекает: ${lic.expiring}` : undefined }} onOpen={open} />
                <KpiRow r={{ key: "share", label: "Доля использования", value: lic.share, text: lic.share === null ? undefined : `${lic.share}%`, tone: lic.share !== null && lic.share >= 95 ? "bad" : lic.share !== null && lic.share >= 85 ? "warn" : undefined }} onOpen={open} />
              </ul>
              {lic.share !== null && <div className="lic-bar" role="img" aria-label={`Использовано ${lic.share}% лицензий`}><i style={{ width: `${Math.min(100, lic.share)}%` }} className={lic.share >= 95 ? "bad" : lic.share >= 85 ? "warn" : ""} /></div>}
              <details className="ov-more">
                <summary>Лицензии по продуктам и источникам ({d!.licenses.groups.length})</summary>
                <div className="table-scroll"><table className="table compact">
                  <thead><tr><th>Продукт</th><th className="num">Лимит</th><th className="num">Занято</th><th>Срок</th><th>Источник</th></tr></thead>
                  <tbody>{d!.licenses.groups.map((g) => (
                    <tr key={g.key}><td>{g.product}{g.shared && <span className="badge accent" title="Общий пул: лимит учтён один раз, использование — сумма по серверам">общий пул</span>}{g.origin.includes("manual") && <span className="badge" title="Внесено администратором вручную">вручную</span>}
                      {g.notes.map((n) => <span key={n} className="sub">{n}</span>)}</td>
                      <td className="num">{g.limit === null ? "—" : num(g.limit)}</td><td className="num">{g.used === null ? "—" : num(g.used)}</td>
                      <td className={`small ${g.state === "expired" ? "bad-text" : g.state === "expiring" ? "warn-text" : ""}`}>{g.expires_at ? fmtDate(g.expires_at) : "—"}<span className="sub">{STATE_RU[g.state]}</span></td>
                      <td className="small">{g.sources.map((s) => s.name).join(", ")}</td></tr>))}</tbody>
                </table></div>
              </details>
            </>)}
        </section>
        <KpiCard title="Безопасность" rows={secRows} onOpen={open} loading={!d}>
          {sec && sec.vulns === null && <p className="ov-note">Данные об уязвимостях появятся после первого расчёта зон (ночью или в «Зонах ответственности»).</p>}
          {eol?.excluded && <p className="ov-note">EOL исключён из аналитики в настройках.</p>}
        </KpiCard>
      </div>

      <div className="ov-charts">
        <section className="ov-card" aria-label="Активность по периодам">
          <header className="ov-head"><h2>Активность по периодам</h2><span>подключались к KSC</span></header>
          {!d ? <span className="skel skel-text" style={{ width: "80%" }} /> : d.periods.length ? <HBars label="Активные компьютеры по периодам" rows={periodBars} selected={String(days)} onSelect={(k) => pick(Number(k))} /> : <p className="trend-empty">Нет данных</p>}
          {t && <p className="ov-foot">Агент установлен на <b>{num(d!.extra?.agent_installed ?? 0)}</b>, защита — на <b>{num(d!.extra?.av_any ?? 0)}</b> из {num(t.total)}: это отдельные признаки.</p>}
        </section>
        <section className="ov-card" aria-label="Структура парка">
          <header className="ov-head"><h2>Структура</h2><span>серверы, станции, неактивные</span></header>
          {t ? <Spectrum label="Структура объектов KSC" segs={structure} onToggle={(k) => open(k as OvMetric, d!.labels[k] ?? k)} unit="" /> : !d ? <span className="skel skel-text" style={{ width: "80%" }} /> : <p className="trend-empty">Нет данных</p>}
        </section>
        <section className="ov-card" aria-label="Состояние защиты">
          <header className="ov-head"><h2>Состояние защиты</h2><span>{t ? `${pct(t.protected, t.active)} активных защищены` : ""}</span></header>
          {t ? <HBars label="Состояние защиты активных компьютеров" rows={protBars} onSelect={(k) => open(k as OvMetric, d!.labels[k] ?? k)} /> : !d ? <span className="skel skel-text" style={{ width: "80%" }} /> : <p className="trend-empty">Нет данных</p>}
        </section>
        <section className="ov-card ov-trend" aria-label="Динамика активности">
          <header className="ov-head"><h2>Динамика активности</h2><span>за {days} сут, по суткам</span></header>
          {d ? <Trend points={d.trend.points} since={d.trend.since} label={`Активные компьютеры за ${days} суток по датам`} /> : <p className="trend-empty">…</p>}
        </section>
      </div>

      <section className="ov-card ov-sources" aria-label="Источники данных">
        <header className="ov-head">
          <h2>Источники данных</h2>
          {ctx.sources.length > 1 && <Segmented<string> label="Источник" value={multi ? "all" : ctx.current.id} onChange={(v) => ctx.setScope(v)} options={[["all", "Все", "Все источники"], ...ctx.sources.map((s) => [s.id, s.name, s.name] as [string, string, string])]} />}
          <span className="spacer" />
          <details className="ov-method">
            <summary>Как считается</summary>
            <div className="ov-method-body">
              <p><b>Активный компьютер</b> — Агент администрирования подключался к Серверу администрирования за выбранный период (поле <code>tmLastNagentConnected</code>). Это единственный признак активности.</p>
              <p>Отдельно и независимо считаются: <b>виден в сети</b> (последняя видимость), <b>Агент установлен</b>, <b>защитный продукт установлен</b>, <b>защита работает</b> (постоянная защита и состояние продукта) и <b>лицензия</b> (по данным KSC). Один признак не подменяет другой.</p>
              <p><b>Сервер / станция</b> — по названию ОС. Linux приходит в KSC как «Linux» без редакции, поэтому такие компьютеры показаны отдельно («тип не определён»).</p>
              <p><b>Лицензии</b>: ключи не хранятся; один ключ на нескольких KSC (общий пул) считается один раз — лимит общий, использование суммируется. Объединить лицензии вручную может администратор.</p>
              {d && <table className="table compact"><caption className="sr-only">Признаки по периодам</caption><thead><tr><th>Период</th><th className="num">Подключались</th><th className="num">Видны в сети</th><th className="num">Защита установлена</th><th className="num">Защита работает</th></tr></thead>
                <tbody>{d.periods.map((p) => <tr key={p.days}><td>{p.days} сут</td><td className="num">{num(p.connected)}</td><td className="num">{num(p.visible)}</td><td className="num">{num(p.av_installed)}</td><td className="num">{num(p.av_running)}</td></tr>)}</tbody></table>}
            </div>
          </details>
        </header>
        <div className="table-scroll"><table className="table compact ov-table">
          <thead><tr><th>Источник</th><th className="num">Всего</th><th className="num">Активные</th><th className="num">Серверы</th><th className="num">Станции</th><th className="num">Защищены</th><th className="num">Без защиты</th><th>Лицензии</th><th>Синхронизация</th></tr></thead>
          <tbody>{!d ? <tr><td colSpan={9}><span className="skel skel-text" style={{ width: "60%" }} /></td></tr> : d.sources.map((s) => {
            const l = s.license;
            return (
              <tr key={s.id} className={s.duplicate_of ? "muted" : ""}>
                <td>{s.duplicate_of ? <b>{s.name}</b> : <button type="button" className="link-btn strong-link" onClick={() => ctx.setScope(s.id)} title="Показать главную для этого источника">{s.name}</button>}{s.ksc_version && <span className="sub">KSC {s.ksc_version}</span>}{s.duplicate_of && <span className="sub">повторное подключение «{s.duplicate_of}»: в итоги не входит</span>}</td>
                {s.error || s.duplicate_of ? <td colSpan={6} className={s.error ? "bad-text small" : "small"}>{s.error ? `Нет данных: ${s.error}` : ""}</td> : (<>
                  <td className="num">{num(s.total ?? null)}</td><td className="num"><b>{num(s.active ?? null)}</b></td><td className="num">{num(s.servers ?? null)}</td><td className="num">{num(s.workstations ?? null)}</td>
                  <td className="num">{num(s.protected ?? null)}</td><td className={`num ${s.no_av ? "bad-text" : ""}`}>{num(s.no_av ?? null)}</td></>)}
                <td className="small">{l && l.limit !== null ? <>{l.used === null ? "—" : num(l.used)} / {num(l.limit)}{l.free !== null && <span className="sub">свободно {num(l.free)}</span>}</> : <span className="muted">нет данных</span>}</td>
                <td className="small nowrap">{s.synced_at ? fmt(s.synced_at) : <span className="muted">—</span>}{s.snapshot && <span className="sub">срез, источник вне выбора</span>}</td>
              </tr>); })}</tbody>
        </table></div>
        {okSources.length > 0 && <p className="ov-foot">Лицензии по источникам показаны раздельно; в карточке «Лицензирование» общие пулы суммируются без двойного счёта.</p>}
      </section>

      {recent.length > 0 && (
        <nav className="ov-recent" aria-label="Последние отчёты"><span className="muted small">Последние отчёты</span>
          {recent.map((r) => { const [l, c] = JOB_STATUS[r.status] ?? [r.status, ""]; return <Link key={r.id} to={`/reports/${r.id}`} className="ov-rep" title={`${l}, ${fmt(r.created_at)}`}><span className={`dot ${c === "ok" ? "ok" : c === "err" ? "bad" : "off"}`} aria-hidden />{r.title}</Link>; })}
          <Link className="small" to="/reports">Все отчёты</Link></nav>)}

      {panel && <HostsDrawer title={panel.title} lede={`${multi ? "Все источники" : ctx.current.name} · ${panel.metric === "total" || panel.metric === "crit_vuln" || panel.metric.startsWith("eol") ? "" : `период ${days} сут`}`.replace(/ · $/, "")}
        listKey={`ov:${panel.metric}`} deps={[panel.metric, days, multi, ctx.current.id]} search="Имя компьютера или адрес" multiSource={multi} activityDays={days}
        sortKeys={{ name: "name", ip: "ip", os: "os", group: "group", last_connected: "last_connected" }}
        fetchPage={async (offset, limit, qy) => {
          const r = await api.overviewHosts(panel.metric, days, offset, limit, qy.q, qy.sort, qy.desc);
          return { items: r.items.map((h) => ({ ...h, source_id: multi ? h.source_id : undefined, source: h.source, days_since_connection: h.days_since_connection ?? undefined })), total: r.total } as unknown as Chunk<DrawerHost>;
        }}
        report={canReport ? { onClick: () => setReport({ metric: panel.metric }) } : null} onClose={() => setPanel(null)} />}
      {report && <QuickReportPanel kind="quick_overview" title={report.metric ? `Сводка: ${d?.labels[report.metric] ?? report.metric}` : "Сводка инфраструктуры"}
        lede="Активные компьютеры, серверы и станции, защита, лицензии и источники данных — с условиями главной страницы" options={{ scope: false }}
        params={{ days, ...(report.metric && !["crit_vuln", "eol_os", "eol_apps"].includes(report.metric) ? { metric: report.metric } : {}) }} sourceIds={multi ? ctx.sources.map((s) => s.id) : [ctx.current.id]}
        activityDays={days} canReport={canReport} onClose={() => setReport(null)} />}
      <p className="sr-only" role="status">{d ? `Активных компьютеров за ${days} суток: ${d.totals?.active ?? "нет данных"}` : "Загрузка"}</p>
    </section>
  );
}
