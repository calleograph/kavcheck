import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type ApiError, type HuntHistoryRow, type Job } from "../api";
import type { Ctx } from "../App";
import { Icon } from "../components/Icons";
import { QuickReportPanel } from "../components/QuickReport";
import { PageHead, Tabs, Empty, SkelRows } from "../components/ui";
import { fmt, num } from "../util";
import { JOB_STATUS } from "./DashboardPage";
import Results from "./hunt/Results";
import Wizard from "./hunt/Wizard";
import { STATUS_TONE } from "./pentest/common";

type Tab = "new" | "results" | "history" | "reports";
const TABS: { id: Tab; label: string }[] = [{ id: "new", label: "Новое задание" }, { id: "results", label: "Результаты" }, { id: "history", label: "История" }, { id: "reports", label: "Отчёты" }];

/** CVE Hunt — целевой поиск: какие компьютеры затронуты конкретной CVE или продуктом. Выполняет сканер Pentest в ускоренном режиме, а также данные KSC; не заменяет полный Pentest. */
export default function HuntPage({ ctx }: { ctx: Ctx }) {
  const [sp] = useSearchParams();
  const nav = useNavigate();
  const tab = (TABS.some((t) => t.id === sp.get("tab")) ? sp.get("tab") : sp.get("job") ? "results" : "new") as Tab;
  const job = sp.get("job");
  const go = useCallback((t: string, extra: Record<string, string> = {}) => { const n = new URLSearchParams(); n.set("tab", t); for (const [k, v] of Object.entries(extra)) n.set(k, v); nav(`/hunt?${n.toString()}`); }, [nav]);
  const prefill = { cves: (sp.get("cve") ?? "").split(",").map((x) => x.trim().toUpperCase()).filter(Boolean),
    product: sp.get("pname") ? { name: sp.get("pname")!, source_id: sp.get("psrc") ?? undefined, product_key: sp.get("pkey") ?? undefined, mode: (sp.get("pmode") as "any" | "below" | "exact" | "range" | "above" | null) ?? "any", below: sp.get("pbelow") ?? "", versions: sp.get("pver") ? sp.get("pver")!.split(",") : [] } : undefined };
  const canReport = ctx.me.user.role !== "viewer";
  return (
    <section>
      <PageHead title="CVE Hunt" lede="Целевой поиск уязвимостей: выберите CVE или программу, область и порты — и получите список компьютеров, которых это может касаться. Это не полный Pentest: проверяется только выбранное." />
      <div className="pt-tabs"><Tabs<Tab> label="Разделы CVE Hunt" value={tab} onChange={(t) => go(t)} items={TABS} /></div>
      {tab === "new" && <Wizard key={sp.toString()} prefill={prefill} onCreated={(id) => go("results", { job: id })} />}
      {tab === "results" && <Results jobId={job} canReport={canReport} admin={ctx.me.user.is_admin} activityDays={ctx.me.activity_days} currentSource={ctx.current?.id ?? null} go={go} />}
      {tab === "history" && <History go={go} />}
      {tab === "reports" && <HuntReports />}
    </section>
  );
}

function History({ go }: { go: (t: string, e?: Record<string, string>) => void }) {
  const [items, setItems] = useState<HuntHistoryRow[] | null>(null); const [err, setErr] = useState(""); const [report, setReport] = useState(false);
  useEffect(() => { api.hunt.jobs({ limit: 100 }).then((r) => setItems(r.items)).catch((e) => setErr((e as ApiError).message)); }, []);
  if (err) return <div className="alert error"><div className="alert-body">{err}</div></div>;
  if (!items) return <SkelRows rows={4} cols={5} />;
  if (!items.length) return <Empty icon="history" title="Целевых проверок пока не было" action={<button className="btn primary" onClick={() => go("new")}>Новое задание</button>}>Здесь сохраняются критерии, область, результаты, журнал и отчёты каждой проверки; любую можно повторить.</Empty>;
  return (<>
    <div className="toolbar"><span className="muted small">{num(items.length)} {items.length === 1 ? "задание" : "заданий"}</span><div className="spacer" />
      <button type="button" className="btn mini" onClick={() => setReport(true)}><Icon name="file" size={15} />Сформировать отчёт</button></div>
    {report && <QuickReportPanel kind="quick_hunt" title="Отчёт: история целевого поиска" lede="Все задания CVE Hunt: итог, находки, ошибки" options={{ scope: false }} params={{ view: "jobs" }} activityDays={0} canReport onClose={() => setReport(false)} />}
    <div className="table-scroll"><table className="table"><thead><tr><th>Задание</th><th>Критерии</th><th>Режим</th><th className="num">Подтверждено</th><th className="num">Вероятно</th><th className="num">Требует проверки</th><th>Состояние</th></tr></thead>
      <tbody>{items.map((j) => (
        <tr key={j.id}><td><button type="button" className="link-btn strong-link" onClick={() => go("results", { job: j.id })}>{j.title}</button><span className="sub small">{j.created_by} · {fmt(j.created_at)}{j.base_job_id ? " · повтор" : ""}</span></td>
          <td className="small">{j.criteria.map((c) => c.title.slice(0, 60)).join("; ")}</td><td className="small">{j.mode === "ksc" ? "KSC" : j.mode === "network" ? "Сеть" : "KSC + сеть"}</td>
          <td className="num">{num(j.counts.confirmed ?? 0)}</td><td className="num">{num(j.counts.probable ?? 0)}</td><td className="num">{num(j.counts.needs_check ?? 0)}</td><td><span className={`badge ${STATUS_TONE[j.status]}`}>{j.status_ru}</span></td></tr>))}</tbody></table></div>
  </>);
}

function HuntReports() {
  const [items, setItems] = useState<Job[] | null>(null); const [err, setErr] = useState("");
  useEffect(() => { api.reports.list(false).then((r) => setItems(r.items.filter((j) => j.kind === "quick_hunt"))).catch((e) => setErr((e as ApiError).message)); }, []);
  if (err) return <div className="alert error"><div className="alert-body">{err}</div></div>;
  if (!items) return <SkelRows rows={4} cols={4} />;
  if (!items.length) return <Empty icon="file" title="Отчётов целевого поиска пока нет">Откройте результаты проверки и нажмите «Сформировать отчёт»: HTML для руководства, PDF, Excel и CSV. По умолчанию в отчёт входят подтверждённые и вероятные совпадения.</Empty>;
  return (
    <div className="table-scroll"><table className="table"><thead><tr><th>Отчёт</th><th>Состояние</th><th className="num">Строк</th><th>Создан</th><th>Файлы</th></tr></thead>
      <tbody>{items.map((j) => { const [l, c] = JOB_STATUS[j.status] ?? [j.status, ""]; return (
        <tr key={j.id}><td><Link to={`/reports/${j.id}`} className="strong-link">{j.title}</Link><span className="sub small">{j.created_by}</span></td><td><span className={`badge ${c}`}>{l}</span></td><td className="num">{j.rows != null ? num(j.rows) : "—"}</td><td className="small nowrap">{fmt(j.created_at)}</td>
          <td>{j.status === "done" ? (["html", "pdf", "xlsx", "csv"] as const).map((f) => <a key={f} className="btn mini ghost" href={api.reports.downloadUrl(j.id, f)} download>{f.toUpperCase()}</a>) : "—"}</td></tr>); })}</tbody></table></div>
  );
}
