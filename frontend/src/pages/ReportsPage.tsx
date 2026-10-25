import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, type ApiError, type AuditParams, type Job, type ReportParams, type SavedCheck, type VersionOp } from "../api";
import { NoSource, type Ctx } from "../App";
import { Fetched } from "../components/Common";
import { ListFoot, VirtualRows, useInfinite, type Chunk } from "../components/Infinite";
import { ConfirmDialog } from "../components/Dialogs";
import { Icon } from "../components/Icons";
import { useToast } from "../components/Toast";
import { Empty, PageHead, SkelRows, SortTh, Spectrum, MaskHint } from "../components/ui";
import { fmt, num } from "../util";
import { QuickReportPanel } from "../components/QuickReport";
import { ZonePicker } from "../components/ZoneBits";
import { DEFAULT_ZONE_CATS } from "./zoneCats";
import { AuditBuilder, AuditResult, draftFromItem, emptyDraft, itemSummary, type Draft, type PreviewState } from "./AuditBuilder";
import { JOB_STATUS } from "./DashboardPage";
import { getSelection, selLabel } from "../selection";

/** Описание условий отчёта одной строкой (проверка версий и отчёты прежнего вида 0.1.0). */
export function describe(p: Record<string, unknown>): string {
  if (Array.isArray(p.items)) return (p.items as Parameters<typeof itemSummary>[0][]).map(itemSummary).join("; ");
  const parts: string[] = [];
  const n = (k: string) => (Array.isArray(p[k]) ? (p[k] as unknown[]).length : 0);
  if (n("cves")) parts.push(`CVE: ${(p.cves as string[]).slice(0, 3).join(", ")}${n("cves") > 3 ? "…" : ""}`);
  if (n("descr_ids")) parts.push(`уязвимостей: ${n("descr_ids")}`);
  if (n("vp_ids") || n("product_names")) parts.push(`программ: ${n("vp_ids") + n("product_names")}`);
  if (n("host_ids")) parts.push(`компьютеров: ${n("host_ids")}`);
  if (n("event_ids")) parts.push(`событий: ${n("event_ids")}`);
  if (n("zone_ids")) parts.push(`зон: ${n("zone_ids")}`);
  if (typeof p.zone === "string" && p.zone) parts.push("зона");
  if (typeof p.problem === "string" && p.problem) parts.push(`проблема: ${p.problem}`);
  if (p.online_only) parts.push("только в сети");
  if (p.rule) parts.push(`правило «${p.rule}»`);
  if (Array.isArray(p.branches) && p.branches.length) parts.push(`ветки ${p.branches.map((b) => b || "не определена").join(", ")}`);
  if (Array.isArray(p.product_ids) && p.product_ids.length) parts.push(`записей реестра: ${p.product_ids.length}`);
  if (p.name_like) parts.push(`название ${p.name_like}`);
  const v = [p.min_version ? `≥ ${p.min_version}` : "", p.max_version ? `≤ ${p.max_version}` : "", p.below_version ? `< ${p.below_version}` : ""].filter(Boolean).join(", ");
  if (v) parts.push(`версия ${v}`);
  if (p.inactive_only) parts.push("только без связи"); else if (p.include_inactive) parts.push("включая без связи"); else if (p.active_days) parts.push(`связь за ${p.active_days} сут`);
  return parts.join("; ") || "—";
}

export default function ReportsPage({ ctx }: { ctx: Ctx }) {
  const { jobId } = useParams();
  if (!ctx.current && !jobId) return <NoSource ctx={ctx} />;
  return jobId ? <JobView ctx={ctx} jobId={jobId} /> : <ReportsHome ctx={ctx} />;
}

type Initial = { items: Draft[]; sources?: string[]; name?: string; params?: Partial<AuditParams> } | null;

function initialFromUrl(sp: URLSearchParams, source: string): Initial {
  if (sp.get("sel")) {   // выбранные в каталоге программы: семейство — один пункт из нескольких продуктов
    const sel = getSelection(source);
    if (sel.length) return { items: sel.map((e) => emptyDraft({ product: { key: e.key, name: e.name, latest_version: e.latest_version }, family: e.family && e.family.length > 1 ? e.family : [] })),
      name: `Проверка: ${sel.map(selLabel).join(", ")}`.slice(0, 200) };
  }
  const key = sp.get("product");
  if (!key) return null;
  const op = (sp.get("op") as VersionOp) || "lt";
  return { items: [emptyDraft({ product: { key, name: sp.get("name") ?? key, latest_version: sp.get("latest") ?? undefined }, op, value: sp.get("value") ?? "", open: op !== "lt" })], name: sp.get("name") ? `${sp.get("name")}: проверка версий` : undefined };
}

function ReportsHome({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const navigate = useNavigate();
  const [checks, setChecks] = useState<SavedCheck[] | null>(null);
  const [jobs, setJobs] = useState<Job[] | null>(null);
  const [editing, setEditing] = useState<SavedCheck | null>(null);
  const [builderKey, setBuilderKey] = useState(0);
  const [initial, setInitial] = useState<Initial>(() => initialFromUrl(sp, ctx.current?.id ?? ""));
  const [delJob, setDelJob] = useState<Job | null>(null);
  const [delCheck, setDelCheck] = useState<SavedCheck | null>(null);
  const [allSources, setAllSources] = useState(false);
  const [zonePick, setZonePick] = useState(false); const [zoneIds, setZoneIds] = useState<string[] | null>(null);
  const [preview, setPreview] = useState<PreviewState>(null);
  const [toast, show] = useToast();
  const canEdit = ctx.me.user.role !== "viewer";
  const loadJobs = useCallback(() => { api.reports.list(!allSources).then((r) => setJobs(r.items)).catch(() => setJobs([])); }, [allSources]);
  const loadChecks = useCallback(() => { api.checks.list().then((r) => setChecks(r.items)).catch(() => setChecks([])); }, []);
  useEffect(() => { loadJobs(); }, [loadJobs]);
  useEffect(() => { loadChecks(); }, [loadChecks]);
  useEffect(() => { if (!jobs?.some((j) => j.status === "queued" || j.status === "running")) return; const t = window.setInterval(loadJobs, 3000); return () => window.clearInterval(t); }, [jobs, loadJobs]);
  const checkId = sp.get("check");
  useEffect(() => { // открыть сохранённую проверку для изменения (?check=…)
    if (!checkId || !checks) return;
    const c = checks.find((x) => x.id === checkId);
    if (c?.params && editing?.id !== c.id) { setEditing(c); setInitial({ items: c.params.items.map(draftFromItem), sources: c.source_ids, name: c.name, params: c.params }); setBuilderKey((k) => k + 1); }
  }, [checkId, checks, editing?.id]);
  // отчёт по выбранным записям реестра (раздел «Программы → Реестр KSC»)
  const legacy = useMemo<ReportParams | null>(() => { try { return sp.get("kind") === "software_hosts" && sp.get("params") ? JSON.parse(sp.get("params") as string) as ReportParams : null; } catch { return null; } }, [sp]);
  const runCheck = async (c: SavedCheck) => { try { const j = await api.checks.run(c.id); navigate(`/reports/${j.id}`, { state: { toast: `Проверка «${c.name}» запущена` } }); } catch (e) { show((e as ApiError).message, "error"); } };
  const editCheck = (c: SavedCheck) => { setSp((p) => { p.set("check", c.id); p.delete("product"); return p; }); window.scrollTo({ top: 0, behavior: "smooth" }); };
  const newCheck = () => { setPreview(null); setEditing(null); setInitial(null); setSp(new URLSearchParams()); setBuilderKey((k) => k + 1); };
  const quick = async (params: ReportParams, title: string) => { try { const j = await api.reports.create("hosts", title, params); navigate(`/reports/${j.id}`, { state: { toast: `Отчёт «${title}» поставлен в очередь` } }); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <section>
      <PageHead title="Отчёты" lede="Программа и версия, ниже которой она устарела, — компьютеры сразу и отчёт XLSX. Сохранённые проверки запускаются одним щелчком.">
        {(editing || initial) && <button className="btn ghost" onClick={newCheck}><Icon name="plus" />Новая проверка</button>}
      </PageHead>
      {legacy && (
        <div className="alert info"><Icon name="info" /><div className="alert-body">Выбрано записей реестра KSC: <b>{legacy.product_ids?.length ?? 0}</b>. Сформировать отчёт «Компьютеры с программами» по ним?</div>
          <button className="btn mini primary" disabled={!canEdit} onClick={async () => { try { const j = await api.reports.create("software_hosts", sp.get("title") ?? "", legacy); navigate(`/reports/${j.id}`, { state: { toast: "Отчёт поставлен в очередь" } }); } catch (e) { show((e as ApiError).message, "error"); } }}>Сформировать</button>
          <button className="btn mini ghost" onClick={() => setSp(new URLSearchParams())}>Отмена</button></div>)}
      <div className="split">
        <AuditBuilder key={builderKey} ctx={ctx} initial={initial} editing={editing} onSaved={(c) => { loadChecks(); setEditing(c); }} onResult={setPreview} />
        <div className="stack">
          <div className="card flush">
            <div className="card-head"><h2>Сохранённые проверки</h2>{checks && <span className="count">{num(checks.length)}</span>}</div>
            {!checks ? <SkelRows rows={3} cols={2} /> : !checks.length ? (
              <p className="muted small pad">Настройте проверку слева и нажмите «Сохранить проверку» — она появится здесь и будет запускаться одним щелчком.</p>
            ) : (
              <ul className="check-list">
                {checks.map((c) => (
                  <li key={c.id} className={editing?.id === c.id ? "on" : ""}>
                    <div className="cl-main"><b>{c.name}</b>
                      <span className="sub">{c.kind === "legacy" ? `Сценарий 0.1.0: ${describe((c.selection ?? {}) as Record<string, unknown>)}` : (c.params?.items ?? []).map(itemSummary).join("; ")}</span>
                      <span className="sub">{c.source_names.join(", ")}{c.last_run_at ? ` · запускалась ${fmt(c.last_run_at)}` : ""}</span></div>
                    <div className="cl-actions">
                      {canEdit && <button className="btn mini primary" onClick={() => runCheck(c)}><Icon name="play" size={14} />Запустить</button>}
                      {c.last_job_id && <Link className="btn mini ghost" to={`/reports/${c.last_job_id}`}>Последний отчёт</Link>}
                      {canEdit && c.kind !== "legacy" && <button className="btn mini ghost icon" onClick={() => editCheck(c)} aria-label={`Изменить проверку ${c.name}`}><Icon name="edit" size={15} /></button>}
                      {canEdit && (c.owner_id === ctx.me.user.id || !c.owner_id || ctx.me.user.is_admin) && <button className="btn mini ghost danger icon" onClick={() => setDelCheck(c)} aria-label={`Удалить проверку ${c.name}`}><Icon name="trash" size={15} /></button>}
                    </div>
                  </li>))}
              </ul>)}
          </div>
          <div className="card">
            <h2>Другие отчёты</h2>
            <button type="button" className="action-row" disabled={!canEdit} onClick={() => quick({ inactive_only: true, include_inactive: true }, "Компьютеры без связи с KSC")}>
              <span className="a-ic"><Icon name="clock" /></span><span className="a-main"><b>Компьютеры без связи с KSC</b><span>Агент не подключался дольше {ctx.me.activity_days} сут</span></span><Icon name="chevronR" className="a-go" /></button>
            <button type="button" className="action-row" disabled={!canEdit} onClick={() => setZonePick(true)}>
              <span className="a-ic"><Icon name="grid" /></span><span className="a-main"><b>Состояние безопасности зоны</b><span>Сводка, проблемные компьютеры и подробности по выбранным зонам</span></span><Icon name="chevronR" className="a-go" /></button>
            <button type="button" className="action-row" disabled={!canEdit} onClick={() => quick({}, "Активные компьютеры")}>
              <span className="a-ic"><Icon name="monitor" /></span><span className="a-main"><b>Активные компьютеры</b><span>Имя, IP, ОС, группа, последнее подключение</span></span><Icon name="chevronR" className="a-go" /></button>
          </div>
        </div>
      </div>

      {preview && <AuditResult id="audit-result" result={preview.result} multi={preview.multi} onXlsx={preview.xlsx} />}

      <div className="section-head"><h2>Сформированные отчёты</h2>{jobs && <span className="count">{num(jobs.length)}</span>}<div className="spacer" />
        {ctx.sources.length > 1 && <label className="check inline-check"><input type="checkbox" className="switch" checked={allSources} onChange={(e) => setAllSources(e.target.checked)} />Все источники</label>}</div>
      <JobsTable jobs={jobs} canEdit={canEdit} onChanged={loadJobs} onDelete={setDelJob} show={show} />
      {delJob && <ConfirmDialog title="Удалить отчёт?" confirmLabel="Удалить отчёт" body={<p>Файлы отчёта «{delJob.title}» будут удалены без возможности восстановления.</p>} onClose={() => setDelJob(null)} onConfirm={async () => { await api.reports.remove(delJob.id); loadJobs(); }} />}
      {delCheck && <ConfirmDialog title="Удалить проверку?" confirmLabel="Удалить" body={<p>Проверка «{delCheck.name}» будет удалена. Сформированные по ней отчёты останутся.</p>} onClose={() => setDelCheck(null)}
        onConfirm={async () => { await api.checks.remove(delCheck.id); if (editing?.id === delCheck.id) newCheck(); loadChecks(); }} />}
      {zonePick && <ZonePicker onClose={() => setZonePick(false)} onPick={(ids) => { setZonePick(false); setZoneIds(ids); }} />}
      {zoneIds && <QuickReportPanel kind="quick_zone" title="Состояние безопасности зон" lede="Тот же отчёт, что отправляется по расписанию" options={{ zone: true }} activityDays={ctx.me.activity_days} canReport={canEdit}
        params={{ zone_ids: zoneIds, categories: DEFAULT_ZONE_CATS, level: "management" }} onClose={() => { setZoneIds(null); loadJobs(); }} />}
      {toast}
    </section>
  );
}

function JobsTable({ jobs, canEdit, onChanged, onDelete, show }: { jobs: Job[] | null; canEdit: boolean; onChanged: () => void; onDelete: (j: Job) => void; show: (t: string, tone?: "ok" | "error") => void }) {
  return (
    <div className="table-scroll">
      {!jobs ? <SkelRows rows={4} cols={5} /> : (
        <table className="table">
          <thead><tr><th>Отчёт</th><th>Состояние</th><th className="num">Строк</th><th>Автор</th><th>Создан</th><th><span className="sr-only">Действия</span></th></tr></thead>
          <tbody>{jobs.map((j) => { const [l, c] = JOB_STATUS[j.status] ?? [j.status, ""]; return (
            <tr key={j.id}><td><Link to={`/reports/${j.id}`} className="strong-link">{j.title}</Link><span className="sub">{j.source_name} · {describe(j.params as Record<string, unknown>)}</span></td>
              <td><span className={`badge ${c}`}>{j.status === "running" && <span className="spin sm" />}{l}</span>{j.status === "running" && j.progress && <span className="sub">{j.progress}</span>}{j.error && <span className="sub bad-text">{j.error}</span>}</td>
              <td className="num">{num(j.rows)}</td><td className="small">{j.created_by}</td><td className="nowrap small">{fmt(j.created_at)}</td>
              <td className="actions">
                {j.status === "done" && <><a className="btn mini" href={api.reports.downloadUrl(j.id, "xlsx")}><Icon name="download" size={15} />XLSX</a>{(j.kind.startsWith("quick_") || j.kind === "version_audit") && <a className="btn mini ghost" href={api.reports.downloadUrl(j.id, "html")}>HTML</a>}<a className="btn mini ghost" href={api.reports.downloadUrl(j.id, "csv")}>CSV</a></>}
                {canEdit && (j.status === "queued" || j.status === "running") && <button className="btn mini ghost" onClick={async () => { await api.reports.cancel(j.id); onChanged(); show("Формирование отменяется"); }}><Icon name="stop" size={14} />Отменить</button>}
                {canEdit && j.status !== "running" && j.status !== "queued" && <><button className="btn mini ghost icon" title="Повторить с теми же условиями" aria-label={`Повторить отчёт ${j.title}`} onClick={async () => { await api.reports.rerun(j.id); onChanged(); show("Отчёт поставлен в очередь"); }}><Icon name="refresh" size={15} /></button>
                  <button className="btn mini ghost danger icon" aria-label={`Удалить отчёт ${j.title}`} onClick={() => onDelete(j)}><Icon name="trash" size={15} /></button></>}</td></tr>); })}
            {!jobs.length && <tr><td colSpan={6}><Empty icon="file" title="Отчётов ещё нет">Настройте проверку выше и нажмите «Сформировать XLSX» или запустите сохранённую проверку.</Empty></td></tr>}
          </tbody>
        </table>)}
    </div>
  );
}

const AUDIT_COLS: [string, string, string?][] = [["source", "Источник"], ["program", "Программа"], ["product", "Продукт"], ["app_version", "Установлена", "mono nowrap"], ["target_version", "Целевая версия", "mono nowrap"], ["name", "Компьютер"],
  ["ip", "IP-адрес", "mono"], ["os", "ОС"], ["last_connected", "Подключение к KSC"], ["group", "Группа"]];
const SOFT_COLS: [string, string, string?][] = [["name", "Компьютер"], ["ip", "IP-адрес", "mono"], ["os", "ОС"], ["app_name", "Программа"], ["app_version", "Версия", "mono"], ["branch", "Ветка", "mono"], ["group", "Группа"], ["last_connected", "Подключение к KSC"], ["activity", "Связь"]];
const HOST_COLS: [string, string, string?][] = [["name", "Компьютер"], ["ip", "IP-адрес", "mono"], ["os", "ОС"], ["group", "Группа"], ["last_connected", "Подключение к KSC"], ["days_since_connection", "Суток без связи"], ["activity", "Связь"]];

function JobView({ ctx, jobId }: { ctx: Ctx; jobId: string }) {
  const [j, setJ] = useState<Job | null>(null);
  const [q, setQ] = useState(""); const [applied, setApplied] = useState("");
  const [source, setSource] = useState(""); const [program, setProgram] = useState("");
  const [sort, setSort] = useState(""); const [desc, setDesc] = useState(false);
  const [err, setErr] = useState("");
  const [toast, show] = useToast();
  const navigate = useNavigate();
  const location = useLocation();
  // уведомление о запуске приходит вместе с переходом: страница, где нажали кнопку, к этому моменту уже закрыта
  useEffect(() => {
    const t = (location.state as { toast?: string } | null)?.toast;
    if (t) { show(t); navigate(location.pathname, { replace: true, state: null }); }
  }, [location.key]); // eslint-disable-line react-hooks/exhaustive-deps
  const load = useCallback(() => api.reports.get(jobId).then(setJ).catch((e) => setErr((e as ApiError).message)), [jobId]);
  useEffect(() => { setJ(null); void load(); }, [load]);
  useEffect(() => { if (!j || (j.status !== "queued" && j.status !== "running")) return; const t = window.setInterval(load, 2000); return () => window.clearInterval(t); }, [j, load]);
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 300); return () => window.clearTimeout(t); }, [q]);
  const done = j?.status === "done";
  const rows = useInfinite<Record<string, unknown>>(`job:${jobId}`, [jobId, done, applied, source, program, sort, desc],
    (offset, limit) => (done ? api.reports.rows(jobId, { offset, limit, q: applied, source, program, sort, desc }) as unknown as Promise<Chunk<Record<string, unknown>>> : Promise.resolve({ items: [], total: 0 })), 200);
  const back = <Link className="back-link" to="/reports"><Icon name="arrowL" size={15} />Отчёты</Link>;
  if (err) return <section><PageHead title="Отчёт" back={back} /><div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>{toast}</section>;
  if (!j) return <section><PageHead title={<span className="skel skel-title" />} back={back} /><div className="table-scroll"><SkelRows /></div>{toast}</section>;
  const [l, c] = JOB_STATUS[j.status] ?? [j.status, ""];
  const audit = j.kind === "version_audit";
  const quickJob = j.kind.startsWith("quick_");
  const qcols = (j.summary?.tables?.[0]?.columns ?? []) as { key: string; title: string; type: string }[];
  const dateKeys = new Set(qcols.filter((c) => c.type === "date").map((c) => c.key));
  const multi = (j.source_ids?.length ?? 1) > 1;
  const fam = (j.params.items ?? []).some((it) => (it.product_keys?.length ?? 0) > 1);   // пункт из нескольких продуктов — нужен столбец «Продукт»
  const cols = (quickJob ? qcols.map((c): [string, string, string?] => [c.key, c.title, c.type === "mono" ? "mono nowrap" : c.type === "num" ? "num" : undefined]) : audit ? AUDIT_COLS.filter(([k]) => (multi || k !== "source") && (fam || k !== "product")) : j.kind === "software_hosts" ? SOFT_COLS : HOST_COLS);
  const s = j.summary;
  const s0 = s ?? {} as NonNullable<typeof s>;
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(false); } };
  const canEdit = ctx.me.user.role !== "viewer";
  const filtered = !!(applied || source || program);
  return (
    <section>
      <PageHead title={j.title} back={back} lede={<>{j.source_name} · {quickJob ? (s0.conditions?.map((c) => c.text).join("; ") ?? "") : describe(j.params as Record<string, unknown>)}. Сформировал {j.created_by}, {fmt(j.created_at)}.</>}>
        <span className={`badge ${c}`}>{l}</span>
        {j.data_fetched_at && <Fetched at={j.data_fetched_at} />}
        {j.status === "done" && <><a className="btn primary" href={api.reports.downloadUrl(j.id, "xlsx")}><Icon name="download" />Скачать XLSX</a><a className="btn" href={api.reports.downloadUrl(j.id, "csv")}>CSV</a>{(audit || quickJob) && <a className="btn" href={api.reports.downloadUrl(j.id, "html")}>HTML</a>}</>}
        {canEdit && j.status !== "running" && j.status !== "queued" && <button className="btn ghost" onClick={async () => { const n = await api.reports.rerun(j.id); navigate(`/reports/${n.id}`, { state: { toast: "Отчёт поставлен в очередь" } }); }}><Icon name="refresh" />Повторить</button>}
      </PageHead>
      {(j.status === "running" || j.status === "queued") && (
        <div className="alert info" role="status"><span className="spin accent" />
          <div className="alert-body">{j.status === "queued" ? "Отчёт в очереди: задания выполняются по порядку." : `Формируется: ${j.progress ?? "чтение данных"}.`}</div>
          {canEdit && <button className="btn mini" onClick={async () => { await api.reports.cancel(j.id); void load(); }}><Icon name="stop" size={14} />Отменить</button>}</div>)}
      {j.error && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{j.error}</div></div>}
      {s?.notes?.map((n) => <div key={n} className="alert warn"><Icon name="info" /><div className="alert-body">{n}</div></div>)}
      {audit && s?.programs?.filter((p) => p.explain).map((p) => <div key={p.program} className="alert info"><Icon name="info" /><div className="alert-body"><b>{p.program}:</b> {p.explain}</div></div>)}
      {s && audit && s.programs && (<>
        <div className="meters">
          <div className="meter"><span className="l">Компьютеров требуют обновления</span><span className="v">{num(s.hosts)}</span><span className="t">{multi ? "уникальных в пределах источника" : "уникальных"}</span></div>
          <div className="meter"><span className="l">Установок с устаревшей версией</span><span className="v">{num(s.rows)}</span></div>
          <div className="meter"><span className="l">Источников</span><span className="v">{num(s.sources?.length ?? 1)}</span></div>
          <div className="meter"><span className="l">Не учтено неактивных</span><span className="v">{s.include_inactive ? "—" : num(s.hidden_inactive_hosts ?? 0)}</span><span className="t">{s.include_inactive ? "учтены все устройства" : `без связи дольше ${s.active_days} сут`}</span></div>
        </div>
        <div className="table-scroll">
          <table className="table">
            <thead><tr><th>Программа</th><th>Условие проверки</th><th>Целевая версия</th>{multi && s.sources?.map((x) => <th key={x.source} className="num">{x.source}</th>)}<th className="num">Компьютеров</th></tr></thead>
            <tbody>{s.programs.map((p) => (
              <tr key={p.program} className={`clickable ${program === p.program ? "sel" : ""}`} onClick={() => { setProgram(program === p.program ? "" : p.program); window.requestAnimationFrame(() => document.getElementById("job-rows")?.scrollIntoView({ behavior: "smooth", block: "start" })); }}>
                <td><b>{p.program}</b></td><td className="small">{p.condition}</td><td className="mono small">{p.target_version || "—"}</td>
                {multi && p.by_source.map((b) => <td key={b.source} className="num">{num(b.hosts)}</td>)}<td className="num"><b>{num(p.hosts)}</b></td></tr>))}
            </tbody>
          </table>
        </div>
      </>)}
      {s && quickJob && (<>
        {s.conditions && <dl className="qr-cond job-cond">{s.conditions.map((c) => <div key={c.label}><dt>{c.label}</dt><dd>{c.text}</dd></div>)}</dl>}
        <div className="meters">{(s.metrics ?? []).map((m) => <div key={m.key} className="meter" title={m.hint}><span className="l">{m.label}</span><span className={`v ${m.tone === "danger" ? "bad-text" : ""}`}>{typeof m.value === "number" ? num(m.value) : m.value}</span>{m.hint && <span className="t">{m.hint}</span>}</div>)}</div>
        {s.severity && s.severity.levels.some((l) => l.value > 0) && <div className="qr-sev job-sev" aria-label={s.severity.title}>
          <div className="qr-sev-bar">{s.severity.levels.filter((l) => l.value > 0).map((l) => <span key={l.key} className={`qs-${l.key}`} style={{ flexGrow: l.value }} title={`${l.label}: ${l.value}`} />)}</div>
          <ul className="qr-sev-legend">{s.severity.levels.map((l) => <li key={l.key} className={l.value ? "" : "zero"}><span className={`dot-sev qs-${l.key}`} />{l.label}: <b>{num(l.value)}</b></li>)}</ul>
          <p className="muted small">{s.severity.title}</p></div>}
      </>)}
      {s && !audit && !quickJob && (
        <div className="meters">
          <div className="meter"><span className="l">Строк в отчёте</span><span className="v">{num(s.rows)}</span></div>
          <div className="meter"><span className="l">Уникальных компьютеров</span><span className="v">{num(s.hosts)}</span></div>
          <div className="meter"><span className="l">Исключено без связи</span><span className="v">{s.include_inactive ? "—" : num(s.excluded_inactive_hosts ?? 0)}</span><span className="t">{s.include_inactive ? "включены все компьютеры" : `порог ${s.active_days} сут`}</span></div>
          {s.branches && s.branches.length > 0 && <div className="meter wide"><span className="l">Версии в отчёте</span>
            <Spectrum label="Ветки в отчёте" size="lg" unit=" уст." segs={s.branches.map((b) => ({ key: b.branch, label: b.branch, value: b.installs, undef: b.branch.startsWith("("), note: `${num(b.hosts)} комп.` }))} /></div>}
        </div>
      )}
      {j.status === "done" && (<>
        <div className="section-head" id="job-rows"><h2>{program ? `Компьютеры: ${program}` : "Данные"}</h2>{!rows.initial && <span className="count">{num(rows.total)}</span>}<div className="spacer" />
          {multi && <select className="w-auto" value={source} onChange={(e) => setSource(e.target.value)} aria-label="Источник"><option value="">Все источники</option>{s?.sources?.map((x) => <option key={x.source} value={x.source}>{x.source}</option>)}</select>}
          {audit && (s?.programs?.length ?? 0) > 1 && <select className="w-auto" value={program} onChange={(e) => setProgram(e.target.value)} aria-label="Программа"><option value="">Все программы</option>{s?.programs?.map((p) => <option key={p.program} value={p.program}>{p.program}</option>)}</select>}
          <div className="input-icon w-search"><Icon name="filter" size={15} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Компьютер, IP, ОС, версия" aria-label="Фильтр строк" /><MaskHint /></div></div>
        <div className={`table-scroll ${rows.refreshing && !rows.initial ? "is-busy" : ""}`}>
          {rows.initial ? <SkelRows cols={7} /> : (
            <table className="table compact virt">
              <thead><tr>{cols.map(([k, t]) => <SortTh key={k} k={k} label={t} sort={sort} desc={desc} onSort={onSort} />)}</tr></thead>
              <tbody><VirtualRows list={rows} colSpan={cols.length} estimate={36} row={(r) => <tr>{cols.map(([k, , cls]) => <td key={k} className={`${cls ?? ""} ${k === "last_connected" || k === "ip" ? "nowrap" : ""}`}>
                {k === "name" && !multi && r.host_id ? <Link to={`/hosts/${String(r.host_id)}`}>{String(r[k] ?? "")}</Link> : k === "last_connected" || dateKeys.has(k) ? fmt(r[k] as string) : k === "program" ? <>{String(r[k] ?? "")}{r.app_name !== r.program && <span className="sub">{String(r.app_name ?? "")}</span>}</> : String(r[k] ?? "")}</td>)}</tr>} />
                {!rows.items.length && !rows.loading && <tr><td colSpan={cols.length}><Empty icon={filtered ? "search" : "checkCircle"} title={filtered ? "Ничего не найдено" : audit ? "Устаревших версий не найдено" : "В отчёте нет строк"}>
                  {filtered ? "Измените фильтр." : audit ? "На учтённых компьютерах версий, подходящих под условие, нет." : "По заданным условиям данных не нашлось."}</Empty></td></tr>}
              </tbody>
            </table>)}
        </div>
        <ListFoot list={rows} />
        {audit && <p className="muted small mt-sm">Результат — соответствие заданному условию версии, а не подтверждённая уязвимость. Уязвимости, найденные KSC, — в разделе «Уязвимости».</p>}
      </>)}
      {toast}
    </section>
  );
}
