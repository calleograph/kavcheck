import { FormEvent, useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, type ApiError, type Job, type ReportParams, type SoftwareRow, type Template } from "../api";
import { NoSource, type Ctx } from "../App";
import { Fetched, Pager } from "../components/Common";
import { ConfirmDialog, Modal } from "../components/Dialogs";
import { useToast } from "../components/Toast";
import { fmt, num } from "../util";
import { describe } from "./VulnsPage";

const STATUS: Record<string, [string, string]> = { queued: ["в очереди", ""], running: ["формируется", "accent"], done: ["готов", "ok"], failed: ["ошибка", "err"], cancelled: ["отменён", "warn"] };
const KINDS: [Job["kind"], string][] = [["software_hosts", "Компьютеры с программами (аудит версий)"], ["hosts", "Компьютеры и активность"]];
const DAYS = [1, 3, 7, 14, 30];

export default function ReportsPage({ ctx }: { ctx: Ctx }) {
  const { jobId } = useParams();
  if (!ctx.current) return <NoSource ctx={ctx} />;
  return jobId ? <JobView ctx={ctx} jobId={jobId} /> : <ReportsHome ctx={ctx} />;
}

function parseParams(s: string | null): ReportParams | null { if (!s) return null; try { return JSON.parse(s) as ReportParams; } catch { return null; } }

function ReportsHome({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const navigate = useNavigate();
  const preset = parseParams(sp.get("params"));
  const [kind, setKind] = useState<Job["kind"]>((sp.get("kind") as Job["kind"]) || "software_hosts");
  const [title, setTitle] = useState(sp.get("title") ?? "");
  const [p, setP] = useState<ReportParams>(preset ?? { include_inactive: false });
  const [rules, setRules] = useState<{ key: string; name: string }[]>([]);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [saveTpl, setSaveTpl] = useState(false);
  const [del, setDel] = useState<Job | null>(null);
  const [toast, show] = useToast();
  const canEdit = ctx.me.user.role !== "viewer";
  const load = useCallback(() => { api.reports.list().then((r) => setJobs(r.items)).catch((e) => setErr((e as ApiError).message)); }, []);
  useEffect(() => { load(); api.software.rules().then((r) => setRules(r.items)).catch(() => undefined); api.reports.templates().then((r) => setTemplates(r.items)).catch(() => undefined); }, [load, ctx.current]);
  useEffect(() => { if (!jobs.some((j) => j.status === "queued" || j.status === "running")) return; const t = window.setInterval(load, 3000); return () => window.clearInterval(t); }, [jobs, load]);
  const set = <K extends keyof ReportParams>(k: K, v: ReportParams[K]) => setP((x) => ({ ...x, [k]: v }));
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setErr("");
    try { const j = await api.reports.create(kind, title, p); show("Отчёт поставлен в очередь"); setSp(new URLSearchParams(), { replace: true }); navigate(`/reports/${j.id}`); } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); }
  };
  const applyTemplate = (t: Template) => { setKind(t.kind); setP(t.params); setTitle(t.name); };
  return (
    <section>
      <h1>Отчёты</h1>
      <div className="grid" style={{ gridTemplateColumns: "minmax(0, 1.2fr) minmax(0, .8fr)", alignItems: "start" }}>
        <form className="card form" onSubmit={submit} style={{ margin: 0, maxWidth: "none" }}>
          <h2>Конструктор отчёта</h2>
          <p className="muted small">Источник: <b>{ctx.current!.name}</b>. Отчёт формируется в фоне проверенными запросами; результат доступен для просмотра, сортировки и экспорта в XLSX и CSV.</p>
          <div className="cols">
            <label>Тип отчёта<select value={kind} onChange={(e) => setKind(e.target.value as Job["kind"])} disabled={!canEdit}>{KINDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
            <label>Название<input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="по умолчанию — по типу отчёта" maxLength={300} /></label>
          </div>
          {kind === "software_hosts" && (
            <fieldset className="group"><legend>Программы и версии</legend>
              {p.product_ids?.length ? <div className="alert info">Выбрано записей реестра: {p.product_ids.length} (из раздела «Программное обеспечение»). <button type="button" className="btn mini ghost" onClick={() => set("product_ids", [])}>Очистить</button></div> : null}
              <div className="cols">
                <label>Правило группировки<select value={p.rule ?? ""} onChange={(e) => set("rule", e.target.value || null)}><option value="">— без правила (по шаблону названия) —</option>{rules.map((r) => <option key={r.key} value={r.key}>{r.name}</option>)}</select></label>
                <label>Ветки (через запятую)<input value={(p.branches ?? []).join(", ")} onChange={(e) => set("branches", e.target.value.split(",").map((x) => x.trim()).filter(Boolean))} placeholder="7.4, 8.1 — пусто: все" /></label>
              </div>
              <div className="cols">
                <label>Шаблон названия (SQL LIKE)<input value={p.name_like ?? ""} onChange={(e) => set("name_like", e.target.value || null)} placeholder="%php% — если правило не выбрано" /></label>
                <label>Регулярное выражение по названию<input value={p.name_regex ?? ""} onChange={(e) => set("name_regex", e.target.value || null)} placeholder="^php[0-9]" /></label>
              </div>
              <div className="cols">
                <label>Версия от (≥)<input value={p.min_version ?? ""} onChange={(e) => set("min_version", e.target.value || null)} placeholder="7" /></label>
                <label>Версия до включительно (≤)<input value={p.max_version ?? ""} onChange={(e) => set("max_version", e.target.value || null)} placeholder="7.4.33" /></label>
                <label>Версия ниже (&lt;)<input value={p.below_version ?? ""} onChange={(e) => set("below_version", e.target.value || null)} placeholder="8 — так задаётся «7.x»" /></label>
              </div>
              <span className="help">Версии сравниваются по алгоритму dpkg (8.10 &gt; 8.9), без эпохи и ревизии пакета. Диапазон «7.x» = от 7 и ниже 8.</span>
            </fieldset>
          )}
          <fieldset className="group"><legend>Компьютеры</legend>
            <div className="cols">
              <label>Порог активности, сут<select value={p.active_days ?? ""} onChange={(e) => set("active_days", e.target.value ? Number(e.target.value) : null)}><option value="">по настройке приложения</option>{DAYS.map((d) => <option key={d} value={d}>{d}</option>)}</select></label>
              <label>Платформа пакета<select value={p.platform ?? ""} onChange={(e) => set("platform", e.target.value || null)}><option value="">любая</option><option value="windows">Windows</option><option value="linux">Linux</option></select></label>
              <label>Группа администрирования содержит<input value={p.group_contains ?? ""} onChange={(e) => set("group_contains", e.target.value || null)} /></label>
            </div>
            {kind === "hosts" && <div className="cols"><label>Имя компьютера содержит<input value={p.q ?? ""} onChange={(e) => set("q", e.target.value || null)} /></label><label>ОС содержит<input value={p.os_contains ?? ""} onChange={(e) => set("os_contains", e.target.value || null)} /></label></div>}
            <label className="check"><input type="checkbox" checked={!!p.include_inactive} onChange={(e) => set("include_inactive", e.target.checked)} /> Включать компьютеры без связи с KSC дольше порога (в отчёте указывается, сколько исключено)</label>
            {kind === "hosts" && <label className="check"><input type="checkbox" checked={!!p.inactive_only} onChange={(e) => set("inactive_only", e.target.checked)} /> Только компьютеры без связи дольше порога</label>}
          </fieldset>
          {err && <div className="alert error">{err}</div>}
          <div className="row form-actions">
            <button className="btn primary" disabled={busy || !canEdit}>Сформировать отчёт</button>
            {canEdit && <button type="button" className="btn" onClick={() => setSaveTpl(true)}>Сохранить как шаблон</button>}
            {!canEdit && <span className="muted small">Формирование отчётов доступно аналитикам и администраторам.</span>}
          </div>
        </form>
        <div className="card">
          <h2>Шаблоны</h2>
          {!templates.length ? <p className="muted small">Сохранённых шаблонов нет.</p> : (
            <ul className="plain">{templates.map((t) => <li key={t.id} className="row tight"><button className="cell-link" onClick={() => applyTemplate(t)}>{t.name}</button><span className="muted small">{KINDS.find(([k]) => k === t.kind)?.[1]}</span><div className="spacer" />{(t.owner_id === ctx.me.user.id || ctx.me.user.is_admin) && <button className="btn mini ghost danger" onClick={async () => { await api.reports.deleteTemplate(t.id); setTemplates((x) => x.filter((y) => y.id !== t.id)); }}>✕</button>}</li>)}</ul>)}
          <h2 style={{ marginTop: 14 }}>Готовые сценарии</h2>
          <ul className="plain">
            <li><button className="cell-link" onClick={() => { setKind("software_hosts"); setP({ rule: "php", include_inactive: false }); setTitle("Аудит PHP: все ветки"); }}>Аудит PHP: все ветки, активные компьютеры</button></li>
            <li><button className="cell-link" onClick={() => { setKind("software_hosts"); setP({ rule: "php", min_version: "7", below_version: "8", include_inactive: false }); setTitle("Аудит PHP 7.x"); }}>Аудит PHP 7.x</button></li>
            <li><button className="cell-link" onClick={() => { setKind("hosts"); setP({ inactive_only: true, include_inactive: true }); setTitle("Компьютеры без связи с KSC"); }}>Компьютеры без связи с KSC</button></li>
          </ul>
        </div>
      </div>
      <h2 style={{ margin: "20px 0 6px" }}>Сформированные отчёты</h2>
      <div className="table-scroll"><table className="table compact">
        <thead><tr><th>Отчёт</th><th>Источник</th><th>Состояние</th><th className="num">Строк</th><th>Автор</th><th>Создан</th><th /></tr></thead>
        <tbody>{jobs.map((j) => { const [l, c] = STATUS[j.status] ?? [j.status, ""]; return (
          <tr key={j.id}><td><Link to={`/reports/${j.id}`}>{j.title}</Link><div className="small muted">{describe(j.params as Record<string, unknown>)}</div></td><td>{j.source_name}</td>
            <td><span className={`badge ${c}`}>{l}</span>{j.status === "running" && j.progress && <div className="small muted">{j.progress}</div>}{j.error && <div className="small bad-text">{j.error}</div>}</td>
            <td className="num">{num(j.rows)}</td><td>{j.created_by}</td><td className="nowrap">{fmt(j.created_at)}</td>
            <td className="actions">{j.status === "done" && <><a className="btn mini" href={api.reports.downloadUrl(j.id, "xlsx")}>XLSX</a> <a className="btn mini" href={api.reports.downloadUrl(j.id, "csv")}>CSV</a> </>}
              {canEdit && (j.status === "queued" || j.status === "running") && <button className="btn mini ghost" onClick={async () => { await api.reports.cancel(j.id); load(); }}>Отменить</button>}
              {canEdit && j.status !== "running" && j.status !== "queued" && <> <button className="btn mini ghost" onClick={async () => { await api.reports.rerun(j.id); load(); }}>Повторить</button> <button className="btn mini ghost danger" onClick={() => setDel(j)}>Удалить</button></>}</td></tr>); })}
          {!jobs.length && <tr><td colSpan={7} className="empty">Отчётов по этому источнику пока нет.</td></tr>}
        </tbody>
      </table></div>
      {saveTpl && <SaveTemplate kind={kind} params={p} defaultName={title} onClose={() => setSaveTpl(false)} onSaved={(t) => { setTemplates((x) => [...x, t]); setSaveTpl(false); show("Шаблон сохранён"); }} />}
      {del && <ConfirmDialog title="Удалить отчёт?" confirmLabel="Удалить" body={<p>Файлы отчёта «{del.title}» будут удалены.</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.reports.remove(del.id); load(); }} />}
      {toast}
    </section>
  );
}

function SaveTemplate({ kind, params, defaultName, onClose, onSaved }: { kind: Job["kind"]; params: ReportParams; defaultName: string; onClose: () => void; onSaved: (t: Template) => void }) {
  const [name, setName] = useState(defaultName); const [shared, setShared] = useState(true); const [err, setErr] = useState("");
  return (
    <Modal title="Сохранить шаблон отчёта" onClose={onClose}>
      <form onSubmit={async (e) => { e.preventDefault(); try { onSaved(await api.reports.saveTemplate(name, kind, params, shared)); } catch (x) { setErr((x as ApiError).message); } }}>
        <label>Название<input value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} autoFocus /></label>
        <label className="check"><input type="checkbox" checked={shared} onChange={(e) => setShared(e.target.checked)} /> Доступен всем пользователям</label>
        {err && <div className="alert error">{err}</div>}
        <div className="row"><button className="btn primary" disabled={!name}>Сохранить</button><button type="button" className="btn ghost" onClick={onClose}>Отмена</button></div>
      </form>
    </Modal>
  );
}

function JobView({ ctx, jobId }: { ctx: Ctx; jobId: string }) {
  const [j, setJ] = useState<Job | null>(null);
  const [rows, setRows] = useState<{ items: (SoftwareRow & Record<string, unknown>)[]; total: number } | null>(null);
  const [offset, setOffset] = useState(0);
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState<string>("");
  const [err, setErr] = useState("");
  const load = useCallback(() => api.reports.get(jobId).then(setJ).catch((e) => setErr((e as ApiError).message)), [jobId]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (!j || (j.status !== "queued" && j.status !== "running")) return; const t = window.setInterval(load, 2000); return () => window.clearInterval(t); }, [j, load]);
  useEffect(() => { if (j?.status === "done") api.reports.rows(jobId, offset, 200).then((r) => setRows(r as unknown as { items: (SoftwareRow & Record<string, unknown>)[]; total: number })).catch((e) => setErr((e as ApiError).message)); }, [j?.status, jobId, offset]);
  if (err) return <section><div className="alert error">{err}</div><Link to="/reports">← Отчёты</Link></section>;
  if (!j) return <div className="muted">Загрузка…</div>;
  const [l, c] = STATUS[j.status] ?? [j.status, ""];
  const cols: [string, string][] = j.kind === "software_hosts"
    ? [["name", "Компьютер"], ["ip", "IP"], ["os", "ОС"], ["app_name", "Программа"], ["app_version", "Версия"], ["branch", "Ветка"], ["group", "Группа"], ["last_connected", "Подключение (UTC)"], ["activity", "Активность"]]
    : [["name", "Компьютер"], ["ip", "IP"], ["os", "ОС"], ["group", "Группа"], ["last_connected", "Подключение (UTC)"], ["days_since_connection", "Суток без связи"], ["activity", "Активность"]];
  let items = rows?.items ?? [];
  if (filter) items = items.filter((r) => Object.values(r).some((v) => String(v ?? "").toLowerCase().includes(filter.toLowerCase())));
  if (sort) { const d = sort.startsWith("-"), k = sort.replace("-", ""); items = [...items].sort((a, b) => String(a[k] ?? "").localeCompare(String(b[k] ?? ""), "ru", { numeric: true }) * (d ? -1 : 1)); }
  const s = j.summary;
  return (
    <section>
      <div className="row"><h1>{j.title}</h1><span className={`badge ${c}`}>{l}</span><div className="spacer" /><Link className="btn" to="/reports">← Отчёты</Link></div>
      <div className="row muted small">Источник: <b>{j.source_name}</b> · {describe(j.params as Record<string, unknown>)} · автор {j.created_by} · создан {fmt(j.created_at)}{j.data_fetched_at && <> · <Fetched at={j.data_fetched_at} /></>}</div>
      {j.status === "running" && <div className="alert info">Формируется: {j.progress ?? "…"} {ctx.me.user.role !== "viewer" && <button className="btn mini" onClick={async () => { await api.reports.cancel(j.id); void load(); }}>Отменить</button>}</div>}
      {j.status === "queued" && <div className="alert">В очереди на формирование. Воркер берёт задания по порядку.</div>}
      {j.error && <div className="alert error">{j.error}</div>}
      {s && (
        <div className="kpi">
          <div className="card"><div className="l">Строк в отчёте</div><div className="v">{num(s.rows)}</div></div>
          <div className="card"><div className="l">Уникальных компьютеров</div><div className="v">{num(s.hosts)}</div></div>
          {j.kind === "software_hosts" && <div className="card"><div className="l">Установок найдено всего</div><div className="v">{num(s.installs_total)}</div><div className="t">до фильтра активности</div></div>}
          <div className="card"><div className="l">Исключено без связи</div><div className="v">{num(s.excluded_inactive_hosts ?? 0)}</div><div className="t">{s.include_inactive ? "включены все" : `порог ${s.active_days} сут`}</div></div>
        </div>
      )}
      {s?.branches && s.branches.length > 0 && (
        <div className="card"><h2>Версии</h2>
          <table className="table compact" style={{ boxShadow: "none" }}><thead><tr><th>Ветка</th><th className="num">Установок</th><th className="num">Компьютеров</th><th>Пакеты</th></tr></thead>
            <tbody>{s.branches.map((b) => <tr key={b.branch}><td>{b.branch}</td><td className="num">{num(b.installs)}</td><td className="num">{num(b.hosts)}</td><td className="small">{b.packages.join(", ")}</td></tr>)}</tbody></table>
        </div>
      )}
      {j.status === "done" && (
        <div className="card">
          <div className="row"><h2>Данные</h2><div className="spacer" />
            <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Фильтр по странице" style={{ maxWidth: 260 }} aria-label="Фильтр" />
            <a className="btn primary" href={api.reports.downloadUrl(j.id, "xlsx")}>⬇ XLSX</a><a className="btn" href={api.reports.downloadUrl(j.id, "csv")}>⬇ CSV</a></div>
          <div className="table-scroll"><table className="table compact">
            <thead><tr>{cols.map(([k, t]) => <th key={k} className="sortable" onClick={() => setSort(sort === k ? `-${k}` : k)}>{t}{sort === k ? " ▴" : sort === `-${k}` ? " ▾" : ""}</th>)}</tr></thead>
            <tbody>{items.map((r, i) => <tr key={i}>{cols.map(([k]) => <td key={k} className={k === "last_connected" || k === "ip" ? "nowrap" : ""}>{k === "name" ? <Link to={`/hosts/${String(r.host_id)}`}>{String(r[k] ?? "")}</Link> : k === "last_connected" ? fmt(r[k] as string) : String(r[k] ?? "")}</td>)}</tr>)}</tbody>
          </table></div>
          {rows && <Pager total={rows.total} offset={offset} limit={200} onPage={setOffset} />}
        </div>
      )}
    </section>
  );
}
