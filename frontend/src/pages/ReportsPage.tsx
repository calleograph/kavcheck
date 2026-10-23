import { FormEvent, useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, type ApiError, type Job, type ReportParams, type SoftwareRow, type Template } from "../api";
import { NoSource, type Ctx } from "../App";
import { Fetched, Pager } from "../components/Common";
import { ConfirmDialog, Modal } from "../components/Dialogs";
import { Icon } from "../components/Icons";
import { useToast } from "../components/Toast";
import { Empty, PageHead, SkelRows, Spectrum } from "../components/ui";
import { fmt, num } from "../util";
import { JOB_STATUS } from "./DashboardPage";
import { describe } from "./VulnsPage";

const KINDS: [Job["kind"], string][] = [["software_hosts", "Компьютеры с программами"], ["hosts", "Компьютеры и связь с KSC"]];
const DAYS = [1, 3, 7, 14, 30];
const PRESETS: { title: string; sub: string; kind: Job["kind"]; params: ReportParams }[] = [
  { title: "Аудит PHP: все ветки", sub: "Все пакеты PHP, только активные компьютеры", kind: "software_hosts", params: { rule: "php", include_inactive: false } },
  { title: "Аудит PHP 7.x", sub: "Версии от 7 и ниже 8", kind: "software_hosts", params: { rule: "php", min_version: "7", below_version: "8", include_inactive: false } },
  { title: "Компьютеры без связи с KSC", sub: "Агент не подключался дольше порога", kind: "hosts", params: { inactive_only: true, include_inactive: true } },
];

export default function ReportsPage({ ctx }: { ctx: Ctx }) {
  const { jobId } = useParams();
  if (!ctx.current && !jobId) return <NoSource ctx={ctx} />;
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
  const [jobs, setJobs] = useState<Job[] | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [saveTpl, setSaveTpl] = useState(false);
  const [del, setDel] = useState<Job | null>(null);
  const [toast, show] = useToast();
  const canEdit = ctx.me.user.role !== "viewer";
  const load = useCallback(() => { api.reports.list().then((r) => setJobs(r.items)).catch((e) => setErr((e as ApiError).message)); }, []);
  useEffect(() => { load(); api.software.rules().then((r) => setRules(r.items)).catch(() => undefined); api.reports.templates().then((r) => setTemplates(r.items)).catch(() => undefined); }, [load]);
  useEffect(() => { if (!jobs?.some((j) => j.status === "queued" || j.status === "running")) return; const t = window.setInterval(load, 3000); return () => window.clearInterval(t); }, [jobs, load]);
  const set = <K extends keyof ReportParams>(k: K, v: ReportParams[K]) => setP((x) => ({ ...x, [k]: v }));
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setErr("");
    try { const j = await api.reports.create(kind, title, p); setSp(new URLSearchParams(), { replace: true }); navigate(`/reports/${j.id}`); } catch (x) { setErr((x as ApiError).message); setBusy(false); }
  };
  const apply = (k: Job["kind"], params: ReportParams, name: string) => { setKind(k); setP(params); setTitle(name); window.scrollTo({ top: 0, behavior: "smooth" }); };
  const needSelection = kind === "software_hosts" && !p.product_ids?.length && !p.rule && !p.name_like;
  return (
    <section>
      <PageHead title="Отчёты" lede={<>Источник <b>{ctx.current?.name}</b>. Отчёт формируется в фоне проверенными запросами; готовый можно просмотреть и выгрузить в XLSX и CSV.</>} />
      <div className="split">
        <form className="card" onSubmit={submit}>
          <h2>Новый отчёт</h2>
          <div className="cols">
            <label>Тип отчёта<select value={kind} onChange={(e) => setKind(e.target.value as Job["kind"])} disabled={!canEdit}>{KINDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
            <label>Название<input value={title} onChange={(e) => setTitle(e.target.value)} placeholder={KINDS.find(([k]) => k === kind)?.[1]} maxLength={300} /></label>
          </div>
          {kind === "software_hosts" && (
            <fieldset className="group"><legend>Программы и версии</legend>
              {p.product_ids?.length ? <div className="alert info"><Icon name="info" /><div className="alert-body">Выбрано записей реестра: <b>{p.product_ids.length}</b> (из раздела «Программное обеспечение»).</div><button type="button" className="btn mini ghost" onClick={() => set("product_ids", [])}>Очистить</button></div> : null}
              <div className="cols">
                <label>Правило группировки<select value={p.rule ?? ""} onChange={(e) => set("rule", e.target.value || null)}><option value="">Без правила — по шаблону названия</option>{rules.map((r) => <option key={r.key} value={r.key}>{r.name}</option>)}</select></label>
                <label>Ветки<input value={(p.branches ?? []).join(", ")} onChange={(e) => set("branches", e.target.value.split(",").map((x) => x.trim()).filter(Boolean))} placeholder="7.4, 8.1" /><span className="help">Через запятую; пусто — все ветки</span></label>
              </div>
              <div className="cols">
                <label>Шаблон названия<input className="mono" value={p.name_like ?? ""} onChange={(e) => set("name_like", e.target.value || null)} placeholder="%nginx%" /><span className="help">SQL LIKE, если правило не выбрано</span></label>
                <label>Регулярное выражение<input className="mono" value={p.name_regex ?? ""} onChange={(e) => set("name_regex", e.target.value || null)} placeholder="^nginx(-core)?$" /><span className="help">Уточняет отбор по названию</span></label>
              </div>
              <div className="cols three">
                <label>Версия от<input className="mono" value={p.min_version ?? ""} onChange={(e) => set("min_version", e.target.value || null)} placeholder="7" /></label>
                <label>Версия до (включительно)<input className="mono" value={p.max_version ?? ""} onChange={(e) => set("max_version", e.target.value || null)} placeholder="7.4.33" /></label>
                <label>Версия ниже<input className="mono" value={p.below_version ?? ""} onChange={(e) => set("below_version", e.target.value || null)} placeholder="8" /></label>
              </div>
              <p className="help" style={{ marginTop: -6, marginBottom: 12 }}>Версии сравниваются по алгоритму dpkg (8.10 новее 8.9), без эпохи и ревизии пакета. «7.x» — от 7 и ниже 8.</p>
            </fieldset>
          )}
          <fieldset className="group"><legend>Компьютеры</legend>
            <div className="cols">
              <label>Связь с KSC за<select value={p.active_days ?? ""} onChange={(e) => set("active_days", e.target.value ? Number(e.target.value) : null)}><option value="">порог из настроек</option>{DAYS.map((d) => <option key={d} value={d}>{d} сут</option>)}</select></label>
              {kind === "software_hosts" && <label>Платформа пакета<select value={p.platform ?? ""} onChange={(e) => set("platform", e.target.value || null)}><option value="">Любая</option><option value="windows">Windows</option><option value="linux">Linux</option></select></label>}
              <label>Группа содержит<input value={p.group_contains ?? ""} onChange={(e) => set("group_contains", e.target.value || null)} /></label>
            </div>
            {kind === "hosts" && <div className="cols"><label>Имя компьютера содержит<input value={p.q ?? ""} onChange={(e) => set("q", e.target.value || null)} /></label><label>ОС содержит<input value={p.os_contains ?? ""} onChange={(e) => set("os_contains", e.target.value || null)} /></label></div>}
            <label className="check"><input type="checkbox" className="switch" checked={!!p.include_inactive} onChange={(e) => set("include_inactive", e.target.checked)} /><span className="check-body">Включать компьютеры без связи<span className="help">Иначе они исключаются, а отчёт показывает, сколько их</span></span></label>
            {kind === "hosts" && <label className="check"><input type="checkbox" className="switch" checked={!!p.inactive_only} onChange={(e) => set("inactive_only", e.target.checked)} /><span className="check-body">Только компьютеры без связи дольше порога</span></label>}
          </fieldset>
          {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
          <div className="form-actions">
            <button className="btn primary" aria-busy={busy} disabled={!canEdit || needSelection}><Icon name="play" size={15} /><span>Сформировать отчёт</span></button>
            {canEdit && <button type="button" className="btn ghost" onClick={() => setSaveTpl(true)} disabled={needSelection}><Icon name="save" />Сохранить как шаблон</button>}
            {needSelection && <span className="help">Выберите правило или шаблон названия</span>}
            {!canEdit && <span className="help">Отчёты формируют аналитики и администраторы.</span>}
          </div>
        </form>
        <div className="stack">
          <div className="card">
            <h2>Готовые сценарии</h2>
            {PRESETS.map((x) => <button key={x.title} type="button" className="action-row" onClick={() => apply(x.kind, x.params, x.title)}>
              <span className="a-ic"><Icon name={x.kind === "hosts" ? "clock" : "branch"} /></span><span className="a-main"><b>{x.title}</b><span>{x.sub}</span></span><Icon name="chevronR" className="a-go" /></button>)}
          </div>
          <div className="card">
            <h2>Мои шаблоны</h2>
            {!templates.length ? <p className="muted small">Сохраните условия формы кнопкой «Сохранить как шаблон», чтобы повторять их одним щелчком.</p> : (
              <ul className="rows">{templates.map((t) => <li key={t.id}><Icon name="file" className="muted" /><div className="r-main"><button className="link-btn" onClick={() => apply(t.kind, t.params, t.name)}>{t.name}</button><span className="r-sub">{KINDS.find(([k]) => k === t.kind)?.[1]}{t.shared ? ", общий" : ""}</span></div>
                {(t.owner_id === ctx.me.user.id || ctx.me.user.is_admin) && <button className="btn mini ghost danger icon" aria-label={`Удалить шаблон ${t.name}`} onClick={async () => { await api.reports.deleteTemplate(t.id); setTemplates((x) => x.filter((y) => y.id !== t.id)); }}><Icon name="trash" size={15} /></button>}</li>)}</ul>)}
          </div>
        </div>
      </div>

      <div className="section-head"><h2>Сформированные отчёты</h2>{jobs && <span className="count">{num(jobs.length)}</span>}</div>
      <div className="table-scroll">
        {!jobs ? <SkelRows rows={4} cols={5} /> : (
          <table className="table">
            <thead><tr><th>Отчёт</th><th>Состояние</th><th className="num">Строк</th><th>Автор</th><th>Создан</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>{jobs.map((j) => { const [l, c] = JOB_STATUS[j.status] ?? [j.status, ""]; return (
              <tr key={j.id}><td><Link to={`/reports/${j.id}`}>{j.title}</Link><span className="sub">{describe(j.params as Record<string, unknown>)}</span></td>
                <td><span className={`badge ${c}`}>{j.status === "running" && <span className="spin" style={{ width: 10, height: 10, borderWidth: 1.5 }} />}{l}</span>{j.status === "running" && j.progress && <span className="sub">{j.progress}</span>}{j.error && <span className="sub bad-text">{j.error}</span>}</td>
                <td className="num">{num(j.rows)}</td><td>{j.created_by}</td><td className="nowrap">{fmt(j.created_at)}</td>
                <td className="actions">
                  {j.status === "done" && <><a className="btn mini" href={api.reports.downloadUrl(j.id, "xlsx")}><Icon name="download" size={15} />XLSX</a><a className="btn mini" href={api.reports.downloadUrl(j.id, "csv")}>CSV</a></>}
                  {canEdit && (j.status === "queued" || j.status === "running") && <button className="btn mini ghost" onClick={async () => { await api.reports.cancel(j.id); load(); show("Формирование отменяется"); }}><Icon name="stop" size={14} />Отменить</button>}
                  {canEdit && j.status !== "running" && j.status !== "queued" && <><button className="btn mini ghost icon" title="Повторить с теми же условиями" aria-label={`Повторить отчёт ${j.title}`} onClick={async () => { await api.reports.rerun(j.id); load(); show("Отчёт поставлен в очередь"); }}><Icon name="refresh" size={15} /></button>
                    <button className="btn mini ghost danger icon" aria-label={`Удалить отчёт ${j.title}`} onClick={() => setDel(j)}><Icon name="trash" size={15} /></button></>}</td></tr>); })}
              {!jobs.length && <tr><td colSpan={6}><Empty icon="file" title="Отчётов по этому источнику ещё нет">Заполните форму выше или начните с готового сценария.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      {saveTpl && <SaveTemplate kind={kind} params={p} defaultName={title} onClose={() => setSaveTpl(false)} onSaved={(t) => { setTemplates((x) => [...x, t]); setSaveTpl(false); show("Шаблон сохранён"); }} />}
      {del && <ConfirmDialog title="Удалить отчёт?" confirmLabel="Удалить отчёт" body={<p>Файлы отчёта «{del.title}» будут удалены без возможности восстановления.</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.reports.remove(del.id); load(); }} />}
      {toast}
    </section>
  );
}

function SaveTemplate({ kind, params, defaultName, onClose, onSaved }: { kind: Job["kind"]; params: ReportParams; defaultName: string; onClose: () => void; onSaved: (t: Template) => void }) {
  const [name, setName] = useState(defaultName); const [shared, setShared] = useState(true); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  return (
    <Modal title="Сохранить шаблон отчёта" onClose={onClose}>
      <form onSubmit={async (e) => { e.preventDefault(); setBusy(true); try { onSaved(await api.reports.saveTemplate(name, kind, params, shared)); } catch (x) { setErr((x as ApiError).message); setBusy(false); } }}>
        <label>Название<input value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} autoFocus /></label>
        <label className="check"><input type="checkbox" className="switch" checked={shared} onChange={(e) => setShared(e.target.checked)} />Доступен всем пользователям</label>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" aria-busy={busy} disabled={!name}><span>Сохранить шаблон</span></button></div>
      </form>
    </Modal>
  );
}

function JobView({ ctx, jobId }: { ctx: Ctx; jobId: string }) {
  const [j, setJ] = useState<Job | null>(null);
  const [rows, setRows] = useState<{ items: (SoftwareRow & Record<string, unknown>)[]; total: number } | null>(null);
  const [offset, setOffset] = useState(0);
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState("");
  const [err, setErr] = useState("");
  const load = useCallback(() => api.reports.get(jobId).then(setJ).catch((e) => setErr((e as ApiError).message)), [jobId]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (!j || (j.status !== "queued" && j.status !== "running")) return; const t = window.setInterval(load, 2000); return () => window.clearInterval(t); }, [j, load]);
  useEffect(() => { if (j?.status === "done") api.reports.rows(jobId, offset, 200).then((r) => setRows(r as unknown as { items: (SoftwareRow & Record<string, unknown>)[]; total: number })).catch((e) => setErr((e as ApiError).message)); }, [j?.status, jobId, offset]);
  const back = <Link className="back-link" to="/reports"><Icon name="arrowL" size={15} />Отчёты</Link>;
  if (err) return <section><PageHead title="Отчёт" back={back} /><div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div></section>;
  if (!j) return <section><PageHead title={<span className="skel" style={{ width: 320, height: 28 }} />} back={back} /><div className="table-scroll"><SkelRows /></div></section>;
  const [l, c] = JOB_STATUS[j.status] ?? [j.status, ""];
  const cols: [string, string][] = j.kind === "software_hosts"
    ? [["name", "Компьютер"], ["ip", "IP-адрес"], ["os", "ОС"], ["app_name", "Программа"], ["app_version", "Версия"], ["branch", "Ветка"], ["group", "Группа"], ["last_connected", "Подключение к KSC"], ["activity", "Связь"]]
    : [["name", "Компьютер"], ["ip", "IP-адрес"], ["os", "ОС"], ["group", "Группа"], ["last_connected", "Подключение к KSC"], ["days_since_connection", "Суток без связи"], ["activity", "Связь"]];
  const mono = new Set(["ip", "app_version", "branch"]);
  let items = rows?.items ?? [];
  if (filter) items = items.filter((r) => Object.values(r).some((v) => String(v ?? "").toLowerCase().includes(filter.toLowerCase())));
  if (sort) { const d = sort.startsWith("-"), k = sort.replace("-", ""); items = [...items].sort((a, b) => String(a[k] ?? "").localeCompare(String(b[k] ?? ""), "ru", { numeric: true }) * (d ? -1 : 1)); }
  const s = j.summary;
  return (
    <section>
      <PageHead title={j.title} back={back} lede={<>{j.source_name}: {describe(j.params as Record<string, unknown>)}. Сформировал {j.created_by}, {fmt(j.created_at)}.</>}>
        <span className={`badge ${c}`}>{l}</span>
        {j.data_fetched_at && <Fetched at={j.data_fetched_at} />}
        {j.status === "done" && <><a className="btn primary" href={api.reports.downloadUrl(j.id, "xlsx")}><Icon name="download" />Скачать XLSX</a><a className="btn" href={api.reports.downloadUrl(j.id, "csv")}>CSV</a></>}
      </PageHead>
      {(j.status === "running" || j.status === "queued") && (
        <div className="alert info" role="status"><span className="spin" style={{ color: "var(--accent)", marginTop: 2 }} />
          <div className="alert-body">{j.status === "queued" ? "Отчёт в очереди: воркер берёт задания по порядку." : `Формируется: ${j.progress ?? "чтение данных"}.`}</div>
          {ctx.me.user.role !== "viewer" && <button className="btn mini" onClick={async () => { await api.reports.cancel(j.id); void load(); }}><Icon name="stop" size={14} />Отменить</button>}</div>)}
      {j.error && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{j.error}</div></div>}
      {s && (
        <div className="meters">
          <div className="meter"><span className="l">Строк в отчёте</span><span className="v">{num(s.rows)}</span></div>
          <div className="meter"><span className="l">Уникальных компьютеров</span><span className="v">{num(s.hosts)}</span></div>
          {j.kind === "software_hosts" && <div className="meter"><span className="l">Установок найдено</span><span className="v">{num(s.installs_total)}</span><span className="t">до фильтра связи с KSC</span></div>}
          <div className="meter"><span className="l">Исключено без связи</span><span className="v">{s.include_inactive ? "—" : num(s.excluded_inactive_hosts ?? 0)}</span><span className="t">{s.include_inactive ? "включены все компьютеры" : `порог ${s.active_days} сут`}</span></div>
          {s.branches && s.branches.length > 0 && <div className="meter wide"><span className="l">Версии в отчёте</span>
            <Spectrum label="Ветки в отчёте" size="lg" unit=" уст." segs={s.branches.map((b) => ({ key: b.branch, label: b.branch, value: b.installs, undef: b.branch.startsWith("("), note: `${num(b.hosts)} комп.` }))} /></div>}
        </div>
      )}
      {j.status === "done" && (<>
        <div className="section-head"><h2>Данные</h2><span className="count">{num(rows?.total)}</span><div className="spacer" />
          <div className="input-icon" style={{ width: 300, maxWidth: "100%" }}><Icon name="filter" size={15} /><input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Фильтр по странице" aria-label="Фильтр строк на странице" /></div></div>
        <div className="table-scroll">
          {!rows ? <SkelRows cols={7} /> : (
            <table className="table compact">
              <thead><tr>{cols.map(([k, t]) => <th key={k} className="sortable" tabIndex={0} aria-sort={sort === k ? "ascending" : sort === `-${k}` ? "descending" : undefined} onClick={() => setSort(sort === k ? `-${k}` : k)} onKeyDown={(e) => { if (e.key === "Enter") setSort(sort === k ? `-${k}` : k); }}>
                {t}<Icon name={sort === k ? "chevronU" : sort === `-${k}` ? "chevronD" : "sort"} size={13} className="sort-ic" /></th>)}</tr></thead>
              <tbody>{items.map((r, i) => <tr key={i}>{cols.map(([k]) => <td key={k} className={`${mono.has(k) ? "mono" : ""} ${k === "last_connected" || k === "ip" ? "nowrap" : ""}`}>
                {k === "name" ? <Link to={`/hosts/${String(r.host_id)}`}>{String(r[k] ?? "")}</Link> : k === "last_connected" ? fmt(r[k] as string) : String(r[k] ?? "")}</td>)}</tr>)}
                {!items.length && <tr><td colSpan={cols.length}><Empty icon="search" title={filter ? "Ничего не найдено" : "В отчёте нет строк"}>{filter ? "Измените текст фильтра." : "По заданным условиям данных не нашлось. Попробуйте включить компьютеры без связи."}</Empty></td></tr>}
              </tbody>
            </table>)}
        </div>
        {rows && <Pager total={rows.total} offset={offset} limit={200} onPage={setOffset} />}
      </>)}
    </section>
  );
}
