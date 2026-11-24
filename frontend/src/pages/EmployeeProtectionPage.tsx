import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { qs, req, type ApiError } from "../api";
import type { Ctx } from "../App";
import { CompactList } from "../components/CompactList";
import { CountButton, FilterBar, ReportButton } from "../components/FilterBar";
import { HostsDrawer, type DrawerHost } from "../components/HostsDrawer";
import { ListFoot, VirtualRows, useInfinite, useKept, usePanel, type Chunk } from "../components/Infinite";
import { QuickReportPanel } from "../components/QuickReport";
import { BackLink, Empty, PageHead, SkelRows, Spectrum, Tabs } from "../components/ui";
import { WorkplaceReview } from "../components/WorkplaceReview";
import { fmt, fmtDate, num, plural } from "../util";

const PATH = "/employee-protection";
const TITLE = "Антивирусная защита сотрудников";
const FILTER_FIELDS = {
  organization: "Организация", department: "Департамент", division: "Подразделение (OU)", zone: "Зона ответственности",
  kind: "Тип оборудования", ownership: "Принадлежность", os: "Операционная система",
  status: "Состояние сотрудника", device_status: "Состояние устройства", freshness: "Актуальность устройства",
} as const;
type Field = keyof typeof FILTER_FIELDS;
type View = "employees" | "devices";
type Metric = "employees" | "uses_av" | "protected" | "partial" | "no_av" | "insufficient" | "devices" | "corporate" | "personal";
type Filters = Partial<Record<Field | "q" | "metric" | "employee_id" | "device_id", string>>;
const OPTIONAL: Field[] = ["organization", "division", "zone", "kind", "ownership", "os", "device_status", "freshness"];
const FILTER_KEYS = [...Object.keys(FILTER_FIELDS), "metric", "employee_id", "device_id"] as (keyof Filters)[];
const METRICS: Record<Metric, string> = {
  employees: "Действующие сотрудники", uses_av: "Есть антивирус Kaspersky", protected: "Полностью защищены",
  partial: "Частично защищены", no_av: "Подтверждено отсутствие Kaspersky", insufficient: "Недостаточно данных",
  devices: "Известные устройства", corporate: "Корпоративные устройства", personal: "Личные устройства",
};
const METRIC_GROUPS: { title: string; metrics: Metric[] }[] = [
  { title: "Охват сотрудников", metrics: ["employees", "uses_av", "protected"] },
  { title: "Требуется внимание", metrics: ["partial", "no_av", "insufficient"] },
  { title: "Оборудование", metrics: ["devices", "corporate", "personal"] },
];
const OWNERSHIP: Record<string, string> = { corporate: "Корпоративное", personal: "Личное", unknown: "Не установлено" };
const TONE: Record<string, string> = { protected: "ok", partial: "warn", problems: "warn", no_av: "err", stale: "warn" };
const percent = (n: number, all: number) => all > 0 ? Math.round(n / all * 1000) / 10 : 0;

interface Choice { value: string; label: string }
interface Labels {
  employee_status: Record<string, string>; device_status: Record<string, string>;
  freshness: Record<string, string>; reason: Record<string, string>;
}
interface Summary {
  ready: boolean; built_at: string | null; census_at: string | null; census_source: string; warnings: string[]; running: boolean;
  totals: Record<Metric, number>; statuses: { id: string; label: string; count: number }[];
  by_department: (Choice & { total: number; uses_av: number; protected: number; partial: number; no_av: number; insufficient: number })[];
  by_os: (Choice & { total: number; protected: number; problems: number; no_av: number })[];
  options: Partial<Record<Field, Choice[]>>; labels: Labels;
}
interface Employee {
  id: string; name: string; login: string; email: string; organization: string; department: string; division: string; title: string;
  account_created: string | null; status: string; reason: string; uses_av: boolean; device_count: number;
  protected_devices: number; installed_devices: number; freshness: string; last_seen: string | null;
  pending_device_count?: number;
}
interface Device {
  id: string; source_id: string | null; host_id: number | null; asset_id: number | null; name: string; ip: string;
  os: string; os_version: string; kind: string; ownership: string; zones: { id: string; name: string }[];
  av_product: string; av_version: string; last_connected: string | null; status: string; reason: string;
  installed: boolean | null; freshness: string; employees: { id: string; name: string; login: string; evidence: string[] }[]; shared_count: number;
}
type Panel = { title: string; filters: Filters };
type Report = { view: View | "summary"; filters: Filters };

function deviceHref(d: Device) {
  if (d.asset_id != null) return `/inventory/assets/${d.asset_id}`;
  return d.source_id && d.host_id != null ? `/devices?card=${d.source_id}:${d.host_id}` : null;
}

function Status({ status, reason, labels, scope }: { status: string; reason: string; labels: Labels; scope: "employee_status" | "device_status" }) {
  const label = reason === "workplace_review" ? "Рабочее место требует проверки" : labels[scope][status];
  return <><span className={`badge ${TONE[status] ?? ""}`}>{label || "Состояние неизвестно"}</span>
    {labels.reason[reason] && <span className="sub">{labels.reason[reason]}</span>}</>;
}

function Breakdown({ title, label, rows, onTotal, onCovered }: {
  title: string; label: string; rows: (Choice & { total: number; covered: number; details: ReactNode })[];
  onTotal: (value: string) => void; onCovered: (value: string) => void;
}) {
  return <section className="card">
    <h2>{title}</h2>
    {rows.length === 0 ? <p className="muted small">Нет данных по выборке.</p> :
      <ul className="ep-chart" aria-label={title}>
        {rows.map((r) => <li key={r.value} className="ep-chart-row">
          <button type="button" className="link-btn ep-chart-name" onClick={() => onTotal(r.value)}>{r.label}</button>
          <button type="button" className="ep-chart-bar" onClick={() => onCovered(r.value)} disabled={r.covered === 0}
            aria-label={`${r.label}. ${label} ${num(r.covered)} из ${num(r.total)}`} title={label}>
            <span className="lic-bar" aria-hidden="true"><i style={{ width: `${percent(r.covered, r.total)}%` }} /></span>
            <span className="small nowrap">{num(r.covered)} / {num(r.total)}</span>
          </button>
          <div className="ep-chart-details small muted">{r.details}</div>
        </li>)}
      </ul>}
  </section>;
}

function EmployeeTable({ filters, userId, revision, labels, onDevices }: { filters: Filters; userId: string; revision: string; labels: Labels; onDevices: (p: Panel) => void }) {
  const list = useInfinite<Employee>(`employee-protection-employees:${userId}`, [filters, revision], (offset, limit) =>
    req<Chunk<Employee>>("GET", `${PATH}/employees${qs({ ...filters, offset, limit })}`), 50);
  return <>
    {list.initial ? <SkelRows /> : list.items.length > 0 ?
      <div className="table-scroll"><table className="table compact virt"><thead><tr>
        <th>Сотрудник</th><th>Оргструктура</th><th>Учётная запись</th><th className="num">Все известные устройства</th><th>Состояние защиты</th><th>Актуальность</th>
      </tr></thead><tbody><VirtualRows list={list} colSpan={6} estimate={66} row={(e) => <tr>
        <td><b>{e.name}</b><span className="sub">{e.title || "—"}</span></td>
        <td>{e.department || "—"}<span className="sub">{[e.organization, e.division].filter(Boolean).join(" · ") || "—"}</span></td>
        <td>{e.login || "—"}<span className="sub">{e.email}</span><span className="sub">Создана {fmtDate(e.account_created)}</span></td>
        <td className="num">
          <CountButton n={e.device_count} label={`Устройства сотрудника ${e.name}`} onClick={() =>
            onDevices({ title: `Устройства · ${e.name}`, filters: { employee_id: e.id } })} />
          <span className="sub">С антивирусом {num(e.installed_devices)}</span>
          <span className="sub">Защищены <CountButton n={e.protected_devices} label={`Защищённые устройства сотрудника ${e.name}`}
            onClick={() => onDevices({ title: `Защищённые устройства · ${e.name}`, filters: { employee_id: e.id, device_status: "protected" } })} /></span>
          <Link className="sub link-btn" to={`${PATH}${qs({ view: "workplaces", employee_id: e.id })}`}>
            {e.pending_device_count ? `На проверку · ${num(e.pending_device_count)}` : "Рабочие места"}
          </Link>
        </td>
        <td><Status status={e.status} reason={e.reason} labels={labels} scope="employee_status" /></td>
        <td className="small">{labels.freshness[e.freshness] || "—"}<span className="sub">{fmt(e.last_seen)}</span></td>
      </tr>} /></tbody></table></div> : !list.error && <Empty icon="users" title="Сотрудники не найдены" />}
    <ListFoot list={list} />
  </>;
}

function DeviceTable({ filters, userId, revision, labels, onEmployee }: { filters: Filters; userId: string; revision: string; labels: Labels; onEmployee: (id: string) => void }) {
  const list = useInfinite<Device>(`employee-protection-devices:${userId}`, [filters, revision], (offset, limit) =>
    req<Chunk<Device>>("GET", `${PATH}/devices${qs({ ...filters, offset, limit })}`), 50);
  return <>
    {list.initial ? <SkelRows /> : list.items.length > 0 ?
      <div className="table-scroll"><table className="table compact virt"><thead><tr>
        <th>Устройство</th><th>Сотрудники и связь</th><th>Принадлежность</th><th>ОС</th><th>Антивирус</th><th>Состояние защиты</th><th>Подключение к KSC</th>
      </tr></thead><tbody><VirtualRows list={list} colSpan={7} estimate={70} row={(d) => {
        const href = deviceHref(d);
        return <tr>
          <td>{href ? <Link className="strong-link" to={href}>{d.name}</Link> : <b>{d.name}</b>}<span className="sub mono">{d.ip || "—"}</span>
            {d.kind && <span className="sub">{d.kind}</span>}</td>
          <td><CompactList items={d.employees} sep="" label="сотрудники" render={(e) => <span className="ep-user">
            <button type="button" className="link-btn" onClick={() => onEmployee(e.id)}>{e.name || e.login}</button>
            <span className="sub">{e.evidence.join(" · ")}</span></span>} />
            {d.shared_count > 1 && <span className="sub">Общее устройство · {num(d.shared_count)} {plural(d.shared_count, "сотрудник", "сотрудника", "сотрудников")}</span>}
            <Link className="sub link-btn" to={`${PATH}${qs({ view: "workplaces", device_id: d.id })}`}>Рабочие места</Link></td>
          <td>{OWNERSHIP[d.ownership] ?? "Не установлено"}<span className="sub"><CompactList items={d.zones.map((z) => z.name)} label="зоны ответственности" /></span></td>
          <td>{d.os || "—"}{d.os_version && d.os_version !== d.os && <span className="sub">{d.os_version}</span>}</td>
          <td>{d.av_product || "—"}<span className="sub mono">{d.av_version}</span></td>
          <td><Status status={d.status} reason={d.reason} labels={labels} scope="device_status" /></td>
          <td className="small">{fmt(d.last_connected)}<span className="sub">{labels.freshness[d.freshness] || "—"}</span></td>
        </tr>;
      }} /></tbody></table></div> : !list.error && <Empty icon="monitor" title="Устройства не найдены" />}
    <ListFoot list={list} />
  </>;
}

function ReportDashboard({ ctx, canRefresh }: { ctx: Ctx; canRefresh: boolean }) {
  const [sp, setSp] = useSearchParams();
  const userId = ctx.me.user.id;
  const [q, setQ] = useKept(`employee-protection-q:${userId}`, "");
  const [applied, setApplied] = useState(q);
  const [data, setData] = useState<Summary | null>(null);
  const [error, setError] = useState("");
  const [nonce, setNonce] = useState(0);
  const [loading, setLoading] = useState(true);
  const [queuing, setQueuing] = useState(false);
  const [drawer, setDrawer] = usePanel<Panel>(`employee-protection-devices:${userId}`);
  const [report, setReport] = usePanel<Report>(`employee-protection-report:${userId}`);
  const table = useRef<HTMLDivElement>(null);
  const view: View = sp.get("view") === "devices" ? "devices" : "employees";
  const criteria = Object.fromEntries(FILTER_KEYS.flatMap((k) => sp.get(k) ? [[k, sp.get(k)!]] : [])) as Filters;
  const filters = { ...criteria, ...(applied ? { q: applied } : {}) };
  const query = qs(filters);
  const metric = criteria.metric as Metric | undefined;
  useEffect(() => {
    const timer = window.setTimeout(() => setApplied(q.trim()), 300);
    return () => window.clearTimeout(timer);
  }, [q]);
  useEffect(() => {
    let active = true;
    let timer: number | undefined;
    setLoading(true);
    setError("");
    const load = () => req<Summary>("GET", `${PATH}/summary${query}`).then((r) => {
      if (!active) return;
      setData(r);
      setError("");
      if (r.running) timer = window.setTimeout(load, 4000);
    }).catch((e: ApiError) => { if (active) setError(e.message); })
      .finally(() => { if (active) setLoading(false); });
    void load();
    return () => { active = false; window.clearTimeout(timer); };
  }, [query, nonce]);

  const update = (patch: Record<string, string>, scroll = false) => {
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(patch)) { if (v) next.set(k, v); else next.delete(k); }
      return next;
    });
    if (scroll) window.requestAnimationFrame(() => {
      table.current?.scrollIntoView({ block: "start", behavior: "auto" });
      table.current?.focus({ preventScroll: true });
    });
  };
  const choices = (k: Field): Choice[] => {
    const labelMap = k === "status" ? data?.labels.employee_status : k === "device_status" ? data?.labels.device_status : k === "freshness" ? data?.labels.freshness : undefined;
    return labelMap ? Object.entries(labelMap).map(([value, label]) => ({ value, label })) : data?.options[k] ?? [];
  };
  const select = (k: Field) => {
    const options = choices(k);
    const value = criteria[k] || "";
    if (!options.length && !value) return null;
    return <label className="field ep-filter" key={k}>{FILTER_FIELDS[k]}
      <select value={value} onChange={(e) => update({ [k]: e.target.value })}>
        <option value="">Все варианты</option>
        {value && !options.some((x) => x.value === value) && <option value={value}>{value}</option>}
        {options.map((x) => <option key={x.value} value={x.value}>{x.label}</option>)}
      </select>
    </label>;
  };
  const clear = () => { setQ(""); setApplied(""); update(Object.fromEntries(FILTER_KEYS.map((k) => [k, ""]))); };
  const refresh = async () => {
    setQueuing(true);
    setError("");
    try { await req("POST", `${PATH}/refresh`); setNonce((n) => n + 1); }
    catch (e) { setError((e as ApiError).message); }
    finally { setQueuing(false); }
  };
  const employeeMetric = (key: Metric) =>
    update({ metric: metric === key || key === "employees" ? "" : key, view: "employees" }, true);
  const deviceMetric = (key: Metric) => setDrawer({ title: METRICS[key], filters: {
    ...filters, ...(key === "corporate" || key === "personal" ? { ownership: key } : {}),
  } });
  const revision = `${data?.built_at ?? ""}:${nonce}`;
  const statusFilter = (key: string) => update({ status: criteria.status === key ? "" : key, metric: "", view: "employees" }, true);
  const reportBusy = loading || applied !== q.trim();

  return <section className="ov ep">
    <PageHead title={TITLE} lede="Охват защиты Kaspersky по сотрудникам и их известным устройствам из всех источников KSC.">
      <Link to={`${PATH}?view=workplaces`} className="btn">Рабочие места</Link>
      {canRefresh && <button type="button" className="btn" onClick={() => void refresh()} disabled={queuing || data?.running}>
        {queuing || data?.running ? "Идёт пересчёт…" : "Пересчитать"}
      </button>}
    </PageHead>
    {(data?.built_at || data?.running) && <p className="ov-note">
      {data.built_at && <>Расчёт {fmt(data.built_at)} · Список сотрудников {fmt(data.census_at)}{data.census_source && ` · ${data.census_source}`}</>}
      {data.running && <span role="status">{data.built_at && " · "}Фоновый расчёт выполняется.</span>}
    </p>}
    {data && data.warnings.length > 0 && <div className="alert warn"><div className="alert-body">
      <ul className="ep-notes">{data.warnings.map((warning, i) => <li key={i}>{warning}</li>)}</ul>
    </div></div>}
    {error && <div className="alert error" role="alert"><div className="alert-body">{error} <button type="button" className="link-btn" onClick={() => setNonce((n) => n + 1)}>Повторить</button></div></div>}
    {data?.ready ? <>
      <FilterBar search={{ value: q, onChange: (value) => setQ(value.slice(0, 200)), placeholder: "Сотрудник, логин, устройство или IP", label: "Поиск по сотрудникам и устройствам" }}
        primary={<>{select("department")}{select("status")}</>}
        more={<>{OPTIONAL.map(select)}</>} moreActive={OPTIONAL.filter((k) => !!criteria[k]).length}
        chips={[
          ...Object.entries(criteria).map(([k, v]) => ({ id: k, label: k === "metric" ? METRICS[v as Metric] ?? "Показатель" :
            k === "employee_id" ? "Выбран сотрудник" : k === "device_id" ? "Выбрано устройство" : choices(k as Field).find((x) => x.value === v)?.label ?? v,
            onRemove: () => update({ [k]: "" }) })),
          ...(q ? [{ id: "q", label: `Поиск · ${q}`, onRemove: () => { setQ(""); setApplied(""); } }] : []),
        ]}
        onReset={clear} count={{ n: loading ? null : data.totals[view], noun: view === "employees" ? ["сотрудник", "сотрудника", "сотрудников"] : ["устройство", "устройства", "устройств"] }}
        onRefresh={() => setNonce((n) => n + 1)} refreshing={loading}
        report={{ onClick: () => setReport({ view, filters }), disabled: reportBusy,
          title: view === "employees" ? "Отчёт по выбранным сотрудникам" : "Отчёт по выбранным устройствам" }} />

      <section className="card ep-summary" aria-labelledby="ep-summary-title">
        <header className="ov-head ep-summary-head">
          <h2 id="ep-summary-title">Сводка защиты</h2>
          <ReportButton onClick={() => setReport({ view: "summary", filters })} disabled={reportBusy}
            title="Отчёт по показателям и диаграммам текущей выборки" />
        </header>
        <div className="ep-metric-grid">
          {METRIC_GROUPS.map(({ title, metrics }) => <div className="ep-metric-group" key={title}>
            <h3>{title}</h3>
            <dl>{metrics.map((key) => {
              const n = data.totals[key];
              const device = key === "devices" || key === "corporate" || key === "personal";
              const showPercent = (key === "uses_av" || key === "protected") && data.totals.employees > 0;
              return <div key={key}>
                <dt>{METRICS[key]}</dt>
                <dd><CountButton n={n} label={METRICS[key]} onClick={() => device ? deviceMetric(key) : employeeMetric(key)} />
                  {showPercent && <span className="muted small"> · {num(percent(n, data.totals.employees))}%</span>}
                </dd>
              </div>;
            })}</dl>
          </div>)}
        </div>
      </section>

      <section className="card">
        <h2>Состояние защиты сотрудников</h2>
        {data.statuses.some((s) => s.count) ?
          <Spectrum label="Распределение по состоянию защиты" size="lg" segs={data.statuses.filter((s) => s.count).map((s) => ({
            key: s.id, label: s.label, value: s.count, tone: s.id === "protected" ? "ok" : s.id === "partial" || s.id === "problems" ? "warn" : undefined,
          }))} selected={new Set(criteria.status ? [criteria.status] : [])} onToggle={statusFilter} /> :
          <p className="muted small">Нет сотрудников по выбранным условиям.</p>}
      </section>

      <div className="split even">
        <Breakdown title="Антивирус по департаментам" label="Сотрудники с антивирусом" rows={data.by_department.map((r) => ({ ...r, covered: r.uses_av,
          details: (["protected", "partial", "no_av", "insufficient"] as const).map((k) => <span key={k}>{METRICS[k]} <CountButton n={r[k]} label={`${r.label} · ${METRICS[k]}`}
            onClick={() => update({ department: r.value, metric: k, view: "employees" }, true)} /></span>),
        }))}
          onTotal={(department) => update({ department, view: "employees" }, true)}
          onCovered={(department) => update({ department, metric: "uses_av", view: "employees" }, true)} />
        <Breakdown title="Защита по операционным системам" label="Защищённые устройства" rows={data.by_os.map((r) => ({ ...r, covered: r.protected,
          details: (["problems", "no_av"] as const).map((k) => <span key={k}>{k === "problems" ? "С проблемами" : "Без Kaspersky"}{" "}
            <CountButton n={r[k]} label={`${r.label} · ${data.labels.device_status[k]}`}
              onClick={() => setDrawer({ title: `${r.label} · ${data.labels.device_status[k]}`, filters: { ...filters, os: r.value, device_status: k } })} />
          </span>),
        }))}
          onTotal={(os) => update({ os, view: "devices" }, true)}
          onCovered={(os) => update({ os, device_status: "protected", view: "devices" }, true)} />
      </div>

      <details className="card disclosure">
        <summary>Как рассчитывается защита</summary>
        <p className="small">Проценты считаются от числа действующих сотрудников в отборе. Полная защита требует актуального подтверждения для всех известных устройств сотрудника. Наличие продукта Kaspersky и его работоспособность оцениваются отдельно.</p>
        <p className="small">Отсутствие устройства в KSC означает, что нужна проверка. Устаревшие наблюдения показываются отдельно. Подтверждённая принадлежность и наблюдения входов описывают разные связи. Общий компьютер учитывается один раз в сводке устройств.</p>
      </details>

      <div className="ep-detail" ref={table} tabIndex={-1} role="region" aria-label="Детализация отчёта">
        <Tabs label="Детализация отчёта" value={view} items={[{ id: "employees", label: "Сотрудники", count: data.totals.employees },
          { id: "devices", label: "Устройства сотрудников", count: data.totals.devices }]}
          onChange={(v) => update({ view: v })} />
        {view === "employees" ? <EmployeeTable filters={filters} userId={userId} revision={revision} labels={data.labels} onDevices={setDrawer} /> :
          <DeviceTable filters={filters} userId={userId} revision={revision} labels={data.labels} onEmployee={(employee_id) => update({ employee_id, view: "employees" }, true)} />}
      </div>
    </> : loading ? <SkelRows /> : !error && <Empty icon="users" title="Нет готового расчёта">Проверьте источник списка действующих сотрудников и дождитесь фонового расчёта.</Empty>}

    {drawer && data?.ready && <HostsDrawer title={drawer.title} activityDays={ctx.me.activity_days} listKey={`employee-protection-device-panel:${userId}`} deps={[drawer.filters, revision]}
      multiSource versions onClose={() => setDrawer(null)}
      report={{ onClick: () => { setReport({ filters: drawer.filters, view: "devices" }); setDrawer(null); } }}
      fetchPage={async (offset, limit) => {
        const page = await req<Chunk<Device>>("GET", `${PATH}/devices${qs({ ...drawer.filters, offset, limit })}`);
        const items: DrawerHost[] = page.items.map((d) => ({ host_id: d.host_id ?? 0, href: deviceHref(d), name: d.name, ip: d.ip, os: d.os,
          group: "", zones: d.zones.map((z) => z.name), last_connected: d.last_connected, source_id: d.source_id ?? undefined,
          source: ctx.sources.find((s) => s.id === d.source_id)?.name, app_name: d.av_product, app_version: d.av_version,
          note: <span className="sub">{data.labels.device_status[d.status] || "Состояние неизвестно"}</span>, id: d.id }));
        return { ...page, items };
      }} />}
    {report && <QuickReportPanel kind="quick_employee_protection"
      title={`${TITLE} · ${{ summary: "сводка", employees: "сотрудники", devices: "устройства" }[report.view]}`}
      params={{ ...report.filters, ...(report.view === "summary" ? { view: "employees", detail: "summary" } : { view: report.view }) }}
      options={{ scope: false }} activityDays={ctx.me.activity_days} canReport onClose={() => setReport(null)} />}
  </section>;
}

export default function EmployeeProtectionPage({ ctx }: { ctx: Ctx }) {
  const [params] = useSearchParams();
  const [access, setAccess] = useState<{ allowed: boolean; can_refresh: boolean } | null>(null);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let active = true;
    setError("");
    req<{ allowed: boolean; can_refresh: boolean }>("GET", `${PATH}/access`).then((r) => { if (active) setAccess(r); })
      .catch((e: ApiError) => { if (active) setError(e.message); });
    return () => { active = false; };
  }, [retry]);
  if (access?.allowed && params.get("view") === "workplaces") return <section className="ep">
    <PageHead title="Рабочие места сотрудников" back={<BackLink to={PATH} label={TITLE} />} />
    <WorkplaceReview employeeId={params.get("employee_id") ?? undefined} deviceId={params.get("device_id") ?? undefined} />
  </section>;
  if (access?.allowed) return <ReportDashboard ctx={ctx} canRefresh={access.can_refresh} />;
  return <section><PageHead title={TITLE} />
    {error ? <div className="alert error" role="alert"><div className="alert-body">{error} <button type="button" className="link-btn" onClick={() => setRetry((n) => n + 1)}>Повторить</button></div></div> :
      access ? <Empty icon="shieldPulse" title="Отчёт недоступен">Для просмотра нужны права на все источники KSC, всю область инвентаризации и раздел «Иерархия предприятия».</Empty> : <SkelRows />}
  </section>;
}
