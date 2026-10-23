import { FormEvent, Fragment, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type ApiError, type Branch, type Grouped, type Host, type Product, type ReportParams, type SoftwareRow, type Summary } from "../api";
import { NoSource, type Ctx } from "../App";
import { ActivityBadge, Fetched, Pager } from "../components/Common";
import { Modal } from "../components/Dialogs";
import { Icon } from "../components/Icons";
import { useToast } from "../components/Toast";
import { Dock, Empty, PageHead, SkelRows, Spectrum, Tabs } from "../components/ui";
import { fmt, fmtDate, num } from "../util";

const DAYS = [1, 3, 7, 14, 30];
const reportHref = (params: ReportParams, title?: string) => `/reports?kind=software_hosts&params=${encodeURIComponent(JSON.stringify(params))}${title ? `&title=${encodeURIComponent(title)}` : ""}`;

export function SortTh({ k, label, sort, desc, onSort, className = "" }: { k: string; label: string; sort: string; desc: boolean; onSort: (k: string) => void; className?: string }) {
  const on = sort === k;
  return <th className={`sortable ${className}`} aria-sort={on ? (desc ? "descending" : "ascending") : undefined} onClick={() => onSort(k)} tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSort(k); } }}>
    {label}<Icon name={on ? (desc ? "chevronD" : "chevronU") : "sort"} size={13} className="sort-ic" /></th>;
}

/** Раздел «Программное обеспечение»: исходный реестр KSC и логическая группировка; отметка версий → компьютеры → отчёт / сценарий аудита. */
export default function SoftwarePage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const mode = sp.get("mode") === "grouped" ? "grouped" : "registry";
  if (!ctx.current) return <NoSource ctx={ctx} />;
  return (
    <section>
      <PageHead title="Программное обеспечение" lede="Реестр приложений Kaspersky Security Center: что установлено, каких версий и на скольких компьютерах." />
      <Tabs label="Режим просмотра" value={mode} onChange={(m) => setSp((p) => { p.set("mode", m); return p; })}
        items={[{ id: "registry", label: "Реестр KSC" }, { id: "grouped", label: "По продуктам и версиям" }]} />
      {mode === "registry" ? <Registry ctx={ctx} /> : <GroupedView ctx={ctx} />}
    </section>
  );
}

function Registry({ ctx }: { ctx: Ctx }) {
  const [sp] = useSearchParams();
  const [q, setQ] = useState(sp.get("q") ?? ""); const [publisher, setPublisher] = useState(""); const [version, setVersion] = useState(""); const [platform, setPlatform] = useState("");
  const [installedOnly, setInstalledOnly] = useState(true);
  const [sort, setSort] = useState("name"); const [desc, setDesc] = useState(false);
  const [applied, setApplied] = useState({ q, publisher, version });
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ items: Product[]; total: number } | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<Map<number, Product>>(new Map());
  const [open, setOpen] = useState<Product | null>(null);
  const [preview, setPreview] = useState(false);
  useEffect(() => { const t = window.setTimeout(() => { setApplied({ q, publisher, version }); setOffset(0); }, 350); return () => window.clearTimeout(t); }, [q, publisher, version]);
  useEffect(() => {
    setBusy(true);
    api.software.registry({ ...applied, platform, installed_only: installedOnly, sort, desc, offset, limit: 50 }).then((r) => { setData(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [applied, platform, installedOnly, sort, desc, offset]);
  const toggle = (p: Product) => setSelected((s) => { const n = new Map(s); if (n.has(p.product_id)) n.delete(p.product_id); else n.set(p.product_id, p); return n; });
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(false); } setOffset(0); };
  const pageIds = (data?.items ?? []).filter((p) => p.installs > 0);
  const allOnPage = pageIds.length > 0 && pageIds.every((p) => selected.has(p.product_id));
  const params: ReportParams = { product_ids: [...selected.keys()] };
  return (
    <>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Название или часть названия" aria-label="Поиск по названию" /></div>
        <input value={publisher} onChange={(e) => setPublisher(e.target.value)} placeholder="Производитель" aria-label="Производитель" style={{ width: 200 }} />
        <input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="Версия начинается с" aria-label="Версия" style={{ width: 180 }} />
        <select value={platform} onChange={(e) => { setPlatform(e.target.value); setOffset(0); }} aria-label="Платформа" style={{ width: "auto" }}><option value="">Все платформы</option><option value="windows">Windows</option><option value="linux">Linux</option></select>
        <label className="check" style={{ margin: 0 }}><input type="checkbox" className="switch" checked={installedOnly} onChange={(e) => { setInstalledOnly(e.target.checked); setOffset(0); }} />Только установленные</label>
        <p className="note">Одна строка — запись реестра KSC (название, версия, производитель). «Установок» — действующие установки, «Компьютеров» — уникальные устройства. Отметьте версии, чтобы найти компьютеры.</p>
      </div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="table-scroll">
        {!data && busy ? <SkelRows cols={6} /> : (
          <table className="table">
            <thead><tr>
              <th className="check"><input type="checkbox" checked={allOnPage} onChange={() => setSelected((s) => { const n = new Map(s); pageIds.forEach((p) => (allOnPage ? n.delete(p.product_id) : n.set(p.product_id, p))); return n; })} aria-label="Выбрать все установленные на странице" disabled={!pageIds.length} /></th>
              <SortTh k="name" label="Программа" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="version" label="Версия" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="publisher" label="Производитель" sort={sort} desc={desc} onSort={onSort} />
              <th className="num">Установок</th><th className="num">Компьютеров</th>
              <SortTh k="first_seen" label="Впервые в сети" sort={sort} desc={desc} onSort={onSort} />
              <th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody style={{ opacity: busy ? .55 : 1, transition: "opacity .15s" }}>
              {(data?.items ?? []).map((p) => (
                <tr key={p.product_id} className={selected.has(p.product_id) ? "sel" : ""}>
                  <td className="check"><input type="checkbox" checked={selected.has(p.product_id)} onChange={() => toggle(p)} aria-label={`Выбрать ${p.name} ${p.version}`} disabled={!p.installs} /></td>
                  <td>{p.name}<span className="sub">{p.platform}</span></td>
                  <td><span className="mono">{p.version}</span>{p.upstream_version !== p.version && <span className="sub mono">upstream {p.upstream_version}</span>}</td>
                  <td className="small">{p.publisher || <span className="muted">—</span>}</td>
                  <td className="num">{num(p.installs)}</td><td className="num">{num(p.hosts)}</td>
                  <td className="nowrap small">{fmtDate(p.first_seen)}</td>
                  <td className="actions"><button className="btn mini" onClick={() => setOpen(p)} disabled={!p.installs}><Icon name="monitor" size={15} />Компьютеры</button></td>
                </tr>))}
              {data && !data.items.length && <tr><td colSpan={8}><Empty icon="search" title="Ничего не найдено">Измените название, производителя или версию. Уберите «Только установленные», чтобы увидеть и удалённые программы.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      {data && <Pager total={data.total} offset={offset} limit={50} onPage={setOffset} />}
      {selected.size > 0 && (
        <Dock label="Выбранные версии">
          <span><b>{selected.size}</b> <span className="muted">{selected.size === 1 ? "версия выбрана" : "версий выбрано"}</span></span>
          <button className="btn mini primary" onClick={() => setPreview(true)}><Icon name="monitor" size={15} />Найти компьютеры</button>
          {ctx.me.user.role !== "viewer" && <Link className="btn mini" to={reportHref(params)}><Icon name="file" size={15} />Отчёт</Link>}
          <button className="btn mini icon" onClick={() => setSelected(new Map())} aria-label="Снять выбор"><Icon name="close" size={15} /></button>
        </Dock>
      )}
      {open && <ProductHostsDialog product={open} onClose={() => setOpen(null)} />}
      {preview && <HostsPreview ctx={ctx} params={params} title={`Компьютеры с выбранными версиями (${selected.size})`} onClose={() => setPreview(false)} />}
    </>
  );
}

function ProductHostsDialog({ product, onClose }: { product: Product; onClose: () => void }) {
  const [d, setD] = useState<Awaited<ReturnType<typeof api.software.productHosts>> | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => { api.software.productHosts(product.product_id).then(setD).catch((e) => setErr((e as ApiError).message)); }, [product.product_id]);
  return (
    <Modal title={`${product.name} ${product.version}`} onClose={onClose} wide>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!d && !err && <div className="table-scroll"><SkelRows rows={4} cols={6} /></div>}
      {d && (<>
        <div className="row">
          <Spectrum label="Активность компьютеров с программой" legend segs={[{ key: "on", label: "Активны", value: d.active, tone: "ok" }, { key: "off", label: `Без связи > ${d.activity_days} сут`, value: d.inactive, tone: "warn" }]} />
          <div className="spacer" /><Fetched at={d.fetched_at} />
        </div>
        <div className="table-scroll">
          <table className="table compact">
            <thead><tr><th>Компьютер</th><th>IP-адрес</th><th>ОС</th><th>Группа</th><th>Установлена</th><th>Подключение к KSC</th><th>Связь</th></tr></thead>
            <tbody>{d.items.map((h: Host) => <tr key={h.install_id ?? h.host_id}><td><Link to={`/hosts/${h.host_id}`}>{h.name}</Link></td><td className="mono nowrap">{h.ip || "—"}</td><td>{h.os}</td><td className="small">{h.group}</td><td className="nowrap">{fmtDate(h.install_date)}</td><td className="nowrap">{fmt(h.last_connected)}</td><td><ActivityBadge days={h.days_since_connection} activityDays={d.activity_days} /></td></tr>)}</tbody>
          </table>
        </div>
        {d.total >= 5000 && <p className="muted small">Показаны первые 5000 установок. Полный список — в отчёте.</p>}
      </>)}
    </Modal>
  );
}

function GroupedView({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const [rules, setRules] = useState<{ key: string; name: string; description: string | null }[]>([]);
  const ruleKey = sp.get("rule") ?? "";
  const [platform, setPlatform] = useState("");
  const [g, setG] = useState<Grouped | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [openBranch, setOpenBranch] = useState<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const [preview, setPreview] = useState(false);
  useEffect(() => { api.software.rules().then((r) => { setRules(r.items); if (!ruleKey && r.items[0]) setSp((p) => { p.set("rule", r.items[0].key); return p; }, { replace: true }); }).catch((e) => setErr((e as ApiError).message)); }, [ruleKey, setSp]);
  useEffect(() => {
    if (!ruleKey) return;
    setBusy(true); setG(null); setPicked(new Set());
    api.software.grouped(ruleKey, platform).then((r) => { setG(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [ruleKey, platform]);
  const rule = rules.find((r) => r.key === ruleKey);
  const key = (b: Branch) => b.branch ?? "";
  const toggle = (k: string) => setPicked((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });
  const params: ReportParams = { rule: ruleKey, branches: [...picked] };
  const pickedRows = (g?.branches ?? []).filter((b) => picked.has(key(b)));
  const branchName = (b: string) => (b ? `${rule?.name ?? ""} ${b}` : "Версия не определена");
  const title = `Аудит ${rule?.name ?? ""}: ${[...picked].map((x) => x || "версия не определена").join(", ")}`;
  return (
    <>
      <div className="toolbar">
        <label className="inline">Продукт
          <select value={ruleKey} onChange={(e) => setSp((p) => { p.set("rule", e.target.value); return p; })}>{rules.map((r) => <option key={r.key} value={r.key}>{r.name}</option>)}</select>
        </label>
        <select value={platform} onChange={(e) => setPlatform(e.target.value)} aria-label="Платформа" style={{ width: "auto" }}><option value="">Все платформы</option><option value="windows">Windows</option><option value="linux">Linux</option></select>
        <div className="spacer" />
        {g && <Fetched at={g.fetched_at} />}
        {rule?.description && <p className="note">{rule.description}</p>}
        {g && <details className="disclosure"><summary>Как отбираются пакеты</summary>
          <p className="small muted" style={{ marginTop: 6 }}>Шаблон в базе <code>{g.rule.name_like}</code>, затем регулярное выражение <code>{g.rule.name_regex}</code>{g.rule.branch_regex && <>; ветка из имени пакета — <code>{g.rule.branch_regex}</code></>}. Если версия пакета не начинается с ветки из имени, используется ветка из имени: версия расширения не выдаётся за версию продукта.</p></details>}
      </div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {busy && <div className="card"><span className="skel" style={{ height: 22, marginBottom: 14 }} /><SkelRows rows={5} cols={5} /></div>}
      {g && (<>
        <div className="card">
          <div className="card-head">
            <h2>Распределение по веткам</h2>
            <span className="muted small">{num(g.installs)} установок на {num(g.hosts)} компьютерах, {num(g.products)} записей реестра</span>
          </div>
          {g.branches.length ? <Spectrum label={`Ветки ${rule?.name ?? ""}`} size="lg" unit=" уст." hover={hover} onHover={setHover} selected={picked} onToggle={toggle}
            segs={g.branches.map((b) => ({ key: key(b), label: b.branch ? `${rule?.name ?? ""} ${b.branch}` : "не определена", value: b.installs, undef: !b.branch, note: `${num(b.hosts)} комп.` }))} />
            : <Empty icon="branch" title="Под правило не попало ни одной установки">Проверьте шаблон правила в разделе «Администрирование → Правила группировки».</Empty>}
          {g.branches.length > 0 && <p className="small muted" style={{ marginTop: 10 }}>Ширина сегмента — доля установок. Щёлкните сегмент или строку, чтобы выбрать ветку.</p>}
        </div>
        {g.branches.length > 0 && (
          <div className="table-scroll" style={{ marginTop: 14 }}>
            <table className="table">
              <thead><tr><th className="check"><span className="sr-only">Выбор</span></th><th>Ветка</th><th className="num">Установок</th><th className="num">Компьютеров</th><th className="num">Пакетов</th><th>Версии пакетов</th><th><span className="sr-only">Действия</span></th></tr></thead>
              <tbody>{g.branches.map((b) => (
                <Fragment key={key(b)}>
                  <tr className={`${picked.has(key(b)) ? "sel" : ""} ${hover === key(b) ? "is-linked" : ""}`} onMouseEnter={() => setHover(key(b))} onMouseLeave={() => setHover(null)}>
                    <td className="check"><input type="checkbox" checked={picked.has(key(b))} onChange={() => toggle(key(b))} aria-label={`Выбрать: ${branchName(key(b))}`} /></td>
                    <td>{b.branch ? <b>{rule?.name} {b.branch}</b> : <span className="badge warn" title="По версии пакета нельзя достоверно определить ветку (метапакет, эпоха дистрибутива)">версия не определена</span>}</td>
                    <td className="num">{num(b.installs)}</td><td className="num">{num(b.hosts)}</td><td className="num">{num(b.packages_count)}</td>
                    <td className="small mono">{b.versions.slice(0, 5).join(", ")}{b.versions.length > 5 ? ` …+${b.versions.length - 5}` : ""}</td>
                    <td className="actions"><button className="btn mini ghost" aria-expanded={openBranch === key(b)} onClick={() => setOpenBranch(openBranch === key(b) ? null : key(b))}>Пакеты<Icon name={openBranch === key(b) ? "chevronU" : "chevronD"} size={15} /></button></td>
                  </tr>
                  {openBranch === key(b) && (
                    <tr className="detail"><td colSpan={7}>
                      <div className="table-scroll"><table className="table compact"><thead><tr><th>Пакет (запись реестра)</th><th>Версия пакета</th><th>Сравниваемая версия</th><th>Производитель</th><th>Платформа</th></tr></thead>
                        <tbody>{b.packages.map((p) => <tr key={p.product_id}><td>{p.name}</td><td className="mono">{p.version}</td><td><span className="mono">{p.compared_version}</span>{p.compared_version !== p.version && <span className="sub">{/^\d+\.\d+$/.test(p.compared_version) && !p.version.startsWith(p.compared_version) ? "ветка из имени пакета" : "без эпохи и ревизии"}</span>}</td><td className="small">{p.publisher || "—"}</td><td>{p.platform}</td></tr>)}</tbody></table></div>
                    </td></tr>
                  )}
                </Fragment>))}
              </tbody>
            </table>
          </div>
        )}
      </>)}
      {picked.size > 0 && (
        <Dock label="Выбранные ветки">
          <span><b>{picked.size}</b> <span className="muted">{picked.size === 1 ? "ветка" : "ветки"}, {num(pickedRows.reduce((a, b) => a + b.installs, 0))} уст.</span></span>
          <button className="btn mini primary" onClick={() => setPreview(true)}><Icon name="monitor" size={15} />Найти компьютеры</button>
          {ctx.me.user.role !== "viewer" && <Link className="btn mini" to={reportHref(params, title)}><Icon name="file" size={15} />Отчёт</Link>}
          <button className="btn mini icon" onClick={() => setPicked(new Set())} aria-label="Снять выбор"><Icon name="close" size={15} /></button>
        </Dock>
      )}
      {preview && <HostsPreview ctx={ctx} params={params} title={title} onClose={() => setPreview(false)} />}
    </>
  );
}

/** Компьютеры по выбору с фильтром активности; отсюда — отчёт или сохранение сценария аудита. */
function HostsPreview({ ctx, params, title, onClose }: { ctx: Ctx; params: ReportParams; title: string; onClose: () => void }) {
  const navigate = useNavigate();
  const [days, setDays] = useState<number | null>(null);
  const [includeInactive, setIncludeInactive] = useState(false);
  const [data, setData] = useState<{ items: SoftwareRow[]; total: number; summary: Summary; branches: Summary["branches"]; fetched_at: string } | null>(null);
  const [offset, setOffset] = useState(0);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [save, setSave] = useState(false);
  const [toast, show] = useToast();
  const full = useMemo<ReportParams>(() => ({ ...params, active_days: days ?? undefined, include_inactive: includeInactive }), [params, days, includeInactive]);
  useEffect(() => { setBusy(true); api.software.hosts(full, offset, 100).then((r) => { setData(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false)); }, [full, offset]);
  const byHost = useMemo(() => { const m = new Map<number, SoftwareRow[]>(); for (const r of data?.items ?? []) m.set(r.host_id, [...(m.get(r.host_id) ?? []), r]); return [...m.values()]; }, [data]);
  const canEdit = ctx.me.user.role !== "viewer";
  const s = data?.summary;
  return (
    <Modal title={title} onClose={onClose} wide>
      <div className="row">
        <label className="inline">Связь с KSC за
          <select value={days ?? ""} onChange={(e) => { setDays(e.target.value ? Number(e.target.value) : null); setOffset(0); }}><option value="">{s?.active_days ?? "…"} сут (по настройке)</option>{DAYS.map((d) => <option key={d} value={d}>{d} сут</option>)}</select></label>
        <label className="check" style={{ margin: 0 }}><input type="checkbox" className="switch" checked={includeInactive} onChange={(e) => { setIncludeInactive(e.target.checked); setOffset(0); }} />Включать компьютеры без связи</label>
        <div className="spacer" />
        {canEdit && <button className="btn" onClick={() => setSave(true)}><Icon name="save" />Сохранить сценарий аудита</button>}
        {canEdit && <button className="btn primary" onClick={() => navigate(reportHref(full, title))}><Icon name="file" />Сформировать отчёт</button>}
      </div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!data && busy && <div className="table-scroll"><SkelRows rows={5} cols={6} /></div>}
      {data && s && (<>
        <div className="meters">
          <div className="meter"><span className="l">Уникальных компьютеров</span><span className="v">{num(s.hosts)}</span></div>
          <div className="meter"><span className="l">Установок</span><span className="v">{num(s.rows)}</span></div>
          <div className="meter"><span className="l">Исключено без связи</span><span className="v">{includeInactive ? "—" : num(s.excluded_inactive_hosts)}</span><span className="t">{includeInactive ? "включены все" : `порог ${s.active_days} сут`}</span></div>
          {s.excluded_not_computers > 0 && <div className="meter"><span className="l">Не компьютеры</span><span className="v">{num(s.excluded_not_computers)}</span><span className="t">кластеры и подчинённые серверы</span></div>}
        </div>
        {data.branches && data.branches.length > 1 && <Spectrum label="Ветки в выборке" unit=" уст." segs={data.branches.map((b) => ({ key: b.branch, label: b.branch, value: b.installs, undef: b.branch.startsWith("("), note: `${b.hosts} комп.` }))} />}
        <div className="row"><span className="muted small">Строки сгруппированы по компьютеру в пределах страницы. Полный список с листами «Установки», «Версии», «Компьютеры» — в отчёте.</span><div className="spacer" /><Fetched at={data.fetched_at} /></div>
        <div className="table-scroll">
          <table className="table compact">
            <thead><tr><th>Компьютер</th><th>IP-адрес</th><th>ОС</th><th>Группа</th><th>Подключение к KSC</th><th>Связь</th><th>Пакеты и версии</th></tr></thead>
            <tbody>{byHost.map((rs) => { const h = rs[0]; return (
              <tr key={h.host_id}><td><Link to={`/hosts/${h.host_id}`}>{h.name}</Link>{h.linux_release && <span className="sub mono">{h.linux_release}</span>}</td><td className="mono nowrap">{h.ip}</td><td>{h.os}</td><td className="small">{h.group}</td><td className="nowrap">{fmt(h.last_connected)}</td>
                <td><ActivityBadge days={h.days_since_connection} activityDays={s.active_days ?? 7} /></td><td className="small mono">{rs.map((r) => `${r.app_name} ${r.app_version}`).join("; ")}</td></tr>); })}
              {!data.items.length && <tr><td colSpan={7}><Empty icon="monitor" title="Компьютеров не найдено">Возможно, все компьютеры с этими версиями давно не подключались к KSC. Включите компьютеры без связи.</Empty></td></tr>}
            </tbody>
          </table>
        </div>
        <Pager total={data.total} offset={offset} limit={100} onPage={setOffset} />
      </>)}
      {save && <SaveCheckDialog params={full} defaultName={title} onClose={() => setSave(false)} onSaved={() => { setSave(false); show("Сценарий сохранён: «Уязвимости → Пользовательские критерии»"); }} />}
      {toast}
    </Modal>
  );
}

function SaveCheckDialog({ params, defaultName, onClose, onSaved }: { params: ReportParams; defaultName: string; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(defaultName.slice(0, 200)); const [cve, setCve] = useState(""); const [severity, setSeverity] = useState("medium"); const [desc, setDesc] = useState(""); const [comment, setComment] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => { e.preventDefault(); setBusy(true); try { await api.reports.saveCheck({ name, selection: params, cve: cve || null, severity, description: desc || null, comment: comment || null }); onSaved(); } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); } };
  return (
    <Modal title="Сохранить сценарий аудита" onClose={onClose}>
      <form onSubmit={submit}>
        <p className="muted small" style={{ marginBottom: 14 }}>Ручная отметка версий — пользовательский критерий проверки. Он показывается отдельно от уязвимостей, найденных KSC.</p>
        <label>Название<input value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} /></label>
        <div className="cols">
          <label>CVE<input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2024-4577, CVE-2024-8926" maxLength={300} /><span className="help">Через запятую, если несколько</span></label>
          <label>Уровень опасности<select value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="low">Низкий</option><option value="medium">Средний</option><option value="high">Высокий</option><option value="critical">Критический</option></select></label>
        </div>
        <label>Описание проблемы<textarea rows={3} value={desc} onChange={(e) => setDesc(e.target.value)} maxLength={4000} /></label>
        <label>Комментарий<textarea rows={2} value={comment} onChange={(e) => setComment(e.target.value)} maxLength={4000} /></label>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" aria-busy={busy} disabled={!name}><span>Сохранить сценарий</span></button></div>
      </form>
    </Modal>
  );
}
