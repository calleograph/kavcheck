import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type ApiError, type Host, type Product, type ReportParams, type SoftwareRow, type Summary } from "../api";
import { NoSource, type Ctx } from "../App";
import { ActivityBadge, Fetched, Pager } from "../components/Common";
import { Modal } from "../components/Dialogs";
import { Icon } from "../components/Icons";
import { Dock, Empty, PageHead, SkelRows, SortTh, Spectrum, Tabs } from "../components/ui";
import { CatalogView, PublishersView } from "./CatalogPage";
import { fmt, fmtDate, num } from "../util";

export { SortTh };

const DAYS = [1, 3, 7, 14, 30];
const reportHref = (params: ReportParams, title?: string) => `/reports?kind=software_hosts&params=${encodeURIComponent(JSON.stringify(params))}${title ? `&title=${encodeURIComponent(title)}` : ""}`;


type Tab = "catalog" | "publishers" | "registry";

/** Раздел «Программы»: каталог продуктов (автоматически из реестра KSC), производители и исходный реестр. */
export default function SoftwarePage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const raw = sp.get("tab") ?? (sp.get("mode") === "registry" ? "registry" : "catalog");
  const tab: Tab = raw === "publishers" || raw === "registry" ? raw : "catalog";
  if (!ctx.current) return <NoSource ctx={ctx} />;
  return (
    <section>
      <PageHead title="Программы" lede="Что установлено на компьютерах, каких версий и где. Каталог объединяет записи реестра KSC в продукты и ветки — выберите программу, чтобы увидеть версии и компьютеры или проверить устаревшие версии." />
      <Tabs label="Вид" value={tab} onChange={(m) => setSp((p) => { p.set("tab", m); p.delete("mode"); if (m !== "catalog") p.delete("publisher"); return p; })}
        items={[{ id: "catalog", label: "Каталог" }, { id: "publishers", label: "Производители" }, { id: "registry", label: "Реестр KSC" }]} />
      {tab === "catalog" ? <CatalogView ctx={ctx} /> : tab === "publishers" ? <PublishersView ctx={ctx} /> : <Registry ctx={ctx} />}
    </section>
  );
}

function Registry({ ctx }: { ctx: Ctx }) {
  const [sp] = useSearchParams();
  const [q, setQ] = useState(sp.get("q") ?? ""); const [publisher, setPublisher] = useState(""); const [version, setVersion] = useState(""); const [platform, setPlatform] = useState("");
  const [installedOnly, setInstalledOnly] = useState(true);
  const [all, setAll] = useState(false);
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
    api.software.registry({ ...applied, platform, installed_only: installedOnly, all_hosts: all, sort, desc, offset, limit: 50 }).then((r) => { setData(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [applied, platform, installedOnly, all, sort, desc, offset]);
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
        <p className="note">Одна строка — запись реестра KSC как есть (название, версия, производитель). «Установок» и «Компьютеров» — на компьютерах, {all ? "включая давно не подключавшиеся" : `активных за ${ctx.me.activity_days} сут`}. Отметьте версии, чтобы найти компьютеры.</p>
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
      <p className="hidden-note"><Icon name={all ? "eye" : "eyeOff"} size={15} /><span>{all ? "Счётчики учитывают все компьютеры." : `Счётчики учитывают компьютеры, подключавшиеся к KSC за ${ctx.me.activity_days} сут.`}</span>
        <button type="button" className="link-btn" onClick={() => { setAll(!all); setOffset(0); }}>{all ? "Только активные" : "Учитывать все"}</button></p>
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

function HostsPreview({ ctx, params, title, onClose }: { ctx: Ctx; params: ReportParams; title: string; onClose: () => void }) {
  const navigate = useNavigate();
  const [days, setDays] = useState<number | null>(null);
  const [includeInactive, setIncludeInactive] = useState(false);
  const [data, setData] = useState<{ items: SoftwareRow[]; total: number; summary: Summary; branches: Summary["branches"]; fetched_at: string } | null>(null);
  const [offset, setOffset] = useState(0);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
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
    </Modal>
  );
}

