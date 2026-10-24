import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type Product, type ReportParams } from "../api";
import { NoSource, type Ctx } from "../App";
import { HostsDrawer, type DrawerHost } from "../components/HostsDrawer";
import { Icon } from "../components/Icons";
import { ListFoot, VirtualRows, useInfinite, useKept, type Chunk } from "../components/Infinite";
import { Dock, Empty, PageHead, SkelRows, SortTh, Tabs } from "../components/ui";
import { CatalogView, PublishersView } from "./CatalogPage";
import { fmtDate, num, plural } from "../util";

export { SortTh };

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
  const [sp, setSp] = useSearchParams();
  const navigate = useNavigate();
  const sid = ctx.current?.id ?? "";
  const [q, setQ] = useKept("registry.q", sp.get("q") ?? ""); const [publisher, setPublisher] = useKept("registry.publisher", ""); const [version, setVersion] = useKept("registry.version", "");
  const [platform, setPlatform] = useKept("registry.platform", "");
  const [installedOnly, setInstalledOnly] = useKept("registry.installed", true);
  const [all, setAll] = useKept("registry.all", false);
  const [sort, setSort] = useKept("registry.sort", "name"); const [desc, setDesc] = useKept("registry.desc", false);
  const [applied, setApplied] = useState({ q, publisher, version });
  // отмеченные записи реестра живут весь сеанс: после карточки компьютера выбор и открытая панель на месте
  const [selected, setSelected] = useKept<Record<number, Product>>(`registry.sel:${sid}`, {});
  useEffect(() => { const t = window.setTimeout(() => setApplied({ q, publisher, version }), 350); return () => window.clearTimeout(t); }, [q, publisher, version]);
  const list = useInfinite<Product>(`registry:${sid}`, [applied, platform, installedOnly, all, sort, desc],
    (offset, limit) => api.software.registry({ ...applied, platform, installed_only: installedOnly, all_hosts: all, sort, desc, offset, limit }) as unknown as Promise<Chunk<Product>>);
  const toggle = (p: Product) => setSelected((s) => { const n = { ...s }; if (n[p.product_id]) delete n[p.product_id]; else n[p.product_id] = p; return n; });
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(false); } };
  const ids = Object.keys(selected).map(Number);
  const params: ReportParams = { product_ids: ids, include_inactive: all };
  const rec = sp.get("rec"); const found = sp.get("found");
  const setParam = (k: string, v: string | null, extra: Record<string, string> = {}) => setSp((x) => { if (v === null) { x.delete(k); Object.keys(extra).forEach((e) => x.delete(e)); } else { x.set(k, v); Object.entries(extra).forEach(([e, ev]) => x.set(e, ev)); } return x; });
  return (
    <>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Название или часть названия" aria-label="Поиск по названию" /></div>
        <input value={publisher} onChange={(e) => setPublisher(e.target.value)} placeholder="Производитель" aria-label="Производитель" className="w-md" />
        <input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="Версия начинается с" aria-label="Версия" className="w-md" />
        <select value={platform} onChange={(e) => setPlatform(e.target.value)} aria-label="Платформа" className="w-auto"><option value="">Все платформы</option><option value="windows">Windows</option><option value="linux">Linux</option></select>
        <label className="check inline-check"><input type="checkbox" className="switch" checked={installedOnly} onChange={(e) => setInstalledOnly(e.target.checked)} />Только установленные</label>
        <p className="note">Одна строка — запись реестра KSC как есть (название, версия, производитель). «Установок» и «Компьютеров» — на компьютерах, {all ? "включая давно не подключавшиеся" : `активных за ${ctx.me.activity_days} сут`}. Отметьте версии, чтобы найти компьютеры.</p>
      </div>
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : (
          <table className="table virt">
            <thead><tr>
              <th className="check"><span className="sr-only">Выбор</span></th>
              <SortTh k="name" label="Программа" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="version" label="Версия" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="publisher" label="Производитель" sort={sort} desc={desc} onSort={onSort} className="hide-sm" />
              <th className="num">Установок</th><th className="num">Компьютеров</th>
              <SortTh k="first_seen" label="Впервые в сети" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /></tr></thead>
            <tbody>
              <VirtualRows list={list} colSpan={7} estimate={46} row={(p) => (
                <tr className={selected[p.product_id] ? "sel" : ""}>
                  <td className="check"><input type="checkbox" checked={!!selected[p.product_id]} onChange={() => toggle(p)} aria-label={`Выбрать ${p.name} ${p.version}`} disabled={!p.installs} /></td>
                  <td>{p.name}<span className="sub">{p.platform}</span></td>
                  <td><span className="mono">{p.version}</span>{p.upstream_version !== p.version && <span className="sub mono">upstream {p.upstream_version}</span>}</td>
                  <td className="small hide-sm">{p.publisher || <span className="muted">—</span>}</td>
                  <td className="num">{num(p.installs)}</td>
                  <td className="num">{p.installs ? <button type="button" className="count-btn" onClick={() => setParam("rec", String(p.product_id), { rn: `${p.name} ${p.version}` })} title="Показать компьютеры">{num(p.hosts)}</button> : num(p.hosts)}</td>
                  <td className="nowrap small hide-sm">{fmtDate(p.first_seen)}</td>
                </tr>)} />
              {!list.items.length && !list.loading && <tr><td colSpan={7}><Empty icon="search" title="Ничего не найдено">Измените название, производителя или версию. Уберите «Только установленные», чтобы увидеть и удалённые программы.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      <p className="hidden-note"><Icon name={all ? "eye" : "eyeOff"} size={15} /><span>{all ? "Счётчики учитывают все компьютеры." : `Счётчики учитывают компьютеры, подключавшиеся к KSC за ${ctx.me.activity_days} сут.`}</span>
        <button type="button" className="link-btn" onClick={() => setAll(!all)}>{all ? "Только активные" : "Учитывать все"}</button></p>
      {ids.length > 0 && (
        <Dock label="Выбранные версии">
          <span><b>{ids.length}</b> <span className="muted">{plural(ids.length, "версия выбрана", "версии выбраны", "версий выбрано")}</span></span>
          <button className="btn mini primary" onClick={() => setParam("found", "1")}><Icon name="monitor" size={15} />Найти компьютеры</button>
          {ctx.me.user.role !== "viewer" && <button className="btn mini" onClick={() => navigate(reportHref(params))}><Icon name="file" size={15} />Отчёт</button>}
          <button className="btn mini icon" onClick={() => setSelected({})} aria-label="Снять выбор"><Icon name="close" size={15} /></button>
        </Dock>
      )}
      {rec && <HostsDrawer title={sp.get("rn") ?? "Запись реестра"} lede="Компьютеры с этой записью реестра KSC (до 5 000)" listKey={`registry-rec:${sid}:${rec}`} deps={[rec]} activityDays={ctx.me.activity_days}
        fetchPage={async (offset) => { if (offset) return { items: [], total: 0 }; const r = await api.software.productHosts(Number(rec)); return { items: r.items as DrawerHost[], total: r.items.length }; }}
        onClose={() => setParam("rec", null, { rn: "" })} />}
      {found && ids.length > 0 && <HostsDrawer title={`Компьютеры с выбранными версиями (${ids.length})`}
        lede={<>Установки отмеченных записей реестра; {all ? "все устройства" : `подключавшиеся к KSC за ${ctx.me.activity_days} сут`}. {ctx.me.user.role !== "viewer" && <Link to={reportHref(params, `Компьютеры с выбранными версиями (${ids.length})`)}>Сформировать отчёт</Link>}</>}
        listKey={`registry-found:${sid}:${ids.join(",")}:${all}`} deps={[ids, all]} activityDays={ctx.me.activity_days}
        fetchPage={(offset, limit) => api.software.hosts(params, offset, limit) as unknown as Promise<Chunk<DrawerHost>>}
        onClose={() => setParam("found", null)} />}
    </>
  );
}
