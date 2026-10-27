import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type Product, type ReportParams } from "../api";
import { NoSource, type Ctx } from "../App";
import { FilterBar } from "../components/FilterBar";
import { HostsDrawer, type DrawerHost } from "../components/HostsDrawer";
import { Icon } from "../components/Icons";
import { ExpandCell, ExpandTh, ExpandedRow, XGrid, XItem, useExpanded } from "../components/ExpandRow";
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
  const ex = useExpanded<number>();
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
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Название или часть названия", label: "Поиск по названию" }}
        primary={<select value={platform} onChange={(e) => setPlatform(e.target.value)} aria-label="Платформа"><option value="">Все платформы</option><option value="windows">Windows</option><option value="linux">Linux</option></select>}
        more={<>
          <label className="field">Производитель<input value={publisher} onChange={(e) => setPublisher(e.target.value)} placeholder="Например, *Adobe*" /></label>
          <label className="field">Версия начинается с<input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="Например, 7.4" className="mono" /></label>
          <label className="check"><input type="checkbox" className="switch" checked={installedOnly} onChange={(e) => setInstalledOnly(e.target.checked)} />Только установленные</label>
          <label className="check"><input type="checkbox" className="switch" checked={all} onChange={(e) => setAll(e.target.checked)} />Учитывать давно не подключавшиеся компьютеры</label>
        </>}
        moreActive={[publisher, version, !installedOnly ? "1" : "", all ? "1" : ""].filter(Boolean).length}
        chips={[...(q ? [{ id: "q", label: `Название: ${q}`, onRemove: () => setQ("") }] : []), ...(platform ? [{ id: "pl", label: `Платформа: ${platform === "linux" ? "Linux" : "Windows"}`, onRemove: () => setPlatform("") }] : []),
          ...(publisher ? [{ id: "pub", label: `Производитель: ${publisher}`, onRemove: () => setPublisher("") }] : []), ...(version ? [{ id: "ver", label: `Версия: ${version}…`, onRemove: () => setVersion("") }] : []),
          ...(!installedOnly ? [{ id: "inst", label: "Включая удалённые программы", onRemove: () => setInstalledOnly(true) }] : []), ...(all ? [{ id: "all", label: "Включая неактивные компьютеры", onRemove: () => setAll(false) }] : [])]}
        onReset={() => { setQ(""); setPlatform(""); setPublisher(""); setVersion(""); setInstalledOnly(true); setAll(false); }}
        count={{ n: list.initial ? null : list.total, noun: ["запись реестра", "записи реестра", "записей реестра"] }}
        report={ctx.me.user.role !== "viewer" ? { onClick: () => navigate(reportHref(ids.length ? params : { ...params, name_like: applied.q ? `%${applied.q}%` : null, platform: platform || null, min_version: null, q: null }, ids.length ? `Компьютеры с выбранными версиями (${ids.length})` : "Реестр KSC: установки по текущим фильтрам")), title: ids.length ? "Отчёт по отмеченным версиям" : "Отчёт по программам с текущими фильтрами" } : null} />
      <p className="muted small fbar-note">Одна строка — запись реестра KSC как есть. «Установок» и «Компьютеров» — на компьютерах, {all ? "включая давно не подключавшиеся" : `активных за ${ctx.me.activity_days} сут`}. Отметьте версии, чтобы найти компьютеры.</p>
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : (
          <table className="table virt">
            <thead><tr>
              <th className="check"><span className="sr-only">Выбор</span></th><ExpandTh />
              <SortTh k="name" label="Программа" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="version" label="Версия" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="publisher" label="Производитель" sort={sort} desc={desc} onSort={onSort} className="hide-sm" />
              <th className="num">Установок</th><th className="num">Компьютеров</th>
              <SortTh k="first_seen" label="Впервые в сети" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /></tr></thead>
            <VirtualRows group list={list} colSpan={8} estimate={46} row={(p) => (
              <>
                <tr className={selected[p.product_id] ? "sel" : ""}>
                  <td className="check"><input type="checkbox" checked={!!selected[p.product_id]} onChange={() => toggle(p)} aria-label={`Выбрать ${p.name} ${p.version}`} disabled={!p.installs} /></td>
                  <ExpandCell id={`s${p.product_id}`} open={ex.has(p.product_id)} onToggle={() => ex.toggle(p.product_id)} label={`${p.name} ${p.version}`} />
                  <td>{p.name}<span className="sub">{p.platform}</span></td>
                  <td><span className="mono">{p.version}</span>{p.upstream_version !== p.version && <span className="sub mono">upstream {p.upstream_version}</span>}</td>
                  <td className="small hide-sm">{p.publisher || <span className="muted">—</span>}</td>
                  <td className="num">{num(p.installs)}</td>
                  <td className="num">{p.installs ? <button type="button" className="count-btn" onClick={() => setParam("rec", String(p.product_id), { rn: `${p.name} ${p.version}` })} title="Показать компьютеры">{num(p.hosts)}</button> : num(p.hosts)}</td>
                  <td className="nowrap small hide-sm">{fmtDate(p.first_seen)}</td>
                </tr>
                <ExpandedRow id={`s${p.product_id}`} open={ex.has(p.product_id)} colSpan={8}>
                  <XGrid>
                    <XItem label="Запись реестра KSC">{p.name}</XItem><XItem label="Платформа">{p.platform}</XItem><XItem label="Версия в реестре"><span className="mono">{p.version}</span></XItem>
                    <XItem label="Версия разработчика (сравниваемая)">{p.upstream_version !== p.version ? <span className="mono">{p.upstream_version}</span> : "совпадает с версией в реестре"}</XItem>
                    <XItem label="Производитель">{p.publisher}</XItem><XItem label="Впервые обнаружена">{fmtDate(p.first_seen)}</XItem>
                    <XItem label="Установок и компьютеров">{num(p.installs)} установок на {num(p.hosts)} компьютерах{!p.installs ? " (программа удалена)" : ""}</XItem><XItem label="Идентификатор записи"><span className="mono">{p.product_id}</span></XItem>
                  </XGrid>
                  <p className="pt-note">Версия пакета не обязательно равна версии работающей программы. Компьютеры с этой версией — по числу в строке (правая панель).</p>
                </ExpandedRow>
              </>)} />
            {!list.items.length && !list.loading && <tbody><tr><td colSpan={8}><Empty icon="search" title="Ничего не найдено">Измените название, производителя или версию. Уберите «Только установленные», чтобы увидеть и удалённые программы.</Empty></td></tr></tbody>}
          </table>)}
      </div>
      <ListFoot list={list} />
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
        report={ctx.me.user.role !== "viewer" ? { onClick: () => navigate(reportHref({ product_ids: [Number(rec)], include_inactive: all }, `Компьютеры: ${sp.get("rn") ?? "запись реестра"}`)) } : null}
        onClose={() => setParam("rec", null, { rn: "" })} />}
      {found && ids.length > 0 && <HostsDrawer title={`Компьютеры с выбранными версиями (${ids.length})`}
        lede={<>Установки отмеченных записей реестра; {all ? "все устройства" : `подключавшиеся к KSC за ${ctx.me.activity_days} сут`}. {ctx.me.user.role !== "viewer" && <Link to={reportHref(params, `Компьютеры с выбранными версиями (${ids.length})`)}>Сформировать отчёт</Link>}</>}
        listKey={`registry-found:${sid}:${ids.join(",")}:${all}`} deps={[ids, all]} activityDays={ctx.me.activity_days}
        fetchPage={(offset, limit) => api.software.hosts(params, offset, limit) as unknown as Promise<Chunk<DrawerHost>>}
        report={ctx.me.user.role !== "viewer" ? { onClick: () => navigate(reportHref(params, `Компьютеры с выбранными версиями (${ids.length})`)) } : null}
        onClose={() => setParam("found", null)} />}
    </>
  );
}
