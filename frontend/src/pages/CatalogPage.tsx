import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type ApiError, type CatalogItem, type CatalogState } from "../api";
import type { Ctx } from "../App";
import { HostsDrawer, type DrawerHost } from "../components/HostsDrawer";
import { Icon } from "../components/Icons";
import { ListFoot, VirtualRows, useInfinite, useKept, type Chunk } from "../components/Infinite";
import { useToast } from "../components/Toast";
import { QuickReportPanel } from "../components/QuickReport";
import { VdbCountBadge, useVdbCounts } from "../components/VdbBits";
import { Dock, Empty, HiddenNote, SkelRows, SortTh, MaskHint } from "../components/ui";
import { selLabel, useSelection } from "../selection";
import { fmt, num, plural } from "../util";

/** Строка состояния каталога: когда построен, идёт ли сборка, ошибка; кнопка обновления для аналитика и администратора. */
export function CatalogStateLine({ state, canRebuild, onRebuilt }: { state: CatalogState | null; canRebuild: boolean; onRebuilt?: (s: CatalogState) => void }) {
  const [busy, setBusy] = useState(false);
  const [toast, show] = useToast();
  if (!state) return null;
  const rebuild = async () => { setBusy(true); try { const s = await api.catalog.rebuild(); onRebuilt?.(s); show("Обновление каталога запрошено: обычно занимает до минуты"); } catch (e) { show((e as ApiError).message, "error"); } finally { setBusy(false); } };
  const building = state.status === "building" || (state.requested_at && (!state.started_at || state.requested_at > state.started_at));
  return (
    <span className="stamp catalog-state" role="status">
      {building ? <><span className="spin" aria-hidden />Каталог обновляется{state.status === "building" && state.progress ? `: ${state.progress}` : "…"}</>
        : state.built_at ? <><Icon name="clock" size={14} />Каталог построен {fmt(state.built_at)}</> : <><Icon name="clock" size={14} />Каталог ещё не построен</>}
      {state.error && <span className="err-text" title={state.error}> · {state.error.length > 80 ? state.error.slice(0, 80) + "…" : state.error}</span>}
      {canRebuild && !building && <button type="button" className="link-btn" onClick={rebuild} aria-busy={busy} disabled={busy}>Обновить</button>}
      {toast}
    </span>
  );
}

const PLATFORM_ICON: Record<string, string> = { Windows: "Win", Linux: "Linux" };

type Row = { item: CatalogItem; member?: boolean; self?: boolean };
const plural3 = (n: number) => plural(n, "компонент", "компонента", "компонентов");

/** Каталог: продукты источника. Без поиска — основные продукты, у семейства раскрываются связанные компоненты (php-xml, php-pear → PHP);
 *  с поиском — все совпадения с названием семейства. Отметки — выбор для проверки версий и отчёта (сохраняется между разделами);
 *  число компьютеров открывает список в боковой панели. */
export function CatalogView({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const navigate = useNavigate();
  const sid = ctx.current?.id ?? "";
  const sel = useSelection(sid);
  const [toast, show] = useToast();
  const [q, setQ] = useKept("catalog.q", sp.get("q") ?? "");
  const publisher = sp.get("publisher") ?? "";
  const [platform, setPlatform] = useKept("catalog.platform", "");
  const [components, setComponents] = useKept("catalog.components", false);
  const [all, setAll] = useKept("catalog.all", false);
  const [sort, setSort] = useKept("catalog.sort", "hosts"); const [desc, setDesc] = useKept("catalog.desc", true);
  const [applied, setApplied] = useState(q);
  const [tick, setTick] = useState(0);
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 300); return () => window.clearTimeout(t); }, [q]);
  const urlQ = sp.get("q");   // переход из поиска в верхней панели на уже открытый каталог
  useEffect(() => { if (urlQ !== null) setQ(urlQ); }, [urlQ]); // eslint-disable-line react-hooks/exhaustive-deps
  const grouped = !applied.trim() && !publisher;
  const list = useInfinite<CatalogItem>(`catalog:${sid}`, [applied, publisher, platform, components, all, sort, desc, tick],
    (offset, limit) => api.catalog.list({ q: applied, publisher, platform, components, all_hosts: all, sort, desc, offset, limit, roots: grouped }) as unknown as Promise<Chunk<CatalogItem>>);
  const state = (list.extra as { state?: CatalogState } | null)?.state ?? null;
  const vcounts = useVdbCounts(list.items.map((p) => p.key), state?.status === "ready");
  // пока каталог строится — обновляем раз в 5 секунд
  const building = state?.status === "building" || state?.status === "empty";
  useEffect(() => { if (!building) return; const t = window.setInterval(() => setTick((x) => x + 1), 5000); return () => window.clearInterval(t); }, [building]);
  // раскрытые семейства и их состав
  const [open, setOpen] = useKept<string[]>(`catalog.open:${sid}`, []);
  const [members, setMembers] = useState<Record<string, CatalogItem[]>>({});
  const loadMembers = useCallback(async (key: string) => {
    const id = `${key}|${all}`;
    if (members[id]) return members[id];
    const r = await api.catalog.list({ family: key, all_hosts: all, components: true, limit: 200 });
    setMembers((m) => ({ ...m, [id]: r.items }));
    return r.items;
  }, [members, all]);
  useEffect(() => { for (const k of open) void loadMembers(k).catch(() => undefined); }, [open, all]); // eslint-disable-line react-hooks/exhaustive-deps
  const rows = useMemo<Row[]>(() => list.items.flatMap((item) => {
    const m = grouped && item.family_size > 1 && open.includes(item.key) ? members[`${item.key}|${all}`] : undefined;
    return m ? [{ item }, { item, member: true, self: true }, ...m.map((x) => ({ item: x, member: true }))] : [{ item }];
  }), [list.items, open, members, grouped, all]);
  const view = useMemo(() => ({ ...list, items: rows }), [list, rows]);
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(k === "hosts" || k === "versions"); } };
  const canEdit = ctx.me.user.role !== "viewer";
  const hostsKey = sp.get("hosts");
  const openHosts = (p: CatalogItem) => setSp((x) => { x.set("hosts", p.key); x.set("hn", p.name); return x; });
  const pick = (p: CatalogItem) => ({ key: p.key, name: p.name, latest_version: p.latest_version });
  const toggleFamily = async (p: CatalogItem) => {
    try { const m = await loadMembers(p.key); sel.toggleFamily(pick(p), [pick(p), ...m.map(pick)]); } catch (e) { show((e as ApiError).message, "error"); }
  };
  const [auditReport, setAuditReport] = useState<Record<string, unknown> | null>(null);
  const report = () => {
    const items = sel.items.map((e) => ({ kind: "product" as const, product_key: e.key, product_keys: e.family?.map((m) => m.key) ?? [],
      product_name: e.family && e.family.length > 1 ? `${e.name} и компоненты` : e.name, op: "any" as const, exclude: [], branches: [] }));
    setAuditReport({ items, include_inactive: all, active_days: null, group_contains: null });
  };
  return (
    <>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Программа, пакет, производитель или вариант названия" aria-label="Поиск программы" /><MaskHint /></div>
        <select value={platform} onChange={(e) => setPlatform(e.target.value)} aria-label="Платформа" className="w-auto"><option value="">Все платформы</option><option value="windows">Windows</option><option value="linux">Linux</option></select>
        <label className="check inline-check"><input type="checkbox" className="switch" checked={components} onChange={(e) => setComponents(e.target.checked)} />Служебные компоненты</label>
        <div className="toolbar-foot">
          {publisher && <span className="chip">Производитель: <b>{list.items[0]?.publisher || publisher}</b><button type="button" className="link-btn" onClick={() => setSp((p) => { p.delete("publisher"); return p; })}>сбросить</button></span>}
          {publisher && canEdit && list.items.length > 0 && <button type="button" className="link-btn" onClick={() => list.items.forEach((p) => { if (!sel.has(p.key)) sel.toggle(pick(p)); })}>выбрать все продукты производителя</button>}
          <CatalogStateLine state={state} canRebuild={canEdit} onRebuilt={() => setTick((x) => x + 1)} />
        </div>
      </div>
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      {state && state.status !== "ready" && !list.items.length && !list.loading && (
        <div className="card"><Empty icon="layers" title={state.status === "failed" ? "Каталог не построен" : "Каталог программ строится"}
          action={canEdit && state.status === "failed" ? <button className="btn" onClick={() => api.catalog.rebuild().then(() => setTick((x) => x + 1))}><Icon name="refresh" />Повторить</button> : undefined}>
          {state.status === "failed" ? state.error : "Записи реестра KSC объединяются в продукты и ветки. Это происходит в фоне и обычно занимает до минуты; страница обновится сама."}
        </Empty></div>
      )}
      {(list.initial || list.items.length > 0 || state?.status === "ready") && (
        <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
          {list.initial ? <SkelRows cols={5} /> : (
            <table className="table virt catalog">
              <thead><tr>
                {canEdit && <th className="check"><span className="sr-only">Выбор</span></th>}
                <SortTh k="name" label="Программа" sort={sort} desc={desc} onSort={onSort} />
                <SortTh k="publisher" label="Производитель" sort={sort} desc={desc} onSort={onSort} className="hide-sm" />
                <th className="hide-sm">Ветки</th>
                <SortTh k="versions" label="Версий" sort={sort} desc={desc} onSort={onSort} className="num" />
                <th className="hide-sm">Новейшая · старейшая</th>
                <SortTh k="hosts" label="Компьютеров" sort={sort} desc={desc} onSort={onSort} className="num" />
                <th className="hide-sm" title="Известные уязвимости по внешним базам (NVD, CISA KEV, OSV, БДУ) для установленных версий; подтверждённые KSC — в разделе «Уязвимости»">Уязвимости</th>
                <th><span className="sr-only">Действия</span></th></tr></thead>
              <tbody>
                <VirtualRows list={view} colSpan={canEdit ? 9 : 8} estimate={46} row={({ item: p, member, self }) => {
                  const fam = !member && p.family_size > 1 && p.family_key === p.key;   // основной продукт семейства: отметка — весь набор
                  const checked = self ? sel.has(p.key) && !sel.hasFamily(p.key) : fam ? sel.hasFamily(p.key) : sel.has(p.key);
                  const partial = fam && !checked && (sel.has(p.key) || (members[`${p.key}|${all}`] ?? []).some((m) => sel.has(m.key)));
                  return (
                    <tr className={`${member ? "member" : ""} ${checked ? "sel" : ""}`}>
                      {canEdit && <td className="check"><input type="checkbox" checked={checked} ref={(el) => { if (el) el.indeterminate = !!partial; }}
                        aria-label={fam ? `Выбрать ${p.name} и ${p.family_size - 1} ${plural3(p.family_size - 1)}` : `Выбрать ${self ? `только ${p.name}` : p.name}`}
                        onChange={() => (fam ? void toggleFamily(p) : sel.toggle(pick(p)))} /></td>}
                      <td>{self ? <span className="muted small">только «{p.name}» — основной продукт</span> : <Link to={`/software/p/${encodeURIComponent(p.key)}`} className="strong-link">{p.name}</Link>}
                        {!self && <span className="sub">{p.platforms.map((x) => PLATFORM_ICON[x] ?? x).join(" · ")}{p.origin === "manual" ? " · исправлено вручную" : ""}{p.component ? " · служебный компонент" : ""}
                          {p.family_name && <> · компонент «<Link to={`/software/p/${encodeURIComponent(p.family_key)}`}>{p.family_name}</Link>»</>}</span>}
                        {fam && !grouped && <span className="sub">основной продукт · {p.family_size - 1} {plural3(p.family_size - 1)}</span>}
                        {fam && grouped && <button type="button" className="fam-toggle" aria-expanded={open.includes(p.key)} onClick={() => setOpen((o) => (o.includes(p.key) ? o.filter((k) => k !== p.key) : [...o, p.key]))}>
                          <Icon name="chevronD" size={14} />{p.family_size - 1} {plural3(p.family_size - 1)}</button>}</td>
                      <td className="small hide-sm">{self ? "" : p.publisher || <span className="muted">—</span>}</td>
                      <td className="hide-sm">{!self && <span className="branch-chips">{p.branches.slice(0, 5).map((b) => <span key={b.branch || "-"} className="bchip" title={`${num(b.hosts)} комп.`}>{b.branch || "?"}</span>)}{p.branches.length > 5 && <span className="muted small">+{p.branches.length - 5}</span>}</span>}</td>
                      <td className="num">{self ? "" : num(p.versions_count)}</td>
                      <td className="mono small nowrap hide-sm">{self ? "" : <>{p.latest_version}{p.oldest_version && p.oldest_version !== p.latest_version ? <span className="muted"> · {p.oldest_version}</span> : null}</>}</td>
                      <td className="num">{self ? "" : <button type="button" className="count-btn" onClick={() => openHosts(p)} title="Показать компьютеры">{num(p.hosts)}</button>}{!self && all && p.hidden_hosts > 0 && <span className="sub">{num(p.hidden_hosts)} неакт.</span>}</td>
                      <td className="hide-sm">{!self && <VdbCountBadge c={vcounts[p.key]} productKey={p.key} />}</td>
                      <td className="actions">{canEdit && !self && <Link className="btn mini ghost row-act" to={`/reports?product=${encodeURIComponent(p.key)}&name=${encodeURIComponent(p.name)}${p.latest_version ? `&latest=${encodeURIComponent(p.latest_version)}` : ""}`} title={`Найти устаревшие версии: ${p.name}`}><Icon name="target" size={15} />Проверить</Link>}</td>
                    </tr>);
                }} />
                {!list.items.length && !list.loading && state?.status === "ready" && <tr><td colSpan={9}><Empty icon="search" title="Ничего не найдено">Измените запрос или включите служебные компоненты и показ всех устройств.</Empty></td></tr>}
              </tbody>
            </table>)}
        </div>)}
      <ListFoot list={list} />
      {!list.initial && <HiddenNote hidden={null} days={ctx.me.activity_days} all={all} onToggle={() => setAll(!all)} />}
      {hostsKey && <HostsDrawer title={`Компьютеры: ${sp.get("hn") ?? hostsKey}`} lede={all ? "Все устройства, включая давно не подключавшиеся" : `Компьютеры, подключавшиеся к KSC за ${ctx.me.activity_days} сут`}
        listKey={`catalog-hosts:${sid}:${hostsKey}`} deps={[hostsKey, all]} activityDays={ctx.me.activity_days}
        fetchPage={(offset, limit) => api.catalog.productHosts(hostsKey, { all_hosts: all, offset, limit }) as unknown as Promise<Chunk<DrawerHost>>}
        onClose={() => setSp((x) => { x.delete("hosts"); x.delete("hn"); return x; })} />}
      {sel.count > 0 && <SelectionDock sel={sel} canEdit={canEdit} onCheck={() => navigate("/reports?sel=1")} onReport={report} />}
      {auditReport && <QuickReportPanel kind="version_audit" title={`Установки: ${sel.items.map(selLabel).join(", ")}`.slice(0, 120)} lede="Компьютеры, где установлены выбранные программы (любая версия)"
        params={auditReport} sourceIds={[sid]} options={{ scope: true }} activityDays={ctx.me.activity_days} canReport={canEdit} onClose={() => setAuditReport(null)} />}
      {toast}
    </>
  );
}

/** Панель выбранных программ: что выбрано и что с этим сделать. Выбор хранится по источнику и не теряется при переходах. */
export function SelectionDock({ sel, canEdit, onCheck, onReport }: { sel: ReturnType<typeof useSelection>; canEdit: boolean; onCheck: () => void; onReport: () => void }) {
  const shown = sel.items.slice(0, 3);
  return (
    <Dock label="Выбранные программы">
      <span className="dock-sel"><b>{num(sel.count)}</b> <span className="muted">{plural(sel.count, "программа", "программы", "программ")}:</span>
        {shown.map((e) => <span key={e.key} className="dock-chip">{selLabel(e)}<button type="button" aria-label={`Убрать ${e.name}`} onClick={() => sel.remove(e.key)}><Icon name="close" size={12} /></button></span>)}
        {sel.items.length > 3 && <span className="muted">и ещё {sel.items.length - 3}</span>}</span>
      {canEdit && <button className="btn mini primary" onClick={onCheck}><Icon name="target" size={15} />Проверить версии</button>}
      {canEdit && <button className="btn mini" onClick={onReport}><Icon name="file" size={15} />Сформировать отчёт</button>}
      <button className="btn mini icon" onClick={sel.clear} aria-label="Снять выбор"><Icon name="close" size={15} /></button>
    </Dock>
  );
}

export function PublishersView({ ctx }: { ctx: Ctx }) {
  const [, setSp] = useSearchParams();
  const [q, setQ] = useKept("publishers.q", ""); const [applied, setApplied] = useState(q);
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 300); return () => window.clearTimeout(t); }, [q]);
  const list = useInfinite<{ publisher_key: string; publisher: string; products: number; top: string[]; max_hosts: number }>(`publishers:${ctx.current?.id}`, [applied],
    (offset, limit) => api.catalog.publishers({ q: applied, offset, limit }) as unknown as Promise<Chunk<{ publisher_key: string; publisher: string; products: number; top: string[]; max_hosts: number }>>);
  const open = (key: string) => setSp((p) => { p.set("tab", "catalog"); p.set("publisher", key); return p; });
  return (
    <>
      <div className="toolbar"><div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Производитель или его программа" aria-label="Поиск производителя" /><MaskHint /></div>
        <p className="note">Производители объединяются без учёта формы собственности: «Google LLC» и «Google Inc.» — один производитель. Показаны компьютеры, активные за {ctx.me.activity_days} сут.</p></div>
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={4} /> : (
          <table className="table virt">
            <thead><tr><th>Производитель</th><th className="num">Продуктов</th><th>Основные продукты</th><th className="num">Компьютеров у самого распространённого</th></tr></thead>
            <tbody>
              <VirtualRows list={list} colSpan={4} estimate={38} row={(p) => (
                <tr className="clickable" onClick={() => open(p.publisher_key)}>
                  <td><button type="button" className="link-btn strong-link" onClick={() => open(p.publisher_key)}>{p.publisher}</button></td>
                  <td className="num">{num(p.products)}</td><td className="small">{p.top.join(", ")}</td><td className="num">{num(p.max_hosts)}</td>
                </tr>)} />
              {!list.items.length && !list.loading && <tr><td colSpan={4}><Empty icon="search" title="Производители не найдены">Каталог пуст или запрос слишком узкий.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
    </>
  );
}
