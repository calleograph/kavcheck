import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { type ApiError, qs, req } from "../../api";
import { FilterBar } from "../../components/FilterBar";
import { ListFoot, useInfinite, VirtualRows } from "../../components/Infinite";
import { useToast } from "../../components/Toast";
import { Empty, SkelRows } from "../../components/ui";
import { fmt, num } from "../../util";
import { useInv } from "./InvBits";
import { GEO_STATUS, placeOf, type GeoObservation } from "./InvGeoCard";
import InvGeoMap, { type GeoGroup } from "./InvGeoMap";
import InvGeoRules from "./InvGeoRules";
import { useInvReport } from "./InvReport";

type GeoRow = GeoObservation & { id: number; inv_no: string; name: string; account_location: string };
type Source = { id: string; name: string; count?: number; finished_at?: string; geoip?: boolean; asn?: boolean; error?: string; geo_errors?: string[] };
type OverviewSummary = { groups?: GeoGroup[]; groups_limited?: boolean; sources?: Source[] };
type Overview = { items: GeoRow[]; total: number } & OverviewSummary;
type Filters = Record<string, string | number>;
type Level = "country" | "region" | "city" | "site";
const LEVELS: Record<Level, string> = { country: "Страны", region: "Регионы", city: "Города", site: "Площадки" };
const LABELS: Record<string, string> = {
  q: "Поиск", dept_id: "Подразделение", zone_id: "Зона", type_id: "Тип", country: "Страна", region: "Регион", city: "Город", site_id: "Площадка",
  freshness: "Актуальность", network: "Сеть", observation_source: "Источник", status: "Состояние наблюдения",
};
const FRESH: Record<string, string> = { fresh: "Актуально", stale: "Старше 7 дней", unknown: "Время неизвестно" };
const ACCOUNT = new Set(["q", "dept_id", "zone_id", "type_id"]);

function pickGroup(g: GeoGroup, level?: Level): Filters {
  if (level === "site" || (!level && g.site_id)) return g.site_id ? { site_id: g.site_id } : {};
  if (level && !g[level]) return {};
  const result: Filters = {};
  for (const k of ["country", "region", "city"] as const) {
    if (g[k]) result[k] = g[k];
    if (k === level) break;
  }
  if (!level && g.status) result.status = g.status;
  return result;
}

export default function InvGeography() {
  const { meta, locs, isAdmin } = useInv();
  const rep = useInvReport();
  const [f, setF] = useState<Filters>({});
  const [version, reload] = useState(0);
  const [level, setLevel] = useState<Level>("city");
  const [rulesOpen, showRules] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [toast, notify] = useToast();
  const filterKey = JSON.stringify(f);
  const list = useInfinite<GeoRow>("inv-geography", [filterKey, version], async (offset, limit) => {
    const result = await req<Overview>("GET", `/inv/geography${qs({ ...f, offset, limit, overview: offset === 0 })}`);
    return { ...result, filterKey };
  }, 100, { retainExtraOnAppend: true });
  const data = list.extra as (OverviewSummary & { filterKey: string }) | null;
  const groups = data?.filterKey === filterKey ? data.groups ?? [] : [];
  const source = data?.sources ?? [];
  const change = (key: string, value: string | number) => setF((prev) => {
    const next = { ...prev };
    if (value === "") delete next[key];
    else next[key] = value;
    return next;
  });
  const drill = (selected: Filters) => setF((prev) => ({ ...Object.fromEntries(Object.entries(prev).filter(([key]) =>
    !["country", "region", "city", "site_id", "status"].includes(key))), ...selected }));
  const places = useMemo(() => {
    const rows = new Map<string, { name: string; n: number; filters: Filters }>();
    for (const g of groups) {
      const filters = pickGroup(g, level);
      const key = JSON.stringify(filters);
      const name = level === "site" ? g.site : g[level] && [g.country, g.region, g.city].slice(0, level === "country" ? 1 : level === "region" ? 2 : 3).filter(Boolean).join(" / ");
      const prev = rows.get(key);
      if (prev) prev.n += g.n;
      else rows.set(key, { name: name || "Не определено", n: g.n, filters });
    }
    return [...rows.values()].sort((a, b) => b.n - a.n || a.name.localeCompare(b.name));
  }, [groups, level]);

  const option = (key: string, opts: { id: string | number; name: string }[], empty: string) => (
    <label className="field">{LABELS[key]}<select value={f[key] ?? ""} onChange={(e) => change(key, e.target.value)}>
      <option value="">{empty}</option>{opts.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}</select></label>);
  const titles = (key: string, value: string | number) => {
    if (key === "status") return GEO_STATUS[value];
    if (key === "freshness") return FRESH[value];
    if (key === "observation_source") return source.find((s) => s.id === value)?.name ?? String(value);
    if (key === "zone_id") return meta.zones.find((s) => s.id === value)?.name ?? String(value);
    if (key === "site_id") return locs?.find((s) => s.id === Number(value))?.path ?? String(value);
    if (key === "dept_id" || key === "type_id") return meta.refs.find((s) => s.id === Number(value))?.name ?? String(value);
    return String(value);
  };
  const requestRefresh = async () => {
    setSubmitting(true);
    try {
      await req("POST", "/inv/geography/refresh");
      notify("Обновление сетевых наблюдений поставлено в очередь");
    } catch (e) { notify((e as ApiError).message, "error"); }
    finally { setSubmitting(false); }
  };
  const report = () => {
    const entries = Object.entries(f);
    rep.open(["geography"], { ...Object.fromEntries(entries.filter(([k]) => ACCOUNT.has(k))),
      geography: Object.fromEntries(entries.filter(([k]) => !ACCOUNT.has(k))) }, "Сетевые местоположения оборудования");
  };

  return <div className="inv-page">
    <div className="inv-head"><h1>Карта оборудования</h1>
      {isAdmin && <div className="row wrap">
        <button type="button" className="btn" onClick={() => showRules(!rulesOpen)} aria-expanded={rulesOpen}>Правила принадлежности</button>
        <button type="button" className="btn" disabled={submitting} onClick={() => void requestRefresh()}>Запросить обновление</button>
      </div>}
    </div>
    {isAdmin && rulesOpen && <InvGeoRules sources={source} onChanged={() => reload((v) => v + 1)} />}
    <FilterBar search={{ value: String(f.q ?? ""), onChange: (v) => change("q", v), placeholder: "Инвентарный номер или имя" }}
      primary={option("freshness", Object.entries(FRESH).map(([id, name]) => ({ id, name })), "Любая")}
      more={<>
        {option("dept_id", meta.refs.filter((r) => r.kind === "dept" && r.active), "Все подразделения")}
        {option("zone_id", meta.zones, "Все зоны")}
        {option("type_id", meta.refs.filter((r) => r.kind === "type" && r.active), "Все типы")}
        {option("observation_source", source, "Все источники")}
        {option("status", Object.entries(GEO_STATUS).map(([id, name]) => ({ id, name })), "Все состояния")}
        <label className="field">Сеть из правила<input value={f.network ?? ""} onChange={(e) => change("network", e.target.value)} maxLength={300} placeholder="192.0.2.0/24" /></label>
      </>}
      moreActive={Object.keys(f).filter((k) => !["q", "freshness"].includes(k)).length}
      chips={Object.entries(f).map(([key, value]) => ({ id: key, label: `${LABELS[key]} · ${titles(key, value)}`, onRemove: () => change(key, "") }))}
      onReset={() => setF({})} count={{ n: list.initial ? null : list.total, noun: ["устройство", "устройства", "устройств"] }}
      onRefresh={() => reload((v) => v + 1)} refreshing={list.initial} report={{ onClick: report, disabled: list.initial || !list.total }} />
    {list.error && list.initial && <p className="field-err" role="alert">{list.error}</p>}
    <div className="card stack">
      <InvGeoMap groups={groups} select={(g) => drill(pickGroup(g))} />
      <p className="small muted">Точки площадок заданы в справочнике. Область вокруг точки показывает приблизительную погрешность географии выхода в сеть. Подложка Natural Earth.</p>
      {!!groups.length && <div className="row wrap inv-geo-groups">
        <label className="field">Сгруппировать<select value={level} onChange={(e) => setLevel(e.target.value as Level)}>
          {Object.entries(LEVELS).map(([id, name]) => <option key={id} value={id}>{name}</option>)}
        </select></label>
        {places.map((p, i) => Object.keys(p.filters).length ?
          <button key={i} type="button" className="btn mini" onClick={() => drill(p.filters)}>{p.name} · {num(p.n)}</button> :
          <span key={i} className="muted small">{p.name} · {num(p.n)}</span>)}
      </div>}
      {data?.filterKey === filterKey && data.groups_limited && <p className="muted small">На карте показаны до 500 крупнейших групп. Уточните фильтры для остальных.</p>}
    </div>
    {list.initial ? <div className="card"><SkelRows rows={6} cols={4} /></div> : !list.items.length ?
      <div className="card"><Empty icon="monitor" title="Устройств по этим условиям нет" /></div> :
      <div className="card flush table-scroll"><table className="table">
        <thead><tr><th>Оборудование</th><th>Учётное местоположение</th><th>Сетевое местоположение</th><th>Наблюдение</th></tr></thead>
        <tbody><VirtualRows list={list} colSpan={4} estimate={64} row={(item) => <tr key={item.id}>
          <td><Link to={`/inventory/assets/${item.id}?tab=place`}>{item.name || item.inv_no}</Link><span className="sub mono">{item.inv_no}</span></td>
          <td>{item.account_location || "—"}</td><td>{placeOf(item) || "—"}<span className="sub">{GEO_STATUS[item.status]}{item.network && ` · ${item.network}`}</span></td>
          <td>{fmt(item.observed_at)}<span className="sub">{source.find((s) => s.id === item.source_id)?.name}{item.observed_at && !item.fresh && " · устарело"}</span></td>
        </tr>} /></tbody></table><ListFoot list={list} /></div>}
    {!!source.length && <details className="card"><summary>Источники наблюдений</summary>
      <ul>{source.map((s) => <li key={s.id}><b>{s.name}</b> · {s.finished_at ? fmt(s.finished_at) : "снимок ожидается"}
        {s.count !== undefined && ` · наблюдений ${num(s.count)}`}{s.finished_at && (s.geoip ? " · база GeoLite2 City доступна" : " · база GeoLite2 City отсутствует")}
        {s.error && " · последнее обновление завершилось ошибкой"}{!!s.geo_errors?.length && " · ошибка базы GeoIP"}</li>)}</ul>
    </details>}
    {rep.node}{toast}
  </div>;
}
