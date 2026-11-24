import { useEffect, useState } from "react";
import { type ApiError, req } from "../../api";
import { fmt } from "../../util";
import { useInv } from "./InvBits";

export const GEO_STATUS: Record<string, string> = {
  unknown: "Недостаточно данных", site: "Площадка по правилу", approx: "Примерно по IP подключения",
  vpn: "VPN или прокси по правилу", conflict: "Противоречивые правила",
};
const ADDRESS_KIND: Record<string, string> = { reported: "Сводный IP KSC", device: "IP, сообщённый устройством", discovered: "IP сетевого опроса", connection: "IP подключения агента" };
const ADDRESS_SCOPE = { public: "публичный", private: "частный", shared: "общий диапазон операторов (CGNAT)", special: "служебный" };
type ConnectionScope = keyof typeof ADDRESS_SCOPE | "missing" | "ambiguous";
const CONNECTION_SCOPE: Record<ConnectionScope, [string, string]> = {
  public: ["Публичный IP подключения", "В зависимости от маршрута адрес может принадлежать шлюзу, NAT, VPN или прокси."],
  private: ["Частный IP подключения", "Адрес может относиться к локальной сети, туннелю или шлюзу. Оценка по GeoIP недоступна."],
  shared: ["IP подключения из общего диапазона операторов (CGNAT)", "Оценка по GeoIP недоступна."],
  special: ["Служебный IP подключения", "Оценка по GeoIP недоступна."],
  missing: ["IP подключения отсутствует", "Адреса устройства и сетевого опроса показаны в исходных наблюдениях при наличии."],
  ambiguous: ["Несколько IP подключения", "Для оценки по GeoIP нужен однозначный адрес подключения."],
};
export interface GeoObservation {
  status: string; source_id: string | null; source?: string; observed_at: string | null; checked_at: string | null; fresh: boolean;
  site?: string; site_id?: number; country?: string; region?: string; city?: string; network?: string; lat?: number | null; lon?: number | null;
  radius_km?: number | null; asn?: number; operator?: string; provider?: string; database_at?: string;
  connection_ip?: { scope: ConnectionScope; ip?: string; source?: string; observed_at?: string | null };
  rules?: { id: number; name: string }[];
  fields?: Record<string, { label: string; value: string; empty: boolean }>;
  evidence?: {
    group?: string; domain?: string; inventory_location?: string; network_location?: string; network_id?: string; last_info_update?: string; last_visible?: string;
    addresses: { ip: string; kind: string; scope?: keyof typeof ADDRESS_SCOPE | null; source?: string; observed_at?: string }[];
    interfaces: { name: string; mac?: string; type?: string }[];
    infra?: { source_id: number; source: string; site?: string; at: string }[];
  };
}

export function placeOf(o: GeoObservation) {
  return o.site || [o.country, o.region, o.city].filter(Boolean).join(" / ");
}

export default function InvGeoCard({ id, onApplied }: { id: number; onApplied?: () => void }) {
  const { can } = useInv();
  const [row, setRow] = useState<GeoObservation | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  useEffect(() => {
    let active = true;
    setRow(null); setError(""); setDone(false);
    req<GeoObservation>("GET", `/inv/geography/assets/${id}`).then((o) => { if (active) setRow(o); })
      .catch((e: ApiError) => { if (active) setError(e.message); });
    return () => { active = false; };
  }, [id]);
  const fields = Object.entries(row?.fields ?? {});
  const fill = fields.filter(([, f]) => f.empty);
  const mayApply = !!fill.length && fill.every(([key]) => can(key === "location_id" ? "location" : key === "resp_id" ? "people" : "edit"));
  const apply = async () => {
    setBusy(true); setError("");
    try {
      await req("POST", `/inv/geography/assets/${id}/apply`, { checked_at: row?.checked_at });
      setDone(true);
      onApplied?.();
    } catch (e) { setError((e as ApiError).message); }
    finally { setBusy(false); }
  };
  const e = row?.evidence;
  const connection = row?.connection_ip;
  return <section className="card">
    <h2>Последнее сетевое местоположение</h2>
    {error && <p className="field-err" role="alert">{error}</p>}
    {!row && !error && <p className="muted">Загрузка…</p>}
    {row && <>
      <div className="row wrap"><b>{placeOf(row) || GEO_STATUS[row.status]}</b><span className="badge">{GEO_STATUS[row.status]}</span>
        {!row.fresh && row.observed_at && <span className="badge">Устарело</span>}</div>
      {row.source && <p className="muted small">{row.source} · наблюдение {fmt(row.observed_at)} · обработано {fmt(row.checked_at)}</p>}
      {connection && <div className="small">
        <b>{CONNECTION_SCOPE[connection.scope][0]}</b>{connection.ip && <> · <span className="mono">{connection.ip}</span></>}
        {connection.source && ` · ${connection.source}`}{connection.observed_at && ` · ${fmt(connection.observed_at)}`}
        <p className="muted small">{CONNECTION_SCOPE[connection.scope][1]}</p>
      </div>}
      {row.status === "approx" && <p className="small">Достоверность низкая. Показана примерная география выхода в сеть{row.radius_km != null ? ` · радиус оценки ${row.radius_km} км` : ""}.</p>}
      {row.provider && <p className="muted small">{row.provider}{row.database_at && ` · база от ${row.database_at}`}{row.asn && ` · AS${row.asn}`}{row.operator && ` · ${row.operator}`}</p>}
      {row.network && <p className="small">Сеть <span className="mono">{row.network}</span></p>}
      {!!row.rules?.length && <p className="small">Правила · {row.rules.map((r) => r.name).join(", ")}</p>}
      {e && <details><summary>Исходные наблюдения</summary>
        {e.group && <p className="small">Группа KSC · {e.group}</p>}{e.domain && <p className="small">Домен или рабочая группа · {e.domain}</p>}
        {[e.inventory_location, e.network_location, e.network_id].some(Boolean) && <p className="small">{[e.inventory_location, e.network_location, e.network_id].filter(Boolean).join(" · ")}</p>}
        {!!e.addresses.length && <ul>{e.addresses.map((a) => <li key={`${a.kind}:${a.ip}`}><span className="mono">{a.ip}</span> · {ADDRESS_KIND[a.kind] || a.kind}{a.scope && ` · ${ADDRESS_SCOPE[a.scope]}`}{a.source && ` · ${a.source}`}{a.observed_at && ` · ${fmt(a.observed_at)}`}</li>)}</ul>}
        {!!e.interfaces.length && <ul>{e.interfaces.map((n, i) => <li key={i}>{[n.name, n.mac, n.type].filter(Boolean).join(" · ")}</li>)}</ul>}
        {!!e.infra?.length && <ul>{e.infra.map((n, i) => <li key={i}>{[n.source, n.site, fmt(n.at)].filter(Boolean).join(" · ")}</li>)}</ul>}
        {e.last_info_update && <p className="muted small">Сведения об устройстве обновлены {fmt(e.last_info_update)}</p>}
      </details>}
      {!!fields.length && <div className="stack mt-sm">
        <h3>Предлагаемые учётные значения</h3>
        <ul>{fields.map(([key, f]) => <li key={key}>{f.label} · {f.value}{!f.empty && " (поле заполнено)"}</li>)}</ul>
        {done ? <p role="status">Предложения для пустых полей применены.</p> :
          mayApply && row.fresh && <div><button type="button" className="btn" disabled={busy} onClick={() => void apply()}>Заполнить пустые поля</button></div>}
      </div>}
    </>}
  </section>;
}
