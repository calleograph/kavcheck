import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

let cache: { id: string; name: string }[] | null = null;
let pending: Promise<{ id: string; name: string }[]> | null = null;
const loadZones = () => cache ? Promise.resolve(cache) : (pending ??= api.zones.options().then((r) => { cache = r.items; return r.items; }).catch(() => { pending = null; return []; }));
export const forgetZones = () => { cache = null; pending = null; };

/** Фильтр «Зона ответственности» для разделов и отчётов; пока зон нет, поле не показывается. */
export function ZoneSelect({ value, onChange, className = "w-md", label = "Зона ответственности", all = "Все зоны" }: { value: string; onChange: (v: string) => void; className?: string; label?: string; all?: string }) {
  const [items, setItems] = useState<{ id: string; name: string }[] | null>(cache);
  useEffect(() => { void loadZones().then(setItems); }, []);
  if (!items || items.length <= 1) return null;          // остаётся только «Без ответственного» — зон ещё не создано
  return <select className={className} value={value} onChange={(e) => onChange(e.target.value)} aria-label={label} title={label}><option value="">{all}</option>{items.map((z) => <option key={z.id} value={z.id}>{z.name}</option>)}</select>;
}

/** Зона компьютера и её ответственные — строка в карточках компьютеров и уязвимостей. */
export function HostZones({ sourceId, hostId }: { sourceId: string | null | undefined; hostId: number }) {
  const [d, setD] = useState<Awaited<ReturnType<typeof api.zones.ofHost>> | null>(null);
  useEffect(() => { if (sourceId) api.zones.ofHost(sourceId, hostId).then(setD).catch(() => setD(null)); }, [sourceId, hostId]);
  if (!d) return null;
  if (!d.zones.length && !d.candidates.length) return <Link className="zone-chip warn" to="/zones/none" title="Компьютер не подошёл ни одной зоне">Без ответственного</Link>;
  return <span className="row tight" style={{ flexWrap: "wrap" }}>
    {d.zones.map((z) => <Link key={z.id} className="zone-chip" to={`/zones/${z.id}`} title={z.responsible.length ? `Ответственные: ${z.responsible.join(", ")}` : "Ответственные не назначены"}>{z.name}{z.responsible.length ? ` · ${z.responsible[0]}${z.responsible.length > 1 ? ` +${z.responsible.length - 1}` : ""}` : ""}</Link>)}
    {d.conflict && <span className="zone-chip warn" title={`Подходит также: ${d.candidates.map((c) => c.name).join(", ")}`}>спорный</span>}
  </span>;
}
