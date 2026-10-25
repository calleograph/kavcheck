import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Modal } from "./Dialogs";

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

/** Поле формы «Зона ответственности» (с подписью): без созданных зон не показывается. */
export function ZoneField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [n, setN] = useState<number | null>(cache ? cache.length : null);
  useEffect(() => { void loadZones().then((x) => setN(x.length)); }, []);
  if (!n || n <= 1) return null;
  return <label className="field">Зона ответственности<ZoneSelect className="" value={value} onChange={onChange} /></label>;
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

/** Выбор зон для отчёта «Состояние безопасности зоны» из раздела «Отчёты»: список зон флажками и переход к настройке отчёта. */
export function ZonePicker({ onPick, onClose }: { onPick: (ids: string[]) => void; onClose: () => void }) {
  const [items, setItems] = useState<{ id: string; name: string }[] | null>(null);
  const [sel, setSel] = useState<string[]>([]);
  useEffect(() => { void loadZones().then(setItems); }, []);
  return (
    <Modal title="Отчёт по зоне ответственности" onClose={onClose} guard={false} lede="Выберите одну или несколько зон: в отчёт войдут компьютеры этих зон из всех доступных источников KSC."
      footer={<><button className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" disabled={!sel.length} onClick={() => onPick(sel)}>Далее</button></>}>
      {!items ? <span className="spin accent" /> : items.length <= 1 && !items.some((z) => z.id !== "none") ? <p className="muted">Зон ещё нет. Создайте их в Администрировании → «Зоны ответственности».</p> : (
        <div className="check-grid">{items.map((z) => <label key={z.id} className="check"><input type="checkbox" checked={sel.includes(z.id)} onChange={() => setSel(sel.includes(z.id) ? sel.filter((x) => x !== z.id) : [...sel, z.id])} />{z.name}</label>)}</div>)}
    </Modal>
  );
}
