/** Общие элементы раздела «Инвентаризация»: контекст (справочники, права), выбор значения справочника, сотрудника, местоположения, учётной единицы, поле дополнительного свойства, метки состояний. */
import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { ApiError } from "../../api";
import { Icon } from "../../components/Icons";
import { inv, type Asset, type BiCandidate, type Loc, type Meta, type Perm, type Person, type Prop, type Ref } from "./invApi";

export interface InvCtxValue { meta: Meta; reload: () => void; can: (p: Perm) => boolean; isAdmin: boolean; role: string; locs: Loc[] | null; reloadLocs: () => void; activityDays: number }
export const InvCtx = createContext<InvCtxValue | null>(null);
export const useInv = () => { const c = useContext(InvCtx); if (!c) throw new Error("InvCtx"); return c; };
export const refsOf = (m: Meta, kind: string, parent?: number | null) => m.refs.filter((r) => r.kind === kind && (parent === undefined || parent === null || r.parent_id === parent));

const ST_TONE: Record<string, string> = { stock: "", use: "ok", reserve: "accent", repair: "warn", writeoff: "err", decom: "", lost: "err" };
export function StBadge({ st, label }: { st: string; label: string }) {
  return <span className={`badge ${ST_TONE[st] ?? ""}`}>{label || "—"}</span>;
}
export function KscBadge({ a }: { a: Pick<Asset, "ksc_link" | "ksc_host_id" | "ksc_name" | "cls"> }) {
  if (!a.ksc_host_id) return ["workstation", "laptop", "server", "vm"].includes(a.cls) ? <span className="badge" title="Учётная карточка не связана с компьютером KSC">нет связи с KSC</span> : null;
  if (a.ksc_link === "lost") return <span className="badge err" title="Компьютер больше не найден в KSC">нет в KSC</span>;
  if (a.ksc_link === "auto") return <span className="badge warn" title="Связь найдена по единственному совпадению имени — подтвердите её в карточке">KSC: предполагается</span>;
  return <span className="badge ok" title={`Компьютер KSC: ${a.ksc_name}`}>KSC</span>;
}

export function RefSelect({ kind, value, onChange, label, parent, empty = "—", disabled, error, required }: { kind: string; value: number | null | undefined; onChange: (v: number | null) => void; label: string; parent?: number | null;
  empty?: string; disabled?: boolean; error?: string; required?: boolean }) {
  const { meta } = useInv();
  const items = refsOf(meta, kind, kind === "model" ? parent : undefined).filter((r) => r.active || r.id === value);
  return (
    <label className={`field ${error ? "invalid" : ""}`}>{label}{required && <span className="req" aria-hidden> *</span>}
      <select value={value ?? ""} onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)} disabled={disabled} aria-invalid={!!error}>
        <option value="">{empty}</option>
        {items.map((r) => <option key={r.id} value={r.id}>{r.name}{!r.active ? " (скрыто)" : ""}</option>)}
      </select>
      {error && <span className="field-err">{error}</span>}
    </label>
  );
}

export function InvZoneSelect({ value, onChange, empty = "Не указана", disabled, error }: { value?: string | null; onChange: (value: string | null) => void; empty?: string; disabled?: boolean; error?: string }) {
  const { meta } = useInv();
  return <label className={`field ${error ? "invalid" : ""}`}>Зона ответственности<select value={value ?? ""} onChange={(e) => onChange(e.target.value || null)} disabled={disabled} aria-invalid={!!error}>
    <option value="">{empty}</option>{(meta.zones ?? []).map((z) => <option key={z.id} value={z.id}>{z.name}</option>)}
    </select>{error && <span className="field-err">{error}</span>}</label>;
}

/** Выбор сотрудника: поиск по учёту и по BI (сотрудник BI переносится в учёт при выборе), быстрое добавление нового. */
export function PersonPicker({ label, value, name, onChange, error, disabled, compact }: { label: string; value: number | null | undefined; name?: string; onChange: (id: number | null, name: string) => void;
  error?: string; disabled?: boolean; compact?: boolean }) {
  const { can } = useInv();
  const [q, setQ] = useState(""); const [open, setOpen] = useState(false);
  const [items, setItems] = useState<Person[]>([]); const [bi, setBi] = useState<BiCandidate[]>([]); const [err, setErr] = useState("");
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const t = window.setTimeout(() => inv.people({ q, limit: 12 }).then((r) => { setItems(r.items); setBi(r.bi); setErr(""); }).catch((e) => setErr((e as ApiError).message)), 200);
    return () => window.clearTimeout(t);
  }, [q, open]);
  useEffect(() => { if (!open) return; const h = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); }; document.addEventListener("mousedown", h); return () => document.removeEventListener("mousedown", h); }, [open]);
  const pick = (p: Person) => { onChange(p.id, p.name); setOpen(false); setQ(""); };
  const fromBi = async (b: BiCandidate) => { try { pick(await inv.addPerson({ bi_id: b.bi_id })); } catch (e) { setErr((e as ApiError).message); } };
  const create = async () => { const nm = q.trim(); if (!nm) return; try { pick(await inv.addPerson({ name: nm, email: nm.includes("@") ? nm : "" })); } catch (e) { setErr((e as ApiError).message); } };
  return (
    <div className={`field inv-pick ${error ? "invalid" : ""}`} ref={box}>
      {!compact && <span className="field-label">{label}</span>}
      <div className="inv-pick-row">
        <button type="button" className="inv-pick-btn" disabled={disabled} aria-haspopup="listbox" aria-expanded={open} aria-label={compact ? label : undefined} onClick={() => setOpen(!open)}>
          {value ? <span>{name || `#${value}`}</span> : <span className="muted">не указан</span>}<Icon name="chevronD" size={14} />
        </button>
        {value && !disabled && <button type="button" className="btn ghost icon mini" aria-label={`Очистить: ${label}`} onClick={() => onChange(null, "")}><Icon name="close" size={14} /></button>}
      </div>
      {open && <div className="inv-pop" role="listbox" aria-label={label}>
        <input autoFocus value={q} onChange={(e) => setQ(e.target.value)} placeholder="ФИО, логин или почта" aria-label="Поиск сотрудника" />
        {err && <p className="field-err">{err}</p>}
        <ul>
          {items.map((p) => <li key={p.id}><button type="button" role="option" aria-selected={p.id === value} onClick={() => pick(p)}><b>{p.name}</b>{!p.active && <span className="badge">не работает</span>}<span className="sub">{[p.dept, p.email].filter(Boolean).join(" · ")}</span></button></li>)}
          {bi.map((b) => <li key={`bi${b.bi_id}`}><button type="button" role="option" aria-selected={false} onClick={() => void fromBi(b)}><b>{b.name}</b><span className="badge">из BI</span><span className="sub">{[b.dept, b.email].filter(Boolean).join(" · ")}</span></button></li>)}
          {!items.length && !bi.length && <li className="muted small inv-pop-empty">{q ? "Никого не найдено" : "Начните вводить имя"}</li>}
        </ul>
        {q.trim().length > 2 && (can("people") || can("create") || can("docs")) && <button type="button" className="btn mini" onClick={() => void create()}><Icon name="plus" size={14} />Добавить сотрудника «{q.trim()}»</button>}
      </div>}
      {error && <span className="field-err">{error}</span>}
    </div>
  );
}

/** Выбор местоположения из дерева: поиск по пути, вложенность отступом. */
export function LocationPicker({ label, value, onChange, error, disabled, placeholder = "не указано" }: { label: string; value: number | null | undefined; onChange: (id: number | null) => void; error?: string; disabled?: boolean; placeholder?: string }) {
  const { locs } = useInv();
  const [open, setOpen] = useState(false); const [q, setQ] = useState("");
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => { if (!open) return; const h = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); }; document.addEventListener("mousedown", h); return () => document.removeEventListener("mousedown", h); }, [open]);
  const list = useMemo(() => (locs ?? []).filter((l) => (l.active || l.id === value) && l.in_scope !== false).sort((a, b) => a.path.localeCompare(b.path, "ru")), [locs, value]);
  const cur = list.find((l) => l.id === value) ?? (locs ?? []).find((l) => l.id === value);
  const hits = q ? list.filter((l) => l.path.toLowerCase().includes(q.toLowerCase())) : list;
  return (
    <div className={`field inv-pick ${error ? "invalid" : ""}`} ref={box}>
      <span className="field-label">{label}</span>
      <div className="inv-pick-row">
        <button type="button" className="inv-pick-btn" disabled={disabled} aria-haspopup="listbox" aria-expanded={open} onClick={() => setOpen(!open)}>
          {cur ? <span title={cur.path}>{cur.path}</span> : <span className="muted">{placeholder}</span>}<Icon name="chevronD" size={14} />
        </button>
        {value && !disabled && <button type="button" className="btn ghost icon mini" aria-label={`Очистить: ${label}`} onClick={() => onChange(null)}><Icon name="close" size={14} /></button>}
      </div>
      {open && <div className="inv-pop" role="listbox" aria-label={label}>
        <input autoFocus value={q} onChange={(e) => setQ(e.target.value)} placeholder="Регион, здание, помещение…" aria-label="Поиск местоположения" />
        <ul>
          {hits.slice(0, 300).map((l) => {
            const depth = q ? 0 : l.path.split(" / ").length - 1;
            return <li key={l.id}><button type="button" role="option" aria-selected={l.id === value} style={{ paddingLeft: 10 + depth * 14 }} onClick={() => { onChange(l.id); setOpen(false); setQ(""); }}>
              {q ? l.path : l.name}<span className="sub">{l.kind_ru}{l.total ? ` · ${l.total} ед.` : ""}</span></button></li>;
          })}
          {!hits.length && <li className="muted small inv-pop-empty">{locs === null ? "Загрузка…" : "Ничего не найдено. Местоположения задаются в разделе «Местоположения»."}</li>}
        </ul>
      </div>}
      {error && <span className="field-err">{error}</span>}
    </div>
  );
}

/** Поиск учётных единиц для добавления в документ, лицензию или связь (сканер штрихкода вводит номер в это поле). */
export function AssetSearch({ onPick, exclude = [], placeholder = "Инвентарный, серийный номер, имя, сотрудник…", extra }: { onPick: (a: Asset) => void; exclude?: number[]; placeholder?: string; extra?: Record<string, string> }) {
  const [q, setQ] = useState(""); const [items, setItems] = useState<Asset[]>([]); const [err, setErr] = useState("");
  useEffect(() => {
    if (q.trim().length < 2) { setItems([]); return; }
    const t = window.setTimeout(() => inv.assets({ q, limit: 15, ...extra }).then((r) => { setItems(r.items); setErr(""); }).catch((e) => setErr((e as ApiError).message)), 220);
    return () => window.clearTimeout(t);
  }, [q, extra]);
  const enter = async () => {
    if (!q.trim()) return;
    try { const a = await inv.lookup(q.trim()); if (!exclude.includes(a.id)) onPick(a); setQ(""); } catch { if (items.length === 1) { onPick(items[0]); setQ(""); } }
  };
  return (
    <div className="inv-asearch">
      <div className="input-icon"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); void enter(); } }} placeholder={placeholder} aria-label="Найти оборудование" /></div>
      {err && <p className="field-err">{err}</p>}
      {items.length > 0 && <ul className="inv-asearch-list">{items.map((a) => {
        const used = exclude.includes(a.id);
        return <li key={a.id}><button type="button" disabled={used} onClick={() => { onPick(a); setQ(""); }}><span className="mono">{a.inv_no}</span><b>{a.label.replace(` (${a.inv_no})`, "")}</b>
          <span className="sub">{[a.serial && `S/N ${a.serial}`, a.user, a.location].filter(Boolean).join(" · ")}</span>{used && <span className="badge">уже добавлено</span>}</button></li>;
      })}</ul>}
    </div>
  );
}

export function PropField({ p, value, onChange, error }: { p: Prop; value: unknown; onChange: (v: unknown) => void; error?: string }) {
  const id = `prop-${p.code}`;
  const lab = <>{p.name}{p.required && <span className="req" aria-hidden> *</span>}</>;
  const help = p.descr ? <span className="field-help">{p.descr}</span> : null;
  const err = error ? <span className="field-err">{error}</span> : null;
  const v = value ?? "";
  if (p.type === "bool") return <label className={`check-row ${error ? "invalid" : ""}`}><input type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)} />{lab}{help}{err}</label>;
  if (p.type === "multiline") return <label className={`field wide ${error ? "invalid" : ""}`} htmlFor={id}>{lab}<textarea id={id} rows={3} value={String(v)} onChange={(e) => onChange(e.target.value)} />{help}{err}</label>;
  if (p.type === "select") return <label className={`field ${error ? "invalid" : ""}`}>{lab}<select value={String(v)} onChange={(e) => onChange(e.target.value || null)}><option value="">—</option>{p.options.map((o) => <option key={o} value={o}>{o}</option>)}</select>{help}{err}</label>;
  if (p.type === "multiselect") {
    const cur = Array.isArray(value) ? (value as string[]) : [];
    return <fieldset className={`field inv-multi ${error ? "invalid" : ""}`}><legend>{lab}</legend><div className="row wrap tight">{p.options.map((o) => <label key={o} className="chip-check"><input type="checkbox" checked={cur.includes(o)} onChange={() => onChange(cur.includes(o) ? cur.filter((x) => x !== o) : [...cur, o])} />{o}</label>)}</div>{help}{err}</fieldset>;
  }
  const type = p.type === "number" ? "text" : p.type === "date" ? "date" : p.type === "url" ? "url" : "text";
  const shown = p.type === "money" && typeof value === "number" ? (value / 100).toFixed(2).replace(".", ",") : String(v);
  return <label className={`field ${error ? "invalid" : ""}`} htmlFor={id}>{lab}<input id={id} type={type} inputMode={p.type === "number" || p.type === "money" ? "decimal" : undefined} value={shown} onChange={(e) => onChange(e.target.value)} placeholder={p.type === "money" ? "0,00" : undefined} />{help}{err}</label>;
}

export function Kv({ rows }: { rows: [string, ReactNode][] }) {
  return <dl className="kv pairs">{rows.filter(([, v]) => v !== null && v !== undefined && v !== "" && v !== false).map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>;
}

export const assetLink = (a: { id: number; inv_no: string }) => <Link to={`/inventory/assets/${a.id}`} className="mono">{a.inv_no}</Link>;
export const shortLabel = (a: Pick<Asset, "label" | "inv_no">) => a.label.replace(` (${a.inv_no})`, "");
export const refName = (refs: Ref[], id: number | null | undefined) => refs.find((r) => r.id === id)?.name ?? "";

/** Путь местоположения в списках: последнее звено крупно, два предыдущих — подписью (полный путь — во всплывающей подсказке). */
export function LocCell({ path, detail }: { path: string; detail?: string }) {
  if (!path) return <span className="muted">не указано</span>;
  const parts = path.split(" / ");
  return <span title={path}>{parts[parts.length - 1]}{detail && <span className="muted"> · {detail}</span>}{parts.length > 1 && <span className="sub">{parts.slice(-3, -1).join(" / ")}</span>}</span>;
}
