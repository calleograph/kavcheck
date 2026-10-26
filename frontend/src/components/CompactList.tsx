import { useState, type ReactNode } from "react";

/** Список значений в ячейке таблицы: до `max` значений, остальные — «+N»; по нажатию раскрывается полный список. В выгрузках (Excel, CSV) списки всегда полные. */
export function CompactList<T>({ items, max = 3, render, label, sep = ", " }: { items: readonly T[]; max?: number; render?: (x: T) => ReactNode; label?: string; sep?: string }) {
  const [open, setOpen] = useState(false);
  if (!items.length) return <span className="muted">—</span>;
  const show = (x: T) => (render ? render(x) : String(x));
  const full = items.length > max && open;
  const head = full ? items : items.slice(0, max);
  const rest = items.length - head.length;
  return (
    <span className={`clist ${full ? "open" : ""}`}>
      {head.map((x, i) => <span key={i} className="clist-i">{show(x)}{i < head.length - 1 || rest > 0 ? sep.trim() ? sep : " " : ""}</span>)}
      {items.length > max && (
        <button type="button" className="clist-more" aria-expanded={full} aria-label={full ? `Свернуть${label ? `: ${label}` : ""}` : `Показать все${label ? `: ${label}` : ""} (ещё ${rest})`}
          title={full ? "Свернуть" : items.map((x) => (typeof x === "string" ? x : "")).filter(Boolean).join(", ") || undefined} onClick={(e) => { e.stopPropagation(); setOpen(!full); }}>
          {full ? "свернуть" : `+${rest}`}
        </button>)}
    </span>
  );
}
