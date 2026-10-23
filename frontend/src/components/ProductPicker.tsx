import { useEffect, useId, useRef, useState } from "react";
import { api } from "../api";
import { num } from "../util";
import { Icon } from "./Icons";

export interface PickedProduct { key: string; name: string; publisher?: string; latest_version?: string }

/** Выбор программы из каталога (по всем выбранным источникам): поиск по названию, производителю и вариантам названий; стрелки, Enter, Escape. */
export function ProductPicker({ value, onChange, sourceIds, autoFocus, label = "Программа" }: { value: PickedProduct | null; onChange: (p: PickedProduct | null) => void; sourceIds: string[]; autoFocus?: boolean; label?: string }) {
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<Awaited<ReturnType<typeof api.catalog.search>>["items"]>([]);
  const [busy, setBusy] = useState(false);
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const listId = useId();
  useEffect(() => {
    if (!open) return;
    const t = window.setTimeout(() => {
      setBusy(true);
      api.catalog.search(q, sourceIds).then((r) => { setItems(r.items); setActive(0); }).catch(() => setItems([])).finally(() => setBusy(false));
    }, 200);
    return () => window.clearTimeout(t);
  }, [q, open, sourceIds.join(",")]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);
  const pick = (i: number) => { const p = items[i]; if (!p) return; onChange({ key: p.key, name: p.name, publisher: p.publisher, latest_version: p.latest_version }); setOpen(false); setQ(""); };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive((a) => Math.min(a + 1, items.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
    else if (e.key === "Enter") { if (open && items.length) { e.preventDefault(); pick(active); } }
    else if (e.key === "Escape") { if (open) { e.stopPropagation(); setOpen(false); } }
  };
  if (value && !open) {
    return (
      <div className="picked" role="group" aria-label={label}>
        <span className="picked-name"><b>{value.name}</b>{value.publisher && <span className="muted"> · {value.publisher}</span>}</span>
        <button type="button" className="btn mini ghost" onClick={() => { setOpen(true); window.requestAnimationFrame(() => input.current?.focus()); }}>Изменить</button>
      </div>
    );
  }
  return (
    <div className="picker" ref={box}>
      <div className="input-icon">
        <Icon name="search" size={16} />
        <input ref={input} value={q} autoFocus={autoFocus} role="combobox" aria-expanded={open} aria-controls={listId} aria-autocomplete="list" aria-label={label}
          aria-activedescendant={open && items[active] ? `${listId}-${active}` : undefined}
          placeholder="Начните вводить: Chrome, 7-Zip, Java, PHP…" onFocus={() => setOpen(true)} onChange={(e) => { setQ(e.target.value); setOpen(true); }} onKeyDown={onKey} />
      </div>
      {open && (
        <ul className="picker-list" id={listId} role="listbox" aria-label="Программы каталога">
          {busy && !items.length && <li className="picker-empty">Поиск…</li>}
          {!busy && !items.length && <li className="picker-empty">{q ? "Ничего не найдено в каталоге выбранных источников" : "Каталог пуст: он строится после подключения источника"}</li>}
          {items.map((p, i) => (
            <li key={p.key} id={`${listId}-${i}`} role="option" aria-selected={i === active} className={i === active ? "on" : ""} onMouseEnter={() => setActive(i)} onMouseDown={(e) => { e.preventDefault(); pick(i); }}>
              <span className="pl-main"><b>{p.name}</b>{p.publisher && <span className="muted"> · {p.publisher}</span>}{p.component && <span className="badge outline">компонент</span>}</span>
              <span className="pl-meta"><span className="mono">{p.latest_version}</span><span>{num(p.hosts)} комп.</span></span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
