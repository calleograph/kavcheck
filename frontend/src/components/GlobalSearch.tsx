import { useEffect, useId, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api, type Host } from "../api";
import { num } from "../util";
import { Icon } from "./Icons";

type Product = Awaited<ReturnType<typeof api.catalog.search>>["items"][number];
type Hit = { kind: "host"; host: Host } | { kind: "product"; product: Product } | { kind: "all"; to: string; label: string };

/** Поиск в верхней панели: компьютер или программа текущего источника за одно действие. «/» или Ctrl+K — к полю; стрелки, Enter, Escape.
 *  На узком экране поле открывается кнопкой поверх верхней панели. */
export function GlobalSearch({ sourceId }: { sourceId: string | null }) {
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [wide, setWide] = useState(false);   // открыто на узком экране
  const [hosts, setHosts] = useState<Host[]>([]);
  const [products, setProducts] = useState<Product[]>([]);
  const [busy, setBusy] = useState(false);
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const listId = useId();
  const term = q.trim();

  useEffect(() => { setOpen(false); setWide(false); setQ(""); }, [pathname, sourceId]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLElement && (e.target.matches("input, textarea, select") || e.target.isContentEditable);
      if ((e.key === "k" && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !typing)) { e.preventDefault(); setWide(true); window.requestAnimationFrame(() => input.current?.focus()); }
    };
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, []);
  useEffect(() => {
    if (!open) return;
    const away = (e: Event) => { if (!box.current?.contains(e.target as Node)) { setOpen(false); setWide(false); } };
    document.addEventListener("mousedown", away); document.addEventListener("touchstart", away, { passive: true });
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("touchstart", away); };
  }, [open]);
  useEffect(() => {
    if (!sourceId || term.length < 2) { setHosts([]); setProducts([]); return; }
    let alive = true;
    const t = window.setTimeout(() => {
      setBusy(true);
      Promise.all([
        api.hosts.list({ q: term, activity: "all", limit: 5 }).then((r) => r.items).catch(() => []),
        api.catalog.search(term, [sourceId]).then((r) => r.items.slice(0, 5)).catch(() => []),
      ]).then(([h, p]) => { if (alive) { setHosts(h); setProducts(p); setActive(0); } }).finally(() => { if (alive) setBusy(false); });
    }, 220);
    return () => { alive = false; window.clearTimeout(t); };
  }, [term, sourceId]);

  const vulnId = /^(cve|bdu|ghsa)[-:]/i.test(term);   // идентификатор уязвимости: база уязвимостей — первым вариантом
  const enc = encodeURIComponent(term);
  const all: Hit[] = [
    { kind: "all", to: `/hosts?activity=all&q=${enc}`, label: `Все компьютеры с «${term}»` },
    { kind: "all", to: `/software?q=${enc}`, label: `Все программы с «${term}»` },
    { kind: "all", to: `/vdb?tab=search&q=${enc}`, label: `Уязвимости с «${term}» в базе уязвимостей` },
  ];
  const hits: Hit[] = term.length < 2 ? [] : [
    ...hosts.map((host) => ({ kind: "host" as const, host })),
    ...products.map((product) => ({ kind: "product" as const, product })),
    ...(vulnId ? [all[2], all[0], all[1]] : all),
  ];
  const go = (h: Hit | undefined) => {
    if (!h) return;
    navigate(h.kind === "host" ? `/hosts/${h.host.host_id}` : h.kind === "product" ? `/software/p/${encodeURIComponent(h.product.key)}` : h.to);
    setOpen(false); setWide(false); setQ(""); input.current?.blur();
  };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive((a) => Math.min(a + 1, hits.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); go(hits[active]); }
    else if (e.key === "Escape") { e.stopPropagation(); setOpen(false); setWide(false); input.current?.blur(); }
  };
  const option = (h: Hit, i: number) => (
    <li key={h.kind === "host" ? `h${h.host.host_id}` : h.kind === "product" ? `p${h.product.key}` : h.to} id={`${listId}-${i}`} role="option" aria-selected={i === active}
      className={`gs-opt ${i === active ? "on" : ""} ${h.kind === "all" ? "gs-all" : ""}`} onMouseEnter={() => setActive(i)} onMouseDown={(e) => { e.preventDefault(); go(h); }}>
      {h.kind === "host" ? <><Icon name="monitor" size={16} /><span className="gs-main"><b>{h.host.name}</b><span className="gs-sub">{[h.host.ip, h.host.os, h.host.group].filter(Boolean).join(" · ")}</span></span></>
        : h.kind === "product" ? <><Icon name="layers" size={16} /><span className="gs-main"><b>{h.product.name}</b><span className="gs-sub">{[h.product.publisher, h.product.latest_version && `новейшая ${h.product.latest_version}`].filter(Boolean).join(" · ")}</span></span><span className="gs-n">{num(h.product.hosts)} комп.</span></>
          : <><Icon name="search" size={16} /><span className="gs-main">{h.label}</span><Icon name="chevronR" size={15} className="gs-go" /></>}
    </li>);
  const firstProduct = hosts.length;
  return (
    <div className={`gsearch ${wide ? "wide" : ""} ${open && term.length >= 2 ? "open" : ""}`} ref={box}>
      <button type="button" className="btn ghost icon gs-toggle" aria-label="Поиск компьютера, программы или уязвимости" onClick={() => { setWide(true); window.requestAnimationFrame(() => input.current?.focus()); }}><Icon name="search" size={19} /></button>
      <div className="input-icon gs-field">
        <Icon name="search" size={16} />
        <input ref={input} value={q} disabled={!sourceId} role="combobox" aria-expanded={open && term.length >= 2} aria-controls={listId} aria-autocomplete="list" aria-label="Поиск компьютера, программы или уязвимости"
          aria-activedescendant={open && hits[active] ? `${listId}-${active}` : undefined} placeholder="Компьютер, программа или CVE" spellCheck={false} autoComplete="off"
          onFocus={() => setOpen(true)} onChange={(e) => { setQ(e.target.value); setOpen(true); }} onKeyDown={onKey} />
        {busy ? <span className="spin sm gs-kbd" aria-hidden /> : !q && <kbd className="gs-kbd" aria-hidden>/</kbd>}
      </div>
      {open && term.length >= 2 && (
        <ul className="gs-list" id={listId} role="listbox" aria-label="Найдено">
          {hosts.length > 0 && <li className="gs-group" role="presentation">Компьютеры</li>}
          {hits.slice(0, firstProduct).map((h, i) => option(h, i))}
          {products.length > 0 && <li className="gs-group" role="presentation">Программы</li>}
          {hits.slice(firstProduct, firstProduct + products.length).map((h, i) => option(h, firstProduct + i))}
          {!hosts.length && !products.length && <li className="gs-empty" role="presentation">{busy ? "Поиск…" : "Точных совпадений нет — поищите в разделах:"}</li>}
          {(hosts.length > 0 || products.length > 0) && <li className="gs-sep" role="presentation" />}
          {hits.slice(firstProduct + products.length).map((h, i) => option(h, firstProduct + products.length + i))}
          <li className="gs-note" role="presentation">Звёздочка * заменяет любые символы: <span className="mono">SRV-*</span>, <span className="mono">*-DB</span>, <span className="mono">*SQL*</span></li>
        </ul>)}
    </div>
  );
}
